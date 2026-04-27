#include "ki.h"

static PSYSTEM_THREAD KiTimerIrqThread;
static IRQ_HANDLER KiTimerIrqHandler;
static NOTIFICATION KiTimerIrqNotification;
static NOTIFICATION KiExpiredTimerNotification;

static PCSTR KiWeekdayString[] = {
    "Sun",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat"
};

SYSTEM_TIME KiInitialSystemTime;
ABSOLUTE_COUNTER_TIME KiInitialCounterTime;

ULONG KiX86TscFreqInMHz;
ULONG64 KiCounterTimeMultiplier;
ULONG64 KiInterruptTimeMultiplier;

/* List of all timers */
static LIST_ENTRY KiTimerList;

static KMUTEX KiTimerDatabaseLock;
/* The following data structures (as well the timer objects in these lists) are
 * protected by the timer database lock */
static LIST_ENTRY KiQueuedTimerList;
static LIST_ENTRY KiExpiredTimerList;
/* END of timer database lock protected data structure */

static PSYSTEM_THREAD KiTimerServiceThread;
static IPC_ENDPOINT KiTimerServiceEndpoint;
/* The timer service notification is bound to the timer service thread's TCB */
static NOTIFICATION KiTimerServiceNotification;
static KMUTEX KiIoTimerDatabaseLock;
/* The following data structures (as well the IO timer objects in these lists) are
 * protected by the IO timer database lock */
static LIST_ENTRY KiQueuedIoTimerList;
static LIST_ENTRY KiExpiredIoTimerList;
/* END of IO timer database lock protected data structure */

/* Note that since the main service thread can be interrupted by the timer service
 * thread (for instance, when an ISR thread calls the timer service), this needs
 * to be accessed atomically. */
static ABSOLUTE_COUNTER_TIME KiGlobalTimerDueTime = { .CounterTime = ~0ULL };

static inline VOID KiAcquireTimerDatabaseLock()
{
    KeAcquireMutex(&KiTimerDatabaseLock);
}

static inline VOID KiReleaseTimerDatabaseLock()
{
    KeReleaseMutex(&KiTimerDatabaseLock);
}

static inline VOID KiAcquireIoTimerDatabaseLock()
{
    KeAcquireMutex(&KiIoTimerDatabaseLock);
}

static inline VOID KiReleaseIoTimerDatabaseLock()
{
    KeReleaseMutex(&KiIoTimerDatabaseLock);
}

static inline BOOLEAN KiTimerIsQueued(IN PTIMER Timer)
{
    return ListHasEntry(&KiQueuedTimerList, &Timer->QueueEntry);
}

static inline BOOLEAN KiTimerIsInExpiredList(IN PTIMER Timer)
{
    return ListHasEntry(&KiExpiredTimerList, &Timer->ExpiredListEntry);
}

VOID KePopulateConstantUserSharedTimeData(PKUSER_SHARED_DATA Data)
{
    Data->InitialSystemTime = KiInitialSystemTime.SystemTime;
    Data->InitialTsc = KiInitialCounterTime.CounterTime;
    Data->TscFrequencyInMHz = KiX86TscFreqInMHz;
}

VOID KiUpdateUserSharedTimeData(VOID)
{
    /* Update the time-related members of the KUSER_SHARED_DATA struct. The
     * KSYSTEM_TIME structs are updated in a way that the user space can
     * read the 64-bit time without interlocked operations: we first write
     * High2Time, then LowPart, then the High1Time. The user space can then
     * read the High1Time first, then LowPart, then High2Time. If the two
     * high times differ, the user space retries the read. */
    PKUSER_SHARED_DATA UserSharedData = PsGetUserSharedData();
    if (UserSharedData != NULL) {
	RELATIVE_COUNTER_TIME CounterTime = KiQueryRelativeCounterTime();
	INTERRUPT_TIME InterruptTime = KiRelativeCounterTimeToInterruptTime(CounterTime);
	ULONG64 SystemTime = KiInterruptTimeToSystemTime(InterruptTime).SystemTime;
	ULONG64 TickCount = KiRelativeCounterTimeToTickCount(CounterTime);
	UserSharedData->InterruptTime.High2Time = (LONG)(InterruptTime.InterruptTime >> 32);
	UserSharedData->InterruptTime.LowPart = (ULONG)InterruptTime.InterruptTime;
	UserSharedData->InterruptTime.High1Time = (LONG)(InterruptTime.InterruptTime >> 32);
	UserSharedData->SystemTime.High2Time = (LONG)(SystemTime >> 32);
	UserSharedData->SystemTime.LowPart = (ULONG)SystemTime;
	UserSharedData->SystemTime.High1Time = (LONG)(SystemTime >> 32);
	UserSharedData->TickCount.High2Time = (LONG)(TickCount >> 32);
	UserSharedData->TickCount.LowPart = (ULONG)TickCount;
	UserSharedData->TickCount.High1Time = (LONG)(TickCount >> 32);
    }
}

/*
 * If the specified time stamp counter value at due time is less than the
 * previously set due time value of the global timer, signal the timer
 * service to set the new, earlier due time. Otherwise, do nothing.
 */
static VOID KiSetGlobalTimer(IN ABSOLUTE_COUNTER_TIME EarliestDueTime)
{
    assert(EarliestDueTime.CounterTime);
    assert(EarliestDueTime.CounterTime != ~0ULL);
    ULONG64 DueTime = InterlockedCompareExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime,
						   0, 0);
    if (EarliestDueTime.CounterTime < DueTime) {
	InterlockedExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime,
			      EarliestDueTime.CounterTime);
	seL4_Signal(KiTimerServiceNotification.TreeNode.Cap);
    }
}

/*
 * Entry point for the timer interrupt service thread
 */
static VOID KiTimerInterruptService()
{
    while (TRUE) {
	KeWaitOnNotification(&KiTimerIrqNotification);
	int AckError = seL4_IRQHandler_Ack(KiTimerIrqHandler.TreeNode.Cap);
	if (AckError != 0) {
	    DbgTrace("Failed to ACK timer interrupt. Error:");
	    KeDbgDumpIPCError(AckError);
	}
	InterlockedExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime, ~0ULL);
	ABSOLUTE_COUNTER_TIME Time = KiQueryAbsoluteCounterTime();
	/* Traverse the queued timer list and wake up the expired timers. If
	 * a timer has a due time smaller than or equal to the current time
	 * counter value, then it has expired. */
	ABSOLUTE_COUNTER_TIME EarliestDueTime = { .CounterTime = ~0ULL };
	BOOLEAN TimerExpired = FALSE;
	KiAcquireTimerDatabaseLock();
	LoopOverList(Timer, &KiQueuedTimerList, TIMER, QueueEntry) {
	    if (Timer->DueTime.CounterTime <= Time.CounterTime) {
		RemoveEntryList(&Timer->QueueEntry);
		InsertTailList(&KiExpiredTimerList, &Timer->ExpiredListEntry);
	    } else if (Timer->DueTime.CounterTime < EarliestDueTime.CounterTime) {
		EarliestDueTime.CounterTime = Timer->DueTime.CounterTime;
	    }
	}
	TimerExpired = !IsListEmpty(&KiExpiredTimerList);
	KiReleaseTimerDatabaseLock();
	KiAcquireIoTimerDatabaseLock();
	LoopOverList(Timer, &KiQueuedIoTimerList, IO_TIMER, Link) {
	    if (Timer->DueTime.CounterTime <= Time.CounterTime) {
		RemoveEntryList(&Timer->Link);
		InsertHeadList(&KiExpiredIoTimerList, &Timer->Link);
		assert(Timer->Notification.TreeNode.Cap);
		seL4_Signal(Timer->Notification.TreeNode.Cap);
	    } else if (Timer->DueTime.CounterTime < EarliestDueTime.CounterTime) {
		EarliestDueTime.CounterTime = Timer->DueTime.CounterTime;
	    }
	}
	KiReleaseIoTimerDatabaseLock();
	if (TimerExpired) {
	    /* Notify the main event loop to check the expired timer list */
	    seL4_Signal(KiExpiredTimerNotification.TreeNode.Cap);
	}
	KiUpdateUserSharedTimeData();
	/* If the earliest due time of the queued timers are less than that we had set
	 * for the global timer, signal the timer service to set a new due time. */
	if (EarliestDueTime.CounterTime != ~0ULL) {
	    KiSetGlobalTimer(EarliestDueTime);
	}
    }
}

static NTSTATUS KiEnableTimerInterruptService()
{
    RET_ERR(HalEnableSystemTimer(&KiTimerIrqHandler));
    RET_ERR(KeCreateIrqHandlerCap(&KiTimerIrqHandler));
    RET_ERR_EX(KeCreateNotification(&KiTimerIrqNotification),
	       MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode));
    RET_ERR_EX(KeConnectIrqNotification(&KiTimerIrqHandler, &KiTimerIrqNotification),
	       {
		   MmCapTreeDeleteNode(&KiTimerIrqNotification.TreeNode);
		   MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode);
	       });
    RET_ERR_EX(PsCreateSystemThread(KiTimerIrqThread, "NTOS Timer ISR",
				    KiTimerInterruptService, FALSE),
	       {
		   MmCapTreeDeleteNode(&KiTimerIrqNotification.TreeNode);
		   MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode);
	       });
    return STATUS_SUCCESS;
}

static inline VOID KiSignalExpiredTimer(IN PTIMER Timer)
{
    KeSignalDispatcherObject(&Timer->Header);
    /* Note here ApcThread can become NULL while ApcRoutine is not NULL.
     * This can happen when a thread object is deleted before the timer
     * object is (the thread object deletion routine will set ApcThread
     * to NULL to remove the thread from the timer APC queue). */
    if (Timer->ApcThread && Timer->ApcRoutine) {
	LARGE_INTEGER DueTime = {
	    .QuadPart = KiAbsoluteCounterTimeToSystemTime(Timer->DueTime).SystemTime
	};
	KeQueueApcToThread(Timer->ApcThread, (PKAPC_ROUTINE) Timer->ApcRoutine,
			   Timer->ApcContext, (PVOID)((ULONG_PTR)DueTime.LowPart),
			   (PVOID)((ULONG_PTR)DueTime.HighPart));
    }
}

VOID KiSignalExpiredTimerList()
{
    KiAcquireTimerDatabaseLock();
    LoopOverList(Timer, &KiExpiredTimerList, TIMER, ExpiredListEntry) {
	/* TODO: For periodic timer, we should compute the new DueTime
	 * and reinsert it into the timer queue */
	RemoveEntryList(&Timer->ExpiredListEntry);
	Timer->State = FALSE;
	KiSignalExpiredTimer(Timer);
    }
    KiReleaseTimerDatabaseLock();
}

/*
 * Entry point for the IO timer service thread
 */
static VOID KiTimerService(VOID)
{
    MWORD Badge = 0;
    seL4_MessageInfo_t Request = seL4_Recv(KiTimerServiceEndpoint.TreeNode.Cap, &Badge);
    while (TRUE) {
	ULONG Label = seL4_MessageInfo_get_label(Request);
	ULONG ReqMsgLength = seL4_MessageInfo_get_length(Request);
	ULONG NumUnwrappedCaps = seL4_MessageInfo_get_capsUnwrapped(Request);
	ULONG NumExtraCaps = seL4_MessageInfo_get_extraCaps(Request);
	DbgTrace("Got message label 0x%x length %d unwrapped caps %d extra caps %d badge 0x%zx\n",
		 Label, ReqMsgLength, NumUnwrappedCaps, NumExtraCaps, Badge);
	NTSTATUS Status;
	if (Label || NumUnwrappedCaps || NumExtraCaps) {
	    DbgTrace("Invalid message. Replying with error.\n");
	    Status = STATUS_INVALID_MESSAGE;
	    goto reply;
	} else {
	    ABSOLUTE_COUNTER_TIME DueTime;
	    if (Badge) {
		if (ReqMsgLength != sizeof(ULONG64) / sizeof(MWORD)) {
		    DbgTrace("Invalid message length. Replying with error.\n");
		    Status = STATUS_INVALID_MESSAGE;
		    goto reply;
		}
		DueTime.CounterTime = seL4_GetMR(0);
#ifndef _WIN64
		DueTime.CounterTime |= ((ULONG64)seL4_GetMR(1)) << 32;
#endif
		assert((LONG64)DueTime.CounterTime > 0);
		PIO_DRIVER_OBJECT DriverObject = GLOBAL_HANDLE_TO_OBJECT(Badge);
		assert(DriverObject);
		KiAcquireIoTimerDatabaseLock();
		DriverObject->IoTimer.DueTime = DueTime;
		RemoveEntryList(&DriverObject->IoTimer.Link);
		InsertHeadList(&KiQueuedIoTimerList, &DriverObject->IoTimer.Link);
		KiReleaseIoTimerDatabaseLock();
		ULONG64 GlobalDueTime =
		    InterlockedCompareExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime, 0, 0);
		if (DueTime.CounterTime < GlobalDueTime) {
		    InterlockedExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime,
					  DueTime.CounterTime);
		} else {
		    Status = STATUS_SUCCESS;
		    goto reply;
		}
	    } else {
		assert(ReqMsgLength == 1);
		assert(seL4_GetMR(0) == Badge);
		DueTime.CounterTime =
		    InterlockedCompareExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime, 0, 0);
	    }
	    ABSOLUTE_COUNTER_TIME CurrentTime = KiQueryAbsoluteCounterTime();
	    RELATIVE_COUNTER_TIME Timeout;
	    if (DueTime.CounterTime < CurrentTime.CounterTime) {
		Timeout.CounterTime = 0;
	    } else {
		Timeout.CounterTime = DueTime.CounterTime - CurrentTime.CounterTime;
	    }
	    HalSetSystemTimer(KiRelativeCounterTimeToInterruptTime(Timeout).InterruptTime);
	    Status = STATUS_SUCCESS;
	reply:
	    seL4_SetMR(0, Status);
	    Request = seL4_ReplyRecv(KiTimerServiceEndpoint.TreeNode.Cap,
				     seL4_MessageInfo_new(0, 0, 0, 1), &Badge);
	}
    }
}

NTSTATUS KeEnableIoTimerService(IN PIPC_ENDPOINT Endpoint,
				IN PCNODE CNode,
				IN MWORD IpcBadge)
{
    return KeDeriveEndpoint(Endpoint, CNode, &KiTimerServiceEndpoint,
			    ENDPOINT_RIGHTS_SEND_GRANTREPLY, IpcBadge);
}

NTSTATUS KiInitTimer()
{
#if defined(_M_IX86) || defined(_M_AMD64)
    assert(KiX86TscFreqInMHz);
    KiCounterTimeMultiplier = (10ULL << TIME_MULTIPLIER_SHIFT) / KiX86TscFreqInMHz;
    KiInterruptTimeMultiplier = ((ULONG64)KiX86TscFreqInMHz << TIME_MULTIPLIER_SHIFT) / 10;
#elif defined(_M_ARM64)
    ULONG64 TscFreqInHz = 0;
    asm volatile ("mrs %0, cntfrq_el0"
		  : "=r"(TscFreqInHz) ::);
    if (!TscFreqInHz) {
	KeBugCheckMsg("Failed to read cntfrq_el0\n");
    }
    KiCounterTimeMultiplier = (10000000ULL << TIME_MULTIPLIER_SHIFT) / TscFreqInHz;
    KiInterruptTimeMultiplier = (TscFreqInHz << TIME_MULTIPLIER_SHIFT) / 10000000;
#else
#error "Unsupported architecture"
#endif

    extern CNODE MiNtosCNode;
    InitializeListHead(&KiTimerList);
    InitializeListHead(&KiQueuedTimerList);
    InitializeListHead(&KiExpiredTimerList);
    InitializeListHead(&KiQueuedIoTimerList);
    InitializeListHead(&KiExpiredIoTimerList);
    RET_ERR(KeCreateMutex(&KiTimerDatabaseLock));
    RET_ERR(KeCreateMutex(&KiIoTimerDatabaseLock));

    /* Create the timer service endpoint and start the timer service thread. */
    RET_ERR(KeCreateEndpoint(&KiTimerServiceEndpoint));
    KiTimerServiceThread = ExAllocatePoolWithTag(sizeof(SYSTEM_THREAD),
						 NTOS_KE_TAG);
    if (KiTimerServiceThread == NULL) {
	return STATUS_NO_MEMORY;
    }
    RET_ERR(PsCreateSystemThread(KiTimerServiceThread, "NTOS Timer Service",
				 KiTimerService, FALSE));
    RET_ERR(PsSetSystemThreadPriority(KiTimerServiceThread, IO_TIMER_SERVICE_LEVEL));

    /* Create the timer service notification and bind it to the timer service
     * thread's TCB cap. */
    RET_ERR(KeCreateNotification(&KiTimerServiceNotification));
    RET_ERR(KiBindNotificationToThread(KiTimerServiceThread->TreeNode.Cap,
				       KiTimerServiceNotification.TreeNode.Cap));

    /* Derive the expired timer notification from the executive service notification.
     * The expired timer notification badge has the first bit set. */
    RET_ERR(KeDeriveNotification(&KiExpiredTimerNotification, &MiNtosCNode,
				 &KiExecutiveServiceNotification,
				 1UL << 1));

    /* Create the timer IRQ thread and set its priority. */
    KiTimerIrqThread = ExAllocatePoolWithTag(sizeof(SYSTEM_THREAD),
					     NTOS_KE_TAG);
    if (KiTimerIrqThread == NULL) {
	return STATUS_NO_MEMORY;
    }
    RET_ERR(KiEnableTimerInterruptService());
    RET_ERR(PsSetSystemThreadPriority(KiTimerIrqThread, TIMER_INTERRUPT_LEVEL));

    /* Read the real time clock from HAL and use it as the system boot time. */
    KiInitialCounterTime = KiQueryAbsoluteCounterTime();
    TIME_FIELDS ClockTime;
    HalQueryRealTimeClock(&ClockTime);
    C_ASSERT(sizeof(SYSTEM_TIME) == sizeof(LARGE_INTEGER));
    BOOLEAN RtcTimeOk = RtlTimeFieldsToTime(&ClockTime, (PVOID)&KiInitialSystemTime);
    if (!RtcTimeOk || (ClockTime.Weekday < 0) || (ClockTime.Weekday > 6)) {
	HalVgaPrint("Corrupt RTC: %d-%02d-%02d %02d:%02d:%02d\n\n",
		   ClockTime.Year, ClockTime.Month, ClockTime.Day, ClockTime.Hour,
		   ClockTime.Minute, ClockTime.Second);
    } else {
	HalVgaPrint("%d-%02d-%02d %s %02d:%02d:%02d UTC.\n\n",
		   ClockTime.Year, ClockTime.Month, ClockTime.Day,
		   KiWeekdayString[ClockTime.Weekday], ClockTime.Hour,
		   ClockTime.Minute, ClockTime.Second);
    }
    return STATUS_SUCCESS;
}

SYSTEM_TIME KeQuerySystemTime(VOID)
{
    return KiAbsoluteCounterTimeToSystemTime(KiQueryAbsoluteCounterTime());
}

INTERRUPT_TIME KeQueryInterruptTime(VOID)
{
    return KiRelativeCounterTimeToInterruptTime(KiQueryRelativeCounterTime());
}

VOID KeInitializeTimer(IN PTIMER Timer,
		       IN TIMER_TYPE Type)
{
    KeInitializeDispatcherHeader(&Timer->Header, Type == NotificationTimer ?
				 NotificationEvent : SynchronizationEvent);
    InsertTailList(&KiTimerList, &Timer->ListEntry);
}

NTSTATUS KeCreateTimer(IN TIMER_TYPE TimerType,
		       OUT PTIMER *pTimer)
{
    PTIMER Timer = NULL;
    TIMER_OBJ_CREATE_CONTEXT CreaCtx = {
	.Type = TimerType
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_TIMER, (POBJECT *)&Timer, &CreaCtx));
    assert(Timer != NULL);
    *pTimer = Timer;
    return STATUS_SUCCESS;
}

BOOLEAN KeSetTimer(IN PTIMER Timer,
		   IN SYSTEM_TIME DueTime,
		   IN PTHREAD ApcThread,
		   IN PTIMER_APC_ROUTINE TimerApcRoutine,
		   IN PVOID TimerApcContext,
		   IN LONG Period)
{
    assert(Timer != NULL);
    if (ApcThread == NULL) {
	assert(TimerApcRoutine == NULL);
	assert(TimerApcContext == NULL);
    }
    if ((LONG64)DueTime.SystemTime <= 0) {
	/* If DueTime is negative, it is relative to the current system time */
	DueTime.SystemTime = -DueTime.SystemTime + KeQuerySystemTime().SystemTime;
    }

    ABSOLUTE_COUNTER_TIME CounterTime = KiSystemTimeToAbsoluteCounterTime(DueTime);
    KiAcquireTimerDatabaseLock();
    Timer->DueTime = CounterTime;
    if (Timer->ApcThread != NULL) {
	RemoveEntryList(&Timer->ThreadLink);
    }
    Timer->ApcThread = ApcThread;
    Timer->ApcRoutine = TimerApcRoutine;
    Timer->ApcContext = TimerApcContext;
    if (ApcThread != NULL) {
	InsertTailList(&ApcThread->TimerApcList, &Timer->ThreadLink);
    }
    Timer->Period = Period;
    /* If the timer is set, it must be in the queue or in the expired list.
     * In both cases we will remove the timer so we can reinsert it later
     * if needed. */
    BOOLEAN State = Timer->State;
    if (State) {
	assert(KiTimerIsQueued(Timer) || KiTimerIsInExpiredList(Timer));
	RemoveEntryList(&Timer->QueueEntry);
    } else {
	/* If the timer is not set, it cannot be in either the queue or
	 * the expired list. */
	assert(!KiTimerIsQueued(Timer) && !KiTimerIsInExpiredList(Timer));
    }
    /* If the due time is less than the current time, we will not insert
     * the timer (because it had already expired). We simply signal it. */
    if (!CounterTime.CounterTime) {
	Timer->State = FALSE;
	KiReleaseTimerDatabaseLock();
	KiSignalExpiredTimer(Timer);
	return State;
    }
    /* Compute the earlist due time in the queued timer. */
    ABSOLUTE_COUNTER_TIME EarliestDueTime = { .CounterTime = ~0ULL };
    LoopOverList(QueuedTimer, &KiQueuedTimerList, TIMER, QueueEntry) {
	if (QueuedTimer->DueTime.CounterTime < EarliestDueTime.CounterTime) {
	    EarliestDueTime.CounterTime = QueuedTimer->DueTime.CounterTime;
	}
    }
    /* Queue the timer and signal the timer service to program the system
     * timer to generate an IRQ when the earliest timer in the system expires. */
    InsertTailList(&KiQueuedTimerList, &Timer->QueueEntry);
    Timer->State = TRUE;
    KiReleaseTimerDatabaseLock();
    KiAcquireIoTimerDatabaseLock();
    LoopOverList(IoTimer, &KiQueuedIoTimerList, IO_TIMER, Link) {
	if (IoTimer->DueTime.CounterTime < EarliestDueTime.CounterTime) {
	    EarliestDueTime.CounterTime = IoTimer->DueTime.CounterTime;
	}
    }
    KiReleaseIoTimerDatabaseLock();
    if (CounterTime.CounterTime < EarliestDueTime.CounterTime) {
	KiSetGlobalTimer(CounterTime);
    }
    return FALSE;
}

BOOLEAN KeCancelTimer(IN PTIMER Timer)
{
    BOOLEAN State;
    KiAcquireTimerDatabaseLock();
    State = Timer->State;
    if (State) {
	assert(KiTimerIsQueued(Timer) || KiTimerIsInExpiredList(Timer));
	RemoveEntryList(&Timer->QueueEntry);
    } else {
	assert(!KiTimerIsQueued(Timer) && !KiTimerIsInExpiredList(Timer));
    }
    Timer->State = FALSE;
    KiReleaseTimerDatabaseLock();
    return State;
}

VOID KeUninitializeTimer(IN PTIMER Timer)
{
    assert(Timer != NULL);
    KeCancelTimer(Timer);
    /* Signal the dispatcher header one last time so any thread that
     * is blocked on this timer gets resumed. We don't deliver APC
     * though because the timer technically didn't expire. */
    KeSignalDispatcherObject(&Timer->Header);
    KeDetachDispatcherObject(&Timer->Header);
    if (Timer->ApcThread != NULL) {
	RemoveEntryList(&Timer->ThreadLink);
    }
    KeRemoveTimer(Timer);
}

VOID KeAddIoTimer(IN PIO_TIMER Timer)
{
    KiAcquireIoTimerDatabaseLock();
    Timer->DueTime.CounterTime = ~0ULL;
    InsertTailList(&KiExpiredIoTimerList, &Timer->Link);
    KiReleaseIoTimerDatabaseLock();
}

VOID KeRemoveIoTimer(IN PIO_TIMER Timer)
{
    KiAcquireIoTimerDatabaseLock();
    RemoveEntryList(&Timer->Link);
    KiReleaseIoTimerDatabaseLock();
}

NTSTATUS NtCreateTimer(IN ASYNC_STATE State,
                       IN PTHREAD Thread,
                       OUT HANDLE *Handle,
                       IN ACCESS_MASK DesiredAccess,
                       IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                       IN TIMER_TYPE TimerType)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Handle != NULL);

    PTIMER Timer = NULL;
    RET_ERR(KeCreateTimer(TimerType, &Timer));
    assert(Timer != NULL);

    RET_ERR_EX(ObCreateHandle(Thread->Process, Timer, FALSE, Handle, NULL),
	       KeUninitializeTimer(Timer));
    ObMakeTemporaryObject(Timer);
    assert(*Handle != NULL);

    return STATUS_SUCCESS;
}

NTSTATUS NtSetTimer(IN ASYNC_STATE State,
                    IN PTHREAD Thread,
                    IN HANDLE TimerHandle,
                    IN PLARGE_INTEGER DueTime,
                    IN PTIMER_APC_ROUTINE TimerApcRoutine,
                    IN PVOID TimerContext,
                    IN BOOLEAN ResumeTimer,
                    IN LONG Period,
                    OUT OPTIONAL BOOLEAN *pPreviousState)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    PTIMER Timer = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, TimerHandle, OBJECT_TYPE_TIMER, (POBJECT *)&Timer));
    assert(Timer != NULL);
    BOOLEAN PreviousState = KeSetTimer(Timer,
				       (SYSTEM_TIME) { .SystemTime = DueTime->QuadPart },
				       Thread, TimerApcRoutine, TimerContext, Period);
    if (pPreviousState != NULL) {
	*pPreviousState = PreviousState;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtDelayExecution(IN ASYNC_STATE AsyncState,
                          IN PTHREAD Thread,
                          IN BOOLEAN Alertable,
                          IN PLARGE_INTEGER Interval)
{
    UNIMPLEMENTED;
}
