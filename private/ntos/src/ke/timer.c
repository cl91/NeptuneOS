#include "ki.h"

static SYSTEM_THREAD KiTimerIrqThread;
static IRQ_HANDLER KiTimerIrqHandler;
static NOTIFICATION KiTimerIrqNotification;
static IPC_ENDPOINT KiTimerServiceNotification;

static PCSTR KiWeekdayString[] = {
    "Sun",
    "Mon",
    "Tue",
    "Wed",
    "Thu",
    "Fri",
    "Sat"
};

/* This is shared between the timer interrupt service and the main thread.
 * You must use interlocked operations to access this! */
static volatile ULONGLONG POINTER_ALIGNMENT KiTimerTickCount;

/* The absolute system time at the time of system initialization (more
 * specifically, when the KiInitTimer function is executing). This is
 * initialized from the system RTC (which we assume is in UTC). The system
 * time is measured in units of 100 nano-seconds since the midnight of
 * January 1, 1601. */
static LARGE_INTEGER KiInitialSystemTime;

/*
 * Convert the number of timer ticks to the interrput time which is the
 * time in units of 100 nano-seconds since system startup.
 */
static inline ULONGLONG KiTimerTickCountToInterruptTime(IN ULONGLONG TickCount)
{
    return TickCount * TIMER_RESOLUTION_IN_100NS;
}

/*
 * Convert the number of timer ticks to the system time which is the sum of the
 * interrupt time plus the system time at the beginning of the timer sub-component
 * initialization (KiInitTime). The system time is measured in units of 100 nano-seconds.
 */
static inline ULONGLONG KiTimerTickCountToSystemTime(IN ULONGLONG TickCount)
{
    return KiTimerTickCountToInterruptTime(TickCount) + KiInitialSystemTime.QuadPart;
}

/* List of all timers */
static LIST_ENTRY KiTimerList;

static KMUTEX KiTimerDatabaseLock;
/* The following data structures (as well the timer objects in these lists) are
 * protected by the timer database lock */
static LIST_ENTRY KiQueuedTimerList;
static LIST_ENTRY KiExpiredTimerList;
/* END of timer database lock protected data structure */

static inline VOID KiAcquireTimerDatabaseLock()
{
    KeAcquireMutex(&KiTimerDatabaseLock);
}

static inline VOID KiReleaseTimerDatabaseLock()
{
    KeReleaseMutex(&KiTimerDatabaseLock);
}

/*
 * Entry point for the timer interrupt service thread
 */
static VOID KiTimerInterruptService()
{
    while (TRUE) {
	int AckError = seL4_IRQHandler_Ack(KiTimerIrqHandler.TreeNode.Cap);
	if (AckError != 0) {
	    DbgTrace("Failed to ACK timer interrupt. Error:");
	    KeDbgDumpIPCError(AckError);
	}
	KeWaitOnNotification(&KiTimerIrqNotification);
	ULONGLONG TimerTicks = InterlockedIncrement64((PLONG64)&KiTimerTickCount);
	/* Update the time-related members of the KUSER_SHARED_DATA struct. The
	 * KSYSTEM_TIME structs are updated in a way that the user space can
	 * read the 64-bit time without interlocked operations: we first write
	 * High2Time, then LowPart, then the High1Time. The user space can then
	 * read the High1Time first, then LowPart, then High2Time. If the two
	 * high times differ, the user space retries the read. */
	PKUSER_SHARED_DATA UserSharedData = PsGetUserSharedData();
	if (UserSharedData != NULL) {
	    ULONGLONG InterruptTime = KiTimerTickCountToInterruptTime(TimerTicks);
	    UserSharedData->InterruptTime.High2Time = (LONG)(InterruptTime >> 32);
	    UserSharedData->InterruptTime.LowPart = (ULONG)InterruptTime;
	    UserSharedData->InterruptTime.High1Time = (LONG)(InterruptTime >> 32);
	    ULONGLONG SystemTime = KiTimerTickCountToSystemTime(TimerTicks);
	    UserSharedData->SystemTime.High2Time = (LONG)(SystemTime >> 32);
	    UserSharedData->SystemTime.LowPart = (ULONG)SystemTime;
	    UserSharedData->SystemTime.High1Time = (LONG)(SystemTime >> 32);
	}
	/* If a timer has a due time smaller than MaxDueTime, then it has expired */
	ULONGLONG MaxDueTime = KiTimerTickCountToSystemTime(TimerTicks + 1);
	/* Traverse the queued timer list and see if any of them expired */
	KiAcquireTimerDatabaseLock();
	LoopOverList(Timer, &KiQueuedTimerList, TIMER, QueueEntry) {
	    if (Timer->DueTime.QuadPart < MaxDueTime) {
		/* TODO: For periodic timer, we should compute the new DueTime
		 * and reinsert it in KiSignalExpiredTimer */
		RemoveEntryList(&Timer->QueueEntry);
		InsertTailList(&KiExpiredTimerList, &Timer->ExpiredListEntry);
	    }
	}
	KiReleaseTimerDatabaseLock();
	if (!IsListEmpty(&KiExpiredTimerList)) {
	    /* Notify the main event loop to check the expired timer list */
	    seL4_NBSend(KiTimerServiceNotification.TreeNode.Cap,
			seL4_MessageInfo_new(0, 0, 0, 0));
	}
    }
}

static NTSTATUS KiEnableTimerInterruptService()
{
    RET_ERR(KeCreateIrqHandler(&KiTimerIrqHandler, TIMER_IRQ_LINE));
    RET_ERR_EX(KeCreateNotification(&KiTimerIrqNotification),
	       MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode));
    RET_ERR_EX(KeConnectIrqNotification(&KiTimerIrqHandler, &KiTimerIrqNotification),
	       {
		   MmCapTreeDeleteNode(&KiTimerIrqNotification.TreeNode);
		   MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode);
	       });
    RET_ERR_EX(PsCreateSystemThread(&KiTimerIrqThread, "NTOS Timer ISR",
				    KiTimerInterruptService, FALSE),
	       {
		   MmCapTreeDeleteNode(&KiTimerIrqNotification.TreeNode);
		   MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode);
	       });
    return STATUS_SUCCESS;
}

static inline VOID KiSignalExpiredTimer(IN PTIMER Timer)
{
    KiSignalDispatcherObject(&Timer->Header);
    if (Timer->ApcRoutine != NULL) {
	KeQueueApcToThread(Timer->ApcThread, (PKAPC_ROUTINE) Timer->ApcRoutine,
			   Timer->ApcContext, (PVOID)((ULONG_PTR)Timer->DueTime.LowPart),
			   (PVOID)((ULONG_PTR)Timer->DueTime.HighPart));
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

NTSTATUS KiInitTimer()
{
    extern CNODE MiNtosCNode;
    InitializeListHead(&KiTimerList);
    InitializeListHead(&KiQueuedTimerList);
    InitializeListHead(&KiExpiredTimerList);
    KeCreateMutex(&KiTimerDatabaseLock);
    KeInitializeIpcEndpoint(&KiTimerServiceNotification, &MiNtosCNode, 0,
			    SERVICE_TYPE_NOTIFICATION);
    RET_ERR(MmCapTreeDeriveBadgedNode(&KiTimerServiceNotification.TreeNode,
				      &KiExecutiveServiceEndpoint.TreeNode,
				      ENDPOINT_RIGHTS_WRITE_GRANTREPLY,
				      SERVICE_TYPE_NOTIFICATION));

    TIME_FIELDS ClockTime;
    HalQueryRealTimeClock(&ClockTime);
    BOOLEAN RtcTimeOk = RtlTimeFieldsToTime(&ClockTime, &KiInitialSystemTime);
    RET_ERR(KiEnableTimerInterruptService());
    RET_ERR(PsSetSystemThreadPriority(&KiTimerIrqThread, TIMER_INTERRUPT_LEVEL));
    if (!RtcTimeOk || (ClockTime.Weekday < 0) || (ClockTime.Weekday > 6)) {
	HalVgaPrint("Corrupt CMOS clock: %d-%02d-%02d %02d:%02d:%02d\n\n",
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

ULONGLONG KeQuerySystemTime(VOID)
{
    ULONGLONG TimerTicks = InterlockedCompareExchange64((PLONG64)&KiTimerTickCount, 0, 0);
    return KiTimerTickCountToSystemTime(TimerTicks);
}

ULONGLONG KeQueryInterruptTime()
{
    ULONGLONG TimerTicks = InterlockedCompareExchange64((PLONG64)&KiTimerTickCount, 0, 0);
    return KiTimerTickCountToInterruptTime(TimerTicks);
}

VOID KeInitializeTimer(IN PTIMER Timer,
		       IN TIMER_TYPE Type)
{
    KiInitializeDispatcherHeader(&Timer->Header, Type == NotificationTimer ?
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
    RET_ERR(ObCreateObject(OBJECT_TYPE_TIMER, (POBJECT *) &Timer,
			   NULL, NULL, 0, &CreaCtx));
    assert(Timer != NULL);
    *pTimer = Timer;
    return STATUS_SUCCESS;
}

BOOLEAN KeSetTimer(IN PTIMER Timer,
		   IN LARGE_INTEGER DueTime,
		   IN PTHREAD ApcThread,
		   IN PTIMER_APC_ROUTINE TimerApcRoutine,
		   IN PVOID TimerApcContext,
		   IN LONG Period)
{
    assert(Timer != NULL);
    ULONGLONG AbsoluteDueTime = DueTime.QuadPart;
    /* If DueTime is negative, it is relative to the current system time */
    if (DueTime.QuadPart < 0) {
	AbsoluteDueTime = -DueTime.QuadPart + KeQuerySystemTime();
    }
    KiAcquireTimerDatabaseLock();
    Timer->DueTime.QuadPart = AbsoluteDueTime;
    if (Timer->ApcThread != NULL) {
	RemoveEntryList(&Timer->ThreadLink);
    }
    Timer->ApcThread = ApcThread;
    Timer->ApcRoutine = TimerApcRoutine;
    Timer->ApcContext = TimerApcContext;
    InsertTailList(&ApcThread->TimerApcList, &Timer->ThreadLink);
    Timer->Period = Period;
    /* If the timer is already set, compute the new due time and return TRUE */
    if (Timer->State) {
	KiReleaseTimerDatabaseLock();
	return TRUE;
    }
    /* If the timer is not set, queue it and return FALSE. Note that if the timer
     * state is not set it is guaranteed to be in neither the timer queue or the
     * expired timer list. */
    InsertTailList(&KiQueuedTimerList, &Timer->QueueEntry);
    KiReleaseTimerDatabaseLock();
    return FALSE;
}

BOOLEAN KeCancelTimer(IN PTIMER Timer)
{
    BOOLEAN State;
    KiAcquireTimerDatabaseLock();
    State = Timer->State;
    if (State) {
	RemoveEntryList(&Timer->QueueEntry);
    }
    Timer->State = FALSE;
    KiReleaseTimerDatabaseLock();
    return State;
}

VOID KeDestroyTimer(IN PTIMER Timer)
{
    assert(Timer != NULL);
    KeCancelTimer(Timer);
    /* Signal the dispatcher header one last time so any thread that
     * is blocked on this timer gets resumed. We don't deliver APC
     * though because the timer technically didn't expire. */
    KiSignalDispatcherObject(&Timer->Header);
    KiDetachDispatcherObject(&Timer->Header);
    if (Timer->ApcThread != NULL) {
	RemoveEntryList(&Timer->ThreadLink);
    }
    KeRemoveTimer(Timer);
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

    RET_ERR(ObCreateHandle(Thread->Process, Timer, Handle));
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
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, TimerHandle, OBJECT_TYPE_TIMER, (POBJECT *)&Timer));
    assert(Timer != NULL);
    BOOLEAN PreviousState = KeSetTimer(Timer, *DueTime, Thread, TimerApcRoutine, TimerContext, Period);
    if (pPreviousState != NULL) {
	*pPreviousState = PreviousState;
    }
    return STATUS_SUCCESS;
}

/**
 * @name KeDelayExecutionThread
 *
 * Puts the current thread into an alertable or nonalertable wait
 * state for a specified interval. This routine is only exposed to
 * the driver processes.
 *
 * @param Alertable
 *        Specify whether the wait is alertable.
 * @param Interval
 *        Specifies the absolute or relative time, in units of 100
 *        nanoseconds, for which the wait is to occur. A negative value
 *        indicates relative time.
 */
NTSTATUS KeDelayExecutionThread(IN ASYNC_STATE State,
				IN PTHREAD Thread,
				IN BOOLEAN Alertable,
				IN PLARGE_INTEGER Interval)
{
    return STATUS_NOT_IMPLEMENTED;
}
