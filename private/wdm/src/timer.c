#include <wdmp.h>

/* List of timers that have been set but have not expired. */
LIST_ENTRY IopPendingTimerList;

SYSTEM_TIME KiInitialSystemTime;
ABSOLUTE_COUNTER_TIME KiInitialCounterTime;

ULONG64 KiCounterTimeMultiplier;
ULONG64 KiInterruptTimeMultiplier;
MWORD KiTimerServiceCap;

/* Earlist due time of the queued timers. */
static ABSOLUTE_COUNTER_TIME KiGlobalTimerDueTime = { .CounterTime = ~0ULL };

static VOID KiInitializeTimer(OUT PKTIMER Timer,
			      IN EVENT_TYPE EventType)
{
    RtlZeroMemory(Timer, sizeof(KTIMER));
    IopInitializeDpcThread();
    ObInitializeObject(&Timer->Header, CLIENT_OBJECT_TIMER, KTIMER);
    Timer->Header.Type = EventType;
    InitializeListHead(&Timer->Header.EnvList);
    Timer->DueTime = ~0ULL;
}

/*
 * Create a timer object.
 *
 * If the DPC thread has not been created, this routine can only be called at
 * PASSIVE_LEVEL. Otherwise, this routine can also be called at DISPATCH_LEVEL.
 */
NTAPI VOID KeInitializeTimer(OUT PKTIMER Timer)
{
    KiInitializeTimer(Timer, NotificationEvent);
}

static VOID KiSetGlobalTimer(IN ABSOLUTE_COUNTER_TIME DueTime)
{
    assert((LONG64)DueTime.CounterTime > 0);
    if (DueTime.CounterTime <= KiQueryAbsoluteCounterTime().CounterTime) {
	NtCurrentTeb()->Wdm.DpcQueued = TRUE;
	IopSignalDpcNotification();
	return;
    }
    ULONG64 GlobalDueTime =
	InterlockedCompareExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime, 0, 0);
    if (DueTime.CounterTime < GlobalDueTime) {
	InterlockedExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime, DueTime.CounterTime);
	seL4_SetMR(0, (MWORD)DueTime.CounterTime);
#ifndef _WIN64
	seL4_SetMR(1, DueTime.CounterTime >> 32);
#endif
	assert(PsCapIsProcessShared(KiTimerServiceCap));
	seL4_Call(RtlProcessCNodeIndexToGuardedCap(KiTimerServiceCap),
		  seL4_MessageInfo_new(0, 0, 0, sizeof(ULONG64) / sizeof(MWORD)));
    }
}

/*
 * This routine is called by the DPC thread to process the timer list.
 */
VOID IopProcessTimerList()
{
    InterlockedExchange64((PVOID)&KiGlobalTimerDueTime.CounterTime, ~0ULL);
    ABSOLUTE_COUNTER_TIME CurrentTime = KiQueryAbsoluteCounterTime();
    ABSOLUTE_COUNTER_TIME NewDueTime = { .CounterTime = ~0ULL };
    /* Acquire the DPC mutex because IopPendingTimerList may be modified by KeSetTimer. */
    IopAcquireDpcMutex();
    LoopOverList(Timer, &IopPendingTimerList, KTIMER, Header.QueueListEntry) {
	/* If the timer is in the pending timer list, it must have been set. */
	assert(Timer->State);
	/* Check if the timer has expired. */
	if (CurrentTime.CounterTime >= Timer->DueTime) {
	    Timer->State = FALSE;
	    RemoveEntryList(&Timer->Header.QueueListEntry);
	    KiSignalWaitableObject(&Timer->Header, FALSE);
	    if (Timer->LowPriority && Timer->WorkItem && Timer->WorkerRoutine) {
		/* If the timer is a low priority timer, queue the IO work item. */
		IoQueueWorkItem(Timer->WorkItem, Timer->WorkerRoutine,
				DelayedWorkQueue, Timer->WorkerContext);
	    } else if (Timer->Dpc && Timer->Dpc->DeferredRoutine) {
		KiInsertQueueDpc(Timer->Dpc, Timer->Dpc->SystemArgument1,
				 Timer->Dpc->SystemArgument2, FALSE);
	    }
	} else if (Timer->DueTime < NewDueTime.CounterTime) {
	    NewDueTime.CounterTime = Timer->DueTime;
	}
    }
    IopReleaseDpcMutex();
    if (NewDueTime.CounterTime != ~0ULL) {
	KiSetGlobalTimer(NewDueTime);
    }
}

/*
 * Call the server to set the timer. If the timer was set before, it will
 * be set to the new due time. The previous state of the timer is returned
 * (ie. returns TRUE if timer was set before the call).
 *
 * This routine must be called at DISPATCH_LEVEL and below.
 */
static BOOLEAN KiSetTimer(IN OUT PKTIMER Timer,
			  IN LARGE_INTEGER DueTime,
			  IN LONG Period,
			  IN OPTIONAL PVOID DpcOrWorkItem,
			  IN OPTIONAL PIO_WORKITEM_ROUTINE WorkerRoutine,
			  IN OPTIONAL PVOID WorkerContext,
			  IN BOOLEAN LowPriorityTimer)
{
    BOOLEAN PreviousState = KeCancelTimer(Timer);
    BOOLEAN ExpireNow = FALSE;
    /* Compute the absolute due time of the timer. */
    LARGE_INTEGER SystemTime;
    KeQuerySystemTime(&SystemTime);
    if (DueTime.QuadPart < 0) {
	DueTime.QuadPart = -DueTime.QuadPart + SystemTime.QuadPart;
    } else {
	/* Timer is due immediately if due time is less than current system time. */
	ExpireNow = DueTime.QuadPart <= SystemTime.QuadPart;
    }
    ABSOLUTE_COUNTER_TIME CounterTime = ExpireNow ? KiQueryAbsoluteCounterTime() :
	KiSystemTimeToAbsoluteCounterTime((SYSTEM_TIME) { .SystemTime = DueTime.QuadPart });
    Timer->Dpc = DpcOrWorkItem;
    Timer->WorkerRoutine = WorkerRoutine;
    Timer->WorkerContext = WorkerContext;
    Timer->DueTime = CounterTime.CounterTime;
    Timer->Period = Period;
    Timer->LowPriority = LowPriorityTimer;
    IopAcquireDpcMutex();
    assert(!Timer->Header.Signaled);
    assert(!ListHasEntry(&IopSignaledObjectList, &Timer->Header.QueueListEntry));
    assert(!ListHasEntry(&IopPendingTimerList, &Timer->Header.QueueListEntry));
    Timer->State = TRUE;
    InsertHeadList(&IopPendingTimerList, &Timer->Header.QueueListEntry);
    /* Find the earlist due time of the currently pending timers (including
     * the one we just queued). */
    ABSOLUTE_COUNTER_TIME EarliestDueTime = { .CounterTime = ~0ULL };
    if (!ExpireNow) {
	LoopOverList(QueuedTimer, &IopPendingTimerList, KTIMER, Header.QueueListEntry) {
	    /* If the timer is in the pending timer list, it must have been set. */
	    assert(QueuedTimer->State);
	    if (QueuedTimer->DueTime < EarliestDueTime.CounterTime) {
		EarliestDueTime.CounterTime = QueuedTimer->DueTime;
	    }
	}
    }
    IopReleaseDpcMutex();
    if (ExpireNow) {
	NtCurrentTeb()->Wdm.DpcQueued = TRUE;
	IopSignalDpcNotification();
    } else {
	KiSetGlobalTimer(EarliestDueTime);
    }
    return PreviousState;
}

NTAPI BOOLEAN KeCancelTimer(IN OUT PKTIMER Timer)
{
    IopAcquireDpcMutex();
    /* If the timer has been signaled (but the main event loop has not processed
     * it), remove the timer from the waitable object list. */
    if (Timer->Header.Signaled) {
	KiCancelWaitableObject(&Timer->Header, FALSE);
    }
    /* Remove the timer from the pending timer list. We won't inform the server
     * of timer cancellation. When the timer expiry message comes in, we will
     * simply ignore the message. */
    BOOLEAN PreviousState = Timer->State;
    if (PreviousState) {
	assert(ListHasEntry(&IopPendingTimerList, &Timer->Header.QueueListEntry));
	RemoveEntryList(&Timer->Header.QueueListEntry);
	Timer->State = FALSE;
    }
    IopReleaseDpcMutex();
    return PreviousState;
}

NTAPI BOOLEAN KeSetTimerEx(IN OUT PKTIMER Timer,
			   IN LARGE_INTEGER DueTime,
			   IN LONG Period,
			   IN OPTIONAL PKDPC Dpc)
{
    return KiSetTimer(Timer, DueTime, Period, Dpc, NULL, NULL, FALSE);
}

NTAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
			 IN LARGE_INTEGER DueTime,
			 IN OPTIONAL PKDPC Dpc)
{
    return KeSetTimerEx(Timer, DueTime, 0, Dpc);
}

NTAPI BOOLEAN KeSetLowPriorityTimer(IN OUT PKTIMER Timer,
				    IN LARGE_INTEGER DueTime,
				    IN LONG Period,
				    IN PIO_WORKITEM WorkItem,
				    IN PIO_WORKITEM_ROUTINE WorkerRoutine,
				    IN OPTIONAL PVOID WorkerContext)
{
    return KiSetTimer(Timer, DueTime, Period,
		      WorkItem, WorkerRoutine, WorkerContext, TRUE);
}

/*
 * @implemented
 */
NTAPI ULONGLONG KeQueryInterruptTime(VOID)
{
    return KiRelativeCounterTimeToInterruptTime(KiQueryRelativeCounterTime()).InterruptTime;
}

/*
 * @implemented
 */
NTAPI VOID KeQuerySystemTime(OUT PLARGE_INTEGER CurrentTime)
{
    CurrentTime->QuadPart =
	KiAbsoluteCounterTimeToSystemTime(KiQueryAbsoluteCounterTime()).SystemTime;
}

/*
 * @implemented
 */
NTAPI VOID KeQueryTickCount(OUT PLARGE_INTEGER CurrentCount)
{
    RELATIVE_COUNTER_TIME Time = KiQueryRelativeCounterTime();
    CurrentCount->QuadPart = KiRelativeCounterTimeToTickCount(Time);
}

/*
 * Returns the the number of 100-nanosecond units that are added to the
 * system time each time the interval clock interrupts.
 */
NTAPI ULONG KeQueryTimeIncrement()
{
    return TIMER_RESOLUTION_IN_100NS;
}

/*
 * @name KeStallExecutionProcessor
 *
 * Stalls the execution of the current thread for the specified interval.
 * This routine should not be used for delays that are longer than 5us.
 *
 * @param MicroSeconds
 *        Specifies the amount of microseconds to stall.
 */
NTAPI VOID KeStallExecutionProcessor(ULONG MicroSeconds)
{
    /* Get the initial time */
    ULONG64 StartTime = KiQueryAbsoluteCounterTime().CounterTime;

    /* Calculate the ending time */
    ULONG64 EndTime = StartTime + SharedUserData->TscFrequencyInMHz * MicroSeconds;

    /* Loop until time is elapsed */
    while (KiQueryAbsoluteCounterTime().CounterTime < EndTime);
}

/**
 * @name KeDelayExecutionThread
 *
 * Puts the current coroutine into an alertable or nonalertable wait
 * state for a specified interval. This routine calls the server and
 * should be used for delays that are longer than 1us.
 *
 * @param Alertable
 *        Specify whether the wait is alertable.
 * @param Interval
 *        Specifies the absolute or relative time, in units of 100
 *        nanoseconds, for which the wait is to occur. A negative value
 *        indicates relative time.
 * @remarks
 *        This routine can only be called at PASSIVE_LEVEL, because it sleeps.
 */
NTSTATUS KeDelayExecutionThread(IN BOOLEAN Alertable,
				IN PLARGE_INTEGER Interval)
{
    PAGED_CODE();
    assert(Interval);
    assert(Interval->QuadPart);
    KTIMER Timer;
    KiInitializeTimer(&Timer, SynchronizationEvent);
    KeSetTimer(&Timer, *Interval, NULL);
    return KeWaitForSingleObject(&Timer, 0, 0, Alertable, NULL);
}
