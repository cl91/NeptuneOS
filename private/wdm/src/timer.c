#include <wdmp.h>

/* List of timers that have been set but have not expired. */
LIST_ENTRY IopPendingTimerList;

ULONG KiStallScaleFactor;

static NTSTATUS KiInitializeTimer(OUT PKTIMER Timer,
				  IN EVENT_TYPE EventType)
{
    RtlZeroMemory(Timer, sizeof(KTIMER));
    IopInitializeDpcThread();
    NTSTATUS Status = WdmCreateTimer(&Timer->Header.Header.GlobalHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    ObInitializeObject(&Timer->Header, CLIENT_OBJECT_TIMER, KTIMER);
    Timer->Header.Type = EventType;
    InitializeListHead(&Timer->Header.EnvList);
    return STATUS_SUCCESS;
}

/*
 * Create a timer object.
 *
 * If the DPC thread has not been created, this routine can only be called at
 * PASSIVE_LEVEL. Otherwise, this routine can also be called at DISPATCH_LEVEL.
 */
NTAPI VOID KeInitializeTimer(OUT PKTIMER Timer)
{
    NTSTATUS Status = KiInitializeTimer(Timer, NotificationEvent);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
}

/*
 * This routine is called by the DPC thread to process the timer list.
 */
VOID IopProcessTimerList()
{
    /* Acquire the DPC mutex because IopPendingTimerList may be modified by KeSetTimer. */
    IopAcquireDpcMutex();
    LoopOverList(Timer, &IopPendingTimerList, KTIMER, Header.QueueListEntry) {
	/* If the timer is in the pending timer list, it must have been set. */
	assert(Timer->State);
	/* Check if the timer has expired. */
	LARGE_INTEGER SystemTime;
	KeQuerySystemTime(&SystemTime);
	if (SystemTime.QuadPart >= Timer->AbsoluteDueTime) {
	    Timer->State = FALSE;
	    RemoveEntryList(&Timer->Header.QueueListEntry);
	    KiSignalWaitableObject(&Timer->Header, FALSE);
	    if (Timer->Dpc && Timer->Dpc->DeferredRoutine) {
		/* DPC routines are called with the DPC mutex released (since it
		 * may call functions that try to acquire the DPC mutex). */
		IopReleaseDpcMutex();
		Timer->Dpc->DeferredRoutine(Timer->Dpc,
					    Timer->Dpc->DeferredContext,
					    Timer->Dpc->SystemArgument1,
					    Timer->Dpc->SystemArgument2);
		IopAcquireDpcMutex();
	    }
	}
    }
    IopReleaseDpcMutex();
}

/*
 * Call the server to set the timer. If the timer was set before, it will
 * be set to the new due time. If specified, returns the previous state of
 * the timer (ie. TRUE if timer was set before the call).
 *
 * This routine must be called at DISPATCH_LEVEL and below.
 */
NTAPI BOOLEAN KeSetTimerEx(IN OUT PKTIMER Timer,
			   IN LARGE_INTEGER DueTime,
			   IN LONG Period,
			   IN OPTIONAL PKDPC Dpc)
{
    /* Compute the absolute due time of the timer. */
    ULARGE_INTEGER AbsoluteDueTime = {
	.QuadPart = DueTime.QuadPart
    };
    if (DueTime.QuadPart < 0) {
	LARGE_INTEGER SystemTime;
	KeQuerySystemTime(&SystemTime);
	AbsoluteDueTime.QuadPart = -DueTime.QuadPart + SystemTime.QuadPart;
    }
    NTSTATUS Status = WdmSetTimer(Timer->Header.Header.GlobalHandle, &AbsoluteDueTime, Period);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Timer->Dpc = Dpc;
    Timer->AbsoluteDueTime = AbsoluteDueTime.QuadPart;
    Timer->Period = Period;
    IopAcquireDpcMutex();
    /* If the timer has expired (but hasn't been processed by the main event loop), we
     * need to remove it from the signaled object list. */
    if (Timer->Header.Signaled) {
	KiCancelWaitableObject(&Timer->Header, FALSE);
    }
    BOOLEAN PreviousState = Timer->State;
    if (!PreviousState) {
	Timer->State = TRUE;
	assert(!Timer->Header.Signaled);
	assert(!ListHasEntry(&IopSignaledObjectList, &Timer->Header.QueueListEntry));
	assert(!ListHasEntry(&IopPendingTimerList, &Timer->Header.QueueListEntry));
	InsertHeadList(&IopPendingTimerList, &Timer->Header.QueueListEntry);
    }
    IopReleaseDpcMutex();
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

NTAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
			 IN LARGE_INTEGER DueTime,
			 IN OPTIONAL PKDPC Dpc)
{
    return KeSetTimerEx(Timer, DueTime, 0, Dpc);
}

/*
 * @implemented
 */
NTAPI ULONGLONG KeQueryInterruptTime(VOID)
{
    LARGE_INTEGER CurrentTime;

    /* Loop until we get a perfect match */
    for (;;) {
        /* Read the time value */
        CurrentTime.HighPart = SharedUserData->InterruptTime.High1Time;
        CurrentTime.LowPart = SharedUserData->InterruptTime.LowPart;
        if (CurrentTime.HighPart == SharedUserData->InterruptTime.High2Time)
	    break;
        YieldProcessor();
    }

    /* Return the time value */
    return CurrentTime.QuadPart;
}

/*
 * @implemented
 */
NTAPI VOID KeQuerySystemTime(OUT PLARGE_INTEGER CurrentTime)
{
    /* Loop until we get a perfect match */
    for (;;) {
        /* Read the time value */
        CurrentTime->HighPart = SharedUserData->SystemTime.High1Time;
        CurrentTime->LowPart = SharedUserData->SystemTime.LowPart;
        if (CurrentTime->HighPart == SharedUserData->SystemTime.High2Time)
	    break;
        YieldProcessor();
    }
}

/*
 * @implemented
 */
NTAPI VOID KeQueryTickCount(OUT PLARGE_INTEGER CurrentCount)
{
    /* Loop until we get a perfect match */
    for (;;) {
        /* Read the time value */
        CurrentCount->HighPart = SharedUserData->TickCount.High1Time;
        CurrentCount->LowPart = SharedUserData->TickCount.LowPart;
        if (CurrentCount->HighPart == SharedUserData->TickCount.High2Time)
	    break;
        YieldProcessor();
    }
}

/*
 * Returns the the number of 100-nanosecond units that are added to the
 * system time each time the interval clock interrupts.
 */
NTAPI ULONG KeQueryTimeIncrement()
{
    return SharedUserData->TickTimeIncrement;
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
    ULONG64 StartTime = __rdtsc();

    /* Calculate the ending time */
    ULONG64 EndTime = StartTime + KiStallScaleFactor * MicroSeconds;

    /* Loop until time is elapsed */
    while (__rdtsc() < EndTime);
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
    KTIMER Timer;
    NTSTATUS Status = KiInitializeTimer(&Timer, SynchronizationEvent);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    KeSetTimer(&Timer, *Interval, NULL);
    return KeWaitForSingleObject(&Timer, 0, 0, Alertable, NULL);
}
