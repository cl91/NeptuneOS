#include <wdmp.h>

LIST_ENTRY IopTimerList;
ULONG KiStallScaleFactor;

static NTSTATUS KiInitializeTimer(OUT PKTIMER Timer)
{
    IopInitializeDpcThread();
    NTSTATUS Status = WdmCreateTimer(&Timer->Header.GlobalHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    ObInitializeObject(Timer, CLIENT_OBJECT_TIMER, KTIMER);
    Timer->State = FALSE;
    Timer->Canceled = FALSE;
    /* IopTimerList is modified by IopProcessTimerList which runs in the DPC
     * thread, so we need to acquire the DPC mutex. */
    IoAcquireDpcMutex();
    InsertTailList(&IopTimerList, &Timer->TimerListEntry);
    IoReleaseDpcMutex();
    return STATUS_SUCCESS;
}

/*
 * Call the server to create a timer object.
 *
 * If the DPC thread has not been created, this routine can only be called at
 * PASSIVE_LEVEL. Otherwise, this routine can also be called at DISPATCH_LEVEL.
 */
NTAPI VOID KeInitializeTimer(OUT PKTIMER Timer)
{
    NTSTATUS Status = KiInitializeTimer(Timer);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
}

/*
 * This routine is called by the DPC thread to process the timer list.
 */
VOID IopProcessTimerList()
{
    /* Acquire the DPC mutex because IopTimerList may be modified by KiInitializeTimer. */
    IoAcquireDpcMutex();
    LoopOverList(Timer, &IopTimerList, KTIMER, TimerListEntry) {
	/* If the timer has not been set, or has already been canceled, do nothing. */
	if (!Timer->State || Timer->Canceled) {
	    return;
	}
	/* Check if the timer has expired. */
	ULONGLONG SystemTime = KeQuerySystemTime();
	if (SystemTime >= Timer->AbsoluteDueTime) {
	    Timer->State = FALSE;
	    if (Timer->Dpc && Timer->Dpc->DeferredRoutine) {
		/* DPC routines are called with the DPC mutex released (since it
		 * may call functions that try to acquire the DPC mutex). */
		IoReleaseDpcMutex();
		Timer->Dpc->DeferredRoutine(Timer->Dpc,
					    Timer->Dpc->DeferredContext,
					    Timer->Dpc->SystemArgument1,
					    Timer->Dpc->SystemArgument2);
		IoAcquireDpcMutex();
	    }
	}
    }
    IoReleaseDpcMutex();
}

/*
 * Call the server to set the timer. If the timer was set before,
 * it will be implicitly canceled. If specified, returns the previous
 * state of the timer (ie. TRUE if timer was set before the call).
 */
NTSTATUS KiSetTimer(IN OUT PKTIMER Timer,
		    IN LARGE_INTEGER DueTime,
		    IN OPTIONAL PKDPC Dpc)
{
    assert(Timer);
    assert(Timer->Header.GlobalHandle);
    if (!Timer->Header.GlobalHandle) {
	RtlRaiseStatus(STATUS_INVALID_HANDLE);
    }
    /* Compute the absolute due time of the timer. */
    ULARGE_INTEGER AbsoluteDueTime = {
	.QuadPart = DueTime.QuadPart
    };
    if (DueTime.QuadPart < 0) {
	AbsoluteDueTime.QuadPart = -DueTime.QuadPart + KeQuerySystemTime();
    }
    NTSTATUS Status = WdmSetTimer(Timer->Header.GlobalHandle, &AbsoluteDueTime);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    /* We don't need to acquire the DPC mutex here, since we update the timer state last. */
    Timer->Dpc = Dpc;
    Timer->AbsoluteDueTime = AbsoluteDueTime.QuadPart;
    Timer->State = TRUE;
    return STATUS_SUCCESS;
}

/*
 * This routine must be called at DISPATCH_LEVEL and below.
 */
NTAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
			 IN LARGE_INTEGER DueTime,
			 IN OPTIONAL PKDPC Dpc)
{
    BOOLEAN PreviousState = Timer->State;
    NTSTATUS Status = KiSetTimer(Timer, DueTime, Dpc);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    return PreviousState;
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
NTAPI ULONGLONG KeQuerySystemTime(VOID)
{
    LARGE_INTEGER CurrentTime;

    /* Loop until we get a perfect match */
    for (;;) {
        /* Read the time value */
        CurrentTime.HighPart = SharedUserData->SystemTime.High1Time;
        CurrentTime.LowPart = SharedUserData->SystemTime.LowPart;
        if (CurrentTime.HighPart == SharedUserData->SystemTime.High2Time)
	    break;
        YieldProcessor();
    }

    /* Return the time value */
    return CurrentTime.QuadPart;
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
 * Puts the current thread into an alertable or nonalertable wait
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
    NTSTATUS Status = KiInitializeTimer(&Timer);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Status = KiSetTimer(&Timer, *Interval, NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    return KeWaitForSingleObject(&Timer, 0, 0, Alertable, NULL);
}
