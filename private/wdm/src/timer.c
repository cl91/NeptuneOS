#include <wdmp.h>

LIST_ENTRY IopTimerList;
ULONG KiStallScaleFactor;

static NTSTATUS KiInitializeTimer(OUT PKTIMER Timer)
{
    NTSTATUS Status = NtCreateTimer(&Timer->Header.Handle, TIMER_ALL_ACCESS,
				    NULL, NotificationTimer);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    ObInitializeObject(Timer, CLIENT_OBJECT_TIMER, KTIMER);
    InsertTailList(&IopTimerList, &Timer->TimerListEntry);
    Timer->Dpc = NULL;
    Timer->State = FALSE;
    Timer->Canceled = FALSE;
    return STATUS_SUCCESS;
}

/*
 * Call the server to create a timer object.
 */
NTAPI VOID KeInitializeTimer(OUT PKTIMER Timer)
{
    NTSTATUS Status = KiInitializeTimer(Timer);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
}

static NTAPI VOID IopTimerExpired(IN PVOID Context,
				  IN ULONG TimerLowValue,
				  IN LONG TimerHighValue)
{
    PKTIMER Timer = (PKTIMER)Context;
    DbgTrace("Timer expired %p\n", Timer);
    assert(Timer != NULL);
    /* If the timer has already been canceled, do nothing. */
    if (Timer->Canceled) {
	return;
    }
    Timer->State = FALSE;
    if (Timer->Dpc != NULL && Timer->Dpc->DeferredRoutine != NULL) {
	Timer->Dpc->DeferredRoutine(Timer->Dpc,
				    Timer->Dpc->DeferredContext,
				    Timer->Dpc->SystemArgument1,
				    Timer->Dpc->SystemArgument2);
    }
}

/*
 * Call the server to set the timer. If the timer was set before,
 * it will be implicitly canceled. If specified, returns the previous
 * state of the timer (ie. TRUE if timer was set before the call).
 */
NTSTATUS KiSetTimer(IN OUT PKTIMER Timer,
		    IN LARGE_INTEGER DueTime,
		    IN OPTIONAL PKDPC Dpc,
		    OUT PBOOLEAN PreviousState)
{
    assert(Timer);
    assert(Timer->Header.Handle != NULL);
    assert(PreviousState);
    if (Timer->Header.Handle == NULL) {
	RtlRaiseStatus(STATUS_INVALID_HANDLE);
    }
    Timer->Dpc = Dpc;
    NTSTATUS Status = NtSetTimer(Timer->Header.Handle, &DueTime, IopTimerExpired,
				 Timer, TRUE, 0, PreviousState);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Timer->State = TRUE;
    return STATUS_SUCCESS;
}

NTAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
			 IN LARGE_INTEGER DueTime,
			 IN OPTIONAL PKDPC Dpc)
{
    BOOLEAN PreviousState;
    NTSTATUS Status = KiSetTimer(Timer, DueTime, Dpc, &PreviousState);
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
 */
NTSTATUS KeDelayExecutionThread(IN BOOLEAN Alertable,
				IN PLARGE_INTEGER Interval)
{
    assert(Interval);
    KTIMER Timer;
    NTSTATUS Status = KiInitializeTimer(&Timer);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    BOOLEAN PreviousState;
    Status = KiSetTimer(&Timer, *Interval, NULL, &PreviousState);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    return KeWaitForSingleObject(&Timer, 0, 0, Alertable, NULL);
}
