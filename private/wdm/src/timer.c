#include <wdmp.h>

LIST_ENTRY IopTimerList;
ULONG KiStallScaleFactor;

/*
 * Call the server to create a timer object.
 */
NTAPI VOID KeInitializeTimer(OUT PKTIMER Timer)
{
    NTSTATUS Status = NtCreateTimer(&Timer->Handle, TIMER_ALL_ACCESS,
				    NULL, NotificationTimer);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    InsertTailList(&IopTimerList, &Timer->TimerListEntry);
    Timer->Dpc = NULL;
    Timer->State = FALSE;
    Timer->Canceled = FALSE;
}

/*
 * FIXME: TODO This needs to be moved into a coroutine since
 * the DPC routine may invoke the IoCallDriverEx routine.
 */
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
NTAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
			 IN LARGE_INTEGER DueTime,
			 IN OPTIONAL PKDPC Dpc)
{
    /* On debug build we should find out why the timer handle is NULL */
    assert(Timer->Handle != NULL);
    if (Timer->Handle == NULL) {
	RtlRaiseStatus(STATUS_INVALID_HANDLE);
    }
    Timer->Dpc = Dpc;
    BOOLEAN PreviousState;
    NTSTATUS Status = NtSetTimer(Timer->Handle, &DueTime, IopTimerExpired,
				 Timer, TRUE, 0, &PreviousState);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    Timer->State = TRUE;
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
NTAPI VOID KeStallExecutionProcessor(ULONG MicroSeconds)
{
    /* Get the initial time */
    ULONG64 StartTime = __rdtsc();

    /* Calculate the ending time */
    ULONG64 EndTime = StartTime + KiStallScaleFactor * MicroSeconds;

    /* Loop until time is elapsed */
    while (__rdtsc() < EndTime);
}
