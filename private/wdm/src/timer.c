#include <wdmp.h>

LIST_ENTRY IopTimerList;

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
    if (Timer->Dpc != NULL) {
	assert(Timer->Dpc->DeferredRoutine != NULL);
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
    Timer->State = TRUE;
    return PreviousState;
}
