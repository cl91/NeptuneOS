#include <hal.h>

LIST_ENTRY IopTimerList;

/*
 * Call the server to create a timer object.
 *
 * Note: If the creation failed (which is unlikely, usually because
 * the server is out of memory), we set the Handle to NULL so all
 * future invocations will fail.
 */
NTAPI VOID KeInitializeTimer(OUT PKTIMER Timer)
{
    InsertTailList(&IopTimerList, &Timer->TimerListEntry);
    Timer->Dpc = NULL;
    Timer->Canceled = FALSE;
    Timer->State = FALSE;
    NTSTATUS Status = NtCreateTimer(&Timer->Handle, TIMER_ALL_ACCESS,
				    NULL, NotificationTimer);
    if (!NT_SUCCESS(Status)) {
	assert(FALSE);
	Timer->Handle = NULL;
	Timer->Canceled = TRUE;
    }
}

static NTAPI VOID KiTimerExpired(IN PVOID TimerContext,
				 IN ULONG TimerLowValue,
				 IN LONG TimerHighValue)
{
    PKDPC Dpc = TimerContext;
    DbgTrace("Timer expired %p\n", Dpc);
    if (Dpc != NULL) {
	Dpc->DeferredRoutine(Dpc, Dpc->DeferredContext, Dpc->SystemArgument1,
			     Dpc->SystemArgument2);
    }
}

/*
 * Call the server to set the timer. If the timer was set before,
 * it will be implicitly canceled. Returns the previous state of
 * the timer (TRUE if timer was set before the call).
 */
NTAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
			 IN LARGE_INTEGER DueTime,
			 IN OPTIONAL PKDPC Dpc)
{
    /* On debug build we should find out why the timer creation
     * failed. On release build we simply return FALSE. */
    assert(Timer->Handle != NULL);
    if (Timer->Canceled || (Timer->Handle == NULL)) {
	return FALSE;
    }
    BOOLEAN PreviousState;
    NTSTATUS Status = NtSetTimer(Timer->Handle, &DueTime, KiTimerExpired,
				 Dpc, TRUE, 0, &PreviousState);
    /* This can fail (due to server running out of memory). Assert in debug
     * build so we can find out why. */
    assert(PreviousState == Timer->State);
    assert(NT_SUCCESS(Status));
    Timer->State = TRUE;
    return PreviousState;
}
