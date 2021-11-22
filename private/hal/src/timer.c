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
    NTSTATUS Status = IopCreateTimer(&Timer->Handle);
    if (!NT_SUCCESS(Status)) {
	assert(FALSE);
	Timer->Handle = NULL;
	Timer->Canceled = TRUE;
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
    BOOLEAN PreviousState = Timer->State;
    NTSTATUS Status = IopSetTimer(Timer->Handle, &DueTime);
    /* This can fail (due to server being out of memory). Assert in debug
     * build so we can find out why. */
    assert(NT_SUCCESS(Status));
    return PreviousState;
}
