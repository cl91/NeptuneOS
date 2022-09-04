#include <wdmp.h>

LIST_ENTRY IopEventList;

NTAPI VOID KeInitializeEvent(OUT PKEVENT Event,
			     IN EVENT_TYPE Type,
			     IN BOOLEAN InitialState)
{
    NTSTATUS Status = NtCreateEvent(&Event->Handle, EVENT_ALL_ACCESS,
				    NULL, Type, InitialState);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    InsertTailList(&IopEventList, &Event->EventListEntry);
    Event->State = InitialState;
}

/* Porting guide: remove the Increment and Wait arguments in Windows/ReactOS.
 * They are meaningless in Neptune OS due to architectural differences. */
NTAPI LONG KeSetEvent(IN PKEVENT Event)
{
    /* For a notification event, since it remains in the signaled state
     * unless it is cleared explicitly, we do not need to call the server
     * if the client side state indicates that it has been signaled. */
    if (Event->Type == NotificationEvent && Event->State) {
	return TRUE;
    }
    /* Otherwise, call the server to set the event. */
    LONG PreviousState;
    NTSTATUS Status = NtSetEvent(Event->Handle, &PreviousState);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    Event->State = TRUE;
    return PreviousState;
}

NTAPI LONG KeResetEvent(IN PKEVENT Event)
{
    /* If the event has already been cleared, simply return. */
    if (!Event->State) {
	return FALSE;
    }
    /* Otherwise, call the server to clear the event. */
    LONG PreviousState;
    NTSTATUS Status = NtResetEvent(Event->Handle, &PreviousState);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    Event->State = FALSE;
    return PreviousState;
}

NTAPI VOID KeClearEvent(IN PKEVENT Event)
{
    /* If the event has already been cleared, simply return. */
    if (!Event->State) {
	return;
    }
    /* Otherwise, call the server to clear the event. */
    NTSTATUS Status = NtClearEvent(Event->Handle);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
    Event->State = FALSE;
}
