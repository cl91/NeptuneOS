#include "ki.h"

VOID KeSetEvent(IN PKEVENT Event)
{
    KiSignalDispatcherObject(&Event->Header);
}

NTSTATUS NtCreateEvent(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
                       OUT HANDLE *EventHandle,
                       IN ACCESS_MASK DesiredAccess,
                       IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                       IN EVENT_TYPE EventType,
                       IN BOOLEAN InitialState)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetEvent(IN ASYNC_STATE State,
		    IN PTHREAD Thread,
                    IN HANDLE EventHandle,
                    OUT OPTIONAL LONG *PreviousState)
{
    return STATUS_NOT_IMPLEMENTED;
}
