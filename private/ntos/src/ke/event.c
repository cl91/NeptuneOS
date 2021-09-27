#include "ki.h"

NTSTATUS NtCreateEvent(IN PTHREAD Thread,
                       OUT HANDLE *EventHandle,
                       IN ACCESS_MASK DesiredAccess,
                       IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                       IN EVENT_TYPE EventType,
                       IN BOOLEAN InitialState)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtSetEvent(IN PTHREAD Thread,
                    IN HANDLE EventHandle,
                    OUT OPTIONAL LONG *PreviousState)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtTestAlert(IN PTHREAD Thread)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtContinue(IN PTHREAD Thread,
                    IN PCONTEXT Context,
                    IN BOOLEAN TestAlert)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtWaitForSingleObject(IN PTHREAD Thread,
                               IN HANDLE ObjectHandle,
                               IN BOOLEAN Alertable,
                               IN OPTIONAL PLARGE_INTEGER TimeOut)
{
    return STATUS_NOT_IMPLEMENTED;
}
