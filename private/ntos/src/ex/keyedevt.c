#include "ei.h"

NTSTATUS NtCreateKeyedEvent(IN ASYNC_STATE AsyncState,
			    IN PTHREAD Thread,
			    OUT HANDLE *KeyedEventHandle,
			    IN ACCESS_MASK DesiredAccess,
			    IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
			    IN ULONG Flags)
{
    UNIMPLEMENTED;
}

NTSTATUS NtWaitForKeyedEvent(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     IN OPTIONAL HANDLE KeyedEventHandle,
			     IN PVOID Key,
			     IN BOOLEAN Alertable,
			     IN OPTIONAL PLARGE_INTEGER Timeout)
{
    UNIMPLEMENTED;
}

NTSTATUS NtReleaseKeyedEvent(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     IN OPTIONAL HANDLE KeyedEventHandle,
			     IN PVOID Key,
			     IN BOOLEAN Alertable,
			     IN OPTIONAL PLARGE_INTEGER Timeout)
{
    UNIMPLEMENTED;
}
