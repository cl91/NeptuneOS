#include "ei.h"

NTSTATUS NtCreateSemaphore(IN ASYNC_STATE State,
			   IN PTHREAD Thread,
			   OUT HANDLE *SemaphoreHandle,
			   IN ACCESS_MASK DesiredAccess,
			   IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
			   IN LONG InitialCount,
			   IN LONG MaximumCount)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenSemaphore(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
			 OUT HANDLE *SemaphoreHandle,
			 IN ACCESS_MASK DesiredAccess,
			 IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
}

NTSTATUS NtReleaseSemaphore(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
			    IN HANDLE SemaphoreHandle,
			    IN LONG ReleaseCount,
			    OUT OPTIONAL PLONG PreviousCount)
{
    UNIMPLEMENTED;
}
