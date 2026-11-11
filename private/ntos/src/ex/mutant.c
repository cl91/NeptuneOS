#include "ei.h"

NTSTATUS NtCreateMutant(IN ASYNC_STATE State,
			OUT HANDLE *MutantHandle,
			IN ACCESS_MASK DesiredAccess,
			IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
			IN BOOLEAN InitialOwner)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenMutant(IN ASYNC_STATE State,
		      OUT HANDLE *MutantHandle,
		      IN ACCESS_MASK DesiredAccess,
		      IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
}

NTSTATUS NtReleaseMutant(IN ASYNC_STATE State,
			 IN HANDLE MutantHandle,
			 IN OPTIONAL PLONG ReleaseCount)
{
    UNIMPLEMENTED;
}
