#include "psp.h"

NTSTATUS NtCreateProcessEx(OUT HANDLE *ProcessHandle,
			   IN ACCESS_MASK DesiredAccess,
			   OPTIONAL IN POBJECT_ATTRIBUTES ObjectAttributes,
			   OPTIONAL IN HANDLE ParentProcess,
			   IN ULONG Flags,
			   OPTIONAL IN HANDLE SectionHandle,
			   OPTIONAL IN HANDLE DebugPort,
			   OPTIONAL IN HANDLE ExceptionPort,
			   IN ULONG JobMemberLevel)
{
    return STATUS_SUCCESS;
}
