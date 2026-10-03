#include "psp.h"

NTSTATUS NtCreateJobObject(IN ASYNC_STATE State,
			   IN PTHREAD Thread,
			   OUT HANDLE *JobHandle,
			   IN ACCESS_MASK DesiredAccess,
			   IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
}

NTSTATUS NtCreateJobSet(IN ASYNC_STATE State,
			IN PTHREAD Thread,
			IN ULONG NumJob,
			IN PJOB_SET_ARRAY UserJobSet,
			IN ULONG Flags)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenJobObject(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
			 OUT HANDLE *JobHandle,
			 IN ACCESS_MASK DesiredAccess,
			 IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
}

NTSTATUS NtIsProcessInJob(IN ASYNC_STATE State,
			  IN PTHREAD Thread,
			  IN HANDLE ProcessHandle,
			  IN HANDLE JobHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtAssignProcessToJobObject(IN ASYNC_STATE State,
				    IN PTHREAD Thread,
				    IN HANDLE JobHandle,
				    IN HANDLE ProcessHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtTerminateJobObject(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
			      IN HANDLE JobHandle,
			      IN NTSTATUS ExitStatus)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryInformationJobObject(IN ASYNC_STATE State,
				     IN PTHREAD Thread,
				     IN HANDLE JobHandle,
				     IN JOB_OBJECT_INFORMATION_CLASS JobInformationClass,
				     OUT PVOID JobInformation,
				     IN ULONG JobInformationLength,
				     OUT OPTIONAL PULONG ReturnLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetInformationJobObject(IN ASYNC_STATE State,
				   IN PTHREAD Thread,
				   IN HANDLE JobHandle,
				   IN JOB_OBJECT_INFORMATION_CLASS JobInformationClass,
				   IN PVOID JobInformation,
				   IN ULONG JobInformationLength)
{
    UNIMPLEMENTED;
}
