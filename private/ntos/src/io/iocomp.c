#include "iop.h"

NTSTATUS NtCreateIoCompletion(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      OUT HANDLE *IoCompletionHandle,
			      IN ACCESS_MASK DesiredAccess,
			      IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
			      IN ULONG NumberOfConcurrentThreads)
{
    UNIMPLEMENTED;
}

NTSTATUS NtRemoveIoCompletion(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      IN HANDLE IoCompletionHandle,
			      OUT PVOID *CompletionKey,
			      OUT PVOID *CompletionContext,
			      OUT IO_STATUS_BLOCK *IoStatusBlock,
			      IN OPTIONAL PLARGE_INTEGER Timeout)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetIoCompletion(IN ASYNC_STATE AsyncState,
			   IN PTHREAD Thread,
			   IN HANDLE IoCompletionHandle,
			   IN PVOID CompletionKey,
			   IN PVOID CompletionContext,
			   IN NTSTATUS CompletionStatus,
			   IN SIZE_T CompletionInformation)
{
    UNIMPLEMENTED;
}
