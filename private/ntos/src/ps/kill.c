#include "psp.h"

static NTSTATUS PspSuspendThread(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_Suspend(Thread->TreeNode.Cap);

    if (Error != 0) {
	DbgTrace("seL4_TCB_Suspend failed for thread cap 0x%zx with error %d\n",
		 Thread->TreeNode.Cap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS NtTerminateThread(IN ASYNC_STATE State,
			   IN PTHREAD Thread,
                           IN HANDLE ThreadHandle,
                           IN NTSTATUS ExitStatus)
{
    if (ThreadHandle == NtCurrentThread()) {
	PspSuspendThread(Thread);
	return STATUS_NTOS_NO_REPLY;
    }
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtTerminateProcess(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
                            IN HANDLE ProcessHandle,
                            IN NTSTATUS ExitStatus)
{
    UNIMPLEMENTED;
}

NTSTATUS NtResumeThread(IN ASYNC_STATE AsyncState,
                        IN PTHREAD Thread,
                        IN HANDLE ThreadHandle,
                        OUT OPTIONAL ULONG *SuspendCount)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDelayExecution(IN ASYNC_STATE AsyncState,
                          IN PTHREAD Thread,
                          IN BOOLEAN Alertable,
                          IN PLARGE_INTEGER Interval)
{
    UNIMPLEMENTED;
}
