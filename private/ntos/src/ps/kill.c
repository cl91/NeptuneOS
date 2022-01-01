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

NTSTATUS PsTerminateThread(IN PTHREAD Thread,
			   IN NTSTATUS ExitStatus)
{
    assert(Thread->Process != NULL);
    /* If the thread to terminate is the main event loop of a driver thread,
     * set the driver status to error and set the InitializationDone event */
    if (Thread->Process->DriverObject != NULL) {
	PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
	DriverObject->EventLoopThreadStatus = ExitStatus;
	KeSetEvent(&DriverObject->InitializationDoneEvent);
    }
    /* For now we simply suspend the thread */
    return PspSuspendThread(Thread);
}

NTSTATUS NtTerminateThread(IN ASYNC_STATE State,
			   IN PTHREAD Thread,
                           IN HANDLE ThreadHandle,
                           IN NTSTATUS ExitStatus)
{
    PTHREAD ThreadToTerminate = NULL;
    if (ThreadHandle == NtCurrentThread()) {
	ThreadToTerminate = Thread;
    } else {
	RET_ERR(ObReferenceObjectByHandle(Thread->Process, ThreadHandle,
					  OBJECT_TYPE_THREAD, (POBJECT *) &ThreadToTerminate));
    }
    assert(ThreadToTerminate != NULL);
    PsTerminateThread(ThreadToTerminate, ExitStatus);
    /* If the current thread is terminating, do not reply to it */
    if (ThreadHandle == NtCurrentThread()) {
	return STATUS_NTOS_NO_REPLY;
    }
    return STATUS_SUCCESS;
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
