#include "psp.h"

/*
 * Unmaps the client-server shared region.
 *
 * See PspMapSharedRegion in create.c
 */
static VOID PspUnmapSharedRegion(IN MWORD ServerStart,
				 IN PPROCESS ClientProcess,
				 IN MWORD ClientStart)
{
    assert(ClientProcess != NULL);
    if (ServerStart != 0) {
	assert(ClientStart != 0);
	MmUnmapServerRegion(ServerStart);
	MmUnmapRegion(&ClientProcess->VSpace, ClientStart);
    }
}

/*
 * Note that since this is called when THREAD object creation fails, it
 * must be able to clean up partially created objects.
 *
 * Refer to the create routine for the order in which the sub-objects of
 * the THREAD object is created.
 */
VOID PspThreadObjectDeleteProc(IN POBJECT Object)
{
    assert(Object != NULL);
    PTHREAD Thread = (PTHREAD)Object;
    /* If we didn't even get to create the TCB cap, simply return */
    if (Thread->Process == NULL) {
	return;
    }

    /* Dereference the PROCESS object because we increased it during THREAD
     * object creation */
    ObDereferenceObject(Thread->Process);

    /* Remove the thread from its PROCESS object's thread list */
    assert(Thread->ThreadListEntry.Flink != NULL);
    assert(Thread->ThreadListEntry.Blink != NULL);
    assert(!IsListEmpty(&Thread->ThreadListEntry));
    RemoveEntryList(&Thread->ThreadListEntry);

    /* Clean up the APC objects queued to this thread */
    LoopOverList(Apc, &Thread->QueuedApcList, KAPC, ThreadApcListEntry) {
	UNUSED BOOLEAN Inserted = KeRemoveQueuedApc(Apc);
	assert(Inserted);
    }

    /* Remove all timers set by this thread (through NtSetTimer) */
    LoopOverList(Timer, &Thread->TimerApcList, TIMER, ThreadLink) {
	assert(Timer->ApcThread == Thread);
	Timer->ApcThread = NULL;
	RemoveEntryList(&Timer->ThreadLink);
    }

    /* Free the debug name allocated during thread creation */
    if (Thread->DebugName != NULL) {
	PspFreePool(Thread->DebugName);
    }

    /* Release the IPC buffer of the thread. Note that both the client
     * side frame and the server side frame is unmapped. The frame object
     * itself is then freed. */
    PspUnmapSharedRegion(Thread->IpcBufferServerAddr, Thread->Process,
			 Thread->IpcBufferClientAddr);

    /* Unmap and release the memory of the thread environment block. */
    PspUnmapSharedRegion(Thread->TebServerAddr, Thread->Process,
			 Thread->TebClientAddr);

    /* Clean up the service endpoints of the THREAD object */
    KeDisableThreadServices(Thread);

    /* If the thread is not the initial thread, unmap the ntdll tls region */
    if (!Thread->InitialThread && Thread->SystemDllTlsBase) {
	MmUnmapRegion(&Thread->Process->VSpace, Thread->SystemDllTlsBase);
    }

    /* Finally, delete the TCB object */
    MmCapTreeDeleteNode(&Thread->TreeNode);
}

VOID PspProcessObjectDeleteProc(IN POBJECT Object)
{
    /* TODO */
}

static NTSTATUS PspSuspendThread(IN MWORD Cap)
{
    int Error = seL4_TCB_Suspend(Cap);

    if (Error != 0) {
	DbgTrace("seL4_TCB_Suspend failed for thread cap 0x%zx with error %d\n",
		 Cap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS PsTerminateThread(IN PTHREAD Thread,
			   IN NTSTATUS ExitStatus)
{
    assert(Thread->Process != NULL);
    DbgTrace("Terminating thread %p with status 0x%08x\n",
	     Thread->DebugName, ExitStatus);
    Thread->ExitStatus = ExitStatus;
    /* If the thread to terminate is the main event loop of a driver thread,
     * set the InitializationDone event to wake up the thread waiting on NtLoadDriver */
    if (Thread->Process->DriverObject != NULL && Thread->InitialThread) {
	PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
	KeSetEvent(&DriverObject->InitializationDoneEvent);
    }
    /* Suspend the thread. This is needed so the thread doesn't keep running
     * when there are other objects referring to the thread (in which case
     * the dereference below does not yet delete the THREAD object). */
    RET_ERR(PspSuspendThread(Thread->TreeNode.Cap));
    /* Dereference the THREAD object so the object manager will delete it
     * (if no one else is referring to it) */
    ObDereferenceObject(Thread);
    return STATUS_SUCCESS;
}

/* A system thread should never be terminated. To aid debugging in debug build we
 * generate an assertion. On release build we simply suspend the thread.
 */
NTSTATUS PsTerminateSystemThread(IN PSYSTEM_THREAD Thread)
{
    assert(FALSE);
    return PspSuspendThread(Thread->TreeNode.Cap);
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
    PTHREAD ThreadToResume = NULL;
    if (ThreadHandle == NtCurrentThread()) {
	return STATUS_INVALID_PARAMETER_1;
    } else {
	RET_ERR(ObReferenceObjectByHandle(Thread->Process, ThreadHandle,
					  OBJECT_TYPE_THREAD, (POBJECT *) &ThreadToResume));
    }
    assert(ThreadToResume != NULL);
    NTSTATUS Status = STATUS_INTERNAL_ERROR;
    IF_ERR_GOTO(out, Status, PsResumeThread(ThreadToResume));
    Status = STATUS_SUCCESS;
out:
    if (ThreadToResume != NULL) {
	ObDereferenceObject(ThreadToResume);
    }
    return Status;
}

NTSTATUS NtDelayExecution(IN ASYNC_STATE AsyncState,
                          IN PTHREAD Thread,
                          IN BOOLEAN Alertable,
                          IN PLARGE_INTEGER Interval)
{
    UNIMPLEMENTED;
}
