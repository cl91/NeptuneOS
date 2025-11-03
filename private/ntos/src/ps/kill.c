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
    DbgTrace("Deleting thread %p\n", Object);
    assert(Object != NULL);
    PTHREAD Thread = (PTHREAD)Object;
    /* If we didn't even get to create the TCB cap, simply return */
    if (Thread->Process == NULL) {
	return;
    }

    /* Dereference the PROCESS object because we increased it during THREAD
     * object creation */
    ObDereferenceObject(Thread->Process);

#ifndef _WIN64
    /* If we have generated the thread ID, remove it */
    if (Thread->CidMapNode.Key) {
	AvlTreeRemoveNode(&PspCidMap, &Thread->CidMapNode);
    }
#endif

    /* If we are deleting the main event loop thread of a driver process,
     * unlink us from the driver object. */
    if (Thread->Process->DriverObject &&
	Thread == Thread->Process->DriverObject->MainEventLoopThread) {
	Thread->Process->DriverObject->MainEventLoopThread = NULL;
    }

    /* Remove the thread from its PROCESS object's thread list */
    assert(Thread->ThreadListEntry.Flink != NULL);
    assert(Thread->ThreadListEntry.Blink != NULL);
    assert(!IsListEmpty(&Thread->ThreadListEntry));
    RemoveEntryList(&Thread->ThreadListEntry);

    /* Cancel and remove the wait timer used by KeWaitForSingleObject */
    KeCancelTimer(&Thread->WaitTimer);
    KeRemoveTimer(&Thread->WaitTimer);

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

    /* Close all LPC port connections established by the thread */
    LoopOverList(Connection, &Thread->LpcConnectionList, LPC_PORT_CONNECTION, ThreadLink) {
	ExClosePortConnection(Connection, TRUE);
    }

    /* Free the debug name allocated during thread creation */
    if (Thread->DebugName != NULL) {
	PspFreePool(Thread->DebugName);
    }

    /* Release the IPC buffers and the TEB of the thread. Note that both the
     * client side frames and the server side frames are unmapped and then freed. */
    PspUnmapSharedRegion(Thread->IpcBufferServerAddr, Thread->Process,
			 Thread->IpcBufferClientAddr);

    /* Clean up the service endpoints of the THREAD object */
    KeDisableThreadServices(Thread);

    /* If we are in the ready list, remove us from it. */
    extern LIST_ENTRY KiReadyThreadList;
    LoopOverList(Entry, &KiReadyThreadList, THREAD, ReadyListLink) {
	if (Entry == Thread) {
	    RemoveEntryList(&Thread->ReadyListLink);
	    break;
	}
    }

    /* Delete the thread-private CNode. This will revoke all caps within it. */
    MmDeleteCNode(Thread->CSpace);

    /* Finally, delete the TCB object */
    MmCapTreeDeleteNode(&Thread->TreeNode);
}

VOID PspProcessObjectDeleteProc(IN POBJECT Object)
{
    DbgTrace("Deleting process %p\n", Object);
    PPROCESS Process = Object;
    if (!Process->ImageSection) {
	return;
    }
    /* At this point the handle table should be empty. */
    assert(!Process->HandleTable.Tree.BalancedRoot);
    /* The thread list should be empty as well. */
    assert(IsListEmpty(&Process->ThreadList));
    KeDetachDispatcherObject(&Process->Header);
    ObDereferenceObject(Process->ImageSection);
    if (Process->DriverObject) {
	Process->DriverObject->DriverProcess = NULL;
    }
    if (Process->DpcMutex.TreeNode.Cap) {
	KeDestroyNotification(&Process->DpcMutex);
    }
    if (Process->WorkItemMutex.TreeNode.Cap) {
	KeDestroyNotification(&Process->WorkItemMutex);
    }
    MmDestroyVSpace(&Process->VSpace);
    MmDeleteCNode(Process->SharedCNode);
    RemoveEntryList(&Process->ProcessListEntry);
#ifndef _WIN64
    /* If we have generated the process ID, remove it */
    if (Process->CidMapNode.Key) {
	AvlTreeRemoveNode(&PspCidMap, &Process->CidMapNode);
    }
#endif
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
    DbgTrace("Terminating thread %s with status 0x%08x\n",
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
    RET_ERR(ObReferenceObjectByHandle(Thread, ThreadHandle,
				      OBJECT_TYPE_THREAD, (POBJECT *)&ThreadToTerminate));
    ObDereferenceObject(ThreadToTerminate);
    assert(ThreadToTerminate != NULL);
    PsTerminateThread(ThreadToTerminate, ExitStatus);
    /* If the current thread is terminating, do not reply to it */
    if (ThreadHandle == NtCurrentThread()) {
	return STATUS_NTOS_NO_REPLY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS PsTerminateProcess(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
			    IN PPROCESS Process,
			    IN NTSTATUS ExitStatus)
{
    ASYNC_BEGIN(State, Locals, {
	    HANDLE HandleToClose;
	});
    DbgTrace("Terminating process %p (%s) with status 0x%08x\n",
	     Process, KEDBG_PROCESS_TO_FILENAME(Process), ExitStatus);

    /* If we are terminating a running driver process, unload the driver.
     * Note we do not do this before the driver is fully loaded since
     * IopLoadDriver takes care of properly dereferencing the driver object
     * if it fails to load. */
    AWAIT_IF(Process->DriverObject && Process->DriverObject->DriverLoaded,
	     IoUnloadDriver, State, Locals, Thread, Process->DriverObject,
	     FALSE, ExitStatus);

close:;
    PAVL_NODE Node = AvlGetFirstNode(&Process->HandleTable.Tree);
    if (!Node) {
	goto out;
    }
    Locals.HandleToClose = (HANDLE)(ULONG_PTR)Node->Key;
    AWAIT(NtClose, State, Locals, Thread, Locals.HandleToClose);
    goto close;

out:
    LoopOverList(Thread, &Process->ThreadList, THREAD, ThreadListEntry) {
	PsTerminateThread(Thread, ExitStatus);
    }
    KeSignalDispatcherObject(&Process->Header);
    ObDereferenceObject(Process);
    ASYNC_END(State, STATUS_SUCCESS);
}

NTSTATUS NtTerminateProcess(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
                            IN HANDLE ProcessHandle,
                            IN NTSTATUS ExitStatus)
{
    ASYNC_BEGIN(State, Locals, {
	    PPROCESS Process;
	});
    PPROCESS Process = NULL;
    ASYNC_RET_ERR(State, ObReferenceObjectByHandle(Thread, ProcessHandle,
						   OBJECT_TYPE_PROCESS,
						   (POBJECT *)&Process));
    assert(Process != NULL);
    Locals.Process = Process;
    ObDereferenceObject(Process);
    AWAIT(PsTerminateProcess, State, Locals, Thread, Locals.Process, ExitStatus);
    /* If the current process is terminating, do not reply to the calling thread. */
    if (ProcessHandle == NtCurrentProcess()) {
	ASYNC_RETURN(State, STATUS_NTOS_NO_REPLY);
    }
    ASYNC_END(State, STATUS_SUCCESS);
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
	RET_ERR(ObReferenceObjectByHandle(Thread, ThreadHandle,
					  OBJECT_TYPE_THREAD, (POBJECT *)&ThreadToResume));
	ObDereferenceObject(ThreadToResume);
    }
    assert(ThreadToResume != NULL);
    RET_ERR(PsResumeThread(ThreadToResume));
    return STATUS_SUCCESS;
}
