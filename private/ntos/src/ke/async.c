#include "ki.h"

static inline VOID KiInitializeSingleWaitBlock(IN PKWAIT_BLOCK WaitBlock,
					       IN PTHREAD Thread,
					       IN PDISPATCHER_HEADER DispatcherObject)
{
    assert(WaitBlock != NULL);
    assert(DispatcherObject != NULL);
    memset(WaitBlock, 0, sizeof(KWAIT_BLOCK));
    WaitBlock->Thread = Thread;
    WaitBlock->WaitType = WaitOne;
    InsertHeadList(&DispatcherObject->WaitBlockList, &WaitBlock->WaitBlockLink);
    WaitBlock->Dispatcher = DispatcherObject;
}

NTSTATUS KeWaitForSingleObject(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN PDISPATCHER_HEADER DispatcherObject)
{
    assert(Thread != NULL);
    assert(DispatcherObject != NULL);
    ASYNC_BEGIN(State);

    /* This is the first time that this function is being called. Add the
     * dispatcher object to the thread's root wait block and suspend the thread. */
    assert(Thread->Suspended == FALSE);
    KiInitializeSingleWaitBlock(&Thread->RootWaitBlock, Thread, DispatcherObject);
    Thread->Suspended = TRUE;

    ASYNC_YIELD(State);

    /* If the control flow gets here it means that we are being called a second
     * time by the system service dispatcher. Remove the dispatcher object from
     * the thread's root block and resume the thread. */
    assert(Thread->Suspended == FALSE);
    assert(Thread->RootWaitBlock.WaitType == WaitOne);
    assert(Thread->RootWaitBlock.Dispatcher != NULL);
    /* If the event type is a synchronization event, set the event to non-signaled. */
    if (Thread->RootWaitBlock.Dispatcher->EventType == SynchronizationEvent) {
	Thread->RootWaitBlock.Dispatcher->Signaled = FALSE;
    }
    RemoveEntryList(&Thread->RootWaitBlock.WaitBlockLink);

    ASYNC_END(STATUS_SUCCESS);
}

/*
 * Add the given thread to the ready thread list. The system service
 * dispatcher will call its service handler function with the saved
 * context and async stack.
 */
static inline VOID KiResumeThread(IN PTHREAD Thread)
{
    /* Make sure we aren't already in the ready list. */
    LoopOverList(Entry, &KiReadyThreadList, THREAD, ReadyListLink) {
	if (Entry == Thread) {
	    return;
	}
    }
    Thread->Suspended = FALSE;
    /* Add the thread to the end of the ready list */
    InsertTailList(&KiReadyThreadList, &Thread->ReadyListLink);
}

/*
 * Returns true if the boolean formula represented by this wait block
 * is satisfied.
 */
static BOOLEAN KiWaitBlockIsSatisfied(IN PKWAIT_BLOCK Block)
{
    if (Block->WaitType == WaitAny) {
	BOOLEAN Satisfied = FALSE;
	LoopOverList(Subblock, &Block->SubBlockList, KWAIT_BLOCK, SiblingLink) {
	    Satisfied |= KiWaitBlockIsSatisfied(Subblock);
	    if (Satisfied) {
		break;
	    }
	}
	Block->Satisfied = Satisfied;
    } else if (Block->WaitType == WaitAll) {
	BOOLEAN Satisfied = TRUE;
	LoopOverList(Subblock, &Block->SubBlockList, KWAIT_BLOCK, SiblingLink) {
	    Satisfied &= KiWaitBlockIsSatisfied(Subblock);
	}
	Block->Satisfied = Satisfied;
    }
    return Block->Satisfied;
}

/*
 * Returns true if all the wait conditions (ie. the master wake formula)
 * is satisfied.
 */
static inline BOOLEAN KiShouldWakeThread(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    return KiWaitBlockIsSatisfied(&Thread->RootWaitBlock);
}

/*
 * Walk the wait block list of the given dispatcher object, set the block
 * to satisfied and wake all thread sleeping on this dispatcher object (if
 * all other wait conditions are satisfied for the thread).
 */
VOID KiSignalDispatcherObject(IN PDISPATCHER_HEADER Dispatcher)
{
    assert(Dispatcher != NULL);
    if (Dispatcher->Signaled) {
	return;
    }
    if (Dispatcher->EventType == NotificationEvent) {
	/* Walk the wait block list and wake the thread up */
	LoopOverList(Block, &Dispatcher->WaitBlockList, KWAIT_BLOCK, WaitBlockLink) {
	    Block->Satisfied = TRUE;
	    assert(Block->Thread != NULL);
	    if (KiShouldWakeThread(Block->Thread)) {
		KiResumeThread(Block->Thread);
	    }
	}
    } else {
	assert(Dispatcher->EventType == SynchronizationEvent);
	if (!IsListEmpty(&Dispatcher->WaitBlockList)) {
	    PKWAIT_BLOCK Block = CONTAINING_RECORD(Dispatcher->WaitBlockList.Flink,
						   KWAIT_BLOCK, WaitBlockLink);
	    Block->Satisfied = TRUE;
	    assert(Block->Thread != NULL);
	    if (KiShouldWakeThread(Block->Thread)) {
		KiResumeThread(Block->Thread);
	    }
	}
    }
    Dispatcher->Signaled = TRUE;
}

NTSTATUS NtTestAlert(IN ASYNC_STATE State,
		     IN PTHREAD Thread)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtContinue(IN ASYNC_STATE State,
		    IN PTHREAD Thread,
                    IN PCONTEXT Context,
                    IN BOOLEAN TestAlert)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtWaitForSingleObject(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
                               IN HANDLE ObjectHandle,
                               IN BOOLEAN Alertable,
                               IN OPTIONAL PLARGE_INTEGER TimeOut)
{
    return STATUS_NOT_IMPLEMENTED;
}
