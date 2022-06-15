#include "ki.h"
#include <stdarg.h>

static inline BOOLEAN KiApcQueueIsEmpty(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    return IsListEmpty(&Thread->QueuedApcList);
}

static inline VOID KiInitializeSingleWaitBlock(IN PKWAIT_BLOCK WaitBlock,
					       IN PTHREAD Thread,
					       IN PDISPATCHER_HEADER DispatcherObject)
{
    assert(WaitBlock != NULL);
    assert(DispatcherObject != NULL);
    memset(WaitBlock, 0, sizeof(KWAIT_BLOCK));
    WaitBlock->Thread = Thread;
    WaitBlock->WaitType = WaitOne;
    InsertHeadList(&DispatcherObject->WaitBlockList, &WaitBlock->DispatcherLink);
    WaitBlock->Dispatcher = DispatcherObject;
}

static inline VOID KiFreeWaitBlock(IN PKWAIT_BLOCK WaitBlock)
{
    assert(WaitBlock != &WaitBlock->Thread->RootWaitBlock);
    assert(WaitBlock->WaitType == WaitOne);
    RemoveEntryList(&WaitBlock->DispatcherLink);
    RemoveEntryList(&WaitBlock->SiblingLink);
    KiFreePool(WaitBlock);
}

/*
 * Invalidate the root wait block of a THREAD object
 *
 * This is strictly not necessary but we want to make debugging easier
 */
static inline VOID KiInvalidateRootWaitBlock(IN PTHREAD Thread)
{
    memset(&Thread->RootWaitBlock, 0, sizeof(KWAIT_BLOCK));
    Thread->RootWaitBlock.Thread = Thread;
}

static inline VOID KiFreeWaitBlockChain(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    assert(Thread->RootWaitBlock.WaitType != WaitOne);
    LoopOverList(WaitBlock, &Thread->RootWaitBlock.SubBlockList, KWAIT_BLOCK, SiblingLink) {
	KiFreeWaitBlock(WaitBlock);
    }
    KiInvalidateRootWaitBlock(Thread);
}

VOID KiDestroyDispatcherHeader(IN PDISPATCHER_HEADER Header)
{
    LoopOverList(WaitBlock, &Header->WaitBlockList, KWAIT_BLOCK, DispatcherLink) {
	assert(WaitBlock->WaitType == WaitOne);
	assert(WaitBlock->Thread != NULL);
	if (WaitBlock != &WaitBlock->Thread->RootWaitBlock) {
	    /* If the wait block is not the root wait block of a thread,
	     * it must be a sub-block of a wait block chain. In this case
	     * we free the wait block, and if it is the last sub-block of
	     * its root wait block, we invalidate the root wait block. */
	    PKWAIT_BLOCK RootWaitBlock = &WaitBlock->Thread->RootWaitBlock;
	    assert(RootWaitBlock->Thread == WaitBlock->Thread);
	    assert(RootWaitBlock->WaitType != WaitOne);
	    KiFreeWaitBlock(WaitBlock);
	    /* Note that even though the root wait block might have become
	     * empty at this point, we don't want to invalidate the root wait
	     * block yet since that is done in KiFreeWaitBlockChain. */
	} else {
	    /* Else, we are detaching the dispatcher header from the root
	     * wait block of a thread. Remove the root wait block from the
	     * dispatcher header's wait block list and invalidate the block. */
	    RemoveEntryList(&WaitBlock->DispatcherLink);
	    KiInvalidateRootWaitBlock(WaitBlock->Thread);
	}
    }
}

static inline NTSTATUS KiCreateWaitBlockChain(IN PTHREAD Thread,
					      IN WAIT_TYPE WaitType,
					      IN KE_DISPATCHER_ITERATOR Iterator,
					      IN PVOID IteratorContext,
					      OUT BOOLEAN *NonEmpty)
{
    assert(Thread != NULL);
    assert(WaitType != WaitOne);
    assert(NonEmpty != NULL);
    PKWAIT_BLOCK RootBlock = &Thread->RootWaitBlock;
    RootBlock->Thread = Thread;
    RootBlock->WaitType = WaitType;
    InitializeListHead(&RootBlock->SubBlockList);
    PDISPATCHER_HEADER DispatcherObject;
    while ((DispatcherObject = Iterator(IteratorContext)) != NULL) {
	*NonEmpty = TRUE;
	KiAllocatePoolEx(WaitBlock, KWAIT_BLOCK, KiFreeWaitBlockChain(Thread));
	KiInitializeSingleWaitBlock(WaitBlock, Thread, DispatcherObject);
	InsertTailList(&RootBlock->SubBlockList, &WaitBlock->SiblingLink);
    }
    return STATUS_SUCCESS;
}

static inline VOID KiInitializeApc(IN PKAPC Apc,
				   IN PTHREAD Thread,
				   IN PKAPC_ROUTINE ApcRoutine,
				   IN PVOID SystemArgument1,
				   IN PVOID SystemArgument2,
				   IN PVOID SystemArgument3)
{
    assert(Apc != NULL);
    assert(Thread != NULL);
    assert(ApcRoutine != NULL);
    Apc->Thread = Thread;
    Apc->Object.ApcRoutine = ApcRoutine;
    Apc->Object.ApcContext[0] = SystemArgument1;
    Apc->Object.ApcContext[1] = SystemArgument2;
    Apc->Object.ApcContext[2] = SystemArgument3;
    Apc->Inserted = FALSE;
}

static inline BOOLEAN KiInsertApc(IN PKAPC Apc)
{
    assert(Apc != NULL);
    assert(Apc->Thread != NULL);
    if (Apc->Inserted) {
	return FALSE;
    }
    InsertTailList(&Apc->Thread->QueuedApcList, &Apc->ThreadApcListEntry);
    Apc->Inserted = TRUE;
    return TRUE;
}

NTSTATUS KeWaitForSingleObject(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN PDISPATCHER_HEADER DispatcherObject,
			       IN BOOLEAN Alertable)
{
    assert(Thread != NULL);
    assert(DispatcherObject != NULL);
    ASYNC_BEGIN(State);

    /* This is the first time that this function is being called. Add the
     * dispatcher object to the thread's root wait block and suspend the thread. */
    assert(Thread->Suspended == FALSE);

    /* If the dispatcher object has already been signaled, we do not need to wait.
     * If the event type is a synchronization event, set the event to non-signaled.
     * Check the APC queue and return. */
    if (DispatcherObject->Signaled) {
	if (DispatcherObject->EventType == SynchronizationEvent) {
	    DispatcherObject->Signaled = FALSE;
	}
	if (Alertable && !KiApcQueueIsEmpty(Thread)) {
	    ASYNC_RETURN(State, STATUS_USER_APC);
	} else {
	    ASYNC_RETURN(State, STATUS_SUCCESS);
	}
    }

    KiInitializeSingleWaitBlock(&Thread->RootWaitBlock, Thread, DispatcherObject);
    Thread->Suspended = TRUE;
    Thread->Alertable = Alertable;

    ASYNC_YIELD(State, _);

    /* If the control flow gets here it means that we are being called a second
     * time by the system service dispatcher. Remove the dispatcher object from
     * the thread's root block and resume the thread. */
    assert(Thread->Suspended == FALSE);
    assert(Thread->Alertable == Alertable);
    assert(Thread->RootWaitBlock.WaitType == WaitOne);
    /* The root wait block might have been invalidated at this point because
     * the dispatcher object may have been deleted. */
    if (Thread->RootWaitBlock.Dispatcher != NULL) {
	if (!Alertable) {
	    assert(Thread->RootWaitBlock.Dispatcher->Signaled);
	}
	/* If the event type is a synchronization event, set the event to non-signaled. */
	if (Thread->RootWaitBlock.Dispatcher->EventType == SynchronizationEvent) {
	    Thread->RootWaitBlock.Dispatcher->Signaled = FALSE;
	}
	RemoveEntryList(&Thread->RootWaitBlock.DispatcherLink);
    }
    /* Reset the thread to non-alertable state */
    Thread->Alertable = FALSE;
    /* If the thread is in an alertable wait and the APC queue is not empty, return
     * STATUS_USER_APC so that the client side stub function can deliver the APCs */
    if (Alertable && !KiApcQueueIsEmpty(Thread)) {
	ASYNC_RETURN(State, STATUS_USER_APC);
    }

    ASYNC_END(State, STATUS_SUCCESS);
}

/*
 * TODO: We need to figure our when to clear the Signaled state. I think what we
 * currently do is correct --- the Signaled state for the event type is cleared
 * here in KeWaitForMultipleObjects. Although I think we need to check for the
 * root wait block before we yield such that a thread waiting on a notification
 * event that has already been signaled will NOT be blocked.
 */
NTSTATUS KeWaitForMultipleObjects(IN ASYNC_STATE State,
				  IN PTHREAD Thread,
				  IN BOOLEAN Alertable,
				  IN WAIT_TYPE WaitType,
				  IN KE_DISPATCHER_ITERATOR Iterator,
				  IN PVOID IteratorContext)
{
    assert(Thread != NULL);
    ASYNC_BEGIN(State);

    /* This is the first time that this function is being called. Build the
     * wait block chain and suspend the thread. */
    assert(Thread->Suspended == FALSE);
    BOOLEAN NonEmpty = FALSE;
    ASYNC_RET_ERR(State, KiCreateWaitBlockChain(Thread, WaitType, Iterator,
						IteratorContext, &NonEmpty));
    /* If the wait block chain is empty, do not wait and simply return. */
    if (!NonEmpty) {
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }
    Thread->Suspended = TRUE;
    Thread->Alertable = Alertable;

    ASYNC_YIELD(State, _);

    /* If the control flow gets here it means that we are being called a second
     * time by the system service dispatcher. Free the wait block chain and
     * resume the thread. */
    assert(Thread->Suspended == FALSE);
    assert(Thread->Alertable == Alertable);
    assert(Thread->RootWaitBlock.WaitType == WaitType);
#if 0
    /* TODO!! */
    if (!Alertable) {
	assert(Thread->RootWaitBlock.Dispatcher->Signaled);
    }
    /* Traverse the wait block chain and see if the any of the the event type is
     * a synchronization event, and set the event to non-signaled in this case. */
    if (Thread->RootWaitBlock.Dispatcher->EventType == SynchronizationEvent) {
	Thread->RootWaitBlock.Dispatcher->Signaled = FALSE;
    }
#endif
    /* Free the wait block chain constructed earlier */
    KiFreeWaitBlockChain(Thread);
    /* Reset the thread to non-alertable state */
    Thread->Alertable = FALSE;
    /* If the thread is in an alertable wait and the APC queue is not empty, return
     * STATUS_USER_APC so that the client side stub function can deliver the APCs */
    if (Alertable && !KiApcQueueIsEmpty(Thread)) {
	ASYNC_RETURN(State, STATUS_USER_APC);
    }

    ASYNC_END(State, STATUS_SUCCESS);
}

/*
 * Add the given thread to the ready thread list. The system service
 * dispatcher will call its service handler function with the saved
 * context and async stack.
 */
static inline VOID KiResumeThread(IN PTHREAD Thread)
{
    DbgTrace("Resuming thread %s|%p\n",
	     Thread->Process->ImageFile->FileName, Thread);
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

NTSTATUS KeQueueApcToThread(IN PTHREAD Thread,
			    IN PKAPC_ROUTINE ApcRoutine,
			    IN PVOID SystemArgument1,
			    IN PVOID SystemArgument2,
			    IN PVOID SystemArgument3)
{
    assert(Thread != NULL);
    KiAllocatePool(Apc, KAPC);
    KiInitializeApc(Apc, Thread, ApcRoutine, SystemArgument1,
		    SystemArgument2, SystemArgument3);
    KiInsertApc(Apc);
    /* If the thread is in an alertable wait, wake it up */
    if (Thread->Alertable && Thread->Suspended) {
	KiResumeThread(Thread);
    }
    return STATUS_SUCCESS;
}

/*
 * Remove the APC object from the thread and free the APC object.
 */
BOOLEAN KeRemoveQueuedApc(IN PKAPC Apc)
{
    assert(Apc != NULL);
    if (!Apc->Inserted) {
	return FALSE;
    }
    RemoveEntryList(&Apc->ThreadApcListEntry);
    KiFreePool(Apc);
    return TRUE;
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
 * is satisfied, or if the thread is in an alertable wait and its APC
 * queue is not empty.
 */
static inline BOOLEAN KiShouldWakeThread(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    return KiWaitBlockIsSatisfied(&Thread->RootWaitBlock) ||
	(Thread->Alertable && !KiApcQueueIsEmpty(Thread));
}

/*
 * Iterate over the queued APC list of the thread and deliver the APC
 * object via the thread's service message buffer.
 *
 * If the thread APC list is not empty after MAX_APC_COUNT_PER_DELIVERY
 * of APCs is delivered (meaning the thread has more than MAX_APC_COUNT
 * _PER_DELIVERY APCs queued at the beginning of this function), then
 * -MAX_APC_COUNT_PER_DELIVERY is returned.
 */
SHORT KiDeliverApc(IN PTHREAD Thread,
		   IN ULONG MsgBufferEnd)
{
    SHORT NumApc = 0;
    PAPC_OBJECT DestApc = &SVC_MSGBUF_OFFSET_TO_ARG(Thread->IpcBufferServerAddr,
						    MsgBufferEnd, APC_OBJECT);
    LoopOverList(Apc, &Thread->QueuedApcList, KAPC, ThreadApcListEntry) {
	assert(Apc->Inserted);
	DestApc[NumApc] = Apc->Object;
	KeRemoveQueuedApc(Apc);
	NumApc++;
	if (NumApc >= MAX_APC_COUNT_PER_DELIVERY) {
	    break;
	}
    }
    return IsListEmpty(&Thread->QueuedApcList) ? NumApc : -NumApc;
}

/*
 * Walk the wait block list of the given dispatcher object, set the block
 * to satisfied and wake all thread sleeping on this dispatcher object (if
 * all other wait conditions are satisfied for the thread).
 */
VOID KiSignalDispatcherObject(IN PDISPATCHER_HEADER Dispatcher)
{
    DbgTrace("Signaling dispatcher %p\n", Dispatcher);
    assert(Dispatcher != NULL);
    if (Dispatcher->Signaled) {
	DbgTrace("Dispatcher %p already signaled\n", Dispatcher);
	return;
    }
    if (Dispatcher->EventType == NotificationEvent) {
	/* Walk the wait block list and wake the thread up */
	LoopOverList(Block, &Dispatcher->WaitBlockList, KWAIT_BLOCK, DispatcherLink) {
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
						   KWAIT_BLOCK, DispatcherLink);
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
    UNIMPLEMENTED;
}
