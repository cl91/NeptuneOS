#include "ki.h"

static inline BOOLEAN KiApcQueueIsEmpty(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    return IsListEmpty(&Thread->QueuedApcList);
}

static inline VOID KiInitializeWaitBlock(IN PKWAIT_BLOCK WaitBlock,
					 IN PASYNC_CONTEXT AsyncContext,
					 IN PDISPATCHER_HEADER DispatcherObject,
					 IN WAIT_TYPE WaitType,
					 IN PKWAIT_BLOCK Next)
{
    assert(WaitBlock != NULL);
    assert(DispatcherObject != NULL);
    memset(WaitBlock, 0, sizeof(KWAIT_BLOCK));
    WaitBlock->AsyncContext = AsyncContext;
    WaitBlock->WaitType = WaitType;
    InsertHeadList(&DispatcherObject->WaitBlockList, &WaitBlock->DispatcherLink);
    WaitBlock->Dispatcher = DispatcherObject;
    WaitBlock->Next = Next;
}

/*
 * Detach the dispatcher object from all of the wait blocks that are waiting
 * for it. This is need when the dispatcher object is being destroyed, but
 * there might still be threads waiting on it.
 */
VOID KeDetachDispatcherObject(IN PDISPATCHER_HEADER Header)
{
    LoopOverList(WaitBlock, &Header->WaitBlockList, KWAIT_BLOCK, DispatcherLink) {
	assert(WaitBlock->AsyncContext != NULL);
	assert(WaitBlock->Dispatcher == Header);
	/* Set the wait blocks' dispatcher object pointer to NULL so that later
	 * the thread can be resumed (see KiWaitBlockIsSatisfied). */
	WaitBlock->Dispatcher = NULL;
    }
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

static inline VOID KiDetachAsyncContextWaitBlocks(IN PASYNC_CONTEXT AsyncContext)
{
    /* Detach the dispatcher object from the async context's root wait block. If we
     * don't do this, later when we add the root wait block to another (or the same)
     * dispatcher object the WaitBlockList will be messed up. Note the dispatcher
     * object can be NULL here because it may have been deleted, in which case we do
     * nothing. */
    for (PKWAIT_BLOCK Blk = &AsyncContext->RootWaitBlock; Blk != NULL; Blk = Blk->Next) {
	if (Blk->Dispatcher != NULL) {
	    RemoveEntryList(&Blk->DispatcherLink);
	    Blk->Dispatcher = NULL;
	}
    }
    AsyncContext->RootWaitBlock.Dispatcher = NULL;
    AsyncContext->RootWaitBlock.Next = NULL;
    /* Do the same for the timer wait block */
    if (AsyncContext->TimerWaitBlock.Dispatcher != NULL) {
	RemoveEntryList(&AsyncContext->TimerWaitBlock.DispatcherLink);
	AsyncContext->TimerWaitBlock.Dispatcher = NULL;
    }
}

NTSTATUS KeWaitForSingleObject(IN ASYNC_STATE State,
			       IN PDISPATCHER_HEADER DispatcherObject,
			       IN BOOLEAN Alertable,
			       IN OPTIONAL PLARGE_INTEGER TimeOut)
{
    assert(State.AsyncContext != NULL);
    assert(State.AsyncContext->Thread != NULL);
    assert(DispatcherObject != NULL);
    ASYNC_BEGIN(State, Thread);

    /* This is the first time that this function is being called. The thread
     * should not be in a suspended state. If it is, things are seriously wrong. */
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

    /* If a timeout is specified, build the timer wait block. */
    if (TimeOut) {
	KiInitializeWaitBlock(&State.AsyncContext->TimerWaitBlock, State.AsyncContext,
			      &State.AsyncContext->WaitTimer.Header, WaitAny, NULL);
	KeSetTimer(&State.AsyncContext->WaitTimer,
		   (SYSTEM_TIME) { .SystemTime = TimeOut->QuadPart },
		   NULL, NULL, NULL, 0);
    }
    KiInitializeWaitBlock(&State.AsyncContext->RootWaitBlock, State.AsyncContext,
			  DispatcherObject, WaitAny,
			  TimeOut ? &State.AsyncContext->TimerWaitBlock : NULL);

    /* Mark the thread as suspended and yield execution back to the system
     * service dispatcher. */
    Thread->Suspended = TRUE;
    Thread->Alertable = Alertable;
    ASYNC_YIELD(State, _, {
	    /* If we got here, it means that this async await is being canceled.
	     * Detach the root wait blocks of the async context. */
	    KiDetachAsyncContextWaitBlocks(State.AsyncContext);
	});

    /* If control flow gets here it means that we are being called a second time
     * by the system service dispatcher. The thread will have been resumed at
     * this point so it should not be in the suspended state. */
    assert(Thread->Suspended == FALSE);
    assert(Thread->Alertable == Alertable);
    /* Detach the root wait blocks of the async context. */
    KiDetachAsyncContextWaitBlocks(State.AsyncContext);
    /* Reset the thread to non-alertable state */
    Thread->Alertable = FALSE;
    /* If the thread is in an alertable wait and the APC queue is not empty, return
     * STATUS_USER_APC so that the client side stub function can deliver the APCs */
    if (Alertable && !KiApcQueueIsEmpty(Thread)) {
	ASYNC_RETURN(State, STATUS_USER_APC);
    }

    ASYNC_END(State, STATUS_SUCCESS);
}

#define CLEAN_UP_WAIT_FOR_MULTIPLE_OBJECTS(State, Locals)   \
    KiDetachAsyncContextWaitBlocks(State.AsyncContext);	    \
    assert(Locals.WaitBlocks != NULL);                      \
    ExFreePoolWithTag(Locals.WaitBlocks, NTOS_KE_TAG)

NTSTATUS KeWaitForMultipleObjects(IN ASYNC_STATE State,
				  IN BOOLEAN Alertable,
				  IN WAIT_TYPE WaitType,
				  IN PDISPATCHER_HEADER *DispatcherObjects,
				  IN ULONG Count,
				  IN OPTIONAL PLARGE_INTEGER TimeOut)
{
    assert(State.AsyncContext != NULL);
    assert(State.AsyncContext->Thread != NULL);
    assert(DispatcherObjects != NULL);
    assert(Count != 0);
    ASYNC_BEGIN(State, Thread, Locals, {
	    PKWAIT_BLOCK WaitBlocks;
	});

    /* TODO: Check whether the wait is satisfied. Return immediately if it is. */

    /* Allocate the wait blocks. Note if Timeout is NULL, the zeroth wait block
     * is not used. */
    Locals.WaitBlocks = (PKWAIT_BLOCK)ExAllocatePoolWithTag(sizeof(KWAIT_BLOCK) * Count,
							    NTOS_KE_TAG);
    if (Locals.WaitBlocks == NULL) {
	ASYNC_RETURN(State, STATUS_NO_MEMORY);
    }

    /* This is the first time that this function is being called. Build the
     * wait block chain. Note we are not going to use the TimerWaitBlock. */
    assert(Thread->Suspended == FALSE);
    if (TimeOut) {
	KiInitializeWaitBlock(&State.AsyncContext->RootWaitBlock, State.AsyncContext,
			      &State.AsyncContext->WaitTimer.Header, WaitAny, NULL);
	KeSetTimer(&State.AsyncContext->WaitTimer,
		   (SYSTEM_TIME) { .SystemTime = TimeOut->QuadPart },
		   NULL, NULL, NULL, 0);
    } else {
	KiInitializeWaitBlock(&State.AsyncContext->RootWaitBlock, State.AsyncContext,
			      DispatcherObjects[0], WaitType, NULL);
    }
    PKWAIT_BLOCK CurrentWaitBlock = &State.AsyncContext->RootWaitBlock;
    for (ULONG i = (TimeOut ? 0 : 1); i < Count; i++) {
	CurrentWaitBlock->Next = &Locals.WaitBlocks[i];
	KiInitializeWaitBlock(&Locals.WaitBlocks[i], State.AsyncContext,
			      DispatcherObjects[i], WaitType, NULL);
	CurrentWaitBlock = &Locals.WaitBlocks[i];
    }

    /* Mark the thread as suspended and yield to the system service dispatcher. */
    Thread->Suspended = TRUE;
    Thread->Alertable = Alertable;
    ASYNC_YIELD(State, Locals, {
	    CLEAN_UP_WAIT_FOR_MULTIPLE_OBJECTS(State, Locals);
	});

    /* If the control flow gets here it means that we are being called a second
     * time by the system service dispatcher. Free the wait block chain and
     * resume the thread. */
    assert(Thread->Suspended == FALSE);
    assert(Thread->Alertable == Alertable);
    CLEAN_UP_WAIT_FOR_MULTIPLE_OBJECTS(State, Locals);
    /* Reset the thread to non-alertable state */
    Thread->Alertable = FALSE;
    /* If the thread is in an alertable wait and the APC queue is not empty, return
     * STATUS_USER_APC so that the client side stub function can deliver the APCs */
    if (Alertable && !KiApcQueueIsEmpty(Thread)) {
	ASYNC_RETURN(State, STATUS_USER_APC);
    }

    ASYNC_END(State, STATUS_SUCCESS);
}

/* This routine should only be called during thread object creation */
NTSTATUS KeAllocateDefaultAsyncContext(IN PTHREAD Thread)
{
    assert(!Thread->AsyncContexts);
    assert(!Thread->AsyncObjMaxId);
    assert(!Thread->AsyncObjUsedMap);
    assert(!Thread->AsyncResumeRoutine);
    assert(!Thread->AsyncRoutineContext);
    Thread->AsyncContexts = ExAllocatePoolWithTag(sizeof(PVOID), NTOS_KE_TAG);
    if (!Thread->AsyncContexts) {
	return STATUS_NO_MEMORY;
    }
    PASYNC_CONTEXT AsyncCtx = ExAllocatePoolWithTag(sizeof(ASYNC_CONTEXT), NTOS_KE_TAG);
    if (!AsyncCtx) {
	ExFreePoolWithTag(Thread->AsyncContexts, NTOS_KE_TAG);
	Thread->AsyncContexts = NULL;
	return STATUS_NO_MEMORY;
    }
    KiInitializeAsyncContext(Thread, 0, AsyncCtx);
    return STATUS_SUCCESS;
}

VOID KeCancelThreadAsyncContexts(IN PTHREAD Thread)
{
    if (Thread->AsyncObjMaxId) {
	/* TODO */
    } else {
	assert(Thread == Thread->AsyncContexts[0]->Thread);
	ObDereferenceObject(Thread);
    }
}

/*
 * Add the given thread to the ready thread list. The system service
 * dispatcher will call its service handler function with the saved
 * context and async stack.
 */
static inline VOID KiResumeThread(IN PTHREAD Thread)
{
    DbgTrace("Resuming thread %s|%p\n",
	     KEDBG_THREAD_TO_FILENAME(Thread), Thread);
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
 * If the thread object associated with the async context is running in
 * synchronous execution mode, simply wake up the thread. If the thread
 * has asynchronous execution enabled, queue an APC object to the thread
 * to pass the async object id to the client.
 */
static inline VOID KiResumeAsyncContext(IN PASYNC_CONTEXT AsyncContext)
{
    assert(AsyncContext);
    PTHREAD Thread = AsyncContext->Thread;
    assert(Thread);
    if (Thread->AsyncObjMaxId) {
	if (Thread->AsyncResumeRoutine) {
	    ULONG_PTR AsyncObjId = AsyncContext->AsyncObjId;
	    KeQueueApcToThread(Thread, (PVOID)Thread->AsyncResumeRoutine,
			       Thread->AsyncRoutineContext,
			       (PVOID)AsyncObjId, NULL);
	}
    } else {
	KiResumeThread(Thread);
    }
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
 * is satisfied. This is computed recursively. Let S be TRUE if the
 * dispatcher object pointed to by this wait block is signaled, and
 * FALSE if otherwise. Let T be the value of the boolean formula for
 * the Next member. For WaitAny, we return S || T, and for WaitAll, we
 * return S && T.
 *
 * Note in the special case there Next is NULL, we simply return S.
 * Additionally, if the dispatcher object has already been deleted (or
 * at least marked for deletion), S is always TRUE. In other words,
 * destroying a dispatcher object will wake up the thread objects
 * waiting on it.
 *
 * Since this is a recursive function there is a danger of stack overrun.
 * In practice the NTOS Executive task has multi-MBs of stack space so
 * this is unlikely going to be a problem.
 */
static BOOLEAN KiWaitBlockIsSatisfied(IN PKWAIT_BLOCK Block)
{
    BOOLEAN Satisfied = Block->Dispatcher ? Block->Dispatcher->Signaled : TRUE;
    if (Block->Next != NULL) {
	if (Block->WaitType == WaitAny) {
	    return Satisfied || KiWaitBlockIsSatisfied(Block->Next);
	} else {
	    assert(Block->WaitType == WaitAll);
	    return Satisfied && KiWaitBlockIsSatisfied(Block->Next);
	}
    }
    return Satisfied;
}

/*
 * Returns true if all the wait conditions (ie. the master wake formula)
 * of the async context is satisfied.
 */
static inline BOOLEAN KiShouldWakeAsyncContext(IN PASYNC_CONTEXT AsyncContext)
{
    assert(AsyncContext != NULL);
    return KiWaitBlockIsSatisfied(&AsyncContext->RootWaitBlock);
}

/*
 * Return true if the thread is in an alertable wait and its APC queue is
 * not empty.
 */
static inline BOOLEAN KiShouldAlertThread(IN PTHREAD Thread)
{
    return Thread->Alertable && !KiApcQueueIsEmpty(Thread);
}

/*
 * Iterate over the queued APC list of the thread and deliver the APC
 * object via the thread's service message buffer, starting at the specified
 * message buffer offset. Return the number of APCs delivered.
 *
 * If we cannot deliver all APCs in one go, MoreToCome is set to TRUE.
 */
ULONG KiDeliverApc(IN PTHREAD Thread,
		   IN ULONG MsgBufOffset,
		   OUT BOOLEAN *MoreToCome)
{
    assert(MsgBufOffset <= SVC_MSGBUF_SIZE);
    assert(MoreToCome != NULL);
    ULONG NumApc = 0;
    PAPC_OBJECT DestApc = &SVC_MSGBUF_OFFSET_TO_ARG(Thread->IpcBufferServerAddr,
						    MsgBufOffset, APC_OBJECT);
    ULONG MaxNumApc = (SVC_MSGBUF_SIZE - MsgBufOffset) / sizeof(APC_OBJECT);
    if (MaxNumApc > MAX_APC_PER_DELIVERY) {
	MaxNumApc = MAX_APC_PER_DELIVERY;
    }
    LoopOverList(Apc, &Thread->QueuedApcList, KAPC, ThreadApcListEntry) {
	if (NumApc >= MaxNumApc) {
	    break;
	}
	assert(Apc->Inserted);
	DestApc[NumApc] = Apc->Object;
	KeRemoveQueuedApc(Apc);
	NumApc++;
    }
    *MoreToCome = !IsListEmpty(&Thread->QueuedApcList);
    return NumApc;
}

/*
 * Walk the wait block list of the given dispatcher object, set the block
 * to satisfied and wake all thread sleeping on this dispatcher object (if
 * all other wait conditions are satisfied for the thread).
 */
VOID KeSignalDispatcherObject(IN PDISPATCHER_HEADER Dispatcher)
{
    DbgTrace("Signaling dispatcher %p\n", Dispatcher);
    assert(Dispatcher != NULL);
    if (Dispatcher->Signaled) {
	DbgTrace("Dispatcher %p already signaled\n", Dispatcher);
    }
    Dispatcher->Signaled = TRUE;
    /* Walk the wait block list and wake the thread up */
    LoopOverList(Block, &Dispatcher->WaitBlockList, KWAIT_BLOCK, DispatcherLink) {
	assert(Block->AsyncContext != NULL);
	if (KiShouldWakeAsyncContext(Block->AsyncContext)) {
	    KiResumeAsyncContext(Block->AsyncContext);
	    /* If the dispatcher is a synchronization dispatcher, set it back to
	     * non-signaled and exit the loop (we only wake up one thread). */
	    if (Dispatcher->EventType == SynchronizationEvent) {
		Dispatcher->Signaled = FALSE;
		break;
	    }
	}
    }
}

NTSTATUS NtTestAlert(IN ASYNC_STATE State)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueueApcThread(IN ASYNC_STATE AsyncState,
			  IN HANDLE ThreadHandle,
			  IN PKNORMAL_ROUTINE ApcRoutine,
			  IN OPTIONAL PVOID NormalContext,
			  IN OPTIONAL PVOID SystemArgument1,
			  IN OPTIONAL PVOID SystemArgument2)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetThreadExecutionMode(IN PTHREAD Thread,
				  IN PTHREAD_EXECUTION_MODE ExecutionMode)
{
    UNIMPLEMENTED;
}

NTSTATUS NtAsyncContinue(IN PTHREAD Thread,
			 IN ULONG_PTR AsyncObjId)
{
    UNIMPLEMENTED;
}
