#include "ki.h"

static inline BOOLEAN KiApcQueueIsEmpty(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    BOOLEAN NeedAsyncObjApc = FALSE;
    if (Thread->AsyncObjMaxId) {
	assert(Thread->AsyncObjUsedMap);
	assert(Thread->AsyncContexts);
	for (ULONG i = 0; i <= Thread->AsyncObjMaxId; i++) {
	    if (GetBit(Thread->AsyncObjUsedMap, i) && Thread->AsyncContexts[i]->DeliverApc) {
		NeedAsyncObjApc = TRUE;
		break;
	    }
	}
    }
    return IsListEmpty(&Thread->QueuedApcList) && !NeedAsyncObjApc;
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
     * If the event type is a synchronization event, decrease the signal count.
     * Check the APC queue and return. */
    if (DispatcherObject->SignalState) {
	if (DispatcherObject->EventType == SynchronizationEvent) {
	    DispatcherObject->SignalState--;
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

    /* Check whether the wait is satisfied. Return immediately if it is. */
    if (WaitType == WaitAny) {
	for (ULONG i = 0; i < Count; i++) {
	    if (DispatcherObjects[i]->SignalState) {
		if (DispatcherObjects[i]->EventType == SynchronizationEvent) {
		    DispatcherObjects[i]->SignalState--;
		}
		if (Alertable && !KiApcQueueIsEmpty(Thread)) {
		    ASYNC_RETURN(State, STATUS_USER_APC);
		} else {
		    ASYNC_RETURN(State, STATUS_SUCCESS);
		}
	    }
	}
    } else {
	assert(WaitType == WaitAll);
	BOOLEAN Satisfied = TRUE;
	for (ULONG i = 0; i < Count; i++) {
	    if (!DispatcherObjects[i]->SignalState) {
		Satisfied = FALSE;
		break;
	    }
	}
	if (Satisfied) {
	    for (ULONG i = 0; i < Count; i++) {
		if (DispatcherObjects[i]->EventType == SynchronizationEvent) {
		    DispatcherObjects[i]->SignalState--;
		}
	    }
	    if (Alertable && !KiApcQueueIsEmpty(Thread)) {
		ASYNC_RETURN(State, STATUS_USER_APC);
	    } else {
		ASYNC_RETURN(State, STATUS_SUCCESS);
	    }
	}
    }

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

/* This routine should only be called during thread object creation. */
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
    Thread->AsyncContexts[0] = AsyncCtx;
    return STATUS_SUCCESS;
}

/* This routine should only be called during thread object deletion. */
VOID KeDeallocateThreadAsyncContexts(IN PTHREAD Thread)
{
    if (!Thread->AsyncContexts) {
	return;
    }

    for (ULONG i = 0; i <= Thread->AsyncObjMaxId; i++) {
	PASYNC_CONTEXT AsyncCtx = Thread->AsyncContexts[i];
	if (!AsyncCtx) {
	    continue;
	}
	/* By the time this routine is called, none of the async contexts should
	 * be active. */
	assert(!Thread->AsyncContexts[i]->Thread);
	if (AsyncCtx->SavedMsgBuf) {
	    assert(AsyncCtx->SavedMsgBufSize);
	    ExFreePoolWithTag(AsyncCtx->SavedMsgBuf, NTOS_KE_TAG);
	}
	ExFreePoolWithTag(AsyncCtx, NTOS_KE_TAG);
	Thread->AsyncContexts[i] = NULL;
    }
    Thread->AsyncObjMaxId = 0;
    if (Thread->AsyncObjUsedMap) {
	ExFreePoolWithTag(Thread->AsyncObjUsedMap, NTOS_KE_TAG);
	Thread->AsyncObjUsedMap = NULL;
    }
    ExFreePoolWithTag(Thread->AsyncContexts, NTOS_KE_TAG);
    Thread->AsyncContexts = NULL;
}

static VOID KiCancelInactiveAsyncContext(IN PASYNC_CONTEXT AsyncCtx)
{
    /* Set the cancel flag for every async frame in the async context, and
     * call the service handler to cancel the async ops. Note we need to do
     * this even if the thread is in synchronous execution mode. */
    ASYNC_WALK_STACK(StackPtr, AsyncCtx->AsyncStack,
		     ASYNC_MAX_CALL_STACK, Frame, {
	    Frame->LineNum |= _ASYNC_CANCELED_FLAG;
	});
    PTHREAD Thread = AsyncCtx->Thread;
    assert(Thread);
    assert(Thread->AsyncContexts[AsyncCtx->AsyncObjId] == AsyncCtx);
    NTSTATUS Status = KiAsyncContinue(AsyncCtx);
    if (Status != STATUS_ASYNC_CANCELED) {
	DbgTrace("Async context %p (thread %s|%p async obj id %d max id %d svc num %d wdm %d) "
		 "returned invalid async status 0x%x during cancel.\n",
		 AsyncCtx, KEDBG_THREAD_TO_FILENAME(Thread), Thread,
		 AsyncCtx->AsyncObjId, Thread->AsyncObjMaxId, AsyncCtx->SvcNum,
		 AsyncCtx->WdmSvc, Status);
	assert(FALSE);
    }
    /* Cancel and remove the wait timer used by KeWaitForSingleObject and
     * KeWaitForMultipleObjects */
    KeCancelTimer(&AsyncCtx->WaitTimer);
    KiRemoveTimer(&AsyncCtx->WaitTimer);
    KiPutAsyncContext(AsyncCtx);
}

/*
 * This routine will cancel all inactive async contexts of a thread.
 */
VOID KeCancelThreadInactiveAsyncContexts(IN PTHREAD Thread,
					 IN OPTIONAL PASYNC_CONTEXT ActiveAsyncCtx)
{
    if (Thread->AsyncContexts) {
	for (ULONG i = 0; i <= Thread->AsyncObjMaxId; i++) {
	    if (Thread->AsyncContexts[i] && Thread->AsyncContexts[i]->Thread &&
		Thread->AsyncContexts[i] != ActiveAsyncCtx) {
		KiCancelInactiveAsyncContext(Thread->AsyncContexts[i]);
	    }
	}
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
 * Return true if the thread is in an alertable wait and its APC queue is
 * not empty.
 */
static inline BOOLEAN KiShouldWakeThread(IN PTHREAD Thread)
{
    return Thread->Alertable && !KiApcQueueIsEmpty(Thread);
}

/*
 * If the thread object associated with the async context is running in
 * synchronous execution mode, simply wake up the thread. If the thread
 * has asynchronous execution enabled, queue an APC object to the thread
 * to pass the async object id to the client, and resume the thread if
 * the thread is in an alertable wait.
 */
static inline VOID KiResumeAsyncContext(IN PASYNC_CONTEXT AsyncContext)
{
    DbgTrace("Resume async context id %d (max id %d) of thread %s|%p\n",
	     AsyncContext->AsyncObjId, AsyncContext->Thread->AsyncObjMaxId,
	     KEDBG_THREAD_TO_FILENAME(AsyncContext->Thread), AsyncContext->Thread);
    assert(AsyncContext);
    AsyncContext->Pending = TRUE;

    PTHREAD Thread = AsyncContext->Thread;
    assert(Thread);
    if (Thread->AsyncObjMaxId) {
	if (Thread->AsyncResumeRoutine) {
	    ULONG_PTR AsyncObjId = AsyncContext->AsyncObjId;
	    NTSTATUS Status = KeQueueApcToThread(Thread, (PVOID)Thread->AsyncResumeRoutine,
						 Thread->AsyncRoutineContext,
						 (PVOID)AsyncObjId, NULL);
	    if (!NT_SUCCESS(Status)) {
		/* If we failed to queue an APC (due to out-of-memory), mark it as
		 * needing an APC delivery so we can deliver APC later. */
		AsyncContext->DeliverApc = TRUE;
	    }
	    if (KiShouldWakeThread(Thread)) {
		KiResumeThread(Thread);
	    }
	}
	if (Thread->AsyncNotification.TreeNode.Cap) {
	    seL4_Signal(Thread->AsyncNotification.TreeNode.Cap);
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
    BOOLEAN Satisfied = Block->Dispatcher ? Block->Dispatcher->SignalState : TRUE;
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
    if (Thread->AsyncObjMaxId) {
	assert(Thread->AsyncObjUsedMap);
	assert(Thread->AsyncContexts);
	while (NumApc < MaxNumApc) {
	    for (ULONG i = 0; i <= Thread->AsyncObjMaxId; i++) {
		if (GetBit(Thread->AsyncObjUsedMap, i) &&
		    Thread->AsyncContexts[i]->DeliverApc) {
		    DestApc[NumApc].ApcType = APC_TYPE_KAPC;
		    DestApc[NumApc].ApcRoutine = (PVOID)Thread->AsyncResumeRoutine;
		    RtlZeroMemory(DestApc[NumApc].ApcContext,
				  sizeof(DestApc[NumApc].ApcContext));
		    DestApc[NumApc].ApcContext[0] = Thread->AsyncRoutineContext;
		    DestApc[NumApc].ApcContext[1] =
			(PVOID)(ULONG_PTR)Thread->AsyncContexts[i]->AsyncObjId;
		    Thread->AsyncContexts[i]->DeliverApc = FALSE;
		    NumApc++;
		}
	    }
	}
    }
    *MoreToCome = !KiApcQueueIsEmpty(Thread);
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
    assert(Dispatcher->SignalState >= 0);
    if (Dispatcher->SignalState) {
	DbgTrace("Increasing dispatcher signal state %p (%d -> %d)\n",
		 Dispatcher, Dispatcher->SignalState,
		 min(Dispatcher->SignalState + 1, Dispatcher->Limit));
    }
    Dispatcher->SignalState++;
    if (Dispatcher->SignalState > Dispatcher->Limit) {
	Dispatcher->SignalState = Dispatcher->Limit;
    }
    /* Walk the wait block list and wake the thread up */
    LoopOverList(Block, &Dispatcher->WaitBlockList, KWAIT_BLOCK, DispatcherLink) {
	assert(Block->AsyncContext != NULL);
	if (KiShouldWakeAsyncContext(Block->AsyncContext)) {
	    KiResumeAsyncContext(Block->AsyncContext);
	    /* If the dispatcher is a synchronization dispatcher, decrease its
	     * signal state and exit the loop if it is no longer signaled (we
	     * only wake up one async context). */
	    if (Dispatcher->EventType == SynchronizationEvent) {
		Dispatcher->SignalState--;
		assert(Dispatcher->SignalState >= 0);
		if (!Dispatcher->SignalState) {
		    break;
		}
	    }
	}
    }
}

NTSTATUS NtTestAlert(IN ASYNC_STATE State)
{
    if (KiApcQueueIsEmpty(State.AsyncContext->Thread)) {
	return STATUS_USER_APC;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtQueueApcThread(IN ASYNC_STATE AsyncState,
			  IN HANDLE ThreadHandle,
			  IN PKNORMAL_ROUTINE ApcRoutine,
			  IN OPTIONAL PVOID NormalContext,
			  IN OPTIONAL PVOID SystemArgument1,
			  IN OPTIONAL PVOID SystemArgument2)
{
    assert(AsyncState.AsyncContext->Thread);
    PTHREAD Thread = NULL;
    RET_ERR(ObReferenceObjectByHandle(AsyncState.AsyncContext->Thread,
				      ThreadHandle, OBJECT_TYPE_THREAD, (POBJECT *)&Thread));
    RET_ERR(KeQueueApcToThread(Thread, ApcRoutine, NormalContext,
			       SystemArgument1, SystemArgument2));
    ObDereferenceObject(Thread);
    return STATUS_SUCCESS;
}

NTSTATUS NtSetThreadExecutionMode(IN PTHREAD Thread,
				  IN PTHREAD_EXECUTION_MODE ExecutionMode)
{
    assert(Thread);
    assert(ExecutionMode);
    /* We do not support disabling asynchronous execution mode once it is enabled. */
    if (!ExecutionMode->AsyncObjMaxId) {
	return STATUS_INVALID_PARAMETER;
    }
    /* We don't support decreasing the number of concurrent async contexts. */
    if (ExecutionMode->AsyncObjMaxId < Thread->AsyncObjMaxId) {
	return STATUS_INVALID_PARAMETER;
    }
    if (ExecutionMode->AsyncObjMaxId == Thread->AsyncObjMaxId) {
	return STATUS_SUCCESS;
    }

    PASYNC_CONTEXT *AsyncContexts =
	ExAllocatePoolWithTag(sizeof(PVOID) * (ExecutionMode->AsyncObjMaxId + 1),
			      NTOS_KE_TAG);
    if (!AsyncContexts) {
	return STATUS_NO_MEMORY;
    }
    MWORD *UsedMap =
	ExAllocatePoolWithTag((ExecutionMode->AsyncObjMaxId + MWORD_BITS) / MWORD_BITS,
			      NTOS_KE_TAG);
    if (!UsedMap) {
	ExFreePoolWithTag(AsyncContexts, NTOS_KE_TAG);
	return STATUS_NO_MEMORY;
    }

    NTSTATUS Status = STATUS_SUCCESS;
    if (ExecutionMode->Flags & THREAD_ASYNC_DELIVER_SPECIAL_APC) {
	Status = STATUS_NOT_IMPLEMENTED;
	goto Error;
    }

    if (ExecutionMode->Flags & THREAD_ASYNC_SIGNAL_NOTIFICATION) {
	extern CNODE MiNtosCNode;
	PIO_DRIVER_OBJECT DriverObject = IoGetDriverObjectFromProcess(Thread->Process);
	if (Thread->DpcThread) {
	    IF_ERR_GOTO(Error, Status, KeDeriveNotification(&Thread->AsyncNotification,
							    &MiNtosCNode,
							    &DriverObject->DpcNotification,
							    ASYNC_NOTIFICATION_BADGE));
	} else if (Thread->IsrThread) {
	    LoopOverList(Interrupt, &DriverObject->InterruptServiceList,
			 INTERRUPT_SERVICE, Link) {
		PTHREAD IsrThread = NULL;
		Status = ObReferenceObjectByHandle(Thread, Interrupt->ThreadHandle,
						   OBJECT_TYPE_THREAD,
						   (PVOID)&IsrThread);
		assert(NT_SUCCESS(Status));
		if (IsrThread) {
		    ObDereferenceObject(IsrThread);
		    if (IsrThread == Thread) {
			IF_ERR_GOTO(Error, Status,
				    KeDeriveNotification(&Thread->AsyncNotification,
							 &MiNtosCNode,
							 &Interrupt->Notification,
							 ASYNC_NOTIFICATION_BADGE));
			break;
		    }
		}
	    }
	    assert(FALSE);
	} else if (DriverObject && Thread->InitialThread) {
	    IF_ERR_GOTO(Error, Status, KeDeriveNotification(&Thread->AsyncNotification,
							    &MiNtosCNode,
							    &DriverObject->EventLoopNotification,
							    ASYNC_NOTIFICATION_BADGE));
	} else {
	    IF_ERR_GOTO(Error, Status, KeCreateNotification(&Thread->AsyncNotification));
	    Status = KiBindNotificationToThread(Thread->TreeNode.Cap,
						Thread->AsyncNotification.TreeNode.Cap);
	    if (!NT_SUCCESS(Status)) {
		KeDestroyNotification(&Thread->AsyncNotification);
	    }
	}
    }

    ULONG OldAsyncObjMaxId = Thread->AsyncObjMaxId;
    PASYNC_CONTEXT DefaultAsyncCtx = NULL;
    if (!OldAsyncObjMaxId) {
	KiGetAsyncContext(Thread, 0, &DefaultAsyncCtx);
	assert(DefaultAsyncCtx);
    }
    Thread->AsyncObjMaxId = ExecutionMode->AsyncObjMaxId;
    RtlCopyMemory(AsyncContexts, Thread->AsyncContexts,
		  sizeof(PVOID) * (OldAsyncObjMaxId + 1));
    ExFreePoolWithTag(Thread->AsyncContexts, NTOS_KE_TAG);
    if (Thread->AsyncObjUsedMap) {
	RtlCopyMemory(UsedMap, Thread->AsyncObjUsedMap,
		      (OldAsyncObjMaxId + MWORD_BITS) / MWORD_BITS);
	ExFreePoolWithTag(Thread->AsyncObjUsedMap, NTOS_KE_TAG);
    }
    Thread->AsyncObjUsedMap = UsedMap;
    Thread->AsyncContexts = AsyncContexts;
    if (!OldAsyncObjMaxId) {
	KiPutAsyncContext(DefaultAsyncCtx);
    }
    Thread->AsyncResumeRoutine = ExecutionMode->ResumeRoutine;
    Thread->AsyncRoutineContext = ExecutionMode->ApcContext;
    return STATUS_SUCCESS;

Error:
    ExFreePoolWithTag(AsyncContexts, NTOS_KE_TAG);
    ExFreePoolWithTag(UsedMap, NTOS_KE_TAG);
    return Status;
}

NTSTATUS NtAsyncContinue(IN PTHREAD Thread,
			 IN ULONG AsyncObjId)
{
    assert(Thread);
    if (!Thread->AsyncObjMaxId || AsyncObjId > Thread->AsyncObjMaxId) {
	return STATUS_INVALID_PARAMETER;
    }
    if (!GetBit(Thread->AsyncObjUsedMap, AsyncObjId)) {
	return STATUS_ASYNC_INVALID_ID;
    }
    PASYNC_CONTEXT AsyncCtx = Thread->AsyncContexts[AsyncObjId];
    if (!AsyncCtx->Pending) {
	return STATUS_ASYNC_NOT_READY;
    }
    AsyncCtx->Pending = FALSE;
    NTSTATUS Status = KiAsyncContinue(AsyncCtx);
    if (Status != STATUS_ASYNC_PENDING) {
	KiPutAsyncContext(AsyncCtx);
    }
    return Status;
}

NTSTATUS NtAsyncCancel(IN PTHREAD Thread,
		       IN ULONG AsyncObjId)
{
    assert(Thread);
    if (!Thread->AsyncObjMaxId || AsyncObjId > Thread->AsyncObjMaxId) {
	return STATUS_INVALID_PARAMETER;
    }
    if (!GetBit(Thread->AsyncObjUsedMap, AsyncObjId)) {
	return STATUS_ASYNC_INVALID_ID;
    }
    KiCancelInactiveAsyncContext(Thread->AsyncContexts[AsyncObjId]);
    return STATUS_SUCCESS;
}
