#include <wdmp.h>

static PVOID KiCoroutineStackChainHead;
static PFIBER KiMasterFiber;

/*
 * Returns the stack top of the first available coroutine stack.
 * Immediately before the stack top is the KI_COROUTINE_STACK structure.
 */
static NTAPI NTSTATUS KiGetFirstAvailableCoroutineStack(IN SIZE_T StackCommitSize,
							IN SIZE_T StackReserveSize,
							OUT PINITIAL_TEB InitialTeb)
{
    assert(StackCommitSize == DRIVER_COROUTINE_STACK_COMMIT);
    assert(StackReserveSize == DRIVER_COROUTINE_STACK_RESERVE);
    PVOID StackTop = KiCoroutineStackChainHead;
    while (StackTop != NULL) {
	PKI_COROUTINE_STACK_TOP Stack = (PKI_COROUTINE_STACK_TOP)StackTop - 1;
	if (Stack->Fiber == NULL) {
	    break;
	}
	StackTop = Stack->NextStackTop;
    }
    if (StackTop == NULL) {
	if (!NT_SUCCESS(WdmCreateCoroutineStack(&StackTop))) {
	    /* System is out of memory. Not much can be done here. */
	    assert(FALSE);
	    return STATUS_NO_MEMORY;
	}
	assert(StackTop != NULL);
	PKI_COROUTINE_STACK_TOP Stack = (PKI_COROUTINE_STACK_TOP)StackTop - 1;
	Stack->NextStackTop = KiCoroutineStackChainHead;
	KiCoroutineStackChainHead = StackTop;
	/* Just in case the server did not, clear the saved SP (seL4 always
	 * clears the page when allocating a new page, so this shouldn't
	 * happen, but we want to make sure there is no surprise). */
	assert(Stack->Fiber == NULL);
	Stack->Fiber = NULL;
    }
    InitialTeb->AllocatedStackBase = (PCHAR)StackTop - StackReserveSize;
    InitialTeb->StackBase = StackTop;
    InitialTeb->StackLimit = (PCHAR)StackTop - StackCommitSize;
    return STATUS_SUCCESS;
}

VOID KiDbgDumpCoroutineStacks(VOID)
{
    DbgTrace("Dumping coroutine stack chain head %p\n",
	     KiCoroutineStackChainHead);
    PKI_COROUTINE_STACK_TOP StackTop = KiCoroutineStackChainHead;
    while (StackTop != NULL) {
	DbgPrint("  (ST %p, FB %p)", StackTop, StackTop[-1].Fiber);
	StackTop = StackTop[-1].NextStackTop;
    }
    DbgPrint("\n");
}

static DECLSPEC_NORETURN VOID KiCoroutineEntryPoint(VOID)
{
    PFIBER Fiber = NtCurrentTeb()->NtTib.FiberData;
    assert(Fiber);
    PIOP_EXEC_ENV Env = Fiber->FiberData;
    assert(Env);
    NTSTATUS Status = Env->EntryPoint(Env->Context);
    KiMasterFiber->FiberContext.RETURN_VALUE = (ULONG)Status;
    RtlSwitchToFiber(KiMasterFiber);
    __builtin_unreachable();
}

static VOID KiInitializeFiberContext(IN PFIBER Fiber,
				     IN PIOP_EXEC_ENV Env)
{
    PCONTEXT Context = &Fiber->FiberContext;
    Context->INSTRUCTION_POINTER = (ULONG_PTR)KiCoroutineEntryPoint;
    Context->STACK_POINTER = (ULONG_PTR)((PKI_COROUTINE_STACK_TOP)Env->CoroutineStackTop - 1);
}

NTSTATUS KiStartCoroutine(IN PIOP_EXEC_ENV Env)
{
    assert(NtCurrentTeb()->NtTib.FiberData == KiMasterFiber);
    assert(!Env->CoroutineStackTop);
    PFIBER Fiber = NULL;
    RET_ERR(RtlCreateFiber(DRIVER_COROUTINE_STACK_COMMIT, DRIVER_COROUTINE_STACK_RESERVE,
			   TRUE, KiGetFirstAvailableCoroutineStack, Env, &Fiber));
    PVOID StackTop = Fiber->StackBase;
    KiSetCoroutineFiber(StackTop, Fiber);
    Env->CoroutineStackTop = StackTop;
    /* Switch to the coroutine stack and call the entrypoint */
    DbgTrace("Switching to coroutine stack top %p (fiber %p)\n", StackTop,
	     KiGetCoroutineFiber(StackTop));
    KiInitializeFiberContext(Fiber, Env);
    return RtlSwitchToFiber(Fiber);
}

NTSTATUS KiResumeCoroutine(IN PIOP_EXEC_ENV Env)
{
    /* We are resuming a coroutine suspended due to, say KeWaitForSingleObject. */
    DbgTrace("Resuming coroutine stack top %p (entrypoint %p finalizer %p). "
	     "Fiber %p\n", Env->CoroutineStackTop, Env->EntryPoint,
	     Env->Finalizer, KiGetCoroutineFiber(Env->CoroutineStackTop));
    return RtlSwitchToFiber(KiGetCoroutineFiber(Env->CoroutineStackTop));
}

static NTAPI VOID KiDeallocateCoroutineStack(IN PVOID DeallocationStack)
{
    /* TODO: For now we do nothing and leave the stack in the chain.
     * Eventually we want to return the stack memory back to the NT
     * Executive if the system is under memory pressure. */
}

VOID KiStopCoroutine(PIOP_EXEC_ENV Env)
{
    if (!Env->CoroutineStackTop) {
	return;
    }
    PFIBER Fiber = KiGetCoroutineFiber(Env->CoroutineStackTop);
    DbgTrace("Releasing coroutine stack %p fiber %p\n",
	     Env->CoroutineStackTop, Fiber);
    assert(Fiber);
    RtlDeleteFiber(Fiber, KiDeallocateCoroutineStack);
    KiSetCoroutineFiber(Env->CoroutineStackTop, NULL);
    Env->CoroutineStackTop = NULL;
}

VOID KiYieldCoroutine(VOID)
{
    assert(KiMasterFiber);
    KiMasterFiber->FiberContext.RETURN_VALUE = (ULONG)STATUS_ASYNC_PENDING;
    RtlSwitchToFiber(KiMasterFiber);
}

NTSTATUS KiInitCoroutine(PVOID CoroutineChainHead)
{
    KiCoroutineStackChainHead = CoroutineChainHead;
    RET_ERR(RtlConvertThreadToFiber(NULL, TRUE));
    KiMasterFiber = NtCurrentTeb()->NtTib.FiberData;
    return STATUS_SUCCESS;
}
