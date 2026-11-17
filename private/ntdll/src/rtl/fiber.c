#include "rtlp.h"

VOID RtlpRundownFls(IN PRTL_FLS_DATA FlsData)
{
    if (!FlsData) {
	return;
    }

    RtlAcquirePebLock();
    PPEB Peb = NtCurrentPeb();
    ULONG FlsHighIndex = Peb->FlsHighIndex;
    RemoveEntryList(&FlsData->ListEntry);
    RtlReleasePebLock();

    for (ULONG n = 1; n <= FlsHighIndex; ++n) {
	PFLS_CALLBACK_FUNCTION Callback = Peb->FlsCallback[n];
	if (Callback && FlsData->Data[n]) {
	    Callback(FlsData->Data[n]);
	}
    }

    RtlFreeHeap(RtlGetProcessHeap(), 0, FlsData);
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS RtlConvertThreadToFiber(IN OPTIONAL LPVOID Parameter,
				       IN BOOLEAN SaveFpuState)
{
    /* Are we already a fiber? */
    PTEB Teb = NtCurrentTeb();
    if (Teb->NtTib.FiberData) {
	return STATUS_ALREADY_INITIALIZED;
    }

    /* Allocate the fiber */
    PFIBER Fiber = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(FIBER));
    if (!Fiber) {
	return STATUS_NO_MEMORY;
    }

    /* Copy some contextual data from the thread to the fiber */
    Fiber->FiberData = Parameter;
    Fiber->ExceptionList = Teb->NtTib.ExceptionList;
    Fiber->StackBase = Teb->NtTib.StackBase;
    Fiber->StackLimit = Teb->NtTib.StackLimit;
    Fiber->DeallocationStack = Teb->NtTib.DeallocationStack;
    Fiber->FlsData = Teb->FlsData;
    Fiber->GuaranteedStackBytes = Teb->GuaranteedStackBytes;
    Fiber->ActivationContextStackPointer = Teb->ActivationContextStackPointer;

    /* Save FPU State if requested, otherwise just the basic registers */
    Fiber->FiberContext.ContextFlags = CONTEXT_FULL;
    if (SaveFpuState) {
	Fiber->FiberContext.ContextFlags |= CONTEXT_FLOATING_POINT;
    }

    /* Associate the fiber to the current thread */
    Teb->NtTib.FiberData = Fiber;

    return STATUS_SUCCESS;
}

NTAPI NTSTATUS RtlConvertFiberToThread(VOID)
{
    /* Check if the thread is already not a fiber */
    PTEB Teb = NtCurrentTeb();
    if (!Teb->NtTib.FiberData) {
	return STATUS_ALREADY_INITIALIZED;
    }

    /* This thread won't run a fiber anymore */
    PFIBER FiberData = Teb->NtTib.FiberData;
    Teb->NtTib.FiberData = NULL;

    /* Free the fiber */
    ASSERT(FiberData != NULL);
    RtlFreeHeap(RtlGetProcessHeap(), 0, FiberData);

    /* Success */
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlCreateFiber(IN SIZE_T StackCommitSize,
			      IN SIZE_T StackReserveSize,
			      IN BOOLEAN SaveFpuState,
			      IN PRTL_FIBER_STACK_ALLOCATION_ROUTINE AllocateStack,
			      IN PVOID FiberData,
			      OUT PFIBER *pFiber)
{
    *pFiber = NULL;
    /* Allocate the Activation Context Stack */
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer = NULL;
    NTSTATUS Status = RtlAllocateActivationContextStack(&ActivationContextStackPointer);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Allocate the fiber */
    PFIBER Fiber = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FIBER));
    if (!Fiber) {
	/* Free the activation context stack */
	RtlFreeActivationContextStack(ActivationContextStackPointer);
	return STATUS_NO_MEMORY;
    }

    /* Create the stack for the fiber */
    INITIAL_TEB InitialTeb = {};
    Status = AllocateStack(StackCommitSize, StackReserveSize, &InitialTeb);
    if (!NT_SUCCESS(Status)) {
	/* Free the fiber */
	RtlFreeHeap(RtlGetProcessHeap(), 0, Fiber);

	/* Free the activation context stack */
	RtlFreeActivationContextStack(ActivationContextStackPointer);
	return Status;
    }

    /* Copy the data into the fiber */
    Fiber->StackBase = InitialTeb.StackBase;
    Fiber->StackLimit = InitialTeb.StackLimit;
    Fiber->DeallocationStack = InitialTeb.AllocatedStackBase;
    Fiber->FiberData = FiberData;
    Fiber->ExceptionList = EXCEPTION_CHAIN_END;
    Fiber->ActivationContextStackPointer = ActivationContextStackPointer;

    /* Save FPU State if requested, otherwise just the basic registers */
    Fiber->FiberContext.ContextFlags = CONTEXT_FULL;
    if (SaveFpuState) {
	Fiber->FiberContext.ContextFlags |= CONTEXT_FLOATING_POINT;
    }
    *pFiber = Fiber;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI VOID RtlDeleteFiber(IN PFIBER Fiber,
			  IN PRTL_FIBER_STACK_DEALLOCATION_ROUTINE DeallocateStack)
{
    /* If the fiber is currently running, do nothing. */
    if (NtCurrentTeb()->NtTib.FiberData == Fiber) {
	return;
    }

    DeallocateStack(Fiber->DeallocationStack);

    /* Get rid of FLS */
    if (Fiber->FlsData)
	RtlpRundownFls(Fiber->FlsData);

    /* Get rid of the activation context stack */
    RtlFreeActivationContextStack(Fiber->ActivationContextStackPointer);

    /* Free the fiber data */
    RtlFreeHeap(RtlGetProcessHeap(), 0, Fiber);
}

/*
 * @implemented
 */
NTAPI ULONG RtlSwitchToFiber(IN PFIBER Fiber)
{
    PTEB Teb = NtCurrentTeb();
    PFIBER CurrentFiber = (PFIBER)Teb->NtTib.FiberData;
    PFIBER NewFiber = (PFIBER)Fiber;

    /* Save the running fiber's TEB-derived state */
    CurrentFiber->FlsData = Teb->FlsData;
    CurrentFiber->ActivationContextStackPointer = Teb->ActivationContextStackPointer;
    CurrentFiber->ExceptionList = Teb->NtTib.ExceptionList;
    CurrentFiber->StackBase = Teb->NtTib.StackBase;
    CurrentFiber->StackLimit = Teb->NtTib.StackLimit;
    CurrentFiber->DeallocationStack = Teb->NtTib.DeallocationStack;
    CurrentFiber->GuaranteedStackBytes = Teb->GuaranteedStackBytes;

    /* Capture the running fiber's registers/stack. The instruction pointer
     * captured points to the instruction immediately after the call to
     * RtlpCaptureFiberContext. */
    FIBER_CONTINUATION_STATUS Status = RtlpCaptureFiberContext(&CurrentFiber->FiberContext);

    /* When this fiber is later scheduled again, RtlpRestoreFiberContext()
     * returns execution right here, and Switched will be set to TRUE, in which
     * case we should return. If Switched is FALSE, we have not switched, and
     * should go ahead and load the new fiber context. */
    if (Status.Switched) {
	return Status.Status;
    }

    /* Make the target fiber current and load its TEB-derived state */
    Teb->NtTib.FiberData = NewFiber;
    Teb->NtTib.ExceptionList = NewFiber->ExceptionList;
    Teb->NtTib.StackBase = NewFiber->StackBase;
    Teb->NtTib.StackLimit = NewFiber->StackLimit;
    Teb->NtTib.DeallocationStack = NewFiber->DeallocationStack;
    Teb->GuaranteedStackBytes = NewFiber->GuaranteedStackBytes;
    Teb->ActivationContextStackPointer = NewFiber->ActivationContextStackPointer;
    Teb->FlsData = NewFiber->FlsData;

#ifdef _M_ARM64
    /* Keep the current thread's TEB pointer (X18). On Windows ARM64 x18 holds
     * the TEB pointer and is *per-thread*, never per-fiber. Native ARM64 CONTEXT
     * exposes x18, so before resuming a native fiber we overwrite its saved x18
     * with the current thread's TEB. */
    NewFiber->FiberContext.X18 = (ULONG_PTR)Teb;
#elif defined(_M_RISCV64)
    /* Similar to ARM64, we need to overwrite the thread pointer with the TEB. */
    NewFiber->FiberContext.Tp = (ULONG_PTR)Teb;
#endif

    /* Switch into the target fiber; this does not return */
    RtlpRestoreFiberContext(&NewFiber->FiberContext);
    __builtin_unreachable();
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlFlsAlloc(PFLS_CALLBACK_FUNCTION Callback,
			   OUT ULONG *pFlsIndex)
{
    PPEB Peb = NtCurrentPeb();
    RtlAcquirePebLock();

    NTSTATUS Status = STATUS_SUCCESS;
    if (!Peb->FlsCallback &&
	!(Peb->FlsCallback = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
					     RTL_FLS_MAXIMUM_AVAILABLE * sizeof(PVOID)))) {
	Status = STATUS_NO_MEMORY;
	goto done;
    }

    ULONG FlsIndex = RtlFindClearBitsAndSet(Peb->FlsBitmap, 1, 1);
    if (FlsIndex == FLS_OUT_OF_INDEXES) {
	Status = STATUS_NO_MORE_ENTRIES;
	goto done;
    }

    PRTL_FLS_DATA FlsData = NtCurrentTeb()->FlsData;
    if (!FlsData &&
	!(FlsData = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				    sizeof(RTL_FLS_DATA)))) {
	RtlClearBits(Peb->FlsBitmap, FlsIndex, 1);
	Status = STATUS_NO_MEMORY;
	goto done;
    }

    if (!NtCurrentTeb()->FlsData) {
	NtCurrentTeb()->FlsData = FlsData;
	InsertTailList(&Peb->FlsListHead, &FlsData->ListEntry);
    }

    FlsData->Data[FlsIndex] = NULL;
    Peb->FlsCallback[FlsIndex] = Callback;

    if (FlsIndex > Peb->FlsHighIndex)
	Peb->FlsHighIndex = FlsIndex;

done:
    if (NT_SUCCESS(Status)) {
	assert(FlsIndex != FLS_OUT_OF_INDEXES);
	*pFlsIndex = FlsIndex;
    } else {
	*pFlsIndex = FLS_OUT_OF_INDEXES;
    }
    RtlReleasePebLock();
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlFlsFree(ULONG FlsIndex)
{
    PPEB Peb = NtCurrentPeb();

    if (FlsIndex >= RTL_FLS_MAXIMUM_AVAILABLE) {
	return STATUS_INVALID_PARAMETER;
    }

    RtlAcquirePebLock();
    BOOLEAN Ret = RtlAreBitsSet(Peb->FlsBitmap, FlsIndex, 1);
    if (!Ret) {
	RtlReleasePebLock();
	return STATUS_INVALID_PARAMETER;
    }

    RtlClearBits(Peb->FlsBitmap, FlsIndex, 1);
    PFLS_CALLBACK_FUNCTION Callback = Peb->FlsCallback[FlsIndex];

    LoopOverList(FlsData, &Peb->FlsListHead, RTL_FLS_DATA, ListEntry) {
	if (FlsData->Data[FlsIndex]) {
	    if (Callback) {
		Callback(FlsData->Data[FlsIndex]);
	    }
	    FlsData->Data[FlsIndex] = NULL;
	}
    }
    Peb->FlsCallback[FlsIndex] = NULL;
    RtlReleasePebLock();
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI PVOID RtlFlsGetValue(ULONG FlsIndex)
{
    PRTL_FLS_DATA FlsData = NtCurrentTeb()->FlsData;
    if (!FlsIndex || FlsIndex >= RTL_FLS_MAXIMUM_AVAILABLE || !FlsData) {
	return NULL;
    }
    return FlsData->Data[FlsIndex];
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlFlsSetValue(ULONG FlsIndex, PVOID Data)
{
    if (!FlsIndex || FlsIndex >= RTL_FLS_MAXIMUM_AVAILABLE) {
	return STATUS_INVALID_PARAMETER;
    }

    PTEB Teb = NtCurrentTeb();

    if (!Teb->FlsData) {
	Teb->FlsData = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				       sizeof(RTL_FLS_DATA));
	if (!Teb->FlsData) {
	    return STATUS_NO_MEMORY;
	}
	RtlAcquirePebLock();
	InsertTailList(&Teb->ProcessEnvironmentBlock->FlsListHead,
		       &Teb->FlsData->ListEntry);
	RtlReleasePebLock();
    }

    Teb->FlsData->Data[FlsIndex] = Data;
    return STATUS_SUCCESS;
}
