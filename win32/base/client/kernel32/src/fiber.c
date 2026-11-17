/*
 * PROJECT:     ReactOS System Libraries
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Fiber Implementation
 * COPYRIGHT:   Copyright 2005-2011 Alex Ionescu (alex@relsoft.net)
 *              Copyright 2003-2008 KJK::Hyperion (noog@libero.it)
 *              Copyright 2018 Mark Jansen (mark.jansen@reactos.org)
 */

#include <k32.h>

/*
 * @implemented
 *
 * Entry point of a freshly scheduled fiber.
 */
WINAPI DECLSPEC_NORETURN VOID BaseFiberStartup(VOID)
{
    PFIBER Fiber = (PFIBER)NtCurrentTeb()->NtTib.FiberData;
#ifdef _M_IX86
    /* For i386, BaseInitializeContext() initializes the fiber context with
     * the start routine in eax and its single parameter in ebx. */
    ULONG_PTR StartRoutine = Fiber->FiberContext.Eax;
    ULONG_PTR Parameter = Fiber->FiberContext.Ebx;
#elif defined(_M_AMD64)
    /* For amd64, BaseInitializeContext() initializes the fiber context with
     * the start routine in rcx and its single parameter in rdx. */
    ULONG_PTR StartRoutine = Fiber->FiberContext.Rcx;
    ULONG_PTR Parameter = Fiber->FiberContext.Rdx;
#elif defined(_M_ARM64)
    /* For arm64, BaseInitializeContext() initializes the fiber context with
     * the start routine in X0 and its single parameter in X1. */
    ULONG_PTR StartRoutine = Fiber->FiberContext.X0;
    ULONG_PTR Parameter = Fiber->FiberContext.X1;
#else
#error "Unsupported architecture"
#endif
    BaseThreadStartup((LPTHREAD_START_ROUTINE)StartRoutine, (LPVOID)Parameter);
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
WINAPI BOOL ConvertFiberToThread(VOID)
{
    NTSTATUS Status = RtlConvertFiberToThread();
    if (Status == STATUS_ALREADY_INITIALIZED) {
	SetLastError(ERROR_ALREADY_FIBER);
    }
    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
WINAPI LPVOID ConvertThreadToFiberEx(_In_opt_ LPVOID lpParameter, _In_ DWORD dwFlags)
{
    DPRINT1("Converting Thread to Fiber\n");

    /* Check for invalid flags */
    if (dwFlags & ~FIBER_FLAG_FLOAT_SWITCH) {
	/* Fail */
	SetLastError(ERROR_INVALID_PARAMETER);
	return NULL;
    }

    NTSTATUS Status = RtlConvertThreadToFiber(lpParameter,
					      !!(dwFlags & FIBER_FLAG_FLOAT_SWITCH));
    if (!NT_SUCCESS(Status)) {
	if (Status == STATUS_ALREADY_INITIALIZED) {
	    SetLastError(ERROR_ALREADY_FIBER);
	} else {
	    BaseSetLastNTError(Status);
	}
	return NULL;
    }

    assert(NtCurrentTeb()->NtTib.FiberData);
    return NtCurrentTeb()->NtTib.FiberData;
}

/*
 * @implemented
 */
WINAPI LPVOID ConvertThreadToFiber(_In_opt_ LPVOID lpParameter)
{
    /* Call the newer function */
    return ConvertThreadToFiberEx(lpParameter, 0);
}

/*
 * @implemented
 */
WINAPI LPVOID CreateFiber(_In_ SIZE_T dwStackSize,
			  _In_ LPFIBER_START_ROUTINE lpStartAddress,
			  _In_opt_ LPVOID lpParameter)
{
    /* Call the Newer Function */
    return CreateFiberEx(dwStackSize, 0, 0, lpStartAddress, lpParameter);
}

static NTAPI NTSTATUS BasepCreaetFiberStack(IN SIZE_T StackCommitSize,
					    IN SIZE_T StackReserveSize,
					    OUT PINITIAL_TEB InitialTeb)
{
    return BaseCreateStack(NtCurrentProcess(), StackCommitSize, StackReserveSize,
			   InitialTeb);
}

/*
 * @implemented
 */
WINAPI LPVOID CreateFiberEx(_In_ SIZE_T dwStackCommitSize, _In_ SIZE_T dwStackReserveSize,
			    _In_ DWORD dwFlags, _In_ LPFIBER_START_ROUTINE lpStartAddress,
			    _In_opt_ LPVOID lpParameter)
{
    DPRINT("Creating Fiber\n");

    /* Check for invalid flags */
    if (dwFlags & ~FIBER_FLAG_FLOAT_SWITCH) {
	/* Fail */
	SetLastError(ERROR_INVALID_PARAMETER);
	return NULL;
    }

    PFIBER Fiber = NULL;
    NTSTATUS Status = RtlCreateFiber(dwStackCommitSize, dwStackReserveSize,
				     !!(dwFlags & FIBER_FLAG_FLOAT_SWITCH),
				     BasepCreaetFiberStack, lpParameter, &Fiber);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return NULL;
    }

    /* Initialize the context for the fiber */
    BaseInitializeContext(&Fiber->FiberContext, lpParameter, lpStartAddress,
			  Fiber->StackBase, 2);

    /* Return the Fiber */
    return Fiber;
}

static NTAPI VOID BasepDeallocateFiberStack(IN PVOID DeallocationStack)
{
    SIZE_T Size = 0;
    NtFreeVirtualMemory(NtCurrentProcess(), &DeallocationStack, &Size,
			MEM_RELEASE);
}

/*
 * @implemented
 */
WINAPI VOID DeleteFiber(_In_ LPVOID lpFiber)
{
    /* Are we deleting ourselves? */
    PTEB Teb = NtCurrentTeb();
    if ((Teb->NtTib.FiberData) && (Teb->NtTib.FiberData == lpFiber)) {
	/* Just exit */
	ExitThread(1);
    }
    RtlDeleteFiber(lpFiber, BasepDeallocateFiberStack);
}

/*
 * @implemented
 */
WINAPI BOOL IsThreadAFiber(VOID)
{
    /* Return flag in the TEB */
    return !!NtCurrentTeb()->NtTib.FiberData;
}

/*
 * @implemented
 */
WINAPI DWORD FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback)
{
    ULONG dwFlsIndex = FLS_OUT_OF_INDEXES;
    NTSTATUS Status = RtlFlsAlloc(lpCallback, &dwFlsIndex);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
    }
    return dwFlsIndex;
}

/*
 * @implemented
 */
WINAPI BOOL FlsFree(DWORD dwFlsIndex)
{
    NTSTATUS Status = RtlFlsFree(dwFlsIndex);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
    }
    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
WINAPI PVOID FlsGetValue(DWORD dwFlsIndex)
{
    PVOID Value = RtlFlsGetValue(dwFlsIndex);
    if (Value) {
	SetLastError(ERROR_SUCCESS);
    } else {
	SetLastError(ERROR_INVALID_PARAMETER);
    }
    return Value;
}

/*
 * @implemented
 */
WINAPI BOOL FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData)
{
    NTSTATUS Status = RtlFlsSetValue(dwFlsIndex, lpFlsData);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
    }
    return NT_SUCCESS(Status);
}

/* EOF */
