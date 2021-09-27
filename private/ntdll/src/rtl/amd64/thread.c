/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS Run-Time Library
 * PURPOSE:           AMD64 stubs
 * FILE:              lib/rtl/amd64/stubs.c
 * PROGRAMMERS:       Stefan Ginsberg (stefan.ginsberg@reactos.org)
 */

/* INCLUDES *****************************************************************/

#include "../rtlp.h"

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
NTAPI VOID RtlInitializeContext(IN HANDLE ProcessHandle,
				OUT PCONTEXT ThreadContext,
				IN PVOID ThreadStartParam OPTIONAL,
				IN PTHREAD_START_ROUTINE ThreadStartAddress,
				IN PINITIAL_TEB StackBase)
{
    /* Initialize everything to 0 */
    RtlZeroMemory(ThreadContext, sizeof(*ThreadContext));

    /* Initialize StartAddress and Stack */
    ThreadContext->Rip = (ULONG64) ThreadStartAddress;
    ThreadContext->Rsp = (ULONG64) StackBase - 6 * sizeof(PVOID);

    /* Align stack by 16 and substract 8 (unaligned on function entry) */
    ThreadContext->Rsp &= ~15;
    ThreadContext->Rsp -= 8;

    /* Enable Interrupts */
    ThreadContext->EFlags = EFLAGS_INTERRUPT_MASK;

    /* Set start parameter */
    ThreadContext->Rcx = (ULONG64) ThreadStartParam;

    /* Set the Selectors */
    if ((LONG64) ThreadStartAddress < 0) {
	/* Initialize kernel mode segments */
	ThreadContext->SegCs = 0;
	ThreadContext->SegDs = 0;
	ThreadContext->SegEs = 0;
	ThreadContext->SegFs = 0;
	ThreadContext->SegGs = (ULONG_PTR) NtCurrentTeb();
	ThreadContext->SegSs = 0;
    } else {
	/* Initialize user mode segments */
	ThreadContext->SegCs = 0;
	ThreadContext->SegDs = 0;
	ThreadContext->SegEs = 0;
	ThreadContext->SegFs = 0;
	ThreadContext->SegGs = (ULONG_PTR) NtCurrentTeb();
	ThreadContext->SegSs = 0;
    }

    /* Only the basic Context is initialized */
    ThreadContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

    return;
}
