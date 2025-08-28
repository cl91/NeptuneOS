/*++

Copyright (c) 2025  Dr. Chang Liu, PhD.

Module Name:

    thread.c

Abstract:

    Thread context routines for the ARM64 architecture

Revision History:

    2025-01-10  File created

--*/

#include "../rtlp.h"

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
    ThreadContext->Pc = (ULONG64)ThreadStartAddress;

    /* Set start parameter */
    ThreadContext->X0 = (ULONG64)ThreadStartParam;

    /* Only the basic Context is initialized */
    ThreadContext->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
}

/*
 * RtlpCallConsolidateCallback
 *
 * Wrapper function to call a consolidate callback from a fake frame. If the
 * callback executes RtlUnwindEx (like for example done in C++ handlers), we
 * have to skip all frames which were already processed. To do that we trick
 * the unwinding functions into thinking the call came from somewhere else.
 */
VOID DECLSPEC_NORETURN RtlpCallConsolidateCallback(PCONTEXT Context,
						   PVOID (*Callback)(PEXCEPTION_RECORD),
						   PEXCEPTION_RECORD ExceptionRecord);

VOID RtlRestoreContext(IN PCONTEXT Context,
		       IN PEXCEPTION_RECORD ExceptionRecord)
{
    if (ExceptionRecord && ExceptionRecord->NumberParameters >= 1) {
	if (ExceptionRecord->ExceptionCode == STATUS_LONGJUMP) {
	    _JUMP_BUFFER *JumpBuffer = (PVOID)ExceptionRecord->ExceptionInformation[0];

	    Context->X19  = JumpBuffer->X19;
	    Context->X20  = JumpBuffer->X20;
	    Context->X21  = JumpBuffer->X21;
	    Context->X22  = JumpBuffer->X22;
	    Context->X23  = JumpBuffer->X23;
	    Context->X24  = JumpBuffer->X24;
	    Context->X25  = JumpBuffer->X25;
	    Context->X26  = JumpBuffer->X26;
	    Context->X27  = JumpBuffer->X27;
	    Context->X28  = JumpBuffer->X28;
	    Context->Fp   = JumpBuffer->Fp;
	    Context->Pc   = JumpBuffer->Lr;
	    Context->Sp   = JumpBuffer->Sp;
	    Context->Fpcr = JumpBuffer->Fpcr;
	    Context->Fpsr = JumpBuffer->Fpsr;

	    for (int i = 0; i < 8; i++) {
		Context->V[8+i].D[0] = JumpBuffer->D[i];
	    }
	} else if (ExceptionRecord->ExceptionCode == STATUS_UNWIND_CONSOLIDATE) {
	    PVOID Callback = (PVOID)ExceptionRecord->ExceptionInformation[0];
	    DPRINT("Calling consolidate callback %p (rec=%p)\n", Callback, ExceptionRecord);
	    RtlpCallConsolidateCallback(Context, Callback, ExceptionRecord);
	}
    }

    DPRINT("returning to %llx stack %llx\n", Context->Pc, Context->Sp);
    NtContinue(Context, NULL);
}
