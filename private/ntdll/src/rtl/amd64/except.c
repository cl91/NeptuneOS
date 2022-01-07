/*
 * PROJECT:     ReactOS Run-Time Library
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     User-mode exception support for AMD64
 * COPYRIGHT:   Copyright 2018-2021 Timo Kreuzer <timo.kreuzer@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "../rtlp.h"

/* PUBLIC FUNCTIONS **********************************************************/

NTAPI VOID RtlRaiseException(IN PEXCEPTION_RECORD ExceptionRecord)
{
    CONTEXT Context;
    NTSTATUS Status = STATUS_INVALID_DISPOSITION;

    /* Capture the current context */
    RtlCaptureContext(&Context);

    /* Fix up Context.Rip for the caller */
    Context.Rip = (ULONG64) _ReturnAddress();

    /* Fix up Context.Rsp for the caller */
    Context.Rsp = (ULONG64) _AddressOfReturnAddress() + 8;

    /* Save the exception address */
    ExceptionRecord->ExceptionAddress = (PVOID) Context.Rip;

    /* Check if user mode debugger is active */
    if (RtlpCheckForActiveDebugger()) {
	/* Raise an exception immediately */
	Status = NtRaiseException(ExceptionRecord, &Context, TRUE);
    } else {
	/* Dispatch the exception and check if we should continue */
	if (!RtlDispatchException(ExceptionRecord, &Context)) {
	    /* Raise the exception */
	    Status = NtRaiseException(ExceptionRecord, &Context, FALSE);
	} else {
	    /* Continue, go back to previous context */
	    Status = NtContinue(&Context, FALSE);
	}
    }

    /* If we returned, raise a status */
    RtlRaiseStatus(Status);
}

/*
 * @unimplemented
 */
NTAPI PVOID RtlpGetExceptionAddress(VOID)
{
    UNIMPLEMENTED;
    return NULL;
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
				   IN PCONTEXT ContextRecord)
{
    /* Perform vectored exception handling for user mode */
    if (RtlCallVectoredExceptionHandlers(ExceptionRecord, ContextRecord)) {
	/* Exception handled, now call vectored continue handlers */
	RtlCallVectoredContinueHandlers(ExceptionRecord, ContextRecord);

	/* Continue execution */
	return TRUE;
    }

    /* Call the internal unwind routine */
    BOOLEAN Handled = RtlpUnwindInternal(NULL,	// TargetFrame
					 NULL,	// TargetIp
					 ExceptionRecord, 0,	// ReturnValue
					 ContextRecord, NULL,	// HistoryTable
					 UNW_FLAG_EHANDLER);

    /* In user mode, call any registered vectored continue handlers */
    RtlCallVectoredContinueHandlers(ExceptionRecord, ContextRecord);

    return Handled;
}
