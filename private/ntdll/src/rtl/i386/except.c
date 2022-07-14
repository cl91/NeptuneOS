/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS Run-Time Library
 * PURPOSE:           User-mode exception support for IA-32
 * FILE:              lib/rtl/i386/except.c
 * PROGRAMERS:        Alex Ionescu (alex@relsoft.net)
 *                    Casper S. Hornstrup (chorns@users.sourceforge.net)
 */

/* INCLUDES *****************************************************************/

#include "../rtlp.h"

typedef struct _DISPATCHER_CONTEXT {
    PEXCEPTION_REGISTRATION_RECORD RegistrationPointer;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

/* PUBLIC FUNCTIONS **********************************************************/

/*
 * @implemented
 */
NTAPI VOID RtlGetCallersAddress(OUT PVOID *CallersAddress,
				OUT PVOID *CallersCaller)
{
    USHORT FrameCount;
    PVOID BackTrace[2];
    PULONG BackTraceHash = NULL;

    /* Get the tow back trace address */
    FrameCount = RtlCaptureStackBackTrace(2, 2, &BackTrace[0], BackTraceHash);

    /* Only if user want it */
    if (CallersAddress != NULL) {
	/* only when first frames exist */
	if (FrameCount >= 1) {
	    *CallersAddress = BackTrace[0];
	} else {
	    *CallersAddress = NULL;
	}
    }

    /* Only if user want it */
    if (CallersCaller != NULL) {
	/* only when second frames exist */
	if (FrameCount >= 2) {
	    *CallersCaller = BackTrace[1];
	} else {
	    *CallersCaller = NULL;
	}
    }
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlDispatchException(IN PEXCEPTION_RECORD ExceptionRecord,
				   IN PCONTEXT Context)
{
    /* Perform vectored exception handling for user mode */
    if (RtlCallVectoredExceptionHandlers(ExceptionRecord, Context)) {
	/* Exception handled, now call vectored continue handlers */
	RtlCallVectoredContinueHandlers(ExceptionRecord, Context);

	/* Continue execution */
	return TRUE;
    }

    /* Get the current stack limits and registration frame */
    ULONG_PTR StackLow, StackHigh;
    RtlpGetStackLimits(&StackLow, &StackHigh);
    PEXCEPTION_REGISTRATION_RECORD RegistrationFrame = RtlpGetExceptionList();
    PEXCEPTION_REGISTRATION_RECORD NestedFrame = NULL;

    /* Now loop every frame */
    while ((RegistrationFrame != NULL) && (RegistrationFrame != EXCEPTION_CHAIN_END)) {
	/* Find out where it ends */
	DbgTrace("Handling exception registration frame %p\n", RegistrationFrame);
	ULONG_PTR RegistrationFrameEnd = (ULONG_PTR)RegistrationFrame + sizeof(EXCEPTION_REGISTRATION_RECORD);

	/* Make sure the registration frame is located within the stack */
	if ((RegistrationFrameEnd > StackHigh) || ((ULONG_PTR) RegistrationFrame < StackLow) ||
	    ((ULONG_PTR) RegistrationFrame & 0x3)) {
	    /* Set invalid stack and bail out */
	    DbgTrace("Invalid registration frame %p\n", RegistrationFrame);
	    ExceptionRecord->ExceptionFlags |= EXCEPTION_STACK_INVALID;
	    return FALSE;
	}
//
	// TODO: Implement and call here RtlIsValidHandler(RegistrationFrame->Handler)
	// for supporting SafeSEH functionality, see the following articles:
	// https://www.optiv.com/blog/old-meets-new-microsoft-windows-safeseh-incompatibility
	// https://msrc-blog.microsoft.com/2012/01/10/more-information-on-the-impact-of-ms12-001/
	//

	/* Check if logging is enabled */

	/* Call the handler */
	DISPATCHER_CONTEXT DispatcherContext;
	EXCEPTION_DISPOSITION Disposition = RtlpExecuteHandlerForException(ExceptionRecord,
									   RegistrationFrame,
									   Context,
									   &DispatcherContext,
									   RegistrationFrame->Handler);
	DbgTrace("Exception handler returned disposition %d\n", Disposition);

	/* Check if this is a nested frame */
	if (RegistrationFrame == NestedFrame) {
	    /* Mask out the flag and the nested frame */
	    ExceptionRecord->ExceptionFlags &= ~EXCEPTION_NESTED_CALL;
	    NestedFrame = NULL;
	}

	/* Handle the dispositions */
	switch (Disposition) {
	/* Continue execution */
	case ExceptionContinueExecution:
	    /* Check if it was non-continuable */
	    if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
		/* Set up the exception record */
		EXCEPTION_RECORD ExceptionRecord2 = {
		    .ExceptionRecord = ExceptionRecord,
		    .ExceptionCode = STATUS_NONCONTINUABLE_EXCEPTION,
		    .ExceptionFlags = EXCEPTION_NONCONTINUABLE,
		    .NumberParameters = 0
		};

		/* Raise the exception */
		RtlRaiseException(&ExceptionRecord2);
	    } else {
		/* In user mode, call any registered vectored continue handlers */
		RtlCallVectoredContinueHandlers(ExceptionRecord, Context);

		/* Execution continues */
		return TRUE;
	    }

	/* Continue searching */
	case ExceptionContinueSearch:
	    if (ExceptionRecord->ExceptionFlags & EXCEPTION_STACK_INVALID) {
		/* We have an invalid stack, bail out */
		return FALSE;
	    }
	    break;

	/* Nested exception */
	case ExceptionNestedException:
	    /* Turn the nested flag on */
	    ExceptionRecord->ExceptionFlags |= EXCEPTION_NESTED_CALL;

	    /* Update the current nested frame */
	    if (DispatcherContext.RegistrationPointer > NestedFrame) {
		/* Get the frame from the dispatcher context */
		NestedFrame = DispatcherContext.RegistrationPointer;
	    }
	    break;

	/* Anything else */
	default:
	{
	    /* Set up the exception record */
	    EXCEPTION_RECORD ExceptionRecord2 = {
		.ExceptionRecord = ExceptionRecord,
		.ExceptionCode = STATUS_INVALID_DISPOSITION,
		.ExceptionFlags = EXCEPTION_NONCONTINUABLE,
		.NumberParameters = 0
	    };

	    /* Raise the exception */
	    RtlRaiseException(&ExceptionRecord2);
	}
	}

	/* Go to the next frame */
	RegistrationFrame = RegistrationFrame->Next;
    }

    /* Unhandled, bail out */
    return FALSE;
}

/*
 * @implemented
 */
NTAPI VOID RtlUnwind(IN PVOID TargetFrame OPTIONAL,
		     IN PVOID TargetIp OPTIONAL,
		     IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
		     IN PVOID ReturnValue)
{
    EXCEPTION_RECORD ExceptionRecord2, ExceptionRecord3;

    /* Capture the current stack limits */
    ULONG_PTR StackLow, StackHigh;
    RtlpGetStackLimits(&StackLow, &StackHigh);

    /* If the caller did not supply an exception record, setup a local one */
    if (!ExceptionRecord) {
	/* Overwrite the argument */
	ExceptionRecord = &ExceptionRecord3;

	/* Setup the local exception record */
	ExceptionRecord3.ExceptionFlags = 0;
	ExceptionRecord3.ExceptionCode = STATUS_UNWIND;
	ExceptionRecord3.ExceptionRecord = NULL;
	ExceptionRecord3.ExceptionAddress = _ReturnAddress();
	ExceptionRecord3.NumberParameters = 0;
    }

    /* Set the UNWINDING exception flag */
    ExceptionRecord->ExceptionFlags |= EXCEPTION_UNWINDING;
    /* If the target frame is not specified, set the Exit Unwind flag as well */
    if (!TargetFrame) {
	ExceptionRecord->ExceptionFlags |= EXCEPTION_EXIT_UNWIND;
    }

    /* Build a local context record which captures the stack frame
     * of the caller of RtlUnwind. This is so that once the unwinding
     * is finished we can jump back to the caller as if we have
     * "returned" from RtlUnwind.
     *
     * Note in ReactOS/Windows this is accomplished by calling a
     * private function RtlpCaptureContext, which captures the stack
     * frame of the caller. RtlpCaptureContext (as well as its public
     * counterpart, RtlCaptureContext) depends on the compiler NOT
     * omitting the frame pointer of RtlUnwind. There doesn't seem
     * to be a reliable way to turn this off under Clang/LLVM, so
     * we instead make use of the compiler builtins.
     */
    CONTEXT LocalContext = {
	.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL,
	.Eax = (ULONG)ReturnValue,
	.Eip = (ULONG)_ReturnAddress(),
	.Ebp = (ULONG)__builtin_frame_address(1),
	.Esp = (ULONG)_AddressOfReturnAddress() + sizeof(PVOID) + sizeof(TargetFrame) +
	       sizeof(TargetIp) + sizeof(ExceptionRecord) + sizeof(ReturnValue)
    };

    /* Get the current frame */
    PEXCEPTION_REGISTRATION_RECORD RegistrationFrame = RtlpGetExceptionList();

    /* Now loop every frame */
    while ((RegistrationFrame != NULL) && (RegistrationFrame != EXCEPTION_CHAIN_END)) {
	DbgTrace("Unwinding exception registration frame %p\n", RegistrationFrame);
	/* If this is the target */
	if (RegistrationFrame == TargetFrame) {
	    DbgTrace("Hit target frame. Stop unwinding.\n");
	    NtContinue(&LocalContext, FALSE);
	}

	/* Check if the frame is too low */
	if (TargetFrame && ((ULONG_PTR)TargetFrame < (ULONG_PTR)RegistrationFrame)) {
	    /* Create an invalid unwind exception */
	    ExceptionRecord2.ExceptionCode = STATUS_INVALID_UNWIND_TARGET;
	    ExceptionRecord2.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
	    ExceptionRecord2.ExceptionRecord = ExceptionRecord;
	    ExceptionRecord2.NumberParameters = 0;

	    /* Raise the exception */
	    RtlRaiseException(&ExceptionRecord2);
	}

	/* Find out where it ends */
	ULONG_PTR RegistrationFrameEnd = (ULONG_PTR)RegistrationFrame + sizeof(EXCEPTION_REGISTRATION_RECORD);

	/* Make sure the registration frame is located within the stack */
	if ((RegistrationFrameEnd > StackHigh) || ((ULONG_PTR)RegistrationFrame < StackLow) ||
	    ((ULONG_PTR)RegistrationFrame & 0x3)) {
	    /* Create an invalid stack exception */
	    ExceptionRecord2.ExceptionCode = STATUS_BAD_STACK;
	    ExceptionRecord2.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
	    ExceptionRecord2.ExceptionRecord = ExceptionRecord;
	    ExceptionRecord2.NumberParameters = 0;

	    /* Raise the exception */
	    RtlRaiseException(&ExceptionRecord2);
	} else {
	    /* Call the handler */
	    DISPATCHER_CONTEXT DispatcherContext;
	    EXCEPTION_DISPOSITION Disposition = RtlpExecuteHandlerForUnwind(ExceptionRecord,
									    RegistrationFrame,
									    &LocalContext,
									    &DispatcherContext,
									    RegistrationFrame->Handler);
	    DbgTrace("Exception handler returned disposition %d\n", Disposition);

	    switch (Disposition) {
	    /* Continue searching */
	    case ExceptionContinueSearch:
		break;

	    /* Collision */
	    case ExceptionCollidedUnwind:
		/* Get the original frame */
		RegistrationFrame = DispatcherContext.RegistrationPointer;
		break;

	    /* Anything else */
	    default:
		/* Set up the exception record */
		ExceptionRecord2.ExceptionRecord = ExceptionRecord;
		ExceptionRecord2.ExceptionCode = STATUS_INVALID_DISPOSITION;
		ExceptionRecord2.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
		ExceptionRecord2.NumberParameters = 0;

		/* Raise the exception */
		RtlRaiseException(&ExceptionRecord2);
		break;
	    }

	    /* Go to the next frame */
	    PEXCEPTION_REGISTRATION_RECORD OldFrame = RegistrationFrame;
	    RegistrationFrame = RegistrationFrame->Next;

	    /* Remove this handler */
	    RtlpSetExceptionList(OldFrame);
	}
    }

    /* Check if we reached the end */
    if (TargetFrame == EXCEPTION_CHAIN_END) {
	DbgTrace("Reached end of exception chain. Stop unwinding.\n");
	/* Unwind completed, so we don't exit */
	NtContinue(&LocalContext, FALSE);
    } else {
	/* This is an exit_unwind or the frame wasn't present in the list */
	NtRaiseException(ExceptionRecord, &LocalContext, FALSE);
    }
}

/*
 * @implemented
 */
NTAPI ULONG RtlWalkFrameChain(OUT PVOID *Callers,
			      IN ULONG Count,
			      IN ULONG Flags)
{
    ULONG_PTR Stack, NewStack, StackBegin, StackEnd = 0;
    ULONG Eip;
    BOOLEAN Result, StopSearch = FALSE;
    ULONG i = 0;

    /* Get current EBP */
#if defined(_M_IX86)
#if defined __GNUC__
    __asm__("mov %%ebp, %0" : "=r" (Stack) : );
#elif defined(_MSC_VER)
    __asm mov Stack, ebp
#endif
#elif defined(_M_MIPS)
        __asm__("move $sp, %0" : "=r" (Stack) : );
#elif defined(_M_PPC)
    __asm__("mr %0,1" : "=r" (Stack) : );
#elif defined(_M_ARM)
#if defined __GNUC__
    __asm__("mov sp, %0" : "=r"(Stack) : );
#elif defined(_MSC_VER)
    // FIXME: Hack. Probably won't work if this ever actually manages to run someday.
    Stack = (ULONG_PTR)&Stack;
#endif
#else
#error Unknown architecture
#endif

    /* Set it as the stack begin limit as well */
    StackBegin = (ULONG_PTR)Stack;

    /* Check if we're called for non-logging mode */
    if (!Flags) {
	/* Get the actual safe limits */
	Result = RtlpCaptureStackLimits((ULONG_PTR)Stack,
					&StackBegin,
					&StackEnd);
	if (!Result) return 0;
    }

    /* Use a SEH block for maximum protection */
    _SEH2_TRY {
	/* Loop the frames */
	for (i = 0; i < Count; i++) {
	    /*
	     * Leave if we're past the stack,
	     * if we're before the stack,
	     * or if we've reached ourselves.
	     */
	    if ((Stack >= StackEnd) ||
		(!i ? (Stack < StackBegin) : (Stack <= StackBegin)) ||
		((StackEnd - Stack) < (2 * sizeof(ULONG_PTR)))) {
		/* We're done or hit a bad address */
		break;
	    }

	    /* Get new stack and EIP */
	    NewStack = *(PULONG_PTR)Stack;
	    Eip = *(PULONG_PTR)(Stack + sizeof(ULONG_PTR));

	    /* Check if the new pointer is above the oldone and past the end */
	    if (!((Stack < NewStack) && (NewStack < StackEnd))) {
		/* Stop searching after this entry */
		StopSearch = TRUE;
	    }

	    /* Also make sure that the EIP isn't a stack address */
	    if ((StackBegin < Eip) && (Eip < StackEnd)) break;

	    /* FIXME: Check that EIP is inside a loaded module */

	    /* Save this frame */
	    Callers[i] = (PVOID)Eip;

	    /* Check if we should continue */
	    if (StopSearch) {
		/* Return the next index */
		i++;
		break;
	    }

	    /* Move to the next stack */
	    Stack = NewStack;
	}
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	/* No index */
	i = 0;
    }
    _SEH2_END;

    /* Return frames parsed */
    return i;
}
