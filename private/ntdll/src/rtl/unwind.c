/*++

Copyright (c) 2025  Dr. Chang Liu, PhD.

Module Name:

    unwind.c

Abstract:

    Stack unwinding routines for non-i386 architectures

Revision History:

    2025-01-09  Split from AMD64 code.

--*/

#include "rtlp.h"

#ifndef _M_IX86

/*
 *! RtlLookupFunctionTable
 *
 * \brief Locates the table of RUNTIME_FUNCTION entries for a code address.
 * \param ControlPc
 *            Address of the code, for which the table should be searched.
 * \param ImageBase
 *            Pointer to a ULONG64 that receives the base address of the
 *            corresponding executable image.
 * \param Length
 *            Pointer to an ULONG that receives the number of table entries
 *            present in the table.
 */
NTAPI PRUNTIME_FUNCTION RtlLookupFunctionTable(IN ULONG64 ControlPc,
					       OUT PULONG64 ImageBase,
					       OUT PULONG Length)
{
    ULONG Size;

    /* Find corresponding file header from code address */
    if (!RtlPcToFileHeader((PVOID)ControlPc, (PVOID *)ImageBase)) {
	/* Nothing found */
	return NULL;
    }

    /* Locate the exception directory */
    PVOID Table = RtlImageDirectoryEntryToData((PVOID)(*ImageBase),
					       TRUE,
					       IMAGE_DIRECTORY_ENTRY_EXCEPTION,
					       &Size);

    /* Return the number of entries */
    if (Length != NULL) {
	*Length = Size / sizeof(RUNTIME_FUNCTION);
    }

    /* Return the address of the table */
    return Table;
}

/*
 *! RtlLookupFunctionEntry
 * \brief Locates the RUNTIME_FUNCTION entry corresponding to a code address.
 * \ref http://msdn.microsoft.com/en-us/library/ms680597(VS.85).aspx
 * \todo Implement HistoryTable
 */
NTAPI PRUNTIME_FUNCTION RtlLookupFunctionEntry(IN ULONG64 ControlPc,
					       OUT PULONG64 ImageBase,
					       OUT OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable)
{
    /* Find the corresponding table */
    ULONG TableLength;
    PRUNTIME_FUNCTION FunctionTable = RtlLookupFunctionTable(ControlPc,
							     ImageBase,
							     &TableLength);

    /* If no table is found, try dynamic function tables */
    if (!FunctionTable) {
        return RtlpLookupDynamicFunctionEntry(ControlPc, ImageBase, HistoryTable);
    }

    return RtlpLookupFunctionEntry(ControlPc, *ImageBase, FunctionTable,
				   TableLength, HistoryTable);
}


/*!
  \remark The implementation is based on the description in this blog: http://www.nynaeve.net/?p=106

  Differences to the desciption:
  - Instead of using 2 pointers to the unwind context and previous context,
  that are being swapped and the context copied, the unwind context is
  kept in the local context and copied back into the context passed in
  by the caller.

  \see http://www.nynaeve.net/?p=106
*/
BOOLEAN RtlpUnwindInternal(IN OPTIONAL PVOID TargetFrame,
			   IN OPTIONAL PVOID TargetIp,
			   IN PEXCEPTION_RECORD ExceptionRecord,
			   IN PVOID ReturnValue,
			   IN PCONTEXT ContextRecord,
			   IN OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable,
			   IN ULONG HandlerType)
{
    DbgTrace("Unwinding target IP %p target frame %p with context %p\n",
	     TargetIp, TargetFrame, ContextRecord);
    if (ContextRecord != NULL) {
	RtlpDumpContext(ContextRecord);
    }

    /* If we have a target frame, then this is our high limit */
    ULONG64 StackHigh = TargetFrame ? (ULONG64)TargetFrame + 1 : 0;

    /* Copy the context */
    CONTEXT UnwindContext = *ContextRecord;

    /* Set up the constant fields of the dispatcher context */
#ifdef _M_ARM64
    DISPATCHER_CONTEXT_NONVOLREG_ARM64 NonvolatileRegs;
#endif
    DISPATCHER_CONTEXT DispatcherContext = {
	.ContextRecord = &UnwindContext,
	.HistoryTable = HistoryTable,
	.TargetIp = (ULONG64)TargetIp,
#ifdef _M_ARM64
	.NonVolatileRegisters = NonvolatileRegs.Buffer
#endif
    };

    /* Start looping */
    while (TRUE) {
	ULONG64 ImageBase;
	/* Lookup the FunctionEntry for the current RIP */
	PRUNTIME_FUNCTION FunctionEntry =
	    RtlLookupFunctionEntry(UnwindContext.INSTRUCTION_POINTER, &ImageBase, NULL);

	if (FunctionEntry == NULL) {
	    /*
	     * No function entry, so this must be a leaf function (and we are unwinding
	     * past a machine frame pushed by KiUserExceptionDispatcher), or a malformed
	     * PE file. In the first case, pop the return address from the stack and
	     * continue unwinding. In the case of a malformed PE file there isn't a
	     * lot we can do here. If the stack pointer points to invalid memory
	     * another exception will be generated and this can potentially lead to
	     * an infinite recursion until the stack space of the thread is exhausted.
	     */
#ifdef _M_AMD64
	    UnwindContext.Rip = ContextRecord->Rip = *(PULONG64)UnwindContext.Rsp;
	    UnwindContext.Rsp = ContextRecord->Rsp += sizeof(ULONG64);
#elif defined(_M_ARM64)
	    UnwindContext.Pc = ContextRecord->Pc = UnwindContext.Lr;
#else
#error "Unsupported architecture"
#endif
	    DbgTrace("Got leaf function with new IP %p and SP %p\n",
		     (PVOID)ContextRecord->INSTRUCTION_POINTER,
		     (PVOID)ContextRecord->STACK_POINTER);
	    continue;
	}

	/* Do a virtual unwind to get the next frame */
	ULONG64 EstablisherFrame;
	PEXCEPTION_ROUTINE ExceptionRoutine = RtlVirtualUnwind(HandlerType,
							       ImageBase,
							       UnwindContext.INSTRUCTION_POINTER,
							       FunctionEntry,
							       &UnwindContext,
							       &DispatcherContext.HandlerData,
							       &EstablisherFrame,
							       NULL);
	DbgTrace("ExceptionRoutine is %p. New context is\n", ExceptionRoutine);
	RtlpDumpContext(&UnwindContext);

	if (UnwindContext.INSTRUCTION_POINTER == 0) {
	    DbgTrace("Hit user space entry point (Old IP %p Old SP %p New SP %p). "
		     "Stop unwinding.\n", (PVOID)ContextRecord->INSTRUCTION_POINTER,
		     (PVOID)ContextRecord->STACK_POINTER,
		     (PVOID)UnwindContext.STACK_POINTER);
	    return FALSE;
	}

	/* Check if we are still within the stack boundaries */
	if (!RtlpIsStackPtrOk((PVOID)EstablisherFrame) ||
	    (StackHigh && EstablisherFrame >= StackHigh) || (EstablisherFrame & 7)) {
	    /* If we are handling an exception, we are done here. */
	    if (HandlerType == UNW_FLAG_EHANDLER) {
		ExceptionRecord->ExceptionFlags |= EXCEPTION_STACK_INVALID;
		return FALSE;
	    }

	    __debugbreak();
	    RtlRaiseStatus(STATUS_BAD_STACK);
	}

	/* Check if we have an exception routine */
	if (ExceptionRoutine != NULL) {
	    /* Check if this is the target frame */
	    if (EstablisherFrame == (ULONG64)TargetFrame) {
		/* Set flag to inform the language handler */
		ExceptionRecord->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
	    }

	    /* Set up the variable fields of the dispatcher context */
	    DispatcherContext.ControlPc = ContextRecord->INSTRUCTION_POINTER;
	    DispatcherContext.ImageBase = ImageBase;
	    DispatcherContext.FunctionEntry = FunctionEntry;
	    DispatcherContext.LanguageHandler = ExceptionRoutine;
	    DispatcherContext.EstablisherFrame = EstablisherFrame;
	    DispatcherContext.ScopeIndex = 0;

	    /* Store the return value in the unwind context */
	    UnwindContext.RETURN_VALUE = (ULONG64)ReturnValue;

	    /* Loop all nested handlers */
	    do {
		/// TODO: call RtlpExecuteHandlerForUnwind instead
		/* Call the language specific handler */
		EXCEPTION_DISPOSITION Disposition = ExceptionRoutine(ExceptionRecord,
								     (PVOID)EstablisherFrame,
								     ContextRecord,
								     &DispatcherContext);
		DbgTrace("Disposition is %d\n", Disposition);

		/* Clear exception flags for the next iteration */
		ExceptionRecord->ExceptionFlags &= ~(EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND);

		/* Check if we do exception handling */
		if (HandlerType == UNW_FLAG_EHANDLER) {
		    if (Disposition == ExceptionContinueExecution) {
			/* Check if it was non-continuable */
			if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) {
			    __debugbreak();
			    RtlRaiseStatus(EXCEPTION_NONCONTINUABLE_EXCEPTION);
			}

			/* Execution continues */
			return TRUE;
		    } else if (Disposition == ExceptionNestedException) {
			/// TODO
			__debugbreak();
		    }
		}

		if (Disposition == ExceptionCollidedUnwind) {
		    /// TODO
		    __debugbreak();
		}

		/* This must be ExceptionContinueSearch now */
		if (Disposition != ExceptionContinueSearch) {
		    __debugbreak();
		    RtlRaiseStatus(STATUS_INVALID_DISPOSITION);
		}
	    } while (ExceptionRecord->ExceptionFlags & EXCEPTION_COLLIDED_UNWIND);
	}

	/* Check, if we have left our stack (8.) */
	if (!RtlpIsStackPtrOk((PVOID)EstablisherFrame) ||
	    (StackHigh && EstablisherFrame > StackHigh) || (EstablisherFrame & 7)) {
	    __debugbreak();

	    if (UnwindContext.INSTRUCTION_POINTER == ContextRecord->INSTRUCTION_POINTER) {
		RtlRaiseStatus(STATUS_BAD_FUNCTION_TABLE);
	    } else {
		NtRaiseException(ExceptionRecord, ContextRecord, FALSE);
	    }
	}

	if (EstablisherFrame == (ULONG64)TargetFrame) {
	    break;
	}

	/* We have successfully unwound a frame. Copy the unwind context back. */
	*ContextRecord = UnwindContext;
    }

    if (ExceptionRecord->ExceptionCode != STATUS_UNWIND_CONSOLIDATE) {
	ContextRecord->INSTRUCTION_POINTER = (ULONG64)TargetIp;
    }

    /* Set the return value */
    ContextRecord->RETURN_VALUE = (ULONG64)ReturnValue;

    /* Restore the context */
    DbgTrace("restoring context\n");
    RtlpDumpContext(ContextRecord);
    RtlRestoreContext(ContextRecord, ExceptionRecord);

    /* Should never get here! */
    ASSERT(FALSE);
    return FALSE;
}

NTAPI VOID RtlUnwindEx(IN OPTIONAL PVOID TargetFrame,
		       IN OPTIONAL PVOID TargetIp,
		       IN OPTIONAL PEXCEPTION_RECORD ExceptionRecord,
		       IN PVOID ReturnValue,
		       IN PCONTEXT ContextRecord,
		       IN OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable)
{
    DbgTrace("Unwinding target IP %p target frame %p with context\n",
	     TargetIp, TargetFrame);
    EXCEPTION_RECORD LocalExceptionRecord;

    /* Capture the current context */
    RtlCaptureContext(ContextRecord);
    RtlpDumpContext(ContextRecord);

    /* Check if we have an exception record */
    if (ExceptionRecord == NULL) {
	/* No exception record was passed, so set up a local one */
	LocalExceptionRecord.ExceptionCode = STATUS_UNWIND;
	LocalExceptionRecord.ExceptionAddress = (PVOID)ContextRecord->INSTRUCTION_POINTER;
	LocalExceptionRecord.ExceptionRecord = NULL;
	LocalExceptionRecord.NumberParameters = 0;
	ExceptionRecord = &LocalExceptionRecord;
    }

    /* Let the langauge handlers know that we are unwinding (as opposed to
     * dispatching exceptions). */
    ExceptionRecord->ExceptionFlags = EXCEPTION_UNWINDING;
    if (TargetFrame == NULL) {
	ExceptionRecord->ExceptionFlags = EXCEPTION_EXIT_UNWIND;
    }

    /* Call the internal function */
    RtlpUnwindInternal(TargetFrame, TargetIp, ExceptionRecord, ReturnValue,
		       ContextRecord, HistoryTable, UNW_FLAG_UHANDLER);
}

NTAPI VOID RtlUnwind(IN PVOID TargetFrame,
		     IN PVOID TargetIp,
		     IN PEXCEPTION_RECORD ExceptionRecord,
		     IN PVOID ReturnValue)
{
    CONTEXT Context;
    memset(&Context, 0, sizeof(CONTEXT));
    return RtlUnwindEx(TargetFrame, TargetIp, ExceptionRecord,
		       ReturnValue, &Context, NULL);
}

NTAPI ULONG RtlWalkFrameChain(OUT PVOID *Callers,
			      IN ULONG Count,
			      IN ULONG Flags)
{
    DPRINT("Enter RtlWalkFrameChain\n");

    /* The upper bits in Flags define how many frames to skip */
    ULONG FramesToSkip = Flags >> 8;

    /* Capture the current Context */
    CONTEXT Context;
    RtlCaptureContext(&Context);
    ULONG64 ControlPc = Context.INSTRUCTION_POINTER;

    ULONG i = 0;
    __try {
	/* Loop the frames */
	for (i = 0; i < FramesToSkip + Count; i++) {
	    ULONG64 ImageBase;
	    /* Lookup the FunctionEntry for the current ControlPc */
	    PRUNTIME_FUNCTION FunctionEntry = RtlLookupFunctionEntry(ControlPc,
								     &ImageBase,
								     NULL);

	    /* Function does not have any unwinding data. If this is a leaf function,
	     * it means we started from an exception stack and are unwinding past the
	     * machine frame pushed by KiUserExceptionDispatcher. If not, this means either
	     * we have hit the userspace entry point, or the exception table section of the
	     * PE file is missing. For the case of leaf function we pop the return address,
	     * otherwise we stop unwinding. */
	    if (!FunctionEntry) {
#ifdef _M_AMD64
		ULONG64 CallerIp = *(PULONG64)Context.Rsp;
		Context.Rsp += sizeof(ULONG64);
#elif defined(_M_ARM64)
		ULONG64 CallerIp = Context.Lr;
#else
#error "Unsupported architecture"
#endif
		if (CallerIp == 0) {
		    /* This is a user space entry point. Stop unwinding. */
		    DPRINT("Hit userspace entry point. Stop unwinding.\n");
		    break;
		}
		Context.INSTRUCTION_POINTER = CallerIp;
		DPRINT("leaf funtion, new ip = %p, new sp = %p\n",
		       (PVOID)Context.INSTRUCTION_POINTER, (PVOID)Context.STACK_POINTER);
		break;
	    }

	    PVOID HandlerData;
	    ULONG64 EstablisherFrame;
	    RtlVirtualUnwind(UNW_FLAG_NHANDLER,
			     ImageBase,
			     ControlPc,
			     FunctionEntry,
			     &Context,
			     &HandlerData, &EstablisherFrame, NULL);
	    DPRINT("normal funtion, new ip = %p, new sp = %p\n",
		   (PVOID)Context.INSTRUCTION_POINTER, (PVOID)Context.STACK_POINTER);

	    /* Check if we left the user range */
	    if ((Context.INSTRUCTION_POINTER < LOWEST_USER_ADDRESS) ||
		(Context.INSTRUCTION_POINTER > HIGHEST_USER_ADDRESS)) {
		break;
	    }

	    /* Check, if we have left our stack */
	    if (!RtlpIsStackPtrOk((PVOID)Context.STACK_POINTER)) {
		break;
	    }

	    /* Continue with new ip */
	    ControlPc = Context.INSTRUCTION_POINTER;

	    /* Save value, if we are past the frames to skip */
	    if (i >= FramesToSkip) {
		Callers[i - FramesToSkip] = (PVOID)ControlPc;
	    }
	}
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	DPRINT1("Exception while getting callers!\n");
	i = 0;
    }

    DPRINT("RtlWalkFrameChain returns %d\n", i);
    return i;
}

/*! RtlGetCallersAddress
 * \ref http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/RtlGetCallersAddress.html
 */
#undef RtlGetCallersAddress
NTAPI VOID RtlGetCallersAddress(OUT PVOID *CallersAddress,
				OUT PVOID *CallersCaller)
{
    PVOID Callers[4];
    ULONG Number;

    /* Get callers:
     * RtlWalkFrameChain -> RtlGetCallersAddress -> x -> y */
    Number = RtlWalkFrameChain(Callers, 4, 0);

    *CallersAddress = (Number >= 3) ? Callers[2] : NULL;
    *CallersCaller = (Number == 4) ? Callers[3] : NULL;

    return;
}

#endif
