/*
 * PROJECT:     ReactOS CRT library
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     C specific exception/unwind handler for AMD64 and ARM64
 * COPYRIGHT:   Copyright 2018-2021 Timo Kreuzer <timo.kreuzer@reactos.org>
*/

#include "rtlp.h"

#ifndef _M_IX86

VOID RtlpDumpDispatcherContext(IN PDISPATCHER_CONTEXT DispatcherContext)
{
    DbgTrace("Dumping dispatcher context %p\n", DispatcherContext);
    if (DispatcherContext != NULL) {
	DbgPrint("    ControlPc = %p\n"
		 "    ImageBase =  %p\n"
		 "    FunctionEntry = %p\n"
		 "    EstablisherFrame = %p\n"
		 "    TargetIp = %p\n"
		 "    ContextRecord = %p\n"
		 "    LanguageHandler = %p\n"
		 "    HandlerData = %p\n"
		 "    HistoryTable = %p\n"
		 "    ScopeIndex = %d\n",
		 (PVOID)DispatcherContext->ControlPc,
		 (PVOID)DispatcherContext->ImageBase,
		 DispatcherContext->FunctionEntry,
		 (PVOID)DispatcherContext->EstablisherFrame,
		 (PVOID)DispatcherContext->TargetIp,
		 DispatcherContext->ContextRecord,
		 DispatcherContext->LanguageHandler,
		 DispatcherContext->HandlerData,
		 DispatcherContext->HistoryTable,
		 DispatcherContext->ScopeIndex);
	if (DispatcherContext->ContextRecord != NULL) {
	    DbgPrint("  ContextRecord is\n");
	    RtlpDumpContext(DispatcherContext->ContextRecord);
	}
    }
}

VOID RtlpDumpScopeTable(IN PSCOPE_TABLE ScopeTable)
{
    DbgTrace("Dumping scope table %p. Count = %d\n",
	     ScopeTable, ScopeTable ? ScopeTable->Count : 0);
    if (ScopeTable != NULL) {
	for (ULONG i = 0; i < ScopeTable->Count; i++) {
	    DbgPrint("   BeginAddress 0x%.8x EndAddress 0x%.8x "
		     "HandlerAddress 0x%.8x JumpTarget 0x%.8x\n",
		     ScopeTable->ScopeRecord[i].BeginAddress,
		     ScopeTable->ScopeRecord[i].EndAddress,
		     ScopeTable->ScopeRecord[i].HandlerAddress,
		     ScopeTable->ScopeRecord[i].JumpTarget);
	}
    }
}

EXCEPTION_DISPOSITION __C_specific_handler(PEXCEPTION_RECORD ExceptionRecord,
					   PVOID EstablisherFrame,
					   PCONTEXT ContextRecord,
					   PDISPATCHER_CONTEXT DispatcherContext)
{
    DbgTrace("ExceptionRecord %p EstablisherFrame %p ContextRecord %p\n",
	     ExceptionRecord, EstablisherFrame, ContextRecord);
    RtlpDumpContext(ContextRecord);
    RtlpDumpDispatcherContext(DispatcherContext);

    /* Set up the EXCEPTION_POINTERS */
    EXCEPTION_POINTERS ExceptionPointers = {
	.ExceptionRecord = ExceptionRecord,
	.ContextRecord = ContextRecord
    };

    /* Get the image base */
    ULONG64 ImageBase = (ULONG64)DispatcherContext->ImageBase;

    /* Get the image base relative instruction pointers */
    ULONG64 ControlPc = DispatcherContext->ControlPc - ImageBase;
    ULONG64 TargetIp = DispatcherContext->TargetIp - ImageBase;

#ifdef _M_ARM64
    /* If ControlPcIsUnwound is set, ControlPc points to a return address.
     * Move ControlPc back by one instruction so it points to the original scope. */
    if (DispatcherContext->ControlPcIsUnwound) {
	ControlPc -= 4;
    }
    LONG __C_ExecuteExceptionFilter(PVOID, PVOID, PVOID, PVOID);
#endif

    /* Get the scope table and current index */
    PSCOPE_TABLE ScopeTable = (PSCOPE_TABLE)DispatcherContext->HandlerData;
    RtlpDumpScopeTable(ScopeTable);

    /* Loop while we have scope table entries */
    while (DispatcherContext->ScopeIndex < ScopeTable->Count) {
	/* Use i as index and update the dispatcher context */
	ULONG i = DispatcherContext->ScopeIndex++;

	/* Get the start and end of the scope */
	ULONG BeginAddress = ScopeTable->ScopeRecord[i].BeginAddress;
	ULONG EndAddress = ScopeTable->ScopeRecord[i].EndAddress;
	DbgTrace("IpOffset 0x%llx BeginAddress 0x%x EndAddress 0x%x\n",
		 ControlPc, BeginAddress, EndAddress);

	/* Skip this scope if we are not within the bounds */
	if ((ControlPc < BeginAddress) || (ControlPc >= EndAddress)) {
	    continue;
	}

	/* Check if this is an unwind */
	if (ExceptionRecord->ExceptionFlags & EXCEPTION_UNWIND) {
	    DbgTrace("Exception record is unwind\n");
	    /* Check if this is a target unwind */
	    if (ExceptionRecord->ExceptionFlags & EXCEPTION_TARGET_UNWIND) {
		/* Check if the target is within the scope itself */
		if ((TargetIp >= BeginAddress) && (TargetIp < EndAddress)) {
		    return ExceptionContinueSearch;
		}
	    }

	    /* Check if this is a termination handler / finally function */
	    if (ScopeTable->ScopeRecord[i].JumpTarget == 0) {
		/* Call the handler */
		ULONG Handler = ScopeTable->ScopeRecord[i].HandlerAddress;
		PTERMINATION_HANDLER TerminationHandler = (PTERMINATION_HANDLER)(ImageBase + Handler);
#ifdef _M_AMD64
		TerminationHandler(TRUE, EstablisherFrame);
#elif defined(_M_ARM64)
		__C_ExecuteExceptionFilter(ULongToPtr(TRUE),
					   EstablisherFrame, TerminationHandler,
					   DispatcherContext->NonVolatileRegisters);
#else
#error "Unsupported architecture"
#endif
	    } else if (ScopeTable->ScopeRecord[i].JumpTarget == TargetIp) {
		return ExceptionContinueSearch;
	    }
	} else {
	    DbgTrace("Exception record is HANDLER\n");
	    /* We are only interested in exception handlers */
	    if (ScopeTable->ScopeRecord[i].JumpTarget == 0) {
		continue;
	    }

	    /* This is an exception filter, get the handler address */
	    ULONG Handler = ScopeTable->ScopeRecord[i].HandlerAddress;
	    DbgTrace("Handler = 0x%x\n", Handler);

	    /* Check for hardcoded EXCEPTION_EXECUTE_HANDLER */
	    LONG FilterResult;
	    if (Handler == EXCEPTION_EXECUTE_HANDLER) {
		/* This is our result */
		FilterResult = EXCEPTION_EXECUTE_HANDLER;
	    } else {
		/* Otherwise we need to call the handler */
		PEXCEPTION_FILTER ExceptionFilter = (PEXCEPTION_FILTER)(ImageBase + Handler);
#ifdef _M_AMD64
		FilterResult = ExceptionFilter(&ExceptionPointers, EstablisherFrame);
#elif defined(_M_ARM64)
		FilterResult = __C_ExecuteExceptionFilter(&ExceptionPointers,
							  EstablisherFrame, ExceptionFilter,
							  DispatcherContext->NonVolatileRegisters);
#else
#error "Unsupported architecture"
#endif
	    }
	    DbgTrace("FilterResult is %d\n", FilterResult);

	    if (FilterResult == EXCEPTION_CONTINUE_EXECUTION) {
		return ExceptionContinueExecution;
	    }

	    if (FilterResult == EXCEPTION_EXECUTE_HANDLER) {
		ULONG64 JumpTarget = ImageBase + ScopeTable->ScopeRecord[i].JumpTarget;

		/* Unwind to the target address to execute the exception handler
		 * (ie. the stmt as in __except (fltr) { stmt; } ). This will
		 * initiate a collided unwind and if successful, should not return
		 * (instead control will transfer to the jump target, typically an
		 * exception handler). */
		RtlUnwindEx(EstablisherFrame,
			    (PVOID)JumpTarget,
			    ExceptionRecord,
			    UlongToPtr(ExceptionRecord->ExceptionCode),
			    DispatcherContext->ContextRecord,
			    DispatcherContext->HistoryTable);

		/* If we got here, the unwind above has failed (for instance, it has
		 * hit KiUserExceptionDispatcher which is logically the end of a call
		 * stack, because it is not called by any function but dispatched by
		 * the server). Raise a debug breakpoint exception. */
		__debugbreak();
	    }
	}
    }

    /* Reached the end of the scope table */
    return ExceptionContinueSearch;
}

void _local_unwind(void *frame, void *target)
{
    RtlUnwind(frame, target, NULL, 0);
}

#endif
