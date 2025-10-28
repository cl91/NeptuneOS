/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Runtime Library
 * PURPOSE:         User-Mode Exception Support
 * FILE:            lib/rtl/exception.c
 * PROGRAMERS:      Alex Ionescu (alex@relsoft.net)
 *                  David Welch <welch@cwcom.net>
 *                  Skywing <skywing@valhallalegends.com>
 *                  KJK::Hyperion <noog@libero.it>
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"

/* GLOBALS *****************************************************************/

PRTLP_UNHANDLED_EXCEPTION_FILTER RtlpUnhandledExceptionFilter;

/* FUNCTIONS ***************************************************************/

/*
 * @implemented
 */
NTAPI USHORT RtlCaptureStackBackTrace(IN ULONG FramesToSkip,
				      IN ULONG FramesToCapture,
				      OUT PVOID *BackTrace,
				      OUT PULONG BackTraceHash OPTIONAL)
{
    PVOID Frames[2 * 64];
    ULONG FrameCount;
    ULONG Hash = 0, i;

    /* Skip a frame for the caller */
    FramesToSkip++;

    /* Don't go past the limit */
    if ((FramesToCapture + FramesToSkip) >= 128)
	return 0;

    /* Do the back trace */
    FrameCount = RtlWalkFrameChain(Frames, FramesToCapture + FramesToSkip, 0);

    /* Make sure we're not skipping all of them */
    if (FrameCount <= FramesToSkip)
	return 0;

    /* Loop all the frames */
    for (i = 0; i < FramesToCapture; i++) {
	/* Don't go past the limit */
	if ((FramesToSkip + i) >= FrameCount)
	    break;

	/* Save this entry and hash it */
	BackTrace[i] = Frames[FramesToSkip + i];
	Hash += PtrToUlong(BackTrace[i]);
    }

    /* Write the hash */
    if (BackTraceHash)
	*BackTraceHash = Hash;

    /* Clear the other entries and return count */
    RtlFillMemoryUlong(Frames, 128, 0);
    return (USHORT) i;
}

/*
 * Private helper function to lookup the module name from a given address.
 * The address can point to anywhere within the module.
 */
static VOID RtlpGetModuleNameFromAddr(IN PVOID Addr,
				      OUT PVOID *ModuleStartAddr,
				      OUT PUNICODE_STRING BaseDllName)
{
    if (NtCurrentPeb()->LdrData && NtCurrentPeb()->LdrData->Initialized) {
	LoopOverList(LdrEntry, &NtCurrentPeb()->LdrData->InMemoryOrderModuleList,
		     LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) {
	    if ((MWORD)Addr >= (MWORD)LdrEntry->DllBase &&
		(MWORD)Addr < (MWORD)LdrEntry->DllBase + LdrEntry->SizeOfImage) {
		*ModuleStartAddr = LdrEntry->DllBase;
		*BaseDllName = LdrEntry->BaseDllName;
		return;
	    }
	}
    }
    *ModuleStartAddr = NULL;
    BaseDllName->Buffer = NULL;
    BaseDllName->Length = BaseDllName->MaximumLength = 0;
}

typedef ULONG (*RTLP_DBG_PRINTER)(PCSTR Fmt, ...);

static VOID RtlpDumpContextEx(IN PCONTEXT Ctx,
			      IN RTLP_DBG_PRINTER DbgPrinter)
{
#ifdef _M_IX86
    /*
     * Print out the CPU registers
     */
    DbgPrinter("EIP: %.8x   EFLAGS: %.8x\n",
	       Ctx->Eip, Ctx->EFlags);
    DbgPrinter("EAX: %.8x   EBX: %.8x   ECX: %.8x   EDX: %.8x\n",
	       Ctx->Eax, Ctx->Ebx, Ctx->Ecx, Ctx->Edx);
    DbgPrinter("EDI: %.8x   ESI: %.8x   EBP: %.8x   ESP: %.8x\n",
	       Ctx->Edi, Ctx->Esi, Ctx->Ebp, Ctx->Esp);
#elif defined(_M_AMD64)
    DbgPrinter("RIP: %.16llx   RSP: %.16llx   EFLAGS: %.8x\n",
	       Ctx->Rip, Ctx->Rsp, Ctx->EFlags);
    DbgPrinter("RAX: %.16llx   RBX: %.16llx   RCX: %.16llx\n",
	       Ctx->Rax, Ctx->Rbx, Ctx->Rcx);
    DbgPrinter("RDX: %.16llx   RDI: %.16llx   RSI: %.16llx\n",
	       Ctx->Rdx, Ctx->Rdi, Ctx->Rsi);
    DbgPrinter("RBP: %.16llx   R8:  %.16llx   R9:  %.16llx\n",
	       Ctx->Rbp, Ctx->R8, Ctx->R9);
    DbgPrinter("R10: %.16llx   R11: %.16llx   R12: %.16llx\n",
	       Ctx->R10, Ctx->R11, Ctx->R12);
    DbgPrinter("R13: %.16llx   R14: %.16llx   R15: %.16llx\n",
	       Ctx->R13, Ctx->R14, Ctx->R15);
#elif defined(_M_ARM)
    DbgPrinter("Pc: %lx   Lr: %lx   Sp: %lx    Cpsr: %lx\n", Ctx->Pc, Ctx->Lr,
	       Ctx->Sp, Ctx->Cpsr);
    DbgPrinter("R0: %lx   R1: %lx   R2: %lx    R3: %lx\n", Ctx->R0, Ctx->R1,
	       Ctx->R2, Ctx->R3);
    DbgPrinter("R4: %lx   R5: %lx   R6: %lx    R7: %lx\n", Ctx->R4, Ctx->R5,
	       Ctx->R6, Ctx->R7);
    DbgPrinter("R8: %lx   R9: %lx  R10: %lx   R11: %lx\n", Ctx->R8, Ctx->R9,
	       Ctx->R10, Ctx->R11);
    DbgPrinter("R12: %lx\n", Ctx->R12);
#elif defined(_M_ARM64)
    DbgPrinter("Pc: %llx   Lr: %llx   Sp: %llx    Cpsr: %llx\n", Ctx->Pc, Ctx->Lr,
	       Ctx->Sp, Ctx->Cpsr);
    DbgPrinter("X0: %llx   X1: %llx   X2: %llx    X3: %llx\n", Ctx->X0, Ctx->X1,
	       Ctx->X2, Ctx->X3);
    DbgPrinter("X4: %llx   X5: %llx   X6: %llx    X7: %llx\n", Ctx->X4, Ctx->X5,
	       Ctx->X6, Ctx->X7);
    DbgPrinter("X8: %llx   X9: %llx  X10: %llx   X11: %llx\n", Ctx->X8, Ctx->X9,
	       Ctx->X10, Ctx->X11);
    DbgPrinter("X12: %llx   X13: %llx  X14: %llx   X15: %llx\n", Ctx->X12, Ctx->X13,
	       Ctx->X14, Ctx->X15);
    DbgPrinter("X16: %llx   X17: %llx  X18: %llx   X19: %llx\n", Ctx->X16, Ctx->X17,
	       Ctx->X18, Ctx->X19);
    DbgPrinter("X20: %llx   X21: %llx  X22: %llx   X23: %llx\n", Ctx->X20, Ctx->X21,
	       Ctx->X22, Ctx->X23);
    DbgPrinter("X24: %llx   X25: %llx  X26: %llx   X27: %llx\n", Ctx->X24, Ctx->X25,
	       Ctx->X26, Ctx->X27);
    DbgPrinter("X28: %llx   X29(Fp): %llx\n", Ctx->X28, Ctx->Fp);
#else
#error "Unknown architecture"
#endif
#if defined(_M_IX86) || defined(_M_AMD64)
    DbgPrinter("FCW: %x  FSW: %x  FTW: %x  FOP: %x\n",
	       Ctx->FltSave.ControlWord, Ctx->FltSave.StatusWord,
	       Ctx->FltSave.TagWord, Ctx->FltSave.ErrorOpcode);
    DbgPrinter("FIP: %zx  FDP: %zx  MXCSR: %x  MXCSR_MASK: %x\n",
	       Ctx->FltSave.ErrorOffset, Ctx->FltSave.DataOffset,
	       Ctx->FltSave.MxCsr, Ctx->FltSave.MxCsr_Mask);
    for (ULONG i = 0; i < 4; i++) {
	DbgPrinter("MM%d: %llx %llx  MM%d: %llx %llx\n", 2*i,
		   Ctx->FltSave.FloatRegisters[2*i].High,
		   Ctx->FltSave.FloatRegisters[2*i].Low, 2*i+1,
		   Ctx->FltSave.FloatRegisters[2*i+1].High,
		   Ctx->FltSave.FloatRegisters[2*i+1].Low);
    }
    for (ULONG i = 0; i < sizeof(MWORD); i++) {
	DbgPrinter("XMM%d: %llx %llx  XMM%d: %llx %llx\n", 2*i,
		   Ctx->FltSave.XmmRegisters[2*i].High,
		   Ctx->FltSave.XmmRegisters[2*i].Low,  2*i+1,
		   Ctx->FltSave.XmmRegisters[2*i+1].High,
		   Ctx->FltSave.XmmRegisters[2*i+1].Low);
    }
#endif
}

/* TODO: We need to generated this from ntstatus.h */
static PCSTR RtlpExceptionCodeToString(IN ULONG ExceptionCode)
{
    switch (ExceptionCode) {
    case STATUS_INTEGER_DIVIDE_BY_ZERO:
	return "STATUS_INTEGER_DIVIDE_BY_ZERO";
    case STATUS_SINGLE_STEP:
	return "STATUS_SINGLE_STEP";
    case STATUS_UNSUCCESSFUL:
	return "STATUS_UNSUCCESSFUL";
    case STATUS_BREAKPOINT:
	return "STATUS_BREAKPOINT";
    case STATUS_INTEGER_OVERFLOW:
	return "STATUS_INTEGER_OVERFLOW";
    case STATUS_ARRAY_BOUNDS_EXCEEDED:
	return "STATUS_ARRAY_BOUNDS_EXCEEDED";
    case STATUS_ILLEGAL_INSTRUCTION:
	return "STATUS_ILLEGAL_INSTRUCTION";
    case STATUS_INVALID_LOCK_SEQUENCE:
	return "STATUS_INVALID_LOCK_SEQUENCE";
    case STATUS_ACCESS_VIOLATION:
	return "STATUS_ACCESS_VIOLATION";
    default:
	return "???";
    }
}

VOID RtlpPrintStackTraceEx(IN PEXCEPTION_POINTERS ExceptionInfo,
			   IN BOOLEAN Unhandled,
			   IN RTLP_DBG_PRINTER DbgPrinter)
{
    PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
    PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

    /* Print a stack trace. */
    __try {
	DbgPrinter("\n==============================================================================\n");
	DbgPrinter("%s exception 0x%x (%s) in process %s (PID/TID %p/%p)\n",
		   Unhandled ? "Unhandled" : "Caught",
		   ExceptionRecord->ExceptionCode,
		   RtlpExceptionCodeToString(ExceptionRecord->ExceptionCode),
		   RtlpDbgTraceModuleName,
		   NtCurrentTib()->ClientId.UniqueProcess,
		   NtCurrentTib()->ClientId.UniqueThread);

	if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION &&
	    ExceptionRecord->NumberParameters == 2) {
	    DbgPrinter("Faulting Address: %p\n",
		       (PVOID)ExceptionRecord->ExceptionInformation[1]);
	}

	/* Trace the wine special error and show the modulename and functionname */
	if (ExceptionRecord->ExceptionCode == 0x80000100 /* EXCEPTION_WINE_STUB */ &&
	    ExceptionRecord->NumberParameters == 2) {
	    DbgPrinter("Missing function: %s!%s\n",
		       (PSZ)ExceptionRecord->ExceptionInformation[0],
		       (PSZ)ExceptionRecord->ExceptionInformation[1]);
	}

	RtlpDumpContextEx(ContextRecord, DbgPrinter);
	PVOID StartAddr;
	UNICODE_STRING BaseDllName;
	RtlpGetModuleNameFromAddr(ExceptionRecord->ExceptionAddress, &StartAddr, &BaseDllName);
	DbgPrinter("Address:\n   %p+%08zx   %wZ\n", (PVOID)StartAddr,
		   (ULONG_PTR)ExceptionRecord->ExceptionAddress - (ULONG_PTR)StartAddr,
		   &BaseDllName);

	/* Don't print the stack content on screen due to screen size limitation. */
	if (DbgPrinter != RtlpVgaPrint) {
	    DbgPrinter("Stack:\n");
	    PPVOID Stack = (PPVOID)ContextRecord->STACK_POINTER;
	    for (INT i = 0; i < 32; i++) {
		DbgPrinter("   %p: %p\n", &Stack[i], Stack[i]);
	    }
	}

	DbgPrinter("Backtrace:\n");
#ifdef _M_IX86
	PULONG_PTR Frame = (PULONG_PTR)ContextRecord->Ebp;

	for (UINT i = 0; i < 16; i++) {
	    if (Frame[1] == 0) {
		DbgPrinter("   <invalid address>\n");
	    } else {
		RtlpGetModuleNameFromAddr((PVOID)Frame[1], &StartAddr, &BaseDllName);
		DbgPrinter("   %p+%.8x   %wZ\n", (PVOID)StartAddr,
			   Frame[1] - (ULONG_PTR)StartAddr, &BaseDllName);
	    }

	    if (Frame[0] == 0)
		break;

	    Frame = (PULONG_PTR) Frame[0];
	}
#else
	DbgPrinter("   NOT IMPLEMENTED YET\n");
#endif

	if (NtCurrentPeb()->LdrData && NtCurrentPeb()->LdrData->Initialized) {
	    DbgPrinter("Modules:\n");
	    LoopOverList(LdrEntry, &NtCurrentPeb()->LdrData->InMemoryOrderModuleList,
			 LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) {
		DbgPrinter("   %wZ (%wZ) @ [%p, %p)\n",
			   &LdrEntry->FullDllName, &LdrEntry->BaseDllName,
			   LdrEntry->DllBase, (PCHAR)LdrEntry->DllBase + LdrEntry->SizeOfImage);
	    }
	}

	DbgPrinter("==============================================================================\n");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

VOID RtlpDumpContext(IN PCONTEXT Ctx)
{
    RtlpDumpContextEx(Ctx, DbgPrint);
}

VOID RtlpPrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo,
			 IN BOOLEAN Unhandled)
{
    RtlpPrintStackTraceEx(ExceptionInfo, Unhandled, DbgPrint);
}

VOID RtlpVgaPrintStackTrace(IN PEXCEPTION_POINTERS ExceptionInfo,
			    IN BOOLEAN Unhandled)
{
    RtlpPrintStackTraceEx(ExceptionInfo, Unhandled, RtlpVgaPrint);
}

/*
 * @unimplemented
 */
NTAPI LONG RtlUnhandledExceptionFilter(IN PEXCEPTION_POINTERS ExceptionInfo)
{
    /* This is used by the security cookie checks, and also called externally */
    UNIMPLEMENTED;
    RtlpPrintStackTrace(ExceptionInfo, TRUE);
    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * @unimplemented
 */
NTAPI LONG RtlUnhandledExceptionFilter2(IN PEXCEPTION_POINTERS ExceptionInfo,
					IN ULONG Flags)
{
    /* This is used by the security cookie checks, and also called externally */
    UNIMPLEMENTED;
    RtlpPrintStackTrace(ExceptionInfo, TRUE);
    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * @implemented
 */
NTAPI VOID RtlSetUnhandledExceptionFilter(IN PRTLP_UNHANDLED_EXCEPTION_FILTER TopLevelExceptionFilter)
{
    /* Set the filter which is used by the CriticalSection package */
    RtlpUnhandledExceptionFilter = RtlEncodePointer(TopLevelExceptionFilter);
}

#ifndef _M_IX86

NTAPI VOID RtlRaiseException(IN PEXCEPTION_RECORD ExceptionRecord)
{
    CONTEXT Context;
    NTSTATUS Status = STATUS_INVALID_DISPOSITION;

    /* Capture the current context */
    RtlCaptureContext(&Context);

    /* Set the instruction pointer in the exception context to the caller */
    Context.INSTRUCTION_POINTER = (ULONG64)_ReturnAddress();

    /* Set the stack pointer in the exception context to the caller's stack pointer
     * immediately before calling this function. */
#ifdef _M_AMD64
    Context.Rsp = (ULONG64)_AddressOfReturnAddress() + 8;
#elif defined(_M_ARM64)
    Context.Sp = (ULONG64)__builtin_frame_address(0);
#else
#error "Unsupported architecture"
#endif

    /* Save the exception address */
    ExceptionRecord->ExceptionAddress = (PVOID)Context.INSTRUCTION_POINTER;

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
					 ExceptionRecord,
					 0,	// ReturnValue
					 ContextRecord,
					 NULL,	// HistoryTable
					 UNW_FLAG_EHANDLER);

    /* In user mode, call any registered vectored continue handlers */
    RtlCallVectoredContinueHandlers(ExceptionRecord, ContextRecord);

    return Handled;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winfinite-recursion"

/*
 * @implemented
 */
NTAPI VOID RtlRaiseStatus(IN NTSTATUS Status)
{
    EXCEPTION_RECORD ExceptionRecord;
    CONTEXT Context;

    /* Capture the context */
    RtlCaptureContext(&Context);

    /* Create an exception record */
    ExceptionRecord.ExceptionAddress = _ReturnAddress();
    ExceptionRecord.ExceptionCode = Status;
    ExceptionRecord.ExceptionRecord = NULL;
    ExceptionRecord.NumberParameters = 0;
    ExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;

    /* Write the context flag */
    Context.ContextFlags = CONTEXT_FULL;

    /* Check if user mode debugger is active */
    if (RtlpCheckForActiveDebugger()) {
	/* Raise an exception immediately */
	NtRaiseException(&ExceptionRecord, &Context, TRUE);
    } else {
	/* Dispatch the exception */
	RtlDispatchException(&ExceptionRecord, &Context);
	/* Raise exception if we got here */
	Status = NtRaiseException(&ExceptionRecord, &Context, FALSE);
    }

    /* If we returned, raise a status */
    RtlRaiseStatus(Status);
}

#pragma GCC diagnostic pop

#endif
