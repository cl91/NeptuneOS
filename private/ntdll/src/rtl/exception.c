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

#ifdef _M_AMD64

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

#endif	/* _M_AMD64 */

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
	LoopOverList(LdrEntry, &NtCurrentPeb()->LdrData->InInitializationOrderModuleList,
		     LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks) {
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

static VOID RtlpDumpContextEx(IN PCONTEXT pc,
			      IN RTLP_DBG_PRINTER DbgPrinter)
{
#ifdef _M_IX86
    /*
     * Print out the CPU registers
     */
    DbgPrinter("EIP: %.8x   EFLAGS: %.8x\n",
	       pc->Eip, pc->EFlags);
    DbgPrinter("EAX: %.8x   EBX: %.8x   ECX: %.8x   EDX: %.8x\n",
	       pc->Eax, pc->Ebx, pc->Ecx, pc->Edx);
    DbgPrinter("EDI: %.8x   ESI: %.8x   EBP: %.8x   ESP: %.8x\n",
	       pc->Edi, pc->Esi, pc->Ebp, pc->Esp);
#elif defined(_M_AMD64)
    DbgPrinter("RIP: %.16llx   RSP: %.16llx   EFLAGS: %.8x\n",
	       pc->Rip, pc->Rsp, pc->EFlags);
    DbgPrinter("RAX: %.16llx   RBX: %.16llx   RCX: %.16llx\n",
	       pc->Rax, pc->Rbx, pc->Rcx);
    DbgPrinter("RDX: %.16llx   RDI: %.16llx   RSI: %.16llx\n",
	       pc->Rdx, pc->Rdi, pc->Rsi);
    DbgPrinter("RBP: %.16llx   R8:  %.16llx   R9:  %.16llx\n",
	       pc->Rbp, pc->R8, pc->R9);
    DbgPrinter("R10: %.16llx   R11: %.16llx   R12: %.16llx\n",
	       pc->R10, pc->R11, pc->R12);
    DbgPrinter("R13: %.16llx   R14: %.16llx   R15: %.16llx\n",
	       pc->R13, pc->R14, pc->R15);
#elif defined(_M_ARM)
    DbgPrinter("Pc: %lx   Lr: %lx   Sp: %lx    Cpsr: %lx\n", pc->Pc, pc->Lr,
	       pc->Sp, pc->Cpsr);
    DbgPrinter("R0: %lx   R1: %lx   R2: %lx    R3: %lx\n", pc->R0, pc->R1,
	       pc->R2, pc->R3);
    DbgPrinter("R4: %lx   R5: %lx   R6: %lx    R7: %lx\n", pc->R4, pc->R5,
	       pc->R6, pc->R7);
    DbgPrinter("R8: %lx   R9: %lx  R10: %lx   R11: %lx\n", pc->R8, pc->R9,
	       pc->R10, pc->R11);
    DbgPrinter("R12: %lx\n", pc->R12);
#else
#error "Unknown architecture"
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
    DbgPrinter("\n==============================================================================\n");
    DbgPrinter("%s exception 0x%x (%s) in process %s (PID/TID %p/%p)\n",
	       Unhandled ? "Unhandled" : "Caught",
	       ExceptionRecord->ExceptionCode,
	       RtlpExceptionCodeToString(ExceptionRecord->ExceptionCode),
	       RtlpDbgTraceModuleName,
	       NtCurrentTeb()->RealClientId.UniqueProcess,
	       NtCurrentTeb()->RealClientId.UniqueThread);

    if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION &&
	ExceptionRecord->NumberParameters == 2) {
	DbgPrinter("Faulting Address: %08zx\n",
		   ExceptionRecord->ExceptionInformation[1]);
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
	__try {
	    DbgPrinter("Stack:\n");
	    PPVOID Stack = (PPVOID)ContextRecord->STACK_POINTER;
	    for (INT i = 0; i < 32; i++) {
		DbgPrinter("   %p: %p\n", &Stack[i], Stack[i]);
	    }
	}  __except (EXCEPTION_EXECUTE_HANDLER) {
	}
    }

    DbgPrinter("Backtrace:\n");
#ifdef _M_IX86
    __try {
	PULONG_PTR Frame = (PULONG_PTR)ContextRecord->BASE_POINTER;

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
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
#else
    DbgPrinter("   NOT IMPLEMENTED YET\n");
#endif

    if (NtCurrentPeb()->LdrData && NtCurrentPeb()->LdrData->Initialized) {
	DbgPrinter("Modules:\n");
	LoopOverList(LdrEntry, &NtCurrentPeb()->LdrData->InInitializationOrderModuleList,
		     LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks) {
	    DbgPrinter("   %wZ (%wZ) @ [%p, %p)\n",
		       &LdrEntry->FullDllName, &LdrEntry->BaseDllName,
		       LdrEntry->DllBase, (PCHAR)LdrEntry->DllBase + LdrEntry->SizeOfImage);
	}
    }

    DbgPrinter("==============================================================================\n");
}

VOID RtlpDumpContext(IN PCONTEXT pc)
{
    RtlpDumpContextEx(pc, DbgPrint);
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
