#pragma once

#include <ntdll.h>

#define TAG_USTR        'RTSU'
#define TAG_ASTR        'RTSA'
#define TAG_OSTR        'RTSO'

/* From winbase.h */
#define INFINITE 0xFFFFFFFFUL

static inline PVOID RtlpAllocateMemory(UINT Bytes,
				       ULONG Tag)
{
    UNREFERENCED_PARAMETER(Tag);
    return RtlAllocateHeap(RtlGetProcessHeap(), 0, Bytes);
}

static inline VOID RtlpFreeMemory(PVOID Mem,
				  ULONG Tag)
{
    UNREFERENCED_PARAMETER(Tag);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Mem);
}

#define RtlpAllocateStringMemory RtlpAllocateMemory
#define RtlpFreeStringMemory RtlpFreeMemory

static inline NTSTATUS RtlpSafeCopyMemory(OUT VOID UNALIGNED *Destination,
					  OUT CONST VOID UNALIGNED *Source,
					  IN SIZE_T Length)
{
    __try {
        RtlCopyMemory((PVOID)Destination, (PCVOID)Source, Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static inline WCHAR *strchrW(const WCHAR *Str, WCHAR Ch)
{
    do {
	if (*Str == Ch) {
	    return (WCHAR *)(ULONG_PTR)Str;
	}
    } while (*Str++);
    return NULL;
}

/* We cannot make these ULONG_PTR as unfortunately on amd64, Microsoft does not
 * support passing a 16-byte aggregate value using two registers (rax:rdx), unlike
 * the SysV calling convention. */
typedef struct _FIBER_CONTINUATION_STATUS {
    ULONG Status;
    ULONG Switched;
} FIBER_CONTINUATION_STATUS;

C_ASSERT(sizeof(FIBER_CONTINUATION_STATUS) == 8);
C_ASSERT(FIELD_OFFSET(FIBER_CONTINUATION_STATUS, Switched) == 4);

/* arch/fiber.S */
FASTCALL NTSYSAPI FIBER_CONTINUATION_STATUS RtlpCaptureFiberContext(OUT PCONTEXT ContextRecord);

FASTCALL NTSYSAPI VOID RtlpRestoreFiberContext(IN PCONTEXT ContextRecord);

/* debug.c */
ULONG RtlpVgaPrint(IN PCSTR Format, ...);

/* exception.c */
#if DBG
VOID RtlpDumpContext(IN PCONTEXT Context);
#else
#define RtlpDumpContext(...)
#endif

/*
 * Exception handling helper routines
 */
NTAPI PEXCEPTION_REGISTRATION_RECORD RtlpGetExceptionList(VOID);

NTAPI VOID RtlpSetExceptionList(PEXCEPTION_REGISTRATION_RECORD NewExceptionList);

/* i386/except.S */
#ifdef _M_IX86
NTAPI EXCEPTION_DISPOSITION
RtlpExecuteHandlerForException(PEXCEPTION_RECORD ExceptionRecord,
			       PEXCEPTION_REGISTRATION_RECORD RegistrationFrame,
			       PCONTEXT Context,
			       PVOID DispatcherContext,
			       PEXCEPTION_ROUTINE ExceptionHandler);
#endif

/* amd64/unwind.c */
#ifdef _M_AMD64
BOOLEAN RtlpUnwindInternal(IN OPTIONAL PVOID TargetFrame,
			   IN OPTIONAL PVOID TargetIp,
			   IN PEXCEPTION_RECORD ExceptionRecord,
			   IN PVOID ReturnValue,
			   IN PCONTEXT ContextRecord,
			   IN OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable,
			   IN ULONG Flags);
#endif

NTAPI EXCEPTION_DISPOSITION
RtlpExecuteHandlerForUnwind(PEXCEPTION_RECORD ExceptionRecord,
                            PEXCEPTION_REGISTRATION_RECORD RegistrationFrame,
                            PCONTEXT Context,
                            PVOID DispatcherContext,
                            PEXCEPTION_ROUTINE ExceptionHandler);

NTAPI VOID
RtlpCheckLogException(IN PEXCEPTION_RECORD ExceptionRecord,
                      IN PCONTEXT ContextRecord,
                      IN PVOID ContextData,
                      IN ULONG Size);

/* util.c */
NTAPI BOOLEAN RtlpCheckForActiveDebugger(VOID);

static inline BOOLEAN RtlpIsStackPtrOk(IN PVOID Ptr)
{
    PTEB Teb = NtCurrentTeb();
    return Ptr >= Teb->NtTib.StackLimit &&
	Ptr <= (Teb->NtTib.StackBase - sizeof(ULONG_PTR));
}

/* vectoreh.c */
BOOLEAN RtlCallVectoredExceptionHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
					 IN PCONTEXT Context);

VOID RtlCallVectoredContinueHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
				     IN PCONTEXT Context);

/* critical.c */
NTSTATUS RtlpInitializeCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection,
				       IN HANDLE LockSemaphore,
				       IN ULONG SpinCount,
				       IN ULONG Flags);

/* nls.c */
WCHAR RtlpUpcaseUnicodeChar(IN WCHAR Source);
WCHAR RtlpDowncaseUnicodeChar(IN WCHAR Source);

/* res.c */
IMAGE_RESOURCE_DIRECTORY *RtlpFindFirstResourceEntry(IMAGE_RESOURCE_DIRECTORY *Dir,
						     PVOID Root,
						     BOOLEAN WantDir);
IMAGE_RESOURCE_DIRECTORY *RtlpFindResourceEntryByName(IMAGE_RESOURCE_DIRECTORY *Dir,
						      LPCWSTR Name,
						      PVOID Root,
						      BOOLEAN WantDir);

/* workitem.c */
extern PRTL_START_POOL_THREAD RtlpStartThreadFunc;
extern PRTL_EXIT_POOL_THREAD RtlpExitThreadFunc;

#ifndef _M_IX86
/* dynfntbl.c */
PRUNTIME_FUNCTION RtlpLookupDynamicFunctionEntry(IN DWORD64 ControlPc,
						 OUT PDWORD64 ImageBase,
						 IN PUNWIND_HISTORY_TABLE HistoryTable);

/* unwind.c */
BOOLEAN RtlpUnwindInternal(IN OPTIONAL PVOID TargetFrame,
			   IN OPTIONAL PVOID TargetIp,
			   IN PEXCEPTION_RECORD ExceptionRecord,
			   IN PVOID ReturnValue,
			   IN PCONTEXT ContextRecord,
			   IN OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable,
			   IN ULONG HandlerType);

/* arch/unwind.c */
PRUNTIME_FUNCTION RtlpLookupFunctionEntry(IN ULONG64 ControlPc,
					  IN ULONG64 ImageBase,
					  IN PRUNTIME_FUNCTION FunctionTable,
					  IN ULONG TableLength,
					  OUT OPTIONAL PUNWIND_HISTORY_TABLE HistoryTable);
#endif
