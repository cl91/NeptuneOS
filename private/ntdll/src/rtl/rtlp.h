#pragma once

#include <ntdll.h>

#define TAG_USTR        'RTSU'
#define TAG_ASTR        'RTSA'
#define TAG_OSTR        'RTSO'

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
        return _SEH2_GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static inline WCHAR *strchrW(const WCHAR *str, WCHAR ch)
{
    do {
	if (*str == ch) {
	    return (WCHAR *)(ULONG_PTR)str;
	}
    } while (*str++);
    return NULL;
}

/* debug.c */
ULONG RtlpVgaPrint(IN PCSTR Format, ...);

/* exception.c */
VOID RtlpDumpContext(IN PCONTEXT pc);

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
    return (Ptr >= Teb->NtTib.StackLimit &&
	    Ptr <= (Teb->NtTib.StackBase - sizeof(ULONG_PTR))) ||
	(Teb->Wdm.CoroutineStackLow &&
	 Teb->Wdm.CoroutineStackHigh &&
	 Teb->Wdm.CoroutineStackLow < Teb->Wdm.CoroutineStackHigh &&
	 Ptr >= Teb->Wdm.CoroutineStackLow &&
	 Ptr <= (Teb->Wdm.CoroutineStackHigh - sizeof(ULONG_PTR)));
}

/* vectoreh.c */
BOOLEAN RtlCallVectoredExceptionHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
					 IN PCONTEXT Context);

VOID RtlCallVectoredContinueHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
				     IN PCONTEXT Context);

/* critical.c */
NTSTATUS RtlpInitializeCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection,
				       IN HANDLE LockSemaphore,
				       IN ULONG SpinCount);

/* nls.c */
WCHAR RtlpUpcaseUnicodeChar(IN WCHAR Source);
WCHAR RtlpDowncaseUnicodeChar(IN WCHAR Source);
