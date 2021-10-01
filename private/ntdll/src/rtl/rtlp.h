#pragma once

#include <ntdll.h>

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

NTAPI VOID RtlpCaptureContext(OUT PCONTEXT ContextRecord);

/* util.c */
NTAPI BOOLEAN RtlpCheckForActiveDebugger(VOID);

NTAPI VOID RtlpGetStackLimits(PULONG_PTR LowLimit,
			      PULONG_PTR HighLimit);

static inline BOOLEAN RtlpCaptureStackLimits(IN ULONG_PTR Ebp,
					     IN ULONG_PTR *StackBegin,
					     IN ULONG_PTR *StackEnd)
{
    /* FIXME: Verify */
    *StackBegin = (ULONG_PTR)NtCurrentTeb()->NtTib.StackLimit;
    *StackEnd = (ULONG_PTR)NtCurrentTeb()->NtTib.StackBase;
    return TRUE;
}

/* vectoreh.c */
BOOLEAN RtlCallVectoredExceptionHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
					 IN PCONTEXT Context);

VOID RtlCallVectoredContinueHandlers(IN PEXCEPTION_RECORD ExceptionRecord,
				     IN PCONTEXT Context);
