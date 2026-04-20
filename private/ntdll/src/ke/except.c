#include <ntdll.h>

VOID KiDispatchUserException(IN PCONTEXT Context,
			     IN PEXCEPTION_RECORD ExceptionRecord)
{
    DbgTrace("Context %p ExceptionRecord %p\n", Context, ExceptionRecord);
    /* NTDLL is compiled with SIMD enabled so we might modify FPU registers
     * when handling an exception. Therefore the user space entry point saves
     * the FPU state before calling us. Mark the context as so.  */
#ifdef _M_IX86
    Context->ContextFlags |= CONTEXT_EXTENDED_REGISTERS;
#else
    Context->ContextFlags |= CONTEXT_FLOATING_POINT;
#endif

    /* Dispatch the exception and check the result */
    NTSTATUS Status;
    if (RtlDispatchException(ExceptionRecord, Context)) {
        /* Continue executing */
        Status = NtContinue(Context, FALSE);
    } else {
        /* Raise an exception */
        Status = NtRaiseException(ExceptionRecord, Context, FALSE);
    }

    /* Setup the Exception record */
    EXCEPTION_RECORD NestedExceptionRecord;
    NestedExceptionRecord.ExceptionCode = Status;
    NestedExceptionRecord.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    NestedExceptionRecord.ExceptionRecord = ExceptionRecord;
    NestedExceptionRecord.NumberParameters = Status;

    /* Raise the exception */
    RtlRaiseException(&NestedExceptionRecord);
}

FASTCALL VOID RtlpRestoreFpuContext(IN PCONTEXT Context);

NTAPI DECLSPEC_NOFPU NTSTATUS NtContinue(IN PCONTEXT Context,
					 IN BOOLEAN TestAlert)
{
    RtlpRestoreFpuContext(Context);
    KeContinue(Context);
    /* This should not return. */
    RtlRaiseStatus(STATUS_UNSUCCESSFUL);
    return STATUS_UNSUCCESSFUL;
}

NTAPI NTSTATUS NtRaiseException(IN PEXCEPTION_RECORD ExceptionRecord,
				IN PCONTEXT Context,
				IN BOOLEAN FirstChance)
{
    if (FirstChance) {
	/* This should never return. If it did, we fall through
	 * and terminate the process. */
	KiDispatchUserException(Context, ExceptionRecord);
    }

    EXCEPTION_POINTERS ExceptionInfo = {
	.ExceptionRecord = ExceptionRecord,
	.ContextRecord = Context
    };
#if DBG
    RtlpPrintStackTrace(&ExceptionInfo, TRUE);
#endif
    RtlpVgaPrintStackTrace(&ExceptionInfo, TRUE);
    NtTerminateProcess(NtCurrentProcess(), ExceptionRecord->ExceptionCode);
    return STATUS_SUCCESS;
}
