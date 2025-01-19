#include <ntdll.h>

/*
 * This table converts the x86/amd64 exception code to the NT status code.
 */
static NTSTATUS KiUserExceptionCodeTable[] = {
    STATUS_INTEGER_DIVIDE_BY_ZERO,  /* 0x00 #DE (Divide Error) */
    STATUS_SINGLE_STEP,		    /* 0x01 #DB (Debug Exception) */
    STATUS_UNSUCCESSFUL,	    /* 0x02 Non-maskable Interrupt */
    STATUS_BREAKPOINT,		    /* 0x03 #BP (Breakpoint Exception) */
    STATUS_INTEGER_OVERFLOW,	    /* 0x04 #OF (Overflow Exception) */
    STATUS_ARRAY_BOUNDS_EXCEEDED,   /* 0x05 #BR (BOUND Range Exceeded) */
    STATUS_ILLEGAL_INSTRUCTION,	    /* 0x06 #UD (Invalid Opcode Code) */
    STATUS_UNSUCCESSFUL,	    /* 0x07 #NM (Device Not Available) */
    STATUS_UNSUCCESSFUL,	    /* 0x08 #DF (Double Fault Exception) */
    STATUS_UNSUCCESSFUL,	    /* 0x09 Reserved */
    STATUS_UNSUCCESSFUL,	    /* 0x0A #TS (Invalid TSS Exception) */
    STATUS_UNSUCCESSFUL,	    /* 0x0B #NP (Segment Not Present) */
    STATUS_UNSUCCESSFUL,	    /* 0x0C #SS (Stack Fault Exception) */
    STATUS_ACCESS_VIOLATION,	    /* 0x0D #GP (General Protection Fault) */
    STATUS_ACCESS_VIOLATION,	    /* 0x0E #PF (Page Fault Exception) */
    STATUS_UNSUCCESSFUL,	    /* 0x0F Reserved */
};

/*
 * This will convert the ExceptionRecord from our own format to
 * what NT generates.
 */
static VOID KiConvertExceptionRecord(IN OUT PEXCEPTION_RECORD ExceptionRecord)
{
    ULONG ExceptionCode = ExceptionRecord->ExceptionCode;

    if (ExceptionCode == KI_VM_FAULT_CODE) {
	ExceptionRecord->ExceptionCode = STATUS_ACCESS_VIOLATION;
	ExceptionRecord->NumberParameters++;
	ExceptionRecord->ExceptionInformation[1] = ExceptionRecord->ExceptionInformation[0];
	ExceptionRecord->ExceptionInformation[0] = 1;
    } else if (ExceptionCode >= ARRAYSIZE(KiUserExceptionCodeTable)) {
	ExceptionRecord->ExceptionCode = STATUS_UNSUCCESSFUL;
    } else {
	ExceptionRecord->ExceptionCode = KiUserExceptionCodeTable[ExceptionCode];
    }

    /* In the case of illegal instruction, we check if it's an invalid lock
     * sequence. Note we don't need to worry about access violations here
     * because system wouldn't send an illegal instruction exception if the
     * IP points to invalid memory. */
    if (ExceptionRecord->ExceptionCode == STATUS_ILLEGAL_INSTRUCTION) {
	/* Check for LOCK prefix */
	if (*(PUCHAR)ExceptionRecord->ExceptionAddress == 0xF0) {
	    ExceptionRecord->ExceptionCode = STATUS_INVALID_LOCK_SEQUENCE;
	}
    }
}

FASTCALL VOID KiDispatchUserException(IN PEXCEPTION_RECORD ExceptionRecord,
				      IN PCONTEXT Context)
{
    DbgTrace("ExceptionRecord %p Context %p\n", ExceptionRecord, Context);
    KiConvertExceptionRecord(ExceptionRecord);

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
	KiDispatchUserException(ExceptionRecord, Context);
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
