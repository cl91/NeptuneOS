HEADER("EXCEPTION_RECORD"),
OFFSET(EXCEPTION_RECORD_EXCEPTION_CODE, EXCEPTION_RECORD, ExceptionCode),
OFFSET(EXCEPTION_RECORD_EXCEPTION_FLAGS, EXCEPTION_RECORD, ExceptionFlags),
OFFSET(EXCEPTION_RECORD_EXCEPTION_RECORD, EXCEPTION_RECORD, ExceptionRecord),
OFFSET(EXCEPTION_RECORD_EXCEPTION_ADDRESS, EXCEPTION_RECORD, ExceptionAddress),
OFFSET(EXCEPTION_RECORD_NUMBER_PARAMETERS, EXCEPTION_RECORD, NumberParameters),
OFFSET(EXCEPTION_RECORD_EXCEPTION_ADDRESS, EXCEPTION_RECORD, ExceptionAddress),
SIZE(EXCEPTION_RECORD_LENGTH, EXCEPTION_RECORD),

HEADER("EXCEPTION_POINTERS"),
OFFSET(EXCEPTION_POINTERS_EXCEPTION_RECORD, EXCEPTION_POINTERS, ExceptionRecord),
OFFSET(EXCEPTION_POINTERS_CONTEXT_RECORD, EXCEPTION_POINTERS, ContextRecord),

HEADER("TEB"),
OFFSET(TEB_EXCEPTION_LIST, TEB, NtTib.ExceptionList),
OFFSET(TEB_STACK_BASE, TEB, NtTib.StackBase),
OFFSET(TEB_STACK_LIMIT, TEB, NtTib.StackLimit),
OFFSET(TEB_FIBER_DATA, TEB, NtTib.FiberData),
OFFSET(TEB_SELF, TEB, NtTib.Self),
OFFSET(TEB_PEB, TEB, ProcessEnvironmentBlock),
OFFSET(TEB_DEALLOCATION_STACK, TEB, DeallocationStack),
OFFSET(TEB_FLS_DATA, TEB, FlsData),

HEADER("CONTEXT"),
OFFSET(CONTEXT_FLAGS, CONTEXT, ContextFlags),
OFFSET(CONTEXT_EDI, CONTEXT, Edi),
OFFSET(CONTEXT_ESI, CONTEXT, Esi),
OFFSET(CONTEXT_EBX, CONTEXT, Ebx),
OFFSET(CONTEXT_EDX, CONTEXT, Edx),
OFFSET(CONTEXT_ECX, CONTEXT, Ecx),
OFFSET(CONTEXT_EAX, CONTEXT, Eax),
OFFSET(CONTEXT_EBP, CONTEXT, Ebp),
OFFSET(CONTEXT_EIP, CONTEXT, Eip),
OFFSET(CONTEXT_EFLAGS, CONTEXT, EFlags),
OFFSET(CONTEXT_ESP, CONTEXT, Esp),
OFFSET(CONTEXT_FS_BASE, CONTEXT, FsBase),
OFFSET(CONTEXT_GS_BASE, CONTEXT, GsBase),
OFFSET(CONTEXT_XMM_SAVE_AREA, CONTEXT, FltSave),
SIZE(CONTEXT_FRAME_LENGTH, CONTEXT),
