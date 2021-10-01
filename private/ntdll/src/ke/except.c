#include <ntdll.h>

NTAPI NTSTATUS NtRaiseException(IN PEXCEPTION_RECORD ExceptionRecord,
				IN PCONTEXT Context,
				IN BOOLEAN SearchFrames)
{
    NtTerminateThread(NtCurrentThread(), STATUS_UNSUCCESSFUL);
    return STATUS_NOT_IMPLEMENTED;
}
