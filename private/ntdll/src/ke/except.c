#include <ntdll.h>

NTAPI NTSTATUS NtRaiseException(IN PEXCEPTION_RECORD ExceptionRecord,
				IN PCONTEXT Context,
				IN BOOLEAN SearchFrames)
{
    return STATUS_NOT_IMPLEMENTED;
}
