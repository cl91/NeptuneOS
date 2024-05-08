#include "ei.h"

NTSTATUS NtRaiseHardError(IN ASYNC_STATE State,
			  IN PTHREAD Thread,
                          IN NTSTATUS ErrorStatus,
                          IN ULONG NumberOfParameters,
                          IN ULONG UnicodeStringParameterMask,
                          IN PULONG_PTR Parameters,
                          IN HARDERROR_RESPONSE_OPTION ResponseOption,
                          OUT HARDERROR_RESPONSE *Response)
{
    /* For now we will simply terminate the current process. */
    HalVgaPrint("Thread %s terminated with hard error 0x%08x. Killing process.\n",
		KEDBG_THREAD_TO_FILENAME(Thread));
    PsTerminateProcess(Thread->Process, ErrorStatus);
    return STATUS_NTOS_NO_REPLY;
}
