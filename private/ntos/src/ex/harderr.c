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
    return STATUS_NOT_IMPLEMENTED;
}
