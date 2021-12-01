#include <ntos.h>

/*
 * TODO: Check if calling process has the required privilege
 */
NTSTATUS NtDisplayString(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
			 IN PCSTR String)
{
    HalDisplayString(String);
    return STATUS_SUCCESS;
}
