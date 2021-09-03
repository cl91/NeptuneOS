#include <ntos.h>

/*
 * TODO: Check if calling process has the required privilege
 */
NTSTATUS SysNtDisplayString(IN PTHREAD Thread,
			    IN PCSTR String)
{
    KeVgaWriteString(String);
    return STATUS_SUCCESS;
}
