#include "rtlp.h"

/*
 * @unimplemented
 */
NTAPI NTSTATUS RtlAdjustPrivilege(IN ULONG Privilege,
				  IN BOOLEAN Enable,
				  IN BOOLEAN CurrentThread,
				  OUT PBOOLEAN Enabled)
{
    return STATUS_SUCCESS;
}
