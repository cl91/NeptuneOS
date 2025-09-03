#include "precomp.h"
#include <scsiwmi.h>

NTAPI BOOLEAN ScsiPortWmiDispatchFunction(_In_ PSCSI_WMILIB_CONTEXT WmiLibInfo,
					  _In_ UCHAR MinorFunction,
					  _In_ PVOID DeviceContext,
					  _In_ PSCSIWMI_REQUEST_CONTEXT RequestContext,
					  _In_ PVOID DataPath,
					  _In_ ULONG BufferSize,
					  _In_ PVOID Buffer)
{
    return FALSE;
}

NTAPI VOID ScsiPortWmiPostProcess(_Inout_ PSCSIWMI_REQUEST_CONTEXT RequestContext,
				  _In_ UCHAR SrbStatus,
				  _In_ ULONG BufferUsed)
{
}
