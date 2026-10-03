#include "k32.h"

#define FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE \
    CTL_CODE(FILE_DEVICE_NAMED_PIPE, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)

static inline BOOL SetNtStatus(NTSTATUS Status)
{
    if (Status)
	SetLastError(RtlNtStatusToDosError(Status));
    return !Status;
}

/***********************************************************************
 *           GetNamedPipeClientProcessId  (KERNEL32.@)
 */
BOOL WINAPI GetNamedPipeClientProcessId(HANDLE Pipe, ULONG *Id)
{
    IO_STATUS_BLOCK Iosb;

    return SetNtStatus(NtFsControlFile(Pipe, NULL, NULL, NULL, &Iosb,
				       FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE,
				       "ClientProcessId",
				       sizeof("ClientProcessId"), Id, sizeof(*Id)));
}
