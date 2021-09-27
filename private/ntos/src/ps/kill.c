#include "psp.h"

NTSTATUS NtTerminateThread(IN PTHREAD Thread,
                           IN HANDLE ThreadHandle,
                           IN NTSTATUS ExitStatus)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtTerminateProcess(IN PTHREAD Thread,
                            IN HANDLE ProcessHandle,
                            IN NTSTATUS ExitStatus)
{
    return STATUS_NOT_IMPLEMENTED;
}
