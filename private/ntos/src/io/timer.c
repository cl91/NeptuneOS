#include <ntos.h>

NTSTATUS IopCreateTimer(IN ASYNC_STATE AsyncState,
                        IN struct _THREAD *Thread,
                        OUT HANDLE *Handle)
{
    return STATUS_SUCCESS;
}

NTSTATUS IopSetTimer(IN ASYNC_STATE AsyncState,
                     IN struct _THREAD *Thread,
                     IN HANDLE Handle,
                     IN PLARGE_INTEGER DueTime)
{
    return STATUS_SUCCESS;
}
