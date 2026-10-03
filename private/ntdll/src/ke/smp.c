#include <ntdll.h>

NTAPI ULONG NtGetCurrentProcessorNumber(VOID)
{
    return 0;
}

NTAPI NTSTATUS NtYieldExecution(VOID)
{
    seL4_Yield();
    return STATUS_SUCCESS;
}
