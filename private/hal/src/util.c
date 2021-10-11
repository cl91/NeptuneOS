#include <hal.h>

/*
 * @implemented
 */
NTAPI PVOID MmPageEntireDriver(IN PVOID Address)
{
    PLDR_DATA_TABLE_ENTRY Module = NULL;
    NTSTATUS Status = LdrFindEntryForAddress(Address, &Module);
    if (!NT_SUCCESS(Status) || Module == NULL) {
	return NULL;
    }
    return Module->DllBase;
}
