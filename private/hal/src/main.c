/*
 * The main event loop of the driver process
 */

#include <hal.h>

static NTSTATUS IopCallDriverEntry(PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY LdrDriverImage = NULL;
    RET_ERR(LdrFindEntryForAddress(NtCurrentPeb()->ImageBaseAddress, &LdrDriverImage));
    PVOID DriverEntry = LdrDriverImage->EntryPoint;
    RET_ERR(((PDRIVER_INITIALIZE)DriverEntry)(DriverObject, NULL));
    return STATUS_SUCCESS;
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    NtDisplayStringA("hal.dll: Allocating DriverObject... ");
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT) RtlAllocateHeap(RtlGetProcessHeap(),
								   HEAP_ZERO_MEMORY,
								   sizeof(DRIVER_OBJECT));
    if (DriverObject == NULL) {
	NtDisplayStringA("FAIL\n");
	return;
    } else {
	NtDisplayStringA("OK\n");
    }

    NtDisplayStringA("hal.dll: Calling DriverEntry...\n");
    NTSTATUS Status = IopCallDriverEntry(DriverObject);
    DbgPrint("hal.dll: IopCallDriverEntry returned with status 0x%x\n",
	     Status);

    while (1);
}
