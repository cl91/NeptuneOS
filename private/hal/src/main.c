/*
 * The main event loop of the driver process
 */

#include <hal.h>

NTSTATUS IopCallDriverEntry()
{
    ANSI_STRING Name;
    RtlInitAnsiString(&Name, "DriverEntry");
    PLDR_DATA_TABLE_ENTRY LdrDriverImage = NULL;
    RET_ERR(LdrFindEntryForAddress(NtCurrentPeb()->ImageBaseAddress, &LdrDriverImage));
    PVOID DriverEntry = LdrDriverImage->EntryPoint;
    RET_ERR(((PDRIVER_INITIALIZE)DriverEntry)(NULL, NULL));
    return STATUS_SUCCESS;
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    NtDisplayStringA("hal.dll: Calling DriverEntry...\n");
    NTSTATUS Status = IopCallDriverEntry();
    DbgPrint("hal.dll: IopCallDriverEntry returned with status 0x%x\n",
	     Status);

    while (1);
}
