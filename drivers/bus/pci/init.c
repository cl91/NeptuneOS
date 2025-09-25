/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/init.c
 * PURPOSE:         Driver Initialization
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* GLOBALS ********************************************************************/

PDRIVER_OBJECT PciDriverObject;
BOOLEAN PciLockDeviceResources;
ULONG PciSystemWideHackFlags;
PPCI_HACK_ENTRY PciHackTable;

/* FUNCTIONS ******************************************************************/

static NTSTATUS PciBuildHackTable(IN HANDLE KeyHandle)
{
    PKEY_FULL_INFORMATION FullInfo;
    ULONG i, HackCount;
    PKEY_VALUE_FULL_INFORMATION ValueInfo;
    PPCI_HACK_ENTRY Entry;
    NTSTATUS Status;
    ULONG NameLength, ResultLength;
    ULONGLONG HackFlags;

    /* So we know what to free at the end of the body */
    FullInfo = NULL;
    ValueInfo = NULL;
    do {
	/* Query the size required for full key information */
	Status = NtQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &ResultLength);
	if (Status != STATUS_BUFFER_TOO_SMALL)
	    break;

	/* Allocate the space required to hold the full key information */
	Status = STATUS_INSUFFICIENT_RESOURCES;
	ASSERT(ResultLength > 0);
	FullInfo = ExAllocatePoolWithTag(NonPagedPool, ResultLength, PCI_POOL_TAG);
	if (!FullInfo)
	    break;

	/* Go ahead and query the key information */
	Status = NtQueryKey(KeyHandle, KeyFullInformation, FullInfo, ResultLength,
			    &ResultLength);
	if (!NT_SUCCESS(Status))
	    break;

	/* The only piece of information that's needed is the count of values */
	HackCount = FullInfo->Values;

	/* Free the structure now */
	ExFreePoolWithTag(FullInfo, 0);
	FullInfo = NULL;

	/* Allocate the hack table, now that the number of entries is known */
	Status = STATUS_INSUFFICIENT_RESOURCES;
	ResultLength = sizeof(PCI_HACK_ENTRY) * HackCount;
	PciHackTable = ExAllocatePoolWithTag(NonPagedPool,
					     ResultLength + sizeof(PCI_HACK_ENTRY),
					     PCI_POOL_TAG);
	if (!PciHackTable)
	    break;

	/* Allocate the space needed to hold the full value information */
	ValueInfo = ExAllocatePoolWithTag(NonPagedPool,
					  sizeof(KEY_VALUE_FULL_INFORMATION) +
					  PCI_HACK_ENTRY_FULL_SIZE,
					  PCI_POOL_TAG);
	if (!PciHackTable)
	    break;

	/* Loop each value in the registry */
	Entry = &PciHackTable[0];
	for (i = 0; i < HackCount; i++) {
	    /* Get the entry for this value */
	    Entry = &PciHackTable[i];

	    /* Query the value in the key */
	    Status = NtEnumerateValueKey(KeyHandle, i, KeyValueFullInformation, ValueInfo,
					 sizeof(KEY_VALUE_FULL_INFORMATION) +
					 PCI_HACK_ENTRY_FULL_SIZE,
					 &ResultLength);
	    if (!NT_SUCCESS(Status)) {
		/* Check why the call failed */
		if ((Status != STATUS_BUFFER_OVERFLOW) &&
		    (Status != STATUS_BUFFER_TOO_SMALL)) {
		    /* The call failed due to an unknown error, bail out */
		    break;
		}

		/* The data seems to mismatch, try the next key in the list */
		continue;
	    }

	    /* Check if the value data matches what's expected */
	    if ((ValueInfo->Type != REG_BINARY) ||
		(ValueInfo->DataLength != sizeof(ULONGLONG))) {
		/* It doesn't, try the next key in the list */
		continue;
	    }

	    /* Read the actual hack flags */
	    HackFlags = *(PULONGLONG)((ULONG_PTR)ValueInfo + ValueInfo->DataOffset);

	    /* Check what kind of errata entry this is, based on the name */
	    NameLength = ValueInfo->NameLength;
	    if ((NameLength != PCI_HACK_ENTRY_SIZE) &&
		(NameLength != PCI_HACK_ENTRY_REV_SIZE) &&
		(NameLength != PCI_HACK_ENTRY_SUBSYS_SIZE) &&
		(NameLength != PCI_HACK_ENTRY_FULL_SIZE)) {
		/* It's an invalid entry, skip it */
		DPRINT1("Skipping hack entry with invalid length name\n");
		continue;
	    }

	    /* Initialize the entry */
	    RtlZeroMemory(Entry, sizeof(PCI_HACK_ENTRY));

	    /* Get the vendor and device data */
	    if (!(PciStringToUSHORT(ValueInfo->Name, &Entry->VendorID)) ||
		!(PciStringToUSHORT(&ValueInfo->Name[4], &Entry->DeviceID))) {
		/* This failed, try the next entry */
		continue;
	    }

	    /* Check if the entry contains subsystem information */
	    if ((NameLength == PCI_HACK_ENTRY_SUBSYS_SIZE) ||
		(NameLength == PCI_HACK_ENTRY_FULL_SIZE)) {
		/* Get the data */
		if (!(PciStringToUSHORT(&ValueInfo->Name[8], &Entry->SubVendorID)) ||
		    !(PciStringToUSHORT(&ValueInfo->Name[12], &Entry->SubSystemID))) {
		    /* This failed, try the next entry */
		    continue;
		}

		/* Save the fact this entry has finer controls */
		Entry->Flags |= PCI_HACK_HAS_SUBSYSTEM_INFO;
	    }

	    /* Check if the entry contains revision information */
	    if ((NameLength == PCI_HACK_ENTRY_REV_SIZE) ||
		(NameLength == PCI_HACK_ENTRY_FULL_SIZE)) {
		/* Get the data */
		if (!PciStringToUSHORT(&ValueInfo->Name[16], &Entry->RevisionID)) {
		    /* This failed, try the next entry */
		    continue;
		}

		/* Save the fact this entry has finer controls */
		Entry->Flags |= PCI_HACK_HAS_REVISION_INFO;
	    }

	    /* Only the last entry should have this set */
	    ASSERT(Entry->VendorID != PCI_INVALID_VENDORID);

	    /* Save the actual hack flags */
	    Entry->HackFlags = HackFlags;

	    /* Print out for the debugger's sake */
#ifdef HACK_DEBUG
	    DPRINT1("Adding Hack entry for Vendor:0x%04x Device:0x%04x ", Entry->VendorID,
		    Entry->DeviceID);
	    if (Entry->Flags & PCI_HACK_HAS_SUBSYSTEM_INFO)
		DbgPrint("SybSys:0x%04x SubVendor:0x%04x ", Entry->SubSystemID,
			 Entry->SubVendorID);
	    if (Entry->Flags & PCI_HACK_HAS_REVISION_INFO)
		DbgPrint("Revision:0x%02x", Entry->RevisionID);
	    DbgPrint(" = 0x%llx\n", Entry->HackFlags);
#endif
	}

	/* Bail out in case of failure */
	if (!NT_SUCCESS(Status))
	    break;

	/* Terminate the table with an invalid entry */
	ASSERT(Entry < (PciHackTable + HackCount + 1));
	Entry->VendorID = PCI_INVALID_VENDORID;

	/* Success path, free the temporary registry data */
	ExFreePoolWithTag(ValueInfo, 0);
	return STATUS_SUCCESS;
    } while (TRUE);

    /* Failure path, free temporary allocations and return failure code */
    ASSERT(!NT_SUCCESS(Status));
    if (FullInfo)
	ExFreePool(FullInfo);
    if (ValueInfo)
	ExFreePool(ValueInfo);
    if (PciHackTable) {
	ExFreePool(PciHackTable);
	PciHackTable = NULL;
    }
    return Status;
}

static NTSTATUS PciGetDebugPorts(IN HANDLE DebugKey)
{
    UNREFERENCED_PARAMETER(DebugKey);
    /* This function is not yet implemented */
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_SUCCESS;
}

DRIVER_UNLOAD PciDriverUnload;

NTAPI VOID PciDriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    /* This function is not yet implemented */
    UNIMPLEMENTED_DBGBREAK("PCI: Unload\n");
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    HANDLE KeyHandle = NULL, ParametersKey = NULL, DebugKey = NULL, ControlSetKey = NULL;
    BOOLEAN Result;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG ResultLength;
    PULONG Value;
    PWCHAR StartOptions;
    UNICODE_STRING OptionString, PciLockString;
    NTSTATUS Status;
    DPRINT1("PCI: DriverEntry!\n");

    /* Remember our object so we can get it to it later */
    PciDriverObject = DriverObject;

    /* Setup the IRP dispatcher */
    DriverObject->MajorFunction[IRP_MJ_POWER] = PciDispatchIrp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PciDispatchIrp;
    DriverObject->MajorFunction[IRP_MJ_PNP] = PciDispatchIrp;
    DriverObject->DriverUnload = PciDriverUnload;

    /* This is how we'll detect a new PCI bus */
    DriverObject->AddDevice = PciAddDevice;

    /* Open the PCI key */
    InitializeObjectAttributes(&ObjectAttributes, RegistryPath,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
	goto out;

    /* Open the Parameters subkey */
    Result = PciOpenKey(L"Parameters", KeyHandle, KEY_QUERY_VALUE, &ParametersKey,
			&Status);
    //if (!Result) goto out;

    /* Build the list of all known PCI erratas */
    Status = PciBuildHackTable(ParametersKey);
    //if (!NT_SUCCESS(Status)) goto out;

    /* Open the debug key, if it exists */
    Result = PciOpenKey(L"Debug", KeyHandle, KEY_QUERY_VALUE, &DebugKey, &Status);
    if (Result) {
	/* There are PCI debug devices, go discover them */
	Status = PciGetDebugPorts(DebugKey);
	if (!NT_SUCCESS(Status))
	    goto out;
    }

    /* Open the control set key */
    Result = PciOpenKey(L"\\Registry\\Machine\\System\\CurrentControlSet", NULL,
			KEY_QUERY_VALUE, &ControlSetKey, &Status);
    if (!Result)
	goto out;

    /* Read the command line */
    Status = PciGetRegistryValue(L"SystemStartOptions", L"Control", ControlSetKey,
				 REG_SZ, (PVOID *)&StartOptions, &ResultLength);
    if (NT_SUCCESS(Status)) {
	/* Initialize the command-line as a string */
	OptionString.Buffer = StartOptions;
	OptionString.MaximumLength = OptionString.Length = ResultLength;

	/* Check if the command-line has the PCILOCK argument */
	RtlInitUnicodeString(&PciLockString, L"PCILOCK");
	if (PciUnicodeStringStrStr(&OptionString, &PciLockString, TRUE)) {
	    /* The PCI Bus driver will keep the BIOS-assigned resources */
	    PciLockDeviceResources = TRUE;
	}

	/* This data isn't needed anymore */
	ExFreePoolWithTag(StartOptions, 0);
    }

    /* The PCILOCK feature can also be enabled per-system in the registry */
    Status = PciGetRegistryValue(L"PCILock", L"Control\\BiosInfo\\PCI", ControlSetKey,
				 REG_DWORD, (PVOID *)&Value, &ResultLength);
    if (NT_SUCCESS(Status)) {
	/* Read the value it's been set to. This overrides /PCILOCK */
	if (ResultLength == sizeof(ULONG))
	    PciLockDeviceResources = *Value;
	ExFreePoolWithTag(Value, 0);
    }

    /* The system can have global PCI erratas in the registry */
    Status = PciGetRegistryValue(L"HackFlags", L"Control\\PnP\\PCI", ControlSetKey,
				 REG_DWORD, (PVOID *)&Value, &ResultLength);
    if (NT_SUCCESS(Status)) {
	/* Read them in */
	if (ResultLength == sizeof(ULONG))
	    PciSystemWideHackFlags = *Value;
	ExFreePoolWithTag(Value, 0);
    }

    /* Build the range lists for all the excluded resource areas */
    Status = PciBuildDefaultExclusionLists();
    if (!NT_SUCCESS(Status))
	goto out;

    Status = STATUS_SUCCESS;

    /* Close all opened keys, return driver status to PnP Manager */
out:
    if (KeyHandle)
	NtClose(KeyHandle);
    if (ControlSetKey)
	NtClose(ControlSetKey);
    if (ParametersKey)
	NtClose(ParametersKey);
    if (DebugKey)
	NtClose(DebugKey);
    return Status;
}
