/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/utils.c
 * PURPOSE:         Utility/Helper Support Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"
#include <stdio.h>

/* GLOBALS ********************************************************************/

ULONG PciDebugPortsCount;

RTL_RANGE_LIST PciIsaBitExclusionList;
RTL_RANGE_LIST PciVgaAndIsaBitExclusionList;

/* FUNCTIONS ******************************************************************/

BOOLEAN PciUnicodeStringStrStr(IN PUNICODE_STRING InputString,
			       IN PCUNICODE_STRING EqualString,
			       IN BOOLEAN CaseInSensitive)
{
    UNICODE_STRING PartialString;
    LONG EqualChars, TotalChars;

    /* Build a partial string with the smaller substring */
    PartialString.Length = EqualString->Length;
    PartialString.MaximumLength = InputString->MaximumLength;
    PartialString.Buffer = InputString->Buffer;

    /* Check how many characters that need comparing */
    EqualChars = 0;
    TotalChars = (InputString->Length - EqualString->Length) / sizeof(WCHAR);

    /* If the substring is bigger, just fail immediately */
    if (TotalChars < 0)
	return FALSE;

    /* Keep checking each character */
    while (!RtlEqualUnicodeString(EqualString, &PartialString, CaseInSensitive)) {
	/* Continue checking until all the required characters are equal */
	PartialString.Buffer++;
	PartialString.MaximumLength -= sizeof(WCHAR);
	if (++EqualChars > TotalChars)
	    return FALSE;
    }

    /* The string is equal */
    return TRUE;
}

BOOLEAN PciStringToUSHORT(IN PWCHAR String, OUT PUSHORT Value)
{
    USHORT Short;
    ULONG Low, High, Length;
    WCHAR Char;

    /* Initialize everything to zero */
    Short = 0;
    Length = 0;
    while (TRUE) {
	/* Get the character and set the high byte based on the previous one */
	Char = *String++;
	High = 16 * Short;

	/* Check for numbers */
	if (Char >= '0' && Char <= '9') {
	    /* Convert them to a byte */
	    Low = Char - '0';
	} else if (Char >= 'A' && Char <= 'F') {
	    /* Convert upper-case hex letters into a byte */
	    Low = Char - '7';
	} else if (Char >= 'a' && Char <= 'f') {
	    /* Convert lower-case hex letters into a byte */
	    Low = Char - 'W';
	} else {
	    /* Invalid string, fail the conversion */
	    return FALSE;
	}

	/* Combine the high and low byte */
	Short = High | Low;

	/* If 4 letters have been reached, the 16-bit integer should exist */
	if (++Length >= 4) {
	    /* Return it to the caller */
	    *Value = Short;
	    return TRUE;
	}
    }
}

BOOLEAN PciIsSuiteVersion(IN USHORT SuiteMask)
{
    ULONGLONG Mask = 0;
    RTL_OSVERSIONINFOEX VersionInfo;

    /* Initialize the version information */
    RtlZeroMemory(&VersionInfo, sizeof(RTL_OSVERSIONINFOEX));
    VersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEX);
    VersionInfo.wSuiteMask = SuiteMask;

    /* Set the comparison mask and return if the passed suite mask matches */
    VER_SET_CONDITION(Mask, VER_SUITENAME, VER_AND);
    return NT_SUCCESS(RtlVerifyVersionInfo(&VersionInfo, VER_SUITENAME, Mask));
}

BOOLEAN PciIsDatacenter(VOID)
{
    BOOLEAN Result;
    PVOID Value;
    ULONG ResultLength;
    NTSTATUS Status;

    /* Assume this isn't Datacenter */
    Result = FALSE;

    /* First, try opening the setup key */
    Status = PciGetRegistryValue(L"",
				 L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services"
				 L"\\setupdd",
				 0, REG_BINARY, &Value, &ResultLength);
    if (!NT_SUCCESS(Status)) {
	/* This is not an in-progress Setup boot, so query the suite version */
	Result = PciIsSuiteVersion(VER_SUITE_DATACENTER);
    } else {
	/* This scenario shouldn't happen yet, since SetupDD isn't used */
	UNIMPLEMENTED_FATAL("ReactOS doesn't use SetupDD for its installation program. "
			    "Therefore this scenario must not happen!\n");
    }

    /* Return if this is Datacenter or not */
    return Result;
}

BOOLEAN PciOpenKey(IN PWCHAR KeyName, IN HANDLE RootKey,
		   IN ACCESS_MASK DesiredAccess, OUT PHANDLE KeyHandle,
		   OUT PNTSTATUS KeyStatus)
{
    PAGED_CODE();
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyString;

    /* Initialize the object attributes */
    RtlInitUnicodeString(&KeyString, KeyName);
    InitializeObjectAttributes(&ObjectAttributes, &KeyString,
			       OBJ_CASE_INSENSITIVE, RootKey, NULL);

    /* Open the key, returning a boolean, and the status, if requested */
    Status = NtOpenKey(KeyHandle, DesiredAccess, &ObjectAttributes);
    if (KeyStatus)
	*KeyStatus = Status;
    return NT_SUCCESS(Status);
}

NTSTATUS PciGetRegistryValue(IN PWCHAR ValueName, IN PWCHAR KeyName,
			     IN HANDLE RootHandle, IN ULONG Type,
			     OUT PVOID *OutputBuffer, OUT PULONG OutputLength)
{
    NTSTATUS Status;
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo;
    ULONG NeededLength, ActualLength;
    UNICODE_STRING ValueString;
    HANDLE KeyHandle;
    BOOLEAN Result;

    /* So we know what to free at the end of the body */
    PartialInfo = NULL;
    KeyHandle = NULL;

    /* Open the key by name, rooted off the handle passed */
    Result = PciOpenKey(KeyName, RootHandle, KEY_QUERY_VALUE, &KeyHandle, &Status);
    if (!Result)
	goto out;

    /* Query for the size that's needed for the value that was passed in */
    RtlInitUnicodeString(&ValueString, ValueName);
    Status = NtQueryValueKey(KeyHandle, &ValueString, KeyValuePartialInformation,
			     NULL, 0, &NeededLength);
    ASSERT(!NT_SUCCESS(Status));
    if (Status != STATUS_BUFFER_TOO_SMALL)
	goto out;

    /* Allocate an appropriate buffer for the size that was returned */
    ASSERT(NeededLength != 0);
    Status = STATUS_INSUFFICIENT_RESOURCES;
    PartialInfo = ExAllocatePoolWithTag(NeededLength, PCI_POOL_TAG);
    if (!PartialInfo)
	goto out;

    /* Query the actual value information now that the size is known */
    Status = NtQueryValueKey(KeyHandle, &ValueString, KeyValuePartialInformation,
			     PartialInfo, NeededLength, &ActualLength);
    if (!NT_SUCCESS(Status))
	goto out;

    /* Make sure it's of the type that the caller expects */
    Status = STATUS_INVALID_PARAMETER;
    if (PartialInfo->Type != Type)
	goto out;

    /* Subtract the registry-specific header, to get the data size */
    ASSERT(NeededLength == ActualLength);
    NeededLength -= sizeof(KEY_VALUE_PARTIAL_INFORMATION);

    /* Allocate a buffer to hold the data and return it to the caller */
    Status = STATUS_INSUFFICIENT_RESOURCES;
    *OutputBuffer = ExAllocatePoolWithTag(NeededLength, PCI_POOL_TAG);
    if (!*OutputBuffer)
	goto out;

    /* Copy the data into the buffer and return its length to the caller */
    RtlCopyMemory(*OutputBuffer, PartialInfo->Data, NeededLength);
    if (OutputLength)
	*OutputLength = NeededLength;
    Status = STATUS_SUCCESS;

    /* Close any opened keys and free temporary allocations */
out:
    if (KeyHandle)
	NtClose(KeyHandle);
    if (PartialInfo)
	ExFreePoolWithTag(PartialInfo, 0);
    return Status;
}

NTSTATUS PciBuildDefaultExclusionLists(VOID)
{
    ULONG Start;
    NTSTATUS Status;
    ASSERT(PciIsaBitExclusionList.Count == 0);
    ASSERT(PciVgaAndIsaBitExclusionList.Count == 0);

    /* Initialize the range lists */
    RtlInitializeRangeList(&PciIsaBitExclusionList);
    RtlInitializeRangeList(&PciVgaAndIsaBitExclusionList);

    /* Loop x86 I/O ranges */
    for (Start = 0x100; Start <= 0xFEFF; Start += 0x400) {
	/* Add the ISA I/O ranges */
	Status = RtlAddRange(&PciIsaBitExclusionList, Start, Start + 0x2FF, 0,
			     RTL_RANGE_LIST_ADD_IF_CONFLICT, NULL, NULL);
	if (!NT_SUCCESS(Status))
	    break;

	/* Add the ISA I/O ranges */
	Status = RtlAddRange(&PciVgaAndIsaBitExclusionList, Start, Start + 0x2AF, 0,
			     RTL_RANGE_LIST_ADD_IF_CONFLICT, NULL, NULL);
	if (!NT_SUCCESS(Status))
	    break;

	/* Add the VGA I/O range for Monochrome Video */
	Status = RtlAddRange(&PciVgaAndIsaBitExclusionList, Start + 0x2BC, Start + 0x2BF,
			     0, RTL_RANGE_LIST_ADD_IF_CONFLICT, NULL, NULL);
	if (!NT_SUCCESS(Status))
	    break;

	/* Add the VGA I/O range for certain CGA adapters */
	Status = RtlAddRange(&PciVgaAndIsaBitExclusionList, Start + 0x2E0, Start + 0x2FF,
			     0, RTL_RANGE_LIST_ADD_IF_CONFLICT, NULL, NULL);
	if (!NT_SUCCESS(Status))
	    break;

	/* Success, ranges added done */
    };

    RtlFreeRangeList(&PciIsaBitExclusionList);
    RtlFreeRangeList(&PciVgaAndIsaBitExclusionList);
    return Status;
}

PPCI_FDO_EXTENSION PciFindParentPciFdoExtension(IN PDEVICE_OBJECT DeviceObject)
{
    PPCI_FDO_EXTENSION DeviceExtension;
    PPCI_PDO_EXTENSION SearchExtension, FoundExtension;

    /* Assume we'll find nothing */
    SearchExtension = DeviceObject->DeviceExtension;
    FoundExtension = NULL;

    /* Now search for the extension */
    DeviceExtension = (PPCI_FDO_EXTENSION)PciFdoExtensionListHead.Next;
    while (DeviceExtension) {
	/* Scan all child PDOs, stop when no more PDOs, or found it */
	for (FoundExtension = DeviceExtension->ChildPdoList;
	     ((FoundExtension) && (FoundExtension != SearchExtension));
	     FoundExtension = FoundExtension->Next)
	    ;

	/* If we found it, break out */
	if (FoundExtension)
	    break;

	/* Move to the next device */
	DeviceExtension = (PPCI_FDO_EXTENSION)DeviceExtension->List.Next;
    }

    /* Return which extension was found, if any */
    return DeviceExtension;
}

VOID PciInsertEntryAtTail(IN PSINGLE_LIST_ENTRY ListHead,
			  IN PPCI_FDO_EXTENSION DeviceExtension)
{
    PAGED_CODE();
    PSINGLE_LIST_ENTRY NextEntry;

    /* Loop the list until we get to the end, then insert this entry there */
    for (NextEntry = ListHead; NextEntry->Next; NextEntry = NextEntry->Next)
	;
    NextEntry->Next = &DeviceExtension->List;
}

VOID PciInsertEntryAtHead(IN PSINGLE_LIST_ENTRY ListHead,
			  IN PSINGLE_LIST_ENTRY Entry)
{
    PAGED_CODE();
    /* Make the entry point to the current head and make the head point to it */
    Entry->Next = ListHead->Next;
    ListHead->Next = Entry;
}

NTSTATUS PciSendIoctl(IN PDEVICE_OBJECT DeviceObject, IN ULONG IoControlCode,
		      IN PVOID InputBuffer, IN ULONG InputBufferLength,
		      IN PVOID OutputBuffer, IN ULONG OutputBufferLength)
{
    PAGED_CODE();
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Build the requested IOCTL IRP */
    Irp = IoBuildDeviceIoControlRequest(IoControlCode, DeviceObject, InputBuffer,
					InputBufferLength, OutputBuffer,
					OutputBufferLength, 0, &IoStatusBlock);
    if (!Irp)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Send the IOCTL to the driver */
    return IoCallDriver(DeviceObject, Irp);
}

ULONGLONG PciGetHackFlags(IN USHORT VendorId, IN USHORT DeviceId,
			  IN USHORT SubVendorId, IN USHORT SubSystemId,
			  IN UCHAR RevisionId)
{
    PPCI_HACK_ENTRY HackEntry;
    ULONGLONG HackFlags;
    ULONG LastWeight, MatchWeight;
    ULONG EntryFlags;

    /* ReactOS SetupLDR Hack */
    if (!PciHackTable)
	return 0;

    /* Initialize the variables before looping */
    LastWeight = 0;
    HackFlags = 0;
    ASSERT(PciHackTable);

    /* Scan the hack table */
    for (HackEntry = PciHackTable; HackEntry->VendorID != PCI_INVALID_VENDORID;
	 ++HackEntry) {
	/* Check if there's an entry for this device */
	if ((HackEntry->DeviceID == DeviceId) && (HackEntry->VendorID == VendorId)) {
	    /* This is a basic match */
	    EntryFlags = HackEntry->Flags;
	    MatchWeight = 1;

	    /* Does the entry have revision information? */
	    if (EntryFlags & PCI_HACK_HAS_REVISION_INFO) {
		/* Check if the revision matches, if so, this is a better match */
		if (HackEntry->RevisionID != RevisionId)
		    continue;
		MatchWeight = 3;
	    }

	    /* Does the netry have subsystem information? */
	    if (EntryFlags & PCI_HACK_HAS_SUBSYSTEM_INFO) {
		/* Check if it matches, if so, this is the best possible match */
		if ((HackEntry->SubVendorID != SubVendorId) ||
		    (HackEntry->SubSystemID != SubSystemId)) {
		    continue;
		}
		MatchWeight += 4;
	    }

	    /* Is this the best match yet? */
	    if (MatchWeight > LastWeight) {
		/* This is the best match for now, use this as the hack flags */
		HackFlags = HackEntry->HackFlags;
		LastWeight = MatchWeight;
	    }
	}
    }

    /* Return the best match */
    return HackFlags;
}

BOOLEAN PciIsCriticalDeviceClass(IN UCHAR BaseClass, IN UCHAR SubClass)
{
    /* Check for system or bridge devices */
    if (BaseClass == PCI_CLASS_BASE_SYSTEM_DEV) {
	/* Interrupt controllers are critical */
	return SubClass == PCI_SUBCLASS_SYS_INTERRUPT_CTLR;
    } else if (BaseClass == PCI_CLASS_BRIDGE_DEV) {
	/* ISA Bridges are critical */
	return SubClass == PCI_SUBCLASS_BR_ISA;
    } else {
	/* All display controllers are critical */
	return BaseClass == PCI_CLASS_DISPLAY_CTLR;
    }
}

PPCI_PDO_EXTENSION PciFindPdoByFunction(IN PPCI_FDO_EXTENSION DeviceExtension,
					IN ULONG FunctionNumber,
					IN PPCI_COMMON_HEADER PciData)
{
    PPCI_PDO_EXTENSION PdoExtension;

    /* Loop every child PDO */
    for (PdoExtension = DeviceExtension->ChildPdoList; PdoExtension;
	 PdoExtension = PdoExtension->Next) {
	/* Find only enumerated PDOs */
	if (!PdoExtension->ReportedMissing) {
	    /* Check if the function number and header data matches */
	    if ((FunctionNumber == PdoExtension->Slot.AsULONG) &&
		(PdoExtension->VendorId == PciData->VendorID) &&
		(PdoExtension->DeviceId == PciData->DeviceID) &&
		(PdoExtension->RevisionId == PciData->RevisionID)) {
		/* This is considered to be the same PDO */
		break;
	    }
	}
    }

    /* If the search found something, this is non-NULL, otherwise it's NULL */
    return PdoExtension;
}

BOOLEAN PciIsDeviceOnDebugPath(IN PPCI_PDO_EXTENSION DeviceExtension)
{
    PAGED_CODE();
    UNREFERENCED_PARAMETER(DeviceExtension);

    /* Check for too many, or no, debug ports */
    ASSERT(PciDebugPortsCount <= MAX_DEBUGGING_DEVICES_SUPPORTED);
    if (!PciDebugPortsCount)
	return FALSE;

    /* eVb has not been able to test such devices yet */
    UNIMPLEMENTED_DBGBREAK();
    return FALSE;
}

NTSTATUS PciGetBiosConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			  OUT PPCI_COMMON_HEADER PciData)
{
    PAGED_CODE();
    HANDLE KeyHandle, SubKeyHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName, KeyValue;
    WCHAR Buffer[32];
    WCHAR DataBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + PCI_COMMON_HDR_LENGTH];
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = (PVOID)DataBuffer;
    NTSTATUS Status;
    ULONG ResultLength;

    /* Open the PCI key */
    Status =
	IoOpenDeviceRegistryKey(DeviceExtension->ParentFdoExtension->PhysicalDeviceObject,
				TRUE, KEY_ALL_ACCESS, &KeyHandle);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Create a volatile BIOS configuration key */
    RtlInitUnicodeString(&KeyName, L"BiosConfig");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, 0, KeyHandle, NULL);
    Status = NtCreateKey(&SubKeyHandle, KEY_READ, &ObjectAttributes, 0, NULL,
			 REG_OPTION_VOLATILE, NULL);
    NtClose(KeyHandle);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Create the key value based on the device and function number */
    swprintf(Buffer, L"DEV_%02x&FUN_%02x", DeviceExtension->Slot.Bits.DeviceNumber,
	     DeviceExtension->Slot.Bits.FunctionNumber);
    RtlInitUnicodeString(&KeyValue, Buffer);

    /* Query the value information (PCI BIOS configuration header) */
    Status = NtQueryValueKey(SubKeyHandle, &KeyValue, KeyValuePartialInformation,
			     PartialInfo, sizeof(DataBuffer), &ResultLength);
    NtClose(SubKeyHandle);
    if (!NT_SUCCESS(Status))
	return Status;

    /* If any information was returned, go ahead and copy its data */
    ASSERT(PartialInfo->DataLength == PCI_COMMON_HDR_LENGTH);
    RtlCopyMemory(PciData, PartialInfo->Data, PCI_COMMON_HDR_LENGTH);
    return Status;
}

NTSTATUS PciSaveBiosConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			   IN PPCI_COMMON_HEADER PciData)
{
    PAGED_CODE();
    HANDLE KeyHandle, SubKeyHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING KeyName, KeyValue;
    WCHAR Buffer[32];
    NTSTATUS Status;

    /* Open the PCI key */
    Status =
	IoOpenDeviceRegistryKey(DeviceExtension->ParentFdoExtension->PhysicalDeviceObject,
				TRUE, KEY_READ | KEY_WRITE, &KeyHandle);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Create a volatile BIOS configuration key */
    RtlInitUnicodeString(&KeyName, L"BiosConfig");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, 0, KeyHandle, NULL);
    Status = NtCreateKey(&SubKeyHandle, KEY_READ | KEY_WRITE, &ObjectAttributes, 0, NULL,
			 REG_OPTION_VOLATILE, NULL);
    NtClose(KeyHandle);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Create the key value based on the device and function number */
    _snwprintf(Buffer, sizeof(Buffer), L"DEV_%02x&FUN_%02x",
	       DeviceExtension->Slot.Bits.DeviceNumber,
	       DeviceExtension->Slot.Bits.FunctionNumber);
    RtlInitUnicodeString(&KeyValue, Buffer);

    /* Set the value data (the PCI BIOS configuration header) */
    Status = NtSetValueKey(SubKeyHandle, &KeyValue, 0, REG_BINARY, PciData,
			   PCI_COMMON_HDR_LENGTH);
    NtClose(SubKeyHandle);
    return Status;
}

UCHAR PciReadDeviceCapability(IN PPCI_PDO_EXTENSION DeviceExtension,
			      IN UCHAR Offset, IN ULONG CapabilityId,
			      OUT PPCI_CAPABILITIES_HEADER Buffer, IN ULONG Length)
{
    ULONG CapabilityCount = 0;

    /* If the device has no capabilility list, fail */
    if (!Offset)
	return 0;

    /* Validate a PDO with capabilities, a valid buffer, and a valid length */
    ASSERT(DeviceExtension->ExtensionType == PciPdoExtensionType);
    ASSERT(DeviceExtension->CapabilitiesPtr != 0);
    ASSERT(Buffer);
    ASSERT(Length >= sizeof(PCI_CAPABILITIES_HEADER));

    /* Loop all capabilities */
    while (Offset) {
	/* Make sure the pointer is spec-aligned and spec-sized */
	ASSERT((Offset >= PCI_COMMON_HDR_LENGTH) && ((Offset & 0x3) == 0));

	/* Read the capability header */
	PciReadDeviceConfig(DeviceExtension, Buffer, Offset,
			    sizeof(PCI_CAPABILITIES_HEADER));

	/* Check if this is the capability being looked up */
	if ((Buffer->CapabilityID == CapabilityId) || !(CapabilityId)) {
	    /* Check if was at a valid offset and length */
	    if ((Offset) && (Length > sizeof(PCI_CAPABILITIES_HEADER))) {
		/* Sanity check */
		ASSERT(Length <= (sizeof(PCI_COMMON_CONFIG) - Offset));

		/* Now read the whole capability data into the buffer */
		PciReadDeviceConfig(DeviceExtension,
				    (PVOID)((ULONG_PTR)Buffer +
					    sizeof(PCI_CAPABILITIES_HEADER)),
				    Offset + sizeof(PCI_CAPABILITIES_HEADER),
				    Length - sizeof(PCI_CAPABILITIES_HEADER));
	    }

	    /* Return the offset where the capability was found */
	    return Offset;
	}

	/* Try the next capability instead */
	CapabilityCount++;
	Offset = Buffer->Next;

	/* There can't be more than 48 capabilities (256 bytes max) */
	if (CapabilityCount > 48) {
	    /* Fail, since this is basically a broken PCI device */
	    DPRINT1("PCI device %p capabilities list is broken.\n", DeviceExtension);
	    return 0;
	}
    }

    /* Capability wasn't found, fail */
    return 0;
}

BOOLEAN PciCanDisableDecodes(IN PPCI_PDO_EXTENSION DeviceExtension,
			     IN PPCI_COMMON_HEADER Config, IN ULONGLONG HackFlags,
			     IN BOOLEAN ForPowerDown)
{
    UCHAR BaseClass, SubClass;
    BOOLEAN IsVga;

    /* Is there a device extension or should the PCI header be used? */
    if (DeviceExtension) {
	/* Never disable decodes for a debug PCI Device */
	if (DeviceExtension->OnDebugPath)
	    return FALSE;

	/* Hack flags will be obtained from the extension, not the caller */
	ASSERT(HackFlags == 0);

	/* Get hacks and classification from the device extension */
	HackFlags = DeviceExtension->HackFlags;
	SubClass = DeviceExtension->SubClass;
	BaseClass = DeviceExtension->BaseClass;
    } else {
	/* There must be a PCI header, go read the classification information */
	ASSERT(Config != NULL);
	BaseClass = Config->BaseClass;
	SubClass = Config->SubClass;
    }

    /* Check for hack flags that prevent disabling the decodes */
    if (HackFlags & (PCI_HACK_PRESERVE_COMMAND | PCI_HACK_CB_SHARE_CMD_BITS |
		     PCI_HACK_DONT_DISABLE_DECODES)) {
	/* Don't do it */
	return FALSE;
    }

    /* Is this a VGA adapter? */
    if ((BaseClass == PCI_CLASS_DISPLAY_CTLR) &&
	(SubClass == PCI_SUBCLASS_VID_VGA_CTLR)) {
	/* Never disable decodes if this is for power down */
	return ForPowerDown;
    }

    /* Check for legacy devices */
    if (BaseClass == PCI_CLASS_PRE_20) {
	/* Never disable video adapter cards if this is for power down */
	if (SubClass == PCI_SUBCLASS_PRE_20_VGA)
	    return ForPowerDown;
    } else if (BaseClass == PCI_CLASS_DISPLAY_CTLR) {
	/* Never disable VGA adapters if this is for power down */
	if (SubClass == PCI_SUBCLASS_VID_VGA_CTLR)
	    return ForPowerDown;
    } else if (BaseClass == PCI_CLASS_BRIDGE_DEV) {
	/* Check for legacy bridges */
	if ((SubClass == PCI_SUBCLASS_BR_ISA) || (SubClass == PCI_SUBCLASS_BR_EISA) ||
	    (SubClass == PCI_SUBCLASS_BR_MCA) || (SubClass == PCI_SUBCLASS_BR_HOST) ||
	    (SubClass == PCI_SUBCLASS_BR_OTHER)) {
	    /* Never disable these */
	    return FALSE;
	} else if ((SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI) ||
		   (SubClass == PCI_SUBCLASS_BR_CARDBUS)) {
	    /* This is a supported bridge, but does it have a VGA card? */
	    if (!DeviceExtension) {
		/* Read the bridge control flag from the PCI header */
		IsVga = Config->Type1.BridgeControl & PCI_ENABLE_BRIDGE_VGA;
	    } else {
		/* Read the cached flag in the device extension */
		IsVga = DeviceExtension->Dependent.Type1.VgaBitSet;
	    }

	    /* Never disable VGA adapters if this is for power down */
	    if (IsVga)
		return ForPowerDown;
	}
    }

    /* Finally, never disable decodes if there's no power management */
    return !(HackFlags & PCI_HACK_NO_PM_CAPS);
}

PCI_DEVICE_TYPES PciClassifyDeviceType(IN PPCI_PDO_EXTENSION PdoExtension)
{
    ASSERT(PdoExtension->ExtensionType == PciPdoExtensionType);

    /* Differentiate between devices and bridges */
    if (PdoExtension->BaseClass != PCI_CLASS_BRIDGE_DEV)
	return PciTypeDevice;

    /* The PCI Bus driver handles only CardBus and PCI bridges (plus host) */
    if (PdoExtension->SubClass == PCI_SUBCLASS_BR_HOST)
	return PciTypeHostBridge;
    if (PdoExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI)
	return PciTypePciBridge;
    if (PdoExtension->SubClass == PCI_SUBCLASS_BR_CARDBUS)
	return PciTypeCardbusBridge;

    /* Any other kind of bridge is treated like a device */
    return PciTypeDevice;
}

ULONG_PTR PciExecuteCriticalSystemRoutine(IN ULONG_PTR IpiContext)
{
    PPCI_IPI_CONTEXT Context = (PPCI_IPI_CONTEXT)IpiContext;

    /* Check if the IPI is already running */
    if (!InterlockedDecrement(&Context->RunCount)) {
	/* Nope, this is the first instance, so execute the IPI function */
	Context->Function(Context->DeviceExtension, Context->Context);

	/* Notify anyone that was spinning that they can stop now */
	Context->Barrier = 0;
    } else {
	/* Spin until it has finished running */
	while (Context->Barrier)
	    ;
    }

    /* Done */
    return 0;
}

BOOLEAN PciIsSlotPresentInParentMethod(IN PPCI_PDO_EXTENSION PdoExtension,
				       IN ULONG Method)
{
    PAGED_CODE();
    BOOLEAN FoundSlot;
    PACPI_METHOD_ARGUMENT Argument;
    ACPI_EVAL_INPUT_BUFFER InputBuffer;
    PACPI_EVAL_OUTPUT_BUFFER OutputBuffer;
    ULONG i, Length;
    NTSTATUS Status;

    /* Assume slot is not part of the parent method */
    FoundSlot = FALSE;

    /* Allocate a 2KB buffer for the method return parameters */
    Length = sizeof(ACPI_EVAL_OUTPUT_BUFFER) + 2048;
    OutputBuffer = ExAllocatePoolWithTag(Length, 'BicP');
    if (OutputBuffer) {
	/* Clear out the output buffer */
	RtlZeroMemory((PVOID)OutputBuffer, Length);

	/* Initialize the input buffer with the method requested */
	InputBuffer.Signature = 0;
	*(PULONG)InputBuffer.MethodName = Method;
	InputBuffer.Signature = ACPI_EVAL_INPUT_BUFFER_SIGNATURE;

	/* Send it to the ACPI driver */
	Status = PciSendIoctl(PdoExtension->ParentFdoExtension->PhysicalDeviceObject,
			      IOCTL_ACPI_EVAL_METHOD, &InputBuffer,
			      sizeof(ACPI_EVAL_INPUT_BUFFER), (PVOID)OutputBuffer, Length);
	if (NT_SUCCESS(Status)) {
	    /* Scan all output arguments */
	    for (i = 0; i < OutputBuffer->Count; i++) {
		/* Make sure it's an integer */
		Argument = &OutputBuffer->Argument[i];
		if (Argument->Type != ACPI_METHOD_ARGUMENT_INTEGER)
		    continue;

		/* Check if the argument matches this PCI slot structure */
		if (Argument->Argument ==
		    ((PdoExtension->Slot.Bits.DeviceNumber) |
		     ((PdoExtension->Slot.Bits.FunctionNumber) << 16))) {
		    /* This slot has been found, return it */
		    FoundSlot = TRUE;
		    break;
		}
	    }
	}

	/* Finished with the buffer, free it */
	ExFreePoolWithTag((PVOID)OutputBuffer, 0);
    }

    /* Return if the slot was found */
    return FoundSlot;
}

ULONG PciGetLengthFromBar(IN ULONG Bar)
{
    ULONG Length;

    /* I/O addresses vs. memory addresses start differently due to alignment */
    Length = 1 << ((Bar & PCI_ADDRESS_IO_SPACE) ? 2 : 4);

    /* Keep going until a set bit */
    while (!(Length & Bar) && (Length))
	Length <<= 1;

    /* Return the length (might be 0 on 64-bit because it's the low-word) */
    if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) != PCI_TYPE_64BIT)
	ASSERT(Length);
    return Length;
}

BOOLEAN PciCreateIoDescriptorFromBarLimit(
    PIO_RESOURCE_DESCRIPTOR ResourceDescriptor, IN PULONG BarArray, IN BOOLEAN Rom)
{
    ULONG CurrentBar, BarLength, BarMask;
    BOOLEAN Is64BitBar = FALSE;

    /* Check if the BAR is nor I/O nor memory */
    CurrentBar = BarArray[0];
    if (!(CurrentBar & ~PCI_ADDRESS_IO_SPACE)) {
	/* Fail this descriptor */
	ResourceDescriptor->Type = CmResourceTypeNull;
	return FALSE;
    }

    /* Set default flag and clear high words */
    ResourceDescriptor->Flags = 0;
    ResourceDescriptor->Generic.MaximumAddress.HighPart = 0;
    ResourceDescriptor->Generic.MinimumAddress.LowPart = 0;
    ResourceDescriptor->Generic.MinimumAddress.HighPart = 0;

    /* Check for ROM Address */
    if (Rom) {
	/* Clean up the BAR to get just the address */
	CurrentBar &= PCI_ADDRESS_ROM_ADDRESS_MASK;
	if (!CurrentBar) {
	    /* Invalid ar, fail this descriptor */
	    ResourceDescriptor->Type = CmResourceTypeNull;
	    return FALSE;
	}

	/* ROM Addresses are always read only */
	ResourceDescriptor->Flags = CM_RESOURCE_MEMORY_READ_ONLY;
    }

    /* Compute the length, assume it's the alignment for now */
    BarLength = PciGetLengthFromBar(CurrentBar);
    ResourceDescriptor->Generic.Length = BarLength;
    ResourceDescriptor->Generic.Alignment = BarLength;

    /* Check what kind of BAR this is */
    if (CurrentBar & PCI_ADDRESS_IO_SPACE) {
	/* Use correct mask to decode the address */
	BarMask = PCI_ADDRESS_IO_ADDRESS_MASK;

	/* Set this as an I/O Port descriptor */
	ResourceDescriptor->Type = CmResourceTypePort;
	ResourceDescriptor->Flags = CM_RESOURCE_PORT_IO;
    } else {
	/* Use correct mask to decode the address */
	BarMask = PCI_ADDRESS_MEMORY_ADDRESS_MASK;

	/* Set this as a memory descriptor */
	ResourceDescriptor->Type = CmResourceTypeMemory;

	/* Check if it's 64-bit or 20-bit decode */
	if ((CurrentBar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT) {
	    /* The next BAR has the high word, read it */
	    ResourceDescriptor->Port.MaximumAddress.HighPart = BarArray[1];
	    Is64BitBar = TRUE;
	} else if ((CurrentBar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_20BIT) {
	    /* Use the correct mask to decode the address */
	    BarMask = ~0xFFF0000F;
	}

	/* Check if the BAR is listed as prefetchable memory */
	if (CurrentBar & PCI_ADDRESS_MEMORY_PREFETCHABLE) {
	    /* Mark the descriptor in the same way */
	    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
	}
    }

    /* Now write down the maximum address based on the base + length */
    ResourceDescriptor->Port.MaximumAddress.QuadPart = (CurrentBar & BarMask) +
	BarLength - 1;

    /* Return if this is a 64-bit BAR, so the loop code knows to skip the next one */
    return Is64BitBar;
}

VOID PciDecodeEnable(IN PPCI_PDO_EXTENSION PdoExtension, IN BOOLEAN Enable,
		     OUT PUSHORT Command)
{
    USHORT CommandValue;

    /*
     * If decodes are being disabled, make sure it's allowed, and in both cases,
     * make sure that a hackflag isn't preventing touching the decodes at all.
     */
    if ((Enable || PciCanDisableDecodes(PdoExtension, 0, 0, 0)) &&
	!(PdoExtension->HackFlags & PCI_HACK_PRESERVE_COMMAND)) {
	/* Did the caller already have a command word? */
	if (Command) {
	    /* Use the caller's */
	    CommandValue = *Command;
	} else {
	    /* Otherwise, read the current command */
	    PciReadDeviceConfig(PdoExtension, &CommandValue,
				FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));
	}

	/* Turn off decodes by default */
	CommandValue &= ~(PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE |
			  PCI_ENABLE_BUS_MASTER);

	/* If requested, enable the decodes that were enabled at init time */
	if (Enable)
	    CommandValue |= PdoExtension->CommandEnables &
		(PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE |
		 PCI_ENABLE_BUS_MASTER);

	/* Update the command word */
	PciWriteDeviceConfig(PdoExtension, &CommandValue,
			     FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));
    }
}

NTSTATUS PciQueryBusInformation(IN PPCI_PDO_EXTENSION PdoExtension,
				IN PPNP_BUS_INFORMATION *Buffer)
{
    PPNP_BUS_INFORMATION BusInfo;

    UNREFERENCED_PARAMETER(Buffer);

    /* Allocate a structure for the bus information */
    BusInfo = ExAllocatePoolWithTag(sizeof(PNP_BUS_INFORMATION), 'BicP');
    if (!BusInfo)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Write the correct GUID and bus type identifier, and fill the bus number */
    BusInfo->BusTypeGuid = GUID_BUS_TYPE_PCI;
    BusInfo->LegacyBusType = PCIBus;
    BusInfo->BusNumber = PdoExtension->ParentFdoExtension->BaseBus;
    return STATUS_SUCCESS;
}

static NTSTATUS PciDetermineSlotNumber(IN PPCI_PDO_EXTENSION PdoExtension,
				       OUT PULONG SlotNumber)
{
    PPCI_FDO_EXTENSION ParentExtension;
    PSLOT_INFO SlotInfo;

    /* Check if a $PIR from the BIOS is used (legacy IRQ routing) */
    ParentExtension = PdoExtension->ParentFdoExtension;
    DPRINT1("Slot lookup for %d.%u.%u\n", ParentExtension ? ParentExtension->BaseBus : -1,
	    PdoExtension->Slot.Bits.DeviceNumber,
	    PdoExtension->Slot.Bits.FunctionNumber);
    if (PciIrqRoutingTable && ParentExtension) {
	/* Read every slot information entry */
	SlotInfo = &PciIrqRoutingTable->Slot[0];
	DPRINT1("PIR$ %p is %x bytes, slot 0 is at: %p\n", PciIrqRoutingTable,
		PciIrqRoutingTable->TableSize, SlotInfo);
	while (SlotInfo < (PSLOT_INFO)((ULONG_PTR)PciIrqRoutingTable +
				       PciIrqRoutingTable->TableSize)) {
	    DPRINT1("Slot Info: %u.%u->#%u\n", SlotInfo->BusNumber,
		    SlotInfo->DeviceNumber, SlotInfo->SlotNumber);

	    /* Check if this slot information matches the PDO being queried */
	    if (ParentExtension->BaseBus == SlotInfo->BusNumber &&
		PdoExtension->Slot.Bits.DeviceNumber == (SlotInfo->DeviceNumber >> 3) &&
		SlotInfo->SlotNumber) {
		/* We found it, return it and return success */
		*SlotNumber = SlotInfo->SlotNumber;
		return STATUS_SUCCESS;
	    }

	    /* Try the next slot */
	    SlotInfo++;
	}
    }

    /* Since there is generally no universal mapping between the slot number
     * (which we take to be the UI number) and the PCI device, if the BIOS
     * didn't tell us about the slot number, there is nothing we can do other
     * than returning failure. */
    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS PciGetDeviceCapabilities(IN PDEVICE_OBJECT DeviceObject,
					 IN OUT PDEVICE_CAPABILITIES DeviceCapability)
{
    PAGED_CODE();
    PIRP Irp;
    NTSTATUS Status;
    PDEVICE_OBJECT AttachedDevice;
    PIO_STACK_LOCATION IoStackLocation;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Zero out capabilities and set undefined values to start with */
    RtlZeroMemory(DeviceCapability, sizeof(DEVICE_CAPABILITIES));
    DeviceCapability->Size = sizeof(DEVICE_CAPABILITIES);
    DeviceCapability->Version = 1;
    DeviceCapability->Address = -1;
    DeviceCapability->UINumber = -1;

    /* Find the device the PDO is attached to */
    AttachedDevice = IoGetAttachedDeviceReference(DeviceObject);

    /* And build an IRP for it */
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, AttachedDevice, NULL, 0, NULL,
				       &IoStatusBlock);
    if (!Irp) {
	/* The IRP failed, fail the request as well */
	ObDereferenceObject(AttachedDevice);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Set default status */
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    /* Get a stack location in this IRP */
    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IoStackLocation);

    /* Initialize it as a query capabilities IRP, with no completion routine */
    RtlZeroMemory(IoStackLocation, sizeof(IO_STACK_LOCATION));
    IoStackLocation->MajorFunction = IRP_MJ_PNP;
    IoStackLocation->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IoStackLocation->Parameters.DeviceCapabilities.Capabilities = DeviceCapability;
    IoSetCompletionRoutine(Irp, NULL, NULL, FALSE, FALSE, FALSE);

    /* Send the IOCTL to the driver */
    Status = IoCallDriver(AttachedDevice, Irp);

    /* Done, dereference the attached device and return the final result */
    ObDereferenceObject(AttachedDevice);
    return Status;
}

static NTSTATUS PciQueryPowerCapabilities(IN PPCI_PDO_EXTENSION PdoExtension,
					  IN PDEVICE_CAPABILITIES DeviceCapability)
{
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS Status;
    DEVICE_CAPABILITIES AttachedCaps;
    DEVICE_POWER_STATE NewPowerState, DevicePowerState, DeviceWakeLevel, DeviceWakeState;
    SYSTEM_POWER_STATE SystemWakeState, DeepestWakeState, CurrentState;

    /* Nothing is known at first */
    DeviceWakeState = PowerDeviceUnspecified;
    SystemWakeState = DeepestWakeState = PowerSystemUnspecified;

    /* Get the PCI capabilities for the parent PDO */
    DeviceObject = PdoExtension->ParentFdoExtension->PhysicalDeviceObject;
    Status = PciGetDeviceCapabilities(DeviceObject, &AttachedCaps);
    ASSERT(NT_SUCCESS(Status));
    if (!NT_SUCCESS(Status))
	return Status;

    /* Check if there's not an existing device state for S0 */
    if (!AttachedCaps.DeviceState[PowerSystemWorking]) {
	/* Set D0<->S0 mapping */
	AttachedCaps.DeviceState[PowerSystemWorking] = PowerDeviceD0;
    }

    /* Check if there's not an existing device state for S3 */
    if (!AttachedCaps.DeviceState[PowerSystemShutdown]) {
	/* Set D3<->S3 mapping */
	AttachedCaps.DeviceState[PowerSystemShutdown] = PowerDeviceD3;
    }

    /* Check for a PDO with broken, or no, power capabilities */
    if (PdoExtension->HackFlags & PCI_HACK_NO_PM_CAPS) {
	/* Unknown wake device states */
	DeviceCapability->DeviceWake = PowerDeviceUnspecified;
	DeviceCapability->SystemWake = PowerSystemUnspecified;

	/* No device state support */
	DeviceCapability->DeviceD1 = FALSE;
	DeviceCapability->DeviceD2 = FALSE;

	/* No waking from any low-power device state is supported */
	DeviceCapability->WakeFromD0 = FALSE;
	DeviceCapability->WakeFromD1 = FALSE;
	DeviceCapability->WakeFromD2 = FALSE;
	DeviceCapability->WakeFromD3 = FALSE;

	/* For the rest, copy whatever the parent PDO had */
	RtlCopyMemory(DeviceCapability->DeviceState, AttachedCaps.DeviceState,
		      sizeof(DeviceCapability->DeviceState));
	return STATUS_SUCCESS;
    }

    /* The PCI Device has power capabilities, so read which ones are supported */
    DeviceCapability->DeviceD1 = PdoExtension->PowerCapabilities.Support.D1;
    DeviceCapability->DeviceD2 = PdoExtension->PowerCapabilities.Support.D2;
    DeviceCapability->WakeFromD0 = PdoExtension->PowerCapabilities.Support.PMED0;
    DeviceCapability->WakeFromD1 = PdoExtension->PowerCapabilities.Support.PMED1;
    DeviceCapability->WakeFromD2 = PdoExtension->PowerCapabilities.Support.PMED2;

    /* Can the attached device wake from D3? */
    if (AttachedCaps.DeviceWake != PowerDeviceD3) {
	/* It can't, so check if this PDO supports hot D3 wake */
	DeviceCapability->WakeFromD3 = PdoExtension->PowerCapabilities.Support.PMED3Hot;
    } else {
	/* It can, is this the root bus? */
	if (PCI_IS_ROOT_FDO(PdoExtension->ParentFdoExtension)) {
	    /* This is the root bus, so just check if it supports hot D3 wake */
	    DeviceCapability->WakeFromD3 =
		PdoExtension->PowerCapabilities.Support.PMED3Hot;
	} else {
	    /* Take the minimums? -- need to check with briang at work */
	    UNIMPLEMENTED;
	}
    }

    /* Now loop each system power state to determine its device state mapping */
    for (CurrentState = PowerSystemWorking; CurrentState < PowerSystemMaximum;
	 CurrentState++) {
	/* Read the current mapping from the attached device */
	DevicePowerState = AttachedCaps.DeviceState[CurrentState];
	NewPowerState = DevicePowerState;

	/* The attachee supports D1, but this PDO does not */
	if ((NewPowerState == PowerDeviceD1) &&
	    !(PdoExtension->PowerCapabilities.Support.D1)) {
	    /* Fall back to D2 */
	    NewPowerState = PowerDeviceD2;
	}

	/* The attachee supports D2, but this PDO does not */
	if ((NewPowerState == PowerDeviceD2) &&
	    !(PdoExtension->PowerCapabilities.Support.D2)) {
	    /* Fall back to D3 */
	    NewPowerState = PowerDeviceD3;
	}

	/* Set the mapping based on the best state supported */
	DeviceCapability->DeviceState[CurrentState] = NewPowerState;

	/* Check if sleep states are being processed, and a mapping was found */
	if ((CurrentState < PowerSystemHibernate) &&
	    (NewPowerState != PowerDeviceUnspecified)) {
	    /* Save this state as being the deepest one found until now */
	    DeepestWakeState = CurrentState;
	}

	/*
         * Finally, check if the computed sleep state is within the states that
         * this device can wake the system from, and if it's higher or equal to
         * the sleep state mapping that came from the attachee, assuming that it
         * had a valid mapping to begin with.
         *
         * It this is the case, then make sure that the computed sleep state is
         * matched by the device's ability to actually wake from that state.
         *
         * For devices that support D3, the PCI device only needs Hot D3 as long
         * as the attachee's state is less than D3. Otherwise, if the attachee
         * might also be at D3, this would require a Cold D3 wake, so check that
         * the device actually support this.
         */
	if ((CurrentState < AttachedCaps.SystemWake) &&
	    (NewPowerState >= DevicePowerState) &&
	    (DevicePowerState != PowerDeviceUnspecified) &&
	    (((NewPowerState == PowerDeviceD0) && (DeviceCapability->WakeFromD0)) ||
	     ((NewPowerState == PowerDeviceD1) && (DeviceCapability->WakeFromD1)) ||
	     ((NewPowerState == PowerDeviceD2) && (DeviceCapability->WakeFromD2)) ||
	     ((NewPowerState == PowerDeviceD3) &&
	      (PdoExtension->PowerCapabilities.Support.PMED3Hot) &&
	      ((DevicePowerState < PowerDeviceD3) ||
	       (PdoExtension->PowerCapabilities.Support.PMED3Cold))))) {
	    /* The mapping is valid, so this will be the lowest wake state */
	    SystemWakeState = CurrentState;
	    DeviceWakeState = NewPowerState;
	}
    }

    /* Read the current wake level */
    DeviceWakeLevel = PdoExtension->PowerState.DeviceWakeLevel;

    /* Check if the attachee's wake levels are valid, and the PDO's is higher */
    if ((AttachedCaps.SystemWake != PowerSystemUnspecified) &&
	(AttachedCaps.DeviceWake != PowerDeviceUnspecified) &&
	(DeviceWakeLevel != PowerDeviceUnspecified) &&
	(DeviceWakeLevel >= AttachedCaps.DeviceWake)) {
	/* Inherit the system wake from the attachee, and this PDO's wake level */
	DeviceCapability->SystemWake = AttachedCaps.SystemWake;
	DeviceCapability->DeviceWake = DeviceWakeLevel;

	/* Now check if the wake level is D0, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD0) &&
	    !(DeviceCapability->WakeFromD0)) {
	    /* Bump to D1 */
	    DeviceCapability->DeviceWake = PowerDeviceD1;
	}

	/* Now check if the wake level is D1, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD1) &&
	    !(DeviceCapability->WakeFromD1)) {
	    /* Bump to D2 */
	    DeviceCapability->DeviceWake = PowerDeviceD2;
	}

	/* Now check if the wake level is D2, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD2) &&
	    !(DeviceCapability->WakeFromD2)) {
	    /* Bump it to D3 */
	    DeviceCapability->DeviceWake = PowerDeviceD3;
	}

	/* Now check if the wake level is D3, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD3) &&
	    !(DeviceCapability->WakeFromD3)) {
	    /* Then no valid wake state exists */
	    DeviceCapability->DeviceWake = PowerDeviceUnspecified;
	    DeviceCapability->SystemWake = PowerSystemUnspecified;
	}

	/* Check if no valid wake state was found */
	if ((DeviceCapability->DeviceWake == PowerDeviceUnspecified) ||
	    (DeviceCapability->SystemWake == PowerSystemUnspecified)) {
	    /* Check if one was computed earlier */
	    if ((SystemWakeState != PowerSystemUnspecified) &&
		(DeviceWakeState != PowerDeviceUnspecified)) {
		/* Use the wake state that had been computed earlier */
		DeviceCapability->DeviceWake = DeviceWakeState;
		DeviceCapability->SystemWake = SystemWakeState;

		/* If that state was D3, then the device supports Hot/Cold D3 */
		if (DeviceWakeState == PowerDeviceD3)
		    DeviceCapability->WakeFromD3 = TRUE;
	    }
	}

	/*
         * Finally, check for off states (lower than S3, such as hibernate) and
         * make sure that the device both supports waking from D3 as well as
         * supports a Cold wake
         */
	if ((DeviceCapability->SystemWake > PowerSystemSleeping3) &&
	    ((DeviceCapability->DeviceWake != PowerDeviceD3) ||
	     !(PdoExtension->PowerCapabilities.Support.PMED3Cold))) {
	    /* It doesn't, so pick the computed lowest wake state from earlier */
	    DeviceCapability->SystemWake = DeepestWakeState;
	}

	/* Set the PCI Specification mandated maximum latencies for transitions */
	DeviceCapability->D1Latency = 0;
	DeviceCapability->D2Latency = 2;
	DeviceCapability->D3Latency = 100;

	/* Sanity check */
	ASSERT(DeviceCapability->DeviceState[PowerSystemWorking] == PowerDeviceD0);
    } else {
	/* No valid sleep states, no latencies to worry about */
	DeviceCapability->D1Latency = 0;
	DeviceCapability->D2Latency = 0;
	DeviceCapability->D3Latency = 0;
    }

    /* This function always succeeds, even without power management support */
    return STATUS_SUCCESS;
}

NTSTATUS PciQueryCapabilities(IN PPCI_PDO_EXTENSION PdoExtension,
			      IN OUT PDEVICE_CAPABILITIES DeviceCapability)
{
    NTSTATUS Status;

    /* A PDO ID is never unique, and its address is its function and device */
    DeviceCapability->UniqueID = FALSE;
    DeviceCapability->Address = PdoExtension->Slot.Bits.FunctionNumber |
	(PdoExtension->Slot.Bits.DeviceNumber << 16);

    /* Check for host bridges */
    if ((PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
	(PdoExtension->SubClass == PCI_SUBCLASS_BR_HOST)) {
	/* Raw device opens to a host bridge are acceptable */
	DeviceCapability->RawDeviceOK = TRUE;
    } else {
	/* Otherwise, other PDOs cannot be directly opened */
	DeviceCapability->RawDeviceOK = FALSE;
    }

    /* PCI PDOs are pretty fixed things */
    DeviceCapability->LockSupported = FALSE;
    DeviceCapability->EjectSupported = FALSE;
    DeviceCapability->Removable = FALSE;
    DeviceCapability->DockDevice = FALSE;

    /* The slot number is stored as a device property, go query it */
    PciDetermineSlotNumber(PdoExtension, &DeviceCapability->UINumber);

    /* Finally, query any power capabilities and convert them for PnP usage */
    Status = PciQueryPowerCapabilities(PdoExtension, DeviceCapability);

    /* Dump the capabilities if it all worked, and return the status */
    if (NT_SUCCESS(Status))
	PciDebugDumpQueryCapabilities(DeviceCapability);
    return Status;
}
