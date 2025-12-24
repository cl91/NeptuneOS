/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pci/id.c
 * PURPOSE:         PCI Device Identification
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"
#include <stdio.h>

/* FUNCTIONS ******************************************************************/

static PWCHAR PciGetDescriptionMessage(IN ULONG Identifier, OUT PULONG Length)
{
    PMESSAGE_RESOURCE_ENTRY Entry;
    ULONG TextLength;
    PWCHAR Description, Buffer;
    ANSI_STRING MessageString;
    UNICODE_STRING UnicodeString;
    NTSTATUS Status;

    /* Find the message identifier in the message table */
    MessageString.Buffer = NULL;
    Status = RtlFindMessage(PciDriverObject->DriverStart,
			    11, // RT_MESSAGETABLE
			    LANG_NEUTRAL, Identifier, &Entry);
    if (!NT_SUCCESS(Status))
	return NULL;

    /* Check if the resource data is Unicode or ANSI */
    if (Entry->Flags & MESSAGE_RESOURCE_UNICODE) {
	/* Subtract one space for the empty message terminator */
	TextLength = Entry->Length - FIELD_OFFSET(MESSAGE_RESOURCE_ENTRY, Text) -
		     sizeof(WCHAR);

	/* Grab the text */
	Description = (PWCHAR)Entry->Text;

	/* Validate valid message length */
	ASSERT(TextLength > 1);

	/* Remove trailing new line characters and the NUL-terminator. */
	while (TextLength) {
	    if (Description[TextLength/sizeof(WCHAR) - 1] == L'\n' ||
		Description[TextLength/sizeof(WCHAR) - 1] == L'\r' ||
		Description[TextLength/sizeof(WCHAR) - 1] == L'\0') {
		TextLength -= sizeof(WCHAR);
	    } else {
		break;
	    }
	}
	if (!TextLength) {
	    assert(FALSE);
	    return NULL;
	}

	/* Allocate the buffer to hold the message string */
	Buffer = ExAllocatePoolWithTag(NonPagedPool, TextLength + sizeof(WCHAR), 'BicP');
	if (!Buffer)
	    return NULL;

	/* Copy the message and terminate it */
	RtlCopyMemory(Buffer, Entry->Text, TextLength);
	Buffer[TextLength / sizeof(WCHAR)] = UNICODE_NULL;

	/* Return the length to the caller, minus the terminating NULL */
	if (Length)
	    *Length = TextLength;
    } else {
	/* Initialize the entry as a string */
	RtlInitAnsiString(&MessageString, (PCHAR)Entry->Text);

	/* Remove the newline character */
	MessageString.Length -= sizeof(CHAR);

	/* Convert it to Unicode */
	RtlAnsiStringToUnicodeString(&UnicodeString, &MessageString, TRUE);
	Buffer = UnicodeString.Buffer;

	/* Return the length to the caller */
	if (Length)
	    *Length = UnicodeString.Length;
    }

    /* Return the message buffer to the caller */
    return Buffer;
}

PWCHAR PciGetDeviceDescriptionMessage(IN UCHAR BaseClass, IN UCHAR SubClass)
{
    PWCHAR Message;
    ULONG Identifier;

    /* The message identifier in the table is encoded based on the PCI class */
    Identifier = (BaseClass << 8) | SubClass;

    /* Go grab the description message for this device */
    Message = PciGetDescriptionMessage(Identifier, NULL);
    if (!Message) {
	/* It wasn't found, allocate a buffer for a generic description */
	Message = ExAllocatePoolWithTag(NonPagedPool, sizeof(L"PCI Device"), 'bicP');
	if (Message)
	    RtlCopyMemory(Message, L"PCI Device", sizeof(L"PCI Device"));
    }

    /* Return the description message */
    return Message;
}

static VOID PciInitIdBuffer(IN PPCI_ID_BUFFER IdBuffer)
{
    RtlZeroMemory(IdBuffer, sizeof(PCI_ID_BUFFER));
}

static VOID PciIdPrintf(IN PPCI_ID_BUFFER IdBuffer, IN PWCHAR Format, ...)
{
    ULONG RemainingWchars = sizeof(IdBuffer->BufferData)/sizeof(WCHAR) - IdBuffer->TotalWchars;
    if (RemainingWchars < 1) {
	return;
    }

    /* Do the actual string formatting into the character buffer */
    va_list va;
    va_start(va, Format);
    ULONG WcharsWritten = _vsnwprintf(IdBuffer->BufferData + IdBuffer->TotalWchars,
				      RemainingWchars - 1, Format, va) + 1;
    va_end(va);

    IdBuffer->TotalWchars += WcharsWritten;
    assert(IdBuffer->TotalWchars <= sizeof(IdBuffer->BufferData) / sizeof(WCHAR));
    assert(IdBuffer->BufferData[IdBuffer->TotalWchars - 1] == L'\0');
}

static VOID PciIdPrintfAppend(IN PPCI_ID_BUFFER IdBuffer, IN PWCHAR Format, ...)
{
    LONG RemainingWchars = sizeof(IdBuffer->BufferData)/sizeof(WCHAR) - IdBuffer->TotalWchars;
    assert(RemainingWchars >= 0);
    if (RemainingWchars <= 1) {
	return;
    }
    if (IdBuffer->TotalWchars) {
	assert(IdBuffer->BufferData[IdBuffer->TotalWchars - 1] == L'\0');
	IdBuffer->TotalWchars--;
	RemainingWchars++;
    }
    va_list va;
    va_start(va, Format);
    LONG WcharsWritten = _vsnwprintf(IdBuffer->BufferData + IdBuffer->TotalWchars,
				     RemainingWchars - 1, Format, va) + 1;
    va_end(va);
    if (WcharsWritten <= 0) {
	assert(FALSE);
	return;
    }
    IdBuffer->TotalWchars += WcharsWritten;
    assert(IdBuffer->TotalWchars <= sizeof(IdBuffer->BufferData) / sizeof(WCHAR));
    assert(IdBuffer->BufferData[IdBuffer->TotalWchars - 1] == L'\0');
}

NTSTATUS PciQueryId(IN PPCI_PDO_EXTENSION DeviceExtension,
		    IN BUS_QUERY_ID_TYPE QueryType, OUT PWCHAR *Buffer)
{
    PAGED_CODE();
    ULONG SubsysId;
    CHAR VendorString[64] = {};
    PPCI_PDO_EXTENSION PdoExtension;
    PPCI_FDO_EXTENSION ParentExtension;
    PCI_ID_BUFFER IdBuffer;
    /* Assume failure */
    *Buffer = NULL;

    /* Start with the genric vendor string, which is the vendor ID + device ID */
    snprintf(VendorString, sizeof(VendorString),
	     "PCI\\VEN_%04X&DEV_%04X", DeviceExtension->VendorId,
	     DeviceExtension->DeviceId);

    /* Initialize the PCI ID Buffer */
    PciInitIdBuffer(&IdBuffer);

    /* Build the subsystem ID as shown in PCI ID Strings */
    SubsysId = DeviceExtension->SubsystemVendorId | (DeviceExtension->SubsystemId << 16);

    /* Check what the caller is requesting */
    switch (QueryType) {
    case BusQueryDeviceID:
	/* A single ID, the vendor string + the revision ID */
	PciIdPrintf(&IdBuffer, L"%S&SUBSYS_%08X&REV_%02X", VendorString, SubsysId,
		    DeviceExtension->RevisionId);
	break;

    case BusQueryHardwareIDs:
	/* First the vendor string + the subsystem ID + the revision ID */
	PciIdPrintf(&IdBuffer, L"%S&SUBSYS_%08X&REV_%02X", VendorString, SubsysId,
		    DeviceExtension->RevisionId);

	/* Next, without the revision */
	PciIdPrintf(&IdBuffer, L"%S&SUBSYS_%08X", VendorString, SubsysId);

	/* Next, the vendor string + the base class + sub class + progif */
	PciIdPrintf(&IdBuffer, L"%S&CC_%02X%02X%02X", VendorString,
		    DeviceExtension->BaseClass, DeviceExtension->SubClass,
		    DeviceExtension->ProgIf);

	/* Next, without the progif */
	PciIdPrintf(&IdBuffer, L"%S&CC_%02X%02X", VendorString, DeviceExtension->BaseClass,
		    DeviceExtension->SubClass);

	/* And finally, a terminator */
	PciIdPrintf(&IdBuffer, L"");
	break;

    case BusQueryCompatibleIDs:
	/* First, the vendor + revision ID only */
	PciIdPrintf(&IdBuffer, L"%S&REV_%02X", VendorString, DeviceExtension->RevisionId);

	/* Next, the vendor string alone */
	PciIdPrintf(&IdBuffer, L"%S", VendorString);

	/* Next, the vendor ID + the base class + the sub class + progif */
	PciIdPrintf(&IdBuffer, L"PCI\\VEN_%04X&CC_%02X%02X%02X", DeviceExtension->VendorId,
		    DeviceExtension->BaseClass, DeviceExtension->SubClass,
		    DeviceExtension->ProgIf);

	/* Now without the progif */
	PciIdPrintf(&IdBuffer, L"PCI\\VEN_%04X&CC_%02X%02X", DeviceExtension->VendorId,
		    DeviceExtension->BaseClass, DeviceExtension->SubClass);

	/* And then just the vendor ID itself */
	PciIdPrintf(&IdBuffer, L"PCI\\VEN_%04X", DeviceExtension->VendorId);

	/* Then the base class + subclass + progif, without any vendor */
	PciIdPrintf(&IdBuffer, L"PCI\\CC_%02X%02X%02X", DeviceExtension->BaseClass,
		    DeviceExtension->SubClass, DeviceExtension->ProgIf);

	/* Next, without the progif */
	PciIdPrintf(&IdBuffer, L"PCI\\CC_%02X%02X", DeviceExtension->BaseClass,
		    DeviceExtension->SubClass);

	/* And finally, a terminator */
	PciIdPrintf(&IdBuffer, L"");
	break;

    case BusQueryInstanceID:
	/* Encode the device and function number */
	PciIdPrintf(&IdBuffer, L"%02X",
		    (DeviceExtension->Slot.Bits.DeviceNumber << 3) |
		    DeviceExtension->Slot.Bits.FunctionNumber);

	/* Loop every parent until the root */
	ParentExtension = DeviceExtension->ParentFdoExtension;
	while (!PCI_IS_ROOT_FDO(ParentExtension)) {
	    /* And encode the parent's device and function number as well */
	    PdoExtension = ParentExtension->PhysicalDeviceObject->DeviceExtension;
	    PciIdPrintfAppend(&IdBuffer, L"%02X",
			      (PdoExtension->Slot.Bits.DeviceNumber << 3) |
				  PdoExtension->Slot.Bits.FunctionNumber);
	    ParentExtension = ParentExtension->ParentFdoExtension;
	}
	break;

    default:
	/* Unknown query type */
	DPRINT1("PciQueryId expected ID type = %d\n", QueryType);
	return STATUS_NOT_SUPPORTED;
    }

    /* Allocate the final string buffer to hold the ID */
    PWCHAR StringBuffer = ExAllocatePoolWithTag(NonPagedPool,
						IdBuffer.TotalWchars * sizeof(WCHAR),
						'BicP');
    if (!StringBuffer)
	return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(StringBuffer, IdBuffer.BufferData, IdBuffer.TotalWchars * sizeof(WCHAR));
    *Buffer = StringBuffer;
    return STATUS_SUCCESS;
}

NTSTATUS PciQueryDeviceText(IN PPCI_PDO_EXTENSION PdoExtension,
			    IN DEVICE_TEXT_TYPE QueryType, IN ULONG Locale,
			    OUT PWCHAR *Buffer)
{
    PWCHAR MessageBuffer, LocationBuffer;
    ULONG Length;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(Locale);

    /* Check what the caller is requesting */
    switch (QueryType) {
    case DeviceTextDescription:
	/* Get the message from the resource section */
	MessageBuffer = PciGetDeviceDescriptionMessage(PdoExtension->BaseClass,
						       PdoExtension->SubClass);

	/* Return it to the caller, and select proper status code */
	*Buffer = MessageBuffer;
	Status = MessageBuffer ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
	break;

    case DeviceTextLocationInformation:
	/* Get the message from the resource section */
	MessageBuffer = PciGetDescriptionMessage(0x10000, &Length);
	if (!MessageBuffer) {
	    /* It should be there, but fail if it wasn't found for some reason */
	    Status = STATUS_NOT_SUPPORTED;
	    break;
	}

	/* Add space for a null-terminator, and allocate the buffer */
	Length += 2 * sizeof(UNICODE_NULL);
	LocationBuffer = ExAllocatePoolWithTag(NonPagedPool,
					       Length * sizeof(WCHAR), 'BicP');
	*Buffer = LocationBuffer;

	/* Check if the allocation succeeded */
	if (LocationBuffer) {
	    /* Build the location string based on bus, function, and device */
	    swprintf(LocationBuffer, MessageBuffer,
		     PdoExtension->ParentFdoExtension->BaseBus,
		     PdoExtension->Slot.Bits.FunctionNumber,
		     PdoExtension->Slot.Bits.DeviceNumber);
	}

	/* Free the original string from the resource section */
	ExFreePoolWithTag(MessageBuffer, 0);

	/* Select the correct status */
	Status = LocationBuffer ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
	break;

    default:
	/* Anything else is unsupported */
	Status = STATUS_NOT_SUPPORTED;
	break;
    }

    /* Return whether or not a device text string was indeed found */
    return Status;
}
