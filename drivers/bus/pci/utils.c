/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/utils.c
 * PURPOSE:         Utility/Helper Support Code
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* GLOBALS ********************************************************************/

/* FUNCTIONS ******************************************************************/

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
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* Build the requested IOCTL IRP */
    Irp = IoBuildDeviceIoControlRequest(IoControlCode, DeviceObject, InputBuffer,
					InputBufferLength, OutputBuffer,
					OutputBufferLength, 0, &Event, &IoStatusBlock);
    if (!Irp)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Send the IOCTL to the driver */
    NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        /* Wait for a response */
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    return Status;
}

static VOID PcipReadWriteConfig(IN volatile CHAR *MappedCfg,
				IN PCHAR Buffer,
				IN ULONG Offset,
				IN ULONG Length,
				IN BOOLEAN Read)
{
#if DBG
    volatile PCI_COMMON_CONFIG *PciCfg = (PVOID)MappedCfg;
    if (PciCfg->Header.VendorID == PCI_INVALID_VENDORID) {
	DPRINT("Invalid vendor ID in PCI configuration space.\n");
    } else {
	DPRINT("PCI device is present\n");
    }
    DPRINT("%s PCI config space mapped at %p, offset 0x%x buffer %p length 0x%x. ",
	   Read ? "Reading" : "Writing", MappedCfg, Offset, Buffer, Length);
    if (!Read) {
	DbgPrint("Buffer content:");
	for (ULONG i = 0; i < Length; i++) {
	    DbgPrint(" %02x", (UCHAR)Buffer[i]);
	}
	DbgPrint("\n");
    }
#endif
    MappedCfg += Offset;
    for (ULONG i = 0; i < Length; i++) {
	if (Read) {
	    Buffer[i] = MappedCfg[i];
	} else {
	    MappedCfg[i] = Buffer[i];
	}
    }
#if DBG
    if (Read) {
	DbgPrint("Got data:");
	for (ULONG i = 0; i < Length; i++) {
	    DbgPrint(" %02x", (UCHAR)Buffer[i]);
	}
	DbgPrint("\n");
    }
#endif
}

static volatile CHAR *PcipMapConfigSpace(IN PPCI_FDO_EXTENSION BusRootFdoExtension,
					 IN ULONG BaseBus,
					 IN PCI_SLOT_NUMBER Slot)
{
    /* Only the root FDO can access configuration space */
    ASSERT(PCI_IS_ROOT_FDO(BusRootFdoExtension));
    PHYSICAL_ADDRESS PhyAddr = BusRootFdoExtension->ConfigBase;
    PhyAddr.QuadPart += ((BaseBus << 8) | (Slot.Bits.DeviceNumber << 3) |
			 Slot.Bits.FunctionNumber) * PCI_EXTENDED_CONFIG_LENGTH;
    volatile CHAR *Ptr = MmMapIoSpace(PhyAddr, PCI_EXTENDED_CONFIG_LENGTH, MmNonCached);
    DPRINT("PCI Config Base 0x%llx BaseBus 0x%x Dev 0x%x Func 0x%x Mapped %p\n",
	   BusRootFdoExtension->ConfigBase.QuadPart, BaseBus,
	   Slot.Bits.DeviceNumber, Slot.Bits.FunctionNumber, Ptr);
    return Ptr;
}

static VOID PciReadWriteConfigSpace(IN PPCI_PDO_EXTENSION DeviceExtension,
				    IN PCHAR Buffer,
				    IN ULONG Offset,
				    IN ULONG Length,
				    IN BOOLEAN Read)
{
    volatile CHAR *Ptr = DeviceExtension->MappedConfigSpace;
    if (!Ptr) {
	assert(DeviceExtension->ParentFdoExtension);
	Ptr = PcipMapConfigSpace(DeviceExtension->ParentFdoExtension->BusRootFdoExtension,
				 DeviceExtension->ParentFdoExtension->BaseBus,
				 DeviceExtension->Slot);
	DeviceExtension->MappedConfigSpace = Ptr;
    }
    if (!Ptr) {
	RtlRaiseStatus(STATUS_ACCESS_DENIED);
    }
    PcipReadWriteConfig(Ptr, Buffer, Offset, Length, Read);
}

VOID PciWriteDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			  IN PVOID Buffer,
			  IN ULONG Offset,
			  IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension, Buffer, Offset, Length, FALSE);
}

VOID PciReadDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			 IN PVOID Buffer,
			 IN ULONG Offset,
			 IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension, Buffer, Offset, Length, TRUE);
}

VOID PciReadSlotConfig(IN PPCI_FDO_EXTENSION DeviceExtension,
		       IN PCI_SLOT_NUMBER Slot, IN PVOID Buffer, IN ULONG Offset,
		       IN ULONG Length)
{
    volatile CHAR *Ptr = PcipMapConfigSpace(DeviceExtension->BusRootFdoExtension,
					    DeviceExtension->BaseBus, Slot);
    if (!Ptr) {
	RtlRaiseStatus(STATUS_ACCESS_DENIED);
    }
    PcipReadWriteConfig(Ptr, Buffer, Offset, Length, TRUE);
    MmUnmapIoSpace((PVOID)Ptr, PCI_EXTENDED_CONFIG_LENGTH);
}

VOID PciSetCommand(IN PPCI_PDO_EXTENSION PdoExtension, IN USHORT CommandBits,
		   IN BOOLEAN Enable)
{
    /* You can only pass the following bits for CommandBits */
    assert(!(CommandBits & ~(PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE |
			     PCI_ENABLE_BUS_MASTER | PCI_DISABLE_LEVEL_INTERRUPT)));

    /* Read the current command */
    USHORT CommandValue = 0;
    PciReadDeviceConfig(PdoExtension, &CommandValue,
			FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));

    /* Update the command word */
    if (Enable) {
	CommandValue |= CommandBits;
    } else {
	CommandValue &= ~CommandBits;
    }
    PciWriteDeviceConfig(PdoExtension, &CommandValue,
			 FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));
}

UCHAR PciReadDeviceCapability(IN PPCI_PDO_EXTENSION DeviceExtension,
			      IN UCHAR Offset,
			      IN ULONG CapabilityId,
			      OUT PPCI_CAPABILITIES_HEADER Buffer,
			      IN ULONG Length)
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
	if ((Buffer->CapabilityID == CapabilityId) || !CapabilityId) {
	    /* Check if was at a valid offset and length */
	    if (Offset && (Length > sizeof(PCI_CAPABILITIES_HEADER))) {
		/* Sanity check */
		ASSERT(Length <= (PCI_EXTENDED_CONFIG_LENGTH - Offset));

		/* Now read the whole capability data into the buffer */
		PciReadDeviceConfig(DeviceExtension,
				    (PCHAR)Buffer + sizeof(PCI_CAPABILITIES_HEADER),
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

static ULONG PcipGetLengthFromBar(IN ULONG Bar)
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

BOOLEAN PciCreateIoDescriptorFromBarLimit(IN PPCI_PDO_EXTENSION PdoExt,
					  OUT PIO_RESOURCE_DESCRIPTOR Desc,
					  IN PULONG BarArray,
					  IN BOOLEAN Rom)
{
    ULONG CurrentBar, BarLength, BarMask;
    BOOLEAN Is64BitBar = FALSE;

    /* Check if the BAR is nor I/O nor memory */
    CurrentBar = BarArray[0];
    if (!(CurrentBar & ~PCI_ADDRESS_IO_SPACE)) {
	/* Fail this descriptor */
	Desc->Type = CmResourceTypeNull;
	return FALSE;
    }

    /* Set share disposition and clear flag and high words. BAR resources
     * are never shared with any other device. */
    Desc->ShareDisposition = PciGetShareDisposition(PdoExt);
    Desc->Flags = 0;
    Desc->Generic.MaximumAddress.HighPart = 0;
    Desc->Generic.MinimumAddress.LowPart = 0;
    Desc->Generic.MinimumAddress.HighPart = 0;

    /* Check for ROM Address */
    if (Rom) {
	/* Clean up the BAR to get just the address */
	CurrentBar &= PCI_ADDRESS_ROM_ADDRESS_MASK;
	if (!CurrentBar) {
	    /* Invalid ar, fail this descriptor */
	    Desc->Type = CmResourceTypeNull;
	    return FALSE;
	}

	/* ROM Addresses are always read only */
	Desc->Flags = CM_RESOURCE_MEMORY_READ_ONLY;
    }

    /* Compute the length, assume it's the alignment for now */
    BarLength = PcipGetLengthFromBar(CurrentBar);
    Desc->Generic.Length = BarLength;
    Desc->Generic.Alignment = BarLength;

    /* Check what kind of BAR this is */
    if (CurrentBar & PCI_ADDRESS_IO_SPACE) {
	/* Use correct mask to decode the address */
	BarMask = PCI_ADDRESS_IO_ADDRESS_MASK;

	/* Set this as an I/O Port descriptor */
	Desc->Type = CmResourceTypePort;
	Desc->Flags = CM_RESOURCE_PORT_IO;
    } else {
	/* Use correct mask to decode the address */
	BarMask = PCI_ADDRESS_MEMORY_ADDRESS_MASK;

	/* Set this as a memory descriptor */
	Desc->Type = CmResourceTypeMemory;

	/* Check if it's 64-bit or 20-bit decode */
	if ((CurrentBar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT) {
	    /* The next BAR has the high word, read it */
	    Desc->Port.MaximumAddress.HighPart = BarArray[1];
	    Is64BitBar = TRUE;
	} else if ((CurrentBar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_20BIT) {
	    /* Use the correct mask to decode the address */
	    BarMask = ~0xFFF0000F;
	}

	/* Check if the BAR is listed as prefetchable memory */
	if (CurrentBar & PCI_ADDRESS_MEMORY_PREFETCHABLE) {
	    /* Mark the descriptor in the same way */
	    Desc->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
	}
    }

    /* Now write down the maximum address based on the base + length */
    Desc->Port.MaximumAddress.QuadPart = (CurrentBar & BarMask) +
	BarLength - 1;

    /* If the device is behind a PCI bridge, make sure the range limit falls within
     * the bridge's forward windows. */
    if (!PCI_IS_ROOT_FDO(PdoExt->ParentFdoExtension)) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Res = PciGetBridgeForwardWindow(PdoExt, Desc->Type,
									Desc->Flags);
	assert(Res->Type == Desc->Type);
	if (Desc->Generic.MinimumAddress.QuadPart < Res->Generic.Start.QuadPart) {
	    Desc->Generic.MinimumAddress.QuadPart = Res->Generic.Start.QuadPart;
	}
	if (Desc->Generic.MaximumAddress.QuadPart >
	    Res->Generic.Start.QuadPart + Res->Generic.Length) {
	    Desc->Generic.MaximumAddress.QuadPart =
		Res->Generic.Start.QuadPart + Res->Generic.Length;
	}
    }

    /* Return if this is a 64-bit BAR, so the loop code knows to skip the next one */
    return Is64BitBar;
}
