/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/device.c
 * PURPOSE:         Device Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* FUNCTIONS ******************************************************************/

VOID Device_MassageHeaderForLimitsDetermination(OUT PPCI_COMMON_HEADER Cfg)
{
    /* Set all the bits on, which will allow us to find the BAR limits */
    RtlFillMemory(Cfg->Type0.BaseAddresses, sizeof(Cfg->Type0.BaseAddresses), 0xFF);

    /* Do the same for the PCI ROM BAR */
    Cfg->Type0.ROMBaseAddress = PCI_ADDRESS_ROM_ADDRESS_MASK;
}

VOID Device_ReadResources(IN PPCI_PDO_EXTENSION PdoExt,
			  OUT PPCI_COMMON_HEADER Cfg)
{
    PCI_READ_CONFIG(PdoExt, Cfg, Type0.BaseAddresses);
    PCI_READ_CONFIG(PdoExt, Cfg, Type0.ROMBaseAddress);
}

VOID Device_WriteResources(IN PPCI_PDO_EXTENSION PdoExt,
			   IN PPCI_COMMON_HEADER Cfg)
{
    PCI_WRITE_CONFIG(PdoExt, Cfg, Type0.BaseAddresses);
    PCI_WRITE_CONFIG(PdoExt, Cfg, Type0.ROMBaseAddress);
}

VOID Device_SaveLimits(IN PPCI_PDO_EXTENSION PdoExtension,
		       IN PPCI_COMMON_HEADER Cfg)
{
    PULONG BarArray = Cfg->Type0.BaseAddresses;

    PIO_RESOURCE_DESCRIPTOR Limit = PdoExtension->Resources->Limit;
    for (ULONG i = 0; i < PCI_TYPE0_ADDRESSES; i++) {
	/* And build them based on the BARs */
	if (PciCreateIoDescriptorFromBarLimit(PdoExtension, &Limit[i], &BarArray[i], FALSE)) {
	    /* This function returns TRUE if the BAR was 64-bit, handle this */
	    ASSERT((i + 1) < PCI_TYPE0_ADDRESSES);
	    i++;
	    Limit[i].Type = CmResourceTypeNull;
	}
    }

    /* Create the last descriptor based on the ROM address */
    PciCreateIoDescriptorFromBarLimit(PdoExtension, &Limit[PCI_TYPE0_ADDRESSES],
				      &Cfg->Type0.ROMBaseAddress, TRUE);
}

VOID Device_SaveCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				IN PPCI_COMMON_HEADER Cfg)
{
    PPCI_FUNCTION_RESOURCES Resources = PdoExtension->Resources;

    /* Loop all the PCI BARs */
    PULONG BarArray = Cfg->Type0.BaseAddresses;
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	/* Get the resource descriptor and limit descriptor for this BAR */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor = &Resources->Current[i];
	PIO_RESOURCE_DESCRIPTOR IoDescriptor = &Resources->Limit[i];

	/* Build the resource descriptor based on the limit descriptor */
	CmDescriptor->Type = IoDescriptor->Type;
	if (CmDescriptor->Type == CmResourceTypeNull)
	    continue;
	CmDescriptor->Flags = IoDescriptor->Flags;
	CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;
	CmDescriptor->Generic.Start.HighPart = 0;
	CmDescriptor->Generic.Length = IoDescriptor->Generic.Length;

	/* Check if we're handling PCI BARs, or the ROM BAR */
	ULONG Bar, BarMask;
	if (i < PCI_TYPE0_ADDRESSES) {
	    /* Read the actual BAR value */
	    Bar = BarArray[i];

	    /* Check if this is an I/O BAR */
	    if (Bar & PCI_ADDRESS_IO_SPACE) {
		/* Use the right mask to get the I/O port base address */
		ASSERT(CmDescriptor->Type == CmResourceTypePort);
		BarMask = PCI_ADDRESS_IO_ADDRESS_MASK;
	    } else {
		/* It's a RAM BAR, use the right mask to get the base address */
		ASSERT(CmDescriptor->Type == CmResourceTypeMemory);
		BarMask = PCI_ADDRESS_MEMORY_ADDRESS_MASK;

		/* Check if it's a 64-bit BAR */
		if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT) {
		    /* The next BAR value is actually the high 32-bits */
		    CmDescriptor->Memory.Start.HighPart = BarArray[i + 1];
		} else if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_20BIT) {
		    /* Legacy BAR, don't read more than 20 bits of the address */
		    BarMask = 0xFFFF0;
		}
	    }
	} else {
	    /* Actually a ROM BAR, so read the correct register */
	    Bar = Cfg->Type0.ROMBaseAddress;

	    /* Apply the correct mask for ROM BARs */
	    BarMask = PCI_ADDRESS_ROM_ADDRESS_MASK;

	    /* Make sure it's enabled */
	    if (!(Bar & PCI_ROMADDRESS_ENABLED)) {
		/* If it isn't, then a descriptor won't be built for it */
		CmDescriptor->Type = CmResourceTypeNull;
		continue;
	    }
	}

	/* Now we have the right mask, read the actual address from the BAR */
	Bar &= BarMask;
	CmDescriptor->Memory.Start.LowPart = Bar;

	/* If address is zero, do not write a valid resource descriptor */
	if (!(CmDescriptor->Memory.Start.HighPart || Bar)) {
	    /* Skip these descriptors */
	    CmDescriptor->Type = CmResourceTypeNull;
	    DPRINT1("Invalid BAR\n");
	}
    }
}

VOID Device_GetAdditionalResourceDescriptors(IN PPCI_PDO_EXTENSION PdoExt,
					     IN PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    /* Nothing to do for devices */
    UNREFERENCED_PARAMETER(IoDescriptor);
}

VOID Device_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension)
{
    /* Nothing to do for devices */
    UNREFERENCED_PARAMETER(PdoExtension);
}

VOID Device_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				   OUT USHORT *CommandEnables)
{
    if (!PdoExtension->Resources) {
        return;
    }

    if ((PdoExtension->BaseClass == PCI_CLASS_DISPLAY_CTLR) &&
	(PdoExtension->SubClass == PCI_SUBCLASS_VID_VGA_CTLR)) {
	/* Always force IO and memory decoding on */
	*CommandEnables |= PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE;
    }

    /* The last resource is the ROM */
    for (ULONG i = 0; i <= PCI_TYPE0_ADDRESSES; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Res = &PdoExtension->Resources->Current[i];
        if (Res->Type == CmResourceTypeNull) {
            continue;
        }

	ULONG LowPart = Res->Generic.Start.LowPart;
        if (i == PCI_TYPE0_ADDRESSES) {
            ASSERT(Res->Type == CmResourceTypeMemory);
	    *CommandEnables |= PCI_ENABLE_MEMORY_SPACE;
	    ULONG Bar = 0;
	    PciReadDeviceConfig(PdoExtension, &Bar,
				FIELD_OFFSET(PCI_COMMON_HEADER, Type0.ROMBaseAddress),
				sizeof(ULONG));
            Bar &= ~PCI_ADDRESS_ROM_ADDRESS_MASK;
            Bar |= (LowPart & PCI_ADDRESS_ROM_ADDRESS_MASK);
	    PciWriteDeviceConfig(PdoExtension, &Bar,
				 FIELD_OFFSET(PCI_COMMON_HEADER, Type0.ROMBaseAddress),
				 sizeof(ULONG));
        } else {
            ULONG Bar = 0;
	    PciReadDeviceConfig(PdoExtension, &Bar,
				FIELD_OFFSET(PCI_COMMON_HEADER, Type0.BaseAddresses[i]),
				sizeof(ULONG));
	    if (Bar & PCI_ADDRESS_IO_SPACE) {
		ASSERT(Res->Type == CmResourceTypePort);
		*CommandEnables |= PCI_ENABLE_IO_SPACE;
	    } else {
		ASSERT(Res->Type == CmResourceTypeMemory);
		*CommandEnables |= PCI_ENABLE_MEMORY_SPACE;
	    }
            Bar &= ~PCI_ADDRESS_MEMORY_ADDRESS_MASK;
            Bar |= (LowPart & PCI_ADDRESS_MEMORY_ADDRESS_MASK);
	    PciWriteDeviceConfig(PdoExtension, &Bar,
				 FIELD_OFFSET(PCI_COMMON_HEADER, Type0.BaseAddresses[i]),
				 sizeof(ULONG));
            if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT) {
		/* A 64-bit address consumes two 32-bit bars. */
		PciWriteDeviceConfig(PdoExtension, &Res->Generic.Start.HighPart,
				     FIELD_OFFSET(PCI_COMMON_HEADER, Type0.BaseAddresses[++i]),
				     sizeof(ULONG));
            } else if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_20BIT) {
		ASSERT((LowPart & 0xfff00000) == 0);
            }
        }
    }
}
