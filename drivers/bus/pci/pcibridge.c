/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pci/ppbridge.c
 * PURPOSE:         PCI-to-PCI Bridge Support
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* FUNCTIONS ******************************************************************/

FORCEINLINE ULONG PciBridgeIoBase(IN PPCI_COMMON_HEADER Cfg)
{
    /* Get the base */
    ULONG Base = Cfg->Type1.IOLimit;

    /* Low bit specifies 32-bit address, top bits specify the base */
    BOOLEAN Is32Bit = (Base & 0xF) == 1;
    ULONG IoBase = (Base & 0xF0) << 8;

    /* Is it 32-bit? */
    if (Is32Bit) {
	/* Read the upper 16-bits from the other register */
	IoBase |= Cfg->Type1.IOBaseUpper16 << 16;
	ASSERT(Cfg->Type1.IOLimit & 0x1);
    }

    /* Return the base address */
    return IoBase;
}

FORCEINLINE ULONG PciBridgeIoLimit(IN PPCI_COMMON_HEADER Cfg)
{
    /* Get the limit */
    ULONG Limit = Cfg->Type1.IOLimit;

    /* Low bit specifies 32-bit address, top bits specify the limit */
    BOOLEAN Is32Bit = (Limit & 0xF) == 1;
    ULONG IoLimit = (Limit & 0xF0) << 8;

    /* Is it 32-bit? */
    if (Is32Bit) {
	/* Read the upper 16-bits from the other register */
	IoLimit |= Cfg->Type1.IOLimitUpper16 << 16;
	ASSERT(Cfg->Type1.IOBase & 0x1);
    }

    /* Return the I/O limit */
    return IoLimit | 0xFFF;
}

FORCEINLINE ULONG PciBridgeMemoryBase(IN PPCI_COMMON_HEADER Cfg)
{
    /* Return the memory base */
    return (Cfg->Type1.MemoryBase << 16);
}

FORCEINLINE ULONG PciBridgeMemoryLimit(IN PPCI_COMMON_HEADER Cfg)
{
    /* Return the memory limit */
    return (Cfg->Type1.MemoryLimit << 16) | 0xFFFFF;
}

FORCEINLINE PHYSICAL_ADDRESS PciBridgePrefetchMemoryBase(IN PPCI_COMMON_HEADER Cfg)
{
    /* Get the base */
    USHORT PrefetchBase = Cfg->Type1.PrefetchBase;

    /* Low bit specifies 64-bit address, top bits specify the base */
    BOOLEAN Is64Bit = (PrefetchBase & 0xF) == 1;
    LARGE_INTEGER Base = { .LowPart = ((PrefetchBase & 0xFFF0) << 16) };

    /* Is it 64-bit? */
    if (Is64Bit) {
	/* Read the upper 32-bits from the other register */
	Base.HighPart = Cfg->Type1.PrefetchBaseUpper32;
    }

    /* Return the base */
    return Base;
}

FORCEINLINE PHYSICAL_ADDRESS PciBridgePrefetchMemoryLimit(IN PPCI_COMMON_HEADER Cfg)
{
    /* Get the base */
    USHORT PrefetchLimit = Cfg->Type1.PrefetchLimit;

    /* Low bit specifies 64-bit address, top bits specify the limit */
    BOOLEAN Is64Bit = (PrefetchLimit & 0xF) == 1;
    LARGE_INTEGER Limit = { .LowPart = (PrefetchLimit << 16) | 0xFFFFF };

    /* Is it 64-bit? */
    if (Is64Bit) {
	/* Read the upper 32-bits from the other register */
	Limit.HighPart = Cfg->Type1.PrefetchLimitUpper32;
    }

    /* Return the limit */
    return Limit;
}

FORCEINLINE ULONG PciBridgeMemoryWorstCaseAlignment(IN ULONG Length)
{
    ULONG Alignment;
    ASSERT(Length != 0);

    /* Start with highest alignment (2^31) */
    Alignment = 0x80000000;

    /* Keep dividing until we reach the correct power of two */
    while (!(Length & Alignment))
	Alignment >>= 1;

    /* Return the alignment */
    return Alignment;
}

#define IO_WINDOW_REG_SIZE	(2 * sizeof(UCHAR))
#define MEMORY_WINDOW_REG_SIZE	(6 * sizeof(USHORT) + 2 * sizeof(ULONG))
VOID PCIBridge_ReadResources(IN PPCI_PDO_EXTENSION PdoExt,
			     OUT PPCI_COMMON_HEADER Cfg)
{
    PCI_READ_CONFIG(PdoExt, Cfg, Type1.BaseAddresses);
    PciReadDeviceConfig(PdoExt, &Cfg->Type1.IOBase,
			FIELD_OFFSET(PCI_COMMON_HEADER, Type1.IOBase),
			IO_WINDOW_REG_SIZE);
    PciReadDeviceConfig(PdoExt, &Cfg->Type1.MemoryBase,
			FIELD_OFFSET(PCI_COMMON_HEADER, Type1.MemoryBase),
			MEMORY_WINDOW_REG_SIZE);
    PCI_READ_CONFIG(PdoExt, Cfg, Type1.ROMBaseAddress);
}

VOID PCIBridge_WriteResources(IN PPCI_PDO_EXTENSION PdoExt,
			      IN PPCI_COMMON_HEADER Cfg)
{
    PCI_WRITE_CONFIG(PdoExt, Cfg, Type1.BaseAddresses);
    PciWriteDeviceConfig(PdoExt, &Cfg->Type1.IOBase,
			 FIELD_OFFSET(PCI_COMMON_HEADER, Type1.IOBase),
			 IO_WINDOW_REG_SIZE);
    PciWriteDeviceConfig(PdoExt, &Cfg->Type1.MemoryBase,
			 FIELD_OFFSET(PCI_COMMON_HEADER, Type1.MemoryBase),
			 MEMORY_WINDOW_REG_SIZE);
    PCI_WRITE_CONFIG(PdoExt, Cfg, Type1.ROMBaseAddress);
}

VOID PCIBridge_MassageHeaderForLimitsDetermination(OUT PPCI_COMMON_HEADER Cfg)
{
    /*
     * Write FFh everywhere so that the PCI bridge ignores what it can't handle.
     * Based on the bits that were ignored (still 0), this is how we can tell
     * what the limit is.
     */
    RtlFillMemory(Cfg->Type1.BaseAddresses, sizeof(Cfg->Type1.BaseAddresses), 0xFF);
    RtlFillMemory(&Cfg->Type1.IOBase, IO_WINDOW_REG_SIZE, 0xFF);
    RtlFillMemory(&Cfg->Type1.MemoryBase, MEMORY_WINDOW_REG_SIZE, 0xFF);
    Cfg->Type1.ROMBaseAddress = PCI_ADDRESS_ROM_ADDRESS_MASK;
}

VOID PCIBridge_SaveCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				   IN PPCI_COMMON_HEADER Cfg)
{
    ULONG Bar, BarMask;
    PHYSICAL_ADDRESS Limit, Base, Length;
    BOOLEAN HaveIoLimit, CheckAlignment;

    PPCI_FUNCTION_RESOURCES Resources = PdoExtension->Resources;

    /* Scan all current and limit descriptors for each BAR needed */
    PULONG BarArray = Cfg->Type1.BaseAddresses;
    for (ULONG i = 0; i < 6; i++) {
	/* Get the current resource descriptor, and the limit requirement */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR CmDescriptor = &Resources->Current[i];
	PIO_RESOURCE_DESCRIPTOR IoDescriptor = &Resources->Limit[i];

	/* Copy descriptor data, skipping null descriptors */
	CmDescriptor->Type = IoDescriptor->Type;
	if (CmDescriptor->Type == CmResourceTypeNull)
	    continue;
	CmDescriptor->Flags = IoDescriptor->Flags;
	CmDescriptor->ShareDisposition = IoDescriptor->ShareDisposition;

	/* Initialize the high-parts to zero, since most stuff is 32-bit only */
	Base.QuadPart = Limit.QuadPart = Length.QuadPart = 0;

	/* Check if we're handling PCI BARs, or the ROM BAR */
	if ((i < PCI_TYPE1_ADDRESSES) || (i == 5)) {
	    /* Is this the ROM BAR? */
	    if (i == 5) {
		/* Read the correct bar, with the appropriate mask */
		Bar = Cfg->Type1.ROMBaseAddress;
		BarMask = PCI_ADDRESS_ROM_ADDRESS_MASK;

		/* Decode the base address, and write down the length */
		Base.LowPart = Bar & BarMask;
		DPRINT1("ROM BAR Base: %x\n", Base.LowPart);
		CmDescriptor->Memory.Length = IoDescriptor->Memory.Length;
	    } else {
		/* Otherwise, get the BAR from the array */
		Bar = BarArray[i];

		/* Is this an I/O BAR? */
		if (Bar & PCI_ADDRESS_IO_SPACE) {
		    /* Set the correct mask */
		    ASSERT(CmDescriptor->Type == CmResourceTypePort);
		    BarMask = PCI_ADDRESS_IO_ADDRESS_MASK;
		} else {
		    /* This is a memory BAR, set the correct base */
		    ASSERT(CmDescriptor->Type == CmResourceTypeMemory);
		    BarMask = PCI_ADDRESS_MEMORY_ADDRESS_MASK;

		    /* Is this a 64-bit BAR? */
		    if ((Bar & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT) {
			/* Read the next 32-bits as well, ie, the next BAR */
			Base.HighPart = BarArray[i + 1];
		    }
		}

		/* Decode the base address, and write down the length */
		Base.LowPart = Bar & BarMask;
		DPRINT1("BAR Base: %x\n", Base.LowPart);
		CmDescriptor->Generic.Length = IoDescriptor->Generic.Length;
	    }
	} else {
	    /* Reset loop conditions */
	    HaveIoLimit = FALSE;
	    CheckAlignment = FALSE;

	    /* Check which descriptor is being parsed */
	    if (i == 2) {
		/* I/O Port Requirements */
		Base.LowPart = PciBridgeIoBase(Cfg);
		Limit.LowPart = PciBridgeIoLimit(Cfg);
		DPRINT1("Bridge I/O Base and Limit: %x %x\n", Base.LowPart,
			Limit.LowPart);

		/* Do we have any I/O Port data? */
		if (!(Base.LowPart) && (Cfg->Type1.IOLimit)) {
		    /* There's a limit */
		    HaveIoLimit = TRUE;
		}
	    } else if (i == 3) {
		/* Memory requirements */
		Base.LowPart = PciBridgeMemoryBase(Cfg);
		Limit.LowPart = PciBridgeMemoryLimit(Cfg);

		/* These should always be there, so check their alignment */
		DPRINT1("Bridge MEM Base and Limit: %x %x\n", Base.LowPart,
			Limit.LowPart);
		CheckAlignment = TRUE;
	    } else if (i == 4) {
		/* This should only be present for prefetch memory */
		ASSERT(CmDescriptor->Flags & CM_RESOURCE_MEMORY_PREFETCHABLE);
		Base = PciBridgePrefetchMemoryBase(Cfg);
		Limit = PciBridgePrefetchMemoryLimit(Cfg);

		/* If it's there, check the alignment */
		DPRINT1("Bridge Prefetch MEM Base and Limit: %llx %llx\n",
			Base.QuadPart, Limit.QuadPart);
		CheckAlignment = TRUE;
	    }

	    /* Check for invalid base address */
	    if (Base.QuadPart >= Limit.QuadPart) {
		/* Assume the descriptor is bogus */
		CmDescriptor->Type = CmResourceTypeNull;
		IoDescriptor->Type = CmResourceTypeNull;
		continue;
	    }

	    /* Check if there's no memory, and no I/O port either */
	    if (!(Base.LowPart) && !(HaveIoLimit)) {
		/* This seems like a bogus requirement, ignore it */
		CmDescriptor->Type = CmResourceTypeNull;
		continue;
	    }

	    /* Set the length to be the limit - the base; should always be 32-bit */
	    Length.QuadPart = Limit.LowPart - Base.LowPart + 1;
	    ASSERT(Length.HighPart == 0);
	    CmDescriptor->Generic.Length = Length.LowPart;

	    /* Check if alignment should be set */
	    if (CheckAlignment) {
		/* Compute the required alignment for this length */
		ASSERT(CmDescriptor->Memory.Length > 0);
		IoDescriptor->Memory.Alignment = PciBridgeMemoryWorstCaseAlignment(
		    CmDescriptor->Memory.Length);
	    }
	}

	/* Now set the base address */
	CmDescriptor->Generic.Start.LowPart = Base.LowPart;
    }

    /* If the bridge has VGA enable bit set, we will need some additional resources,
     * so the PnP manager will reserve the VGA memory range and IO port ranges. Note
     * this only applies to positive decode PCI bridges. */
    if (!PdoExtension->BridgeInfo.SubtractiveDecode &&
	PdoExtension->BridgeInfo.VgaBitSet) {
	PdoExtension->AdditionalResourceCount = 4;
    }
}

VOID PCIBridge_SaveLimits(IN PPCI_PDO_EXTENSION PdoExt,
			  IN PPCI_COMMON_HEADER Cfg)
{
    PULONG BarArray = Cfg->Type1.BaseAddresses;
    PIO_RESOURCE_DESCRIPTOR Limit = PdoExt->Resources->Limit;

    /* First, create a descriptor for the limit of each of the BARs */
    for (ULONG i = 0; i < PCI_TYPE1_ADDRESSES; i++) {
	if (PciCreateIoDescriptorFromBarLimit(PdoExt, &Limit[i], &BarArray[i], FALSE)) {
	    /* This was a 64-bit descriptor, make sure there's space */
	    ASSERT((i + 1) < PCI_TYPE1_ADDRESSES);

	    /* Skip the next descriptor since this one is double sized */
	    i++;
	    Limit[i].Type = CmResourceTypeNull;
	}
    }

    /* Check if this is a subtractive decode bridge */
    if (PdoExt->ProgIf == 0x1) {
	/* We found subtractive decode. These type of bridges don't use forward windows. */
	DPRINT1("PCI : Bridge for bus %d is subtractive decode\n",
		PdoExt->BridgeInfo.SecondaryBus);
	PdoExt->BridgeInfo.SubtractiveDecode = TRUE;
	Limit += PCI_TYPE1_ADDRESSES + 3;
    } else {
	/* For normal decode bridges, we'll need to build the resource descriptors for
	 * the IO/memory windows forwarded by the bridge. The allowed address range will
	 * be set to the largest address range allowed by the IO resource type. The size
	 * of the forward window is initially zero (at this point the resource descriptor
	 * will not be reported to the PnP manager). When we need to enlarge the forward
	 * window configured by the firmware (or if the bridge is hotplugged into the
	 * system and no forward window has been configured), the size of the forward
	 * windows will be dynamically adjusted to match the demand of the downstream
	 * devices. We cannot do this when the bridge is first enumerated by the parent
	 * bus, because the downstream devices have not yet been enumerated (PciScanBus
	 * is called during QUERY-DEVICE-RELATIONS of the PNP device node of the bridge,
	 * which occurs much later than the resource arbitration and device start sequence
	 * of the bridge device node). */
	Limit += PCI_TYPE1_ADDRESSES;

	/* The first IO descriptor after the BARs is the IO port forward window. */
	ASSERT(Cfg->Type1.IOLimit != 0);
	ASSERT((Cfg->Type1.IOLimit & 0x0E) == 0);
	PHYSICAL_ADDRESS MemoryLimit = {
	    .LowPart = PciBridgeIoLimit(Cfg)
	};
	Limit->ShareDisposition = PciGetShareDisposition(PdoExt);
	Limit->Type = CmResourceTypePort;
	Limit->Flags = CM_RESOURCE_PORT_WINDOW_DECODE | CM_RESOURCE_PORT_POSITIVE_DECODE;
	Limit->Port.Alignment = 0x1000;
	Limit->Port.MinimumAddress.QuadPart = 0;
	Limit->Port.MaximumAddress = MemoryLimit;
	Limit->Port.Length = 0;
	Limit++;

	/* The next IO resource descriptor is for the non-prefetchable memory window */
	ASSERT((Cfg->Type1.MemoryLimit & 0xF) == 0);
	MemoryLimit.LowPart = PciBridgeMemoryLimit(Cfg);
	Limit->ShareDisposition = PciGetShareDisposition(PdoExt);
	Limit->Flags = CM_RESOURCE_MEMORY_READ_WRITE;
	Limit->Type = CmResourceTypeMemory;
	Limit->Memory.Alignment = 0x100000;
	Limit->Memory.MinimumAddress.QuadPart = 0;
	Limit->Memory.MaximumAddress = MemoryLimit;
	Limit->Memory.Length = 0;
	Limit++;

	/* The next IO resource descriptor is for the prefetchable memory window. This
	 * descriptor may not exist, in which case we set the descriptor type to null. */
	if (Cfg->Type1.PrefetchLimit) {
	    MemoryLimit = PciBridgePrefetchMemoryLimit(Cfg);
	    Limit->ShareDisposition = PciGetShareDisposition(PdoExt);
	    Limit->Flags = CM_RESOURCE_MEMORY_PREFETCHABLE;
	    Limit->Type = CmResourceTypeMemory;
	    Limit->Memory.Alignment = 0x100000;
	    Limit->Memory.MinimumAddress.QuadPart = 0;
	    Limit->Memory.MaximumAddress = MemoryLimit;
	    Limit->Memory.Length = 0;
	} else {
	    Limit->Type = CmResourceTypeNull;
	}
	Limit++;
    }

    /* Does the ROM have its own BAR? */
    if (Cfg->Type1.ROMBaseAddress & PCI_ROMADDRESS_ENABLED) {
	/* Build a limit for it as well */
	PciCreateIoDescriptorFromBarLimit(PdoExt, Limit, &Cfg->Type1.ROMBaseAddress, TRUE);
    }
}

VOID PCIBridge_GetAdditionalResourceDescriptors(IN PPCI_PDO_EXTENSION PdoExt,
						IN PIO_RESOURCE_DESCRIPTOR IoDescriptor)
{
    /* Does this bridge have VGA decodes on it? */
    if (PdoExt->BridgeInfo.VgaBitSet) {
	/* Build a private descriptor so PciComputeNewCurrentSettings
	 * can skip the next 3 entries. */
	IoDescriptor->Type = CmResourceTypeDevicePrivate;
	IoDescriptor->DevicePrivate.Data[0] = PciLockResource;
	IoDescriptor->DevicePrivate.Data[1] = 3;

	/* First, the VGA range at 0xA0000 */
	IoDescriptor[1].Type = CmResourceTypeMemory;
	IoDescriptor[1].Flags = CM_RESOURCE_MEMORY_READ_WRITE;
	IoDescriptor[1].Port.Length = 0x20000;
	IoDescriptor[1].Port.Alignment = 1;
	IoDescriptor[1].Port.MinimumAddress.QuadPart = 0xA0000;
	IoDescriptor[1].Port.MaximumAddress.QuadPart = 0xBFFFF;

	/* Then, the VGA registers at 0x3B0 */
	IoDescriptor[2].Type = CmResourceTypePort;
	IoDescriptor[2].Flags = CM_RESOURCE_PORT_POSITIVE_DECODE |
	    CM_RESOURCE_PORT_10_BIT_DECODE;
	IoDescriptor[2].Port.Length = 12;
	IoDescriptor[2].Port.Alignment = 1;
	IoDescriptor[2].Port.MinimumAddress.QuadPart = 0x3B0;
	IoDescriptor[2].Port.MaximumAddress.QuadPart = 0x3BB;

	/* And finally the VGA registers at 0x3C0 */
	IoDescriptor[3].Type = CmResourceTypePort;
	IoDescriptor[3].Flags = CM_RESOURCE_PORT_POSITIVE_DECODE |
	    CM_RESOURCE_PORT_10_BIT_DECODE;
	IoDescriptor[3].Port.Length = 32;
	IoDescriptor[3].Port.Alignment = 1;
	IoDescriptor[3].Port.MinimumAddress.QuadPart = 0x3C0;
	IoDescriptor[3].Port.MaximumAddress.QuadPart = 0x3DF;
    }
}

VOID PCIBridge_ResetDevice(IN PPCI_PDO_EXTENSION PdoExtension)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNIMPLEMENTED_DBGBREAK();
}

VOID PCIBridge_ChangeResourceSettings(IN PPCI_PDO_EXTENSION PdoExtension,
				      OUT USHORT *CommandEnables)
{
    PCI_COMMON_HEADER Cfg = {};
    if (PdoExtension->BridgeInfo.SubtractiveDecode) {
	/* No resources are needed on a subtractive decode bridge */
	Cfg.Type1.MemoryBase = 0xFFFF;
	Cfg.Type1.PrefetchBase = 0xFFFF;
	Cfg.Type1.IOBase = 0xFF;
	Cfg.Type1.IOLimit = 0;
	Cfg.Type1.MemoryLimit = 0;
	Cfg.Type1.PrefetchLimit = 0;
	Cfg.Type1.PrefetchBaseUpper32 = 0;
	Cfg.Type1.PrefetchLimitUpper32 = 0;
	Cfg.Type1.IOBaseUpper16 = 0;
	Cfg.Type1.IOLimitUpper16 = 0;
	/* For subtractive decode bridges we always turn on IO and memory decoding. */
	*CommandEnables |= PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE;
    }

    PPCI_FUNCTION_RESOURCES PciResources = PdoExtension->Resources;
    if (PciResources) {
	/* Set the BAR resources first */
	for (ULONG i = 0; i < PCI_TYPE1_ADDRESSES; i++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Res = &PdoExtension->Resources->Current[i];
            if (Res->Type == CmResourceTypeNull) {
                continue;
            }

	    assert(Res->Type == CmResourceTypeMemory || Res->Type == CmResourceTypePort);
	    if (Res->Type == CmResourceTypeMemory) {
		*CommandEnables |= PCI_ENABLE_MEMORY_SPACE;
		ULONG BaseAddress = Cfg.Type1.BaseAddresses[i];
		if ((BaseAddress & PCI_ADDRESS_MEMORY_TYPE_MASK) == PCI_TYPE_64BIT) {
		    /* We have a 64-bit BAR. It must be the first resource, and the
		     * second resource must be NULL. */
		    assert(i == 0);
		    assert((Res+1)->Type == CmResourceTypeNull);
		    Cfg.Type1.BaseAddresses[1] = Res->Memory.Start.HighPart;
		}
	    } else {
		*CommandEnables |= PCI_ENABLE_IO_SPACE;
	    }
	    /* This applies for both Memory and Port resources. */
	    Cfg.Type1.BaseAddresses[i] = Res->Generic.Start.LowPart;
	}

	/* The next resource must be IO forward window */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Res =
	    &PdoExtension->Resources->Current[PCI_BRIDGE_IO_PORT_RESOURCE];
	if (Res->Type == CmResourceTypePort) {
	    ULONG Start = Res->Port.Start.LowPart;
	    ULONG End = Start + Res->Port.Length - 1;
	    /* Port window is always 4K aligned. */
	    assert(((Start & 0xFFF) == 0) && ((End & 0xFFF) == 0xFFF));
	    /* If the bridge only supports 16-bit IO ports, make sure the upper
	     * 16 bits are zero. */
	    if ((Cfg.Type1.IOBase & 0xF) != 1) {
		assert(!(Start & 0xFFFF0000));
		assert(!(End & 0xFFFF0000));
	    }
	    Cfg.Type1.IOBaseUpper16  = Start >> 16;
	    Cfg.Type1.IOLimitUpper16 = End >> 16;
	    Cfg.Type1.IOBase  = (Start >> 8) & 0xF0;
	    Cfg.Type1.IOLimit = (End >> 8) & 0xF0;
	    *CommandEnables |= PCI_ENABLE_IO_SPACE;
	} else {
	    assert(Res->Type == CmResourceTypeNull);
	}

	/* The next resource must be non-prefetchable memory window */
	Res++;
	if (Res->Type == CmResourceTypeMemory) {
	    ULONG Start = Res->Memory.Start.LowPart;
	    ULONG End = Start + Res->Memory.Length - 1;
	    /* Memory window is always 1MB aligned. */
	    assert(((Start & 0xFFFFF) == 0) && ((End & 0xFFFFF) == 0xFFFFF));
	    Cfg.Type1.MemoryBase = Start >> 16;
	    Cfg.Type1.MemoryLimit = (End >> 16) & 0xFFF0;
	    *CommandEnables |= PCI_ENABLE_MEMORY_SPACE;
	} else {
	    assert(Res->Type == CmResourceTypeNull);
	}

	/* The next resource must be prefetchable memory window */
	Res++;
	if (Res->Type == CmResourceTypeMemory) {
	    ULONG64 Start = Res->Memory.Start.QuadPart;
	    ULONG64 End = Res->Memory.Start.QuadPart + Res->Memory.Length - 1;
	    assert(((Start & 0xFFFFFULL) == 0) && (End & 0xFFFFFULL) == 0xFFFFFULL);
	    Cfg.Type1.PrefetchBase = Start >> 16;
	    Cfg.Type1.PrefetchLimit = (End >> 16) & 0xFFF0ULL;
	    Cfg.Type1.PrefetchBaseUpper32 = Start >> 32;
	    Cfg.Type1.PrefetchLimitUpper32 = End >> 32;
	    *CommandEnables |= PCI_ENABLE_MEMORY_SPACE;
	} else {
	    assert(Res->Type == CmResourceTypeNull);
	}

	/* The last resource must be ROM */
	Res++;
	if (Res->Type == CmResourceTypeMemory) {
	    ULONG BaseAddress = Cfg.Type1.ROMBaseAddress;
	    BaseAddress &= ~PCI_ADDRESS_ROM_ADDRESS_MASK;
	    BaseAddress |= Res->Memory.Start.LowPart & PCI_ADDRESS_ROM_ADDRESS_MASK;
	    Cfg.Type1.ROMBaseAddress = BaseAddress;
	    *CommandEnables |= PCI_ENABLE_MEMORY_SPACE;
	} else {
	    assert(Res->Type == CmResourceTypeNull);
	}
    }
}
