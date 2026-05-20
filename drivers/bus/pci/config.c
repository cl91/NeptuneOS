/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pci/config.c
 * PURPOSE:         PCI Configuration Space Routines
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* GLOBALS ********************************************************************/

BOOLEAN PciAssignBusNumbers;

/* FUNCTIONS ******************************************************************/

#define CFG_SHIFT	12

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
			 Slot.Bits.FunctionNumber) << CFG_SHIFT;
    volatile CHAR *Ptr = MmMapIoSpace(PhyAddr, 1UL << CFG_SHIFT, MmNonCached);
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
    MmUnmapIoSpace((PVOID)Ptr, 1UL << CFG_SHIFT);
}
