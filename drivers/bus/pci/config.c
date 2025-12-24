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

static VOID PciReadWriteConfigSpace(IN PPCI_FDO_EXTENSION DeviceExtension,
				    IN PCI_SLOT_NUMBER Slot,
				    IN PCHAR Buffer,
				    IN ULONG Offset,
				    IN ULONG Length,
				    IN BOOLEAN Read)
{
    /* Only the root FDO can access configuration space */
    ASSERT(PCI_IS_ROOT_FDO(DeviceExtension->BusRootFdoExtension));
    PHYSICAL_ADDRESS PhyAddr = DeviceExtension->BusRootFdoExtension->ConfigBase;
    PhyAddr.QuadPart += ((DeviceExtension->BaseBus << 8) | (Slot.Bits.DeviceNumber << 3) |
			 Slot.Bits.FunctionNumber) << CFG_SHIFT;
    volatile CHAR *Ptr = MmMapIoSpace(PhyAddr, 1UL << CFG_SHIFT, MmNonCached);
    DPRINT("%s PCI Config Base 0x%llx BaseBus 0x%x Dev 0x%x Func 0x%x "
	   "Mapped %p Buffer %p Offset 0x%x Length 0x%x\n",
	   Read ? "Reading" : "Writing",
	   DeviceExtension->BusRootFdoExtension->ConfigBase.QuadPart,
	   DeviceExtension->BaseBus, Slot.Bits.DeviceNumber, Slot.Bits.FunctionNumber,
	   Ptr, Buffer, Offset, Length);
    if (!Ptr) {
	RtlRaiseStatus(STATUS_ACCESS_DENIED);
    }
#if DBG
    volatile PCI_COMMON_CONFIG *PciCfg = (PVOID)Ptr;
    if (PciCfg->Header.VendorID == PCI_INVALID_VENDORID) {
	DPRINT("Invalid vendor ID in PCI configuration space.\n");
    } else {
	DPRINT("PCI device is present\n");
    }
#endif
    Ptr += Offset;
    for (ULONG i = 0; i < Length; i++) {
	if (Read) {
	    Buffer[i] = Ptr[i];
	} else {
	    Ptr[i] = Buffer[i];
	}
    }
}

VOID PciWriteDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			  IN PVOID Buffer,
			  IN ULONG Offset,
			  IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension->ParentFdoExtension,
			    DeviceExtension->Slot,
			    Buffer, Offset, Length, FALSE);
}

VOID PciReadDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension,
			 IN PVOID Buffer,
			 IN ULONG Offset,
			 IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension->ParentFdoExtension,
			    DeviceExtension->Slot,
			    Buffer, Offset, Length, TRUE);
}

VOID PciReadSlotConfig(IN PPCI_FDO_EXTENSION DeviceExtension,
		       IN PCI_SLOT_NUMBER Slot, IN PVOID Buffer, IN ULONG Offset,
		       IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension, Slot, Buffer, Offset, Length, TRUE);
}
