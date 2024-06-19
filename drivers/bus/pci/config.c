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

NTAPI UCHAR PciGetAdjustedInterruptLine(IN PPCI_PDO_EXTENSION PdoExtension)
{
    UCHAR InterruptLine = 0, PciInterruptLine;
    ULONG Length;

    /* Does the device have an interrupt pin? */
    if (PdoExtension->InterruptPin) {
	/* Find the associated line on the parent bus */
	Length = HalGetBusDataByOffset(
	    PCIConfiguration, PdoExtension->ParentFdoExtension->BaseBus,
	    PdoExtension->Slot.AsULONG, &PciInterruptLine,
	    FIELD_OFFSET(PCI_COMMON_HEADER, Type0.InterruptLine), sizeof(UCHAR));
	if (Length)
	    InterruptLine = PciInterruptLine;
    }

    /* Either keep the original interrupt line, or the one on the master bus */
    return InterruptLine ? PdoExtension->RawInterruptLine : InterruptLine;
}

NTAPI VOID PciReadWriteConfigSpace(IN PPCI_FDO_EXTENSION DeviceExtension,
				   IN PCI_SLOT_NUMBER Slot, IN PVOID Buffer,
				   IN ULONG Offset, IN ULONG Length, IN BOOLEAN Read)
{
    /* TODO! */
#if 0
    PPCI_BUS_INTERFACE_STANDARD PciInterface;
    PBUS_HANDLER BusHandler;
    PPCIBUSDATA BusData;
    PciReadWriteConfig HalFunction;

    /* Only the root FDO can access configuration space */
    ASSERT(PCI_IS_ROOT_FDO(DeviceExtension->BusRootFdoExtension));

    /* Get the ACPI-compliant PCI interface */
    PciInterface = DeviceExtension->BusRootFdoExtension->PciBusInterface;
    if (PciInterface) {
	/* Currently this driver only supports the legacy HAL interface */
	UNIMPLEMENTED_DBGBREAK();
    } else {
	/* Make sure there's a registered HAL bus handler */
	ASSERT(DeviceExtension->BusHandler);

	/* PCI Bus Number assignment is only valid on ACPI systems */
	ASSERT(!PciAssignBusNumbers);

	/* Grab the HAL PCI Bus Handler data */
	BusHandler = (PBUS_HANDLER)DeviceExtension->BusHandler;
	BusData = (PPCIBUSDATA)BusHandler->BusData;

	/* Choose the appropriate read or write function, and call it */
	HalFunction = Read ? BusData->ReadConfig : BusData->WriteConfig;
	HalFunction(BusHandler, Slot, Buffer, Offset, Length);
    }
#endif
}

NTAPI VOID PciWriteDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension, IN PVOID Buffer,
				IN ULONG Offset, IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension->ParentFdoExtension, DeviceExtension->Slot,
			    Buffer, Offset, Length, FALSE);
}

NTAPI VOID PciReadDeviceConfig(IN PPCI_PDO_EXTENSION DeviceExtension, IN PVOID Buffer,
			       IN ULONG Offset, IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension->ParentFdoExtension, DeviceExtension->Slot,
			    Buffer, Offset, Length, TRUE);
}

NTAPI VOID PciReadSlotConfig(IN PPCI_FDO_EXTENSION DeviceExtension,
			     IN PCI_SLOT_NUMBER Slot, IN PVOID Buffer, IN ULONG Offset,
			     IN ULONG Length)
{
    /* Call the generic worker function */
    PciReadWriteConfigSpace(DeviceExtension, Slot, Buffer, Offset, Length, TRUE);
}
