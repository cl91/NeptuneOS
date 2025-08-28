/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/debug.c
 * PURPOSE:         Debug Helpers
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* GLOBALS ********************************************************************/

PCHAR PnpCodes[] = { "START_DEVICE",
    "QUERY_REMOVE_DEVICE",
    "REMOVE_DEVICE",
    "CANCEL_REMOVE_DEVICE",
    "STOP_DEVICE",
    "QUERY_STOP_DEVICE",
    "CANCEL_STOP_DEVICE",
    "QUERY_DEVICE_RELATIONS",
    "QUERY_INTERFACE",
    "QUERY_CAPABILITIES",
    "QUERY_RESOURCES",
    "QUERY_RESOURCE_REQUIREMENTS",
    "QUERY_DEVICE_TEXT",
    "FILTER_RESOURCE_REQUIREMENTS",
    "** UNKNOWN PNP IRP Minor Code **",
    "READ_CONFIG",
    "WRITE_CONFIG",
    "EJECT",
    "SET_LOCK",
    "QUERY_ID",
    "QUERY_PNP_DEVICE_STATE",
    "QUERY_BUS_INFORMATION",
    "DEVICE_USAGE_NOTIFICATION" };

PCHAR PoCodes[] = {
    "WAIT_WAKE",
    "POWER_SEQUENCE",
    "SET_POWER",
    "QUERY_POWER",
};

PCHAR SystemPowerStates[] = { "Unspecified", "Working",	  "Sleeping1", "Sleeping2",
    "Sleeping3",   "Hibernate", "Shutdown" };

PCHAR DevicePowerStates[] = { "Unspecified", "D0", "D1", "D2", "D3" };

ULONG PciBreakOnPdoPowerIrp, PciBreakOnFdoPowerIrp;
ULONG PciBreakOnPdoPnpIrp, PciBreakOnFdoPnpIrp;

/* FUNCTIONS ******************************************************************/

PCHAR PciDebugPnpIrpTypeToText(IN USHORT MinorFunction)
{
    PCHAR Text;

    /* Catch invalid code */
    if (MinorFunction >= IRP_MN_SURPRISE_REMOVAL) {
	/* New version of Windows? Or driver bug */
	Text = "** UNKNOWN PNP IRP Minor Code **";
    } else {
	/* Get the right text for it */
	Text = PnpCodes[MinorFunction];
    }

    /* Return the symbolic name for the IRP */
    return Text;
}

PCHAR PciDebugPoIrpTypeToText(IN USHORT MinorFunction)
{
    PCHAR Text;

    /* Catch invalid code */
    if (MinorFunction >= IRP_MN_QUERY_POWER) {
	/* New version of Windows? Or driver bug */
	Text = "** UNKNOWN PO IRP Minor Code **";
    } else {
	/* Get the right text for it */
	Text = PoCodes[MinorFunction];
    }

    /* Return the symbolic name for the IRP */
    return Text;
}

BOOLEAN PciDebugIrpDispatchDisplay(IN PIO_STACK_LOCATION IoStackLocation,
				   IN PPCI_FDO_EXTENSION DeviceExtension,
				   IN USHORT MaxMinor)
{
    PPCI_PDO_EXTENSION PdoDeviceExtension;
    ULONG BreakMask;
    //ULONG DebugLevel = 0;
    PCHAR IrpString;

    /* Only two functions are recognized */
    switch (IoStackLocation->MajorFunction) {
    case IRP_MJ_POWER:

	/* Get the string and the correct break mask for the extension */
	BreakMask = (DeviceExtension->ExtensionType == PciPdoExtensionType) ?
	    PciBreakOnPdoPowerIrp :
	PciBreakOnFdoPowerIrp;
	IrpString = PciDebugPoIrpTypeToText(IoStackLocation->MinorFunction);
	break;

    case IRP_MJ_PNP:

	/* Get the string and the correct break mask for the extension */
	BreakMask = (DeviceExtension->ExtensionType == PciFdoExtensionType) ?
	    PciBreakOnPdoPnpIrp :
	PciBreakOnFdoPnpIrp;
	IrpString = PciDebugPnpIrpTypeToText(IoStackLocation->MinorFunction);
	break;

    default:

	/* Other functions are not decoded */
	BreakMask = FALSE;
	IrpString = "";
	break;
    }

    /* Check if this is a PDO */
    if (DeviceExtension->ExtensionType == PciPdoExtensionType) {
	/* Choose the correct debug level based on which function this is */
	if (IoStackLocation->MajorFunction == IRP_MJ_POWER) {
	    //DebugLevel = 0x500;
	} else if (IoStackLocation->MajorFunction == IRP_MJ_PNP) {
	    //DebugLevel = 0x200;
	}

	/* For a PDO, print out the bus, device, and function number */
	PdoDeviceExtension = (PVOID)DeviceExtension;
	DPRINT1("PDO(b=0x%x, d=0x%x, f=0x%x)<-%s\n",
		PdoDeviceExtension->ParentFdoExtension->BaseBus,
		PdoDeviceExtension->Slot.Bits.DeviceNumber,
		PdoDeviceExtension->Slot.Bits.FunctionNumber, IrpString);
    } else if (DeviceExtension->ExtensionType == PciFdoExtensionType) {
	/* Choose the correct debug level based on which function this is */
	if (IoStackLocation->MajorFunction == IRP_MJ_POWER) {
	    //DebugLevel = 0x400;
	} else if (IoStackLocation->MajorFunction == IRP_MJ_PNP) {
	    //DebugLevel = 0x100;
	}

	/* For an FDO, just dump the extension pointer and IRP string */
	DPRINT1("FDO(%p)<-%s\n", DeviceExtension, IrpString);
    }

    /* If the function is illegal for this extension, complain */
    if (IoStackLocation->MinorFunction > MaxMinor)
	DPRINT1("Unknown IRP, minor = 0x%x\n", IoStackLocation->MinorFunction);

    /* Return whether or not the debugger should be broken into for this IRP */
    return ((1 << IoStackLocation->MinorFunction) & BreakMask);
}

VOID PciDebugDumpCommonConfig(IN PPCI_COMMON_HEADER PciData)
{
    USHORT i;

    /* Loop the PCI header */
    for (i = 0; i < PCI_COMMON_HDR_LENGTH; i += 4) {
	/* Dump each DWORD and its offset */
	DPRINT1("  %02x - %08x\n", i, *(PULONG)((ULONG_PTR)PciData + i));
    }
}

VOID PciDebugDumpQueryCapabilities(IN PDEVICE_CAPABILITIES DeviceCaps)
{
    ULONG i;

    /* Dump the capabilities */
    DPRINT1("Capabilities\n  Lock:%u, Eject:%u, Remove:%u, Dock:%u, UniqueId:%u\n",
	    DeviceCaps->LockSupported, DeviceCaps->EjectSupported, DeviceCaps->Removable,
	    DeviceCaps->DockDevice, DeviceCaps->UniqueID);
    DbgPrint("  SilentInstall:%u, RawOk:%u, SurpriseOk:%u\n", DeviceCaps->SilentInstall,
	     DeviceCaps->RawDeviceOK, DeviceCaps->SurpriseRemovalOK);
    DbgPrint("  Address %08x, UINumber %08x, Latencies D1 %u, D2 %u, D3 %u\n",
	     DeviceCaps->Address, DeviceCaps->UINumber, DeviceCaps->D1Latency,
	     DeviceCaps->D2Latency, DeviceCaps->D3Latency);

    /* Dump and convert the wake levels */
    DbgPrint("  System Wake: %s, Device Wake: %s\n  DeviceState[PowerState] [",
	     SystemPowerStates[min(DeviceCaps->SystemWake, PowerSystemMaximum)],
	     DevicePowerStates[min(DeviceCaps->DeviceWake, PowerDeviceMaximum)]);

    /* Dump and convert the power state mappings */
    for (i = PowerSystemWorking; i < PowerSystemMaximum; i++)
	DbgPrint(" %s", DevicePowerStates[DeviceCaps->DeviceState[i]]);

    /* Finish the dump */
    DbgPrint(" ]\n");
}
