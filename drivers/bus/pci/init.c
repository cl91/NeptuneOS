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

/* FUNCTIONS ******************************************************************/

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
    /* Remember our object so we can get it to it later */
    PciDriverObject = DriverObject;

    /* Setup the IRP dispatcher */
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PciDispatchIrp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = PciDispatchIrp;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PciDispatchIrp;
    DriverObject->MajorFunction[IRP_MJ_PNP] = PciDispatchIrp;
    DriverObject->DriverUnload = PciDriverUnload;

    /* This is how we'll detect a new PCI bus */
    DriverObject->AddDevice = PciAddDevice;

    return STATUS_SUCCESS;
}
