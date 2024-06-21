/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/dispatch.c
 * PURPOSE:         WDM Dispatch Routines
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* FUNCTIONS ******************************************************************/

static NTSTATUS PciCallDownIrpStack(IN PPCI_FDO_EXTENSION DeviceExtension, IN PIRP Irp)
{
    DPRINT1("PciCallDownIrpStack ...\n");
    ASSERT_FDO(DeviceExtension);

    /* Call the attached device */
    return IoCallDriverEx(DeviceExtension->AttachedDeviceObject, Irp, NULL);
}

static NTSTATUS PciPassIrpFromFdoToPdo(IN PPCI_FDO_EXTENSION DeviceExtension, IN PIRP Irp)
{
    DPRINT1("Pci PassIrp ...\n");
    return IoCallDriver(DeviceExtension->AttachedDeviceObject, Irp);
}

NTAPI NTSTATUS PciDispatchIrp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PPCI_FDO_EXTENSION DeviceExtension;
    PIO_STACK_LOCATION IoStackLocation;
    PPCI_MJ_DISPATCH_TABLE IrpDispatchTable;
    BOOLEAN PassToPdo;
    NTSTATUS Status;
    PPCI_MN_DISPATCH_TABLE TableArray = NULL, Table;
    USHORT MaxMinor;
    PCI_DISPATCH_STYLE DispatchStyle = 0;
    PCI_DISPATCH_FUNCTION DispatchFunction = NULL;
    DPRINT1("PCI: Dispatch IRP\n");

    /* Get the extension and I/O stack location for this IRP */
    DeviceExtension = (PPCI_FDO_EXTENSION)DeviceObject->DeviceExtension;
    IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ASSERT((DeviceExtension->ExtensionType == PciPdoExtensionType) ||
	   (DeviceExtension->ExtensionType == PciFdoExtensionType));

    /* Deleted extensions don't respond to IRPs */
    if (DeviceExtension->DeviceState == PciDeleted) {
	/* Fail this IRP */
	Status = STATUS_NO_SUCH_DEVICE;
	PassToPdo = FALSE;
    } else {
	/* Otherwise, get the dispatch table for the extension */
	IrpDispatchTable = DeviceExtension->IrpDispatchTable;

	/* And choose which function table to use */
	switch (IoStackLocation->MajorFunction) {
	case IRP_MJ_POWER:
	    /* Power Manager IRPs */
	    TableArray = IrpDispatchTable->PowerIrpDispatchTable;
	    MaxMinor = IrpDispatchTable->PowerIrpMaximumMinorFunction;
	    break;

	case IRP_MJ_PNP:
	    /* Plug-and-Play Manager IRPs */
	    TableArray = IrpDispatchTable->PnpIrpDispatchTable;
	    MaxMinor = IrpDispatchTable->PnpIrpMaximumMinorFunction;
	    break;

	case IRP_MJ_SYSTEM_CONTROL:
	    /* WMI IRPs */
	    DispatchFunction = IrpDispatchTable->SystemControlIrpDispatchFunction;
	    DispatchStyle = IrpDispatchTable->SystemControlIrpDispatchStyle;
	    MaxMinor = 0xFFFF;
	    break;

	default:
	    /* Unrecognized IRPs */
	    DispatchFunction = IrpDispatchTable->OtherIrpDispatchFunction;
	    DispatchStyle = IrpDispatchTable->OtherIrpDispatchStyle;
	    MaxMinor = 0xFFFF;
	    break;
	}

	/* Only deal with recognized IRPs */
	if (MaxMinor != 0xFFFF) {
	    /* Make sure the function is recognized */
	    if (IoStackLocation->MinorFunction > MaxMinor) {
		/* Pick the terminator, which should return unrecognized */
		Table = &TableArray[MaxMinor + 1];
	    } else {
		/* Pick the appropriate table for this function */
		Table = &TableArray[IoStackLocation->MinorFunction];
	    }

	    /* From that table, get the function code and dispatch style */
	    DispatchStyle = Table->DispatchStyle;
	    DispatchFunction = Table->DispatchFunction;
	}

	/* Print out debugging information, and see if we should break */
	if (PciDebugIrpDispatchDisplay(IoStackLocation, DeviceExtension, MaxMinor)) {
	    /* The developer/user wants us to break for this IRP, do it */
	    DbgBreakPoint();
	}

	/* Check if this IRP should be sent up the stack first */
	if (DispatchStyle == IRP_UPWARD) {
	    /* Do it now before handling it ourselves */
	    PciCallDownIrpStack(DeviceExtension, Irp);
	}

	/* Call the our driver's handler for this IRP and deal with the IRP */
	Status = DispatchFunction(Irp, IoStackLocation, DeviceExtension);
	switch (DispatchStyle) {
	/* Complete IRPs are completely immediately by our driver */
	case IRP_COMPLETE:
	    PassToPdo = FALSE;
	    break;

	/* Downward IRPs are send to the attached FDO */
	case IRP_DOWNWARD:
	    PassToPdo = TRUE;
	    break;

	/* Upward IRPs are completed immediately by our driver */
	case IRP_UPWARD:
	    PassToPdo = FALSE;
	    break;

	/* Dispatch IRPs are immediately returned */
	case IRP_DISPATCH:
	    return Status;

	/* There aren't any other dispatch styles! */
	default:
	    ASSERT(FALSE);
	    return Status;
	}
    }

    /* Pending IRPs are returned immediately */
    if (Status == STATUS_PENDING)
	return Status;

    /* Handled IRPs return their status in the status block */
    if (Status != STATUS_NOT_SUPPORTED)
	Irp->IoStatus.Status = Status;

    /* Successful, or unhandled IRPs that are "DOWNWARD" are sent to the PDO */
    if ((PassToPdo) && ((NT_SUCCESS(Status)) || (Status == STATUS_NOT_SUPPORTED))) {
	/* Let the PDO deal with it */
	Status = PciPassIrpFromFdoToPdo(DeviceExtension, Irp);
    } else {
	/* Otherwise, the IRP is returned with its status */
	Status = Irp->IoStatus.Status;

	/* And now this IRP can be completed */
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    /* And the status returned back to the caller */
    return Status;
}

NTSTATUS PciIrpNotSupported(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			    IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    /* Not supported */
    DPRINT1("WARNING: PCI received unsupported IRP!\n");
    //DbgBreakPoint();
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS PciIrpInvalidDeviceRequest(IN PIRP Irp,
				    IN PIO_STACK_LOCATION IoStackLocation,
				    IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    /* Not supported */
    return STATUS_INVALID_DEVICE_REQUEST;
}
