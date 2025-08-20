/*
 * PROJECT:        ReactOS Floppy Disk Controller Driver
 * LICENSE:        GNU GPLv2 only as published by the Free Software Foundation
 * FILE:           drivers/storage/fdc/fdc/fdc.c
 * PURPOSE:        Main Driver Routines
 * PROGRAMMERS:    Eric Kohl
 *                 Vizzini (vizzini@plasmic.com)
 * REVISIONS:
 *                 15-Feb-2004 vizzini - Created
 * NOTES:
 *  - This driver is only designed to work with ISA-bus floppy controllers.  This
 *    won't work on PCI-based controllers or on anything else with level-sensitive
 *    interrupts without modification.  I don't think these controllers exist.
 *
 * ---- Support for proper media detection ----
 * TODO: Handle MFM flag
 * TODO: Un-hardcode the data rate from various places
 * TODO: Proper media detection (right now we're hardcoded to 1.44)
 * TODO: Media detection based on sector 1
 */

/* INCLUDES *******************************************************************/

#include "fdc.h"

/* FUNCTIONS ******************************************************************/

static NTSTATUS NTAPI FdcAddDevice(IN PDRIVER_OBJECT DriverObject,
				   IN PDEVICE_OBJECT Pdo)
{
    DPRINT("FdcAddDevice()\n");

    ASSERT(DriverObject);
    ASSERT(Pdo);
    /* If we are called for the class DO (the \Device\Floopy0 device object),
     * do nothing. These PDOs are distinguished from the PDOs enumerated by
     * the parent bus by having a device extension. */
    if (Pdo->DeviceExtension) {
	return STATUS_SUCCESS;
    }

    /* Create functional device object for the controller */
    PDEVICE_OBJECT Fdo = NULL;
    NTSTATUS Status = IoCreateDevice(DriverObject, sizeof(FDO_DEVICE_EXTENSION), NULL,
				     FILE_DEVICE_CONTROLLER,
				     FILE_DEVICE_SECURE_OPEN | DO_DIRECT_IO |
				     DO_MAP_IO_BUFFER | DO_POWER_PAGABLE,
				     FALSE, &Fdo);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    ASSERT(Fdo);
    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)Fdo->DeviceExtension;
    RtlZeroMemory(DeviceExtension, sizeof(FDO_DEVICE_EXTENSION));

    DeviceExtension->Common.IsFDO = TRUE;
    DeviceExtension->Common.DeviceObject = Fdo;

    DeviceExtension->Pdo = Pdo;

    Status = IoAttachDeviceToDeviceStackSafe(Fdo, Pdo, &DeviceExtension->LowerDevice);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("IoAttachDeviceToDeviceStackSafe() failed with status 0x%08x\n", Status);
	IoDeleteDevice(Fdo);
	return Status;
    }

    KeInitializeEvent(&DeviceExtension->ControllerInfo.SynchEvent,
		      SynchronizationEvent, FALSE);

    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static NTAPI VOID FdcDriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    DPRINT("FdcDriverUnload()\n");
}

static NTAPI NTSTATUS FdcCreate(IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp)
{
    DPRINT("FdcCreate()\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS FdcClose(IN PDEVICE_OBJECT DeviceObject,
			       IN PIRP Irp)
{
    DPRINT("FdcClose()\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS FdcReadWrite(IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION Common = DeviceObject->DeviceExtension;

    DPRINT("FdcReadWrite()\n");
    if (Common->IsFDO) {
	ERR_(FLOPPY, "You can only send ReadWrite to the PDO\n");
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else if (!Irp->MdlAddress) {
	WARN_(FLOPPY,
	      "FdcReadWrite(): MDL not found in IRP - Completing with STATUS_INVALID_PARAMETER\n");
	Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else {
	PPDO_DEVICE_EXTENSION DeviceExtension = (PPDO_DEVICE_EXTENSION)Common;
	ReadWrite(DeviceExtension->DriveInfo, Irp);
    }
    return Irp->IoStatus.Status;
}

static NTAPI NTSTATUS FdcDeviceControl(IN PDEVICE_OBJECT DeviceObject,
				       IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION Common = DeviceObject->DeviceExtension;

    DPRINT("FdcDeviceControl()\n");
    if (Common->IsFDO) {
	ERR_(FLOPPY, "You can only send DeviceIoControl to the PDO\n");
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else {
	PPDO_DEVICE_EXTENSION DeviceExtension = (PPDO_DEVICE_EXTENSION)Common;
	DeviceIoctl(DeviceExtension->DriveInfo, Irp);
    }
    return Irp->IoStatus.Status;
}

static NTAPI NTSTATUS FdcPnp(IN PDEVICE_OBJECT DeviceObject,
			     IN PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION Common = DeviceObject->DeviceExtension;

    DPRINT("FdcPnP()\n");
    if (Common->IsFDO) {
	return FdcFdoPnp(DeviceObject, Irp);
    } else {
	return FdcPdoPnp(DeviceObject, Irp);
    }
}

static NTAPI NTSTATUS FdcPower(IN PDEVICE_OBJECT DeviceObject,
			       IN PIRP Irp)
{
    NTSTATUS Status = Irp->IoStatus.Status;
    PFDO_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    DPRINT("FdcPower()\n");

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (DeviceExtension->Common.IsFDO) {
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(DeviceExtension->LowerDevice, Irp);
    } else {
	switch (IrpSp->MinorFunction) {
	case IRP_MN_QUERY_POWER:
	case IRP_MN_SET_POWER:
	    Status = STATUS_SUCCESS;
	    break;
	}
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
    }
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    DPRINT("FDC: DriverEntry()\n");

    DriverObject->MajorFunction[IRP_MJ_CREATE] = FdcCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = FdcClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = FdcReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = FdcReadWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FdcDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_PNP] = FdcPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = FdcPower;

    DriverObject->AddDevice = FdcAddDevice;
    DriverObject->DriverUnload = FdcDriverUnload;

    return STATUS_SUCCESS;
}
