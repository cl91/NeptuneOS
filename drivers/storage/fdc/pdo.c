/*
 * PROJECT:        ReactOS Floppy Disk Controller Driver
 * LICENSE:        GNU GPLv2 only as published by the Free Software Foundation
 * FILE:           drivers/storage/fdc/fdc/pdo.c
 * PURPOSE:        Physical Device Object routines
 * PROGRAMMERS:    Eric Kohl
 * NOTES:
 *     This file implements the function driver part of the FDC stack. This
 * might seem rather counter-intuitive, as this file is titled "Physical Device
 * Object routines". See fdc.h for the reason why.
 */

/* INCLUDES *******************************************************************/

#include "fdc.h"

/* FUNCTIONS ******************************************************************/

static NTSTATUS FdcPdoQueryCapabilities(IN PDEVICE_OBJECT DeviceObject,
					IN PIO_STACK_LOCATION IrpSp)
{
    DPRINT("FdcPdoQueryCapabilities Called\n");

    PPDO_DEVICE_EXTENSION DeviceExtension =
	(PPDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PDEVICE_CAPABILITIES DeviceCapabilities =
	IrpSp->Parameters.DeviceCapabilities.Capabilities;

    if (DeviceCapabilities->Version != 1)
	return STATUS_UNSUCCESSFUL;

    DeviceCapabilities->UniqueID = FALSE;
    DeviceCapabilities->Address = DeviceExtension->DriveInfo->PeripheralNumber;

    return STATUS_SUCCESS;
}

static NTSTATUS FdcPdoQueryId(IN PDEVICE_OBJECT DeviceObject,
			      IN PIO_STACK_LOCATION IrpSp,
			      OUT ULONG_PTR *Information)
{
    PUNICODE_STRING SourceString;

    PPDO_DEVICE_EXTENSION DeviceExtension =
	(PPDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    UNICODE_STRING String;
    RtlInitUnicodeString(&String, NULL);

    switch (IrpSp->Parameters.QueryId.IdType) {
    case BusQueryDeviceID:
	DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryDeviceID\n");
	SourceString = &DeviceExtension->DeviceId;
	break;

    case BusQueryHardwareIDs:
	DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryHardwareIDs\n");
	SourceString = &DeviceExtension->HardwareIds;
	break;

    case BusQueryCompatibleIDs:
	DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryCompatibleIDs\n");
	SourceString = &DeviceExtension->CompatibleIds;
	break;

    case BusQueryInstanceID:
	DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryInstanceID\n");
	SourceString = &DeviceExtension->InstanceId;
	break;

    default:
	DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_ID / unknown query id type 0x%x\n",
		IrpSp->Parameters.QueryId.IdType);
	ASSERT(FALSE);
	return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
						SourceString, &String);

    *Information = (ULONG_PTR)String.Buffer;

    return Status;
}

NTAPI NTSTATUS FdcPdoPnp(IN PDEVICE_OBJECT DeviceObject,
			 IN PIRP Irp)
{
    ULONG_PTR Information = 0;

    DPRINT("FdcPdoPnp()\n");

    NTSTATUS Status = Irp->IoStatus.Status;

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpSp->MinorFunction) {
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
	DPRINT1("Unimplemented IRP_MN_DEVICE_USAGE_NOTIFICATION received\n");
	break;

    case IRP_MN_EJECT:
	DPRINT1("Unimplemented IRP_MN_EJECT received\n");
	break;

    case IRP_MN_QUERY_BUS_INFORMATION:
	DPRINT("IRP_MN_QUERY_BUS_INFORMATION received\n");
	break;

    case IRP_MN_QUERY_CAPABILITIES:
	DPRINT("IRP_MN_QUERY_CAPABILITIES received\n");
	Status = FdcPdoQueryCapabilities(DeviceObject, IrpSp);
	break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
	DPRINT("IRP_MN_QUERY_DEVICE_RELATIONS received\n");
	break;

    case IRP_MN_QUERY_DEVICE_TEXT:
	DPRINT("IRP_MN_QUERY_DEVICE_TEXT received\n");
	break;

    case IRP_MN_QUERY_ID:
	DPRINT("IRP_MN_QUERY_ID received\n");
	Status = FdcPdoQueryId(DeviceObject, IrpSp, &Information);
	break;

    case IRP_MN_QUERY_PNP_DEVICE_STATE:
	DPRINT1("Unimplemented IRP_MN_QUERY_ID received\n");
	break;

    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	DPRINT("IRP_MN_QUERY_RESOURCE_REQUIREMENTS received\n");
	break;

    case IRP_MN_QUERY_RESOURCES:
	DPRINT("IRP_MN_QUERY_RESOURCES received\n");
	break;

    case IRP_MN_SET_LOCK:
	DPRINT1("Unimplemented IRP_MN_SET_LOCK received\n");
	break;

    case IRP_MN_START_DEVICE:
	DPRINT("IRP_MN_START_DEVICE received\n");
	break;

    case IRP_MN_QUERY_STOP_DEVICE:
    case IRP_MN_CANCEL_STOP_DEVICE:
    case IRP_MN_STOP_DEVICE:
    case IRP_MN_QUERY_REMOVE_DEVICE:
    case IRP_MN_CANCEL_REMOVE_DEVICE:
    case IRP_MN_SURPRISE_REMOVAL:
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_REMOVE_DEVICE:
	DPRINT("IRP_MN_REMOVE_DEVICE received\n");
	break;

    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	DPRINT("IRP_MN_FILTER_RESOURCE_REQUIREMENTS received\n");
	/* Nothing to do */
	Irp->IoStatus.Status = Status;
	break;

    default:
	DPRINT1("Unknown IOCTL 0x%x\n", IrpSp->MinorFunction);
	break;
    }

    Irp->IoStatus.Information = Information;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DPRINT("Leaving FdcPdoPnp. Status 0x%X\n", Status);

    return Status;
}
