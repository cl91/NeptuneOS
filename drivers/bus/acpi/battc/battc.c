/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            drivers/battery/battc/battc.c
 * PURPOSE:         Battery Class Driver
 * PROGRAMMERS:     Cameron Gutman (cameron.gutman@reactos.org)
 */

#include "battc.h"

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    DPRINT("Battery class driver initialized\n");

    return STATUS_SUCCESS;
}

NTAPI NTSTATUS BatteryClassUnload(PVOID ClassData)
{
    PBATTERY_CLASS_DATA BattClass;

    DPRINT("Battery %p is being unloaded\n", ClassData);

    BattClass = ClassData;
    if (BattClass->InterfaceName.Length != 0) {
	IoSetDeviceInterfaceState(&BattClass->InterfaceName, FALSE);
	RtlFreeUnicodeString(&BattClass->InterfaceName);
    }

    ExFreePoolWithTag(BattClass, BATTERY_CLASS_DATA_TAG);

    return STATUS_SUCCESS;
}

NTAPI NTSTATUS BatteryClassSystemControl(IN PVOID ClassData,
					 IN PVOID WmiLibContext,
					 IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp,
					 IN PVOID Disposition)
{
    UNIMPLEMENTED;

    return STATUS_WMI_GUID_NOT_FOUND;
}

NTAPI NTSTATUS BatteryClassQueryWmiDataBlock(IN PVOID ClassData,
					     IN PDEVICE_OBJECT DeviceObject,
					     IN PIRP Irp,
					     IN ULONG GuidIndex,
					     OUT PULONG InstanceLengthArray,
					     IN ULONG OutBufferSize,
					     OUT PUCHAR Buffer)
{
    UNIMPLEMENTED;

    return STATUS_WMI_GUID_NOT_FOUND;
}

NTAPI NTSTATUS BatteryClassStatusNotify(IN PVOID ClassData)
{
    PBATTERY_CLASS_DATA BattClass;
    PBATTERY_WAIT_STATUS BattWait;
    BATTERY_STATUS BattStatus;
    NTSTATUS Status;

    DPRINT("Received battery status notification from %p\n", ClassData);

    BattClass = ClassData;
    BattWait = BattClass->EventTriggerContext;

    switch (BattClass->EventTrigger) {
    case EVENT_BATTERY_TAG:
	DPRINT1("Waiting for battery is UNIMPLEMENTED!\n");
	break;

    case EVENT_BATTERY_STATUS:
	Status = BattClass->MiniportInfo.QueryStatus(BattClass->MiniportInfo.Context,
						     BattWait->BatteryTag, &BattStatus);
	if (!NT_SUCCESS(Status))
	    return Status;

	if (!(BattWait->PowerState & BattStatus.PowerState) ||
	    (BattWait->HighCapacity > BattStatus.Capacity) ||
	    (BattWait->LowCapacity < BattStatus.Capacity)) {
	    /* TODO: Schedule a work item to process the battery class IOCTL */
	    assert(FALSE);
	}

	break;

    default:
	ASSERT(FALSE);
	break;
    }

    return STATUS_SUCCESS;
}

NTAPI NTSTATUS BatteryClassInitializeDevice(IN PBATTERY_MINIPORT_INFO MiniportInfo,
					    IN PVOID *ClassData)
{
    PBATTERY_CLASS_DATA BattClass = ExAllocatePoolWithTag(NonPagedPool,
							  sizeof(BATTERY_CLASS_DATA),
							  BATTERY_CLASS_DATA_TAG);
    if (BattClass == NULL)
	return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(BattClass, sizeof(BATTERY_CLASS_DATA));

    RtlCopyMemory(&BattClass->MiniportInfo, MiniportInfo,
		  sizeof(BattClass->MiniportInfo));

    NTSTATUS Status = STATUS_SUCCESS;
    if (MiniportInfo->Pdo != NULL) {
	Status = IoRegisterDeviceInterface(MiniportInfo->Pdo, &GUID_DEVICE_BATTERY, NULL,
					   &BattClass->InterfaceName);
	if (NT_SUCCESS(Status)) {
	    DPRINT("Initialized battery interface: %wZ\n", &BattClass->InterfaceName);
	    Status = IoSetDeviceInterfaceState(&BattClass->InterfaceName, TRUE);
	    if (Status == STATUS_OBJECT_NAME_EXISTS) {
		DPRINT1("Got STATUS_OBJECT_NAME_EXISTS for SetDeviceInterfaceState\n");
		Status = STATUS_SUCCESS;
	    }
	} else {
	    DPRINT1("IoRegisterDeviceInterface failed (0x%x)\n", Status);
	}
    }

    *ClassData = BattClass;

    return Status;
}

NTAPI NTSTATUS BatteryClassIoctl(IN PVOID ClassData, IN PIRP Irp)
{
    PBATTERY_CLASS_DATA BattClass;
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    ULONG WaitTime;
    PBATTERY_WAIT_STATUS BattWait;
    PBATTERY_QUERY_INFORMATION BattQueryInfo;
    PBATTERY_SET_INFORMATION BattSetInfo;
    LARGE_INTEGER Timeout;
    PBATTERY_STATUS BattStatus;
    BATTERY_NOTIFY BattNotify;
    ULONG ReturnedLength;

    DPRINT("BatteryClassIoctl(%p %p)\n", ClassData, Irp);

    BattClass = ClassData;

    IrpSp = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    DPRINT("Received IOCTL %x for %p\n", IrpSp->Parameters.DeviceIoControl.IoControlCode,
	   ClassData);

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_BATTERY_QUERY_TAG:
	if ((IrpSp->Parameters.DeviceIoControl.InputBufferLength != sizeof(ULONG) &&
	     IrpSp->Parameters.DeviceIoControl.InputBufferLength != 0) ||
	    IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	WaitTime = IrpSp->Parameters.DeviceIoControl.InputBufferLength == sizeof(ULONG) ?
	    *(PULONG)Irp->SystemBuffer : 0;

	Timeout.QuadPart = Int32x32To64(WaitTime, -1000);

	Status = BattClass->MiniportInfo.QueryTag(BattClass->MiniportInfo.Context,
						  (PULONG)Irp->SystemBuffer);
	if (!NT_SUCCESS(Status)) {
	    BattClass->EventTrigger = EVENT_BATTERY_TAG;
	    /* TODO: Queue the IRP in a driver-defined queue, and move the rest into
	     * the work item that gets scheduled when event is triggered. */
	    assert(FALSE);

	    if (Status == STATUS_SUCCESS) {
		Status = BattClass->MiniportInfo.QueryTag(BattClass->MiniportInfo.Context,
							  (PULONG)Irp->SystemBuffer);
		if (NT_SUCCESS(Status))
		    Irp->IoStatus.Information = sizeof(ULONG);
	    } else {
		Status = STATUS_NO_SUCH_DEVICE;
	    }
	} else {
	    Irp->IoStatus.Information = sizeof(ULONG);
	}
	break;

    case IOCTL_BATTERY_QUERY_STATUS:
	if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(*BattWait) ||
	    IrpSp->Parameters.DeviceIoControl.OutputBufferLength <
		sizeof(BATTERY_STATUS)) {
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	BattWait = Irp->SystemBuffer;

	Timeout.QuadPart = Int32x32To64(BattWait->Timeout, -1000);

	Status = BattClass->MiniportInfo.QueryStatus(BattClass->MiniportInfo.Context,
						     BattWait->BatteryTag,
						     (PBATTERY_STATUS)Irp->SystemBuffer);

	BattStatus = Irp->SystemBuffer;

	if (!NT_SUCCESS(Status) || ((BattWait->PowerState & BattStatus->PowerState) &&
				    (BattWait->HighCapacity <= BattStatus->Capacity) &&
				    (BattWait->LowCapacity >= BattStatus->Capacity))) {
	    BattNotify.PowerState = BattWait->PowerState;
	    BattNotify.HighCapacity = BattWait->HighCapacity;
	    BattNotify.LowCapacity = BattWait->LowCapacity;

	    BattClass->MiniportInfo.SetStatusNotify(BattClass->MiniportInfo.Context,
						    BattWait->BatteryTag, &BattNotify);

	    BattClass->EventTrigger = EVENT_BATTERY_STATUS;
	    BattClass->EventTriggerContext = BattWait;

	    /* TODO: Queue the IRP in a driver-defined queue, and move the rest into
	     * the work item that gets scheduled when event is triggered. */
	    assert(FALSE);

	    BattClass->MiniportInfo.DisableStatusNotify(BattClass->MiniportInfo.Context);

	    if (Status == STATUS_SUCCESS) {
		Status = BattClass->MiniportInfo.QueryStatus(BattClass->MiniportInfo.Context,
							     BattWait->BatteryTag,
							     (PBATTERY_STATUS)Irp->SystemBuffer);
		if (NT_SUCCESS(Status))
		    Irp->IoStatus.Information = sizeof(ULONG);
	    } else {
		Status = STATUS_NO_SUCH_DEVICE;
	    }
	} else {
	    Irp->IoStatus.Information = sizeof(BATTERY_STATUS);
	}
	break;

    case IOCTL_BATTERY_QUERY_INFORMATION:
	if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(*BattQueryInfo)) {
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	BattQueryInfo = Irp->SystemBuffer;
	ULONG OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	Status = BattClass->MiniportInfo.QueryInformation(BattClass->MiniportInfo.Context,
							  BattQueryInfo->BatteryTag,
							  BattQueryInfo->InformationLevel,
							  BattQueryInfo->AtRate,
							  Irp->SystemBuffer,
							  OutputBufferLength,
							  &ReturnedLength);
	Irp->IoStatus.Information = ReturnedLength;
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("QueryInformation failed (0x%x)\n", Status);
	}
	break;

    case IOCTL_BATTERY_SET_INFORMATION:
	if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(*BattSetInfo)) {
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	BattSetInfo = Irp->SystemBuffer;

	Status = BattClass->MiniportInfo.SetInformation(BattClass->MiniportInfo.Context,
							BattSetInfo->BatteryTag,
							BattSetInfo->InformationLevel,
							BattSetInfo->Buffer);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("SetInformation failed (0x%x)\n", Status);
	}
	break;

    default:
	DPRINT1("Received unsupported IRP %x\n",
		IrpSp->Parameters.DeviceIoControl.IoControlCode);
	/* Do NOT complete the irp */
	return STATUS_NOT_SUPPORTED;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
