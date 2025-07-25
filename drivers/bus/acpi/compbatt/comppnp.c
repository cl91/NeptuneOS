/*
 * PROJECT:         ReactOS Composite Battery Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            boot/drivers/bus/acpi/compbatt/comppnp.c
 * PURPOSE:         Plug-and-Play IOCTL/IRP Handling
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "compbatt.h"

#include <wdmguid.h>

/* FUNCTIONS ******************************************************************/

NTAPI NTSTATUS CompBattPowerDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PCOMPBATT_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: PowerDispatch received power IRP.\n");
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(DeviceExtension->AttachedDevice, Irp);
}

static PCOMPBATT_BATTERY_DATA
RemoveBatteryFromList(IN PCUNICODE_STRING BatteryName,
		      IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension)
{
    PLIST_ENTRY ListHead, NextEntry;
    PCOMPBATT_BATTERY_DATA BatteryData;
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: ENTERING RemoveBatteryFromList\n");

    /* Loop the battery list */
    ListHead = &DeviceExtension->BatteryList;
    NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	/* Get the battery information and compare the name */
	BatteryData = CONTAINING_RECORD(NextEntry, COMPBATT_BATTERY_DATA, BatteryLink);
	if (!RtlCompareUnicodeString(BatteryName, &BatteryData->BatteryName, TRUE)) {
	    /* Remove the entry from the list */
	    RemoveEntryList(&BatteryData->BatteryLink);
	    return BatteryData;
	}

	/* Next */
	NextEntry = NextEntry->Flink;
    }

    /* Done */
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: EXITING RemoveBatteryFromList\n");
    return NULL;
}

static BOOLEAN IsBatteryAlreadyOnList(IN PCUNICODE_STRING BatteryName,
				      IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension)
{
    PLIST_ENTRY ListHead, NextEntry;
    PCOMPBATT_BATTERY_DATA BatteryData;
    BOOLEAN Found = FALSE;
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: ENTERING IsBatteryAlreadyOnList\n");

    /* Loop the battery list */
    ListHead = &DeviceExtension->BatteryList;
    NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	/* Get the battery information and compare the name */
	BatteryData = CONTAINING_RECORD(NextEntry, COMPBATT_BATTERY_DATA, BatteryLink);
	if (!RtlCompareUnicodeString(BatteryName, &BatteryData->BatteryName, TRUE)) {
	    /* Got it */
	    Found = TRUE;
	    break;
	}

	/* Next */
	NextEntry = NextEntry->Flink;
    }

    /* Return search status */
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: EXITING IsBatteryAlreadyOnList\n");
    return Found;
}

static NTSTATUS CompBattAddNewBattery(IN PUNICODE_STRING BatteryName,
				      IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCOMPBATT_BATTERY_DATA BatteryData;
    PIRP Irp;
    PIO_STACK_LOCATION IoStackLocation;

    if (CompBattDebug & 1)
	DbgPrint("CompBatt: ENTERING AddNewBattery \"%wZ\" \n", &BatteryName);

    /* Is this a new battery? */
    if (!IsBatteryAlreadyOnList(BatteryName, DeviceExtension)) {
	/* Allocate battery data */
	BatteryData = ExAllocatePoolWithTag(sizeof(COMPBATT_BATTERY_DATA) + BatteryName->Length,
					    'CtaB');
	if (BatteryData) {
	    /* Initialize the data and write the battery name */
	    RtlZeroMemory(BatteryData, sizeof(COMPBATT_BATTERY_DATA));
	    BatteryData->Tag = 0;
	    BatteryData->BatteryName.MaximumLength = BatteryName->Length;
	    BatteryData->BatteryName.Buffer = (PWCHAR)(BatteryData + 1);
	    RtlCopyUnicodeString(&BatteryData->BatteryName, BatteryName);

	    /* Get the device object */
	    PFILE_OBJECT FileObject;
	    Status = IoGetDeviceObjectPointer(BatteryName, FILE_ALL_ACCESS,
					      &FileObject,
					      &BatteryData->DeviceObject);
	    if (NT_SUCCESS(Status)) {
		/* Drop the FO since IoGetDeviceObjectPointer referenced it. */
		ObDereferenceObject(FileObject);

		/* Allocate the battery IRP */
		Irp = IoAllocateIrp(BatteryData->DeviceObject->StackSize + 1);
		if (Irp) {
		    /* Save it */
		    BatteryData->Irp = Irp;

		    /* Setup the stack location */
		    IoStackLocation = IoGetNextIrpStackLocation(Irp);
		    IoStackLocation->Parameters.Others.Argument1 = DeviceExtension;
		    IoStackLocation->Parameters.Others.Argument2 = BatteryData;

		    /* Set IRP data */
		    Irp->IoStatus.Status = STATUS_DEVICE_NOT_CONNECTED;
		    BatteryData->WaitFlag = 0;

		    /* Insert this battery in the list */
		    InsertTailList(&DeviceExtension->BatteryList,
				   &BatteryData->BatteryLink);
		    Status = STATUS_SUCCESS;
		} else {
		    /* Fail, no memory */
		    if (CompBattDebug & 8)
			DbgPrint("CompBatt: Couldn't allocate new battery Irp\n");
		    Status = STATUS_INSUFFICIENT_RESOURCES;
		    ObDereferenceObject(BatteryData->DeviceObject);
		}
	    } else if (CompBattDebug & 8) {
		/* Fail */
		DbgPrint("CompBattAddNewBattery: Failed to get device Object. status = "
			 "%x\n",
			 Status);
	    }

	    /* Free the battery data */
	    ExFreePool(BatteryData);
	} else {
	    /* Fail, no memory */
	    if (CompBattDebug & 8)
		DbgPrint("CompBatt: Couldn't allocate new battery node\n");
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	}
    }

    /* We're done */
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: EXITING AddNewBattery\n");
    return Status;
}

static NTSTATUS CompBattRemoveBattery(IN PCUNICODE_STRING BatteryName,
				      IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension)
{
    PCOMPBATT_BATTERY_DATA BatteryData;
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: RemoveBattery\n");

    /* Remove the entry */
    BatteryData = RemoveBatteryFromList(BatteryName, DeviceExtension);
    if (BatteryData) {
	/* Dereference and free it */
	ObDereferenceObject(BatteryData->DeviceObject);
	ExFreePool(BatteryData);

	/* Notify class driver */
	DeviceExtension->Flags = 0;
	BatteryClassStatusNotify(DeviceExtension->ClassData);
    }

    /* It's done */
    return STATUS_SUCCESS;
}

static NTSTATUS CompBattGetBatteries(IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension)
{
    PWCHAR p;
    NTSTATUS Status;
    PWCHAR LinkList;
    UNICODE_STRING LinkString;
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: ENTERING GetBatteries\n");

    /* Get all battery links */
    Status = IoGetDeviceInterfaces(&GUID_DEVICE_BATTERY, NULL, 0, &LinkList);
    p = LinkList;
    if (NT_SUCCESS(Status)) {
	/* Loop all strings inside */
	while (TRUE) {
	    /* Create the string */
	    RtlInitUnicodeString(&LinkString, p);
	    if (!LinkString.Length)
		break;

	    /* Add this battery and move on */
	    Status = CompBattAddNewBattery(&LinkString, DeviceExtension);
	    p += (LinkString.Length / sizeof(WCHAR)) + sizeof(UNICODE_NULL);
	}

	/* Parsing complete, clean up buffer */
	ExFreePool(LinkList);
    } else if (CompBattDebug & 8) {
	/* Fail */
	DbgPrint("CompBatt: Couldn't get list of batteries\n");
    }

    /* Done */
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: EXITING GetBatteries\n");
    return Status;
}

static NTAPI NTSTATUS
CompBattPnpEventHandler(IN PDEVICE_INTERFACE_CHANGE_NOTIFICATION Notification,
			IN PCOMPBATT_DEVICE_EXTENSION DeviceExtension)
{
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: ENTERING PnpEventHandler\n");
    if (CompBattDebug & 2)
	DbgPrint("CompBatt: Received device interface change notification\n");

    /* Check what happened */
    if (IsEqualGUIDAligned(&Notification->Event, &GUID_DEVICE_INTERFACE_ARRIVAL)) {
	/* Add the new battery */
	if (CompBattDebug & 2)
	    DbgPrint("CompBatt: Received notification of battery arrival\n");
	CompBattAddNewBattery(Notification->SymbolicLinkName, DeviceExtension);
    } else if (IsEqualGUIDAligned(&Notification->Event, &GUID_DEVICE_INTERFACE_REMOVAL)) {
	/* Don't do anything */
	if (CompBattDebug & 2)
	    DbgPrint("CompBatt: Received notification of battery removal\n");
    } else {
	/* Shouldn't happen */
	if (CompBattDebug & 2)
	    DbgPrint("CompBatt: Received unhandled PnP event\n");
    }

    /* Done, return success */
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: EXITING PnpEventHandler\n");
    return STATUS_SUCCESS;
}

NTAPI NTSTATUS CompBattAddDevice(IN PDRIVER_OBJECT DriverObject,
				 IN PDEVICE_OBJECT PdoDeviceObject)
{
    NTSTATUS Status;
    UNICODE_STRING DeviceName;
    PCOMPBATT_DEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING SymbolicLinkName;
    BATTERY_MINIPORT_INFO MiniportInfo;
    if (CompBattDebug & 2)
	DbgPrint("CompBatt: Got an AddDevice - %p\n", PdoDeviceObject);

    /* Create the device */
    RtlInitUnicodeString(&DeviceName, L"\\Device\\CompositeBattery");
    Status = IoCreateDevice(DriverObject, sizeof(COMPBATT_DEVICE_EXTENSION), &DeviceName,
			    FILE_DEVICE_BATTERY, FILE_DEVICE_SECURE_OPEN, FALSE,
			    &DeviceObject);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Setup symbolic link for Win32 access */
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\CompositeBattery");
    IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);

    /* Initialize the device extension */
    DeviceExtension = DeviceObject->DeviceExtension;
    RtlZeroMemory(DeviceExtension, sizeof(COMPBATT_DEVICE_EXTENSION));

    /* Attach to device stack and set DO pointers */
    DeviceExtension->AttachedDevice = IoAttachDeviceToDeviceStack(DeviceObject,
								  PdoDeviceObject);
    DeviceExtension->DeviceObject = DeviceObject;
    if (!DeviceExtension->AttachedDevice) {
	/* Fail */
	if (CompBattDebug & 8)
	    DbgPrint("CompBattAddDevice: Could not attach to LowerDevice.\n");
	IoDeleteDevice(DeviceObject);
	return STATUS_UNSUCCESSFUL;
    }

    /* Set device object flags */
    DeviceObject->Flags |= (DO_POWER_PAGABLE | DO_BUFFERED_IO);
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Setup the device extension */
    InitializeListHead(&DeviceExtension->BatteryList);
    DeviceExtension->Flags = 0;
    DeviceExtension->NextTag = 1;

    /* Setup the miniport data */
    RtlZeroMemory(&MiniportInfo, sizeof(MiniportInfo));
    MiniportInfo.MajorVersion = BATTERY_CLASS_MAJOR_VERSION;
    MiniportInfo.MinorVersion = BATTERY_CLASS_MINOR_VERSION;
    MiniportInfo.Context = DeviceExtension;
    MiniportInfo.DeviceName = &DeviceName;
    MiniportInfo.QueryTag = (BCLASS_QUERY_TAG)CompBattQueryTag;
    MiniportInfo.QueryInformation = (BCLASS_QUERY_INFORMATION)CompBattQueryInformation;
    MiniportInfo.SetInformation = NULL;
    MiniportInfo.QueryStatus = (BCLASS_QUERY_STATUS)CompBattQueryStatus;
    MiniportInfo.SetStatusNotify = (BCLASS_SET_STATUS_NOTIFY)CompBattSetStatusNotify;
    MiniportInfo.DisableStatusNotify = (BCLASS_DISABLE_STATUS_NOTIFY)
	CompBattDisableStatusNotify;
    MiniportInfo.Pdo = NULL;

    /* Register with the class driver */
    Status = BatteryClassInitializeDevice(&MiniportInfo, &DeviceExtension->ClassData);
    if (!NT_SUCCESS(Status)) {
	/* Undo everything */
	IoDetachDevice(DeviceExtension->AttachedDevice);
	IoDeleteDevice(DeviceObject);
    }

    /* Return status */
    return Status;
}

NTAPI NTSTATUS CompBattPnpDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    PCOMPBATT_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: ENTERING PnpDispatch\n");

    /* Set default error */
    Status = STATUS_NOT_SUPPORTED;

    /* Check what kind of PnP function this is */
    switch (IoStackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
	/* Device is starting, register for new batteries and pick up current ones */
	Status = IoRegisterPlugPlayNotification(
	    EventCategoryDeviceInterfaceChange, 0, (PVOID)&GUID_DEVICE_BATTERY,
	    DeviceObject->DriverObject,
	    (PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)CompBattPnpEventHandler,
	    DeviceExtension, &DeviceExtension->NotificationEntry);
	if (NT_SUCCESS(Status)) {
	    /* Now go get the batteries */
	    if (CompBattDebug & 2)
		DbgPrint("CompBatt: Successfully registered for PnP notification\n");
	    Status = CompBattGetBatteries(DeviceExtension);
	} else {
	    /* We failed */
	    if (CompBattDebug & 8)
		DbgPrint("CompBatt: Couldn't register for PnP notification - %x\n",
			 Status);
	}
	break;

    case IRP_MN_CANCEL_STOP_DEVICE:
	/* Explicitly say ok */
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
	/* Explicitly say ok */
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_SURPRISE_REMOVAL:
	/* Explicitly say ok */
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_QUERY_PNP_DEVICE_STATE:
	/* Add this in */
	Irp->IoStatus.Information |= PNP_DEVICE_NOT_DISABLEABLE;
	Status = STATUS_SUCCESS;
	break;

    default:
	/* Not supported */
	Status = STATUS_INVALID_DEVICE_REQUEST;
	break;
    }

    /* Set IRP status if we have one */
    if (Status != STATUS_NOT_SUPPORTED)
	Irp->IoStatus.Status = Status;

    /* Did someone pick it up? */
    if ((NT_SUCCESS(Status)) || (Status == STATUS_NOT_SUPPORTED)) {
	/* Still unsupported, try ACPI */
	IoSkipCurrentIrpStackLocation(Irp);
	Status = IoCallDriver(DeviceExtension->AttachedDevice, Irp);
    } else {
	/* Complete the request */
	Status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    /* Return status */
    if (CompBattDebug & 1)
	DbgPrint("CompBatt: EXITING PnpDispatch\n");
    return Status;
}
