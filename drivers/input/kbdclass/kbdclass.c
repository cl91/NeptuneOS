/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Keyboard class driver
 * FILE:            drivers/kbdclass/kbdclass.c
 * PURPOSE:         Keyboard class driver
 * PROGRAMMERS:     Hervé Poussineau (hpoussin@reactos.org)
 *
 * NOTES:
 *   The kbdclass driver sits above the keyboard port driver
 * (such as i8042prt) and implements the common interface for
 * keyboard devices. The userspace can then request keyboard
 * data via the \Device\KeyboardClass0 (etc.) device objects.
 *
 * There are multiple device objects that are involved here.
 * Below is a schematic diagram of the case where parameter
 * ConnectMultiplePorts is set to one. In this case the kbdclass
 * driver exposes a single device object \Device\KeyboardClass0
 * that controls multiple port drivers.
 *
 * |---------------------------------|
 * |            kbdclass             |
 * |---------------------------------|
 *        ClassDO      ---->   FDO        -----      FDO       -----  etc..
 * \Device\KeyboardClass0   [unnamed]             [unnamed]
 *                              ^                     ^
 *                              |                     |
 *                        |------------|         |--------|
 *                        |  i8042prt  |         | inport |
 *                        |------------|         |--------|
 *                             FDO
 *                   [unnamed, has symbolic link]
 *                              ^
 *                              |
 *                        |------------|          |-----------|
 *                        |  i8042prt  |          |  acpi.sys |
 *                        |------------|          |-----------|
 *                             PDO   ============  Enumerated by
 *                          [unnamed]              the ACPI bus
 *
 * The ClassDO aggregates the keyboard input of port devices that
 * it has connected to. This is done by generating read IRPs for
 * each port device and forward them to the port drivers. When the
 * read IRPs are completed their IO completion routines copy the
 * port data into the aggregated class data buffer. On Windows the
 * class driver implements a ClassCallback which the port driver
 * will then call in their interrupt service routines. On Neptune OS,
 * class and filter drivers are loaded in two places: once as a
 * standalone driver in their own address space, and for each port
 * driver above which the class/filter drivers are attached, the
 * required class/filter driver is loaded inside the port driver's
 * address space. The latter is done so that passing an IRP from
 * upper drivers to lower drivers does not require context switches.
 * In order to unify the IRP handling in both cases, we remove the
 * ClassCallback mechanism and simply have the class driver generate
 * read IRPs and then forward them to the port driver.
 *
 * In the case where ConnectMultiplePorts is set to zero, there
 * will be one ClassDO for each port FDO. Instead of generating
 * read IRPs we will simply forward the read IRPs to the port FDO.
 * This applies also to the case where ConnectMultiplePorts is one
 * but there is only one port device connected to it. If you are
 * certain that the system will only have one keyboard device,
 * setting ConnectMultiplePorts to zero can improve performace, as
 * in this case IRP passing does not require context switches.
 */

#include "kbdclass.h"

#include <stdio.h>
#include <kbdmou.h>
#include <debug.h>

static DRIVER_UNLOAD DriverUnload;
static DRIVER_DISPATCH ClassCreate;
static DRIVER_DISPATCH ClassClose;
static DRIVER_DISPATCH ClassCleanup;
static DRIVER_DISPATCH ClassRead;
static DRIVER_DISPATCH ClassDeviceControl;
static DRIVER_DISPATCH ClassPower;
static DRIVER_ADD_DEVICE ClassAddDevice;

static NTAPI VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
    // nothing to do here yet
}

static NTAPI NTSTATUS ForwardIrpAndForget(IN PDEVICE_OBJECT DeviceObject,
					  IN PIRP Irp)
{
    ASSERT(!((PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->IsClassDO);
    PDEVICE_OBJECT LowerDevice =
	((PPORT_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowerDevice;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(LowerDevice, Irp);
}

static NTAPI NTSTATUS ClassCreate(IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp)
{
    TRACE_(CLASS_NAME, "IRP_MJ_CREATE\n");

    if (!((PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->IsClassDO)
	return ForwardIrpAndForget(DeviceObject, Irp);

    /* FIXME: open all associated Port devices */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS ClassClose(IN PDEVICE_OBJECT DeviceObject,
				 IN PIRP Irp)
{
    TRACE_(CLASS_NAME, "IRP_MJ_CLOSE\n");

    if (!((PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->IsClassDO)
	return ForwardIrpAndForget(DeviceObject, Irp);

    /* FIXME: close all associated Port devices */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS ClassCleanup(IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp)
{
    TRACE_(CLASS_NAME, "IRP_MJ_CLEANUP\n");

    if (!((PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->IsClassDO)
	return ForwardIrpAndForget(DeviceObject, Irp);

    /* FIXME: cleanup all associated Port devices */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static inline ULONG GetListSize(IN PLIST_ENTRY ListHead)
{
    ULONG Size = 0;
    for (PLIST_ENTRY Entry = ListHead->Flink; Entry != ListHead; Entry = Entry->Flink) {
	Size++;
    }
    return Size;
}

static NTAPI NTSTATUS ClassRead(IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp)
{
    PCLASS_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    TRACE_(CLASS_NAME, "IRP_MJ_READ\n");

    ASSERT(DeviceExtension->Common.IsClassDO);

    if (!((PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->IsClassDO)
	return ForwardIrpAndForget(DeviceObject, Irp);

    /* If there is no port device connected, simply return failure. */
    if (!GetListSize(&DeviceExtension->PortDeviceList)) {
	Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_NO_SUCH_DEVICE;
    }

    /* If there is only one port device connected to this class device object,
     * simply forward the read IRP to the port device. */
    if (GetListSize(&DeviceExtension->PortDeviceList) == 1) {
	PLIST_ENTRY Head = &DeviceExtension->PortDeviceList;
	PPORT_DEVICE_EXTENSION PortDevExt = CONTAINING_RECORD(Head->Flink,
							      PORT_DEVICE_EXTENSION,
							      PortDeviceListEntry);
	return ForwardIrpAndForget(PortDevExt->DeviceObject, Irp);
    }

    if (IoGetCurrentIrpStackLocation(Irp)->Parameters.Read.Length < sizeof(KEYBOARD_INPUT_DATA)) {
	Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_BUFFER_TOO_SMALL;
    }

    /* If there are multiple port devices connected to this class device object
     * we need to generate read IRPs for each port device and aggregate their input. */
    UNIMPLEMENTED;
    assert(FALSE);
    return STATUS_NOT_IMPLEMENTED;
}

static NTAPI NTSTATUS ClassDeviceControl(IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp)
{
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    TRACE_(CLASS_NAME, "IRP_MJ_DEVICE_CONTROL\n");

    if (!((PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->IsClassDO)
	return ForwardIrpAndForget(DeviceObject, Irp);

    switch (IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_KEYBOARD_QUERY_ATTRIBUTES:
    case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
    case IOCTL_KEYBOARD_QUERY_INDICATORS:
    case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
    {
	/* FIXME: We hope that all devices will return the same result.
	 * Ask only the first one */
	PLIST_ENTRY Head = &((PCLASS_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->PortDeviceList;
	if (Head->Flink != Head) {
	    /* We have at least one device */
	    PPORT_DEVICE_EXTENSION DevExt = CONTAINING_RECORD(Head->Flink,
							      PORT_DEVICE_EXTENSION,
							      PortDeviceListEntry);
	    IoGetCurrentIrpStackLocation(Irp)->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	    IoSkipCurrentIrpStackLocation(Irp);
	    return IoCallDriver(DevExt->DeviceObject, Irp);
	}
	break;
    }
    case IOCTL_KEYBOARD_SET_INDICATORS:
    case IOCTL_KEYBOARD_SET_TYPEMATIC:	/* not in MSDN, would seem logical */
    {
	/* Send it to all associated Port devices */
	PLIST_ENTRY Head = &((PCLASS_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->PortDeviceList;
	PLIST_ENTRY Entry = Head->Flink;
	Status = STATUS_SUCCESS;
	while (Entry != Head) {
	    PPORT_DEVICE_EXTENSION DevExt = CONTAINING_RECORD(Entry, PORT_DEVICE_EXTENSION,
							      PortDeviceListEntry);

	    IoGetCurrentIrpStackLocation(Irp)->MajorFunction = IRP_MJ_INTERNAL_DEVICE_CONTROL;
	    if (IoForwardIrpSynchronously(DevExt->LowerDevice, Irp)) {
		if (!NT_SUCCESS(Irp->IoStatus.Status)) {
		    Status = Irp->IoStatus.Status;
		}
	    } else {
		Status = STATUS_UNSUCCESSFUL;
	    }
	    Entry = Entry->Flink;
	}
	break;
    }
    default:
	WARN_(CLASS_NAME,
	      "IRP_MJ_DEVICE_CONTROL / unknown I/O control code 0x%x\n",
	      IoGetCurrentIrpStackLocation(Irp)->Parameters.
	      DeviceIoControl.IoControlCode);
	ASSERT(FALSE);
	break;
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

static NTAPI NTSTATUS ClassPower(IN PDEVICE_OBJECT DeviceObject,
				 IN PIRP Irp)
{
    NTSTATUS Status;
    PPORT_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    if (!DeviceExtension->Common.IsClassDO) {
	/* Forward port DO IRPs to lower device */
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(DeviceExtension->LowerDevice, Irp);
    }

    switch (IoGetCurrentIrpStackLocation(Irp)->MinorFunction) {
    case IRP_MN_SET_POWER:
    case IRP_MN_QUERY_POWER:
	Irp->IoStatus.Status = STATUS_SUCCESS;
	break;
    }
    Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS ReadRegistryEntries(IN PUNICODE_STRING RegistryPath,
				    IN PCLASS_DRIVER_EXTENSION DriverExtension)
{
    UNICODE_STRING ParametersRegistryKey;
    RTL_QUERY_REGISTRY_TABLE Parameters[4];
    NTSTATUS Status;

    /* HACK: We don't support multiple devices with this disabled */
    ULONG DefaultConnectMultiplePorts = 1;
    ULONG DefaultDataQueueSize = 0x64;
    PCWSTR DefaultDeviceBaseName = L"KeyboardClass";

    ParametersRegistryKey.Length = 0;
    ParametersRegistryKey.MaximumLength = RegistryPath->Length
	+ sizeof(L"\\Parameters") + sizeof(UNICODE_NULL);
    ParametersRegistryKey.Buffer = ExAllocatePoolWithTag(NonPagedPool,
							 ParametersRegistryKey.MaximumLength,
							 CLASS_TAG);
    if (!ParametersRegistryKey.Buffer) {
	WARN_(CLASS_NAME, "ExAllocatePoolWithTag() failed\n");
	return STATUS_NO_MEMORY;
    }
    RtlCopyUnicodeString(&ParametersRegistryKey, RegistryPath);
    RtlAppendUnicodeToString(&ParametersRegistryKey, L"\\Parameters");
    ParametersRegistryKey.Buffer[ParametersRegistryKey.Length / sizeof(WCHAR)] = UNICODE_NULL;

    RtlZeroMemory(Parameters, sizeof(Parameters));

    Parameters[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_REGISTRY_OPTIONAL;
    Parameters[0].Name = L"ConnectMultiplePorts";
    Parameters[0].EntryContext = &DriverExtension->ConnectMultiplePorts;
    Parameters[0].DefaultType = REG_DWORD;
    Parameters[0].DefaultData = &DefaultConnectMultiplePorts;
    Parameters[0].DefaultLength = sizeof(ULONG);

    Parameters[1].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_REGISTRY_OPTIONAL;
    Parameters[1].Name = L"KeyboardDataQueueSize";
    Parameters[1].EntryContext = &DriverExtension->DataQueueSize;
    Parameters[1].DefaultType = REG_DWORD;
    Parameters[1].DefaultData = &DefaultDataQueueSize;
    Parameters[1].DefaultLength = sizeof(ULONG);

    Parameters[2].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_REGISTRY_OPTIONAL;
    Parameters[2].Name = L"KeyboardDeviceBaseName";
    Parameters[2].EntryContext = &DriverExtension->DeviceBaseName;
    Parameters[2].DefaultType = REG_SZ;
    Parameters[2].DefaultData = (PVOID) DefaultDeviceBaseName;
    Parameters[2].DefaultLength = 0;

    Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
				    ParametersRegistryKey.Buffer,
				    Parameters, NULL, NULL);

    if (NT_SUCCESS(Status)) {
	/* Check values */
	if (DriverExtension->ConnectMultiplePorts != 0
	    && DriverExtension->ConnectMultiplePorts != 1) {
	    DriverExtension->ConnectMultiplePorts = DefaultConnectMultiplePorts;
	}
	if (DriverExtension->DataQueueSize == 0) {
	    DriverExtension->DataQueueSize = DefaultDataQueueSize;
	}
    } else if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
	/* Registry path doesn't exist. Set defaults */
	DriverExtension->ConnectMultiplePorts = DefaultConnectMultiplePorts;
	DriverExtension->DataQueueSize = DefaultDataQueueSize;
	if (RtlCreateUnicodeString(&DriverExtension->DeviceBaseName, DefaultDeviceBaseName))
	    Status = STATUS_SUCCESS;
	else
	    Status = STATUS_NO_MEMORY;
    }

    ExFreePoolWithTag(ParametersRegistryKey.Buffer, CLASS_TAG);
    return Status;
}

static NTSTATUS CreateClassDeviceObject(IN PDRIVER_OBJECT DriverObject,
					IN OPTIONAL PDEVICE_OBJECT Fdo,
					OUT PDEVICE_OBJECT *ClassDO OPTIONAL)
{
    PCLASS_DRIVER_EXTENSION DriverExtension;
    ULONG DeviceId = 0;
    ULONG PrefixLength;
    UNICODE_STRING DeviceNameU;
    PWSTR DeviceIdW = NULL;	/* Pointer into DeviceNameU.Buffer */
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS Status;

    TRACE_(CLASS_NAME, "CreateClassDeviceObject(%p)\n", DriverObject);

    /* Create new device object */
    DriverExtension = IoGetDriverObjectExtension(DriverObject, DriverObject);
    DeviceNameU.Length = 0;
    DeviceNameU.MaximumLength = (USHORT) wcslen(L"\\Device\\") * sizeof(WCHAR) /* "\Device\" */
	+ DriverExtension->DeviceBaseName.Length /* "KeyboardClass" */
	+ 4 * sizeof(WCHAR)	/* Id between 0 and 9999 */
	+ sizeof(UNICODE_NULL);	/* Final NULL char */
    DeviceNameU.Buffer = ExAllocatePoolWithTag(NonPagedPool,
					       DeviceNameU.MaximumLength, CLASS_TAG);
    if (!DeviceNameU.Buffer) {
	WARN_(CLASS_NAME, "ExAllocatePoolWithTag() failed\n");
	return STATUS_NO_MEMORY;
    }
    Status = RtlAppendUnicodeToString(&DeviceNameU, L"\\Device\\");
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME, "RtlAppendUnicodeToString() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }
    Status = RtlAppendUnicodeStringToString(&DeviceNameU,
					    &DriverExtension->DeviceBaseName);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME,
	      "RtlAppendUnicodeStringToString() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }
    PrefixLength = DeviceNameU.MaximumLength - 4 * sizeof(WCHAR) - sizeof(UNICODE_NULL);
    DeviceIdW = &DeviceNameU.Buffer[PrefixLength / sizeof(WCHAR)];
    while (DeviceId < 9999) {
	DeviceNameU.Length = (USHORT)(PrefixLength +
				      swprintf(DeviceIdW, L"%lu", DeviceId) * sizeof(WCHAR));
	ULONG64 Flags = FILE_DEVICE_SECURE_OPEN | DO_POWER_PAGABLE;
	if (Fdo) {
	    if (Fdo->Flags & DO_BUFFERED_IO) {
		Flags |= DO_BUFFERED_IO;
	    } else if (Fdo->Flags & DO_DIRECT_IO) {
		Flags |= DO_DIRECT_IO;
	    }
	} else {
	    Flags |= DO_BUFFERED_IO;
	}
	Status = IoCreateDevice(DriverObject, sizeof(CLASS_DEVICE_EXTENSION),
				&DeviceNameU, FILE_DEVICE_KEYBOARD, Flags,
				FALSE, &DeviceObject);
	if (NT_SUCCESS(Status))
	    goto cleanup;
	else if (Status != STATUS_OBJECT_NAME_COLLISION) {
	    WARN_(CLASS_NAME,
		  "IoCreateDevice() failed with status 0x%08x\n", Status);
	    goto cleanup;
	}
	DeviceId++;
    }
    WARN_(CLASS_NAME, "Too many devices starting with '\\Device\\%wZ'\n",
	  &DriverExtension->DeviceBaseName);
    Status = STATUS_TOO_MANY_NAMES;
cleanup:
    if (!NT_SUCCESS(Status)) {
	ExFreePoolWithTag(DeviceNameU.Buffer, CLASS_TAG);
	return Status;
    }

    PCLASS_DEVICE_EXTENSION DeviceExtension = (PCLASS_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    RtlZeroMemory(DeviceExtension, sizeof(CLASS_DEVICE_EXTENSION));
    DeviceExtension->Common.IsClassDO = TRUE;
    DeviceExtension->DriverExtension = DriverExtension;
    InitializeListHead(&DeviceExtension->PortDeviceList);
    DeviceExtension->InputCount = 0;
    DeviceExtension->PortData =
	ExAllocatePoolWithTag(NonPagedPool,
			      DeviceExtension->DriverExtension->DataQueueSize * sizeof(KEYBOARD_INPUT_DATA),
			      CLASS_TAG);
    if (!DeviceExtension->PortData) {
	ExFreePoolWithTag(DeviceNameU.Buffer, CLASS_TAG);
	return STATUS_NO_MEMORY;
    }
    DeviceExtension->DeviceName = DeviceNameU.Buffer;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Add entry entry to HKEY_LOCAL_MACHINE\Hardware\DeviceMap\[DeviceBaseName] */
    RtlWriteRegistryValue(RTL_REGISTRY_DEVICEMAP,
			  DriverExtension->DeviceBaseName.Buffer,
			  DeviceExtension->DeviceName,
			  REG_SZ,
			  DriverExtension->RegistryPath.Buffer,
			  DriverExtension->RegistryPath.MaximumLength);

    if (ClassDO)
	*ClassDO = DeviceObject;

    return STATUS_SUCCESS;
}

/* Send IOCTL_INTERNAL_*_CONNECT to port */
static NTSTATUS ConnectPortDriver(IN PDEVICE_OBJECT PortDO,
				  IN PDEVICE_OBJECT ClassDO)
{
    TRACE_(CLASS_NAME, "Connecting PortDO %p (drv %p) to ClassDO %p (drv %p)\n",
	   PortDO, PortDO->DriverObject, ClassDO, ClassDO->DriverObject);

    CONNECT_DATA ConnectData = {
	.Dummy = 0
    };

    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp = IoBuildDeviceIoControlRequest(IOCTL_INTERNAL_KEYBOARD_CONNECT, PortDO,
					     &ConnectData, sizeof(CONNECT_DATA),
					     NULL, 0, TRUE, &Event, &IoStatus);
    if (!Irp)
	return STATUS_INSUFFICIENT_RESOURCES;

    IoStatus.Status = IoCallDriver(PortDO, Irp);
    if (IoStatus.Status == STATUS_PENDING) {
	KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE, NULL);
    }
    assert(IoStatus.Status != STATUS_PENDING);

    if (NT_SUCCESS(IoStatus.Status)) {
	InsertTailList(&((PCLASS_DEVICE_EXTENSION)ClassDO->DeviceExtension)->PortDeviceList,
		       &((PPORT_DEVICE_EXTENSION)PortDO->DeviceExtension)->PortDeviceListEntry);
    }

    return IoStatus.Status;
}

/* Send IOCTL_INTERNAL_*_DISCONNECT to port + destroy the Port DO */
static VOID DestroyPortDriver(IN PDEVICE_OBJECT PortDO)
{
    TRACE_(CLASS_NAME, "Destroying PortDO %p\n", PortDO);

    PPORT_DEVICE_EXTENSION DeviceExtension = (PPORT_DEVICE_EXTENSION)PortDO->DeviceExtension;
    PCLASS_DEVICE_EXTENSION ClassDeviceExtension = DeviceExtension->ClassDO->DeviceExtension;
    PCLASS_DRIVER_EXTENSION DriverExtension = IoGetDriverObjectExtension(PortDO->DriverObject,
									 PortDO->DriverObject);

    /* Send IOCTL_INTERNAL_*_DISCONNECT */
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp = IoBuildDeviceIoControlRequest(IOCTL_INTERNAL_KEYBOARD_DISCONNECT,
					     PortDO, NULL, 0, NULL, 0, TRUE,
					     &Event, &IoStatus);
    if (Irp) {
	IoStatus.Status = IoCallDriver(PortDO, Irp);
	if (IoStatus.Status == STATUS_PENDING) {
	    KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE, NULL);
	}
	assert(IoStatus.Status != STATUS_PENDING);
    }

    /* Remove from ClassDeviceExtension->PortDeviceList list */
    RemoveEntryList(&DeviceExtension->PortDeviceListEntry);

    /* Remove entry from HKEY_LOCAL_MACHINE\Hardware\DeviceMap\[DeviceBaseName] */
    RtlDeleteRegistryValue(RTL_REGISTRY_DEVICEMAP,
			   DriverExtension->DeviceBaseName.Buffer,
			   ClassDeviceExtension->DeviceName);

    if (DeviceExtension->LowerDevice)
	IoDetachDevice(DeviceExtension->LowerDevice);

    if (!DriverExtension->ConnectMultiplePorts && DeviceExtension->ClassDO) {
	ExFreePoolWithTag(ClassDeviceExtension->PortData, CLASS_TAG);
	ExFreePoolWithTag((PVOID)ClassDeviceExtension->DeviceName, CLASS_TAG);
	IoDeleteDevice(DeviceExtension->ClassDO);
    }

    IoDeleteDevice(PortDO);
}

static NTAPI NTSTATUS ClassAddDevice(IN PDRIVER_OBJECT DriverObject,
				     IN PDEVICE_OBJECT Pdo)
{
    PCLASS_DRIVER_EXTENSION DriverExtension = IoGetDriverObjectExtension(DriverObject, DriverObject);
    PDEVICE_OBJECT Fdo = NULL;

    TRACE_(CLASS_NAME, "ClassAddDevice called. Pdo = %p\n", Pdo);

    /* We may get a NULL Pdo at the first call as we're a legacy driver. Ignore it */
    if (Pdo == NULL) {
	return STATUS_SUCCESS;
    }

    /* If we are running inside the function driver but ConnectMultiplePorts is
     * specified, do nothing. The singleton object will handle all the IO. */
    if (DriverExtension->ConnectMultiplePorts && !IoIsSingletonMode(DriverObject)) {
	return STATUS_SUCCESS;
    }

    /* If we are the singleton object, but are not connecting to multiple ports,
     * do nothing. The driver code running in the function driver process will
     * handle all the IO. */
    if (!DriverExtension->ConnectMultiplePorts && IoIsSingletonMode(DriverObject)) {
	return STATUS_SUCCESS;
    }

    /* Create new device object */
    ULONG64 Flags = 0;
    if (Pdo->Flags & FILE_DEVICE_SECURE_OPEN)
	Flags |= FILE_DEVICE_SECURE_OPEN;
    if (Pdo->Flags & DO_POWER_PAGABLE)
	Flags |= DO_POWER_PAGABLE;
    if (Pdo->Flags & DO_BUFFERED_IO)
	Flags |= DO_BUFFERED_IO;
    if (Pdo->Flags & DO_DIRECT_IO)
	Flags |= DO_DIRECT_IO;
    NTSTATUS Status = IoCreateDevice(DriverObject, sizeof(PORT_DEVICE_EXTENSION),
				     NULL, Pdo->DeviceType, Flags, FALSE, &Fdo);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME, "IoCreateDevice() failed with status 0x%08x\n", Status);
	goto cleanup;
    }
    IoSetStartIoAttributes(Fdo, TRUE, TRUE);

    PPORT_DEVICE_EXTENSION DeviceExtension = (PPORT_DEVICE_EXTENSION)Fdo->DeviceExtension;
    RtlZeroMemory(DeviceExtension, sizeof(PORT_DEVICE_EXTENSION));
    DeviceExtension->Common.IsClassDO = FALSE;
    DeviceExtension->DeviceObject = Fdo;
    DeviceExtension->PnpState = dsStopped;
    Status = IoAttachDeviceToDeviceStackSafe(Fdo, Pdo, &DeviceExtension->LowerDevice);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME,
	      "IoAttachDeviceToDeviceStackSafe() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }

    if (DriverExtension->ConnectMultiplePorts) {
	assert(IoIsSingletonMode(DriverObject));
	assert(DriverExtension->MainClassDeviceObject);
	DeviceExtension->ClassDO = DriverExtension->MainClassDeviceObject;
    } else {
	/* We need a new class device object for this Fdo */
	Status = CreateClassDeviceObject(DriverObject, Fdo,
					 &DeviceExtension->ClassDO);
	if (!NT_SUCCESS(Status)) {
	    WARN_(CLASS_NAME,
		  "CreateClassDeviceObject() failed with status 0x%08x\n",
		  Status);
	    goto cleanup;
	}
    }
    Status = ConnectPortDriver(Fdo, DeviceExtension->ClassDO);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME,
	      "ConnectPortDriver() failed with status 0x%08x\n", Status);
	goto cleanup;
    }
    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    /* Register interface ; ignore the error (if any) as having
     * a registered interface is not so important... */
    Status = IoRegisterDeviceInterface(Pdo,
				       &GUID_DEVINTERFACE_KEYBOARD,
				       NULL,
				       &DeviceExtension->InterfaceName);
    if (!NT_SUCCESS(Status))
	DeviceExtension->InterfaceName.Length = 0;

    return STATUS_SUCCESS;

cleanup:
    if (Fdo)
	DestroyPortDriver(Fdo);
    return Status;
}

static NTAPI NTSTATUS ClassPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PPORT_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;

    switch (IrpSp->MinorFunction) {
    case IRP_MN_START_DEVICE:
	if (IoForwardIrpSynchronously(DeviceExtension->LowerDevice, Irp)) {
	    Status = Irp->IoStatus.Status;
	} else {
	    Status = STATUS_UNSUCCESSFUL;
	}
	if (NT_SUCCESS(Status) && DeviceExtension->InterfaceName.Buffer != NULL &&
	    DeviceExtension->InterfaceName.Buffer[0] != L'\0') {
	    OBJECT_ATTRIBUTES ObjectAttributes;
	    IO_STATUS_BLOCK Iosb;
	    InitializeObjectAttributes(&ObjectAttributes,
				       &DeviceExtension->InterfaceName,
				       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				       NULL, NULL);
	    Status = NtOpenFile(&DeviceExtension->FileHandle,
				FILE_READ_DATA,
				&ObjectAttributes, &Iosb, 0, 0);
	    if (!NT_SUCCESS(Status))
		DeviceExtension->FileHandle = NULL;
	} else {
	    DeviceExtension->FileHandle = NULL;
	}
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;

    case IRP_MN_STOP_DEVICE:
	if (DeviceExtension->FileHandle) {
	    NtClose(DeviceExtension->FileHandle);
	    DeviceExtension->FileHandle = NULL;
	}
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_REMOVE_DEVICE:
	if (DeviceExtension->FileHandle) {
	    NtClose(DeviceExtension->FileHandle);
	    DeviceExtension->FileHandle = NULL;
	}
	IoSkipCurrentIrpStackLocation(Irp);
	Status = IoCallDriver(DeviceExtension->LowerDevice, Irp);
	DestroyPortDriver(DeviceObject);
	return Status;

    default:
	Status = STATUS_NOT_SUPPORTED;
	break;
    }

    Irp->IoStatus.Status = Status;
    if (NT_SUCCESS(Status) || Status == STATUS_NOT_SUPPORTED) {
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(DeviceExtension->LowerDevice, Irp);
    } else {
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
    }
}

static NTAPI VOID SearchForLegacyDrivers(IN PDRIVER_OBJECT DriverObject,
					 IN PVOID Context,	/* PCLASS_DRIVER_EXTENSION */
					 IN ULONG Count)
{
    UNICODE_STRING DeviceMapKeyU = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Hardware\\DeviceMap");
    PCLASS_DRIVER_EXTENSION DriverExtension;
    UNICODE_STRING PortBaseName = { 0, 0, NULL };
    PKEY_VALUE_BASIC_INFORMATION KeyValueInformation = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hDeviceMapKey = (HANDLE) - 1;
    HANDLE hPortKey = (HANDLE) - 1;
    ULONG Index = 0;
    ULONG Size, ResultLength;
    NTSTATUS Status;

    TRACE_(CLASS_NAME, "SearchForLegacyDrivers(%p %p %u)\n",
	   DriverObject, Context, Count);

    if (Count != 1)
	return;
    DriverExtension = (PCLASS_DRIVER_EXTENSION) Context;

    /* Create port base name, by replacing Class by Port at the end of the class base name */
    Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
				       &DriverExtension->DeviceBaseName,
				       &PortBaseName);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME,
	      "RtlDuplicateUnicodeString() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }
    PortBaseName.Length -= (sizeof(L"Class") - sizeof(UNICODE_NULL));
    RtlAppendUnicodeToString(&PortBaseName, L"Port");

    /* Allocate memory */
    Size = sizeof(KEY_VALUE_BASIC_INFORMATION) + MAX_PATH;
    KeyValueInformation = ExAllocatePoolWithTag(NonPagedPool, Size, CLASS_TAG);
    if (!KeyValueInformation) {
	WARN_(CLASS_NAME, "ExAllocatePoolWithTag() failed\n");
	Status = STATUS_NO_MEMORY;
	goto cleanup;
    }

    /* Open HKEY_LOCAL_MACHINE\Hardware\DeviceMap */
    InitializeObjectAttributes(&ObjectAttributes, &DeviceMapKeyU,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			       NULL, NULL);
    Status = NtOpenKey(&hDeviceMapKey, 0, &ObjectAttributes);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
	INFO_(CLASS_NAME, "HKLM\\Hardware\\DeviceMap is non-existent\n");
	Status = STATUS_SUCCESS;
	goto cleanup;
    } else if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME, "NtOpenKey() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }

    /* Open sub key */
    InitializeObjectAttributes(&ObjectAttributes, &PortBaseName,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			       hDeviceMapKey, NULL);
    Status = NtOpenKey(&hPortKey, KEY_QUERY_VALUE, &ObjectAttributes);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
	INFO_(CLASS_NAME,
	      "HKLM\\Hardware\\DeviceMap\\%wZ is non-existent\n",
	      &PortBaseName);
	Status = STATUS_SUCCESS;
	goto cleanup;
    } else if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME, "NtOpenKey() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }

    /* Read each value name */
    while (NT_SUCCESS(NtEnumerateValueKey(hPortKey, Index++, KeyValueBasicInformation,
					  KeyValueInformation, Size, &ResultLength))) {
	UNICODE_STRING PortName;
	PDEVICE_OBJECT PortDeviceObject = NULL;

	PortName.Length = PortName.MaximumLength = (USHORT)KeyValueInformation->NameLength;
	PortName.Buffer = KeyValueInformation->Name;

	/* Open the device object pointer */
	Status = IoGetDeviceObjectPointer(&PortName, FILE_READ_ATTRIBUTES,
					  &PortDeviceObject);
	if (!NT_SUCCESS(Status)) {
	    WARN_(CLASS_NAME,
		  "IoGetDeviceObjectPointer(%wZ) failed with status 0x%08x\n",
		  &PortName, Status);
	    continue;
	}
	INFO_(CLASS_NAME, "Legacy driver found\n");

	Status = ClassAddDevice(DriverObject, PortDeviceObject);
	if (!NT_SUCCESS(Status)) {
	    /* FIXME: Log the error */
	    WARN_(CLASS_NAME,
		  "ClassAddDevice() failed with status 0x%08x\n", Status);
	}
    }

cleanup:
    if (KeyValueInformation != NULL)
	ExFreePoolWithTag(KeyValueInformation, CLASS_TAG);
    if (hDeviceMapKey != (HANDLE)(-1))
	NtClose(hDeviceMapKey);
    if (hPortKey != (HANDLE)(-1))
	NtClose(hPortKey);
}

/*
 * Standard DriverEntry method.
 */
NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    PCLASS_DRIVER_EXTENSION DriverExtension;
    NTSTATUS Status;

    Status = IoAllocateDriverObjectExtension(DriverObject, DriverObject,
					     sizeof(CLASS_DRIVER_EXTENSION),
					     (PVOID *)&DriverExtension);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME,
	      "IoAllocateDriverObjectExtension() failed with status 0x%08x\n",
	      Status);
	return Status;
    }
    RtlZeroMemory(DriverExtension, sizeof(CLASS_DRIVER_EXTENSION));

    Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
				       RegistryPath, &DriverExtension->RegistryPath);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME,
	      "RtlDuplicateUnicodeString() failed with status 0x%08x\n",
	      Status);
	return Status;
    }

    Status = ReadRegistryEntries(RegistryPath, DriverExtension);
    if (!NT_SUCCESS(Status)) {
	WARN_(CLASS_NAME,
	      "ReadRegistryEntries() failed with status 0x%08x\n",
	      Status);
	return Status;
    }

    if (IoIsSingletonMode(DriverObject) && DriverExtension->ConnectMultiplePorts == 1) {
	Status = CreateClassDeviceObject(DriverObject, NULL,
					 &DriverExtension->MainClassDeviceObject);
	if (!NT_SUCCESS(Status)) {
	    WARN_(CLASS_NAME,
		  "CreateClassDeviceObject() failed with status 0x%08x\n",
		  Status);
	    return Status;
	}
    }

    DriverObject->AddDevice = ClassAddDevice;
    DriverObject->DriverUnload = DriverUnload;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = ClassCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = ClassClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = ClassCleanup;
    DriverObject->MajorFunction[IRP_MJ_READ] = ClassRead;
    DriverObject->MajorFunction[IRP_MJ_POWER] = ClassPower;
    DriverObject->MajorFunction[IRP_MJ_PNP] = ClassPnp;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ClassDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = ForwardIrpAndForget;

    /* We will detect the legacy devices later */
    if (IoIsSingletonMode(DriverObject)) {
	IoRegisterDriverReinitialization(DriverObject,
					 SearchForLegacyDrivers,
					 DriverExtension);
    }

    return STATUS_SUCCESS;
}
