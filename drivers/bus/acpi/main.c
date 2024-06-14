#include "precomp.h"

#include <stdio.h>
#include <poclass.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_ADD_DEVICE Bus_AddDevice;

extern struct acpi_device *sleep_button;
extern struct acpi_device *power_button;

UNICODE_STRING ProcessorHardwareIds = { 0, 0, NULL };
LPWSTR ProcessorIdString = NULL;
LPWSTR ProcessorNameString = NULL;

static NTAPI NTSTATUS Bus_AddDevice(PDRIVER_OBJECT DriverObject,
				    PDEVICE_OBJECT PhysicalDeviceObject)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    PFDO_DEVICE_DATA deviceData = NULL;

    DPRINT("Add Device: 0x%p\n", PhysicalDeviceObject);

    DPRINT("#################### Bus_AddDevice Creating FDO ####################\n");
    status = IoCreateDevice(DriverObject, sizeof(FDO_DEVICE_DATA), NULL, FILE_DEVICE_ACPI,
			    FILE_DEVICE_SECURE_OPEN, TRUE, &deviceObject);
    if (!NT_SUCCESS(status)) {
	DPRINT1("IoCreateDevice() failed with status 0x%X\n", status);
	goto End;
    }

    deviceData = (PFDO_DEVICE_DATA)deviceObject->DeviceExtension;
    RtlZeroMemory(deviceData, sizeof(FDO_DEVICE_DATA));

    //
    // Set the initial state of the FDO
    //

    INITIALIZE_PNP_STATE(deviceData->Common);

    deviceData->Common.IsFDO = TRUE;

    deviceData->Common.Self = deviceObject;

    InitializeListHead(&deviceData->ListOfPDOs);

    // Set the PDO for use with PlugPlay functions

    deviceData->UnderlyingPDO = PhysicalDeviceObject;

    //
    // Set the initial powerstate of the FDO
    //

    deviceData->Common.DevicePowerState = PowerDeviceUnspecified;
    deviceData->Common.SystemPowerState = PowerSystemWorking;

    deviceObject->Flags |= DO_POWER_PAGABLE;

    //
    // Attach our FDO to the device stack.
    // The return value of IoAttachDeviceToDeviceStack is the top of the
    // attachment chain.  This is where all the IRPs should be routed.
    //

    deviceData->NextLowerDriver = IoAttachDeviceToDeviceStack(deviceObject,
							      PhysicalDeviceObject);

    if (NULL == deviceData->NextLowerDriver) {
	status = STATUS_NO_SUCH_DEVICE;
	goto End;
    }

    //
    // We are done with initializing, so let's indicate that and return.
    // This should be the final step in the AddDevice process.
    //
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

End:
    if (!NT_SUCCESS(status) && deviceObject) {
	if (deviceData && deviceData->NextLowerDriver) {
	    IoDetachDevice(deviceData->NextLowerDriver);
	}
	IoDeleteDevice(deviceObject);
    }
    return status;
}

static NTAPI NTSTATUS Bus_CreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS Bus_DeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    PCOMMON_DEVICE_DATA commonData;
    ULONG Caps = 0;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IRP_MJ_DEVICE_CONTROL == irpStack->MajorFunction);

    commonData = (PCOMMON_DEVICE_DATA)DeviceObject->DeviceExtension;

    Irp->IoStatus.Information = 0;

    if (!commonData->IsFDO) {
	switch (irpStack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_ACPI_ASYNC_EVAL_METHOD:
	case IOCTL_ACPI_EVAL_METHOD:
	    status = Bus_PDO_EvalMethod((PPDO_DEVICE_DATA)commonData, Irp);
	    break;

	case IOCTL_GET_SYS_BUTTON_CAPS:
	    if (irpStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
		status = STATUS_BUFFER_TOO_SMALL;
		break;
	    }

	    if (wcsstr(((PPDO_DEVICE_DATA)commonData)->HardwareIDs, L"PNP0C0D")) {
		DPRINT1("Lid button reported to power manager\n");
		Caps |= SYS_BUTTON_LID;
	    } else if (((PPDO_DEVICE_DATA)commonData)->AcpiHandle == NULL) {
		/* We have to return both at the same time because since we
                   * have a NULL handle we are the fixed feature DO and we will
                   * only be called once (not once per device)
                   */
		if (power_button) {
		    DPRINT("Fixed power button reported to power manager\n");
		    Caps |= SYS_BUTTON_POWER;
		}
		if (sleep_button) {
		    DPRINT("Fixed sleep button reported to power manager\n");
		    Caps |= SYS_BUTTON_SLEEP;
		}
	    } else if (wcsstr(((PPDO_DEVICE_DATA)commonData)->HardwareIDs, L"PNP0C0C")) {
		DPRINT("Control method power button reported to power manager\n");
		Caps |= SYS_BUTTON_POWER;
	    } else if (wcsstr(((PPDO_DEVICE_DATA)commonData)->HardwareIDs, L"PNP0C0E")) {
		DPRINT("Control method sleep reported to power manager\n");
		Caps |= SYS_BUTTON_SLEEP;
	    } else {
		DPRINT1("IOCTL_GET_SYS_BUTTON_CAPS sent to a non-button device\n");
		status = STATUS_INVALID_PARAMETER;
	    }

	    if (Caps != 0) {
		RtlCopyMemory(Irp->SystemBuffer, &Caps, sizeof(Caps));
		Irp->IoStatus.Information = sizeof(Caps);
		status = STATUS_SUCCESS;
	    }
	    break;

	case IOCTL_GET_SYS_BUTTON_EVENT:
	    AcpiBusQueueGetButtonEventIrp(Irp);
	    status = STATUS_PENDING;
	    break;

	case IOCTL_BATTERY_QUERY_TAG:
	    DPRINT("IOCTL_BATTERY_QUERY_TAG is not supported!\n");
	    break;

	default:
	    DPRINT1("Unsupported IOCTL: %x\n",
		    irpStack->Parameters.DeviceIoControl.IoControlCode);
	    break;
	}
    } else {
	DPRINT1("IOCTL sent to the ACPI FDO! Kill the caller!\n");
    }

    if (status != STATUS_PENDING) {
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else {
	IoMarkIrpPending(Irp);
    }
    return status;
}

static NTSTATUS AcpiRegOpenKey(IN HANDLE ParentKeyHandle, IN LPCWSTR KeyName,
			       IN ACCESS_MASK DesiredAccess, OUT HANDLE KeyHandle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name;

    RtlInitUnicodeString(&Name, KeyName);

    InitializeObjectAttributes(&ObjectAttributes, &Name,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, ParentKeyHandle,
			       NULL);

    return NtOpenKey(KeyHandle, DesiredAccess, &ObjectAttributes);
}

static NTSTATUS AcpiRegQueryValue(IN HANDLE KeyHandle, IN LPWSTR ValueName,
				  OUT PULONG Type OPTIONAL, OUT PVOID Data OPTIONAL,
				  IN OUT PULONG DataLength OPTIONAL)
{
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo;
    UNICODE_STRING Name;
    ULONG BufferLength = 0;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, ValueName);

    if (DataLength != NULL)
	BufferLength = *DataLength;

    /* Check if the caller provided a valid buffer */
    if ((Data != NULL) && (BufferLength != 0)) {
	BufferLength += FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);

	/* Allocate memory for the value */
	ValueInfo = ExAllocatePoolWithTag(BufferLength, 'MpcA');
	if (ValueInfo == NULL)
	    return STATUS_NO_MEMORY;
    } else {
	/* Caller didn't provide a valid buffer, assume he wants the size only */
	ValueInfo = NULL;
	BufferLength = 0;
    }

    /* Query the value */
    Status = NtQueryValueKey(KeyHandle, &Name, KeyValuePartialInformation, ValueInfo,
			     BufferLength, &BufferLength);

    if (DataLength != NULL)
	*DataLength = BufferLength;

    /* Check if we have the size only */
    if (ValueInfo == NULL) {
	/* Check for unexpected status */
	if ((Status != STATUS_BUFFER_OVERFLOW) && (Status != STATUS_BUFFER_TOO_SMALL)) {
	    return Status;
	}

	/* All is well */
	Status = STATUS_SUCCESS;
    } else if (NT_SUCCESS(Status)) {
    /* Otherwise the caller wanted data back, check if we got it */
	if (Type != NULL)
	    *Type = ValueInfo->Type;

	/* Copy it */
	RtlMoveMemory(Data, ValueInfo->Data, ValueInfo->DataLength);

	/* if the type is REG_SZ and data is not 0-terminated
         * and there is enough space in the buffer NT appends a \0 */
	if (((ValueInfo->Type == REG_SZ) || (ValueInfo->Type == REG_EXPAND_SZ) ||
	     (ValueInfo->Type == REG_MULTI_SZ)) &&
	    (ValueInfo->DataLength <= *DataLength - sizeof(WCHAR))) {
	    WCHAR *ptr = (WCHAR *)((ULONG_PTR)Data + ValueInfo->DataLength);
	    if ((ptr > (WCHAR *)Data) && ptr[-1])
		*ptr = 0;
	}
    }

    /* Free the memory and return status */
    if (ValueInfo != NULL) {
	ExFreePoolWithTag(ValueInfo, 'MpcA');
    }

    return Status;
}

static NTSTATUS GetProcessorInformation(VOID)
{
    LPWSTR ProcessorIdentifier = NULL;
    LPWSTR ProcessorVendorIdentifier = NULL;
    LPWSTR HardwareIdsBuffer = NULL;
    HANDLE ProcessorHandle = NULL;
    ULONG Length = 0, Level1Length = 0, Level2Length = 0, Level3Length = 0;
    SIZE_T HardwareIdsLength = 0;
    SIZE_T VendorIdentifierLength;
    ULONG i;
    PWCHAR Ptr;
    NTSTATUS Status;

    DPRINT("GetProcessorInformation()\n");

    /* Open the key for CPU 0 */
    Status = AcpiRegOpenKey(NULL,
			    L"\\Registry\\Machine\\Hardware\\Description\\System\\Central"
			    L"Processor\\0",
			    KEY_READ, &ProcessorHandle);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to open CentralProcessor registry key: 0x%x\n", Status);
	goto done;
    }

    /* Query the processor identifier length */
    Status = AcpiRegQueryValue(ProcessorHandle, L"Identifier", NULL, NULL, &Length);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to query Identifier value: 0x%x\n", Status);
	goto done;
    }

    /* Remember the length as fallback for level 1-3 length */
    Level1Length = Level2Length = Level3Length = Length;

    /* Allocate a buffer large enough to be zero terminated */
    Length += sizeof(UNICODE_NULL);
    ProcessorIdentifier = ExAllocatePoolWithTag(Length, ACPI_TAG);
    if (ProcessorIdentifier == NULL) {
	DPRINT1("Failed to allocate 0x%x bytes\n", Length);
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto done;
    }

    /* Query the processor identifier string */
    Status = AcpiRegQueryValue(ProcessorHandle, L"Identifier", NULL, ProcessorIdentifier,
			       &Length);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to query Identifier value: 0x%x\n", Status);
	goto done;
    }

    /* Query the processor name length */
    Length = 0;
    Status = AcpiRegQueryValue(ProcessorHandle, L"ProcessorNameString", NULL, NULL,
			       &Length);
    if (NT_SUCCESS(Status)) {
	/* Allocate a buffer large enough to be zero terminated */
	Length += sizeof(UNICODE_NULL);
	ProcessorNameString = ExAllocatePoolWithTag(Length, ACPI_TAG);
	if (ProcessorNameString == NULL) {
	    DPRINT1("Failed to allocate 0x%x bytes\n", Length);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto done;
	}

	/* Query the processor name string */
	Status = AcpiRegQueryValue(ProcessorHandle, L"ProcessorNameString", NULL,
				   ProcessorNameString, &Length);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Failed to query ProcessorNameString value: 0x%x\n", Status);
	    goto done;
	}
    }

    /* Query the vendor identifier length */
    Length = 0;
    Status = AcpiRegQueryValue(ProcessorHandle, L"VendorIdentifier", NULL, NULL, &Length);
    if (!NT_SUCCESS(Status) || (Length == 0)) {
	DPRINT1("Failed to query VendorIdentifier value: 0x%x\n", Status);
	goto done;
    }

    /* Allocate a buffer large enough to be zero terminated */
    Length += sizeof(UNICODE_NULL);
    ProcessorVendorIdentifier = ExAllocatePoolWithTag(Length, ACPI_TAG);
    if (ProcessorVendorIdentifier == NULL) {
	DPRINT1("Failed to allocate 0x%x bytes\n", Length);
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto done;
    }

    /* Query the vendor identifier string */
    Status = AcpiRegQueryValue(ProcessorHandle, L"VendorIdentifier", NULL,
			       ProcessorVendorIdentifier, &Length);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to query VendorIdentifier value: 0x%x\n", Status);
	goto done;
    }

    /* Change spaces to underscores */
    for (i = 0; i < wcslen(ProcessorIdentifier); i++) {
	if (ProcessorIdentifier[i] == L' ')
	    ProcessorIdentifier[i] = L'_';
    }

    Ptr = wcsstr(ProcessorIdentifier, L"Stepping");
    if (Ptr != NULL) {
	Ptr--;
	Level1Length = (ULONG)(Ptr - ProcessorIdentifier);
    }

    Ptr = wcsstr(ProcessorIdentifier, L"Model");
    if (Ptr != NULL) {
	Ptr--;
	Level2Length = (ULONG)(Ptr - ProcessorIdentifier);
    }

    Ptr = wcsstr(ProcessorIdentifier, L"Family");
    if (Ptr != NULL) {
	Ptr--;
	Level3Length = (ULONG)(Ptr - ProcessorIdentifier);
    }

    VendorIdentifierLength = (USHORT)wcslen(ProcessorVendorIdentifier);

    /* Calculate the size of the full REG_MULTI_SZ data (see swprintf below) */
    HardwareIdsLength = (5 + VendorIdentifierLength + 3 + Level1Length + 1 + 1 +
			 VendorIdentifierLength + 3 + Level1Length + 1 + 5 +
			 VendorIdentifierLength + 3 + Level2Length + 1 + 1 +
			 VendorIdentifierLength + 3 + Level2Length + 1 + 5 +
			 VendorIdentifierLength + 3 + Level3Length + 1 + 1 +
			 VendorIdentifierLength + 3 + Level3Length + 1 + 1) *
			sizeof(WCHAR);

    /* Allocate a buffer to the data */
    HardwareIdsBuffer = ExAllocatePoolWithTag(HardwareIdsLength, ACPI_TAG);
    if (HardwareIdsBuffer == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto done;
    }

    Length = 0;
    Length += swprintf(&HardwareIdsBuffer[Length], L"ACPI\\%s_-_%.*s",
		       ProcessorVendorIdentifier, Level1Length, ProcessorIdentifier);
    HardwareIdsBuffer[Length++] = UNICODE_NULL;

    Length += swprintf(&HardwareIdsBuffer[Length], L"*%s_-_%.*s",
		       ProcessorVendorIdentifier, Level1Length, ProcessorIdentifier);
    HardwareIdsBuffer[Length++] = UNICODE_NULL;

    Length += swprintf(&HardwareIdsBuffer[Length], L"ACPI\\%s_-_%.*s",
		       ProcessorVendorIdentifier, Level2Length, ProcessorIdentifier);
    HardwareIdsBuffer[Length++] = UNICODE_NULL;

    Length += swprintf(&HardwareIdsBuffer[Length], L"*%s_-_%.*s",
		       ProcessorVendorIdentifier, Level2Length, ProcessorIdentifier);
    HardwareIdsBuffer[Length++] = UNICODE_NULL;

    Length += swprintf(&HardwareIdsBuffer[Length], L"ACPI\\%s_-_%.*s",
		       ProcessorVendorIdentifier, Level3Length, ProcessorIdentifier);
    HardwareIdsBuffer[Length++] = UNICODE_NULL;

    Length += swprintf(&HardwareIdsBuffer[Length], L"*%s_-_%.*s",
		       ProcessorVendorIdentifier, Level3Length, ProcessorIdentifier);
    HardwareIdsBuffer[Length++] = UNICODE_NULL;
    HardwareIdsBuffer[Length++] = UNICODE_NULL;

    /* Make sure we counted correctly */
    NT_ASSERT(Length * sizeof(WCHAR) == HardwareIdsLength);

    ProcessorHardwareIds.Length = (SHORT)HardwareIdsLength;
    ProcessorHardwareIds.MaximumLength = ProcessorHardwareIds.Length;
    ProcessorHardwareIds.Buffer = HardwareIdsBuffer;

    Length = (5 + VendorIdentifierLength + 3 + Level1Length + 1) * sizeof(WCHAR);
    ProcessorIdString = ExAllocatePoolWithTag(Length, ACPI_TAG);
    if (ProcessorIdString != NULL) {
	Length = swprintf(ProcessorIdString, L"ACPI\\%s_-_%.*s",
			  ProcessorVendorIdentifier, Level1Length, ProcessorIdentifier);
	ProcessorIdString[Length++] = UNICODE_NULL;
	DPRINT("ProcessorIdString: %S\n", ProcessorIdString);
    }

done:
    if (ProcessorHandle != NULL)
	NtClose(ProcessorHandle);

    if (ProcessorIdentifier != NULL)
	ExFreePoolWithTag(ProcessorIdentifier, ACPI_TAG);

    if (ProcessorVendorIdentifier != NULL)
	ExFreePoolWithTag(ProcessorVendorIdentifier, ACPI_TAG);

    if (!NT_SUCCESS(Status)) {
	if (HardwareIdsBuffer != NULL)
	    ExFreePoolWithTag(HardwareIdsBuffer, ACPI_TAG);
    }

    return Status;
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;
    DPRINT("Driver Entry \n");

    Status = GetProcessorInformation();
    if (!NT_SUCCESS(Status)) {
	NT_ASSERT(FALSE);
	return Status;
    }

    //
    // Set entry points into the driver
    //
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Bus_DeviceControl;
    DriverObject->MajorFunction[IRP_MJ_PNP] = Bus_PnP;
    DriverObject->MajorFunction[IRP_MJ_POWER] = Bus_Power;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = Bus_CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = Bus_CreateClose;

    DriverObject->AddDevice = Bus_AddDevice;

    return STATUS_SUCCESS;
}
