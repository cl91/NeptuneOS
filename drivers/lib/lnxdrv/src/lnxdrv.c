#include "lnxdrvp.h"

typedef struct _LNX_DRIVER_EXTENSION {
    HANDLE SectionHandle;
    PVOID ImageBase;
    SIZE_T ViewSize;
    PLNX_DRV_ENTRY_POINT EntryPoint;
    LNX_DRV_EXPORT_TABLE ExportTable;
} LNX_DRIVER_EXTENSION, *PLNX_DRIVER_EXTENSION;

static VOID LnxDbgPrint(IN PCSTR Format, IN va_list ArgList)
{
    vDbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, Format, ArgList);
}

static PVOID LnxAllocateMemory(IN SIZE_T Size)
{
    return ExAllocatePool(NonPagedPool, Size);
}

static VOID LnxFreeMemory(IN PVOID Ptr)
{
    ExFreePool(Ptr);
}

static HANDLE LnxCreateMutex()
{
    PKEVENT Event = ExAllocatePool(NonPagedPool, sizeof(KEVENT));
    KeInitializeEvent(Event, SynchronizationEvent, FALSE);
    return Event;
}

static NTAPI VOID LnxThreadWorkerRoutine(IN PDEVICE_OBJECT DevObj,
					 IN PVOID Arg)
{
    LNX_DRV_THREAD_ENTRY Entry = (PVOID)DevObj;
    Entry(Arg);
}

static HANDLE LnxCreateThread(IN LNX_DRV_THREAD_ENTRY Entry, PVOID Arg)
{
    PIO_WORKITEM WorkItem = IoAllocateWorkItem((PVOID)Entry);
    if (!WorkItem) {
	return NULL;
    }
    IoQueueWorkItem(WorkItem, LnxThreadWorkerRoutine,
		    DelayedWorkQueue, Arg);
    return WorkItem;
}

static LNX_DRV_IMPORT_TABLE LnxDrvImportTable = {
    .DbgPrint = LnxDbgPrint,
    .AllocateMemory = LnxAllocateMemory,
    .FreeMemory = LnxFreeMemory,
    .CreateMutex = LnxCreateMutex,
    .CreateThread = LnxCreateThread
};

static NTAPI NTSTATUS LnxDrvAddDevice(IN struct _DRIVER_OBJECT *DriverObject,
				      IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTAPI NTSTATUS LnxDrvDispatchCreate(IN PDEVICE_OBJECT DeviceObject,
					   IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS LnxInitializeDriver(IN PDRIVER_OBJECT DriverObject,
			     IN PUNICODE_STRING RegistryPath)
{
    /* Allocate driver object extension */
    PLNX_DRIVER_EXTENSION DriverExtension;
    NTSTATUS Status = IoAllocateDriverObjectExtension(DriverObject, DriverObject,
						      sizeof(LNX_DRIVER_EXTENSION),
						      (PVOID *)&DriverExtension);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    RtlZeroMemory(DriverExtension, sizeof(*DriverExtension));

    /* Open service key (RegistryPath) */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, RegistryPath,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE ServiceKeyHandle = NULL;
    Status = NtOpenKey(&ServiceKeyHandle, KEY_READ, &ObjectAttributes);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Open Parameters subkey */
    UNICODE_STRING ParametersKeyName;
    RtlInitUnicodeString(&ParametersKeyName, L"Parameters");

    InitializeObjectAttributes(&ObjectAttributes, &ParametersKeyName,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, ServiceKeyHandle,
			       NULL);

    HANDLE ParametersKeyHandle = NULL;
    Status = NtOpenKey(&ParametersKeyHandle, KEY_READ, &ObjectAttributes);

    NtClose(ServiceKeyHandle);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    UNICODE_STRING ValueName;
    RtlInitUnicodeString(&ValueName, L"DriverExtensionImage");

    ULONG ResultLength;
    Status = NtQueryValueKey(ParametersKeyHandle, &ValueName, KeyValuePartialInformation,
			     NULL, 0, &ResultLength);

    if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW) {
	NtClose(ParametersKeyHandle);
	return Status;
    }

    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = ExAllocatePoolWithTag(NonPagedPool,
								     ResultLength,
								     LNXDRV_TAG);

    if (ValueInfo == NULL) {
	NtClose(ParametersKeyHandle);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = NtQueryValueKey(ParametersKeyHandle, &ValueName, KeyValuePartialInformation,
			     ValueInfo, ResultLength, &ResultLength);

    NtClose(ParametersKeyHandle);

    if (!NT_SUCCESS(Status) || ValueInfo->Type != REG_SZ) {
	ExFreePool(ValueInfo);
	return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    UNICODE_STRING ImagePath;
    ImagePath.Buffer = (PWSTR)ValueInfo->Data;
    ImagePath.Length = wcslen(ImagePath.Buffer) * sizeof(WCHAR),
    ImagePath.MaximumLength = (USHORT)ValueInfo->DataLength;

    InitializeObjectAttributes(&ObjectAttributes, &ImagePath,
			       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus;
    Status = NtCreateFile(&FileHandle, FILE_EXECUTE | FILE_READ_DATA | SYNCHRONIZE,
			  &ObjectAttributes, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL,
			  FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    ExFreePool(ValueInfo);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Create SEC_IMAGE section */
    HANDLE SectionHandle = NULL;
    Status = NtCreateSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ, NULL,
			     NULL, PAGE_EXECUTE, SEC_IMAGE, FileHandle);

    NtClose(FileHandle);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Query image base address and transfer address */
    SECTION_BASIC_INFORMATION SectionInfo;
    Status = NtQuerySection(SectionHandle, SectionBasicInformation, &SectionInfo,
			    sizeof(SectionInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    SECTION_IMAGE_INFORMATION ImageInfo;
    Status = NtQuerySection(SectionHandle, SectionImageInformation, &ImageInfo,
			    sizeof(ImageInfo), NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Map into driver address space */
    PVOID ImageBase = NULL;
    SIZE_T ViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle, NtCurrentProcess(), &ImageBase, 0, 0, NULL,
				&ViewSize, ViewShare, 0, PAGE_EXECUTE_READ);

    if (!NT_SUCCESS(Status)) {
	NtClose(SectionHandle);
	return Status;
    }

    if (ImageBase != SectionInfo.BaseAddress) {
	DPRINT("Error: image %wZ cannot be loaded at preferred base %p (got image base %p)\n",
	       &ImagePath, SectionInfo.BaseAddress, ImageBase);
	return STATUS_IMAGE_NOT_AT_BASE;
    }

    /* Locate PE entry point */
    PLNX_DRV_ENTRY_POINT EntryPoint = ImageInfo.TransferAddress;

    DriverExtension->SectionHandle = SectionHandle;
    DriverExtension->ImageBase = ImageBase;
    DriverExtension->ViewSize = ViewSize;
    DriverExtension->EntryPoint = EntryPoint;

    /* Call extension entry */
    Status = EntryPoint(&LnxDrvImportTable, &DriverExtension->ExportTable);

    if (!NT_SUCCESS(Status)) {
	NtUnmapViewOfSection(NtCurrentProcess(), ImageBase);
	NtClose(SectionHandle);
	RtlZeroMemory(DriverExtension, sizeof(*DriverExtension));
	return Status;
    }

    DriverExtension->ExportTable.QueryDriverInfo();

    DriverObject->AddDevice = LnxDrvAddDevice;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = LnxDrvDispatchCreate;
    return STATUS_SUCCESS;
}

PLNX_DRV_EXPORT_TABLE LnxDrvGetExportTable(IN PDRIVER_OBJECT DriverObject)
{
    PLNX_DRIVER_EXTENSION DriverExtension = IoGetDriverObjectExtension(DriverObject,
								       DriverObject);
    if (!DriverExtension) {
	assert(FALSE);
	return NULL;
    }
    return &DriverExtension->ExportTable;
}
