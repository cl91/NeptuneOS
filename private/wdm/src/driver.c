#include <wdmp.h>
#include <wdmguid.h>

typedef struct _PNP_NOTIFY_ENTRY {
    LIST_ENTRY PnpNotifyList;
    PVOID Context;
    PDRIVER_OBJECT DriverObject;
    PDRIVER_NOTIFICATION_CALLBACK_ROUTINE PnpNotificationProc;
    IO_WORKITEM WorkItem;
    union {
	GUID Guid; // for EventCategoryDeviceInterfaceChange
	PDEVICE_OBJECT DeviceObject; // for EventCategoryTargetDeviceChange
    };
    IO_NOTIFICATION_EVENT_CATEGORY EventCategory;
} PNP_NOTIFY_ENTRY, *PPNP_NOTIFY_ENTRY;

#define SERVICE_KEY_NAME	(CONTROL_KEY_NAME L"Services\\")

static LIST_ENTRY IopDriverList;
static LIST_ENTRY PiNotifyDeviceInterfaceList;
static LIST_ENTRY PiNotifyHwProfileList;
static LIST_ENTRY PiNotifyTargetDeviceList;

static NTSTATUS IopCallDriverEntry(IN PDRIVER_OBJECT DriverObject)
{
    assert(DriverObject);
    PLDR_DATA_TABLE_ENTRY DriverImage = NULL;
    NTSTATUS Status = LdrFindEntryForAddress(DriverObject->DriverStart,
					     &DriverImage);
    if (!NT_SUCCESS(Status)) {
	return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
    }
    assert(DriverImage);
    PDRIVER_INITIALIZE DriverEntry = DriverImage->EntryPoint;
    DbgTrace("Driver entry %p. Registry path %wZ\n",
	     DriverEntry, &DriverObject->RegistryPath);
    Status = DriverEntry(DriverObject, &DriverObject->RegistryPath);
    if (!NT_SUCCESS(Status)) {
	return STATUS_FAILED_DRIVER_ENTRY;
    }
    return STATUS_SUCCESS;
}

static VOID IopCallReinitRoutine(IN PDRIVER_OBJECT DriverObject)
{
    DriverObject->Flags &= ~DRVO_REINIT_REGISTERED;
    LoopOverList(Entry, &DriverObject->ReinitListHead, DRIVER_REINIT_ITEM, ItemEntry) {
	Entry->Count++;
	Entry->ReinitRoutine(Entry->DriverObject, Entry->Context, Entry->Count);
    }
}

static NTSTATUS IopCreateDriverObject(IN PUNICODE_STRING RegistryPath,
				      IN PVOID BaseAddress,
				      OUT PDRIVER_OBJECT *pDriverObject)
{
    /* Get the base name of the driver service from the registry path */
    const UNICODE_STRING PathDividers = RTL_CONSTANT_STRING(L"\\/");
    USHORT Position;
    if (!NT_SUCCESS(RtlFindCharInUnicodeString(RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END,
					       RegistryPath, &PathDividers, &Position))) {
	assert(FALSE);
	return STATUS_INTERNAL_ERROR;
    }
    Position += sizeof(WCHAR);
    if (Position >= RegistryPath->Length) {
	assert(FALSE);
	return STATUS_INTERNAL_ERROR;
    }
    IopAllocateObject(DriverObject, DRIVER_OBJECT);
    DriverObject->DriverStart = BaseAddress;
    DriverObject->RegistryPath = *RegistryPath;
    DriverObject->DriverName.Buffer = RegistryPath->Buffer + Position / sizeof(WCHAR);
    DriverObject->DriverName.MaximumLength = DriverObject->DriverName.Length =
	RegistryPath->Length - Position;
    InsertHeadList(&IopDriverList, &DriverObject->ListEntry);
    InitializeListHead(&DriverObject->ReinitListHead);
    *pDriverObject = DriverObject;
    return STATUS_SUCCESS;
}

static VOID IopFreeDriverObject(IN PDRIVER_OBJECT DriverObject)
{
    RemoveEntryList(&DriverObject->ListEntry);
    IopFreePool(DriverObject);
}

static NTSTATUS IopInitDriverObject(PUNICODE_STRING RegistryPath,
				    PVOID ImageBaseAddress)
{
    PDRIVER_OBJECT DriverObject = NULL;
    NTSTATUS Status = IopCreateDriverObject(RegistryPath, ImageBaseAddress, &DriverObject);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Status = IopCallDriverEntry(DriverObject);
    if (!NT_SUCCESS(Status)) {
	IopFreeDriverObject(DriverObject);
	return Status;
    }

    IopCallReinitRoutine(DriverObject);
    return STATUS_SUCCESS;
}

NTSTATUS IopDriverInitialize(IN PUNICODE_STRING RegistryPath)
{
    InitializeListHead(&IopDriverList);
    InitializeListHead(&PiNotifyDeviceInterfaceList);
    InitializeListHead(&PiNotifyHwProfileList);
    InitializeListHead(&PiNotifyTargetDeviceList);

    ReverseLoopOverList(Entry, &NtCurrentPeb()->LdrData->InLoadOrderModuleList,
			LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) {
	if (Entry->DllBase == NtCurrentPeb()->ImageBaseAddress) {
	    continue;
	}
	UNICODE_STRING Suffix = RTL_CONSTANT_STRING(L".sys");
	if (Entry->BaseDllName.Length < Suffix.Length) {
	    continue;
	}
	USHORT Offset = (Entry->BaseDllName.Length - Suffix.Length) / sizeof(WCHAR);
	UNICODE_STRING Tail = {
	    .Buffer = Entry->BaseDllName.Buffer + Offset,
	    .Length = Suffix.Length,
	    .MaximumLength  = Suffix.Length
	};
	if (!RtlEqualUnicodeString(&Tail, &Suffix, TRUE)) {
	    continue;
	}
	ULONG ServiceBufSize = sizeof(SERVICE_KEY_NAME) + Offset * sizeof(WCHAR);
	IopAllocatePool(DriverService, WCHAR, ServiceBufSize);
	memcpy(DriverService, SERVICE_KEY_NAME, sizeof(SERVICE_KEY_NAME));
	memcpy(DriverService + sizeof(SERVICE_KEY_NAME) / sizeof(WCHAR) - 1,
	       Entry->BaseDllName.Buffer, Offset * sizeof(WCHAR));
	UNICODE_STRING ServicePath = {
	    .Buffer = DriverService,
	    .Length = ServiceBufSize - sizeof(WCHAR),
	    .MaximumLength = ServiceBufSize
	};
	RET_ERR(IopInitDriverObject(&ServicePath, Entry->DllBase));
    }

    return IopInitDriverObject(RegistryPath, NtCurrentPeb()->ImageBaseAddress);
}

PDRIVER_OBJECT IopLocateDriverObject(IN PCSTR BaseName)
{
    ULONG BaseNameLength = strlen(BaseName);
    WCHAR BaseNameBuffer[BaseNameLength];
    ULONG UnicodeLength = 0;
    RtlUTF8ToUnicodeN(BaseNameBuffer, BaseNameLength * sizeof(WCHAR),
		      &UnicodeLength, BaseName, BaseNameLength);
    UNICODE_STRING BaseNameU = {
	.Buffer = BaseNameBuffer,
	.Length = UnicodeLength,
	.MaximumLength = sizeof(BaseNameBuffer)
    };
    LoopOverList(DriverObject, &IopDriverList, DRIVER_OBJECT, ListEntry) {
	if (BaseNameLength) {
	    if (!RtlCompareUnicodeString(&BaseNameU, &DriverObject->DriverName, TRUE)) {
		return DriverObject;
	    }
	} else {
	    if (IoIsSingletonMode(DriverObject)) {
		return DriverObject;
	    }
	}
    }
    return NULL;
}

NTSTATUS IopLoadDriver(IN PCSTR BaseName)
{
    if (IopLocateDriverObject(BaseName)) {
	return STATUS_SUCCESS;
    }

    ULONG ServiceBufSize = sizeof(SERVICE_KEY_NAME) + strlen(BaseName) * sizeof(WCHAR);
    IopAllocatePool(DriverService, WCHAR, ServiceBufSize);
    memcpy(DriverService, SERVICE_KEY_NAME, sizeof(SERVICE_KEY_NAME));
    PWCHAR BaseNameU = &DriverService[sizeof(SERVICE_KEY_NAME) / sizeof(WCHAR) - 1];
    ULONG BaseNameLength = 0;
    RET_ERR_EX(RtlUTF8ToUnicodeN(BaseNameU, strlen(BaseName) * sizeof(WCHAR),
				 &BaseNameLength, BaseName, strlen(BaseName)),
	       IopFreePool(DriverService));
    UNICODE_STRING DriverServiceKey = {
	.Buffer = DriverService,
	.Length = sizeof(SERVICE_KEY_NAME) - sizeof(WCHAR) + BaseNameLength,
	.MaximumLength = ServiceBufSize
    };
    HANDLE KeyHandle = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = NULL;
    NTSTATUS Status;
    IF_ERR_GOTO(out, Status, IopOpenKey(DriverServiceKey, &KeyHandle));
    assert(KeyHandle != NULL);
    IF_ERR_GOTO(out, Status, IopQueryValueKey(KeyHandle, L"ImagePath", &PartialInfo));
    if (!(PartialInfo->Type == REG_SZ || PartialInfo->Type == REG_EXPAND_SZ)) {
	assert(FALSE);
	Status = STATUS_OBJECT_TYPE_MISMATCH;
	goto out;
    }
    PVOID BaseAddress = NULL;
    UNICODE_STRING ImagePath = {
	.Buffer = (PWSTR)PartialInfo->Data,
	.Length = wcsnlen((PWSTR)PartialInfo->Data,
			  PartialInfo->DataLength / sizeof(WCHAR)) * sizeof(WCHAR),
	.MaximumLength = PartialInfo->DataLength
    };
    IF_ERR_GOTO(out, Status, LdrLoadDll(NULL, NULL, &ImagePath, &BaseAddress));
    Status = IopInitDriverObject(&DriverServiceKey, BaseAddress);
    if (!NT_SUCCESS(Status)) {
	LdrUnloadDll(BaseAddress);
    }

out:
    if (!NT_SUCCESS(Status)) {
	IopFreePool(DriverService);
    }
    if (KeyHandle) {
	NtClose(KeyHandle);
    }
    if (PartialInfo) {
	ExFreePool(PartialInfo);
    }
    return Status;
}

/*
 * @implemented
 *
 * Allocates a per-driver context area and assigns a unique identifier to it.
 * The per-driver context area follows the header IO_CLIENT_EXTENSION which
 * records the identifier and chains all extensions of one driver. The pointer
 * to the beginning of the per-driver context area (ie. the memory immediately
 * after the header) is returned via pDriverExtension.
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoAllocateDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
					       IN PVOID ClientIdentAddr,
					       IN ULONG DriverExtensionSize,
					       OUT PVOID *pDriverExtension)
{
    PAGED_CODE();

    /* Assume failure */
    *pDriverExtension = NULL;

    /* Make sure client indentification address is not already used */
    for (PIO_CLIENT_EXTENSION DrvExt = DriverObject->ClientDriverExtension;
	 DrvExt != NULL; DrvExt = DrvExt->NextExtension) {
        /* Check if the identifier matches */
        if (DrvExt->ClientIdentificationAddress == ClientIdentAddr) {
            /* We have a collision, return error */
            return STATUS_OBJECT_NAME_COLLISION;
        }
    }

    /* Allocate the driver extension */
    PIO_CLIENT_EXTENSION DrvExt = ExAllocatePoolWithTag(NonPagedPool,
							sizeof(IO_CLIENT_EXTENSION)
							+ DriverExtensionSize,
							TAG_DRIVER_EXTENSION);
    if (!DrvExt) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Fill out the extension and add it to the driver's client extension list */
    DrvExt->ClientIdentificationAddress = ClientIdentAddr;
    DrvExt->NextExtension =DriverObject->ClientDriverExtension;
    DriverObject->ClientDriverExtension = DrvExt;

    /* Return the pointer to the memory immediately after the header */
    *pDriverExtension = DrvExt + 1;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 *
 * Returns the pointer to the beginning of the per-driver context area
 * (ie. the memory immediately after the header) matching the given identifer.
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI PVOID IoGetDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
				       IN PVOID ClientIdentAddr)
{
    PAGED_CODE();
    /* Loop the list until we find the right one */
    for (PIO_CLIENT_EXTENSION DrvExt = DriverObject->ClientDriverExtension;
	 DrvExt != NULL; DrvExt = DrvExt->NextExtension) {
        /* Check if the identifier matches */
        if (DrvExt->ClientIdentificationAddress == ClientIdentAddr) {
	    /* Return the pointer to the memory immediately after the header */
	    return DrvExt + 1;
        }
    }
    return NULL;
}

/*
 * @implemented
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoRegisterDriverReinitialization(IN PDRIVER_OBJECT DriverObject,
					    IN PDRIVER_REINITIALIZE ReinitRoutine,
					    IN PVOID Context)
{
    PAGED_CODE();
    /* Allocate the entry */
    PDRIVER_REINIT_ITEM ReinitItem = ExAllocatePoolWithTag(NonPagedPool,
							   sizeof(DRIVER_REINIT_ITEM),
							   TAG_REINIT);
    if (!ReinitItem) {
	return;
    }

    /* Fill it out */
    ReinitItem->DriverObject = DriverObject;
    ReinitItem->ReinitRoutine = ReinitRoutine;
    ReinitItem->Context = Context;
    ReinitItem->Count = 0;

    /* Set the Driver Object flag and insert the entry into the list */
    DriverObject->Flags |= DRVO_REINIT_REGISTERED;
    InsertTailList(&DriverObject->ReinitListHead, &ReinitItem->ItemEntry);
}

NTAPI NTSTATUS
IoRegisterPlugPlayNotification(IN IO_NOTIFICATION_EVENT_CATEGORY EventCategory,
			       IN ULONG EventCategoryFlags,
			       IN OPTIONAL PVOID EventCategoryData,
			       IN PDRIVER_OBJECT DriverObject,
			       IN PDRIVER_NOTIFICATION_CALLBACK_ROUTINE CallbackRoutine,
			       IN OUT OPTIONAL PVOID Context,
			       OUT PVOID *NotificationEntry)
{
    PAGED_CODE();

    DPRINT("%s(EventCategory 0x%x, EventCategoryFlags 0x%x, DriverObject %p "
	   "EventCategoryData %p) called.\n",
	   __FUNCTION__, EventCategory, EventCategoryFlags, DriverObject,
	   EventCategoryData);

    if (EventCategory == EventCategoryTargetDeviceChange) {
	if (!EventCategoryData) {
	    assert(FALSE);
	    return STATUS_INVALID_PARAMETER;
	}
	PDEVICE_OBJECT DeviceObject = EventCategoryData;
	if (DeviceObject->Header.Type != CLIENT_OBJECT_DEVICE) {
	    assert(FALSE);
	    return STATUS_OBJECT_TYPE_MISMATCH;
	}
    }

    /* Try to allocate entry for notification before sending any notification */
    PPNP_NOTIFY_ENTRY Entry = ExAllocatePoolWithTag(NonPagedPool,
						    sizeof(PNP_NOTIFY_ENTRY),
						    TAG_PNP_NOTIFY);
    if (!Entry) {
	DPRINT("ExAllocatePool() failed\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    Entry->PnpNotificationProc = CallbackRoutine;
    Entry->Context = Context;
    Entry->DriverObject = DriverObject;
    Entry->EventCategory = EventCategory;
    IoInitializeWorkItem(NULL, &Entry->WorkItem);
    GUID EventGuid = {};
    GLOBAL_HANDLE EventDeviceHandle = 0;

    switch (EventCategory) {
    case EventCategoryDeviceInterfaceChange:
	Entry->Guid = *(LPGUID)EventCategoryData;
	EventGuid = Entry->Guid;
	// first register the notification
	InsertTailList(&PiNotifyDeviceInterfaceList, &Entry->PnpNotifyList);
	break;

    case EventCategoryHardwareProfileChange:
	InsertTailList(&PiNotifyHwProfileList, &Entry->PnpNotifyList);
	break;

    case EventCategoryTargetDeviceChange:
	// save it so we can dereference it later
	Entry->DeviceObject = (PDEVICE_OBJECT)EventCategoryData;
	EventDeviceHandle = Entry->DeviceObject->Header.GlobalHandle;
	ObReferenceObject(Entry->DeviceObject);
	InsertTailList(&PiNotifyTargetDeviceList, &Entry->PnpNotifyList);
	break;

    default:
	DPRINT1("%s: unknown EventCategory 0x%x UNIMPLEMENTED\n", __FUNCTION__,
		EventCategory);

	ExFreePoolWithTag(Entry, TAG_PNP_NOTIFY);
	return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS Status = WdmRegisterPlugPlayNotification(EventCategory,
						      &EventGuid, EventDeviceHandle);
    if (!NT_SUCCESS(Status)) {
	RemoveEntryList(&Entry->PnpNotifyList);
	ExFreePoolWithTag(Entry, TAG_PNP_NOTIFY);
	return Status;
    }

    *NotificationEntry = Entry;

    if (EventCategory == EventCategoryDeviceInterfaceChange &&
	(EventCategoryFlags & PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES)) {
	PWSTR SymbolicLinkList;
	Status = IoGetDeviceInterfaces(&Entry->Guid,
				       NULL, /* PhysicalDeviceObject OPTIONAL */
				       0, /* Flags */
				       &SymbolicLinkList);
	if (!NT_SUCCESS(Status)) {
	    return STATUS_SUCCESS;
	}

	/* Enumerate SymbolicLinkList */
	DEVICE_INTERFACE_CHANGE_NOTIFICATION NotificationInfos;
	UNICODE_STRING SymbolicLinkU;
	NotificationInfos.Version = 1;
	NotificationInfos.Size = sizeof(DEVICE_INTERFACE_CHANGE_NOTIFICATION);
	NotificationInfos.Event = GUID_DEVICE_INTERFACE_ARRIVAL;
	NotificationInfos.InterfaceClassGuid = Entry->Guid;
	NotificationInfos.SymbolicLinkName = &SymbolicLinkU;

	for (PWSTR SymbolicLink = SymbolicLinkList; *SymbolicLink;
	     SymbolicLink += (SymbolicLinkU.Length / sizeof(WCHAR)) + 1) {
	    RtlInitUnicodeString(&SymbolicLinkU, SymbolicLink);
	    DPRINT("Calling callback routine for %wZ\n", &SymbolicLinkU);
	    Entry->PnpNotificationProc(&NotificationInfos, Entry->Context);
	}

	ExFreePool(SymbolicLinkList);
    }

    return STATUS_SUCCESS;
}

NTAPI NTSTATUS IoUnregisterPlugPlayNotification(IN PVOID NotificationEntry)
{
    PAGED_CODE();
    PPNP_NOTIFY_ENTRY Entry = NotificationEntry;
    GUID EventGuid = {};
    GLOBAL_HANDLE DeviceHandle = 0;

    DPRINT("%s(NotificationEntry %p) called\n", __FUNCTION__, Entry);

    PLIST_ENTRY List;
    UNREFERENCED_PARAMETER(List);
    switch (Entry->EventCategory) {
    case EventCategoryDeviceInterfaceChange:
	List = &PiNotifyDeviceInterfaceList;
	EventGuid = Entry->Guid;
	break;
    case EventCategoryHardwareProfileChange:
	List = &PiNotifyHwProfileList;
	break;
    case EventCategoryTargetDeviceChange:
	List = &PiNotifyTargetDeviceList;
	assert(Entry->DeviceObject);
	DeviceHandle = Entry->DeviceObject->Header.GlobalHandle;
	ObDereferenceObject(Entry->DeviceObject);
	break;
    default:
	assert(FALSE);
	return STATUS_NOT_SUPPORTED;
    }

    assert(ListHasEntry(List, &Entry->PnpNotifyList));
    WdmUnregisterPlugPlayNotification(Entry->EventCategory,
				      &EventGuid, DeviceHandle);
    RemoveEntryList(&Entry->PnpNotifyList);
    IopRemoveWorkItem(&Entry->WorkItem);
    ExFreePoolWithTag(Entry, TAG_PNP_NOTIFY);
    return STATUS_SUCCESS;
}

NTAPI NTSTATUS IoRegisterShutdownNotification(IN PDEVICE_OBJECT DeviceObject)
{
    PAGED_CODE();
    assert(DeviceObject->Header.GlobalHandle);
    return WdmRegisterShutdownNotification(DeviceObject->Header.GlobalHandle);
}

NTAPI VOID IoUnregisterShutdownNotification(PDEVICE_OBJECT DeviceObject)
{
    PAGED_CODE();
    assert(DeviceObject->Header.GlobalHandle);
    WdmUnregisterShutdownNotification(DeviceObject->Header.GlobalHandle);
}

/*
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI PVOID MmMapIoSpace(IN PHYSICAL_ADDRESS PhysicalAddress,
			 IN SIZE_T NumberOfBytes,
			 IN MEMORY_CACHING_TYPE CacheType)
{
    PAGED_CODE();
    PVOID VirtualAddress = 0;
    if (!NT_SUCCESS(WdmMapIoSpace(PhysicalAddress.QuadPart, NumberOfBytes,
				  CacheType, &VirtualAddress))) {
	return NULL;
    }
    return VirtualAddress;
}

/*
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI VOID MmUnmapIoSpace(IN PVOID BaseAddress,
			  IN SIZE_T NumberOfBytes)
{
    PAGED_CODE();
    WdmUnmapIoSpace(BaseAddress, NumberOfBytes);
}

NTAPI NTSTATUS HalRegisterFrameBuffer(IN PULONG_PTR PfnDb,
				      IN ULONG PfnCount,
				      IN ULONG Offset,
				      IN ULONG Width,
				      IN ULONG Height,
				      IN ULONG Pitch,
				      IN UCHAR BitsPerPixel,
				      IN UCHAR BlueIndex,
				      IN UCHAR GreenIndex,
				      IN UCHAR RedIndex,
				      IN BOOLEAN NeedFlush)
{
    return WdmHalRegisterFrameBuffer(PfnDb, PfnCount, Offset, Width, Height, Pitch,
				     BitsPerPixel, BlueIndex, GreenIndex, RedIndex, NeedFlush);
}

NTAPI NTSTATUS HalUnregisterFrameBuffer(IN ULONG_PTR PhysicalBase)
{
    return WdmHalUnregisterFrameBuffer(PhysicalBase);
}

static PHAL_FRAMEBUFFER_DAMAGE_HANDLER HalpFrameBufferDamageHandler;
NTAPI VOID HalRegisterFrameBufferDamageHandler(IN PHAL_FRAMEBUFFER_DAMAGE_HANDLER Func)
{
    HalpFrameBufferDamageHandler = Func;
}

VOID IopHandleFrameBufferDamage(IN ULONG_PTR PhyBase,
				IN ULONG StartWidth,
				IN ULONG StartHeight,
				IN ULONG EndWidth,
				IN ULONG EndHeight)
{
    if (HalpFrameBufferDamageHandler) {
	HalpFrameBufferDamageHandler(PhyBase, StartWidth, StartHeight, EndWidth, EndHeight);
    }
}
