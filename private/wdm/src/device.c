#include <initguid.h>
#include <wdmp.h>
#include <wdmguid.h>
#define TEXT(x) L##x
#include <regstr.h>

#define GUID_STRING_CHARS 38
#define GUID_STRING_BYTES (GUID_STRING_CHARS * sizeof(WCHAR))
C_ASSERT(sizeof(L"{01234567-89ab-cdef-0123-456789abcdef}") ==
	 GUID_STRING_BYTES + sizeof(UNICODE_NULL));

#define PROFILE_KEY_NAME L"Hardware Profiles\\Current\\System\\CurrentControlSet\\"
#define CLASS_KEY_NAME L"Control\\Class\\"
#define ENUM_KEY_NAME L"Enum\\"
#define DEVICE_PARAMETERS_KEY_NAME L"Device Parameters"
#define BOOT_CONFIG_KEY_NAME L"LogConf"
#define DEVICE_CLASSES_KEY_NAME						\
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DeviceClasses\\"

/* Caches all device objects that have been queried, including
 * the device objects created by this driver. */
LIST_ENTRY IopDeviceList;

/*
 * Search the list of all cached device objects and return
 * the one matching the given GLOBAL_HANDLE. Returns NULL if not found.
 */
PDEVICE_OBJECT IopGetDeviceObject(IN GLOBAL_HANDLE Handle)
{
    LoopOverList(Object, &IopDeviceList, DEVICE_OBJECT, Private.Link) {
	if (Handle == Object->Header.GlobalHandle) {
	    return Object;
	}
    }
    return NULL;
}

/*
 * Search the list of all cached device objects and return the global
 * handle of the given device object pointer.
 */
GLOBAL_HANDLE IopGetDeviceHandle(IN PDEVICE_OBJECT Device)
{
    return Device ? Device->Header.GlobalHandle : 0;
}

/*
 * NOTE: If DriverObject is NULL, it means that this device is created by
 * a foreign driver. Otherwise it must be the local driver object.
 */
static inline VOID IopInitializeDeviceObject(IN PDEVICE_OBJECT DeviceObject,
					     IN ULONG DevExtSize,
					     IN IO_DEVICE_INFO DevInfo,
					     IN GLOBAL_HANDLE DeviceHandle,
					     IN CHAR StackSize,
					     IN PDRIVER_OBJECT DriverObject)
{
    assert(StackSize > 0);
    ObInitializeObject(DeviceObject, CLIENT_OBJECT_DEVICE, DEVICE_OBJECT);
    DeviceObject->Header.Size += DevExtSize;
    DeviceObject->DriverObject = DriverObject;
    DeviceObject->DeviceExtension = DevExtSize ? (PVOID)(DeviceObject + 1) : NULL;
    DeviceObject->DeviceType = DevInfo.DeviceType;
    DeviceObject->Flags = DevInfo.Flags;
    DeviceObject->Header.GlobalHandle = DeviceHandle;
    DeviceObject->StackSize = StackSize;
    assert(IopGetDeviceObject(DeviceHandle) == NULL);
    InsertTailList(&IopDeviceList, &DeviceObject->Private.Link);
}

/*
 * Returns the client-side device object if there is already one with the given
 * global handle. In this case, if Reference is TRUE, the refcount of the returned
 * device object will be increased by one. Otherwise, create the client-side device
 * object and return it (NULL is returned if we are out of memory). In this case,
 * the newly created device object will have a refcount of one.
 */
PDEVICE_OBJECT IopGetDeviceObjectOrCreate(IN GLOBAL_HANDLE DeviceHandle,
					  IN IO_DEVICE_INFO DevInfo,
					  IN CHAR StackSize,
					  IN BOOLEAN Reference)
{
    PDEVICE_OBJECT DeviceObject = IopGetDeviceObject(DeviceHandle);
    if (DeviceObject == NULL) {
	DeviceObject = (PDEVICE_OBJECT)ExAllocatePool(NonPagedPool,
						      sizeof(DEVICE_OBJECT));
	if (DeviceObject == NULL) {
	    return NULL;
	}
	IopInitializeDeviceObject(DeviceObject, 0, DevInfo, DeviceHandle, StackSize, NULL);
    } else {
	assert(StackSize >= DeviceObject->StackSize);
	DeviceObject->StackSize = StackSize;
	if (Reference) {
	    ObReferenceObject(DeviceObject);
	}
    }
    assert(DeviceObject != NULL);
    return DeviceObject;
}

/*
 * Allocates the client side DEVICE_OBJECT and calls server to create
 * the device object.
 *
 * Note: DeviceName must be a full path.
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoCreateDevice(IN PDRIVER_OBJECT DriverObject,
			      IN ULONG DeviceExtensionSize,
			      IN PUNICODE_STRING DeviceName OPTIONAL,
			      IN DEVICE_TYPE DeviceType,
			      IN ULONG64 Flags,
			      IN BOOLEAN Exclusive,
			      OUT PDEVICE_OBJECT *pDeviceObject)
{
    assert(DriverObject != NULL);
    assert(pDeviceObject != NULL);
    PAGED_CODE();

    /* Both device object and device extension are aligned by MEMORY_ALLOCATION_ALIGNMENT */
    SIZE_T AlignedDevExtSize = ALIGN_UP_BY(DeviceExtensionSize,
					   MEMORY_ALLOCATION_ALIGNMENT);

    /* The driver-specific device extension follows the DEVICE_OBJECT */
    SIZE_T TotalSize = sizeof(DEVICE_OBJECT) + AlignedDevExtSize;
    IopAllocatePool(DeviceObject, DEVICE_OBJECT, TotalSize);

    IO_DEVICE_INFO DevInfo = {
	.DeviceType = DeviceType,
	.Flags = Flags
    };

    GLOBAL_HANDLE DeviceHandle = 0;
    RET_ERR_EX(WdmCreateDevice(DeviceName, &DevInfo, Exclusive, &DeviceHandle),
	       IopFreePool(DeviceObject));
    assert(DeviceHandle != 0);
    assert(IopGetDeviceObject(DeviceHandle) == NULL);

    /* Initially the device object will have a device stack size of one. */
    IopInitializeDeviceObject(DeviceObject, DeviceExtensionSize,
			      DevInfo, DeviceHandle, 1, DriverObject);
    DeviceObject->Flags |= DO_DEVICE_INITIALIZING;
    if (Exclusive) {
	DeviceObject->Flags |= DO_EXCLUSIVE;
    }
    if (DeviceName) {
	DeviceObject->Flags |= DO_DEVICE_HAS_NAME;
	RtlDuplicateUnicodeString(0, DeviceName, &DeviceObject->DeviceName);
    }
    KeInitializeDeviceQueue(&DeviceObject->DeviceQueue);

    /* Set the correct sector size. */
    DeviceObject->SectorSize = IopDeviceTypeToSectorSize(DeviceType);

    *pDeviceObject = DeviceObject;
    DbgTrace("Created device object %p handle %p extension %p driver %p name %ws "
	     "buffered-io %d direct-io %d\n",
	     DeviceObject, (PVOID)DeviceHandle, DeviceObject->DeviceExtension,
	     DeviceObject->DriverObject, DeviceName ? DeviceName->Buffer : L"(nil)",
	     !!(DeviceObject->Flags & DO_BUFFERED_IO),
	     !!(DeviceObject->Flags & DO_DIRECT_IO));
    return STATUS_SUCCESS;
}

NTAPI VOID IoDeleteDevice(IN PDEVICE_OBJECT DeviceObject)
{
    PAGED_CODE();
    /* We simply dereference the device object. The actual deletion will happen when
     * there are no outstanding reference to it. */
    ObDereferenceObject(DeviceObject);
}

VOID IopDeleteDeviceObject(IN PDEVICE_OBJECT DeviceObject)
{
    DbgTrace("Deleting client-side device object %p (global handle %p driver object %p\n",
	     DeviceObject, (PVOID)DeviceObject->Header.GlobalHandle,
	     DeviceObject->DriverObject);
    assert(!DeviceObject->Header.RefCount);

    /* Call the server to notify it that we have cleaned up our local references to the
     * global handle, and it can delete the server-side object and reuse the global handle
     * if needed. */
    assert(DeviceObject->Header.GlobalHandle);
    WdmDeleteDevice(DeviceObject->Header.GlobalHandle);

    if (DeviceObject->Vpb) {
	PVPB Vpb = DeviceObject->Vpb;
	if (Vpb->DeviceObject) {
	    Vpb->DeviceObject->Vpb = NULL;
	}
	if (Vpb->RealDevice) {
	    Vpb->RealDevice->Vpb = NULL;
	}
	IopFreePool(Vpb);
    }

    assert(ListHasEntry(&IopDeviceList, &DeviceObject->Private.Link));
    RemoveEntryList(&DeviceObject->Private.Link);
#if DBG
    RtlZeroMemory(DeviceObject, sizeof(DEVICE_OBJECT));
#endif
    IopFreePool(DeviceObject);
}

NTAPI NTSTATUS IoGetDeviceObjectPointer(IN PUNICODE_STRING ObjectName,
					IN ACCESS_MASK DesiredAccess,
					OUT PDEVICE_OBJECT *DeviceObject)
{
    PAGED_CODE();
    *DeviceObject = NULL;

    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK StatusBlock;
    HANDLE FileHandle;

    /* Open the Device */
    InitializeObjectAttributes(&ObjectAttributes,
                               ObjectName,
                               OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);
    NTSTATUS Status = NtOpenFile(&FileHandle,
				 DesiredAccess,
				 &ObjectAttributes,
				 &StatusBlock,
				 0,
				 FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    GLOBAL_HANDLE TopDeviceHandle;
    IO_DEVICE_INFO TopDeviceInfo;
    ULONG TopDeviceStackSize;
    Status = WdmGetTopDeviceObject(FileHandle, &TopDeviceHandle,
				   &TopDeviceInfo, &TopDeviceStackSize);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    *DeviceObject = IopGetDeviceObjectOrCreate(TopDeviceHandle, TopDeviceInfo,
					       TopDeviceStackSize, TRUE);
    Status = *DeviceObject ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;

out:
    NtClose(FileHandle);
    return Status;
}

/*
 * @implemented
 *
 * Call the server to attach the SourceDevice on top of the device
 * stack of TargetDevice, returning the previous topmost device
 * object in the device stack.
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI PDEVICE_OBJECT IoAttachDeviceToDeviceStack(IN PDEVICE_OBJECT SourceDevice,
						 IN PDEVICE_OBJECT TargetDevice)
{
    PAGED_CODE();

    GLOBAL_HANDLE SourceHandle = IopGetDeviceHandle(SourceDevice);
    GLOBAL_HANDLE TargetHandle = IopGetDeviceHandle(TargetDevice);
    if ((SourceHandle == 0) || (TargetHandle == 0)) {
	assert(FALSE);
	return NULL;
    }
    PDEVICE_OBJECT OldTopDevice = (PDEVICE_OBJECT)ExAllocatePool(NonPagedPool,
								 sizeof(DEVICE_OBJECT));
    if (OldTopDevice == NULL) {
	return NULL;
    }
    GLOBAL_HANDLE OldTopHandle = 0;
    IO_DEVICE_INFO DevInfo;
    ULONG StackSize = 0;
    if (!NT_SUCCESS(WdmAttachDeviceToDeviceStack(SourceHandle, TargetHandle,
						 &OldTopHandle, &DevInfo, &StackSize))) {
	IopFreePool(OldTopDevice);
	return NULL;
    }
    assert(OldTopHandle != 0);
    assert(StackSize);
    PDEVICE_OBJECT RetVal = IopGetDeviceObject(OldTopHandle);
    if (RetVal == NULL) {
	IopInitializeDeviceObject(OldTopDevice, 0, DevInfo, OldTopHandle, StackSize, NULL);
	RetVal = OldTopDevice;
    } else {
	IopFreePool(OldTopDevice);
    }
    SourceDevice->StackSize = StackSize + 1;
    return RetVal;
}

/*++
 * @name IoGetAttachedDevice
 * @implemented
 *
 * Returns the pointer to the highest level device object in the device stack
 * of the given device object. This routine makes a call to the server so
 * that we always get the most up-to-date device object.
 *
 * This routine increases the refcount of the object.
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI PDEVICE_OBJECT IoGetAttachedDeviceReference(IN PDEVICE_OBJECT DeviceObject)
{
    PAGED_CODE();

    GLOBAL_HANDLE Handle = IopGetDeviceHandle(DeviceObject);
    if (Handle == 0) {
	return NULL;
    }
    GLOBAL_HANDLE TopHandle = 0;
    IO_DEVICE_INFO DevInfo;
    ULONG StackSize = 0;
    if (!NT_SUCCESS(WdmGetAttachedDevice(Handle, &TopHandle, &DevInfo, &StackSize))) {
	return NULL;
    }
    assert(TopHandle != 0);
    return IopGetDeviceObjectOrCreate(TopHandle, DevInfo, StackSize, TRUE);
}

/*
 * @unimplemented
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoDetachDevice(IN PDEVICE_OBJECT TargetDevice)
{
    PAGED_CODE();

    UNIMPLEMENTED;
}

static NTSTATUS IopQueueDeviceChangeEvent(LPCGUID EventGuid,
					  PGUID DeviceGuid,
					  PUNICODE_STRING SymbolicName)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI VOID IoInvalidateDeviceRelations(IN PDEVICE_OBJECT DeviceObject,
				       IN DEVICE_RELATION_TYPE Type)
{
    /* TODO: Queue device relation invalidation message */
}

NTAPI NTSTATUS
IoReportTargetDeviceChangeAsynchronous(IN PDEVICE_OBJECT Pdo,
				       IN PVOID Notification,
				       IN OPTIONAL PDEVICE_CHANGE_COMPLETE_CALLBACK Callback,
				       IN OPTIONAL PVOID Context)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS IopGetDeviceInstancePath(IN PDEVICE_OBJECT DeviceObject,
					 OUT PUNICODE_STRING InstancePath)
{
    ULONG BufferSize = 0;
    WCHAR Buffer[256];
    NTSTATUS Status = WdmGetDeviceProperty(DeviceObject->Header.GlobalHandle,
					   DevicePropertyInstancePath,
					   sizeof(Buffer), Buffer, &BufferSize);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
	return Status;
    }
    PWCHAR Path = ExAllocatePool(NonPagedPool, BufferSize);
    if (!Path) {
	return STATUS_NO_MEMORY;
    }
    if (Status == STATUS_BUFFER_TOO_SMALL) {
	Status = WdmGetDeviceProperty(DeviceObject->Header.GlobalHandle,
				      DevicePropertyInstancePath,
				      BufferSize, Path, &BufferSize);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    } else {
	RtlCopyMemory(Path, Buffer, BufferSize);
    }
    InstancePath->Buffer = Path;
    InstancePath->Length = BufferSize - sizeof(WCHAR);
    assert(InstancePath->Length == wcslen(Path) * sizeof(WCHAR));
    InstancePath->MaximumLength = BufferSize;
    return STATUS_SUCCESS;
}

/*
 * Returns the alias device interface of the specified device interface
 */
static NTSTATUS IopOpenInterfaceKey(IN CONST GUID *InterfaceClassGuid,
				    IN ACCESS_MASK DesiredAccess,
				    OUT HANDLE *pInterfaceKey)
{
    UNICODE_STRING LocalMachine = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\");
    UNICODE_STRING GuidString;
    UNICODE_STRING KeyName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE InterfaceKey = NULL;
    NTSTATUS Status;

    GuidString.Buffer = KeyName.Buffer = NULL;

    Status = RtlStringFromGUID(InterfaceClassGuid, &GuidString);
    if (!NT_SUCCESS(Status)) {
	DPRINT("RtlStringFromGUID() failed with status 0x%08x\n", Status);
	goto cleanup;
    }

    KeyName.Length = 0;
    KeyName.MaximumLength = LocalMachine.Length +
	((USHORT)wcslen(REGSTR_PATH_DEVICE_CLASSES) + 1) * sizeof(WCHAR) +
	GuidString.Length;
    KeyName.Buffer = ExAllocatePool(NonPagedPool, KeyName.MaximumLength);
    if (!KeyName.Buffer) {
	DPRINT("ExAllocatePool() failed\n");
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto cleanup;
    }

    Status = RtlAppendUnicodeStringToString(&KeyName, &LocalMachine);
    if (!NT_SUCCESS(Status)) {
	DPRINT("RtlAppendUnicodeStringToString() failed with status 0x%08x\n", Status);
	goto cleanup;
    }
    Status = RtlAppendUnicodeToString(&KeyName, REGSTR_PATH_DEVICE_CLASSES);
    if (!NT_SUCCESS(Status)) {
	DPRINT("RtlAppendUnicodeToString() failed with status 0x%08x\n", Status);
	goto cleanup;
    }
    Status = RtlAppendUnicodeToString(&KeyName, L"\\");
    if (!NT_SUCCESS(Status)) {
	DPRINT("RtlAppendUnicodeToString() failed with status 0x%08x\n", Status);
	goto cleanup;
    }
    Status = RtlAppendUnicodeStringToString(&KeyName, &GuidString);
    if (!NT_SUCCESS(Status)) {
	DPRINT("RtlAppendUnicodeStringToString() failed with status 0x%08x\n", Status);
	goto cleanup;
    }

    InitializeObjectAttributes(&ObjectAttributes, &KeyName,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenKey(&InterfaceKey, DesiredAccess, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	DPRINT("NtOpenKey() failed with status 0x%08x\n", Status);
	goto cleanup;
    }

    *pInterfaceKey = InterfaceKey;
    Status = STATUS_SUCCESS;

cleanup:
    if (!NT_SUCCESS(Status)) {
	if (InterfaceKey != NULL)
	    NtClose(InterfaceKey);
    }
    RtlFreeUnicodeString(&GuidString);
    RtlFreeUnicodeString(&KeyName);
    return Status;
}


static inline NTSTATUS IopReadRegValue(IN HANDLE KeyHandle,
				       IN PWCHAR ValueName,
				       IN ULONG ValueType,
				       IN ULONG BufferSize,
				       OUT PVOID Data,
				       OUT OPTIONAL ULONG *DataLength)
{
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = NULL;
    NTSTATUS Status = IopQueryValueKey(KeyHandle, ValueName, &PartialInfo);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    if (DataLength) {
	*DataLength = PartialInfo->DataLength;
    }
    if (PartialInfo->Type != ValueType) {
	Status = STATUS_OBJECT_TYPE_MISMATCH;
	goto out;
    }
    if (PartialInfo->DataLength > BufferSize) {
	Status = STATUS_BUFFER_TOO_SMALL;
	goto out;
    }
    RtlCopyMemory(Data, PartialInfo->Data, PartialInfo->DataLength);
    Status = STATUS_SUCCESS;
out:
    ExFreePool(PartialInfo);
    return Status;
}

/**
 * @brief
 * Parses the specified symbolic link onto the 4 parts: prefix, device string,
 * class GUID and reference string.
 *
 * @param[in] SymbolicLinkName
 * Pointer to a symbolic link string to parse.
 *
 * @param[out] PrefixString
 * Receives prefix of symbolic link. Can be '\??\' for Kernel mode or '\\?\' for User
 * mode.
 *
 * @param[out] MungedString
 * Receives device string. For example, ##?#ACPI#PNP0501#1#.
 *
 * @param[out] GuidString
 * Receives device interface class GUID string represented by device interface.
 * For example, {01234567-89ab-cdef-0123-456789abcdef}.
 *
 * @param[out] ReferenceString
 * Receives reference string, if any. Usually contains a human-readable
 * subdevice name or class GUID.
 *
 * @param[out] ReferenceStringPresent
 * Pointer to variable that indicates whether the reference string exists in symbolic
 * link. TRUE if it does, FALSE otherwise.
 *
 * @param[out] InterfaceClassGuid
 * Receives the interface class GUID to which specified symbolic link belongs to.
 *
 * @return
 * STATUS_SUCCESS in case of success, or an NTSTATUS error code otherwise.
 **/
static NTSTATUS IopSeparateSymbolicLink(IN PCUNICODE_STRING SymbolicLinkName,
					OUT OPTIONAL PUNICODE_STRING PrefixString,
					OUT OPTIONAL PUNICODE_STRING MungedString,
					OUT OPTIONAL PUNICODE_STRING GuidString,
					OUT OPTIONAL PUNICODE_STRING ReferenceString,
					OUT OPTIONAL PBOOLEAN ReferenceStringPresent,
					OUT OPTIONAL LPGUID InterfaceClassGuid)
{
    static const UNICODE_STRING KernelModePrefix = RTL_CONSTANT_STRING(L"\\??\\");
    static const UNICODE_STRING UserModePrefix = RTL_CONSTANT_STRING(L"\\\\?\\");
    UNICODE_STRING MungedStringReal, GuidStringReal, ReferenceStringReal;
    UNICODE_STRING LinkNameNoPrefix;
    USHORT i, ReferenceStringOffset;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("Symbolic link is %wZ\n", SymbolicLinkName);

    /* The symbolic link name looks like \??\ACPI#PNP0501#1#{GUID}\ReferenceString
     * Make sure it starts with the expected prefix. */
    if (!RtlPrefixUnicodeString(&KernelModePrefix, SymbolicLinkName, FALSE) &&
	!RtlPrefixUnicodeString(&UserModePrefix, SymbolicLinkName, FALSE)) {
	DPRINT1("Invalid link name %wZ\n", SymbolicLinkName);
	return STATUS_INVALID_PARAMETER;
    }

    /* Sanity checks */
    ASSERT(KernelModePrefix.Length == UserModePrefix.Length);
    ASSERT(SymbolicLinkName->Length >= KernelModePrefix.Length);

    /* Make a version without the prefix for further processing */
    LinkNameNoPrefix.Buffer = SymbolicLinkName->Buffer +
			      KernelModePrefix.Length / sizeof(WCHAR);
    LinkNameNoPrefix.Length = SymbolicLinkName->Length - KernelModePrefix.Length;
    LinkNameNoPrefix.MaximumLength = LinkNameNoPrefix.Length;

    DPRINT("Symbolic link without prefix is %wZ\n", &LinkNameNoPrefix);

    /* Find the reference string, if any */
    for (i = 0; i < LinkNameNoPrefix.Length / sizeof(WCHAR); i++) {
	if (LinkNameNoPrefix.Buffer[i] == L'\\')
	    break;
    }
    ReferenceStringOffset = i * sizeof(WCHAR);

    /* The GUID is before the reference string or at the end */
    ASSERT(LinkNameNoPrefix.Length >= ReferenceStringOffset);
    if (ReferenceStringOffset < GUID_STRING_BYTES + sizeof(WCHAR)) {
	DPRINT1("Invalid link name %wZ\n", SymbolicLinkName);
	return STATUS_INVALID_PARAMETER;
    }

    /* Get reference string (starts with \ after {GUID}) from link without prefix */
    ReferenceStringReal.Buffer = LinkNameNoPrefix.Buffer +
				 ReferenceStringOffset / sizeof(WCHAR);
    ReferenceStringReal.Length = LinkNameNoPrefix.Length - ReferenceStringOffset;
    ReferenceStringReal.MaximumLength = ReferenceStringReal.Length;

    DPRINT("Reference string is %wZ\n", &ReferenceStringReal);

    /* Get GUID string (device class GUID in {} brackets) */
    GuidStringReal.Buffer = LinkNameNoPrefix.Buffer +
			    (ReferenceStringOffset - GUID_STRING_BYTES) / sizeof(WCHAR);
    GuidStringReal.Length = GUID_STRING_BYTES;
    GuidStringReal.MaximumLength = GuidStringReal.Length;

    DPRINT("GUID string is %wZ\n", &GuidStringReal);

    /* Validate GUID string for:
     * 1) {} brackets at the start and the end;
     * 2) - separators in the appropriate places. */
    ASSERT(GuidStringReal.Buffer[0] == L'{');
    ASSERT(GuidStringReal.Buffer[GUID_STRING_CHARS - 1] == L'}');
    ASSERT(GuidStringReal.Buffer[9] == L'-');
    ASSERT(GuidStringReal.Buffer[14] == L'-');
    ASSERT(GuidStringReal.Buffer[19] == L'-');
    ASSERT(GuidStringReal.Buffer[24] == L'-');

    if (MungedString) {
	/* Create a munged path string (looks like ACPI#PNP0501#1#) */
	MungedStringReal.Buffer = LinkNameNoPrefix.Buffer;
	MungedStringReal.Length = LinkNameNoPrefix.Length - ReferenceStringReal.Length -
				  GUID_STRING_BYTES - sizeof(WCHAR);
	MungedStringReal.MaximumLength = MungedStringReal.Length;

	DPRINT("Munged string is %wZ\n", &MungedStringReal);
    }

    /* Store received parts if the parameters are not null */
    if (PrefixString) {
	PrefixString->Buffer = SymbolicLinkName->Buffer;
	PrefixString->Length = KernelModePrefix.Length; // Same as UserModePrefix.Length
	PrefixString->MaximumLength = PrefixString->Length;

	DPRINT("Prefix string is %wZ\n", PrefixString);
    }

    if (MungedString)
	*MungedString = MungedStringReal;

    if (GuidString)
	*GuidString = GuidStringReal;

    if (ReferenceString) {
	if (ReferenceStringReal.Length > sizeof(WCHAR))
	    *ReferenceString = ReferenceStringReal;
	else
	    RtlInitEmptyUnicodeString(ReferenceString, NULL, 0);
    }

    if (ReferenceStringPresent)
	*ReferenceStringPresent = ReferenceStringReal.Length > sizeof(WCHAR);

    if (InterfaceClassGuid) {
	/* Convert GUID string into a GUID and store it also */
	Status = RtlGUIDFromString(&GuidStringReal, InterfaceClassGuid);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("RtlGUIDFromString() failed, Status 0x%08x\n", Status);
	}
    }

    /* We're done */
    return Status;
}

/*
 * Create registry key. If parent keys do not exist, this routine creates them recursively.
 */
static NTSTATUS IopCreateKeyEx(OUT PHANDLE Handle,
			       IN OPTIONAL HANDLE RootHandle,
			       IN PUNICODE_STRING KeyName,
			       IN ACCESS_MASK DesiredAccess,
			       IN ULONG CreateOptions,
			       OUT OPTIONAL PULONG Disposition)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG KeyDisposition, RootHandleIndex = 0, i = 1, NestedCloseLevel = 0;
    USHORT Length;
    HANDLE HandleArray[2];
    BOOLEAN Recursing = TRUE;
    PWCHAR pp, p, p1;
    UNICODE_STRING KeyString;
    NTSTATUS Status = STATUS_SUCCESS;
    PAGED_CODE();

    /* P1 is start, pp is end */
    p1 = KeyName->Buffer;
    assert(!(KeyName->Length & 1));
    pp = p1 + KeyName->Length / sizeof(WCHAR);

    /* Create the target key */
    InitializeObjectAttributes(&ObjectAttributes, KeyName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, RootHandle,
			       NULL);
    Status = NtCreateKey(&HandleArray[i], DesiredAccess, &ObjectAttributes, 0, NULL,
			 CreateOptions, &KeyDisposition);

    /* Now we check if this failed */
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_NAME_INVALID) {
	/* Target key failed, so we'll need to create its parent.
	 * If you did not specify a root handle, you must specify an absolute path
	 * that begins with L"\\Registry\\Machine\\System\\CurrentControlSet\\",
	 * which we will try to create. */
	if (!RootHandle) {
	    UNICODE_STRING Prefix;
	    RtlInitUnicodeString(&Prefix,
				 L"\\Registry\\Machine\\System\\CurrentControlSet\\");
	    if (!RtlPrefixUnicodeString(&Prefix, KeyName, TRUE)) {
		assert(FALSE);
		return STATUS_INVALID_PARAMETER;
	    }
	    p1 += Prefix.Length / sizeof(WCHAR);

	    Prefix.Length -= sizeof(WCHAR);
	    InitializeObjectAttributes(&ObjectAttributes, &Prefix,
				       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				       NULL, NULL);
	    Status = NtCreateKey(&RootHandle, DesiredAccess, &ObjectAttributes, 0,
				 NULL, CreateOptions, &KeyDisposition);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	    assert(RootHandle);
	}

	HandleArray[0] = NULL;
	HandleArray[1] = RootHandle;

	/* Keep recursing for each missing parent */
	while (Recursing) {
	    /* And if we're deep enough, close the last handle */
	    if (NestedCloseLevel > 1)
		NtClose(HandleArray[RootHandleIndex]);

	    /* We're setup to ping-pong between the two handle array entries */
	    RootHandleIndex = i;
	    i = (i + 1) & 1;

	    /* Clear the one we're attempting to open now */
	    HandleArray[i] = NULL;

	    /* Process the parent key name */
	    for (p = p1; ((p < pp) && (*p != OBJ_NAME_PATH_SEPARATOR)); p++)
		;
	    Length = (USHORT)(p - p1) * sizeof(WCHAR);

	    /* Is there a parent name? */
	    if (Length) {
		/* Build the unicode string for it */
		KeyString.Buffer = p1;
		KeyString.Length = KeyString.MaximumLength = Length;

		/* Now try opening the parent */
		InitializeObjectAttributes(&ObjectAttributes, &KeyString,
					   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
					   HandleArray[RootHandleIndex], NULL);
		Status = NtCreateKey(&HandleArray[i], DesiredAccess, &ObjectAttributes, 0,
				     NULL, CreateOptions, &KeyDisposition);
		if (NT_SUCCESS(Status)) {
		    /* It worked, we have one more handle */
		    NestedCloseLevel++;
		} else {
		    /* Parent key creation failed, abandon loop */
		    Recursing = FALSE;
		    continue;
		}
	    } else {
		/* We don't have a parent name, probably corrupted key name */
		Status = STATUS_INVALID_PARAMETER;
		Recursing = FALSE;
		continue;
	    }

	    /* Now see if there's more parents to create */
	    p1 = p + 1;
	    if ((p == pp) || (p1 == pp)) {
		/* We're done, hopefully successfully, so stop */
		Recursing = FALSE;
	    }
	}

	/* Outer loop check for handle nesting that requires closing the top handle */
	if (NestedCloseLevel > 1)
	    NtClose(HandleArray[RootHandleIndex]);
    }

    /* Check if we broke out of the loop due to success */
    if (NT_SUCCESS(Status)) {
	/* Return the target handle (we closed all the parent ones) and disposition */
	*Handle = HandleArray[i];
	if (Disposition)
	    *Disposition = KeyDisposition;
    }

    /* Return the success state */
    return Status;
}

/**
 * @brief
 * Retrieves a handles to the device and instance registry keys
 * for the previously opened registry key handle of the specified symbolic link.
 **/
static NTSTATUS IopOpenOrCreateSymbolicLinkSubKeys(OUT OPTIONAL PHANDLE DeviceHandle,
						   OUT OPTIONAL PULONG DeviceDisposition,
						   OUT OPTIONAL PHANDLE InstanceHandle,
						   OUT OPTIONAL PULONG InstanceDisposition,
						   IN HANDLE ClassHandle,
						   IN PCUNICODE_STRING SymbolicLinkName,
						   IN ACCESS_MASK DesiredAccess,
						   IN BOOLEAN Create)
{
    UNICODE_STRING ReferenceString = {};
    UNICODE_STRING SymbolicLink = {};
    HANDLE DeviceKeyHandle = NULL, InstanceKeyHandle = NULL;
    ULONG DeviceKeyDisposition, InstanceKeyDisposition;
    BOOLEAN ReferenceStringPresent = FALSE; /* Assuming no ref string by default */
    NTSTATUS Status;
    USHORT i;

    /* Duplicate the symbolic link (we'll modify it later) */
    Status = RtlDuplicateUnicodeString(0, SymbolicLinkName, &SymbolicLink);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("RtlDuplicateUnicodeString() failed, Status 0x%08x\n", Status);
	goto Quit;
    }

    /* Separate it into its constituents */
    Status = IopSeparateSymbolicLink(&SymbolicLink, NULL, NULL, NULL, &ReferenceString,
				     &ReferenceStringPresent, NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to separate symbolic link %wZ, Status 0x%08x\n", &SymbolicLink,
		Status);
	goto Quit;
    }

    /* Did we got a ref string? */
    if (ReferenceStringPresent) {
	/* Remove it from our symbolic link */
	SymbolicLink.MaximumLength = SymbolicLink.Length -= ReferenceString.Length;

	/* Replace the 1st backslash `\` character by '#' pound */
	ReferenceString.Buffer[0] = L'#';
    } else {
	/* No ref string, initialize it with a single pound character '#' */
	RtlInitUnicodeString(&ReferenceString, L"#");
    }

    /* Replace all '\' by '#' in symbolic link */
    for (i = 0; i < SymbolicLink.Length / sizeof(WCHAR); i++) {
	if (SymbolicLink.Buffer[i] == L'\\')
	    SymbolicLink.Buffer[i] = L'#';
    }

    /* Fix prefix: '#??#' -> '##?#' */
    SymbolicLink.Buffer[1] = L'#';

    DPRINT("Munged symbolic link is %wZ\n", &SymbolicLink);

    /* Try to open or create device interface keys */
    if (Create) {
	Status = IopCreateKeyEx(&DeviceKeyHandle, ClassHandle, &SymbolicLink,
				DesiredAccess | KEY_ENUMERATE_SUB_KEYS,
				REG_OPTION_NON_VOLATILE, &DeviceKeyDisposition);
    } else {
	Status = IopOpenKeyEx(&DeviceKeyHandle, ClassHandle, &SymbolicLink,
			      DesiredAccess | KEY_ENUMERATE_SUB_KEYS);
    }

    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to create or open %wZ, Status 0x%08x\n", &SymbolicLink, Status);
	goto Quit;
    }

    DPRINT("Munged reference string is %wZ\n", &ReferenceString);

    /* Try to open or create instance subkeys */
    if (Create) {
	Status = IopCreateKeyEx(&InstanceKeyHandle, DeviceKeyHandle,
				&ReferenceString, DesiredAccess,
				REG_OPTION_NON_VOLATILE, &InstanceKeyDisposition);
    } else {
	Status = IopOpenKeyEx(&InstanceKeyHandle, DeviceKeyHandle,
			      &ReferenceString, DesiredAccess);
    }

    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to create or open %wZ, Status 0x%08x\n", &ReferenceString,
		Status);
	goto Quit;
    }

    Status = STATUS_SUCCESS;

Quit:
    if (NT_SUCCESS(Status)) {
	if (DeviceHandle)
	    *DeviceHandle = DeviceKeyHandle;
	else
	    NtClose(DeviceKeyHandle);

	if (DeviceDisposition)
	    *DeviceDisposition = DeviceKeyDisposition;

	if (InstanceHandle)
	    *InstanceHandle = InstanceKeyHandle;
	else
	    NtClose(InstanceKeyHandle);

	if (InstanceDisposition)
	    *InstanceDisposition = InstanceKeyDisposition;
    } else {
	if (InstanceKeyHandle)
	    NtClose(InstanceKeyHandle);

	if (Create)
	    NtDeleteKey(DeviceKeyHandle);

	if (DeviceKeyHandle)
	    NtClose(DeviceKeyHandle);
    }

    if (SymbolicLink.Buffer)
	RtlFreeUnicodeString(&SymbolicLink);

    return Status;
}

/**
 * @brief
 * Retrieves a handles to the GUID, device and instance registry keys
 * for the specified symbolic link.
 **/
static NTSTATUS OpenRegistryHandlesFromSymbolicLink(IN PCUNICODE_STRING SymbolicLinkName,
						    IN ACCESS_MASK DesiredAccess,
						    OUT OPTIONAL PHANDLE GuidKey,
						    OUT OPTIONAL PHANDLE DeviceKey,
						    OUT OPTIONAL PHANDLE InstanceKey)
{
    UNICODE_STRING BaseKeyU = {};
    UNICODE_STRING GuidString = {};
    HANDLE ClassesKey = NULL;
    HANDLE GuidKeyReal = NULL;
    HANDLE DeviceKeyReal = NULL;
    HANDLE InstanceKeyReal = NULL;

    RtlInitUnicodeString(&BaseKeyU, DEVICE_CLASSES_KEY_NAME);

    /* Separate symbolic link onto the parts */
    NTSTATUS Status = IopSeparateSymbolicLink(SymbolicLinkName, NULL, NULL,
					      &GuidString, NULL, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to parse symbolic link %wZ, Status 0x%08x\n",
		SymbolicLinkName, Status);
	goto Quit;
    }

    /* Open the DeviceClasses key. We need to skip the trailing '\\' */
    BaseKeyU.Length -= sizeof(WCHAR);
    Status = IopOpenKeyEx(&ClassesKey, NULL, &BaseKeyU,
			  DesiredAccess | KEY_ENUMERATE_SUB_KEYS);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to open %wZ, Status 0x%08x\n", &BaseKeyU, Status);
	goto Quit;
    }
    BaseKeyU.Length += sizeof(WCHAR);

    /* Open the GUID subkey */
    Status = IopOpenKeyEx(&GuidKeyReal, ClassesKey, &GuidString,
			  DesiredAccess | KEY_ENUMERATE_SUB_KEYS);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to open %wZ%wZ, Status 0x%08x\n", &BaseKeyU, &GuidString,
		Status);
	goto Quit;
    }

    /* Open the device and instance subkeys */
    Status = IopOpenOrCreateSymbolicLinkSubKeys(&DeviceKeyReal, NULL, &InstanceKeyReal,
						NULL, GuidKeyReal, SymbolicLinkName,
						DesiredAccess, FALSE);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to open %wZ%wZ, Status 0x%08x\n", &BaseKeyU, &GuidString,
		Status);
	goto Quit;
    }

    Status = STATUS_SUCCESS;

Quit:
    if (NT_SUCCESS(Status)) {
	if (GuidKey)
	    *GuidKey = GuidKeyReal;
	else
	    NtClose(GuidKeyReal);

	if (DeviceKey)
	    *DeviceKey = DeviceKeyReal;
	else
	    NtClose(DeviceKeyReal);

	if (InstanceKey)
	    *InstanceKey = InstanceKeyReal;
	else
	    NtClose(InstanceKeyReal);
    } else {
	if (GuidKeyReal)
	    NtClose(GuidKeyReal);

	if (DeviceKeyReal)
	    NtClose(DeviceKeyReal);

	if (InstanceKeyReal)
	    NtClose(InstanceKeyReal);
    }

    if (ClassesKey)
	NtClose(ClassesKey);

    return Status;
}

/*++
 * @name IoRegisterDeviceInterface
 * @implemented
 *
 * Registers a device interface class, if it has not been previously registered,
 * and creates a new instance of the interface class, which a driver can
 * subsequently enable for use by applications or other system components.
 * Documented in WDK.
 *
 * @param PhysicalDeviceObject
 *        Points to an optional PDO that narrows the search to only the
 *        device interfaces of the device represented by the PDO
 *
 * @param InterfaceClassGuid
 *        Points to a class GUID specifying the device interface class
 *
 * @param ReferenceString
 *        Optional parameter, pointing to a unicode string. For a full
 *        description of this rather rarely used param (usually drivers
 *        pass NULL here) see WDK
 *
 * @param SymbolicLinkName
 *        Pointer to the resulting unicode string
 *
 * @return Returns STATUS_SUCCESS if the interface registration is successful.
 *         Returns STATUS_INVALID_DEVICE_REQUEST if registration failed.
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 *
 *--*/
NTAPI NTSTATUS IoRegisterDeviceInterface(IN PDEVICE_OBJECT PhysicalDeviceObject,
					 IN CONST GUID *InterfaceClassGuid,
					 IN OPTIONAL PUNICODE_STRING ReferenceString,
					 OUT PUNICODE_STRING SymbolicLinkName)
{
    PAGED_CODE();

    WCHAR PdoName[256] = {};
    ULONG PdoNameLength = 0;
    UNICODE_STRING DeviceInstance = RTL_CONSTANT_STRING(L"DeviceInstance");
    UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"SymbolicLink");
    UNICODE_STRING InstancePath = {};
    UNICODE_STRING GuidString = {};
    UNICODE_STRING SubKeyName = {};
    UNICODE_STRING InterfaceKeyName = {};
    HANDLE ClassKey = NULL;
    HANDLE InterfaceKey = NULL;
    HANDLE SubKey = NULL;

    DPRINT("IoRegisterDeviceInterface(): PDO %p, RefString: %wZ\n", PhysicalDeviceObject,
	   ReferenceString);

    if (ReferenceString != NULL) {
	/* Reference string must not contain path-separator symbols */
	for (ULONG i = 0; i < ReferenceString->Length / sizeof(WCHAR); i++) {
	    if ((ReferenceString->Buffer[i] == '\\') ||
		(ReferenceString->Buffer[i] == '/'))
		return STATUS_INVALID_DEVICE_REQUEST;
	}
    }

    NTSTATUS Status = RtlStringFromGUID(InterfaceClassGuid, &GuidString);
    if (!NT_SUCCESS(Status)) {
	DPRINT("RtlStringFromGUID() failed with status 0x%08x\n", Status);
	return Status;
    }

    /* Get Pdo name: \Device\xxxxxxxx */
    Status = IoGetDeviceProperty(PhysicalDeviceObject,
				 DevicePropertyPhysicalDeviceObjectName,
				 sizeof(PdoName), PdoName, &PdoNameLength);
    if (!NT_SUCCESS(Status)) {
	DPRINT("IoGetDeviceProperty() failed with status 0x%08x\n", Status);
	goto out;
    }
    ASSERT(PdoNameLength);

    Status = IopGetDeviceInstancePath(PhysicalDeviceObject, &InstancePath);
        if (!NT_SUCCESS(Status)) {
	DPRINT("IopGetDeviceInstancePath() failed with status 0x%08x\n", Status);
	goto out;
    }

    /* Create key name for this interface:
     * HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{GUID}\##?#ACPI#PNP0501#1#{GUID}
     */
    InterfaceKeyName.Length = sizeof(DEVICE_CLASSES_KEY_NAME) - sizeof(WCHAR);
    InterfaceKeyName.MaximumLength = InterfaceKeyName.Length
	+ GuidString.Length + 5 * sizeof(WCHAR) /* add space for \##?# */
	+ InstancePath.Length + sizeof(WCHAR) /* add space for # */
	+ GuidString.Length;
    InterfaceKeyName.Buffer = ExAllocatePool(NonPagedPool,
					     InterfaceKeyName.MaximumLength);
    if (!InterfaceKeyName.Buffer) {
	DPRINT("ExAllocatePool() failed\n");
	goto out;
    }
    RtlCopyMemory(InterfaceKeyName.Buffer, DEVICE_CLASSES_KEY_NAME,
		  InterfaceKeyName.Length);
    RtlAppendUnicodeStringToString(&InterfaceKeyName, &GuidString);
    RtlAppendUnicodeToString(&InterfaceKeyName, L"\\##?#");
    ULONG StartIndex = InterfaceKeyName.Length / sizeof(WCHAR);
    RtlAppendUnicodeStringToString(&InterfaceKeyName, &InstancePath);
    for (ULONG i = 0; i < InstancePath.Length / sizeof(WCHAR); i++) {
	if (InterfaceKeyName.Buffer[StartIndex + i] == '\\')
	    InterfaceKeyName.Buffer[StartIndex + i] = '#';
    }
    RtlAppendUnicodeToString(&InterfaceKeyName, L"#");
    RtlAppendUnicodeStringToString(&InterfaceKeyName, &GuidString);

    /* Create the interface key in registry */
    Status = IopCreateKeyEx(&InterfaceKey, NULL, &InterfaceKeyName, KEY_WRITE,
			    REG_OPTION_NON_VOLATILE, NULL);

    if (!NT_SUCCESS(Status)) {
	DPRINT("IopCreateKeyEx() failed with status 0x%08x\n", Status);
	goto out;
    }

    /* Write DeviceInstance entry. Value is InstancePath */
    Status = NtSetValueKey(InterfaceKey, &DeviceInstance, 0, /* TileIndex */
			   REG_SZ, InstancePath.Buffer, InstancePath.Length);
    if (!NT_SUCCESS(Status)) {
	DPRINT("NtSetValueKey() failed with status 0x%08x\n", Status);
	goto out;
    }

    /* Create subkey. Name is #ReferenceString */
    SubKeyName.Length = 0;
    SubKeyName.MaximumLength = sizeof(WCHAR);
    if (ReferenceString && ReferenceString->Length)
	SubKeyName.MaximumLength += ReferenceString->Length;
    SubKeyName.Buffer = ExAllocatePool(NonPagedPool, SubKeyName.MaximumLength);
    if (!SubKeyName.Buffer) {
	DPRINT("ExAllocatePool() failed\n");
	goto out;
    }
    RtlAppendUnicodeToString(&SubKeyName, L"#");
    if (ReferenceString && ReferenceString->Length)
	RtlAppendUnicodeStringToString(&SubKeyName, ReferenceString);

    /* Create SubKeyName key in registry */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &SubKeyName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			       InterfaceKey, /* RootDirectory */
			       NULL); /* SecurityDescriptor */

    Status = NtCreateKey(&SubKey, KEY_WRITE, &ObjectAttributes, 0, /* TileIndex */
			 NULL, /* Class */
			 REG_OPTION_NON_VOLATILE, NULL); /* Disposition */

    if (!NT_SUCCESS(Status)) {
	DPRINT("NtCreateKey() failed with status 0x%08x\n", Status);
	goto out;
    }

    /* Create symbolic link name: \??\ACPI#PNP0501#1#{GUID}\ReferenceString */
    SymbolicLinkName->Length = 0;
    SymbolicLinkName->MaximumLength = SymbolicLinkName->Length +
	4 * sizeof(WCHAR) /* add space for \??\ */
	+ InstancePath.Length + sizeof(WCHAR) /* add space for # */
	+ GuidString.Length + sizeof(WCHAR); /* add space for trailing NUL */
    if (ReferenceString && ReferenceString->Length)
	SymbolicLinkName->MaximumLength += sizeof(WCHAR) + ReferenceString->Length;
    SymbolicLinkName->Buffer = ExAllocatePool(PagedPool, SymbolicLinkName->MaximumLength);
    if (!SymbolicLinkName->Buffer) {
	DPRINT("ExAllocatePool() failed\n");
	goto out;
    }
    RtlAppendUnicodeToString(SymbolicLinkName, L"\\??\\");
    StartIndex = SymbolicLinkName->Length / sizeof(WCHAR);
    RtlAppendUnicodeStringToString(SymbolicLinkName, &InstancePath);
    for (ULONG i = 0; i < InstancePath.Length / sizeof(WCHAR); i++) {
	if (SymbolicLinkName->Buffer[StartIndex + i] == '\\')
	    SymbolicLinkName->Buffer[StartIndex + i] = '#';
    }
    RtlAppendUnicodeToString(SymbolicLinkName, L"#");
    RtlAppendUnicodeStringToString(SymbolicLinkName, &GuidString);
    SymbolicLinkName->Buffer[SymbolicLinkName->Length / sizeof(WCHAR)] = L'\0';

    /* Create symbolic link */
    DPRINT("IoRegisterDeviceInterface(): creating symbolic link %wZ -> %ws\n",
	   SymbolicLinkName, PdoName);
    UNICODE_STRING PdoNameU;
    RtlInitUnicodeString(&PdoNameU, PdoName);
    NTSTATUS SymLinkStatus = IoCreateSymbolicLink(SymbolicLinkName, &PdoNameU);

    /* If the symbolic link already exists, return an informational success status */
    if (SymLinkStatus == STATUS_OBJECT_NAME_COLLISION) {
	/* HACK: Delete the existing symbolic link and update it to the new PDO name */
	IoDeleteSymbolicLink(SymbolicLinkName);
	IoCreateSymbolicLink(SymbolicLinkName, &PdoNameU);
	SymLinkStatus = STATUS_OBJECT_NAME_EXISTS;
    }

    if (!NT_SUCCESS(SymLinkStatus)) {
	DPRINT1("IoCreateSymbolicLink() failed with status 0x%08x\n", SymLinkStatus);
	goto out;
    }

    if (ReferenceString && ReferenceString->Length) {
	RtlAppendUnicodeToString(SymbolicLinkName, L"\\");
	RtlAppendUnicodeStringToString(SymbolicLinkName, ReferenceString);
    }
    SymbolicLinkName->Buffer[SymbolicLinkName->Length / sizeof(WCHAR)] = L'\0';

    /* Write symbolic link name in registry */
    SymbolicLinkName->Buffer[1] = '\\';
    Status = NtSetValueKey(SubKey, &SymbolicLink, 0, /* TileIndex */
			   REG_SZ, SymbolicLinkName->Buffer, SymbolicLinkName->Length);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("NtSetValueKey() failed with status 0x%08x\n", Status);
	ExFreePool(SymbolicLinkName->Buffer);
    } else {
	SymbolicLinkName->Buffer[1] = '?';
    }

out:
    if (SubKey) {
	NtClose(SubKey);
    }
    if (InterfaceKey) {
	NtClose(InterfaceKey);
    }
    if (ClassKey) {
	NtClose(ClassKey);
    }
    if (InstancePath.Buffer) {
	ExFreePool(InstancePath.Buffer);
    }
    if (SubKeyName.Buffer) {
	ExFreePool(SubKeyName.Buffer);
    }
    if (InterfaceKeyName.Buffer) {
	ExFreePool(InterfaceKeyName.Buffer);
    }

    return NT_SUCCESS(Status) ? SymLinkStatus : Status;
}

/*++
 * @name IoSetDeviceInterfaceState
 * @implemented
 *
 * Enables or disables an instance of a previously registered device
 * interface class.
 * Documented in WDK.
 *
 * @param SymbolicLinkName
 *        Pointer to the string identifying instance to enable or disable
 *
 * @param Enable
 *        TRUE = enable, FALSE = disable
 *
 * @return Usual NTSTATUS
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 *--*/
NTAPI NTSTATUS IoSetDeviceInterfaceState(IN PUNICODE_STRING SymbolicLinkName,
					 IN BOOLEAN Enable)
{
    PAGED_CODE();

    UNICODE_STRING GuidString;
    NTSTATUS Status;
    LPCGUID EventGuid;
    HANDLE InstanceHandle, ControlHandle;
    UNICODE_STRING KeyName, DeviceInstance;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG LinkedValue, Index;
    GUID DeviceGuid;
    UNICODE_STRING DosDevicesPrefix1 = RTL_CONSTANT_STRING(L"\\??\\");
    UNICODE_STRING DosDevicesPrefix2 = RTL_CONSTANT_STRING(L"\\\\?\\");
    UNICODE_STRING LinkNameNoPrefix;
    USHORT ReferenceStringOffset;

    if (SymbolicLinkName == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    DPRINT("IoSetDeviceInterfaceState('%wZ', %u)\n", SymbolicLinkName, Enable);

    /* Symbolic link name is \??\ACPI#PNP0501#1#{GUID}\ReferenceString */
    /* Make sure it starts with the expected prefix */
    if (!RtlPrefixUnicodeString(&DosDevicesPrefix1, SymbolicLinkName, FALSE) &&
	!RtlPrefixUnicodeString(&DosDevicesPrefix2, SymbolicLinkName, FALSE)) {
	DPRINT1("IoSetDeviceInterfaceState() invalid link name '%wZ'\n",
		SymbolicLinkName);
	return STATUS_INVALID_PARAMETER;
    }

    /* Make a version without the prefix for further processing */
    ASSERT(DosDevicesPrefix1.Length == DosDevicesPrefix2.Length);
    ASSERT(SymbolicLinkName->Length >= DosDevicesPrefix1.Length);
    LinkNameNoPrefix.Buffer = SymbolicLinkName->Buffer +
			      DosDevicesPrefix1.Length / sizeof(WCHAR);
    LinkNameNoPrefix.Length = SymbolicLinkName->Length - DosDevicesPrefix1.Length;
    LinkNameNoPrefix.MaximumLength = LinkNameNoPrefix.Length;

    /* Find the reference string, if any */
    ULONG i;
    for (i = 0; i < LinkNameNoPrefix.Length / sizeof(WCHAR); i++) {
	if (LinkNameNoPrefix.Buffer[i] == L'\\') {
	    break;
	}
    }
    ReferenceStringOffset = i * sizeof(WCHAR);

    /* The GUID is before the reference string or at the end */
    ASSERT(LinkNameNoPrefix.Length >= ReferenceStringOffset);
    if (ReferenceStringOffset < GUID_STRING_BYTES + sizeof(WCHAR)) {
	DPRINT1("IoSetDeviceInterfaceState() invalid link name '%wZ'\n",
		SymbolicLinkName);
	return STATUS_INVALID_PARAMETER;
    }

    GuidString.Buffer = LinkNameNoPrefix.Buffer +
			(ReferenceStringOffset - GUID_STRING_BYTES) / sizeof(WCHAR);
    GuidString.Length = GUID_STRING_BYTES;
    GuidString.MaximumLength = GuidString.Length;
    Status = RtlGUIDFromString(&GuidString, &DeviceGuid);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("RtlGUIDFromString() invalid GUID '%wZ' in link name '%wZ'\n",
		&GuidString, SymbolicLinkName);
	return Status;
    }

    /* Open registry keys */
    Status = OpenRegistryHandlesFromSymbolicLink(SymbolicLinkName, KEY_CREATE_SUB_KEY,
						 NULL, NULL, &InstanceHandle);
    if (!NT_SUCCESS(Status))
	return Status;

    RtlInitUnicodeString(&KeyName, L"Control");
    InitializeObjectAttributes(&ObjectAttributes, &KeyName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, InstanceHandle,
			       NULL);
    Status = NtCreateKey(&ControlHandle, KEY_SET_VALUE, &ObjectAttributes, 0, NULL,
			 REG_OPTION_VOLATILE, NULL);
    NtClose(InstanceHandle);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to create the Control subkey\n");
	return Status;
    }

    LinkedValue = (Enable ? 1 : 0);

    RtlInitUnicodeString(&KeyName, L"Linked");
    Status = NtSetValueKey(ControlHandle, &KeyName, 0, REG_DWORD, &LinkedValue,
			   sizeof(ULONG));
    NtClose(ControlHandle);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to write the Linked value\n");
	return Status;
    }

    ASSERT(GuidString.Buffer >= LinkNameNoPrefix.Buffer + 1);
    DeviceInstance.Length = (USHORT)((GuidString.Buffer - LinkNameNoPrefix.Buffer - 1) *
				     sizeof(WCHAR));
    if (DeviceInstance.Length == 0) {
	DPRINT1("No device instance in link name '%wZ'\n", SymbolicLinkName);
	return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    DeviceInstance.MaximumLength = DeviceInstance.Length;
    DeviceInstance.Buffer = ExAllocatePoolWithTag(PagedPool, DeviceInstance.MaximumLength,
						  TAG_IO);
    if (DeviceInstance.Buffer == NULL) {
	/* no memory */
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(DeviceInstance.Buffer, LinkNameNoPrefix.Buffer, DeviceInstance.Length);

    for (Index = 0; Index < DeviceInstance.Length / sizeof(WCHAR); Index++) {
	if (DeviceInstance.Buffer[Index] == L'#') {
	    DeviceInstance.Buffer[Index] = L'\\';
	}
    }

    ExFreePoolWithTag(DeviceInstance.Buffer, TAG_IO);

    EventGuid = Enable ? &GUID_DEVICE_INTERFACE_ARRIVAL : &GUID_DEVICE_INTERFACE_REMOVAL;

    Status = IopQueueDeviceChangeEvent(EventGuid, &DeviceGuid, SymbolicLinkName);

    DPRINT("Status %x\n", Status);
    return STATUS_SUCCESS;
}

/*++
 * @name IoGetDeviceInterfaces
 * @implemented
 *
 * Returns a list of device interfaces of a particular device interface class.
 * Documented in WDK
 *
 * @param InterfaceClassGuid
 *        Points to a class GUID specifying the device interface class
 *
 * @param PhysicalDeviceObject
 *        Points to an optional PDO that narrows the search to only the
 *        device interfaces of the device represented by the PDO
 *
 * @param Flags
 *        Specifies flags that modify the search for device interfaces. The
 *        DEVICE_INTERFACE_INCLUDE_NONACTIVE flag specifies that the list of
 *        returned symbolic links should contain also disabled device
 *        interfaces in addition to the enabled ones.
 *
 * @param SymbolicLinkList
 *        Points to a character pointer that is filled in on successful return
 *        with a list of unicode strings identifying the device interfaces
 *        that match the search criteria. The newly allocated buffer contains
 *        a list of symbolic link names. Each unicode string in the list is
 *        null-terminated; the end of the whole list is marked by an additional
 *        NULL. The caller is responsible for freeing the buffer (ExFreePool)
 *        when it is no longer needed.
 *        If no device interfaces match the search criteria, this routine
 *        returns STATUS_SUCCESS and the string contains a single NULL
 *        character.
 *
 * @return Usual NTSTATUS
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 *
 *--*/
NTAPI NTSTATUS IoGetDeviceInterfaces(IN CONST GUID *InterfaceClassGuid,
				     IN OPTIONAL PDEVICE_OBJECT PhysicalDeviceObject,
				     IN ULONG Flags,
				     OUT PWSTR *SymbolicLinkList)
{
    PAGED_CODE();

    UNICODE_STRING Control = RTL_CONSTANT_STRING(L"Control");
    HANDLE InterfaceKey = NULL;
    HANDLE DeviceKey = NULL;
    HANDLE ReferenceKey = NULL;
    HANDLE ControlKey = NULL;
    PKEY_BASIC_INFORMATION DeviceBasicInfo = NULL;
    PKEY_BASIC_INFORMATION RefBasicInfo = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = NULL;
    PKEY_VALUE_PARTIAL_INFORMATION PartialInfo;
    UNICODE_STRING KeyName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    BOOLEAN FoundRightPDO = FALSE;
    ULONG i = 0, j, Size, LinkedValue;
    UNICODE_STRING ReturnBuffer = { 0, 0, NULL };
    NTSTATUS Status;

    UNICODE_STRING DeviceInstancePath = { 0, 0, NULL };
    if (PhysicalDeviceObject) {
	Status = IopGetDeviceInstancePath(PhysicalDeviceObject, &DeviceInstancePath);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }

    Status = IopOpenInterfaceKey(InterfaceClassGuid, KEY_ENUMERATE_SUB_KEYS,
				 &InterfaceKey);
    if (!NT_SUCCESS(Status)) {
	DPRINT("IopOpenInterfaceKey() failed with status 0x%08x\n", Status);
	goto cleanup;
    }

    /* Enumerate subkeys (i.e. the different device objects) */
    while (TRUE) {
	KEY_BASIC_INFORMATION BasicInfo;
	Size = sizeof(KEY_BASIC_INFORMATION);
	Status = NtEnumerateKey(InterfaceKey, i, KeyBasicInformation,
				&BasicInfo, Size, &Size);
	if (Status == STATUS_NO_MORE_ENTRIES) {
	    break;
	} else if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
	    DPRINT("NtEnumerateKey() failed with status 0x%08x\n", Status);
	    goto cleanup;
	}

	DeviceBasicInfo = ExAllocatePool(NonPagedPool, Size);
	if (!DeviceBasicInfo) {
	    DPRINT("ExAllocatePool() failed\n");
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto cleanup;
	}
	Status = NtEnumerateKey(InterfaceKey, i++, KeyBasicInformation,
				DeviceBasicInfo, Size, &Size);
	if (!NT_SUCCESS(Status)) {
	    DPRINT("NtEnumerateKey() failed with status 0x%08x\n", Status);
	    goto cleanup;
	}

	/* Open device key */
	KeyName.Length = KeyName.MaximumLength = (USHORT)DeviceBasicInfo->NameLength;
	KeyName.Buffer = DeviceBasicInfo->Name;
	InitializeObjectAttributes(&ObjectAttributes, &KeyName,
				   OBJ_CASE_INSENSITIVE, InterfaceKey, NULL);
	Status = NtOpenKey(&DeviceKey, KEY_ENUMERATE_SUB_KEYS, &ObjectAttributes);
	if (!NT_SUCCESS(Status)) {
	    DPRINT("NtOpenKey() failed with status 0x%08x\n", Status);
	    goto cleanup;
	}

	if (PhysicalDeviceObject) {
	    /* Check if we are on the right physical device object,
	     * by reading the DeviceInstance string */
	    Status = IopQueryValueKey(DeviceKey, L"DeviceInstance", &PartialInfo);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }
	    UNICODE_STRING FoundInstance = {};
	    RtlInitUnicodeString(&FoundInstance, (PWSTR)PartialInfo->Data);
	    FoundRightPDO = !RtlCompareUnicodeString(&FoundInstance,
						     &DeviceInstancePath, TRUE);
	    ExFreePool(PartialInfo);
	    PartialInfo = NULL;
	    if (!FoundRightPDO) {
		/* not yet found */
		continue;
	    }
	}

	/* Enumerate subkeys (ie the different reference strings) */
	j = 0;
	while (TRUE) {
	    KEY_BASIC_INFORMATION BasicInfo;
	    Size = sizeof(KEY_BASIC_INFORMATION);
	    Status = NtEnumerateKey(DeviceKey, j, KeyBasicInformation,
				    &BasicInfo, Size, &Size);
	    if (Status == STATUS_NO_MORE_ENTRIES) {
		break;
	    } else if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
		DPRINT("NtEnumerateKey() failed with status 0x%08x\n", Status);
		goto cleanup;
	    }

	    RefBasicInfo = ExAllocatePool(NonPagedPool, Size);
	    if (!RefBasicInfo) {
		DPRINT("ExAllocatePool() failed\n");
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	    }
	    Status = NtEnumerateKey(DeviceKey, j++, KeyBasicInformation, RefBasicInfo,
				    Size, &Size);
	    if (!NT_SUCCESS(Status)) {
		DPRINT("NtEnumerateKey() failed with status 0x%08x\n", Status);
		goto cleanup;
	    }

	    KeyName.Length = KeyName.MaximumLength = (USHORT)RefBasicInfo->NameLength;
	    KeyName.Buffer = RefBasicInfo->Name;
	    if (RtlEqualUnicodeString(&KeyName, &Control, TRUE)) {
		/* Skip Control subkey */
		goto NextReferenceString;
	    }

	    /* Open reference key */
	    InitializeObjectAttributes(&ObjectAttributes, &KeyName,
				       OBJ_CASE_INSENSITIVE,
				       DeviceKey, NULL);
	    Status = NtOpenKey(&ReferenceKey, KEY_QUERY_VALUE, &ObjectAttributes);
	    if (!NT_SUCCESS(Status)) {
		DPRINT("NtOpenKey() failed with status 0x%08x\n", Status);
		goto cleanup;
	    }

	    if (!(Flags & DEVICE_INTERFACE_INCLUDE_NONACTIVE)) {
		/* We have to check if the interface is enabled, by
		 * reading the Linked value in the Control subkey
		 */
		InitializeObjectAttributes(&ObjectAttributes, &Control,
					   OBJ_CASE_INSENSITIVE,
					   ReferenceKey, NULL);
		Status = NtOpenKey(&ControlKey, KEY_QUERY_VALUE, &ObjectAttributes);
		if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
		    /* That's OK. The key doesn't exist (yet) because
		     * the interface is not activated. */
		    goto NextReferenceString;
		} else if (!NT_SUCCESS(Status)) {
		    DPRINT1("NtOpenKey() failed with status 0x%08x\n", Status);
		    goto cleanup;
		}

		Status = IopReadRegValue(ControlKey, L"Linked", REG_DWORD,
					 sizeof(ULONG), &LinkedValue, NULL);
		if (!NT_SUCCESS(Status)) {
		    goto cleanup;
		}
		if (LinkedValue == 0) {
		    /* This interface isn't active */
		    goto NextReferenceString;
		}
	    }

	    /* Read the SymbolicLink string and add it into SymbolicLinkList */
	    Status = IopQueryValueKey(ReferenceKey, L"SymbolicLink",
				      &ValueInfo);
	    if (!NT_SUCCESS(Status)) {
		DPRINT("IopQueryValueKey() failed with status 0x%08x\n", Status);
		goto cleanup;
	    } else if (ValueInfo->Type != REG_SZ) {
		DPRINT("Unexpected registry type 0x%x (expected 0x%x)\n", ValueInfo->Type,
		       REG_SZ);
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	    } else if (ValueInfo->DataLength < 5 * sizeof(WCHAR)) {
		DPRINT("Registry string too short (length %u, expected %zu at least)\n",
		       ValueInfo->DataLength, 5 * sizeof(WCHAR));
		Status = STATUS_UNSUCCESSFUL;
		goto cleanup;
	    }
	    KeyName.MaximumLength = (USHORT)ValueInfo->DataLength;
	    KeyName.Buffer = (PWSTR)ValueInfo->Data;
	    KeyName.Length = wcsnlen((PWSTR)ValueInfo->Data,
				     ValueInfo->DataLength / sizeof(WCHAR)) * sizeof(WCHAR);

	    /* Fixup the prefix (from "\\?\") */
	    RtlCopyMemory(KeyName.Buffer, L"\\??\\", 4 * sizeof(WCHAR));

	    /* Add new symbolic link to symbolic link list */
	    if (ReturnBuffer.Length + KeyName.Length + sizeof(WCHAR) >
		ReturnBuffer.MaximumLength) {
		PWSTR NewBuffer;
		ReturnBuffer.MaximumLength = (USHORT)max(
		    2 * ReturnBuffer.MaximumLength,
		    (USHORT)(ReturnBuffer.Length + KeyName.Length + 2 * sizeof(WCHAR)));
		NewBuffer = ExAllocatePool(NonPagedPool, ReturnBuffer.MaximumLength);
		if (!NewBuffer) {
		    DPRINT("ExAllocatePool() failed\n");
		    Status = STATUS_INSUFFICIENT_RESOURCES;
		    goto cleanup;
		}
		if (ReturnBuffer.Buffer) {
		    RtlCopyMemory(NewBuffer, ReturnBuffer.Buffer, ReturnBuffer.Length);
		    ExFreePool(ReturnBuffer.Buffer);
		}
		ReturnBuffer.Buffer = NewBuffer;
	    }
	    DPRINT("Adding symbolic link %wZ\n", &KeyName);
	    Status = RtlAppendUnicodeStringToString(&ReturnBuffer, &KeyName);
	    if (!NT_SUCCESS(Status)) {
		DPRINT("RtlAppendUnicodeStringToString() failed with status 0x%08x\n",
		       Status);
		goto cleanup;
	    }
	    /* RtlAppendUnicodeStringToString added a NULL at the end of the
             * destination string, but didn't increase the Length field.
             * Do it for it.
             */
	    ReturnBuffer.Length += sizeof(WCHAR);

	NextReferenceString:
	    ExFreePool(RefBasicInfo);
	    RefBasicInfo = NULL;
	    if (ValueInfo)
		ExFreePool(ValueInfo);
	    ValueInfo = NULL;
	    if (ReferenceKey != NULL) {
		NtClose(ReferenceKey);
		ReferenceKey = NULL;
	    }
	    if (ControlKey != NULL) {
		NtClose(ControlKey);
		ControlKey = NULL;
	    }
	}
	if (FoundRightPDO) {
	    /* No need to go further, as we already have found what we searched */
	    break;
	}

	ExFreePool(DeviceBasicInfo);
	DeviceBasicInfo = NULL;
	NtClose(DeviceKey);
	DeviceKey = NULL;
    }

    /* Add final NULL to ReturnBuffer */
    ASSERT(ReturnBuffer.Length <= ReturnBuffer.MaximumLength);
    if (ReturnBuffer.Length >= ReturnBuffer.MaximumLength) {
	PWSTR NewBuffer;
	ReturnBuffer.MaximumLength += sizeof(WCHAR);
	NewBuffer = ExAllocatePool(NonPagedPool, ReturnBuffer.MaximumLength);
	if (!NewBuffer) {
	    DPRINT("ExAllocatePool() failed\n");
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto cleanup;
	}
	if (ReturnBuffer.Buffer) {
	    RtlCopyMemory(NewBuffer, ReturnBuffer.Buffer, ReturnBuffer.Length);
	    ExFreePool(ReturnBuffer.Buffer);
	}
	ReturnBuffer.Buffer = NewBuffer;
    }
    ReturnBuffer.Buffer[ReturnBuffer.Length / sizeof(WCHAR)] = UNICODE_NULL;
    *SymbolicLinkList = ReturnBuffer.Buffer;
    Status = STATUS_SUCCESS;

cleanup:
    if (DeviceInstancePath.Buffer) {
	ExFreePool(DeviceInstancePath.Buffer);
    }
    if (!NT_SUCCESS(Status) && ReturnBuffer.Buffer)
	ExFreePool(ReturnBuffer.Buffer);
    if (InterfaceKey != NULL)
	NtClose(InterfaceKey);
    if (DeviceKey != NULL)
	NtClose(DeviceKey);
    if (ReferenceKey != NULL)
	NtClose(ReferenceKey);
    if (ControlKey != NULL)
	NtClose(ControlKey);
    if (DeviceBasicInfo)
	ExFreePool(DeviceBasicInfo);
    if (RefBasicInfo)
	ExFreePool(RefBasicInfo);
    if (ValueInfo)
	ExFreePool(ValueInfo);
    return Status;
}

/*
 * @implemented
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoCreateSymbolicLink(IN PUNICODE_STRING SymbolicLinkName,
				    IN PUNICODE_STRING DeviceName)
{
    PAGED_CODE();

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, SymbolicLinkName,
                               OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);
    HANDLE Handle;
    NTSTATUS Status = NtCreateSymbolicLinkObject(&Handle, SYMBOLIC_LINK_ALL_ACCESS,
						 &ObjectAttributes, DeviceName);
    if (NT_SUCCESS(Status)) {
	NtClose(Handle);
    }
    return Status;
}

/*
 * @implemented
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoDeleteSymbolicLink(IN PUNICODE_STRING SymbolicLinkName)
{
    PAGED_CODE();

    /* Initialize the object attributes and open the link */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes,
                               SymbolicLinkName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    HANDLE Handle;
    NTSTATUS Status = NtOpenSymbolicLinkObject(&Handle, DELETE, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Make the link temporary and close its handle */
    Status = NtMakeTemporaryObject(Handle);
    if (NT_SUCCESS(Status)) {
	NtClose(Handle);
    }

    return Status;
}

/**
 * @name IoOpenDeviceRegistryKey
 *
 * Open a registry key unique for a specified driver or device instance.
 *
 * @param DeviceObject   Device to get the registry key for.
 * @param DevInstKeyType Type of the key to return. If zero, will open the base key.
 * @param DesiredAccess  Access mask (eg. KEY_READ | KEY_WRITE).
 * @param DevInstRegKey  Handle to the opened registry key on
 *                       successful return.
 *
 * @return Status.
 *
 * @implemented
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoOpenDeviceRegistryKey(IN PDEVICE_OBJECT DeviceObject,
				       IN ULONG DevInstKeyType,
				       IN ACCESS_MASK DesiredAccess,
				       OUT PHANDLE DevInstRegKey)
{
    PAGED_CODE();

    ULONG KeyNameLength;
    PWSTR KeyNameBuffer;
    UNICODE_STRING KeyName;
    ULONG DriverKeyLength;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;

    UNICODE_STRING InstancePath;
    Status = IopGetDeviceInstancePath(DeviceObject, &InstancePath);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Calculate the length of the base key name. This is the full
     * name for driver key or the name excluding "Device Parameters"
     * subkey for device key. */
    KeyNameLength = sizeof(CONTROL_KEY_NAME);
    if (DevInstKeyType & PLUGPLAY_REGKEY_CURRENT_HWPROFILE)
	KeyNameLength += sizeof(PROFILE_KEY_NAME) - sizeof(UNICODE_NULL);
    if (DevInstKeyType & PLUGPLAY_REGKEY_DRIVER) {
	KeyNameLength += sizeof(CLASS_KEY_NAME) - sizeof(UNICODE_NULL);
	Status = IoGetDeviceProperty(DeviceObject, DevicePropertyDriverKeyName, 0, NULL,
				     &DriverKeyLength);
	if (Status != STATUS_BUFFER_TOO_SMALL)
	    return Status;
	KeyNameLength += DriverKeyLength;
    } else {
	KeyNameLength += sizeof(ENUM_KEY_NAME) - sizeof(UNICODE_NULL) +
			 InstancePath.Length;
    }

    /* Allocate the buffer for the key name */
    KeyNameBuffer = ExAllocatePool(NonPagedPool, KeyNameLength);
    if (KeyNameBuffer == NULL)
	return STATUS_INSUFFICIENT_RESOURCES;

    KeyName.Length = 0;
    KeyName.MaximumLength = (USHORT)KeyNameLength;
    KeyName.Buffer = KeyNameBuffer;

    /* Build the key name */
    KeyName.Length += sizeof(CONTROL_KEY_NAME) - sizeof(UNICODE_NULL);
    RtlCopyMemory(KeyNameBuffer, CONTROL_KEY_NAME, KeyName.Length);

    if (DevInstKeyType & PLUGPLAY_REGKEY_CURRENT_HWPROFILE)
	RtlAppendUnicodeToString(&KeyName, PROFILE_KEY_NAME);

    if (DevInstKeyType & PLUGPLAY_REGKEY_DRIVER) {
	RtlAppendUnicodeToString(&KeyName, CLASS_KEY_NAME);
	Status = IoGetDeviceProperty(DeviceObject, DevicePropertyDriverKeyName,
				     DriverKeyLength,
				     KeyNameBuffer + (KeyName.Length / sizeof(WCHAR)),
				     &DriverKeyLength);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Call to IoGetDeviceProperty() failed with Status 0x%08x\n", Status);
	    ExFreePool(KeyNameBuffer);
	    return Status;
	}
	KeyName.Length += (USHORT)DriverKeyLength - sizeof(UNICODE_NULL);
    } else {
	RtlAppendUnicodeToString(&KeyName, ENUM_KEY_NAME);
	Status = RtlAppendUnicodeStringToString(&KeyName, &InstancePath);
	if (KeyName.Length == 0) {
	    ExFreePool(KeyNameBuffer);
	    return Status;
	}
    }

    /* Open the base key. */
    Status = IopOpenKeyEx(DevInstRegKey, NULL, &KeyName, DesiredAccess);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("IoOpenDeviceRegistryKey(%wZ): failed to open base key, status 0x%08x\n",
		&KeyName, Status);
	ExFreePool(KeyNameBuffer);
	return Status;
    }
    ExFreePool(KeyNameBuffer);

    /* If user requested the base key or the driver key we're done. */
    if (!DevInstKeyType || (DevInstKeyType & PLUGPLAY_REGKEY_DRIVER))
	return Status;

    /* For device key we must open "Device Parameters" subkey and create it
     * if it doesn't exist. For boot configuration we must open "LogConf". */
    if (DevInstKeyType & PLUGPLAY_REGKEY_DEVICE) {
	RtlInitUnicodeString(&KeyName, DEVICE_PARAMETERS_KEY_NAME);
    } else if (DevInstKeyType & PLUGPLAY_REGKEY_BOOT_CONFIGURATION) {
	RtlInitUnicodeString(&KeyName, BOOT_CONFIG_KEY_NAME);
    } else {
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }
    InitializeObjectAttributes(&ObjectAttributes, &KeyName,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			       *DevInstRegKey, NULL);
    Status = NtCreateKey(DevInstRegKey, DesiredAccess, &ObjectAttributes, 0, NULL,
			 REG_OPTION_NON_VOLATILE, NULL);

out:
    NtClose(ObjectAttributes.RootDirectory);
    return Status;
}

#define PIP_REGISTRY_DATA(x, y) ValueName = x; ValueType = y; break

/*
 * @implemented
 *
 * This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoGetDeviceProperty(IN PDEVICE_OBJECT DeviceObject,
				   IN DEVICE_REGISTRY_PROPERTY DeviceProperty,
				   IN ULONG BufferLength,
				   OUT PVOID PropertyBuffer,
				   OUT PULONG ResultLength)
{
    PAGED_CODE();

    PWSTR ValueName = NULL;
    ULONG ValueType;
    ULONG KeyType = 0;
    switch (DeviceProperty) {
	/* Registry-based properties */
    case DevicePropertyUINumber:
	PIP_REGISTRY_DATA(REGSTR_VAL_UI_NUMBER, REG_DWORD);
    case DevicePropertyLocationInformation:
	PIP_REGISTRY_DATA(REGSTR_VAL_LOCATION_INFORMATION, REG_SZ);
    case DevicePropertyDeviceDescription:
	PIP_REGISTRY_DATA(REGSTR_VAL_DEVDESC, REG_SZ);
    case DevicePropertyHardwareID:
	PIP_REGISTRY_DATA(REGSTR_VAL_HARDWAREID, REG_MULTI_SZ);
    case DevicePropertyCompatibleIDs:
	PIP_REGISTRY_DATA(REGSTR_VAL_COMPATIBLEIDS, REG_MULTI_SZ);
    case DevicePropertyBootConfiguration:
	KeyType = PLUGPLAY_REGKEY_BOOT_CONFIGURATION;
	PIP_REGISTRY_DATA(REGSTR_VAL_BOOTCONFIG, REG_RESOURCE_LIST);
    case DevicePropertyClassName:
	PIP_REGISTRY_DATA(REGSTR_VAL_CLASS, REG_SZ);
    case DevicePropertyClassGuid:
	PIP_REGISTRY_DATA(REGSTR_VAL_CLASSGUID, REG_SZ);
    case DevicePropertyDriverKeyName:
	PIP_REGISTRY_DATA(REGSTR_VAL_DRIVER, REG_SZ);
    case DevicePropertyManufacturer:
	PIP_REGISTRY_DATA(REGSTR_VAL_MFG, REG_SZ);
    case DevicePropertyFriendlyName:
	PIP_REGISTRY_DATA(REGSTR_VAL_FRIENDLYNAME, REG_SZ);
    case DevicePropertyInstallState:
	PIP_REGISTRY_DATA(REGSTR_VAL_CONFIGFLAGS, REG_DWORD);
    case DevicePropertyRemovalPolicy:
	KeyType = PLUGPLAY_REGKEY_DEVICE;
	PIP_REGISTRY_DATA(TEXT("RemovalPolicy"), REG_DWORD);
    case DevicePropertyContainerID:
    case DevicePropertyResourceRequirements:
    case DevicePropertyAllocatedResources:
	UNIMPLEMENTED;
	break;
    default:
	return WdmGetDeviceProperty(DeviceObject->Header.GlobalHandle,
				    DeviceProperty, BufferLength,
				    PropertyBuffer, ResultLength);
    }
    if (!ValueName) {
	return STATUS_NOT_IMPLEMENTED;
    }

    HANDLE KeyHandle = NULL;
    NTSTATUS Status = IoOpenDeviceRegistryKey(DeviceObject, KeyType, KEY_READ, &KeyHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Status = IopReadRegValue(KeyHandle, ValueName, ValueType,
			     BufferLength, PropertyBuffer, ResultLength);
    NtClose(KeyHandle);
    return Status;
}

NTAPI NTSTATUS IoGetDevicePropertyData(IN PDEVICE_OBJECT Pdo,
				       IN CONST DEVPROPKEY *PropertyKey,
				       IN LCID Lcid,
				       IN ULONG Flags,
				       IN ULONG Size,
				       OUT PVOID Data,
				       OUT PULONG RequiredSize,
				       OUT PDEVPROPTYPE Type)
{
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * Note: this function has a somewhat peculiar behavior at first glance.
 * If the device queue is not busy, the function does NOT insert the entry
 * into the queue, and instead simply sets the device queue to busy.
 * On the other hand, if the device queue is busy, the entry is inserted
 * at the end of the queue. The return value indicates whether the insertion
 * has been performed.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI BOOLEAN KeInsertDeviceQueue(IN PKDEVICE_QUEUE Queue,
				  IN PKDEVICE_QUEUE_ENTRY Entry)
{
    PAGED_CODE();
    assert(Queue != NULL);
    assert(Entry != NULL);
    if (!Queue->Busy) {
        Entry->Inserted = FALSE;
        Queue->Busy = TRUE;
    } else {
        Entry->Inserted = TRUE;
        InsertTailList(&Queue->DeviceListHead, &Entry->DeviceListEntry);
    }
    return Entry->Inserted;
}

/*
 * Same as KeInsertDeviceQueue, except that the insertion is sorted by
 * the specified key (the given queue entry is inserted after the first
 * entry that satisfies the property that the specified key is larger or
 * equal to it but smaller than its successor).
 *
 * NOTE: Queue must be already sorted (or empty). Otherwise the function
 * behaves unpredictably.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI BOOLEAN KeInsertByKeyDeviceQueue(IN PKDEVICE_QUEUE Queue,
				       IN PKDEVICE_QUEUE_ENTRY Entry,
				       IN ULONG SortKey)
{
    PAGED_CODE();
    assert(Queue != NULL);
    assert(Entry != NULL);
    Entry->SortKey = SortKey;

    if (!Queue->Busy) {
        Entry->Inserted = FALSE;
        Queue->Busy = TRUE;
    } else {
        /* Make sure the list isn't empty */
	PLIST_ENTRY NextEntry = &Queue->DeviceListHead;
        if (!IsListEmpty(NextEntry)) {
            /* Get the last entry */
	    PKDEVICE_QUEUE_ENTRY LastEntry = CONTAINING_RECORD(NextEntry->Blink,
							       KDEVICE_QUEUE_ENTRY,
							       DeviceListEntry);

	    /* Find the first occurrence where the specified key is larger or equal
	     * to an entry but smaller than its successor. */
            if (SortKey < LastEntry->SortKey) {
                do {
                    NextEntry = NextEntry->Flink;
                    LastEntry = CONTAINING_RECORD(NextEntry,
                                                  KDEVICE_QUEUE_ENTRY,
                                                  DeviceListEntry);
                } while (SortKey >= LastEntry->SortKey);
            }
        }

        /* Now insert us */
        InsertTailList(NextEntry, &Entry->DeviceListEntry);
        Entry->Inserted = TRUE;
    }
    return Entry->Inserted;
}

/*
 * Removes the entry from the head and returns the removed entry. If queue
 * is empty, return NULL. This function should only be called when the queue
 * is set to busy state, otherwise it asserts.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI PKDEVICE_QUEUE_ENTRY KeRemoveDeviceQueue(IN PKDEVICE_QUEUE Queue)
{
    PAGED_CODE();
    PKDEVICE_QUEUE_ENTRY Entry = NULL;

    assert(Queue != NULL);
    assert(Queue->Busy);

    /* Check if this is an empty queue */
    if (IsListEmpty(&Queue->DeviceListHead)) {
        /* Set it to idle and return nothing */
        Queue->Busy = FALSE;
    } else {
        /* Remove the Entry from the List */
	PLIST_ENTRY ListEntry = RemoveHeadList(&Queue->DeviceListHead);
        Entry = CONTAINING_RECORD(ListEntry, KDEVICE_QUEUE_ENTRY, DeviceListEntry);
        Entry->Inserted = FALSE;
    }
    return Entry;
}

/*
 * Same as KeRemoveDeviceQueue, except the entry to be removed is the first entry
 * with a key that is greater or equal to the specified sort key. If all entries
 * have keys smaller than the specified sort key, then the head of the queue is
 * removed and returned.
 *
 * The queue must be busy, otherwise the function asserts in debug build.
 *
 * NOTE: Queue must be already sorted. Otherwise the function behaves unpredictably.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI PKDEVICE_QUEUE_ENTRY KeRemoveByKeyDeviceQueue(IN PKDEVICE_QUEUE Queue,
						    IN ULONG SortKey)
{
    PAGED_CODE();
    PKDEVICE_QUEUE_ENTRY Entry = NULL;

    assert(Queue != NULL);
    assert(Queue->Busy);

    /* Check if this is an empty queue */
    if (IsListEmpty(&Queue->DeviceListHead)) {
        /* Set it to idle and return nothing */
        Queue->Busy = FALSE;
    } else {
	PLIST_ENTRY NextEntry = &Queue->DeviceListHead;
        Entry = CONTAINING_RECORD(NextEntry->Blink, KDEVICE_QUEUE_ENTRY, DeviceListEntry);
        /* If SortKey is greater than the last key, then return the first entry right away */
        if (Entry->SortKey <= SortKey) {
            Entry = CONTAINING_RECORD(NextEntry->Flink, KDEVICE_QUEUE_ENTRY, DeviceListEntry);
        } else {
            NextEntry = Queue->DeviceListHead.Flink;
            while (TRUE) {
                /* Make sure we don't go beyond the end of the queue */
                assert(NextEntry != &Queue->DeviceListHead);

                /* Get the next entry and check if its key is greater or equal to SortKey */
                Entry = CONTAINING_RECORD(NextEntry, KDEVICE_QUEUE_ENTRY, DeviceListEntry);
                if (SortKey <= Entry->SortKey) {
		    break;
		}
                NextEntry = NextEntry->Flink;
            }
        }

        RemoveEntryList(&Entry->DeviceListEntry);
        Entry->Inserted = FALSE;
    }
    return Entry;
}

/*
 * Removes the specified entry from the queue, returning TRUE.
 * If the entry is not inserted, nothing is done and we return FALSE.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI BOOLEAN KeRemoveEntryDeviceQueue(IN PKDEVICE_QUEUE Queue,
				       IN PKDEVICE_QUEUE_ENTRY Entry)
{
    PAGED_CODE();
    assert(Queue != NULL);
    assert(Queue->Busy);
    if (Entry->Inserted) {
        Entry->Inserted = FALSE;
        RemoveEntryList(&Entry->DeviceListEntry);
	return TRUE;
    }
    return FALSE;
}

static VOID IopStartNextPacketByKey(IN PDEVICE_OBJECT DeviceObject,
				    IN BOOLEAN Cancelable,
				    IN ULONG Key)
{
    PAGED_CODE();
    /* Clear the current IRP */
    DeviceObject->CurrentIrp = NULL;

    /* Remove an entry from the queue */
    PKDEVICE_QUEUE_ENTRY Entry = KeRemoveByKeyDeviceQueue(&DeviceObject->DeviceQueue, Key);
    if (Entry) {
	/* Get the IRP and set it */
	PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.DeviceQueueEntry);
	DeviceObject->CurrentIrp = Irp;

	/* Check if this is a cancelable packet */
	if (Cancelable) {
	    /* Check if the caller requested no cancellation */
	    if (DeviceObject->StartIoFlags & DOE_SIO_NO_CANCEL) {
		/* He did, so remove the cancel routine */
		Irp->CancelRoutine = NULL;
	    }
	}
	/* Call the Start I/O Routine */
	DeviceObject->DriverObject->DriverStartIo(DeviceObject, Irp);
    }
}

static VOID IopStartNextPacket(IN PDEVICE_OBJECT DeviceObject,
			       IN BOOLEAN Cancelable)
{
    PAGED_CODE();
    /* Clear the current IRP */
    DeviceObject->CurrentIrp = NULL;

    /* Remove an entry from the queue */
    PKDEVICE_QUEUE_ENTRY Entry = KeRemoveDeviceQueue(&DeviceObject->DeviceQueue);
    if (Entry) {
	/* Get the IRP and set it */
	PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.DeviceQueueEntry);
	DeviceObject->CurrentIrp = Irp;

	/* Check if this is a cancelable packet */
	if (Cancelable) {
	    /* Check if the caller requested no cancellation */
	    if (DeviceObject->StartIoFlags & DOE_SIO_NO_CANCEL) {
		/* He did, so remove the cancel routine */
		Irp->CancelRoutine = NULL;
	    }
	}

	/* Call the Start I/O Routine */
	DeviceObject->DriverObject->DriverStartIo(DeviceObject, Irp);
    }
}

static VOID IopStartNextPacketByKeyEx(IN PDEVICE_OBJECT DeviceObject,
				      IN ULONG Key,
				      IN ULONG Flags)
{
    PAGED_CODE();
    ULONG CurrentKey = Key;
    ULONG CurrentFlags = Flags;

    while (TRUE) {
	/* Increase the count */
	if ((--DeviceObject->StartIoCount) > 1) {
	    /*
	     * We've already called the routine once...
	     * All we have to do is save the key and add the new flags
	     */
	    DeviceObject->StartIoFlags |= CurrentFlags;
	    DeviceObject->StartIoKey = CurrentKey;
	} else {
	    /* Mask out the current packet flags and key */
	    DeviceObject->StartIoFlags &= ~(DOE_SIO_WITH_KEY |
					    DOE_SIO_NO_KEY |
					    DOE_SIO_CANCELABLE);
	    DeviceObject->StartIoKey = 0;

	    /* Check if this is a packet start with key */
	    if (Flags & DOE_SIO_WITH_KEY) {
		/* Start the packet with a key */
		IopStartNextPacketByKey(DeviceObject,
					(Flags & DOE_SIO_CANCELABLE) ? TRUE : FALSE,
					CurrentKey);
	    } else if (Flags & DOE_SIO_NO_KEY) {
		/* Start the packet */
		IopStartNextPacket(DeviceObject,
				   (Flags & DOE_SIO_CANCELABLE) ? TRUE : FALSE);
	    }
	}

	/* Decrease the Start I/O count and check if it's 0 now */
	if (!(--DeviceObject->StartIoCount)) {
	    /* Get the current active key and flags */
	    CurrentKey = DeviceObject->StartIoKey;
	    CurrentFlags = DeviceObject-> StartIoFlags &
		(DOE_SIO_WITH_KEY | DOE_SIO_NO_KEY | DOE_SIO_CANCELABLE);

	    /* Check if we should still loop */
	    if (!(CurrentFlags & (DOE_SIO_WITH_KEY | DOE_SIO_NO_KEY)))
		break;
	} else {
	    /* There are still Start I/Os active, so quit this loop */
	    break;
	}
    }
}

/*
 * @implemented
 *
 * Starts the IO packet if the device queue is not busy. Otherwise, queue
 * the IRP to the device queue. Also set the supplied cancel function
 * as the cancel routine of the IRP. If the IRP has been canceled for some
 * reason, call the cancel routine.
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoStartPacket(IN PDEVICE_OBJECT DeviceObject,
			 IN PIRP Irp,
			 IN PULONG Key,
			 IN PDRIVER_CANCEL CancelFunction)
{
    PAGED_CODE();
    if (CancelFunction) {
        Irp->CancelRoutine = CancelFunction;
    }

    /* Check if we have a key */
    BOOLEAN Inserted;
    if (Key) {
        /* Insert by key */
        Inserted = KeInsertByKeyDeviceQueue(&DeviceObject->DeviceQueue,
					    &Irp->Tail.DeviceQueueEntry,
					    *Key);
    } else {
        /* Insert without a key */
        Inserted = KeInsertDeviceQueue(&DeviceObject->DeviceQueue,
				       &Irp->Tail.DeviceQueueEntry);
    }

    /* If Inserted is FALSE, it means that the device queue was
     * empty and was in a Non-Busy state. In other words, this Irp
     * should now be started now. Set the IRP to the current IRP and
     * call the StartIo routine */
    if (!Inserted) {
        DeviceObject->CurrentIrp = Irp;

        if (CancelFunction) {
            /* Check if the caller requested no cancellation */
            if (DeviceObject->StartIoFlags & DOE_SIO_NO_CANCEL) {
                /* He did, so remove the cancel routine */
                Irp->CancelRoutine = NULL;
            }
        }
        /* Call the Start I/O function, which will handle cancellation. */
        DeviceObject->DriverObject->DriverStartIo(DeviceObject, Irp);
    } else {
        /* The packet was inserted, which means that the device queue
	 * is busy. Check if we have a cancel function */
        if (CancelFunction) {
            /* Check if the IRP got cancelled */
            if (Irp->Cancel) {
                /* Set the cancel IRQL, clear the currnet cancel routine and
                 * call ours */
                Irp->CancelRoutine = NULL;
                CancelFunction(DeviceObject, Irp);
            }
        }
    }
}

/*
 * @implemented
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoStartNextPacket(IN PDEVICE_OBJECT DeviceObject,
			     IN BOOLEAN Cancelable)
{
    PAGED_CODE();
    /* Check if deferred start was requested */
    if (DeviceObject->StartIoFlags & DOE_SIO_DEFERRED) {
        /* Call our internal function to handle the defered case */
        IopStartNextPacketByKeyEx(DeviceObject,  0,
                                  DOE_SIO_NO_KEY |
                                  (Cancelable ? DOE_SIO_CANCELABLE : 0));
    } else {
        /* Call the normal routine */
        IopStartNextPacket(DeviceObject, Cancelable);
    }
}

/*
 * @implemented
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoStartNextPacketByKey(IN PDEVICE_OBJECT DeviceObject,
				  IN BOOLEAN Cancelable,
				  IN ULONG Key)
{
    PAGED_CODE();
    /* Check if deferred start was requested */
    if (DeviceObject->StartIoFlags & DOE_SIO_DEFERRED) {
        /* Call our internal function to handle the defered case */
        IopStartNextPacketByKeyEx(DeviceObject, Key, DOE_SIO_WITH_KEY |
                                  (Cancelable ? DOE_SIO_CANCELABLE : 0));
    } else {
        /* Call the normal routine */
        IopStartNextPacketByKey(DeviceObject, Cancelable, Key);
    }
}
