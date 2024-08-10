#include <wdmp.h>
#define TEXT(x) L##x
#include <regstr.h>

#define CONTROL_KEY_NAME L"\\Registry\\Machine\\System\\CurrentControlSet\\"
#define PROFILE_KEY_NAME L"Hardware Profiles\\Current\\System\\CurrentControlSet\\"
#define CLASS_KEY_NAME L"Control\\Class\\"
#define ENUM_KEY_NAME L"Enum\\"
#define DEVICE_PARAMETERS_KEY_NAME L"Device Parameters"
#define BOOT_CONFIG_KEY_NAME L"LogConf"

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
					     IN PDRIVER_OBJECT DriverObject)
{
    assert(DriverObject == NULL || DriverObject == &IopDriverObject);
    ObInitializeObject(DeviceObject, CLIENT_OBJECT_DEVICE, DEVICE_OBJECT);
    DeviceObject->Header.Size += DevExtSize;
    DeviceObject->DriverObject = DriverObject;
    DeviceObject->DeviceExtension = DevExtSize ? (PVOID)(DeviceObject + 1) : NULL;
    DeviceObject->DeviceType = DevInfo.DeviceType;
    DeviceObject->Flags = DevInfo.Flags;
    DeviceObject->Header.GlobalHandle = DeviceHandle;
    assert(IopGetDeviceObject(DeviceHandle) == NULL);
    InsertTailList(&IopDeviceList, &DeviceObject->Private.Link);
}

/*
 * Get the device handle if device has already been created. Otherwise,
 * create the device and return the device object. Return NULL if out of memory.
 */
PDEVICE_OBJECT IopGetDeviceObjectOrCreate(IN GLOBAL_HANDLE DeviceHandle,
					  IN IO_DEVICE_INFO DevInfo)
{
    PDEVICE_OBJECT DeviceObject = IopGetDeviceObject(DeviceHandle);
    if (DeviceObject == NULL) {
	DeviceObject = (PDEVICE_OBJECT)ExAllocatePool(sizeof(DEVICE_OBJECT));
	if (DeviceObject == NULL) {
	    return NULL;
	}
	IopInitializeDeviceObject(DeviceObject, 0, DevInfo, DeviceHandle, NULL);
    }
    assert(DeviceObject != NULL);
    return DeviceObject;
}

/*
 * Allocates the client side DEVICE_OBJECT and calls server to create
 * the device object.
 *
 * Note: DeviceName must be a full path.
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

    /* We don't support creating device objects for a different driver. */
    if (DriverObject != &IopDriverObject) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

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

    IopInitializeDeviceObject(DeviceObject, DeviceExtensionSize,
			      DevInfo, DeviceHandle, &IopDriverObject);
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

    DriverObject->DeviceObject = DeviceObject;
    *pDeviceObject = DeviceObject;
    DbgTrace("Created device object %p handle %p extension %p name %ws\n",
	     DeviceObject, (PVOID)DeviceHandle, DeviceObject->DeviceExtension,
	     DeviceName ? DeviceName->Buffer : L"(nil)");
    return STATUS_SUCCESS;
}

NTAPI VOID IoDeleteDevice(IN PDEVICE_OBJECT DeviceObject)
{
}

NTAPI NTSTATUS IoGetDeviceObjectPointer(IN PUNICODE_STRING ObjectName,
					IN ACCESS_MASK DesiredAccess,
					OUT PFILE_OBJECT *FileObject,
					OUT PDEVICE_OBJECT *DeviceObject)
{
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @implemented
 *
 * Call the server to attach the SourceDevice on top of the device
 * stack of TargetDevice, returning the previous topmost device
 * object in the device stack.
 */
NTAPI PDEVICE_OBJECT IoAttachDeviceToDeviceStack(IN PDEVICE_OBJECT SourceDevice,
						 IN PDEVICE_OBJECT TargetDevice)
{
    GLOBAL_HANDLE SourceHandle = IopGetDeviceHandle(SourceDevice);
    GLOBAL_HANDLE TargetHandle = IopGetDeviceHandle(TargetDevice);
    if ((SourceHandle == 0) || (TargetHandle == 0)) {
	assert(FALSE);
	return NULL;
    }
    PDEVICE_OBJECT OldTopDevice = (PDEVICE_OBJECT) ExAllocatePool(sizeof(DEVICE_OBJECT));
    if (OldTopDevice == NULL) {
	return NULL;
    }
    GLOBAL_HANDLE OldTopHandle = 0;
    IO_DEVICE_INFO DevInfo;
    if (!NT_SUCCESS(WdmAttachDeviceToDeviceStack(SourceHandle, TargetHandle,
						 &OldTopHandle, &DevInfo))) {
	IopFreePool(OldTopDevice);
	return NULL;
    }
    assert(OldTopHandle != 0);
    PDEVICE_OBJECT RetVal = IopGetDeviceObject(OldTopHandle);
    if (RetVal == NULL) {
	IopInitializeDeviceObject(OldTopDevice, 0, DevInfo, OldTopHandle, NULL);
	RetVal = OldTopDevice;
    } else {
	IopFreePool(OldTopDevice);
    }
    return RetVal;
}

/*++
 * @name IoGetAttachedDevice
 * @implemented
 *
 * Returns the pointer to the highest level device object in the device stack
 * of the given device object. This routine makes a call to the server so
 * that we always get the most up-to-date device object.
 */
NTAPI PDEVICE_OBJECT IoGetAttachedDevice(IN PDEVICE_OBJECT DeviceObject)
{
    GLOBAL_HANDLE Handle = IopGetDeviceHandle(DeviceObject);
    if (Handle == 0) {
	return NULL;
    }
    GLOBAL_HANDLE TopHandle = 0;
    IO_DEVICE_INFO DevInfo;
    if (!NT_SUCCESS(WdmGetAttachedDevice(Handle, &TopHandle, &DevInfo))) {
	return NULL;
    }
    assert(TopHandle != 0);
    return IopGetDeviceObjectOrCreate(TopHandle, DevInfo);
}

NTAPI PDEVICE_OBJECT IoGetAttachedDeviceReference(IN PDEVICE_OBJECT DeviceObject)
{
    PDEVICE_OBJECT DevObj = IoGetAttachedDevice(DeviceObject);
    if (!DevObj) {
	return NULL;
    }
    DevObj->Header.RefCount++;
    return DevObj;
}

/*
 * @unimplemented
 */
NTAPI VOID IoDetachDevice(IN PDEVICE_OBJECT TargetDevice)
{
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
 *        Returns STATUS_INVALID_DEVICE_REQUEST if registration failed.
 *--*/
NTAPI NTSTATUS IoRegisterDeviceInterface(IN PDEVICE_OBJECT PhysicalDeviceObject,
					 IN CONST GUID *InterfaceClassGuid,
					 IN OPTIONAL PUNICODE_STRING ReferenceString,
					 OUT PUNICODE_STRING SymbolicLinkName)
{
    return STATUS_NOT_IMPLEMENTED;
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
 * @remarks Must be called at IRQL = PASSIVE_LEVEL in the context of a
 *          system thread
 *
 *--*/
NTAPI NTSTATUS IoSetDeviceInterfaceState(IN PUNICODE_STRING SymbolicLinkName,
					 IN BOOLEAN Enable)
{
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
    PWCHAR Path = ExAllocatePool(BufferSize);
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
    InstancePath->Length = BufferSize;
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
	((USHORT)wcslen(REGSTR_PATH_DEVICE_CLASSES) + 1) *
	sizeof(WCHAR) +
	GuidString.Length;
    KeyName.Buffer = ExAllocatePool(KeyName.MaximumLength);
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
	DPRINT("ZwOpenKey() failed with status 0x%08x\n", Status);
	goto cleanup;
    }

    *pInterfaceKey = InterfaceKey;
    Status = STATUS_SUCCESS;

cleanup:
    if (!NT_SUCCESS(Status)) {
	if (InterfaceKey != NULL)
	    ZwClose(InterfaceKey);
    }
    RtlFreeUnicodeString(&GuidString);
    RtlFreeUnicodeString(&KeyName);
    return Status;
}

static NTSTATUS IopQueryValueKey(IN HANDLE KeyHandle,
				 IN PWCHAR ValueName,
				 OUT PKEY_VALUE_PARTIAL_INFORMATION *PartialInfo)
{
    ULONG BufferSize;
    UNICODE_STRING ValueNameU;
    RtlInitUnicodeString(&ValueNameU, ValueName);
    NTSTATUS Status = NtQueryValueKey(KeyHandle, &ValueNameU,
				      KeyValuePartialInformation,
				      NULL, 0, &BufferSize);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
	return Status;
    }

    *PartialInfo = ExAllocatePool(BufferSize);
    if (!*PartialInfo) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = NtQueryValueKey(KeyHandle, &ValueNameU,
			     KeyValuePartialInformation, *PartialInfo,
			     BufferSize, &BufferSize);
    if (!NT_SUCCESS(Status)) {
	ExFreePool(*PartialInfo);
    }
    return Status;
}

static NTSTATUS IopReadRegValue(IN HANDLE KeyHandle,
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
 * @remarks None
 *
 *--*/
NTAPI NTSTATUS IoGetDeviceInterfaces(IN CONST GUID *InterfaceClassGuid,
				     IN OPTIONAL PDEVICE_OBJECT PhysicalDeviceObject,
				     IN ULONG Flags,
				     OUT PWSTR *SymbolicLinkList)
{
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
	Status = NtEnumerateKey(InterfaceKey, i, KeyBasicInformation, NULL, 0, &Size);
	if (Status == STATUS_NO_MORE_ENTRIES) {
	    break;
	} else if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
	    DPRINT("NtEnumerateKey() failed with status 0x%08x\n", Status);
	    goto cleanup;
	}

	DeviceBasicInfo = ExAllocatePool(Size);
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
	    if (PartialInfo->DataLength == DeviceInstancePath.Length &&
		RtlCompareMemory(PartialInfo->Data, DeviceInstancePath.Buffer,
				 DeviceInstancePath.Length) == DeviceInstancePath.Length) {
		FoundRightPDO = TRUE;
	    }
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
	    Status = NtEnumerateKey(DeviceKey, j, KeyBasicInformation, NULL, 0, &Size);
	    if (Status == STATUS_NO_MORE_ENTRIES) {
		break;
	    } else if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
		DPRINT("NtEnumerateKey() failed with status 0x%08x\n", Status);
		goto cleanup;
	    }

	    RefBasicInfo = ExAllocatePool(Size);
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
	    KeyName.Length = KeyName.MaximumLength = (USHORT)ValueInfo->DataLength;
	    KeyName.Buffer = (PWSTR)ValueInfo->Data;

	    /* Fixup the prefix (from "\\?\") */
	    RtlCopyMemory(KeyName.Buffer, L"\\??\\", 4 * sizeof(WCHAR));

	    /* Add new symbolic link to symbolic link list */
	    if (ReturnBuffer.Length + KeyName.Length + sizeof(WCHAR) >
		ReturnBuffer.MaximumLength) {
		PWSTR NewBuffer;
		ReturnBuffer.MaximumLength = (USHORT)max(
		    2 * ReturnBuffer.MaximumLength,
		    (USHORT)(ReturnBuffer.Length + KeyName.Length + 2 * sizeof(WCHAR)));
		NewBuffer = ExAllocatePool(ReturnBuffer.MaximumLength);
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
	NewBuffer = ExAllocatePool(ReturnBuffer.MaximumLength);
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
 */
NTAPI NTSTATUS IoCreateSymbolicLink(IN PUNICODE_STRING SymbolicLinkName,
				    IN PUNICODE_STRING DeviceName)
{
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

static NTSTATUS IopOpenKey(OUT PHANDLE KeyHandle,
			   IN HANDLE ParentKey,
			   IN PUNICODE_STRING Name,
			   IN ACCESS_MASK DesiredAccess)
{
    *KeyHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, Name,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			       ParentKey, NULL);
    return NtOpenKey(KeyHandle, DesiredAccess, &ObjectAttributes);
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
 */
NTAPI NTSTATUS IoOpenDeviceRegistryKey(IN PDEVICE_OBJECT DeviceObject,
				       IN ULONG DevInstKeyType,
				       IN ACCESS_MASK DesiredAccess,
				       OUT PHANDLE DevInstRegKey)
{
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
    KeyNameBuffer = ExAllocatePool(KeyNameLength);
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
    Status = IopOpenKey(DevInstRegKey, NULL, &KeyName, DesiredAccess);
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
 */
NTAPI NTSTATUS IoGetDeviceProperty(IN PDEVICE_OBJECT DeviceObject,
				   IN DEVICE_REGISTRY_PROPERTY DeviceProperty,
				   IN ULONG BufferLength,
				   OUT PVOID PropertyBuffer,
				   OUT PULONG ResultLength)
{
    PWSTR ValueName = NULL;
    ULONG ValueType;
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
    ULONG KeyType = (DeviceProperty == DevicePropertyBootConfiguration)
	? PLUGPLAY_REGKEY_BOOT_CONFIGURATION : 0;
    NTSTATUS Status = IoOpenDeviceRegistryKey(DeviceObject, KeyType, KEY_READ, &KeyHandle);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    Status = IopReadRegValue(KeyHandle, ValueName, ValueType,
			     BufferLength, PropertyBuffer, ResultLength);
    NtClose(KeyHandle);
    return Status;
}

/*
 * Note: this function has a somewhat peculiar behavior at first glance.
 * If the device queue is not busy, the function does NOT insert the entry
 * into the queue, and instead simply sets the device queue to busy.
 * On the other hand, if the device queue is busy, the entry is inserted
 * at the end of the queue. The return value indicates whether the insertion
 * has been performed.
 */
NTAPI BOOLEAN KeInsertDeviceQueue(IN PKDEVICE_QUEUE Queue,
				  IN PKDEVICE_QUEUE_ENTRY Entry)
{
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
 */
NTAPI BOOLEAN KeInsertByKeyDeviceQueue(IN PKDEVICE_QUEUE Queue,
				       IN PKDEVICE_QUEUE_ENTRY Entry,
				       IN ULONG SortKey)
{
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
 */
NTAPI PKDEVICE_QUEUE_ENTRY KeRemoveDeviceQueue(IN PKDEVICE_QUEUE Queue)
{
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
 */
NTAPI PKDEVICE_QUEUE_ENTRY KeRemoveByKeyDeviceQueue(IN PKDEVICE_QUEUE Queue,
						    IN ULONG SortKey)
{
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
