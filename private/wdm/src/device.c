#include <wdmp.h>

/* Caches all device objects that have been queried, including
 * the device objects created by this driver. */
LIST_ENTRY IopDeviceList;

/*
 * Search the list of all cached device objects and return
 * the one matching the given GLOBAL_HANDLE. Returns NULL if not found.
 */
PDEVICE_OBJECT IopGetDeviceObject(IN GLOBAL_HANDLE Handle)
{
    LoopOverList(Entry, &IopDeviceList, DEVICE_LIST_ENTRY, Link) {
	if (Handle == Entry->Handle) {
	    return Entry->Object;
	}
    }
    return NULL;
}

/*
 * Search the list of all cached device objects and return the global
 * handle of the given device object pointer. Returns NULL if not found.
 */
GLOBAL_HANDLE IopGetDeviceHandle(IN PDEVICE_OBJECT Device)
{
    LoopOverList(Entry, &IopDeviceList, DEVICE_LIST_ENTRY, Link) {
	if (Device == Entry->Object) {
	    return Entry->Handle;
	}
    }
    return 0;
}

static inline VOID IopInitializeDeviceObject(IN PDEVICE_OBJECT DeviceObject,
					     IN ULONG DevExtSize,
					     IN IO_DEVICE_INFO DevInfo)
{
    DeviceObject->Type = IO_TYPE_DEVICE;
    DeviceObject->Size = sizeof(DEVICE_OBJECT) + DevExtSize;
    DeviceObject->DeviceExtension = DevExtSize ? (PVOID)(DeviceObject + 1) : NULL;
    DeviceObject->DeviceType = DevInfo.DeviceType;
    DeviceObject->Characteristics = DevInfo.DeviceCharacteristics;
}

static inline VOID IopInsertDeviceList(IN PDEVICE_OBJECT DeviceObject,
				       IN GLOBAL_HANDLE DeviceHandle,
				       IN PDEVICE_LIST_ENTRY DeviceListEntry)
{
    DeviceListEntry->Object = DeviceObject;
    DeviceListEntry->Handle = DeviceHandle;
    InsertTailList(&IopDeviceList, &DeviceListEntry->Link);
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
			      IN ULONG DeviceCharacteristics,
			      IN BOOLEAN Exclusive,
			      OUT PDEVICE_OBJECT *pDeviceObject)
{
    assert(DriverObject != NULL);
    assert(pDeviceObject != NULL);

    /* Both device object and device extension are aligned by MEMORY_ALLOCATION_ALIGNMENT */
    SIZE_T AlignedDevExtSize = ALIGN_UP_BY(DeviceExtensionSize,
					   MEMORY_ALLOCATION_ALIGNMENT);

    /* The driver-specific device extension follows the DEVICE_OBJECT */
    SIZE_T TotalSize = sizeof(DEVICE_OBJECT) + AlignedDevExtSize;
    IopAllocatePool(DeviceObject, DEVICE_OBJECT, TotalSize);
    IopAllocateObjectEx(DeviceListEntry, DEVICE_LIST_ENTRY, IopFreePool(DeviceObject));

    IO_DEVICE_INFO DevInfo = {
	.DeviceType = DeviceType,
	.DeviceCharacteristics = DeviceCharacteristics
    };
    IopInitializeDeviceObject(DeviceObject, DeviceExtensionSize, DevInfo);
    DeviceObject->DriverObject = DriverObject;
    DeviceObject->Flags = DO_DEVICE_INITIALIZING;
    if (Exclusive) {
	DeviceObject->Flags |= DO_EXCLUSIVE;
    }
    if (DeviceName) {
	DeviceObject->Flags |= DO_DEVICE_HAS_NAME;
	RtlDuplicateUnicodeString(0, DeviceName, &DeviceObject->DeviceName);
    }
    KeInitializeDeviceQueue(&DeviceObject->DeviceQueue);

    /* Set the right Sector Size. TODO: Server-side? */
    switch (DeviceType) {
        case FILE_DEVICE_DISK_FILE_SYSTEM:
        case FILE_DEVICE_DISK:
        case FILE_DEVICE_VIRTUAL_DISK:
            /* The default is 512 bytes */
            DeviceObject->SectorSize  = 512;
            break;
        case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
            /* The default is 2048 bytes */
            DeviceObject->SectorSize = 2048;
    }

    GLOBAL_HANDLE DeviceHandle = 0;
    RET_ERR_EX(IopCreateDevice(DeviceName, &DevInfo, Exclusive, &DeviceHandle),
	       {
		   IopFreePool(DeviceObject);
		   IopFreePool(DeviceListEntry);
	       });
    assert(DeviceHandle != 0);
    assert(IopGetDeviceObject(DeviceHandle) == NULL);
    IopInsertDeviceList(DeviceObject, DeviceHandle, DeviceListEntry);

    *pDeviceObject = DeviceObject;
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
    PDEVICE_LIST_ENTRY DeviceListEntry = (PDEVICE_LIST_ENTRY) ExAllocatePool(sizeof(DEVICE_LIST_ENTRY));
    if (DeviceListEntry == NULL) {
	ExFreePool(OldTopDevice);
	return NULL;
    }
    GLOBAL_HANDLE OldTopHandle = 0;
    IO_DEVICE_INFO DevInfo;
    if (!NT_SUCCESS(IopIoAttachDeviceToDeviceStack(SourceHandle, TargetHandle,
						   &OldTopHandle, &DevInfo))) {
	IopFreePool(OldTopDevice);
	return NULL;
    }
    assert(OldTopHandle != 0);
    PDEVICE_OBJECT RetVal = IopGetDeviceObject(OldTopHandle);
    if (RetVal == NULL) {
	IopInitializeDeviceObject(OldTopDevice, 0, DevInfo);
	IopInsertDeviceList(OldTopDevice, OldTopHandle, DeviceListEntry);
	RetVal = OldTopDevice;
    } else {
	IopFreePool(OldTopDevice);
	IopFreePool(DeviceListEntry);
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
    if (!NT_SUCCESS(IopGetAttachedDevice(Handle, &TopHandle, &DevInfo))) {
	return NULL;
    }
    assert(TopHandle != 0);
    PDEVICE_OBJECT TopDevice = IopGetDeviceObject(TopHandle);
    if (TopDevice == NULL) {
	TopDevice = (PDEVICE_OBJECT)ExAllocatePool(sizeof(DEVICE_OBJECT));
	if (TopDevice == NULL) {
	    return NULL;
	}
	PDEVICE_LIST_ENTRY DeviceListEntry = (PDEVICE_LIST_ENTRY)ExAllocatePool(sizeof(DEVICE_LIST_ENTRY));
	if (DeviceListEntry == NULL) {
	    ExFreePool(TopDevice);
	    return NULL;
	}
	IopInitializeDeviceObject(TopDevice, 0, DevInfo);
	IopInsertDeviceList(TopDevice, TopHandle, DeviceListEntry);
    }
    return TopDevice;
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
					 IN PUNICODE_STRING ReferenceString OPTIONAL,
					 OUT PUNICODE_STRING SymbolicLinkName)
{
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @implemented
 */
NTAPI VOID IoDetachDevice(IN PDEVICE_OBJECT TargetDevice)
{
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
