#include <hal.h>

/* List of all devices created by this driver */
LIST_ENTRY IopDeviceList;

/*
 * Search the list of all devices created by this driver and return
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

    DeviceObject->Type = IO_TYPE_DEVICE;
    DeviceObject->Size = sizeof(DEVICE_OBJECT) + DeviceExtensionSize;
    DeviceObject->DriverObject = DriverObject;
    DeviceObject->DeviceExtension = (PVOID)(DeviceObject + 1);
    DeviceObject->DeviceType = DeviceType;
    DeviceObject->Characteristics = DeviceCharacteristics;
    DeviceObject->StackSize = 1;
    DeviceObject->Flags = DO_DEVICE_INITIALIZING;
    if (Exclusive) {
	DeviceObject->Flags |= DO_EXCLUSIVE;
    }
    if (DeviceName) {
	DeviceObject->Flags |= DO_DEVICE_HAS_NAME;
    }
    KeInitializeDeviceQueue(&DeviceObject->DeviceQueue);

    /* Set the right Sector Size */
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
    RET_ERR_EX(IopCreateDevice(DeviceName, DeviceType, DeviceCharacteristics,
			       Exclusive, &DeviceHandle),
	       {
		   IopFreePool(DeviceObject);
		   IopFreePool(DeviceListEntry);
	       });
    assert(DeviceHandle != 0);
    DeviceListEntry->Object = DeviceObject;
    DeviceListEntry->Handle = DeviceHandle;
    InsertTailList(&IopDeviceList, &DeviceListEntry->Link);

    *pDeviceObject = DeviceObject;
    return STATUS_SUCCESS;
}

NTAPI VOID IoDeleteDevice(IN PDEVICE_OBJECT DeviceObject)
{
}
