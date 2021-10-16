#include <hal.h>

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

    HANDLE DeviceHandle = 0;
    RET_ERR_EX(IopCreateDevice(DeviceName, DeviceType, DeviceCharacteristics,
			       Exclusive, &DeviceHandle),
	       IopFreePool(DeviceObject));
    assert(DeviceHandle != 0);
    DeviceObject->DeviceHandle = DeviceHandle;

    return STATUS_SUCCESS;
}

NTAPI VOID IoDeleteDevice(IN PDEVICE_OBJECT DeviceObject)
{
}
