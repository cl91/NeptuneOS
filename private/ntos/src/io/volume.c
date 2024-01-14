#include "iop.h"

typedef struct _IO_FILE_SYSTEM {
    PIO_DEVICE_OBJECT DevObj;
    LIST_ENTRY ListEntry;
} IO_FILE_SYSTEM, *PIO_FILE_SYSTEM;

static LIST_ENTRY IopDiskFileSystemList;
static LIST_ENTRY IopNetworkFileSystemList;
static LIST_ENTRY IopCdRomFileSystemList;
static LIST_ENTRY IopTapeFileSystemList;

NTSTATUS IopInitFileSystem()
{
    InitializeListHead(&IopDiskFileSystemList);
    InitializeListHead(&IopNetworkFileSystemList);
    InitializeListHead(&IopCdRomFileSystemList);
    InitializeListHead(&IopTapeFileSystemList);
    return STATUS_SUCCESS;
}

NTSTATUS IopMountVolume(IN ASYNC_STATE State,
			IN PTHREAD Thread,
			IN PIO_DEVICE_OBJECT DevObj)
{
    if (!IopIsVolumeDevice(DevObj) || IopIsVolumeMounted(DevObj)) {
	return STATUS_SUCCESS;
    }
    UNIMPLEMENTED;
}

NTSTATUS IopRegisterFileSystem(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN GLOBAL_HANDLE DeviceHandle)
{
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    PIO_DEVICE_OBJECT DevObj = IopGetDeviceObject(DeviceHandle, DriverObject);
    if (!DevObj) {
	/* This shouldn't happen since we checked the validity of device handle on client side. */
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    IopAllocatePool(FsObj, IO_FILE_SYSTEM);

    /* Check what kind of FS this is. */
    PLIST_ENTRY FsList = NULL;
    DEVICE_TYPE DevType = DevObj->DeviceInfo.DeviceType;
    if (DevType == FILE_DEVICE_DISK_FILE_SYSTEM) {
        FsList = &IopDiskFileSystemList;
    } else if (DevType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        FsList = &IopNetworkFileSystemList;
    } else if (DevType == FILE_DEVICE_CD_ROM_FILE_SYSTEM) {
        FsList = &IopCdRomFileSystemList;
    } else if (DevType == FILE_DEVICE_TAPE_FILE_SYSTEM) {
        FsList = &IopTapeFileSystemList;
    } else {
	IopFreePool(FsObj);
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    assert(FsList);
    /* We insert to the head of the list so file system drivers loaded later
     * take priority. Typically the file system recognizer is the first file
     * system driver loaded in a system, so this way it will be the last
     * file system driver that the system tries when mounting a volume. */
    InsertHeadList(FsList, &FsObj->ListEntry);
    FsObj->DevObj = DevObj;
    return STATUS_SUCCESS;
}
