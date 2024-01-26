#include "iop.h"

typedef struct _IO_FILE_SYSTEM {
    PIO_DEVICE_OBJECT FsctlDevObj; /* Device object to which we send FS control IRPs. */
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

/*
 * If the specified device object is a volume on a storage device, try
 * mounting the device. Otherwise, we return success.
 *
 * Note that network file systems are handled separately from this logic because
 * mounting a network FS typically involves specifying additional parameters,
 * such as network address and login information. Usually a "userspace" program
 * will initiate the mount process by issuing the mount request directly to
 * the network FS driver.
 */
NTSTATUS IopMountVolume(IN ASYNC_STATE State,
			IN PTHREAD Thread,
			IN PIO_DEVICE_OBJECT DevObj)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State, Locals, {
	    PLIST_ENTRY FsList;
	    PLIST_ENTRY Entry;
	    PIO_FILE_SYSTEM CurrentFs;
	    PIO_PACKET IoPacket;
	    PPENDING_IRP PendingIrp;
	});

    if (!IopIsStorageDevice(DevObj)) {
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }
    Locals.IoPacket = NULL;
    Locals.PendingIrp = NULL;

    /* If another mount is already in progress, wait for it to complete. */
    AWAIT_IF(DevObj->Vcb && DevObj->Vcb->MountInProgress, KeWaitForSingleObject,
	     State, Locals, Thread, &DevObj->MountCompleted.Header, FALSE, NULL);
    if (DevObj->Vcb) {
	assert(!DevObj->Vcb->MountInProgress);
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }

    DevObj->Vcb = ExAllocatePoolWithTag(sizeof(IO_VOLUME_CONTROL_BLOCK), NTOS_IO_TAG);
    if (!DevObj->Vcb) {
	ASYNC_RETURN(State, STATUS_NO_MEMORY);
    }
    DevObj->Vcb->MountInProgress = TRUE;

    /* Select the appropriate list of file systems to send the mount request to. */
    if ((DevObj->DeviceInfo.DeviceType == FILE_DEVICE_DISK) ||
	(DevObj->DeviceInfo.DeviceType == FILE_DEVICE_VIRTUAL_DISK)) {
	Locals.FsList = &IopDiskFileSystemList;
    } else if (DevObj->DeviceInfo.DeviceType == FILE_DEVICE_CD_ROM) {
	Locals.FsList = &IopCdRomFileSystemList;
    } else {
	Locals.FsList = &IopTapeFileSystemList;
    }
    Locals.Entry = Locals.FsList->Flink;
    Status = STATUS_UNRECOGNIZED_VOLUME;

    /* Loop over the fs list and send the mount request to each FS, until one of them
     * is able to mount the volume. */
next:
    if (Locals.Entry == Locals.FsList) {
	goto out;
    }
    Locals.CurrentFs = CONTAINING_RECORD(Locals.Entry, IO_FILE_SYSTEM, ListEntry);
    IF_ERR_GOTO(out, Status,
		IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &Locals.IoPacket));
    assert(Locals.IoPacket != NULL);

    Locals.IoPacket->Request.MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
    Locals.IoPacket->Request.MinorFunction = IRP_MN_MOUNT_VOLUME;
    Locals.IoPacket->Request.MountVolume.StorageDevice = OBJECT_TO_GLOBAL_HANDLE(DevObj);
    Locals.IoPacket->Request.MountVolume.StorageDeviceInfo = DevObj->DeviceInfo;
    Locals.IoPacket->Request.Device.Object = Locals.CurrentFs->FsctlDevObj;
    IF_ERR_GOTO(out, Status, IopAllocatePendingIrp(Locals.IoPacket, Thread, &Locals.PendingIrp));
    IopQueueIoPacket(Locals.PendingIrp, Thread);

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);

    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	IopCleanupPendingIrp(Locals.PendingIrp);
	Locals.PendingIrp = NULL;
	Locals.IoPacket = NULL;
	Locals.Entry = Locals.Entry->Flink;
	goto next;
    }

out:
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    } else if (Locals.IoPacket) {
	IopFreePool(Locals.IoPacket);
    }
    if (DevObj->Vcb) {
	if (NT_SUCCESS(Status)) {
	    DevObj->Vcb->MountInProgress = FALSE;
	} else {
	    IopFreePool(DevObj->Vcb);
	    DevObj->Vcb = NULL;
	}
    }
    KeSetEvent(&DevObj->MountCompleted);
    ASYNC_END(State, Status);
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
    FsObj->FsctlDevObj = DevObj;
    return STATUS_SUCCESS;
}
