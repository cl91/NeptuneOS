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
	    PPENDING_IRP PendingIrp;
	    PCLOSE_DEVICE_REQUEST CloseReq;
	});

    if (!IopIsStorageDevice(DevObj)) {
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }

    /* If the volume is being dismounted, exit now. */
    if (DevObj->Vcb && DevObj->Vcb->Dismounted) {
	ASYNC_RETURN(State, STATUS_VOLUME_DISMOUNTED);
    }

    /* If another mount is already in progress, wait for it to complete. */
    AWAIT_IF(DevObj->Vcb && DevObj->Vcb->MountInProgress, KeWaitForSingleObject,
	     State, Locals, Thread, &DevObj->MountCompleted.Header, FALSE, NULL);
    if (DevObj->Vcb) {
	assert(!DevObj->Vcb->MountInProgress);
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }

    DevObj->Vcb = ExAllocatePoolWithTag(sizeof(IO_VOLUME_CONTROL_BLOCK), NTOS_IO_TAG);
    if (!DevObj->Vcb) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }
    DevObj->Vcb->MountInProgress = TRUE;
    /* FileSize is set to zero for the time being as we don't know the volume size yet. */
    IF_ERR_GOTO(out, Status, IopCreateFcb(&DevObj->Vcb->VolumeFcb, 0, "\\$$Volume$$",
					  DevObj->Vcb, 0));
    IF_ERR_GOTO(out, Status, ObCreateObject(OBJECT_TYPE_DIRECTORY,
					    (PVOID *)&DevObj->Vcb->Subobjects, NULL));
    DevObj->Vcb->StorageDevice = DevObj;

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

next:
    /* Loop over the fs list and send the mount request to each FS, until one of them
     * is able to mount the volume. */
    if (Locals.Entry == Locals.FsList) {
	goto out;
    }
    Locals.CurrentFs = CONTAINING_RECORD(Locals.Entry, IO_FILE_SYSTEM, ListEntry);

    /* Queue a CLOSE_DEVICE_REQUEST to the storage device so when it gets
     * deleted, the file system driver will know. */
    assert(!Locals.CloseReq);
    Locals.CloseReq = ExAllocatePoolWithTag(sizeof(CLOSE_DEVICE_REQUEST),
					    NTOS_IO_TAG);
    if (!Locals.CloseReq) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }
    Locals.CloseReq->Req = ExAllocatePoolWithTag(sizeof(IO_PACKET), NTOS_IO_TAG);
    if (!Locals.CloseReq->Req) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL,
	.MinorFunction = IRP_MN_MOUNT_VOLUME,
	.Device.Object = Locals.CurrentFs->FsctlDevObj,
	.MountVolume.StorageDevice = OBJECT_TO_GLOBAL_HANDLE(DevObj),
	.MountVolume.StorageDeviceInfo = DevObj->DeviceInfo
    };
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));
    Locals.CloseReq->DriverObject = Locals.CurrentFs->FsctlDevObj->DriverObject;
    Locals.CloseReq->DeviceObject = DevObj;
    InsertTailList(&DevObj->CloseReqList, &Locals.CloseReq->DeviceLink);
    InsertTailList(&Locals.CloseReq->DriverObject->CloseDeviceReqList,
		   &Locals.CloseReq->DriverLink);
    Locals.CloseReq = NULL;

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);

    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (NT_SUCCESS(Status)) {
	/* Get the volume device that the FS driver has created, and link it with our VCB. */
	PIO_RESPONSE_DATA Response = Locals.PendingIrp->IoResponseData;
	if (!Response) {
	    /* In case of success the client should supply us with valid IO response data.
	     * On debug build we stop so we can find out what's going on. */
	    assert(FALSE);
	    Status = STATUS_UNRECOGNIZED_VOLUME;
	    goto out;
	}
	if (!Response->VolumeMounted.VolumeSize) {
	    assert(FALSE);
	    Status = STATUS_UNRECOGNIZED_VOLUME;
	    goto out;
	}
	PIO_DEVICE_OBJECT VolumeDevice = IopGetDeviceObject(Response->VolumeMounted.VolumeDeviceHandle,
							    Locals.CurrentFs->FsctlDevObj->DriverObject);
	if (!VolumeDevice) {
	    assert(FALSE);
	    Status = STATUS_UNRECOGNIZED_VOLUME;
	    goto out;
	}
	DevObj->Vcb->VolumeDevice = VolumeDevice;
	DevObj->Vcb->ClusterSize = Response->VolumeMounted.ClusterSize;
	DevObj->Vcb->MountInProgress = FALSE;
	VolumeDevice->Vcb = DevObj->Vcb;
	DevObj->Vcb->VolumeFcb->FileSize = Response->VolumeMounted.VolumeSize;
    } else {
	IopCleanupPendingIrp(Locals.PendingIrp);
	Locals.PendingIrp = NULL;
	Locals.Entry = Locals.Entry->Flink;
	goto next;
    }

out:
    if (Locals.CloseReq) {
	if (Locals.CloseReq->Req) {
	    IopFreePool(Locals.CloseReq->Req);
	}
	IopFreePool(Locals.CloseReq);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    if (DevObj->Vcb && !NT_SUCCESS(Status)) {
	if (DevObj->Vcb->VolumeFcb) {
	    IopDeleteFcb(DevObj->Vcb->VolumeFcb);
	}
	if (DevObj->Vcb->Subobjects) {
	    ObDereferenceObject(DevObj->Vcb->Subobjects);
	}
	IopFreePool(DevObj->Vcb);
	DevObj->Vcb = NULL;
    }
    KeSetEvent(&DevObj->MountCompleted);
    ASYNC_END(State, Status);
}

NTSTATUS WdmRegisterFileSystem(IN ASYNC_STATE State,
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

VOID IopDismountVolume(IN PIO_DEVICE_OBJECT VolumeDevice)
{
    assert(VolumeDevice);
    assert(VolumeDevice->Vcb);
    if (!VolumeDevice || !VolumeDevice->Vcb) {
	return;
    }
    PIO_VOLUME_CONTROL_BLOCK Vcb = VolumeDevice->Vcb;
    DbgTrace("Dismounting volume with Vcb %p\n", Vcb);
    IopDbgDumpVcb(Vcb);
    Vcb->Dismounted = TRUE;
    /* Decrease the refcount of the volume file that we increased in IopOpenDevice,
     * when the volume file was first opened. */
    ObDereferenceObject(Vcb->VolumeFile);
    /* Dereference the volume device object that the file system driver created
     * when mounting the volume. */
    ObDereferenceObject(Vcb->VolumeDevice);
    /* TODO: Force dismount. This is used in the VERIFY_VOLUME case. */
}

static VOID IopDbgVcbSubobjectVisitor(IN POBJECT Object,
				      IN PVOID Context)
{
    ULONG Indentation = (ULONG)(ULONG_PTR)Context;
    OBJECT_TYPE_ENUM Type = ObObjectGetType(Object);
    if (Type == OBJECT_TYPE_DIRECTORY) {
	ObDirectoryObjectVisitObject((POBJECT_DIRECTORY)Object,
				     IopDbgVcbSubobjectVisitor, (PCHAR)Context+2);
    } else if (Type == OBJECT_TYPE_FILE) {
	IoDbgDumpFileObject((PIO_FILE_OBJECT)Object, Indentation + 2);
    } else {
	DbgPrint("Invalid object type %d\n", Type);
	assert(FALSE);
    }
}

VOID IopDbgDumpVcb(IN PIO_VOLUME_CONTROL_BLOCK Vcb)
{
    DbgPrint("Dumping VCB %p\n", Vcb);
    DbgPrint("  VolumeDevice %p StorageDevice %p\n  VolumeFcb %p VolumeFile %p\n"
	     "  ClusterSize 0x%x MountInProgress %d Dismounted %d\n",
	     Vcb->VolumeDevice, Vcb->StorageDevice, Vcb->VolumeFcb, Vcb->VolumeFile,
	     Vcb->ClusterSize, Vcb->MountInProgress, Vcb->Dismounted);
    IopDbgDumpDeviceObject(Vcb->VolumeDevice, 2);
    IopDbgDumpDeviceObject(Vcb->StorageDevice, 2);
    IoDbgDumpFileObject(Vcb->VolumeFile, 2);
    ObDirectoryObjectVisitObject(Vcb->Subobjects, IopDbgVcbSubobjectVisitor, (PVOID)2);
}
