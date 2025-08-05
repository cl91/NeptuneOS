#include "iop.h"

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
    /* If the driver crashed during the mount, the device will be marked as removed,
     * in which case we return error. */
    if (DevObj->Removed) {
	ASYNC_RETURN(State, STATUS_IO_DEVICE_ERROR);
    }

    DevObj->Vcb = ExAllocatePoolWithTag(sizeof(IO_VOLUME_CONTROL_BLOCK), NTOS_IO_TAG);
    if (!DevObj->Vcb) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }
    DevObj->Vcb->ForceDismountMsg = ExAllocatePoolWithTag(sizeof(IO_PACKET), NTOS_IO_TAG);
    if (!DevObj->Vcb->ForceDismountMsg) {
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
	Locals.CurrentFs = NULL;
	goto out;
    }
    Locals.CurrentFs = CONTAINING_RECORD(Locals.Entry, IO_FILE_SYSTEM, ListEntry);

    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL,
	.MinorFunction = IRP_MN_MOUNT_VOLUME,
	.Device.Object = Locals.CurrentFs->FsctlDevObj,
	.MountVolume.StorageDeviceInfo = DevObj->DeviceInfo
    };
    /* Queue a CLOSE_DEVICE_MESSAGE to the storage device so when it gets
     * deleted, the file system driver will know. */
    IF_ERR_GOTO(out, Status,
		IopGrantDeviceHandleToDriver(DevObj,
					     Locals.CurrentFs->FsctlDevObj->DriverObject,
					     &Irp.MountVolume.StorageDevice));
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));

    /* Increase the refcount of the FSCTL device object, so it won't get deleted
     * if the file system driver crashed during the mount. */
    ObpReferenceObject(Locals.CurrentFs->FsctlDevObj);
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
	if (!DevObj->Vcb) {
	    /* If the storage driver crashed, the file system driver should complete the IRP with
	     * an error status. We assert on debug build so we can fix the file system driver. */
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
	ObDereferenceObject(Locals.CurrentFs->FsctlDevObj);
	goto next;
    }

out:
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    if (Locals.CurrentFs && Locals.CurrentFs->FsctlDevObj) {
	ObDereferenceObject(Locals.CurrentFs->FsctlDevObj);
    }
    if (DevObj->Vcb && !NT_SUCCESS(Status)) {
	if (DevObj->Vcb->VolumeFcb) {
	    IopDeleteFcb(DevObj->Vcb->VolumeFcb);
	}
	if (DevObj->Vcb->Subobjects) {
	    ObDereferenceObject(DevObj->Vcb->Subobjects);
	}
	if (DevObj->Vcb->ForceDismountMsg) {
	    IopFreePool(DevObj->Vcb->ForceDismountMsg);
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
    DevObj->FsObj = FsObj;
    DbgTrace("Registered file system control device object %p\n", DevObj);
    return STATUS_SUCCESS;
}

VOID IopUnregisterFileSystem(IN PIO_DEVICE_OBJECT DevObj)
{
    DbgTrace("Unregistering FSCTL dev obj %p\n", DevObj);
    PIO_FILE_SYSTEM FsObj = DevObj->FsObj;
    assert(FsObj);
    assert(FsObj->ListEntry.Blink);
    assert(FsObj->ListEntry.Flink);
    assert(ListHasEntry(&IopDiskFileSystemList, &FsObj->ListEntry) ||
	   ListHasEntry(&IopCdRomFileSystemList, &FsObj->ListEntry) ||
	   ListHasEntry(&IopNetworkFileSystemList, &FsObj->ListEntry) ||
	   ListHasEntry(&IopTapeFileSystemList, &FsObj->ListEntry));
    RemoveEntryList(&FsObj->ListEntry);
    IopFreePool(FsObj);
    DevObj->FsObj = NULL;
}

static VOID IopVcbDetachSubobject(IN POBJECT Object,
				  IN PVOID Context)
{
    if (ObObjectIsType(Object, OBJECT_TYPE_DIRECTORY)) {
	ObDirectoryObjectVisitObject(Object, IopVcbDetachSubobject, NULL);
	assert(ObGetObjectRefCount(Object) == 1);
	ObDereferenceObject(Object);
    } else {
	assert(ObObjectIsType(Object, OBJECT_TYPE_FILE));
	ObRemoveObject(Object);
    }
}

VOID IopDismountVolume(IN PIO_VOLUME_CONTROL_BLOCK Vcb,
		       IN BOOLEAN Force)
{
    assert(Vcb);
    if (!Vcb) {
	return;
    }
    DbgTrace("Dismounting volume with Vcb %p\n", Vcb);
    IopDbgDumpVcb(Vcb);
    Vcb->Dismounted = TRUE;
    /* Decrease the refcount of the volume file that we increased in IopOpenDevice,
     * when the volume file was first opened. */
    if (Vcb->VolumeFile) {
	ObDereferenceObject(Vcb->VolumeFile);
    }
    /* If we are forcing the dismount due to for instance media change or a driver
     * crashing, queue the ForceDismount message to the file system driver. Note if
     * the file system driver has already crashed at this point, the queued IO packet
     * will be deleted soon, by the delete routine of the driver object. */
    if (Force) {
	if (Vcb->VolumeDevice) {
	    assert(Vcb->ForceDismountMsg);
	    PIO_PACKET Msg = Vcb->ForceDismountMsg;
	    Vcb->ForceDismountMsg = NULL;
	    Msg->Type = IoPacketTypeServerMessage;
	    Msg->Size = sizeof(IO_PACKET);
	    Msg->ServerMsg.Type = IoSrvMsgForceDismount;
	    Msg->ServerMsg.ForceDismount.VolumeDevice = OBJECT_TO_GLOBAL_HANDLE(Vcb->VolumeDevice);
	    InsertTailList(&Vcb->VolumeDevice->DriverObject->IoPacketQueue, &Msg->IoPacketLink);
	    KeSetEvent(&Vcb->VolumeDevice->DriverObject->IoPacketQueuedEvent);
	}
	if (Vcb->Subobjects) {
	    /* Detach the file objects of this volume from the volume control block.
	     * This is only needed if we are forcing the dismount. For normal dismount
	     * the subobject directory should be empty. */
	    ObDirectoryObjectVisitObject(Vcb->Subobjects, IopVcbDetachSubobject, NULL);
	    assert(ObGetObjectRefCount(Vcb->Subobjects) == 1);
	    ObDereferenceObject(Vcb->Subobjects);
	}
	if (Vcb->VolumeFcb) {
	    IopDeleteFcb(Vcb->VolumeFcb);
	}
	/* If we are force dismounting during the process of mounting the volume
	 * (this happens for instance, when the storage driver has crashed),
	 * signal the mount completion event. */
	if (Vcb->MountInProgress) {
	    KeSetEvent(&Vcb->StorageDevice->MountCompleted);
	}
	/* Detach the VCB from the device objects. Note in the normal dismount case,
	 * this is done when the volume device is deleted. */
	if (Vcb->VolumeDevice) {
	    Vcb->VolumeDevice->Vcb = NULL;
	}
	if (Vcb->StorageDevice) {
	    Vcb->StorageDevice->Vcb = NULL;
	}
	IopFreePool(Vcb);
    } else {
	/* Else, just dereference the volume device object that the file system driver
	 * created when mounting the volume. Note the refcount of the volume device should
	 * be greater than one at this point, so the deref will not delete the object. */
	assert(ObGetObjectRefCount(Vcb->VolumeDevice) > 1);
	ObDereferenceObject(Vcb->VolumeDevice);
    }
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
