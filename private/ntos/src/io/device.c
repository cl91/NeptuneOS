#include "iop.h"

/*
 * Creation context for the device object creation routine
 */
typedef struct _DEVICE_OBJ_CREATE_CONTEXT {
    PIO_DRIVER_OBJECT DriverObject;
    IO_DEVICE_INFO DeviceInfo;
    BOOLEAN Exclusive;
} DEVICE_OBJ_CREATE_CONTEXT, *PDEVICE_OBJ_CREATE_CONTEXT;

NTSTATUS IopDeviceObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx)
{
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT)Object;
    PDEVICE_OBJ_CREATE_CONTEXT Ctx = (PDEVICE_OBJ_CREATE_CONTEXT)CreaCtx;
    PIO_DRIVER_OBJECT DriverObject = Ctx->DriverObject;
    IO_DEVICE_INFO DeviceInfo = Ctx->DeviceInfo;
    BOOLEAN Exclusive = Ctx->Exclusive;
    InitializeListHead(&Device->OpenFileList);
    InitializeListHead(&Device->CloseMsgList);
    KeInitializeEvent(&Device->MountCompleted, NotificationEvent);

    Device->DriverObject = DriverObject;
    ObpReferenceObject(DriverObject);
    InsertTailList(&DriverObject->DeviceList, &Device->DeviceLink);
    Device->DeviceInfo = DeviceInfo;
    Device->Exclusive = Exclusive;

    return STATUS_SUCCESS;
}

NTSTATUS IopDeviceObjectParseProc(IN POBJECT Self,
				  IN PCSTR Path,
				  IN BOOLEAN CaseInsensitive,
				  OUT POBJECT *FoundObject,
				  OUT PCSTR *RemainingPath)
{
    assert(Self != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    assert(RemainingPath != NULL);

    PIO_DEVICE_OBJECT DevObj = (PIO_DEVICE_OBJECT)Self;
    DbgTrace("Device %p trying to parse Path = %s case-%s\n", Self, Path,
	     CaseInsensitive ? "insensitively" : "sensitively");

    *RemainingPath = Path;
    *FoundObject = NULL;
    /* If the device object is not a mounted volume, we should stop parsing.
     * Non-volume devices do not cache subobjects. */
    if (!DevObj->Vcb) {
	return STATUS_NTOS_STOP_PARSING;
    }

    /* If the path is empty, return the volume file object. Note this is different
     * from the root directory file. */
    if (!Path[0]) {
	*FoundObject = DevObj->Vcb->VolumeFile;
	return *FoundObject ? STATUS_SUCCESS : STATUS_OBJECT_PATH_NOT_FOUND;
    }

    if (!DevObj->Vcb->Subobjects) {
	/* A successfully mounted volume should always have the Subobjects
	 * directory, so there must be a bug. */
	assert(FALSE);
	return STATUS_NTOS_BUG;
    }

    RET_ERR(ObParseObjectByName(DevObj->Vcb->Subobjects, Path,
				CaseInsensitive, FoundObject));
    /* If the object we found is an object directory, return the directory file
     * object, located under the object directory with name "." */
    if (ObObjectIsType(*FoundObject, OBJECT_TYPE_DIRECTORY)) {
	RET_ERR(ObParseObjectByName(*FoundObject, ".", FALSE, FoundObject));
    }
    *RemainingPath = Path + strlen(Path);
    return STATUS_SUCCESS;
}

NTSTATUS IopDeviceObjectInsertProc(IN POBJECT Self,
				   IN POBJECT Object,
				   IN PCSTR Path)
{
    PIO_DEVICE_OBJECT DevObj = Self;
    PIO_FILE_OBJECT FileObj = Object;
    assert(Self != NULL);
    assert(Path != NULL);
    assert(Object != NULL);
    DbgTrace("Inserting subobject %p (path %s, type %d) for device object %p\n",
	     Object, Path, ObObjectGetType(Object), Self);

    /* The object to be inserted must be a file object. */
    if (!ObObjectIsType(Object, OBJECT_TYPE_FILE)) {
	assert(FALSE);
	return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* The device object must be a mounted volume device. */
    if (!DevObj->Vcb) {
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!DevObj->Vcb->Subobjects) {
	/* A successfully mounted volume should always have the Subobjects
	 * directory, so there must be a bug. */
	assert(FALSE);
	return STATUS_NTOS_BUG;
    }

    /* If the object path is empty, we insert the file object as the volume file object. */
    if (*Path == '\0') {
	if (DevObj->Vcb->VolumeFile) {
	    assert(FALSE);
	    ObRemoveObject(DevObj->Vcb->VolumeFile);
	}
	/* The volume file object should not have a parent directory object. */
	assert(!OBJECT_TO_OBJECT_HEADER(FileObj)->ParentLink);
	DevObj->Vcb->VolumeFile = FileObj;
	/* Increase its refcount so the volume file object is never deleted until
	 * the volume is unmounted. */
	ObpReferenceObject(FileObj);
	/* The volume file object should not have an FCB allocated. */
	assert(!FileObj->Fcb);
	/* We assign the volume FCB to it. */
	FileObj->Fcb = DevObj->Vcb->VolumeFcb;
	/* And set us as the master file object of the volume FCB. */
	FileObj->Fcb->MasterFileObject = FileObj;
	return STATUS_SUCCESS;
    }

    /* Otherwise, the path must start with '\' */
    if (Path[0] != OBJ_NAME_PATH_SEPARATOR) {
	return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }
    Path++;

    /* Insert the file object under the subobject directory. The parent directories
     * along the object path will be created if needed. If the final component of
     * the object path is empty, (ie. if the path ends in "\", which means it's a
     * directory file), we insert into the parent directory using name "." */
    return ObDirectoryObjectInsertPath(DevObj->Vcb->Subobjects, Object, Path, ".", TRUE);
}

NTSTATUS IopDeviceObjectCloseProc(IN ASYNC_STATE State,
				  IN PTHREAD Thread,
				  IN POBJECT Object)
{
    /* We don't have to do anything here since the close routine for file objects
     * will take care of closing a file handle. */
    return STATUS_SUCCESS;
}

VOID IopDeviceObjectRemoveProc(IN POBJECT Subobject)
{
    POBJECT_DIRECTORY ParentDir = ObGetParentDirectory(Subobject);
    if (ParentDir) {
	assert(ObObjectIsType(Subobject, OBJECT_TYPE_FILE));
	ObDirectoryObjectRemoveObject(Subobject);
	PIO_FILE_OBJECT FileObj = Subobject;
	/* The file may be a zombie object (whose device object has been forcibly
	 * removed). In this case we simply detach the file from the object directory.
	 * IopVcbDetachSubobject will dereference the object directory itself. */
	if (FileObj->Fcb) {
	    PIO_VOLUME_CONTROL_BLOCK Vcb = FileObj->Fcb->Vcb;
	    assert(Vcb);
	    /* If the parent directory is empty, delete it, unless it's the root subobject
	     * directory. */
	    if (!ObDirectoryGetObjectCount(ParentDir) && ParentDir != Vcb->Subobjects) {
		ObDereferenceObject(ParentDir);
	    }
	}
    }
}

NTSTATUS IopOpenDevice(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
		       IN PIO_DEVICE_OBJECT Device,
		       IN PIO_FILE_OBJECT MasterFileObject,
		       IN PCSTR SubPath,
		       IN ACCESS_MASK DesiredAccess,
		       IN ULONG Attributes,
		       IN PIO_OPEN_CONTEXT OpenContext,
		       OUT PIO_FILE_OBJECT *pFileObject)
{
    assert(Device);
    NTSTATUS Status = STATUS_NTOS_BUG;
    POPEN_PACKET OpenPacket = &OpenContext->OpenPacket;
    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PIO_DEVICE_OBJECT TargetDevice;
	    PPENDING_IRP PendingIrp;
	});

    /* If the device object is from the underlying storage driver of a mounted volume,
     * we send open IRPs to its file system volume device object instead. */
    Locals.TargetDevice = IopIsStorageDevice(Device) && Device->Vcb ?
	Device->Vcb->VolumeDevice : Device;

    if (MasterFileObject) {
	FILE_OBJ_CREATE_CONTEXT Ctx = {
	    .MasterFileObject = MasterFileObject,
	    .AllocateCloseMsg = !!MasterFileObject->DeviceObject
	};
	Status = ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *)&Locals.FileObject, &Ctx);
    } else {
	Status = IopCreateMasterFileObject(SubPath, Locals.TargetDevice,
					   OpenPacket->FileAttributes, DesiredAccess,
					   OpenPacket->ShareAccess, &Locals.FileObject);
    }
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    assert(Locals.FileObject != NULL);

    if (Device->Vcb && !MasterFileObject && !OpenPacket->OpenTargetDirectory) {
	/* If the open is case-insensitive, we insert with an all-lower case path. */
	PCHAR ObjectName = NULL;
	if (Attributes & OBJ_CASE_INSENSITIVE) {
	    ObjectName = ExAllocatePoolWithTag(strlen(SubPath) + 1, NTOS_IO_TAG);
	    if (!ObjectName) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto out;
	    }
	    for (PCSTR p = SubPath; p[0]; p++) {
		ObjectName[p - SubPath] = tolower(*p);
	    }
	    /* Set the case-insensitivity flag of the file object according. */
	    Locals.FileObject->Flags |= FO_OPENED_CASE_SENSITIVE;
	}
	Status = ObInsertObject(Locals.TargetDevice, Locals.FileObject,
				ObjectName ? ObjectName : SubPath, OBJ_NO_PARSE);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
    }

    /* Check if this is Synch I/O and set the sync flag accordingly */
    if (OpenPacket->CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) {
	Locals.FileObject->Flags |= FO_SYNCHRONOUS_IO;
	/* Check if it's also alertable and set the alertable flag accordingly */
	if (OpenPacket->CreateOptions & FILE_SYNCHRONOUS_IO_ALERT) {
	    Locals.FileObject->Flags |= FO_ALERTABLE_IO;
	}
    }

    ULONG PathLen = strlen(SubPath);
    ULONG DataSize = PathLen ? PathLen + 1 : 0;
    PIO_REQUEST_PARAMETERS Irp = ExAllocatePoolWithTag(sizeof(IO_REQUEST_PARAMETERS) + DataSize,
						       NTOS_IO_TAG);
    if (!Irp) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }

    /* For IO packets involving the creation of file objects, we need to pass
     * FILE_OBJECT_CREATE_PARAMETERS to the client driver so it can record the
     * file object information there */
    if (PathLen) {
	PUCHAR FileNamePtr = (PUCHAR)(Irp + 1);
	memcpy(FileNamePtr, SubPath, PathLen + 1);
    }
    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters = {
	.AllocationSize = OpenPacket->AllocationSize,
	.ReadAccess = Locals.FileObject->ReadAccess,
	.WriteAccess = Locals.FileObject->WriteAccess,
	.DeleteAccess = Locals.FileObject->DeleteAccess,
	.SharedRead = Locals.FileObject->SharedRead,
	.SharedWrite = Locals.FileObject->SharedWrite,
	.SharedDelete = Locals.FileObject->SharedDelete,
	.Flags = Locals.FileObject->Flags,
	.FileNameOffset = DataSize ? sizeof(IO_REQUEST_PARAMETERS) : 0
    };

    ULONG CreateOptions = OpenPacket->CreateOptions | (OpenPacket->Disposition << 24);
    if (OpenPacket->CreateFileType == CreateFileTypeNone) {
	Irp->MajorFunction = IRP_MJ_CREATE;
	Irp->Create.Options = CreateOptions;
	Irp->Create.FileAttributes = OpenPacket->FileAttributes;
	Irp->Create.ShareAccess = OpenPacket->ShareAccess;
	Irp->Create.FileObjectParameters = FileObjectParameters;
	Irp->Create.OpenTargetDirectory = OpenPacket->OpenTargetDirectory;
    } else if (OpenPacket->CreateFileType == CreateFileTypeNamedPipe) {
	Irp->MajorFunction = IRP_MJ_CREATE_NAMED_PIPE;
	Irp->CreatePipe.Options = CreateOptions;
	Irp->CreatePipe.ShareAccess = OpenPacket->ShareAccess;
	Irp->CreatePipe.Parameters = *(OpenPacket->NamedPipeCreateParameters);
	Irp->CreatePipe.FileObjectParameters = FileObjectParameters;
    } else {
	assert(OpenPacket->CreateFileType == CreateFileTypeMailslot);
	Irp->MajorFunction = IRP_MJ_CREATE_MAILSLOT;
	Irp->CreateMailslot.Options = CreateOptions;
	Irp->CreateMailslot.ShareAccess = OpenPacket->ShareAccess;
	Irp->CreateMailslot.Parameters = *(OpenPacket->MailslotCreateParameters);
	Irp->CreateMailslot.FileObjectParameters = FileObjectParameters;
    }

    Irp->DataSize = DataSize;
    Irp->Device.Object = Locals.TargetDevice;
    Irp->File.Object = Locals.FileObject;
    Status = IopCallDriver(Thread, Irp, &Locals.PendingIrp);
    /* IopCallDriver makes a copy of the IO_REQUEST_PARAMETERS structure so
     * we should free the Irp object regardless of its return status. */
    IopFreePool(Irp);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* For create/open we always wait for the driver to complete the request. */
    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);

    /* This is the starting point when the function is resumed. Note if the driver
     * crashed during handling of the IO packet, IopUnloadDriver will have manually
     * completed the IO request with an error. */
    assert(Locals.FileObject != NULL);

    if (Locals.PendingIrp->IoResponseDataSize && Locals.FileObject->Fcb) {
	PIO_RESPONSE_DATA IoResponseData = Locals.PendingIrp->IoResponseData;
	Locals.FileObject->Fcb->FileSize = IoResponseData->FileSizes.FileSize;
    }

    IO_STATUS_BLOCK IoStatus = Locals.PendingIrp->IoResponseStatus;
    OpenContext->Information = IoStatus.Information;
    Status = IoStatus.Status;

    /* TODO: Handle NTFS reparse point. We need to retrieve the reparse string
     * returned by the driver and allocate a copy from the pool with OB_PARSE_TAG. */
    if (NT_SUCCESS(Status)) {
	if (Locals.FileObject->Fcb) {
	    Locals.FileObject->Fcb->OpenInProgress = FALSE;
	    KeSetEvent(&Locals.FileObject->Fcb->OpenCompleted);
	}
	*pFileObject = Locals.FileObject;
    }

out:
    if (!NT_SUCCESS(Status) && Locals.FileObject) {
	ObRemoveObject(Locals.FileObject);
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(State, Status);
}

NTSTATUS IopDeviceObjectOpenProc(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN POBJECT Object,
				 IN PCSTR SubPath,
				 IN ACCESS_MASK DesiredAccess,
				 IN ULONG Attributes,
				 IN POB_OPEN_CONTEXT Context,
				 OUT POBJECT *pOpenedInstance,
				 OUT PCSTR *pRemainingPath)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(SubPath != NULL);
    assert(Context != NULL);
    assert(pOpenedInstance != NULL);

    /* These must come before ASYNC_BEGIN since they are referenced
     * throughout the whole function (in particular, after the AWAIT call) */
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT)Object;
    PIO_OPEN_CONTEXT OpenContext = (PIO_OPEN_CONTEXT)Context;
    PIO_FILE_OBJECT FileObject = NULL;
    assert(Device->DriverObject != NULL);

    /* This is initialized to STATUS_NTOS_BUG so we can catch bugs */
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State);

    /* Reject the open if the open context is not IO_OPEN_CONTEXT */
    if (Context->Type != OPEN_CONTEXT_DEVICE_OPEN) {
	Status = STATUS_OBJECT_TYPE_MISMATCH;
	goto out;
    }

    /* If the device object represents a volume on a storage device,
     * make sure its file system is mounted. */
    AWAIT_EX(Status, IopMountVolume, State, _, Thread, Device);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    AWAIT_EX(Status, IopOpenDevice, State, _, Thread, Device, NULL,
	     SubPath, DesiredAccess, Attributes, OpenContext, &FileObject);

out:
    if (NT_SUCCESS(Status)) {
	*pOpenedInstance = FileObject;
	*pRemainingPath = SubPath + strlen(SubPath);
	Status = STATUS_SUCCESS;
    } else {
	*pOpenedInstance = NULL;
	*pRemainingPath = SubPath;
    }
    ASYNC_END(State, Status);
}

VOID IopDeviceObjectDeleteProc(IN POBJECT Self)
{
    PIO_DEVICE_OBJECT DevObj = Self;
    DbgTrace("Deleting device object %p\n", DevObj);
    IopDbgDumpDeviceObject(DevObj, 0);
    assert(IsListEmpty(&DevObj->OpenFileList));
    assert(IsListEmpty(&DevObj->CloseMsgList));
    KeUninitializeEvent(&DevObj->MountCompleted);
    RemoveEntryList(&DevObj->DeviceLink);
    ObDereferenceObject(DevObj->DriverObject);
    if (DevObj->AttachedDevice) {
	DevObj->AttachedDevice->AttachedTo = DevObj->AttachedTo;
    }
    if (DevObj->AttachedTo) {
	DevObj->AttachedTo->AttachedDevice = DevObj->AttachedDevice;
    }
    if (DevObj->Vcb) {
	PIO_VOLUME_CONTROL_BLOCK Vcb = DevObj->Vcb;
	ObRemoveEmptySubDirectories(Vcb->Subobjects);
	assert(ObGetObjectRefCount(Vcb->Subobjects) == 1);
	ObDereferenceObject(Vcb->Subobjects);
	Vcb->StorageDevice->Vcb = NULL;
	Vcb->VolumeDevice->Vcb = NULL;
	IopFreePool(Vcb);
    }
    if (DevObj->FsObj) {
	IopUnregisterFileSystem(DevObj);
    }
    if (DevObj->DeviceNode) {
	assert(DevObj->DeviceNode->PhyDevObj == DevObj);
	DevObj->DeviceNode->PhyDevObj = NULL;
	IopDeviceNodeSetCurrentState(DevObj->DeviceNode, DeviceNodeDeleted);
    }
}

/*
 * Remove the device object. If Force is TRUE, this routine will perform a
 * forced removal of the device object. This case is called when the driver
 * process that owns (ie. created) the device has crashed. Otherwise, this
 * routine performs a normal device removal as a result of the client driver
 * calling WdmDeleteDevice on a device object it owns.
 */
VOID IopRemoveDevice(IN PIO_DEVICE_OBJECT DevObj,
		     IN BOOLEAN Force)
{
    DbgTrace("%s device object %p (%s)\n", Force ? "Force removing" : "Removing",
	     DevObj, KEDBG_PROCESS_TO_FILENAME(DevObj->DriverObject->DriverProcess));
    /* Set the status of the device node of the PDO to DeviceNodeRemoved. */
    PDEVICE_NODE DevNode = IopGetDeviceNode(DevObj);
    if (DevNode) {
	IopDeviceNodeSetCurrentState(DevNode, DeviceNodeRemoved);
    }
    /* For all opened file objects of this device object, mark the file object
     * as a zombie because we cannot delete it just yet (at least one NT client
     * still has an open handle to it). These file objects will be deleted when
     * all open handles to them are closed. */
    LoopOverList(FileObj, &DevObj->OpenFileList, IO_FILE_OBJECT, DeviceLink) {
	assert(DevObj == FileObj->DeviceObject);
	if (FileObj->Fcb && FileObj == FileObj->Fcb->MasterFileObject) {
	    PIO_FILE_CONTROL_BLOCK Fcb = FileObj->Fcb;
	    /* The slave files will detached in IopDeleteFcb. */
	    LoopOverList(Slave, &Fcb->SlaveList, IO_FILE_OBJECT, SlaveLink) {
		assert(Slave != FileObj);
		assert(Slave->Zombie);
		assert(!Slave->DeviceObject);
	    }
	    if (DevObj->Vcb && Fcb == DevObj->Vcb->VolumeFcb) {
		DevObj->Vcb->VolumeFcb = NULL;
	    }
	    IopDeleteFcb(Fcb);
	}
	FileObj->Fcb = NULL;
	FileObj->DeviceObject = NULL;
	FileObj->Zombie = TRUE;
	RemoveEntryList(&FileObj->DeviceLink);
	/* Decrease the refcount of the device object because we increased it
	 * at the time the file object was created. */
	ObDereferenceObject(DevObj);
    }
    /* For all drivers that did not create the device object but have requested its
     * global handle be granted (for instance, the file system driver needs to know
     * the global handle of the storage device on which it will mount the volume),
     * send a CloseDevice server message to the client driver, so it will properly
     * cleanup the client-side device object and notify the server to deref the
     * device object (via WdmDeleteDevice). */
    LoopOverList(CloseMsg, &DevObj->CloseMsgList, CLOSE_DEVICE_MESSAGE, DeviceLink) {
	assert(CloseMsg->DriverObject);
	assert(CloseMsg->DriverObject != DevObj->DriverObject);
	assert(CloseMsg->DeviceObject == DevObj);
	PIO_PACKET Msg = CloseMsg->Msg;
	assert(Msg);
	Msg->Type = IoPacketTypeServerMessage;
	Msg->Size = sizeof(IO_PACKET);
	Msg->ServerMsg.Type = IoSrvMsgCloseDevice;
	Msg->ServerMsg.CloseDevice.DeviceObject = OBJECT_TO_GLOBAL_HANDLE(DevObj);
	/* The IO packet will be deleted later after it is sent to the driver. */
	InsertTailList(&CloseMsg->DriverObject->IoPacketQueue, &Msg->IoPacketLink);
	KeSetEvent(&CloseMsg->DriverObject->IoPacketQueuedEvent);
	RemoveEntryList(&CloseMsg->DeviceLink);
	RemoveEntryList(&CloseMsg->DriverLink);
	IopFreePool(CloseMsg);
	/* Note despite the fact that we have increased the refcount of the device
	 * object when granting the device handle to foreign driver processes, we
	 * do NOT decrease the refcount here. Instead the client driver will call
	 * WdmDeleteDevice after it has properly cleaned up the client-side device
	 * object. This way we maintain that clients and server always see a
	 * consistent set of global handles for device objects. */
    }
    /* Dismount the volume if we are removing a storage device or mounted volume
     * device. This can happen both in the forced removal case and in the normal
     * removal case. In the normal removal case, if the volume device has already
     * been dismounted as a result of an NT client calling FSCTL_DISMOUNT_VOLUME,
     * this call is a no-op. Note the case of "forced" vs "normal" dismount here
     * are distinguished by whether we are dealing with a crashed driver or not.
     * Dismount as a result of media change is not considered forced dismount from
     * the Executive server's point of view, since drivers are running just fine
     * in this case. On the other hand, a storage driver removing its storage device
     * (regardless of whether it's a normal removal or not) before the file system
     * is able to properly dismount the volume is treated as a forced dismount,
     * since the storage device went away unexpectedly, as if its storage driver
     * has just crashed. */
    if (DevObj->Vcb) {
	IopDismountVolume(DevObj->Vcb, Force);
    }
    /* At this point the device object may still have more than one references.
     * Mark the device as removed so no more IRPs will be sent to it. */
    DevObj->Removed = TRUE;
}

/*
 * This routine must be called before a GLOBAL_HANDLE for a device object
 * is given out to a driver object that did not create said device object.
 * It queues a CLOSE_DEVICE_MESSAGE so we can send the driver a notification
 * to clean up the device handle on the client side.
 */
NTSTATUS IopGrantDeviceHandleToDriver(IN OPTIONAL PIO_DEVICE_OBJECT DeviceObject,
				      IN PIO_DRIVER_OBJECT DriverObject,
				      OUT GLOBAL_HANDLE *DeviceHandle)
{
    assert(DeviceHandle);
    assert(DriverObject);
    if (!DeviceObject) {
	*DeviceHandle = 0;
	return STATUS_SUCCESS;
    }
    /* The owning driver is responsible for deleting the device objects it has created,
     * so we don't need to queue a CLOSE_DEVICE_MESSAGE for the owning driver. */
    if (DriverObject == DeviceObject->DriverObject) {
	goto out;
    }
    /* Queue a CLOSE_DEVICE_MESSAGE to the driver object if it has not been done before. */
    LoopOverList(ExistingReq, &DeviceObject->CloseMsgList, CLOSE_DEVICE_MESSAGE, DeviceLink) {
	if (ExistingReq->DriverObject == DriverObject) {
	    goto out;
	}
    }
    IopAllocatePool(CloseMsg, CLOSE_DEVICE_MESSAGE);
    IopAllocatePoolEx(Msg, IO_PACKET, IopFreePool(CloseMsg));
    CloseMsg->Msg = Msg;
    CloseMsg->DeviceObject = DeviceObject;
    CloseMsg->DriverObject = DriverObject;
    InsertTailList(&DeviceObject->CloseMsgList, &CloseMsg->DeviceLink);
    InsertTailList(&DriverObject->CloseDeviceMsgList, &CloseMsg->DriverLink);
    /* Increase the refcount of the device object, because we are handing it out to a
     * foreign driver. */
    ObpReferenceObject(DeviceObject);
out:
    *DeviceHandle = OBJECT_TO_GLOBAL_HANDLE(DeviceObject);
    return STATUS_SUCCESS;
}

static ULONG IopGetDeviceStackSize(IN PIO_DEVICE_OBJECT DeviceObject)
{
    ULONG StackSize = 1;
    while ((DeviceObject = DeviceObject->AttachedTo) != NULL) {
	StackSize++;
    }
    return StackSize;
}

/*
 * Note: DeviceName must be a full path.
 */
NTSTATUS WdmCreateDevice(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
                         IN OPTIONAL PCSTR DeviceName,
                         IN PIO_DEVICE_INFO DeviceInfo,
                         IN BOOLEAN Exclusive,
                         OUT GLOBAL_HANDLE *DeviceHandle)
{
    assert(Thread != NULL);
    assert(Thread->Process->DriverObject != NULL);
    assert(DeviceHandle != NULL);
    assert(IopThreadIsAtPassiveLevel(Thread));

    PIO_DEVICE_OBJECT DeviceObject = NULL;
    DEVICE_OBJ_CREATE_CONTEXT CreaCtx = {
	.DriverObject = Thread->Process->DriverObject,
	.DeviceInfo = *DeviceInfo,
	.Exclusive = Exclusive
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_DEVICE, (POBJECT *)&DeviceObject, &CreaCtx));
    if (DeviceName) {
	RET_ERR_EX(ObInsertObject(NULL, DeviceObject, DeviceName, 0),
		   ObDereferenceObject(DeviceObject));
    }
    assert(DeviceObject != NULL);

    *DeviceHandle = OBJECT_TO_GLOBAL_HANDLE(DeviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS WdmAttachDeviceToDeviceStack(IN ASYNC_STATE AsyncState,
				      IN PTHREAD Thread,
				      IN GLOBAL_HANDLE SrcDevHandle,
				      IN GLOBAL_HANDLE TgtDevHandle,
				      OUT GLOBAL_HANDLE *PrevTopDevHandle,
				      OUT IO_DEVICE_INFO *PrevTopDevInfo,
				      OUT ULONG *PrevTopStackSize)
{
    assert(IopThreadIsAtPassiveLevel(Thread));
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    PIO_DEVICE_OBJECT SrcDev = IopGetDeviceObject(SrcDevHandle, DriverObject);
    PIO_DEVICE_OBJECT TgtDev = IopGetDeviceObject(TgtDevHandle, NULL);
    if (SrcDev == NULL || TgtDev == NULL) {
	/* This shouldn't happen since we check the validity of device handles before */
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    PIO_DEVICE_OBJECT PrevTop = TgtDev;
    while (PrevTop->AttachedDevice != NULL) {
	PrevTop = PrevTop->AttachedDevice;
    }
    /* Detach the source device from the previous device stack (if any) */
    if (SrcDev->AttachedTo != NULL) {
	assert(SrcDev->AttachedTo->AttachedDevice == SrcDev);
	SrcDev->AttachedTo->AttachedDevice = NULL;
    }
    RET_ERR(IopGrantDeviceHandleToDriver(PrevTop, DriverObject, PrevTopDevHandle));
    SrcDev->AttachedTo = PrevTop;
    PrevTop->AttachedDevice = SrcDev;
    *PrevTopDevInfo = PrevTop->DeviceInfo;
    *PrevTopStackSize = IopGetDeviceStackSize(PrevTop);
    return STATUS_SUCCESS;
}

NTSTATUS WdmGetDeviceObject(IN ASYNC_STATE AsyncState,
                            IN PTHREAD Thread,
                            IN HANDLE OpenFileHandle,
                            OUT GLOBAL_HANDLE *GlobalFileHandle,
                            OUT GLOBAL_HANDLE *TopDeviceHandle)
{
    UNIMPLEMENTED;
}

/*
 * A client driver process calls this routine so the server can be notified that
 * the client has cleaned up its local bookkeeping of the device object, and is
 * no longer expecting the global handle of the device object to be valid. If
 * the device object is created by the calling driver, the server will notify all
 * other drivers to which the device object's global handle has been granted, so
 * these drivers can clean-up their local bookkeeping as well. Only when all
 * drivers (including the owner and the foreign drivers that have access to the
 * global handle of the device) have called WdmDeleteDevice will the device object's
 * server-side refcount reach zero, at which point the delete routine of the device
 * object will be called.
 */
NTSTATUS WdmDeleteDevice(IN ASYNC_STATE AsyncState,
                         IN PTHREAD Thread,
                         IN GLOBAL_HANDLE GlobalHandle)
{
    assert(IopThreadIsAtPassiveLevel(Thread));
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    PIO_DEVICE_OBJECT DevObj = IopGetDeviceObject(GlobalHandle, DriverObject);
    if (!DevObj) {
	assert(FALSE);
	return STATUS_INVALID_HANDLE;
    }
    /* If the driver owns the device object (ie. the driver called IoCreateDevice
     * to create this device object), we will perform a (normal, unless it's a
     * storage device of a mounted volume) removal of the device object which will
     * notify all foreign drivers so they can delete their local references to the
     * device object. This will also dismount the volume if the device is a storage
     * or mounted volume device. Note if the device being removed is the storage
     * device of a mounted volume, we do a forced removal so the file system driver
     * can perform a forced dismount. This case should not happen normally and we
     * assert on debug build. Storage driver should not be unloaded when there is
     * a mounted volume on it. */
    if (DevObj->DriverObject == DriverObject) {
	BOOLEAN Force = DevObj->Vcb && !DevObj->Vcb->Dismounted &&
	    DevObj == DevObj->Vcb->StorageDevice;
	assert(!Force);
	IopRemoveDevice(DevObj, Force);
    }
    ObDereferenceObject(DevObj);
    return STATUS_SUCCESS;
}

NTSTATUS WdmGetAttachedDevice(IN ASYNC_STATE AsyncState,
                              IN PTHREAD Thread,
                              IN GLOBAL_HANDLE DeviceHandle,
                              OUT GLOBAL_HANDLE *TopDeviceHandle,
                              OUT IO_DEVICE_INFO *TopDeviceInfo,
			      OUT ULONG *StackSize)
{
    assert(IopThreadIsAtPassiveLevel(Thread));
    if (!DeviceHandle) {
	return STATUS_INVALID_PARAMETER;
    }
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    PIO_DEVICE_OBJECT Device = IopGetDeviceObject(DeviceHandle, DriverObject);
    if (!Device) {
	return STATUS_INVALID_HANDLE;
    }
    Device = IopGetTopDevice(Device);
    RET_ERR(IopGrantDeviceHandleToDriver(Device, DriverObject, TopDeviceHandle));
    *TopDeviceInfo = Device->DeviceInfo;
    *StackSize = IopGetDeviceStackSize(Device);
    return STATUS_SUCCESS;
}

VOID IopDbgDumpDeviceObject(IN PIO_DEVICE_OBJECT DevObj,
			    IN ULONG Indentation)
{
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Dumping device object %p\n", DevObj);
    if (!DevObj) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("  (nil)\n");
	return;
    }
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  RefCount = %lld\n", OBJECT_TO_OBJECT_HEADER(DevObj)->RefCount);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  DriverObject = %p (%s)\n", DevObj->DriverObject,
	     DevObj->DriverObject ? KEDBG_PROCESS_TO_FILENAME(DevObj->DriverObject->DriverProcess) : "");
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  DeviceType = %d\n", DevObj->DeviceInfo.DeviceType);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  Flags = 0x%llx\n", DevObj->DeviceInfo.Flags);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  Exclusive = %d\n", DevObj->Exclusive);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  Vcb = %p\n", DevObj->Vcb);
    ObDbgDumpObjectHandles(DevObj, Indentation + 2);
    if (IsListEmpty(&DevObj->OpenFileList)) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("  No open file for device object %p\n", DevObj);
    } else {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("  Open files for device object %p\n", DevObj);
	LoopOverList(FileObj, &DevObj->OpenFileList, IO_FILE_OBJECT, DeviceLink) {
	    IoDbgDumpFileObject(FileObj, Indentation + 4);
	}
    }
}
