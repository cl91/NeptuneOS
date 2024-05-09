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
    KeInitializeEvent(&Device->MountCompleted, NotificationEvent);

    Device->DriverObject = DriverObject;
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
    DbgTrace("Inserting subobject %p (path %s) for device object %p\n",
	     Object, Path, Self);

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

    PCSTR ObjName = Path + ObLocateLastPathSeparator(Path) + 1;
    /* If the object name is empty (ie. if the path ends in "\", which means it's a
     * directory file), we insert into the object directory using name "." */
    if (!ObjName[0]) {
	ObjName = ".";
    }

    /* Create the parent object directory if it does not exist. */
    POBJECT_DIRECTORY ParentDir = NULL;
    RET_ERR(ObCreateParentDirectory(DevObj->Vcb->Subobjects, Path, &ParentDir));
    assert(ParentDir);

    /* Insert the file object under the object directory. */
    return ObDirectoryObjectInsertObject(ParentDir, Object, ObjName);
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
    assert(ParentDir);
    ObDirectoryObjectRemoveObject(Subobject);
    if (ParentDir && !ObDirectoryGetObjectCount(ParentDir)) {
	ObDereferenceObject(ParentDir);
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

    /* If the device object is from the underlying storage driver, we send open IRPs to
     * its file system volume device object instead. */
    /* TODO: Implement raw mount. */
    Locals.TargetDevice = IopIsStorageDevice(Device) ? Device->Vcb->VolumeDevice : Device;

    if (MasterFileObject) {
	FILE_OBJ_CREATE_CONTEXT Ctx = {
	    .MasterFileObject = MasterFileObject,
	    .AllocateCloseReq = TRUE
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
	Status = ObInsertObject(Device, Locals.FileObject,
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

    /* This is the starting point when the function is resumed. */
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
	ASYNC_RETURN(State, STATUS_OBJECT_TYPE_MISMATCH);
    }

    /* If the device object represents a volume on a storage device,
     * make sure its file system is mounted. */
    AWAIT_EX(Status, IopMountVolume, State, _, Thread, Device);
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(State, Status);
    }

    AWAIT_EX(Status, IopOpenDevice, State, _, Thread, Device, NULL,
	     SubPath, DesiredAccess, Attributes, OpenContext, &FileObject);
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
    /* TODO! */
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
				      IN GLOBAL_HANDLE SourceDeviceHandle,
				      IN GLOBAL_HANDLE TargetDeviceHandle,
				      OUT GLOBAL_HANDLE *PreviousTopDeviceHandle,
				      OUT IO_DEVICE_INFO *PreviousTopDeviceInfo)
{
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    PIO_DEVICE_OBJECT SrcDev = IopGetDeviceObject(SourceDeviceHandle, DriverObject);
    PIO_DEVICE_OBJECT TgtDev = IopGetDeviceObject(TargetDeviceHandle, NULL);
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
    SrcDev->AttachedTo = PrevTop;
    PrevTop->AttachedDevice = SrcDev;
    *PreviousTopDeviceHandle = OBJECT_TO_GLOBAL_HANDLE(PrevTop);
    *PreviousTopDeviceInfo = PrevTop->DeviceInfo;
    return STATUS_SUCCESS;
}

NTSTATUS WdmGetAttachedDevice(IN ASYNC_STATE AsyncState,
                              IN PTHREAD Thread,
                              IN GLOBAL_HANDLE DeviceHandle,
                              OUT GLOBAL_HANDLE *TopDeviceHandle,
                              OUT IO_DEVICE_INFO *TopDeviceInfo)
{
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    PIO_DEVICE_OBJECT Device = IopGetDeviceObject(DeviceHandle, DriverObject);
    Device = IopGetTopDevice(Device);
    *TopDeviceHandle = OBJECT_TO_GLOBAL_HANDLE(Device);
    *TopDeviceInfo = Device->DeviceInfo;
    return STATUS_SUCCESS;
}

NTSTATUS NtDeviceIoControlFile(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
                               IN HANDLE FileHandle,
                               IN HANDLE EventHandle,
                               IN PIO_APC_ROUTINE ApcRoutine,
                               IN PVOID ApcContext,
                               OUT IO_STATUS_BLOCK *IoStatusBlock,
                               IN ULONG Ioctl,
                               IN PVOID InputBuffer,
                               IN ULONG InputBufferLength,
                               IN PVOID OutputBuffer,
                               IN ULONG OutputBufferLength)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PEVENT_OBJECT EventObject;
	    PPENDING_IRP PendingIrp;
	});

    if (FileHandle == NULL) {
	ASYNC_RETURN(State, STATUS_INVALID_HANDLE);
    }
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    assert(Locals.FileObject->DeviceObject != NULL);
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);

    if (EventHandle != NULL) {
	IF_ERR_GOTO(out, Status,
		    ObReferenceObjectByHandle(Thread, EventHandle, OBJECT_TYPE_EVENT,
					      (POBJECT *)&Locals.EventObject));
	assert(Locals.EventObject != NULL);
    }

    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
	.MajorFunction = IRP_MJ_DEVICE_CONTROL,
	.MinorFunction = 0,
	.InputBuffer = (MWORD)InputBuffer,
	.OutputBuffer = (MWORD)OutputBuffer,
	.InputBufferLength = InputBufferLength,
	.OutputBufferLength = OutputBufferLength,
	.DeviceIoControl.IoControlCode = Ioctl
    };
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));

    /* For now every IO is synchronous. For async IO, we need to figure
     * out how we pass IO_STATUS_BLOCK back to the userspace safely.
     * The idea is to pass it via APC. When NtWaitForSingleObject
     * returns from the wait the special APC runs and write to the
     * IO_STATUS_BLOCK. We have reserved the APC_TYPE_IO for this. */
    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);

    /* This is the starting point when the function is resumed. */
    if (IoStatusBlock != NULL) {
	*IoStatusBlock = Locals.PendingIrp->IoResponseStatus;
    }
    Status = Locals.PendingIrp->IoResponseStatus.Status;

out:
    /* Regardless of the outcome of the IO request, we should dereference the
     * file object and the event object because increased their refcount above. */
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.EventObject) {
	ObDereferenceObject(Locals.EventObject);
    }
    /* This will free the pending IRP and detach the pending irp from the
     * thread. At this point the IRP has already been detached from the driver
     * object, so we do not need to remove it from the driver IRP queue here. */
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(State, Status);
}
