#include "iop.h"
#include "helpers.h"

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
    assert(*Path != OBJ_NAME_PATH_SEPARATOR);

    PIO_DEVICE_OBJECT DevObj = (PIO_DEVICE_OBJECT)Self;
    DbgTrace("Device %p trying to parse Path = %s case-%s\n", Self, Path,
	     CaseInsensitive ? "insensitively" : "sensitively");

    if (DevObj->Subobjects) {
	return ObParseObjectByName(DevObj->Subobjects, Path, CaseInsensitive,
				   FoundObject, RemainingPath);
    }

    return STATUS_OBJECT_PATH_NOT_FOUND;
}

NTSTATUS IopDeviceObjectInsertProc(IN POBJECT Self,
				   IN POBJECT Object,
				   IN PCSTR Path)
{
    PIO_DEVICE_OBJECT DevObj = (PIO_DEVICE_OBJECT)Self;
    assert(Self != NULL);
    assert(Path != NULL);
    assert(Object != NULL);
    DbgTrace("Inserting subobject %p (path %s) for device object %p\n",
	     Object, Path, Self);

    /* Object path must not be empty. */
    if (*Path == '\0') {
	DbgTrace("Cannot insert empty path\n");
	return STATUS_OBJECT_PATH_INVALID;
    }

    /* Object path must not be absolute. */
    if (*Path == OBJ_NAME_PATH_SEPARATOR) {
	DbgTrace("Cannot insert absolute path %s\n", Path);
	return STATUS_OBJECT_PATH_INVALID;
    }

    if (!DevObj->Subobjects) {
	RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY,
			       (POBJECT *)&DevObj->Subobjects, NULL));
    }

    assert(DevObj->Subobjects);
    return ObInsertObject(DevObj->Subobjects, Object, Path, 0);
}

VOID IopDeviceObjectRemoveProc(IN POBJECT Parent,
			       IN POBJECT Subobject,
			       IN PCSTR Subpath)
{
    /* We don't need to do anything here because the remove proc of the
     * directory object will take care of removing the subobject for us. */
}

NTSTATUS IopDeviceObjectOpenProc(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN POBJECT Object,
				 IN PCSTR SubPath,
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

    *pRemainingPath = SubPath;

    /* These must come before ASYNC_BEGIN since they are referenced
     * throughout the whole function (in particular, after the AWAIT call) */
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT)Object;
    PIO_OPEN_CONTEXT OpenContext = (PIO_OPEN_CONTEXT)Context;
    POPEN_PACKET OpenPacket = &OpenContext->OpenPacket;
    assert(Device->DriverObject != NULL);

    /* This is initialized to STATUS_NTOS_BUG so we can catch bugs */
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PIO_DEVICE_OBJECT TargetDevice;
	    PIO_PACKET IoPacket;
	    PPENDING_IRP PendingIrp;
	    ULONG FileNameLength;
	});
    Locals.FileObject = NULL;
    Locals.IoPacket = NULL;
    Locals.PendingIrp = NULL;

    /* Reject the open if the parse context is not IO_OPEN_CONTEXT */
    if (Context->Type != OPEN_CONTEXT_DEVICE_OPEN) {
	ASYNC_RETURN(State, STATUS_OBJECT_TYPE_MISMATCH);
    }

    /* If the device object represents a volume on a storage device, make sure
     * its file system is mounted. */
    AWAIT_EX(Status, IopMountVolume, State, Locals, Thread, Device);
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(State, Status);
    }

    /* If the device object is from the underlying storage driver, we send open IRPs to
     * its file system volume device object instead. */
    Locals.TargetDevice = IopIsStorageDevice(Device) ? Device->Vcb->VolumeDevice : Device;

    IF_ERR_GOTO(out, Status,
		IopCreateMasterFileObject(SubPath, Locals.TargetDevice, &Locals.FileObject));
    assert(Locals.FileObject != NULL);

    /* Check if this is Synch I/O and set the sync flag accordingly */
    if (OpenPacket->CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) {
	Locals.FileObject->Flags |= FO_SYNCHRONOUS_IO;
	/* Check if it's also alertable and set the alertable flag accordingly */
	if (OpenPacket->CreateOptions & FILE_SYNCHRONOUS_IO_ALERT) {
	    Locals.FileObject->Flags |= FO_ALERTABLE_IO;
	}
    }

    Locals.FileNameLength = strlen(SubPath);
    ULONG IoPacketSize = sizeof(IO_PACKET);
    if (Locals.FileNameLength) {
	IoPacketSize += Locals.FileNameLength + 2;
    }
    IF_ERR_GOTO(out, Status,
		IopAllocateIoPacket(IoPacketTypeRequest, IoPacketSize, &Locals.IoPacket));
    assert(Locals.IoPacket != NULL);

    /* For IO packets involving the creation of file objects, we need to pass
     * FILE_OBJECT_CREATE_PARAMETERS to the client driver so it can record the
     * file object information there */
    if (Locals.FileNameLength) {
	PUCHAR FileNamePtr = (PUCHAR)(&Locals.IoPacket[1]);
	/* Note since we are handling the case of an absolute open (an open
	 * request with RelatedFileObject == NULL), we prepend the path with
	 * '\\' so the file system driver knows it's an absolute path. */
	FileNamePtr[0] = '\\';
	memcpy(FileNamePtr + 1, SubPath, Locals.FileNameLength + 1);
    }
    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters = {
	.ReadAccess = Locals.FileObject->ReadAccess,
	.WriteAccess = Locals.FileObject->WriteAccess,
	.DeleteAccess = Locals.FileObject->DeleteAccess,
	.SharedRead = Locals.FileObject->SharedRead,
	.SharedWrite = Locals.FileObject->SharedWrite,
	.SharedDelete = Locals.FileObject->SharedDelete,
	.Flags = Locals.FileObject->Flags,
	.FileNameOffset = Locals.FileNameLength ? sizeof(IO_PACKET) : 0
    };

    ULONG CreateOptions = OpenPacket->CreateOptions | (OpenPacket->Disposition << 24);
    if (OpenPacket->CreateFileType == CreateFileTypeNone) {
	Locals.IoPacket->Request.MajorFunction = IRP_MJ_CREATE;
	Locals.IoPacket->Request.Create.Options = CreateOptions;
	Locals.IoPacket->Request.Create.FileAttributes = OpenPacket->FileAttributes;
	Locals.IoPacket->Request.Create.ShareAccess = OpenPacket->ShareAccess;
	Locals.IoPacket->Request.Create.FileObjectParameters = FileObjectParameters;
    } else if (OpenPacket->CreateFileType == CreateFileTypeNamedPipe) {
	Locals.IoPacket->Request.MajorFunction = IRP_MJ_CREATE_NAMED_PIPE;
	Locals.IoPacket->Request.CreatePipe.Options = CreateOptions;
	Locals.IoPacket->Request.CreatePipe.ShareAccess = OpenPacket->ShareAccess;
	Locals.IoPacket->Request.CreatePipe.Parameters = *(OpenPacket->NamedPipeCreateParameters);
	Locals.IoPacket->Request.CreatePipe.FileObjectParameters = FileObjectParameters;
    } else {
	assert(OpenPacket->CreateFileType == CreateFileTypeMailslot);
	Locals.IoPacket->Request.MajorFunction = IRP_MJ_CREATE_MAILSLOT;
	Locals.IoPacket->Request.CreateMailslot.Options = CreateOptions;
	Locals.IoPacket->Request.CreateMailslot.ShareAccess = OpenPacket->ShareAccess;
	Locals.IoPacket->Request.CreateMailslot.Parameters = *(OpenPacket->MailslotCreateParameters);
	Locals.IoPacket->Request.CreateMailslot.FileObjectParameters = FileObjectParameters;
    }

    Locals.IoPacket->Request.Device.Object = Locals.TargetDevice;
    Locals.IoPacket->Request.File.Object = Locals.FileObject;
    IF_ERR_GOTO(out, Status, IopAllocatePendingIrp(Locals.IoPacket, Thread, &Locals.PendingIrp));
    IopQueueIoPacket(Locals.PendingIrp, Thread);

    /* For create/open we always wait till the driver has completed the request. */
    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);

    /* This is the starting point when the function is resumed. */
    assert(Locals.FileObject != NULL);

    IO_STATUS_BLOCK IoStatus = Locals.PendingIrp->IoResponseStatus;
    OpenContext->Information = IoStatus.Information;
    Status = IoStatus.Status;

    if (NT_SUCCESS(Status)) {
	*pOpenedInstance = Locals.FileObject;
	*pRemainingPath += Locals.FileNameLength;
    }

out:
    if (!NT_SUCCESS(Status) && Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.PendingIrp) {
	/* This will free the pending IRP and detach the pending irp from the thread.
	 * At this point the IRP has already been detached from the driver object,
	 * so we do not need to remove it from the driver IRP queue here. */
	IopCleanupPendingIrp(Locals.PendingIrp);
    } else if (Locals.IoPacket) {
	IopFreePool(Locals.IoPacket);
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
NTSTATUS IopCreateDevice(IN ASYNC_STATE State,
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

NTSTATUS IopIoAttachDeviceToDeviceStack(IN ASYNC_STATE AsyncState,
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

NTSTATUS IopGetAttachedDevice(IN ASYNC_STATE AsyncState,
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

NTSTATUS IoSetDeviceInterfaceState(IN ASYNC_STATE AsyncState,
                                   IN PTHREAD Thread,
                                   IN PCSTR SymbolicLinkName,
                                   IN BOOLEAN Enable)
{
    UNIMPLEMENTED;
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
    IO_SERVICE_PROLOGUE(State, Locals, FileObject, EventObject,
			IoPacket, PendingIrp);

    Locals.IoPacket->Request.MajorFunction = IRP_MJ_DEVICE_CONTROL;
    Locals.IoPacket->Request.MinorFunction = 0;
    Locals.IoPacket->Request.InputBuffer = (MWORD)InputBuffer;
    Locals.IoPacket->Request.OutputBuffer = (MWORD)OutputBuffer;
    Locals.IoPacket->Request.InputBufferLength = InputBufferLength;
    Locals.IoPacket->Request.OutputBufferLength = OutputBufferLength;
    Locals.IoPacket->Request.DeviceIoControl.IoControlCode = Ioctl;

    IO_SERVICE_EPILOGUE(out, Status, Locals, FileObject, EventObject,
			IoPacket, PendingIrp, IoStatusBlock);

out:
    IO_SERVICE_CLEANUP(Status, Locals, FileObject,
		       EventObject, IoPacket, PendingIrp);
}
