#include "iop.h"

NTSTATUS IopDeviceObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx)
{
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT) Object;
    PDEVICE_OBJ_CREATE_CONTEXT Ctx = (PDEVICE_OBJ_CREATE_CONTEXT) CreaCtx;
    PIO_DRIVER_OBJECT DriverObject = Ctx->DriverObject;
    PCSTR DeviceName = Ctx->DeviceName;
    IO_DEVICE_INFO DeviceInfo = Ctx->DeviceInfo;
    BOOLEAN Exclusive = Ctx->Exclusive;
    InitializeListHead(&Device->DeviceLink);

    /* If the client has supplied a non-empty DeviceName, record it */
    if ((DeviceName != NULL) && (DeviceName[0] != '\0')) {
	/* DeviceName must be a full path */
	if (DeviceName[0] != OBJ_NAME_PATH_SEPARATOR) {
	    return STATUS_INVALID_PARAMETER_1;
	}
	PCSTR DeviceNameCopy = RtlDuplicateString(DeviceName, NTOS_IO_TAG);
	if (DeviceNameCopy == NULL) {
	    return STATUS_NO_MEMORY;
	}
	/* If the client has supplied a device name, insert the device
	 * object into the global object namespace, with the given path. */
	RET_ERR_EX(ObInsertObjectByPath(DeviceName, Device),
		   ExFreePool(DeviceNameCopy));
	Device->DeviceName = DeviceNameCopy;
    }

    Device->DriverObject = DriverObject;
    InsertTailList(&DriverObject->DeviceList, &Device->DeviceLink);
    Device->DeviceInfo = DeviceInfo;
    Device->Exclusive = Exclusive;

    return STATUS_SUCCESS;
}

NTSTATUS IopDeviceObjectOpenProc(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN POBJECT Object,
				 IN PCSTR SubPath,
				 IN POB_PARSE_CONTEXT ParseContext,
				 OUT POBJECT *pOpenedInstance,
				 OUT PCSTR *pRemainingPath)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(SubPath != NULL);
    assert(ParseContext != NULL);
    assert(pOpenedInstance != NULL);

    /* We haven't implemented file system devices yet */
    *pRemainingPath = SubPath;
    if (*SubPath != '\0') {
	UNIMPLEMENTED;
    }

    /* These must come before ASYNC_BEGIN since they are referenced
     * throughout the whole function (in particular, after the AWAIT call) */
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT)Object;
    PIO_DRIVER_OBJECT Driver = Device->DriverObject;
    PIO_OPEN_CONTEXT OpenContext = (PIO_OPEN_CONTEXT)ParseContext;
    POPEN_PACKET OpenPacket = &OpenContext->OpenPacket;
    assert(Driver != NULL);

    /* This is initialized to STATUS_NTOS_BUG so we can catch bugs */
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PIO_PACKET IoPacket;
	    PPENDING_IRP PendingIrp;
	});

    /* Reject the open if the parse context is not IO_OPEN_CONTEXT */
    if (ParseContext->Type != PARSE_CONTEXT_DEVICE_OPEN) {
	ASYNC_RETURN(State, STATUS_OBJECT_TYPE_MISMATCH);
    }

    IF_ERR_GOTO(out, Status,
		IopCreateFileObject(Device->DeviceName, Device, NULL, 0,
				    &Locals.FileObject));
    assert(Locals.FileObject != NULL);

    /* Check if this is Synch I/O and set the sync flag accordingly */
    if (OpenPacket->CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) {
	Locals.FileObject->Flags |= FO_SYNCHRONOUS_IO;
	/* Check if it's also alertable and set the alertable flag accordingly */
	if (OpenPacket->CreateOptions & FILE_SYNCHRONOUS_IO_ALERT) {
	    Locals.FileObject->Flags |= FO_ALERTABLE_IO;
	}
    }

    ULONG FileNameLength = strlen(Locals.FileObject->FileName);
    ULONG IoPacketSize = sizeof(IO_PACKET) + FileNameLength + 1;
    IF_ERR_GOTO(out, Status,
		IopAllocateIoPacket(IoPacketTypeRequest, IoPacketSize, &Locals.IoPacket));
    assert(Locals.IoPacket != NULL);

    /* For IO packets involving the creation of file objects, we need to pass FILE_OBJECT_CREATE_PARAMETERS
     * so the client can record the file object information there */
    memcpy(Locals.IoPacket+1, Locals.FileObject->FileName, FileNameLength + 1);
    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters = {
	.ReadAccess = Locals.FileObject->ReadAccess,
	.WriteAccess = Locals.FileObject->WriteAccess,
	.DeleteAccess = Locals.FileObject->DeleteAccess,
	.SharedRead = Locals.FileObject->SharedRead,
	.SharedWrite = Locals.FileObject->SharedWrite,
	.SharedDelete = Locals.FileObject->SharedDelete,
	.Flags = Locals.FileObject->Flags,
	.FileNameOffset = sizeof(IO_PACKET)
    };

    if (OpenPacket->CreateFileType == CreateFileTypeNone) {
	Locals.IoPacket->Request.MajorFunction = IRP_MJ_CREATE;
	Locals.IoPacket->Request.Create.Options = OpenPacket->CreateOptions;
	Locals.IoPacket->Request.Create.FileAttributes = OpenPacket->FileAttributes;
	Locals.IoPacket->Request.Create.ShareAccess = OpenPacket->ShareAccess;
	Locals.IoPacket->Request.Create.FileObjectParameters = FileObjectParameters;
    } else if (OpenPacket->CreateFileType == CreateFileTypeNamedPipe) {
	Locals.IoPacket->Request.MajorFunction = IRP_MJ_CREATE_NAMED_PIPE;
	Locals.IoPacket->Request.CreatePipe.Options = OpenPacket->CreateOptions;
	Locals.IoPacket->Request.CreatePipe.ShareAccess = OpenPacket->ShareAccess;
	Locals.IoPacket->Request.CreatePipe.Parameters = *(OpenPacket->NamedPipeCreateParameters);
	Locals.IoPacket->Request.CreatePipe.FileObjectParameters = FileObjectParameters;
    } else {
	assert(OpenPacket->CreateFileType == CreateFileTypeMailslot);
	Locals.IoPacket->Request.MajorFunction = IRP_MJ_CREATE_MAILSLOT;
	Locals.IoPacket->Request.CreateMailslot.Options = OpenPacket->CreateOptions;
	Locals.IoPacket->Request.CreateMailslot.ShareAccess = OpenPacket->ShareAccess;
	Locals.IoPacket->Request.CreateMailslot.Parameters = *(OpenPacket->MailslotCreateParameters);
	Locals.IoPacket->Request.CreateMailslot.FileObjectParameters = FileObjectParameters;
    }

    Locals.IoPacket->Request.Device.Object = Device;
    Locals.IoPacket->Request.File.Object = Locals.FileObject;
    IF_ERR_GOTO(out, Status, IopAllocatePendingIrp(Locals.IoPacket, Thread, &Locals.PendingIrp));
    IopQueueIoPacket(Locals.PendingIrp, Driver, Thread);

    /* For create/open we always wait till the driver has completed the request. */
    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);

    /* This is the starting point when the function is resumed. */
    assert(Locals.FileObject != NULL);

    IO_STATUS_BLOCK IoStatus = Locals.PendingIrp->IoResponseStatus;
    OpenContext->Information = IoStatus.Information;
    Status = IoStatus.Status;

    if (NT_SUCCESS(Status)) {
	*pOpenedInstance = Locals.FileObject;
    }

out:
    if (!NT_SUCCESS(Status) && Locals.FileObject != NULL) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.PendingIrp == NULL && Locals.IoPacket != NULL) {
	ExFreePool(Locals.IoPacket);
    } else {
	/* This will free the pending IRP and detach the pending irp from the thread.
	 * At this point the IRP has already been detached from the driver object,
	 * so we do not need to remove it from the driver IRP queue here. */
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(State, Status);
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
	.DeviceName = DeviceName,
	.DeviceInfo = *DeviceInfo,
	.Exclusive = Exclusive
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_DEVICE, (POBJECT *) &DeviceObject, &CreaCtx));
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
    /* Detech the source device from the previous device stack (if any) */
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
    while (Device->AttachedDevice != NULL) {
	Device = Device->AttachedDevice;
    }
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
                               IN HANDLE Event,
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
	    PIO_DRIVER_OBJECT DriverObject;
	    PIO_PACKET IoPacket;
	    MWORD DriverInputBuffer;
	    MWORD DriverOutputBuffer;
	    PPENDING_IRP PendingIrp;
	});

    if (FileHandle == NULL) {
	ASYNC_RETURN(State, STATUS_INVALID_HANDLE);
    }
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread->Process, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    assert(Locals.FileObject->DeviceObject != NULL);
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);
    Locals.DriverObject = Locals.FileObject->DeviceObject->DriverObject;

    IF_ERR_GOTO(out, Status,
		IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET),
				    &Locals.IoPacket));
    assert(Locals.IoPacket != NULL);

    Locals.IoPacket->Request.MajorFunction = IRP_MJ_DEVICE_CONTROL;
    Locals.IoPacket->Request.MinorFunction = 0;
    Locals.IoPacket->Request.Control = 0;
    Locals.IoPacket->Request.Flags = 0;
    Locals.IoPacket->Request.Device.Object = Locals.FileObject->DeviceObject;
    Locals.IoPacket->Request.File.Object = Locals.FileObject;

    IF_ERR_GOTO(out, Status,
		IopMapUserBuffer(Thread->Process, Locals.DriverObject,
				 (MWORD) InputBuffer, InputBufferLength,
				 &Locals.DriverInputBuffer, TRUE));

    IF_ERR_GOTO(out, Status,
		IopMapUserBuffer(Thread->Process, Locals.DriverObject,
				 (MWORD) OutputBuffer, OutputBufferLength,
				 &Locals.DriverOutputBuffer,
				 METHOD_FROM_CTL_CODE(Ioctl) == METHOD_IN_DIRECT));

    Locals.IoPacket->Request.DeviceIoControl.InputBuffer = (PVOID)Locals.DriverInputBuffer;
    Locals.IoPacket->Request.DeviceIoControl.OutputBuffer = (PVOID)Locals.DriverOutputBuffer;
    Locals.IoPacket->Request.DeviceIoControl.InputBufferLength = InputBufferLength;
    Locals.IoPacket->Request.DeviceIoControl.OutputBufferLength = OutputBufferLength;
    Locals.IoPacket->Request.DeviceIoControl.IoControlCode = Ioctl;

    IF_ERR_GOTO(out, Status,
		IopAllocatePendingIrp(Locals.IoPacket, Thread, &Locals.PendingIrp));
    IopQueueIoPacket(Locals.PendingIrp, Locals.DriverObject, Thread);

    /* Only wait for the IO completion if file is opened with
     * the synchronize flag. Otherwise, return pending status */
    if (!IopFileIsSynchronous(Locals.FileObject)) {
	/* TODO: Event, APC and IO completion port... */
	ASYNC_RETURN(State, STATUS_PENDING);
    }
    AWAIT_IF(IopFileIsSynchronous(Locals.FileObject), KeWaitForSingleObject, State,
	     Locals, Thread, &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);

    /* This is the starting point when the function is resumed. */
    Status = Locals.PendingIrp->IoResponseStatus.Status;

out:
    if (!NT_SUCCESS(Status) && Locals.FileObject != NULL) {
	/* The IO request has returned a error status. Clean up the file object. */
	ObDereferenceObject(Locals.FileObject);
    }
    IopUnmapUserBuffer(Locals.DriverObject, Locals.DriverInputBuffer);
    IopUnmapUserBuffer(Locals.DriverObject, Locals.DriverOutputBuffer);
    if (Locals.PendingIrp == NULL & Locals.IoPacket != NULL) {
	ExFreePool(Locals.IoPacket);
    } else {
	/* This will free the pending IRP and detach the pending irp from the thread.
	 * At this point the IRP has already been detached from the driver object,
	 * so we do not need to remove it from the driver IRP queue here. */
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(State, Status);
}
