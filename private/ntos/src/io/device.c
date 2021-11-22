#include "iop.h"

NTSTATUS IopDeviceObjectInitProc(POBJECT Object)
{
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT) Object;
    InitializeListHead(&Device->DeviceLink);
    return STATUS_SUCCESS;
}

NTSTATUS IopDeviceObjectOpenProc(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN POBJECT Object,
				 IN PVOID Context,
				 IN PVOID OpenResponse,
				 OUT POBJECT *pOpenedInstance)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(Context != NULL);
    assert(OpenResponse != NULL);
    assert(pOpenedInstance != NULL);

    /* These must come before ASYNC_BEGIN since they are referenced
     * throughout the whole function (in particular, after the AWAIT call) */
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT)Object;
    PIO_DRIVER_OBJECT Driver = Device->DriverObject;
    assert(Driver != NULL);
    POPEN_PACKET OpenPacket = (POPEN_PACKET)Context;

    ASYNC_BEGIN(State);

    PIO_FILE_OBJECT FileObject = NULL;
    RET_ERR(IopCreateFileObject(Device->DeviceName, Device, NULL, 0, &FileObject));
    assert(FileObject != NULL);

    /* Check if this is Synch I/O and set the sync flag accordingly */
    if (OpenPacket->CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) {
	FileObject->Flags |= FO_SYNCHRONOUS_IO;
	/* Check if it's also alertable and set the alertable flag accordingly */
	if (OpenPacket->CreateOptions & FILE_SYNCHRONOUS_IO_ALERT) {
	    FileObject->Flags |= FO_ALERTABLE_IO;
	}
    }

    PIO_REQUEST_PACKET Irp = NULL;
    RET_ERR_EX(IopAllocateIrp(IrpTypeRequest, &Irp), ObDereferenceObject(FileObject));
    assert(Irp != NULL);

    if (OpenPacket->CreateFileType == CreateFileTypeNone) {
	Irp->Request.MajorFunction = IRP_MJ_CREATE;
	Irp->Request.Parameters.Create.Options = OpenPacket->CreateOptions;
	Irp->Request.Parameters.Create.FileAttributes = OpenPacket->FileAttributes;
	Irp->Request.Parameters.Create.ShareAccess = OpenPacket->ShareAccess;
    } else if (OpenPacket->CreateFileType == CreateFileTypeNamedPipe) {
	Irp->Request.MajorFunction = IRP_MJ_CREATE_NAMED_PIPE;
	Irp->Request.Parameters.CreatePipe.Options = OpenPacket->CreateOptions;
	Irp->Request.Parameters.CreatePipe.ShareAccess = OpenPacket->ShareAccess;
	Irp->Request.Parameters.CreatePipe.Parameters = *(OpenPacket->NamedPipeCreateParameters);
    } else {
	assert(OpenPacket->CreateFileType == CreateFileTypeMailslot);
	Irp->Request.MajorFunction = IRP_MJ_CREATE_MAILSLOT;
	Irp->Request.Parameters.CreateMailslot.Options = OpenPacket->CreateOptions;
	Irp->Request.Parameters.CreateMailslot.ShareAccess = OpenPacket->ShareAccess;
	Irp->Request.Parameters.CreateMailslot.Parameters = *(OpenPacket->MailslotCreateParameters);
    }

    Irp->Request.Device.Object = Device;
    Irp->Request.File.Object = FileObject;
    IopQueueIrp(Irp, Driver, Thread);

    /* For create/open we always wait till the driver has completed the request. */
    AWAIT(KeWaitForSingleObject, State, Thread, &Thread->IoCompletionEvent.Header);

    /* This is the starting point when the function is resumed.
     * Note: The local variable Irp is undefined here. Irp in the previous async block
     * is stored as Thread's PendingIrp */
    assert(Thread->PendingIrp->Type == IrpTypeRequest);
    PIO_FILE_OBJECT FileObject = Thread->PendingIrp->Request.File.Object;
    assert(FileObject != NULL);

    IO_STATUS_BLOCK IoStatus = Thread->IoResponseStatus;
    ((POPEN_RESPONSE)OpenResponse)->Information = IoStatus.Information;
    NTSTATUS Status = IoStatus.Status;

    if (NT_SUCCESS(Status)) {
	*pOpenedInstance = FileObject;
    } else {
	/* The IO request has returned a error status. Clean up the file object. */
	ObDereferenceObject(FileObject);
    }

    /* This will free the pending IRP and set the thread pending irp to NULL.
     * At this point the IRP has already been detached from the driver object,
     * so we do not need to remove it from the driver IRP queue here. */
    IopFreePendingIrp(Thread);
    ASYNC_END(Status);
}

/*
 * Note: DeviceName must be a full path.
 */
NTSTATUS IopCreateDevice(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
                         IN OPTIONAL PCSTR DeviceName,
                         IN DEVICE_TYPE DeviceType,
                         IN ULONG DeviceCharacteristics,
                         IN BOOLEAN Exclusive,
                         OUT GLOBAL_HANDLE *DeviceHandle)
{
    assert(Thread != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    assert(DeviceHandle != NULL);

    PIO_DEVICE_OBJECT DeviceObject = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_DEVICE, (POBJECT *) &DeviceObject));
    assert(DeviceObject != NULL);

    /* If the client has supplied a non-empty DeviceName, record it */
    if ((DeviceName != NULL) && (DeviceName[0] != '\0')) {
	/* DeviceName must be a full path */
	if (DeviceName[0] != OBJ_NAME_PATH_SEPARATOR) {
	    return STATUS_INVALID_PARAMETER_1;
	}
	PCSTR DeviceNameCopy = RtlDuplicateString(DeviceName, NTOS_IO_TAG);
	if (DeviceNameCopy == NULL) {
	    ObDereferenceObject(DeviceObject);
	    return STATUS_NO_MEMORY;
	}
	/* If the client has supplied a device name, insert the device
	 * object into the global object namespace, with the given path. */
	RET_ERR_EX(ObInsertObjectByPath(DeviceName, DeviceObject),
		   {
		       ExFreePool((PVOID) DeviceNameCopy);
		       ObDereferenceObject(DeviceObject);
		   });
	DeviceObject->DeviceName = DeviceNameCopy;
    }

    DeviceObject->DriverObject = DriverObject;
    InsertTailList(&DriverObject->DeviceList, &DeviceObject->DeviceLink);
    DeviceObject->DeviceType = DeviceType;
    DeviceObject->DeviceCharacteristics = DeviceCharacteristics;
    DeviceObject->Exclusive = Exclusive;

    *DeviceHandle = OBJECT_TO_GLOBAL_HANDLE(DeviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS NtDeviceIoControlFile(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
                               IN HANDLE FileHandle,
                               IN HANDLE Event,
                               IN PIO_APC_ROUTINE ApcRoutine,
                               IN PVOID ApcContext,
                               OUT IO_STATUS_BLOCK *IoStatusBlock,
                               IN ULONG IoControlCode,
                               IN PVOID InputBuffer,
                               IN ULONG InputBufferLength,
                               IN PVOID OutputBuffer,
                               IN ULONG OutputBufferLength)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);

    ASYNC_BEGIN(State);

    if (FileHandle == NULL) {
	return STATUS_INVALID_HANDLE;
    }
    PIO_FILE_OBJECT FileObject = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, FileHandle,
				      OBJECT_TYPE_FILE, (POBJECT *)&FileObject));
    assert(FileObject != NULL);
    assert(FileObject->DeviceObject != NULL);
    assert(FileObject->DeviceObject->DriverObject != NULL);
    PIO_DRIVER_OBJECT DriverObject = FileObject->DeviceObject->DriverObject;

    PIO_REQUEST_PACKET Irp = NULL;
    RET_ERR_EX(IopAllocateIrp(IrpTypeRequest, &Irp),
	       ObDereferenceObject(FileObject));
    assert(Irp != NULL);

    Irp->Request.MajorFunction = IRP_MJ_DEVICE_CONTROL;
    Irp->Request.MinorFunction = 0;
    Irp->Request.Control = 0;
    Irp->Request.Flags = 0;
    Irp->Request.Device.Object = FileObject->DeviceObject;
    Irp->Request.File.Object = FileObject;

    MWORD DriverInputBuffer = 0;
    if ((InputBuffer != NULL) && (InputBufferLength != 0)) {
	RET_ERR_EX(IopMapUserBuffer(Thread->Process, DriverObject,
				    (MWORD) InputBuffer, InputBufferLength,
				    &DriverInputBuffer, TRUE),
		   {
		       ObDereferenceObject(FileObject);
		       ExFreePool(Irp);
		   });
    }

    MWORD DriverOutputBuffer = 0;
    if ((OutputBuffer != NULL) && (OutputBufferLength != 0)) {
	RET_ERR_EX(IopMapUserBuffer(Thread->Process, DriverObject,
				    (MWORD) OutputBuffer, OutputBufferLength,
				    &DriverOutputBuffer, FALSE),
		   {
		       ObDereferenceObject(FileObject);
		       ExFreePool(Irp);
		       if (DriverInputBuffer != 0) {
			   IopUnmapUserBuffer(DriverObject, DriverInputBuffer);
		       }
		   });
    }

    Irp->Request.Parameters.DeviceIoControl.InputBuffer = (PVOID)DriverInputBuffer;
    Irp->Request.Parameters.DeviceIoControl.OutputBuffer = (PVOID)DriverOutputBuffer;
    Irp->Request.Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
    Irp->Request.Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;
    Irp->Request.Parameters.DeviceIoControl.IoControlCode = IoControlCode;

    IopQueueIrp(Irp, DriverObject, Thread);

    /* Only wait for the IO completion if file is opened with
     * the synchronize flag. Otherwise, return pending status */
    if (!IopFileIsSynchronous(FileObject)) {
	/* TODO: Event, APC and IO completion port... */
	return STATUS_PENDING;
    }
    AWAIT_IF(IopFileIsSynchronous(FileObject), KeWaitForSingleObject, State,
	     Thread, &Thread->IoCompletionEvent.Header);

    /* This is the starting point when the function is resumed. */
    assert(Thread->PendingIrp->Type == IrpTypeRequest);
    PIO_FILE_OBJECT FileObject = Thread->PendingIrp->Request.File.Object;
    assert(FileObject != NULL);

    NTSTATUS Status = Thread->IoResponseStatus.Status;

    if (!NT_SUCCESS(Status)) {
	/* The IO request has returned a error status. Clean up the file object. */
	ObDereferenceObject(FileObject);
    }

    /* This will free the pending IRP and set the thread pending irp to NULL.
     * At this point the IRP has already been detached from the driver object,
     * so we do not need to remove it from the driver IRP queue here. */
    IopFreePendingIrp(Thread);
    ASYNC_END(Status);
}
