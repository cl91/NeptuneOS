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
    PIO_FILE_OBJECT FileObject = NULL;

    ASYNC_BEGIN(State);

    RET_ERR(IopCreateFileObject(Device->DeviceName, Device, NULL, 0, &FileObject));
    assert(FileObject != NULL);

    PIO_REQUEST_PACKET Irp = NULL;
    RET_ERR_EX(IopAllocateIrp(IrpTypeRequest, &Irp), ObDeleteObject(FileObject));
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
    FileObject = Thread->PendingIrp->Request.File.Object;
    assert(FileObject != NULL);

    IO_STATUS_BLOCK IoStatus = Thread->IoResponseStatus;
    ((POPEN_RESPONSE)OpenResponse)->Information = IoStatus.Information;
    NTSTATUS Status = IoStatus.Status;

    if (!NT_SUCCESS(Status)) {
	/* The IO request has returned a error status. Clean up the file object. */
	ObDeleteObject(FileObject);
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
	    ObDeleteObject(DeviceObject);
	    return STATUS_NO_MEMORY;
	}
	/* If the client has supplied a device name, insert the device
	 * object into the global object namespace, with the given path. */
	RET_ERR_EX(ObInsertObjectByPath(DeviceName, DeviceObject),
		   {
		       ExFreePool((PVOID) DeviceNameCopy);
		       ObDeleteObject(DeviceObject);
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
    return STATUS_NOT_IMPLEMENTED;
}
