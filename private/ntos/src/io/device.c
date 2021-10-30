#include "iop.h"

NTSTATUS IopDeviceObjectInitProc(POBJECT Object)
{
    PIO_DEVICE_OBJECT Device = (PIO_DEVICE_OBJECT) Object;
    InitializeListHead(&Device->DeviceLink);
    return STATUS_SUCCESS;
}

/*
 * Note: DeviceName must be a full path.
 */
NTSTATUS IopCreateDevice(IN PTHREAD Thread,
                         IN OPTIONAL PCSTR DeviceName,
                         IN DEVICE_TYPE DeviceType,
                         IN ULONG DeviceCharacteristics,
                         IN BOOLEAN Exclusive,
                         OUT HANDLE *DeviceHandle)
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

    *DeviceHandle = (HANDLE) OBJECT_TO_GLOBAL_HANDLE(DeviceObject);

    return STATUS_SUCCESS;
}

NTSTATUS NtDeviceIoControlFile(IN PTHREAD Thread,
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
