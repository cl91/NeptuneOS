#include <wdmp.h>

NTSTATUS IopCreateFileObject(IN PIO_PACKET IoPacket,
			     IN PDEVICE_OBJECT DeviceObject,
			     IN PFILE_OBJECT_CREATE_PARAMETERS Params,
			     IN GLOBAL_HANDLE Handle,
			     OUT PFILE_OBJECT *pFileObject)
{
    assert(Params != NULL);
    assert(Handle != 0);
    assert(pFileObject != NULL);
    assert(!IopGetFileObject(Handle));
    IopAllocateObject(FileObject, FILE_OBJECT);
    FileObject->DeviceObject = DeviceObject;
    UNICODE_STRING FileName = {0};
    if (Params->FileNameOffset) {
	RET_ERR_EX(RtlpUtf8ToUnicodeString(RtlGetProcessHeap(),
					   (PCHAR)(&IoPacket->Request) + Params->FileNameOffset,
					   &FileName),
		   IopFreePool(FileObject));
    }
    ObInitializeObject(FileObject, CLIENT_OBJECT_FILE, FILE_OBJECT);
    FileObject->Header.GlobalHandle = Handle;
    FileObject->ReadAccess = Params->ReadAccess;
    FileObject->WriteAccess = Params->WriteAccess;
    FileObject->DeleteAccess = Params->DeleteAccess;
    FileObject->SharedRead = Params->SharedRead;
    FileObject->SharedWrite = Params->SharedWrite;
    FileObject->SharedDelete = Params->SharedDelete;
    FileObject->Flags = Params->Flags;
    FileObject->FileName = FileName;
    InsertTailList(&IopFileObjectList, &FileObject->Private.Link);
    *pFileObject = FileObject;
    return STATUS_SUCCESS;
}

VOID IopDeleteFileObject(IN PFILE_OBJECT FileObject)
{
    assert(FileObject != NULL);
    assert(FileObject->Private.Link.Flink != NULL);
    assert(FileObject->Private.Link.Blink != NULL);
    assert(FileObject->Header.GlobalHandle != 0);
    RemoveEntryList(&FileObject->Private.Link);
    if (FileObject->FileName.Buffer) {
	IopFreePool(FileObject->FileName.Buffer);
    }
    IopFreePool(FileObject);
}

NTAPI NTSTATUS IoRegisterFileSystem(IN PDEVICE_OBJECT DeviceObject)
{
    GLOBAL_HANDLE Handle = IopGetDeviceHandle(DeviceObject);
    if (Handle == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    return WdmRegisterFileSystem(Handle);
}

/*
 * A stream file object is a special file object used by the cache manager to
 * allow the client driver to perform cached IO on a device object using the
 * cache manager API. Drivers wishing to perform cached IO on a device object
 * create a stream file object from the device object, and invoke the necessary
 * cache manager API against this stream file object. A stream file object is
 * strictly local and does not have a server-side object.
 */
NTAPI PFILE_OBJECT IoCreateStreamFileObject(IN PDEVICE_OBJECT DeviceObject)
{
    if (!DeviceObject) {
	return NULL;
    }
    PFILE_OBJECT FileObject = RtlAllocateHeap(RtlGetProcessHeap(),
					      HEAP_ZERO_MEMORY,
					      sizeof(FILE_OBJECT));
    if (!FileObject) {
	return NULL;
    }
    ObInitializeObject(FileObject, CLIENT_OBJECT_FILE, FILE_OBJECT);
    FileObject->DeviceObject = DeviceObject;
    FileObject->Flags = FO_STREAM_FILE;
    return FileObject;
}
