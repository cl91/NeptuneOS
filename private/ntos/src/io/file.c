#include "iop.h"

NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx)
{
    assert(CreaCtx);
    PIO_FILE_OBJECT File = (PIO_FILE_OBJECT)Object;
    PFILE_OBJ_CREATE_CONTEXT Ctx = (PFILE_OBJ_CREATE_CONTEXT)CreaCtx;

    /* If the FileName is not NULL but points to an empty string, we
     * must be opening a non-file-system device object, in which case
     * we do not allocate an FCB. */
    if ((Ctx->FileName && *Ctx->FileName == '\0') || Ctx->NoFcb) {
	File->Fcb = NULL;
    } else if (Ctx->Fcb) {
	File->Fcb = Ctx->Fcb;
    } else {
	IopAllocatePool(Fcb, IO_FILE_CONTROL_BLOCK);
	File->Fcb = Fcb;
	if (Ctx->FileName) {
	    Fcb->FileName = RtlDuplicateString(Ctx->FileName, NTOS_IO_TAG);
	    if (!Fcb->FileName) {
		IopFreePool(Fcb);
		return STATUS_NO_MEMORY;
	    }
	}
	Fcb->FileSize = Ctx->FileSize;
	Fcb->Vcb = Ctx->Vcb;
	InitializeListHead(&Fcb->PrivateCacheMaps);
    }

    File->DeviceObject = Ctx->DeviceObject;
    File->ReadAccess = Ctx->ReadAccess;
    File->WriteAccess = Ctx->WriteAccess;
    File->DeleteAccess = Ctx->DeleteAccess;
    File->SharedRead = Ctx->SharedRead;
    File->SharedWrite = Ctx->SharedWrite;
    File->SharedDelete = Ctx->SharedDelete;
    if (Ctx->DeviceObject) {
	InsertTailList(&Ctx->DeviceObject->OpenFileList, &File->DeviceLink);
    }

    return STATUS_SUCCESS;
}

/*
 * Create a "master" file object for a newly opened device object. If
 * FileName is not an empty string (typically when the device object is
 * a volume object belonging to a file system), the file object will
 * be inserted under the device object using the file name as sub-path.
 * File object created will have all IO access rights granted.
 */
NTSTATUS IopCreateMasterFileObject(IN PCSTR FileName,
				   IN PIO_DEVICE_OBJECT DeviceObject,
				   OUT PIO_FILE_OBJECT *pFile)
{
    assert(FileName);
    assert(DeviceObject);
    assert(pFile);
    PIO_FILE_OBJECT File = NULL;
    FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	.DeviceObject = DeviceObject,
	.FileName = FileName,
	.FileSize = 0,
	.Fcb = NULL,
	.Vcb = DeviceObject->Vcb,
	.NoFcb = FALSE,
	.ReadAccess = TRUE,
	.WriteAccess = TRUE,
	.DeleteAccess = TRUE,
	.SharedRead = TRUE,
	.SharedWrite = TRUE,
	.SharedDelete = TRUE
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *)&File, &CreaCtx));
    assert(File != NULL);
    if (*FileName != '\0') {
	RET_ERR_EX(ObInsertObject(DeviceObject, File, FileName, 0),
		   ObDereferenceObject(File));
    }
    *pFile = File;
    return STATUS_SUCCESS;
}

/*
 * TODO: We need to handle opening against a RelatedFileObject
 */
NTSTATUS IopFileObjectOpenProc(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN POBJECT Object,
			       IN PCSTR SubPath,
			       IN ULONG Attributes,
			       IN POB_OPEN_CONTEXT OpenContext,
			       OUT POBJECT *pOpenedInstance,
			       OUT PCSTR *pRemainingPath)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(SubPath != NULL);
    assert(pOpenedInstance != NULL);

    *pRemainingPath = SubPath;
    if (*SubPath != '\0') {
	return STATUS_OBJECT_NAME_INVALID;
    }
    *pOpenedInstance = Object;
    return STATUS_SUCCESS;
}

VOID IopFileObjectDeleteProc(IN POBJECT Self)
{
}

/*
 * This is a helper function for the ldr component to create the initrd
 * boot module files. These files do not have a corresponding device object
 * because they are not managed by any file system.
 *
 * If File and ParentDirectory are not NULL, the file object is inserted
 * under ParentDirectory as a sub-object. Otherwise, the file object created
 * is a no-name object and is not part of any namespace as far as the object
 * manager is concerned.
 */
NTSTATUS IoCreateDevicelessFile(IN OPTIONAL PCSTR FileName,
				IN OPTIONAL POBJECT ParentDirectory,
				IN OPTIONAL MWORD FileSize,
				OUT PIO_FILE_OBJECT *pFile)
{
    assert(pFile);
    PIO_FILE_OBJECT File = NULL;
    FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	.DeviceObject = NULL,
	.FileName = FileName,
	.FileSize = FileSize,
	.Fcb = NULL,
	.Vcb = NULL,
	.NoFcb = !FileSize
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *)&File, &CreaCtx));
    assert(File != NULL);
    NTSTATUS Status;
    if (FileSize) {
	IF_ERR_GOTO(out, Status, CcInitializeCacheMap(File->Fcb, NULL, NULL));
    }
    if (FileName && ParentDirectory) {
	IF_ERR_GOTO(out, Status, ObInsertObject(ParentDirectory, File, FileName, 0));
    }
    *pFile = File;
    Status = STATUS_SUCCESS;
out:
    if (!NT_SUCCESS(Status)) {
	ObDereferenceObject(File);
    }
    return Status;
}

NTSTATUS NtCreateFile(IN ASYNC_STATE State,
		      IN PTHREAD Thread,
                      OUT HANDLE *FileHandle,
                      IN ACCESS_MASK DesiredAccess,
                      IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                      OUT IO_STATUS_BLOCK *IoStatusBlock,
                      IN OPTIONAL PLARGE_INTEGER AllocationSize,
                      IN ULONG FileAttributes,
                      IN ULONG ShareAccess,
                      IN ULONG CreateDisposition,
                      IN ULONG CreateOptions,
                      IN OPTIONAL PVOID EaBuffer,
                      IN ULONG EaLength)
{
    NTSTATUS Status;

    ASYNC_BEGIN(State, Locals, {
	    IO_OPEN_CONTEXT OpenContext;
	});
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_DEVICE_OPEN;
    Locals.OpenContext.OpenPacket.CreateFileType = CreateFileTypeNone;
    Locals.OpenContext.OpenPacket.CreateOptions = CreateOptions;
    Locals.OpenContext.OpenPacket.FileAttributes = FileAttributes;
    Locals.OpenContext.OpenPacket.ShareAccess = ShareAccess;
    Locals.OpenContext.OpenPacket.Disposition = CreateDisposition;

    AWAIT_EX(Status, ObOpenObjectByName, State, Locals,
	     Thread, ObjectAttributes, OBJECT_TYPE_FILE,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, FileHandle);
    if (IoStatusBlock != NULL) {
	IoStatusBlock->Status = Status;
	IoStatusBlock->Information = Locals.OpenContext.Information;
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtOpenFile(IN ASYNC_STATE State,
		    IN PTHREAD Thread,
                    OUT HANDLE *FileHandle,
                    IN ACCESS_MASK DesiredAccess,
                    IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                    OUT IO_STATUS_BLOCK *IoStatusBlock,
                    IN ULONG ShareAccess,
                    IN ULONG OpenOptions)
{
    NTSTATUS Status;

    ASYNC_BEGIN(State, Locals, {
	    IO_OPEN_CONTEXT OpenContext;
	});
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_DEVICE_OPEN;
    Locals.OpenContext.OpenPacket.CreateFileType = CreateFileTypeNone;
    Locals.OpenContext.OpenPacket.CreateOptions = OpenOptions;
    Locals.OpenContext.OpenPacket.FileAttributes = 0;
    Locals.OpenContext.OpenPacket.ShareAccess = ShareAccess;
    Locals.OpenContext.OpenPacket.Disposition = 0;

    AWAIT_EX(Status, ObOpenObjectByName, State, Locals,
	     Thread, ObjectAttributes, OBJECT_TYPE_FILE,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, FileHandle);
    if (IoStatusBlock != NULL) {
	IoStatusBlock->Status = Status;
	IoStatusBlock->Information = Locals.OpenContext.Information;
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtReadFile(IN ASYNC_STATE State,
                    IN PTHREAD Thread,
                    IN HANDLE FileHandle,
                    IN HANDLE EventHandle,
                    IN PIO_APC_ROUTINE ApcRoutine,
                    IN PVOID ApcContext,
                    OUT IO_STATUS_BLOCK *IoStatusBlock,
                    OUT PVOID Buffer,
                    IN ULONG BufferLength,
                    IN OPTIONAL PLARGE_INTEGER ByteOffset,
                    IN OPTIONAL PULONG Key)
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

    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = Locals.FileObject,
	.MajorFunction = IRP_MJ_READ,
	.MinorFunction = 0,
	.OutputBuffer = (MWORD)Buffer,
	.OutputBufferLength = BufferLength,
	.Read.Key = Key ? *Key : 0
    };
    if (ByteOffset) {
	Irp.Read.ByteOffset = *ByteOffset;
    } else {
	/* TODO: Use current byte offset of the file object (must be synchronous) */
	/* Irp.Read.ByteOffset = ; */
    }
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
    /* The IO request has returned a error status. Clean up the
       file object. */
    if (!NT_SUCCESS(Status) && Locals.FileObject != NULL) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (!NT_SUCCESS(Status) && Locals.EventObject != NULL) {
	ObDereferenceObject(Locals.EventObject);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtWriteFile(IN ASYNC_STATE AsyncState,
                     IN PTHREAD Thread,
                     IN HANDLE FileHandle,
                     IN HANDLE Event,
                     IN PIO_APC_ROUTINE ApcRoutine,
                     IN PVOID ApcContext,
                     OUT IO_STATUS_BLOCK *IoStatusBlock,
                     IN PVOID Buffer,
                     IN ULONG BufferLength,
                     IN OPTIONAL PLARGE_INTEGER ByteOffset,
                     IN OPTIONAL PULONG Key)
{
    /* Note that since Buffer can be in the service message buffer, we cannot
     * sleep until we have called IopCallDriver. */
    UNIMPLEMENTED;
}

NTSTATUS NtDeleteFile(IN ASYNC_STATE AsyncState,
                      IN PTHREAD Thread,
                      IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetInformationFile(IN ASYNC_STATE AsyncState,
                              IN PTHREAD Thread,
                              IN HANDLE FileHandle,
                              OUT IO_STATUS_BLOCK *IoStatusBlock,
                              IN PVOID FileInfoBuffer,
                              IN ULONG BufferLength,
                              IN FILE_INFORMATION_CLASS FileInformationClass)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryAttributesFile(IN ASYNC_STATE AsyncState,
                               IN PTHREAD Thread,
                               IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                               OUT FILE_BASIC_INFORMATION *FileInformation)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryVolumeInformationFile(IN ASYNC_STATE AsyncState,
                                      IN PTHREAD Thread,
                                      IN HANDLE FileHandle,
                                      OUT IO_STATUS_BLOCK *IoStatusBlock,
                                      IN PVOID FsInfoBuffer,
                                      IN ULONG Length,
                                      IN FS_INFORMATION_CLASS FsInformationClass)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryInformationFile(IN ASYNC_STATE AsyncState,
                                IN PTHREAD Thread,
                                IN HANDLE FileHandle,
                                OUT IO_STATUS_BLOCK *IoStatusBlock,
                                IN PVOID FileInfoBuffer,
                                IN ULONG Length,
                                IN FILE_INFORMATION_CLASS FileInformationClass)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryDirectoryFile(IN ASYNC_STATE AsyncState,
                              IN PTHREAD Thread,
                              IN HANDLE FileHandle,
                              IN HANDLE Event,
                              IN PIO_APC_ROUTINE ApcRoutine,
                              IN PVOID ApcContext,
                              OUT IO_STATUS_BLOCK *IoStatusBlock,
                              IN PVOID FileInfoBuffer,
                              IN ULONG BufferLength,
                              IN FILE_INFORMATION_CLASS FileInformationClass,
                              IN BOOLEAN ReturnSingleEntry,
                              IN OPTIONAL PCSTR FileName,
                              IN BOOLEAN RestartScan)
{
    UNIMPLEMENTED;
}

VOID IoDbgDumpFileObject(IN PIO_FILE_OBJECT File)
{
#ifdef CONFIG_DEBUG_BUILD
    DbgPrint("Dumping file object %p\n", File);
    if (File == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }
    DbgPrint("    DeviceObject = %p\n", File->DeviceObject);
    DbgPrint("    Fcb = %p\n", File->Fcb);
    if (File->Fcb) {
	DbgPrint("    FileName = %s\n", File->Fcb->FileName);
	DbgPrint("    FileSize = 0x%zx\n", File->Fcb->FileSize);
	DbgPrint("    SharedCacheMap = %p\n", File->Fcb->SharedCacheMap);
	DbgPrint("    ImageSectionObject = %p\n", File->Fcb->ImageSectionObject);
	DbgPrint("    DataSectionObject = %p\n", File->Fcb->DataSectionObject);
    }
#endif
}
