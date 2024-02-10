#include "iop.h"
#include "helpers.h"

/*
 * For now IO_FILE_OBJECT is just a pointer to an in-memory buffer.
 */
NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx)
{
    assert(CreaCtx);
    PIO_FILE_OBJECT File = (PIO_FILE_OBJECT)Object;
    PFILE_OBJ_CREATE_CONTEXT Ctx = (PFILE_OBJ_CREATE_CONTEXT)CreaCtx;

    if (!Ctx->FileName || *Ctx->FileName == '\0' || Ctx->NoNewFcb) {
	File->Fcb = NULL;
    } else if (Ctx->Fcb) {
	File->Fcb = Ctx->Fcb;
    } else {
	IopAllocatePool(Fcb, IO_FILE_CONTROL_BLOCK);
	File->Fcb = Fcb;
	Fcb->FileName = Ctx->FileName;
	Fcb->FileSize = Ctx->FileSize;
	Fcb->BufferPtr = Ctx->BufferPtr;
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
	.BufferPtr = NULL,
	.FileSize = 0,
	.Fcb = NULL,
	.NoNewFcb = FALSE,
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
 * If ParentDirectory is not NULL, the file object is inserted under it as
 * a sub-object. Otherwise, the file object created is a no-name object and
 * is not part of any namespace (as far as the object manager is concerned).
 */
NTSTATUS IoCreateDevicelessFile(IN PCSTR FileName,
				IN OPTIONAL POBJECT ParentDirectory,
				IN PVOID BufferPtr,
				IN MWORD FileSize,
				OUT PIO_FILE_OBJECT *pFile)
{
    assert(FileName);
    assert(BufferPtr);
    assert(FileSize);
    assert(pFile);
    PIO_FILE_OBJECT File = NULL;
    FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	.DeviceObject = NULL,
	.FileName = FileName,
	.BufferPtr = BufferPtr,
	.FileSize = FileSize,
	.Fcb = NULL,
	.NoNewFcb = FALSE
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *)&File, &CreaCtx));
    assert(File != NULL);
    if (ParentDirectory) {
	RET_ERR_EX(ObInsertObject(ParentDirectory, File, FileName, 0),
		   ObDereferenceObject(File));
    }
    *pFile = File;
    return STATUS_SUCCESS;
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

    /* We haven't implemented file systems yet so we hard-code the logic
     * for directory files. */
    if (OpenOptions & FILE_DIRECTORY_FILE) {
	POBJECT_DIRECTORY Dir = NULL;
	Status = ObReferenceObjectByName(ObjectAttributes.ObjectNameBuffer,
					 OBJECT_TYPE_DIRECTORY, NULL,
					 !!(ObjectAttributes.Attributes & OBJ_CASE_INSENSITIVE),
					 (POBJECT *)&Dir);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	assert(Dir != NULL);
	Status = ObCreateHandle(Thread->Process, Dir, FileHandle);
	ObDereferenceObject(Dir);
    out:
	if (IoStatusBlock != NULL) {
	    IoStatusBlock->Status = Status;
	    IoStatusBlock->Information = 0;
	}
	return Status;
    }

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
                    IN PVOID Buffer,
                    IN ULONG BufferLength,
                    IN OPTIONAL PLARGE_INTEGER ByteOffset,
                    IN OPTIONAL PULONG Key)
{
    IO_SERVICE_PROLOGUE(State, Locals, FileObject, EventObject,
			IoPacket, PendingIrp);

    Locals.IoPacket->Request.MajorFunction = IRP_MJ_READ;
    Locals.IoPacket->Request.MinorFunction = 0;
    Locals.IoPacket->Request.OutputBuffer = (MWORD)Buffer;
    Locals.IoPacket->Request.OutputBufferLength = BufferLength;
    Locals.IoPacket->Request.Read.Key = Key ? *Key : 0;
    if (ByteOffset != NULL) {
	Locals.IoPacket->Request.Read.ByteOffset = *ByteOffset;
    }

    IO_SERVICE_EPILOGUE(out, Status, Locals, FileObject, EventObject,
			IoPacket, PendingIrp, IoStatusBlock);

out:
    IO_SERVICE_CLEANUP(Status, Locals, FileObject,
		       EventObject, IoPacket, PendingIrp);
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
	DbgPrint("    BufferPtr = %p\n", (PVOID)File->Fcb->BufferPtr);
	DbgPrint("    ImageSectionObject = %p\n", File->Fcb->ImageSectionObject);
	DbgPrint("    DataSectionObject = %p\n", File->Fcb->DataSectionObject);
    }
#endif
}
