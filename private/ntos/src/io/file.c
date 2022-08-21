#include "iop.h"
#include "helpers.h"

LIST_ENTRY IopFileObjectList;

/*
 * For now IO_FILE_OBJECT is just a pointer to an in-memory buffer.
 */
NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx)
{
    PIO_FILE_OBJECT File = (PIO_FILE_OBJECT)Object;
    PFILE_OBJ_CREATE_CONTEXT Ctx = (PFILE_OBJ_CREATE_CONTEXT)CreaCtx;

    File->DeviceObject = Ctx->DeviceObject;
    File->FileName = Ctx->FileName;
    File->BufferPtr = Ctx->BufferPtr;
    File->Size = Ctx->FileSize;
    InsertTailList(&IopFileObjectList, &File->Link);

    return STATUS_SUCCESS;
}

NTSTATUS IopCreateFileObject(IN PCSTR FileName,
			     IN POBJECT ParentDirectory,
			     IN PIO_DEVICE_OBJECT DeviceObject,
			     IN PVOID BufferPtr,
			     IN MWORD FileSize,
			     OUT PIO_FILE_OBJECT *pFile)
{
    assert(pFile != NULL);
    PIO_FILE_OBJECT File = NULL;
    FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	.DeviceObject = DeviceObject,
	.FileName = FileName,
	.BufferPtr = BufferPtr,
	.FileSize = FileSize
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *) &File, ParentDirectory,
			   ParentDirectory ? FileName : NULL, 0, &CreaCtx));
    assert(File != NULL);

    *pFile = File;
    return STATUS_SUCCESS;
}

/*
 * This is a temporary function for the ldr component to create the initrd
 * boot module files. Eventually we will turn them into a proper DEVICE object.
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
 * This is a temporary function for the ldr component to create the initrd
 * boot module files. When we finished the cache manager we will use the cc
 * facilities for this.
 *
 * If ParentDirectory is not NULL, the file object is inserted under it as
 * a sub-object. Otherwise, the file object created is a no-name object and
 * is not part of any namespace (as far as the object manager is concerned).
 */
NTSTATUS IoCreateFile(IN PCSTR FileName,
		      IN POBJECT ParentDirectory,
		      IN PVOID BufferPtr,
		      IN MWORD FileSize,
		      OUT PIO_FILE_OBJECT *pFile)
{
    return IopCreateFileObject(FileName, ParentDirectory, NULL,
			       BufferPtr, FileSize, pFile);
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

#ifdef CONFIG_DEBUG_BUILD
VOID IoDbgDumpFileObject(IN PIO_FILE_OBJECT File)
{
    DbgPrint("Dumping file object %p\n", File);
    if (File == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }
    DbgPrint("    DeviceObject = %p\n", File->DeviceObject);
    DbgPrint("    FileName = %s\n", File->FileName);
    DbgPrint("    ImageSectionObject = %p\n", File->SectionObject.ImageSectionObject);
    DbgPrint("    DataSectionObject = %p\n", File->SectionObject.DataSectionObject);
    DbgPrint("    BufferPtr = %p\n", (PVOID) File->BufferPtr);
    DbgPrint("    Size = 0x%zx\n", File->Size);
}
#endif
