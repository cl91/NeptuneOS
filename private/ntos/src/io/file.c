#include "iop.h"

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

    return STATUS_SUCCESS;
}

NTSTATUS IopCreateFileObject(IN PCSTR FileName,
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
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *) &File, &CreaCtx));
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
			       IN PVOID Context,
			       OUT POBJECT *pOpenedInstance,
			       OUT PCSTR *pRemainingPath,
			       IN PVOID OpenResponse)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(SubPath != NULL);
    assert(Context != NULL);
    assert(OpenResponse != NULL);
    assert(pOpenedInstance != NULL);

    *pRemainingPath = SubPath;
    if (*SubPath != '\0') {
	return STATUS_OBJECT_NAME_INVALID;
    }
    *pOpenedInstance = Object;
    return STATUS_SUCCESS;
}

/*
 * This is a temporary function for the ldr component to create the initrd
 * boot module files. When we finished the cache manager we will use the cc
 * facilities for this.
 */
NTSTATUS IoCreateFile(IN PCSTR FileName,
		      IN PVOID BufferPtr,
		      IN MWORD FileSize,
		      OUT PIO_FILE_OBJECT *pFile)
{
    return IopCreateFileObject(FileName, NULL, BufferPtr, FileSize, pFile);
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
    PCSTR DevicePath = ObjectAttributes.ObjectNameBuffer;
    NTSTATUS Status;
    OPEN_RESPONSE OpenResponse;

    ASYNC_BEGIN(State);
    Thread->NtCreateFileSavedState.OpenPacket.CreateFileType = CreateFileTypeNone;
    Thread->NtCreateFileSavedState.OpenPacket.CreateOptions = CreateOptions;
    Thread->NtCreateFileSavedState.OpenPacket.FileAttributes = FileAttributes;
    Thread->NtCreateFileSavedState.OpenPacket.ShareAccess = ShareAccess;
    Thread->NtCreateFileSavedState.OpenPacket.Disposition = CreateDisposition;

    AWAIT_EX(ObOpenObjectByName, Status, State, Thread, DevicePath,
	     OBJECT_TYPE_MASK_DEVICE, &Thread->NtCreateFileSavedState.OpenPacket,
	     &OpenResponse, FileHandle);
    ASYNC_END(Status);
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
    PCSTR FilePath = ObjectAttributes.ObjectNameBuffer;
    NTSTATUS Status;
    OPEN_RESPONSE OpenResponse;

    ASYNC_BEGIN(State);
    Thread->NtOpenFileSavedState.OpenPacket.CreateFileType = CreateFileTypeNone;
    Thread->NtOpenFileSavedState.OpenPacket.CreateOptions = OpenOptions;
    Thread->NtOpenFileSavedState.OpenPacket.FileAttributes = 0;
    Thread->NtOpenFileSavedState.OpenPacket.ShareAccess = ShareAccess;
    Thread->NtOpenFileSavedState.OpenPacket.Disposition = 0;

    /* TODO: We need to implement file system drivers */
    AWAIT_EX(ObOpenObjectByName, Status, State, Thread, FilePath,
	     /* Eventually the following mask will be changed to just DEVICE */
	     OBJECT_TYPE_MASK_DEVICE | OBJECT_TYPE_MASK_FILE,
	     &Thread->NtOpenFileSavedState.OpenPacket, &OpenResponse, FileHandle);
    ASYNC_END(Status);
}

NTSTATUS NtReadFile(IN ASYNC_STATE AsyncState,
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
