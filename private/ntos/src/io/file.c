#include "iop.h"
#include "mm.h"

VOID IopInitializeFcb(IN PIO_FILE_CONTROL_BLOCK Fcb,
		      IN ULONG64 FileSize,
		      IN PIO_VOLUME_CONTROL_BLOCK Vcb)
{
    Fcb->FileSize = FileSize;
    Fcb->Vcb = Vcb;
    AvlInitializeTree(&Fcb->FileOffsetMappings);
    InitializeListHead(&Fcb->PrivateCacheMaps);
    KeInitializeEvent(&Fcb->WriteCompleted, NotificationEvent);
}

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
	Fcb->MasterFileObject = File;
	if (Ctx->FileName) {
	    Fcb->FileName = RtlDuplicateString(Ctx->FileName, NTOS_IO_TAG);
	    if (!Fcb->FileName) {
		IopFreePool(Fcb);
		return STATUS_NO_MEMORY;
	    }
	}
	IopInitializeFcb(Fcb, Ctx->FileSize, Ctx->Vcb);
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
				IN OPTIONAL ULONG64 FileSize,
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
    if (AllocationSize) {
	Locals.OpenContext.OpenPacket.AllocationSize = AllocationSize->QuadPart;
    }

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

typedef struct _CACHED_IO_CONTEXT {
    KEVENT IoCompletionEvent;
    PIO_FILE_OBJECT FileObject;
    PEVENT_OBJECT EventToSignal;
    PIO_APC_ROUTINE ApcRoutine;
    PVOID ApcContext;
    PTHREAD RequestorThread;
    PVOID Buffer;
    IO_STATUS_BLOCK IoStatus;
    ULONG64 OldFileSize;
    BOOLEAN Write;
} CACHED_IO_CONTEXT, *PCACHED_IO_CONTEXT;

static VOID IopCachedIoCallback(IN PIO_FILE_CONTROL_BLOCK Fcb,
				IN ULONG64 FileOffset,
				IN ULONG64 TargetLength,
				IN NTSTATUS Status,
				IN OUT PVOID Ctx)
{
    PCACHED_IO_CONTEXT Context = Ctx;
    ULONG Length = 0;
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    if (Context->Write && FileOffset > Context->OldFileSize) {
	CcZeroData(Fcb, Context->OldFileSize, FileOffset - Context->OldFileSize);
    }

    while (Length < TargetLength) {
	ULONG BytesToCopy = 0;
	PVOID CacheBuffer = NULL;
	IF_ERR_GOTO(out, Status,
		    CcMapDataEx(NULL, Fcb, FileOffset + Length, TargetLength - Length,
				&BytesToCopy, &CacheBuffer, Context->Write));
	assert(BytesToCopy <= TargetLength - Length);
	ULONG BytesCopied = 0;
	while (BytesCopied < BytesToCopy) {
	    PVOID MappedBuffer = NULL;
	    ULONG MappedLength = 0;
	    IF_ERR_GOTO(out, Status,
			MmMapHyperspacePage(&Context->RequestorThread->Process->VSpace,
					    (MWORD)Context->Buffer + Length + BytesCopied,
					    !Context->Write, &MappedBuffer, &MappedLength));
	    MappedLength = min(MappedLength, BytesToCopy - BytesCopied);
	    if (Context->Write) {
		RtlCopyMemory((PUCHAR)CacheBuffer + BytesCopied, MappedBuffer, MappedLength);
	    } else {
		RtlCopyMemory(MappedBuffer, (PUCHAR)CacheBuffer + BytesCopied, MappedLength);
	    }
	    MmUnmapHyperspacePage(MappedBuffer);
	    BytesCopied += MappedLength;
	}
	assert(BytesCopied == BytesToCopy);
	Length += BytesToCopy;
    }
    assert(Length == TargetLength);
    Status = STATUS_SUCCESS;
out:
    Context->IoStatus.Status = Status;
    Context->IoStatus.Information = Length;
    KeSetEvent(&Context->IoCompletionEvent);
}

static NTSTATUS IopReadWriteFile(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN HANDLE FileHandle,
				 IN HANDLE EventHandle,
				 IN PIO_APC_ROUTINE ApcRoutine,
				 IN PVOID ApcContext,
				 OUT IO_STATUS_BLOCK *IoStatusBlock,
				 IN OUT PVOID Buffer,
				 IN ULONG BufferLength,
				 IN OPTIONAL PLARGE_INTEGER ByteOffset,
				 IN OPTIONAL PULONG Key,
				 IN BOOLEAN Write)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PEVENT_OBJECT EventObject;
	    PPENDING_IRP PendingIrp;
	    PCACHED_IO_CONTEXT Context;
	    PKEVENT IoCompletionEvent;
	    IO_STATUS_BLOCK IoStatus;
	    ULONG64 FileOffset;
	});

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

    if (ByteOffset && ByteOffset->QuadPart != FILE_USE_FILE_POINTER_POSITION) {
	Locals.FileOffset = ByteOffset->QuadPart;
    } else if (Locals.FileObject->Flags & FO_SYNCHRONOUS_IO) {
	Locals.FileOffset = Locals.FileObject->CurrentOffset;
    } else {
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }

    if (Locals.FileOffset == FILE_WRITE_TO_END_OF_FILE) {
	if (!Write) {
	    Status = STATUS_INVALID_PARAMETER;
	    goto out;
	}
	if (Locals.FileObject->Fcb) {
	    Locals.FileOffset = Locals.FileObject->Fcb->FileSize;
	}
    }

    /* If the target file is part of a mounted volume and we need to extend the file, make
     * sure there isn't a concurrent WRITE IRP in progress. If there is one, wait for it
     * to finish. */
    AWAIT_IF(Locals.FileObject->Fcb && Locals.FileObject->Fcb->WritePending &&
	     Locals.FileOffset + BufferLength > Locals.FileObject->Fcb->FileSize,
	     KeWaitForSingleObject, State, Locals, Thread,
	     &Locals.FileObject->Fcb->WriteCompleted.Header, FALSE, NULL);

    /* If the target file is part of a mounted volume, go through Cc to do the IO. */
    if (Locals.FileObject->Fcb) {
	IF_ERR_GOTO(out, Status, CcInitializeCacheMap(Locals.FileObject->Fcb, NULL, NULL));
	Locals.Context = ExAllocatePoolWithTag(sizeof(CACHED_IO_CONTEXT), NTOS_IO_TAG);
	if (!Locals.Context) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	KeInitializeEvent(&Locals.Context->IoCompletionEvent, NotificationEvent);
	Locals.Context->FileObject = Locals.FileObject;
	Locals.Context->EventToSignal = Locals.EventObject;
	Locals.Context->ApcRoutine = ApcRoutine;
	Locals.Context->ApcContext = ApcContext;
	Locals.Context->RequestorThread = Thread;
	Locals.Context->Buffer = Buffer;
	Locals.Context->OldFileSize = Locals.FileObject->Fcb->FileSize;
	Locals.Context->Write = Write;
	CcPinDataEx(Locals.FileObject->Fcb, Locals.FileOffset, BufferLength, Write,
		    IopCachedIoCallback, Locals.Context);
	Locals.IoCompletionEvent = &Locals.Context->IoCompletionEvent;
    } else {
	/* Otherwise, queue an IRP to the target driver object. */
	IO_REQUEST_PARAMETERS Irp = {
	    .Device.Object = Locals.FileObject->DeviceObject,
	    .File.Object = Locals.FileObject
	};
	if (Write) {
	    Irp.MajorFunction = IRP_MJ_WRITE;
	    Irp.InputBuffer = (MWORD)Buffer;
	    Irp.InputBufferLength = BufferLength;
	    Irp.Write.ByteOffset.QuadPart = Locals.FileOffset;
	    Irp.Write.Key = Key ? *Key : 0;
	} else {
	    Irp.MajorFunction = IRP_MJ_READ;
	    Irp.OutputBuffer = (MWORD)Buffer;
	    Irp.OutputBufferLength = BufferLength;
	    Irp.Read.ByteOffset.QuadPart = Locals.FileOffset;
	    Irp.Read.Key = Key ? *Key : 0;
	}
	IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));
	Locals.IoCompletionEvent = &Locals.PendingIrp->IoCompletionEvent;
    }

    /* For now every IO is synchronous. */
    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.IoCompletionEvent->Header, FALSE, NULL);
    Locals.IoStatus = Locals.Context ? Locals.Context->IoStatus :
	Locals.PendingIrp->IoResponseStatus;
    Status = STATUS_SUCCESS;

out:
    if (!NT_SUCCESS(Status)) {
	Locals.IoStatus.Status = Status;
    } else {
	Status = Locals.IoStatus.Status;
    }
    if (IoStatusBlock != NULL) {
	*IoStatusBlock = Locals.IoStatus;
    }
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.EventObject) {
	ObDereferenceObject(Locals.EventObject);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    if (Locals.Context) {
	KeUninitializeEvent(&Locals.Context->IoCompletionEvent);
	IopFreePool(Locals.Context);
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
    return IopReadWriteFile(State, Thread, FileHandle, EventHandle, ApcRoutine, ApcContext,
			    IoStatusBlock, Buffer, BufferLength, ByteOffset, Key, FALSE);
}

NTSTATUS NtWriteFile(IN ASYNC_STATE State,
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
    return IopReadWriteFile(State, Thread, FileHandle, EventHandle, ApcRoutine, ApcContext,
			    IoStatusBlock, Buffer, BufferLength, ByteOffset, Key, TRUE);
}

#define CHECK_LENGTH(BufferLength,Class, Struct)	\
        case Class:					\
            if (BufferLength < sizeof(Struct))		\
                return STATUS_INFO_LENGTH_MISMATCH;	\
            break

NTSTATUS NtQueryDirectoryFile(IN ASYNC_STATE State,
                              IN PTHREAD Thread,
                              IN HANDLE FileHandle,
                              IN HANDLE EventHandle,
                              IN PIO_APC_ROUTINE ApcRoutine,
                              IN PVOID ApcContext,
                              OUT IO_STATUS_BLOCK *IoStatusBlock,
                              IN PVOID FileInfoBuffer,
                              IN ULONG Length,
                              IN FILE_INFORMATION_CLASS FileInformationClass,
                              IN BOOLEAN ReturnSingleEntry,
                              IN OPTIONAL PCSTR FileName,
                              IN BOOLEAN RestartScan)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PEVENT_OBJECT EventObject;
	    PIO_REQUEST_PARAMETERS Irp;
	    PPENDING_IRP PendingIrp;
	    IO_STATUS_BLOCK IoStatus;
	});

    switch (FileInformationClass) {
        CHECK_LENGTH(Length, FileDirectoryInformation, FILE_DIRECTORY_INFORMATION);
        CHECK_LENGTH(Length, FileFullDirectoryInformation, FILE_FULL_DIR_INFORMATION);
        CHECK_LENGTH(Length, FileIdFullDirectoryInformation, FILE_ID_FULL_DIR_INFORMATION);
        CHECK_LENGTH(Length, FileNamesInformation, FILE_NAMES_INFORMATION);
        CHECK_LENGTH(Length, FileBothDirectoryInformation, FILE_BOTH_DIR_INFORMATION);
        CHECK_LENGTH(Length, FileIdBothDirectoryInformation, FILE_ID_BOTH_DIR_INFORMATION);
    default:
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }

    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    /* Deviceless files cannot be queried. */
    if (!Locals.FileObject->DeviceObject) {
	Status = STATUS_NOT_IMPLEMENTED;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);

    if (EventHandle != NULL) {
	IF_ERR_GOTO(out, Status,
		    ObReferenceObjectByHandle(Thread, EventHandle, OBJECT_TYPE_EVENT,
					      (POBJECT *)&Locals.EventObject));
	assert(Locals.EventObject != NULL);
    }

    /* Queue an IRP to the target driver object. */
    ULONG DataSize = FileName ? strlen(FileName) + 1 : 0;
    Locals.Irp = ExAllocatePoolWithTag(sizeof(IO_REQUEST_PARAMETERS) + DataSize*2,
				       NTOS_IO_TAG);
    Locals.Irp->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    Locals.Irp->MinorFunction = IRP_MN_QUERY_DIRECTORY;
    Locals.Irp->Device.Object = Locals.FileObject->DeviceObject;
    Locals.Irp->File.Object = Locals.FileObject;
    Locals.Irp->OutputBuffer = (MWORD)FileInfoBuffer;
    Locals.Irp->OutputBufferLength = Length;
    Locals.Irp->QueryDirectory.FileInformationClass = FileInformationClass;
    Locals.Irp->QueryDirectory.FileIndex = 0;
    Locals.Irp->QueryDirectory.ReturnSingleEntry = ReturnSingleEntry;
    Locals.Irp->QueryDirectory.RestartScan = RestartScan;
    if (FileName) {
	memcpy(Locals.Irp->QueryDirectory.FileName, FileName, DataSize);
    }
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, Locals.Irp, &Locals.PendingIrp));

    /* For now every IO is synchronous. */
    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Locals.IoStatus = Locals.PendingIrp->IoResponseStatus;
    Status = STATUS_SUCCESS;

out:
    if (!NT_SUCCESS(Status)) {
	Locals.IoStatus.Status = Status;
    } else {
	Status = Locals.IoStatus.Status;
    }
    if (IoStatusBlock != NULL) {
	*IoStatusBlock = Locals.IoStatus;
    }
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.EventObject) {
	ObDereferenceObject(Locals.EventObject);
    }
    if (Locals.Irp) {
	IopFreePool(Locals.Irp);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }

    ASYNC_END(State, Status);
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
                              IN ULONG Length,
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

NTSTATUS NtQueryVolumeInformationFile(IN ASYNC_STATE State,
                                      IN PTHREAD Thread,
                                      IN HANDLE FileHandle,
                                      OUT IO_STATUS_BLOCK *IoStatusBlock,
                                      IN PVOID FsInfoBuffer,
                                      IN ULONG Length,
                                      IN FS_INFORMATION_CLASS FsInformationClass)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PPENDING_IRP PendingIrp;
	    IO_STATUS_BLOCK IoStatus;
	});

    switch (FsInformationClass) {
        CHECK_LENGTH(Length, FileFsVolumeInformation, FILE_FS_VOLUME_INFORMATION);
        CHECK_LENGTH(Length, FileFsSizeInformation, FILE_FS_SIZE_INFORMATION);
	CHECK_LENGTH(Length, FileFsDeviceInformation, FILE_FS_DEVICE_INFORMATION);
	CHECK_LENGTH(Length, FileFsAttributeInformation, FILE_FS_ATTRIBUTE_INFORMATION);
	CHECK_LENGTH(Length, FileFsControlInformation, FILE_FS_CONTROL_INFORMATION);
	CHECK_LENGTH(Length, FileFsFullSizeInformation, FILE_FS_FULL_SIZE_INFORMATION);
	CHECK_LENGTH(Length, FileFsObjectIdInformation, FILE_FS_OBJECTID_INFORMATION);
	CHECK_LENGTH(Length, FileFsDriverPathInformation, FILE_FS_DRIVER_PATH_INFORMATION);
    default:
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }

    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    /* Deviceless files cannot be queried. */
    if (!Locals.FileObject->DeviceObject) {
	Status = STATUS_NOT_IMPLEMENTED;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);

    PIO_DEVICE_INFO DevInfo = &Locals.FileObject->DeviceObject->DeviceInfo;
    /* Quick path for FileFsDeviceInformation. The NT executive has enough info
     * to reply to the client without asking the file system driver, except for
     * network file systems. */
    if (FsInformationClass == FileFsDeviceInformation &&
	DevInfo->DeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM) {
	/* TODO: Eventually we will schedule an IO APC to deliver the results
	 * to the client side in order to avoid doing a syscall. For now we
	 * will just map the user buffer to NT Executive address space. */
	PFILE_FS_DEVICE_INFORMATION FsDeviceInfo = NULL;
	IF_ERR_GOTO(out, Status, MmMapUserBuffer(&Thread->Process->VSpace,
						 (MWORD)FsInfoBuffer, Length,
						 (PVOID *)&FsDeviceInfo));
	FsDeviceInfo->DeviceType = DevInfo->DeviceType;
	FsDeviceInfo->Characteristics = DevInfo->Flags;
	/* Complete characteristcs with mount status if relevant */
	if (IopIsVolumeMounted(Locals.FileObject->DeviceObject)) {
	    FsDeviceInfo->Characteristics |= FILE_DEVICE_IS_MOUNTED;
	}
	Locals.IoStatus.Information = sizeof(FILE_FS_DEVICE_INFORMATION);
	Locals.IoStatus.Status = STATUS_SUCCESS;
	MmUnmapUserBuffer(FsDeviceInfo);
	goto out;
    } else if (FsInformationClass == FileFsDriverPathInformation) {
	/* The FsInfoBuffer for FileFsDriverPathInformation is in fact both an
	 * IN buffer and an OUT buffer. This doesn't appear to be used anywhere
	 * in the ReactOS code base so we won't bother supporting it. */
        Status = STATUS_NOT_IMPLEMENTED;
	goto out;
    }

    /* Queue an IRP to the target driver object. */
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = Locals.FileObject,
	.MajorFunction = IRP_MJ_QUERY_VOLUME_INFORMATION,
	.OutputBuffer = (MWORD)FsInfoBuffer,
	.OutputBufferLength = Length,
	.QueryVolume.FsInformationClass = FsInformationClass
    };
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Locals.IoStatus = Locals.PendingIrp->IoResponseStatus;
    Status = STATUS_SUCCESS;

out:
    if (!NT_SUCCESS(Status)) {
	Locals.IoStatus.Status = Status;
    } else {
	Status = Locals.IoStatus.Status;
    }
    if (IoStatusBlock != NULL) {
	*IoStatusBlock = Locals.IoStatus;
    }
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }

    ASYNC_END(State, Status);
}

NTSTATUS NtQueryInformationFile(IN ASYNC_STATE AsyncState,
                                IN PTHREAD Thread,
                                IN HANDLE FileHandle,
                                OUT IO_STATUS_BLOCK *IoStatusBlock,
                                OUT PVOID FileInfoBuffer,
                                IN ULONG Length,
                                IN FILE_INFORMATION_CLASS FileInformationClass)
{
    UNIMPLEMENTED;
}

NTSTATUS NtFlushBuffersFile(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
			    IN HANDLE FileHandle,
			    OUT IO_STATUS_BLOCK *IoStatusBlock)
{
    assert(Thread);
    assert(Thread->Process);
    assert(IoStatusBlock);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PPENDING_IRP PendingIrp;
	});

    if (FileHandle == NULL) {
	ASYNC_RETURN(State, STATUS_INVALID_HANDLE);
    }
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject);

    if (!Locals.FileObject->DeviceObject) {
	/* Purely in-memory file objects do not require flushing. Return success. */
	if (IoStatusBlock) {
	    IoStatusBlock->Status = STATUS_SUCCESS;
	    IoStatusBlock->Information = 0;
	}
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }

    assert(Locals.FileObject->DeviceObject->DriverObject);
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = Locals.FileObject,
	.MajorFunction = IRP_MJ_FLUSH_BUFFERS
    };
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);

    if (IoStatusBlock != NULL) {
	*IoStatusBlock = Locals.PendingIrp->IoResponseStatus;
    }
    Status = Locals.PendingIrp->IoResponseStatus.Status;

out:
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(State, Status);
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
	DbgPrint("    FileSize = 0x%llx\n", File->Fcb->FileSize);
	DbgPrint("    SharedCacheMap = %p\n", File->Fcb->SharedCacheMap);
	DbgPrint("    ImageSectionObject = %p\n", File->Fcb->ImageSectionObject);
	DbgPrint("    DataSectionObject = %p\n", File->Fcb->DataSectionObject);
    }
#endif
}
