#include "iop.h"

NTSTATUS IopCreateFcb(OUT PIO_FILE_CONTROL_BLOCK *pFcb,
		      IN ULONG64 FileSize,
		      IN PCSTR FileName,
		      IN PIO_VOLUME_CONTROL_BLOCK Vcb,
		      IN ULONG FileAttributes)
{
    IopAllocatePool(Fcb, IO_FILE_CONTROL_BLOCK);
    if (FileName) {
	Fcb->FileName = RtlDuplicateString(FileName, NTOS_IO_TAG);
	if (!Fcb->FileName) {
	    IopFreePool(Fcb);
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
    }
    Fcb->FileSize = FileSize;
    Fcb->Vcb = Vcb;
    Fcb->IsDirectory = FileAttributes & FILE_ATTRIBUTE_DIRECTORY;
    AvlInitializeTree(&Fcb->FileRegionMappings);
    InitializeListHead(&Fcb->PrivateCacheMaps);
    InitializeListHead(&Fcb->SlaveList);
    KeInitializeEvent(&Fcb->OpenCompleted, NotificationEvent);
    KeInitializeEvent(&Fcb->WriteCompleted, NotificationEvent);
    if (!Fcb->IsDirectory) {
	RET_ERR_EX(CcInitializeCacheMap(Fcb, NULL, NULL),
		   IopDeleteFcb(Fcb));
    }
    *pFcb = Fcb;
    return STATUS_SUCCESS;
}

VOID IopDeleteFcb(IN PIO_FILE_CONTROL_BLOCK Fcb)
{
    LoopOverList(Slave, &Fcb->SlaveList, IO_FILE_OBJECT, SlaveLink) {
	Slave->Fcb = NULL;
	RemoveEntryList(&Slave->SlaveLink);
    }
    if (Fcb->MasterFileObject) {
	assert(Fcb->MasterFileObject->Fcb == Fcb);
	Fcb->MasterFileObject->Fcb = NULL;
    }
    if (Fcb->Vcb && Fcb->Vcb->VolumeFcb == Fcb) {
	Fcb->Vcb->VolumeFcb = NULL;
    }
    if (Fcb->ImageSectionObject) {
	assert(Fcb == Fcb->ImageSectionObject->Fcb);
	Fcb->ImageSectionObject->Fcb = NULL;
    }
    if (Fcb->DataSectionObject) {
	assert(Fcb == Fcb->DataSectionObject->Fcb);
	Fcb->DataSectionObject->Fcb = NULL;
    }
    if (Fcb->FileName) {
	IopFreePool(Fcb->FileName);
    }
    CcUninitializeCacheMap(Fcb);
    KeUninitializeEvent(&Fcb->OpenCompleted);
    KeUninitializeEvent(&Fcb->WriteCompleted);
    IopFreePool(Fcb);
}

FORCEINLINE BOOLEAN ReadAccessDesired(IN ACCESS_MASK DesiredAccess)
{
    return DesiredAccess & (FILE_READ_DATA | FILE_EXECUTE);
}

FORCEINLINE BOOLEAN WriteAccessDesired(IN ACCESS_MASK DesiredAccess)
{
    return DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA);
}

FORCEINLINE BOOLEAN DeleteAccessDesired(IN ACCESS_MASK DesiredAccess)
{
    return DesiredAccess & DELETE;
}

NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx)
{
    assert(CreaCtx);
    PIO_FILE_OBJECT File = (PIO_FILE_OBJECT)Object;
    PFILE_OBJ_CREATE_CONTEXT Ctx = (PFILE_OBJ_CREATE_CONTEXT)CreaCtx;
    PIO_PACKET CloseMsg = NULL;

    if (Ctx->MasterFileObject) {
	assert(!Ctx->DeviceObject);
	assert(!Ctx->FileName);
	assert(!Ctx->FileSize);
	assert(!Ctx->Fcb);
	assert(!Ctx->Vcb);
    }
    if (Ctx->DeviceObject || Ctx->AllocateCloseMsg) {
	CloseMsg = ExAllocatePoolWithTag(sizeof(IO_PACKET), NTOS_IO_TAG);
	if (!CloseMsg) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
    }

    /* If the FileName is not NULL but points to an empty string, we
     * must be opening a non-file-system device object or the volume
     * file object, in which case we do not allocate an FCB. */
    if ((Ctx->FileName && *Ctx->FileName == '\0') || Ctx->NoFcb) {
	File->Fcb = NULL;
    } else if (!Ctx->MasterFileObject) {
	PIO_FILE_CONTROL_BLOCK Fcb = NULL;
	RET_ERR_EX(IopCreateFcb(&Fcb, Ctx->FileSize, Ctx->FileName, Ctx->Vcb,
				Ctx->FileAttributes),
		   if (CloseMsg) {
		       IopFreePool(CloseMsg);
		   });
	assert(Fcb);
	File->Fcb = Fcb;
	Fcb->MasterFileObject = File;
	Fcb->OpenInProgress = !!Ctx->Vcb;
    }

    File->CloseMsg = CloseMsg;
    File->DeviceObject = Ctx->DeviceObject;
    if (Ctx->MasterFileObject) {
	ObpReferenceObject(Ctx->MasterFileObject);
	assert(Ctx->MasterFileObject->Fcb);
	assert(Ctx->MasterFileObject->Fcb->MasterFileObject == Ctx->MasterFileObject);
	File->Fcb = Ctx->MasterFileObject->Fcb;
	File->DeviceObject = Ctx->MasterFileObject->DeviceObject;
    }
    if (File->DeviceObject) {
	ObpReferenceObject(File->DeviceObject);
    }
    File->ReadAccess = ReadAccessDesired(Ctx->DesiredAccess);
    File->WriteAccess = WriteAccessDesired(Ctx->DesiredAccess);
    File->DeleteAccess = DeleteAccessDesired(Ctx->DesiredAccess);
    File->SharedRead = Ctx->ShareAccess & FILE_SHARE_READ;
    File->SharedWrite = Ctx->ShareAccess & FILE_SHARE_WRITE;
    File->SharedDelete = Ctx->ShareAccess & FILE_SHARE_DELETE;
    File->DirectIo = Ctx->DirectIo;
    if (File->DeviceObject) {
	InsertTailList(&File->DeviceObject->OpenFileList, &File->DeviceLink);
    }

    return STATUS_SUCCESS;
}

/*
 * Create a "master" file object for a device object being opened.
 * File object created will have all IO access rights granted.
 */
NTSTATUS IopCreateMasterFileObject(IN PCSTR FileName,
				   IN PIO_DEVICE_OBJECT DeviceObject,
				   IN ULONG FileAttributes,
				   IN ACCESS_MASK DesiredAccess,
				   IN ULONG ShareAccess,
				   IN BOOLEAN DirectIo,
				   OUT PIO_FILE_OBJECT *pFile)
{
    assert(FileName);
    assert(DeviceObject);
    assert(pFile);
    PIO_FILE_OBJECT File = NULL;
    FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	.DeviceObject = DeviceObject,
	.FileName = FileName,
	.Vcb = DeviceObject->Vcb,
	.FileAttributes = FileAttributes,
	.DesiredAccess = DesiredAccess,
	.ShareAccess = ShareAccess,
	.DirectIo = DirectIo
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *)&File, &CreaCtx));
    assert(File != NULL);
    *pFile = File;
    return STATUS_SUCCESS;
}

NTSTATUS IopFileObjectParseProc(IN POBJECT Self,
				IN PCSTR Path,
				IN BOOLEAN CaseInsensitive,
				OUT POBJECT *FoundObject,
				OUT PCSTR *RemainingPath)
{
    DbgTrace("Parsing file obj %p path %s\n", Self, Path);
    PIO_FILE_OBJECT FileObj = Self;
    IoDbgDumpFileObject(FileObj, 0);
    *RemainingPath = Path;
    /* File objects don't have sub-objects. */
    *FoundObject = *Path ? NULL : Self;
    return *Path ? STATUS_OBJECT_PATH_NOT_FOUND : STATUS_NTOS_STOP_PARSING;
}

FORCEINLINE BOOLEAN DispositionIsOverwrite(IN ULONG Disposition)
{
    return Disposition == FILE_SUPERSEDE || Disposition == FILE_OVERWRITE ||
	Disposition == FILE_OVERWRITE_IF;
}

NTSTATUS IopFileObjectOpenProc(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN POBJECT Self,
			       IN PCSTR SubPath,
			       IN ACCESS_MASK DesiredAccess,
			       IN ULONG Attributes,
			       IN POB_OPEN_CONTEXT Context,
			       OUT POBJECT *pOpenedInstance,
			       OUT PCSTR *pRemainingPath)
{
    assert(Thread != NULL);
    assert(Self != NULL);
    assert(SubPath != NULL);
    assert(pOpenedInstance != NULL);

    NTSTATUS Status = STATUS_NTOS_BUG;
    PIO_FILE_OBJECT FileObject = Self;
    PIO_FILE_OBJECT OpenedFile = NULL;
    PIO_OPEN_CONTEXT OpenContext = (PIO_OPEN_CONTEXT)Context;
    POPEN_PACKET OpenPacket = &OpenContext->OpenPacket;
    ASYNC_BEGIN(State, Locals, {
	    BOOLEAN CallDriver;
	});

    /* Reject the open if the open context is not IO_OPEN_CONTEXT. */
    if (Context->Type != OPEN_CONTEXT_DEVICE_OPEN) {
	Status = STATUS_OBJECT_TYPE_MISMATCH;
	goto out;
    }

    DbgTrace("Opening file obj %p path %s\n", Self, SubPath);
    IoDbgDumpFileObject(FileObject, 0);

    /* Non-volume file objects do not support sub-objects. */
    if (!FileObject->Fcb) {
	assert(FALSE);
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto out;
    }

    /* If there is an existing file open request, wait for it to finish. */
    AWAIT_IF(FileObject->Fcb->Vcb && FileObject->Fcb->OpenInProgress,
	     KeWaitForSingleObject, State, Locals, Thread,
	     &FileObject->Fcb->OpenCompleted.Header, FALSE, NULL);

    /* TODO: We need to handle related open which is used by NTFS to
     * support multiple data streams of the same file. */
    if (SubPath[0]) {
	Status = STATUS_NOT_IMPLEMENTED;
	goto out;
    }

    /* If the user requested to create a new file, deny it. */
    if (OpenContext->OpenPacket.Disposition == FILE_CREATE) {
	Status = STATUS_OBJECT_NAME_COLLISION;
	goto out;
    }
    /* If the master file object was opened without read access and the
     * caller requested READ, deny the open. Likewise for WRITE and DELETE. */
    if ((!FileObject->SharedRead && ReadAccessDesired(DesiredAccess)) ||
	(!FileObject->SharedWrite && WriteAccessDesired(DesiredAccess)) ||
	(!FileObject->SharedDelete && DeleteAccessDesired(DesiredAccess))) {
	Status = STATUS_ACCESS_DENIED;
	goto out;
    }

    /* If the desired access is greater than that of the master file object,
     * or we are requesting to delete the file (this include overwrite, supersede,
     * and rename), call the driver to create a new client-side handle. Otherwise,
     * simply create a slave file object which does not have a client-side handle. */
    BOOLEAN CallDriver = DispositionIsOverwrite(OpenPacket->Disposition)||
	(!FileObject->ReadAccess && ReadAccessDesired(DesiredAccess)) ||
	(!FileObject->WriteAccess && DeleteAccessDesired(DesiredAccess)) ||
	(!FileObject->DeleteAccess && DeleteAccessDesired(DesiredAccess)) ||
	(OpenPacket->CreateOptions & FILE_DELETE_ON_CLOSE) ||
	OpenPacket->OpenTargetDirectory;

    if (!CallDriver || !FileObject->DeviceObject) {
	FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	    .MasterFileObject = FileObject,
	    .DirectIo = OpenPacket->CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING
	};
	IF_ERR_GOTO(out, Status,
		    ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *)&OpenedFile, &CreaCtx));
	InsertTailList(&FileObject->Fcb->SlaveList, &OpenedFile->SlaveLink);
	if (OpenPacket->CreateOptions & (FILE_SYNCHRONOUS_IO_ALERT |
					 FILE_SYNCHRONOUS_IO_NONALERT)) {
	    OpenedFile->Flags |= FO_SYNCHRONOUS_IO;
	    if (OpenPacket->CreateOptions & FILE_SYNCHRONOUS_IO_ALERT) {
		OpenedFile->Flags |= FO_ALERTABLE_IO;
	    }
	}
	if (Attributes & OBJ_CASE_INSENSITIVE) {
	    OpenedFile->Flags |= FO_OPENED_CASE_SENSITIVE;
	}
	Status = STATUS_SUCCESS;
	goto out;
    }

    AWAIT_EX(Status, IopOpenDevice, State, Locals, Thread, FileObject->DeviceObject,
	     FileObject, FileObject->Fcb->FileName, DesiredAccess, Attributes,
	     OpenContext, &OpenedFile);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* For overwrite or supersede we should also invalidate the caches. */
    if (DispositionIsOverwrite(OpenPacket->Disposition)) {
	/* TODO! */
	assert(FALSE);
	Status = STATUS_NOT_IMPLEMENTED;
    }

out:
    if (NT_SUCCESS(Status)) {
	*pOpenedInstance = OpenedFile;
	*pRemainingPath = SubPath + strlen(SubPath);
	Status = STATUS_SUCCESS;
    } else {
	*pOpenedInstance = NULL;
	*pRemainingPath = SubPath;
    }
    ASYNC_END(State, Status);
}

NTSTATUS IopFileObjectCloseProc(IN ASYNC_STATE State,
				IN PTHREAD Thread,
				IN POBJECT Self)
{
    assert(Thread != NULL);
    assert(Self != NULL);

    NTSTATUS Status = STATUS_NTOS_BUG;
    PIO_FILE_OBJECT FileObj = Self;
    ASYNC_BEGIN(State, Locals, {
	    PPENDING_IRP PendingIrp;
	});

    DbgTrace("Closing file %p\n", FileObj);
    IoDbgDumpFileObject(FileObj, 0);

    if (FileObj->Fcb && FileObj == FileObj->Fcb->MasterFileObject) {
	/* If we are a master file object, count the number of our slave file objects.
	 * If it's not zero, delay the CLEANUP IRP till all slave files are closed. */
	if (!IsListEmpty(&FileObj->Fcb->SlaveList)) {
	    FileObj->Fcb->MasterClosed = TRUE;
	    ASYNC_RETURN(State, STATUS_SUCCESS);
	}
	if (FileObj->Fcb->Vcb) {
	    /* If we are closing the volume file, delay the close until the volume is
	     * dismounted. */
	    if (FileObj == FileObj->Fcb->Vcb->VolumeFile && !FileObj->Fcb->Vcb->Dismounted) {
		FileObj->Fcb->MasterClosed = TRUE;
		ASYNC_RETURN(State, STATUS_SUCCESS);
	    }
	    /* Remove the file from the cached subobject directory, so any CREATE request
	     * for the same file from this point on will insert a new file object into the
	     * cached subobject directory. */
	    ObRemoveObject(Self);
	}
    }

    /* If the file does not have a client-side handle, check whether the master file
     * object has been closed and there are no more slave file objects. If true, send
     * a CLEANUP IRP to the file system driver. Otherwise, we do nothing. */
    PIO_FILE_OBJECT TargetFileObject = FileObj;
    if (!FileObj->CloseMsg) {
	if (!FileObj->Fcb) {
	    ASYNC_RETURN(State, STATUS_SUCCESS);
	}
	assert(ListHasEntry(&FileObj->Fcb->SlaveList, &FileObj->SlaveLink));
	RemoveEntryList(&FileObj->SlaveLink);
	if (!FileObj->DeviceObject || !FileObj->Fcb->MasterClosed ||
	    !IsListEmpty(&FileObj->Fcb->SlaveList)) {
	    ASYNC_RETURN(State, STATUS_SUCCESS);
	}
	/* For the volume file, only send the CLEANUP IRP when dismounting. */
	if (FileObj->Fcb->Vcb && FileObj->Fcb == FileObj->Fcb->Vcb->VolumeFcb
	    && !FileObj->Fcb->Vcb->Dismounted) {
	    ASYNC_RETURN(State, STATUS_SUCCESS);
	}
	TargetFileObject = FileObj->Fcb->MasterFileObject;
    } else if (FileObj->Zombie) {
	/* If the file is in a zombie state (ie. its device object was forcibly
	 * removed due to for instance a driver crash), simply return. */
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }
    /* File with a client-side handle must have a device object. */
    assert(FileObj->DeviceObject);
    /* If the file has a client-side handle, send the driver a IRP_MJ_CLEANUP
     * for the needed cleanup. */
    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_CLEANUP,
	.Device.Object = FileObj->DeviceObject,
	.File.Object = TargetFileObject,
    };
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));
    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    IopCleanupPendingIrp(Locals.PendingIrp);

    /* For files with caching initialized, flush dirty data to disk. */
    if (!FileObj->Fcb || !FileObj->Fcb->SharedCacheMap) {
	Status = STATUS_SUCCESS;
	goto out;
    }
    CiFlushPrivateCacheToShared(FileObj->Fcb);
    if (FileObj->Fcb->Vcb && FileObj->Fcb != FileObj->Fcb->Vcb->VolumeFcb) {
	CiFlushDirtyDataToVolume(FileObj->Fcb);
    }

out:
    ASYNC_END(State, Status);
}

VOID IopFileObjectDeleteProc(IN POBJECT Self)
{
    PIO_FILE_OBJECT FileObj = Self;
    DbgTrace("Releasing file object %p from memory\n", FileObj);
    IoDbgDumpFileObject(FileObj, 0);
    /* For file objects that have a client-side object, we queue an
     * IRP_MJ_CLOSE request to its driver object. This request is
     * sent in a server message which does not expect a reply. */
    if (FileObj->CloseMsg) {
	if (FileObj->Zombie) {
	    /* In the case of a zombie file, we simply free the close message. */
	    IopFreePool(FileObj->CloseMsg);
	} else {
	    FileObj->CloseMsg->Type = IoPacketTypeServerMessage;
	    FileObj->CloseMsg->Size = sizeof(IO_PACKET);
	    FileObj->CloseMsg->ServerMsg.Type = IoSrvMsgCloseFile;
	    FileObj->CloseMsg->ServerMsg.CloseFile.FileObject =
		OBJECT_TO_GLOBAL_HANDLE(FileObj);
	    assert(FileObj->DeviceObject);
	    PIO_DRIVER_OBJECT Driver = FileObj->DeviceObject->DriverObject;
	    /* The IO packet will be deleted later after it is sent to the driver. */
	    InsertTailList(&Driver->IoPacketQueue, &FileObj->CloseMsg->IoPacketLink);
	    KeSetEvent(&Driver->IoPacketQueuedEvent);
	}
    }

    /* For files with caching initialized, flush dirty data to disk. */
    if (FileObj->Fcb && FileObj->Fcb->SharedCacheMap && !FileObj->Zombie) {
	CiFlushPrivateCacheToShared(FileObj->Fcb);
	if (FileObj->Fcb->Vcb && FileObj->Fcb != FileObj->Fcb->Vcb->VolumeFcb) {
	    CiFlushDirtyDataToVolume(FileObj->Fcb);
	}
    }
    if (FileObj->Fcb) {
	if (FileObj->Fcb->MasterFileObject == FileObj) {
	    IopDeleteFcb(FileObj->Fcb);
	} else if (FileObj->Fcb->MasterFileObject) {
	    ObDereferenceObject(FileObj->Fcb->MasterFileObject);
	}
    }
    if (FileObj->DeviceObject) {
	RemoveEntryList(&FileObj->DeviceLink);
	ObDereferenceObject(FileObj->DeviceObject);
    }
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
				IN OPTIONAL ULONG FileAttributes,
				OUT PIO_FILE_OBJECT *pFile)
{
    assert(pFile);
    PIO_FILE_OBJECT File = NULL;
    FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	.FileName = FileName,
	.FileSize = FileSize,
	.NoFcb = !FileSize,
	.FileAttributes = FileAttributes,
	.DesiredAccess = FILE_READ_ACCESS | FILE_WRITE_ACCESS,
	 /* We don't allow NT clients to open a deviceless file for delete. */
	.ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_FILE, (POBJECT *)&File, &CreaCtx));
    assert(File != NULL);
    NTSTATUS Status;
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

static NTSTATUS IopCreateFile(IN ASYNC_STATE State,
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
			      IN BOOLEAN OpenTargetDirectory)
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
    Locals.OpenContext.OpenPacket.OpenTargetDirectory = OpenTargetDirectory;
    if (AllocationSize) {
	Locals.OpenContext.OpenPacket.AllocationSize = AllocationSize->QuadPart;
    }

    AWAIT_EX(Status, ObOpenObjectByName, State, Locals,
	     Thread, ObjectAttributes, OBJECT_TYPE_FILE, DesiredAccess,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, FileHandle);
    if (IoStatusBlock != NULL) {
	IoStatusBlock->Status = Status;
	IoStatusBlock->Information = NT_SUCCESS(Status) ? Locals.OpenContext.Information : 0;
    }
    ASYNC_END(State, Status);
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
    return IopCreateFile(State, Thread, FileHandle, DesiredAccess, ObjectAttributes,
			 IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
			 CreateDisposition, CreateOptions, FALSE);
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
    return IopCreateFile(State, Thread, FileHandle, DesiredAccess, ObjectAttributes,
			 IoStatusBlock, NULL, 0, ShareAccess, FILE_OPEN, OpenOptions, FALSE);
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
    if (Context->FileObject->Flags & FO_SYNCHRONOUS_IO) {
	Context->FileObject->CurrentOffset = FileOffset + Length;
    }
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
    if (Locals.FileObject->Zombie) {
	Status = STATUS_FILE_FORCED_CLOSED;
	goto out;
    }
    if (!Locals.FileObject->DeviceObject && !Locals.FileObject->Fcb) {
	assert(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto out;
    }
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
    if (!Write && Locals.FileObject->Fcb) {
	if (Locals.FileOffset > Locals.FileObject->Fcb->FileSize) {
	    Status = STATUS_END_OF_FILE;
	    goto out;
	}
	BufferLength = min(BufferLength, Locals.FileObject->Fcb->FileSize - Locals.FileOffset);
	if (!BufferLength) {
	    Status = STATUS_SUCCESS;
	    goto out;
	}
    }

    /* If the target file is part of a mounted volume and we need to extend the file, make
     * sure there isn't a concurrent WRITE IRP in progress. If there is one, wait for it
     * to finish. */
    AWAIT_IF(Locals.FileObject->Fcb && Locals.FileObject->Fcb->WritePending &&
	     Locals.FileOffset + BufferLength > Locals.FileObject->Fcb->FileSize,
	     KeWaitForSingleObject, State, Locals, Thread,
	     &Locals.FileObject->Fcb->WriteCompleted.Header, FALSE, NULL);

    /* If the target file is part of a mounted volume, go through Cc to do the IO,
     * unless FILE_NO_INTERMEDIATE_BUFFERING was set when the file was opened. */
    if (Locals.FileObject->Fcb && !Locals.FileObject->DirectIo) {
	/* We don't let NT clients read or write to directory files. */
	if (Locals.FileObject->Fcb->IsDirectory) {
	    Status = STATUS_FILE_IS_A_DIRECTORY;
	    goto out;
	}
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
	/* Otherwise, queue an IRP to the target driver object. If the file object
	 * has a master file object, the IRP will be sent to the master file object. */
	PIO_FILE_OBJECT TargetFileObject = Locals.FileObject;
	PIO_FILE_CONTROL_BLOCK Fcb = TargetFileObject->Fcb;
	assert(!Fcb || Fcb->MasterFileObject);
	if (Fcb && Fcb->MasterFileObject) {
	    assert(Fcb->MasterFileObject->Fcb == Fcb);
	    TargetFileObject = Fcb->MasterFileObject;
	}
	assert(TargetFileObject->DeviceObject);
	IO_REQUEST_PARAMETERS Irp = {
	    .Device.Object = TargetFileObject->DeviceObject,
	    .File.Object = TargetFileObject,
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

static NTSTATUS IopDeviceIoControlFile(IN ASYNC_STATE State,
				       IN PTHREAD Thread,
				       IN HANDLE FileHandle,
				       IN HANDLE EventHandle,
				       IN PIO_APC_ROUTINE ApcRoutine,
				       IN PVOID ApcContext,
				       OUT IO_STATUS_BLOCK *IoStatusBlock,
				       IN ULONG ControlCode,
				       IN PVOID InputBuffer,
				       IN ULONG InputBufferLength,
				       IN PVOID OutputBuffer,
				       IN ULONG OutputBufferLength,
				       IN BOOLEAN FsControl)
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
    if (!Locals.FileObject->DeviceObject) {
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);

    if (EventHandle != NULL) {
	IF_ERR_GOTO(out, Status,
		    ObReferenceObjectByHandle(Thread, EventHandle, OBJECT_TYPE_EVENT,
					      (POBJECT *)&Locals.EventObject));
	assert(Locals.EventObject != NULL);
    }

    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
	.MajorFunction = FsControl ? IRP_MJ_FILE_SYSTEM_CONTROL : IRP_MJ_DEVICE_CONTROL,
	.MinorFunction = FsControl ? IRP_MN_USER_FS_REQUEST : 0,
	.InputBuffer = (MWORD)InputBuffer,
	.OutputBuffer = (MWORD)OutputBuffer,
	.InputBufferLength = InputBufferLength,
	.OutputBufferLength = OutputBufferLength,
	.DeviceIoControl.IoControlCode = ControlCode
    };
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
    if (FsControl && ControlCode == FSCTL_DISMOUNT_VOLUME && NT_SUCCESS(Status)) {
	assert(Locals.FileObject->DeviceObject);
	assert(Locals.FileObject->DeviceObject->Vcb);
	IopDismountVolume(Locals.FileObject->DeviceObject->Vcb, FALSE);
    }

out:
    /* Regardless of the outcome of the IO request, we should dereference the
     * file object and the event object because increased their refcount above. */
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.EventObject) {
	ObDereferenceObject(Locals.EventObject);
    }
    /* This will free the pending IRP and detach the pending irp from the
     * thread. At this point the IRP has already been detached from the driver
     * object, so we do not need to remove it from the driver IRP queue here. */
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtDeviceIoControlFile(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
                               IN HANDLE FileHandle,
                               IN HANDLE EventHandle,
                               IN PIO_APC_ROUTINE ApcRoutine,
                               IN PVOID ApcContext,
                               OUT IO_STATUS_BLOCK *IoStatusBlock,
                               IN ULONG Ioctl,
                               IN PVOID InputBuffer,
                               IN ULONG InputBufferLength,
                               IN PVOID OutputBuffer,
                               IN ULONG OutputBufferLength)
{
    return IopDeviceIoControlFile(State, Thread, FileHandle, EventHandle,
				  ApcRoutine, ApcContext, IoStatusBlock, Ioctl,
				  InputBuffer, InputBufferLength,
				  OutputBuffer, OutputBufferLength, FALSE);
}

NTSTATUS NtFsControlFile(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
			 IN HANDLE FileHandle,
			 IN HANDLE EventHandle,
			 IN PIO_APC_ROUTINE ApcRoutine,
			 IN PVOID ApcContext,
			 OUT IO_STATUS_BLOCK *IoStatusBlock,
			 IN ULONG Fsctl,
			 IN PVOID InputBuffer,
			 IN ULONG InputBufferLength,
			 IN PVOID OutputBuffer,
			 IN ULONG OutputBufferLength)
{
    return IopDeviceIoControlFile(State, Thread, FileHandle, EventHandle,
				  ApcRoutine, ApcContext, IoStatusBlock, Fsctl,
				  InputBuffer, InputBufferLength,
				  OutputBuffer, OutputBufferLength, TRUE);
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
	IoDbgDumpFileObject(Locals.FileObject, 0);
	Status = Locals.FileObject->Zombie ? STATUS_FILE_FORCED_CLOSED : STATUS_NOT_IMPLEMENTED;
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
    Locals.Irp->File.Object = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
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

NTSTATUS NtDeleteFile(IN ASYNC_STATE State,
                      IN PTHREAD Thread,
                      IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;
    HANDLE FileHandle = NULL;
    IO_STATUS_BLOCK IoStatus;

    ASYNC_BEGIN(State, Locals, {
	    HANDLE FileHandle;
	});

    /* Somewhat counter-intuitively, deleting a file involves opening a file
     * with the FILE_DELETE_ON_CLOSE option, which will invoke the file system
     * driver so it can mark the file as being delete. Once all open handles
     * to the file are closed, the file system driver deletes the file in the
     * IRP_MJ_CLEANUP dispatch function. */
    AWAIT_EX(Status, IopCreateFile, State, Locals, Thread, &FileHandle, DELETE,
	     ObjectAttributes, &IoStatus, NULL, 0, FILE_SHARE_DELETE,
	     FILE_OPEN, FILE_DELETE_ON_CLOSE, FALSE);
    Locals.FileHandle = FileHandle;
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(State, Status);
    }

    AWAIT(NtClose, State, Locals, Thread, Locals.FileHandle);
    ASYNC_END(State, STATUS_SUCCESS);
}

/* TODO: We need to cache basic file info since this is accessed frequently. */
NTSTATUS NtQueryAttributesFile(IN ASYNC_STATE State,
                               IN PTHREAD Thread,
                               IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
                               OUT FILE_BASIC_INFORMATION *FileInformation)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;
    HANDLE FileHandle = NULL;

    ASYNC_BEGIN(State, Locals, {
	    HANDLE FileHandle;
	    PIO_FILE_OBJECT FileObject;
	    IO_OPEN_CONTEXT OpenContext;
	    IO_STATUS_BLOCK IoStatus;
	    PPENDING_IRP PendingIrp;
	});

    Locals.OpenContext.Header.Type = OPEN_CONTEXT_DEVICE_OPEN;
    Locals.OpenContext.OpenPacket.CreateFileType = CreateFileTypeNone;
    Locals.OpenContext.OpenPacket.CreateOptions = FILE_OPEN_REPARSE_POINT;
    Locals.OpenContext.OpenPacket.FileAttributes = FILE_READ_ATTRIBUTES;
    Locals.OpenContext.OpenPacket.ShareAccess = FILE_SHARE_READ;
    Locals.OpenContext.OpenPacket.Disposition = FILE_OPEN;

    AWAIT_EX(Status, ObOpenObjectByName, State, Locals, Thread,
	     ObjectAttributes, OBJECT_TYPE_FILE, FILE_READ_ATTRIBUTES,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, &FileHandle);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.FileHandle = FileHandle;
    assert(Locals.FileHandle != NULL);
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (PVOID *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    if (Locals.FileObject->Zombie) {
	Status = STATUS_FILE_FORCED_CLOSED;
	goto out;
    }
    if (!Locals.FileObject->DeviceObject) {
	/* TODO! */
	assert(FALSE);
	Status = STATUS_NOT_IMPLEMENTED;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);

    /* Queue an IRP to the target driver object. */
    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    /* TODO: Embed the response in the IO response message. */
    assert((MWORD)FileInformation > Thread->IpcBufferServerAddr);
    assert((MWORD)FileInformation < Thread->IpcBufferServerAddr + PAGE_SIZE);
    MWORD TargetBuffer = (MWORD)FileInformation - Thread->IpcBufferServerAddr
	+ Thread->IpcBufferClientAddr;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
	.MajorFunction = IRP_MJ_QUERY_INFORMATION,
	.OutputBuffer = TargetBuffer,
	.OutputBufferLength = sizeof(FILE_BASIC_INFORMATION),
	.QueryFile.FileInformationClass = FileBasicInformation
    };
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Locals.IoStatus = Locals.PendingIrp->IoResponseStatus;
    Status = STATUS_SUCCESS;

out:
    if (!NT_SUCCESS(Status)) {
	Locals.IoStatus.Status = Status;
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    AWAIT_IF(Locals.FileHandle, NtClose, State, Locals, Thread, Locals.FileHandle);
    ASYNC_END(State, Locals.IoStatus.Status);
}

NTSTATUS NtQueryInformationFile(IN ASYNC_STATE State,
                                IN PTHREAD Thread,
                                IN HANDLE FileHandle,
                                OUT IO_STATUS_BLOCK *IoStatusBlock,
                                OUT PVOID FileInfoBuffer,
                                IN ULONG Length,
                                IN FILE_INFORMATION_CLASS FileInfoClass)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PPENDING_IRP PendingIrp;
	    IO_STATUS_BLOCK IoStatus;
	});

    switch (FileInfoClass) {
	CHECK_LENGTH(Length, FileBasicInformation, FILE_BASIC_INFORMATION);
	CHECK_LENGTH(Length, FileStandardInformation, FILE_STANDARD_INFORMATION);
	CHECK_LENGTH(Length, FileInternalInformation, FILE_INTERNAL_INFORMATION);
	CHECK_LENGTH(Length, FileEaInformation, FILE_EA_INFORMATION);
	CHECK_LENGTH(Length, FileAccessInformation, FILE_ACCESS_INFORMATION);
	CHECK_LENGTH(Length, FileNamesInformation, FILE_NAME_INFORMATION);
	CHECK_LENGTH(Length, FilePositionInformation, FILE_POSITION_INFORMATION);
	CHECK_LENGTH(Length, FileModeInformation, FILE_MODE_INFORMATION);
	CHECK_LENGTH(Length, FileAlignmentInformation, FILE_ALIGNMENT_INFORMATION);
	CHECK_LENGTH(Length, FileAllInformation, FILE_ALL_INFORMATION);
	CHECK_LENGTH(Length, FileNameInformation, FILE_NAME_INFORMATION);
	CHECK_LENGTH(Length, FileStreamInformation, FILE_STREAM_INFORMATION);
	CHECK_LENGTH(Length, FilePipeInformation, FILE_PIPE_INFORMATION);
	CHECK_LENGTH(Length, FilePipeLocalInformation, FILE_PIPE_LOCAL_INFORMATION);
	CHECK_LENGTH(Length, FilePipeRemoteInformation, FILE_PIPE_REMOTE_INFORMATION);
	CHECK_LENGTH(Length, FileMailslotQueryInformation, FILE_MAILSLOT_QUERY_INFORMATION);
	CHECK_LENGTH(Length, FileCompressionInformation, FILE_COMPRESSION_INFORMATION);
	CHECK_LENGTH(Length, FileObjectIdInformation, FILE_OBJECTID_INFORMATION);
	CHECK_LENGTH(Length, FileQuotaInformation, FILE_QUOTA_INFORMATION);
	CHECK_LENGTH(Length, FileReparsePointInformation, FILE_REPARSE_POINT_INFORMATION);
	CHECK_LENGTH(Length, FileNetworkOpenInformation, FILE_NETWORK_OPEN_INFORMATION);
	CHECK_LENGTH(Length, FileAttributeTagInformation, FILE_ATTRIBUTE_TAG_INFORMATION);
	CHECK_LENGTH(Length, FileIoCompletionNotificationInformation,
		     FILE_IO_COMPLETION_NOTIFICATION_INFORMATION);
	CHECK_LENGTH(Length, FileIoStatusBlockRangeInformation,
		     FILE_IOSTATUSBLOCK_RANGE_INFORMATION);
	CHECK_LENGTH(Length, FileIoPriorityHintInformation, FILE_IO_PRIORITY_HINT_INFORMATION);
	CHECK_LENGTH(Length, FileSfioReserveInformation, FILE_SFIO_RESERVE_INFORMATION);
	CHECK_LENGTH(Length, FileSfioVolumeInformation, FILE_SFIO_VOLUME_INFORMATION);
	CHECK_LENGTH(Length, FileProcessIdsUsingFileInformation,
		     FILE_PROCESS_IDS_USING_FILE_INFORMATION);
	CHECK_LENGTH(Length, FileNetworkPhysicalNameInformation,
		     FILE_NETWORK_PHYSICAL_NAME_INFORMATION);
    default:
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }

    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    if (Locals.FileObject->Zombie) {
	Status = STATUS_FILE_FORCED_CLOSED;
	goto out;
    }

    /* Quick path for FilePositionInformation. The NT executive has enough info
     * to reply to the client without asking the file system driver. */
    if (FileInfoClass == FilePositionInformation) {
	/* TODO: Eventually we will schedule an IO APC to deliver the results
	 * to the client side in order to avoid doing an seL4 syscall. For now we
	 * will just map the user buffer to NT Executive address space. */
	PFILE_POSITION_INFORMATION PosInfo = NULL;
	IF_ERR_GOTO(out, Status, MmMapUserBuffer(&Thread->Process->VSpace,
						 (MWORD)FileInfoBuffer, Length,
						 (PVOID *)&PosInfo));
	PosInfo->CurrentByteOffset.QuadPart = Locals.FileObject->CurrentOffset;
	Locals.IoStatus.Information = sizeof(FILE_POSITION_INFORMATION);
	Locals.IoStatus.Status = STATUS_SUCCESS;
	MmUnmapUserBuffer(PosInfo);
	goto out;
    } else {
	/* TODO: Handle FileAccessInformation and FileModeInformation, both of
	 * which can be handled purely on the server-side. */
    }
    /* TODO: We need to cache FileBasicInformation and FileStandardInformation
     * just like the fast IO path on Windows. */

    /* Deviceless files cannot be queried. */
    if (!Locals.FileObject->DeviceObject) {
	Status = STATUS_NOT_IMPLEMENTED;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);
    /* Queue an IRP to the target driver object. */
    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
	.MajorFunction = IRP_MJ_QUERY_INFORMATION,
	.OutputBuffer = (MWORD)FileInfoBuffer,
	.OutputBufferLength = Length,
	.QueryFile.FileInformationClass = FileInfoClass
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

static NTSTATUS IopOpenTargetDirectory(IN ASYNC_STATE State,
				       IN PTHREAD Thread,
				       IN PFILE_RENAME_INFORMATION RenameInfo,
				       IN PIO_FILE_OBJECT FileObject,
				       OUT PIO_FILE_OBJECT *TargetDirectory,
				       OUT HANDLE *TargetDirectoryHandle)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;
    IO_STATUS_BLOCK IoStatus;

    ASYNC_BEGIN(State, Locals, {
	    PCHAR FileName;
	    OB_OBJECT_ATTRIBUTES ObjAttr;
	});
    *TargetDirectory = NULL;
    *TargetDirectoryHandle = NULL;

    Locals.FileName = ExAllocatePoolWithTag(RenameInfo->FileNameLength, NTOS_IO_TAG);
    if (!Locals.FileName) {
	ASYNC_RETURN(State, STATUS_INSUFFICIENT_RESOURCES);
    }
    ULONG FileNameLength = 0;
    Status = RtlUnicodeToUTF8N(Locals.FileName, RenameInfo->FileNameLength - 1,
			       &FileNameLength, RenameInfo->FileName,
			       RenameInfo->FileNameLength);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.FileName[FileNameLength] = '\0';

    Locals.ObjAttr.Attributes = FileObject->Flags & FO_OPENED_CASE_SENSITIVE ?
	0 : OBJ_CASE_INSENSITIVE;
    Locals.ObjAttr.ObjectNameBuffer = Locals.FileName;
    Locals.ObjAttr.ObjectNameBufferLength = FileNameLength + 1;
    Locals.ObjAttr.RootDirectory = RenameInfo->RootDirectory;
    assert(FileObject->Fcb);
    AWAIT_EX(Status, IopCreateFile, State, Locals, Thread, TargetDirectoryHandle,
	     (FileObject->Fcb->IsDirectory ? FILE_ADD_SUBDIRECTORY : 0) | SYNCHRONIZE,
	     Locals.ObjAttr, &IoStatus, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
	     FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, TRUE);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    if (IoStatus.Information == FILE_EXISTS && !RenameInfo->ReplaceIfExists) {
	Status = STATUS_OBJECT_NAME_COLLISION;
	goto close;
    }

    Status = ObReferenceObjectByHandle(Thread, *TargetDirectoryHandle,
				       OBJECT_TYPE_FILE, (PVOID *)TargetDirectory);
    if (!NT_SUCCESS(Status)) {
	/* This should not happen. */
	assert(FALSE);
	goto close;
    }

    if ((*TargetDirectory)->DeviceObject != FileObject->DeviceObject) {
	Status = STATUS_NOT_SAME_DEVICE;
	goto close;
    }

    Status = STATUS_SUCCESS;
    goto out;

close:
    AWAIT(NtClose, State, Locals, Thread, *TargetDirectoryHandle);
    if (*TargetDirectory) {
	ObDereferenceObject(*TargetDirectory);
    }
    *TargetDirectoryHandle = NULL;
    *TargetDirectory = NULL;

out:
    if (Locals.FileName) {
	IopFreePool(Locals.FileName);
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtSetInformationFile(IN ASYNC_STATE State,
                              IN PTHREAD Thread,
                              IN HANDLE FileHandle,
                              OUT IO_STATUS_BLOCK *IoStatusBlock,
                              IN PVOID FileInfoBuffer,
                              IN ULONG Length,
                              IN FILE_INFORMATION_CLASS FileInfoClass)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;
    PIO_FILE_OBJECT TargetDirectory = NULL;
    HANDLE TargetDirectoryHandle = NULL;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PFILE_RENAME_INFORMATION RenameInfo;
	    PIO_FILE_OBJECT TargetDirectory;
	    HANDLE TargetDirectoryHandle;
	    PPENDING_IRP PendingIrp;
	    IO_STATUS_BLOCK IoStatus;
	});

    switch (FileInfoClass) {
	CHECK_LENGTH(Length, FileBasicInformation, FILE_BASIC_INFORMATION);
	CHECK_LENGTH(Length, FileRenameInformation, FILE_RENAME_INFORMATION);
	CHECK_LENGTH(Length, FileLinkInformation, FILE_LINK_INFORMATION);
	CHECK_LENGTH(Length, FileDispositionInformation, FILE_DISPOSITION_INFORMATION);
	CHECK_LENGTH(Length, FilePositionInformation, FILE_POSITION_INFORMATION);
	CHECK_LENGTH(Length, FileModeInformation, FILE_MODE_INFORMATION);
	CHECK_LENGTH(Length, FileAllocationInformation, FILE_ALLOCATION_INFORMATION);
	CHECK_LENGTH(Length, FileEndOfFileInformation, FILE_END_OF_FILE_INFORMATION);
	CHECK_LENGTH(Length, FilePipeInformation, FILE_PIPE_INFORMATION);
	CHECK_LENGTH(Length, FileMailslotSetInformation, FILE_MAILSLOT_SET_INFORMATION);
	CHECK_LENGTH(Length, FileObjectIdInformation, FILE_OBJECTID_INFORMATION);
	CHECK_LENGTH(Length, FileCompletionInformation, FILE_COMPLETION_INFORMATION);
	CHECK_LENGTH(Length, FileMoveClusterInformation, FILE_MOVE_CLUSTER_INFORMATION);
	CHECK_LENGTH(Length, FileQuotaInformation, FILE_QUOTA_INFORMATION);
	CHECK_LENGTH(Length, FileTrackingInformation, FILE_TRACKING_INFORMATION);
	CHECK_LENGTH(Length, FileValidDataLengthInformation, FILE_VALID_DATA_LENGTH_INFORMATION);
	CHECK_LENGTH(Length, FileShortNameInformation, UNICODE_STRING);
    default:
	    Status = STATUS_INVALID_PARAMETER;
	goto out;
    }

    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    if (Locals.FileObject->Zombie) {
	Status = STATUS_FILE_FORCED_CLOSED;
	goto out;
    }

    if (FileInfoClass == FilePositionInformation || FileInfoClass == FileRenameInformation ||
	FileInfoClass == FileLinkInformation || FileInfoClass == FileMoveClusterInformation) {
	PVOID Buffer = NULL;
	BOOLEAN Map = !KePtrInSvcMsgBuf((MWORD)FileInfoBuffer, Thread);
	if (Map) {
	    IF_ERR_GOTO(out, Status, MmMapUserBuffer(&Thread->Process->VSpace,
						     (MWORD)FileInfoBuffer, Length, &Buffer));
	} else {
	    Buffer = (PVOID)((MWORD)FileInfoBuffer - Thread->IpcBufferClientAddr +
			     Thread->IpcBufferServerAddr);
	}
	if (FileInfoClass == FilePositionInformation) {
	    PFILE_POSITION_INFORMATION PosInfo = Buffer;
	    Locals.FileObject->CurrentOffset = PosInfo->CurrentByteOffset.QuadPart;
	    Locals.IoStatus.Information = 0;
	    Locals.IoStatus.Status = STATUS_SUCCESS;
	} else if (Locals.FileObject->Fcb) {
	    Locals.RenameInfo = Buffer;
	    /* AWAIT must be in the outermost scope, so we jump to a outermost scope
	     * to open the target directory. */
	    goto open_target;
	target_opened:
	    if (!NT_SUCCESS(Status)) {
#ifdef CONFIG_DEBUG_BUILD
		UNICODE_STRING Path = {
		    .Buffer = Locals.RenameInfo->FileName,
		    .Length = Locals.RenameInfo->FileNameLength,
		    .MaximumLength = Locals.RenameInfo->FileNameLength
		};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"
		DbgTrace("Opening target directory failed. Path = %wZ\n", &Path);
#pragma GCC diagnostic pop
#endif
	    }
	} else {
	    /* File objects from non-file system drivers cannot be renamed. */
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	}
	if (Map) {
	    MmUnmapUserBuffer(Buffer);
	}
	/* For FilePositionInformation, we don't need to call the file system driver. */
	if (FileInfoClass == FilePositionInformation || !NT_SUCCESS(Status)) {
	    goto out;
	}
    }
    goto call_driver;

open_target:
    AWAIT_EX(Status, IopOpenTargetDirectory, State, Locals, Thread, Locals.RenameInfo,
	     Locals.FileObject, &TargetDirectory, &TargetDirectoryHandle);
    Locals.TargetDirectory = TargetDirectory;
    Locals.TargetDirectoryHandle = TargetDirectoryHandle;
    goto target_opened;

call_driver:
    /* Deviceless files only support setting FilePositionInformation. */
    if (!Locals.FileObject->DeviceObject) {
	Status = STATUS_NOT_SUPPORTED;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);

    /* Queue an IRP to the target driver object. */
    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
	.MajorFunction = IRP_MJ_SET_INFORMATION,
	.InputBuffer = (MWORD)FileInfoBuffer,
	.InputBufferLength = Length,
    };
    if (FileInfoClass == FileRenameInformation || FileInfoClass == FileLinkInformation ||
	FileInfoClass == FileMoveClusterInformation) {
	Irp.SetFile.FileInformationClass = FileInfoClass;
	Irp.SetFile.TargetDirectory = OBJECT_TO_GLOBAL_HANDLE(Locals.TargetDirectory);
    }
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, &Irp, &Locals.PendingIrp));

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Locals.IoStatus = Locals.PendingIrp->IoResponseStatus;
    Status = STATUS_SUCCESS;

    if (!Locals.TargetDirectoryHandle) {
	goto out;
    }
    AWAIT(NtClose, State, Locals, Thread, Locals.TargetDirectoryHandle);
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
    if (Locals.TargetDirectory) {
	ObDereferenceObject(Locals.TargetDirectory);
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }

    ASYNC_END(State, Status);
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
    if (Locals.FileObject->Zombie) {
	Status = STATUS_FILE_FORCED_CLOSED;
	goto out;
    }
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
    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
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
    if (Locals.FileObject->Zombie) {
	Status = STATUS_FILE_FORCED_CLOSED;
	goto out;
    }

    if (!Locals.FileObject->DeviceObject) {
	/* Purely in-memory file objects do not require flushing. Return success. */
	if (IoStatusBlock) {
	    IoStatusBlock->Status = STATUS_SUCCESS;
	    IoStatusBlock->Information = 0;
	}
	Status = STATUS_SUCCESS;
	goto out;
    }

    assert(Locals.FileObject->DeviceObject->DriverObject);
    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
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

VOID IoDbgDumpFileObject(IN PIO_FILE_OBJECT File,
			 IN ULONG Indentation)
{
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Dumping file object %p\n", File);
    if (File == NULL) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("  (nil)\n");
	return;
    }
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  RefCount = %lld\n", OBJECT_TO_OBJECT_HEADER(File)->RefCount);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  DeviceObject = %p%s\n", File->DeviceObject,
	     File->Zombie ? "  ZOMBIE!" : "");
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  Read %d Write %d Delete %d  SharedRead %d ShareWrite %d ShareDelete %d\n",
	     File->ReadAccess, File->WriteAccess, File->DeleteAccess,
	     File->SharedRead, File->SharedWrite, File->SharedDelete);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  DirectIo = %d\n", File->DirectIo);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  CurrentOffset = 0x%llx\n", File->CurrentOffset);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  CloseMsg = %p\n", File->CloseMsg);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  Fcb = %p\n", File->Fcb);
    if (File->Fcb) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    FileName = %s\n", File->Fcb->FileName);
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    FileSize = 0x%llx\n", File->Fcb->FileSize);
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    MasterFileObject = %p\n", File->Fcb->MasterFileObject);
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    SlaveFileCount = %zd\n", (MWORD)GetListLength(&File->Fcb->SlaveList));
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    MasterClosed = %d\n", File->Fcb->MasterClosed);
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    OpenInProgress = %d\n", File->Fcb->OpenInProgress);
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    SharedCacheMap = %p\n", File->Fcb->SharedCacheMap);
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    DataSectionObject = %p\n", File->Fcb->DataSectionObject);
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("    ImageSectionObject = %p\n", File->Fcb->ImageSectionObject);
	if (File->Fcb->ImageSectionObject) {
	    RtlDbgPrintIndentation(Indentation);
	    DbgPrint("      ImageCacheFile = %p\n",
		     File->Fcb->ImageSectionObject->ImageCacheFile);
	    IoDbgDumpFileObject(File->Fcb->ImageSectionObject->ImageCacheFile,
				Indentation + 2);
	}
    }
    ObDbgDumpObjectHandles(File, Indentation + 2);
}
