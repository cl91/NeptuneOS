#include "ex.h"
#include "io.h"
#include "iop.h"
#include "ke.h"
#include "mm.h"
#include "ntdef.h"
#include "ntioapi.h"
#include "ntrtl.h"
#include "ntstatus.h"
#include "ob.h"
#include "util.h"

NTSTATUS IopCreateFcb(OUT PIO_FILE_CONTROL_BLOCK *pFcb,
		      IN ULONG64 FileSize,
		      IN PIO_VOLUME_CONTROL_BLOCK Vcb,
		      IN BOOLEAN CreateDirectory)
{
    IopAllocatePool(Fcb, IO_FILE_CONTROL_BLOCK);
    Fcb->FileSize = FileSize;
    Fcb->Vcb = Vcb;
    AvlInitializeTree(&Fcb->FileOffsetMappings);
    InitializeListHead(&Fcb->PrivateCacheMaps);
    KeInitializeEvent(&Fcb->OpenCompleted, NotificationEvent);
    KeInitializeEvent(&Fcb->WriteCompleted, NotificationEvent);
    if (CreateDirectory) {
	RET_ERR_EX(ObCreateObject(OBJECT_TYPE_DIRECTORY,
				  (POBJECT *)&Fcb->Subobjects, NULL),
		   IopDeleteFcb(Fcb));
    }
    RET_ERR_EX(CcInitializeCacheMap(Fcb, NULL, NULL),
	       IopDeleteFcb(Fcb));
    *pFcb = Fcb;
    return STATUS_SUCCESS;
}

VOID IopDeleteFcb(IN PIO_FILE_CONTROL_BLOCK Fcb)
{
    CcUninitializeCacheMap(Fcb);
    if (Fcb->Subobjects) {
	ObDereferenceObject(Fcb->Subobjects);
    }
    KeUninitializeEvent(&Fcb->OpenCompleted);
    KeUninitializeEvent(&Fcb->WriteCompleted);
    IopFreePool(Fcb);
}

NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx)
{
    assert(CreaCtx);
    PIO_FILE_OBJECT File = (PIO_FILE_OBJECT)Object;
    PFILE_OBJ_CREATE_CONTEXT Ctx = (PFILE_OBJ_CREATE_CONTEXT)CreaCtx;

    if (Ctx->MasterFileObject) {
	assert(!Ctx->DeviceObject);
	assert(!Ctx->FileName);
	assert(!Ctx->FileSize);
	assert(!Ctx->Fcb);
	assert(!Ctx->Vcb);
	assert(!Ctx->IsDirectory);
    }

    /* If the FileName is not NULL but points to an empty string, we
     * must be opening a non-file-system device object, in which case
     * we do not allocate an FCB. */
    if ((Ctx->FileName && *Ctx->FileName == '\0') || Ctx->NoFcb) {
	File->Fcb = NULL;
    } else if (Ctx->MasterFileObject) {
	File->Fcb = Ctx->MasterFileObject->Fcb;
    } else {
	PIO_FILE_CONTROL_BLOCK Fcb = NULL;
	RET_ERR(IopCreateFcb(&Fcb, Ctx->FileSize, Ctx->Vcb, Ctx->IsDirectory));
	assert(Fcb);
	File->Fcb = Fcb;
	Fcb->MasterFileObject = File;
	Fcb->OpenInProgress = TRUE;
	if (Ctx->FileName) {
	    Fcb->FileName = RtlDuplicateString(Ctx->FileName, NTOS_IO_TAG);
	    if (!Fcb->FileName) {
		IopDeleteFcb(Fcb);
		return STATUS_NO_MEMORY;
	    }
	}
    }

    File->DeviceObject = Ctx->DeviceObject;
    if (Ctx->MasterFileObject) {
	ObpReferenceObject(Ctx->MasterFileObject);
	File->Fcb = Ctx->MasterFileObject->Fcb;
	File->DeviceObject = Ctx->MasterFileObject->DeviceObject;
    }
    if (Ctx->DeviceObject) {
	ObpReferenceObject(Ctx->DeviceObject);
    }
    File->ReadAccess = Ctx->ReadAccess;
    File->WriteAccess = Ctx->WriteAccess;
    File->DeleteAccess = Ctx->DeleteAccess;
    File->SharedRead = Ctx->SharedRead;
    File->SharedWrite = Ctx->SharedWrite;
    File->SharedDelete = Ctx->SharedDelete;
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
				   IN BOOLEAN IsDirectory,
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
	.IsDirectory = IsDirectory,
	.ReadAccess = TRUE,
	.WriteAccess = TRUE,
	.DeleteAccess = TRUE,
	.SharedRead = TRUE,
	.SharedWrite = TRUE,
	.SharedDelete = TRUE
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
    IoDbgDumpFileObject(FileObj);
    *RemainingPath = Path;
    *FoundObject = NULL;
    if (!Path[0]) {
	return STATUS_NTOS_STOP_PARSING;
    }
    POBJECT_DIRECTORY Subobjs = FileObj->Fcb ? FileObj->Fcb->Subobjects : NULL;
    if (!Subobjs) {
	return STATUS_OBJECT_NAME_INVALID;
    }
    ULONG Sep = ObLocateFirstPathSeparator(Path);
    NTSTATUS Status = ObDirectoryObjectSearchObject(Subobjs, Path, Sep,
						    CaseInsensitive, FoundObject);
    if (!NT_SUCCESS(Status)) {
	*FoundObject = NULL;
	return Status;
    }
    *RemainingPath = Path + Sep;
    return STATUS_SUCCESS;
}

NTSTATUS IopFileObjectOpenProc(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN POBJECT Self,
			       IN PCSTR SubPath,
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
    ASYNC_BEGIN(State, Locals, {
	    PCHAR FullPath;
	    ULONG SubPathLen;
	});

    /* Reject the open if the open context is not IO_OPEN_CONTEXT */
    if (Context->Type != OPEN_CONTEXT_DEVICE_OPEN) {
	ASYNC_RETURN(State, STATUS_OBJECT_TYPE_MISMATCH);
    }

    DbgTrace("Opening file obj %p path %s\n", Self, SubPath);
    IoDbgDumpFileObject(FileObject);
    *pRemainingPath = SubPath;
    assert(FileObject->Fcb);

    /* If there is an existing file open request, wait for it to finish. */
    AWAIT_IF(FileObject->Fcb->Vcb && FileObject->Fcb->OpenInProgress,
	     KeWaitForSingleObject, State, Locals, Thread,
	     &FileObject->Fcb->OpenCompleted.Header, FALSE, NULL);

    if (!SubPath[0]) {
	/* If the user requested to create a new file, deny it. */
	if (OpenContext->OpenPacket.Disposition == FILE_CREATE) {
	    ASYNC_RETURN(State, STATUS_OBJECT_NAME_COLLISION);
	}
	/* TODO: Handle FILE_SUPERSEDE, FILE_OVERWRITE, etc */
	FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	    .MasterFileObject = FileObject
	};
	ASYNC_RET_ERR(State, ObCreateObject(OBJECT_TYPE_FILE,
					    (POBJECT *)&OpenedFile, &CreaCtx));
	*pOpenedInstance = OpenedFile;
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }

    /* Concatenate the path of this file and the subpath to be opened to
     * form the full path of the target file object. */
    ULONG FileNameLen = strlen(FileObject->Fcb->FileName);
    Locals.SubPathLen = strlen(SubPath);
    Locals.FullPath = ExAllocatePoolWithTag(FileNameLen + Locals.SubPathLen + 2,
					    NTOS_IO_TAG);
    if (!Locals.FullPath) {
	ASYNC_RETURN(State, STATUS_INSUFFICIENT_RESOURCES);
    }
    RtlCopyMemory(Locals.FullPath, FileObject->Fcb->FileName, FileNameLen);
    Locals.FullPath[FileNameLen] = OBJ_NAME_PATH_SEPARATOR;
    RtlCopyMemory(Locals.FullPath + FileNameLen + 1, SubPath, Locals.SubPathLen + 1);

    /* Open the target file object */
    AWAIT_EX(Status, IopOpenDevice, State, Locals, Thread,
	     FileObject->DeviceObject, Locals.FullPath, Attributes,
	     OpenContext, &OpenedFile);
    if (NT_SUCCESS(Status)) {
	*pOpenedInstance = OpenedFile;
	*pRemainingPath = SubPath + Locals.SubPathLen;
	Status = STATUS_SUCCESS;
    } else {
	*pOpenedInstance = NULL;
	*pRemainingPath = SubPath;
    }
    IopFreePool(Locals.FullPath);
    ASYNC_END(State, Status);
}

NTSTATUS IopFileObjectInsertProc(IN POBJECT Self,
				 IN POBJECT Object,
				 IN PCSTR Path)
{
    PIO_FILE_OBJECT FileObj = (PIO_FILE_OBJECT)Self;
    assert(Self != NULL);
    assert(Path != NULL);
    assert(Object != NULL);
    DbgTrace("Inserting subobject %p (path %s) for file object %p\n",
	     Object, Path, Self);

    /* Object path must not be empty. Object path must also not contain the path
     * separator but this is checked below, by ObDirectoryObjectInsertObject. */
    if (*Path == '\0') {
	assert(FALSE);
	return STATUS_OBJECT_PATH_INVALID;
    }

    POBJECT_DIRECTORY Subobjs =  FileObj->Fcb ? FileObj->Fcb->Subobjects : NULL;
    /* Inserting into a non-directory file is not allowed. */
    if (!Subobjs) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }

    return ObDirectoryObjectInsertObject(Subobjs, Object, Path);
}

VOID IopFileObjectRemoveProc(IN POBJECT Subobject)
{
    ObDirectoryObjectRemoveObject(Subobject);
}

VOID IopFileObjectDeleteProc(IN POBJECT Self)
{
    PIO_FILE_OBJECT FileObj = Self;
    if (FileObj->DeviceObject) {
	ObDereferenceObject(FileObj->DeviceObject);
	RemoveEntryList(&FileObj->DeviceLink);
    }
    if (FileObj->Fcb->MasterFileObject == FileObj) {
	IopDeleteFcb(FileObj->Fcb);
    } else {
	ObDereferenceObject(FileObj->Fcb->MasterFileObject);
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
				OUT PIO_FILE_OBJECT *pFile)
{
    assert(pFile);
    PIO_FILE_OBJECT File = NULL;
    FILE_OBJ_CREATE_CONTEXT CreaCtx = {
	.FileName = FileName,
	.FileSize = FileSize,
	.NoFcb = !FileSize
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
			      IN ULONG CreateOptions)
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
			 CreateDisposition, CreateOptions);
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
			 IoStatusBlock, NULL, 0, ShareAccess, FILE_OPEN, OpenOptions);
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
	    .File.Object = Locals.FileObject,
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
	IoDbgDumpFileObject(Locals.FileObject);
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

NTSTATUS NtDeleteFile(IN ASYNC_STATE AsyncState,
                      IN PTHREAD Thread,
                      IN OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
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
    PIO_FILE_OBJECT FileObject = NULL;

    ASYNC_BEGIN(State, Locals, {
	    IO_OPEN_CONTEXT OpenContext;
	    PIO_FILE_OBJECT FileObject;
	    IO_STATUS_BLOCK IoStatus;
	    PPENDING_IRP PendingIrp;
	});

    Locals.OpenContext.Header.Type = OPEN_CONTEXT_DEVICE_OPEN;
    Locals.OpenContext.OpenPacket.CreateFileType = CreateFileTypeNone;
    Locals.OpenContext.OpenPacket.CreateOptions = FILE_OPEN_REPARSE_POINT;
    Locals.OpenContext.OpenPacket.FileAttributes = FILE_READ_ATTRIBUTES;
    Locals.OpenContext.OpenPacket.ShareAccess = FILE_SHARE_READ;
    Locals.OpenContext.OpenPacket.Disposition = FILE_OPEN;

    AWAIT_EX(Status, ObOpenObjectByNameEx, State, Locals, Thread,
	     ObjectAttributes, OBJECT_TYPE_FILE,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, FALSE, (PVOID *)&FileObject);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.FileObject = FileObject;
    assert(Locals.FileObject != NULL);
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
    if (!NT_SUCCESS(Locals.IoStatus.Status)) {
	Status = Locals.IoStatus.Status;
    }
    if (Locals.PendingIrp) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }

    ASYNC_END(State, Status);
}

NTSTATUS NtQueryInformationFile(IN ASYNC_STATE State,
                                IN PTHREAD Thread,
                                IN HANDLE FileHandle,
                                OUT IO_STATUS_BLOCK *IoStatusBlock,
                                OUT PVOID FileInfoBuffer,
                                IN ULONG Length,
                                IN FILE_INFORMATION_CLASS FileInformationClass)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PPENDING_IRP PendingIrp;
	    IO_STATUS_BLOCK IoStatus;
	});

    switch (FileInformationClass) {
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
    /* Deviceless files cannot be queried. */
    if (!Locals.FileObject->DeviceObject) {
	Status = STATUS_NOT_IMPLEMENTED;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);

    PIO_DEVICE_INFO DevInfo = &Locals.FileObject->DeviceObject->DeviceInfo;
    /* Quick path for FilePositionInformation. The NT executive has enough info
     * to reply to the client without asking the file system driver. */
    if (FileInformationClass == FilePositionInformation) {
	/* TODO: Eventually we will schedule an IO APC to deliver the results
	 * to the client side in order to avoid doing a syscall. For now we
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

    /* Queue an IRP to the target driver object. */
    PIO_FILE_OBJECT TargetFileObject = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    IO_REQUEST_PARAMETERS Irp = {
	.Device.Object = Locals.FileObject->DeviceObject,
	.File.Object = TargetFileObject,
	.MajorFunction = IRP_MJ_QUERY_INFORMATION,
	.OutputBuffer = (MWORD)FileInfoBuffer,
	.OutputBufferLength = Length,
	.QueryFile.FileInformationClass = FileInformationClass
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

    if (!Locals.FileObject->DeviceObject) {
	/* Purely in-memory file objects do not require flushing. Return success. */
	if (IoStatusBlock) {
	    IoStatusBlock->Status = STATUS_SUCCESS;
	    IoStatusBlock->Information = 0;
	}
	ASYNC_RETURN(State, STATUS_SUCCESS);
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
	DbgPrint("    Subobjects = %p\n", File->Fcb->Subobjects);
    }
#endif
}
