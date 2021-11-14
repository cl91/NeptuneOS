#include <hal.h>

/* The IRP object includes the IRP struct itself plus an array of
 * IO_STACK_LOCATION objects. Since we run drivers in their own
 * process environment there only has to be two IO stack per IRP.
 * One for the initial request and one for the IoCallDriver request. */
#define MAX_IO_STACK_LOCATIONS	(2)
#define IRP_OBJECT_SIZE (IoSizeOfIrp(MAX_IO_STACK_LOCATIONS))

PIO_REQUEST_PACKET IopIncomingIrpBuffer;
PIO_REQUEST_PACKET IopOutgoingIrpBuffer;
/* List of all IRPs queued to this driver */
LIST_ENTRY IopIrpQueue;
/* List of all IRPs that have completed processing */
LIST_ENTRY IopCompletedIrpList;
/* List of all file objects created by this driver */
LIST_ENTRY IopFileObjectList;

static inline NTSTATUS IopCreateFileObject(IN PFILE_OBJECT_CREATE_PARAMETERS Params,
					   IN GLOBAL_HANDLE Handle,
					   OUT PFILE_LIST_ENTRY *pFileListEntry)
{
    assert(Params != NULL);
    assert(Handle != 0);
    assert(pFileListEntry != NULL);
    IopAllocateObject(FileObject, FILE_OBJECT);
    IopAllocateObjectEx(FileListEntry, FILE_LIST_ENTRY, IopFreePool(FileObject));
    UNICODE_STRING FileName;
    RET_ERR_EX(RtlpUtf8ToUnicodeString(RtlGetProcessHeap(), Params->FileName, &FileName),
	       {
		   IopFreePool(FileObject);
		   IopFreePool(FileListEntry);
	       });
    FileObject->ReadAccess = Params->ReadAccess;
    FileObject->WriteAccess = Params->WriteAccess;
    FileObject->DeleteAccess = Params->DeleteAccess;
    FileObject->SharedRead = Params->SharedRead;
    FileObject->SharedWrite = Params->SharedWrite;
    FileObject->SharedDelete = Params->SharedDelete;
    FileObject->Flags = Params->Flags;
    FileObject->FileName = FileName;
    FileListEntry->Object = FileObject;
    FileListEntry->Handle = Handle;
    InsertTailList(&IopFileObjectList, &FileListEntry->Link);
    *pFileListEntry = FileListEntry;
    return STATUS_SUCCESS;
}

static inline VOID IopDeleteFileObject(IN PFILE_LIST_ENTRY FileListEntry)
{
    assert(FileListEntry != NULL);
    assert(FileListEntry->Link.Flink != NULL);
    assert(FileListEntry->Link.Blink != NULL);
    assert(FileListEntry->Handle != 0);
    assert(FileListEntry->Object != NULL);
    RemoveEntryList(&FileListEntry->Link);
    IopFreePool(FileListEntry->Object->FileName.Buffer);
    IopFreePool(FileListEntry->Object);
    IopFreePool(FileListEntry);
}

/*
 * Search the list of all files created by this driver and return
 * the one matching the given GLOBAL_HANDLE. Returns NULL if not found.
 */
static inline PFILE_OBJECT IopGetFileObject(IN GLOBAL_HANDLE Handle)
{
    LoopOverList(Entry, &IopFileObjectList, FILE_LIST_ENTRY, Link) {
	if (Handle == Entry->Handle) {
	    return Entry->Object;
	}
    }
    return NULL;
}

static inline VOID IopFreeIrpQueueEntry(IN PIRP_QUEUE_ENTRY Entry)
{
    IopFreePool(Entry->Irp);
    IopFreePool(Entry);
}

/*
 * Populate the local IRP object from the source IO packet in the IRP buffer
 */
static NTSTATUS IopServerIrpToLocal(IN PIRP Irp,
				    IN PIO_REQUEST_PACKET Src)
{
    assert(Src->Type == IrpTypeRequest);
    PDEVICE_OBJECT DeviceObject = IopGetDeviceObject(Src->Request.Device.Handle);
    if (DeviceObject == NULL) {
	assert(FALSE);
	return STATUS_INVALID_HANDLE;
    }
    PFILE_OBJECT FileObject = NULL;
    PFILE_LIST_ENTRY FileListEntry = NULL;
    if ((Src->Request.MajorFunction == IRP_MJ_CREATE) ||
	(Src->Request.MajorFunction == IRP_MJ_CREATE_MAILSLOT) ||
	(Src->Request.MajorFunction == IRP_MJ_CREATE_NAMED_PIPE)) {
	RET_ERR(IopCreateFileObject(&Src->Request.Parameters.Create.FileObjectParameters,
				    Src->Request.File.Handle, &FileListEntry));
	FileObject = FileListEntry->Object;
    } else {
	FileObject = IopGetFileObject(Src->Request.File.Handle);
    }
    if (FileObject == NULL) {
	assert(FALSE);
	return STATUS_INVALID_HANDLE;
    }

    Irp->Type = IO_TYPE_IRP;
    Irp->Size = IRP_OBJECT_SIZE;
    Irp->StackCount = MAX_IO_STACK_LOCATIONS;
    Irp->CurrentLocation = 0;

    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    IoStack->MajorFunction = Src->Request.MajorFunction;
    IoStack->MinorFunction = Src->Request.MinorFunction;
    IoStack->Flags = Src->Request.Flags;
    IoStack->Control = Src->Request.Control;
    IoStack->DeviceObject = DeviceObject;
    IoStack->FileObject = FileObject;
    IoStack->CompletionRoutine = NULL;
    IoStack->Context = NULL;
    switch (Src->Request.MajorFunction) {
    case IRP_MJ_CREATE:
	IoStack->Parameters.Create.SecurityContext = NULL;
	IoStack->Parameters.Create.Options = Src->Request.Parameters.Create.Options;
	IoStack->Parameters.Create.FileAttributes = Src->Request.Parameters.Create.FileAttributes;
	IoStack->Parameters.Create.ShareAccess = Src->Request.Parameters.Create.ShareAccess;
	IoStack->Parameters.Create.EaLength = 0;
	break;
    case IRP_MJ_CREATE_NAMED_PIPE:
	IoStack->Parameters.CreatePipe.SecurityContext = NULL;
	IoStack->Parameters.CreatePipe.Options = Src->Request.Parameters.CreatePipe.Options;
	IoStack->Parameters.CreatePipe.Reserved = 0;
	IoStack->Parameters.CreatePipe.ShareAccess = Src->Request.Parameters.CreatePipe.ShareAccess;
	assert(FileListEntry != NULL);
	IopAllocateObjectEx(NamedPipeCreateParameters, NAMED_PIPE_CREATE_PARAMETERS,
			    IopDeleteFileObject(FileListEntry));
	*NamedPipeCreateParameters = Src->Request.Parameters.CreatePipe.Parameters;
	IoStack->Parameters.CreatePipe.Parameters = NamedPipeCreateParameters;
	break;
    case IRP_MJ_CREATE_MAILSLOT:
	IoStack->Parameters.CreateMailslot.SecurityContext = NULL;
	IoStack->Parameters.CreateMailslot.Options = Src->Request.Parameters.CreateMailslot.Options;
	IoStack->Parameters.CreateMailslot.Reserved = 0;
	IoStack->Parameters.CreateMailslot.ShareAccess = Src->Request.Parameters.CreateMailslot.ShareAccess;
	assert(FileListEntry != NULL);
	IopAllocateObjectEx(MailslotCreateParameters, MAILSLOT_CREATE_PARAMETERS,
			    IopDeleteFileObject(FileListEntry));
	*MailslotCreateParameters = Src->Request.Parameters.CreateMailslot.Parameters;
	IoStack->Parameters.CreateMailslot.Parameters = MailslotCreateParameters;
	break;
    }

    return STATUS_SUCCESS;
}

static VOID IopLocalIrpToServer(IN PIRP_QUEUE_ENTRY IrpQueueEntry,
				IN PIO_REQUEST_PACKET Dest)
{
    memset(Dest, 0, sizeof(IO_REQUEST_PACKET));
    /* TODO: Implement the case for IoCallDriver */
    Dest->Type = IrpTypeIoCompleted;
    Dest->IoStatus = IrpQueueEntry->Irp->IoStatus;
    Dest->ParentIrp.Handle = IrpQueueEntry->ThisIrp;
}

VOID IoDbgDumpIoStackLocation(IN PIO_STACK_LOCATION Stack)
{
    DbgTrace("Dumping IO stack location %p\n", Stack);
    DbgPrint("    Major function %d.  Minor function %d.  Flags 0x%x.  Control 0x%x\n",
	     Stack->MajorFunction, Stack->MinorFunction, Stack->Flags, Stack->Control);
    DbgPrint("    DeviceObject %p FileObject %p CompletionRoutine %p Context %p\n",
	     Stack->DeviceObject, Stack->FileObject, Stack->CompletionRoutine, Stack->Context);
    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
	DbgPrint("    CREATE  SecurityContext %p Options 0x%x FileAttr 0x%x ShareAccess 0x%x EaLength %d\n",
		 Stack->Parameters.Create.SecurityContext, Stack->Parameters.Create.Options,
		 Stack->Parameters.Create.FileAttributes, Stack->Parameters.Create.ShareAccess,
		 Stack->Parameters.Create.EaLength);
    }
}

VOID IoDbgDumpIrp(IN PIRP Irp)
{
    DbgTrace("Dumping IRP %p size %d\n", Irp, Irp->Size);
    DbgPrint("    MdlAddress %p Flags 0x%08x Stack Count %d Current Location %d\n",
	     Irp->MdlAddress, Irp->Flags, Irp->StackCount, Irp->CurrentLocation);
    DbgPrint("    IO Status Block Status 0x%08x Information %p\n",
	     Irp->IoStatus.Status, (PVOID) Irp->IoStatus.Information);
    DbgPrint("    IO Stack Location %p\n", IoGetCurrentIrpStackLocation(Irp));
    IoDbgDumpIoStackLocation(IoGetCurrentIrpStackLocation(Irp));
}

NTSTATUS IopProcessIrpQueue()
{
    assert(IopDriverObject != NULL);
    LoopOverList(Entry, &IopIrpQueue, IRP_QUEUE_ENTRY, Link) {
	PIRP Irp = Entry->Irp;
	IoDbgDumpIrp(Irp);
	/* Detach the IRP from the IRP queue */
	RemoveEntryList(&Entry->Link);
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
	PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
	PDRIVER_DISPATCH DispatchRoutine = IopDriverObject->MajorFunction[IoStack->MajorFunction];
	NTSTATUS Status = STATUS_SUCCESS;
	if (DispatchRoutine != NULL) {
	    Status = DispatchRoutine(DeviceObject, Irp);
	} else {
	    /* TODO: Handle null dispatch routine */
	}
	/* TODO: Handle error status */
	/* Move the IRP into the completed IRP list */
	InsertTailList(&IopCompletedIrpList, &Entry->Link);
    }
    return STATUS_SUCCESS;
}

NTSTATUS IopProcessIrp(OUT ULONG *pNumResponses,
		       IN ULONG NumRequests)
{
    for (ULONG i = 0; i < NumRequests; i++) {
	/* TODO: Call Fast IO routines if available */
	PIO_REQUEST_PACKET SrcIrp = &IopIncomingIrpBuffer[i];
	/* Allocate the IRP queue entry and the actual IRP. We should not
	 * run out of memory here since the incoming IRP buffer is finite.
	 * If we did run out of memory what might have happened is that
	 * either there is a memory leak in the driver (or ntdll/hal.dll),
	 * or a lower-level driver is not responding (at least not quickly
	 * enough) so IRPs get piled here in its higher-level driver. Not
	 * much can be done here, so we simply clean up and return error */
	if (SrcIrp->Type == IrpTypeRequest) {
	    IopAllocateObject(QueueEntry, IRP_QUEUE_ENTRY);
	    IopAllocatePoolEx(IrpObj, IRP, IRP_OBJECT_SIZE, IopFreePool(QueueEntry));
	    QueueEntry->ThisIrp = SrcIrp->ThisIrp;
	    QueueEntry->Irp = IrpObj;
	    RET_ERR_EX(IopServerIrpToLocal(IrpObj, SrcIrp),
		       {
			   IopFreePool(IrpObj);
			   IopFreePool(QueueEntry);
		       });
	    InsertTailList(&IopIrpQueue, &QueueEntry->Link);
	} else if (SrcIrp->Type == IrpTypeDpc) {
	    /* TODO */
	} else {
	    assert(SrcIrp->Type == IrpTypeIoCompleted);
	    /* TODO */
	}
    }

    /* Process all DPCs first */

    /* Process all queued IRP. Once processed, the IRP gets moved to the completed IRP list. */
    RET_ERR(IopProcessIrpQueue());

    /* Move the finished IRPs to the outgoing buffer. */
    ULONG NumResponses = GetListLength(&IopCompletedIrpList);
    if (NumResponses * sizeof(IO_REQUEST_PACKET) > DRIVER_IRP_BUFFER_COMMIT) {
	/* TODO: Commit more memory */
	NumResponses = DRIVER_IRP_BUFFER_COMMIT / sizeof(IO_REQUEST_PACKET);
    }
    PIRP_QUEUE_ENTRY Entry = CONTAINING_RECORD(IopCompletedIrpList.Flink,
					       IRP_QUEUE_ENTRY, Link);
    PIRP_QUEUE_ENTRY NextEntry = NULL;
    for (ULONG i = 0; i < NumResponses; i++, Entry = NextEntry) {
	/* Save the next entry since we will be deleting this entry */
	NextEntry = CONTAINING_RECORD(Entry->Link.Flink, IRP_QUEUE_ENTRY, Link);
	/* Detach this entry from the completed IRP list */
	RemoveEntryList(&Entry->Link);
	PIO_REQUEST_PACKET DestIrp = &IopOutgoingIrpBuffer[i];
	IopLocalIrpToServer(Entry, DestIrp);
	/* This will free the IRP as well */
	IopFreeIrpQueueEntry(Entry);
    }

    *pNumResponses = NumResponses;
    return STATUS_SUCCESS;
}

NTAPI VOID IoCompleteRequest(IN PIRP Irp,
			     IN CHAR PriorityBoost)
{
}
