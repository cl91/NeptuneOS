#include <wdmp.h>
#include "coroutine.h"

PIO_PACKET IopIncomingIoPacketBuffer;
PIO_PACKET IopOutgoingIoPacketBuffer;
/* List of all IRPs queued to this driver */
LIST_ENTRY IopIrpQueue;
/* List of all IRPs that have completed processing */
LIST_ENTRY IopCompletedIrpList;
/* List of all IRPs that are being forwarded */
LIST_ENTRY IopForwardedIrpList;
/* List of all IRPs to clean up after the dispatch routine has returned */
LIST_ENTRY IopCleanupIrpList;
/* List of all file objects created by this driver */
LIST_ENTRY IopFileObjectList;

static inline NTSTATUS IopCreateFileObject(IN PIO_PACKET IoPacket,
					   IN PFILE_OBJECT_CREATE_PARAMETERS Params,
					   IN GLOBAL_HANDLE Handle,
					   OUT PFILE_LIST_ENTRY *pFileListEntry)
{
    assert(Params != NULL);
    assert(Handle != 0);
    assert(pFileListEntry != NULL);
    IopAllocateObject(FileObject, FILE_OBJECT);
    IopAllocateObjectEx(FileListEntry, FILE_LIST_ENTRY, IopFreePool(FileObject));
    UNICODE_STRING FileName;
    RET_ERR_EX(RtlpUtf8ToUnicodeString(RtlGetProcessHeap(),
				       (PCHAR)IoPacket + Params->FileNameOffset, &FileName),
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

static NTSTATUS IopMarshalIoctlBuffers(IN PIRP_QUEUE_ENTRY Entry,
				       IN ULONG Ioctl,
				       IN PVOID InputBuffer,
				       IN ULONG InputBufferLength,
				       IN PVOID OutputBuffer,
				       IN ULONG OutputBufferLength)
{
    PIRP Irp = Entry->Irp;
    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
	ULONG SystemBufferLength = max(InputBufferLength, OutputBufferLength);
	IopAllocatePool(SystemBuffer, UCHAR, SystemBufferLength);
	Irp->AssociatedIrp.SystemBuffer = SystemBuffer;
	/* Copy the user input data to the system buffer if there is any */
	if (InputBufferLength != 0) {
	    memcpy(Irp->AssociatedIrp.SystemBuffer, InputBuffer, InputBufferLength);
	}
	Entry->OutputBuffer = OutputBuffer;
    } else if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_NEITHER) {
	/* Type3InputBuffer is set in the IopServerIoPacketToLocal function */
	Irp->UserBuffer = OutputBuffer;
    } else {
	/* Direct IO: METHOD_IN_DIRECT or METHOD_OUT_DIRECT */
	Irp->AssociatedIrp.SystemBuffer = InputBuffer;
	if (OutputBufferLength != 0) {
	    IopAllocateObject(Mdl, MDL);
	    Mdl->MappedSystemVa = OutputBuffer;
	    Mdl->ByteCount = OutputBufferLength;
	    Irp->MdlAddress = Mdl;
	}
    }
    return STATUS_SUCCESS;
}

static VOID IopUnmarshalIoctlBuffers(IN PIRP_QUEUE_ENTRY Entry,
				     IN ULONG Ioctl,
				     IN ULONG OutputBufferLength)
{
    PIRP Irp = Entry->Irp;
    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
	/* Copy the system buffer back to the user output buffer if needed */
	if (OutputBufferLength != 0) {
	    assert(Entry->OutputBuffer != NULL);
	    memcpy(Entry->OutputBuffer, Irp->AssociatedIrp.SystemBuffer,
		   OutputBufferLength);
	}
	IopFreePool(Irp->AssociatedIrp.SystemBuffer);
	Irp->AssociatedIrp.SystemBuffer = NULL;
    } else if ((METHOD_FROM_CTL_CODE(Ioctl) == METHOD_IN_DIRECT) ||
	       (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_OUT_DIRECT)) {
	if (OutputBufferLength != 0) {
	    assert(Irp->MdlAddress != NULL);
	    IopFreePool(Irp->MdlAddress);
	    Irp->MdlAddress = NULL;
	}
    }
}

/*
 * Populate the local IRP object from the server IO packet
 */
static NTSTATUS IopServerIoPacketToLocal(IN PIRP_QUEUE_ENTRY QueueEntry,
					 IN PIO_PACKET Src)
{
    assert(QueueEntry != NULL);
    PIRP Irp = QueueEntry->Irp;
    assert(Irp != NULL);
    assert(Src != NULL);
    assert(Src->Type == IoPacketTypeRequest);
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
	RET_ERR(IopCreateFileObject(Src, &Src->Request.Parameters.Create.FileObjectParameters,
				    Src->Request.File.Handle, &FileListEntry));
	FileObject = FileListEntry->Object;
    } else {
	FileObject = IopGetFileObject(Src->Request.File.Handle);
    }

    IoInitializeIrp(Irp);

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
    case IRP_MJ_DEVICE_CONTROL:
    {
	ULONG Ioctl = Src->Request.Parameters.DeviceIoControl.IoControlCode;
	PVOID InputBuffer = Src->Request.Parameters.DeviceIoControl.InputBuffer;
	ULONG InputBufferLength = Src->Request.Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputBufferLength = Src->Request.Parameters.DeviceIoControl.OutputBufferLength;
	IoStack->Parameters.DeviceIoControl.IoControlCode = Ioctl;
	IoStack->Parameters.DeviceIoControl.Type3InputBuffer = InputBuffer;
	IoStack->Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
	IoStack->Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;
	RET_ERR(IopMarshalIoctlBuffers(QueueEntry, Ioctl, InputBuffer, InputBufferLength,
				       Src->Request.Parameters.DeviceIoControl.OutputBuffer,
				       OutputBufferLength));
	break;
    }
    case IRP_MJ_PNP:
    {
	switch (Src->Request.MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    IoStack->Parameters.QueryDeviceRelations.Type = Src->Request.Parameters.QueryDeviceRelations.Type;
	    break;
	case IRP_MN_QUERY_ID:
	    IoStack->Parameters.QueryId.IdType = Src->Request.Parameters.QueryId.IdType;
	    break;
	default:
	    UNIMPLEMENTED;
	    return STATUS_NOT_IMPLEMENTED;
	}
	break;
    }
    default:
	UNIMPLEMENTED;
	return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

static BOOLEAN IopLocalIrpToServer(IN PIRP_QUEUE_ENTRY IrpQueueEntry,
				   IN PIO_PACKET Dest,
				   IN ULONG BufferSize)
{
    ULONG Size = sizeof(IO_PACKET);
    PIO_STACK_LOCATION IoSp = IoGetCurrentIrpStackLocation(IrpQueueEntry->Irp);
    if (IoSp->MajorFunction == IRP_MJ_PNP) {
	switch (IoSp->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	{
	    PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)IrpQueueEntry->Irp->IoStatus.Information;
	    ULONG ResponseOffset = FIELD_OFFSET(IO_PACKET, ClientMsg.Parameters.IoCompleted.ResponseData);
	    assert(sizeof(IO_PACKET) > ResponseOffset);
	    ULONG MaxCount = (sizeof(IO_PACKET) - ResponseOffset)/sizeof(GLOBAL_HANDLE);
	    if (Relations != NULL && Relations->Count > MaxCount) {
		Size += (Relations->Count - MaxCount) * sizeof(GLOBAL_HANDLE);
	    }
	}
	break;

	case IRP_MN_QUERY_ID:
	{
	    /* For UTF-16 strings that are legal device IDs its characters are always within ASCII */
	    if (IrpQueueEntry->Irp->IoStatus.Information != 0) {
		Size += wcslen((PWSTR)IrpQueueEntry->Irp->IoStatus.Information) + 1;
	    }
	}
	break;

	default:
	    UNIMPLEMENTED;
	    return FALSE;
	}
    }
    if (BufferSize < Size) {
	return FALSE;
    }
    memset(Dest, 0, Size);

    /* TODO: Implement the case for IoCallDriver */
    Dest->Type = IoPacketTypeClientMessage;
    Dest->Size = Size;
    Dest->ClientMsg.Type = IoCliMsgIoCompleted;
    Dest->ClientMsg.Parameters.IoCompleted.OriginatingThread = IrpQueueEntry->OriginatingThread;
    Dest->ClientMsg.Parameters.IoCompleted.OriginalIrp = IrpQueueEntry->Identifier;
    Dest->ClientMsg.Parameters.IoCompleted.IoStatus = IrpQueueEntry->Irp->IoStatus;

    switch (IoSp->MajorFunction) {
    case IRP_MJ_PNP:
    {
	switch (IoSp->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    if (IrpQueueEntry->Irp->IoStatus.Information != 0) {
		/* Dest->...IoStatus.Information is DEVICE_RELATIONS.Count. ResponseData[] are the GLOBAL_HANDLE
		 * of the device objects in DEVICE_RELATIONS.Objects. */
		PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)IrpQueueEntry->Irp->IoStatus.Information;
		Dest->ClientMsg.Parameters.IoCompleted.IoStatus.Information = Relations->Count;
		for (ULONG i = 0; i < Relations->Count; i++) {
		    Dest->ClientMsg.Parameters.IoCompleted.ResponseData[i] = IopGetDeviceHandle(Relations->Objects[i]);
		}
		Dest->ClientMsg.Parameters.IoCompleted.ResponseDataSize = Relations->Count * sizeof(GLOBAL_HANDLE);
		IopFreePool(Relations);
	    }
	    break;

	case IRP_MN_QUERY_ID:
	    if (IrpQueueEntry->Irp->IoStatus.Information != 0) {
		/* ResponseData[] is the UTF-8 string of the device id.
		 * ResponseDataSize is the size of the string including terminating NUL.
		 * Dest->...IoStatus.Information is cleared. */
		PWSTR String = (PWSTR)IrpQueueEntry->Irp->IoStatus.Information;
		ULONG ResponseDataSize = wcslen(String) + 1;
		Dest->ClientMsg.Parameters.IoCompleted.IoStatus.Information = 0;
		Dest->ClientMsg.Parameters.IoCompleted.ResponseDataSize = ResponseDataSize;
		PCHAR DestStr = (PCHAR)Dest->ClientMsg.Parameters.IoCompleted.ResponseData;
		for (ULONG i = 0; i < ResponseDataSize; i++) {
		    DestStr[i] = (CHAR)String[i];
		}
		IopFreePool(String);
	    }
	    break;

	default:
	    break;
	}
	break;
    }
    default:
	break;
    }

    return TRUE;
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
	break;
    case IRP_MJ_DEVICE_CONTROL:
	DbgPrint("    DEVICE-CONTROL  OutputBufferLength 0x%x InputBufferLength 0x%x IoControlCode %d Type3InputBuffer %p\n",
		 Stack->Parameters.DeviceIoControl.OutputBufferLength,
		 Stack->Parameters.DeviceIoControl.InputBufferLength,
		 Stack->Parameters.DeviceIoControl.IoControlCode,
		 Stack->Parameters.DeviceIoControl.Type3InputBuffer);
	break;
    case IRP_MJ_PNP:
	switch (Stack->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    DbgPrint("    PNP  QUERY-DEVICE-RELATIONS  Type %s\n",
		     IopDbgDeviceRelationTypeStr(Stack->Parameters.QueryDeviceRelations.Type));
	    break;
	case IRP_MN_QUERY_ID:
	    DbgPrint("    PNP  QUERY-ID  Type %s\n",
		     IopDbgQueryIdTypeStr(Stack->Parameters.QueryId.IdType));
	    break;
	default:
	    DbgPrint("    PNP  UNKNOWN-MINOR-FUNCTION\n");
	}
	break;
    default:
	DbgPrint("    UNKNOWN-MAJOR-FUNCTION\n");
    }
}

VOID IoDbgDumpIrp(IN PIRP Irp)
{
    DbgTrace("Dumping IRP %p size %d\n", Irp, Irp->Size);
    DbgPrint("    MdlAddress %p Flags 0x%08x\n",
	     Irp->MdlAddress, Irp->Flags);
    DbgPrint("    IO Status Block Status 0x%08x Information %p\n",
	     Irp->IoStatus.Status, (PVOID) Irp->IoStatus.Information);
    DbgPrint("    IO Stack Location %p\n", IoGetCurrentIrpStackLocation(Irp));
    IoDbgDumpIoStackLocation(IoGetCurrentIrpStackLocation(Irp));
}

/*
 * This function has to be FASTCALL since we pass its argument in register %ecx
 * (or %rcx in amd64, see coroutine.h).
 */
FASTCALL NTSTATUS IopCallDispatchRoutine(IN PIRP_QUEUE_ENTRY Entry) /* %ecx/%rcx */
{
    assert(Entry != NULL);
    PIRP Irp = Entry->Irp;
    assert(Irp != NULL);
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
    PDRIVER_DISPATCH DispatchRoutine = IopDriverObject.MajorFunction[IoStack->MajorFunction];
    NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
    if (DispatchRoutine != NULL) {
	Status = DispatchRoutine(DeviceObject, Irp);
    }
    return Status;
}

static VOID IopProcessIrpQueue()
{
    LoopOverList(Entry, &IopIrpQueue, IRP_QUEUE_ENTRY, Link) {
	PIRP Irp = Entry->Irp;
	IoDbgDumpIrp(Irp);
	/* Find the first available coroutine stack to use */
	PVOID Stack = KiGetFirstAvailableCoroutineStack();
	/* If KiGetFirstAvailableCoroutineStack returns NULL, it means that
	 * the system is out of memory. Simply stop processing and wait for
	 * memory to become available in the future. */
	if (Stack == NULL) {
	    break;
	}
	/* Save the current stack location in case dispatch function changes it */
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
	/* Switch to the coroutine stack and call the dispatch routine */
	NTSTATUS Status = IopStartCoroutine(Stack, Entry);
	/* If the dispatch routine is blocked on waiting for an object,
	 * suspend the coroutine and process the next IRP. */
	if (Status == STATUS_ASYNC_PENDING) {
	    continue;
	}
	if (NT_SUCCESS(Irp->IoStatus.Status) && !NT_SUCCESS(Status)) {
	    /* If the driver did not return error in IoStatus but returned
	     * error in its dispatch routine, return the dispatch routine
	     * error instead of the IoStatus status code so the calling
	     * thread knows something is wrong. */
	    Irp->IoStatus.Status = Status;
	}
	/* For buffered IO, we need to copy the system buffer back to user output buffer */
	switch (IoStack->MajorFunction) {
	case IRP_MJ_DEVICE_CONTROL:
	{
	    IopUnmarshalIoctlBuffers(Entry, IoStack->Parameters.DeviceIoControl.IoControlCode,
				     IoStack->Parameters.DeviceIoControl.OutputBufferLength);
	    break;
	}
	default:
	    break;
	    /* TODO */
	}
	/* Detach the IRP from the IRP queue */
	RemoveEntryList(&Entry->Link);
	/* Move the IRP into the completed IRP list */
	InsertTailList(&IopCompletedIrpList, &Entry->Link);
    }
}

/*
 * Allocate the driver-side IRP queue entry and the driver-side IRP.
 * Copy the server-side IO packet to the driver-side IRP, taking care to
 * correctly convert the server-side packet to driver-side IRP. We should
 * not run out of memory here since the incoming IO packet buffer is finite.
 * If we did run out of memory what might have happened is that either
 * there is a memory leak in the driver (or ntdll.dll or hal.dll), or a
 * lower-level driver is not responding (at least not quickly enough) so
 * IRPs get piled here in its higher-level driver. Not much can be done
 * here, so we simply clean up and return error.
 */
static inline NTSTATUS IopQueueRequestIoPacket(IN PIO_PACKET SrcIoPacket)
{
    assert(SrcIoPacket->Type == IoPacketTypeRequest);
    IopAllocateObject(QueueEntry, IRP_QUEUE_ENTRY);
    IopAllocatePoolEx(IrpObj, IRP, IO_SIZE_OF_IRP, IopFreePool(QueueEntry));
    QueueEntry->OriginatingThread = SrcIoPacket->Request.OriginatingThread.Handle;
    QueueEntry->Identifier = SrcIoPacket->Request.Identifier;
    QueueEntry->Irp = IrpObj;
    RET_ERR_EX(IopServerIoPacketToLocal(QueueEntry, SrcIoPacket),
	       {
		   IopFreePool(IrpObj);
		   IopFreePool(QueueEntry);
	       });
    InsertTailList(&IopIrpQueue, &QueueEntry->Link);
    return STATUS_SUCCESS;
}

VOID IopProcessIoPackets(OUT ULONG *pNumResponses,
			 IN ULONG NumRequests)
{
    ULONG ErrorResponseCount = 0;
    PIO_PACKET SrcIoPacket = IopIncomingIoPacketBuffer;
    for (ULONG i = 0; i < NumRequests; i++) {
	/* TODO: Call Fast IO routines if available */
	if (SrcIoPacket->Type == IoPacketTypeRequest) {
	    /* Allocate, populate, and queue the driver-side IRP from server-side
	     * IO packet in the incoming buffer. Once this is done, the information
	     * stored in the incoming IRP buffer is copied into the IRP queue. */
	    NTSTATUS Status = IopQueueRequestIoPacket(SrcIoPacket);
	    /* If this returned error, we sent a client message to inform the server
	     * that we are unable to process this IRP. We should never run out of
	     * outgoing packet buffer here since the outgoing buffer has the same
	     * size as the incoming buffer. */
	    if (!NT_SUCCESS(Status)) {
		/* Since all response packet has the same size we can use the array syntax */
		IopOutgoingIoPacketBuffer[ErrorResponseCount].Type = IoPacketTypeClientMessage;
		IopOutgoingIoPacketBuffer[ErrorResponseCount].Size = sizeof(IO_PACKET);
		IopOutgoingIoPacketBuffer[ErrorResponseCount].ClientMsg.Type = IoCliMsgIoCompleted;
		IopOutgoingIoPacketBuffer[ErrorResponseCount].ClientMsg.Parameters.IoCompleted.OriginatingThread =
		    SrcIoPacket->Request.OriginatingThread.Handle;
		IopOutgoingIoPacketBuffer[ErrorResponseCount].ClientMsg.Parameters.IoCompleted.OriginalIrp =
		    SrcIoPacket->Request.Identifier;
		IopOutgoingIoPacketBuffer[ErrorResponseCount].ClientMsg.Parameters.IoCompleted.IoStatus.Status = Status;
		IopOutgoingIoPacketBuffer[ErrorResponseCount].ClientMsg.Parameters.IoCompleted.IoStatus.Information = 0;
		ErrorResponseCount++;
	    }
	} else if (SrcIoPacket->Type == IoPacketTypeServerMessage) {
	    /* Process all server message */
	} else {
	    DbgPrint("Invalid IO packet type %d\n", SrcIoPacket->Type);
	    assert(FALSE);
	}
	SrcIoPacket = (PIO_PACKET)((MWORD)SrcIoPacket + SrcIoPacket->Size);
    }

    /* Process all queued IRP. Once processed, the IRP gets moved to the completed IRP list. */
    IopProcessIrpQueue();

    /* Since the incoming buffer and outgoing buffer have the same size we should never
     * run out of outgoing buffer at this point. */
    assert(ErrorResponseCount <= DRIVER_IO_PACKET_BUFFER_COMMIT / sizeof(IO_PACKET));
    ULONG RemainingBufferSize = DRIVER_IO_PACKET_BUFFER_COMMIT - ErrorResponseCount * sizeof(IO_PACKET);
    ULONG ResponseCount = 0;
    /* Move the finished IRPs to the outgoing buffer. */
    PIO_PACKET DestIrp = IopOutgoingIoPacketBuffer + ErrorResponseCount;
    LoopOverList(Entry, &IopCompletedIrpList, IRP_QUEUE_ENTRY, Link) {
	/* IopLocalIrpToServer will return FALSE if remaining size is too small for the IO packet */
	if (!IopLocalIrpToServer(Entry, DestIrp, RemainingBufferSize)) {
	    break;
	}
	/* Detach this entry from the completed IRP list */
	RemoveEntryList(&Entry->Link);
	/* This will free the IRP as well */
	IopFreeIrpQueueEntry(Entry);
	assert(DestIrp->Size >= sizeof(IO_PACKET));
	assert(RemainingBufferSize >= DestIrp->Size);
	if (RemainingBufferSize <= DestIrp->Size) {
	    break;
	}
	IoDbgDumpIoPacket(DestIrp, TRUE);
	DestIrp = (PIO_PACKET)((MWORD)DestIrp + DestIrp->Size);
	RemainingBufferSize -= DestIrp->Size;
	ResponseCount++;
    }

    *pNumResponses = ErrorResponseCount + ResponseCount;
}

/*
 * Forward the specified IRP to the specified device object.
 *
 * If the IRP has an IO completion routine, IoCallDriverEx returns immediately
 * with STATUS_IRP_FORWARDED. The IRP will be forwarded to the driver object
 * corresponding to the device object, and the IO completion routine will be
 * invoked once the server has informed us of the completion of this IRP.
 * The IRP object is then deleted after the IO completion routine has returned.
 * We call this asynchronous IRP forwarding.
 *
 * If the IRP has a user IO status block, this routine yields the current
 * coroutine to the main event loop. The suspended coroutine will resume
 * once the IRP is completed, or if the specified non-zero timeout is lapsed.
 * The status returned is the final IO status of the IRP, or STATUS_TIMEOUT
 * if the timeout is lapsed before the lower-level driver has responded. A
 * NULL Timeout or a zero timeout (ie. Timeout is not NULL and *Timeout
 * equals zero) is ignored. We call this synchronous IRP forwarding.
 * 
 * If neither is specified, the behavior of this routine is determined by
 * the Timeout parameter. If the *Timeout is zero (ie. Timeout is not NULL
 * and *Timeout equals zero), the routine returns immediately with the IRP
 * forwarded status. The IRP object is then deleted after it has been forwarded
 * to the NTOS server. On the other hand, if Timeout is NULL, or if *Timeout
 * is not zero, the IRP is forwarded synchronously as is the case of a user IO
 * status block, where Timeout == NULL means waiting indefinitely.
 *
 * A special case is where DeviceObject refers to a device object created by
 * this driver. In this case the server is not informed and all IRP forwarding
 * happens locally. The behaviors described above with regards to (a)synchronous
 * IRP forwarding still apply.
 *
 * NOTE: This function can only be called inside a coroutine. In particular,
 * you cannot call IoCallDriver(Ex) in a DPC or StartIO routine. On Windows/ReactOS
 * StartIO routines run in DISPATCH_LEVEL (same as DPC routines), and Microsoft
 * discourages higher-level drivers from calling lower-level drivers in StartIO
 * routines [1]. On NeptuneOS this becomes a hard error.
 *
 * [1] docs.microsoft.com/en-us/windows-hardware/drivers/kernel/startio-routines-in-higher-level-drivers
 */
NTAPI NTSTATUS IoCallDriverEx(IN PDEVICE_OBJECT DeviceObject,
			      IN OUT PIRP Irp,
			      IN PLARGE_INTEGER Timeout)
{
    assert(DeviceObject != NULL);
    assert(Irp != NULL);
    /* Determine whether we should forward the IRP synchronously or asynchronously */
    BOOLEAN Wait = FALSE;
    if (Irp->UserIosb != NULL) {
	Wait = TRUE;
    }
    if (IoGetCurrentIrpStackLocation(Irp)->CompletionRoutine == NULL &&
	(Timeout == NULL || Timeout->QuadPart != 0)) {
	Wait = TRUE;
    }
    PIRP_QUEUE_ENTRY IrpQueueEntry = KiGetCurrentIrpQueueEntry();
    /* This routine must be called within a coroutine. */
    assert(IrpQueueEntry != NULL);
    /* Check whether the IRP being forwarded is the current IRP being processed,
     * or if it is a new IRP that was created immediately before calling this. */
    if (Irp != IrpQueueEntry->Irp) {
	/* If we are supplied with a new Irp, make sure it hasn't been queued.
	 * This check is only done in debug build. */
	LoopOverList(Entry, &IopIrpQueue, IRP_QUEUE_ENTRY, Link) {
	    assert(Entry->Irp != Irp);
	}
	IopAllocateObject(Entry, IRP_QUEUE_ENTRY);
	/* For IRPs originating from driver objects we set OriginatingThread to NULL */
	Entry->Identifier = (HANDLE)Irp;
	Entry->Irp = Irp;
    } else {
	/* If we are forwarding the current IRP, remove it from the IRP queue */
	RemoveEntryList(&IrpQueueEntry->Link);
    }
    /* Add the IRP queue entry to the forwarded IRP list */
    InsertTailList(&IopForwardedIrpList, &IrpQueueEntry->Link);
    /* If we are not waiting for the completion of the IRP, simply return */
    if (!Wait) {
	return STATUS_IRP_FORWARDED;
    }
    /* Otherwise, yield the current coroutine. The control flow will return to
     * IopStartCoroutine */
    KiYieldCoroutine();
    /* When the control flow gets here, it means that the coroutine has been
     * resumed due to the completion of the IRP. For IRPs that are generated
     * by the driver object (rather than by the NTOS Executive), we need to
     * move the IRP from the forwarded IRP list to the list of IRPs to clean
     * up so the event loop will clean it up after the dispatch routine has
     * returned. If the IRP is supplied by the server, we move it back to
     * the IRP queue so that the event loop will complete it. */
    RemoveEntryList(&IrpQueueEntry->Link);
    if (Irp != KiGetCurrentIrpQueueEntry()->Irp) {
	InsertTailList(&IopCleanupIrpList, &IrpQueueEntry->Link);
    } else {
	InsertTailList(&IopIrpQueue, &IrpQueueEntry->Link);
    }
    /* Return the final IO status of the IRP */
    return Irp->IoStatus.Status;
}

static VOID IopStartNextPacketByKey(IN PDEVICE_OBJECT DeviceObject,
				    IN BOOLEAN Cancelable,
				    IN ULONG Key)
{
    /* Clear the current IRP */
    DeviceObject->CurrentIrp = NULL;

    /* Remove an entry from the queue */
    PKDEVICE_QUEUE_ENTRY Entry = KeRemoveByKeyDeviceQueue(&DeviceObject->DeviceQueue, Key);
    if (Entry) {
	/* Get the IRP and set it */
	PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.DeviceQueueEntry);
	DeviceObject->CurrentIrp = Irp;

	/* Check if this is a cancelable packet */
	if (Cancelable) {
	    /* Check if the caller requested no cancellation */
	    if (DeviceObject->StartIoFlags & DOE_SIO_NO_CANCEL) {
		/* He did, so remove the cancel routine */
		Irp->CancelRoutine = NULL;
	    }
	}
	/* Call the Start I/O Routine */
	DeviceObject->DriverObject->DriverStartIo(DeviceObject, Irp);
    }
}

static VOID IopStartNextPacket(IN PDEVICE_OBJECT DeviceObject,
			       IN BOOLEAN Cancelable)
{
    /* Clear the current IRP */
    DeviceObject->CurrentIrp = NULL;

    /* Remove an entry from the queue */
    PKDEVICE_QUEUE_ENTRY Entry = KeRemoveDeviceQueue(&DeviceObject->DeviceQueue);
    if (Entry) {
	/* Get the IRP and set it */
	PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.DeviceQueueEntry);
	DeviceObject->CurrentIrp = Irp;

	/* Check if this is a cancelable packet */
	if (Cancelable) {
	    /* Check if the caller requested no cancellation */
	    if (DeviceObject->StartIoFlags & DOE_SIO_NO_CANCEL) {
		/* He did, so remove the cancel routine */
		Irp->CancelRoutine = NULL;
	    }
	}

	/* Call the Start I/O Routine */
	DeviceObject->DriverObject->DriverStartIo(DeviceObject, Irp);
    }
}

static VOID IopStartNextPacketByKeyEx(IN PDEVICE_OBJECT DeviceObject,
				      IN ULONG Key,
				      IN ULONG Flags)
{
    ULONG CurrentKey = Key;
    ULONG CurrentFlags = Flags;

    while (TRUE) {
	/* Increase the count */
	if ((--DeviceObject->StartIoCount) > 1) {
	    /*
	     * We've already called the routine once...
	     * All we have to do is save the key and add the new flags
	     */
	    DeviceObject->StartIoFlags |= CurrentFlags;
	    DeviceObject->StartIoKey = CurrentKey;
	} else {
	    /* Mask out the current packet flags and key */
	    DeviceObject->StartIoFlags &= ~(DOE_SIO_WITH_KEY |
					    DOE_SIO_NO_KEY |
					    DOE_SIO_CANCELABLE);
	    DeviceObject->StartIoKey = 0;

	    /* Check if this is a packet start with key */
	    if (Flags & DOE_SIO_WITH_KEY) {
		/* Start the packet with a key */
		IopStartNextPacketByKey(DeviceObject,
					(Flags & DOE_SIO_CANCELABLE) ? TRUE : FALSE,
					CurrentKey);
	    } else if (Flags & DOE_SIO_NO_KEY) {
		/* Start the packet */
		IopStartNextPacket(DeviceObject,
				   (Flags & DOE_SIO_CANCELABLE) ? TRUE : FALSE);
	    }
	}

	/* Decrease the Start I/O count and check if it's 0 now */
	if (!(--DeviceObject->StartIoCount)) {
	    /* Get the current active key and flags */
	    CurrentKey = DeviceObject->StartIoKey;
	    CurrentFlags = DeviceObject-> StartIoFlags &
		(DOE_SIO_WITH_KEY | DOE_SIO_NO_KEY | DOE_SIO_CANCELABLE);

	    /* Check if we should still loop */
	    if (!(CurrentFlags & (DOE_SIO_WITH_KEY | DOE_SIO_NO_KEY)))
		break;
	} else {
	    /* There are still Start I/Os active, so quit this loop */
	    break;
	}
    }
}

/*
 * @implemented
 *
 * Starts the IO packet if the device queue is not busy. Otherwise, queue
 * the IRP to the device queue. Also set the supplied cancel function
 * as the cancel routine of the IRP. If the IRP has been canceled for some
 * reason, call the cancel routine.
 */
NTAPI VOID IoStartPacket(IN PDEVICE_OBJECT DeviceObject,
			 IN PIRP Irp,
			 IN PULONG Key,
			 IN PDRIVER_CANCEL CancelFunction)
{
    if (CancelFunction) {
        Irp->CancelRoutine = CancelFunction;
    }

    /* Check if we have a key */
    BOOLEAN Inserted;
    if (Key) {
        /* Insert by key */
        Inserted = KeInsertByKeyDeviceQueue(&DeviceObject->DeviceQueue,
					    &Irp->Tail.DeviceQueueEntry,
					    *Key);
    } else {
        /* Insert without a key */
        Inserted = KeInsertDeviceQueue(&DeviceObject->DeviceQueue,
				       &Irp->Tail.DeviceQueueEntry);
    }

    /* If Inserted is FALSE, it means that the device queue was
     * empty and was in a Non-Busy state. In other words, this Irp
     * should now be started now. Set the IRP to the current IRP and
     * call the StartIo routine */
    if (!Inserted) {
        DeviceObject->CurrentIrp = Irp;

        if (CancelFunction) {
            /* Check if the caller requested no cancellation */
            if (DeviceObject->StartIoFlags & DOE_SIO_NO_CANCEL) {
                /* He did, so remove the cancel routine */
                Irp->CancelRoutine = NULL;
            }
        }
        /* Call the Start I/O function, which will handle cancellation. */
        DeviceObject->DriverObject->DriverStartIo(DeviceObject, Irp);
    } else {
        /* The packet was inserted, which means that the device queue
	 * is busy. Check if we have a cancel function */
        if (CancelFunction) {
            /* Check if the IRP got cancelled */
            if (Irp->Cancel) {
                /* Set the cancel IRQL, clear the currnet cancel routine and
                 * call ours */
                Irp->CancelRoutine = NULL;
                CancelFunction(DeviceObject, Irp);
            }
        }
    }
}

/*
 * @implemented
 */
NTAPI VOID IoStartNextPacket(IN PDEVICE_OBJECT DeviceObject,
			     IN BOOLEAN Cancelable)
{
    /* Check if deferred start was requested */
    if (DeviceObject->StartIoFlags & DOE_SIO_DEFERRED) {
        /* Call our internal function to handle the defered case */
        IopStartNextPacketByKeyEx(DeviceObject,  0,
                                  DOE_SIO_NO_KEY |
                                  (Cancelable ? DOE_SIO_CANCELABLE : 0));
    } else {
        /* Call the normal routine */
        IopStartNextPacket(DeviceObject, Cancelable);
    }
}

/*
 * @implemented
 */
NTAPI VOID IoStartNextPacketByKey(IN PDEVICE_OBJECT DeviceObject,
				  IN BOOLEAN Cancelable,
				  IN ULONG Key)
{
    /* Check if deferred start was requested */
    if (DeviceObject->StartIoFlags & DOE_SIO_DEFERRED) {
        /* Call our internal function to handle the defered case */
        IopStartNextPacketByKeyEx(DeviceObject, Key, DOE_SIO_WITH_KEY |
                                  (Cancelable ? DOE_SIO_CANCELABLE : 0));
    } else {
        /* Call the normal routine */
        IopStartNextPacketByKey(DeviceObject, Cancelable, Key);
    }
}
