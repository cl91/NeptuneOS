#include <halp.h>
#include "coroutine.h"

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
static NTSTATUS IopServerIrpToLocal(IN PIRP_QUEUE_ENTRY QueueEntry,
				    IN PIO_REQUEST_PACKET Src)
{
    assert(QueueEntry != NULL);
    PIRP Irp = QueueEntry->Irp;
    assert(Irp != NULL);
    assert(Src != NULL);
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
    case IRP_MJ_DEVICE_CONTROL:
    {
	ULONG Ioctl = Src->Request.Parameters.DeviceIoControl.IoControlCode;
	IoStack->Parameters.DeviceIoControl.IoControlCode = Ioctl;
	IoStack->Parameters.DeviceIoControl.InputBufferLength = Src->Request.Parameters.DeviceIoControl.InputBufferLength;
	IoStack->Parameters.DeviceIoControl.OutputBufferLength = Src->Request.Parameters.DeviceIoControl.OutputBufferLength;
	ULONG SystemBufferLength = 0;
	if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
	    SystemBufferLength = max(IoStack->Parameters.DeviceIoControl.InputBufferLength,
				     IoStack->Parameters.DeviceIoControl.OutputBufferLength);
	} else {
	    /* TODO: Direct IO and Neither IO */
	    assert(FALSE);
	}
	if (SystemBufferLength != 0) {
	    Irp->AssociatedIrp.SystemBuffer = (PVOID)RtlAllocateHeap(RtlGetProcessHeap(),
								     HEAP_ZERO_MEMORY,
								     SystemBufferLength);
	    if (Irp->AssociatedIrp.SystemBuffer == NULL) {
		return STATUS_NO_MEMORY;
	    }
	    /* Copy the user input data to the system buffer if needed */
	    if (IoStack->Parameters.DeviceIoControl.InputBufferLength != 0) {
		memcpy(Irp->AssociatedIrp.SystemBuffer, Src->Request.Parameters.DeviceIoControl.InputBuffer,
		       IoStack->Parameters.DeviceIoControl.InputBufferLength);
	    }
	    QueueEntry->OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
	}
	break;
    }
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
	break;
    case IRP_MJ_DEVICE_CONTROL:
	DbgPrint("    DEVICE-CONTROL  OutputBufferLength 0x%x InputBufferLength 0x%x IoControlCode %d Type3InputBuffer %p\n",
		 Stack->Parameters.DeviceIoControl.OutputBufferLength,
		 Stack->Parameters.DeviceIoControl.InputBufferLength,
		 Stack->Parameters.DeviceIoControl.IoControlCode,
		 Stack->Parameters.DeviceIoControl.Type3InputBuffer);
	break;
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
	    ULONG Ioctl = IoStack->Parameters.DeviceIoControl.IoControlCode;
	    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
		/* Copy the system buffer back to the user output buffer if needed */
		if (IoStack->Parameters.DeviceIoControl.OutputBufferLength != 0) {
		    assert(Entry->OutputBuffer != NULL);
		    memcpy(Entry->OutputBuffer, Irp->AssociatedIrp.SystemBuffer,
			   IoStack->Parameters.DeviceIoControl.OutputBufferLength);
		}
	    } else {
		/* TODO: Direct IO and Neither IO */
		assert(FALSE);
	    }
	    if (Irp->AssociatedIrp.SystemBuffer != NULL) {
		IopFreePool(Irp->AssociatedIrp.SystemBuffer);
		Irp->AssociatedIrp.SystemBuffer = NULL;
	    }
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
 * Copy the server-side IRP to the driver-side IRP, taking care to
 * correctly convert the server-side IRP to driver-side IRP. We should
 * not run out of memory here since the incoming IRP buffer is finite.
 * If we did run out of memory what might have happened is that either
 * there is a memory leak in the driver (or ntdll.dll or hal.dll), or a
 * lower-level driver is not responding (at least not quickly enough) so
 * IRPs get piled here in its higher-level driver. Not much can be done
 * here, so we simply clean up and return error.
 */
static inline NTSTATUS IopQueueRequestIrp(IN PIO_REQUEST_PACKET SrcIrp)
{
    IopAllocateObject(QueueEntry, IRP_QUEUE_ENTRY);
    IopAllocatePoolEx(IrpObj, IRP, IRP_OBJECT_SIZE, IopFreePool(QueueEntry));
    QueueEntry->ThisIrp = SrcIrp->ThisIrp;
    QueueEntry->Irp = IrpObj;
    RET_ERR_EX(IopServerIrpToLocal(QueueEntry, SrcIrp),
	       {
		   IopFreePool(IrpObj);
		   IopFreePool(QueueEntry);
	       });
    InsertTailList(&IopIrpQueue, &QueueEntry->Link);
    return STATUS_SUCCESS;
}

VOID IopProcessIrp(OUT ULONG *pNumResponses,
		   IN ULONG NumRequests)
{
    for (ULONG i = 0; i < NumRequests; i++) {
	/* TODO: Call Fast IO routines if available */
	PIO_REQUEST_PACKET SrcIrp = &IopIncomingIrpBuffer[i];
	if (SrcIrp->Type == IrpTypeRequest) {
	    /* Allocate, queue, and populate the driver-side IRP from server-side
	     * IRP in the incoming buffer. Once this is done, the information
	     * stored in the incoming IRP buffer is copied into the IRP queue. */
	    NTSTATUS Status = IopQueueRequestIrp(SrcIrp);
	    /* If this returned error, we set the SrcIrp's ErrorStatus to
	     * inform the server that driver is unable to process this IRP. */
	    if (!NT_SUCCESS(Status)) {
		SrcIrp->ErrorStatus = Status;
	    }
	} else if (SrcIrp->Type == IrpTypeNotification) {
	    /* Process all Notifications first */
	} else {
	    assert(SrcIrp->Type == IrpTypeIoCompleted);
	    /* TODO */
	}
    }

    /* Process all queued IRP. Once processed, the IRP gets moved to the completed IRP list. */
    IopProcessIrpQueue();

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
