/*
 * FILE:            private/wdm/src/irp.c
 * PURPOSE:         Client-side IRP processing
 * NOTES:
 *
 * This file implements driver IRP processing. There are several cases that we need
 * to handle here. In the following diagrams, IncomingIoPacket refers to an IO request
 * packet from the IopIncomingIoPacketBuffer. Arrow means we are detaching the IRP
 * from the source list and adding it to the destination list. OutgoingIoPacket refers
 * to the outgoing IO packet buffer.
 *
 * Case 0 (processing a server-originated IRP, returning non-PENDING status):
 *
 * |----------|
 * | Incoming | Copy |----------| Dispatch fcn. returns   |--------------|
 * | IoPacket | ---> | IrpQueue | --------------------->  | ReplyIrpList |
 * |----------|      |----------| immed. w. non-PENDING   |--------------|
 *                                                          |
 *                                                          | Copy |----------|
 *                                                          |----> | Outgoing |
 *                                                          |      | IoPacket |
 *                                                          |      |----------|
 *                                                         \|/
 *                                                  |----------------|
 *                 (Deleted once replied to server) | CleanupIrpList |
 *                                                  |----------------|
 *
 * Case 1 (processing a server-originated IRP, saving the IRP to a driver-defined
 * queue, and returning PENDING status in the dispatch function):
 *
 * |----------|
 * | Incoming | Copy |----------| Dispatch func.
 * | IoPacket | ---> | IrpQueue | --------------> IRP is not in any list!
 * |----------|      |----------| returns PENDING
 *
 * Driver must call IoMarkIrpPending before returning. Driver must manually call
 * IoCompleteRequest later to move the IRP to the cleanup list.
 *
 * Case 2 (processing a server-originated IRP, invoking IoCallDriver on it asynchronously,
 * not expecting a reply):
 *
 * |----------|
 * | Incoming | Copy |----------| Dispatch returns PENDING      |--------------|
 * | IoPacket | ---> | IrpQueue | ----------------------------> | ReplyIrpList |
 * |----------|      |----------| IRP not marked pending and    |--------------|
 *                                has no IO completion routine    |
 *                                nor any associated IRP          |Forward  |----------|
 *                                                                |-------> | Outgoing |
 *                                                                |         | IoPacket |
 *                                                                |         |----------|
 *                                                               \|/
 *                                                         |----------------|
 *                                (Deleted once forwarded) | CleanupIrpList |
 *                                                         |----------------|
 *
 * Note: on debug build we assert if dispatch routine returns STATUS_PENDING but does
 * not mark IRP pending, or set an IO completion routine, or set an associated IRP,
 * or forward the IRP via IoCallDriver. See [1].
 *
 * Case 3 (processing a server-originated IRP, invoking IoCallDriver on it asynchronously
 * and expecting a reply):
 *
 * |----------|
 * | Incoming | Copy |----------| Dispatch returns PENDING   |--------------|
 * | IoPacket | ---> | IrpQueue | -------------------------> | ReplyIrpList |
 * |----------|      |----------| IRP has completion routine |--------------|
 *                                or associated IRP            |
 *                                                             |Forward  |----------|
 *                                                             |-------> | Outgoing |
 *                                                             |         | IoPacket |
 *                                                            \|/        |----------|
 *                                                    |----------------|
 *                                                    | PendingIrpList |
 *                                                    |----------------|
 *                                                             |
 *                                                             |
 *                              (IoCompleted message received) |
 *                                                             |
 *                                                            \|/
 *           (If completion routine returns Continue,  |----------------|
 *            IRP will be in cleanup list and deleted. | CleanupIrpList |
 *            Otherwise IRP is not in any list and     |----------------|
 *            driver must manually call IoCompleteRequest
 *            to clean it up.)
 *
 * Case 4 (processing a server-originated IRP, invoking IoCallDriver and wait synchronously):
 *
 * |----------|
 * | Incoming | Copy |----------| Dispatch ret.    |--------------|----------------------|
 * | IoPacket | ---> | IrpQueue | ---------------> | ReplyIrpList | Add IopCurrentEnv to |
 * |----------|      |----------| ASYNC_PENDING    |              |   KEVENT::EnvList    |
 *                                                 |--------------|----------------------|
 *                                                         |
 *                                                         |Forward  |----------|
 *                                                         |-------> | Outgoing |
 *                                                         |         | IoPacket |
 *                                                        \|/        |----------|
 *                                                 |----------------|
 *                                                 | PendingIrpList |
 *                                                 |----------------|
 *                                                         |
 *                          (IoCompleted message received) |
 *                                                        \|/
 *                                                   Not in any list
 *                                                  Resumes coroutine
 *
 * In this case, the driver either sets the UserEvent member of the IRP or sets an IO
 * completion routine that will signal an event object when the IRP is completed. The
 * driver then invokes IoCallDriver and waits on the event object associated with the
 * IRP. KeWaitForSingleObject adds IopCurrentEnv to KEVENT::EnvList and suspends the
 * current execution environment (ie. coroutine). The control flow is then returned
 * to the IopExecuteCoroutines function which will process the next queued execution
 * environment.
 *
 * Case 5 (calling IoCallDriver on a locally generated IRP, asynchronously):
 *
 * NewIrp |--------------|        |----------------------|          |----------------|
 *        | ReplyIrpList | -----> |   PendingIrpList?    | -------> | CleanupIrpList |
 *        |--------------|        | (skip if not needed) |   |      |----------------|
 *           |                    |----------------------|   |
 *           |---> Sent to server                 (IoCompleted message
 *                 for processing                  received and completion
 *                                                 routine returns Continue).
 *
 * If driver called IoCallDriver asynchronously, it simply inserts the NewIrp into the
 * ReplyIrpList and returns STATUS_PENDING back to whoever called it. When processing
 * the ReplyIrpList the IRP will be either inserted into PendingIrpList if a completion
 * notification from the server is needed, and CleanupIrpList if not.
 *
 * Case 6 (calling IoCallDriver on a locally generated IRP, synchronously):
 *
 *   NewIrp
 *  |----------------------|        |----------------|          |----------------|
 *  |     ReplyIrpList     | -----> | PendingIrpList | -------> | CleanupIrpList |
 *  |----------------------| |      |----------------|  |       |----------------|
 *  | Add IopCurrentEnv to | |                          |
 *  |   KEVENT::EnvList    | |---> Sent to server      (IoCompleted message
 *  |----------------------|       for processing      received and completion
 *                                                     routine returns Continue).
 *
 * Just like Case 4, the IRP will be added to the ReplyIrpList by IoCallDriver and
 * eventualy moved to the PendingIrpList. The current execution environment will be
 * suspended due to the synchronous wait.
 *
 * In all cases, for associated IRPs, if its master IRP has NotifyCompletion set, then
 * the associated IRP's NotifyCompletion state is implicitly set to TRUE, regardless
 * of whether the associated IRP itself requires completion notification. The master
 * IRP is completed only when all its associated IRPs are completed. If the master
 * IRP has NotifyCompletion == FALSE, then the associated IRPs are forwarded normally
 * as if they do not have a master IRP.
 *
 * Note a special situation in all of the cases above is that if the driver forwards
 * an IRP (whether it's the one being processed or a new IRP generated locally) to a
 * local device object. In this case all of the above still apply, with the exception
 * that when examining the ReplyList, the IRP will not be sent to the server but will
 * be detached and reinserted into the IRP queue for local processing. The dispatch
 * function for it may decide to forward it a second time, potentially to a foreign
 * driver. This can be done indefinitely. Note in this case the IO transfer type of
 * the target device must match that of the source device.
 *
 * [1] See https://community.osr.com/discussion/162053/iomarkirppending
 *  The allowed combinations of dispatch routine return status and
 *  IRP processing are
 *
 *  1) call IoMarkIrpPending, then queue the IRP to some driver-defined queue
 *     where it will be pended, then return STATUS_PENDING.
 *
 *  2) Fill Irp->IoStatus, call IoCompleteRequest, return the same
 *     status code as was set in Irp->IoStatus.Status. Note that a) you
 *     cannot touch the IRP after IoCompleteRequest and b) you cannot
 *     set Irp->IoStatus.Status to STATUS_PENDING.
 *
 *  3) "return IoCallDriver", without ever calling IoMarkIrpPending.
 *
 * See also http://www.osronline.com/article.cfm%5eid=83.htm
 */

#include <wdmp.h>
#include <scsi.h>
#include <srbhelper.h>

PIO_PACKET IopIncomingIoPacketBuffer;
PIO_PACKET IopOutgoingIoPacketBuffer;

/* List of all IRPs that can be processed immediately */
static LIST_ENTRY IopIrpQueue;
/* List of all IRPs that may require sending a reply to the server. */
static LIST_ENTRY IopReplyIrpList;
/* List of all IRPs that are waiting for a server IoCompleted message */
static LIST_ENTRY IopPendingIrpList;
/* List of all IRPs that are to be deleted */
static LIST_ENTRY IopCleanupIrpList;

/* List of signaled waitable objects. */
LIST_ENTRY IopSignaledObjectList;
/* List of execution environments that are either running or suspended. */
static LIST_ENTRY IopExecEnvList;
/* Current execution environment. It may correspond to a dispatch function
 * (IOP_DISPATCH_FUNCTION) or an IO work item. */
PIOP_EXEC_ENV IopCurrentEnv;

#if DBG
static inline BOOLEAN IrpIsInReplyList(IN PIRP Irp)
{
    return ListHasEntry(&IopReplyIrpList, &Irp->Private.Link);
}

static inline BOOLEAN IrpIsInIrpQueue(IN PIRP Irp)
{
    return ListHasEntry(&IopIrpQueue, &Irp->Private.Link);
}

static inline BOOLEAN IrpIsInPendingList(IN PIRP Irp)
{
    return ListHasEntry(&IopPendingIrpList, &Irp->Private.Link);
}

static inline BOOLEAN IrpIsInCleanupList(IN PIRP Irp)
{
    return ListHasEntry(&IopCleanupIrpList, &Irp->Private.Link);
}
#endif	/* DBG */

FORCEINLINE BOOLEAN IopIrpNeedsCompletionNotification(IN PIRP Irp)
{
    /* If the IRP is an associated IRP and the master IRP requires completion
     * notification, then the associated IRP needs notification too. */
    return Irp->Private.NotifyCompletion ||
	(Irp->MasterIrp && Irp->MasterIrp->Private.NotifyCompletion);
}

NTSTATUS IopAllocateMdl(IN PVOID Buffer,
			IN ULONG BufferLength,
			IN PULONG_PTR PfnDb,
			IN ULONG PfnCount,
			IN BOOLEAN BufferMapped,
			OUT PMDL *pMdl)
{
    assert(PfnCount);
    ULONG MdlSize = sizeof(MDL) + PfnCount * sizeof(ULONG_PTR);
    IopAllocatePool(Mdl, MDL, MdlSize);
    if (BufferMapped) {
	Mdl->MappedSystemVa = Buffer;
    }
    Mdl->ByteOffset = (ULONG_PTR)Buffer & (MDL_PFN_PAGE_SIZE(Mdl->PfnEntries[0]) - 1);
    Mdl->ByteCount = BufferLength;
    Mdl->PfnCount = PfnCount;
    memcpy(Mdl->PfnEntries, PfnDb, PfnCount * sizeof(ULONG_PTR));
    *pMdl = Mdl;
    return STATUS_SUCCESS;
}

static NTSTATUS IopMarshalIoBuffers(OUT PIRP Irp,
				    IN PIO_PACKET IoPacket,
				    IN PVOID Buffer,
				    IN ULONG BufferLength,
				    IN ULONG PfnOffset,
				    IN ULONG PfnCount,
				    IN BOOLEAN ForceBufferedIo)
{
    if (BufferLength == 0 || Buffer == NULL) {
	return STATUS_SUCCESS;
    }
    assert(PfnOffset < PAGE_SIZE);
    assert(PfnCount < PAGE_SIZE / sizeof(MWORD));
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    Irp->Flags &= ~IRP_DEALLOCATE_BUFFER;
    Irp->Flags &= ~IRP_BUFFERED_IO;
    ULONG64 DeviceFlags = IoStack->DeviceObject->Flags;
    if (DeviceFlags & DO_DIRECT_IO) {
	RET_ERR(IopAllocateMdl(Buffer, BufferLength,
			       (PULONG_PTR)((PUCHAR)IoPacket + PfnOffset), PfnCount,
			       DeviceFlags & DO_MAP_IO_BUFFER, &Irp->MdlAddress));
    } else {
	/* For both BUFFERED_IO and NEITHER_IO, we need to allocate a buffer if
	 * the buffer is embedded in the IRP. Note this can only apply to input
	 * buffer and not output buffer. */
	if ((MWORD)Buffer < PAGE_SIZE) {
	    assert((MWORD)Buffer == IoPacket->Request.InputBuffer);
	    assert(BufferLength == IoPacket->Request.InputBufferLength);
	    assert(BufferLength < IRP_DATA_BUFFER_SIZE);
	    IopAllocatePool(BufferCopy, VOID, BufferLength);
	    memcpy(BufferCopy, (PUCHAR)IoPacket + (MWORD)Buffer, BufferLength);
	    Buffer = BufferCopy;
	    Irp->Flags |= IRP_DEALLOCATE_BUFFER;
	}
	if ((DeviceFlags & DO_BUFFERED_IO) || ForceBufferedIo) {
	    Irp->Flags |= IRP_BUFFERED_IO;
	    Irp->SystemBuffer = Buffer;
	} else {
	    Irp->UserBuffer = Buffer;
	}
    }
    return STATUS_SUCCESS;
}

/*
 * This function works for both DeviceIoControl and FsContext thanks to the fact
 * that the DeviceIoControl and the FileSystemControl member of IO_STACK_LOCATION
 * are exactly the same.
 */
static NTSTATUS IopMarshalIoctlBuffers(OUT PIRP Irp,
				       IN PIO_PACKET Src)
{
    ULONG Ioctl = Src->Request.DeviceIoControl.IoControlCode;
    MWORD InputBuffer = Src->Request.InputBuffer;
    MWORD OutputBuffer = Src->Request.OutputBuffer;
    ULONG InputBufferLength = Src->Request.InputBufferLength;
    ULONG OutputBufferLength = Src->Request.OutputBufferLength;
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    IoStack->Parameters.DeviceIoControl.IoControlCode = Ioctl;
    IoStack->Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
    IoStack->Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;

    Irp->Flags &= ~IRP_DEALLOCATE_BUFFER;
    Irp->Flags &= ~IRP_BUFFERED_IO;
    ULONG SystemBufferLength = InputBufferLength;
    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
	SystemBufferLength = max(InputBufferLength, OutputBufferLength);
	if (!SystemBufferLength) {
	    return STATUS_SUCCESS;
	}
	Irp->Private.OutputBuffer = (PVOID)OutputBuffer;
	Irp->Flags |= IRP_BUFFERED_IO;
    }
    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED ||
	(InputBuffer && InputBuffer < PAGE_SIZE)) {
	IopAllocatePool(SystemBuffer, UCHAR, SystemBufferLength);
	/* Copy the user input data (if exists) to the system buffer */
	if (InputBufferLength) {
	    PUCHAR SrcBuffer;
	    if (InputBuffer < PAGE_SIZE) {
		SrcBuffer = (PUCHAR)Src + InputBuffer;
	    } else {
		SrcBuffer = (PUCHAR)InputBuffer;
	    }
	    memcpy(SystemBuffer, SrcBuffer, InputBufferLength);
	}
	if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_NEITHER) {
	    IoStack->Parameters.DeviceIoControl.Type3InputBuffer = SystemBuffer;
	} else {
	    Irp->SystemBuffer = SystemBuffer;
	}
	Irp->Flags |= IRP_DEALLOCATE_BUFFER;
    } else if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_NEITHER) {
	Irp->UserBuffer = (PVOID)OutputBuffer;
	IoStack->Parameters.DeviceIoControl.Type3InputBuffer = (PVOID)InputBuffer;
    } else {
	assert(Src->Request.Flags & IOP_IRP_OUTPUT_DIRECT_IO);
	assert(!InputBuffer || InputBuffer >= PAGE_SIZE);
	Irp->SystemBuffer = (PVOID)InputBuffer;
	/* For DIRECT_IO (METHOD_IN_DIRECT or METHOD_OUT_DIRECT), only the output
	 * buffer has the MDL generated. */
	PULONG_PTR PfnDb = (PULONG_PTR)((PUCHAR)Src + Src->Request.OutputBufferPfn);
	ULONG PfnCount = Src->Request.OutputBufferPfnCount;
	if (OutputBufferLength) {
	    RET_ERR(IopAllocateMdl((PVOID)OutputBuffer, OutputBufferLength, PfnDb,
				   PfnCount, TRUE, &Irp->MdlAddress));
	}
    }
    return STATUS_SUCCESS;
}

/*
 * This function works for both DeviceIoControl and FsContext thanks to the fact
 * that the DeviceIoControl and the FileSystemControl member of IO_STACK_LOCATION
 * are exactly the same.
 */
static VOID IopUnmarshalIoctlBuffers(IN PIRP Irp,
				     IN ULONG Ioctl,
				     IN ULONG OutputBufferLength)
{
    /* Copy the system buffer back to the user output buffer if needed. */
    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED && OutputBufferLength) {
	assert(Irp->Private.OutputBuffer != NULL);
	memcpy(Irp->Private.OutputBuffer, Irp->SystemBuffer,
	       OutputBufferLength);
    }
    /* The MDL will be freed by IoFreeIrp so we don't need to free it here. */
    if (Irp->Flags & IRP_DEALLOCATE_BUFFER) {
	if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_NEITHER) {
	    assert(Irp->CurrentLocation == Irp->StackCount + 1);
	    PIO_STACK_LOCATION IoStack = IoGetNextIrpStackLocation(Irp);
	    IopFreePool(IoStack->Parameters.DeviceIoControl.Type3InputBuffer);
	    IoStack->Parameters.DeviceIoControl.Type3InputBuffer = NULL;
	} else {
	    IopFreePool(Irp->SystemBuffer);
	    Irp->SystemBuffer = NULL;
	}
    }
}

static inline VOID IopUnmarshalIoBuffer(IN PIRP Irp)
{
    assert(Irp->CurrentLocation == Irp->StackCount + 1);
    PIO_STACK_LOCATION IoStack = IoGetNextIrpStackLocation(Irp);
    switch (IoStack->MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    {
	IopUnmarshalIoctlBuffers(Irp, IoStack->Parameters.DeviceIoControl.IoControlCode,
				 IoStack->Parameters.DeviceIoControl.OutputBufferLength);
	break;
    }
    case IRP_MJ_FILE_SYSTEM_CONTROL:
    {
	if (IoStack->MinorFunction == IRP_MN_USER_FS_REQUEST) {
	    IopUnmarshalIoctlBuffers(Irp, IoStack->Parameters.FileSystemControl.FsControlCode,
				     IoStack->Parameters.FileSystemControl.OutputBufferLength);
	}
	break;
    }
    case IRP_MJ_READ:
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_INFORMATION:
    {
	/* The MDL will be freed by IoFreeIrp so we don't need to free it here. */
	if (Irp->Flags & IRP_DEALLOCATE_BUFFER) {
	    if (Irp->Flags & IRP_BUFFERED_IO) {
		IopFreePool(Irp->SystemBuffer);
		Irp->SystemBuffer = NULL;
	    } else {
		IopFreePool(Irp->UserBuffer);
		Irp->UserBuffer = NULL;
	    }
	}
	break;
    }
    case IRP_MJ_DIRECTORY_CONTROL:
    case IRP_MJ_QUERY_INFORMATION:
    case IRP_MJ_QUERY_VOLUME_INFORMATION:
    case IRP_MJ_CREATE:
    case IRP_MJ_PNP:
    case IRP_MJ_FLUSH_BUFFERS:
    case IRP_MJ_SHUTDOWN:
    case IRP_MJ_CLEANUP:
    case IRP_MJ_POWER:
    case IRP_MJ_ADD_DEVICE:
	/* Do nothing */
	break;
    default:
	assert(FALSE);
    }
}

/*
 * Populate the local IRP object from the server IO packet
 */
static NTSTATUS IopBuildLocalIrpFromServerIoPacket(IN PIO_PACKET Src,
						   OUT PIRP *pIrp)
{
    assert(pIrp != NULL);
    assert(Src != NULL);
    assert(Src->Type == IoPacketTypeRequest);
    PDEVICE_OBJECT DeviceObject = NULL;
    PFILE_OBJECT FileObject = NULL;
    PDRIVER_OBJECT DriverObject = NULL;
    if (Src->Request.MajorFunction == IRP_MJ_ADD_DEVICE) {
	DriverObject = IopLocateDriverObject(Src->Request.AddDevice.BaseName);
	if (!DriverObject) {
	    assert(FALSE);
	    return STATUS_INTERNAL_ERROR;
	}
	GLOBAL_HANDLE PhyDevHandle = Src->Request.Device.Handle;
	IO_DEVICE_INFO PhyDevInfo = Src->Request.AddDevice.PhysicalDeviceInfo;
	/* The physical device object will have a device stack size of one. */
	DeviceObject = IopGetDeviceObjectOrCreate(PhyDevHandle, PhyDevInfo, 1, FALSE);
	if (!DeviceObject) {
	    return STATUS_NO_MEMORY;
	}
	/* The physical device object must remain valid even after this IRP is freed, so
	 * we increase its refcount. */
	ObReferenceObject(DeviceObject);
    } else {
	DeviceObject = IopGetDeviceObject(Src->Request.Device.Handle);
	if (!DeviceObject) {
	    assert(FALSE);
	    return STATUS_INVALID_HANDLE;
	}
	ObReferenceObject(DeviceObject);
	if ((Src->Request.MajorFunction == IRP_MJ_CREATE) ||
	    (Src->Request.MajorFunction == IRP_MJ_CREATE_MAILSLOT) ||
	    (Src->Request.MajorFunction == IRP_MJ_CREATE_NAMED_PIPE)) {
	    RET_ERR(IopCreateFileObject(Src, DeviceObject,
					&Src->Request.Create.FileObjectParameters,
					Src->Request.File.Handle, &FileObject));
	    /* Increase the refcount of the file object so it won't get deleted
	     * when the IRP is freed. We need the file object to stay even if
	     * the CREATE has failed. The server will send a CloseFile message
	     * when the server-side file object is being deleted. */
	    ObReferenceObject(FileObject);
	} else {
	    FileObject = IopGetFileObject(Src->Request.File.Handle);
	    if (FileObject) {
		ObReferenceObject(FileObject);
	    }
	}
    }

    DbgTrace("Populating local IRP from server IO packet %p, devobj %p, fileobj %p\n",
	     Src, DeviceObject, FileObject);
    IoDbgDumpIoPacket(Src, TRUE);
    PIRP Irp = IoAllocateIrp(DeviceObject->StackSize);
    if (!Irp) {
	*pIrp = NULL;
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* If we errored out below, the caller will need to free the allocated Irp object. */
    *pIrp = Irp;
    IoSetNextIrpStackLocation(Irp);
    Irp->Private.OriginalRequestor = Src->Request.OriginalRequestor;
    Irp->Private.Identifier = Src->Request.Identifier;
    if (Src->Request.MajorFunction == IRP_MJ_ADD_DEVICE) {
	/* Store the driver object in the IRP so later we can call the correct AddDevice. */
	assert(DriverObject);
	Irp->Tail.DriverContext[0] = DriverObject;
    }

    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    IoStack->MajorFunction = Src->Request.MajorFunction;
    IoStack->MinorFunction = Src->Request.MinorFunction;
    IoStack->Flags = Src->Request.Flags & IOP_IRP_OVERRIDE_VERIFY ?
	SL_OVERRIDE_VERIFY_VOLUME : 0;
    IoStack->Control = 0;
    IoStack->DeviceObject = DeviceObject;
    IoStack->FileObject = FileObject;
    IoStack->CompletionRoutine = NULL;
    IoStack->Context = NULL;
    /* If we have an error below, we do not need to dereference DeviceObject and
     * FileObject, because they are dereferenced by IoFreeIrp. */
    switch (Src->Request.MajorFunction) {
    case IRP_MJ_CREATE:
    {
	IopAllocateObject(SecurityContext, IO_SECURITY_CONTEXT);
	Irp->AllocationSize.QuadPart = Src->Request.Create.FileObjectParameters.AllocationSize;
	IoStack->Parameters.Create.SecurityContext = SecurityContext;
	IoStack->Parameters.Create.Options = Src->Request.Create.Options;
	IoStack->Parameters.Create.FileAttributes = Src->Request.Create.FileAttributes;
	IoStack->Parameters.Create.ShareAccess = Src->Request.Create.ShareAccess;
	IoStack->Parameters.Create.EaLength = 0;
	if (Src->Request.Create.OpenTargetDirectory) {
	    IoStack->Flags |= SL_OPEN_TARGET_DIRECTORY;
	}
	break;
    }

    case IRP_MJ_CREATE_NAMED_PIPE:
    {
	IopAllocateObject(SecurityContext, IO_SECURITY_CONTEXT);
	assert(FileObject != NULL);
	IopAllocateObjectEx(NamedPipeCreateParameters, NAMED_PIPE_CREATE_PARAMETERS,
			    IopFreePool(SecurityContext));
	Irp->AllocationSize.QuadPart = Src->Request.Create.FileObjectParameters.AllocationSize;
	IoStack->Parameters.CreatePipe.SecurityContext = SecurityContext;
	IoStack->Parameters.CreatePipe.Options = Src->Request.CreatePipe.Options;
	IoStack->Parameters.CreatePipe.Reserved = 0;
	IoStack->Parameters.CreatePipe.ShareAccess = Src->Request.CreatePipe.ShareAccess;
	*NamedPipeCreateParameters = Src->Request.CreatePipe.Parameters;
	IoStack->Parameters.CreatePipe.Parameters = NamedPipeCreateParameters;
	break;
    }

    case IRP_MJ_CREATE_MAILSLOT:
    {
	IopAllocateObject(SecurityContext, IO_SECURITY_CONTEXT);
	assert(FileObject != NULL);
	IopAllocateObjectEx(MailslotCreateParameters, MAILSLOT_CREATE_PARAMETERS,
			    IopFreePool(SecurityContext));
	Irp->AllocationSize.QuadPart = Src->Request.Create.FileObjectParameters.AllocationSize;
	IoStack->Parameters.CreateMailslot.SecurityContext = SecurityContext;
	IoStack->Parameters.CreateMailslot.Options = Src->Request.CreateMailslot.Options;
	IoStack->Parameters.CreateMailslot.Reserved = 0;
	IoStack->Parameters.CreateMailslot.ShareAccess = Src->Request.CreateMailslot.ShareAccess;
	*MailslotCreateParameters = Src->Request.CreateMailslot.Parameters;
	IoStack->Parameters.CreateMailslot.Parameters = MailslotCreateParameters;
	break;
    }

    case IRP_MJ_READ:
    {
	ULONG BufferLength = Src->Request.OutputBufferLength;
	IoStack->Parameters.Read.Length = BufferLength;
	IoStack->Parameters.Read.Key = Src->Request.Read.Key;
	IoStack->Parameters.Read.ByteOffset = Src->Request.Read.ByteOffset;
	RET_ERR(IopMarshalIoBuffers(Irp, Src, (PVOID)Src->Request.OutputBuffer,
				    BufferLength, Src->Request.OutputBufferPfn,
				    Src->Request.OutputBufferPfnCount, FALSE));
	break;
    }

    case IRP_MJ_WRITE:
    {
	ULONG BufferLength = Src->Request.InputBufferLength;
	IoStack->Parameters.Write.Length = BufferLength;
	IoStack->Parameters.Write.Key = Src->Request.Write.Key;
	IoStack->Parameters.Write.ByteOffset = Src->Request.Write.ByteOffset;
	RET_ERR(IopMarshalIoBuffers(Irp, Src, (PVOID)Src->Request.InputBuffer,
				    BufferLength, Src->Request.InputBufferPfn,
				    Src->Request.InputBufferPfnCount, FALSE));
	break;
    }

    case IRP_MJ_SET_INFORMATION:
    {
	FILE_INFORMATION_CLASS FileInfoClass = Src->Request.SetFile.FileInformationClass;
	IoStack->Parameters.SetFile.FileInformationClass = FileInfoClass;
	PFILE_OBJECT Target = NULL;
	if (FileInfoClass == FileRenameInformation || FileInfoClass == FileLinkInformation ||
	    FileInfoClass == FileMoveClusterInformation) {
	    Target = IopGetFileObject(Src->Request.SetFile.TargetDirectory);
	    if (!Target) {
		assert(FALSE);
		return STATUS_INTERNAL_ERROR;
	    }
	    IoStack->Parameters.SetFile.FileObject = Target;
	    ObReferenceObject(Target);
	}
	ULONG BufferLength = Src->Request.InputBufferLength;
	IoStack->Parameters.SetFile.Length = BufferLength;
	RET_ERR_EX(IopMarshalIoBuffers(Irp, Src, (PVOID)Src->Request.InputBuffer,
				       BufferLength, Src->Request.InputBufferPfn,
				       Src->Request.InputBufferPfnCount, TRUE),
		   if (Target) {
		       ObDereferenceObject(Target);
		   });
	if (FileInfoClass == FileRenameInformation || FileInfoClass == FileLinkInformation) {
	    PFILE_RENAME_INFORMATION RenameInfo = Irp->SystemBuffer;
	    IoStack->Parameters.SetFile.ReplaceIfExists = RenameInfo->ReplaceIfExists;
	} else if (FileInfoClass == FileMoveClusterInformation) {
	    PFILE_MOVE_CLUSTER_INFORMATION MoveClusterInfo = Irp->SystemBuffer;
	    IoStack->Parameters.SetFile.ClusterCount = MoveClusterInfo->ClusterCount;
	}
	break;
    }

    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    {
	RET_ERR(IopMarshalIoctlBuffers(Irp, Src));
	break;
    }

    case IRP_MJ_DIRECTORY_CONTROL:
    {
	switch (Src->Request.MinorFunction) {
	case IRP_MN_QUERY_DIRECTORY:
	{
	    PUNICODE_STRING FileName = ExAllocatePool(NonPagedPool, sizeof(UNICODE_STRING));
	    if (!FileName) {
		return STATUS_INSUFFICIENT_RESOURCES;
	    }
	    RET_ERR_EX(RtlpUtf8ToUnicodeString(RtlGetProcessHeap(),
					       Src->Request.QueryDirectory.FileName,
					       FileName),
		       IopFreePool(FileName));
	    Irp->SystemBuffer = Irp->UserBuffer = (PVOID)Src->Request.OutputBuffer;
	    IoStack->Parameters.QueryDirectory.FileName = FileName;
	    IoStack->Parameters.QueryDirectory.Length = Src->Request.OutputBufferLength;
	    IoStack->Parameters.QueryDirectory.FileIndex = Src->Request.QueryDirectory.FileIndex;
	    IoStack->Parameters.QueryDirectory.FileInformationClass =
		Src->Request.QueryDirectory.FileInformationClass;
	    if (Src->Request.QueryDirectory.ReturnSingleEntry) {
		IoStack->Flags |= SL_RETURN_SINGLE_ENTRY;
	    }
	    if (Src->Request.QueryDirectory.RestartScan) {
		IoStack->Flags |= SL_RESTART_SCAN;
	    }
	    break;
	}
	default:
	    UNIMPLEMENTED;
	    assert(FALSE);
	    return STATUS_NOT_IMPLEMENTED;
	}
	break;
    }

    case IRP_MJ_QUERY_INFORMATION:
    {
	Irp->SystemBuffer = Irp->UserBuffer = (PVOID)Src->Request.OutputBuffer;
	IoStack->Parameters.QueryFile.Length = Src->Request.OutputBufferLength;
	IoStack->Parameters.QueryFile.FileInformationClass =
	    Src->Request.QueryFile.FileInformationClass;
	break;
    }

    case IRP_MJ_QUERY_VOLUME_INFORMATION:
    {
	Irp->SystemBuffer = Irp->UserBuffer = (PVOID)Src->Request.OutputBuffer;
	IoStack->Parameters.QueryVolume.Length = Src->Request.OutputBufferLength;
	IoStack->Parameters.QueryVolume.FsInformationClass =
	    Src->Request.QueryVolume.FsInformationClass;
	break;
    }

    case IRP_MJ_FILE_SYSTEM_CONTROL:
    {
	switch (Src->Request.MinorFunction) {
	case IRP_MN_USER_FS_REQUEST:
	    RET_ERR(IopMarshalIoctlBuffers(Irp, Src));
	    break;
	case IRP_MN_MOUNT_VOLUME:
	    IoStack->Parameters.MountVolume.Vpb = RtlAllocateHeap(RtlGetProcessHeap(),
								  HEAP_ZERO_MEMORY,
								  sizeof(VPB));
	    if (!IoStack->Parameters.MountVolume.Vpb) {
		return STATUS_NO_MEMORY;
	    }
	    /* The storage device object will have a device stack size of one. */
	    IoStack->Parameters.MountVolume.DeviceObject =
		IopGetDeviceObjectOrCreate(Src->Request.MountVolume.StorageDevice,
					   Src->Request.MountVolume.StorageDeviceInfo,
					   1, FALSE);
	    if (!IoStack->Parameters.MountVolume.DeviceObject) {
		IopFreePool(IoStack->Parameters.MountVolume.Vpb);
		IoStack->Parameters.MountVolume.Vpb = NULL;
		return STATUS_INSUFFICIENT_RESOURCES;
	    }
	    break;
	default:
	    UNIMPLEMENTED;
	    assert(FALSE);
	    return STATUS_NOT_IMPLEMENTED;
	}
	break;
    }

    case IRP_MJ_PNP:
    {
	switch (Src->Request.MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    IoStack->Parameters.QueryDeviceRelations.Type = Src->Request.QueryDeviceRelations.Type;
	    break;

	case IRP_MN_QUERY_ID:
	    IoStack->Parameters.QueryId.IdType = Src->Request.QueryId.IdType;
	    break;

	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	case IRP_MN_QUERY_BUS_INFORMATION:
	    /* No parameters to marshal. Do nothing. */
	    break;

	case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	    if (!Src->Request.FilterResourceRequirements.ListSize) {
		Irp->IoStatus.Information = 0;
		IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList = NULL;
		break;
	    }
	    ULONG ListSize = Src->Request.FilterResourceRequirements.ListSize;
	    PIO_RESOURCE_REQUIREMENTS_LIST ResList = ExAllocatePool(NonPagedPool,
								    ListSize);
	    if (!ResList) {
		return STATUS_NO_MEMORY;
	    }
	    memcpy(ResList, Src->Request.FilterResourceRequirements.Data, ListSize);
	    IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList = ResList;
	    Irp->IoStatus.Information = (ULONG_PTR)ResList;
	    break;

	case IRP_MN_START_DEVICE:
	    if (Src->Request.StartDevice.ResourceListSize != 0) {
		IoStack->Parameters.StartDevice.AllocatedResources =
		    RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				    Src->Request.StartDevice.ResourceListSize);
		if (!IoStack->Parameters.StartDevice.AllocatedResources) {
		    return STATUS_NO_MEMORY;
		}
		memcpy(IoStack->Parameters.StartDevice.AllocatedResources,
		       Src->Request.StartDevice.Data,
		       Src->Request.StartDevice.ResourceListSize);
	    }
	    if (Src->Request.StartDevice.TranslatedListSize != 0) {
		IoStack->Parameters.StartDevice.AllocatedResourcesTranslated =
		    RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				    Src->Request.StartDevice.TranslatedListSize);
		if (!IoStack->Parameters.StartDevice.AllocatedResourcesTranslated) {
		    IopFreePool(IoStack->Parameters.StartDevice.AllocatedResources);
		    IoStack->Parameters.StartDevice.AllocatedResources = NULL;
		    return STATUS_NO_MEMORY;
		}
		memcpy(IoStack->Parameters.StartDevice.AllocatedResourcesTranslated,
		       &Src->Request.StartDevice.Data[Src->Request.StartDevice.ResourceListSize],
		       Src->Request.StartDevice.TranslatedListSize);
	    }
	    break;

	case IRP_MN_READ_CONFIG:
	case IRP_MN_WRITE_CONFIG:
	    IoStack->Parameters.ReadWriteConfig.WhichSpace =
		Src->Request.ReadWriteConfig.WhichSpace;
	    IoStack->Parameters.ReadWriteConfig.Offset =
		Src->Request.ReadWriteConfig.Offset;
	    IoStack->Parameters.ReadWriteConfig.Buffer =
		(Src->Request.MinorFunction == IRP_MN_READ_CONFIG) ?
		(PVOID)Src->Request.OutputBuffer : (PVOID)Src->Request.InputBuffer;
	    IoStack->Parameters.ReadWriteConfig.Length =
		(Src->Request.MinorFunction == IRP_MN_READ_CONFIG) ?
		Src->Request.OutputBufferLength : Src->Request.InputBufferLength;
	    break;

	default:
	    UNIMPLEMENTED;
	    assert(FALSE);
	    return STATUS_NOT_IMPLEMENTED;
	}
	break;
    }

    case IRP_MJ_POWER:
	switch (Src->Request.MinorFunction) {
	case IRP_MN_SET_POWER:
	    IoStack->Parameters.Power.Type = Src->Request.Power.Type;
	    IoStack->Parameters.Power.State = Src->Request.Power.State;
	    IoStack->Parameters.Power.ShutdownType = Src->Request.Power.ShutdownType;
	    break;

	default:
	    UNIMPLEMENTED;
	    assert(FALSE);
	    return STATUS_NOT_IMPLEMENTED;
	}
	break;

    case IRP_MJ_FLUSH_BUFFERS:
    case IRP_MJ_SHUTDOWN:
    case IRP_MJ_CLEANUP:
    case IRP_MJ_ADD_DEVICE:
	/* Do nothing */
	break;
    default:
	UNIMPLEMENTED;
	assert(FALSE);
	return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

static VOID IopPopulateLocalIrpFromServerIoResponse(OUT PIRP Irp,
						    IN PIO_COMPLETED_MESSAGE Msg)
{
    Irp->IoStatus = Msg->IoStatus;
    PIO_STACK_LOCATION Sp = IoGetCurrentIrpStackLocation(Irp);
    if (Sp->MajorFunction == IRP_MJ_READ && Sp->MinorFunction == IRP_MN_MDL) {
	assert(!Irp->UserBuffer);
	assert(!Irp->MdlAddress);
	PMDL PrevMdl = NULL;
	PIO_RESPONSE_DATA Data = (PIO_RESPONSE_DATA)&Msg->ResponseData[0];
	for (ULONG i = 0; i < Data->MdlChain.MdlCount; i++) {
	    PMDL Mdl = ExAllocatePool(NonPagedPool, sizeof(MDL));
	    if (!Mdl) {
		/* The partial MDL chain will be freed eventually when
		 * the IRP is freed (by IoFreeIrp). */
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Irp->IoStatus.Information = 0;
		break;
	    }
	    Mdl->MappedSystemVa = Data->MdlChain.Mdl[i].MappedSystemVa;
	    Mdl->ByteCount = Data->MdlChain.Mdl[i].ByteCount;
	    if (PrevMdl) {
		PrevMdl->Next = Mdl;
	    } else {
		Irp->MdlAddress = Mdl;
	    }
	    PrevMdl = Mdl;
	}
    } else if (Sp->MajorFunction == IRP_MJ_PNP &&
	       Sp->MinorFunction == IRP_MN_QUERY_DEVICE_RELATIONS) {
	if (!NT_SUCCESS(Irp->IoStatus.Status)) {
	    Irp->IoStatus.Information = 0;
	    return;
	}
	PGLOBAL_HANDLE Response = (PVOID)&Msg->ResponseData[0];
	ULONG Count = Irp->IoStatus.Information;
	ULONG Size = sizeof(DEVICE_RELATIONS) + Count * sizeof(PDEVICE_OBJECT);
	PDEVICE_RELATIONS Relations = ExAllocatePool(NonPagedPool, Size);
	if (!Relations) {
	    Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
	    Irp->IoStatus.Information = 0;
	    return;
	}
	for (ULONG i = 0; i < Count; i++) {
	    IO_DEVICE_INFO DeviceInfo = {};
	    ULONG StackSize = 0;
	    NTSTATUS Status = WdmGetDevice(Response[i], &DeviceInfo, &StackSize);
	    if (!NT_SUCCESS(Status)) {
		goto err;
	    }
	    Relations->Objects[i] = IopGetDeviceObjectOrCreate(Response[i], DeviceInfo,
							       StackSize, TRUE);
	    if (!Relations->Objects[i]) {
	    err:
		for (ULONG j = 0; j < i; j++) {
		    ObDereferenceObject(Relations->Objects[j]);
		}
		ExFreePool(Relations);
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Irp->IoStatus.Information = 0;
		return;
	    }
	}
	Relations->Count = Count;
	Irp->IoStatus.Information = (ULONG_PTR)Relations;
    }
}

NTAPI VOID IoReuseIrp(IN OUT PIRP Irp,
		      IN NTSTATUS Status)
{
    /* Make sure it's OK to reuse it */
    assert(!Irp->CancelRoutine);
    assert(!IrpIsInIrpQueue(Irp));
    assert(!IrpIsInCleanupList(Irp));
    assert(!IrpIsInPendingList(Irp));
    assert(!IrpIsInReplyList(Irp));

    /* Reinitialize the IRP */
    assert(Irp->Size == IoSizeOfIrp(Irp->StackCount));
    USHORT Size = Irp->Size;
    UCHAR StackCount = Irp->StackCount;
    RtlZeroMemory(Irp, Size);
    IoInitializeIrp(Irp, Size, StackCount);

    /* Duplicate the status */
    Irp->IoStatus.Status = Status;
}

NTAPI VOID IoFreeIrp(IN PIRP Irp)
{
    assert(Irp->Size);
    if (Irp->MasterIrp && ListHasEntry(&Irp->MasterIrp->Private.MasterPendingList,
				       &Irp->Private.AssociatedIrpLink)) {
	/* The IRP is an associated IRP of a master IRP. This can happen if the driver
	 * forwards an associated IRP without expecting a completion notification.
	 * Detach the IRP from its master. */
	RemoveEntryList(&Irp->Private.AssociatedIrpLink);
	Irp->MasterIrp = NULL;
    } else {
	/* If the IRP is a master IRP itself, detach it from all its associated IRPs. */
	LoopOverList(AssociatedIrp, &Irp->Private.MasterPendingList, IRP,
		     Private.AssociatedIrpLink) {
	    RemoveEntryList(&AssociatedIrp->Private.AssociatedIrpLink);
	    AssociatedIrp->MasterIrp = NULL;
	}
    }

    IoFreeMdl(Irp->MdlAddress);
    /* At this point the IRP should not have any IO stack locations. */
    assert(Irp->CurrentLocation == Irp->StackCount + 1);
#if DBG
    RtlZeroMemory(Irp, Irp->Size);
#endif
    ExFreePool(Irp);
}

/*
 * This will also free the memory allocated when creating the IRP
 * (in IopPopulateLocalIrpFromServerIoPacket);
 */
static VOID IopDeleteIrp(PIRP Irp)
{
    assert(Irp->CurrentLocation == Irp->StackCount + 1);
    PIO_STACK_LOCATION IoStack = IoGetNextIrpStackLocation(Irp);
    switch (IoStack->MajorFunction) {
    case IRP_MJ_CREATE:
	if (IoStack->Parameters.Create.SecurityContext) {
	    IopFreePool(IoStack->Parameters.Create.SecurityContext);
	}
	break;
    case IRP_MJ_CREATE_NAMED_PIPE:
	if (IoStack->Parameters.CreatePipe.SecurityContext) {
	    IopFreePool(IoStack->Parameters.CreatePipe.SecurityContext);
	}
	if (IoStack->Parameters.CreatePipe.Parameters) {
	    IopFreePool(IoStack->Parameters.CreatePipe.Parameters);
	}
	break;
    case IRP_MJ_CREATE_MAILSLOT:
	if (IoStack->Parameters.CreateMailslot.SecurityContext) {
	    IopFreePool(IoStack->Parameters.CreateMailslot.SecurityContext);
	}
	if (IoStack->Parameters.CreateMailslot.Parameters) {
	    IopFreePool(IoStack->Parameters.CreateMailslot.Parameters);
	}
	break;
    case IRP_MJ_SET_INFORMATION:
    {
	FILE_INFORMATION_CLASS FileInfoClass = IoStack->Parameters.SetFile.FileInformationClass;
	if (FileInfoClass == FileRenameInformation || FileInfoClass == FileLinkInformation ||
	    FileInfoClass == FileMoveClusterInformation) {
	    ObDereferenceObject(IoStack->Parameters.SetFile.FileObject);
	}
	break;
    }
    case IRP_MJ_DIRECTORY_CONTROL:
	switch (IoStack->MinorFunction) {
	case IRP_MN_QUERY_DIRECTORY:
	    if (IoStack->Parameters.QueryDirectory.FileName &&
		IoStack->Parameters.QueryDirectory.FileName->Buffer) {
		IopFreePool(IoStack->Parameters.QueryDirectory.FileName->Buffer);
	    }
	    if (IoStack->Parameters.QueryDirectory.FileName) {
		IopFreePool(IoStack->Parameters.QueryDirectory.FileName);
	    }
	    break;
	default:
	    UNIMPLEMENTED;
	    assert(FALSE);
	}
	break;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
	switch (IoStack->MinorFunction) {
	case IRP_MN_MOUNT_VOLUME:
	    /* If the driver fails the MOUNT_VOLUME IRP, we need to clean up the VPB
	     * that we have allocated before. However if the mount succeeded, the VPB
	     * should not be deleted as it has been linked with the volume devices. */
	    if (!NT_SUCCESS(Irp->IoStatus.Status) && IoStack->Parameters.MountVolume.Vpb) {
		/* Unlink the VPB from the volume device objects, if needed. */
		if (IoStack->Parameters.MountVolume.Vpb->DeviceObject) {
		    IoStack->Parameters.MountVolume.Vpb->DeviceObject->Vpb = NULL;
		    /* In this case we should dereference the DeviceObject in the VPB
		     * because we increased it when creating the IRP. Note if the mount
		     * succeeded, we should not do this as the FS driver now needs it. */
		    ObDereferenceObject(IoStack->Parameters.MountVolume.DeviceObject);
		}
		if (IoStack->Parameters.MountVolume.Vpb->RealDevice) {
		    IoStack->Parameters.MountVolume.Vpb->RealDevice->Vpb = NULL;
		}
		IopFreePool(IoStack->Parameters.MountVolume.Vpb);
	    }
	    break;
	}
	break;
    case IRP_MJ_PNP:
	switch (IoStack->MinorFunction) {
	case IRP_MN_START_DEVICE:
	    if (IoStack->Parameters.StartDevice.AllocatedResources) {
		IopFreePool(IoStack->Parameters.StartDevice.AllocatedResources);
	    }
	    if (IoStack->Parameters.StartDevice.AllocatedResourcesTranslated) {
		IopFreePool(IoStack->Parameters.StartDevice.AllocatedResourcesTranslated);
	    }
	    break;
	case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	    if (!IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList) {
		break;
	    }
	    IopFreePool(IoStack->Parameters.FilterResourceRequirements.IoResourceRequirementList);
	    break;
	default:
	    break;
	}
    default:
	break;
    }
    if (Irp->Private.LastIoStackFileObject) {
	ObDereferenceObject(Irp->Private.LastIoStackFileObject);
    }
    IoFreeIrp(Irp);
}

static VOID IopPopulateIoCompleteMessageFromIoStatus(OUT PIO_PACKET Dest,
						     IN NTSTATUS Status,
						     IN GLOBAL_HANDLE OriginalRequestor,
						     IN HANDLE IrpIdentifier)
{
    assert(Status != STATUS_ASYNC_PENDING);
    assert(Status != STATUS_PENDING);
    assert(Status != -1);
    assert(OriginalRequestor != 0);
    assert(IrpIdentifier != NULL);
    memset(Dest, 0, sizeof(IO_PACKET));
    Dest->Type = IoPacketTypeClientMessage;
    Dest->Size = sizeof(IO_PACKET);
    Dest->ClientMsg.Type = IoCliMsgIoCompleted;
    Dest->ClientMsg.IoCompleted.OriginalRequestor = OriginalRequestor;
    Dest->ClientMsg.IoCompleted.Identifier = IrpIdentifier;
    Dest->ClientMsg.IoCompleted.IoStatus.Status = Status;
}

static ULONG IopGetQueryIdResponseDataSize(IN PWSTR String,
					   IN BUS_QUERY_ID_TYPE IdType)
{
    /* For HardwareIDs and CompatibleIDs, the string is a REG_MULTI_SZ. */
    if (IdType == BusQueryHardwareIDs || IdType == BusQueryCompatibleIDs) {
	if (String[0] == L'\0') {
	    return 0;
	}
	ULONG Size = 0;
	while (TRUE) {
	    Size++;
	    if (String[0] == L'\0') {
		if (String[1] == L'\0') {
		    Size++;
		    break;
		}
	    }
	    String++;
	}
	return Size;
    } else {
	/* For UTF-16 strings that are legal device IDs its characters are
	 * always representable in two bytes. */
	return wcslen(String) + 1;
    }
}

static BOOLEAN IopPopulateIoCompleteMessageFromLocalIrp(OUT PIO_PACKET Dest,
							IN PIRP Irp,
							IN ULONG BufferSize)
{
    ULONG Size = sizeof(IO_PACKET);
    PIO_STACK_LOCATION IoSp = IoGetNextIrpStackLocation(Irp);
    assert(!IoSp->FileObject);
    PFILE_OBJECT LastIoStackFileObject = Irp->Private.LastIoStackFileObject;
    ULONG64 FileSize = 0;
    ULONG64 AllocationSize = 0;
    ULONG64 ValidDataLength = 0;
    PFSRTL_COMMON_FCB_HEADER Fcb = LastIoStackFileObject ?
	LastIoStackFileObject->FsContext : NULL;
    if (Fcb) {
	FileSize = Fcb->FileSizes.FileSize.QuadPart;
	AllocationSize = Fcb->FileSizes.AllocationSize.QuadPart;
	ValidDataLength = Fcb->FileSizes.ValidDataLength.QuadPart;
    }
    if (LastIoStackFileObject) {
	ObDereferenceObject(LastIoStackFileObject);
    }
    Irp->Private.LastIoStackFileObject = NULL;

    switch (IoSp->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_INFORMATION:
	if (NT_SUCCESS(Irp->IoStatus.Status) && Fcb) {
	    Size += sizeof(IO_RESPONSE_DATA);
	}
	break;
    case IRP_MJ_PNP:
	switch (IoSp->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		PDEVICE_RELATIONS Relations = (PVOID)Irp->IoStatus.Information;
		Size += Relations->Count * sizeof(GLOBAL_HANDLE);
	    }
	    break;

	case IRP_MN_QUERY_ID:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		Size += IopGetQueryIdResponseDataSize((PVOID)Irp->IoStatus.Information,
						      IoSp->Parameters.QueryId.IdType);
	    }
	    break;

	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		PIO_RESOURCE_REQUIREMENTS_LIST Res = (PVOID)Irp->IoStatus.Information;
		if (Res->ListSize <= MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE) {
		    assert(FALSE);
		    return FALSE;
		}
		Size += Res->ListSize;
	    }
	    break;

	case IRP_MN_QUERY_BUS_INFORMATION:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		Size += sizeof(PNP_BUS_INFORMATION);
	    }
	    break;

	case IRP_MN_START_DEVICE:
	case IRP_MN_READ_CONFIG:
	case IRP_MN_WRITE_CONFIG:
	    /* Do nothing */
	    break;

	default:
	    /* UNIMPLEMENTED */
	    assert(FALSE);
	    return FALSE;
	}
	break;

    case IRP_MJ_FILE_SYSTEM_CONTROL:
	switch (IoSp->MinorFunction) {
	case IRP_MN_USER_FS_REQUEST:
	    break;
	case IRP_MN_MOUNT_VOLUME:
	    assert(IoSp->Parameters.MountVolume.Vpb);
	    if (NT_SUCCESS(Irp->IoStatus.Status)) {
		if (!IoSp->Parameters.MountVolume.Vpb->DeviceObject) {
		    return FALSE;
		}
		Size += sizeof(IO_RESPONSE_DATA);
	    }
	    break;
	default:
	    /* UNIMPLEMENTED */
	    assert(FALSE);
	    return FALSE;
	}
	break;
    }
    if (BufferSize < Size) {
	return FALSE;
    }
    memset(Dest, 0, Size);

    Dest->Type = IoPacketTypeClientMessage;
    Dest->Size = Size;
    Dest->ClientMsg.Type = IoCliMsgIoCompleted;
    assert(Irp->Private.OriginalRequestor != 0);
    assert(Irp->Private.Identifier != NULL);
    assert(Irp->IoStatus.Status != STATUS_PENDING);
    assert(Irp->IoStatus.Status != STATUS_ASYNC_PENDING);
    Dest->ClientMsg.IoCompleted.OriginalRequestor = Irp->Private.OriginalRequestor;
    Dest->ClientMsg.IoCompleted.Identifier = Irp->Private.Identifier;
    Dest->ClientMsg.IoCompleted.IoStatus = Irp->IoStatus;

    switch (IoSp->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_INFORMATION:
	/* If the file object is part of a file system, we need to inform the
	 * server of the file size information. */
	if (NT_SUCCESS(Irp->IoStatus.Status) && Fcb) {
	    Dest->ClientMsg.IoCompleted.ResponseDataSize = sizeof(IO_RESPONSE_DATA);
	    PIO_RESPONSE_DATA Ptr = (PIO_RESPONSE_DATA)Dest->ClientMsg.IoCompleted.ResponseData;
	    Ptr->FileSizes.FileSize = FileSize;
	    Ptr->FileSizes.AllocationSize = AllocationSize;
	    Ptr->FileSizes.ValidDataLength = ValidDataLength;
	}
	break;
    case IRP_MJ_PNP:
    {
	switch (IoSp->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		/* Dest->...IoStatus.Information is DEVICE_RELATIONS.Count.
		 * ResponseData[] are the GLOBAL_HANDLE of the device objects
		 * in DEVICE_RELATIONS.Objects. */
		PDEVICE_RELATIONS Relations = (PVOID)Irp->IoStatus.Information;
		Dest->ClientMsg.IoCompleted.IoStatus.Information = Relations->Count;
		PGLOBAL_HANDLE Data = (PVOID)Dest->ClientMsg.IoCompleted.ResponseData;
		for (ULONG i = 0; i < Relations->Count; i++) {
		    Data[i] = IopGetDeviceHandle(Relations->Objects[i]);
		}
		Dest->ClientMsg.IoCompleted.ResponseDataSize = Relations->Count * sizeof(GLOBAL_HANDLE);
		IopFreePool(Relations);
		Irp->IoStatus.Information = 0;
	    }
	    break;

	case IRP_MN_QUERY_ID:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		/* ResponseData[] is the UTF-8 string of the device id.
		 * ResponseDataSize is the size of the string including terminating NUL.
		 * Dest->...IoStatus.Information is cleared. */
		PWSTR String = (PWSTR)Irp->IoStatus.Information;
		BUS_QUERY_ID_TYPE IdType = IoSp->Parameters.QueryId.IdType;
		ULONG ResponseDataSize = IopGetQueryIdResponseDataSize(String, IdType);
		Dest->ClientMsg.IoCompleted.IoStatus.Information = 0;
		Dest->ClientMsg.IoCompleted.ResponseDataSize = ResponseDataSize;
		PCHAR DestStr = (PCHAR)Dest->ClientMsg.IoCompleted.ResponseData;
		for (ULONG i = 0; i < ResponseDataSize; i++) {
		    /* A simple cast works for ASCII characters as their values are
		     * identical in both 8-bit ASCII and UCS-2 or UTF-16. */
		    DestStr[i] = (CHAR)String[i];
		}
		IopFreePool(String);
		Irp->IoStatus.Information = 0;
	    }
	    break;

	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		/* ResponseData[] is the IO_RESOURCE_REQUIREMENTS_LIST, copied verbatim.
		 * ResponseDataSize is its size in bytes.
		 * Dest->...IoStatus.Information is cleared. */
		PIO_RESOURCE_REQUIREMENTS_LIST Res = (PVOID)Irp->IoStatus.Information;
		ULONG ResponseDataSize = Res->ListSize;
		Dest->ClientMsg.IoCompleted.IoStatus.Information = 0;
		Dest->ClientMsg.IoCompleted.ResponseDataSize = ResponseDataSize;
		memcpy(Dest->ClientMsg.IoCompleted.ResponseData, Res, ResponseDataSize);
		IopFreePool(Res);
		Irp->IoStatus.Information = 0;
		if (IoSp->MinorFunction == IRP_MN_FILTER_RESOURCE_REQUIREMENTS) {
		    IoSp->Parameters.FilterResourceRequirements.IoResourceRequirementList = NULL;
		}
	    }
	    break;

	case IRP_MN_QUERY_BUS_INFORMATION:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		/* ResponseData[] is the PNP_BUS_INFORMATION, copied verbatim.
		 * ResponseDataSize is its size in bytes.
		 * Dest->...IoStatus.Information is cleared. */
		PPNP_BUS_INFORMATION Info = (PVOID)Irp->IoStatus.Information;
		ULONG ResponseDataSize = sizeof(PNP_BUS_INFORMATION);
		Dest->ClientMsg.IoCompleted.IoStatus.Information = 0;
		Dest->ClientMsg.IoCompleted.ResponseDataSize = ResponseDataSize;
		memcpy(Dest->ClientMsg.IoCompleted.ResponseData, Info, ResponseDataSize);
		IopFreePool(Info);
		Irp->IoStatus.Information = 0;
	    }
	    break;

	case IRP_MN_START_DEVICE:
	case IRP_MN_READ_CONFIG:
	case IRP_MN_WRITE_CONFIG:
	    /* Do nothing */
	    break;

	default:
	    /* UNIMPLEMENTED */
	    assert(FALSE);
	    break;
	}
	break;
    }
    case IRP_MJ_FILE_SYSTEM_CONTROL:
	switch (IoSp->MinorFunction) {
	case IRP_MN_USER_FS_REQUEST:
	    break;
	case IRP_MN_MOUNT_VOLUME:
	    if (NT_SUCCESS(Irp->IoStatus.Status)) {
		Dest->ClientMsg.IoCompleted.ResponseDataSize = sizeof(IO_RESPONSE_DATA);
		PIO_RESPONSE_DATA Ptr = (PVOID)Dest->ClientMsg.IoCompleted.ResponseData;
		Ptr->VolumeMounted.VolumeSize = IoSp->Parameters.MountVolume.Vpb->VolumeSize;
		Ptr->VolumeMounted.VolumeDeviceHandle =
		    IopGetDeviceHandle(IoSp->Parameters.MountVolume.Vpb->DeviceObject);
	    }
	    break;
	default:
	    /* UNIMPLEMENTED */
	    assert(FALSE);
	    return FALSE;
	}
	break;
    default:
	break;
    }

    /* If the IRP itself is a master IRP, set the MasterSent member of all its
     * assoicated IRPs to TRUE. */
    if (!Irp->MasterIrp) {
	LoopOverList(AssociatedIrp, &Irp->Private.MasterPendingList,
		     IRP, Private.AssociatedIrpLink) {
	    AssociatedIrp->Private.MasterIrpSent = TRUE;
	}
    }
    return TRUE;
}

static BOOLEAN IopPopulateForwardIrpMessage(IN PIO_PACKET Dest,
					    IN PIRP Irp,
					    IN ULONG BufferSize)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    assert(IoStack);
    assert(IoStack->MajorFunction <= IRP_MJ_MAXIMUM_FUNCTION);
    PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
    assert(DeviceObject != NULL);
    assert(DeviceObject->DriverObject == NULL);
    assert(DeviceObject->Header.GlobalHandle != 0);
    assert(Irp->Private.OriginalRequestor != 0);
    /* We are forwarding an IRP originated from the server,
     * simply send the ForwardIrp client message */
    if (BufferSize < sizeof(IO_PACKET)) {
	return FALSE;
    }
    memset(Dest, 0, sizeof(IO_PACKET));
    Dest->Type = IoPacketTypeClientMessage;
    Dest->Size = sizeof(IO_PACKET);
    Dest->ClientMsg.Type = IoCliMsgForwardIrp;
    Dest->ClientMsg.ForwardIrp.OriginalRequestor = Irp->Private.OriginalRequestor;
    Dest->ClientMsg.ForwardIrp.Identifier = Irp->Private.Identifier;
    Dest->ClientMsg.ForwardIrp.DeviceObject = DeviceObject->Header.GlobalHandle;
    Dest->ClientMsg.ForwardIrp.NotifyCompletion = Irp->Private.NotifyCompletion;
    Dest->ClientMsg.ForwardIrp.OverrideVerify = IoStack->Flags & SL_OVERRIDE_VERIFY_VOLUME;
    if (IoStack->MajorFunction == IRP_MJ_READ) {
	Dest->ClientMsg.ForwardIrp.NewOffset = IoStack->Parameters.Read.ByteOffset;
	Dest->ClientMsg.ForwardIrp.NewLength = IoStack->Parameters.Read.Length;
    } else if (IoStack->MajorFunction == IRP_MJ_WRITE) {
	Dest->ClientMsg.ForwardIrp.NewOffset = IoStack->Parameters.Write.ByteOffset;
	Dest->ClientMsg.ForwardIrp.NewLength = IoStack->Parameters.Write.Length;
    }
    PFSRTL_COMMON_FCB_HEADER Fcb = IoStack->FileObject ? IoStack->FileObject->FsContext : NULL;
    if (Fcb) {
	Dest->ClientMsg.ForwardIrp.NewFileSize = Fcb->FileSizes.FileSize.QuadPart;
	Dest->ClientMsg.ForwardIrp.NewAllocationSize = Fcb->FileSizes.AllocationSize.QuadPart;
	Dest->ClientMsg.ForwardIrp.NewValidDataLength = Fcb->FileSizes.ValidDataLength.QuadPart;
    }
    if (Irp->MasterIrp) {
	assert(!Irp->Private.AssociatedIrpCount);
    } else {
	/* If the IRP itself is a master IRP, set the MasterSent member of all its
	 * associated IRPs to TRUE. */
	LoopOverList(AssociatedIrp, &Irp->Private.MasterPendingList,
		     IRP, Private.AssociatedIrpLink) {
	    AssociatedIrp->Private.MasterIrpSent = TRUE;
	}
    }
    Dest->ClientMsg.ForwardIrp.AssociatedIrpCount = Irp->Private.AssociatedIrpCount;
    return TRUE;
}

static BOOLEAN IopPopulateIoRequestMessage(OUT PIO_PACKET Dest,
					   IN PIRP Irp,
					   IN ULONG BufferSize)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
    assert(DeviceObject != NULL);
    assert(DeviceObject->DriverObject == NULL);
    assert(DeviceObject->Header.GlobalHandle != 0);
    assert(IoStack);
    assert(IoStack->MajorFunction <= IRP_MJ_MAXIMUM_FUNCTION);
    assert(Irp->Private.OriginalRequestor == 0);
    ULONG Size = sizeof(IO_PACKET);
    if (BufferSize < Size) {
	return FALSE;
    }
    /* If the IRP is an associated IRP of a master IRP and the master IRP
     * has not yet been sent to the server, wait till it has. */
    if (Irp->MasterIrp && !Irp->Private.MasterIrpSent) {
	return FALSE;
    }
    memset(Dest, 0, Size);
    Dest->Type = IoPacketTypeRequest;
    Dest->Size = Size;
    Dest->Request.MajorFunction = IoStack->MajorFunction;
    Dest->Request.MinorFunction = IoStack->MinorFunction;
    Dest->Request.Device.Handle = DeviceObject->Header.GlobalHandle;
    /* Use the address of the IRP as identifier. OriginalRequestor is
     * left as NULL since the server is going to fill it. */
    Dest->Request.Identifier = Irp;
    if (Irp->MasterIrp) {
	assert(Irp->MasterIrp->Private.OriginalRequestor || Irp->Private.MasterIrpSent);
	assert(Irp->MasterIrp->Private.Identifier);
	Dest->Request.MasterIrp.OriginalRequestor = Irp->MasterIrp->Private.OriginalRequestor;
	Dest->Request.MasterIrp.Identifier = Irp->MasterIrp->Private.Identifier;
    }
    if (IopIrpNeedsCompletionNotification(Irp)) {
	Dest->Request.Flags |= IOP_IRP_NOTIFY_COMPLETION;
    }
    if (IoStack->Flags & SL_OVERRIDE_VERIFY_VOLUME) {
	Dest->Request.Flags |= IOP_IRP_OVERRIDE_VERIFY;
    }

    switch (IoStack->MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    {
	ULONG Ioctl = IoStack->Parameters.DeviceIoControl.IoControlCode;
	ULONG InputBufferLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputBufferLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
	/* Note here as opposed to Windows/ReactOS, regardless of the IO transfer type
	 * of the IOCTL code, we always use Type3InputBuffer to store the input buffer
	 * address and UserBuffer to store the output buffer (see util.c, function
	 * IoBuildDeviceIoControlRequest). This eliminates an unnecessary buffer
	 * allocation since the system will take care of properly copying/mapping
	 * the IO buffers to the target driver address space. */
	PVOID InputBuffer = IoStack->Parameters.DeviceIoControl.Type3InputBuffer;
	PVOID OutputBuffer = Irp->UserBuffer;
	Dest->Request.InputBuffer = (MWORD)InputBuffer;
	Dest->Request.OutputBuffer = (MWORD)OutputBuffer;
	Dest->Request.InputBufferLength = InputBufferLength;
	Dest->Request.OutputBufferLength = OutputBufferLength;
	Dest->Request.DeviceIoControl.IoControlCode = Ioctl;
	break;
    }
    case IRP_MJ_READ:
    {
	/* Likewise, for READ IRP we always assume NEITHER IO. */
	Dest->Request.OutputBuffer = (MWORD)Irp->UserBuffer;
	Dest->Request.OutputBufferLength = IoStack->Parameters.Read.Length;
	Dest->Request.Read.Key = IoStack->Parameters.Read.Key;
	Dest->Request.Read.ByteOffset = IoStack->Parameters.Read.ByteOffset;
	break;
    }
    case IRP_MJ_WRITE:
    {
	/* Always assume NEITHER IO. See above. */
	Dest->Request.InputBuffer = (MWORD)Irp->UserBuffer;
	Dest->Request.InputBufferLength = IoStack->Parameters.Write.Length;
	Dest->Request.Write.Key = IoStack->Parameters.Write.Key;
	Dest->Request.Write.ByteOffset = IoStack->Parameters.Write.ByteOffset;
	break;
    }
    case IRP_MJ_FLUSH_BUFFERS:
    case IRP_MJ_SHUTDOWN:
	/* Do nothing */
	break;
    case IRP_MJ_PNP:
	switch (IoStack->MinorFunction) {
	case IRP_MN_READ_CONFIG:
	case IRP_MN_WRITE_CONFIG:
	    Dest->Request.ReadWriteConfig.WhichSpace =
		IoStack->Parameters.ReadWriteConfig.WhichSpace;
	    Dest->Request.ReadWriteConfig.Offset =
		IoStack->Parameters.ReadWriteConfig.Offset;
	    if (IoStack->MinorFunction == IRP_MN_READ_CONFIG) {
		Dest->Request.OutputBuffer = (MWORD)IoStack->Parameters.ReadWriteConfig.Buffer;
		Dest->Request.OutputBufferLength = IoStack->Parameters.ReadWriteConfig.Length;
	    } else {
		Dest->Request.InputBuffer = (MWORD)IoStack->Parameters.ReadWriteConfig.Buffer;
		Dest->Request.InputBufferLength = IoStack->Parameters.ReadWriteConfig.Length;
	    }
	    break;
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    Dest->Request.QueryDeviceRelations.Type =
		IoStack->Parameters.QueryDeviceRelations.Type;
	    break;
	default:
	    assert(FALSE);
	    return FALSE;
	}
	break;
    default:
	/* UNIMPLEMENTED */
	assert(FALSE);
	return FALSE;
    }
    /* If the IRP itself is a master IRP, set the MasterSent member of all its
     * assoicated IRPs to TRUE. */
    if (!Irp->MasterIrp) {
	LoopOverList(AssociatedIrp, &Irp->Private.MasterPendingList,
		     IRP, Private.AssociatedIrpLink) {
	    AssociatedIrp->Private.MasterIrpSent = TRUE;
	}
    }
    return TRUE;
}

VOID IoDbgDumpIoStackLocation(IN PIO_STACK_LOCATION Stack)
{
#if DBG
    DbgPrint("    Major function %d.  Minor function %d.  Flags 0x%x.  Control 0x%x\n",
	     Stack->MajorFunction, Stack->MinorFunction, Stack->Flags, Stack->Control);
    DbgPrint("    DeviceObject %p(%p, ext %p, drv %p, refcount %d stacksize %d) "
	     "FileObject %p(%p, fcb %p, refcount %d) "
	     "CompletionRoutine %p Context %p\n",
	     Stack->DeviceObject, (PVOID)IopGetDeviceHandle(Stack->DeviceObject),
	     Stack->DeviceObject ? Stack->DeviceObject->DeviceExtension : NULL,
	     Stack->DeviceObject ? Stack->DeviceObject->DriverObject : NULL,
	     Stack->DeviceObject ? ObGetObjectRefCount(Stack->DeviceObject) : 0,
	     Stack->DeviceObject ? Stack->DeviceObject->StackSize : 0,
	     Stack->FileObject, (PVOID)IopGetFileHandle(Stack->FileObject),
	     Stack->FileObject ? Stack->FileObject->FsContext : NULL,
	     Stack->FileObject ? ObGetObjectRefCount(Stack->FileObject) : 0,
	     Stack->CompletionRoutine, Stack->Context);
    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
	DbgPrint("    CREATE  SecurityContext %p Options 0x%x FileAttr 0x%x "
		 "ShareAccess 0x%x EaLength %d\n",
		 Stack->Parameters.Create.SecurityContext, Stack->Parameters.Create.Options,
		 Stack->Parameters.Create.FileAttributes, Stack->Parameters.Create.ShareAccess,
		 Stack->Parameters.Create.EaLength);
	break;

    case IRP_MJ_READ:
	DbgPrint("    READ%s  Length 0x%x Key 0x%x ByteOffset 0x%llx\n",
		 Stack->MinorFunction == IRP_MN_MDL ? " MDL" : "",
		 Stack->Parameters.Read.Length,
		 Stack->Parameters.Read.Key,
		 Stack->Parameters.Read.ByteOffset.QuadPart);
	break;

    case IRP_MJ_WRITE:
	DbgPrint("    WRITE%s  Length 0x%x Key 0x%x ByteOffset 0x%llx\n",
		 Stack->MinorFunction == IRP_MN_MDL ? " MDL" : "",
		 Stack->Parameters.Write.Length,
		 Stack->Parameters.Write.Key,
		 Stack->Parameters.Write.ByteOffset.QuadPart);
	break;

    case IRP_MJ_DIRECTORY_CONTROL:
	DbgPrint("    DIRECTORY-CONTROL  ");
	switch (Stack->MinorFunction) {
	case IRP_MN_QUERY_DIRECTORY:
            DbgPrint("QUERY-DIRECTORY  FileInformationClass %d FileIndex %d "
		     "Length 0x%x FileName ",
                     Stack->Parameters.QueryDirectory.FileInformationClass,
                     Stack->Parameters.QueryDirectory.FileIndex,
		     Stack->Parameters.QueryDirectory.Length);
	    if (Stack->Parameters.QueryDirectory.FileName &&
		Stack->Parameters.QueryDirectory.FileName->Buffer &&
		Stack->Parameters.QueryDirectory.FileName->Length) {
		DbgPrint("%wZ", Stack->Parameters.QueryDirectory.FileName);
	    }
	    DbgPrint("\n");
	    break;
	default:
	    DbgPrint("UNKNOWN-MINOR-FUNCTION\n");
	}
	break;

    case IRP_MJ_QUERY_INFORMATION:
	DbgPrint("    QUERY-INFORMATION  FileInformationClass %d Length 0x%x\n",
		 Stack->Parameters.QueryFile.FileInformationClass,
		 Stack->Parameters.QueryFile.Length);
	break;

    case IRP_MJ_SET_INFORMATION:
	DbgPrint("    SET-INFORMATION  FileInformationClass %d Length 0x%x "
		 "FileObject %p(%p, fcb %p, refcount %d)",
		 Stack->Parameters.SetFile.FileInformationClass,
		 Stack->Parameters.SetFile.Length,
		 Stack->Parameters.SetFile.FileObject,
		 (PVOID)IopGetFileHandle(Stack->Parameters.SetFile.FileObject),
		 Stack->Parameters.SetFile.FileObject
		 ? Stack->Parameters.SetFile.FileObject->FsContext : NULL,
		 Stack->Parameters.SetFile.FileObject
		 ? ObGetObjectRefCount(Stack->Parameters.SetFile.FileObject) : 0);
	if (Stack->Parameters.SetFile.FileInformationClass == FileRenameInformation ||
	    Stack->Parameters.SetFile.FileInformationClass == FileLinkInformation) {
	    DbgPrint(" ReplaceIfExists %d\n", Stack->Parameters.SetFile.ReplaceIfExists);
	} else if (Stack->Parameters.SetFile.FileInformationClass == FileMoveClusterInformation) {
	    DbgPrint(" ClusterCount %d\n", Stack->Parameters.SetFile.ClusterCount);
	} else {
	    DbgPrint("\n");
	}
	break;

    case IRP_MJ_QUERY_VOLUME_INFORMATION:
	DbgPrint("    QUERY-VOLUME-INFORMATION  FsInformationClass %d Length 0x%x\n",
		 Stack->Parameters.QueryVolume.FsInformationClass,
		 Stack->Parameters.QueryVolume.Length);
	break;

    case IRP_MJ_FLUSH_BUFFERS:
	DbgPrint("    FLUSH-BUFFERS\n");
	break;

    case IRP_MJ_CLOSE:
	DbgPrint("    CLOSE\n");
	break;

    case IRP_MJ_SHUTDOWN:
	DbgPrint("    SHUTDOWN\n");
	break;

    case IRP_MJ_CLEANUP:
	DbgPrint("    CLEANUP\n");
	break;

    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
	if (Stack->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL &&
	    (DEVICE_TYPE_FROM_CTL_CODE(Stack->Parameters.DeviceIoControl.IoControlCode) ==
	     FILE_DEVICE_SCSI || !Stack->Parameters.DeviceIoControl.IoControlCode)) {
	    PSTORAGE_REQUEST_BLOCK Srb = Stack->Parameters.Scsi.Srb;
	    DbgPrint("    SCSI  SRB %p Signature 0x%x Verion 0x%x SrbLength 0x%x SrbFunction "
		     "0x%x SrbStatus 0x%x SrbFlags 0x%x\n"
		     "      RequestTag 0x%x RequestPriority 0x%x RequestAttribute 0x%x"
		     " TimeOutValue 0x%x SystemStatus 0x%x\n"
		     "      AddressOffset 0x%x NumSrbExData 0x%x DataTransferLength 0x%x"
		     " DataBuffer %p\n"
		     "      OriginalRequest %p ClassContext %p PortContext %p MiniportContext %p"
		     " NextSrb %p\n",
		     Srb, Srb->Signature, Srb->Version, Srb->SrbLength, Srb->SrbFunction,
		     Srb->SrbStatus, Srb->SrbFlags, Srb->RequestTag, Srb->RequestPriority,
		     Srb->RequestAttribute, Srb->TimeOutValue, Srb->SystemStatus,
		     Srb->AddressOffset, Srb->NumSrbExData, Srb->DataTransferLength,
		     Srb->DataBuffer, Srb->OriginalRequest, Srb->ClassContext,
		     Srb->PortContext, Srb->MiniportContext, Srb->NextSrb);

	    if (Srb->AddressOffset) {
		PSTOR_ADDRESS StorAddr = (PVOID)((PUCHAR)Srb + Srb->AddressOffset);
		if (StorAddr->Type == STOR_ADDRESS_TYPE_BTL8) {
		    DbgPrint("      BusId %d TargetId %d Lun %d\n",
			     ((PSTOR_ADDR_BTL8)StorAddr)->Path,
			     ((PSTOR_ADDR_BTL8)StorAddr)->Target,
			     ((PSTOR_ADDR_BTL8)StorAddr)->Lun);
		} else {
		    DbgPrint("      INVALID SRB ADDRESS TYPE 0x%x\n", StorAddr->Type);
		}
	    }

	    for (ULONG i = 0; i < Srb->NumSrbExData; i++) {
		ULONG Offset = Srb->SrbExDataOffset[i];
		if (Offset < sizeof(STORAGE_REQUEST_BLOCK) || Offset >= Srb->SrbLength) {
		    DbgPrint("      INVALID SRBEX DATA OFFSET [%d] 0x%x\n",
			     i, Offset);
		    continue;
		}
		PSRBEX_DATA SrbExData = (PVOID)((PUCHAR)Srb + Srb->SrbExDataOffset[i]);
		DbgPrint("      SRBEX DATA OFFSET [%d] 0x%x TYPE 0x%x LENGTH 0x%x\n",
			 i, Offset, SrbExData->Type, SrbExData->Length);
		switch (SrbExData->Type) {
		case SrbExDataTypeBidirectional:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_BIDIRECTIONAL) >
			Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB BIDIRECTIONAL DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_BIDIRECTIONAL BidData = (PVOID)SrbExData;
		    DbgPrint("        DataInTransferLength 0x%x DataInBuffer %p\n",
			     BidData->DataInTransferLength, BidData->DataInBuffer);
		    break;

		case SrbExDataTypeWmi:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_WMI) > Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB WMI DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_WMI WmiData = (PVOID)SrbExData;
		    DbgPrint("        WMISubFunction 0x%x WMIFlags 0x%x DataPath %p\n",
			     WmiData->WMISubFunction, WmiData->WMIFlags,
			     WmiData->DataPath);
		    break;

		case SrbExDataTypePower:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_POWER) > Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB POWER DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_POWER PowerData = (PVOID)SrbExData;
		    DbgPrint("        SrbPowerFlags 0x%x DevicePowerState 0x%x "
			     "PowerAction 0x%x\n",
			     PowerData->SrbPowerFlags, PowerData->DevicePowerState,
			     PowerData->PowerAction);
		    break;

		case SrbExDataTypePnP:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_PNP) > Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB PNP DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_PNP PnpData = (PVOID)SrbExData;
		    DbgPrint("        PnPSubFunction 0x%x PnPAction 0x%x SrbPnPFlags 0x%x\n",
			     PnpData->PnPSubFunction, PnpData->PnPAction,
			     PnpData->SrbPnPFlags);
		    break;

		case SrbExDataTypeScsiCdb16:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB16) >
			Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB CDB16 DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_SCSI_CDB16 Cdb16Data = (PVOID)SrbExData;
		    DbgPrint("        ScsiStatus 0x%x SenseInfoBufferLength 0x%x "
			     "CdbLength 0x%x SenseInfoBuffer %p\n",
			     Cdb16Data->ScsiStatus, Cdb16Data->SenseInfoBufferLength,
			     Cdb16Data->CdbLength, Cdb16Data->SenseInfoBuffer);
		    DbgPrint("        CDB 0x%08x 0x%08x 0x%08x 0x%08x\n",
			     ((PULONG)Cdb16Data->Cdb)[0],
			     ((PULONG)Cdb16Data->Cdb)[1],
			     ((PULONG)Cdb16Data->Cdb)[2],
			     ((PULONG)Cdb16Data->Cdb)[3]);
		    break;

		case SrbExDataTypeScsiCdb32:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB32) >
			Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB CDB32 DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_SCSI_CDB32 Cdb32Data = (PVOID)SrbExData;
		    DbgPrint("        ScsiStatus 0x%x SenseInfoBufferLength 0x%x "
			     "CdbLength 0x%x SenseInfoBuffer %p\n",
			     Cdb32Data->ScsiStatus, Cdb32Data->SenseInfoBufferLength,
			     Cdb32Data->CdbLength, Cdb32Data->SenseInfoBuffer);
		    DbgPrint("        CDB 0x%08x 0x%08x 0x%08x 0x%08x  "
			     "0x%08x 0x%08x 0x%08x 0x%08x\n",
			     ((PULONG)Cdb32Data->Cdb)[0],
			     ((PULONG)Cdb32Data->Cdb)[1],
			     ((PULONG)Cdb32Data->Cdb)[2],
			     ((PULONG)Cdb32Data->Cdb)[3],
			     ((PULONG)Cdb32Data->Cdb)[4],
			     ((PULONG)Cdb32Data->Cdb)[5],
			     ((PULONG)Cdb32Data->Cdb)[6],
			     ((PULONG)Cdb32Data->Cdb)[7]);
		    break;

		case SrbExDataTypeScsiCdbVar:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_SCSI_CDB_VAR) >
			Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB CDBVAR DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_SCSI_CDB_VAR CdbVarData = (PVOID)SrbExData;
		    DbgPrint("      ScsiStatus 0x%x SenseInfoBufferLength 0x%x "
			     "CdbLength 0x%x SenseInfoBuffer %p      CDB\n",
			     CdbVarData->ScsiStatus, CdbVarData->SenseInfoBufferLength,
			     CdbVarData->CdbLength, CdbVarData->SenseInfoBuffer);
		    for (ULONG i = 0; i < CdbVarData->CdbLength; i++) {
			DbgPrint(" 0x%x", CdbVarData->Cdb[i]);
		    }
		    break;

		case SrbExDataTypeIoInfo:
		    if (Srb->SrbExDataOffset[i] + sizeof(SRBEX_DATA_IO_INFO) >
			Srb->SrbLength) {
			DbgPrint("      NOT ENOUGH SPACE FOR SRB CDBVAR DATA [%d] 0x%x\n",
				 i, Offset);
			continue;
		    }
		    PSRBEX_DATA_IO_INFO IoInfo = (PVOID)SrbExData;
		    DbgPrint("        Flags 0x%x Key 0x%x RWLength 0x%x "
			     "IsWriteRequest %d CachePriority %d Reserved[2] 0x%x 0x%x "
			     "Reserved1[2] 0x%x 0x%x\n",
			     IoInfo->Flags, IoInfo->Key, IoInfo->RWLength,
			     IoInfo->IsWriteRequest, IoInfo->CachePriority,
			     IoInfo->Reserved[0], IoInfo->Reserved[1],
			     IoInfo->Reserved1[0], IoInfo->Reserved1[1]);
		    break;

		default:
		    UNIMPLEMENTED;
		    assert(FALSE);
		}

	    }
	} else {
	    DbgPrint("    %sDEVICE-CONTROL  IoControlCode 0x%x OutputBufferLength 0x%x "
		     "InputBufferLength 0x%x Type3InputBuffer %p\n",
		     Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL ? "" : "INTERNAL-",
		     Stack->Parameters.DeviceIoControl.IoControlCode,
		     Stack->Parameters.DeviceIoControl.OutputBufferLength,
		     Stack->Parameters.DeviceIoControl.InputBufferLength,
		     Stack->Parameters.DeviceIoControl.Type3InputBuffer);
	}
	break;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
	DbgPrint("    FILE-SYSTEM-CONTROL  ");
	switch (Stack->MinorFunction) {
	case IRP_MN_USER_FS_REQUEST:
	    DbgPrint("USER-FS-REQUEST  FsControlCode 0x%x OutputBufferLength 0x%x "
		     "InputBufferLength 0x%x Type3InputBuffer %p\n",
		     Stack->Parameters.FileSystemControl.FsControlCode,
		     Stack->Parameters.FileSystemControl.OutputBufferLength,
		     Stack->Parameters.FileSystemControl.InputBufferLength,
		     Stack->Parameters.FileSystemControl.Type3InputBuffer);
	    break;
	case IRP_MN_MOUNT_VOLUME:
	    DbgPrint("MOUNT-VOLUME Vpb %p DevObj %p\n",
		     Stack->Parameters.MountVolume.Vpb,
		     Stack->Parameters.MountVolume.DeviceObject);
	    break;
	default:
	    DbgPrint("UNKNOWN-MINOR-FUNCTION\n");
	    assert(FALSE);
	}
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
	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	    DbgPrint("    PNP  QUERY-RESOURCE-REQUIREMENTS\n");
	    break;
	case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	    DbgPrint("    PNP  FILTER-RESOURCE-REQUIREMENTS  ResourceList %p\n",
		     Stack->Parameters.FilterResourceRequirements.IoResourceRequirementList);
	    break;
	case IRP_MN_QUERY_BUS_INFORMATION:
	    DbgPrint("    PNP  QUERY-BUS-INFORMATION\n");
	    break;
	case IRP_MN_START_DEVICE:
	    DbgPrint("    PNP  START-DEVICE  AllocatedResources %p (count %d) "
		     "AllocatedResourcesTranslated %p (count %d)\n",
		     Stack->Parameters.StartDevice.AllocatedResources,
		     Stack->Parameters.StartDevice.AllocatedResources ?
		     Stack->Parameters.StartDevice.AllocatedResources->List[0].PartialResourceList.Count : 0,
		     Stack->Parameters.StartDevice.AllocatedResourcesTranslated,
		     Stack->Parameters.StartDevice.AllocatedResourcesTranslated ?
		     Stack->Parameters.StartDevice.AllocatedResourcesTranslated->List[0].PartialResourceList.Count : 0);
	    break;
	case IRP_MN_READ_CONFIG:
	case IRP_MN_WRITE_CONFIG:
	    DbgPrint("    PNP  %s-CONFIG  WhichSpace %d Buffer %p Offset 0x%x Length 0x%x\n",
		     Stack->MinorFunction == IRP_MN_READ_CONFIG ? "READ" : "WRITE",
		     Stack->Parameters.ReadWriteConfig.WhichSpace,
		     Stack->Parameters.ReadWriteConfig.Buffer,
		     Stack->Parameters.ReadWriteConfig.Offset,
		     Stack->Parameters.ReadWriteConfig.Length);
	    break;
	default:
	    DbgPrint("    PNP  UNKNOWN-MINOR-FUNCTION\n");
	    assert(FALSE);
	}
	break;
    case IRP_MJ_POWER:
	switch (Stack->MinorFunction) {
	case IRP_MN_POWER_SEQUENCE:
	    DbgPrint("    POWER  POWER-SEQUENCE %p",
		     Stack->Parameters.PowerSequence.PowerSequence);
	    if (Stack->Parameters.PowerSequence.PowerSequence) {
		DbgPrint("(%d %d %d)\n",
			 Stack->Parameters.PowerSequence.PowerSequence->SequenceD1,
			 Stack->Parameters.PowerSequence.PowerSequence->SequenceD2,
			 Stack->Parameters.PowerSequence.PowerSequence->SequenceD3);
	    } else {
		DbgPrint("\n");
	    }
	    break;
	case IRP_MN_SET_POWER:
	case IRP_MN_QUERY_POWER:
	    DbgPrint("    POWER  %s-POWER Type %d State %d PowerAction %d\n",
		     Stack->MinorFunction == IRP_MN_SET_POWER ? "SET" : "QUERY",
		     Stack->Parameters.Power.Type,
		     Stack->Parameters.Power.State.SystemState,
		     Stack->Parameters.Power.ShutdownType);
	    break;
	default:
	    DbgPrint("    POWER  UNKNOWN-MINOR-FUNCTION 0x%x\n",
		     Stack->MinorFunction);
	    assert(FALSE);
	}
	break;
    case IRP_MJ_ADD_DEVICE:
	DbgPrint("    ADD-DEVICE\n");
	break;
    default:
	DbgPrint("    UNKNOWN-MAJOR-FUNCTION\n");
	assert(FALSE);
    }
#endif
}

VOID IoDbgDumpIrp(IN PIRP Irp)
{
    DbgTrace("Dumping IRP %p type %d size %d\n", Irp, Irp->Type, Irp->Size);
    DbgPrint("    MdlAddress %p Flags 0x%08x StackCount %d CurrentLocation %d (Ptr %p)\n",
	     Irp->MdlAddress, Irp->Flags, Irp->StackCount, Irp->CurrentLocation,
	     IoGetCurrentIrpStackLocation(Irp));
    DbgPrint("    System Buffer %p User Buffer %p Completed %d AllocationSize 0x%llx\n",
	     Irp->SystemBuffer, Irp->UserBuffer, Irp->Completed,
	     Irp->AllocationSize.QuadPart);
    DbgPrint("    IO Status Block Status 0x%08x Information %p UserIosb %p UserEvent %p\n",
	     Irp->IoStatus.Status, (PVOID) Irp->IoStatus.Information,
	     Irp->UserIosb, Irp->UserEvent);
    DbgPrint("    MasterIrp %p\n", Irp->MasterIrp);
    DbgPrint("    PRIV OriginalRequestor %p Identifier %p "
	     "OutputBuffer %p NotifyCompletion %s LastIoStackFileObject %p\n",
	     (PVOID)Irp->Private.OriginalRequestor,
	     Irp->Private.Identifier, Irp->Private.OutputBuffer,
	     Irp->Private.NotifyCompletion ? "TRUE" : "FALSE",
	     Irp->Private.LastIoStackFileObject);
    DbgPrint("    PRIV AssociatedIrpCount %d MasterPendingList FL %p BL %p "
	     "AssociatedIrpLink FL %p BL %p MasterCompleted %d MasterIrpSent %d\n",
	     Irp->Private.AssociatedIrpCount, Irp->Private.MasterPendingList.Flink,
	     Irp->Private.MasterPendingList.Blink, Irp->Private.AssociatedIrpLink.Flink,
	     Irp->Private.AssociatedIrpLink.Blink, Irp->Private.MasterCompleted,
	     Irp->Private.MasterIrpSent);
    if (Irp->CurrentLocation <= Irp->StackCount && Irp->CurrentLocation >= 1) {
	IoDbgDumpIoStackLocation(IoGetCurrentIrpStackLocation(Irp));
    }
}

/*
 * The coroutine entry point for dispatch routines. This has to be FASTCALL
 * since we pass its argument in register %ecx (or %rcx in amd64).
 *
 * For details, see coroutine.h
 */
FASTCALL NTSTATUS IopCallDispatchRoutine(IN PVOID Context) /* %ecx/%rcx */
{
    assert(Context != NULL);
    PIRP Irp = (PIRP)Context;
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
    assert(DeviceObject);
    if (IoStack->MajorFunction == IRP_MJ_ADD_DEVICE) {
	PDRIVER_OBJECT DriverObject = Irp->Tail.DriverContext[0];
	assert(DriverObject);
	PDRIVER_ADD_DEVICE AddDevice = DriverObject->AddDevice;
	if (AddDevice) {
	    return AddDevice(DriverObject, IoStack->DeviceObject);
	} else {
	    Irp->IoStatus.Information = 0;
	    return Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
	}
    }
    assert(IopDeviceObjectIsLocal(DeviceObject));
    PDRIVER_DISPATCH DispatchRoutine =
	DeviceObject->DriverObject->MajorFunction[IoStack->MajorFunction];
    NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
    if (DispatchRoutine != NULL) {
	Status = DispatchRoutine(DeviceObject, Irp);
    } else {
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
    }
    return Status;
}

static VOID IopDispatchFcnExecEnvFinalizer(PIOP_EXEC_ENV Env, NTSTATUS Status);

/*
 * If the IRP has already been completed, do nothing. Otherwise complete the IRP.
 */
static VOID IopCompleteIrp(IN PIRP Irp)
{
    if (Irp->Completed) {
	return;
    }

    assert(!IrpIsInIrpQueue(Irp));
    assert(!IrpIsInCleanupList(Irp));
    assert(!IrpIsInPendingList(Irp));
    assert(!IrpIsInReplyList(Irp));

    /* If the IRP has any pending associated IRPs, stop the completion, but
     * set MasterCompleted to TRUE so when all pending associated IRPs are
     * completed, we can complete the master IRP. */
    if (!Irp->MasterIrp && !IsListEmpty(&Irp->Private.MasterPendingList)) {
	Irp->Private.MasterCompleted = TRUE;
	return;
    }

    /* If an user IO status block is specified, copy the IO status to it. */
    if (Irp->UserIosb) {
	*Irp->UserIosb = Irp->IoStatus;
    }

    /* Execute the completion routine if one is registered. If it returns
     * StopCompletion, IRP completion is halted and the IRP remains in a
     * pending state. Otherwise, IRP is completed.*/
    assert(Irp->CurrentLocation >= 1);
    assert(Irp->CurrentLocation <= Irp->StackCount);
    while (Irp->CurrentLocation <= Irp->StackCount) {
	BOOLEAN LastStack = Irp->CurrentLocation == Irp->StackCount;
	PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
	PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
	PFILE_OBJECT FileObject = IoStack->FileObject;
	IoStack->DeviceObject = NULL;
	IoStack->FileObject = NULL;
	IoSkipCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_CONTINUE_COMPLETION;
	if (IoStack->CompletionRoutine) {
	    Status = IoStack->CompletionRoutine(DeviceObject, Irp,
						IoStack->Context);
	}
	if (DeviceObject) {
	    ObDereferenceObject(DeviceObject);
	}
	if (LastStack) {
	    Irp->Private.LastIoStackFileObject = FileObject;
	} else if (FileObject) {
	    ObDereferenceObject(FileObject);
	}
	if (Status == StopCompletion) {
	    /* Check the list of execution environment and remove us so
	     * the finalizer will not try to complete the IRP. */
	    LoopOverList(Env, &IopExecEnvList, IOP_EXEC_ENV, QueueListEntry) {
		if (Env->Context == Irp) {
		    assert(Env->Finalizer == IopDispatchFcnExecEnvFinalizer);
		    Env->Context = NULL;
		}
	    }
	    return;
	}
    }

    Irp->Completed = TRUE;
    /* Move the IRP into the ReplyIrp list which will be processed at
     * the end of IopProcessIoPackets. Note in the case where the
     * completion routine returned StopCompletion, the IRP is NOT
     * moved back to the pending IRP list. It will in fact not be in
     * any of the IRP lists. The driver is responsible for storing it
     * and remembering to call IoCompleteRequest on it later. */
    InsertTailList(&IopReplyIrpList, &Irp->Private.Link);

    /* For buffered IO, we need to copy whatever data the driver
     * dispatch routine has written in the buffer we allocated
     * back to the requestor's buffer. This only applies to IRPs
     * originated from the server (not to locally generated IRPs). */
    if (Irp->Private.OriginalRequestor) {
	IopUnmarshalIoBuffer(Irp);
    }

    /* If the IRP is an associated IRP of a master IRP, detach it from
     * the master. If the master has already been marked as completed
     * and no more associated IRPs are pending, complete the master IRP. */
    if (Irp->MasterIrp) {
	PIRP MasterIrp = Irp->MasterIrp;
	Irp->MasterIrp = NULL;
	assert(ListHasEntry(&MasterIrp->Private.MasterPendingList,
			    &Irp->Private.AssociatedIrpLink));
	RemoveEntryList(&Irp->Private.AssociatedIrpLink);
	if (MasterIrp->Private.MasterCompleted &&
	    IsListEmpty(&MasterIrp->Private.MasterPendingList)) {
	    IopCompleteIrp(MasterIrp);
	}
    }

    /* If an event has been associated with the IRP, signal the event. */
    if (Irp->UserEvent) {
	KeSetEvent(Irp->UserEvent);
    }
}

static VOID IopHandleIoCompleteServerMessage(PIO_PACKET SrvMsg)
{
    assert(SrvMsg != NULL);
    assert(SrvMsg->Type == IoPacketTypeServerMessage);
    assert(SrvMsg->ServerMsg.Type == IoSrvMsgIoCompleted);
    GLOBAL_HANDLE Orig = SrvMsg->ServerMsg.IoCompleted.OriginalRequestor;
    HANDLE Id = SrvMsg->ServerMsg.IoCompleted.Identifier;
    /* Check the pending IRP list for all pending IRPs */
    LoopOverList(Irp, &IopPendingIrpList, IRP, Private.Link) {
	if (Irp->Private.OriginalRequestor == Orig && Irp->Private.Identifier == Id) {
	    /* Update the data in the local IRP with the result in the server message */
	    IopPopulateLocalIrpFromServerIoResponse(Irp, &SrvMsg->ServerMsg.IoCompleted);
	    /* Detach the IRP from the pending IRP list. */
	    RemoveEntryList(&Irp->Private.Link);
	    /* Complete the IRP. This will signal the KEVENT and wake up the execution
	     * environment suspended on it. */
	    IopCompleteIrp(Irp);
	    return;
	}
    }
    /* We should never get here. If we do, either server sent an invalid IRP
     * identifier pair or we forgot to keep some IRPs in the pending IRP list. */
    assert(FALSE);
}

static VOID IopHandleLoadDriverServerMessage(PIO_PACKET SrvMsg)
{
    assert(SrvMsg != NULL);
    assert(SrvMsg->Type == IoPacketTypeServerMessage);
    assert(SrvMsg->ServerMsg.Type == IoSrvMsgLoadDriver);
    NTSTATUS Status = IopLoadDriver(SrvMsg->ServerMsg.LoadDriver.BaseName);
    /* If we failed, we have no other option other than raising an exception. */
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
}

/*
 * Handle the CloseFile server message by simulating a locally-generated IRP call.
 * We do not notify the server of this IRP completion as server does not expect a
 * response for the CloseFile message.
 */
static VOID IopHandleCloseFileServerMessage(PIO_PACKET SrvMsg)
{
    PFILE_OBJECT FileObj = IopGetFileObject(SrvMsg->ServerMsg.CloseFile.FileObject);
    if (!FileObj) {
	assert(FALSE);
	return;
    }
    if (FileObj->Header.GlobalHandle) {
	FileObj->Header.GlobalHandle = 0;
    }
    if (!FileObj->DeviceObject) {
	assert(FALSE);
	return;
    }
    PIRP Irp = IoAllocateIrp(FileObj->DeviceObject->StackSize);
    IoSetNextIrpStackLocation(Irp);
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    Stack->DeviceObject = FileObj->DeviceObject;
    ObReferenceObject(Stack->DeviceObject);
    /* Note here we do not increase the refcount of the file object so it
     * can get deleted after the IRP_MJ_CLOSE dispatch routine returns. */
    Stack->FileObject = FileObj;
    Stack->MajorFunction = IRP_MJ_CLOSE;
    /* Note the original requestor is set to zero, so no server reply will
     * be generated. */
    InsertTailList(&IopIrpQueue, &Irp->Private.Link);
}

static VOID IopHandleCloseDeviceServerMessage(PIO_PACKET SrvMsg)
{
    PDEVICE_OBJECT DevObj = IopGetDeviceObject(SrvMsg->ServerMsg.CloseDevice.DeviceObject);
    if (!DevObj) {
	/* It is ok that the client has deleted the device object at this point.
	 * In this case we simply do nothing. */
	return;
    }
    ObDereferenceObject(DevObj);
}

static VOID IopHandleForceDismountServerMessage(PIO_PACKET SrvMsg)
{
    PDEVICE_OBJECT VolDev = IopGetDeviceObject(SrvMsg->ServerMsg.ForceDismount.VolumeDevice);
    if (!VolDev) {
	assert(FALSE);
	return;
    }
    /* TODO! */
    assert(FALSE);
}

static VOID IopDispatchFcnExecEnvFinalizer(PIOP_EXEC_ENV Env, NTSTATUS Status)
{
    assert(Status != STATUS_ASYNC_PENDING);
    DbgTrace("%s for exec env %p context %p suspended %d status 0x%08x:\n",
	     Status == STATUS_PENDING ? "Not completing IRP" : "Completing IRP",
	     Env, Env->Context, Env->Suspended, Status);
    PIRP Irp = Env->Context;
    if (!Irp) {
	return;
    }
    IoDbgDumpIrp(Irp);
    if (Status != STATUS_PENDING) {
	Irp->IoStatus.Status = Status;
	/* This will execute the completion routine of the IRP if registered,
	 * and add the IRP to either the cleanup list or the pending list,
	 * depending on the result of the completion routine. */
	IopCompleteIrp(Irp);
    }
}

/*
 * Process the IRPs queued in the IrpQueue
 */
static VOID IopProcessIrpQueue()
{
    LoopOverList(Irp, &IopIrpQueue, IRP, Private.Link) {
	DbgTrace("Processing IRP from IRP queue:\n");
	IoDbgDumpIrp(Irp);
	/* Detach the IRP from the queue. If at any point of its processing,
	 * IoCallDriver is called on this IRP, IoCallDriver will add it to
	 * either the CleanupIrp list or the PendingIrp list. */
	RemoveEntryList(&Irp->Private.Link);
	/* Allocate an execution environment for this IRP. If we run out of
	 * memory here, not much can be done, so we just stop. */
	PIOP_EXEC_ENV Env = ExAllocatePool(NonPagedPool, sizeof(IOP_EXEC_ENV));
	if (!Env) {
	    break;
	}
	/* Initialize the execution environment and add it to the list */
	Env->Context = Irp;
	Env->EntryPoint = IopCallDispatchRoutine;
	Env->Finalizer = IopDispatchFcnExecEnvFinalizer;
	InsertTailList(&IopExecEnvList, &Env->QueueListEntry);
    }
}

static VOID IopProcessSignaledObjectList()
{
    IopAcquireDpcMutex();
    LoopOverList(Object, &IopSignaledObjectList, WAITABLE_OBJECT_HEADER, QueueListEntry) {
	BOOLEAN HasEnvToWakeUp = !IsListEmpty(&Object->EnvList);
	LoopOverList(Env, &Object->EnvList, IOP_EXEC_ENV, EventLink) {
	    Env->Suspended = FALSE;
	    RemoveEntryList(&Env->EventLink);
	    /* If the object is a synchronization event, only wake up the first coroutine
	     * waiting on it. */
	    if (Object->Type == SynchronizationEvent) {
		break;
	    }
	}
	/* If the object is a synchronization event, reset the event to non-signaled state. */
	if (Object->Type == SynchronizationEvent) {
	    if (HasEnvToWakeUp) {
		RemoveEntryList(&Object->QueueListEntry);
		Object->Signaled = FALSE;
	    }
	} else {
	    assert(Object->Type == NotificationEvent);
	    /* If the object is a notification event, we should have woken up all coroutines
	     * waiting on it, but the object remains in signaled state. */
	    assert(IsListEmpty(&Object->EnvList));
	    assert(Object->Signaled);
	}
    }
    IopReleaseDpcMutex();
}

static BOOLEAN IopHasEnvToWakeUp()
{
    IopAcquireDpcMutex();
    LoopOverList(Object, &IopSignaledObjectList, WAITABLE_OBJECT_HEADER, QueueListEntry) {
	if (!IsListEmpty(&Object->EnvList)) {
	    IopReleaseDpcMutex();
	    return TRUE;
	}
    }
    IopReleaseDpcMutex();
    return FALSE;
}

static VOID IopExecuteCoroutines()
{
    LoopOverList(Env, &IopExecEnvList, IOP_EXEC_ENV, QueueListEntry) {
	DbgTrace("Processing execution environment %p context %p suspended %d:\n",
		 Env, Env->Context, Env->Suspended);
	if (Env->Suspended) {
	    continue;
	}

	NTSTATUS Status = STATUS_NTOS_BUG;
	IopCurrentEnv = Env;
	if (!Env->CoroutineStackTop) {
	    /* Find the first available coroutine stack to use */
	    PUCHAR Stack = KiGetFirstAvailableCoroutineStack();
	    /* If KiGetFirstAvailableCoroutineStack returns NULL, it means that
	     * the system is out of memory. Simply stop processing and wait for
	     * memory to become available in the future. */
	    if (Stack == NULL) {
		break;
	    }
	    Env->CoroutineStackTop = Stack;
	    /* Switch to the coroutine stack and call the dispatch routine */
	    DbgTrace("Switching to coroutine stack top %p\n", Stack);
	    PTEB Teb = NtCurrentTeb();
	    Teb->Wdm.CoroutineStackHigh = Stack;
	    Teb->Wdm.CoroutineStackLow = Stack - DRIVER_COROUTINE_STACK_COMMIT;
	    Status = KiStartCoroutine(Stack, Env->EntryPoint, Env->Context);
	    Teb->Wdm.CoroutineStackHigh = Teb->Wdm.CoroutineStackLow = NULL;
	} else {
	    /* We are resuming a coroutine suspended due to KeWaitForSingleObject. */
	    DbgTrace("Resuming coroutine stack top %p. Saved SP %p\n",
		     Env->CoroutineStackTop,
		     KiGetCoroutineSavedSP(Env->CoroutineStackTop));
	    PUCHAR Stack = Env->CoroutineStackTop;
	    PTEB Teb = NtCurrentTeb();
	    Teb->Wdm.CoroutineStackHigh = Stack;
	    Teb->Wdm.CoroutineStackLow = Stack - DRIVER_COROUTINE_STACK_COMMIT;
	    Status = KiResumeCoroutine(Env->CoroutineStackTop);
	    Teb->Wdm.CoroutineStackHigh = Teb->Wdm.CoroutineStackLow = NULL;
	}
	IopCurrentEnv = NULL;
	if (Status == STATUS_ASYNC_PENDING) {
	    /* Mark the execution environment as suspended. */
	    DbgTrace("Suspending exec env %p, coroutine stack %p, saved SP %p, "
		     "context %p\n", Env, Env->CoroutineStackTop,
		     KiGetCoroutineSavedSP(Env->CoroutineStackTop), Env->Context);
	    Env->Suspended = TRUE;
	} else {
	    /* The dispatch function returns without suspending the coroutine.
	     * Release the coroutine stack and execute the finalizer. */
	    assert(Env->CoroutineStackTop);
	    KiReleaseCoroutineStack(Env->CoroutineStackTop);
	    RemoveEntryList(&Env->QueueListEntry);
	    if (Env->Finalizer) {
		Env->Finalizer(Env, Status);
	    }
	    /* Make sure we (or the driver author) did not accidentally leave a KEVENT
	     * that was allocated on the coroutine stack in the signaled object list. */
#if DBG
	    IopAcquireDpcMutex();
	    LoopOverList(Object, &IopSignaledObjectList, WAITABLE_OBJECT_HEADER, QueueListEntry) {
		assert(!((ULONG_PTR)Object < (ULONG_PTR)Env->CoroutineStackTop &&
			 (ULONG_PTR)Object >= (ULONG_PTR)Env->CoroutineStackTop -
			 DRIVER_COROUTINE_STACK_COMMIT));
	    }
	    IopReleaseDpcMutex();
#endif
	    ExFreePool(Env);
	}
    }
}

/*
 * Allocate the local IRP object and copy the server-side IO packet to the
 * local IRP object, taking care to correctly unmarshal server data. Once
 * these are done, queue the IRP object to the IRP queue. We should not run
 * out of memory here unless either there is a memory leak in the driver
 * (or ntdll.dll or wdm.dll), or a lower-level driver is not responding
 * (at least not quickly enough) so IRPs get piled here in its higher-level
 * driver. Not much can be done in those cases, so we simply clean up and
 * return error.
 */
static inline NTSTATUS IopQueueRequestIoPacket(IN PIO_PACKET SrcIoPacket)
{
    assert(SrcIoPacket->Type == IoPacketTypeRequest);
    PIRP Irp = NULL;
    NTSTATUS Status = IopBuildLocalIrpFromServerIoPacket(SrcIoPacket, &Irp);
    if (!NT_SUCCESS(Status)) {
	IoFreeIrp(Irp);
	return Status;
    }
    InsertTailList(&IopIrpQueue, &Irp->Private.Link);
    return STATUS_SUCCESS;
}

VOID IopInitIrpProcessing()
{
    InitializeListHead(&IopIrpQueue);
    InitializeListHead(&IopReplyIrpList);
    InitializeListHead(&IopPendingIrpList);
    InitializeListHead(&IopCleanupIrpList);
    InitializeListHead(&IopExecEnvList);
}

/*
 * This is the main IO packet processing routine of the driver event loop. This
 * routine examines the incoming IO packet buffer and processes them, producing
 * the reply IO packets and sending them to the outgoing IO packet buffer. This
 * routine returns TRUE if at the end of the IO processing, there are remaining
 * outgoing IO packets waiting to be sent to the server (due to the finite size
 * of the outgoing IO packet buffer).
 */
BOOLEAN IopProcessIoPackets(OUT ULONG *pNumResponses,
			    IN ULONG NumRequests)
{
    ULONG ResponseCount = 0;
    PIO_PACKET SrcIoPacket = IopIncomingIoPacketBuffer;
    LONG RemainingBufferSize;
    PIO_PACKET DestIrp;

    for (ULONG i = 0; i < NumRequests; i++) {
	if (SrcIoPacket->Type == IoPacketTypeRequest) {
	    /* Allocate, populate, and queue the driver-side IRP from server-side
	     * IO packet in the incoming buffer. Once this is done, the information
	     * stored in the incoming IRP buffer is copied into the IRP queue. */
	    NTSTATUS Status = IopQueueRequestIoPacket(SrcIoPacket);
	    /* If this IRP cannot be processed (due to say out-of-memory), we send
	     * the IoCompleted message to inform the server now. We should never run
	     * out of outgoing packet buffer here since the outgoing buffer has the
	     * same size as the incoming buffer. */
	    if (!NT_SUCCESS(Status)) {
		/* Since all response packet has the same size we can use the array syntax */
		IopPopulateIoCompleteMessageFromIoStatus(IopOutgoingIoPacketBuffer+ResponseCount,
							 Status,
							 SrcIoPacket->Request.OriginalRequestor,
							 SrcIoPacket->Request.Identifier);
		ResponseCount++;
	    }
	} else if (SrcIoPacket->Type == IoPacketTypeServerMessage) {
	    DbgTrace("Got IoPacket type Server Message\n");
	    IoDbgDumpIoPacket(SrcIoPacket, TRUE);
	    if (SrcIoPacket->ServerMsg.Type == IoSrvMsgIoCompleted) {
		IopHandleIoCompleteServerMessage(SrcIoPacket);
	    } else if (SrcIoPacket->ServerMsg.Type == IoSrvMsgLoadDriver) {
		IopHandleLoadDriverServerMessage(SrcIoPacket);
	    } else if (SrcIoPacket->ServerMsg.Type == IoSrvMsgCacheFlushed) {
		CiHandleCacheFlushedServerMessage(SrcIoPacket);
	    } else if (SrcIoPacket->ServerMsg.Type == IoSrvMsgCloseFile) {
		IopHandleCloseFileServerMessage(SrcIoPacket);
	    } else if (SrcIoPacket->ServerMsg.Type == IoSrvMsgCloseDevice) {
		IopHandleCloseDeviceServerMessage(SrcIoPacket);
	    } else if (SrcIoPacket->ServerMsg.Type == IoSrvMsgForceDismount) {
		IopHandleForceDismountServerMessage(SrcIoPacket);
	    } else {
		DbgPrint("Invalid server message type %d\n", SrcIoPacket->ServerMsg.Type);
		assert(FALSE);
	    }
	} else {
	    DbgPrint("Invalid IO packet type %d\n", SrcIoPacket->Type);
	    assert(FALSE);
	}
	SrcIoPacket = (PIO_PACKET)((MWORD)SrcIoPacket + SrcIoPacket->Size);
    }

    /* Since the incoming buffer and outgoing buffer have the same size we should never
     * run out of outgoing buffer at this point. */
    assert(ResponseCount <= DRIVER_IO_PACKET_BUFFER_COMMIT / sizeof(IO_PACKET));
    RemainingBufferSize = DRIVER_IO_PACKET_BUFFER_COMMIT - ResponseCount*sizeof(IO_PACKET);
    DestIrp = IopOutgoingIoPacketBuffer + ResponseCount;

again:
    /* Process all queued IRP now. Once processed, the IRPs may be moved to the
     * ReplyIrpList or the CleanupIrpList, or not be part of any list. */
    IopProcessIrpQueue();
    /* The IRP queue should be empty after the queue is processed. We never leave
     * an IRP in the queue, unless we ran out of memory. */
    assert(IsListEmpty(&IopIrpQueue));

    /* Now process the IO work item queue */
    IopProcessWorkItemQueue();

    /* Check the list of signaled waitable objects and wake up the execution
     * environments suspended on them. */
    IopProcessSignaledObjectList();

    /* Process the execution environments. This is where the dispatch
     * functions and work items are actually executed. */
    IopExecuteCoroutines();

    /* Process the dirty buffer list and inform the server of them. */
    ULONG DirtyBufferMsgCount = CiProcessDirtyBufferList(RemainingBufferSize, DestIrp);
    RemainingBufferSize -= DirtyBufferMsgCount * sizeof(IO_PACKET);
    DestIrp += DirtyBufferMsgCount;
    ResponseCount += DirtyBufferMsgCount;
    assert(RemainingBufferSize > 0);
    if (RemainingBufferSize < sizeof(IO_PACKET)) {
	goto delete;
    }

    /* Process the flush cache request list and inform the server of them. */
    ULONG FlushCacheMsgCount = CiProcessFlushCacheRequestList(RemainingBufferSize, DestIrp);
    RemainingBufferSize -= FlushCacheMsgCount * sizeof(IO_PACKET);
    DestIrp += FlushCacheMsgCount;
    ResponseCount += FlushCacheMsgCount;
    assert(RemainingBufferSize > 0);
    if (RemainingBufferSize < sizeof(IO_PACKET)) {
	goto delete;
    }

    /* Move all associated IRPs to the back of the list so their master IRPs
     * get processed first. This is so that the server is informed of the
     * master IRP's identifier pair and any possible file size changes. */
    LIST_ENTRY AssociatedIrps;
    InitializeListHead(&AssociatedIrps);
    LoopOverList(Irp, &IopReplyIrpList, IRP, Private.Link) {
	if (Irp->MasterIrp && !Irp->Private.MasterIrpSent) {
	    RemoveEntryList(&Irp->Private.Link);
	    InsertTailList(&AssociatedIrps, &Irp->Private.Link);
	}
    }
    LoopOverList(Irp, &AssociatedIrps, IRP, Private.Link) {
	RemoveEntryList(&Irp->Private.Link);
	InsertTailList(&IopReplyIrpList, &Irp->Private.Link);
    }

    /* Process the ReplyIrpList which contains IRPs that may require sending
     * a reply to the server. */
    BOOLEAN RecheckReplyList = FALSE;
reply:
    LoopOverList(Irp, &IopReplyIrpList, IRP, Private.Link) {
	/* This will become FALSE if remaining size is too small for the IO packet */
	BOOLEAN Ok = TRUE;
	/* Detach this IRP from the ReplyIrp list first. We will insert it to other
	 * lists below. */
	RemoveEntryList(&Irp->Private.Link);
	if (Irp->Completed) {
	    assert(Irp->CurrentLocation == Irp->StackCount + 1);
	    /* If the IRP being completed is not locally generated, notify server
	     * that we have finished processing it. Note for IRP_MJ_CLOSE we do not
	     * notify server as the Irp->Private.OriginalRequestor is set to zero. */
	    if (Irp->Private.OriginalRequestor) {
		Ok = IopPopulateIoCompleteMessageFromLocalIrp(DestIrp, Irp,
							      RemainingBufferSize);
	    } else if (Irp->Flags & IRP_DEALLOCATE_BUFFER) {
		/* For locally generated IRPS, we need to deallocate the system buffer
		 * if previously allocated. */
		Irp->Flags &= ~IRP_DEALLOCATE_BUFFER;
		assert(Irp->SystemBuffer);
		ExFreePool(Irp->SystemBuffer);
		Irp->SystemBuffer = NULL;
	    }
	    /* Add the IRP to the cleanup list, if it's locally generated, or
	     * if the server has been notified. */
	    if (!Irp->Private.OriginalRequestor || Ok) {
		InsertTailList(&IopCleanupIrpList, &Irp->Private.Link);
		/* For locally generated IRPs, we don't need to notify server,
		 * so just continue. */
		if (!Irp->Private.OriginalRequestor) {
		    continue;
		}
	    }
	} else if (IopDeviceObjectIsLocal(IoGetCurrentIrpStackLocation(Irp)->DeviceObject)) {
	    /* If we are forwarding this IRP to a local device object, requeue it to
	     * the IRP queue. For a locally generated IRP with buffered IO, we allocate
	     * or set the system buffer. */
	    if (!Irp->Private.OriginalRequestor) {
		PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
		PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
		if (IoStack->MajorFunction == IRP_MJ_DEVICE_CONTROL ||
		    IoStack->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
		    ULONG Ioctl = IoStack->Parameters.DeviceIoControl.IoControlCode;
		    PVOID InputBuffer = IoStack->Parameters.DeviceIoControl.Type3InputBuffer;
		    PVOID OutputBuffer = Irp->UserBuffer;
		    ULONG InputLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
		    ULONG OutputLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
		    if (IoStack->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL &&
			(!Ioctl || DEVICE_TYPE_FROM_CTL_CODE(Ioctl) == FILE_DEVICE_SCSI)) {
			/* For SRBs we simply set the system buffer to UserBuffer. */
			Irp->SystemBuffer = OutputBuffer;
		    } else if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED &&
			       !(Irp->Flags & IRP_DEALLOCATE_BUFFER)) {
			if (InputBuffer && OutputBuffer && InputBuffer != OutputBuffer) {
			    /* In this case we need to allocate a system buffer. */
			    assert(!Irp->SystemBuffer);
			    assert(InputLength);
			    assert(OutputLength);
			    PVOID SystemBuffer = ExAllocatePool(NonPagedPool,
								max(InputLength, OutputLength));
			    if (!SystemBuffer) {
				Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				/* IopCompleteIrp will append this IRP to the end of the
				 * reply IRP list. This is safe even if this IRP is the
				 * last IRP in the list. */
				IopCompleteIrp(Irp);
				RecheckReplyList = TRUE;
				continue;
			    }
			    Irp->SystemBuffer = SystemBuffer;
			    Irp->Flags |= IRP_DEALLOCATE_BUFFER;
			} else if (OutputBuffer) {
			    Irp->SystemBuffer = OutputBuffer;
			} else {
			    Irp->SystemBuffer = InputBuffer;
			}
		    } else if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_IN_DIRECT ||
			       METHOD_FROM_CTL_CODE(Ioctl) == METHOD_OUT_DIRECT) {
			Irp->SystemBuffer = InputBuffer;
			if (OutputLength) {
			    Irp->MdlAddress = IoAllocateMdl(OutputBuffer,
							    OutputLength);
			    if (!Irp->MdlAddress) {
				assert(FALSE);
				Irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
				IopCompleteIrp(Irp);
				RecheckReplyList = TRUE;
				continue;
			    }
			}
		    }
		} else if (DeviceObject->Flags & DO_BUFFERED_IO) {
		    Irp->SystemBuffer = Irp->UserBuffer;
		} else if ((DeviceObject->Flags & DO_DIRECT_IO) && Irp->UserBuffer) {
		    Irp->MdlAddress = IoAllocateMdl(Irp->UserBuffer,
						    IoStack->Parameters.Read.Length);
		    if (!Irp->MdlAddress) {
			assert(FALSE);
			Irp->IoStatus.Status = STATUS_INVALID_USER_BUFFER;
			IopCompleteIrp(Irp);
			RecheckReplyList = TRUE;
			continue;
		    }
		}
	    }
	    InsertTailList(&IopIrpQueue, &Irp->Private.Link);
	    continue;
	} else {
	    if (Irp->Private.OriginalRequestor) {
		Ok = IopPopulateForwardIrpMessage(DestIrp, Irp, RemainingBufferSize);
	    } else {
		Ok = IopPopulateIoRequestMessage(DestIrp, Irp, RemainingBufferSize);
	    }
	    /* Add the IRP to either the PendingList or the CleanupList, depending on
	     * whether we expect the server to inform us of its completion. */
	    if (Ok) {
		if (IopIrpNeedsCompletionNotification(Irp)) {
		    InsertTailList(&IopPendingIrpList, &Irp->Private.Link);
		} else {
		    /* If the IRP has not been completed, advance the current IO stack
		     * location pointer as if we had implicitly completed the IRP, so
		     * IopDeleteIrp can free the full IRP correctly. */
		    if (!Irp->Completed) {
			/* LastIoStackFileObject is only set if the IRP has been completed. */
			assert(!Irp->Private.LastIoStackFileObject);
			PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
			PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
			if (DeviceObject) {
			    ObDereferenceObject(DeviceObject);
			}
			IoStack->DeviceObject = NULL;
			PFILE_OBJECT FileObject = IoStack->FileObject;
			if (FileObject) {
			    ObDereferenceObject(FileObject);
			}
			IoStack->FileObject = NULL;
			IoSkipCurrentIrpStackLocation(Irp);
		    }
		    InsertTailList(&IopCleanupIrpList, &Irp->Private.Link);
		}
	    }
	}
	if (!Ok) {
	    /* Add the IRP back to the Reply list, because we failed to process it. */
	    InsertHeadList(&IopReplyIrpList, &Irp->Private.Link);
	    continue;
	}

	assert(DestIrp->Size >= sizeof(IO_PACKET));
	assert(RemainingBufferSize >= DestIrp->Size);
	DbgTrace("Processed the following IRP from the ReplyList\n");
	IoDbgDumpIoPacket(DestIrp, TRUE);
	RemainingBufferSize -= DestIrp->Size;
	ResponseCount++;
	DestIrp = (PIO_PACKET)((PCHAR)DestIrp + DestIrp->Size);
	if (RemainingBufferSize < sizeof(IO_PACKET)) {
	    break;
	}
    }

    /* The reply IRP list might be modified by IopCompleteIrp, so recheck if needed. */
    if (RecheckReplyList) {
	RecheckReplyList = FALSE;
	goto reply;
    }

delete:
    /* Clean up the list of IRPs marked for deletion */
    LoopOverList(Irp, &IopCleanupIrpList, IRP, Private.Link) {
	RemoveEntryList(&Irp->Private.Link);
	IopDeleteIrp(Irp);
    }

    /* If there are IRPs requeued (due to them being forwarded to a local device
     * object) or waitable objects signaled, or work items queued, restart the
     * whole process again. */
    BOOLEAN WorkItemsQueued = FALSE;
    KeAcquireMutex(&IopWorkItemMutex);
    WorkItemsQueued = !IsListEmpty(&IopWorkItemQueue);
    KeReleaseMutex(&IopWorkItemMutex);

    if (!IsListEmpty(&IopIrpQueue) || IopHasEnvToWakeUp() || WorkItemsQueued) {
	goto again;
    }

    /* If any of the IRP dispatch routine or work item queued DPC, now
     * is the time to wake up the DPC thread. Note we don't care about
     * IO work items or event objects at this point because they should
     * have all been processed above. */
    NtCurrentTeb()->Wdm.IoWorkItemQueued = FALSE;
    NtCurrentTeb()->Wdm.EventSignaled = FALSE;
    IopSignalDpcNotification();

    *pNumResponses = ResponseCount;
    return !IsListEmpty(&IopReplyIrpList);
}

/*
 * Complete the IRP.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoCompleteRequest(IN PIRP Irp,
			     IN CHAR PriorityBoost)
{
    PAGED_CODE();
    DbgTrace("Completing IRP %p\n", Irp);
    IoDbgDumpIrp(Irp);
    assert(Irp != NULL);
    /* Never complete an IRP with pending status */
    assert(Irp->IoStatus.Status != STATUS_PENDING);
    assert(Irp->IoStatus.Status != STATUS_ASYNC_PENDING);
    /* -1 is an invalid NTSTATUS */
    assert(Irp->IoStatus.Status != -1);
    /* Remove the IRP pending flag */
    IoGetCurrentIrpStackLocation((Irp))->Control &= ~SL_PENDING_RETURNED;
    Irp->PriorityBoost = PriorityBoost;
    IopCompleteIrp(Irp);
}

/*
 * Cancel the IRP. A driver can only cancel the IRP that it has initiated.
 * If a driver does not own the IRP, a status is raised.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoCancelIrp(IN PIRP Irp)
{
    PAGED_CODE();
    /* UNIMPLEMENTED */
}

/*
 * Forward the IRP to the specified device object for processing. Before
 * calling this routine, the caller must set up the next IO stack location
 * appropriately, by calling either IoSkipCurrentIrpStackLocation or by
 * calling IoCopyCurrentIrpStackLocationToNext.
 *
 * If no IO completion routine is specified, the IRP object is deleted
 * immediately after it has been forwarded. If an IO completion routine is
 * specified, the IRP is saved to a pending IRP queue and will be processed
 * once the server has informed us of its completion, by which time its IO
 * completion routine will be invoke.
 *
 * A special case is when DeviceObject refers to a device object created by
 * the driver itself. In this case the dispatch routine is not sent to the
 * server and processed locally. A additional requirement in this case is
 * that the IO transfer type of the target device match that of the source
 * device.
 *
 * Note if you send associated IRPs, you must send all of them (that belong
 * to the same master IRP) before you leave the dispatch routine or the IO
 * work item. Failing to do so may lead to the master IRP being completed
 * prematurely.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoCallDriver(IN PDEVICE_OBJECT DeviceObject,
			    IN OUT PIRP Irp)
{
    PAGED_CODE();

    assert(DeviceObject);
    assert(Irp);

    IoSetNextIrpStackLocation(Irp);
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);

    DbgTrace("Forwarding Irp %p to DeviceObject %p(%p)\n", Irp,
	     DeviceObject, (PVOID)IopGetDeviceHandle(DeviceObject));
    IoDbgDumpIrp(Irp);

    /* If we are forwarding the IRP to a local device object, make sure the IO
     * transfer type of the target device match that of the source device. */
    if (IopDeviceObjectIsLocal(DeviceObject) && IoStack->DeviceObject) {
	assert((IoStack->DeviceObject->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO)) ==
	       (DeviceObject->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO)));
    }

    /* Dereference the device object since we increased its refcount when
     * putting its pointer into the IO stack location. Note this needs to
     * be done for both the skip and the copy case. */
    ObReferenceObject(DeviceObject);
    if (IoStack->DeviceObject) {
	ObDereferenceObject(IoStack->DeviceObject);
    }
    IoStack->DeviceObject = DeviceObject;

    /* Add the IRP to the ReplyList which we will examine towards the end of
     * the IRP processing. If the IRP is forwarded to a foreign driver, it
     * will be sent to the server. If it is forwarded to a local device object,
     * it will be moved to the IRP queue for local processing. The IRP must not
     * already have been in any IRP list. */
    assert(!IrpIsInIrpQueue(Irp));
    assert(!IrpIsInCleanupList(Irp));
    assert(!IrpIsInPendingList(Irp));
    assert(!IrpIsInReplyList(Irp));
    InsertTailList(&IopReplyIrpList, &Irp->Private.Link);

    /* If we are forwarding the IRP synchronously, or if an IO completion routine
     * has been set, then we ask the server to notify us so we can either signal
     * the event or run the IO completion routine. */
    Irp->Private.NotifyCompletion = (Irp->UserEvent || IoStack->CompletionRoutine);

    /* If the IRP is locally generated, set its server-side identifier to the
     * local address of the IRP. */
    if (!Irp->Private.Identifier) {
	Irp->Private.Identifier = Irp;
    }

    /* If the IRP has specified a master IRP, add us as its associated IRP. */
    if (Irp->MasterIrp) {
	/* We don't support forwarding associated IRPs in the DPC or ISR thread. */
	assert(IoThreadIsAtPassiveLevel());
	assert(!ListHasEntry(&Irp->MasterIrp->Private.MasterPendingList,
			     &Irp->Private.AssociatedIrpLink));
	Irp->MasterIrp->Private.AssociatedIrpCount++;
	InsertTailList(&Irp->MasterIrp->Private.MasterPendingList,
		       &Irp->Private.AssociatedIrpLink);
    }

    return STATUS_PENDING;
}
