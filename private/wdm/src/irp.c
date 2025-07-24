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
 * Case 4 (processing a server-originated IRP, invoking IoCallDriver on it synchronously):
 *
 * |----------|
 * | Incoming | Copy |----------| Dispatch ret.    |--------------|---------------------|
 * | IoPacket | ---> | IrpQueue | ---------------> | ReplyIrpList | Private.EnvToWakeUp |
 * |----------|      |----------| ASYNC_PENDING    |              | = IopCurrentEnv     |
 *                                                 |--------------|---------------------|
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
 * What happens in this situation (invoking IoCallDriver on an IRP synchronously) is
 * that IoCallDriver records the IopCurrentEnv in Irp->Private.EnvToWakeUp and suspends
 * the current execution environment (ie. coroutine). The control flow is then returned
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
 *  |---------------------|        |----------------|          |----------------|
 *  |     ReplyIrpList    | -----> | PendingIrpList | -------> | CleanupIrpList |
 *  |---------------------| |      |----------------|  |       |----------------|
 *  | Private.EnvToWakeUp | |                          |
 *  | = IopCurrentEnv     | |---> Sent to server      (IoCompleted message
 *  |---------------------|       for processing      received and completion
 *                                                    routine returns Continue).
 *
 * Just like Case 4, the private member EnvToWakeUp of the IRP will be used to wake
 * up the execution environment that was suspended due to the synchronous wait. In
 * this particular case where we synchronously forward a locally generated new IRP
 * (as opposed to Case 4 which is synchronous forward of a server-originated IRP),
 * the private member ExecEnv of the IRP will be different from EnvToWakeUp. This
 * allows us to distinguish these two cases.
 *
 * For associated IRPs, if its master IRP has NotifyCompletion == TRUE, then the
 * associated IRP's NotifyCompletion state is implicitly set to TRUE, regardless of
 * whether the associated IRP itself requires completion notification. The master
 * IRP is completed only when all its associated IRPs are completed. If the master
 * IRP has NotifyCompletion == FALSE, then the associated IRPs are forwarded normally
 * as if they do not have a master IRP.
 *
 * Note a special situation in all of the cases above is that if the driver forwards
 * an IRP (whether it's the one being processed or a new IRP generated locally) to a
 * local device object. In this case all of the above still apply, with the exception
 * that when examining the ReplyList, the IRP will not be sent to the server but
 * will be detached and reinserted into the IRP queue for local processing. The
 * dispatch function for it may decide to forward it a second time, potentially
 * to a foreign driver. This can be done indefinitely. However since on Neptune OS
 * the IO stack size is always one, there can only be one IO completion routine
 * set for an IRP, and once forwarded, the original device object of the IO stack
 * is overwritten with the device object that the IRP is forwarded to. The dispatch
 * function for the IRP will not be able to retrieve the original device object from
 * the IRP. Drivers that forward IRPs back to its local device objects need to be
 * aware of this issue and store the original device object appropriately if needed.
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
#include "coroutine.h"
#include "debug.h"
#include "ntddk.h"
#include "ntioapi.h"
#include "ntstatus.h"
#include "util.h"
#include "wdmsvc.h"

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

/* List of execution environments that are either running or suspended. */
static LIST_ENTRY IopExecEnvList;
/* Current execution environment. This may be a dispatch function
 * (IOP_DISPATCH_FUNCTION) or an IO work item. */
PIOP_EXEC_ENV IopCurrentEnv;
/* Used for saving the Irp->Private.EnvToWakeUp member when the driver
 * calls IoCallDriver synchronously. */
PIOP_EXEC_ENV IopOldEnvToWakeUp;

/* List of all file objects created by this driver */
LIST_ENTRY IopFileObjectList;

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

static NTSTATUS IopAllocateMdl(IN PVOID Buffer,
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
	    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
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
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
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
    case IRP_MJ_CLEANUP:
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
static NTSTATUS IopPopulateLocalIrpFromServerIoPacket(OUT PIRP Irp,
						      IN PIO_PACKET Src)
{
    assert(Irp != NULL);
    assert(Src != NULL);
    assert(Src->Type == IoPacketTypeRequest);
    PDEVICE_OBJECT DeviceObject = NULL;
    PFILE_OBJECT FileObject = NULL;
    if (Src->Request.MajorFunction == IRP_MJ_ADD_DEVICE) {
	PDRIVER_OBJECT DriverObject = IopLocateDriverObject(Src->Request.AddDevice.BaseName);
	if (!DriverObject) {
	    assert(FALSE);
	    return STATUS_INTERNAL_ERROR;
	}
	GLOBAL_HANDLE PhyDevHandle = Src->Request.Device.Handle;
	IO_DEVICE_INFO PhyDevInfo = Src->Request.AddDevice.PhysicalDeviceInfo;
	DeviceObject = IopGetDeviceObjectOrCreate(PhyDevHandle, PhyDevInfo);
	if (!DeviceObject) {
	    return STATUS_NO_MEMORY;
	}
	/* The physical device object must remain valid even after this IRP is freed, so
	 * we increase its refcount. */
	ObReferenceObject(DeviceObject);
	/* Store the driver object in the IRP so later we can call the correct AddDevice. */
	Irp->Tail.DriverContext[0] = DriverObject;
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
    IoInitializeIrp(Irp);

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
	    PUNICODE_STRING FileName = ExAllocatePool(sizeof(UNICODE_STRING));
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
	    IoStack->Parameters.MountVolume.DeviceObject =
		IopGetDeviceObjectOrCreate(Src->Request.MountVolume.StorageDevice,
					   Src->Request.MountVolume.StorageDeviceInfo);
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
	    /* No parameters to marshal. Do nothing. */
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

	default:
	    UNIMPLEMENTED;
	    assert(FALSE);
	    return STATUS_NOT_IMPLEMENTED;
	}
	break;
    }
    case IRP_MJ_FLUSH_BUFFERS:
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
	    PMDL Mdl = ExAllocatePool(sizeof(MDL));
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
    }
}

/*
 * This will also free the memory allocated when creating the IRP
 * (in IopPopulateLocalIrpFromServerIoPacket);
 */
static VOID IopDeleteIrp(PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
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
	}
	break;
    default:
	break;
    }
    if (Irp->MasterIrp) {
	/* The IRP is an associated IRP of a master IRP. This can happen if the driver
	 * forwards an associated IRP without expecting a completion notification.
	 * Detach the IRP from its master. */
	assert(ListHasEntry(&Irp->MasterIrp->Private.AssociatedIrp.PendingList,
			    &Irp->Private.AssociatedIrp.Link));
	RemoveEntryList(&Irp->Private.AssociatedIrp.Link);
	Irp->MasterIrp = NULL;
    } else {
	/* If the IRP is a master IRP itself, detach it from all its associated IRPs. */
	LoopOverList(AssociatedIrp, &Irp->Private.AssociatedIrp.PendingList, IRP,
		     Private.AssociatedIrp.Link) {
	    RemoveEntryList(&AssociatedIrp->Private.AssociatedIrp.Link);
	    InitializeListHead(&AssociatedIrp->Private.AssociatedIrp.PendingList);
	    AssociatedIrp->MasterIrp = NULL;
	}
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

static BOOLEAN IopPopulateIoCompleteMessageFromLocalIrp(OUT PIO_PACKET Dest,
							IN PIRP Irp,
							IN ULONG BufferSize)
{
    ULONG Size = sizeof(IO_PACKET);
    PIO_STACK_LOCATION IoSp = IoGetCurrentIrpStackLocation(Irp);
    switch (IoSp->MajorFunction) {
    case IRP_MJ_CREATE:
	assert(IoSp->FileObject);
	if (NT_SUCCESS(Irp->IoStatus.Status) && IoSp->FileObject->FsContext) {
	    Size += sizeof(IO_RESPONSE_DATA);
	}
	break;
    case IRP_MJ_PNP:
	switch (IoSp->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
		Size += Relations->Count * sizeof(GLOBAL_HANDLE);
	    }
	    break;

	case IRP_MN_QUERY_ID:
	    /* For UTF-16 strings that are legal device IDs its characters are always within ASCII */
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		Size += wcslen((PWSTR)Irp->IoStatus.Information) + 1;
	    }
	    break;

	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		PIO_RESOURCE_REQUIREMENTS_LIST Res = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
		if (Res->ListSize <= MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE) {
		    assert(FALSE);
		    return FALSE;
		}
		Size += Res->ListSize;
	    }
	    break;

	case IRP_MN_START_DEVICE:
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
	if (NT_SUCCESS(Irp->IoStatus.Status) && IoSp->FileObject && IoSp->FileObject->FsContext) {
	    Dest->ClientMsg.IoCompleted.ResponseDataSize = sizeof(IO_RESPONSE_DATA);
	    PIO_RESPONSE_DATA Ptr = (PIO_RESPONSE_DATA)Dest->ClientMsg.IoCompleted.ResponseData;
	    PFSRTL_COMMON_FCB_HEADER Fcb = IoSp->FileObject->FsContext;
	    Ptr->FileSizes.FileSize = Fcb->FileSizes.FileSize.QuadPart;
	    Ptr->FileSizes.AllocationSize = Fcb->FileSizes.AllocationSize.QuadPart;
	    Ptr->FileSizes.ValidDataLength = Fcb->FileSizes.ValidDataLength.QuadPart;
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
		PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
		Dest->ClientMsg.IoCompleted.IoStatus.Information = Relations->Count;
		PGLOBAL_HANDLE Data = (PGLOBAL_HANDLE)Dest->ClientMsg.IoCompleted.ResponseData;
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
		ULONG ResponseDataSize = wcslen(String) + 1;
		Dest->ClientMsg.IoCompleted.IoStatus.Information = 0;
		Dest->ClientMsg.IoCompleted.ResponseDataSize = ResponseDataSize;
		PCHAR DestStr = (PCHAR)Dest->ClientMsg.IoCompleted.ResponseData;
		for (ULONG i = 0; i < ResponseDataSize; i++) {
		    DestStr[i] = (CHAR)String[i];
		}
		IopFreePool(String);
		Irp->IoStatus.Information = 0;
	    }
	    break;

	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	    if (NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Information) {
		/* ResponseData[] is the IO_RESOURCE_REQUIREMENTS_LIST, copied verbatim.
		 * ResponseDataSize is its size in bytes.
		 * Dest->...IoStatus.Information is cleared. */
		PIO_RESOURCE_REQUIREMENTS_LIST Res = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
		ULONG ResponseDataSize = Res->ListSize;
		Dest->ClientMsg.IoCompleted.IoStatus.Information = 0;
		Dest->ClientMsg.IoCompleted.ResponseDataSize = ResponseDataSize;
		memcpy(Dest->ClientMsg.IoCompleted.ResponseData, Res, ResponseDataSize);
		IopFreePool(Res);
		Irp->IoStatus.Information = 0;
	    }
	    break;

	case IRP_MN_START_DEVICE:
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
		PIO_RESPONSE_DATA Ptr = (PIO_RESPONSE_DATA)Dest->ClientMsg.IoCompleted.ResponseData;
		Ptr->VolumeMounted.VolumeSize = IoSp->Parameters.MountVolume.Vpb->VolumeSize;
		Ptr->VolumeMounted.ClusterSize = IoSp->Parameters.MountVolume.Vpb->ClusterSize;
		Ptr->VolumeMounted.VolumeDeviceHandle = IopGetDeviceHandle(IoSp->Parameters.MountVolume.Vpb->DeviceObject);
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
	LoopOverList(AssociatedIrp, &Irp->Private.AssociatedIrp.PendingList,
		     IRP, Private.AssociatedIrp.Link) {
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
    PDEVICE_OBJECT DeviceObject = Irp->Private.ForwardedTo;
    assert(DeviceObject != NULL);
    assert(DeviceObject != IoStack->DeviceObject);
    assert(DeviceObject->DriverObject == NULL);
    assert(DeviceObject->Header.GlobalHandle != 0);
    assert(IoStack->DeviceObject != NULL);
    assert(IopDeviceObjectIsLocal(IoStack->DeviceObject));
    assert(Irp->Private.OriginalRequestor != 0);
    /* We are forwarding an IRP originated from the server,
     * simply send the ForwardIrp client message */
    if (BufferSize < sizeof(IO_PACKET)) {
	return FALSE;
    }
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
	 * assoicated IRPs to TRUE. */
	LoopOverList(AssociatedIrp, &Irp->Private.AssociatedIrp.PendingList,
		     IRP, Private.AssociatedIrp.Link) {
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
    PDEVICE_OBJECT DeviceObject = Irp->Private.ForwardedTo;
    assert(DeviceObject != NULL);
    assert(DeviceObject->DriverObject == NULL);
    assert(DeviceObject->Header.GlobalHandle != 0);
    assert(IoStack);
    assert(IoStack->MajorFunction <= IRP_MJ_MAXIMUM_FUNCTION);
    assert(IoStack->DeviceObject != NULL);
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
	/* Do nothing */
	break;
    default:
	/* UNIMPLEMENTED */
	assert(FALSE);
	return FALSE;
    }
    /* If the IRP itself is a master IRP, set the MasterSent member of all its
     * assoicated IRPs to TRUE. */
    if (!Irp->MasterIrp) {
	LoopOverList(AssociatedIrp, &Irp->Private.AssociatedIrp.PendingList,
		     IRP, Private.AssociatedIrp.Link) {
	    AssociatedIrp->Private.MasterIrpSent = TRUE;
	}
    }
    return TRUE;
}

VOID IoDbgDumpIoStackLocation(IN PIO_STACK_LOCATION Stack)
{
    DbgPrint("    Major function %d.  Minor function %d.  Flags 0x%x.  Control 0x%x\n",
	     Stack->MajorFunction, Stack->MinorFunction, Stack->Flags, Stack->Control);
    DbgPrint("    DeviceObject %p(%p, ext %p, drv %p, refcount %d) "
	     "FileObject %p(%p, fcb %p, refcount %d) "
	     "CompletionRoutine %p Context %p\n",
	     Stack->DeviceObject, (PVOID)IopGetDeviceHandle(Stack->DeviceObject),
	     Stack->DeviceObject ? Stack->DeviceObject->DeviceExtension : NULL,
	     Stack->DeviceObject ? Stack->DeviceObject->DriverObject : NULL,
	     Stack->DeviceObject ? ObGetObjectRefCount(Stack->DeviceObject) : 0,
	     Stack->FileObject, (PVOID)IopGetFileHandle(Stack->FileObject),
	     Stack->FileObject ? Stack->FileObject->FsContext : NULL,
	     Stack->FileObject ? ObGetObjectRefCount(Stack->FileObject) : 0,
	     Stack->CompletionRoutine, Stack->Context);
    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
	DbgPrint("    CREATE  SecurityContext %p Options 0x%x FileAttr 0x%x ShareAccess 0x%x EaLength %d\n",
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
    case IRP_MJ_CLEANUP:
	DbgPrint("    CLEANUP\n");
	break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
	DbgPrint("    %sDEVICE-CONTROL  IoControlCode 0x%x OutputBufferLength 0x%x "
		 "InputBufferLength 0x%x Type3InputBuffer %p\n",
		 Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL ? "" : "INTERNAL-",
		 Stack->Parameters.DeviceIoControl.IoControlCode,
		 Stack->Parameters.DeviceIoControl.OutputBufferLength,
		 Stack->Parameters.DeviceIoControl.InputBufferLength,
		 Stack->Parameters.DeviceIoControl.Type3InputBuffer);
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
	default:
	    DbgPrint("    PNP  UNKNOWN-MINOR-FUNCTION\n");
	}
	break;
    case IRP_MJ_ADD_DEVICE:
	DbgPrint("    ADD-DEVICE\n");
	break;
    default:
	DbgPrint("    UNKNOWN-MAJOR-FUNCTION\n");
    }
}

VOID IoDbgDumpIrp(IN PIRP Irp)
{
    DbgTrace("Dumping IRP %p type %d size %d\n", Irp, Irp->Type, Irp->Size);
    DbgPrint("    MdlAddress %p Flags 0x%08x IO Stack Location %p\n",
	     Irp->MdlAddress, Irp->Flags, IoGetCurrentIrpStackLocation(Irp));
    DbgPrint("    System Buffer %p User Buffer %p Completed %d AllocationSize 0x%llx\n",
	     Irp->SystemBuffer, Irp->UserBuffer, Irp->Completed, Irp->AllocationSize.QuadPart);
    DbgPrint("    IO Status Block Status 0x%08x Information %p\n",
	     Irp->IoStatus.Status, (PVOID) Irp->IoStatus.Information);
    DbgPrint("    PRIV OriginalRequestor %p Identifier %p OutputBuffer %p\n",
	     (PVOID)Irp->Private.OriginalRequestor, Irp->Private.Identifier,
	     Irp->Private.OutputBuffer);
    DbgPrint("    PRIV ForwardedTo %p(0x%zx, ext %p, refcount %d) ExecEnv %p "
	     "EnvToWakeUp %p NotifyCompletion %s\n",
	     Irp->Private.ForwardedTo, IopGetDeviceHandle(Irp->Private.ForwardedTo),
	     Irp->Private.ForwardedTo ? Irp->Private.ForwardedTo->DeviceExtension : NULL,
	     Irp->Private.ForwardedTo ? ObGetObjectRefCount(Irp->Private.ForwardedTo) : 0,
	     Irp->Private.ExecEnv, Irp->Private.EnvToWakeUp,
	     Irp->Private.NotifyCompletion ? "TRUE" : "FALSE");
    IoDbgDumpIoStackLocation(IoGetCurrentIrpStackLocation(Irp));
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
    /* Irp cannot have been forwarded to a different driver. */
    assert(Irp->Private.ForwardedTo == NULL);
    PDEVICE_OBJECT DeviceObject = IoStack->DeviceObject;
    assert(DeviceObject);
    /* The IRP_MJ_CLOSE routine is called in IopHandleCloseFileServerMessage,
     * as a response of a server message. */
    assert(IoStack->MajorFunction != IRP_MJ_CLOSE);
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

/*
 * If the IRP has already been completed, do nothing. Otherwise complete the IRP.
 */
static VOID IopCompleteIrp(IN PIRP Irp)
{
    /* If there is an execution environment that was suspended waiting
     * for the completion of this IRP, wake it up now. Note this must
     * be done even if the IRP has been marked as completed, because
     * it might have been forwarded multiple times. */
    if (Irp->Private.EnvToWakeUp) {
	((PIOP_EXEC_ENV)Irp->Private.EnvToWakeUp)->Suspended = FALSE;
	Irp->Private.EnvToWakeUp = NULL;
    }

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
    if (!Irp->MasterIrp && !IsListEmpty(&Irp->Private.AssociatedIrp.PendingList)) {
	Irp->Private.MasterCompleted = TRUE;
	return;
    }

    /* Execute the completion routine if one is registered. If it returns
     * StopCompletion, IRP completion is halted and the IRP remains in
     * pending state. Otherwise, IRP is completed.*/
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    if (IoStack->CompletionRoutine) {
	NTSTATUS Status = IoStack->CompletionRoutine(IoStack->DeviceObject,
						     Irp, IoStack->Context);
	if (Status == StopCompletion) {
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
	assert(ListHasEntry(&MasterIrp->Private.AssociatedIrp.PendingList,
			    &Irp->Private.AssociatedIrp.Link));
	RemoveEntryList(&Irp->Private.AssociatedIrp.Link);
	if (MasterIrp->Private.MasterCompleted &&
	    IsListEmpty(&MasterIrp->Private.AssociatedIrp.PendingList)) {
	    IopCompleteIrp(MasterIrp);
	}
    }
}

static VOID IopHandleIoCompleteServerMessage(PIO_PACKET SrvMsg)
{
    assert(SrvMsg != NULL);
    assert(SrvMsg->Type == IoPacketTypeServerMessage);
    assert(SrvMsg->ServerMsg.Type == IoSrvMsgIoCompleted);
    GLOBAL_HANDLE Orig = SrvMsg->ServerMsg.IoCompleted.OriginalRequestor;
    HANDLE Id = SrvMsg->ServerMsg.IoCompleted.Identifier;
    /* Check the pending IRP list for all pending IRPs (this includes both
     * asynchronously pending IRPs and IRPs suspended in a coroutine stack) */
    LoopOverList(Irp, &IopPendingIrpList, IRP, Private.Link) {
	if (Irp->Private.OriginalRequestor == Orig && Irp->Private.Identifier == Id) {
	    /* Update the data in the local IRP with the result in the server message */
	    IopPopulateLocalIrpFromServerIoResponse(Irp, &SrvMsg->ServerMsg.IoCompleted);
	    /* Detach the IRP from the pending IRP list. */
	    RemoveEntryList(&Irp->Private.Link);
	    /* If the execution environment associated with this IRP is different
	     * from the one that was suspended waiting for its completion, we
	     * should complete the IRP. If they are equal, the dispatch routine
	     * must have called IoCallDriver on the IRP itself (synchronously),
	     * so the right thing to do in this case is to resume the suspended
	     * coroutine, rather than completing the IRP. */
	    if (Irp->Private.ExecEnv != Irp->Private.EnvToWakeUp) {
		IopCompleteIrp(Irp);
	    }
	    /* If there is an execution environment that was suspended waiting
	     * for the completion of this IRP, wake it up now. */
	    if (Irp->Private.EnvToWakeUp) {
		((PIOP_EXEC_ENV)Irp->Private.EnvToWakeUp)->Suspended = FALSE;
		Irp->Private.EnvToWakeUp = NULL;
	    }
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
	goto done;
    }
    PDRIVER_OBJECT DriverObject = FileObj->DeviceObject->DriverObject;
    assert(DriverObject);
    /* The dispatch routine for IRP_MJ_CLOSE cannot sleep, and in general
     * should always succeed. We ignore any error that it returns. */
    PDRIVER_DISPATCH Close = DriverObject->MajorFunction[IRP_MJ_CLOSE];
    if (!Close) {
	goto done;
    }
    PIRP Irp = IoAllocateIrp();
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    Stack->DeviceObject = FileObj->DeviceObject;
    ObReferenceObject(Stack->DeviceObject);
    Stack->FileObject = FileObj;
    ObReferenceObject(Stack->FileObject);
    Stack->MajorFunction = IRP_MJ_CLOSE;
    if (!NT_SUCCESS(Close(FileObj->DeviceObject, Irp))) {
	assert(FALSE);
    }
    /* If the dispatch routine did not complete the IRP, do it now.
     * This will move the IRP to the reply list and eventually to the
     * delete list so it gets freed. */
    IoCompleteRequest(Irp, 0);
    /* Dereference the file object since we increased its refcount after CREATE. */
done:
    ObDereferenceObject(FileObj);
}

static VOID IopHandleCloseDeviceServerMessage(PIO_PACKET SrvMsg)
{
    PDEVICE_OBJECT DevObj = IopGetDeviceObject(SrvMsg->ServerMsg.CloseDevice.DeviceObject);
    if (!DevObj) {
	assert(FALSE);
	return;
    }
    if (DevObj->Header.GlobalHandle) {
	DevObj->Header.GlobalHandle = 0;
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
    DbgTrace("Running finalizer for exec env %p context %p suspended %d "
	     "EnvToWakeUp %p, status 0x%08x:\n", Env, Env->Context,
	     Env->Suspended, Env->EnvToWakeUp, Status);
    PIRP Irp = Env->Context;
    IoDbgDumpIrp(Irp);
    Irp->Private.ExecEnv = NULL;
    if (Status != STATUS_PENDING) {
	assert(Irp->IoStatus.Status == Status);
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
	PIOP_EXEC_ENV Env = ExAllocatePool(sizeof(IOP_EXEC_ENV));
	if (!Env) {
	    break;
	}
	/* Initialize the execution environment and add it to the list */
	Irp->Private.ExecEnv = Env;
	Env->Context = Irp;
	Env->EntryPoint = IopCallDispatchRoutine;
	Env->Finalizer = IopDispatchFcnExecEnvFinalizer;
	InsertTailList(&IopExecEnvList, &Env->Link);
    }
}

static VOID IopExecuteCoroutines()
{
again:
    LoopOverList(Env, &IopExecEnvList, IOP_EXEC_ENV, Link) {
	DbgTrace("Processing execution environment %p context %p suspended %d "
		 "EnvToWakeUp %p:\n", Env, Env->Context, Env->Suspended,
		 Env->EnvToWakeUp);
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
	    assert(!Env->EnvToWakeUp);
	    IopOldEnvToWakeUp = NULL;
	    PTEB Teb = NtCurrentTeb();
	    Teb->Wdm.CoroutineStackHigh = Stack;
	    Teb->Wdm.CoroutineStackLow = Stack - DRIVER_COROUTINE_STACK_COMMIT;
	    Status = KiStartCoroutine(Stack, Env->EntryPoint, Env->Context);
	    Env->EnvToWakeUp = IopOldEnvToWakeUp;
	    Teb->Wdm.CoroutineStackHigh = Teb->Wdm.CoroutineStackLow = NULL;
	} else {
	    /* We are resuming a coroutine suspended due to IoCallDriver. */
	    DbgTrace("Resuming coroutine stack top %p. Saved SP %p\n",
		     Env->CoroutineStackTop,
		     KiGetCoroutineSavedSP(Env->CoroutineStackTop));
	    PUCHAR Stack = Env->CoroutineStackTop;
	    PTEB Teb = NtCurrentTeb();
	    Teb->Wdm.CoroutineStackHigh = Stack;
	    Teb->Wdm.CoroutineStackLow = Stack - DRIVER_COROUTINE_STACK_COMMIT;
	    IopOldEnvToWakeUp = Env->EnvToWakeUp;
	    Status = KiResumeCoroutine(Env->CoroutineStackTop);
	    Env->EnvToWakeUp = IopOldEnvToWakeUp;
	    Teb->Wdm.CoroutineStackHigh = Teb->Wdm.CoroutineStackLow = NULL;
	}
	IopCurrentEnv = NULL;
	IopOldEnvToWakeUp = NULL;
	if (Status == STATUS_ASYNC_PENDING) {
	    /* Mark the execution environment as suspended. */
	    DbgTrace("Suspending exec env %p, coroutine stack %p, saved SP %p, "
		     "context %p, EnvToWakeUp %p\n", Env, Env->CoroutineStackTop,
		     KiGetCoroutineSavedSP(Env->CoroutineStackTop),
		     Env->Context, Env->EnvToWakeUp);
	    Env->Suspended = TRUE;
	} else {
	    /* The dispatch function returns without suspending the coroutine.
	     * Release the coroutine stack and execute the finalizer. */
	    assert(Env->CoroutineStackTop);
	    KiReleaseCoroutineStack(Env->CoroutineStackTop);
	    RemoveEntryList(&Env->Link);
	    if (Env->Finalizer) {
		Env->Finalizer(Env, Status);
	    }
	    ExFreePool(Env);
	}
    }

    /* If there are still execution environments running, repeat the process. */
    BOOLEAN Running = FALSE;
    LoopOverList(Env, &IopExecEnvList, IOP_EXEC_ENV, Link) {
	if (!Env->Suspended) {
	    Running = TRUE;
	    break;
	}
    }
    if (Running) {
	goto again;
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
    PIRP Irp = IoAllocateIrp();
    if (!Irp) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    Irp->Private.OriginalRequestor = SrcIoPacket->Request.OriginalRequestor;
    Irp->Private.Identifier = SrcIoPacket->Request.Identifier;
    NTSTATUS Status = IopPopulateLocalIrpFromServerIoPacket(Irp, SrcIoPacket);
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
 * the reply IO packets and sending them to the outgoing IO packet buffer.
 */
VOID IopProcessIoPackets(OUT ULONG *pNumResponses,
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

workitem:
    /* Now process the IO work item queue */
    IopProcessWorkItemQueue();

    /* Process the execution environments. This is where the dispatch
     * functions and work items are actually executed. */
    IopExecuteCoroutines();

    /* Dispatch functions and work items can both queue work items, so
     * go back and process the work item queue again, until it is empty. */
    KeAcquireMutex(&IopWorkItemMutex);
    if (!IsListEmpty(&IopWorkItemQueue)) {
	KeReleaseMutex(&IopWorkItemMutex);
	goto workitem;
    }
    KeReleaseMutex(&IopWorkItemMutex);

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
    LoopOverList(Irp, &IopReplyIrpList, IRP, Private.Link) {
	/* This will become FALSE if remaining size is too small for the IO packet */
	BOOLEAN Ok = TRUE;
	/* Either the IRP is completed, or it is forwarded (someone called IoCallDriver
	 * on it). We assert if these conditions have not been met. */
	assert(Irp->Completed || Irp->Private.ForwardedTo);
	/* Detach this IRP from the ReplyIrp list first. We will insert it to other
	 * lists below. */
	RemoveEntryList(&Irp->Private.Link);
	if (Irp->Completed) {
	    /* If the IRP being completed is not locally generated, notify server
	     * that we have finished processing it. */
	    if (Irp->Private.OriginalRequestor) {
		Ok = IopPopulateIoCompleteMessageFromLocalIrp(DestIrp, Irp,
							      RemainingBufferSize);
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
	} else if (IopDeviceObjectIsLocal(Irp->Private.ForwardedTo)) {
	    /* If we are forwarding this IRP to a local device object, requeue it to
	     * the IRP queue. Note drivers should be careful when forwarding IRPs
	     * locally. In particular, since on Neptune OS the IRP stack size is always
	     * one, drivers can only set one IoCompeltion routine even if it forwards
	     * an IRP multiple times, and likewise the DeviceObject in the IO request
	     * stack always points to the current device object that this IRP has been
	     * forwarded to. Secondly, the IO transfer type of the target device must
	     * match that of the source device. Finally, for IRPs generated locally and
	     * forwarded to local device objects, the IO tranfer type is ignored and
	     * NEITHER IO is always assumed, so the relevant dispatch routine will need
	     * to handle this case separately. */
	    assert((Irp->Private.ForwardedTo->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO)) ==
		   (IoGetCurrentIrpStackLocation(Irp)->DeviceObject->Flags &
		    (DO_BUFFERED_IO | DO_DIRECT_IO)));
	    InsertTailList(&IopIrpQueue, &Irp->Private.Link);
	    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
	    if (IoStack->DeviceObject) {
		ObDereferenceObject(IoStack->DeviceObject);
	    }
	    IoStack->DeviceObject = Irp->Private.ForwardedTo;
	    Irp->Private.ForwardedTo = NULL;
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

delete:
    /* Clean up the list of IRPs marked for deletion */
    LoopOverList(Irp, &IopCleanupIrpList, IRP, Private.Link) {
	RemoveEntryList(&Irp->Private.Link);
	IopDeleteIrp(Irp);
    }

    /* If there are IRPs requeued (due to them being forwarded to a local
     * device object), restart the whole process again. */
    if (!IsListEmpty(&IopIrpQueue)) {
	goto again;
    }

    /* If any of the IRP dispatch routine or work item queued DPC, now
     * is the time to wake up the DPC thread. Note we don't care about
     * IO work items at this point because they should have all been
     * processed above. */
    NtCurrentTeb()->Wdm.IoWorkItemQueued = FALSE;
    IopSignalDpcNotification();

    *pNumResponses = ResponseCount;
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
 * Cancel the IRP. A driver can only cancel the IRP that is has initiated.
 * If a driver does own the IRP, a status is raised.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoCancelIrp(IN PIRP Irp)
{
    PAGED_CODE();
    /* UNIMPLEMENTED */
}

/*
 * Forward the IRP to the specified device object for processing.
 *
 * If the IRP has a user IO status block, IoCallDriverEx will forward the
 * IRP to the driver object corresponding to the device object and then
 * yield the current coroutine and return to the main event loop thread.
 * The suspended coroutine will resume once the IRP is completed, or if the
 * specified non-zero timeout is lapsed. The status returned is the final IO
 * status of the IRP, or STATUS_TIMEOUT if the timeout is lapsed before the
 * lower-level driver has responded. A NULL Timeout or a zero timeout (ie.
 * Timeout is not NULL and *Timeout equals zero) is ignored. We call this
 * synchronous IRP forwarding.
 *
 * If no user IO status block is specified, the behavior of this routine is
 * determined by the Timeout parameter. If the *Timeout is zero (ie. Timeout
 * is not NULL and *Timeout equals zero), the routine forwards the IRP and
 * returns immediately with STATUS_IRP_FORWARDED. We call this asynchronous
 * IRP forwarding. If no IO completion routine is specified, the IRP object
 * is deleted immediately after it has been forwarded. If an IO completion
 * routine is specified, the IRP is saved to a pending IRP queue and will be
 * processed once the server has informed us of its completion, by which time
 * its IO completion routine will be invoke. On the other hand, if Timeout
 * is NULL, or if *Timeout is not zero, the IRP is forwarded synchronously
 * just like the case of having a user IO status block. If an IO completion
 * routine is specified in this case, it will be invoked as soon as the
 * coroutine is resumed.
 *
 * A special case is when DeviceObject refers to a device object created by
 * the driver itself. In this case the dispatch routine is not sent to the
 * server and processed locally. Note that since our IRP stack has exacly one
 * stack location there can only be one IO completion routine (the top-level
 * one) for each IRP.
 *
 *
 * Microsoft discourages higher-level drivers from having a StartIO routine,
 * let alone calling lower-level drivers in a StartIO routines [1] on Windows.
 * On Neptune OS, doing so is also discouraged, although it is nonetheless
 * possible, if you forward the IRP asynchronously.
 *
 * This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS IoCallDriverEx(IN PDEVICE_OBJECT DeviceObject,
			      IN OUT PIRP Irp,
			      IN PLARGE_INTEGER Timeout)
{
    PAGED_CODE();

    /* TODO: Implement the case with a non-zero timeout. Add a new Timeout
     * member to the Irp->Private struct and inform the server of the timeout.
     * We will need to calculate the absolute time if timeout is relative. */
    assert(Timeout == NULL || Timeout->QuadPart == 0);
    assert(DeviceObject);
    assert(Irp != NULL);
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    assert(IoStack->DeviceObject);

    /* Determine whether we should forward the IRP synchronously or asynchronously */
    BOOLEAN Wait = Irp->UserIosb || !Timeout || Timeout->QuadPart;
    DbgTrace("Forwarding Irp %p to DeviceObject %p(%p) %ssynchronously\n", Irp,
	     DeviceObject, (PVOID)IopGetDeviceHandle(DeviceObject),
	     Wait ? "" : "a");
    IoDbgDumpIrp(Irp);
    if (Wait && !KiCurrentCoroutineStackTop) {
	/* Synchronous IoCallDriver should always be called in a context where
	 * we are allowed to sleep. Note on release build this leaks the IRP
	 * as it is never correctly completed and cleaned up, but we don't have
	 * a lot of options here. */
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* IRPs can only be forwarded once. Note in the case of forwarding to a local
     * device object, the ForwardedTo member is cleared when the IRP was moved to
     * the IRP queue. */
    assert(!Irp->Private.ForwardedTo);
    Irp->Private.ForwardedTo = DeviceObject;
    ObReferenceObject(DeviceObject);

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
     * has been set, then we ask the server to notify us so we can either resume
     * the coroutine or run the IO completion routine. */
    Irp->Private.NotifyCompletion = (Wait || IoStack->CompletionRoutine != NULL);

    /* If the IRP is locally generated, set its server-side identifier to the
     * local address of the IRP. */
    if (!Irp->Private.Identifier) {
	Irp->Private.Identifier = Irp;
    }

    /* If the IRP has specified a master IRP, add us as its associated IRP. */
    if (Irp->MasterIrp) {
	/* The master IRP cannot be an associated IRP of another IRP. */
	assert(!Irp->MasterIrp->MasterIrp);
	assert(!ListHasEntry(&Irp->MasterIrp->Private.AssociatedIrp.PendingList,
			     &Irp->Private.AssociatedIrp.Link));
	Irp->MasterIrp->Private.AssociatedIrpCount++;
	InsertTailList(&Irp->MasterIrp->Private.AssociatedIrp.PendingList,
		       &Irp->Private.AssociatedIrp.Link);
    }

    /* If we are not waiting for the completion of the IRP, release the DPC mutex
     * and return. */
    if (!Wait) {
	return STATUS_IRP_FORWARDED;
    }

    /* Otherwise, we are forwarding the IRP synchronously. We must have a
     * coroutine stack in this case.  */
    assert(KiCurrentCoroutineStackTop);
    /* Record the object associated with the current coroutine stack so we can
     * wake it up when we receive a IoCompleted message for this IRP. */
    assert(!IopOldEnvToWakeUp);
    IopOldEnvToWakeUp = Irp->Private.EnvToWakeUp;
    Irp->Private.EnvToWakeUp = IopCurrentEnv;

    DbgTrace("Suspending coroutine stack %p\n", KiCurrentCoroutineStackTop);
    /* Yield the current coroutine to the main thread. The control flow will
     * return to either KiStartCoroutine or KiResumeCoroutine. */
    KiYieldCoroutine();

    /* Where the coroutine resumes, this is where the control jumps to. We
     * restore the EnvToWakeUp member and return the final IO status of the
     * IRP back to the caller. */
    Irp->Private.EnvToWakeUp = IopOldEnvToWakeUp;
    IopOldEnvToWakeUp = NULL;
    assert(Irp->IoStatus.Status != STATUS_ASYNC_PENDING);
    assert(Irp->IoStatus.Status != STATUS_PENDING);
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
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoStartPacket(IN PDEVICE_OBJECT DeviceObject,
			 IN PIRP Irp,
			 IN PULONG Key,
			 IN PDRIVER_CANCEL CancelFunction)
{
    PAGED_CODE();
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
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoStartNextPacket(IN PDEVICE_OBJECT DeviceObject,
			     IN BOOLEAN Cancelable)
{
    PAGED_CODE();
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
 *
 * @remarks This routine can only be called at PASSIVE_LEVEL.
 */
NTAPI VOID IoStartNextPacketByKey(IN PDEVICE_OBJECT DeviceObject,
				  IN BOOLEAN Cancelable,
				  IN ULONG Key)
{
    PAGED_CODE();
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
