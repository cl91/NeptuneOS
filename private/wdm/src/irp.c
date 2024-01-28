/*
 * FILE:            private/wdm/src/irp.c
 * PURPOSE:         Client-side IRP processing
 * NOTES:
 *
 * This file implements driver IRP processing. There are several cases that we need to handle here:
 *
 * Case 1:
 * |------------------| Copy |----------| Dispatch fcn. returns  |------------------| ----> Deleted once replied
 * | IncomingIoPacket | ---> | IrpQueue | ---------------------> |  CleanupIrpList  |
 * |------------------|      |----------| immed. w. non-PENDING  |------------------| Copy  |------------------|
 *                                                               |   ReplyIrpList   | ----> | OutgoingIoPacket |
 *                                                               |------------------|       |------------------|
 * Case 2:
 * |------------------| Copy |----------| Dispatch returns PENDING      |----------------| ----> Deleted once forwarded
 * | IncomingIoPacket | ---> | IrpQueue | ----------------------------> | CleanupIrpList |
 * |------------------|      |----------| IRP not marked pending and    |----------------| Forward  |------------------|
 *                                        has no IO completion routine  |  ReplyIrpList  | -------> | OutgoingIoPacket |
 *                                                                      |----------------|          |------------------|
 *
 * Note: on debug build we assert if dispatch routine returns STATUS_PENDING but does not mark
 * IRP pending or set an IO completion routine or forward the IRP via IoCallDriver. See [1].
 *
 * Case 3:
 * |------------------| Copy |----------| Dispatch returns PENDING   |----------------|---------------|
 * | IncomingIoPacket | ---> | IrpQueue | -------------------------> | PendingIrpList | ReplyIrpList? |
 * |------------------|      |----------| IRP marked pending or has  |----------------|---------------|
 *                                        IO completion routine set         |               |
 *                                                                          |               |
 *             IoCompleteRequest called <-----------------------------------|      Queued if forwarded via IoCallDriver
 *          or IoCompleted message received                                        Otherwise empty
 *                       |
 *                      \|/
 *                |------------------| ----> Deleted once replied to server
 *                |  CleanupIrpList  |
 *                |------------------| Copy  |------------------|
 *                |   ReplyIrpList   | ----> | OutgoingIoPacket |
 *                |------------------|       |------------------|
 *
 * Case 4:
 * |------------------| Copy |----------| Dispatch ret. ASYNC_PENDING   |----------------|---------------|
 * | IncomingIoPacket | ---> | IrpQueue | ----------------------------> | PendingIrpList | ReplyIrpList? |
 * |------------------|      |----------|                               |----------------|---------------|
 *                                                                             |               |
 *         IoCompleted message received <--------------------------------------|               |
 *                        |                                                                   \|/
 *                       \|/                                     Queued if this IRP itself is forwarded via IoCallDriver
 *                   |----------|                                Empty if a new IRP is forwarded via IoCallDriver
 *                   | IrpQueue | ----> Resumes coroutine
 *                   |----------|
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

PIO_PACKET IopIncomingIoPacketBuffer;
PIO_PACKET IopOutgoingIoPacketBuffer;
/* List of all IRPs queued to this driver */
LIST_ENTRY IopIrpQueue;
/* List of all IRPs that have been completed. */
LIST_ENTRY IopReplyIrpList;
/* List of all IRPs that are saved for further processing */
LIST_ENTRY IopPendingIrpList;
/* List of all IRPs that are to be deleted at the end of this round of IRP processing */
LIST_ENTRY IopCleanupIrpList;
/* List of all AddDevice requests that have been received but not yet finished processing */
LIST_ENTRY IopAddDeviceRequestList;
/* List of all AddDevice requests that have been suspended */
LIST_ENTRY IopSuspendedAddDeviceRequestList;
/* List of all AddDevice requests that have been completed */
LIST_ENTRY IopCompletedAddDeviceRequestList;
/* List of all file objects created by this driver */
LIST_ENTRY IopFileObjectList;
/* Current IO object being processed. This can be an IRP, an AddDevice
 * request, or an IO workitem. These are identified by the common header
 * {Type, Size}. */
PVOID IopCurrentObject;

#if DBG
static inline VOID IopAssertIrpLists(IN PIRP Irp)
{
    assert(!ListHasEntry(&IopReplyIrpList, &Irp->Private.Link));
    assert(!ListHasEntry(&IopIrpQueue, &Irp->Private.ReplyListEntry));
    assert(!ListHasEntry(&IopPendingIrpList, &Irp->Private.ReplyListEntry));
    assert(!ListHasEntry(&IopCleanupIrpList, &Irp->Private.ReplyListEntry));
}

static inline BOOLEAN IrpIsInReplyList(IN PIRP Irp)
{
    IopAssertIrpLists(Irp);
    return ListHasEntry(&IopReplyIrpList, &Irp->Private.ReplyListEntry);
}

static inline BOOLEAN IrpIsInIrpQueue(IN PIRP Irp)
{
    IopAssertIrpLists(Irp);
    return ListHasEntry(&IopIrpQueue, &Irp->Private.Link);
}

static inline BOOLEAN IrpIsInPendingList(IN PIRP Irp)
{
    IopAssertIrpLists(Irp);
    return ListHasEntry(&IopPendingIrpList, &Irp->Private.Link);
}

static inline BOOLEAN IrpIsInCleanupList(IN PIRP Irp)
{
    IopAssertIrpLists(Irp);
    return ListHasEntry(&IopCleanupIrpList, &Irp->Private.Link);
}
#endif	/* DBG */

static inline NTSTATUS IopCreateFileObject(IN PIO_PACKET IoPacket,
					   IN PFILE_OBJECT_CREATE_PARAMETERS Params,
					   IN GLOBAL_HANDLE Handle,
					   OUT PFILE_OBJECT *pFileObject)
{
    assert(Params != NULL);
    assert(Handle != 0);
    assert(pFileObject != NULL);
    IopAllocateObject(FileObject, FILE_OBJECT);
    UNICODE_STRING FileName = {0};
    if (Params->FileNameOffset) {
	RET_ERR_EX(RtlpUtf8ToUnicodeString(RtlGetProcessHeap(),
					   (PCHAR)IoPacket + Params->FileNameOffset,
					   &FileName),
		   IopFreePool(FileObject));
    }
    FileObject->ReadAccess = Params->ReadAccess;
    FileObject->WriteAccess = Params->WriteAccess;
    FileObject->DeleteAccess = Params->DeleteAccess;
    FileObject->SharedRead = Params->SharedRead;
    FileObject->SharedWrite = Params->SharedWrite;
    FileObject->SharedDelete = Params->SharedDelete;
    FileObject->Flags = Params->Flags;
    FileObject->FileName = FileName;
    FileObject->Private.Handle = Handle;
    InsertTailList(&IopFileObjectList, &FileObject->Private.Link);
    *pFileObject = FileObject;
    return STATUS_SUCCESS;
}

static inline VOID IopDeleteFileObject(IN PFILE_OBJECT FileObject)
{
    assert(FileObject != NULL);
    assert(FileObject->Private.Link.Flink != NULL);
    assert(FileObject->Private.Link.Blink != NULL);
    assert(FileObject->Private.Handle != 0);
    RemoveEntryList(&FileObject->Private.Link);
    if (FileObject->FileName.Buffer) {
	IopFreePool(FileObject->FileName.Buffer);
    }
    IopFreePool(FileObject);
}

/*
 * Search the list of all files created by this driver and return
 * the one matching the given GLOBAL_HANDLE. Returns NULL if not found.
 */
static inline PFILE_OBJECT IopGetFileObject(IN GLOBAL_HANDLE Handle)
{
    LoopOverList(Object, &IopFileObjectList, FILE_OBJECT, Private.Link) {
	if (Handle == Object->Private.Handle) {
	    return Object;
	}
    }
    return NULL;
}

static inline GLOBAL_HANDLE IopGetFileHandle(IN PFILE_OBJECT File)
{
    return File ? File->Private.Handle : 0;
}

static inline NTSTATUS IopAllocateMdl(IN PVOID Buffer,
				      IN ULONG BufferLength,
				      IN PULONG_PTR PfnDb,
				      IN ULONG PfnCount,
				      OUT PMDL *pMdl)
{
    ULONG MdlSize = sizeof(MDL) + PfnCount * sizeof(ULONG_PTR);
    IopAllocatePool(Mdl, MDL, MdlSize);
    Mdl->MappedSystemVa = Buffer;
    Mdl->ByteCount = BufferLength;
    Mdl->PfnCount = PfnCount;
    memcpy(Mdl->PfnEntries, PfnDb, PfnCount * sizeof(ULONG_PTR));
    *pMdl = Mdl;
    return STATUS_SUCCESS;
}

static inline NTSTATUS IopMarshalIoBuffers(IN PIRP Irp,
					   IN PVOID Buffer,
					   IN ULONG BufferLength,
					   IN PULONG_PTR PfnDb,
					   IN ULONG PfnCount)
{
    if (BufferLength == 0 || Buffer == NULL) {
	return STATUS_SUCCESS;
    }
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG DeviceFlags = IoStack->DeviceObject->Flags;
    if (DeviceFlags & DO_BUFFERED_IO) {
	Irp->AssociatedIrp.SystemBuffer = Buffer;
    } else if (DeviceFlags & DO_DIRECT_IO) {
	RET_ERR(IopAllocateMdl(Buffer, BufferLength, PfnDb, PfnCount,
			       &Irp->MdlAddress));
   } else {
	/* NEITHER_IO */
	Irp->UserBuffer = Buffer;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS IopMarshalIoctlBuffers(IN PIRP Irp,
				       IN ULONG Ioctl,
				       IN PVOID InputBuffer,
				       IN ULONG InputBufferLength,
				       IN PVOID OutputBuffer,
				       IN ULONG OutputBufferLength,
				       IN PULONG_PTR OutputBufferPfnDb,
				       IN ULONG OutputBufferPfnCount)
{
    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
	ULONG SystemBufferLength = max(InputBufferLength, OutputBufferLength);
	IopAllocatePool(SystemBuffer, UCHAR, SystemBufferLength);
	Irp->AssociatedIrp.SystemBuffer = SystemBuffer;
	/* Copy the user input data (if exists) to the system buffer */
	if (InputBufferLength != 0) {
	    memcpy(Irp->AssociatedIrp.SystemBuffer, InputBuffer, InputBufferLength);
	}
	Irp->Private.OutputBuffer = OutputBuffer;
    } else if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_NEITHER) {
	/* Type3InputBuffer is set in IopPopulateLocalIrpFromServerIoPacket */
	Irp->UserBuffer = OutputBuffer;
    } else {
	/* Direct IO: METHOD_IN_DIRECT or METHOD_OUT_DIRECT */
	Irp->AssociatedIrp.SystemBuffer = InputBuffer;
	if (OutputBufferLength != 0) {
	    RET_ERR(IopAllocateMdl(OutputBuffer, OutputBufferLength,
				   OutputBufferPfnDb, OutputBufferPfnCount,
				   &Irp->MdlAddress));
	}
    }
    return STATUS_SUCCESS;
}

/* Note this function is called in two cases: (1) when the driver
 * completes an IOCTL IRP sent from a foreign driver, and (2) when
 * the driver completes an IOCTL IRP sent within the same driver
 * address space. In the former case we need to properly copy the
 * response of the driver back to the server-bound IoPacket and
 * free the intermediate buffer we have allocated. In the latter
 * case, whether we are completing an IOCTL IRP forwarded to a
 * foreign driver or sent back to this driver (including all library
 * drivers loded within the same address space), we do not allocate
 * any intermediate buffer and always assume the NEITHER IO transfer
 * type. */
static VOID IopUnmarshalIoctlBuffers(IN PIRP Irp,
				     IN ULONG Ioctl,
				     IN ULONG OutputBufferLength)
{
    if (!Irp->Private.OriginalRequestor) {
	return;
    }
    if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
	/* Copy the system buffer back to the user output buffer if needed. */
	if (OutputBufferLength != 0) {
	    assert(Irp->Private.OutputBuffer != NULL);
	    memcpy(Irp->Private.OutputBuffer, Irp->AssociatedIrp.SystemBuffer,
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
    case IRP_MJ_CREATE:
    case IRP_MJ_READ:
    case IRP_MJ_PNP:
	/* Do nothing */
	break;
    default:
	assert(FALSE);
    }
}

/*
 * Populate the local IRP object from the server IO packet
 */
static NTSTATUS IopPopulateLocalIrpFromServerIoPacket(IN PIRP Irp,
						      IN PIO_PACKET Src)
{
    assert(Irp != NULL);
    assert(Src != NULL);
    assert(Src->Type == IoPacketTypeRequest);
    PDEVICE_OBJECT DeviceObject = IopGetDeviceObject(Src->Request.Device.Handle);
    if (DeviceObject == NULL) {
	assert(FALSE);
	return STATUS_INVALID_HANDLE;
    }
    PFILE_OBJECT FileObject = NULL;
    if ((Src->Request.MajorFunction == IRP_MJ_CREATE) ||
	(Src->Request.MajorFunction == IRP_MJ_CREATE_MAILSLOT) ||
	(Src->Request.MajorFunction == IRP_MJ_CREATE_NAMED_PIPE)) {
	RET_ERR(IopCreateFileObject(Src, &Src->Request.Create.FileObjectParameters,
				    Src->Request.File.Handle, &FileObject));
    } else {
	FileObject = IopGetFileObject(Src->Request.File.Handle);
    }

    DbgTrace("Populating local IRP from server IO packet %p, devobj %p, fileobj %p\n",
	     Src, DeviceObject, FileObject);
    IoDbgDumpIoPacket(Src, TRUE);
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
	IoStack->Parameters.Create.Options = Src->Request.Create.Options;
	IoStack->Parameters.Create.FileAttributes = Src->Request.Create.FileAttributes;
	IoStack->Parameters.Create.ShareAccess = Src->Request.Create.ShareAccess;
	IoStack->Parameters.Create.EaLength = 0;
	break;

    case IRP_MJ_CREATE_NAMED_PIPE:
	IoStack->Parameters.CreatePipe.SecurityContext = NULL;
	IoStack->Parameters.CreatePipe.Options = Src->Request.CreatePipe.Options;
	IoStack->Parameters.CreatePipe.Reserved = 0;
	IoStack->Parameters.CreatePipe.ShareAccess = Src->Request.CreatePipe.ShareAccess;
	assert(FileObject != NULL);
	IopAllocateObjectEx(NamedPipeCreateParameters, NAMED_PIPE_CREATE_PARAMETERS,
			    IopDeleteFileObject(FileObject));
	*NamedPipeCreateParameters = Src->Request.CreatePipe.Parameters;
	IoStack->Parameters.CreatePipe.Parameters = NamedPipeCreateParameters;
	break;

    case IRP_MJ_CREATE_MAILSLOT:
	IoStack->Parameters.CreateMailslot.SecurityContext = NULL;
	IoStack->Parameters.CreateMailslot.Options = Src->Request.CreateMailslot.Options;
	IoStack->Parameters.CreateMailslot.Reserved = 0;
	IoStack->Parameters.CreateMailslot.ShareAccess = Src->Request.CreateMailslot.ShareAccess;
	assert(FileObject != NULL);
	IopAllocateObjectEx(MailslotCreateParameters, MAILSLOT_CREATE_PARAMETERS,
			    IopDeleteFileObject(FileObject));
	*MailslotCreateParameters = Src->Request.CreateMailslot.Parameters;
	IoStack->Parameters.CreateMailslot.Parameters = MailslotCreateParameters;
	break;

    case IRP_MJ_READ:
    {
	PVOID Buffer = (PVOID)Src->Request.OutputBuffer;
	ULONG BufferLength = Src->Request.OutputBufferLength;
	PULONG_PTR PfnDb = (PULONG_PTR)((MWORD)Src + Src->Request.OutputBufferPfn);
	ULONG PfnCount = Src->Request.OutputBufferPfnCount;
	IoStack->Parameters.Read.Length = BufferLength;
	IoStack->Parameters.Read.Key = Src->Request.Read.Key;
	IoStack->Parameters.Read.ByteOffset = Src->Request.Read.ByteOffset;
	RET_ERR(IopMarshalIoBuffers(Irp, Buffer, BufferLength, PfnDb, PfnCount));
	break;
    }

    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
    {
	ULONG Ioctl = Src->Request.DeviceIoControl.IoControlCode;
	PVOID InputBuffer = (PVOID)Src->Request.InputBuffer;
	ULONG InputBufferLength = Src->Request.InputBufferLength;
	ULONG OutputBufferLength = Src->Request.OutputBufferLength;
	/* For DIRECT_IO only the output buffer has the MDL generated. */
	PULONG_PTR PfnDb = (PULONG_PTR)((MWORD)Src + Src->Request.OutputBufferPfn);
	ULONG PfnCount = Src->Request.OutputBufferPfnCount;
	IoStack->Parameters.DeviceIoControl.IoControlCode = Ioctl;
	IoStack->Parameters.DeviceIoControl.Type3InputBuffer = InputBuffer;
	IoStack->Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
	IoStack->Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;
	RET_ERR(IopMarshalIoctlBuffers(Irp, Ioctl, InputBuffer, InputBufferLength,
				       (PVOID)Src->Request.OutputBuffer,
				       OutputBufferLength, PfnDb, PfnCount));
	break;
    }

    case IRP_MJ_FILE_SYSTEM_CONTROL:
    {
	switch (Src->Request.MinorFunction) {
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
    default:
	UNIMPLEMENTED;
	assert(FALSE);
	return STATUS_NOT_IMPLEMENTED;
    }

    return STATUS_SUCCESS;
}

/*
 * This will also free the memory allocated when creating the IRP
 * (in IopPopulateLocalIrpFromServerIoPacket);
 */
static inline VOID IopDeleteIrp(PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    switch (IoStack->MajorFunction) {
    case IRP_MJ_FILE_SYSTEM_CONTROL:
	switch (IoStack->MinorFunction) {
	case IRP_MN_MOUNT_VOLUME:
	    if (IoStack->Parameters.MountVolume.Vpb) {
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
    }
    IopFreePool(Irp);
}

static VOID IopPopulateIoCompleteMessageFromIoStatus(IN PIO_PACKET Dest,
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

static BOOLEAN IopPopulateIoCompleteMessageFromLocalIrp(IN PIO_PACKET Dest,
							IN PIRP Irp,
							IN ULONG BufferSize)
{
    ULONG Size = FIELD_OFFSET(IO_PACKET, ClientMsg.IoCompleted.ResponseData);
    PIO_STACK_LOCATION IoSp = IoGetCurrentIrpStackLocation(Irp);
    if (IoSp->MajorFunction == IRP_MJ_PNP) {
	switch (IoSp->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    if (Irp->IoStatus.Information != 0) {
		PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
		Size += Relations->Count * sizeof(GLOBAL_HANDLE);
	    }
	    break;

	case IRP_MN_QUERY_ID:
	    /* For UTF-16 strings that are legal device IDs its characters are always within ASCII */
	    if (Irp->IoStatus.Information != 0) {
		Size += wcslen((PWSTR)Irp->IoStatus.Information) + 1;
	    }
	    break;

	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	    if (Irp->IoStatus.Information != 0) {
		PIO_RESOURCE_REQUIREMENTS_LIST Res = (PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
		if (Res->ListSize <= MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE) {
		    assert(FALSE);
		    return STATUS_INVALID_PARAMETER;
		}
		Size += Res->ListSize;
	    }
	    break;

	case IRP_MN_START_DEVICE:
	    /* Do nothing */
	    break;

	default:
	    UNIMPLEMENTED;
	    assert(FALSE);
	    return FALSE;
	}
    }
    if (Size < sizeof(IO_PACKET)) {
	Size = sizeof(IO_PACKET);
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
    case IRP_MJ_PNP:
    {
	switch (IoSp->MinorFunction) {
	case IRP_MN_QUERY_DEVICE_RELATIONS:
	    if (Irp->IoStatus.Information != 0) {
		/* Dest->...IoStatus.Information is DEVICE_RELATIONS.Count. ResponseData[] are the GLOBAL_HANDLE
		 * of the device objects in DEVICE_RELATIONS.Objects. */
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
	    if (Irp->IoStatus.Information != 0) {
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
	    if (Irp->IoStatus.Information != 0) {
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
	    UNIMPLEMENTED;
	    assert(FALSE);
	    break;
	}
	break;
    }
    default:
	break;
    }

    return TRUE;
}

static BOOLEAN IopPopulateForwardIrpMessage(IN PIO_PACKET Dest,
					    IN PIRP Irp,
					    IN ULONG BufferSize)
{
    UNUSED PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT DeviceObject = Irp->Private.ForwardedTo;
    assert(DeviceObject != NULL);
    assert(DeviceObject != IoStack->DeviceObject);
    assert(DeviceObject->DriverObject == NULL);
    assert(DeviceObject->Private.Handle != 0);
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
    Dest->ClientMsg.ForwardIrp.DeviceObject = DeviceObject->Private.Handle;
    Dest->ClientMsg.ForwardIrp.NotifyCompletion = Irp->Private.NotifyCompletion;
    return TRUE;
}

static BOOLEAN IopPopulateIoRequestMessage(IN PIO_PACKET Dest,
					   IN PIRP Irp,
					   IN ULONG BufferSize)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_OBJECT DeviceObject = Irp->Private.ForwardedTo;
    assert(DeviceObject != NULL);
    assert(DeviceObject->DriverObject == NULL);
    assert(DeviceObject->Private.Handle != 0);
    assert(IoStack->DeviceObject != NULL);
    assert(Irp->Private.OriginalRequestor == 0);
    ULONG Size = sizeof(IO_PACKET);
    if (BufferSize < Size) {
	return FALSE;
    }
    memset(Dest, 0, Size);
    Dest->Type = IoPacketTypeRequest;
    Dest->Size = Size;
    Dest->Request.MajorFunction = IoStack->MajorFunction;
    Dest->Request.MinorFunction = IoStack->MinorFunction;
    Dest->Request.Device.Handle = DeviceObject->Private.Handle;
    /* Use the address of the IRP as identifier. OriginalRequestor is
     * left as NULL since the server is going to fill it. */
    Dest->Request.Identifier = Irp;

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
    default:
	UNIMPLEMENTED;
	assert(FALSE);
	return FALSE;
    }
    return TRUE;
}

VOID IoDbgDumpIoStackLocation(IN PIO_STACK_LOCATION Stack)
{
    DbgPrint("    Major function %d.  Minor function %d.  Flags 0x%x.  Control 0x%x\n",
	     Stack->MajorFunction, Stack->MinorFunction, Stack->Flags, Stack->Control);
    DbgPrint("    DeviceObject %p(%p, ext %p) FileObject %p(%p) CompletionRoutine %p Context %p\n",
	     Stack->DeviceObject, (PVOID)IopGetDeviceHandle(Stack->DeviceObject),
	     Stack->DeviceObject ? Stack->DeviceObject->DeviceExtension : NULL,
	     Stack->FileObject, (PVOID)IopGetFileHandle(Stack->FileObject),
	     Stack->CompletionRoutine, Stack->Context);
    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
	DbgPrint("    CREATE  SecurityContext %p Options 0x%x FileAttr 0x%x ShareAccess 0x%x EaLength %d\n",
		 Stack->Parameters.Create.SecurityContext, Stack->Parameters.Create.Options,
		 Stack->Parameters.Create.FileAttributes, Stack->Parameters.Create.ShareAccess,
		 Stack->Parameters.Create.EaLength);
	break;
    case IRP_MJ_READ:
	DbgPrint("    READ  Length 0x%x Key 0x%x ByteOffset 0x%llx\n",
		 Stack->Parameters.Read.Length, Stack->Parameters.Read.Key,
		 Stack->Parameters.Read.ByteOffset.QuadPart);
	break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
	DbgPrint("    %sDEVICE-CONTROL  IoControlCode 0x%x OutputBufferLength 0x%x InputBufferLength 0x%x Type3InputBuffer %p\n",
		 Stack->MajorFunction == IRP_MJ_DEVICE_CONTROL ? "" : "INTERNAL-",
		 Stack->Parameters.DeviceIoControl.IoControlCode,
		 Stack->Parameters.DeviceIoControl.OutputBufferLength,
		 Stack->Parameters.DeviceIoControl.InputBufferLength,
		 Stack->Parameters.DeviceIoControl.Type3InputBuffer);
	break;
    case IRP_MJ_FILE_SYSTEM_CONTROL:
	switch (Stack->MinorFunction) {
	case IRP_MN_MOUNT_VOLUME:
	    DbgPrint("    FILE-SYSTEM-CONTROL  MOUNT-VOLUME Vpb %p DevObj %p\n",
		     Stack->Parameters.MountVolume.Vpb,
		     Stack->Parameters.MountVolume.DeviceObject);
	    break;
	default:
	    DbgPrint("    FILE-SYSTEM-CONTROL  UNKNOWN-MINOR-FUNCTION\n");
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
    default:
	DbgPrint("    UNKNOWN-MAJOR-FUNCTION\n");
    }
}

VOID IoDbgDumpIrp(IN PIRP Irp)
{
    DbgTrace("Dumping IRP %p type %d size %d\n", Irp, Irp->Type, Irp->Size);
    DbgPrint("    MdlAddress %p Flags 0x%08x IO Stack Location %p\n",
	     Irp->MdlAddress, Irp->Flags, IoGetCurrentIrpStackLocation(Irp));
    DbgPrint("    System Buffer %p User Buffer %p\n",
	     Irp->AssociatedIrp.SystemBuffer, Irp->UserBuffer);
    DbgPrint("    IO Status Block Status 0x%08x Information %p\n",
	     Irp->IoStatus.Status, (PVOID) Irp->IoStatus.Information);
    DbgPrint("    PRIV OriginalRequestor %p Identifier %p OutputBuffer %p\n",
	     (PVOID)Irp->Private.OriginalRequestor, Irp->Private.Identifier,
	     Irp->Private.OutputBuffer);
    DbgPrint("    PRIV CoroutineStackTop %p ForwardedTo %p(%p, ext %p) "
	     "ForwardedBy %p NotifyCompletion %s\n",
	     Irp->Private.CoroutineStackTop, Irp->Private.ForwardedTo,
	     (PVOID)IopGetDeviceHandle(Irp->Private.ForwardedTo),
	     Irp->Private.ForwardedTo ? Irp->Private.ForwardedTo->DeviceExtension : NULL,
	     Irp->Private.ForwardedBy, Irp->Private.NotifyCompletion ? "TRUE" : "FALSE");
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
    assert(DeviceObject != NULL);
    /* TODO: Call Fast IO routines if available */
    PDRIVER_DISPATCH DispatchRoutine = IopDriverObject.MajorFunction[IoStack->MajorFunction];
    NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
    if (DispatchRoutine != NULL) {
	Status = DispatchRoutine(DeviceObject, Irp);
    }
    return Status;
}

/*
 * Returns TRUE if Irp has been marked pending or if an IO completion
 * routine has been set for the IRP.
 */
static inline BOOLEAN IrpIsPending(IN PIRP Irp)
{
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    return (IoStack->Control & SL_PENDING_RETURNED) || (IoStack->CompletionRoutine != NULL);
}

/*
 * Complete the IRP. The IRP must not be suspended in a coroutine.
 */
static VOID IopCompleteIrp(IN PIRP Irp)
{
    assert(Irp->Private.CoroutineStackTop == NULL);

    /* Move the IRP into the list of IRPs to clean up at the end */
    RemoveEntryList(&Irp->Private.Link);
    InsertTailList(&IopCleanupIrpList, &Irp->Private.Link);

    /* For buffered IO, we need to copy the system buffer back to user output buffer */
    IopUnmarshalIoBuffer(Irp);

    /* If the IRP originates from the server, add the IRP to the
     * list of IRPs to reply to the server */
    assert(!IrpIsInReplyList(Irp));
    if (Irp->Private.OriginalRequestor) {
	InsertTailList(&IopReplyIrpList, &Irp->Private.ReplyListEntry);
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
     * (asynchronously) pending IRPs and IRPs suspended in a coroutine stack) */
    LoopOverList(Irp, &IopPendingIrpList, IRP, Private.Link) {
	if (Irp->Private.OriginalRequestor == Orig && Irp->Private.Identifier == Id) {
	    /* Fill the IO status block of the IRP with the result in the server message */
	    Irp->IoStatus = SrvMsg->ServerMsg.IoCompleted.IoStatus;
	    if (Irp->Private.CoroutineStackTop == NULL) {
		/* If the IRP is not suspended in a coroutine, we should run the IO
		 * completion routine. If it returns StopCompletion, IRP completion
		 * is halted and the IRP remains in pending state. Otherwise, IRP
		 * is completed. */
		PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
		if (IoStack->CompletionRoutine != NULL) {
		    NTSTATUS Status = IoStack->CompletionRoutine(IoStack->DeviceObject,
								 Irp, IoStack->Context);
		    if (Status == StopCompletion) {
			IoMarkIrpPending(Irp);
			continue;
		    }
		}
		/* Complete the IRP. This will detach the IRP from the queue and add
		 * it to the cleanup list. It will also add the IRP to the ReplyList
		 * if we are completing a server-originated IRP (ie. we are not
		 * completing an IRP that we sent out ourselves). */
		IopCompleteIrp(Irp);
		/* Also resume the object (IRP, AddDevice request, or IO workitem) that was
		 * pending due to the driver calling IoCallDriver on this IRP. */
		if (Irp->Private.ForwardedBy != NULL) {
		    PADD_DEVICE_REQUEST Req = (PADD_DEVICE_REQUEST)Irp->Private.ForwardedBy;
		    if (Req->Type == IOP_TYPE_ADD_DEVICE_REQUEST) {
			assert(Req->Size == sizeof(ADD_DEVICE_REQUEST));
			RemoveEntryList(&Req->Link);
			InsertTailList(&IopAddDeviceRequestList, &Req->Link);
		    } else if (Req->Type == IO_TYPE_IRP) {
			assert(Req->Size >= sizeof(IO_PACKET));
			PIRP PendingIrp = (PIRP) Req;
			/* This pending IRP should not have been forwarded by another IRP */
			assert(PendingIrp->Private.ForwardedBy == NULL);
			/* The pending IRP must have been suspended in a coroutine */
			assert(PendingIrp->Private.CoroutineStackTop != NULL);
			/* Move the pending IRP back to the queue so it will be resumed */
			RemoveEntryList(&PendingIrp->Private.Link);
			InsertTailList(&IopIrpQueue, &PendingIrp->Private.Link);
		    } else {
			PIO_WORKITEM WorkItem = (PIO_WORKITEM) Req;
			assert(WorkItem->Type == IOP_TYPE_WORKITEM);
			assert(WorkItem->Size == sizeof(IO_WORKITEM));
			/* Move the IO workitem back to the queue so it will be resumed */
			DbgTrace("Inserting work item %p back to the queue\n", WorkItem);
			assert(IopWorkItemIsInSuspendedList(WorkItem));
			RemoveEntryList(&WorkItem->SuspendedListEntry);
			RtlInterlockedPushEntrySList(&IopWorkItemQueue, &WorkItem->QueueEntry);
		    }
		    /* Set the pended object pointer to NULL. This is strictly speaking
		     * unnecessary but we want to make debugging easier. */
		    Irp->Private.ForwardedBy = NULL;
		}
	    } else {
		/* Else, we move the Irp back to the IRP queue so the coroutine
		 * can be resumed. */
		RemoveEntryList(&Irp->Private.Link);
		InsertTailList(&IopIrpQueue, &Irp->Private.Link);
	    }
	    return;
	}
    }
    /* We should never get here. If we do, either server sent an invalid IRP
     * identifier pair or we forgot to keep some IRPs in the pending IRP list. */
    assert(FALSE);
}

/*
 * Process the IRPs queued in the IrpQueue
 */
static VOID IopProcessIrpQueue()
{
    LoopOverList(Irp, &IopIrpQueue, IRP, Private.Link) {
	DbgTrace("Processing IRP from IRP queue:\n");
	IoDbgDumpIrp(Irp);
	NTSTATUS Status = STATUS_NTOS_BUG;
	IopCurrentObject = Irp;
	if (Irp->Private.CoroutineStackTop == NULL) {
	    /* Find the first available coroutine stack to use */
	    PVOID Stack = KiGetFirstAvailableCoroutineStack();
	    /* If KiGetFirstAvailableCoroutineStack returns NULL, it means that
	     * the system is out of memory. Simply stop processing and wait for
	     * memory to become available in the future. */
	    if (Stack == NULL) {
		break;
	    }
	    Irp->Private.CoroutineStackTop = Stack;
	    /* Switch to the coroutine stack and call the dispatch routine */
	    DbgTrace("Switching to coroutine stack top %p\n", Stack);
	    Status = KiStartCoroutine(Stack, IopCallDispatchRoutine, Irp);
	} else {
	    /* We are resuming a coroutine suspended due to IoCallDriver. */
	    DbgTrace("Resuming coroutine stack top %p. Saved SP %p\n",
		     Irp->Private.CoroutineStackTop,
		     KiGetCoroutineSavedSP(Irp->Private.CoroutineStackTop));
	    Status = KiResumeCoroutine(Irp->Private.CoroutineStackTop);
	}
	IopCurrentObject = NULL;
	/* If the dispatch function returns without suspending the coroutine,
	 * release the coroutine stack and set the IRP coroutine stack to NULL */
	if (Status != STATUS_ASYNC_PENDING) {
	    assert(Irp->Private.CoroutineStackTop != NULL);
	    KiReleaseCoroutineStack(Irp->Private.CoroutineStackTop);
	    Irp->Private.CoroutineStackTop = NULL;
	}
	/* If the dispatch routine is blocked waiting for an object,
	 * or if the dispatch function has marked the IRP as pending,
	 * or if the dispatch function has set an IO completion routine,
	 * add the IRP to the pending list so processing can resume later. */
	if (Status == STATUS_ASYNC_PENDING || IrpIsPending(Irp)) {
	    /* IRP cannot be marked completed in this case. */
	    assert(!Irp->Completed);
	    RemoveEntryList(&Irp->Private.Link);
	    InsertTailList(&IopPendingIrpList, &Irp->Private.Link);
	} else if (Irp->Completed) {
	    /* If the dispatch routine returned PENDING, but completed the IRP
	     * (say by calling IoStartPacket), complete the IRP. */
	    IopCompleteIrp(Irp);
	} else if (Status == STATUS_PENDING) {
	    /* The dispatch routine returned pending, but did not mark the IRP as
	     * pending or set an IO completion routine, it must have forwarded this
	     * IRP to a lower driver. We assert if this is not the case. */
	    assert(Irp->Private.ForwardedTo != NULL);
	    /* IRP cannot be marked completed in this case. */
	    assert(!Irp->Completed);
	    /* Move the IRP to the list of IRPs to clean up at the end, because
	     * it has been forwarded to the lower driver and requires no further
	     * processing at this level (since no IO completion routine is set). */
	    RemoveEntryList(&Irp->Private.Link);
	    InsertTailList(&IopCleanupIrpList, &Irp->Private.Link);
	    /* IoCallDriver adds the IRP to the ReplyList so we don't have to here */
	} else {
	    /* Otherwise, the dispatch routine has not explicitly marked the IRP
	     * as completed, but returned non-PENDING status, complete the IRP. */
	    assert(Irp->IoStatus.Status == Status);
	    IopCompleteIrp(Irp);
	}
    }
}

/*
 * This is the coroutine entry point for the AddDevice routines
 */
FASTCALL NTSTATUS IopCallAddDeviceRoutine(IN PVOID Context) /* %ecx/%rcx */
{
    PADD_DEVICE_REQUEST Req = (PADD_DEVICE_REQUEST)Context;
    assert(Req != NULL);
    assert(Req->Type == IOP_TYPE_ADD_DEVICE_REQUEST);
    assert(Req->Size == sizeof(ADD_DEVICE_REQUEST));
    assert(Req->AddDevice != NULL);
    assert(Req->PhyDevObj != NULL);
    assert(Req->CoroutineStackTop != NULL);
    return Req->AddDevice(&IopDriverObject, Req->PhyDevObj);
}

/*
 * Process the AddDevice requests queued in the AddDeviceRequestList
 */
static VOID IopProcessAddDeviceRequests()
{
    NTSTATUS Status = STATUS_NTOS_BUG;
    LoopOverList(Req, &IopAddDeviceRequestList, ADD_DEVICE_REQUEST, Link) {
	IopCurrentObject = Req;
	if (Req->CoroutineStackTop == NULL) {
	    /* If we are not resuming a previous AddDevice invocation,
	     * Find the first available coroutine stack to use */
	    PVOID Stack = KiGetFirstAvailableCoroutineStack();
	    /* If KiGetFirstAvailableCoroutineStack returns NULL, it means that
	     * the system is out of memory. Simply stop processing and wait for
	     * memory to become available in the future. */
	    if (Stack == NULL) {
		return;
	    }
	    Req->CoroutineStackTop = Stack;
	    /* Switch to the coroutine stack and call the dispatch routine */
	    DbgTrace("Switching to coroutine stack top %p for AddDevice routine\n", Stack);
	    Status = KiStartCoroutine(Stack, IopCallAddDeviceRoutine, Req);
	} else {
	    /* Else, we are resuming a previous AddDevice invocation. */
	    DbgTrace("Resuming coroutine stack top %p for AddDevice routine. Saved SP %p\n",
		     Req->CoroutineStackTop,
		     KiGetCoroutineSavedSP(Req->CoroutineStackTop));
	    Status = KiResumeCoroutine(Req->CoroutineStackTop);
	}
	IopCurrentObject = NULL;
	RemoveEntryList(&Req->Link);
	/* If the AddDevice routine is blocked on waiting for an object,
	 * suspend the coroutine and process the next AddDevice request. */
	if (Status == STATUS_ASYNC_PENDING) {
	    DbgTrace("Suspending AddDevice routine, coroutine stack %p, saved SP %p\n",
		     Req->CoroutineStackTop,
		     KiGetCoroutineSavedSP(Req->CoroutineStackTop));
	    assert(KiGetCoroutineSavedSP(Req->CoroutineStackTop) != NULL);
	    InsertTailList(&IopSuspendedAddDeviceRequestList, &Req->Link);
	} else {
	    /* Otherwise, the AddDevice routine has completed. Release the
	     * coroutine stack and move the AddDevice routine to the list
	     * of completed AddDevice requests. */
	    assert(Status != STATUS_PENDING);
	    assert(Req->CoroutineStackTop != NULL);
	    KiReleaseCoroutineStack(Req->CoroutineStackTop);
	    Req->CoroutineStackTop = NULL;
	    InsertTailList(&IopCompletedAddDeviceRequestList, &Req->Link);
	    Req->Status = Status;
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
    if (SrcIoPacket->Request.MajorFunction == IRP_MJ_ADD_DEVICE) {
	PDRIVER_ADD_DEVICE AddDevice = IopDriverObject.AddDevice;
	if (AddDevice == NULL) {
	    return STATUS_NOT_IMPLEMENTED;
	}
	GLOBAL_HANDLE PhyDevHandle = SrcIoPacket->Request.Device.Handle;
	IO_DEVICE_INFO PhyDevInfo = SrcIoPacket->Request.AddDevice.PhysicalDeviceInfo;
	PDEVICE_OBJECT PhyDev = IopGetDeviceObjectOrCreate(PhyDevHandle, PhyDevInfo);
	if (PhyDev == NULL) {
	    return STATUS_NO_MEMORY;
	}
	IopAllocateObject(Req, ADD_DEVICE_REQUEST);
	Req->Type = IOP_TYPE_ADD_DEVICE_REQUEST;
	Req->Size = sizeof(ADD_DEVICE_REQUEST);
	Req->AddDevice = AddDevice;
	Req->PhyDevObj = PhyDev;
	Req->OriginalRequestor = SrcIoPacket->Request.OriginalRequestor;
	Req->Identifier = SrcIoPacket->Request.Identifier;
	InsertTailList(&IopAddDeviceRequestList, &Req->Link);
    } else {
	IopAllocatePool(Irp, IRP, IO_SIZE_OF_IRP);
	IoInitializeIrp(Irp);
	Irp->Private.OriginalRequestor = SrcIoPacket->Request.OriginalRequestor;
	Irp->Private.Identifier = SrcIoPacket->Request.Identifier;
	NTSTATUS Status = IopPopulateLocalIrpFromServerIoPacket(Irp, SrcIoPacket);
	if (!NT_SUCCESS(Status)) {
	    IopFreePool(Irp);
	    return Status;
	}
	InsertTailList(&IopIrpQueue, &Irp->Private.Link);
    }
    return STATUS_SUCCESS;
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

    /* Process all the queued DPC objects first. */
    IopProcessDpcQueue();

    /* Process the AddDevice requests. Normally there should only be one
     * such request, but we make it flexible here. */
    IopProcessAddDeviceRequests();

    /* Process all queued IRP now. Once processed, the IRPs are moved to either
     * the PendingIrpList or the CleanupIrpList. IRPs may also optionally be a
     * member of the ReplyIrpList. */
    IopProcessIrpQueue();
    /* The IRP queue should be empty after the queue is processed. We never leave
     * an IRP in the queue: it's either in the PendingList or the CleanupList. */
    assert(IsListEmpty(&IopIrpQueue));

    /* Traverse the ReplyList and see if any of the IRPs is being forwarded
     * to a local device object (ie. back to the same driver). This is an error.
     * On debug build we assert. On release build this is skipped. */
    LoopOverList(Irp, &IopReplyIrpList, IRP, Private.ReplyListEntry) {
	/* These will return FALSE if remaining size is too small for the IO packet */
	if (Irp->Private.ForwardedTo != NULL) {
	    assert(!IopDeviceObjectIsLocal(Irp->Private.ForwardedTo));
	    assert(Irp->Private.ForwardedTo->DriverObject == NULL);
	}
    }

    /* Now process the IO work item queue */
    IopProcessWorkItemQueue();

    /* Traverse the pending IRP list to see if any of them was completed by the IO
     * work item, in which case we move it to the reply list and the cleanup list. */
    LoopOverList(Irp, &IopPendingIrpList, IRP, Private.Link) {
	if (Irp->Completed) {
	    IopCompleteIrp(Irp);
	}
    }

    /* Since the incoming buffer and outgoing buffer have the same size we should never
     * run out of outgoing buffer at this point. */
    assert(ResponseCount <= DRIVER_IO_PACKET_BUFFER_COMMIT / sizeof(IO_PACKET));
    ULONG RemainingBufferSize = DRIVER_IO_PACKET_BUFFER_COMMIT - ResponseCount*sizeof(IO_PACKET);

    /* Send the IoCompleted IO packet to inform the server of the AddDevice request completion */
    PIO_PACKET DestIrp = IopOutgoingIoPacketBuffer + ResponseCount;
    LoopOverList(Req, &IopCompletedAddDeviceRequestList, ADD_DEVICE_REQUEST, Link) {
	if (RemainingBufferSize < sizeof(IO_PACKET)) {
	    break;
	}
	IopPopulateIoCompleteMessageFromIoStatus(DestIrp, Req->Status, Req->OriginalRequestor,
						 Req->Identifier);
	RemoveEntryList(&Req->Link);
	IopFreePool(Req);
	DestIrp++;
	RemainingBufferSize -= sizeof(IO_PACKET);
	ResponseCount++;
    }

    /* Move the completed IRPs to the outgoing buffer. */
    LoopOverList(Irp, &IopReplyIrpList, IRP, Private.ReplyListEntry) {
	/* This will become FALSE if remaining size is too small for the IO packet */
	BOOLEAN Continue = FALSE;
	if (Irp->Completed) {
	    Continue = IopPopulateIoCompleteMessageFromLocalIrp(DestIrp, Irp,
								RemainingBufferSize);
	} else if (Irp->Private.OriginalRequestor != 0) {
	    assert(Irp->Private.ForwardedTo != NULL);
	    assert(Irp->Private.ForwardedTo->DriverObject == NULL);
	    Continue = IopPopulateForwardIrpMessage(DestIrp, Irp, RemainingBufferSize);
	} else {
	    assert(Irp->Private.ForwardedTo != NULL);
	    assert(Irp->Private.ForwardedTo->DriverObject == NULL);
	    Continue = IopPopulateIoRequestMessage(DestIrp, Irp, RemainingBufferSize);
	}
	if (!Continue) {
	    break;
	}
	/* Detach this entry from the reply IRP list */
	RemoveEntryList(&Irp->Private.ReplyListEntry);
	assert(DestIrp->Size >= sizeof(IO_PACKET));
	assert(RemainingBufferSize >= DestIrp->Size);
	DbgTrace("Replying to server with the following IO packet\n");
	IoDbgDumpIoPacket(DestIrp, TRUE);
	DestIrp = (PIO_PACKET)((MWORD)DestIrp + DestIrp->Size);
	RemainingBufferSize -= DestIrp->Size;
	ResponseCount++;
	if (RemainingBufferSize < DestIrp->Size) {
	    break;
	}
    }

    /* Clean up the list of IRPs marked for deletion */
    LoopOverList(Irp, &IopCleanupIrpList, IRP, Private.Link) {
	RemoveEntryList(&Irp->Private.Link);
	IopDeleteIrp(Irp);
    }

    *pNumResponses = ResponseCount;
}

/*
 * Mark the IRP as completed
 *
 * NOTE: we do NOT run the IO completion routine here. IO completion
 * routines are run when the server has sent us a IoCompleted message.
 */
NTAPI VOID IoCompleteRequest(IN PIRP Irp,
			     IN CHAR PriorityBoost)
{
    DbgTrace("Completing IRP %p\n", Irp);
    IoDbgDumpIrp(Irp);
    assert(Irp != NULL);
    /* Never complete an IRP with pending status */
    assert(Irp->IoStatus.Status != STATUS_PENDING);
    assert(Irp->IoStatus.Status != STATUS_ASYNC_PENDING);
    /* -1 is an invalid NTSTATUS */
    assert(Irp->IoStatus.Status != -1);
    /* IRP must be either in the pending list or in the IRP queue */
    assert(IrpIsInPendingList(Irp) || IrpIsInIrpQueue(Irp));
    Irp->PriorityBoost = PriorityBoost;
    /* Simply mark the IRP as completed. The event loop will scan
     * the pending IRP list at appropriate time. */
    Irp->Completed = TRUE;
    /* Remove the IRP pending flag */
    IoGetCurrentIrpStackLocation((Irp))->Control &= ~SL_PENDING_RETURNED;
    if (Irp->Flags & IRP_ASSOCIATED_IRP) {
	IoCompleteRequest(Irp->AssociatedIrp.MasterIrp, PriorityBoost);
    }
};

/*
 * Forward the specified IRP to the specified device object.
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
 * the driver itself. In this case the dispatch routine is called directly
 * and effectively all IRP forwarding (at this level of the device stack) is
 * synchronous. Note that since our IRP stack has exacly one stack location
 * there can only be one IO completion routine (the top-level one) for each
 * IRP.
 *
 * NOTE: Synchronous forwarding of IRP must occur in a coroutine. IoCallDriverEx
 * returns error if synchronous IRP forwarding is specified but no current
 * coroutine stack is found. In particular, you cannot forward IRPs synchronously
 * in a DPC or StartIO routine. This is the same as Windows/ReactOS: DPC and
 * StartIO routines run in DISPATCH_LEVEL so you cannot sleep.
 *
 * Microsoft discourages higher-level drivers from having a StartIO routine
 * to begin with, let alone call lower-level drivers in a StartIO routines [1].
 * It is nonetheless possible to do so, if you forward the IRP asynchronously.
 *
 * [1] docs.microsoft.com/en-us/windows-hardware/drivers/kernel/startio-routines-in-higher-level-drivers
 */
NTAPI NTSTATUS IoCallDriverEx(IN PDEVICE_OBJECT DeviceObject,
			      IN OUT PIRP Irp,
			      IN PLARGE_INTEGER Timeout)
{
    /* TODO: The case with a non-zero timeout is NOT implemented yet. This is not
     * used frequently so we are good so far. To implement this, add a new Timeout
     * member to the Irp->Private struct and inform the server of the timeout. We
     * will need to calculate the absolute time if timeout is relative. */
    assert(Timeout == NULL || Timeout->QuadPart == 0);
    assert(DeviceObject != NULL);
    assert(Irp != NULL);
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    assert(IoStack->DeviceObject != NULL);
    if (IopDeviceObjectIsLocal(DeviceObject)) {
	/* If we are forwarding this IRP to a local device object, just call
	 * the dispatch routine directly. Note drivers should generally avoid
	 * doing this. In particular, for IOCTL IRPs forwarded to local device
	 * objects, the IO tranfer type of the IOCTL code is ignored and we
	 * always assume NEITHER IO. */
	PDRIVER_DISPATCH DispatchRoutine = IopDriverObject.MajorFunction[IoStack->MajorFunction];
	NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
	PDEVICE_OBJECT OldDeviceObject = IoStack->DeviceObject;
	IoStack->DeviceObject = DeviceObject;
	if (DispatchRoutine != NULL) {
	    Status = DispatchRoutine(DeviceObject, Irp);
	}
	IoStack->DeviceObject = OldDeviceObject;
	return Status;
    }

    /* We are forwarding this IRP to a foreign device object. In this case
     * it can only be forwarded once. */
    assert(Irp->Private.ForwardedTo == NULL);
    assert(Irp->Private.ForwardedBy == NULL);
    /* Determine whether we should forward the IRP synchronously or asynchronously */
    BOOLEAN Wait = FALSE;
    if (Irp->UserIosb != NULL || Timeout == NULL || Timeout->QuadPart != 0) {
	Wait = TRUE;
    }
    DbgTrace("Forwarding Irp %p to DeviceObject %p(%p) %ssynchronously\n", Irp,
	     DeviceObject, (PVOID)IopGetDeviceHandle(DeviceObject),
	     Wait ? "" : "a");
    IoDbgDumpIrp(Irp);
    if (Wait && KiCurrentCoroutineStackTop == NULL) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    Irp->Private.ForwardedTo = DeviceObject;
    /* Add the IRP to the list of IRPs to be forwarded to the server.
     * The IRP must not already have been in the ReplyList. */
    assert(!IrpIsInReplyList(Irp));
    InsertTailList(&IopReplyIrpList, &Irp->Private.ReplyListEntry);
    /* If we are forwarding the IRP synchronously, or if an IO completion routine
     * has been set, then we ask the server to notify us so we can either resume
     * the coroutine or run the IO completion routine. */
    Irp->Private.NotifyCompletion = (Wait || IoStack->CompletionRoutine != NULL);
    /* If this is a new IRP, add it to either the PendingList or the CleanupList,
     * depending on whether we expect the server to inform us of its completion. */
    if (Irp->Private.OriginalRequestor == 0) {
	assert(Irp->Private.Link.Blink == NULL);
	assert(Irp->Private.Link.Flink == NULL);
	assert(Irp->Private.Identifier == NULL);
	Irp->Private.Identifier = Irp;
	if (Irp->Private.NotifyCompletion) {
	    InsertTailList(&IopPendingIrpList, &Irp->Private.Link);
	} else {
	    InsertTailList(&IopCleanupIrpList, &Irp->Private.Link);
	}
    }
    /* If we are not waiting for the completion of the IRP, simply return */
    if (!Wait) {
	return STATUS_IRP_FORWARDED;
    }

    /* Otherwise, we are forwarding the IRP synchronously. We must have a
     * coroutine stack in this case.  */
    assert(KiCurrentCoroutineStackTop != NULL);
    /* Record the current Irp or AddDevice request so we know which IRP to
     * wake up when we receive a IoCompleted message for this IRP */
    if (IopCurrentObject != Irp) {
	Irp->Private.ForwardedBy = IopCurrentObject;
    }
    DbgTrace("Suspending coroutine stack %p\n", KiCurrentCoroutineStackTop);
    /* Yield the current coroutine to the main thread. The control flow will
     * return to either KiStartCoroutine or KiResumeCoroutine. */
    KiYieldCoroutine();
    /* Return the final IO status of the IRP */
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
