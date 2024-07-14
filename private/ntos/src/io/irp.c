#include "iop.h"

LIST_ENTRY IopNtosPendingIrpList;

#define SERVER_OBJECT_TO_CLIENT_HANDLE(o)				\
    ((POBJECT)(o) == IOP_PAGING_IO_REQUESTOR ? (GLOBAL_HANDLE)(o) : OBJECT_TO_GLOBAL_HANDLE(o))
#define CLIENT_HANDLE_TO_SERVER_OBJECT(o)				\
    ((o) == (MWORD)IOP_PAGING_IO_REQUESTOR ? (PVOID)(o) : GLOBAL_HANDLE_TO_OBJECT(o))

static NTSTATUS IopAllocateIoPacket(IN IO_PACKET_TYPE Type,
				    IN ULONG Size,
				    OUT PIO_PACKET *pIoPacket)
{
    assert(pIoPacket != NULL);
    assert(Size >= sizeof(IO_PACKET));
    ExAllocatePoolEx(IoPacket, IO_PACKET, Size, NTOS_IO_TAG, {});
    IoPacket->Type = Type;
    IoPacket->Size = Size;
    *pIoPacket = IoPacket;
    return STATUS_SUCCESS;
}

static VOID IopFreeIoPacket(IN PIO_PACKET IoPacket)
{
    if (IoPacket->Type == IoPacketTypeRequest) {
	if (IoPacket->Request.InputBufferPfn) {
	    IopFreePool((PVOID)IoPacket->Request.InputBufferPfn);
	}
	if (IoPacket->Request.OutputBufferPfn) {
	    IopFreePool((PVOID)IoPacket->Request.OutputBufferPfn);
	}
    }
    IopFreePool(IoPacket);
}

static NTSTATUS IopAllocatePendingIrp(IN PIO_PACKET IoPacket,
				      IN POBJECT Requestor,
				      OUT PPENDING_IRP *pPendingIrp)
{
    assert(IoPacket != NULL);
    assert(Requestor != NULL);
    assert(pPendingIrp != NULL);
    IopAllocatePool(PendingIrp, PENDING_IRP);
    PendingIrp->IoPacket = IoPacket;
    PendingIrp->Requestor = Requestor;
    /* This is needed so RemoveEntryList(&PendingIrp->Link) is a no-op
     * even if the PendingIrp has not been inserted into any list. */
    InitializeListHead(&PendingIrp->Link);
    KeInitializeEvent(&PendingIrp->IoCompletionEvent, NotificationEvent);
    assert(Requestor == IOP_PAGING_IO_REQUESTOR ||
	   ObObjectIsType(Requestor, OBJECT_TYPE_DRIVER) ||
	   ObObjectIsType(Requestor, OBJECT_TYPE_THREAD));
    *pPendingIrp = PendingIrp;
    return STATUS_SUCCESS;
}

static VOID IopFreePendingIrp(IN PPENDING_IRP PendingIrp)
{
    KeUninitializeEvent(&PendingIrp->IoCompletionEvent);
    if (PendingIrp->IoResponseData != NULL) {
	IopFreePool(PendingIrp->IoResponseData);
	PendingIrp->IoResponseData = NULL;
    }
    IopFreePool(PendingIrp);
}

/*
 * Detach the given pending IRP from the thread that it has been queued on.
 * Free the IO response data, and delete both the IO packet struct and the
 * PENDING_IRP struct itself. You must eventually call this after every
 * successful call to IopCallDriver or IopCallDriverEx.
 */
VOID IopCleanupPendingIrp(IN PPENDING_IRP PendingIrp)
{
    RemoveEntryList(&PendingIrp->Link);
    if (PendingIrp->IoPacket != NULL) {
	IopFreeIoPacket(PendingIrp->IoPacket);
    }
    IopFreePendingIrp(PendingIrp);
}

/*
 * Returns the IO_PACKET queued in the driver object's PendingIoPacketList,
 * given the handle pair (OriginalRequestor, IrpIdentifier) that uniquely
 * identifies the IO_PACKET (currently).
 */
static PIO_PACKET IopLocateIrpInDriverPendingList(IN PIO_DRIVER_OBJECT DriverObject,
						  IN GLOBAL_HANDLE OriginalRequestor,
						  IN HANDLE IrpIdentifier)
{
    PIO_PACKET CompletedIrp = NULL;
    LoopOverList(PendingIoPacket, &DriverObject->PendingIoPacketList,
		 IO_PACKET, IoPacketLink) {
	/* The IO packets in the pending IO packet list must be of type
	 * IoPacketTypeRequest. We never put IoPacketTypeClientMessage etc
	 * into the pending IO packet list. */
	assert(PendingIoPacket->Type == IoPacketTypeRequest);
	if ((PendingIoPacket->Request.OriginalRequestor == OriginalRequestor) &&
	    (PendingIoPacket->Request.Identifier == IrpIdentifier)) {
	    CompletedIrp = PendingIoPacket;
	}
    }
    return CompletedIrp;
}

/*
 * Returns the first PENDING_IRP for which the Locator evaluates to TRUE.
 * Note that for driver objects this searches the ForwardedIrpList not the
 * PendingIoPacketList. The latter is used for a different purpose (see iop.h).
 */
typedef BOOLEAN (*PPENDING_IRP_LOCATOR)(IN PPENDING_IRP PendingIrp,
					IN PVOID Context);
static PPENDING_IRP
IopLocatePendingIrpInOriginalRequestor(IN GLOBAL_HANDLE OriginalRequestor,
				       IN PPENDING_IRP_LOCATOR Locator,
				       IN PVOID Context)
{
    POBJECT RequestorObject = CLIENT_HANDLE_TO_SERVER_OBJECT(OriginalRequestor);
    if (RequestorObject == IOP_PAGING_IO_REQUESTOR) {
	LoopOverList(PendingIrp, &IopNtosPendingIrpList, PENDING_IRP, Link) {
	    assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	    assert(PendingIrp->IoPacket->Request.OriginalRequestor == OriginalRequestor);
	    if (Locator(PendingIrp, Context)) {
		assert(PendingIrp->Requestor == RequestorObject);
		return PendingIrp;
	    }
	}
    } else if (ObObjectIsType(RequestorObject, OBJECT_TYPE_THREAD)) {
	PTHREAD Thread = (PTHREAD)RequestorObject;
	LoopOverList(PendingIrp, &Thread->PendingIrpList, PENDING_IRP, Link) {
	    assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	    assert(PendingIrp->IoPacket->Request.OriginalRequestor == OriginalRequestor);
	    if (Locator(PendingIrp, Context)) {
		assert(PendingIrp->Requestor == RequestorObject);
		return PendingIrp;
	    }
	}
    } else if (ObObjectIsType(RequestorObject, OBJECT_TYPE_DRIVER)) {
	PIO_DRIVER_OBJECT Driver = (PIO_DRIVER_OBJECT)RequestorObject;
	LoopOverList(PendingIrp, &Driver->ForwardedIrpList, PENDING_IRP, Link) {
	    assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	    assert(PendingIrp->IoPacket->Request.OriginalRequestor == OriginalRequestor);
	    if (Locator(PendingIrp, Context)) {
		assert(PendingIrp->Requestor == RequestorObject);
		return PendingIrp;
	    }
	}
    } else {
	assert(FALSE);
    }
    return NULL;
}

/*
 * Returns the PENDING_IRP struct of the given IO_PACKET.
 */
static BOOLEAN IopIoPacketLocator(IN PPENDING_IRP PendingIrp,
				  IN PVOID IoPacket)
{
    return PendingIrp->IoPacket == IoPacket;
}
static PPENDING_IRP IopLocateIrpInOriginalRequestor(IN GLOBAL_HANDLE OriginalRequestor,
						    IN PIO_PACKET IoPacket)
{
    return IopLocatePendingIrpInOriginalRequestor(OriginalRequestor,
						  IopIoPacketLocator, IoPacket);
}

/*
 * Returns the PENDING_IRP struct of the given IRP identifier.
 */
static BOOLEAN IopIrpIdLocator(IN PPENDING_IRP PendingIrp,
			       IN PVOID Identifier)
{
    return PendingIrp->IoPacket->Request.Identifier == Identifier;
}
static PPENDING_IRP IopLocateIrpIdInOriginalRequestor(IN GLOBAL_HANDLE OriginalRequestor,
						      IN HANDLE Identifier)
{
    return IopLocatePendingIrpInOriginalRequestor(OriginalRequestor,
						  IopIrpIdLocator, Identifier);
}

static VOID IopDumpDriverPendingIoPacketList(IN PIO_DRIVER_OBJECT DriverObject,
					     IN GLOBAL_HANDLE OriginalRequestor,
					     IN HANDLE IrpIdentifier)
{
    DbgTrace("Received response packet from driver %s with invalid IRP identifier %p:%p."
	     " Dumping all IO packets in the driver's pending IO packet list.\n",
	     DriverObject->DriverImagePath, (PVOID)OriginalRequestor, IrpIdentifier);
    LoopOverList(PendingIoPacket, &DriverObject->PendingIoPacketList,
		 IO_PACKET, IoPacketLink) {
	IoDbgDumpIoPacket(PendingIoPacket, FALSE);
    }
}

NTSTATUS IopWaitForMultipleIoCompletions(IN ASYNC_STATE State,
					 IN PTHREAD Thread,
					 IN BOOLEAN Alertable,
					 IN WAIT_TYPE WaitType,
					 IN PPENDING_IRP *PendingIrps,
					 IN ULONG IrpCount)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ASYNC_BEGIN(State, Locals, {
	    PDISPATCHER_HEADER *DspObjs;
	});
    if (!IrpCount) {
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }
    Locals.DspObjs = (PDISPATCHER_HEADER *)ExAllocatePoolWithTag(sizeof(PVOID) * IrpCount,
								 NTOS_IO_TAG);
    if (Locals.DspObjs == NULL) {
	ASYNC_RETURN(State, STATUS_NO_MEMORY);
    }
    for (ULONG i = 0; i < IrpCount; i++) {
	assert(PendingIrps[i] != NULL);
	Locals.DspObjs[i] = &PendingIrps[i]->IoCompletionEvent.Header;
    }
    AWAIT_EX(Status, KeWaitForMultipleObjects, State, Locals, Thread, Alertable,
	     WaitType, Locals.DspObjs, IrpCount, NULL);
    assert(Locals.DspObjs != NULL);
    ExFreePoolWithTag(Locals.DspObjs, NTOS_IO_TAG);
    ASYNC_END(State, Status);
}

/*
 * Maps the specified user IO buffer to the driver process's VSpace.
 *
 * If ReadOnly is TRUE, the driver pages will be mapped read-only. Otherwise
 * the driver pages will be mapped read-write.
 *
 * If ReadOnly is FALSE, the user IO buffer must be writable by the user.
 * Otherwise STATUS_INVALID_PAGE_PROTECTION is returned.
 */
static NTSTATUS IopMapUserBuffer(IN PVIRT_ADDR_SPACE UserVSpace,
				 IN PIO_DRIVER_OBJECT Driver,
				 IN MWORD UserBufferStart,
				 IN MWORD UserBufferLength,
				 OUT MWORD *DriverBufferStart,
				 IN BOOLEAN ReadOnly)
{
    assert(UserVSpace != NULL);
    DbgTrace("Mapping user buffer %p from vspace cap 0x%zx into driver %s\n",
	     (PVOID)UserBufferStart, UserVSpace->VSpaceCap, Driver->DriverImagePath);
    assert(Driver->DriverProcess != NULL);
    PVIRT_ADDR_SPACE DriverVSpace = &Driver->DriverProcess->VSpace;
    assert(DriverVSpace != NULL);
    if (UserBufferStart != 0 && UserBufferLength != 0) {
	RET_ERR(MmMapUserBufferEx(UserVSpace, UserBufferStart,
				  UserBufferLength, DriverVSpace,
				  USER_IMAGE_REGION_START,
				  USER_IMAGE_REGION_END,
				  DriverBufferStart, ReadOnly));
	DbgTrace("Mapped driver buffer for %s at %p\n",
		 Driver->DriverImagePath, (PVOID)*DriverBufferStart);
    }
    return STATUS_SUCCESS;
}

/*
 * Unmap the user buffer mapped by IopMapUserBuffer
 */
static VOID IopUnmapUserBuffer(IN PIO_DRIVER_OBJECT Driver,
			       IN MWORD DriverBuffer)
{
    assert(Driver != NULL);
    assert(Driver->DriverProcess != NULL);
    DbgTrace("Unmapping driver %s (VSpace cap 0x%zx) buffer %p\n",
	     Driver->DriverImagePath, Driver->DriverProcess->VSpace.VSpaceCap,
	     (PVOID)DriverBuffer);
    if (DriverBuffer != 0) {
	MmUnmapRegion(&Driver->DriverProcess->VSpace, DriverBuffer);
    }
}

typedef enum _IO_TRANSFER_TYPE {
    MappedIo = 1, /* If data size is small, embed data in the IRP. Otherwise map. */
    DirectIo, /* Only send MDL. Do not map the buffer into driver address space */
    MappedDirectIo /* Send MDL and map the buffer into driver address space.
		    * Note this is equal to MappedIo | DirectIo. */
} IO_TRANSFER_TYPE;

/*
 * Map the IO buffers into the target driver address space.
 *
 * Before calling this routine, the IO buffers in the IO_PACKET are
 * pointers in the requestor address space. After this routine returns
 * with SUCCESS status, the IO buffers in the IO_PACKET are updated to
 * the pointers in the target driver address space, and the original
 * IO buffer pointers are saved into the PENDING_IRP struct.
 */
NTSTATUS IopMapIoBuffers(IN PPENDING_IRP PendingIrp)
{
    assert(PendingIrp->IoPacket);
    assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
    PIO_REQUEST_PARAMETERS Irp = &PendingIrp->IoPacket->Request;
    assert(PendingIrp->Requestor != NULL);
    MWORD InputBuffer = Irp->InputBuffer;
    MWORD InputBufferLength = Irp->InputBufferLength;
    MWORD OutputBuffer = Irp->OutputBuffer;
    MWORD OutputBufferLength = Irp->OutputBufferLength;
    PVIRT_ADDR_SPACE RequestorVSpace = NULL;
    if (PendingIrp->Requestor == IOP_PAGING_IO_REQUESTOR) {
	extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
	RequestorVSpace = &MiNtosVaddrSpace;
    } else if (ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_THREAD)) {
	RequestorVSpace = &((PTHREAD)PendingIrp->Requestor)->Process->VSpace;
    } else {
	assert(ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_DRIVER));
	RequestorVSpace = &((PIO_DRIVER_OBJECT)PendingIrp->Requestor)->DriverProcess->VSpace;
    }
    assert(RequestorVSpace != NULL);

    PIO_DEVICE_OBJECT DeviceObject = Irp->Device.Object;
    assert(DeviceObject != NULL);
    PIO_DRIVER_OBJECT DriverObject = DeviceObject->DriverObject;
    assert(DriverObject != NULL);

    /* Determine the IO transfer type of the input buffer and the output buffer */
    IO_TRANSFER_TYPE InputIoType = MappedIo, OutputIoType = MappedIo;
    BOOLEAN OutputIsReadOnly = FALSE;
    if (Irp->MajorFunction == IRP_MJ_DEVICE_CONTROL ||
	Irp->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
	ULONG Ioctl = Irp->DeviceIoControl.IoControlCode;
	if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_IN_DIRECT ||
	    METHOD_FROM_CTL_CODE(Ioctl) == METHOD_OUT_DIRECT) {
	    /* Ioctl dispatch functions typically need to access the memory
	     * mapped by the MDL, so we always map the buffer for direct IO. */
	    OutputIoType |= DirectIo;
	    /* If the IOCTL has type METHOD_IN_DIRECT, the OutputBuffer
	     * is used as an input buffer (yes, I know, Microsoft loves
	     * to be confusing) and will be mapped read-only. */
	    OutputIsReadOnly = METHOD_FROM_CTL_CODE(Ioctl) == METHOD_IN_DIRECT;
	}
    } else if (DeviceObject->DeviceInfo.Flags & DO_DIRECT_IO) {
	InputIoType = DirectIo;
	OutputIoType = DirectIo;
	if (DeviceObject->DeviceInfo.Flags & DO_MAP_IO_BUFFER) {
	    InputIoType |= MappedIo;
	    OutputIoType |= MappedIo;
	}
    }

    /* If a non-NULL InputBuffer is given, InputBufferLength cannot be zero. */
    if (InputBuffer && !InputBufferLength) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* For DIRECT_IO, the buffer pointers cannot be an offset. */
    if ((InputIoType & DirectIo) && (InputBuffer && InputBuffer < PAGE_SIZE)) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* For DIRECT_IO, the input buffer length must be large enough. This check
     * is needed for malicious clients that circumvent the normal system service
     * interfaces in ntdll. */
    if ((InputIoType & DirectIo) &&
	(InputBufferLength && InputBufferLength < IRP_DATA_BUFFER_SIZE)) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* If the requestor specified a NULL OutputBuffer with a non-zero
     * OutputBufferLength and the target device is not a mounted file system,
     * it wants the driver to embed the data in the IRP, in which case the
     * data size cannot be too large. In the case of a mounted file system,
     * a READ IRP with a NULL OutputBuffer comes from the cache manager which
     * will take care of mapping the cache pages later */
    if (!OutputBuffer && !((DeviceObject->Vcb && Irp->MajorFunction == IRP_MJ_READ) ||
			   OutputBufferLength < IRP_DATA_BUFFER_SIZE)) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* If the OutputBuffer is not NULL, it is always interpreted as a pointer
     * in the requestor address space (and never as an offset, unlike the case
     * of InputBuffer), so it cannot be less than PAGE_SIZE. Additionally, in
     * this case the output buffer length cannot be zero. */
    if (OutputBuffer && (OutputBuffer < PAGE_SIZE || !OutputBufferLength)) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* Generate the PFN database if input IO type is direct IO */
    if (Irp->InputBuffer && (InputIoType & DirectIo)) {
	assert(Irp->InputBuffer >= PAGE_SIZE);
	assert(Irp->InputBufferLength >= IRP_DATA_BUFFER_SIZE);
	if (!Irp->InputBufferPfn) {
	    assert(!Irp->InputBufferPfnCount);
	    if (!MmGeneratePageFrameDatabase(NULL, RequestorVSpace, InputBuffer,
					     InputBufferLength, &Irp->InputBufferPfnCount)) {
		assert(FALSE);
		return STATUS_INVALID_USER_BUFFER;
	    }
	    assert(Irp->InputBufferPfnCount);
	    IopAllocateArray(PfnDb, MWORD, Irp->InputBufferPfnCount);
	    Irp->InputBufferPfn = (MWORD)PfnDb;
	    MmGeneratePageFrameDatabase((PULONG_PTR)PfnDb, RequestorVSpace,
					InputBuffer, InputBufferLength, NULL);
	    DbgTrace("Generated PFN database for input buffer %p, db %p count %d\n",
		     (PVOID)InputBuffer, PfnDb, Irp->InputBufferPfnCount);
	}
	assert(Irp->InputBufferPfnCount);
	Irp->Flags |= IOP_IRP_INPUT_DIRECT_IO;
    } else {
	/* We need to clear the INPUT_DIRECT_IO flag because a previous
	 * device object might be DIRECT_IO. */
	Irp->Flags &= ~IOP_IRP_INPUT_DIRECT_IO;
    }

    /* Generate the PFN database if output IO type is direct IO */
    if (Irp->OutputBuffer && (OutputIoType & DirectIo)) {
	assert(Irp->OutputBuffer >= PAGE_SIZE);
	assert(Irp->OutputBufferLength >= IRP_DATA_BUFFER_SIZE);
	if (!Irp->OutputBufferPfn) {
	    assert(!Irp->OutputBufferPfnCount);
	    if (!MmGeneratePageFrameDatabase(NULL, RequestorVSpace, OutputBuffer,
					     OutputBufferLength, &Irp->OutputBufferPfnCount)) {
		assert(FALSE);
		return STATUS_INVALID_USER_BUFFER;
	    }
	    assert(Irp->OutputBufferPfnCount);
	    IopAllocateArray(PfnDb, MWORD, Irp->OutputBufferPfnCount);
	    Irp->OutputBufferPfn = (MWORD)PfnDb;
	    MmGeneratePageFrameDatabase((PULONG_PTR)PfnDb, RequestorVSpace,
					OutputBuffer, OutputBufferLength, NULL);
	    DbgTrace("Generated PFN database for output buffer %p, db %p count %d\n",
		     (PVOID)OutputBuffer, PfnDb, Irp->OutputBufferPfnCount);
	}
	assert(Irp->OutputBufferPfnCount);
	Irp->Flags |= IOP_IRP_OUTPUT_DIRECT_IO;
    } else {
	/* We need to clear the OUTPUT_DIRECT_IO flag because a previous
	 * device object might be DIRECT_IO. */
	Irp->Flags &= ~IOP_IRP_OUTPUT_DIRECT_IO;
    }

    /* Map the input buffer if InputBuffer is not an offset and input IO type
     * is mapped IO. */
    MWORD MappedInputBuffer = 0;
    if (InputBuffer >= PAGE_SIZE && (InputIoType & MappedIo)) {
	/* The input buffer must not already have been mapped. */
	assert(!PendingIrp->InputBuffer);
	RET_ERR(IopMapUserBuffer(RequestorVSpace, DriverObject, InputBuffer,
				 InputBufferLength, &MappedInputBuffer, TRUE));
	assert(MappedInputBuffer != 0);
	DbgTrace("Mapped input buffer %p into driver %s at %p\n", (PVOID)InputBuffer,
		 DriverObject->DriverImagePath, (PVOID)MappedInputBuffer);
	Irp->InputBuffer = MappedInputBuffer;
	PendingIrp->InputBuffer = InputBuffer;
    }

    /* Map the output buffer if OutputBuffer is given and the output IO type
     * is mapped IO. */
    if (OutputBuffer && (OutputIoType & MappedIo)) {
	assert(OutputBuffer >= PAGE_SIZE);
	/* The output buffer must not already have been mapped. */
	assert(!PendingIrp->OutputBuffer);
	MWORD MappedOutputBuffer = 0;
	RET_ERR_EX(IopMapUserBuffer(RequestorVSpace, DriverObject,
				    OutputBuffer, OutputBufferLength,
				    &MappedOutputBuffer, OutputIsReadOnly),
		   if (MappedInputBuffer) {
		       IopUnmapUserBuffer(DriverObject, MappedInputBuffer);
		   });
	assert(MappedOutputBuffer != 0);
	DbgTrace("Mapped output buffer %p into driver %s at %p\n",
		 (PVOID)OutputBuffer, DriverObject->DriverImagePath,
		 (PVOID)MappedOutputBuffer);
	Irp->OutputBuffer = MappedOutputBuffer;
	PendingIrp->OutputBuffer = OutputBuffer;
    }
    return STATUS_SUCCESS;
}

static VOID IopUnmapDriverIrpBuffers(IN PPENDING_IRP PendingIrp)
{
    assert(PendingIrp != NULL);
    assert(PendingIrp->IoPacket != NULL);
    /* We can only unmap the lowest-level PENDING_IRP because otherwise
     * lower drivers will have their IO buffers unmapped before it has
     * completed the IRP. */
    assert(PendingIrp->ForwardedTo == NULL);
    PIO_REQUEST_PARAMETERS Irp = &PendingIrp->IoPacket->Request;
    PIO_DRIVER_OBJECT DriverObject = Irp->Device.Object->DriverObject;
    if (PendingIrp->InputBuffer) {
	assert(Irp->InputBuffer);
	IopUnmapUserBuffer(DriverObject, Irp->InputBuffer);
	Irp->InputBuffer = PendingIrp->InputBuffer;
	PendingIrp->InputBuffer = 0;
    }
    if (PendingIrp->OutputBuffer) {
	assert(Irp->OutputBuffer);
	IopUnmapUserBuffer(DriverObject, Irp->OutputBuffer);
	Irp->OutputBuffer = PendingIrp->OutputBuffer;
	PendingIrp->OutputBuffer = 0;
    }
}

static VOID IopQueueIoPacketEx(IN PPENDING_IRP PendingIrp,
			       IN PIO_DRIVER_OBJECT Driver,
			       IN PTHREAD Thread)
{
    assert(Thread == IOP_PAGING_IO_REQUESTOR || ObObjectIsType(Thread, OBJECT_TYPE_THREAD));
    /* Queue the IRP to the driver */
    InsertTailList(&Driver->IoPacketQueue, &PendingIrp->IoPacket->IoPacketLink);
    PIO_REQUEST_PARAMETERS Irp = &PendingIrp->IoPacket->Request;
    Irp->OriginalRequestor = SERVER_OBJECT_TO_CLIENT_HANDLE(Thread);
    /* Use the GLOBAL_HANDLE of the IoPacket as the Identifier */
    Irp->Identifier = (HANDLE)POINTER_TO_GLOBAL_HANDLE(PendingIrp->IoPacket);
    if (Thread == IOP_PAGING_IO_REQUESTOR) {
	InsertTailList(&IopNtosPendingIrpList, &PendingIrp->Link);
    } else {
	InsertTailList(&Thread->PendingIrpList, &PendingIrp->Link);
    }
    KeSetEvent(&Driver->IoPacketQueuedEvent);
}

static VOID IopQueueIoPacket(IN PPENDING_IRP PendingIrp,
			     IN PTHREAD Thread)
{
    /* We can only queue IO request packets */
    assert(PendingIrp != NULL);
    assert(PendingIrp->IoPacket != NULL);
    assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
    assert(PendingIrp->IoPacket->Request.MajorFunction != IRP_MJ_ADD_DEVICE);
    assert(Thread == IOP_PAGING_IO_REQUESTOR || ObObjectIsType(Thread, OBJECT_TYPE_THREAD));
    PIO_DRIVER_OBJECT Driver = PendingIrp->IoPacket->Request.Device.Object->DriverObject;
    assert(Driver != NULL);
    IopQueueIoPacketEx(PendingIrp, Driver, Thread);
}

static ULONG IopGetIoPacketSizeFromIrp(IN PTHREAD RequestorThread,
				       IN PIO_REQUEST_PARAMETERS Irp)
{
    ULONG DataOffset = ALIGN_UP(sizeof(IO_PACKET) + Irp->DataSize, MWORD);
    /* For paging IO we never embed the IO data in the IRP. */
    if (RequestorThread == IOP_PAGING_IO_REQUESTOR) {
	return DataOffset;
    }
    /* If the input buffer pointer falls within the service message area of
     * the requestor thread, the input data would be embedded in the IRP. */
    if (Irp->InputBuffer && KePtrInSvcMsgBuf(Irp->InputBuffer, RequestorThread)) {
	MWORD MsgOffset = Irp->InputBuffer - RequestorThread->IpcBufferClientAddr;
	if (MsgOffset + Irp->InputBufferLength > SVC_MSGBUF_SIZE) {
	    /* This shouldn't normally happen because the client-side stub
	     * ensures that the input buffer can fit in to the service message
	     * area. However a malicious client can go around ntdll and call
	     * the server directly, so make sure we don't copy beyond the service
	     * message area to avoid crashing the server. */
	    assert(FALSE);
	    return DataOffset + SVC_MSGBUF_SIZE - MsgOffset;
	}
	DataOffset += ALIGN_UP(Irp->InputBufferLength, MWORD);
    }
    return DataOffset;
}

/* If the input buffer pointer falls within the service message area of
 * the requestor thread, embed the input data in the IRP. */
static VOID IopCopyInputDataToIoPacket(IN PTHREAD RequestorThread,
				       IN PIO_REQUEST_PARAMETERS Irp,
				       OUT PIO_PACKET IoPacket)
{
    if (RequestorThread == IOP_PAGING_IO_REQUESTOR) {
	return;
    }
    ULONG DataOffset = ALIGN_UP(sizeof(IO_PACKET) + Irp->DataSize, MWORD);
    if (Irp->InputBuffer && KePtrInSvcMsgBuf(Irp->InputBuffer, RequestorThread)) {
	MWORD MsgOffset = Irp->InputBuffer - RequestorThread->IpcBufferClientAddr;
	if (MsgOffset + Irp->InputBufferLength > SVC_MSGBUF_SIZE) {
	    assert(FALSE);
	    Irp->InputBufferLength = SVC_MSGBUF_SIZE - MsgOffset;
	    IoPacket->Request.InputBufferLength = Irp->InputBufferLength;
	}
	PVOID Src = (PVOID)(RequestorThread->IpcBufferServerAddr + MsgOffset);
	PVOID Dest = (PCHAR)IoPacket + DataOffset;
	memcpy(Dest, Src, Irp->InputBufferLength);
	IoPacket->Request.InputBuffer = DataOffset;
    }
}

/*
 * Allocate the IO_PACKET and PENDING_IRP structures and copy the supplied
 * IO request parameters to the newly allocated IO_PACKET, map the relevant
 * IO buffers to the target driver address space, and queue the IO_PACKET
 * to the driver IRP queue.
 *
 * If DriverObject is not NULL, it would be used as the target driver object.
 * Otherwise, the driver object of the device object specified in the IO
 * request parameters would be the target driver.
 *
 * The caller can wait on the IoCompletionEvent of the PENDING_IRP for the
 * completion of the IO. The IO response data are available in the IoResponseData
 * member of the PENDING_IRP. The caller must call IopCleanupPendingIrp after
 * the IO has completed and it has read the relevant IO response data (if any).
 */
NTSTATUS IopCallDriverEx(IN PTHREAD Thread,
			 IN PIO_REQUEST_PARAMETERS Irp,
			 IN OPTIONAL PIO_DRIVER_OBJECT DriverObject,
			 OUT PPENDING_IRP *pPendingIrp)
{
    assert(Thread);
    assert(Irp);
    assert(pPendingIrp);
    assert(Thread == IOP_PAGING_IO_REQUESTOR || ObObjectIsType(Thread, OBJECT_TYPE_THREAD));
    *pPendingIrp = NULL;
    ULONG IoPacketSize = IopGetIoPacketSizeFromIrp(Thread, Irp);
    PIO_PACKET IoPacket = NULL;
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, IoPacketSize, &IoPacket));
    assert(IoPacket);
    memcpy(&IoPacket->Request, Irp, sizeof(IO_REQUEST_PARAMETERS) + Irp->DataSize);
    /* If the input data is short enough, the client-side stub function will copy
     * the input data to the service message area so we can avoid the overhead of
     * mapping the client buffer. In this case the input data is embedded in the
     * IRP, so do the copy now. */
    IopCopyInputDataToIoPacket(Thread, Irp, IoPacket);

    NTSTATUS Status;
    IF_ERR_GOTO(err, Status, IopAllocatePendingIrp(IoPacket, Thread, pPendingIrp));
    assert(*pPendingIrp);

    if (DriverObject) {
	/* This is used by the PNP manager to queue the AddDevice request.
	 * Since AddDevice request doesn't have IO buffers, we don't call
	 * IopMapIoBuffers. */
	assert(Irp->MajorFunction == IRP_MJ_ADD_DEVICE);
	IopQueueIoPacketEx(*pPendingIrp, DriverObject, Thread);
    } else {
	/* Non-AddDevice request is always queued on the driver object of
	 * the target device object of the IRP. Note here the IO buffers in the
	 * driver address space are freed when the server receives the IoCompleted
	 * message, so we don't need to free them manually. */
	IF_ERR_GOTO(err, Status, IopMapIoBuffers(*pPendingIrp));
	IopQueueIoPacket(*pPendingIrp, Thread);
    }
    return STATUS_SUCCESS;

err:
    if (IoPacket) {
	IopFreeIoPacket(IoPacket);
    }
    if (*pPendingIrp) {
	IopFreePendingIrp(*pPendingIrp);
    }
    *pPendingIrp = NULL;
    return Status;
}

/*
 * Complete the PENDING_IRP. If the original requestor is a DRIVER object,
 * the driver is replied to and the PENDING_IRP is cleaned up. If the original
 * requestor is a THREAD object, the response data are saved in the PENDING_IRP
 * and the PENDING_IRP is not freed in this case. The original requestor needs
 * to call IopCleanupPendingIrp to clean up the PENDING_IRP.
 */
VOID IopCompletePendingIrp(IN OUT PPENDING_IRP PendingIrp,
			   IN IO_STATUS_BLOCK IoStatus,
			   IN PVOID ResponseData,
			   IN ULONG ResponseDataSize)
{
    /* Unmap the IO buffers mapped into the driver address space */
    IopUnmapDriverIrpBuffers(PendingIrp);
    /* Find the THREAD or DRIVER object at this level */
    PIO_PACKET Irp = PendingIrp->IoPacket;
    POBJECT Requestor = PendingIrp->Requestor;
    assert(Irp->Request.AssociatedIrpCount >= 0);

    if (Requestor == IOP_PAGING_IO_REQUESTOR || ObObjectIsType(Requestor, OBJECT_TYPE_THREAD) ||
	(!PendingIrp->ForwardedFrom && Irp->Request.AssociatedIrpCount > 0)) {
	/* In these three cases we need to save the IO response data in the PENDING_IRP
	 * for future use. Note we will not deallocate the PENDING_IRP in these cases. */
	assert(!PendingIrp->ForwardedFrom);
	assert(!PendingIrp->IoResponseData);
	PendingIrp->IoResponseStatus = IoStatus;
	PendingIrp->IoResponseDataSize = ResponseDataSize;
	if (ResponseDataSize) {
	    PendingIrp->IoResponseData = ExAllocatePoolWithTag(ResponseDataSize,
							       NTOS_IO_TAG);
	    if (PendingIrp->IoResponseData != NULL) {
		assert(ResponseData);
		memcpy(PendingIrp->IoResponseData, ResponseData, ResponseDataSize);
	    }
	}
    }

    if (!PendingIrp->ForwardedFrom) {
	/* If this is a top-level PENDING_IRP (ie. those created by the original
	 * requestor) and there are pending associated IRPs for this IRP, postpone
	 * the completion till all associated IRPs have been completed. */
	if (Irp->Request.AssociatedIrpCount > 0) {
	    assert(!Irp->Request.ServerPrivate.MasterCompleted);
	    /* Master IRPs cannot themselves be associated IRPs to some other IRPs. */
	    assert(!Irp->Request.MasterIrp.Placeholder);
	    assert(!Irp->Request.MasterIrp.Ptr);
	    Irp->Request.ServerPrivate.MasterCompleted = TRUE;
	    return;
	}
	/* If this IRP is an associated IRP, decrease the pending associated IRP
	 * count of its master IRP, and complete it if it has reached zero. */
	if (Irp->Request.MasterIrp.Ptr) {
	    assert(Irp->Request.MasterIrp.Placeholder == -1);
	    PPENDING_IRP MasterPendingIrp = Irp->Request.MasterIrp.Ptr;
	    /* MasterPendingIrp should always be the top-level PENDING_IRP. */
	    assert(!MasterPendingIrp->ForwardedFrom);
	    PIO_PACKET MasterIrp = MasterPendingIrp->IoPacket;
	    assert(MasterIrp->Request.AssociatedIrpCount > 0);
	    MasterIrp->Request.AssociatedIrpCount--;
	    if (!MasterIrp->Request.AssociatedIrpCount &&
		MasterIrp->Request.ServerPrivate.MasterCompleted) {
		IopCompletePendingIrp(MasterPendingIrp,
				      MasterPendingIrp->IoResponseStatus,
				      MasterPendingIrp->IoResponseData,
				      MasterPendingIrp->IoResponseDataSize);
	    }
	}
    }

    if (Requestor == IOP_PAGING_IO_REQUESTOR || ObObjectIsType(Requestor, OBJECT_TYPE_THREAD)) {
	/* The original requestor is either a THREAD object or the NTOS Executive.
	 * The latter uses the special pseudo requestor IOP_PAGING_IO_REQUESTOR to
	 * indicate that the IRP is generated by Cc for paging IO. First we wake
	 * the THREAD object up. This does nothing in the paging IO case. */
	KeSetEvent(&PendingIrp->IoCompletionEvent);
	/* Call the IO completion callback if the requestor has registered one. */
	PIRP_CALLBACK Callback = Irp->Request.ServerPrivate.Callback;
	if ((Irp->Request.Flags & IOP_IRP_COMPLETION_CALLBACK) && Callback) {
	    Callback(PendingIrp, Irp->Request.ServerPrivate.Context, TRUE);
	}
    } else {
	/* Otherwise, it must be a driver object. Reply to the driver, unless this
	 * is the top-level PENDING_IRP and the original requestor did not require
	 * completion notification. */
	assert(ObObjectIsType(Requestor, OBJECT_TYPE_DRIVER));
	if (!PendingIrp->ForwardedFrom && !(Irp->Request.Flags & IOP_IRP_NOTIFY_COMPLETION)) {
	    goto free;
	}
	/* Note that since a lower driver can create an IRP and send it to a
	 * higher-level driver, which can in turn reflect this IRP back to the
	 * lower driver, the Requestor can sometimes be equal to DriverObject. */
	PIO_DRIVER_OBJECT RequestorDriver = (PIO_DRIVER_OBJECT)Requestor;

	/* Allocate a new IO packet of type ServerMessage */
	PIO_PACKET SrvMsg = NULL;
	NTSTATUS Status = IopAllocateIoPacket(IoPacketTypeServerMessage,
					      sizeof(IO_PACKET) + ResponseDataSize,
					      &SrvMsg);
	if (!NT_SUCCESS(Status)) {
	    /* If the allocation failed, there isn't much we can do other than
	     * simply ignoring it. On debug build we will stop the system so we
	     * can figure out why the system is running out of critical memory. */
	    assert(FALSE);
	    goto free;
	}
	/* Copy the IO response to the new IO packet */
	assert(SrvMsg != NULL);
	SrvMsg->ServerMsg.Type = IoSrvMsgIoCompleted;
	SrvMsg->ServerMsg.IoCompleted.Identifier = Irp->Request.Identifier;
	SrvMsg->ServerMsg.IoCompleted.IoStatus = IoStatus;
	SrvMsg->ServerMsg.IoCompleted.ResponseDataSize = ResponseDataSize;
	if (ResponseDataSize) {
	    memcpy(SrvMsg->ServerMsg.IoCompleted.ResponseData, ResponseData,
		   ResponseDataSize);
	}
	if (PendingIrp->ForwardedFrom == NULL) {
	    /* If the requestor is the original requestor, set the OriginalRequestor
	     * field to NULL since driver objects set this field to NULL when they
	     * request a new IRP. */
	    assert(Requestor == CLIENT_HANDLE_TO_SERVER_OBJECT(Irp->Request.OriginalRequestor));
	    SrvMsg->ServerMsg.IoCompleted.OriginalRequestor = 0;
	} else {
	    /* Otherwise, this is an intermediate requestor that set NotifyCompletion
	     * to TRUE. Move the completed IRP to its pending IRP list so when it replies
	     * we know that the identifier pair it supplied is valid. */
	    InsertTailList(&RequestorDriver->PendingIoPacketList, &Irp->IoPacketLink);
	    /* Also restore the device object of the completed IRP to the previous
	     * device object (before this IRP is forwarded to the DriverObject) */
	    assert(PendingIrp->PreviousDeviceObject != NULL);
	    Irp->Request.Device.Object = PendingIrp->PreviousDeviceObject;
	    SrvMsg->ServerMsg.IoCompleted.OriginalRequestor = Irp->Request.OriginalRequestor;
	    DbgTrace("Restoring IRP device object to %p from %s\n",
		     PendingIrp->PreviousDeviceObject,
		     PendingIrp->PreviousDeviceObject->DriverObject->DriverImagePath);
	}

	/* Add the server message IO packet to the driver IO packet queue */
	InsertTailList(&RequestorDriver->IoPacketQueue, &SrvMsg->IoPacketLink);
	/* Signal the driver that an IO packet has been queued */
	KeSetEvent(&RequestorDriver->IoPacketQueuedEvent);
    free:
	/* Detach the PENDING_IRP from the driver's ForwardedIrpList */
	RemoveEntryList(&PendingIrp->Link);
	assert(PendingIrp->ForwardedTo == NULL);
	if (PendingIrp->ForwardedFrom == NULL) {
	    /* If the PENDING_IRP is the top-level one (ie. we are replying to the
	     * driver that originally requested the IRP), free the IO_PACKET. */
	    assert(PendingIrp->IoPacket != NULL);
	    IopFreeIoPacket(PendingIrp->IoPacket);
	} else {
	    /* Otherwise, detach the PENDING_IRP from the IRP stack */
	    PendingIrp->ForwardedFrom->ForwardedTo = NULL;
	}
	/* In either case, we want to free the PENDING_IRP itself */
	IopFreePendingIrp(PendingIrp);
    }
}

static NTSTATUS IopHandleIoCompleteClientMessage(IN PIO_PACKET Response,
						 IN PIO_DRIVER_OBJECT DriverObject)
{
    GLOBAL_HANDLE OriginalRequestor = Response->ClientMsg.IoCompleted.OriginalRequestor;
    HANDLE IrpIdentifier = Response->ClientMsg.IoCompleted.Identifier;
    /* Check the driver's pending IO packet list to see if OriginalIrp is valid */
    PIO_PACKET CompletedIrp = IopLocateIrpInDriverPendingList(DriverObject,
							      OriginalRequestor,
							      IrpIdentifier);
    if (CompletedIrp == NULL) {
	IopDumpDriverPendingIoPacketList(DriverObject, OriginalRequestor,
					 IrpIdentifier);
	return STATUS_INVALID_PARAMETER;
    }
    assert(CompletedIrp->Type == IoPacketTypeRequest);

    /* IRP identifier is valid. Detach the IO packet from the
     * driver's pending IO packet list. */
    RemoveEntryList(&CompletedIrp->IoPacketLink);
    PPENDING_IRP PendingIrp = IopLocateIrpInOriginalRequestor(OriginalRequestor,
							      CompletedIrp);
    /* If the IRP identifier is valid, PendingIrp should never be NULL.
     * We assert on debug build and return error on release build. */
    if (PendingIrp == NULL) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    assert(PendingIrp->IoPacket == CompletedIrp);
    /* The PENDING_IRP must be top-most (ie. not forwarded from
     * a higher-level driver) */
    assert(PendingIrp->ForwardedFrom == NULL);
    /* AddDevice requests require special handling */
    if (CompletedIrp->Request.MajorFunction == IRP_MJ_ADD_DEVICE) {
	/* AddDevice requests cannot be forwarded so there should only
	 * be one THREAD object waiting on it */
	assert(PendingIrp->ForwardedTo == NULL);
	assert(PendingIrp->Requestor == CLIENT_HANDLE_TO_SERVER_OBJECT(OriginalRequestor));
	/* DRIVER object cannot initiate AddDevice requests */
	assert(ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_THREAD));
	/* AddDevice request cannot have any response data */
	if (Response->ClientMsg.IoCompleted.ResponseDataSize) {
	    assert(FALSE);
	    return STATUS_INVALID_PARAMETER;
	}
	/* Copy the IO response data and wake the THREAD up. */
	PendingIrp->IoResponseStatus = Response->ClientMsg.IoCompleted.IoStatus;
	KeSetEvent(&PendingIrp->IoCompletionEvent);
	return STATUS_SUCCESS;
    }

    DbgTrace("Completed IRP device obj driver obj is %s, driverobj is %s\n",
	     CompletedIrp->Request.Device.Object->DriverObject->DriverImagePath,
	     DriverObject->DriverImagePath);
    assert(CompletedIrp->Request.Device.Object->DriverObject == DriverObject);
    /* Locate the lowest-level driver object in the IRP flow */
    while (PendingIrp->ForwardedTo != NULL) {
	PendingIrp = PendingIrp->ForwardedTo;
	assert(PendingIrp->IoPacket == CompletedIrp);
    }

    IopCompletePendingIrp(PendingIrp, Response->ClientMsg.IoCompleted.IoStatus,
			  Response->ClientMsg.IoCompleted.ResponseData,
			  Response->ClientMsg.IoCompleted.ResponseDataSize);
    return STATUS_SUCCESS;
}

static NTSTATUS IopHandleForwardIrpClientMessage(IN PIO_PACKET Msg,
						 IN PIO_DRIVER_OBJECT SourceDriver)
{
    assert(Msg != NULL);
    assert(Msg->Type == IoPacketTypeClientMessage);
    assert(Msg->ClientMsg.Type == IoCliMsgForwardIrp);
    DbgTrace("Got ForwardIrp message from driver %s forwarding IRP (%p:%p) to device handle %p\n",
	     SourceDriver->DriverImagePath,
	     (PVOID)Msg->ClientMsg.ForwardIrp.OriginalRequestor,
	     Msg->ClientMsg.ForwardIrp.Identifier,
	     (PVOID)Msg->ClientMsg.ForwardIrp.DeviceObject);

    /* Locate the IO_PACKET and DeviceObject specified in the ForwardIrp message */
    GLOBAL_HANDLE OriginalRequestor = Msg->ClientMsg.ForwardIrp.OriginalRequestor;
    HANDLE IrpIdentifier = Msg->ClientMsg.ForwardIrp.Identifier;
    PIO_PACKET Irp = IopLocateIrpInDriverPendingList(SourceDriver,
						     OriginalRequestor,
						     IrpIdentifier);
    if (Irp == NULL || Irp->Type != IoPacketTypeRequest) {
	IopDumpDriverPendingIoPacketList(SourceDriver, OriginalRequestor, IrpIdentifier);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    /* AddDevice requests cannot be forwarded */
    if (Irp->Request.MajorFunction == IRP_MJ_ADD_DEVICE) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    GLOBAL_HANDLE DeviceHandle = Msg->ClientMsg.ForwardIrp.DeviceObject;
    PIO_DEVICE_OBJECT ForwardedTo = IopGetDeviceObject(DeviceHandle, NULL);
    if (ForwardedTo == NULL) {
	DbgTrace("Driver %s sent ForwardIrp message with invalid device handle %p\n",
		 SourceDriver->DriverImagePath, (PVOID)DeviceHandle);
	return STATUS_INVALID_PARAMETER;
    }
    assert(ForwardedTo->DriverObject != NULL);

    PPENDING_IRP PendingIrp = IopLocateIrpInOriginalRequestor(OriginalRequestor, Irp);
    /* If the IRP identifier is valid, PendingIrp should never be NULL. We assert on
     * debug build and return error on release build. */
    if (PendingIrp == NULL) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    /* Locate the lowest-level driver object in the IRP flow */
    while (PendingIrp->ForwardedTo != NULL) {
	PendingIrp = PendingIrp->ForwardedTo;
    }
    if (PendingIrp->PreviousDeviceObject != NULL) {
	DbgTrace("Lowest level PendingIrp->PreviousDeviceObject = %p "
		 "DriverObject = %p DriverImagePath = %s\n",
		 PendingIrp->PreviousDeviceObject,
		 PendingIrp->PreviousDeviceObject->DriverObject,
		 PendingIrp->PreviousDeviceObject->DriverObject->DriverImagePath);
    }
    RemoveEntryList(&Irp->IoPacketLink);
    Irp->Request.AssociatedIrpCount += Msg->ClientMsg.ForwardIrp.AssociatedIrpCount;

    if (Irp->Request.File.Object && Irp->Request.File.Object->Fcb) {
	CcSetFileSize(Irp->Request.File.Object->Fcb, Msg->ClientMsg.ForwardIrp.NewFileSize);
    }

    if (Msg->ClientMsg.ForwardIrp.OverrideVerify) {
	Irp->Request.Flags |= IOP_IRP_OVERRIDE_VERIFY;
    } else {
	Irp->Request.Flags &= ~IOP_IRP_OVERRIDE_VERIFY;
    }

    /* If client has requested completion notification, in addition to
     * moving the IO_PACKET from the source driver object to the target
     * driver, we also create a PENDING_IRP that links to the existing
     * PENDING_IRP */
    PIO_DEVICE_OBJECT PreviousDeviceObject = Irp->Request.Device.Object;
    assert(PreviousDeviceObject != NULL);
    NTSTATUS Status;
    if (Msg->ClientMsg.ForwardIrp.NotifyCompletion) {
	PPENDING_IRP NewPendingIrp = NULL;
	IF_ERR_GOTO(fail, Status,
		    IopAllocatePendingIrp(Irp, SourceDriver, &NewPendingIrp));
	NewPendingIrp->PreviousDeviceObject = PreviousDeviceObject;
	NewPendingIrp->ForwardedFrom = PendingIrp;
	PendingIrp->ForwardedTo = NewPendingIrp;
	InsertTailList(&SourceDriver->ForwardedIrpList, &NewPendingIrp->Link);
	PendingIrp = NewPendingIrp;
	DbgTrace("Allocated new PendingIrp with PreviousDeviceObject %p from %s\n",
		 PendingIrp->PreviousDeviceObject,
		 PendingIrp->PreviousDeviceObject->DriverObject->DriverImagePath);
    } else {
	/* Otherwise, we need to unmap the IO buffers that were mapped
	 * into the source driver */
	IopUnmapDriverIrpBuffers(PendingIrp);
    }

    /* For IRP_MJ_READ and IRP_MJ_WRITE, if the driver specified new offset and
     * length, update the IO_PACKET. Note that the new length cannot be larger
     * than the old length, unless the target device is a mounted volume, in which
     * case the cutoff is the old length rounded up to the cluster size of the
     * mounted volume. */
    ULONG NewLength = Msg->ClientMsg.ForwardIrp.NewLength;
    ULONG ClusterSize = ForwardedTo->Vcb ? ForwardedTo->Vcb->ClusterSize : 0;
    if (Irp->Request.MajorFunction == IRP_MJ_READ) {
	ULONG OldLength = Irp->Request.OutputBufferLength;
	if ((NewLength > OldLength) &&
	    (!ClusterSize || NewLength > ALIGN_UP_BY(OldLength, ClusterSize))) {
	    assert(FALSE);
	    return STATUS_INVALID_PARAMETER;
	}
	Irp->Request.Read.ByteOffset = Msg->ClientMsg.ForwardIrp.NewOffset;
	Irp->Request.OutputBufferLength = NewLength;
    } else if (Irp->Request.MajorFunction == IRP_MJ_WRITE) {
	ULONG OldLength = Irp->Request.InputBufferLength;
	if ((NewLength > OldLength) &&
	    (!ClusterSize || NewLength > ALIGN_UP_BY(OldLength, ClusterSize))) {
	    assert(FALSE);
	    return STATUS_INVALID_PARAMETER;
	}
	Irp->Request.Write.ByteOffset = Msg->ClientMsg.ForwardIrp.NewOffset;
	Irp->Request.InputBufferLength = NewLength;
    }

    /* Call the IO interception callback if the requestor has registered one. */
    PIRP_CALLBACK Callback = Irp->Request.ServerPrivate.Callback;
    if ((Irp->Request.Flags & IOP_IRP_INTERCEPTION_CALLBACK) && Callback) {
	if (!Callback(PendingIrp, Irp->Request.ServerPrivate.Context, FALSE)) {
	    /* If the callback function returned FALSE, IRP forwarding should
	     * be halted. */
	    return STATUS_SUCCESS;
	}
    }

    /* Set the Device object of the Irp to be the new device (ForwardedTo) */
    Irp->Request.Device.Object = ForwardedTo;
    Status = IopMapIoBuffers(PendingIrp);
    if (!NT_SUCCESS(Status)) {
	/* Restore the original device object in the IRP if error */
	Irp->Request.Device.Object = PreviousDeviceObject;
	/* Also undo the completion notification path above */
	if (Msg->ClientMsg.ForwardIrp.NotifyCompletion) {
	    assert(PendingIrp->ForwardedFrom != NULL);
	    PendingIrp = PendingIrp->ForwardedFrom;
	    RemoveEntryList(&PendingIrp->ForwardedTo->Link);
	    IopFreePendingIrp(PendingIrp->ForwardedTo);
	    PendingIrp->ForwardedTo = NULL;
	}
	goto fail;
    }

    /* Move the original IO_PACKET from SourceDriver to ForwardedTo and wake the
     * target driver up */
    InsertTailList(&ForwardedTo->DriverObject->IoPacketQueue, &Irp->IoPacketLink);
    KeSetEvent(&ForwardedTo->DriverObject->IoPacketQueuedEvent);
    return STATUS_SUCCESS;

    IO_STATUS_BLOCK IoStatus;
fail:
    IoStatus.Status = Status;
    IoStatus.Information = 0;
    IopCompletePendingIrp(PendingIrp, IoStatus, NULL, 0);
    return Status;
}

static VOID IopCachedReadCallback(IN PIO_FILE_CONTROL_BLOCK Fcb,
				  IN ULONG64 FileOffset,
				  IN ULONG64 Length,
				  IN NTSTATUS Status,
				  IN OUT PVOID Context)
{
    PIO_RESPONSE_DATA ResponseData = NULL;
    ULONG ResponseDataSize = 0;
    PPENDING_IRP PendingIrp = Context;
    if (!NT_SUCCESS(Status)) {
	Status = STATUS_IO_DEVICE_ERROR;
	goto out;
    }
    assert(ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_DRIVER));
    PIO_DRIVER_OBJECT DriverObject = PendingIrp->Requestor;
    struct _MDL_LIST {
	LIST_ENTRY Link;
	PVOID MappedSystemVa;
	ULONG_PTR ByteCount;
    } MdlListHead = {}, *PrevMdl = NULL;
    InitializeListHead(&MdlListHead.Link);
    ULONG MdlCount = 0;
    ULONG64 CurrentLength = 0;
    while (CurrentLength < Length) {
	ULONG MappedLength = 0;
	PVOID Buffer = NULL;
	Status = CcMapDataEx(DriverObject, Fcb, FileOffset + CurrentLength,
			     Length - CurrentLength, &MappedLength, &Buffer, FALSE);
	if (!NT_SUCCESS(Status)) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto free;
	}
	assert(Buffer);
	if (PrevMdl && (PUCHAR)PrevMdl->MappedSystemVa + PrevMdl->ByteCount == Buffer) {
	    PrevMdl->ByteCount += MappedLength;
	    CurrentLength += MappedLength;
	    continue;
	}
	struct _MDL_LIST *MdlListEntry = ExAllocatePoolWithTag(sizeof(struct _MDL_LIST),
							       NTOS_IO_TAG);
	if (!MdlListEntry) {
	    goto free;
	}
	PrevMdl = MdlListEntry;
	MdlListEntry->MappedSystemVa = Buffer;
	MdlListEntry->ByteCount = MappedLength;
	InsertTailList(&MdlListHead.Link, &MdlListEntry->Link);
	CurrentLength += MappedLength;
	MdlCount++;
    }

    ResponseDataSize = sizeof(IO_RESPONSE_DATA) + MdlCount * sizeof(PVOID) * 2;
    ResponseData = ExAllocatePoolWithTag(ResponseDataSize, NTOS_IO_TAG);
    if (!ResponseData) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto free;
    }
    ResponseData->MdlChain.MdlCount = MdlCount;
    ULONG i = 0;
    LoopOverList(Entry, &MdlListHead.Link, struct _MDL_LIST, Link) {
	ResponseData->MdlChain.Mdl[i].MappedSystemVa = Entry->MappedSystemVa;
	ResponseData->MdlChain.Mdl[i].ByteCount = Entry->ByteCount;
	i++;
    }
    assert(i == MdlCount);
    Status = STATUS_SUCCESS;

free:
    LoopOverList(Entry, &MdlListHead.Link, struct _MDL_LIST, Link) {
	IopFreePool(Entry);
    }
    IO_STATUS_BLOCK IoStatus;
out:
    IoStatus.Status = Status;
    IoStatus.Information = NT_SUCCESS(Status) ? Length : 0;
    IopCompletePendingIrp(PendingIrp, IoStatus, ResponseData, ResponseDataSize);
    if (ResponseData) {
	IopFreePool(ResponseData);
    }
}

static NTSTATUS IopHandleIoRequestMessage(IN PIO_PACKET Src,
					  IN PIO_DRIVER_OBJECT DriverObject)
{
    assert(Src->Type == IoPacketTypeRequest);
    PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(Src->Request.Device.Handle, NULL);
    assert(DeviceObject != NULL);
    assert(Src->Request.Identifier != NULL);
    if (!DeviceObject || !Src->Request.Identifier) {
	IoDbgDumpIoPacket(Src, TRUE);
	return STATUS_INVALID_PARAMETER;
    }
    assert(DeviceObject->DriverObject != NULL);

    /* If the IRP specified a master IRP, find it and record its PENDING_IRP. */
    PPENDING_IRP MasterPendingIrp = NULL;
    if (Src->Request.MasterIrp.Identifier) {
	GLOBAL_HANDLE MasterOriginalRequestor = Src->Request.MasterIrp.OriginalRequestor;
	if (!MasterOriginalRequestor) {
	    MasterOriginalRequestor = SERVER_OBJECT_TO_CLIENT_HANDLE(DriverObject);
	}
	MasterPendingIrp = IopLocateIrpIdInOriginalRequestor(MasterOriginalRequestor,
							     Src->Request.MasterIrp.Identifier);
	if (!MasterPendingIrp) {
	    IoDbgDumpIoPacket(Src, TRUE);
	    return STATUS_INVALID_PARAMETER;
	}
    }

    if (Src->Size != ALIGN_UP(sizeof(IO_PACKET) + Src->Request.DataSize, MWORD)) {
	IoDbgDumpIoPacket(Src, TRUE);
	return STATUS_INVALID_PARAMETER;
    }
    PIO_PACKET IoPacket = NULL;
    IopAllocateIoPacket(IoPacketTypeRequest, Src->Size, &IoPacket);
    assert(IoPacket != NULL);
    memcpy(IoPacket, Src, Src->Size);
    IoPacket->Request.Device.Object = DeviceObject;
    IoPacket->Request.File.Object = IopGetFileObject(DeviceObject, Src->Request.File.Handle);
    IoPacket->Request.OriginalRequestor = SERVER_OBJECT_TO_CLIENT_HANDLE(DriverObject);
    if (MasterPendingIrp) {
	IoPacket->Request.MasterIrp.Placeholder = -1;
	IoPacket->Request.MasterIrp.Ptr = MasterPendingIrp;
	PIO_REQUEST_PARAMETERS MasterIrp = &MasterPendingIrp->IoPacket->Request;
	IoPacket->Request.Flags |= MasterIrp->Flags & (IOP_IRP_COMPLETION_CALLBACK |
						       IOP_IRP_INTERCEPTION_CALLBACK);
	IoPacket->Request.ServerPrivate.Callback = MasterIrp->ServerPrivate.Callback;
	IoPacket->Request.ServerPrivate.Context = MasterIrp->ServerPrivate.Context;
    } else {
	IoPacket->Request.MasterIrp.Placeholder = 0;
	IoPacket->Request.MasterIrp.Ptr = NULL;
    }
    PPENDING_IRP PendingIrp = NULL;
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, DriverObject, &PendingIrp),
	       IopFreeIoPacket(IoPacket));
    assert(PendingIrp != NULL);

    /* If the IRP has an interception callback, run it, and stop if it returns FALSE. */
    PIRP_CALLBACK Callback = IoPacket->Request.ServerPrivate.Callback;
    if ((IoPacket->Request.Flags & IOP_IRP_INTERCEPTION_CALLBACK) && Callback) {
	if (!Callback(PendingIrp, IoPacket->Request.ServerPrivate.Context, FALSE)) {
	    return STATUS_SUCCESS;
	}
    }

    /* If the device object is a mounted volume and the IRP is an MDL READ,
     * we intercept the IRP and call Cc to handle it. We disallow WRITE IRPs
     * for mounted volumes as these can lead to cache inconsistencies. All IO
     * to a mounted volume must be done through the Cc functions in wdm.dll. */
    if (DeviceObject->Vcb) {
	if (Src->Request.MajorFunction == IRP_MJ_WRITE) {
	    IO_STATUS_BLOCK IoStatus = { .Status = STATUS_INVALID_DEVICE_REQUEST };
	    IopCompletePendingIrp(PendingIrp, IoStatus, NULL, 0);
	    return STATUS_SUCCESS;
	}
	if (!Src->Request.OutputBuffer && Src->Request.MajorFunction == IRP_MJ_READ &&
	    Src->Request.MinorFunction == IRP_MN_MDL) {
	    assert(Src->Request.OutputBufferLength);
	    CcPinDataEx(DeviceObject->Vcb->VolumeFcb,
			Src->Request.Read.ByteOffset.QuadPart,
			Src->Request.OutputBufferLength, FALSE,
			IopCachedReadCallback, PendingIrp);
	    return STATUS_SUCCESS;
	}
    }

    /* Map the input/output buffers from source driver to target driver */
    RET_ERR_EX(IopMapIoBuffers(PendingIrp),
	       {
		   IopFreeIoPacket(IoPacket);
		   IopFreePendingIrp(PendingIrp);
	       });

    InsertTailList(&DriverObject->ForwardedIrpList, &PendingIrp->Link);
    InsertTailList(&DeviceObject->DriverObject->IoPacketQueue, &IoPacket->IoPacketLink);
    KeSetEvent(&DeviceObject->DriverObject->IoPacketQueuedEvent);

    return STATUS_SUCCESS;
}

static NTSTATUS IopHandleDirtyBufferMessage(IN PIO_PACKET Msg,
					    IN PIO_DRIVER_OBJECT DriverObject)
{
    for (ULONG i = 0; i < IO_CLI_MSG_MAX_DIRTY_BUFFER_COUNT; i++) {
	MWORD ViewAddress = Msg->ClientMsg.DirtyBuffers[i].ViewAddress;
	if (!ViewAddress) {
	    break;
	}
	CcSetDirtyData(DriverObject, ViewAddress,
		       Msg->ClientMsg.DirtyBuffers[i].DirtyBits);
    }
    return STATUS_SUCCESS;
}

static VOID IopCacheFlushedCallback(IN PIO_DEVICE_OBJECT VolumeDevice,
				    IN PIO_FILE_OBJECT FileObject,
				    IN IO_STATUS_BLOCK IoStatus,
				    IN OUT PVOID Context)
{
    PIO_DRIVER_OBJECT DriverObject = Context;

    /* Allocate a new IO packet of type ServerMessage */
    PIO_PACKET SrvMsg = NULL;
    NTSTATUS Status = IopAllocateIoPacket(IoPacketTypeServerMessage,
					  sizeof(IO_PACKET), &SrvMsg);
    if (!NT_SUCCESS(Status)) {
	/* If the allocation failed, there isn't much we can do other than
	 * simply ignoring it. On debug build we will stop the system so we
	 * can figure out why the system is running out of critical memory. */
	assert(FALSE);
	return;
    }
    assert(SrvMsg != NULL);
    SrvMsg->ServerMsg.Type = IoSrvMsgCacheFlushed;
    SrvMsg->ServerMsg.CacheFlushed.DeviceObject = SERVER_OBJECT_TO_CLIENT_HANDLE(VolumeDevice);
    SrvMsg->ServerMsg.CacheFlushed.FileObject = SERVER_OBJECT_TO_CLIENT_HANDLE(FileObject);
    SrvMsg->ServerMsg.CacheFlushed.IoStatus = IoStatus;

    /* Add the server message IO packet to the driver IO packet queue */
    InsertTailList(&DriverObject->IoPacketQueue, &SrvMsg->IoPacketLink);
    /* Signal the driver that an IO packet has been queued */
    KeSetEvent(&DriverObject->IoPacketQueuedEvent);
}

static NTSTATUS IopHandleFlushCacheMessage(IN PIO_PACKET Msg,
					   IN PIO_DRIVER_OBJECT DriverObject)
{
    GLOBAL_HANDLE DeviceHandle = Msg->ClientMsg.FlushCache.DeviceObject;
    GLOBAL_HANDLE FileHandle = Msg->ClientMsg.FlushCache.FileObject;
    PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(DeviceHandle, NULL);
    if (!DeviceObject || !DeviceObject->Vcb) {
	IoDbgDumpIoPacket(Msg, TRUE);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    PIO_DEVICE_OBJECT VolumeDevice = DeviceObject->Vcb->VolumeDevice;
    assert(VolumeDevice);
    PIO_FILE_OBJECT FileObject = IopGetFileObject(VolumeDevice, FileHandle);
    assert(FileObject);
    CcFlushCache(VolumeDevice, FileObject, IopCacheFlushedCallback, DriverObject);
    return STATUS_SUCCESS;
}

/*
 * Handler function for the WDM service IopRequestIoPackets. This service should
 * only be called in the main event loop thread of the driver process.
 *
 * Check the previous batch of incoming IO packets first and see if any of them
 * errored out, and then process the driver's outgoing IO packet buffer. Once that
 * is done, process the driver's IO packet queue and forward them to the driver's
 * incoming IO packet buffer.
 */
NTSTATUS WdmRequestIoPackets(IN ASYNC_STATE State,
			     IN PTHREAD Thread,
			     IN ULONG NumCliMsgs,
			     OUT ULONG *pNumSrvMsgs)
{
    assert(Thread != NULL);
    assert(pNumSrvMsgs != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    NTSTATUS Status = STATUS_NTOS_BUG;
    assert(DriverObject != NULL);

    ASYNC_BEGIN(State);
    if (Thread != DriverObject->MainEventLoopThread) {
	ASYNC_RETURN(State, STATUS_INVALID_PARAMETER);
    }
    KeSetEvent(&DriverObject->InitializationDoneEvent);

    /* Process the driver's outgoing IO packet buffer first. This buffer
     * contains the client driver's messages to the server. */
    PIO_PACKET CliMsg = (PIO_PACKET)DriverObject->OutgoingIoPacketsServerAddr;
    MWORD OutgoingPacketEnd = DriverObject->OutgoingIoPacketsServerAddr
	+ DRIVER_IO_PACKET_BUFFER_COMMIT;
    for (ULONG i = 0; i < NumCliMsgs; i++) {
	if (CliMsg->Size < sizeof(IO_PACKET) ||
	    ((MWORD)CliMsg + CliMsg->Size >= OutgoingPacketEnd)) {
	    DbgTrace("Invalid IO packet size %d from driver %s. Processing halted.\n",
		     CliMsg->Size, DriverObject->DriverImagePath);
	    assert(FALSE);
	    break;
	}

	switch (CliMsg->Type) {
	case IoPacketTypeClientMessage:
	    switch (CliMsg->ClientMsg.Type) {
	    case IoCliMsgIoCompleted:
		Status = IopHandleIoCompleteClientMessage(CliMsg, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleIoCompleteClientMessage returned error status 0x%x\n",
			     Status);
		}
		break;

	    case IoCliMsgForwardIrp:
		Status = IopHandleForwardIrpClientMessage(CliMsg, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleForwardIrpClientMessage returned error status 0x%x\n",
			     Status);
		}
		break;

	    case IoCliMsgDirtyBuffers:
		Status = IopHandleDirtyBufferMessage(CliMsg, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleDirtyBufferMessage returned error status 0x%x\n",
			     Status);
		}
		break;

	    case IoCliMsgFlushCache:
		Status = IopHandleFlushCacheMessage(CliMsg, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleFlushCacheMessage returned error status 0x%x\n",
			     Status);
		}
		break;

	    default:
		DbgTrace("Invalid client message type from driver %s. Type is %d.\n",
			 DriverObject->DriverImagePath, CliMsg->ClientMsg.Type);
		Status = STATUS_INVALID_PARAMETER;
	    }
	    break;

	case IoPacketTypeRequest:
	    Status = IopHandleIoRequestMessage(CliMsg, DriverObject);
	    break;

	default:
	    DbgTrace("Received invalid response packet from driver %s. Dumping it now.\n",
		     DriverObject->DriverImagePath);
	    IoDbgDumpIoPacket(CliMsg, TRUE);
	    Status = STATUS_INVALID_PARAMETER;
	}
	/* If the routines above returned error, there isn't a lot we can do
	 * other than simply ignoring the error and continue processing.
	 * On debug build we will assert so we can know what's going on. */
	assert(NT_SUCCESS(Status));
	CliMsg = (PIO_PACKET)((MWORD)CliMsg + CliMsg->Size);
    }

    /* Wait for other threads to queue an IO packet on this driver. */
    AWAIT_EX(Status, KeWaitForSingleObject, State, _, Thread,
	     &DriverObject->IoPacketQueuedEvent.Header, TRUE, NULL);

    /* Now process the driver's queued IO packets and send them to the driver's incoming
     * IO packet buffer, which contains the server's messages to the client driver. */
    ULONG NumSrvMsgs = 0;
    ULONG TotalSize = 0;
    PIO_PACKET Dest = (PIO_PACKET)DriverObject->IncomingIoPacketsServerAddr;
    LoopOverList(Src, &DriverObject->IoPacketQueue, IO_PACKET, IoPacketLink) {
	assert(Src->Size >= sizeof(IO_PACKET));
	ULONG DestIoPacketSize = ALIGN_UP(Src->Size, MWORD);
	assert(Src->Type != IoPacketTypeClientMessage);
	if (Src->Type == IoPacketTypeRequest) {
	    DestIoPacketSize += sizeof(MWORD) * (Src->Request.InputBufferPfnCount +
						 Src->Request.OutputBufferPfnCount);
	}
	TotalSize += DestIoPacketSize;
	if (TotalSize > DRIVER_IO_PACKET_BUFFER_COMMIT) {
	    /* The driver's incoming IO packet buffer is full, so the rest of the
	     * pending IO packets are skipped and left in the queue. If this happens
	     * a lot, one should increase the driver's IO packet buffer size. In debug
	     * build we assert so we can know.
	     * TODO: Dynamically commit more memory in this case. Make sure to commit
	     * the outgoing buffer memory as well since we assume that the outgoing
	     * buffer has the same size as the incoming buffer. */
	    assert(FALSE);
	    break;
	}
	/* Ok to send this one. */
	NumSrvMsgs++;
	/* Copy this IoPacket to the driver's incoming IO packet buffer */
	memcpy(Dest, Src, Src->Size);
	Dest->Size = ALIGN_UP(Src->Size, MWORD);
	/* Massage the client-side copy of the IO packet so all server pointers are
	 * replaced by the client-side GLOBAL_HANDLE. Copy the PFN database if any. */
	if (Src->Type == IoPacketTypeRequest) {
	    assert(Src->Request.OriginalRequestor != 0);
	    assert(Src->Request.MajorFunction == IRP_MJ_ADD_DEVICE ||
		   Src->Request.Device.Object != NULL);
	    assert(Src->Request.MajorFunction == IRP_MJ_ADD_DEVICE ||
		   Src->Request.Device.Object->DriverObject == DriverObject);
	    Dest->Request.Device.Handle = SERVER_OBJECT_TO_CLIENT_HANDLE(Src->Request.Device.Object);
	    Dest->Request.File.Handle = SERVER_OBJECT_TO_CLIENT_HANDLE(Src->Request.File.Object);
	    if (Src->Request.Flags & IOP_IRP_INPUT_DIRECT_IO) {
		assert(Src->Request.InputBufferPfn);
		assert(Src->Request.InputBufferPfnCount);
		PUCHAR PfnDb = (PUCHAR)Dest + Dest->Size;
		ULONG PfnDbSize = sizeof(MWORD) * Src->Request.InputBufferPfnCount;
		memcpy(PfnDb, (PVOID)Src->Request.InputBufferPfn, PfnDbSize);
		Dest->Request.InputBufferPfn = Dest->Size;
		Dest->Size += PfnDbSize;
	    }
	    if (Src->Request.Flags & IOP_IRP_OUTPUT_DIRECT_IO) {
		assert(Src->Request.OutputBufferPfn);
		assert(Src->Request.OutputBufferPfnCount);
		PUCHAR PfnDb = (PUCHAR)Dest + Dest->Size;
		ULONG PfnDbSize = sizeof(MWORD) * Src->Request.OutputBufferPfnCount;
		memcpy(PfnDb, (PVOID)Src->Request.OutputBufferPfn, PfnDbSize);
		Dest->Request.OutputBufferPfn = Dest->Size;
		Dest->Size += PfnDbSize;
	    }
	}
	assert(Dest->Size == DestIoPacketSize);
	IoDbgDumpIoPacket(Dest, TRUE);
	Dest = (PIO_PACKET)((PUCHAR)Dest + Dest->Size);
	/* Detach this IoPacket from the driver's IO packet queue */
	RemoveEntryList(&Src->IoPacketLink);
	if (Src->Type == IoPacketTypeRequest) {
	    /* If this is a request packet, move it to the driver's
	     * pending IO packet list */
	    InsertTailList(&DriverObject->PendingIoPacketList, &Src->IoPacketLink);
	} else {
	    /* Else, clean up this IO packet since we do not expect a reply */
	    IopFreeIoPacket(Src);
	}
    }
    *pNumSrvMsgs = NumSrvMsgs;

    /* Returns APC status if the alertable wait above returned APC status */
    ASYNC_END(State, Status);
}
