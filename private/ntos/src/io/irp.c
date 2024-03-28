#include "iop.h"

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
    PendingIrp->PreviousDeviceObject = NULL;
    assert(ObObjectIsType(Requestor, OBJECT_TYPE_DRIVER) ||
	   ObObjectIsType(Requestor, OBJECT_TYPE_THREAD));
    *pPendingIrp = PendingIrp;
    return STATUS_SUCCESS;
}

static VOID IopFreeIoResponseData(IN PPENDING_IRP PendingIrp)
{
    if (PendingIrp->IoResponseData != NULL) {
	IopFreePool(PendingIrp->IoResponseData);
	PendingIrp->IoResponseData = NULL;
    }
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
    IopFreeIoResponseData(PendingIrp);
    if (PendingIrp->IoPacket != NULL) {
	IopFreePool(PendingIrp->IoPacket);
    }
    IopFreePool(PendingIrp);
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
 * Returns the PENDING_IRP struct of the given IoPacket. Note that for driver
 * objects this searches the ForwardedIrpList not the PendingIoPacketList.
 * The latter is used for a different purpose (see io.h).
 */
static PPENDING_IRP IopLocateIrpInOriginalRequestor(IN GLOBAL_HANDLE OriginalRequestor,
						    IN PIO_PACKET IoPacket)
{
    POBJECT RequestorObject = GLOBAL_HANDLE_TO_OBJECT(OriginalRequestor);
    if (ObObjectIsType(RequestorObject, OBJECT_TYPE_THREAD)) {
	PTHREAD Thread = (PTHREAD)RequestorObject;
	LoopOverList(PendingIrp, &Thread->PendingIrpList, PENDING_IRP, Link) {
	    if (PendingIrp->IoPacket == IoPacket) {
		assert(PendingIrp->Requestor == RequestorObject);
		return PendingIrp;
	    }
	}
    } else if (ObObjectIsType(RequestorObject, OBJECT_TYPE_DRIVER)) {
	PIO_DRIVER_OBJECT Driver = (PIO_DRIVER_OBJECT)RequestorObject;
	LoopOverList(PendingIrp, &Driver->ForwardedIrpList, PENDING_IRP, Link) {
	    if (PendingIrp->IoPacket == IoPacket) {
		assert(PendingIrp->Requestor == RequestorObject);
		return PendingIrp;
	    }
	}
    } else {
	assert(FALSE);
    }
    return NULL;
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
    AWAIT(KeWaitForMultipleObjects, State, Locals, Thread, Alertable,
	  WaitType, Locals.DspObjs, IrpCount, NULL);
    assert(Locals.DspObjs != NULL);
    ExFreePoolWithTag(Locals.DspObjs, NTOS_IO_TAG);
    ASYNC_END(State, STATUS_SUCCESS);
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
static NTSTATUS IopMapUserBuffer(IN PPROCESS User,
				 IN PIO_DRIVER_OBJECT Driver,
				 IN MWORD UserBufferStart,
				 IN MWORD UserBufferLength,
				 OUT MWORD *DriverBufferStart,
				 IN BOOLEAN ReadOnly)
{
    PVIRT_ADDR_SPACE UserVSpace = &User->VSpace;
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
    NeitherIo, /* IO buffer is mapped into target driver address space */
    BufferedIo, /* If data size is small, embed data in the IRP. Otherwise map. */
    DirectIo, /* Only send MDL. Do not map the buffer into driver address space */
    MappedDirectIo /* Send MDL and map the buffer into driver address space. */
} IO_TRANSFER_TYPE;

/*
 * Determine the IO transfer type based on either the IOCTL code (for IOCTL IRPs)
 * or the device object flags for READ/WRITE IRPs.
 */
static VOID IopGetIoTransferTypeFromIrp(IN PIO_REQUEST_PARAMETERS Irp,
					IN PIO_DEVICE_OBJECT DeviceObject,
					OUT OPTIONAL IO_TRANSFER_TYPE *pInputIoType,
					OUT OPTIONAL IO_TRANSFER_TYPE *pOutputIoType,
					OUT OPTIONAL BOOLEAN *pOutputIsReadOnly)
{
    IO_TRANSFER_TYPE InputIoType = 0, OutputIoType = 0;
    BOOLEAN OutputIsReadOnly = FALSE;
    if (Irp->MajorFunction == IRP_MJ_DEVICE_CONTROL ||
	Irp->MajorFunction == IRP_MJ_INTERNAL_DEVICE_CONTROL) {
	ULONG Ioctl = Irp->DeviceIoControl.IoControlCode;
	if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_BUFFERED) {
	    InputIoType = OutputIoType = BufferedIo;
	} else if (METHOD_FROM_CTL_CODE(Ioctl) == METHOD_NEITHER) {
	    InputIoType = OutputIoType = NeitherIo;
	} else {
	    InputIoType = BufferedIo;
	    /* Ioctl dispatch functions typically need to access the memory
	     * mapped by the MDL, so we always map the buffer for direct IO. */
	    OutputIoType = MappedDirectIo;
	    /* If the IOCTL has type METHOD_IN_DIRECT, the OutputBuffer
	     * is used as an input buffer (yes, I know, Microsoft loves
	     * to be confusing) and will be mapped read-only. */
	    OutputIsReadOnly = METHOD_FROM_CTL_CODE(Ioctl) == METHOD_IN_DIRECT;
	}
    } else {
	IO_TRANSFER_TYPE IoType = NeitherIo;
	if (DeviceObject->DeviceInfo.Flags & DO_DIRECT_IO) {
	    IoType = DirectIo;
	    if (DeviceObject->DeviceInfo.Flags & DO_MAP_IO_BUFFER) {
		IoType = MappedDirectIo;
	    }
	} else if (DeviceObject->DeviceInfo.Flags & DO_BUFFERED_IO) {
	    IoType = BufferedIo;
	}
	InputIoType = OutputIoType = IoType;
    }
    if (pInputIoType) {
	*pInputIoType = InputIoType;
    }
    if (pOutputIoType) {
	*pOutputIoType = OutputIoType;
    }
    if (pOutputIsReadOnly) {
	*pOutputIsReadOnly = OutputIsReadOnly;
    }
}

static VOID IopCopyIoBuffersToIoPacket(IN PTHREAD Thread,
				       IN PIO_REQUEST_PARAMETERS Irp,
				       IN PIO_PACKET IoPacket,
				       OUT ULONG *PfnDbOffset)
{
    ULONG DataOffset = ALIGN_UP(sizeof(IO_PACKET) + Irp->DataSize, MWORD);
    IO_TRANSFER_TYPE InputIoType;
    IopGetIoTransferTypeFromIrp(Irp, Irp->Device.Object, &InputIoType, NULL, NULL);
    /* For BUFFERED_IO, if the input buffer pointer falls within the service
     * message area of the requestor thread, embed the input data in the IRP. */
    if (InputIoType == BufferedIo && Irp->InputBuffer && Irp->InputBufferLength &&
	Irp->InputBufferLength < IRP_DATA_BUFFER_SIZE &&
	KePtrInSvcMsgBuf(Irp->InputBuffer, Thread)) {
	MWORD MsgOffset = Irp->InputBuffer - Thread->IpcBufferClientAddr;
	if (MsgOffset + Irp->InputBufferLength > SVC_MSGBUF_SIZE) {
	    /* This shouldn't normally happen because the client-side stub
	     * ensures that the input buffer can fit in to the service message
	     * area. However a malicious client can go around ntdll and call
	     * the server directly, so make sure we don't copy beyond the service
	     * message area to avoid crashing the server. */
	    assert(FALSE);
	    return;
	}
	PVOID Src = (PVOID)(Thread->IpcBufferServerAddr + MsgOffset);
	PVOID Dest = (PCHAR)IoPacket + DataOffset;
	memcpy(Dest, Src, Irp->InputBufferLength);
	IoPacket->Request.InputBuffer = DataOffset;
	*PfnDbOffset = DataOffset + ALIGN_UP(Irp->InputBufferLength, MWORD);
    } else {
	*PfnDbOffset = DataOffset;
    }
}

static VOID IopAppendPfnDatabaseToIoPacket(IN PPROCESS RequestorProcess,
					   IN PIO_REQUEST_PARAMETERS Irp,
					   OUT PIO_PACKET IoPacket,
					   IN ULONG PfnDbOffset)
{
    assert(IS_ALIGNED_BY(PfnDbOffset, sizeof(MWORD)));
    IO_TRANSFER_TYPE InputIoType, OutputIoType;
    IopGetIoTransferTypeFromIrp(Irp, Irp->Device.Object,
				&InputIoType, &OutputIoType, NULL);
    ULONG InputPfnCount, OutputPfnCount;
    MWORD *PfnDb = (PUCHAR)IoPacket + PfnDbOffset;
    if (Irp->InputBuffer && (InputIoType & DirectIo)) {
	assert(Irp->InputBufferLength);
	MmGeneratePageFrameDatabase(PfnDb, RequestorProcess, Irp->InputBuffer,
				    Irp->InputBufferLength, &InputPfnCount);
	/* Before calling the function the caller must compute the input PFN
	 * count and record it in the IO_REQUEST_PARAMETERS */
	assert(InputPfnCount == Irp->InputBufferPfnCount);
    }
    if (Irp->OutputBuffer && (OutputIoType & DirectIo)) {
	assert(Irp->OutputBufferLength);
	MmGeneratePageFrameDatabase(PfnDb + InputPfnCount, RequestorProcess,
				    Irp->OutputBuffer, Irp->OutputBufferLength,
				    &OutputPfnCount);
	assert(OutputPfnCount == Irp->OutputBufferPfnCount);
    }
    IoPacket->Request.InputBufferPfn = PfnDbOffset;
    IoPacket->Request.OutputBufferPfn = PfnDbOffset + sizeof(MWORD) * InputPfnCount;
    IoPacket->Request.InputBufferPfnCount = InputPfnCount;
    IoPacket->Request.OutputBufferPfnCount = OutputPfnCount;
}

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
    PIO_PACKET Irp = PendingIrp->IoPacket;
    assert(Irp != NULL);
    assert(Irp->Type == IoPacketTypeRequest);
    assert(PendingIrp->Requestor != NULL);
    MWORD InputBuffer = Irp->Request.InputBuffer;
    MWORD InputBufferLength = Irp->Request.InputBufferLength;
    MWORD OutputBuffer = Irp->Request.OutputBuffer;
    MWORD OutputBufferLength = Irp->Request.OutputBufferLength;
    PPROCESS RequestorProcess = NULL;
    if (ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_THREAD)) {
	RequestorProcess = ((PTHREAD)PendingIrp->Requestor)->Process;
    } else {
	assert(ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_DRIVER));
	RequestorProcess = ((PIO_DRIVER_OBJECT)PendingIrp->Requestor)->DriverProcess;
    }
    assert(RequestorProcess != NULL);

    PIO_DEVICE_OBJECT DeviceObject = Irp->Request.Device.Object;
    assert(DeviceObject != NULL);
    PIO_DRIVER_OBJECT DriverObject = DeviceObject->DriverObject;
    assert(DriverObject != NULL);

    IO_TRANSFER_TYPE InputIoType, OutputIoType;
    BOOLEAN OutputIsReadOnly;
    IopGetIoTransferTypeFromIrp(&Irp->Request, Irp->Request.Device.Object,
				&InputIoType, &OutputIoType, &OutputIsReadOnly);

    /* We allow InputBuffer to be zero if the target device is a mounted
     * file system volume and the IoType is NEITHER_IO. In this case the
     * cache manager will take care of mapping the cache pages later. If
     * the requestor specified a non-zero OutputBufferLength with a NULL
     * OutputBuffer, the output data must be able to fit in the IRP (ie.
     * OutputBufferLength must be less than IRP_DATA_BUFFER_SIZE). If the
     * OutputBuffer is not NULL, it is always interpreted as a pointer in
     * the requestor address space (and never as an offset, unlike the case
     * of InputBuffer), so it cannot be less than PAGE_SIZE. */
    if ((InputBuffer && !InputBufferLength) ||
	(!InputBuffer && InputBufferLength &&
	 !(DeviceObject->Vcb && InputIoType == NeitherIo)) ||
	(OutputBuffer && (!OutputBufferLength || OutputBuffer < PAGE_SIZE)) ||
	(!OutputBuffer && OutputBufferLength >= IRP_DATA_BUFFER_SIZE)) {
	return STATUS_INVALID_PARAMETER;
    }

    MWORD MappedInputBuffer = 0;
    if (InputBuffer && ((InputIoType == BufferedIo && InputBuffer >= PAGE_SIZE) ||
			InputIoType == NeitherIo || InputIoType == MappedDirectIo)) {
	assert(InputBuffer >= PAGE_SIZE);
	RET_ERR(IopMapUserBuffer(RequestorProcess, DriverObject,
				 InputBuffer, InputBufferLength,
				 &MappedInputBuffer, TRUE));
	assert(MappedInputBuffer != 0);
	DbgTrace("Mapped input buffer %p into driver %s at %p, pfn count %d\n",
		 (PVOID)InputBuffer, DriverObject->DriverImagePath,
		 (PVOID)MappedInputBuffer, Irp->InputBufferPfnCount);
	Irp->InputBuffer = MappedInputBuffer;
	PendingIrp->InputBuffer = InputBuffer;
    }

    if (OutputBuffer && OutputIoType != DirectIo) {
	assert(OutputBuffer >= PAGE_SIZE);
	MWORD MappedOutputBuffer = 0;
	RET_ERR_EX(IopMapUserBuffer(RequestorProcess, DriverObject,
				    OutputBuffer, OutputBufferLength,
				    &MappedOutputBuffer, OutputIsReadOnly),
		   if (MappedInputBuffer) {
		       IopUnmapUserBuffer(DriverObject, MappedInputBuffer);
		   });
	assert(MappedOutputBuffer != 0);
	DbgTrace("Mapped output buffer %p into driver %s at %p, pfn count %d\n",
		 (PVOID)OutputBuffer, DriverObject->DriverImagePath,
		 (PVOID)MappedOutputBuffer, Irp->OutputBufferPfnCount);
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
    PIO_DRIVER_OBJECT DriverObject = PendingIrp->IoPacket->Request.Device.Object->DriverObject;
    if (PendingIrp->InputBuffer) {
	assert(PendingIrp->IoPacket->Request.InputBuffer);
	IopUnmapUserBuffer(DriverObject, PendingIrp->IoPacket->Request.InputBuffer);
	PendingIrp->IoPacket->Request.InputBuffer = PendingIrp->InputBuffer;
    }
    if (PendingIrp->OutputBuffer) {
	assert(PendingIrp->IoPacket->Request.OutputBuffer);
	IopUnmapUserBuffer(DriverObject, PendingIrp->IoPacket->Request.OutputBuffer);
	PendingIrp->IoPacket->Request.OutputBuffer = PendingIrp->OutputBuffer;
    }
}

static VOID IopQueueIoPacketEx(IN PPENDING_IRP PendingIrp,
			       IN PIO_DRIVER_OBJECT Driver,
			       IN PTHREAD Thread)
{
    /* Queue the IRP to the driver */
    InsertTailList(&Driver->IoPacketQueue, &PendingIrp->IoPacket->IoPacketLink);
    PendingIrp->IoPacket->Request.OriginalRequestor = OBJECT_TO_GLOBAL_HANDLE(Thread);
    /* Use the GLOBAL_HANDLE of the IoPacket as the Identifier */
    PendingIrp->IoPacket->Request.Identifier = (HANDLE)POINTER_TO_GLOBAL_HANDLE(PendingIrp->IoPacket);
    InsertTailList(&Thread->PendingIrpList, &PendingIrp->Link);
    KeInitializeEvent(&PendingIrp->IoCompletionEvent, NotificationEvent);
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
    PIO_DRIVER_OBJECT Driver = PendingIrp->IoPacket->Request.Device.Object->DriverObject;
    assert(Driver != NULL);
    IopQueueIoPacketEx(PendingIrp, Driver, Thread);
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
    *pPendingIrp = NULL;
    ULONG IoPacketSize = IopGetIoPacketSizeFromIrp(Irp);
    PIO_PACKET IoPacket = NULL;
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, IoPacketSize, &IoPacket));
    assert(IoPacket);
    ULONG PfnDbOffset = 0;
    IopCopyIoBuffersToIoPacket(Thread, Irp, IoPacket, &PfnDbOffset);
    assert(PfnDbOffset);
    IopAppendPfnDatabaseToIoPacket(Thread->Process, Irp, IoPacket, PfnDbOffset);

    NTSTATUS Status;
    IF_ERR_GOTO(err, Status, IopAllocatePendingIrp(IoPacket, Thread, pPendingIrp));
    assert(*pPendingIrp);

    /* Note here the IO buffers in the driver address space are freed when
     * the server receives the IoCompleted message, so we don't need to free
     * them manually. */
    IF_ERR_GOTO(err, Status, IopMapIoBuffers(*pPendingIrp));

    if (DriverObject) {
	/* This is used by the PNP manager to queue the AddDevice request. */
	IopQueueIoPacketEx(*pPendingIrp, DriverObject, Thread);
    } else {
	/* Non-AddDevice request is always queued on the driver object of
	 * the target device object of the IRP. */
	IopQueueIoPacket(*pPendingIrp, Thread);
    }
    return STATUS_SUCCESS;

err:
    if (IoPacket) {
	IopFreePool(IoPacket);
    }
    if (*pPendingIrp) {
	IopFreePool(*pPendingIrp);
    }
    *pPendingIrp = NULL;
    return Status;
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
	IopDumpDriverPendingIoPacketList(DriverObject,
					 OriginalRequestor,
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
	assert(PendingIrp->Requestor == GLOBAL_HANDLE_TO_OBJECT(OriginalRequestor));
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
    /* Unmap the IO buffers mapped into the driver address space */
    IopUnmapDriverIrpBuffers(PendingIrp);
    /* Find the THREAD or DRIVER object at this level */
    POBJECT Requestor = PendingIrp->Requestor;
    if (ObObjectIsType(Requestor, OBJECT_TYPE_THREAD)) {
	/* The original requestor is a THREAD object */
	assert(PendingIrp->ForwardedFrom == NULL);
	assert(PendingIrp->IoResponseData == NULL);
	/* Copy the IO response data to the server. */
	PendingIrp->IoResponseStatus = Response->ClientMsg.IoCompleted.IoStatus;
	ULONG ResponseDataSize = Response->ClientMsg.IoCompleted.ResponseDataSize;
	PendingIrp->IoResponseDataSize = ResponseDataSize;
	if (ResponseDataSize) {
	    PendingIrp->IoResponseData = ExAllocatePoolWithTag(ResponseDataSize,
							       NTOS_IO_TAG);
	    if (PendingIrp->IoResponseData != NULL) {
		memcpy(PendingIrp->IoResponseData,
		       Response->ClientMsg.IoCompleted.ResponseData,
		       ResponseDataSize);
	    }
	}
	/* Wake the THREAD object up */
	KeSetEvent(&PendingIrp->IoCompletionEvent);
    } else {
	/* Otherwise, it must be a driver object. Reply to the driver. */
	assert(ObObjectIsType(Requestor, OBJECT_TYPE_DRIVER));
	/* Note that since a lower driver can create an IRP and send it to a
	 * higher-level driver, which can in turn reflect this IRP back to the
	 * lower driver, the Requestor can sometimes be equal to DriverObject. */
	PIO_DRIVER_OBJECT RequestorDriver = (PIO_DRIVER_OBJECT)Requestor;

	/* Allocate a new IO packet of type ServerMessage */
	PIO_PACKET SrvMsg = NULL;
	RET_ERR(IopAllocateIoPacket(IoPacketTypeServerMessage,
				    Response->Size, &SrvMsg));
	/* Copy the IO response to the new IO packet */
	assert(SrvMsg != NULL);
	SrvMsg->ServerMsg.Type = IoSrvMsgIoCompleted;
	SrvMsg->ServerMsg.IoCompleted = Response->ClientMsg.IoCompleted;
	if (SrvMsg->ServerMsg.IoCompleted.ResponseDataSize != 0) {
	    memcpy(SrvMsg->ServerMsg.IoCompleted.ResponseData,
		   Response->ClientMsg.IoCompleted.ResponseData,
		   Response->ClientMsg.IoCompleted.ResponseDataSize);
	}
	/* If the requestor is the original requestor, set the OriginalRequestor
	 * field to NULL since driver objects set this field to NULL when they
	 * request a new IRP */
	if (PendingIrp->ForwardedFrom == NULL) {
	    assert(Requestor == IopLocateIrpInOriginalRequestor(OriginalRequestor,
								CompletedIrp)->Requestor);
	    SrvMsg->ServerMsg.IoCompleted.OriginalRequestor = 0;
	} else {
	    /* Otherwise, this is an intermediate requestor. Move the completed
	     * IRP to its pending IRP list so when it replies we know that its
	     * identifier pair is valid. The original requestor never replies
	     * to the IoCompleted server message so we do not do this. */
	    InsertTailList(&RequestorDriver->PendingIoPacketList,
			   &CompletedIrp->IoPacketLink);
	    /* Also restore the device object of the completed IRP to the previous
	     * device object (before this IRP is forwarded to the DriverObject) */
	    assert(PendingIrp->PreviousDeviceObject != NULL);
	    CompletedIrp->Request.Device.Object = PendingIrp->PreviousDeviceObject;
	    DbgTrace("Restoring IRP device object to %p from %s\n",
		     PendingIrp->PreviousDeviceObject,
		     PendingIrp->PreviousDeviceObject->DriverObject->DriverImagePath);
	}

	/* Add the server message IO packet to the driver IO packet queue */
	InsertTailList(&RequestorDriver->IoPacketQueue, &SrvMsg->IoPacketLink);
	/* Signal the driver that an IO packet has been queued */
	KeSetEvent(&RequestorDriver->IoPacketQueuedEvent);
	/* Detach the PENDING_IRP from the driver's ForwardedIrpList */
	RemoveEntryList(&PendingIrp->Link);
	assert(PendingIrp->ForwardedTo == NULL);
	if (PendingIrp->ForwardedFrom == NULL) {
	    /* If the PENDING_IRP is the top-level one (ie. the original requestor),
	     * free the original IO_PACKET */
	    assert(PendingIrp->IoPacket != NULL);
	    IopFreePool(PendingIrp->IoPacket);
	} else {
	    /* Otherwise, detach the PENDING_IRP from the IRP stack */
	    PendingIrp->ForwardedFrom->ForwardedTo = NULL;
	}
	/* In either cases, we want to free the PENDING_IRP itself */
	IopFreePool(PendingIrp);
    }

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
	IopDumpDriverPendingIoPacketList(SourceDriver,
					 OriginalRequestor,
					 IrpIdentifier);
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
	DbgTrace("Lowest level PendingIrp->PreviousDeviceObject = %p DriverObject = %p DriverImagePath = %s\n",
		 PendingIrp->PreviousDeviceObject, PendingIrp->PreviousDeviceObject->DriverObject,
		 PendingIrp->PreviousDeviceObject->DriverObject->DriverImagePath);
    }

    /* If client has requested completion notification, in addition to
     * moving the IO_PACKET from the source driver object to the target
     * driver, we also create a PENDING_IRP that links to the existing
     * PENDING_IRP */
    PIO_DEVICE_OBJECT PreviousDeviceObject = Irp->Request.Device.Object;
    assert(PreviousDeviceObject != NULL);
    if (Msg->ClientMsg.ForwardIrp.NotifyCompletion) {
	PPENDING_IRP NewPendingIrp = NULL;
	RET_ERR(IopAllocatePendingIrp(Irp, SourceDriver, &NewPendingIrp));
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

    /* Set the Device object of the Irp to be the new device (ForwardedTo) */
    Irp->Request.Device.Object = ForwardedTo;
    RET_ERR_EX(IopMapIoBuffers(PendingIrp),
	       {
		   /* Restore the original device object in the IRP if error */
		   Irp->Request.Device.Object = PreviousDeviceObject;
		   /* Also undo the completion notification path above */
		   if (Msg->ClientMsg.ForwardIrp.NotifyCompletion) {
		       assert(PendingIrp->ForwardedFrom != NULL);
		       PendingIrp->ForwardedFrom->ForwardedTo = NULL;
		       RemoveEntryList(&PendingIrp->Link);
		       IopFreePool(PendingIrp);
		   }
	       });

    /* Move the original IO_PACKET from SourceDriver to ForwardedTo and wake the
     * target driver up */
    RemoveEntryList(&Irp->IoPacketLink);
    InsertTailList(&ForwardedTo->DriverObject->IoPacketQueue, &Irp->IoPacketLink);
    KeSetEvent(&ForwardedTo->DriverObject->IoPacketQueuedEvent);
    return STATUS_SUCCESS;
}

static NTSTATUS IopHandleIoRequestMessage(IN PIO_PACKET Src,
					  IN PIO_DRIVER_OBJECT DriverObject)
{
    PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(Src->Request.Device.Handle, NULL);
    assert(DeviceObject != NULL);
    assert(Src->Request.Identifier != NULL);
    if (DeviceObject == NULL || IoPacket->Request.Identifier == NULL) {
	IoDbgDumpIoPacket(Src, TRUE);
	return STATUS_INVALID_PARAMETER;
    }
    assert(DeviceObject->DriverObject != NULL);

    ULONG InputPfnCount = 0, OutputPfnCount = 0;
    IopGetPfnDatabaseSize(DriverObject->DriverProcess, DeviceObject, &Src->Request,
			  &InputPfnCount, &OutputPfnCount);
    ULONG PfnDbOffset = ALIGN_UP(Src->Size, MWORD);
    ULONG IoPacketSize = PfnDbOffset + sizeof(MWORD) * (InputPfnCount + OutputPfnCount);
    PIO_PACKET IoPacket = NULL;
    IopAllocateIoPacket(IoPacketTypeRequest, IoPacketSize, &IoPacket);
    assert(IoPacket != NULL);
    memcpy(IoPacket, Src, Src->Size);
    IoPacket->Request.Device.Object = DeviceObject;
    IoPacket->Request.File.Object = IopGetFileObject(DeviceObject, Src->Request.File.Handle);
    IoPacket->Request.OriginalRequestor = OBJECT_TO_GLOBAL_HANDLE(DriverObject);
    IoPacket->Request.InputBufferPfnCount = InputPfnCount;
    IoPacket->Request.OutputBufferPfnCount = OutputPfnCount;
    IopAppendPfnDatabaseToIoPacket(DriverObject->DriverProcess, &IoPacket->Request,
				   IoPacket, PfnDbOffset);
    PPENDING_IRP PendingIrp = NULL;
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, DriverObject, &PendingIrp),
	       IopFreePool(IoPacket));
    assert(PendingIrp != NULL);

    /* Map the input/output buffers from source driver to target driver */
    RET_ERR_EX(IopMapIoBuffers(PendingIrp),
	       {
		   IopFreePool(IoPacket);
		   IopFreePool(PendingIrp);
	       });

    InsertTailList(&DriverObject->ForwardedIrpList, &PendingIrp->Link);
    InsertTailList(&DeviceObject->DriverObject->IoPacketQueue, &IoPacket->IoPacketLink);
    KeSetEvent(&DeviceObject->DriverObject->IoPacketQueuedEvent);

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
NTSTATUS IopRequestIoPackets(IN ASYNC_STATE State,
			     IN PTHREAD Thread,
			     IN ULONG NumResponsePackets,
			     OUT ULONG *pNumRequestPackets)
{
    assert(Thread != NULL);
    assert(pNumRequestPackets != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    NTSTATUS Status = STATUS_NTOS_BUG;
    assert(DriverObject != NULL);

    ASYNC_BEGIN(State);
    KeSetEvent(&DriverObject->InitializationDoneEvent);

    /* Process the driver's response IO packet buffer first */
    PIO_PACKET Response = (PIO_PACKET)DriverObject->OutgoingIoPacketsServerAddr;
    MWORD OutgoingPacketEnd = DriverObject->OutgoingIoPacketsServerAddr + DRIVER_IO_PACKET_BUFFER_COMMIT;
    for (ULONG i = 0; i < NumResponsePackets; i++) {
	if (Response->Size < sizeof(IO_PACKET) || ((MWORD)Response + Response->Size >= OutgoingPacketEnd)) {
	    DbgTrace("Invalid IO packet size %d from driver %s. Processing halted.\n",
		     Response->Size, DriverObject->DriverImagePath);
	    assert(FALSE);
	    break;
	}

	switch (Response->Type) {
	case IoPacketTypeClientMessage:
	    switch (Response->ClientMsg.Type) {
	    case IoCliMsgIoCompleted:
		Status = IopHandleIoCompleteClientMessage(Response, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleIoCompleteClientMessage returned error status 0x%x\n",
			     Status);
		}
		break;

	    case IoCliMsgForwardIrp:
		Status = IopHandleForwardIrpClientMessage(Response, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleForwardIrpClientMessage returned error status 0x%x\n",
			     Status);
		}
		break;

	    default:
		DbgTrace("Invalid IO message type from driver %s. Type is %d.\n",
			 DriverObject->DriverImagePath, Response->ClientMsg.Type);
		Status = STATUS_INVALID_PARAMETER;
	    }
	    break;

	case IoPacketTypeRequest:
	    Status = IopHandleIoRequestMessage(Response, DriverObject);
	    break;

	default:
	    DbgTrace("Received invalid response packet from driver %s. Dumping it now.\n",
		     DriverObject->DriverImagePath);
	    IoDbgDumpIoPacket(Response, TRUE);
	    Status = STATUS_INVALID_PARAMETER;
	}
	/* If the routines above returned error, there isn't a lot we can do
	 * other than simply ignoring the error and continue processing.
	 * On debug build we will assert so we can know what's going on. */
	assert(NT_SUCCESS(Status));
	Response = (PIO_PACKET)((MWORD)Response + Response->Size);
    }

    /* Now process the driver's queued IO packets and forward them to the driver's
     * incoming IO packet buffer. */
    AWAIT_EX(Status, KeWaitForSingleObject, State, _, Thread,
	     &DriverObject->IoPacketQueuedEvent.Header, TRUE, NULL);

    /* Copy the current IO packet queue to the driver's incoming IO packet buffer. */
    ULONG NumRequestPackets = 0;
    ULONG TotalSize = 0;
    PIO_PACKET Dest = (PIO_PACKET)DriverObject->IncomingIoPacketsServerAddr;
    LoopOverList(Src, &DriverObject->IoPacketQueue, IO_PACKET, IoPacketLink) {
	assert(Src->Size >= sizeof(IO_PACKET));
	assert(IS_ALIGNED_BY(Src->Size, sizeof(MWORD)));
	TotalSize += Src->Size;
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
	NumRequestPackets++;
	/* Copy this IoPacket to the driver's incoming IO packet buffer */
	memcpy(Dest, Src, Src->Size);
	/* Massage the client-side copy of the IO packet so all server pointers
	 * are replaced by the client-side GLOBAL_HANDLE. */
	if (Src->Type == IoPacketTypeRequest) {
	    assert(Src->Request.OriginalRequestor != 0);
	    assert(Src->Request.MajorFunction == IRP_MJ_ADD_DEVICE ||
		   Src->Request.Device.Object != NULL);
	    assert(Src->Request.MajorFunction == IRP_MJ_ADD_DEVICE ||
		   Src->Request.Device.Object->DriverObject == DriverObject);
	    Dest->Request.Device.Handle = OBJECT_TO_GLOBAL_HANDLE(Src->Request.Device.Object);
	    Dest->Request.File.Handle = OBJECT_TO_GLOBAL_HANDLE(Src->Request.File.Object);
	}
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
	    IopFreePool(Src);
	}
    }
    *pNumRequestPackets = NumRequestPackets;

    /* Returns APC status if the alertable wait above returned APC status */
    ASYNC_END(State, Status);
}
