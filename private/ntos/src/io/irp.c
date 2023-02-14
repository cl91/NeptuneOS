#include "iop.h"

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
    Locals.DspObjs = (PDISPATCHER_HEADER *)ExAllocatePoolWithTag(sizeof(PVOID)*IrpCount,
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

/* Returns the number of PFN entry needed for the MDL of the specified buffer */
static ULONG IopGetBufferPfnCount(IN PPROCESS Process,
				  IN MWORD Buffer,
				  IN MWORD BufferLength)
{
    ULONG PfnCount = 0;
    MmGeneratePageFrameDatabase(NULL, Process, Buffer, BufferLength, &PfnCount);
    return PfnCount;
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
static inline NTSTATUS IopMapUserBuffer(IN PPROCESS User,
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
static inline VOID IopUnmapUserBuffer(IN PIO_DRIVER_OBJECT Driver,
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

/*
 * Before calling this routine, the IO buffers in the IO_PACKET are
 * pointers in the requestor address space. After this routine returns
 * with SUCCESS status, the IO buffers in the IO_PACKET are update to
 * the pointers in the target driver address space, and the original
 * IO buffer pointers are saved into the PENDING_IRP struct.
 */
NTSTATUS IopMapIoBuffers(IN PPENDING_IRP PendingIrp,
			 IN BOOLEAN OutputIsReadOnly)
{
    assert(PendingIrp->IoPacket != NULL);
    assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
    assert(PendingIrp->IoPacket->Request.Device.Object != NULL);
    assert(PendingIrp->Requestor != NULL);
    /* Map the IO buffers into the new driver address space */
    PPROCESS RequestorProcess = NULL;
    if (ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_THREAD)) {
	RequestorProcess = ((PTHREAD)PendingIrp->Requestor)->Process;
    } else {
	assert(ObObjectIsType(PendingIrp->Requestor, OBJECT_TYPE_DRIVER));
	RequestorProcess = ((PIO_DRIVER_OBJECT)PendingIrp->Requestor)->DriverProcess;
    }
    assert(RequestorProcess != NULL);

    MWORD InputBuffer = PendingIrp->IoPacket->Request.InputBuffer;
    MWORD InputBufferLength = PendingIrp->IoPacket->Request.InputBufferLength;
    MWORD OutputBuffer = PendingIrp->IoPacket->Request.OutputBuffer;
    MWORD OutputBufferLength = PendingIrp->IoPacket->Request.OutputBufferLength;
    PIO_DRIVER_OBJECT DriverObject = PendingIrp->IoPacket->Request.Device.Object->DriverObject;
    assert(DriverObject != NULL);
    MWORD DriverInputBuffer = 0;
    DbgTrace("Mapping input buffer %p from process vad 0x%zx\n",
	     (PVOID)InputBuffer, RequestorProcess->VSpace.VSpaceCap);
    ULONG InputBufferPfnCount = 0;
    ULONG OutputBufferPfnCount = 0;
    if (InputBuffer && InputBufferLength) {
	RET_ERR(IopMapUserBuffer(RequestorProcess, DriverObject,
				 InputBuffer, InputBufferLength,
				 &DriverInputBuffer, TRUE));
	assert(DriverInputBuffer != 0);
	DbgTrace("Mapped input buffer %p into driver %s at %p\n",
		 (PVOID)InputBuffer, DriverObject->DriverImagePath,
		 (PVOID)DriverInputBuffer);
	InputBufferPfnCount = IopGetBufferPfnCount(RequestorProcess,
						   InputBuffer,
						   InputBufferLength);
    }

    MWORD DriverOutputBuffer = 0;
    DbgTrace("Mapping output buffer %p from process vad 0x%zx\n",
	     (PVOID)OutputBuffer, RequestorProcess->VSpace.VSpaceCap);
    if (OutputBuffer && OutputBufferLength) {
	RET_ERR_EX(IopMapUserBuffer(RequestorProcess, DriverObject,
				    OutputBuffer, OutputBufferLength,
				    &DriverOutputBuffer, OutputIsReadOnly),
		   IopUnmapUserBuffer(DriverObject, DriverInputBuffer));
	assert(DriverOutputBuffer != 0);
	DbgTrace("Mapped output buffer %p into driver %s at %p\n",
		 (PVOID)OutputBuffer, DriverObject->DriverImagePath,
		 (PVOID)DriverOutputBuffer);
	OutputBufferPfnCount = IopGetBufferPfnCount(RequestorProcess,
						    OutputBuffer,
						    OutputBufferLength);
    }
    PendingIrp->IoPacket->Request.InputBuffer = DriverInputBuffer;
    PendingIrp->IoPacket->Request.OutputBuffer = DriverOutputBuffer;
    PendingIrp->IoPacket->Request.InputBufferPfnCount = InputBufferPfnCount;
    PendingIrp->IoPacket->Request.OutputBufferPfnCount = OutputBufferPfnCount;
    PendingIrp->InputBuffer = InputBuffer;
    PendingIrp->OutputBuffer = OutputBuffer;
    return STATUS_SUCCESS;
}

static VOID IopUnmapDriverIrpBuffers(IN PPENDING_IRP PendingIrp)
{
    assert(PendingIrp != NULL);
    assert(PendingIrp->IoPacket != NULL);
    if (PendingIrp->IoPacket->Request.InputBuffer) {
	assert(PendingIrp->InputBuffer);
    }
    if (PendingIrp->InputBuffer) {
	assert(PendingIrp->IoPacket->Request.InputBuffer);
    }
    if (PendingIrp->IoPacket->Request.OutputBuffer) {
	assert(PendingIrp->OutputBuffer);
    }
    if (PendingIrp->OutputBuffer) {
	assert(PendingIrp->IoPacket->Request.OutputBuffer);
    }
    /* We can only unmap the lowest-level PENDING_IRP because otherwise
     * lower drivers will have their IO buffers unmapped before it has
     * completed the IRP. */
    assert(PendingIrp->ForwardedTo == NULL);
    PIO_DRIVER_OBJECT DriverObject = PendingIrp->IoPacket->Request.Device.Object->DriverObject;
    IopUnmapUserBuffer(DriverObject, PendingIrp->IoPacket->Request.InputBuffer);
    IopUnmapUserBuffer(DriverObject, PendingIrp->IoPacket->Request.OutputBuffer);
    PendingIrp->IoPacket->Request.InputBuffer = PendingIrp->InputBuffer;
    PendingIrp->IoPacket->Request.OutputBuffer = PendingIrp->OutputBuffer;
}

static NTSTATUS IopHandleIoCompletedClientMessage(IN PIO_PACKET Response,
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
	/* Note that since a lower driver can create an IRP and send it to
	 * a higher-level driver, which can in turn forward this IRP back to the
	 * lower driver, the Requestor may in fact be equal to DriverObject. */
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

    PPENDING_IRP PendingIrp = IopLocateIrpInOriginalRequestor(OriginalRequestor,
							      Irp);
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
    RET_ERR_EX(IopMapIoBuffers(PendingIrp, FALSE),
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
    PIO_PACKET IoPacket = NULL;
    IopAllocateIoPacket(IoPacketTypeRequest, Src->Size, &IoPacket);
    assert(IoPacket != NULL);
    memcpy(IoPacket, Src, Src->Size);
    PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(Src->Request.Device.Handle, NULL);
    assert(DeviceObject != NULL);
    assert(IoPacket->Request.Identifier != NULL);
    if (DeviceObject == NULL || IoPacket->Request.Identifier == NULL) {
	IoDbgDumpIoPacket(Src, TRUE);
	return STATUS_INVALID_PARAMETER;
    }
    assert(DeviceObject->DriverObject != NULL);
    IoPacket->Request.Device.Object = DeviceObject;
    IoPacket->Request.File.Object = IopGetFileObject(Src->Request.File.Handle);
    IoPacket->Request.OriginalRequestor = OBJECT_TO_GLOBAL_HANDLE(DriverObject);
    PPENDING_IRP PendingIrp = NULL;
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, DriverObject, &PendingIrp),
	       IopFreePool(IoPacket));
    assert(PendingIrp != NULL);

    /* Map the input/output buffers from source driver to target driver */
    RET_ERR_EX(IopMapIoBuffers(PendingIrp, FALSE),
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
		Status = IopHandleIoCompletedClientMessage(Response, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleIoCompletedClientMessage returned error status 0x%x\n", Status);
		}
		break;

	    case IoCliMsgForwardIrp:
		Status = IopHandleForwardIrpClientMessage(Response, DriverObject);
		if (!NT_SUCCESS(Status)) {
		    DbgTrace("IopHandleForwardIrpClientMessage returned error status 0x%x\n", Status);
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
	 * other than simply ignoring the error and continue processing. */
	assert(NT_SUCCESS(Status));
	Response = (PIO_PACKET)((MWORD)Response + Response->Size);
    }

    /* Now process the driver's queued IO packets and forward them to the driver's
     * incoming IO packet buffer. */
    AWAIT_EX(Status, KeWaitForSingleObject, State, _, Thread,
	     &DriverObject->IoPacketQueuedEvent.Header, TRUE, NULL);

    /* Determine how many packets we can send in one go since the driver IO packet
     * buffer has a finite size. This includes potentially the FileName buffer.
     * The rest of the IO packets in the IO packet queue are skipped and left in
     * the queue. Hopefully next time there is enough space. */
    ULONG NumRequestPackets = 0;
    ULONG TotalSendSize = 0;
    LoopOverList(IoPacket, &DriverObject->IoPacketQueue, IO_PACKET, IoPacketLink) {
	assert(IoPacket->Size >= sizeof(IO_PACKET));
	TotalSendSize += ALIGN_UP_BY(IoPacket->Size, sizeof(ULONG_PTR));
	/* For IO request packets we need extra space for the page frame database */
	if (IoPacket->Type == IoPacketTypeRequest) {
	    TotalSendSize += (IoPacket->Request.InputBufferPfnCount +
			      IoPacket->Request.OutputBufferPfnCount) * sizeof(ULONG_PTR);
	}
	if (TotalSendSize > DRIVER_IO_PACKET_BUFFER_COMMIT) {
	    /* TODO: Commit more memory in this case. Make sure to commit the outgoing
	     * buffer memory as well since we assume that the outgoing buffer has the
	     * same size as the incoming buffer. */
	    assert(FALSE);
	    break;
	}
	/* Ok to send this one. */
	NumRequestPackets++;
    }

    /* Copy the current IO packet queue to the driver's incoming IO packet buffer. */
    PIO_PACKET IoPacket = CONTAINING_RECORD(DriverObject->IoPacketQueue.Flink,
					    IO_PACKET, IoPacketLink);
    PIO_PACKET Dest = (PIO_PACKET)DriverObject->IncomingIoPacketsServerAddr;
    for (ULONG i = 0; i < NumRequestPackets; i++) {
	/* Copy this IoPacket to the driver's incoming IO packet buffer */
	memcpy(Dest, IoPacket, IoPacket->Size);
	/* Align the IO packet size up to pointer alignment so the page frame
	 * database (if any) and the next IoPacket is pointer aligned. */
	ULONG IoPacketSize = ALIGN_UP_BY(IoPacket->Size, sizeof(ULONG_PTR));
	/* Massage the client-side copy of the IO packet so all server pointers
	 * are replaced by the client-side GLOBAL_HANDLE, and generate the page
	 * frame database for the MDLs. Note we only need to send the page frame
	 * database from the server to the client. Client never needs to send
	 * PFN database to the server (server ignores them if it did). */
	if (IoPacket->Type == IoPacketTypeRequest) {
	    assert(IoPacket->Request.OriginalRequestor != 0);
	    assert(IoPacket->Request.MajorFunction == IRP_MJ_ADD_DEVICE ||
		   IoPacket->Request.Device.Object != NULL);
	    assert(IoPacket->Request.MajorFunction == IRP_MJ_ADD_DEVICE ||
		   IoPacket->Request.Device.Object->DriverObject == DriverObject);
	    Dest->Request.Device.Handle = OBJECT_TO_GLOBAL_HANDLE(IoPacket->Request.Device.Object);
	    Dest->Request.File.Handle = OBJECT_TO_GLOBAL_HANDLE(IoPacket->Request.File.Object);
	    if (Dest->Request.InputBufferPfnCount) {
		Dest->Request.InputBufferPfn = IoPacketSize;
		MmGeneratePageFrameDatabase((PULONG_PTR)((MWORD)Dest + IoPacketSize),
					    DriverObject->DriverProcess,
					    Dest->Request.InputBuffer,
					    Dest->Request.InputBufferLength,
					    &Dest->Request.InputBufferPfnCount);
		IoPacketSize += Dest->Request.InputBufferPfnCount * sizeof(ULONG_PTR);
	    }
	    if (Dest->Request.OutputBufferPfnCount) {
		Dest->Request.OutputBufferPfn = IoPacketSize;
		MmGeneratePageFrameDatabase((PULONG_PTR)((MWORD)Dest + IoPacketSize),
					    DriverObject->DriverProcess,
					    Dest->Request.OutputBuffer,
					    Dest->Request.OutputBufferLength,
					    &Dest->Request.OutputBufferPfnCount);
		IoPacketSize += Dest->Request.OutputBufferPfnCount * sizeof(ULONG_PTR);
	    }
	}
	Dest->Size = IoPacketSize;
	IoDbgDumpIoPacket(Dest, TRUE);
	Dest = (PIO_PACKET)((MWORD)Dest + IoPacketSize);
	PIO_PACKET NextIoPacket = CONTAINING_RECORD(IoPacket->IoPacketLink.Flink,
						    IO_PACKET, IoPacketLink);
	/* Detach this IoPacket from the driver's IO packet queue */
	RemoveEntryList(&IoPacket->IoPacketLink);
	if (IoPacket->Type == IoPacketTypeRequest) {
	    /* If this is a request packet, move it to the driver's
	     * pending IO packet list */
	    InsertTailList(&DriverObject->PendingIoPacketList, &IoPacket->IoPacketLink);
	} else {
	    /* Else, clean up this IO packet since we do not expect a reply */
	    IopFreePool(IoPacket);
	}
	IoPacket = NextIoPacket;
    }
    *pNumRequestPackets = NumRequestPackets;

    /* Returns APC status if the alertable wait above returned APC status */
    ASYNC_END(State, Status);
}
