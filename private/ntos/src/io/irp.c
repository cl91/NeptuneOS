#include "iop.h"

typedef struct _PENDING_IRP_ITERATOR_CONTEXT {
    PLIST_ENTRY ListHead;
    PLIST_ENTRY CurrentEntry;
} PENDING_IRP_ITERATOR_CONTEXT, *PPENDING_IRP_ITERATOR_CONTEXT;

static PDISPATCHER_HEADER IopPendingIrpIterator(IN PVOID Context)
{
    PPENDING_IRP_ITERATOR_CONTEXT Ctx = (PPENDING_IRP_ITERATOR_CONTEXT)Context;
    assert(Ctx != NULL);
    assert(Ctx->ListHead != NULL);
    assert(Ctx->CurrentEntry != NULL);
    if (Ctx->CurrentEntry->Flink == Ctx->ListHead) {
	return NULL;
    }
    PPENDING_IRP PendingIrp = CONTAINING_RECORD(Ctx->CurrentEntry, PENDING_IRP, Link);
    Ctx->CurrentEntry = Ctx->CurrentEntry->Flink;
    return &PendingIrp->IoCompletionEvent.Header;
}

NTSTATUS IopThreadWaitForIoCompletion(IN ASYNC_STATE State,
				      IN PTHREAD Thread,
				      IN BOOLEAN Alertable,
				      IN WAIT_TYPE WaitType)
{
    ASYNC_BEGIN(State, Locals, {
	    IN OUT PENDING_IRP_ITERATOR_CONTEXT Ctx;
	});
    Locals.Ctx.ListHead = &Thread->PendingIrpList;
    Locals.Ctx.CurrentEntry = Thread->PendingIrpList.Flink;
    AWAIT(KeWaitForMultipleObjects, State, Locals, Thread, Alertable,
	  WaitType, IopPendingIrpIterator, &Locals.Ctx);
    ASYNC_END(State, STATUS_SUCCESS);
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

    /* IRP identifier is valid. Detach the IO packet from the driver's pending IO packet list. */
    RemoveEntryList(&CompletedIrp->IoPacketLink);
    PPENDING_IRP PendingIrp = IopLocateIrpInOriginalRequestor(OriginalRequestor, CompletedIrp);
    /* If the IRP identifier is valid, PendingIrp should never be NULL. We assert on
     * debug build and return error on release build. */
    if (PendingIrp == NULL) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    /* The PENDING_IRP must be top-most (ie. not forwarded from a higher-level driver) */
    assert(PendingIrp->ForwardedFrom == NULL);
    /* Locate the lowest-level driver object in the IRP flow */
    while (PendingIrp->ForwardedTo != NULL) {
	PendingIrp = PendingIrp->ForwardedTo;
    }
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
	    PendingIrp->IoResponseData = ExAllocatePoolWithTag(ResponseDataSize, NTOS_IO_TAG);
	    if (PendingIrp->IoResponseData != NULL) {
		memcpy(PendingIrp->IoResponseData,
		       Response->ClientMsg.IoCompleted.ResponseData,
		       ResponseDataSize);
	    }
	}
	/* Set the device object in the Irp to the original device object */
	assert(PendingIrp->IoPacket != NULL);
	assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	assert(PendingIrp->DeviceObject != NULL);
	PendingIrp->IoPacket->Request.Device.Object = PendingIrp->DeviceObject;
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
	RET_ERR(IopAllocateIoPacket(IoPacketTypeServerMessage, Response->Size, &SrvMsg));
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
	}

	/* Add the IO packet to the driver IO packet queue */
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
	    ExFreePool(PendingIrp->IoPacket);
	} else {
	    /* Otherwise, detach the PENDING_IRP from the IRP stack */
	    PendingIrp->ForwardedFrom->ForwardedTo = NULL;
	}
	/* In either cases, we want to free the PENDING_IRP itself */
	ExFreePool(PendingIrp);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS IopHandleForwardIrpClientMessage(IN PIO_PACKET Msg,
						 IN PIO_DRIVER_OBJECT SourceDriver)
{
    assert(Msg != NULL);
    assert(Msg->Type == IoPacketTypeClientMessage);
    assert(Msg->ClientMsg.Type == IoCliMsgForwardIrp);

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
    PIO_DEVICE_OBJECT ForwardedFrom = Irp->Request.Device.Object;
    assert(ForwardedFrom != NULL);
    GLOBAL_HANDLE DeviceHandle = Msg->ClientMsg.ForwardIrp.DeviceObject;
    PIO_DEVICE_OBJECT ForwardedTo = IopGetDeviceObject(DeviceHandle,
						       NULL);
    if (ForwardedTo == NULL) {
	DbgTrace("Driver %s sent ForwardIrp message with invalid device handle %p\n",
		 SourceDriver->DriverImagePath, (PVOID)DeviceHandle);
	return STATUS_INVALID_PARAMETER;
    }
    assert(ForwardedTo->DriverObject != NULL);

    /* If client has requested completion notification, in addition to
     * moving the IO_PACKET from the source driver object to the target
     * driver, we also create a PENDING_IRP that links to the existing
     * PENDING_IRP */
    if (Msg->ClientMsg.ForwardIrp.NotifyCompletion) {
	PPENDING_IRP PendingIrp = IopLocateIrpInOriginalRequestor(OriginalRequestor,
								  Irp);
	/* If the IRP identifier is valid, PendingIrp should never be NULL. */
	assert(PendingIrp != NULL);
	/* On release build we simply drop the completion notification. It's
	 * better than crashing the Executive */
	if (PendingIrp != NULL) {
	    PPENDING_IRP NewPendingIrp = NULL;
	    IopAllocatePendingIrp(Irp, SourceDriver, ForwardedFrom, &NewPendingIrp);
	    NewPendingIrp->ForwardedFrom = PendingIrp;
	    PendingIrp->ForwardedTo = NewPendingIrp;
	    InsertTailList(&SourceDriver->ForwardedIrpList, &NewPendingIrp->Link);
	}
    }

    /* Move the original IO_PACKET from SourceDriver to ForwardedTo and wake the
     * target driver up */
    RemoveEntryList(&Irp->IoPacketLink);
    InsertTailList(&ForwardedTo->DriverObject->IoPacketQueue, &Irp->IoPacketLink);
    /* Set the Device object of the Irp to be the new device (ForwardedTo) */
    Irp->Request.Device.Object = ForwardedTo;
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
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, DriverObject, DeviceObject, &PendingIrp),
	       ExFreePool(IoPacket));
    assert(PendingIrp != NULL);

    /* Map the input/output buffers from source driver to target driver */
    switch (Src->Request.MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
	assert(DriverObject->DriverProcess != NULL);
	RET_ERR_EX(IopMapUserBuffer(DriverObject->DriverProcess, DeviceObject->DriverObject,
				    (MWORD)Src->Request.DeviceIoControl.InputBuffer,
				    Src->Request.DeviceIoControl.InputBufferLength,
				    (MWORD *)&IoPacket->Request.DeviceIoControl.InputBuffer, TRUE),
		   {
		       ExFreePool(IoPacket);
		       ExFreePool(PendingIrp);
		   });
	RET_ERR_EX(IopMapUserBuffer(DriverObject->DriverProcess, DeviceObject->DriverObject,
				    (MWORD)Src->Request.DeviceIoControl.OutputBuffer,
				    Src->Request.DeviceIoControl.OutputBufferLength,
				    (MWORD *)&IoPacket->Request.DeviceIoControl.OutputBuffer, FALSE),
		   {
		       ExFreePool(IoPacket);
		       ExFreePool(PendingIrp);
		       IopUnmapUserBuffer(DeviceObject->DriverObject,
					  (MWORD)IoPacket->Request.DeviceIoControl.InputBuffer);
		   });
	break;

    default:
	UNIMPLEMENTED;
    }

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
		break;

	    case IoCliMsgForwardIrp:
		Status = IopHandleForwardIrpClientMessage(Response, DriverObject);
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
	     &DriverObject->IoPacketQueuedEvent.Header, TRUE);

    /* Determine how many packets we can send in one go since the driver IO packet
     * buffer has a finite size. This includes potentially the FileName buffer.
     * The rest of the IO packets in the IO packet queue are skipped and left in the queue.
     * Hopefully next time there is enough space. */
    ULONG NumRequestPackets = 0;
    ULONG TotalSendSize = 0;
    LoopOverList(IoPacket, &DriverObject->IoPacketQueue, IO_PACKET, IoPacketLink) {
	assert(IoPacket->Size >= sizeof(IO_PACKET));
	TotalSendSize += IoPacket->Size;
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
    PIO_PACKET IoPacket = CONTAINING_RECORD(DriverObject->IoPacketQueue.Flink, IO_PACKET, IoPacketLink);
    PIO_PACKET Dest = (PIO_PACKET)DriverObject->IncomingIoPacketsServerAddr;
    for (ULONG i = 0; i < NumRequestPackets; i++) {
	/* Copy this IoPacket to the driver's incoming IO packet buffer */
	memcpy(Dest, IoPacket, IoPacket->Size);
	/* Massage the client-side copy of the IO packet so all server pointers are
	 * replaced by the client-side GLOBAL_HANDLE */
	if (IoPacket->Type == IoPacketTypeRequest) {
	    assert(IoPacket->Request.Device.Object != NULL);
	    assert(IoPacket->Request.OriginalRequestor != 0);
	    assert(IoPacket->Request.MajorFunction == IRP_MJ_ADD_DEVICE ||
		   IoPacket->Request.Device.Object->DriverObject == DriverObject);
	    Dest->Request.Device.Handle = OBJECT_TO_GLOBAL_HANDLE(IoPacket->Request.Device.Object);
	    Dest->Request.File.Handle = OBJECT_TO_GLOBAL_HANDLE(IoPacket->Request.File.Object);
	}
	IoDbgDumpIoPacket(Dest, TRUE);
	Dest = (PIO_PACKET)((MWORD)Dest + IoPacket->Size);
	PIO_PACKET NextIoPacket = CONTAINING_RECORD(IoPacket->IoPacketLink.Flink,
						    IO_PACKET, IoPacketLink);
	/* Detach this IoPacket from the driver's IO packet queue */
	RemoveEntryList(&IoPacket->IoPacketLink);
	if (IoPacket->Type == IoPacketTypeRequest) {
	    /* If this is a request packet, move it to the driver's pending IO packet list */
	    InsertTailList(&DriverObject->PendingIoPacketList, &IoPacket->IoPacketLink);
	} else {
	    /* Else, clean up this IO packet since we do not expect a reply */
	    ExFreePool(IoPacket);
	}
	IoPacket = NextIoPacket;
    }
    *pNumRequestPackets = NumRequestPackets;

    /* Returns APC status if the alertable wait above returned APC status */
    ASYNC_END(State, Status);
}
