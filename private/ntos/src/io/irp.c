#include "iop.h"

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
	case IoPacketTypeClientMessage: {
	    switch (Response->ClientMsg.Type) {
	    case IoCliMsgIoCompleted: {
		PTHREAD OriginatingThread = (PTHREAD)
		    GLOBAL_HANDLE_TO_OBJECT(Response->ClientMsg.Parameters.IoCompleted.OriginatingThread);
		HANDLE OriginalIrp = Response->ClientMsg.Parameters.IoCompleted.OriginalIrp;
		/* Check the driver's pending IO packet list to see if OriginalIrp is valid */
		PIO_PACKET CompletedIrp = NULL;
		LoopOverList(PendingIoPacket, &DriverObject->PendingIoPacketList, IO_PACKET, IoPacketLink) {
		    /* The IO packets in the pending IO packet list must be of type IoPacketTypeRequest.
		     * We never put IoPacketTypeClientMessage etc into the pending IO packet list */
		    assert(PendingIoPacket->Type == IoPacketTypeRequest);
		    if ((PendingIoPacket->Request.OriginatingThread.Object == OriginatingThread) &&
			(PendingIoPacket->Request.Identifier == OriginalIrp)) {
			CompletedIrp = PendingIoPacket;
		    }
		}
		if (CompletedIrp == NULL) {
		    DbgTrace("Received response packet from driver %s with invalid IRP identifier %p:%p."
			     " Dumping all IO packets in the driver's pending IO packet list.\n",
			     DriverObject->DriverImagePath, OriginatingThread, OriginalIrp);
		    LoopOverList(PendingIoPacket, &DriverObject->PendingIoPacketList, IO_PACKET, IoPacketLink) {
			IoDbgDumpIoPacket(PendingIoPacket, FALSE);
		    }
		    continue;
		}

		/* OriginalIrp is valid. Detach the IO packet from the driver's pending IO packet list. */
		RemoveEntryList(&CompletedIrp->IoPacketLink);
		PPENDING_IRP PendingIrp = IopGetPendingIrp(OriginatingThread, CompletedIrp);
		/* If the IRP was queued on the thread, wake it up. */
		if (PendingIrp != NULL) {
		    PendingIrp->IoResponseStatus = Response->ClientMsg.Parameters.IoCompleted.IoStatus;
		    ULONG ResponseDataSize = Response->ClientMsg.Parameters.IoCompleted.ResponseDataSize;
		    if (ResponseDataSize) {
			PendingIrp->IoResponseData = ExAllocatePoolWithTag(ResponseDataSize, NTOS_IO_TAG);
			if (PendingIrp->IoResponseData != NULL) {
			    memcpy(PendingIrp->IoResponseData,
				   Response->ClientMsg.Parameters.IoCompleted.ResponseData,
				   ResponseDataSize);
			}
		    }
		    KeSetEvent(&PendingIrp->IoCompletionEvent);
		} else {
		    /* Else, the original IRP was generated by a driver object via IoCallDriverEx.
		     * Add the IRP to its completed IRP list, so later we can inform the driver object
		     * of the completion of the IRP. */
		    assert(OriginatingThread->Process != NULL);
		    PIO_DRIVER_OBJECT DriverObject = OriginatingThread->Process->DriverObject;
		    /* TODO */
		}
	    } break;

	    case IoCliMsgForwardIrp: {
	    } break;

	    default:
		DbgTrace("Invalid IO message type from driver %s. Type is %d.\n",
			 DriverObject->DriverImagePath, Response->ClientMsg.Type);
	    }
	} break;

	case IoPacketTypeRequest: {
	    UNIMPLEMENTED;
	} break;

	default:
	    DbgTrace("Received invalid response packet from driver %s. Dumping it now.\n",
		     DriverObject->DriverImagePath);
	    IoDbgDumpIoPacket(Response, TRUE);
	    assert(FALSE);
	}
	Response = (PIO_PACKET)((MWORD)Response + Response->Size);
    }

    /* Now process the driver's queued IO packets and forward them to the driver's
     * incoming IO packet buffer. */
    AWAIT_EX_NO_LOCALS(Status, KeWaitForSingleObject, State, Thread,
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
	    assert(IoPacket->Request.OriginatingThread.Object != NULL);
	    Dest->Request.Device.Handle = OBJECT_TO_GLOBAL_HANDLE(IoPacket->Request.Device.Object);
	    Dest->Request.File.Handle = OBJECT_TO_GLOBAL_HANDLE(IoPacket->Request.File.Object);
	    Dest->Request.OriginatingThread.Handle =
		OBJECT_TO_GLOBAL_HANDLE(IoPacket->Request.OriginatingThread.Object);
	}
	/* Move this IoPacket from the driver's IO packet queue to its pending IO packet list */
	RemoveEntryList(&IoPacket->IoPacketLink);
	InsertTailList(&DriverObject->PendingIoPacketList, &IoPacket->IoPacketLink);
	IoDbgDumpIoPacket(Dest, TRUE);
	Dest = (PIO_PACKET)((MWORD)Dest + IoPacket->Size);
	IoPacket = CONTAINING_RECORD(IoPacket->IoPacketLink.Flink, IO_PACKET, IoPacketLink);
    }
    *pNumRequestPackets = NumRequestPackets;

    /* Returns APC status if the alertable wait above returned APC status */
    ASYNC_END(Status);
}
