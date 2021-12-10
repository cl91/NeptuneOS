#include "iop.h"

/*
 * Handler function for the WDM service IopRequestIrp. This service should
 * only be called in the main event loop thread of the driver process.
 *
 * Check the previous batch of incoming IRPs first and see if any of them
 * errored out, and then process the driver's outgoing IRP buffer. Once that
 * is done, process the driver's IRP queue and forward them to the driver's
 * incoming IRP buffer.
 */
NTSTATUS IopRequestIrp(IN ASYNC_STATE State,
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

    /* Check the previous batch of incoming IRPs to see if any of them
     * is marked with an error status. This means that the driver process
     * has encountered a serious error (probably out-of-memory). */
    PIO_REQUEST_PACKET Request = (PIO_REQUEST_PACKET)DriverObject->IncomingIrpServerAddr;
    for (ULONG i = 0; i < DriverObject->NumRequestPackets; i++) {
	if (Request[i].Type == IrpTypeRequest) {
	    PIO_REQUEST_PACKET ThisIrp = (PIO_REQUEST_PACKET)
		GLOBAL_HANDLE_TO_POINTER(Request[i].ThisIrp);
	    /* Check the driver's pending IRP list to see if ThisIrp is valid */
	    BOOLEAN Valid = FALSE;
	    LoopOverList(PendingIrp, &DriverObject->PendingIrpList, IO_REQUEST_PACKET, IrpLink) {
		if (PendingIrp == ThisIrp) {
		    Valid = TRUE;
		}
	    }
	    /* If ThisIrp is not valid, what has most likely happened is that the driver has
	     * messed up the incoming IRP buffer. */
	    if (!Valid) {
		DbgTrace("BUG BUG BUG --- Driver %s made a mess of the incoming IRP buffer!",
			 DriverObject->DriverImageName);
		/* On debug build we should assert so we can stop and debug. */
		assert(FALSE);
		continue;
	    }
	    /* ThisIrp is valid. Check if it errored out. */
	    if (Request[i].ErrorStatus != STATUS_SUCCESS) {
		/* Driver should never return a status code that is not STATUS_SUCCESS, but
		 * does not have the error bit in the NTSTATUS word set. If this happens, then
		 * most likely driver process has messed up the incoming IRP buffer. */
		if (NT_SUCCESS(Request[i].ErrorStatus)) {
		    DbgTrace("BUG BUG BUG --- Driver %s made a mess of the incoming IRP buffer!",
			     DriverObject->DriverImageName);
		    /* On debug build we should assert so we can stop and debug. */
		    assert(FALSE);
		}
		PTHREAD ThreadToWakeUp = ThisIrp->Thread.Object;
		assert(ThreadToWakeUp != NULL);
		assert((MWORD)ThreadToWakeUp > EX_POOL_START);
		assert((MWORD)ThreadToWakeUp < EX_POOL_END);
		assert(ThreadToWakeUp->PendingIrp == ThisIrp);
		/* Wake up the thread waiting for its IO completion event. */
		ThreadToWakeUp->IoResponseStatus = Request[i].IoStatus;
		KeSetEvent(&ThreadToWakeUp->IoCompletionEvent);
		/* Also remove the IRP from the driver's pending IRP list. */
		RemoveEntryList(&ThisIrp->IrpLink);
	    }
	} else if (Request[i].Type == IrpTypeRequest) {
	    DbgTrace("BUG BUG BUG --- Driver %s made a mess of the incoming IRP buffer!\n",
		     DriverObject->DriverImageName);
	    /* On debug build we should assert so we can stop and debug. */
	    assert(FALSE);
	    continue;
	}
    }

    /* Now process the driver's response IRP buffer */
    PIO_REQUEST_PACKET Response = (PIO_REQUEST_PACKET)DriverObject->OutgoingIrpServerAddr;
    for (ULONG i = 0; i < NumResponsePackets; i++) {
	if (Response[i].Type == IrpTypeIoCompleted) {
	    PIO_REQUEST_PACKET ParentIrp = (PIO_REQUEST_PACKET)
		GLOBAL_HANDLE_TO_POINTER(Response[i].ParentIrp.Handle);
	    /* Check the driver's pending IRP list to see if ParentIrp is valid */
	    BOOLEAN Valid = FALSE;
	    LoopOverList(PendingIrp, &DriverObject->PendingIrpList, IO_REQUEST_PACKET, IrpLink) {
		if (PendingIrp == ParentIrp) {
		    Valid = TRUE;
		}
	    }
	    if (!Valid) {
		DbgTrace("Received response packet from driver %s with invalid ParentIrp %p."
			 " Dumping all IRPs in the driver's pending IRP list.\n",
			 DriverObject->DriverImageName, ParentIrp);
		LoopOverList(PendingIrp, &DriverObject->PendingIrpList, IO_REQUEST_PACKET, IrpLink) {
		    IoDbgDumpIoRequestPacket(PendingIrp, FALSE);
		}
		continue;
	    }
	    /* ParentIrp is valid. Wake up the thread waiting for its IO completion event. */
	    PTHREAD ThreadToWakeUp = ParentIrp->Thread.Object;
	    assert(ThreadToWakeUp != NULL);
	    assert((MWORD)ThreadToWakeUp > EX_POOL_START);
	    assert((MWORD)ThreadToWakeUp < EX_POOL_END);
	    assert(ThreadToWakeUp->PendingIrp == ParentIrp);
	    ThreadToWakeUp->IoResponseStatus = Response[i].IoStatus;
	    KeSetEvent(&ThreadToWakeUp->IoCompletionEvent);
	    /* Finally, remove the IRP from the driver's pending IRP list. */
	    RemoveEntryList(&ParentIrp->IrpLink);
	} else if (Response[i].Type == IrpTypeRequest) {
	    /* TODO */
	} else {
	    DbgTrace("Received invalid response packet from driver %s. Dumping it below.\n",
		     DriverObject->DriverImageName);
	    IoDbgDumpIoRequestPacket(&Response[i], TRUE);
	    continue;
	}
    }

    /* Now process the driver's queued IRPs and forward them to the driver's
     * incoming IRP buffer. */
    AWAIT_EX(KeWaitForSingleObject, Status, State, Thread,
	     &DriverObject->IrpQueuedEvent.Header, TRUE);

    /* Determine how many packets we can send in one go since the driver IRP
     * buffer has a finite size. This includes potentially the FileName buffer.
     * The rest of the IRPs in the IRP queue are skipped and left in the queue.
     * Hopefully next time there is enough space. */
    ULONG NumRequestPackets = 0;
    ULONG TotalSendSize = 0;
    LoopOverList(Irp, &DriverObject->IrpQueue, IO_REQUEST_PACKET, IrpLink) {
	TotalSendSize += sizeof(IO_REQUEST_PACKET);
	if ((Irp->Type == IrpTypeRequest) &&
	    ((Irp->Request.MajorFunction == IRP_MJ_CREATE) ||
	     (Irp->Request.MajorFunction == IRP_MJ_CREATE_MAILSLOT) ||
	     (Irp->Request.MajorFunction == IRP_MJ_CREATE_NAMED_PIPE))) {
	    PIO_FILE_OBJECT FileObject = Irp->Request.File.Object;
	    ULONG FileNameLength = strlen(FileObject->FileName);
	    TotalSendSize += FileNameLength + 1; /* Trailing '\0' */
	}
	if (TotalSendSize > DRIVER_IRP_BUFFER_COMMIT) {
	    /* TODO: Commit more memory in this case */
	    break;
	}
	/* Ok to send this one. */
	NumRequestPackets++;
    }

    /* Copy the current IRP queue to the driver's incoming IRP buffer. */
    PIO_REQUEST_PACKET Irp = CONTAINING_RECORD(DriverObject->IrpQueue.Flink,
					       IO_REQUEST_PACKET, IrpLink);
    PIO_REQUEST_PACKET IrpBuffer = (PIO_REQUEST_PACKET)DriverObject->IncomingIrpServerAddr;
    PCHAR StringBuffer = (PCHAR)(IrpBuffer + NumRequestPackets);
    for (ULONG i = 0; i < NumRequestPackets; i++, IrpBuffer++,
	     Irp = CONTAINING_RECORD(Irp->IrpLink.Flink, IO_REQUEST_PACKET, IrpLink)) {
	/* Copy this Irp to the driver's incoming IRP buffer */
	memcpy(IrpBuffer, Irp, sizeof(IO_REQUEST_PACKET));
	/* Massage the client-side copy of the IRP so all server pointers are
	 * replaced by the client-side GLOBAL_HANDLE */
	if (Irp->Type == IrpTypeRequest) {
	    assert(Irp->Request.Device.Object != NULL);
	    assert(Irp->Request.File.Object != NULL);
	    IrpBuffer->Request.Device.Handle = OBJECT_TO_GLOBAL_HANDLE(Irp->Request.Device.Object);
	    IrpBuffer->Request.File.Handle = OBJECT_TO_GLOBAL_HANDLE(Irp->Request.File.Object);
	    /* For IRPs involving the creation of file objects, we also pass FILE_OBJECT_CREATE_PARAMETERS
	     * so the client can record the file object information there */
	    if ((Irp->Request.MajorFunction == IRP_MJ_CREATE) ||
		(Irp->Request.MajorFunction == IRP_MJ_CREATE_MAILSLOT) ||
		(Irp->Request.MajorFunction == IRP_MJ_CREATE_NAMED_PIPE)) {
		PIO_FILE_OBJECT FileObject = Irp->Request.File.Object;
		ULONG FileNameLength = strlen(FileObject->FileName);
		/* Find the CLIENT pointer of the file name buffer */
		PCSTR FileName = (PCSTR)(DriverObject->IncomingIrpClientAddr + (MWORD)StringBuffer
					 - DriverObject->IncomingIrpServerAddr);
		memcpy(StringBuffer, FileObject->FileName, FileNameLength + 1);
		StringBuffer += FileNameLength + 1;
		FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters = {
		    .ReadAccess = FileObject->ReadAccess,
		    .WriteAccess = FileObject->WriteAccess,
		    .DeleteAccess = FileObject->DeleteAccess,
		    .SharedRead = FileObject->SharedRead,
		    .SharedWrite = FileObject->SharedWrite,
		    .SharedDelete = FileObject->SharedDelete,
		    .Flags = FileObject->Flags,
		    .FileName = FileName
		};
		/* IMPORTANT: FileObjectParameters must be the first member of the Create,
		 * CreateMailslot, and CreateNamedPipe struct. See wdmsvc.h */
		Irp->Request.Parameters.Create.FileObjectParameters = FileObjectParameters;
		IrpBuffer->Request.Parameters.Create.FileObjectParameters = FileObjectParameters;
	    }
	}
	if (Irp->ParentIrp.Object != NULL) {
	    IrpBuffer->ParentIrp.Handle = POINTER_TO_GLOBAL_HANDLE(Irp->ParentIrp.Object);
	}
	if (Irp->Thread.Object != NULL) {
	    IrpBuffer->Thread.Handle = OBJECT_TO_GLOBAL_HANDLE(Irp->Thread.Object);
	}
	IrpBuffer->ThisIrp = POINTER_TO_GLOBAL_HANDLE(Irp);
	IrpBuffer->ErrorStatus = STATUS_SUCCESS;
	/* Move this Irp from the driver's IRP queue to its pending IRP list */
	RemoveEntryList(&Irp->IrpLink);
	InsertTailList(&DriverObject->PendingIrpList, &Irp->IrpLink);
	/* Note this adds sizeof(IO_REQUEST_PACKET) to the actual address. */
	IrpBuffer++;
    }
    *pNumRequestPackets = NumRequestPackets;
    DriverObject->NumRequestPackets = NumRequestPackets;

    /* Returns APC status if the alertable wait above returned APC status */
    ASYNC_END(Status);
}
