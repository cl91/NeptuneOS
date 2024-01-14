#pragma once

#include "iop.h"

#define IO_SERVICE_PROLOGUE(State, Locals, FileObject,			\
			    EventObject, IoPacket, PendingIrp)		\
    assert(Thread != NULL);						\
    assert(Thread->Process != NULL);					\
    NTSTATUS Status = STATUS_NTOS_BUG;					\
									\
    ASYNC_BEGIN(State, Locals, {					\
	    PIO_FILE_OBJECT FileObject;					\
	    PEVENT_OBJECT EventObject;					\
	    PIO_PACKET IoPacket;					\
	    PPENDING_IRP PendingIrp;					\
	});								\
									\
    if (FileHandle == NULL) {						\
	ASYNC_RETURN(State, STATUS_INVALID_HANDLE);			\
    }									\
    IF_ERR_GOTO(out, Status,						\
		ObReferenceObjectByHandle(				\
		    Thread->Process,					\
		    FileHandle,						\
		    OBJECT_TYPE_FILE,					\
		    (POBJECT *)&Locals.FileObject));			\
    assert(Locals.FileObject != NULL);					\
    assert(Locals.FileObject->DeviceObject != NULL);			\
    assert(Locals.FileObject->DeviceObject->DriverObject != NULL);	\
									\
    if (EventHandle != NULL) {						\
	IF_ERR_GOTO(out, Status,					\
		    ObReferenceObjectByHandle(				\
			Thread->Process,				\
			EventHandle,					\
			OBJECT_TYPE_EVENT,				\
			(POBJECT *)&Locals.EventObject));		\
	assert(Locals.EventObject != NULL);				\
    }									\
									\
    IF_ERR_GOTO(out, Status,						\
		IopAllocateIoPacket(IoPacketTypeRequest,		\
				    sizeof(IO_PACKET),			\
				    &Locals.IoPacket));			\
    assert(Locals.IoPacket != NULL);					\
    Locals.IoPacket->Request.Device.Object =				\
	Locals.FileObject->DeviceObject;				\
    Locals.IoPacket->Request.File.Object = Locals.FileObject

#define IO_SERVICE_EPILOGUE(out, Status, Locals, FileObject,		\
			    EventObject, IoPacket, PendingIrp,		\
			    IoStatusBlock)				\
    IF_ERR_GOTO(out, Status,						\
		IopAllocatePendingIrp(Locals.IoPacket, Thread,		\
				      &Locals.PendingIrp));		\
    /* Note here the IO buffers in the driver address space are freed	\
     * when the server receives the IoCompleted message, so we don't	\
     * need to free them manually. */					\
    Status = IopMapIoBuffers(Locals.PendingIrp, FALSE);			\
    if (NT_SUCCESS(Status)) {						\
	IopQueueIoPacket(Locals.PendingIrp, Thread);			\
    } else {								\
	IopFreePool(Locals.PendingIrp);					\
	Locals.PendingIrp = NULL;					\
	goto out;							\
    }									\
									\
    /* For now every IO is synchronous. For async IO, we need to figure	\
     * out how we pass IO_STATUS_BLOCK back to the userspace safely.	\
     * The idea is to pass it via APC. When NtWaitForSingleObject	\
     * returns from the wait the special APC runs and write to the	\
     * IO_STATUS_BLOCK. We have reserved the APC_TYPE_IO for this. */	\
									\
    AWAIT(KeWaitForSingleObject, State,					\
	  Locals, Thread,						\
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);	\
									\
    /* This is the starting point when the function is resumed. */	\
    if (IoStatusBlock != NULL) {					\
	*IoStatusBlock = Locals.PendingIrp->IoResponseStatus;		\
    }									\
    Status = Locals.PendingIrp->IoResponseStatus.Status

#define IO_SERVICE_CLEANUP(Status, Locals, FileObject,			\
			   EventObject, IoPacket, PendingIrp)		\
    /* The IO request has returned a error status. Clean up the		\
       file object. */							\
    if (!NT_SUCCESS(Status) && Locals.FileObject != NULL) {		\
	ObDereferenceObject(Locals.FileObject);				\
    }									\
    if (!NT_SUCCESS(Status) && Locals.EventObject != NULL) {		\
	ObDereferenceObject(Locals.EventObject);			\
    }									\
    if (Locals.PendingIrp == NULL & Locals.IoPacket != NULL) {		\
	IopFreePool(Locals.IoPacket);					\
    }									\
    /* This will free the pending IRP and detach the pending irp	\
     * from the thread. At this point the IRP has already been		\
     * detached from the driver object, so we do not need to remove	\
     * it from the driver IRP queue here. */				\
    if (Locals.PendingIrp != NULL) {					\
	IopCleanupPendingIrp(Locals.PendingIrp);			\
    }									\
    ASYNC_END(State, Status)
