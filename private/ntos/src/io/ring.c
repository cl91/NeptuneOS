#include "iop.h"

typedef struct _IO_RING_OBJECT {
    PIO_FILE_OBJECT FileObject;
    PPROCESS ClientProcess;
    LIST_ENTRY ClientLink;
    PIO_DRIVER_OBJECT DriverObject;
    LIST_ENTRY DriverLink;
    PSECTION SubmissionQueue;
    SIZE_T SubmissionQueueSize;
    LIST_ENTRY SubmissionSectionLink;
    PSECTION CompletionQueue;
    SIZE_T CompletionQueueSize;
    LIST_ENTRY CompletionSectionLink;
    NOTIFICATION ClientSubmissionNotification; /* In the client's CSpace (shared or
						* private). Client signals this so driver
						* can check the submission queue. This can
						* be either derived from the event loop
						* notification of the driver, or from a
						* dedicated notification cap supplied by
						* the driver. This cap can be NULL. Note
						* it is fine for the client thread to get
						* deleted before this notification cap is
						* deleted, because the thread CNode is
						* deleted lazily. Also note that since we
						* increase the driver object's refcount
						* when creating the IO ring object, we are
						* always guaranteed that the driver's event
						* loop notification is deleted AFTER this
						* notification is deleted. */
    MWORD DriverCompletionNotificationCap; /* In the driver's process shared CNode.
					    * Driver signals this to notify client
					    * to check the completion queue. This
					    * is derived from the client completion
					    * notification with the specified badge.
					    * This cap can be NUL. Note in the case
					    * of the client crashing, the lazy deletion
					    * of EX_NOTIFICATION will make sure the
					    * parent (ie. the client completion) cap
					    * is deleted AFTER this cap is deleted. */
    ULONG_PTR DriverIdentifier;	/* Unique (per driver) identifier supplied by the
				 * driver to identify this IO ring. */
} IO_RING_OBJECT, *PIO_RING_OBJECT;

typedef struct _IO_RING_OBJ_CREATE_CONTEXT {
    PIO_FILE_OBJECT FileObject;
    PPROCESS ClientProcess;
    PIO_DRIVER_OBJECT DriverObject;
    PSECTION SubmissionQueue;
    SIZE_T SubmissionQueueSize;
    PSECTION CompletionQueue;
    SIZE_T CompletionQueueSize;
    MWORD OriginalSubmissionNotificationCap; /* In driver's CSpace. Can be NUL. */
    MWORD SubmissionNotificationBadge;
    MWORD DriverCompletionNotificationCap;
    ULONG_PTR DriverIdentifier;
} IO_RING_OBJ_CREATE_CONTEXT, *PIO_RING_OBJ_CREATE_CONTEXT;

static NTSTATUS IopIoRingObjectCreateProc(IN POBJECT Object,
					  IN PVOID CreaCtx)
{
    assert(CreaCtx);
    PIO_RING_OBJECT IoRing = Object;
    PIO_RING_OBJ_CREATE_CONTEXT Ctx = CreaCtx;
    assert(Ctx->FileObject);
    IoRing->FileObject = Ctx->FileObject;
    ObReferenceObjectByPointer(Ctx->FileObject);
}

static NTSTATUS IopIoRingObjectCloseProc(IN ASYNC_STATE State,
					 IN PTHREAD Thread,
					 IN POBJECT Self)
{
    /* Send the IRP_MN_DELETE_IO_RING IRP to the driver object and wait for it
     * to clean up the local bookkeeping of the io ring. In particular, the
     * driver needs to stop signaling the completion notification as it will soon
     * be deleted. */
}

static VOID IopDbgDumpIoRingObject(IN PIO_RING_OBJECT IoRing,
				   IN ULONG Indentation)
{
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Dumping io ring object %p\n", IoRing);
    if (IoRing == NULL) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("  (nil)\n");
	return;
    }
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  ClientProcess = %p (%s)\n", IoRing->ClientProcess,
	     KEDBG_PROCESS_TO_FILENAME(IoRing->ClientProcess));
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  DriverObject = %p (%s)\n", IoRing->DriverObject,
	     IODBG_DRIVER_FILENAME(IoRing->DriverObject));
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  SubmissionQueue = %p, Size = 0x%zx\n", IoRing->SubmissionQueue,
	     IoRing->SubmissionQueueSize);
    if (IoRing->SubmissionQueue) {
	MmDbgDumpSection(IoRing->SubmissionQueue);
    }
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  CompletionQueue = %p, Size = 0x%zx\n", IoRing->CompletionQueue,
	     IoRing->CompletionQueueSize);
    if (IoRing->CompletionQueue) {
	MmDbgDumpSection(IoRing->CompletionQueue);
    }
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  ClientSubmissionNotificationCap = 0x%zx\n",
	     IoRing->ClientSubmissionNotification.TreeNode.Cap);
    MmDbgDumpCapTreeNode(&IoRing->ClientSubmissionNotification.TreeNode);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  CompletionNotification = %p\n", IoRing->CompletionNotification);
    if (IoRing->CompletionNotification) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("  CompletionNotificationCap = 0x%zx\n",
		 IoRing->CompletionNotification->Notification.TreeNode.Cap);
	MmDbgDumpCapTreeNode(&IoRing->CompletionNotification->Notification.TreeNode);
    }
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  DriverCompletionNotificationCap = 0x%zx\n",
	     IoRing->DriverCompletionNotification.TreeNode.Cap);
    MmDbgDumpCapTreeNode(&IoRing->DriverCompletionNotification.TreeNode);
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("  FileObject = %p\n", IoRing->FileObject);
    if (IoRing->FileObject) {
	IoDbgDumpFileObject(IoRing->FileObject, Indentation + 2);
    }
}

static VOID IopIoRingObjectDeleteProc(IN POBJECT Self)
{
    PIO_RING_OBJECT IoRingObj = Self;
    DbgTrace("Releasing io ring object %p from memory\n", IoRingObj);
    IopDbgDumpIoRingObject(IoRingObj, 0);
}

NTSTATUS IopCreateIoRingType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = IopIoRingObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = NULL,
	.CloseProc = IopIoRingObjectCloseProc,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.QueryNameProc = NULL,
	.DeleteProc = IopIoRingObjectDeleteProc
    };
    return ObCreateObjectType(OBJECT_TYPE_IO_RING,
			      "IoRing",
			      sizeof(IO_RING_OBJECT),
			      TypeInfo);
}

NTSTATUS NtCreateIoRing(IN ASYNC_STATE State,
                        IN PTHREAD Thread,
                        OUT HANDLE *IoRingHandle,
                        IN HANDLE FileHandle,
                        IN HANDLE SubmissionQueueHandle,
                        IN SIZE_T SubmissionQueueSize,
                        OUT OPTIONAL LOCAL_HANDLE *SubmissionNotification,
			IN BOOLEAN SubmissionNotificationIsThreadPrivate,
                        OUT HANDLE *CompletionQueueHandle,
                        OUT SIZE_T *CompletionQueueSize,
                        IN OPTIONAL LOCAL_HANDLE *CompletionNotification,
                        IN ULONG_PTR CompletionNotificationBadge,
			IN PIO_APC_ROUTINE ApcRoutine,
			IN PVOID ApcContext)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State, Locals, {
	    PIO_FILE_OBJECT FileObject;
	    PIO_DRIVER_OBJECT DriverObject;
	    PSECTION SubmissionQueueSection;
	    PSECTION CompletionQueueSection;
	    PIO_REQUEST_PARAMETERS Irp;
	    PPENDING_IRP PendingIrp;
	    PIO_RING_OBJECT IoRingObject;
	});

    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByHandle(Thread, FileHandle, OBJECT_TYPE_FILE,
					  (POBJECT *)&Locals.FileObject));
    assert(Locals.FileObject != NULL);
    if (!Locals.FileObject->DeviceObject) {
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto out;
    }
    assert(Locals.FileObject->DeviceObject->DriverObject);
    ObReferenceObjectByPointer(Locals.FileObject->DeviceObject->DriverObject);

    Locals.Irp = ExAllocatePoolWithTag(sizeof(IO_REQUEST_PARAMETERS), NTOS_IO_TAG);
    if (!Locals.Irp) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    Locals.Irp->MajorFunction = IRP_MJ_IO_RING;
    Locals.Irp->MinorFunction = IRP_MN_CREATE_IO_RING;
    Locals.Irp->Device.Object = Locals.FileObject->DeviceObject;
    Locals.Irp->File.Object = Locals.FileObject->Fcb ?
	Locals.FileObject->Fcb->MasterFileObject : Locals.FileObject;
    Locals.Irp->CreateIoRing.
    IF_ERR_GOTO(out, Status, IopCallDriver(Thread, Locals.Irp, &Locals.PendingIrp));


    IO_RING_OBJ_CREATE_CONTEXT CreaCtx = {
    };
    IF_ERR_GOTO(out, Status, ObCreateObject(OBJECT_TYPE_IO_RING,
					    (POBJECT *)&Locals.IoRingObject, &CreaCtx));
    IF_ERR_GOTO(out, Status, ObCreateHandle(Thread->Process, Locals.IoRingObject, TRUE,
					    IoRingHandle, NULL));

out:
    if (Locals.FileObject) {
	ObDereferenceObject(Locals.FileObject);
    }
    if (Locals.DriverObject) {
	ObDereferenceObject(Locals.DriverObject);
    }
    if (!NT_SUCCESS(Status) && Locals.IoRingObject) {
	ObDereferenceObject(Locals.IoRingObject);
    }
    ASYNC_END(State, Status);
}

NTSTATUS NtRegisterBuffersForIoRing(IN ASYNC_STATE AsyncState,
                                    IN PTHREAD Thread,
                                    IN HANDLE IoRingHandle,
                                    IN PPVOID Buffers,
                                    IN ULONG BufferCount,
                                    IN ULONG Flags)
{
    UNIMPLEMENTED;
}
