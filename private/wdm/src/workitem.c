#include <wdmp.h>

DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER IopWorkItemQueue;
static HANDLE IopWorkerThreadHandle;
static MWORD IopWorkerThreadNotification;

/*
 * @implemented
 */
NTAPI PIO_WORKITEM IoAllocateWorkItem(IN PDEVICE_OBJECT DeviceObject)
{
    PIO_WORKITEM IoWorkItem = ExAllocatePool(sizeof(IO_WORKITEM));
    if (IoWorkItem == NULL) {
	return NULL;
    }
    IoWorkItem->DeviceObject = DeviceObject;
    return IoWorkItem;
}

/*
 * @implemented
 */
NTAPI VOID IoFreeWorkItem(IN PIO_WORKITEM IoWorkItem)
{
    ExFreePool(IoWorkItem);
}

static VOID IopWorkerThreadEntry()
{
}

/*
 * Create the worker thread if necessary and queue the work item into the work queue.
 *
 * NOTE: The QueueType is ignored for now and every work item has the same priority.
 * The queue type was needed in Windows due to performance reasons since work items
 * are processed in system worker threads which are shared by system components and
 * device drivers. We process work item in dedicated driver threads so we may never
 * need to implement more than one work queue.
 */
NTAPI VOID IoQueueWorkItem(IN OUT PIO_WORKITEM IoWorkItem,
			   IN PIO_WORKITEM_ROUTINE WorkerRoutine,
			   IN WORK_QUEUE_TYPE QueueType,
			   IN OPTIONAL PVOID Context)
{
    assert(IoWorkItem != NULL);
    if (IopWorkerThreadHandle == NULL) {
	NTSTATUS Status = IopCreateWorkerThread(IopWorkerThreadEntry,
						&IopWorkerThreadHandle,
						&IopWorkerThreadNotification);
	if (!NT_SUCCESS(Status)) {
	    RtlRaiseStatus(Status);
	}
    }
    /* We want to make sure that all work items are dequeued before re-queuing them */
    assert(IoWorkItem->WorkerRoutine == NULL);
    IoWorkItem->WorkerRoutine = WorkerRoutine;
    IoWorkItem->Context = Context;
    IoWorkItem->ExtendedRoutine = FALSE;
    RtlInterlockedPushEntrySList(&IopWorkItemQueue, &IoWorkItem->Entry);
    /* Notify the worker thread of new work item */
    assert(IopWorkerThreadNotification != 0);
    seL4_Signal(IopWorkerThreadNotification);
}
