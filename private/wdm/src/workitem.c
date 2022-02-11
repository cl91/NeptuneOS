#include <wdmp.h>
#include "coroutine.h"

LIST_ENTRY IopWorkItemQueue;
LIST_ENTRY IopSuspendedWorkItemList;

/*
 * @implemented
 */
NTAPI PIO_WORKITEM IoAllocateWorkItem(IN PDEVICE_OBJECT DeviceObject)
{
    PIO_WORKITEM IoWorkItem = ExAllocatePool(sizeof(IO_WORKITEM));
    if (IoWorkItem == NULL) {
	return NULL;
    }
    IoWorkItem->Type = IOP_TYPE_WORKITEM;
    IoWorkItem->Size = sizeof(IO_WORKITEM);
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

/*
 * Create the worker thread if necessary and queue the work item into the work queue.
 *
 * NOTE: The QueueType is ignored for now and every work item has the same priority.
 * The queue type was needed in Windows due to performance reasons since work items
 * are processed in system worker threads which are shared by system components and
 * device drivers. We process work items in the main event loop thread of the driver
 * process so we don't have that problem.
 */
NTAPI VOID IoQueueWorkItem(IN OUT PIO_WORKITEM IoWorkItem,
			   IN PIO_WORKITEM_ROUTINE WorkerRoutine,
			   IN WORK_QUEUE_TYPE QueueType,
			   IN OPTIONAL PVOID Context)
{
    assert(IoWorkItem != NULL);
    /* We want to make sure that all work items are dequeued before re-queuing them */
    assert(IoWorkItem->WorkerRoutine == NULL);
    IoWorkItem->WorkerRoutine = WorkerRoutine;
    IoWorkItem->Context = Context;
    IoWorkItem->ExtendedRoutine = FALSE;
    InsertTailList(&IopWorkItemQueue, &IoWorkItem->Link);
}

/*
 * This is the coroutine entry point for the workitem routines
 */
FASTCALL NTSTATUS IopCallWorkItemRoutine(IN PVOID Context) /* %ecx/%rcx */
{
    PIO_WORKITEM WorkItem = (PIO_WORKITEM)Context;
    assert(WorkItem != NULL);
    assert(WorkItem->Type == IOP_TYPE_WORKITEM);
    assert(WorkItem->Size == sizeof(IO_WORKITEM));
    if (WorkItem->ExtendedRoutine) {
	assert(WorkItem->WorkerRoutineEx != NULL);
	WorkItem->WorkerRoutineEx(WorkItem->DeviceObject,
				  WorkItem->Context, WorkItem);
    } else {
	assert(WorkItem->WorkerRoutine != NULL);
	WorkItem->WorkerRoutine(WorkItem->DeviceObject,
				WorkItem->Context);
    }
    return STATUS_SUCCESS;
}

VOID IopProcessWorkItemQueue()
{
    NTSTATUS Status = STATUS_NTOS_BUG;
    LoopOverList(WorkItem, &IopWorkItemQueue, IO_WORKITEM, Link) {
	IopCurrentObject = WorkItem;
	if (WorkItem->CoroutineStackTop == NULL) {
	    /* We are starting a new workitem. Find a coroutine stack. */
	    PVOID Stack = KiGetFirstAvailableCoroutineStack();
	    /* If KiGetFirstAvailableCoroutineStack returns NULL, it means that
	     * the system is out of memory. Simply stop processing and wait for
	     * memory to become available in the future. */
	    if (Stack == NULL) {
		return;
	    }
	    WorkItem->CoroutineStackTop = Stack;
	    /* Switch to the coroutine stack and call the dispatch routine */
	    DbgTrace("Switching to coroutine stack top %p for WorkItem routine %p\n",
		     Stack, WorkItem);
	    Status = KiStartCoroutine(Stack, IopCallWorkItemRoutine, WorkItem);
	} else {
	    /* We are resuming a suspended workitem. */
	    DbgTrace("Resuming coroutine stack top %p for workitem routine %p. Saved SP %p\n",
		     WorkItem->CoroutineStackTop, WorkItem,
		     KiGetCoroutineSavedSP(WorkItem->CoroutineStackTop));
	    Status = KiResumeCoroutine(WorkItem->CoroutineStackTop);
	}
	IopCurrentObject = NULL;
	RemoveEntryList(&WorkItem->Link);
	/* If the workitem routine is blocked on waiting for an object,
	 * suspend the coroutine and process the next workitem. */
	if (Status == STATUS_ASYNC_PENDING) {
	    DbgTrace("Suspending workitm routine %p, coroutine stack %p, saved SP %p\n",
		     WorkItem, WorkItem->CoroutineStackTop,
		     KiGetCoroutineSavedSP(WorkItem->CoroutineStackTop));
	    assert(KiGetCoroutineSavedSP(WorkItem->CoroutineStackTop) != NULL);
	    InsertTailList(&IopSuspendedWorkItemList, &WorkItem->Link);
	} else {
	    /* Otherwise, the workitem routine has completed. Release the
	     * coroutine stack. Note that we shouldn't delete the workitem
	     * object here since the driver is supposed to do that (the
	     * workitem object may be statically allocated). */
	    assert(Status != STATUS_PENDING);
	    assert(WorkItem->CoroutineStackTop != NULL);
	    KiReleaseCoroutineStack(WorkItem->CoroutineStackTop);
	}
    }
}
