#include <wdmp.h>
#include "coroutine.h"

/* The IO work item queue is protected by the IO work item mutex below. */
LIST_ENTRY IopWorkItemQueue;
KMUTEX IopWorkItemMutex;

/*
 * @implemented
 */
NTAPI PIO_WORKITEM IoAllocateWorkItem(IN PDEVICE_OBJECT DeviceObject)
{
    IopInitializeDpcThread();
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

/*
 * Insert the work item into the work queue.
 *
 * NOTE: The QueueType is ignored for now and every work item has the same priority.
 * The queue type was needed in Windows due to performance reasons since work items
 * are processed in system worker threads which are shared by system components and
 * device drivers. We process work items in the main event loop thread of the driver
 * process so we don't have that problem.
 *
 * This routine can be called at any IRQL (ie. in the main event loop thread, in the
 * DPC thread, and in an ISR thread).
 */
NTAPI VOID IoQueueWorkItem(IN OUT PIO_WORKITEM IoWorkItem,
			   IN PIO_WORKITEM_ROUTINE WorkerRoutine,
			   IN WORK_QUEUE_TYPE QueueType,
			   IN OPTIONAL PVOID Context)
{
    DbgTrace("Queuing workitem %p worker routine %p\n", IoWorkItem, WorkerRoutine);
    assert(IoWorkItem != NULL);
    KeAcquireMutex(&IopWorkItemMutex);
    if (IoWorkItem->Queued) {
	/* We want to make sure the same worker routine and context are used. */
	assert(IoWorkItem->WorkerRoutine == WorkerRoutine);
	assert(IoWorkItem->Context == Context);
	KeReleaseMutex(&IopWorkItemMutex);
	return;
    }
    IoWorkItem->WorkerRoutine = WorkerRoutine;
    IoWorkItem->Context = Context;
    IoWorkItem->ExtendedRoutine = FALSE;
    IoWorkItem->Queued = TRUE;
    InsertHeadList(&IopWorkItemQueue, &IoWorkItem->QueueEntry);
    KeReleaseMutex(&IopWorkItemMutex);
    NtCurrentTeb()->Wdm.IoWorkItemQueued = TRUE;
}

/*
 * This is the coroutine entry point for the workitem routines
 */
FASTCALL NTSTATUS IopCallWorkItemRoutine(IN PVOID Context) /* %ecx/%rcx */
{
    PIO_WORKITEM WorkItem = (PIO_WORKITEM)Context;
    assert(WorkItem != NULL);
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
    PLIST_ENTRY Entry;
    KeAcquireMutex(&IopWorkItemMutex);
    Entry = IopWorkItemQueue.Flink;

check:
    if (Entry == &IopWorkItemQueue) {
	KeReleaseMutex(&IopWorkItemMutex);
	goto done;
    }
    PIO_WORKITEM WorkItem = CONTAINING_RECORD(Entry, IO_WORKITEM, QueueEntry);
    WorkItem->Queued = FALSE;
    Entry = WorkItem->QueueEntry.Flink;
    RemoveEntryList(&WorkItem->QueueEntry);
    KeReleaseMutex(&IopWorkItemMutex);

    /* Allocate an execution environment for this IO work item. If we run out of
     * memory here, not much can be done, so we just stop. */
    PIOP_EXEC_ENV Env = ExAllocatePool(sizeof(IOP_EXEC_ENV));
    if (!Env) {
	goto done;
    }
    /* Initialize the execution environment and add it to the list */
    Env->Context = WorkItem;
    Env->EntryPoint = IopCallWorkItemRoutine;
    InsertTailList(&IopExecEnvList, &Env->Link);

    KeAcquireMutex(&IopWorkItemMutex);
    goto check;
done:
    return;
}

VOID IopDbgDumpWorkItem(IN PIO_WORKITEM WorkItem)
{
    DbgTrace("Dumping workitem %p\n", WorkItem);
    if (WorkItem != NULL) {
	DbgPrint("    Device object %p(%p) WorkerRoutine %p ExtendedRoutine %s\n",
		 WorkItem->DeviceObject, (PVOID)IopGetDeviceHandle(WorkItem->DeviceObject),
		 WorkItem->WorkerRoutine,
		 WorkItem->ExtendedRoutine ? "TRUE" : "FALSE");
    } else {
	DbgPrint("    (nil)\n");
    }
}
