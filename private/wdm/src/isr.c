#include <wdmp.h>

DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER IopDpcQueue;
DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER IopInterruptServiceRoutineList;

/* For now all interrupt service routines run in the same thread.
 * Eventually we will have different threads for different IRQL.
 */
static HANDLE IopInterruptServiceThreadHandle;
static MWORD IopInterruptServiceNotification;
static MWORD IopInterruptServiceMutex;

static NTAPI ULONG IopInterruptServiceThreadEntry(PVOID NotificationCap)
{
    DbgTrace("NotificationCap is %p\n", NotificationCap);
    while (TRUE) ;
    return 0;
}

NTAPI NTSTATUS IoConnectInterrupt(OUT PKINTERRUPT *pInterruptObject,
				  IN PKSERVICE_ROUTINE ServiceRoutine,
				  IN OPTIONAL PVOID ServiceContext,
				  IN ULONG Vector,
				  IN KIRQL Irql,
				  IN KIRQL SynchronizeIrql,
				  IN KINTERRUPT_MODE InterruptMode,
				  IN BOOLEAN ShareVector,
				  IN KAFFINITY ProcessorEnableMask,
				  IN BOOLEAN FloatingSave)
{
    assert(pInterruptObject);
    if (IopInterruptServiceThreadHandle == NULL) {
	RET_ERR(IopCreateInterruptServiceThread(IopInterruptServiceThreadEntry,
						&IopInterruptServiceThreadHandle,
						&IopInterruptServiceNotification,
						&IopInterruptServiceMutex));
    }
    assert(IopInterruptServiceThreadHandle != NULL);
    assert(IopInterruptServiceNotification != 0);
    assert(IopInterruptServiceMutex != 0);
    IopAllocateObject(InterruptObject, KINTERRUPT);
    InterruptObject->ServiceRoutine = ServiceRoutine;
    InterruptObject->ServiceContext = ServiceContext;
    InterruptObject->Vector = Vector;
    InterruptObject->Irql = Irql;
    InterruptObject->SynchronizeIrql = SynchronizeIrql;
    InterruptObject->InterruptMode = InterruptMode;
    RtlInterlockedPushEntrySList(&IopInterruptServiceRoutineList,
				 &InterruptObject->Entry);
    *pInterruptObject = InterruptObject;
    return STATUS_SUCCESS;
}

NTAPI VOID IoDisconnectInterrupt(IN PKINTERRUPT InterruptObject)
{
}

/*
 * As opposed to Windows/ReactOS we allow DPC objects to be queued
 * multiple times because it can be safely done. This can simplify
 * driver ISR code.
 */
NTAPI BOOLEAN KeInsertQueueDpc(IN PKDPC Dpc,
			       IN PVOID SystemArgument1,
			       IN PVOID SystemArgument2)
{
    Dpc->SystemArgument1 = SystemArgument1;
    Dpc->SystemArgument2 = SystemArgument2;
    RtlInterlockedPushEntrySList(&IopDpcQueue, &Dpc->Entry);
    return TRUE;
}

NTAPI VOID IoAcquireInterruptMutex(IN PKINTERRUPT Interrupt)
{
    KeAcquireMutex(&Interrupt->Mutex);
}

NTAPI VOID IoReleaseInterruptMutex(IN PKINTERRUPT Interrupt)
{
    KeReleaseMutex(&Interrupt->Mutex);
}
