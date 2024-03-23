#include <wdmp.h>

LIST_ENTRY IopDpcQueue;
KMUTEX IopDpcMutex;

VOID IopProcessDpcQueue()
{
    PLIST_ENTRY Entry;
    PKDPC Dpc;
    KeAcquireMutex(&IopDpcMutex);
    Entry = IopDpcQueue.Flink;
Next:
    if (Entry == &IopDpcQueue) {
	KeReleaseMutex(&IopDpcMutex);
	return;
    }
    Dpc = CONTAINING_RECORD(Entry, KDPC, Entry);
    assert(Dpc->Queued);
    KeReleaseMutex(&IopDpcMutex);

    if (Dpc->DeferredRoutine != NULL) {
	Dpc->DeferredRoutine(Dpc,
			     Dpc->DeferredContext,
			     Dpc->SystemArgument1,
			     Dpc->SystemArgument1);
    }

    KeAcquireMutex(&IopDpcMutex);
    Entry = Entry->Flink;
    Dpc->Queued = FALSE;
    RemoveEntryList(&Dpc->Entry);
    goto Next;
}

/*
 * As is in Windows/ReactOS you cannot queue DPC objects multiple
 * times. This routine returns false if the DPC object has already
 * been queued.
 */
NTAPI BOOLEAN KeInsertQueueDpc(IN PKDPC Dpc,
			       IN PVOID SystemArgument1,
			       IN PVOID SystemArgument2)
{
    BOOLEAN Queued = FALSE;
    KeAcquireMutex(&IopDpcMutex);
    if (!Dpc->Queued) {
	DbgTrace("Inserting DPC %p args %p %p\n",
		 Dpc, SystemArgument1, SystemArgument2);
	Dpc->SystemArgument1 = SystemArgument1;
	Dpc->SystemArgument2 = SystemArgument2;
	InsertTailList(&IopDpcQueue, &Dpc->Entry);
	Dpc->Queued = TRUE;
	Queued = TRUE;
    } else {
	DbgTrace("DPC %p already inserted. Not inserting\n", Dpc);
    }
    KeReleaseMutex(&IopDpcMutex);
    return Queued;
}

static NTAPI ULONG IopInterruptServiceThreadEntry(PVOID Context)
{
    PKINTERRUPT Interrupt = (PKINTERRUPT)Context;
    __sel4_ipc_buffer = Interrupt->ThreadIpcBuffer;
    KiWdmServiceCap = Interrupt->WdmServiceCap;
    assert(Interrupt->ServiceRoutine != NULL);
    while (TRUE) {
	int AckError = seL4_IRQHandler_Ack(Interrupt->IrqHandlerCap);
	if (AckError != 0) {
	    DbgTrace("Failed to ACK IRQ handler cap %zd for vector %d. Error:",
		     Interrupt->IrqHandlerCap, Interrupt->Vector);
	    KeDbgDumpIPCError(AckError);
	}
	seL4_Wait(Interrupt->NotificationCap, NULL);
	IoAcquireInterruptMutex(Interrupt);
	Interrupt->ServiceRoutine(Interrupt, Interrupt->ServiceContext);
	IoReleaseInterruptMutex(Interrupt);
	/* Signal the main thread to check for DPC queue and IO work item queue */
	WdmNotifyMainThread();
    }
    return 0;
}

static inline NTSTATUS PspResumeThread(IN MWORD ThreadCap)
{
    assert(ThreadCap != 0);
    int Error = seL4_TCB_Resume(ThreadCap);

    if (Error != 0) {
	DbgTrace("seL4_TCB_Resume failed for thread cap 0x%zx with error %d\n",
		 ThreadCap, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS KiConnectIrqNotification(IN MWORD IrqHandlerCap,
					 IN MWORD NotificationCap)
{
    assert(IrqHandlerCap != 0);
    assert(NotificationCap != 0);
    int Error = seL4_IRQHandler_SetNotification(IrqHandlerCap,
						NotificationCap);
    if (Error != 0) {
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
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
    IopAllocateObject(InterruptObject, KINTERRUPT);
    InterruptObject->ServiceRoutine = ServiceRoutine;
    InterruptObject->ServiceContext = ServiceContext;
    InterruptObject->Vector = Vector;
    InterruptObject->Irql = Irql;
    InterruptObject->SynchronizeIrql = SynchronizeIrql;
    InterruptObject->InterruptMode = InterruptMode;

    MWORD MutexCap = 0;
    RET_ERR(WdmConnectInterrupt(Vector,
				ShareVector,
				IopInterruptServiceThreadEntry,
				InterruptObject,
				&InterruptObject->WdmServiceCap,
				&InterruptObject->ThreadCap,
				&InterruptObject->ThreadIpcBuffer,
				&InterruptObject->IrqHandlerCap,
				&InterruptObject->NotificationCap,
				&MutexCap));
    assert(InterruptObject->ThreadCap != 0);
    assert(InterruptObject->ThreadIpcBuffer != 0);
    assert(InterruptObject->IrqHandlerCap != 0);
    assert(InterruptObject->NotificationCap != 0);
    assert(MutexCap != 0);
    KeInitializeMutex(&InterruptObject->Mutex, MutexCap);

    DbgTrace("Created interrupt object %p ThreadCap %zd IpcBuffer %p "
	     "IrqHandler %zd Notification %zd Mutex %zd\n",
	     InterruptObject, InterruptObject->ThreadCap,
	     InterruptObject->ThreadIpcBuffer,
	     InterruptObject->IrqHandlerCap,
	     InterruptObject->NotificationCap,
	     InterruptObject->Mutex.Notification);
    RET_ERR_EX(KiConnectIrqNotification(InterruptObject->IrqHandlerCap,
					InterruptObject->NotificationCap),
	       IoDisconnectInterrupt(InterruptObject));
    RET_ERR_EX(PspResumeThread(InterruptObject->ThreadCap),
	       IoDisconnectInterrupt(InterruptObject));
    *pInterruptObject = InterruptObject;
    return STATUS_SUCCESS;
}

NTAPI VOID IoDisconnectInterrupt(IN PKINTERRUPT InterruptObject)
{
}

NTAPI VOID IoAcquireInterruptMutex(IN PKINTERRUPT Interrupt)
{
    KeAcquireMutex(&Interrupt->Mutex);
}

NTAPI VOID IoReleaseInterruptMutex(IN PKINTERRUPT Interrupt)
{
    KeReleaseMutex(&Interrupt->Mutex);
}
