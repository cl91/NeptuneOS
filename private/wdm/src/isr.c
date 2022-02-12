#include <wdmp.h>

DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER IopDpcQueue;

static NTAPI ULONG IopInterruptServiceThreadEntry(PVOID Context)
{
    PKINTERRUPT Interrupt = (PKINTERRUPT)Context;
    __sel4_ipc_buffer = Interrupt->ThreadIpcBuffer;
    assert(Interrupt->ServiceRoutine != NULL);
    while (TRUE) {
	int AckError = seL4_IRQHandler_Ack(Interrupt->IrqHandlerCap);
	if (AckError != 0) {
	    DbgTrace("Failed to ACK IRQ handler cap %d for vector %d. Error:",
		     Interrupt->IrqHandlerCap, Interrupt->Vector);
	    KeDbgDumpIPCError(AckError);
	}
	seL4_Wait(Interrupt->NotificationCap, NULL);
	Interrupt->ServiceRoutine(Interrupt, Interrupt->ServiceContext);
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
    RET_ERR(IopConnectInterrupt(Vector,
				ShareVector,
				IopInterruptServiceThreadEntry,
				InterruptObject,
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

    DbgTrace("Created interrupt object %p ThreadCap %d IpcBuffer %p "
	     "IrqHandler %d Notification %d Mutex %d\n",
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
