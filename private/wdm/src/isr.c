#include <wdmp.h>

/* The DPC queue is protected by the DPC mutex. */
LIST_ENTRY IopDpcQueue;

static ULONG_PTR IopDpcNotificationCap;
static ULONG_PTR IopDpcThreadWdmServiceCap;
static HANDLE IopDpcThreadHandle;
/* Protects the pending timer list and signaled object list. */
KMUTEX IopDpcMutex;

VOID IopAcquireDpcMutex()
{
    KeAcquireMutex(&IopDpcMutex);
}

VOID IopReleaseDpcMutex()
{
    KeReleaseMutex(&IopDpcMutex);
}

static VOID IopProcessDpcQueue()
{
    PTEB Teb = NtCurrentTeb();
    Teb->Wdm.ServiceCap = IopDpcThreadWdmServiceCap;
    Teb->Wdm.IsDpcThread = TRUE;
    PLIST_ENTRY Entry;
    while (TRUE) {
	MWORD Badge = 0;
	seL4_Wait(RtlGetGuardedCapInProcessCNode(IopDpcNotificationCap), &Badge);
	IopAcquireDpcMutex();
	Entry = IopDpcQueue.Flink;
    check:
	if (Entry == &IopDpcQueue) {
	    IopReleaseDpcMutex();
	    goto done;
	}
	PKDPC Dpc = CONTAINING_RECORD(Entry, KDPC, QueueEntry);
	assert(Dpc->Queued);
	Dpc->Queued = FALSE;
	Entry = Dpc->QueueEntry.Flink;
	RemoveEntryList(&Dpc->QueueEntry);
	IopReleaseDpcMutex();
	if (Dpc->DeferredRoutine != NULL) {
	    Dpc->DeferredRoutine(Dpc,
				 Dpc->DeferredContext,
				 Dpc->SystemArgument1,
				 Dpc->SystemArgument1);
	}
	IopAcquireDpcMutex();
	goto check;
    done:
	if (Badge & TIMER_NOTIFICATION_BADGE) {
	    IopProcessTimerList();
	}
	WdmNotifyMainThread();
    }
}

VOID IopSignalDpcNotification()
{
    PTEB Teb = NtCurrentTeb();
    if ((Teb->Wdm.DpcQueued || Teb->Wdm.IoWorkItemQueued || Teb->Wdm.EventSignaled) &&
	IopDpcNotificationCap) {
	assert(PsCapIsProcessShared(IopDpcNotificationCap));
	Teb->Wdm.DpcQueued = FALSE;
	Teb->Wdm.IoWorkItemQueued = FALSE;
	Teb->Wdm.EventSignaled = FALSE;
	seL4_Signal(RtlGetGuardedCapInProcessCNode(IopDpcNotificationCap));
    }
}

VOID IopInitializeDpcThread()
{
    if (!IopDpcNotificationCap) {
	PAGED_CODE();
	NTSTATUS Status = WdmCreateDpcThread(IopProcessDpcQueue,
					     &IopDpcThreadHandle,
					     &IopDpcThreadWdmServiceCap,
					     &IopDpcNotificationCap);
	if (!NT_SUCCESS(Status)) {
	    RtlRaiseStatus(Status);
	    return;
	}
	assert(IopDpcNotificationCap);
	assert(PsCapIsProcessShared(IopDpcNotificationCap));
	assert(IopDpcThreadHandle);
	Status = NtResumeThread(IopDpcThreadHandle, NULL);
	if (!NT_SUCCESS(Status)) {
	    RtlRaiseStatus(Status);
	    return;
	}
    }
}

/*
 * DPC initialization function
 */
NTAPI VOID KeInitializeDpc(IN PKDPC Dpc,
			   IN PKDEFERRED_ROUTINE DeferredRoutine,
			   IN PVOID DeferredContext)
{
    IopInitializeDpcThread();
    Dpc->DeferredRoutine = DeferredRoutine;
    Dpc->DeferredContext = DeferredContext;
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
    IopAcquireDpcMutex();
    if (!Dpc->Queued) {
	DbgTrace("Inserting DPC %p args %p %p\n",
		 Dpc, SystemArgument1, SystemArgument2);
	Dpc->SystemArgument1 = SystemArgument1;
	Dpc->SystemArgument2 = SystemArgument2;
	InsertHeadList(&IopDpcQueue, &Dpc->QueueEntry);
	Dpc->Queued = TRUE;
	Queued = TRUE;
	NtCurrentTeb()->Wdm.DpcQueued = TRUE;
    } else {
	DbgTrace("DPC %p already inserted. Not inserting\n", Dpc);
    }
    IopReleaseDpcMutex();
    return Queued;
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

static NTAPI ULONG IopInterruptServiceThreadEntry(PVOID Context)
{
    NtCurrentTeb()->Wdm.IsIsrThread = TRUE;
    PKINTERRUPT Interrupt = (PKINTERRUPT)Context;
    assert(Interrupt->ServiceRoutine != NULL);

    NTSTATUS Status = KiConnectIrqNotification(Interrupt->IrqHandlerCap,
					       Interrupt->NotificationCap);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
	return Status;
    }
    seL4_IRQHandler_Ack(Interrupt->IrqHandlerCap);

    while (TRUE) {
	seL4_Wait(Interrupt->NotificationCap, NULL);
	int AckError = seL4_IRQHandler_Ack(Interrupt->IrqHandlerCap);
	if (AckError != 0) {
	    DbgTrace("Failed to ACK IRQ handler cap %zd for vector %d. Error:",
		     Interrupt->IrqHandlerCap, Interrupt->Vector);
	    KeDbgDumpIPCError(AckError);
	}
	IoAcquireInterruptMutex(Interrupt);
	Interrupt->ServiceRoutine(Interrupt, Interrupt->ServiceContext);
	IoReleaseInterruptMutex(Interrupt);
	/* Signal the DPC thread to check for the DPC queue */
	IopSignalDpcNotification();
    }
    return 0;
}

/*
 * ROUTINE DESCRIPTION:
 *     Connect the specified interrupt service routine to the  given
 *     interrupt vector.
 *
 * ARGUMENTS:
 *     pInterruptObject - A pointer to the PKINTERRUPT object to be connected.
 *     ServiceRoutine   - Interrupt service routine
 *     ServiceContext   - Optional context for the interrupt service routine
 *     Vector           - The CPU interrupt vector to connect to. Caller should
 *                        set this to the Vector member of the translated
 *                        interrupt resource supplied by the PnP manager.
 *
 * The following arguments are ignored and are kept for compatibility reason.
 *
 *     Irql                - Device IRQ level.
 *     SynchronizeIrql     - Synchronization IRQ level.
 *     InterruptMode       - Whether the interrupt is LevelSensitive or Latched.
 *     ShareVector         - Whether the device allows the interrupt to be shared.
 *     ProcessorEnableMask - Specifies the process affinity of the ISR.
 *     FloatingSave        - Whether the floating point states should be saved
 *                           for the ISR.
 *
 * RETURNS:
 *     STATUS_SUCCESS is the interrupt has been connected successfully. Error
 *     status if otherwise.
 *
 * REMARKS:
 *     When porting from ReactOS/Windows, remove the Spinlock argument.
 *     This routine must be called at PASSIVE_LEVEL.
 */
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
    PAGED_CODE();
    assert(pInterruptObject);
    IopAllocateObject(InterruptObject, KINTERRUPT);
    InterruptObject->ServiceRoutine = ServiceRoutine;
    InterruptObject->ServiceContext = ServiceContext;
    InterruptObject->Vector = Vector;

    MWORD MutexCap = 0;
    RET_ERR(WdmConnectInterrupt(Vector,
				IopInterruptServiceThreadEntry,
				InterruptObject,
				&InterruptObject->ThreadHandle,
				&InterruptObject->IrqHandlerCap,
				&InterruptObject->NotificationCap,
				&MutexCap));
    assert(InterruptObject->ThreadHandle);
    assert(InterruptObject->IrqHandlerCap != 0);
    assert(InterruptObject->NotificationCap != 0);
    /* Both the IRQ handler cap and the notification cap is in the thread private
     * CNode of the ISR thread. */
    assert(PsGetGuardValueOfCap(InterruptObject->IrqHandlerCap));
    assert(PsGetGuardValueOfCap(InterruptObject->IrqHandlerCap) !=
	   RtlGetThreadCSpaceGuard());
    assert(PsGetGuardValueOfCap(InterruptObject->NotificationCap));
    assert(PsGetGuardValueOfCap(InterruptObject->NotificationCap) !=
	   RtlGetThreadCSpaceGuard());
    assert(MutexCap != 0);
    KeInitializeMutex(&InterruptObject->Mutex, MutexCap);
    /* The mutex cap should be in the process shared CNode. */
    assert(PsCapIsProcessShared(MutexCap));

    DbgTrace("Created interrupt object %p ThreadHandle %p "
	     "IrqHandler 0x%zx Notification 0x%zx Mutex 0x%zx\n",
	     InterruptObject, InterruptObject->ThreadHandle,
	     InterruptObject->IrqHandlerCap,
	     InterruptObject->NotificationCap,
	     InterruptObject->Mutex.Notification);
    RET_ERR_EX(NtResumeThread(InterruptObject->ThreadHandle, NULL),
	       IoDisconnectInterrupt(InterruptObject));
    *pInterruptObject = InterruptObject;
    return STATUS_SUCCESS;
}

NTAPI VOID IoDisconnectInterrupt(IN PKINTERRUPT InterruptObject)
{
    PAGED_CODE();
}

NTAPI VOID IoAcquireInterruptMutex(IN PKINTERRUPT Interrupt)
{
    if (!Interrupt) {
	assert(FALSE);
	return;
    }
    KeAcquireMutex(&Interrupt->Mutex);
}

NTAPI VOID IoReleaseInterruptMutex(IN PKINTERRUPT Interrupt)
{
    if (!Interrupt) {
	assert(FALSE);
	return;
    }
    KeReleaseMutex(&Interrupt->Mutex);
}
