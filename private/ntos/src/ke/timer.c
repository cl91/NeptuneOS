#include "ki.h"

/* TODO: This is for x86 and PIC only. We don't support IOAPIC yet. */
#define TIMER_IRQ_LINE		0

/* TODO: Most BIOS set the frequency divider to either 65535 or 0 (representing
 * 65536). We assume it is 65536. We should really be setting the frequency
 * divider ourselves. */
#define TIMER_TICK_PER_SECOND	(1193182 >> 16)

static SYSTEM_THREAD KiTimerIrqThread;
static IRQ_HANDLER KiTimerIrqHandler;
static NOTIFICATION KiTimerIrqNotification;

/* This is supposed to be shared between the timer interrupt service and
 * the main thread (although we currently do not read this from the main
 * thread). You must use interlocked operations to access this! */
static ULONGLONG POINTER_ALIGNMENT KiTimerTickCount;

static KMUTEX KiTimerDatabaseLock;
/* The following data structures are protected by the timer database lock */
LIST_ENTRY KiQueuedTimerList;
LIST_ENTRY KiExpiredTimerList;
/* END of timer database lock protected data structure */

static inline BOOLEAN KiTryAcquireTimerDatabaseLock()
{
    return KeTryAcquireMutex(&KiTimerDatabaseLock);
}

static inline VOID KiReleaseTimerDatabaseLock()
{
    KeReleaseMutex(&KiTimerDatabaseLock);
}

/*
 * This can only be called in the main event loop thread.
 *
 * IMPORTANT NOTICE: Never call this function in the timer interrupt handler thread.
 */
static inline VOID KiAcquireTimerDatabaseLock()
{
    BOOLEAN Acquired = KiTryAcquireTimerDatabaseLock();
    /* On single process system we should always be able to acquire the lock.
     * Assert if we can't */
    if (KiProcessorCount == 1) {
	assert(Acquired);
    }
    /* On SMP systems we spin until the lock is acquired. */
    while (!Acquired) {
	Acquired = KiTryAcquireTimerDatabaseLock();
    }
}

static NTSTATUS KiCreateIrqHandler(IN PIRQ_HANDLER IrqHandler,
				   IN MWORD IrqLine)
{
    extern CNODE MiNtosCNode;
    assert(IrqHandler != NULL);
    MWORD Cap = 0;
    RET_ERR(MmAllocateCap(&MiNtosCNode, &Cap));
    assert(Cap != 0);
    int Error = seL4_IRQControl_Get(seL4_CapIRQControl, IrqLine,
				    MiNtosCNode.TreeNode.Cap,
				    Cap, MiNtosCNode.Depth);
    if (Error != 0) {
	MmDeallocateCap(&MiNtosCNode, Cap);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    KiInitializeIrqHandler(IrqHandler, &MiNtosCNode, Cap, IrqLine);
    assert(Cap == IrqHandler->TreeNode.Cap);
    return STATUS_SUCCESS;
}

static NTSTATUS KiCreateIrqNotification(IN PNOTIFICATION Notification)
{
    PUNTYPED Untyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_NotificationBits, &Untyped));
    assert(Untyped != NULL);
    KeInitializeNotification(Notification, Untyped->TreeNode.CSpace, 0, 0, 0);
    RET_ERR_EX(MmRetypeIntoObject(Untyped, seL4_NotificationObject, seL4_NotificationBits,
				  &Notification->TreeNode),
	       MmReleaseUntyped(Untyped));
    return STATUS_SUCCESS;
}

static NTSTATUS KiConnectIrqNotification(IN PIRQ_HANDLER IrqHandler,
					 IN PNOTIFICATION Notification)
{
    assert(IrqHandler != NULL);
    assert(Notification != NULL);
    int Error = seL4_IRQHandler_SetNotification(IrqHandler->TreeNode.Cap,
						Notification->TreeNode.Cap);
    if (Error != 0) {
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static VOID KiTimerInterruptService()
{
    while (TRUE) {
	int AckError = seL4_IRQHandler_Ack(KiTimerIrqHandler.TreeNode.Cap);
	if (AckError != 0) {
	    DbgTrace("Failed to ACK timer interrupt. Error:");
	    KeDbgDumpIPCError(AckError);
	}
	seL4_Wait(KiTimerIrqNotification.TreeNode.Cap, NULL);
	ULONGLONG TimerTicks = InterlockedIncrement64((PLONG64)&KiTimerTickCount);
	DbgTrace("Timer ticks %lld\n", TimerTicks);
    }
}

NTSTATUS KiEnableTimerInterruptService()
{
    RET_ERR(KiCreateIrqHandler(&KiTimerIrqHandler, TIMER_IRQ_LINE));
    RET_ERR_EX(KiCreateIrqNotification(&KiTimerIrqNotification),
	       MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode));
    RET_ERR_EX(KiConnectIrqNotification(&KiTimerIrqHandler, &KiTimerIrqNotification),
	       {
		   MmCapTreeDeleteNode(&KiTimerIrqNotification.TreeNode);
		   MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode);
	       });
    RET_ERR_EX(PsCreateSystemThread(&KiTimerIrqThread, "NTOS Timer ISR",
				    KiTimerInterruptService),
	       {
		   MmCapTreeDeleteNode(&KiTimerIrqNotification.TreeNode);
		   MmCapTreeDeleteNode(&KiTimerIrqHandler.TreeNode);
	       });
    return STATUS_SUCCESS;
}
