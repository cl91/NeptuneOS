/*
 * The main event loop of the driver process
 */

#include <wdmp.h>
#include "coroutine.h"

ULONG InitSafeBootMode = 0;

/* Notification that our event loop sleeps on. Signaled by the NT Executive server and
 * the DPC/ISR threads. Note this is in the process-wide shared CNode. */
MWORD IopEventLoopNotification;
/* Signaled by us to notify NT Executive server of outgoing IO packets to process */
MWORD IopExecutiveNotification;

/*
 * This is the main event loop of the driver process
 */
static NTSTATUS IopDriverEventLoop()
{
    /* At driver startup, we need to call IopProcessIoPackets to process the IRPs
     * and IO work items queued during driver startup (in DriverEntry) and then
     * signal the NT Executive server to notify that driver startup has completed. */
    IopProcessIoPackets();
    assert(PsCapHasCorrectGuard(IopExecutiveNotification));
    assert(PsCapIsThreadPrivate(IopExecutiveNotification));
    seL4_Signal(IopExecutiveNotification);

    while (TRUE) {
	MWORD Badge = 0;
	assert(IopEventLoopNotification);
	assert(PsCapIsProcessShared(IopEventLoopNotification));
	seL4_Wait(RtlProcessCNodeIndexToGuardedCap(IopEventLoopNotification), &Badge);
	IopProcessIoPackets();
    }
}

VOID WdmStartup(IN seL4_CPtr WdmServiceCap,
		IN PNTDLL_DRIVER_INIT_INFO InitInfo,
		IN PUNICODE_STRING RegistryPath)
{
    /* WdmServiceCap must be a cap within the thread-private CNode and has
     * the correct guard value. */
    assert(PsCapIsThreadPrivate(WdmServiceCap));
    assert(PsCapHasCorrectGuard(WdmServiceCap));
    NtCurrentTeb()->Wdm.ServiceCap = WdmServiceCap;
    NtCurrentTeb()->Wdm.IsMainThread = TRUE;
    IopIncomingIoPacketBuffer = InitInfo->IncomingIoPacketBuffer;
    IopOutgoingIoPacketBuffer = InitInfo->OutgoingIoPacketBuffer;
    IopEventLoopNotification = InitInfo->EventLoopNotificationCap;
    IopExecutiveNotification = InitInfo->ExecutiveNotificationCap;
    KiCoroutineStackChainHead = (PVOID)InitInfo->InitialCoroutineStackTop;
    ULONG TscFreqInMHz = SharedUserData->TscFrequencyInMHz;
    KiCounterTimeMultiplier = (10ULL << TIME_MULTIPLIER_SHIFT) / TscFreqInMHz;
    KiInterruptTimeMultiplier = ((ULONG64)TscFreqInMHz << TIME_MULTIPLIER_SHIFT) / 10;
    KiInitialSystemTime.SystemTime = SharedUserData->InitialSystemTime;
    KiInitialCounterTime.CounterTime = SharedUserData->InitialTsc;
    InitializeListHead(&IopDmaPoolList);
    InitializeListHead(&IopDeviceList);
    InitializeListHead(&IopFileObjectList);
    InitializeListHead(&IopSignaledObjectList);
    InitializeListHead(&IopPendingTimerList);
#if defined(_M_IX86) || defined(_M_AMD64)
    InitializeListHead(&IopX86PortList);
    IoInitializeMutex(&IopX86PortMutex, InitInfo->X86PortMutexCap);
#endif
    InitializeListHead(&IopDpcQueue);
    InitializeListHead(&IopWorkItemQueue);
    IoInitializeMutex(&IopDpcMutex, InitInfo->DpcMutexCap);
    IoInitializeMutex(&IopWorkItemMutex, InitInfo->WorkItemMutexCap);
    IopInitIrpProcessing();
    HalpInitDma();
    CiInitialzeCacheManager();

    NTSTATUS Status = IopDriverInitialize(RegistryPath);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    Status = IopDriverEventLoop();

fail:
    /* The driver startup failed. Terminate the driver process. */
    NtTerminateProcess(NtCurrentProcess(), Status);
}
