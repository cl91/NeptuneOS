/*
 * The main event loop of the driver process
 */

#include <wdmp.h>
#include "coroutine.h"

/*
 * This is the main event loop of the driver process
 */
static NTSTATUS IopDriverEventLoop()
{
    ULONG NumResponsePackets = 0;
    while (TRUE) {
	ULONG NumRequestPackets = 0;
	/* This should never return error. If it did, something is seriously
	 * wrong and we should terminate the driver process. */
	RET_ERR(WdmRequestIoPackets(NumResponsePackets, &NumRequestPackets));
	IopProcessIoPackets(&NumResponsePackets, NumRequestPackets);
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
    IopIncomingIoPacketBuffer = (PIO_PACKET)InitInfo->IncomingIoPacketBuffer;
    IopOutgoingIoPacketBuffer = (PIO_PACKET)InitInfo->OutgoingIoPacketBuffer;
    KiCoroutineStackChainHead = (PVOID)InitInfo->InitialCoroutineStackTop;
    InitializeListHead(&IopDeviceList);
    InitializeListHead(&IopFileObjectList);
    InitializeListHead(&IopEventList);
    InitializeListHead(&IopTimerList);
#if defined(_M_IX86) || defined(_M_AMD64)
    InitializeListHead(&IopX86PortList);
    KiStallScaleFactor = (ULONG)InitInfo->X86TscFreq;
#elif defined(_M_ARM64)
    ULONG64 KiStallScaleFactor64;
    asm volatile ("mrs %0, cntfrq_el0; isb;" : "=r"(KiStallScaleFactor64) :: "memory");
    KiStallScaleFactor = KiStallScaleFactor64;
#else
#error "Unsupported architecture"
#endif
    RtlInitializeSListHead(&IopWorkItemQueue);
    InitializeListHead(&IopDpcQueue);
    KeInitializeMutex(&IopDpcMutex, InitInfo->DpcMutexCap);
    IopInitIrpProcessing();
    HalpInitDma();
    CiInitialzeCacheManager();

    NTSTATUS Status = IopInitDriverObject(RegistryPath);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    Status = IopDriverEventLoop();

fail:
    /* The driver startup failed. Terminate the driver process. */
    NtTerminateProcess(NtCurrentProcess(), Status);
}
