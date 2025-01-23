/*
 * The main event loop of the driver process
 */

#include <wdmp.h>
#include "coroutine.h"

DRIVER_OBJECT IopDriverObject;

static NTSTATUS IopCallDriverEntry(IN PUNICODE_STRING RegistryPath)
{
    PLDR_DATA_TABLE_ENTRY LdrDriverImage = NULL;
    NTSTATUS Status = LdrFindEntryForAddress(NtCurrentPeb()->ImageBaseAddress,
					     &LdrDriverImage);
    if (!NT_SUCCESS(Status)) {
	return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;
    }
    PVOID DriverEntry = LdrDriverImage->EntryPoint;
    DbgTrace("Registry path %wZ\n", RegistryPath);
    Status = ((PDRIVER_INITIALIZE)DriverEntry)(&IopDriverObject, RegistryPath);
    if (!NT_SUCCESS(Status)) {
	return STATUS_FAILED_DRIVER_ENTRY;
    }
    return STATUS_SUCCESS;
}

static VOID IopCallReinitRoutines()
{
    IopDriverObject.Flags &= ~DRVO_REINIT_REGISTERED;
    LoopOverList(Entry, &IopDriverObject.ReinitListHead, DRIVER_REINIT_ITEM, ItemEntry) {
	Entry->Count++;
	Entry->ReinitRoutine(Entry->DriverObject, Entry->Context, Entry->Count);
    }
}

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
    NtCurrentTeb()->Wdm.ServiceCap = WdmServiceCap;
    IopIncomingIoPacketBuffer = (PIO_PACKET)InitInfo->IncomingIoPacketBuffer;
    IopOutgoingIoPacketBuffer = (PIO_PACKET)InitInfo->OutgoingIoPacketBuffer;
    KiCoroutineStackChainHead = (PVOID)InitInfo->InitialCoroutineStackTop;
    IopDriverObject.DriverStart = NtCurrentPeb()->ImageBaseAddress;
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
    InitializeListHead(&IopDriverObject.ReinitListHead);
    RtlInitializeSListHead(&IopWorkItemQueue);
    InitializeListHead(&IopDpcQueue);
    KeInitializeMutex(&IopDpcMutex, InitInfo->DpcMutexCap);
    IopInitIrpProcessing();
    HalpInitDma();
    CiInitialzeCacheManager();

    NTSTATUS Status = IopCallDriverEntry(RegistryPath);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    IopCallReinitRoutines();

    Status = IopDriverEventLoop();

fail:
    /* The driver startup failed. Terminate the driver process. */
    NtTerminateProcess(NtCurrentProcess(), Status);
}
