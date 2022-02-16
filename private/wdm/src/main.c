/*
 * The main event loop of the driver process
 */

#include <wdmp.h>
#include "coroutine.h"

PCSTR IopDbgTraceModuleName = "WDM";
DRIVER_OBJECT IopDriverObject;

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
__thread seL4_CPtr KiWdmServiceCap;

ULONG _tls_index;

/*
 * TLS raw template data start and end.
 *
 * Note that we merge the .tls section and the .data section to save space.
 * In doing so we need to make sure that the .tls section comes before
 * the .data section, since clang generates code that expects that tls
 * data are at the very beginning of a section. This is done by passing
 * /merge:.data=.tls to the linker (note that the ordering matters).
 *
 * We use here pointer-types for start/end so that tls-data remains
 * aligned on pointer-size-width.
 */
__declspec(allocate(".tls")) char *_tls_start = NULL;
__declspec(allocate(".tls$ZZZ")) char *_tls_end = NULL;

/*
 * TLS directory. Must be called _tls_used as the linker expects this name.
 */
const IMAGE_TLS_DIRECTORY _tls_used = {
    (ULONG_PTR) &_tls_start, (ULONG_PTR) &_tls_end,
    (ULONG_PTR) &_tls_index, 0, 0, 0
};

static NTSTATUS IopCallDriverEntry(IN PUNICODE_STRING RegistryPath)
{
    PLDR_DATA_TABLE_ENTRY LdrDriverImage = NULL;
    RET_ERR(LdrFindEntryForAddress(NtCurrentPeb()->ImageBaseAddress, &LdrDriverImage));
    PVOID DriverEntry = LdrDriverImage->EntryPoint;
    DbgTrace("Registry path %wZ\n", RegistryPath);
    RET_ERR(((PDRIVER_INITIALIZE)DriverEntry)(&IopDriverObject, RegistryPath));
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
	RET_ERR(IopRequestIoPackets(NumResponsePackets, &NumRequestPackets));
	IopProcessIoPackets(&NumResponsePackets, NumRequestPackets);
    }
}

VOID WdmStartup(IN seL4_IPCBuffer *IpcBuffer,
		IN seL4_CPtr WdmServiceCap,
		IN PNTDLL_DRIVER_INIT_INFO InitInfo,
		IN PUNICODE_STRING RegistryPath)
{
    __sel4_ipc_buffer = IpcBuffer;
    KiWdmServiceCap = WdmServiceCap;
    IopIncomingIoPacketBuffer = (PIO_PACKET) InitInfo->IncomingIoPacketBuffer;
    IopOutgoingIoPacketBuffer = (PIO_PACKET) InitInfo->OutgoingIoPacketBuffer;
    KiCoroutineStackChainHead = (PVOID) InitInfo->InitialCoroutineStackTop;
    KiStallScaleFactor = (ULONG)InitInfo->X86TscFreq;
    InitializeListHead(&IopDeviceList);
    InitializeListHead(&IopFileObjectList);
    InitializeListHead(&IopTimerList);
    InitializeListHead(&IopIrpQueue);
    InitializeListHead(&IopReplyIrpList);
    InitializeListHead(&IopPendingIrpList);
    InitializeListHead(&IopCleanupIrpList);
    InitializeListHead(&IopAddDeviceRequestList);
    InitializeListHead(&IopSuspendedAddDeviceRequestList);
    InitializeListHead(&IopCompletedAddDeviceRequestList);
    InitializeListHead(&IopX86PortList);
    InitializeListHead(&IopDriverObject.ReinitListHead);
    RtlInitializeSListHead(&IopWorkItemQueue);
    InitializeListHead(&IopSuspendedWorkItemList);
    InitializeListHead(&IopDpcQueue);
    KeInitializeMutex(&IopDpcMutex, InitInfo->DpcMutexCap);

    /* Set the IopDbgTraceModuleName to the driver base name */
    if (RegistryPath != NULL && RegistryPath->Length > 2) {
	ULONG BaseNameStart = RegistryPath->Length / sizeof(WCHAR);
	if (RegistryPath->Buffer[BaseNameStart] == L'\0') {
	    BaseNameStart--;
	}
	if (RegistryPath->Buffer[BaseNameStart] == L'\\') {
	    BaseNameStart--;
	}
	while (BaseNameStart != 0 && RegistryPath->Buffer[BaseNameStart] != L'\\') {
	    BaseNameStart--;
	}
	BaseNameStart++;
	assert(RegistryPath->Length/sizeof(WCHAR) > BaseNameStart);
	ULONG StrLen = RegistryPath->Length/sizeof(WCHAR) - BaseNameStart;
	PCHAR Name = RtlAllocateHeap(RtlGetProcessHeap(),
				     HEAP_ZERO_MEMORY,
				     StrLen+1);
	for (ULONG i = 0; i < StrLen; i++) {
	    Name[i] = (CHAR) RegistryPath->Buffer[BaseNameStart+i];
	}
	IopDbgTraceModuleName = Name;
    }

    NTSTATUS Status = IopCallDriverEntry(RegistryPath);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    IopCallReinitRoutines();

    Status = IopDriverEventLoop();

fail:
    /* The driver startup failed. Raise the status to terminate the driver process. */
    RtlRaiseStatus(Status);
}
