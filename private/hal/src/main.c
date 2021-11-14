/*
 * The main event loop of the driver process
 */

#include <hal.h>

PDRIVER_OBJECT IopDriverObject;

__thread seL4_IPCBuffer *__sel4_ipc_buffer;
__thread seL4_CPtr KiHalServiceCap;

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

static NTSTATUS IopCallDriverEntry()
{
    assert(IopDriverObject != NULL);
    PLDR_DATA_TABLE_ENTRY LdrDriverImage = NULL;
    RET_ERR(LdrFindEntryForAddress(NtCurrentPeb()->ImageBaseAddress, &LdrDriverImage));
    PVOID DriverEntry = LdrDriverImage->EntryPoint;
    RET_ERR(((PDRIVER_INITIALIZE)DriverEntry)(IopDriverObject, NULL));
    return STATUS_SUCCESS;
}

static NTSTATUS IopDriverEventLoop()
{
    assert(IopDriverObject != NULL);
    ULONG NumResponsePackets = 0;
    while (TRUE) {
	ULONG NumRequestPackets = 0;
	RET_ERR(IopRequestIrp(NumResponsePackets, &NumRequestPackets));
	NTSTATUS Status = IopProcessIrp(&NumResponsePackets, NumRequestPackets);
	if (!NT_SUCCESS(Status)) {
	    DbgTrace("IopProcessIrp returned error 0x%08x\n", Status);
	    /* On debug build, we simply stop the driver so we can debug the
	     * error and fix it. On release build, we have no choice but
	     * to keep going. Since the IopProcessIrp function never generates
	     * partial response packets (if a response packet gets into the
	     * outgoing IRP queue it is guaranteed to be valid), it will appear
	     * that the driver simply dropped some request packets, which will
	     * never get a response. */
	    assert(FALSE);
	}
    }
}

VOID HalStartup(IN seL4_IPCBuffer *IpcBuffer,
		IN seL4_CPtr HalServiceCap,
		IN PNTDLL_DRIVER_INIT_INFO InitInfo)
{
    __sel4_ipc_buffer = IpcBuffer;
    KiHalServiceCap = HalServiceCap;
    IopIncomingIrpBuffer = (PIO_REQUEST_PACKET) InitInfo->IncomingIrpBuffer;
    IopOutgoingIrpBuffer = (PIO_REQUEST_PACKET) InitInfo->OutgoingIrpBuffer;
    InitializeListHead(&IopIrpQueue);
    InitializeListHead(&IopCompletedIrpList);
    InitializeListHead(&IopDeviceList);
    InitializeListHead(&IopFileObjectList);

    IopDriverObject = (PDRIVER_OBJECT) RtlAllocateHeap(RtlGetProcessHeap(),
						       HEAP_ZERO_MEMORY,
						       sizeof(DRIVER_OBJECT));

    NTSTATUS Status = STATUS_SUCCESS;
    if (IopDriverObject == NULL) {
	Status = STATUS_NO_MEMORY;
	goto fail;
    }

    Status = IopCallDriverEntry();
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    Status = IopDriverEventLoop();

fail:
    /* The driver startup failed. Raise the status to terminate the driver process. */
    RtlRaiseStatus(Status);
}
