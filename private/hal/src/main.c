/*
 * The main event loop of the driver process
 */

#include <hal.h>

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

static NTSTATUS IopCallDriverEntry(IN PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY LdrDriverImage = NULL;
    RET_ERR(LdrFindEntryForAddress(NtCurrentPeb()->ImageBaseAddress, &LdrDriverImage));
    PVOID DriverEntry = LdrDriverImage->EntryPoint;
    RET_ERR(((PDRIVER_INITIALIZE)DriverEntry)(DriverObject, NULL));
    return STATUS_SUCCESS;
}

static NTSTATUS IopDriverEventLoop(IN PDRIVER_OBJECT DriverObject)
{
    while (TRUE) {
	ULONG NumIrp = 0;
	RET_ERR(IopRequestIrp(&NumIrp));
	while (1) ;
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

    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT) RtlAllocateHeap(RtlGetProcessHeap(),
								   HEAP_ZERO_MEMORY,
								   sizeof(DRIVER_OBJECT));

    NTSTATUS Status = STATUS_SUCCESS;
    if (DriverObject == NULL) {
	Status = STATUS_NO_MEMORY;
	goto fail;
    }

    Status = IopCallDriverEntry(DriverObject);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    Status = IopDriverEventLoop(DriverObject);

fail:
    /* The driver startup failed. Raise the status to terminate the driver process. */
    RtlRaiseStatus(Status);
}
