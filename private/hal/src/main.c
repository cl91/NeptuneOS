/*
 * The main event loop of the driver process
 */

#include <hal.h>

__thread seL4_IPCBuffer *__sel4_ipc_buffer;

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

static VOID IopDriverEventLoop(IN PDRIVER_OBJECT DriverObject)
{
    while (TRUE) {
	/* TODO */
    }
}

VOID HalStartup(seL4_IPCBuffer *IpcBuffer)
{
    __sel4_ipc_buffer = IpcBuffer;

    NtDisplayStringA("hal.dll: Allocating DriverObject... ");
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT) RtlAllocateHeap(RtlGetProcessHeap(),
								   HEAP_ZERO_MEMORY,
								   sizeof(DRIVER_OBJECT));
    if (DriverObject == NULL) {
	NtDisplayStringA("FAIL\n");
	return;
    } else {
	NtDisplayStringA("OK\n");
    }

    NtDisplayStringA("hal.dll: Calling DriverEntry... ");
    NTSTATUS Status = IopCallDriverEntry(DriverObject);
    if (NT_SUCCESS(Status)) {
	NtDisplayStringA("OK\n");
    } else {
	NtDisplayStringA("FAIL\n");
	return;
    }

    IopDriverEventLoop(DriverObject);

    /* The event loop function should never return. Raise a status if it did. */
    RtlRaiseStatus(STATUS_UNSUCCESSFUL);
}
