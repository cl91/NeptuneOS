/*
 * The main event loop of the driver process
 */

#include <hal.h>

__thread seL4_IPCBuffer *__sel4_ipc_buffer;

ULONG _tls_index;

/* TLS raw template data start and end.
   We use here pointer-types for start/end so that tls-data remains
   aligned on pointer-size-width.  This seems to be required for
   pe-loader. */
__declspec(allocate(".tls")) char *_tls_start = NULL;
__declspec(allocate(".tls$ZZZ")) char *_tls_end = NULL;

__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = 0;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = 0;

const IMAGE_TLS_DIRECTORY _tls_used = {
  (ULONG_PTR) &_tls_start, (ULONG_PTR) &_tls_end,
  (ULONG_PTR) &_tls_index, (ULONG_PTR) (&__xl_a+1),
  (ULONG) 0, (ULONG) 0
};

static NTSTATUS IopCallDriverEntry(PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY LdrDriverImage = NULL;
    RET_ERR(LdrFindEntryForAddress(NtCurrentPeb()->ImageBaseAddress, &LdrDriverImage));
    PVOID DriverEntry = LdrDriverImage->EntryPoint;
    RET_ERR(((PDRIVER_INITIALIZE)DriverEntry)(DriverObject, NULL));
    return STATUS_SUCCESS;
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

    while (1);
}
