#include <ntdll.h>

/*
 * Executable always has _tls_index == 0. NTDLL always has _tls_index == 1
 * We will set this during LdrpInitialize
 */
#define SYSTEMDLL_TLS_INDEX	1
ULONG _tls_index;

#define MAX_NUMBER_OF_TLS_REGIONS	500

/* This must be placed at the very beginning ot the .tls section */
__declspec(allocate(".tls")) PVOID THREAD_LOCAL_STORAGE_POINTERS_ARRAY[MAX_NUMBER_OF_TLS_REGIONS];

/* Address for the IPC buffer of the initial thread. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;

static CHAR LdrpUninitializedArray[1024];

static CHAR LdrpInitializedArray[1024] = "From initialized array.\n";

__fastcall void LdrpInitialize(IN seL4_IPCBuffer *IpcBuffer,
			       IN PPVOID SystemDllTlsRegion)
{
    _tls_index = SYSTEMDLL_TLS_INDEX;
    SystemDllTlsRegion[SYSTEMDLL_TLS_INDEX] = SystemDllTlsRegion;
    __sel4_ipc_buffer = IpcBuffer;
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugPutString("Hello, world from NT client!\n");
    seL4_DebugPutString(LdrpInitializedArray);
    memcpy(LdrpUninitializedArray, "From .bss array\n", sizeof("From .bss array\n"));
    seL4_DebugPutString(LdrpUninitializedArray);
#endif

    UNICODE_STRING ClientWelcome;
    RtlInitUnicodeString(&ClientWelcome, L"Hello, world from NT client!\n");
    NtDisplayString(&ClientWelcome);

    while (1);
}
