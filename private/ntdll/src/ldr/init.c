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

static WCHAR LdrpUninitializedArray[512];

static WCHAR LdrpInitializedArray[512] = L"From initialized array.\n";

static inline VOID LdrpDisplayString(PCWSTR String)
{
    UNICODE_STRING UnicodeString;
    RtlInitUnicodeString(&UnicodeString, String);
    NtDisplayString(&UnicodeString);
}

__fastcall void LdrpInitialize(IN seL4_IPCBuffer *IpcBuffer,
			       IN PPVOID SystemDllTlsRegion)
{
    _tls_index = SYSTEMDLL_TLS_INDEX;
    SystemDllTlsRegion[SYSTEMDLL_TLS_INDEX] = SystemDllTlsRegion;
    __sel4_ipc_buffer = IpcBuffer;

    LdrpDisplayString(L"Hello, world from NT client!\n");
    LdrpDisplayString(LdrpInitializedArray);
    memcpy(LdrpUninitializedArray, L"From .bss array\n", sizeof(L"From .bss array\n"));
    LdrpDisplayString(LdrpUninitializedArray);

    while (1);
}
