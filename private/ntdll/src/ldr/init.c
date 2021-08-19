#include <sel4/sel4.h>
#include <nt.h>
#include <string.h>
#include <ke.h>
#include <services.h>
#include <stdint.h>

/* The executable always has tls_index == 0, and NTDLL always has tls_index == 1 */
ULONG _tls_index = 1;

/* Address for the IPC buffer of the initial thread. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;
__thread seL4_IPCBuffer *__sel4_ipc_buffer2;

static CHAR LdrpUninitializedArray[1024];

static CHAR LdrpInitializedArray[1024] = "From initialized array.\n";

VOID __assert_fail(PCSTR str, PCSTR file, int line, PCSTR function)
{
}

void LdrpInitialize()
{
    __sel4_ipc_buffer = (seL4_IPCBuffer *) IPC_BUFFER_START;
    __sel4_ipc_buffer2 = (seL4_IPCBuffer *) IPC_BUFFER_START;
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugPutString("Hello, world from NT client!\n");
    seL4_DebugPutString(LdrpInitializedArray);
    memcpy(LdrpUninitializedArray, "From .bss array\n", sizeof("From .bss array\n"));
    seL4_DebugPutString(LdrpUninitializedArray);
#endif

    NtDisplayString("Hello, world from NT client!\n");

    while (1);
}
