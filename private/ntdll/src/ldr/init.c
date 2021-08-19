#include <sel4/sel4.h>
#include <nt.h>
#include <string.h>
#include <ke.h>
#include <services.h>
#include <stdint.h>

/* Address for the IPC buffer of the initial thread. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;

static CHAR LdrpUninitializedArray[1024];

static CHAR LdrpInitializedArray[1024] = "From initialized array.\n";

VOID __assert_fail(PCSTR str, PCSTR file, int line, PCSTR function)
{
}

__fastcall void LdrpInitialize(IN seL4_IPCBuffer *IpcBuffer)
{
    PUCHAR p = (PUCHAR) 0x00404000;
    p[0] = 'a';
    __sel4_ipc_buffer = IpcBuffer;
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugPutString("Hello, world from NT client!\n");
    seL4_DebugPutString(LdrpInitializedArray);
    memcpy(LdrpUninitializedArray, "From .bss array\n", sizeof("From .bss array\n"));
    seL4_DebugPutString(LdrpUninitializedArray);
#endif

    NtDisplayString("Hello, world from NT client!\n");

    while (1);
}
