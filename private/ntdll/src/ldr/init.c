#include <sel4/sel4.h>
#include <nt.h>
#include <string.h>

static CHAR LdrpUninitializedArray[1024];

static CHAR LdrpInitializedArray[1024] = "From initialized array.\n";

void LdrpInitialize()
{
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugPutString("Hello, world from NT client!\n");
    seL4_DebugPutString(LdrpInitializedArray);
    memcpy(LdrpUninitializedArray, "From .bss array\n", sizeof("From .bss array\n"));
    seL4_DebugPutString(LdrpUninitializedArray);
#endif

    while (1);
}
