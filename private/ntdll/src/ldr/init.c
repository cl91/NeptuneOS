#include <sel4/sel4.h>

void LdrpInitialize()
{
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugPutString("Hello, world from NT client!\n");
#endif

    while (1);
}
