#include <sel4/sel4.h>

void LdrpInitialize()
{
    char *str = "Hello, world from NT client!\n";

    for (char *p = str; *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }

    while (1);
}
