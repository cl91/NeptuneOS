#include <sel4/sel4.h>

int main()
{
    char *str = "Hello, World!\n";

    for (char *p = str; *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }

    return 0;
}
