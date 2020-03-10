#include <sel4/sel4.h>
#include <ldr.h>

void hello()
{
    char *str = "Hello, World!\n";

    for (char *p = str; *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }
}

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    hello();
    LdrInitBootEnvironment(bootinfo);
}
