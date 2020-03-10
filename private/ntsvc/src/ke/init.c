#include <sel4/sel4.h>
#include <ldr.h>
#include <printf.h>

void hello()
{
    char buf[128];
    snprintf(buf, sizeof(buf), "Hello, world! Number: %d\n", 69);

    for (char *p = buf; *p != '\0'; p++) {
	seL4_DebugPutChar(*p);
    }
}

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    hello();
    LdrInitBootEnvironment(bootinfo);
}
