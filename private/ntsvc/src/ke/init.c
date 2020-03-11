#include <sel4/sel4.h>
#include <ldr.h>
#include <rtl.h>
#include <ke.h>

void KiInitializeSystem(seL4_BootInfo *bootinfo) {
    KeBugCheckMsg("hello, world! bootinfo pointer = %p", bootinfo);
    LdrInitBootEnvironment(bootinfo);
}
