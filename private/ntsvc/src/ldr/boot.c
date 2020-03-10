#include <stdint.h>
#include <sel4/sel4.h>
#include <libelf/libelf.h>
#include <cpio/cpio.h>
#include <ke.h>
#include <ldr.h>

BOOT_ENVIRONMENT LdrpBootEnvironment;

PBOOT_ENVIRONMENT LdrGetBootEnvironment()
{
    return &LdrpBootEnvironment;
}

static void LdrpLoadBootElfImage()
{
//    seL4_SlotRegion frames = bootinfo->userImageFrames;
}

void LdrLoadBootModules()
{
}

void LdrInitBootEnvironment(seL4_BootInfo *bootinfo) {
    LdrpBootEnvironment.BootInfo = bootinfo;
    LdrpBootEnvironment.InitialThreadIpcBuffer = bootinfo->ipcBuffer;
    LdrpBootEnvironment.InitialThreadTcb = seL4_CapInitThreadTCB;
}
