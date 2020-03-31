#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include <libelf/libelf.h>

typedef struct {
    seL4_BootInfo *BootInfo;
    seL4_CPtr InitialThreadTcb;
    seL4_IPCBuffer *InitialThreadIpcBuffer;
    seL4_CPtr InitialCapSpaceRoot;
    seL4_CPtr InitialCapSpaceStart;
    seL4_CPtr InitialCapSpaceEnd;
    elf_t BootElfImage;
} BOOT_ENVIRONMENT, *PBOOT_ENVIRONMENT;

PBOOT_ENVIRONMENT KeGetBootEnvironment();
VOID KeBugCheckMsg(PCSTR Format, ...);
