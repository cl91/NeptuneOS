#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include <libelf/libelf.h>

typedef struct {
    seL4_BootInfo *BootInfo;
    seL4_CPtr InitialThreadTcb;
    seL4_IPCBuffer *InitialThreadIpcBuffer;
    elf_t BootElfImage;
} BOOT_ENVIRONMENT, *PBOOT_ENVIRONMENT;

PBOOT_ENVIRONMENT KeGetBootEnvironment();
VOID KeBugCheckMsg(PCSTR Format, ...);
