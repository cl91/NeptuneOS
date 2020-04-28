#pragma once

#include <sel4/sel4.h>

typedef struct {
    seL4_BootInfo *BootInfo;
    seL4_IPCBuffer *InitialThreadIpcBuffer;
    seL4_CPtr InitialCapSpaceStart;
    seL4_CPtr InitialCapSpaceEnd;
} BOOT_ENVIRONMENT, *PBOOT_ENVIRONMENT;

VOID KiInitVga();
