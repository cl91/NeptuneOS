#pragma once

#include <nt.h>
#include "mm.h"
#include "ex.h"
#include "ob.h"

#ifdef _M_IX86
#define seL4_VSpaceObject seL4_X86_PageDirectoryObject
#endif

#ifdef _M_AMD64
#define seL4_VSpaceObject seL4_X64_PML4Object
#endif

#define PS_THREAD_OBJECT_CAPS	(1)
typedef struct _PS_THREAD_OBJECT {
    MWORD TcbCap;
    MWORD ThreadHandle;
    MWORD ProcessHandle;
} PS_THREAD_OBJECT, *PPS_THREAD_OBJECT;

#define PS_PROCESS_OBJECT_CAPS	(1)
typedef struct _PS_PROCESS_OBJECT {
    MWORD VspaceCap;
    MWORD ProcessHandle;
} PS_PROCESS_OBJECT, *PPS_PROCESS_OBJECT;
