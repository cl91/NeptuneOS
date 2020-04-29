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

#define NTOS_PS_TAG	EX_POOL_TAG('n', 't', 'p', 's')

typedef struct _THREAD {
    LIST_ENTRY ThreadListEntry;
    PMM_UNTYPED TcbUntyped;
    PMM_UNTYPED IpcBufferUntyped;
    MWORD TcbCap;
    MWORD IpcBufferCap;
} THREAD, *PTHREAD;

typedef struct _PROCESS {
    PTHREAD InitThread;
    LIST_ENTRY ThreadList;
    MM_VADDR_SPACE VaddrSpace;	/* Virtual address space */
} PROCESS, *PPROCESS;
