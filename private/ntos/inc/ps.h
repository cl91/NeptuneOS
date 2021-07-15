#pragma once

#include <nt.h>
#include "mm.h"
#include "ex.h"
#include "ob.h"

#ifdef _M_IX86
#define seL4_VSpaceObject seL4_X86_PageDirectoryObject
#define IPC_BUFFER_VADDR	(0xc0000000)
#endif

#ifdef _M_AMD64
#define seL4_VSpaceObject seL4_X64_PML4Object
#define IPC_BUFFER_VADDR	(0xc0000000)
#endif

#define IPC_BUFFER_PAGENUM	(IPC_BUFFER_VADDR >> MM_PAGE_BITS)

#define NTOS_PS_TAG	EX_POOL_TAG('n', 't', 'p', 's')

typedef struct _THREAD {
    LIST_ENTRY ThreadListEntry;
    PMM_UNTYPED TcbUntyped;
    MWORD TcbCap;
    PMM_PAGE IpcBuffer;
} THREAD, *PTHREAD;

typedef struct _PROCESS {
    PTHREAD InitThread;
    LIST_ENTRY ThreadList;
    MM_VADDR_SPACE VaddrSpace;	/* Virtual address space */
} PROCESS, *PPROCESS;

/* init.c */
NTSTATUS PsInitSystem();

/* create.c */
NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread);
NTSTATUS PsCreateProcess(OUT PPROCESS *pProcess);
