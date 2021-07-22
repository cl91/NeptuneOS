#pragma once

#include <nt.h>
#include "mm.h"
#include "ex.h"
#include "ob.h"

#ifdef _M_IX86
#define IPC_BUFFER_VADDR	(0xc0000000)
#endif

#ifdef _M_AMD64
#define IPC_BUFFER_VADDR	(0xc0000000)
#endif

#define NTOS_PS_TAG		EX_POOL_TAG('n', 't', 'p', 's')

typedef struct _THREAD {
    LIST_ENTRY ThreadListEntry;
    PUNTYPED TcbUntyped;
    MWORD TcbCap;
    PPAGING_STRUCTURE IpcBuffer;
} THREAD, *PTHREAD;

typedef struct _PROCESS {
    PTHREAD InitThread;
    LIST_ENTRY ThreadList;
    PCNODE CNode;
    VIRT_ADDR_SPACE VaddrSpace;	/* Virtual address space */
} PROCESS, *PPROCESS;

/* init.c */
NTSTATUS PsInitSystem();

/* create.c */
NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread);
NTSTATUS PsCreateProcess(OUT PPROCESS *pProcess);
