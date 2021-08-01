#pragma once

#include <nt.h>
#include "mm.h"
#include "ex.h"
#include "ob.h"

/* All hard-coded addresses in client processes' address space go here. */
#define THREAD_STACK_START		(0x00100000)
#define THREAD_STACK_END		(0x00200000)
#define IPC_BUFFER_VADDR		(0xc0000000)

#define ROOT_TCB_CAP			(seL4_CapInitThreadTCB)

#define NTOS_PS_TAG		EX_POOL_TAG('n', 't', 'p', 's')

typedef seL4_UserContext THREAD_CONTEXT;
typedef ULONG THREAD_PRIORITY;

typedef struct _THREAD {
    struct _PROCESS *Process;
    LIST_ENTRY ThreadListEntry;
    PUNTYPED TcbUntyped;
    MWORD TcbCap;
    PPAGING_STRUCTURE IpcBuffer;
    THREAD_CONTEXT Context;
    THREAD_PRIORITY CurrentPriority;
} THREAD, *PTHREAD;

typedef struct _PROCESS {
    PTHREAD InitThread;
    LIST_ENTRY ThreadList;
    PCNODE CNode;
    VIRT_ADDR_SPACE VaddrSpace;	/* Virtual address space */
    PSECTION ImageSection;
} PROCESS, *PPROCESS;

/* init.c */
NTSTATUS PsInitSystem();

/* create.c */
NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread);
NTSTATUS PsCreateProcess(IN PFILE_OBJECT ImageFile,
			 OUT PPROCESS *pProcess);
