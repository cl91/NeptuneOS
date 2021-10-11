#pragma once

#include <nt.h>
#include "mm.h"
#include "ex.h"
#include "ob.h"

#define ROOT_TCB_CAP			(seL4_CapInitThreadTCB)

/* Initial CNode for client processes has 256 slots */
#define PROCESS_INIT_CNODE_LOG2SIZE	(8)

compile_assert(CNODE_USEDMAP_NOT_AT_LEAST_ONE_MWORD,
	       (1ULL << PROCESS_INIT_CNODE_LOG2SIZE) >= MWORD_BITS);

#define NTOS_PS_TAG		EX_POOL_TAG('n', 't', 'p', 's')

/* Not to be confused with CONTEXT, defined in the NT headers */
typedef seL4_UserContext THREAD_CONTEXT, *PTHREAD_CONTEXT;
typedef ULONG THREAD_PRIORITY;

typedef struct _THREAD {
    CAP_TREE_NODE TreeNode;
    struct _PROCESS *Process;
    LIST_ENTRY ThreadListEntry;
    PIPC_ENDPOINT SystemServiceEndpoint;
    MWORD IpcBufferClientAddr;
    MWORD IpcBufferServerAddr;
    MWORD TebClientAddr;
    MWORD TebServerAddr;
    MWORD SystemDllTlsBase; /* Address in the client's virtual address space */
    MWORD StackTop;
    MWORD StackReserve;
    MWORD StackCommit;
    THREAD_PRIORITY CurrentPriority;
} THREAD, *PTHREAD;

typedef struct _PROCESS {
    PTHREAD InitThread;
    LIST_ENTRY ThreadList;
    PCNODE CSpace;
    VIRT_ADDR_SPACE VSpace;	/* Virtual address space of the process */
    PIO_FILE_OBJECT ImageFile;
    PSECTION ImageSection;
    MWORD ImageBaseAddress;
    MWORD ImageVirtualSize;
    LIST_ENTRY ProcessListEntry;
    MWORD PebClientAddr;
    MWORD PebServerAddr;
    MWORD LoaderSharedDataClientAddr;
    MWORD LoaderSharedDataServerAddr;
    NTDLL_PROCESS_INIT_INFO InitInfo;
} PROCESS, *PPROCESS;

#define PROC_CREA_FLAG_DRIVER	(0x1)

/* init.c */
NTSTATUS PsInitSystemPhase0();
NTSTATUS PsInitSystemPhase1();

/* create.c */
NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread);
NTSTATUS PsCreateProcess(IN PIO_FILE_OBJECT ImageFile,
			 IN MWORD Flags,
			 OUT PPROCESS *pProcess);
NTSTATUS PsLoadDll(IN PPROCESS Process,
		   IN PCSTR DllName);
