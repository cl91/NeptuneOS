#pragma once

#include <nt.h>
#include "mm.h"
#include "ex.h"
#include "ob.h"

#define ROOT_TCB_CAP			(seL4_CapInitThreadTCB)

/* Initial CNode for client processes has exactly MWORD_BITS slots */
#define PROCESS_INIT_CNODE_LOG2SIZE	(MWORD_LOG2SIZE + 3)

compile_assert(CNODE_USEDMAP_NOT_AT_LEAST_ONE_MWORD,
	       (1ULL << PROCESS_INIT_CNODE_LOG2SIZE) >= MWORD_BITS);

#define NTOS_PS_TAG		EX_POOL_TAG('n', 't', 'p', 's')

typedef seL4_UserContext THREAD_CONTEXT, *PTHREAD_CONTEXT;
typedef ULONG THREAD_PRIORITY;

typedef struct _THREAD {
    CAP_TREE_NODE TreeNode;
    struct _PROCESS *Process;
    LIST_ENTRY ThreadListEntry;
    PIPC_ENDPOINT SystemServiceEndpoint;
    PPAGING_STRUCTURE IpcBufferClientPage;
    MWORD IpcBufferServerAddr;
    MWORD TEBClientAddr;
    MWORD TEBServerAddr;
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
    PSECTION ImageSection;
    LIST_ENTRY ProcessListEntry;
    MWORD SystemDllTlsSize;
    MWORD PEBClientAddr;
    MWORD PEBServerAddr;
} PROCESS, *PPROCESS;

/* init.c */
NTSTATUS PsInitSystemPhase0();

/* create.c */
NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread);
NTSTATUS PsCreateProcess(IN PFILE_OBJECT ImageFile,
			 OUT PPROCESS *pProcess);
PTHREAD PsFindThreadWithBadge(IN MWORD Badge);
