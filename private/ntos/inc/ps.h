#pragma once

#include <nt.h>
#include "mm.h"
#include "ex.h"
#include "ob.h"

/* All hard-coded addresses in client processes' address space go here. */
#define LOWEST_USER_ADDRESS		(0x00010000)
#define WIN32_TEB_START			(0x70000000)
#define WIN32_TEB_END			(0x7ffdf000)
#define WIN32_PEB_START			(WIN32_TEB_END)
/* First 1MB of 0x80000000 unmapped to catch stack overflow */
#define THREAD_STACK_REGION_START	(0x80100000)
/* 1G thread space ~ 1024 threads with 1M stack */
#define THREAD_STACK_REGION_END		(0xcff00000)
/* 1MB-64K after thread stack region unmapped to catch stack underflow */
#define USER_SHARED_DATA		(0xcfff0000)
/* 64KB-4KB following user shared data is unmapped */
#define SYSTEM_DLL_IMAGE_START		(0xd0000000)
/* Subsystem dlls (kernel32.dll etc) follow NTDLL. 128MB */
#define SUBSYSTEM_DLL_IMAGE_END		(0xd8000000)
/* 4K system dll tls region per thread. 64MB == 16K threads */
#define SYSTEM_DLL_TLS_REGION_START	(SUBSYSTEM_DLL_IMAGE_END)
#define SYSTEM_DLL_TLS_REGION_END	(0xdc000000)
/* 4K IPC buffer per thread. 64MB == 16K threads */
#define IPC_BUFFER_START		(SYSTEM_DLL_TLS_REGION_END)
#define IPC_BUFFER_END			(0xe0000000)
#define HIGHEST_USER_ADDRESS		(0xe0000000)

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
    PFILE_OBJECT ImageFile;
    PSECTION ImageSection;
    PSUBSECTION SystemDllTlsSubsection;
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
