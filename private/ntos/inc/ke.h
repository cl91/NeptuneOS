#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include "mm.h"

#define NTOS_KE_TAG			(EX_POOL_TAG('n','t','k','e'))

VOID KeRunAllTests();

VOID KeBugCheckMsg(IN PCSTR Format, ...);

VOID KeBugCheck(IN PCSTR Function,
		IN PCSTR File,
		IN ULONG Line,
		IN ULONG Error);

#define BUGCHECK_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { \
	    KeBugCheck(__func__, __FILE__, __LINE__, Error);}}

#define LoopOverUntyped(cap, desc, bootinfo)				\
    for (MWORD cap = bootinfo->untyped.start;				\
	 cap < bootinfo->untyped.end; cap++)				\
	for (seL4_UntypedDesc *desc =					\
		 &bootinfo->untypedList[cap - bootinfo->untyped.start]; \
	     desc != NULL; desc = NULL)

#define ENDPOINT_RIGHTS_WRITE_GRANTREPLY	seL4_CapRights_new(1, 0, 0, 1)

typedef struct _IPC_ENDPOINT {
    CAP_TREE_NODE TreeNode;
    MWORD Badge;
} IPC_ENDPOINT, *PIPC_ENDPOINT;

typedef struct _X86_IOPORT {
    CAP_TREE_NODE TreeNode; /* capability with which to invoke seL4_X86_IOPort_* */
    USHORT PortNum;	    /* port number */
} X86_IOPORT, *PX86_IOPORT;

/* services.c */
struct _PROCESS;
struct _THREAD;
NTSTATUS KeEnableSystemServices(IN struct _PROCESS *Process,
				IN struct _THREAD *Thread);
VOID KeDbgDumpIPCError(IN int Error);

/* port.c */
NTSTATUS KeEnableIoPortX86(IN PCNODE CSpace,
			   IN USHORT PortNum,
			   IN PX86_IOPORT IoPort);

/* Generated by syssvc-gen.py */
#include <ntos_syssvc_gen.h>
