#pragma once

#include <nt.h>
#include <sel4/sel4.h>

typedef struct _KTHREAD {
    LIST_ENTRY ThreadListEntry;
} KTHREAD, *PKTHREAD;

typedef struct _KPROCESS {
    PKTHREAD InitThread;
    LIST_ENTRY ThreadList;
} KPROCESS, *PKPROCESS;

VOID KeRunAllTests();

VOID KeBugCheckMsg(PCSTR Format, ...);

#define BUGCHECK_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { \
	    KeBugCheckMsg("Unrecoverable error at %s @ %s line %d: Error Code 0x%x\n",\
			  __func__, __FILE__, __LINE__, Error);}}

#define LoopOverUntyped(cap, desc, bootinfo)				\
    for (MWORD cap = bootinfo->untyped.start;				\
	 cap < bootinfo->untyped.end; cap++)				\
	for (seL4_UntypedDesc *desc =					\
		 &bootinfo->untypedList[cap - bootinfo->untyped.start]; \
	     desc != NULL; desc = NULL)
