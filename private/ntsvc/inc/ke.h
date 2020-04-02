#pragma once

#include <nt.h>
#include <ntos.h>
#include <sel4/sel4.h>
#include <libelf/libelf.h>

typedef struct {
    seL4_BootInfo *BootInfo;
    seL4_IPCBuffer *InitialThreadIpcBuffer;
    seL4_CPtr InitialCapSpaceStart;
    seL4_CPtr InitialCapSpaceEnd;
    elf_t BootElfImage;
    PCAPSPACE_DESCRIPTOR InitialCapSpace;
} BOOT_ENVIRONMENT, *PBOOT_ENVIRONMENT;

PBOOT_ENVIRONMENT KeGetBootEnvironment();
VOID KeBugCheckMsg(PCSTR Format, ...);

#define BUGCHECK_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { \
	    KeBugCheckMsg("Unrecoverable error at %s @ %s line %s: Error Code 0x%x\n",\
			  __func__, __FILE__, __LINE__, Error);		\
	    return Error; }}

#define LoopOverUntyped(cap, desc, BootEnvironment)			\
    for (MWORD cap = BootEnvironment->BootInfo->untyped.start;		\
	 cap < BootEnvironment->BootInfo->untyped.end; cap++)		\
	for (seL4_UntypedDesc *desc =					\
		 &BootEnvironment->BootInfo->untypedList[cap - BootEnvironment->BootInfo->untyped.start]; \
	     desc != NULL; desc = NULL)
