#pragma once

#include <ntos.h>
#include <ntimage.h>

#define PspAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_PS_TAG); \
    if ((Var) == NULL) { return STATUS_NO_MEMORY; }

/* Initial CNode for client processes has exactly MWORD_BITS slots */
#define PROCESS_INIT_CNODE_LOG2SIZE	(MWORD_LOG2SIZE + 3)

COMPILE_ASSERT(CNODE_USEDMAP_NOT_AT_LEAST_ONE_MWORD,
	       (1ULL << PROCESS_INIT_CNODE_LOG2SIZE) >= MWORD_BITS);

/* create.c */
NTSTATUS PspThreadObjectCreateProc(POBJECT Object);
NTSTATUS PspProcessObjectCreateProc(POBJECT Object);
