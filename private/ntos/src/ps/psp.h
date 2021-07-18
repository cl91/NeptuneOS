#pragma once

#include <ntos.h>
#include <ntimage.h>

#define PspAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_PS_TAG); \
    if ((Var) == NULL) { return STATUS_NO_MEMORY; }

#define PROCESS_INIT_CNODE_LOG2SIZE	4

/* create.c */
NTSTATUS PspThreadObjectCreateProc(PVOID Object);
NTSTATUS PspProcessObjectCreateProc(PVOID Object);
