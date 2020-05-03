#pragma once

#include <ntos.h>
#include <ntimage.h>

#define PspAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_PS_TAG); \
    if ((Var) == NULL) { return STATUS_NTOS_OUT_OF_MEMORY; }

/* create.c */
NTSTATUS PspThreadObjectCreateProc(PVOID Object);
NTSTATUS PspProcessObjectCreateProc(PVOID Object);
