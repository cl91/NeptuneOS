#pragma once

#include <ntos.h>
#include <ntimage.h>

#define PspAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_PS_TAG); \
    if ((Var) == NULL) { return STATUS_NO_MEMORY; }

/* arch/context.c */
VOID PspInitializeThreadContext(IN PTHREAD Thread,
				IN PTHREAD_CONTEXT Context);

/* create.c */
NTSTATUS PspThreadObjectCreateProc(POBJECT Object);
NTSTATUS PspProcessObjectCreateProc(POBJECT Object);

/* init.c */
extern LIST_ENTRY PspProcessList;
extern PSECTION PspSystemDllSection;
extern PSUBSECTION PspSystemDllTlsSubsection;
