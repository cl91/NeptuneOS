#pragma once

#include <nt.h>
#include <ntos.h>

#define IopAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_IO_TAG, OnError)
#define IopAllocatePool(Var, Type)	IopAllocatePoolEx(Var, Type, {})
#define IopAllocateArray(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_IO_TAG, OnError)

/* init.c */
PSECTION IopHalDllSection;

/* create.c */
NTSTATUS IopFileObjectCreateProc(POBJECT Object);

/* open.c */
NTSTATUS IopFileObjectOpenProc(POBJECT Object);
