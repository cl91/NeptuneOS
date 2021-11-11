#pragma once

#include <nt.h>
#include <ntos.h>

#define IopAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_IO_TAG, OnError)
#define IopAllocatePool(Var, Type)	IopAllocatePoolEx(Var, Type, {})
#define IopAllocateArrayEx(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_IO_TAG, OnError)
#define IopAllocateArray(Var, Type, Size)	\
    IopAllocateArrayEx(Var, Type, Size, {})

/* init.c */
PSECTION IopHalDllSection;

/* file.c */
NTSTATUS IopFileObjectInitProc(POBJECT Object);
NTSTATUS IopFileObjectOpenProc(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN POBJECT Object,
			       OUT POBJECT *pOpenedInstance);

/* device.c */
NTSTATUS IopDeviceObjectInitProc(POBJECT Object);

/* driver.c */
NTSTATUS IopDriverObjectInitProc(POBJECT Object);
