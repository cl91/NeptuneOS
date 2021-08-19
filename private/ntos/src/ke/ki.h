#pragma once

#include <ntos.h>
#include <sel4/sel4.h>

#define KiAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_KE_TAG, OnError)
#define KiAllocatePool(Var, Type)	KiAllocatePoolEx(Var, Type, {})
#define KiAllocateArray(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_KE_TAG, OnError)

VOID KiInitVga();
NTSTATUS KiCreateSystemServicesEndpoint();
VOID KiDispatchSystemServices();
