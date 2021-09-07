#pragma once

#include <ntos.h>

#define NTOS_LDR_BOOT_TAG	(EX_POOL_TAG('L', 'D', 'R', 'B'))

#define LdrpAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_LDR_BOOT_TAG, OnError)
#define LdrpAllocatePool(Var, Type)	LdrpAllocatePoolEx(Var, Type, {})
#define LdrpAllocateArray(Var, Type, Size)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_LDR_BOOT_TAG, {})
