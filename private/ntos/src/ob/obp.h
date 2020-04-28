#pragma once

#include <ntos.h>

#define NTOS_OB_TAG	(EX_POOL_TAG('n', 't', 'o', 'b'))

#define ObpAllocatePool(Var, Type)					\
    Type *Var = (Type *)ExAllocatePoolWithTag(sizeof(Type), NTOS_OB_TAG); \
    if ((Var) == NULL) { return STATUS_NTOS_OUT_OF_MEMORY; }
