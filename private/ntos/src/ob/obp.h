#pragma once

#include <ntos.h>

#define NTOS_OB_TAG	(EX_POOL_TAG('n', 't', 'o', 'b'))

#define ObpAllocatePoolEx(Var, Type, Size, OnError)		\
    ExAllocatePoolEx(Var, Type, Size, NTOS_OB_TAG, OnError)

#define ObpAllocatePool(Var, Type)				\
    ObpAllocatePoolEx(Var, Type, sizeof(Type), {})

typedef struct _OBJECT_DIRECTORY_ENTRY {
    LIST_ENTRY ChainLink;
    PCSTR Name;	   /* Owned by this struct, allocated on the expool */
    POBJECT_HEADER Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

extern LIST_ENTRY ObpObjectList;
extern POBJECT_DIRECTORY ObpRootObjectDirectory;

static inline void ObpReferenceObject(POBJECT_HEADER ObjectHeader)
{
    ObjectHeader->RefCount++;
}

/* dirobj.c */
NTSTATUS ObpInitDirectoryObjectType();
NTSTATUS ObpLookupObjectName(IN PCSTR Path,
			     OUT POBJECT_HEADER *FoundObject);
