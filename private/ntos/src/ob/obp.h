#pragma once

#include <ntos.h>

/* Change this to 0 to enable debug tracing */
#if 1
#define DbgPrint(...)
#endif

#define NTOS_OB_TAG	(EX_POOL_TAG('n', 't', 'o', 'b'))

#define ObpAllocatePoolEx(Var, Type, Size, OnError)		\
    ExAllocatePoolEx(Var, Type, Size, NTOS_OB_TAG, OnError)

#define ObpAllocatePool(Var, Type)				\
    ObpAllocatePoolEx(Var, Type, sizeof(Type), {})

#define OBP_DIROBJ_HASH_BUCKETS 37
typedef struct _OBJECT_DIRECTORY {
    LIST_ENTRY HashBuckets[OBP_DIROBJ_HASH_BUCKETS];
} OBJECT_DIRECTORY;

typedef struct _OBJECT_DIRECTORY_ENTRY {
    LIST_ENTRY ChainLink;
    PCSTR Name;	   /* Owned by this struct, allocated on the expool */
    POBJECT Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

extern LIST_ENTRY ObpObjectList;
extern POBJECT_DIRECTORY ObpRootObjectDirectory;

static inline void ObpReferenceObjectHeader(POBJECT_HEADER ObjectHeader)
{
    ObjectHeader->RefCount++;
}

static inline void ObpReferenceObject(POBJECT Object)
{
    ObpReferenceObjectHeader(OBJECT_TO_OBJECT_HEADER(Object));
}

/* dirobj.c */
NTSTATUS ObpInitDirectoryObjectType();

/* obref.c */
VOID ObpDeleteObject(IN POBJECT_HEADER ObjectHeader);

/* open.c */
NTSTATUS ObpLookupObjectName(IN PCSTR Path,
			     IN POB_PARSE_CONTEXT ParseContext,
			     OUT PCSTR *pRemainingPath,
			     OUT POBJECT *FoundObject);
