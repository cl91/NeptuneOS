#pragma once

/* Uncomment this to turn on debugging outputs specific to Ob */
/* #define OBDBG */

#include <ntos.h>

#define NTOS_OB_TAG	(EX_POOL_TAG('n', 't', 'o', 'b'))

#define ObpAllocatePoolEx(Var, Type, Size, OnError)		\
    ExAllocatePoolEx(Var, Type, Size, NTOS_OB_TAG, OnError)

#define ObpAllocatePool(Var, Type)				\
    ObpAllocatePoolEx(Var, Type, sizeof(Type), {})

#define ObpFreePool(Var) ExFreePoolWithTag(Var, NTOS_OB_TAG)

#define OBP_DIROBJ_HASH_BUCKETS 37
typedef struct _OBJECT_DIRECTORY {
    LIST_ENTRY HashBuckets[OBP_DIROBJ_HASH_BUCKETS];
    PIO_FILE_OBJECT FileObject;
} OBJECT_DIRECTORY;

typedef struct _OBJECT_DIRECTORY_ENTRY {
    LIST_ENTRY ChainLink;
    POBJECT Object;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

extern LIST_ENTRY ObpObjectList;
extern POBJECT_DIRECTORY ObpRootObjectDirectory;

/* dirobj.c */
NTSTATUS ObpInitDirectoryObjectType();
