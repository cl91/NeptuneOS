#pragma once

#include <ntos.h>

#define NTOS_OB_TAG	(EX_POOL_TAG('n', 't', 'o', 'b'))

#define ObpAllocatePoolEx(Var, Type, Size, OnError)		\
    ExAllocatePoolEx(Var, Type, Size, NTOS_OB_TAG, OnError)

#define ObpAllocatePool(Var, Type)				\
    ObpAllocatePoolEx(Var, Type, sizeof(Type), {})

#define ObpFreePool(Var) ExFreePoolWithTag(Var, NTOS_OB_TAG)

extern LIST_ENTRY ObpObjectList;
extern POBJECT_DIRECTORY ObpRootObjectDirectory;

/* dirobj.c */
NTSTATUS ObpInitDirectoryObjectType();

/* open.c */
NTSTATUS ObpParseObjectByName(IN POBJECT DirectoryObject,
			      IN PCSTR Path,
			      IN BOOLEAN CaseInsensitive,
			      OUT POBJECT *FoundObject,
			      OUT PCSTR *RemainingPath,
			      OUT PCSTR *StringToFree);

/* symlink.c */
NTSTATUS ObpInitSymlinkObjectType();
