#pragma once

#include <nt.h>
#include "ob.h"

#ifdef CMDBG
#define CmDbg(...)	DbgTrace(__VA_ARGS__)
#define CmDbgPrint(...)	DbgPrint(__VA_ARGS__)
#else
#define CmDbg(...)
#define CmDbgPrint(...)
#endif

#define REGISTRY_OBJECT_DIRECTORY	"\\Registry"

typedef struct _CM_OPEN_CONTEXT {
    IN OB_OPEN_CONTEXT Header;
    IN BOOLEAN Create;
    IN ULONG TitleIndex;
    IN OPTIONAL PCSTR Class;
    IN ULONG CreateOptions;
    OUT OPTIONAL PULONG Disposition;
} CM_OPEN_CONTEXT, *PCM_OPEN_CONTEXT;

/* init.c */
NTSTATUS CmInitSystemPhase1();

/* value.c */
NTSTATUS CmReadKeyValueByPath(IN PCSTR KeyPath,
			      IN PCSTR Value,
			      OUT POBJECT *KeyObject,
			      OUT ULONG *Type,
			      OUT PVOID *Data);
NTSTATUS CmReadKeyValueByPointer(IN POBJECT KeyObject,
				 IN PCSTR Value,
				 OUT ULONG *Type,
				 OUT PVOID *Data);
