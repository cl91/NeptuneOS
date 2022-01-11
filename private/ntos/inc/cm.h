#pragma once

#include <nt.h>
#include "ob.h"

#define REGISTRY_OBJECT_DIRECTORY	"\\Registry"

typedef struct _CM_OPEN_CONTEXT {
    IN OB_PARSE_CONTEXT Header;
    IN BOOLEAN Create;
    IN ULONG TitleIndex;
    IN OPTIONAL PCSTR Class;
    IN ULONG CreateOptions;
    IN OPTIONAL PULONG Disposition;
} CM_OPEN_CONTEXT, *PCM_OPEN_CONTEXT;

/* init.c */
NTSTATUS CmInitSystemPhase1();
