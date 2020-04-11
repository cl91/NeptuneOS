#pragma once

#include <nt.h>
#include "mm.h"

typedef struct _KTHREAD {
    LIST_ENTRY ThreadListEntry;
} KTHREAD, *PKTHREAD;

typedef struct _KPROCESS {
    PKTHREAD InitThread;
    LIST_ENTRY ThreadList;
} KPROCESS, *PKPROCESS;

typedef struct _EPROCESS {
    KPROCESS Pcb;		/* Must be first entry */
    struct _MM_VADDR_SPACE *VaddrSpace;
} EPROCESS, *PEPROCESS;
