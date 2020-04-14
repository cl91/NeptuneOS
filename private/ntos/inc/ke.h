#pragma once

#include <nt.h>

typedef struct _KTHREAD {
    LIST_ENTRY ThreadListEntry;
} KTHREAD, *PKTHREAD;

typedef struct _KPROCESS {
    PKTHREAD InitThread;
    LIST_ENTRY ThreadList;
} KPROCESS, *PKPROCESS;
