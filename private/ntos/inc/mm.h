#pragma once

#include <nt.h>
#include "ntosdef.h"

#ifdef _M_IX86
#include "i386/mm.h"
#elif defined(_M_AMD64)
#include "amd64/mm.h"
#endif

/* Information needed to initialize the Executive Pool */
typedef struct _MM_INIT_INFO_CLASS {
    MWORD InitVSpaceCap;
    MWORD InitUntypedCap;
    LONG InitUntypedLog2Size;
    MWORD RootCNodeCap;
    LONG RootCNodeLog2Size;
    MWORD RootCNodeFreeCapStart;
    LONG RootCNodeFreeCapNumber;
} MM_INIT_INFO_CLASS, *PMM_INIT_INFO_CLASS;

/* Describes the entire CapSpace */
typedef struct _CAPSPACE_DESCRIPTOR {
    MWORD Root;
    struct _CAPSPACE_CNODE_DESCRIPTOR *RootCNode;
} CAPSPACE_DESCRIPTOR, *PCAPSPACE_DESCRIPTOR;

/* Describes a single CNode */
typedef struct _CAPSPACE_CNODE_DESCRIPTOR {
    PCAPSPACE_DESCRIPTOR CapSpace;
    MWORD Log2Size;
    struct _CAPSPACE_CNODE_DESCRIPTOR *FirstChild;
    LIST_ENTRY SiblingList;
    enum { CAPSPACE_TYPE_TAIL_DEALLOC_ONLY, CAPSPACE_TYPE_ALLOW_DEALLOC } Policy;
    union {
	PUCHAR UsedMap;
	struct {
	    MWORD StartCap;  /* Full CPtr to the starting cap */
	    LONG Number;     /* Indicate range [Start,Start+Number) */
	} FreeRange;
    };
} CAPSPACE_CNODE_DESCRIPTOR, *PCAPSPACE_CNODE_DESCRIPTOR;

typedef struct _UNTYPED_DESCRIPTOR {
    PCAPSPACE_DESCRIPTOR CapSpace;
    seL4_Word Cap;
    LONG Log2Size;
    BOOLEAN Split;
} UNTYPED_DESCRIPTOR, *PUNTYPED_DESCRIPTOR;

typedef struct _PAGE_DESCRIPTOR {
    PUNTYPED_DESCRIPTOR Untyped;
    PCAPSPACE_DESCRIPTOR CapSpace;
    MWORD Cap;
    MWORD VSpaceCap;
    MM_PAGE_SIZE PageSize;
    BOOLEAN Mapped;
    MWORD VirtualAddr;
    seL4_CapRights_t Rights;
    seL4_X86_VMAttributes Attributes;
} PAGE_DESCRIPTOR, PPAGE_DESCRIPTOR;

NTSTATUS MmRegisterClass(IN PMM_INIT_INFO_CLASS InitInfo);
NTSTATUS MmRegisterUntyped(IN MWORD Untyped, LONG Log2Size);
NTSTATUS MmRequestUntyped(IN LONG Log2Size, OUT UNTYPED_DESCRIPTOR *Untyped);

#define MM_RIGHTS_RW	(seL4_ReadWrite)
