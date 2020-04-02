#pragma once

#include <nt.h>
#include "ntosdef.h"

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
    LONG Log2Size;
    BOOLEAN Mapped;
    MWORD VirtualAddr;
    seL4_CapRights_t Rights;
    seL4_X86_VMAttributes Attributes;
} PAGE_DESCRIPTOR, PPAGE_DESCRIPTOR;

NTSTATUS MmCapSpaceAllocCaps(IN PCAPSPACE_DESCRIPTOR CapSpace,
			     OUT MWORD *StartCap,
			     IN LONG NumberRequested);
NTSTATUS MmCapSpaceDeallocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
			      IN MWORD Cap);

static inline NTSTATUS
MmCapSpaceAllocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
		   OUT MWORD *Cap)
{
    return MmCapSpaceAllocCaps(CapSpace, Cap, 1);
}

NTSTATUS MmSplitUntyped(IN PUNTYPED_DESCRIPTOR SrcUntyped,
			OUT PUNTYPED_DESCRIPTOR DestUntyped1,
			OUT PUNTYPED_DESCRIPTOR DestUntyped2);

NTSTATUS MmMapTopLevelPage(PPAGE_DESCRIPTOR Page);
