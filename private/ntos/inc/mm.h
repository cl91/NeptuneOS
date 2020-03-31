#pragma once

#include <nt.h>
#include <sel4/sel4.h>

typedef struct _CAPSPACE_DESCRIPTOR {
    seL4_Word Root;
    seL4_Word Log2Size;
    LONG TotalLevels;		/* Total levels of sub-spaces */
    struct {
	LIST_ENTRY ListEntry;
	seL4_Word Start;
	LONG Number;		/* Indicate range [Start,Start+Number) */
    } FreeList;
} CAPSPACE_DESCRIPTOR, *PCAPSPACE_DESCRIPTOR;

typedef struct _UNTYPED_DESCRIPTOR {
    PCAPSPACE_DESCRIPTOR CapSpace;
    seL4_Word Cap;
    LONG Log2Size;
    BOOLEAN Split;
} UNTYPED_DESCRIPTOR, *PUNTYPED_DESCRIPTOR;

NTSTATUS MmCapSpaceAllocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
			    OUT seL4_Word *CapStart,
			    IN LONG NumberRequested);
NTSTATUS MmCapSpaceDeallocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
			      IN seL4_Word CapStart,
			      IN LONG NumberRequested);

NTSTATUS MmSplitUntyped(IN PUNTYPED_DESCRIPTOR SrcUntyped,
			OUT PUNTYPED_DESCRIPTOR DestUntyped1,
			OUT PUNTYPED_DESCRIPTOR DestUntyped2);
