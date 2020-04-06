#pragma once

#include <nt.h>
#include <ntos.h>

NTSTATUS MiCapSpaceAllocCaps(IN PCAPSPACE_DESCRIPTOR CapSpace,
			     OUT MWORD *StartCap,
			     IN LONG NumberRequested);
NTSTATUS MiCapSpaceDeallocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
			      IN MWORD Cap);

static inline NTSTATUS
MiCapSpaceAllocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
		   OUT MWORD *Cap)
{
    return MiCapSpaceAllocCaps(CapSpace, Cap, 1);
}

NTSTATUS MiSplitUntyped(IN PUNTYPED_DESCRIPTOR SrcUntyped,
			OUT PUNTYPED_DESCRIPTOR DestUntyped1,
			OUT PUNTYPED_DESCRIPTOR DestUntyped2);

typedef enum _MM_PAGING_STRUCTURE_TYPE { MM_PAGE,
					 MM_LARGE_PAGE,
					 MM_PAGE_TABLE,
} MM_PAGING_STRUCTURE_TYPE;

typedef struct _PAGING_STRUCTURE_DESCRIPTOR {
    PUNTYPED_DESCRIPTOR Untyped;
    PCAPSPACE_DESCRIPTOR CapSpace;
    MWORD Cap;
    MWORD VSpaceCap;
    MM_PAGING_STRUCTURE_TYPE Type;
    BOOLEAN Mapped;
    MWORD VirtualAddr;
    seL4_CapRights_t Rights;
    seL4_X86_VMAttributes Attributes;
} PAGING_STRUCTURE_DESCRIPTOR, PPAGING_STRUCTURE_DESCRIPTOR;

NTSTATUS MiMapPagingStructure(PPAGING_STRUCTURE_DESCRIPTOR Page);
