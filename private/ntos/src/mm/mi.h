#pragma once

#include <nt.h>
#include <ntos.h>

NTSTATUS MiCapSpaceAllocCaps(IN PMM_CAPSPACE CapSpace,
			     OUT MWORD *StartCap,
			     IN LONG NumberRequested);
NTSTATUS MiCapSpaceDeallocCap(IN PMM_CAPSPACE CapSpace,
			      IN MWORD Cap);

static inline NTSTATUS
MiCapSpaceAllocCap(IN PMM_CAPSPACE CapSpace,
		   OUT MWORD *Cap)
{
    return MiCapSpaceAllocCaps(CapSpace, Cap, 1);
}

NTSTATUS MiSplitUntyped(IN PMM_UNTYPED SrcUntyped,
			OUT PMM_UNTYPED DestUntyped1,
			OUT PMM_UNTYPED DestUntyped2);

NTSTATUS MiMapPagingStructure(PMM_PAGING_STRUCTURE Page);
