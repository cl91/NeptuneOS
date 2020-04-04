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

NTSTATUS MiMapLargePage(PPAGE_DESCRIPTOR Page);
