/* Capability space and CNode management */

#include "mi.h"

/* Allocate a continuous range of capability slots */
static NTSTATUS MiCNodeAllocCaps(IN PMM_CNODE CNode,
				 OUT MWORD *StartCap,
				 IN LONG NumberRequested)
{
    if (CNode->Policy == MM_CNODE_TAIL_DEALLOC_ONLY) {
	if (CNode->FreeRange.Number < NumberRequested) {
	    return STATUS_NTOS_CAPSPACE_EXHAUSTION;
	}
	*StartCap = CNode->FreeRange.StartCap;
	CNode->FreeRange.StartCap += NumberRequested;
	CNode->FreeRange.Number -= NumberRequested;
    } else {			/* CAPSPACE_TYPE_ALLOW_DEALLOC */
	/* Todo: Implement logic */
    }
    return STATUS_SUCCESS;
}

/* Perform a depth-first search of free (continuous) cap slots
 * Check first child first, then current cnode, then all other children.
 */
static NTSTATUS MiCNodeAllocCapsRecursive(IN PMM_CNODE CNode,
					  OUT MWORD *StartCap,
					  IN LONG NumberRequested)
{
    if (CNode->FirstChild != NULL) {
	if (NT_SUCCESS(MiCNodeAllocCapsRecursive(CNode->FirstChild, StartCap, NumberRequested))) {
	    return STATUS_SUCCESS;
	}
    }

    if (NT_SUCCESS(MiCNodeAllocCaps(CNode, StartCap, NumberRequested))) {
	return STATUS_SUCCESS;
    }

    if (CNode->FirstChild != NULL) {
	LoopOverList(Sibling, &CNode->FirstChild->SiblingList, MM_CNODE, SiblingList) {
	    if (NT_SUCCESS(MiCNodeAllocCapsRecursive(Sibling, StartCap, NumberRequested))) {
		return STATUS_SUCCESS;
	    }
	}
    }

    return STATUS_NTOS_CAPSPACE_EXHAUSTION;
}

static NTSTATUS MiCNodeDeallocCap(IN PMM_CNODE CNode,
				  IN MWORD Cap)
{
    if (CNode->Policy == MM_CNODE_TAIL_DEALLOC_ONLY) {
	if (CNode->FreeRange.StartCap == Cap) {
	    /* Check StartCap-- stays within the CNode */
	    CNode->FreeRange.StartCap--;
	    CNode->FreeRange.Number++;
	} else {
	    return STATUS_NTOS_INVALID_ARGUMENT;
	}
    } else {			/* CAPSPACE_TYPE_ALLOW_DEALLOC */
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MiCapSpaceAllocCaps(IN PMM_CAPSPACE CapSpace,
				    OUT MWORD *StartCap,
				    IN LONG NumberRequested)
{
    return MiCNodeAllocCapsRecursive(CapSpace->RootCNode, StartCap, NumberRequested);
}

/* Dealloc caps in reverse order, ie. dealloc Caps[NumberRequested-1] first
 * and Caps[0] last
 */
static NTSTATUS MiCapSpaceDeallocCap(IN PMM_CAPSPACE CapSpace,
				     IN MWORD Cap)
{
    /* Fixme: Find the right cnode to operate on */
    return MiCNodeDeallocCap(CapSpace->RootCNode, Cap);
}

NTSTATUS MmAllocateCaps(OUT MWORD *StartCap,
			IN LONG NumberRequested)
{
    return MiCapSpaceAllocCaps(&MiNtosCapSpace, StartCap, NumberRequested);
}

NTSTATUS MmAllocateCap(OUT MWORD *Cap)
{
    return MmAllocateCaps(Cap, 1);
}

NTSTATUS MmDeallocateCap(IN MWORD Cap)
{
    return MiCapSpaceDeallocCap(&MiNtosCapSpace, Cap);
}

MWORD MmRootCspaceCap()
{
    return MiNtosCapSpace.RootCap;
}
