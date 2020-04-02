#include <ntos.h>

/* Allocate a continuous range of capability slots */
NTSTATUS MiCNodeAllocCaps(IN PCAPSPACE_CNODE_DESCRIPTOR CNode,
			  OUT MWORD *StartCap,
			  IN LONG NumberRequested)
{
    if (CNode->Policy == CAPSPACE_TYPE_TAIL_DEALLOC_ONLY) {
	if (CNode->FreeRange.Number < NumberRequested) {
	    return STATUS_NTOS_EXEC_CAPSPACE_EXHAUSTION;
	}
	*StartCap = CNode->FreeRange.StartCap;
	CNode->FreeRange.StartCap += NumberRequested;
	CNode->FreeRange.Number -= NumberRequested;
    } else {			/* CAPSPACE_TYPE_ALLOW_DEALLOC */
	/* Todo: Implement logic */
    }
    return STATUS_SUCCESS;
}

/* Perform a depth-first search of all free cap slots
 * Check first child first, then current cnode, then all other children.
 */
NTSTATUS MiCNodeAllocCapsRecursive(IN PCAPSPACE_CNODE_DESCRIPTOR CNode,
				   OUT MWORD *StartCap,
				   IN LONG NumberRequested)
{
    if (CNode->FirstChild != NULL) {
	LONG NumberSatisfiedFirstChild = 0;
	if (NT_SUCCESS(MiCNodeAllocCapsRecursive(CNode->FirstChild, StartCap, NumberRequested))) {
	    return STATUS_SUCCESS;
	}
    }

    if (NT_SUCCESS(MiCNodeAllocCaps(CNode, StartCap, NumberRequested))) {
	return STATUS_SUCCESS;
    }

    if (CNode->FirstChild != NULL) {
	PLIST_ENTRY SiblingListEntry = CNode->FirstChild->SiblingList.Flink;
	while (SiblingListEntry != &CNode->FirstChild->SiblingList) {
	    PCAPSPACE_CNODE_DESCRIPTOR Sibling = CONTAINING_RECORD(SiblingListEntry,
								   CAPSPACE_CNODE_DESCRIPTOR,
								   SiblingList);
	    if (NT_SUCCESS(MiCNodeAllocCapsRecursive(Sibling, StartCap, NumberRequested))) {
		return STATUS_SUCCESS;
	    }
	}
    }

    return STATUS_NTOS_EXEC_CAPSPACE_EXHAUSTION;
}

NTSTATUS MiCNodeDeallocCap(IN PCAPSPACE_CNODE_DESCRIPTOR CNode,
			   IN MWORD Cap)
{
    if (CNode->Policy == CAPSPACE_TYPE_TAIL_DEALLOC_ONLY) {
	if (CNode->FreeRange.StartCap == Cap) {
	    /* Check StartCap-- stays within the CNode */
	    CNode->FreeRange.StartCap--;
	    CNode->FreeRange.Number++;
	} else {
	    return STATUS_NTOS_EXEC_INVALID_ARGUMENT;
	}
    } else {			/* CAPSPACE_TYPE_ALLOW_DEALLOC */
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmCapSpaceAllocCaps(IN PCAPSPACE_DESCRIPTOR CapSpace,
			     OUT MWORD *StartCap,
			     IN LONG NumberRequested)
{
    return MiCNodeAllocCapsRecursive(CapSpace->RootCNode, StartCap, NumberRequested);
}

/* Dealloc caps in reverse order, ie. dealloc Caps[NumberRequested-1] first
 * and Caps[0] last
 */
NTSTATUS MmCapSpaceDeallocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
			      IN MWORD Cap)
{
    /* Fixme: Find the right cnode to operate on */
    return MiCNodeDeallocCap(CapSpace->RootCNode, Cap);
}
