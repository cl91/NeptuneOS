/*++

Copyright (c) 2077  Definitely-Not-Micro$oft Corporation

Module Name:

    cap.c

Abstract:

    Capability space and CNode management

    The basic design here is to have a large initial root
    CNode as the CSpace of the root task, which contains
    all the seL4 kernel objects being managed. The size of the
    initial root CNode is specified at compile time by the
    cmake option KernelRootCNodeSizeBits. Assuming the main
    source of cnode slot usage is from page management (for
    each virtual address space, all mapped pages need their
    own capabilities since sharing pages require duplicating
    page capabilities), for each 4K page we assess four slots
    on x32 and one slot on x64 (since x64 is more likely to
    use large pages often), and determine the initial cnode
    size from the typical memory sizes for each architecture.
    This is 256MB for x32 and 4G for x64. Users with larger
    or smaller RAM should adjust the numbers accordingly.

    Each process will have a CSpace with only a single level
    of CNode, namely the root CNode of the CSpace. The NTOS
    root task has a large root CNode (with, say 2^16 slots),
    since all capabilities to kernel objects are stored in
    the NTOS CSpace. These include all TCBs, all pages, and
    all untyped caps. Client processes will have a much smaller
    root CNode (of order, say 16 slots), since we only store
    the relevant per-process endpoint capabilities there.

    Each CNode has a bitmap to keep track of the slot usage.
    Allocation and deallocation of a cap slot modify the
    corresponding bit in the bitmap. To speed up free bit
    lookup we keep a pointer to the most recently freed bit.

Revision History:

    2021-07-16  Revised the design to use a large root CNode
                for the root task CSpace and a small CNode
                for each client process.

--*/

#include "mi.h"

/* Allocate a continuous range of capability slots */
NTSTATUS MmAllocateCapRangeEx(IN PMM_CNODE CNode,
			      OUT MWORD *StartCap,
			      IN LONG NumberRequested)
{
    assert(CNode != NULL);
    assert(StartCap != NULL);
    *StartCap = 0;

    ULONG CNodeSize = 1 << CNode->Log2Size;
    if (CNode->TotalUsed >= CNodeSize) {
	return STATUS_NTOS_CAPSPACE_EXHAUSTION;
    }

    /* Starting from the RecentFree bit, search for
     * consecutive free slots of the required number.
     * If Index exceeds CNodeSize, wrap back to 0. */
    ULONG Index = CNode->RecentFree;
    ULONG MaxIndex = CNodeSize + CNode->RecentFree;

Lookup:
    /* Skip the bits that are used */
    while (Index < MaxIndex) {
	if (!GetBit(CNode->UsedMap, Index % CNodeSize)) {
	    break;
	}
	Index++;
    }
    /* We don't have enough free slots */
    if (Index >= MaxIndex) {
	return STATUS_NTOS_CAPSPACE_EXHAUSTION;
    }
    /* Check whether the next (NumberRequested-1) bits are
     * free (the bit pointed by Index is already free) */
    for (ULONG i = 1; i < NumberRequested; i++) {
	Index++;
	if (GetBit(CNode->UsedMap, Index % CNodeSize)) {
	    /* Not enough consecutive free bits here, go back */
	    goto Lookup;
	}
    }
    /* We found enough free slots. Index now points to the last bit
     * in the consecutive free slots. However, it might be the case
     * that Index % CNodeSize has wrapped back to zero while the index
     * to the first bit (Index-NumberRequested+1) has not, and the
     * slots are not actually consecutive. Go back in this case. */
    if ((Index-NumberRequested+1) < CNodeSize && Index >= CNodeSize) {
	goto Lookup;
    }
    /* We found enough free slots that are actually consecutive.
     * Mark them as used and return them to the user. */
    CNode->TotalUsed += NumberRequested;
    *StartCap = (Index-NumberRequested+1) % CNodeSize;
    for (ULONG i = Index-NumberRequested+1; i <= Index; i++) {
	assert(!GetBit(CNode->UsedMap, i)); /* Bug if asserted. */
	SetBit(CNode->UsedMap, i);
    }
    /* To speed up lookup, we advance the RecentFree to point to
     * the bit after Index, since the old RecentFree no longer
     * points to a free bit. */
    CNode->RecentFree = (Index+1) % CNodeSize;

    return STATUS_SUCCESS;
}

/* Mark the capability slot of the given CNode as free */
NTSTATUS MmDeallocateCapEx(IN PMM_CNODE CNode,
			   IN MWORD Cap)
{
    assert(CNode != NULL);
    assert(Cap < (1 << CNode->Log2Size));
    assert(CNode->UsedMap != NULL);
    assert(GetBit(CNode->UsedMap, Cap) == TRUE);
    assert(Cap != 0);		/* Freeing the null cap is a bug. */

    ClearBit(CNode->UsedMap, Cap);
    CNode->RecentFree = Cap;
    CNode->TotalUsed++;
    
    return STATUS_SUCCESS;
}
