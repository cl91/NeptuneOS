#include <ntos.h>

NTSTATUS MmCapSpaceAllocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
			    OUT seL4_Word *CapStart,
			    IN LONG NumberRequested)
{
    /* TODO: Complete logic */
    if (CapSpace->FreeList.Number < NumberRequested) {
	return STATUS_NTOS_EXEC_CAPSPACE_EXHAUSTION;
    }
    *CapStart = CapSpace->FreeList.Start;
    CapSpace->FreeList.Start += NumberRequested;
    CapSpace->FreeList.Number -= NumberRequested;
    return STATUS_SUCCESS;
}

NTSTATUS MmCapSpaceDeallocCap(IN PCAPSPACE_DESCRIPTOR CapSpace,
			      IN seL4_Word CapStart,
			      IN LONG NumberRequested)
{
    /* TODO: Complete logic */
    if (CapSpace->FreeList.Start != CapStart + NumberRequested) {
	return STATUS_NTOS_EXEC_INVALID_ARGUMENT;
    }
    CapSpace->FreeList.Start -= NumberRequested;
    return STATUS_SUCCESS;
}
