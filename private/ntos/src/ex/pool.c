#include <ntos.h>

static RTL_SMALL_POOL EiSmallPool;

#if DBG
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
VOID RtlpAssertPool(IN PCSTR Expr,
		    IN PCSTR File,
		    IN ULONG Line)
{
    static BOOLEAN FirstTime = TRUE;
    DbgPrint("Fatal error: assertion %s at %s:%d failed\n"
	     "Callstack: %p %p %p %p\n",
	     Expr, File, Line,
	     __builtin_return_address(1),
	     __builtin_return_address(2),
	     __builtin_return_address(3),
	     __builtin_return_address(4));
    if (FirstTime) {
	FirstTime = FALSE;
	RtlDbgDumpPool(&EiSmallPool);
    }
    KeBugCheckMsg("Fatal error: assertion %s at %s:%d failed\n"
		  "Callstack: %p %p %p %p\n",
		  Expr, File, Line,
		  __builtin_return_address(1),
		  __builtin_return_address(2),
		  __builtin_return_address(3),
		  __builtin_return_address(4));
}
#pragma GCC diagnostic pop
#endif	/* DBG */

NTSTATUS ExInitializePool(IN MWORD HeapStart,
			  IN LONG NumPages)
{
    return RtlInitializeSmallPool(&EiSmallPool, HeapStart, NumPages);
}

ULONG RtlPoolAllocateNewPages(IN PRTL_SMALL_POOL Pool)
{
    /* Check if we have enough ExPool virtual space first, before we
     * request more pages from mm. */
    if (Pool->HeapEnd >= EX_POOL_END) {
	return 0;
    }
    /* If we are already asking Mm for more memory, make sure we don't
     * make concurrent requests. */
    static BOOLEAN AllocationInProgress = FALSE;
    if (AllocationInProgress) {
	return 0;
    }
    AllocationInProgress = TRUE;
    LONG Size = PAGE_SIZE;
    MM_MEM_PRESSURE MemPressure = MmQueryMemoryPressure();
    if (MemPressure == MM_MEM_PRESSURE_SUFFICIENT_MEMORY) {
	Size = LARGE_PAGE_SIZE;
    } else if (MemPressure == MM_MEM_PRESSURE_LOW_MEMORY) {
	Size = 4 * PAGE_SIZE;
	/* Otherwise we are critically low on memory, just get one page */
    }
    /* Make sure we don't run over the end of ExPool space. */
    if (Pool->HeapEnd + Size >= EX_POOL_END) {
	Size = EX_POOL_END - Pool->HeapEnd;
    }
    NTSTATUS Status = MmCommitVirtualMemory(Pool->HeapEnd, Size);
    if (!NT_SUCCESS(Status)) {
	/* If we tried to request more than one page, try again with only
	 * one page instead. */
	if (Size != PAGE_SIZE) {
	    Size = PAGE_SIZE;
	    Status = MmCommitVirtualMemory(Pool->HeapEnd, Size);
	    if (!NT_SUCCESS(Status)) {
		AllocationInProgress = FALSE;
		return 0;
	    }
	} else {
	    AllocationInProgress = FALSE;
	    return 0;
	}
    }
    AllocationInProgress = FALSE;
    return Size;
}

static PVOID EiAllocateFromLargePool(IN MWORD NumberOfBytes)
{
    assert(NumberOfBytes > PAGE_SIZE);
    PMMVAD Vad = NULL;
    NTSTATUS Status = MmReserveVirtualMemory(EX_LARGE_POOL_START, EX_LARGE_POOL_END,
					     NumberOfBytes, 0,
					     MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES,
					     &Vad);
    if (!NT_SUCCESS(Status)) {
	return NULL;
    }
    Status = MmCommitVirtualMemory(Vad->AvlNode.Key, Vad->WindowSize);
    if (!NT_SUCCESS(Status)) {
	MmUnmapServerRegion(Vad->AvlNode.Key);
	return NULL;
    }
    return (PVOID)Vad->AvlNode.Key;
}

/*
 * If request size is larger than the page size, allocate from the large
 * object pool. Otherwise allocate from the small object pool.
 *
 * Note: on successful allocation, allocated memory is always zeroed.
 */
PVOID ExAllocatePoolWithTag(IN MWORD NumberOfBytes, IN ULONG Tag)
{
    if (NumberOfBytes > PAGE_SIZE) {
	return EiAllocateFromLargePool(NumberOfBytes);
    }

    return RtlAllocateSmallPoolWithTag(&EiSmallPool, NumberOfBytes, Tag);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
VOID ExFreePoolWithTag(IN PCVOID Ptr, IN ULONG Tag)
{
    assert(Ptr != NULL);
    if ((MWORD)Ptr >= EX_LARGE_POOL_START && (MWORD)Ptr < EX_LARGE_POOL_END) {
	if (!IS_PAGE_ALIGNED(Ptr)) {
	    KeBugCheckMsg("ExPool: Freeing unaligned object %p. Call stack: %p %p %p %p %p %p\n",
			  Ptr, __builtin_return_address(0), __builtin_return_address(1),
			  __builtin_return_address(2), __builtin_return_address(3),
			  __builtin_return_address(4), __builtin_return_address(5));
	}
	MmUnmapServerRegion((MWORD)Ptr);
	return;
    }

    if ((MWORD)Ptr <= EiSmallPool.HeapStart || (MWORD)Ptr >= EiSmallPool.HeapEnd) {
	KeBugCheckMsg("ExPool: Freeing invalid pointer %p. Call stack: %p %p %p %p %p %p\n",
		      Ptr, __builtin_return_address(0), __builtin_return_address(1),
		      __builtin_return_address(2), __builtin_return_address(3),
		      __builtin_return_address(4), __builtin_return_address(5));
    }

    if (!IS_PAGE_ALIGNED(Ptr)) {
	PRTL_POOL_HEADER Header = RTL_POOL_BLOCK_TO_HEADER(Ptr);
	assert(Header->Used);
	/* Check if tag is correct */
	if (Header->Tag != Tag) {
	    KeBugCheckMsg("ExPool: Freeing %p with invalid tag. Expected 0x%08x, "
			  "got 0x%08x. Call stack: %p %p %p %p %p %p\n",
			  Ptr, Header->Tag, Tag,
			  __builtin_return_address(0), __builtin_return_address(1),
			  __builtin_return_address(2), __builtin_return_address(3),
			  __builtin_return_address(4), __builtin_return_address(5));
	}
    }

    RtlFreeSmallPoolWithTag(&EiSmallPool, Ptr, Tag);
}
#pragma GCC diagnostic pop

/* Check if tag is correct */
BOOLEAN ExCheckPoolObjectTag(IN PCVOID Ptr, IN ULONG Tag)
{
    PRTL_POOL_HEADER Header = RTL_POOL_BLOCK_TO_HEADER(Ptr);
    assert(Header->Used);
    return Header->Used && Header->Tag == Tag;
}
