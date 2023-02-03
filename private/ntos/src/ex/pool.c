/* Comment this out to enable debug tracing on debug build */
#ifndef NDEBUG
#define NDEBUG
#endif

#include "ei.h"

/* Returns Ceil(x/y) for unsigned integers x and y */
#define RtlDivCeilUnsigned(x,y)	(((x)+(y)-1)/(y))

static VOID EiAssertPool(IN PCSTR Expr,
			 IN PCSTR File,
			 IN ULONG Line);

/*
 * For ExPool we always enforce the assertions even in release build.
 */
#undef assert
#define assert(_Expr)							\
    (void)((!!(_Expr)) || (EiAssertPool(#_Expr, __FILE__, __LINE__), 0))

static EX_POOL EiPool;

/*
 * Get the previous pool block header, if any.
 */
static inline PEX_POOL_HEADER EiGetPrevPoolHeader(IN PEX_POOL_HEADER Header)
{
    PEX_POOL_HEADER Prev = NULL;
    if (Header->PreviousSize) {
	Prev = (PEX_POOL_HEADER)((MWORD)Header - EX_POOL_OVERHEAD
				 - Header->PreviousSize * EX_POOL_SMALLEST_BLOCK);
	assert(Prev->BlockSize == Header->PreviousSize);
    }
    return Prev;
}

/*
 * Get the next pool block header.
 *
 * Note since we always allocate blocks within a page, if a block ends on page
 * boundary it is the last block within this page. In this case we return NULL.
 */
static inline PEX_POOL_HEADER EiGetNextPoolHeader(IN PEX_POOL_HEADER Header)
{
    PEX_POOL_HEADER Next = (PEX_POOL_HEADER)((MWORD)Header + EX_POOL_OVERHEAD +
					     Header->BlockSize * EX_POOL_SMALLEST_BLOCK);
    if (IS_PAGE_ALIGNED(Next)) {
	return NULL;
    }
    assert(Next->PreviousSize == Header->BlockSize);
    return Next;
}

static inline VOID EiDbgDumpPoolHeader(IN PEX_POOL_HEADER Header)
{
    DbgPrint("  %s %p PS %d BS %d",
	     Header->Used ? "USED" : "FREE", Header,
	     Header->PreviousSize, Header->BlockSize);
}

static inline VOID EiDbgDumpPoolPage(IN MWORD Page)
{
    PEX_POOL_HEADER Header = (PEX_POOL_HEADER)Page;
    DbgPrint("Pool page %p", (PVOID)Page);
    ULONG Index = 0;
    do {
	if (Index % 4 == 0) {
	    DbgPrint("\n");
	}
	EiDbgDumpPoolHeader(Header);
	Header = EiGetNextPoolHeader(Header);
	if ((Header != NULL) && (((MWORD)Header - Page) >= PAGE_SIZE)) {
	    DbgPrint("**ERROR**");
	    break;
	}
	Index++;
    } while (Header != NULL);
    DbgPrint("\n");
}

static inline VOID EiDbgDumpFreeList(IN ULONG Index)
{
    DbgPrint("Dumping free list index %d\n", Index);
    LoopOverList(FreeEntry, &EiPool.FreeLists[Index], EX_POOL_BLOCK, FreeListEntry) {
	PEX_POOL_HEADER Header = EX_POOL_BLOCK_TO_HEADER(FreeEntry);
	EiDbgDumpPoolHeader(Header);
    }
    if (!IsListEmpty(&EiPool.FreeLists[Index])) {
	DbgPrint("\n");
    }
}

static VOID EiDbgDumpPool()
{
    DbgTrace("Dumping EX_POOL TotalPages 0x%x UsedPages 0x%x HeapStart %p HeapEnd %p\n",
	     EiPool.TotalPages, EiPool.UsedPages, (PVOID)EiPool.HeapStart, (PVOID)EiPool.HeapEnd);
    for (ULONG i = 0; i < EiPool.UsedPages; i++) {
	EiDbgDumpPoolPage(EiPool.HeapStart + i * PAGE_SIZE);
    }
    for (ULONG i = 0; i < EX_POOL_FREE_LISTS; i++) {
	EiDbgDumpFreeList(i);
    }
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-address"
static VOID EiAssertPool(IN PCSTR Expr,
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
	EiDbgDumpPool();
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

/* Add the free page to the FreeLists */
static inline VOID EiAddFreeSpaceToPool(IN PEX_POOL Pool,
					IN MWORD Addr,
					IN USHORT PreviousSize,
					IN USHORT BlockSize)
{
    DbgTrace("Adding free space %p PS %d BS %d to pool\n", (PVOID)Addr,
	     PreviousSize, BlockSize);
    /* Make sure PoolHeader->Used is not set. */
    assert(*((PPVOID)Addr) == 0);
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) Addr;
    PoolHeader->PreviousSize = PreviousSize;
    PoolHeader->BlockSize = BlockSize;
    PLIST_ENTRY FreeEntry = &EX_POOL_HEADER_TO_BLOCK(Addr)->FreeListEntry;
    InsertHeadList(&Pool->FreeLists[BlockSize-1], FreeEntry);
}

/* Add the free page to the FreeLists */
static inline VOID EiAddPageToPool(IN PEX_POOL Pool,
				   IN MWORD Addr)
{
#if DBG
    /* seL4 should give us clean pages so we should never get dirty data here.
     * On debug build we generate an assertion if this has not been enforced. */
    for (PPVOID p = (PPVOID)Addr; (MWORD)p < Addr + PAGE_SIZE; p++) {
	assert(*p == 0);
    }
#endif
    EiAddFreeSpaceToPool(Pool, Addr, 0, EX_POOL_FREE_LISTS);
}

/* We require at least 3 consecutive 4K pages mapped at EX_POOL_START */
NTSTATUS ExInitializePool(IN MWORD HeapStart,
			  IN LONG NumPages)
{
    /* Initialize FreeLists */
    for (int i = 0; i < EX_POOL_FREE_LISTS; i++) {
	InitializeListHead(&EiPool.FreeLists[i]);
    }

    if ((HeapStart & (PAGE_SIZE-1)) != 0 || NumPages < 3) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Add pages to pool */
    EiPool.TotalPages = NumPages;
    EiPool.UsedPages = 1;
    EiPool.HeapStart = HeapStart;
    EiPool.HeapEnd = HeapStart + PAGE_SIZE;
    EiAddPageToPool(&EiPool, HeapStart);

    return STATUS_SUCCESS;
}

/* Examine the number of available pages in the pool and optionally
 * request the memory management subcomponent for more pages.
 *
 * Returns TRUE if successfully added page(s) to ExPool. Returns
 * FALSE if unable to request more pool pages from mm.
 *
 * If we have more than two pages in the pool, simply add one page
 * to the FreeLists.
 *
 * If there is only one page left, add it to the pool and request mm
 * for more pages. The reason for adding the last page is that mm
 * may need to allocate in order to build the capability derivation tree
 * and paging structure descriptors.
 *
 * If pool is initialized with at least 3 pages, then the amount of
 * available pages never goes below one, assuming there is free untyped
 * memory available.
 */
static BOOLEAN EiRequestPoolPage(IN PEX_POOL Pool)
{
    LONG AvailablePages = Pool->TotalPages - Pool->UsedPages;
    if (AvailablePages >= 1) {
	/* Add one page to the pool */
	Pool->UsedPages++;
	EiAddPageToPool(Pool, Pool->HeapEnd);
	Pool->HeapEnd += PAGE_SIZE;
	if (AvailablePages >= 4) {
	    /* Plenty of resources here. Simply return */
	    return TRUE;
	} else {
	    /* We are running low on resources. Check if we have run out of ExPool
	     * virtual space first, and then request more pages from mm. */
	    if (Pool->HeapEnd >= EX_POOL_END) {
		return FALSE;
	    }
	    MM_MEM_PRESSURE MemPressure = MmQueryMemoryPressure();
	    LONG Size = PAGE_SIZE;
	    if (MemPressure == MM_MEM_PRESSURE_SUFFICIENT_MEMORY) {
		Size = LARGE_PAGE_SIZE;
	    } else if (MemPressure == MM_MEM_PRESSURE_LOW_MEMORY) {
		Size = 4 * PAGE_SIZE;
	    } /* Otherwise we are critically low on memory, just get one page only */
	    /* Make sure we don't run over the end of ExPool space. */
	    if (Pool->HeapEnd + Size >= EX_POOL_END) {
		Size = EX_POOL_END - Pool->HeapEnd;
	    }
	    NTSTATUS Status = MmCommitVirtualMemory(Pool->HeapEnd, Size);
	    if (!NT_SUCCESS(Status)) {
		return FALSE;
	    }
	    Pool->TotalPages += Size >> PAGE_LOG2SIZE;
	}
    }
    return TRUE;
}

/* If request size > EX_POOL_LARGEST_BLOCK, deny request
 * Else, allocate from the free list, and clear the memory.
 * If no more space in free list, request one more page.
 */
static PVOID EiAllocatePoolWithTag(IN PEX_POOL Pool,
				   IN MWORD NumberOfBytes,
				   IN ULONG Tag)
{
    DbgTrace("Trying to allocate %zd bytes tag %c%c%c%c\n",
	     NumberOfBytes,
	     EX_POOL_GET_TAG0(Tag),
	     EX_POOL_GET_TAG1(Tag),
	     EX_POOL_GET_TAG2(Tag),
	     EX_POOL_GET_TAG3(Tag));
    if (NumberOfBytes == 0) {
	return NULL;
    }

    if (NumberOfBytes > EX_POOL_LARGEST_BLOCK) {
	return NULL;
    }

    ULONG NumberOfBlocks = RtlDivCeilUnsigned(NumberOfBytes, EX_POOL_SMALLEST_BLOCK);
    NumberOfBytes = NumberOfBlocks * EX_POOL_SMALLEST_BLOCK;
    ULONG FreeListIndex = NumberOfBlocks - 1;

    /* Search FreeLists for available space */
    while (IsListEmpty(&Pool->FreeLists[FreeListIndex])) {
	FreeListIndex++;
	if (FreeListIndex >= EX_POOL_FREE_LISTS) {
	    break;
	}
    }

    /* If not found, try adding more pages to the pool and try again */
    if (FreeListIndex >= EX_POOL_FREE_LISTS) {
	if (!EiRequestPoolPage(Pool)) {
	    return NULL;
	}
	FreeListIndex = NumberOfBlocks - 1;
	while (IsListEmpty(&Pool->FreeLists[FreeListIndex])) {
	    FreeListIndex++;
	    if (FreeListIndex >= EX_POOL_FREE_LISTS) {
		/* Still not enough resource, we are out of memory */
		return NULL;
	    }
	}
    }

    LONG AvailableBlocks = FreeListIndex + 1;
    PLIST_ENTRY FreeEntry = Pool->FreeLists[FreeListIndex].Flink;
    MWORD BlockStart = (MWORD) FreeEntry;
    PEX_POOL_HEADER PoolHeader = EX_POOL_BLOCK_TO_HEADER(BlockStart);
    DbgTrace("PoolHeader %p PS %d BS %d USED %s\n", PoolHeader,
	     PoolHeader->PreviousSize, PoolHeader->BlockSize,
	     PoolHeader->Used ? "TRUE" : "FALSE");
    assert(!PoolHeader->Used);
    RemoveEntryList(FreeEntry);
    InvalidateListEntry(FreeEntry);
    /* Note this is LONG not ULONG so it can be negative */
    LONG LeftOverBlocks = AvailableBlocks - NumberOfBlocks - 1;
    if (LeftOverBlocks > 0) {
	PEX_POOL_HEADER Next = EiGetNextPoolHeader(PoolHeader);
	PoolHeader->BlockSize = NumberOfBlocks;
	EiAddFreeSpaceToPool(Pool, BlockStart+NumberOfBytes, NumberOfBlocks, LeftOverBlocks);
	if (Next != NULL) {
	    Next->PreviousSize = LeftOverBlocks;
	}
    } else {
	PoolHeader->BlockSize = AvailableBlocks;
    }
    PoolHeader->Used = TRUE;
    PoolHeader->Tag = Tag;

#if DBG
    /* ExFreePoolWithTag always clears the memory so we should never get dirty data here.
     * On debug build we generate an assertion if this has not been enforced.
     * If this assertion is triggered it means that either ExPool has a bug or
     * someone is still accessing this data after it has been freed. */
    for (ULONG i = 0; i < NumberOfBytes; i++) {
	if (((PCHAR)BlockStart)[i]) {
	    DbgTrace("block start %p block size %d tag %c%c%c%c addr %p "
		     "data 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
		     (PVOID)BlockStart, PoolHeader->BlockSize,
		     EX_POOL_GET_TAG0(Tag),
		     EX_POOL_GET_TAG1(Tag),
		     EX_POOL_GET_TAG2(Tag),
		     EX_POOL_GET_TAG3(Tag),
		     &((PCHAR)BlockStart)[i],
		     ((PUCHAR)BlockStart)[i],
		     ((PUCHAR)BlockStart)[i+1],
		     ((PUCHAR)BlockStart)[i+2],
		     ((PUCHAR)BlockStart)[i+3],
		     ((PUCHAR)BlockStart)[i+4],
		     ((PUCHAR)BlockStart)[i+5],
		     ((PUCHAR)BlockStart)[i+6],
		     ((PUCHAR)BlockStart)[i+7]);
	}
	assert(((PCHAR)BlockStart)[i] == 0);
    }
#else
    /* On release build we simply clean the memory */
    memset((PVOID)BlockStart, 0, NumberOfBytes);
#endif
    DbgTrace("Allocated block start %p PS %d BS %d\n",
	     (PVOID)BlockStart, PoolHeader->PreviousSize, PoolHeader->BlockSize);
    return (PVOID) BlockStart;
}

/*
 * Free the given pointer from the given pool, bug-check if consistency was not
 * maintained (this includes the case where the tag does not match and the case
 * where internal data structure consistency has not been maintained).
 *
 * Since we check the Used bit of the block header and clear the memory on every
 * free, double free will result in a bug-check.
 */
static VOID EiFreePoolWithTag(IN PEX_POOL Pool,
			      IN PCVOID Ptr,
			      IN ULONG Tag)
{
    assert(Pool != NULL);
    assert(Ptr != NULL);
    DbgTrace("Freeing %p tag %c%c%c%c\n", Ptr,
	     EX_POOL_GET_TAG0(Tag),
	     EX_POOL_GET_TAG1(Tag),
	     EX_POOL_GET_TAG2(Tag),
	     EX_POOL_GET_TAG3(Tag));
    PEX_POOL_HEADER Header = EX_POOL_BLOCK_TO_HEADER(Ptr);
    assert(Header->Used);
    /* Check if tag is correct */
    assert(Header->Tag == Tag);
    DbgTrace("Header %p PS %d BS %d\n", Header, Header->PreviousSize, Header->BlockSize);
    PEX_POOL_HEADER Prev = EiGetPrevPoolHeader(Header);
    DbgTrace("Prev %p PS %d BS %d\n", Prev, Prev ? Prev->PreviousSize : 0,
	     Prev ? Prev->BlockSize : 0);
    PEX_POOL_HEADER Next = EiGetNextPoolHeader(Header);
    DbgTrace("Next %p PS %d BS %d\n", Next, Next ? Next->PreviousSize : 0,
	     Next ? Next->BlockSize : 0);
    /* We also need to update the next block after Next in the case where we merge
     * the current free block with Next. */
    PEX_POOL_HEADER NextNext = Next ? EiGetNextPoolHeader(Next) : NULL;
    DbgTrace("NextNext %p PS %d BS %d\n", NextNext,
	     NextNext ? NextNext->PreviousSize : 0,
	     NextNext ? NextNext->BlockSize : 0);
    /* If the previous block is free, merge it with the current block */
    if (Prev != NULL && !Prev->Used) {
	DbgTrace("Merging with Prev\n");
	RemoveEntryList(&EX_POOL_HEADER_TO_BLOCK(Prev)->FreeListEntry);
	Prev->BlockSize += 1 + Header->BlockSize;
	Header = Prev;
	if (Next != NULL) {
	    Next->PreviousSize = Header->BlockSize;
	}
    }
    /* If the next block is free, merge it with the current block */
    if (Next != NULL && !Next->Used) {
	DbgTrace("Merging with Next\n");
	RemoveEntryList(&EX_POOL_HEADER_TO_BLOCK(Next)->FreeListEntry);
	Header->BlockSize += 1 + Next->BlockSize;
	if (NextNext != NULL) {
	    NextNext->PreviousSize = Header->BlockSize;
	}
    }
    /* Clear the memory of the block */
    DbgTrace("clearing memory %p size 0x%llx\n", EX_POOL_HEADER_TO_BLOCK(Header),
	     Header->BlockSize * EX_POOL_SMALLEST_BLOCK);
    memset(EX_POOL_HEADER_TO_BLOCK(Header), 0, Header->BlockSize * EX_POOL_SMALLEST_BLOCK);
    /* Insert the block to the free list */
    Header->Used = FALSE;
    PLIST_ENTRY FreeEntry = &EX_POOL_HEADER_TO_BLOCK(Header)->FreeListEntry;
    assert(Header->BlockSize <= EX_POOL_FREE_LISTS);
    InsertHeadList(&Pool->FreeLists[Header->BlockSize - 1], FreeEntry);
    DbgTrace("Prev %p PS %d BS %d Header %p PS %d BS %d Next %p PS %d BS %d NextNext %p PS %d BS %d\n",
	     Prev, Prev ? Prev->PreviousSize : 0, Prev ? Prev->BlockSize : 0,
	     Header, Header ? Header->PreviousSize : 0, Header ? Header->BlockSize : 0,
	     Next, Next ? Next->PreviousSize : 0, Next ? Next->BlockSize : 0,
	     NextNext, NextNext ? NextNext->PreviousSize : 0,
	     NextNext ? NextNext->BlockSize : 0);
}

/*
 * Note: on successful allocation, allocated memory is always zeroed.
 */
PVOID ExAllocatePoolWithTag(IN MWORD NumberOfBytes,
			    IN ULONG Tag)
{
    return EiAllocatePoolWithTag(&EiPool, NumberOfBytes, Tag);
}

VOID ExFreePoolWithTag(IN PCVOID Ptr,
		       IN ULONG Tag)
{
    EiFreePoolWithTag(&EiPool, Ptr, Tag);
}
