#include "ei.h"

/* Comment this out to enable debug tracing on debug build */
#undef DbgTrace
#define DbgTrace(...)

/* Returns Ceil(x/y) for unsigned integers x and y */
#define RtlDivCeilUnsigned(x,y)	(((x)+(y)-1)/(y))

#if DBG
static VOID EiAssertPool(IN PCSTR Expr,
			 IN PCSTR File,
			 IN ULONG Line);
#undef assert
#define assert(_Expr)							\
    (void)((!!(_Expr)) || (EiAssertPool(#_Expr, __FILE__, __LINE__), 0))
#endif	/* DBG */

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
    EiDbgDumpPoolPage(EiPool.HeapStart);
    for (ULONG i = 0; i < EX_POOL_FREE_LISTS; i++) {
	EiDbgDumpFreeList(i);
    }
}

#if DBG
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
#endif	/* DBG */

/* Add the free space to the FreeLists */
static inline VOID EiAddFreeSpaceToPool(IN PEX_POOL Pool,
					IN MWORD Addr,
					IN USHORT PreviousSize,
					IN USHORT BlockSize)
{
    DbgTrace("Adding free space %p PS %d BS %d to pool\n", (PVOID)Addr,
	     PreviousSize, BlockSize);
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER)Addr;
    memset(PoolHeader, 0, sizeof(EX_POOL_HEADER));
    PoolHeader->PreviousSize = PreviousSize;
    PoolHeader->BlockSize = BlockSize;
    PLIST_ENTRY FreeEntry = &EX_POOL_HEADER_TO_BLOCK(Addr)->FreeListEntry;
    InsertHeadList(&Pool->FreeLists[BlockSize-1], FreeEntry);
}

/* Add the free page to the FreeLists */
static inline VOID EiAddPageToFreeLists(IN PEX_POOL Pool,
					IN MWORD Addr)
{
    EiAddFreeSpaceToPool(Pool, Addr, 0, EX_POOL_FREE_LISTS);
}

/* We require at least 3 consecutive pages mapped at EX_POOL_START */
NTSTATUS ExInitializePool(IN MWORD HeapStart,
			  IN LONG NumPages)
{
    InitializeListHead(&EiPool.FreePageList);
    for (int i = 0; i < EX_POOL_FREE_LISTS; i++) {
	InitializeListHead(&EiPool.FreeLists[i]);
    }

    if (!IS_PAGE_ALIGNED(HeapStart) || NumPages < 3) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Add pages to the pool */
    EiPool.TotalPages = NumPages;
    EiPool.UsedPages = 1;
    EiPool.HeapStart = HeapStart;
    EiPool.HeapEnd = HeapStart + NumPages * PAGE_SIZE;
    EiAddPageToFreeLists(&EiPool, HeapStart);

    /* Add the remaining free pages to the free page list */
    for (LONG Page = 1; Page < NumPages; Page++) {
	PEX_FREE_PAGE FreePage = (PEX_FREE_PAGE)(HeapStart + PAGE_SIZE * Page);
	InsertTailList(&EiPool.FreePageList, &FreePage->Link);
    }

    return STATUS_SUCCESS;
}

/*
 * Request one page from the list of free pages, returning the
 * starting address of the page. If the number of free pages goes
 * too low, request the memory management subcomponent for more pages.
 *
 * If AddToFreeLists is TRUE, we will also add the newly-allocated free
 * page to the FreeLists. This needs to be done before we call Mm to
 * commit new pages because Mm will need to allocate pool memory in
 * order to build the capability derivation tree and paging structure
 * descriptors.
 */
static MWORD EiRequestFreePage(IN PEX_POOL Pool,
			       IN BOOLEAN AddToFreeLists)
{
    LONG AvailablePages = Pool->TotalPages - Pool->UsedPages;
    assert(AvailablePages >= 0);
    assert(AvailablePages == GetListLength(&Pool->FreePageList));
    if (AvailablePages < 1) {
	return 0;
    }

    /* Detach the first free page in the list of free pages. */
    assert(!IsListEmpty(&Pool->FreePageList));
    MWORD PageAddr = (MWORD)Pool->FreePageList.Flink;
    RemoveHeadList(&Pool->FreePageList);
    Pool->UsedPages++;
    AvailablePages--;
    if (AddToFreeLists) {
	EiAddPageToFreeLists(Pool, PageAddr);
    }

    if (AvailablePages >= 4) {
	/* Still have plenty of free pages. Simply return. */
	return PageAddr;
    }

    /* We are running low on free pages, so we should allocate more
     * before we totally run out. Check if we have enough ExPool
     * virtual space first, and then request more pages from mm. */
    if (Pool->HeapEnd >= EX_POOL_END) {
	return PageAddr;
    }
    /* If we are already asking Mm for more memory, make sure we don't
     * make concurrent requests. */
    static BOOLEAN AllocationInProgress = FALSE;
    if (AllocationInProgress) {
	return PageAddr;
    }
    AllocationInProgress = TRUE;
    MM_MEM_PRESSURE MemPressure = MmQueryMemoryPressure();
    LONG Size = PAGE_SIZE;
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
		return PageAddr;
	    }
	} else {
	    AllocationInProgress = FALSE;
	    return PageAddr;
	}
    }
    Pool->TotalPages += Size >> PAGE_LOG2SIZE;
    /* Add the newly allocated pages to the free page list. */
    for (MWORD Offset = 0; Offset < Size; Offset += PAGE_SIZE) {
	PEX_FREE_PAGE FreePage = (PEX_FREE_PAGE)(Pool->HeapEnd + Offset);
	InsertTailList(&Pool->FreePageList, &FreePage->Link);
    }
    Pool->HeapEnd += Size;
    AllocationInProgress = FALSE;
    return PageAddr;
}

/* If request size is larger than the page size, deny request.
 * If request size is larger than EX_POOL_LARGEST_BLOCK, just
 * allocate a whole page. Otherwise, allocate from the free list.
 * Memory is cleared before returning.
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

    if (NumberOfBytes > PAGE_SIZE) {
	return NULL;
    }

    if (NumberOfBytes > EX_POOL_LARGEST_BLOCK) {
	PVOID Page = (PVOID)EiRequestFreePage(Pool, FALSE);
	if (Page) {
	    memset(Page, 0, PAGE_SIZE);
	}
	return Page;
    }

    ULONG NumberOfBlocks = RtlDivCeilUnsigned(NumberOfBytes,
					      EX_POOL_SMALLEST_BLOCK);
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
	/* Request one free page from the list of free pages and add it
	 * to the pool. */
	MWORD PageAddr = EiRequestFreePage(Pool, TRUE);
	if (!PageAddr) {
	    return NULL;
	}
	FreeListIndex = NumberOfBlocks - 1;
	while (IsListEmpty(&Pool->FreeLists[FreeListIndex])) {
	    FreeListIndex++;
	    if (FreeListIndex >= EX_POOL_FREE_LISTS) {
		/* When requesting for more free pages, MmCommitVirtualMemory
		 * might have done too many allocations to exhaust the free
		 * lists again. If this happens, there is really nothing we
		 * could do, so just return failure. */
		return NULL;
	    }
	}
    }

    LONG AvailableBlocks = FreeListIndex + 1;
    PLIST_ENTRY FreeEntry = Pool->FreeLists[FreeListIndex].Flink;
    MWORD BlockStart = (MWORD)FreeEntry;
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
	EiAddFreeSpaceToPool(Pool, BlockStart + NumberOfBytes,
			     NumberOfBlocks, LeftOverBlocks);
	if (Next != NULL) {
	    Next->PreviousSize = LeftOverBlocks;
	}
    } else {
	PoolHeader->BlockSize = AvailableBlocks;
    }
    PoolHeader->Used = TRUE;
    PoolHeader->Tag = Tag;

    memset((PVOID)BlockStart, 0, NumberOfBytes);
    DbgTrace("Allocated block start %p PS %d BS %d\n",
	     (PVOID)BlockStart, PoolHeader->PreviousSize, PoolHeader->BlockSize);
    return (PVOID)BlockStart;
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
    /* If the pointer is page aligned, simpy add it to the list of free pages. */
    if (IS_PAGE_ALIGNED(Ptr)) {
	PEX_FREE_PAGE Page = (PEX_FREE_PAGE)Ptr;
	InsertHeadList(&Pool->FreePageList, &Page->Link);
	Pool->UsedPages--;
	return;
    }

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
