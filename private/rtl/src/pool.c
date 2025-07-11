/*
 * This file implements a simple pool that allocates memory from a single
 * contiguous region of pages. It is used by the NT Executive server and
 * the POSIX subsystem dll.
 */

#include <pool.h>

/* Comment this out to enable debug tracing on debug build */
#undef DbgTrace
#define DbgTrace(...)

/* Returns Ceil(x/y) for unsigned integers x and y */
#define RtlDivCeilUnsigned(x,y)	(((x)+(y)-1)/(y))

#if DBG
VOID RtlpAssertPool(IN PCSTR Expr,
		    IN PCSTR File,
		    IN ULONG Line);
#undef assert
#define assert(_Expr)							\
    (void)((!!(_Expr)) || (RtlpAssertPool(#_Expr, __FILE__, __LINE__), 0))
#endif	/* DBG */

/*
 * Get the previous pool block header, if any.
 */
static inline PRTL_POOL_HEADER RtlpGetPrevPoolHeader(IN PRTL_POOL_HEADER Header)
{
    PRTL_POOL_HEADER Prev = NULL;
    if (Header->PreviousSize) {
	Prev = (PRTL_POOL_HEADER)((MWORD)Header - RTL_POOL_OVERHEAD
				 - Header->PreviousSize * RTL_POOL_SMALLEST_BLOCK);
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
static inline PRTL_POOL_HEADER RtlpGetNextPoolHeader(IN PRTL_POOL_HEADER Header)
{
    PRTL_POOL_HEADER Next = (PRTL_POOL_HEADER)((MWORD)Header + RTL_POOL_OVERHEAD +
					     Header->BlockSize * RTL_POOL_SMALLEST_BLOCK);
    if (IS_PAGE_ALIGNED(Next)) {
	return NULL;
    }
    assert(Next->PreviousSize == Header->BlockSize);
    return Next;
}

static inline VOID RtlpDbgDumpPoolHeader(IN PRTL_POOL_HEADER Header)
{
    DbgPrint("  %s %p PS %d BS %d",
	     Header->Used ? "USED" : "FREE", Header,
	     Header->PreviousSize, Header->BlockSize);
}

static inline VOID RtlpDbgDumpPoolPage(IN MWORD Page)
{
    PRTL_POOL_HEADER Header = (PRTL_POOL_HEADER)Page;
    DbgPrint("Pool page %p", (PVOID)Page);
    ULONG Index = 0;
    do {
	if (Index % 4 == 0) {
	    DbgPrint("\n");
	}
	RtlpDbgDumpPoolHeader(Header);
	Header = RtlpGetNextPoolHeader(Header);
	if ((Header != NULL) && (((MWORD)Header - Page) >= PAGE_SIZE)) {
	    DbgPrint("**ERROR**");
	    break;
	}
	Index++;
    } while (Header != NULL);
    DbgPrint("\n");
}

static inline VOID RtlpDbgDumpFreeList(IN PRTL_SMALL_POOL Pool,
				       IN ULONG Index)
{
    DbgPrint("Dumping free list index %d\n", Index);
    LoopOverList(FreeEntry, &Pool->FreeLists[Index], RTL_POOL_BLOCK, FreeListEntry) {
	PRTL_POOL_HEADER Header = RTL_POOL_BLOCK_TO_HEADER(FreeEntry);
	RtlpDbgDumpPoolHeader(Header);
    }
    if (!IsListEmpty(&Pool->FreeLists[Index])) {
	DbgPrint("\n");
    }
}

VOID RtlDbgDumpPool(IN PRTL_SMALL_POOL Pool)
{
    DbgTrace("Dumping RTL_POOL TotalPages 0x%x UsedPages 0x%x HeapStart %p HeapEnd %p\n",
	     Pool->TotalPages, Pool->UsedPages,
	     (PVOID)Pool->HeapStart, (PVOID)Pool->HeapEnd);
    RtlpDbgDumpPoolPage(Pool->HeapStart);
    for (ULONG i = 0; i < RTL_POOL_FREE_LISTS; i++) {
	RtlpDbgDumpFreeList(Pool, i);
    }
}

/* Add the free space to the FreeLists */
static inline VOID RtlpAddFreeSpaceToPool(IN PRTL_SMALL_POOL Pool,
					  IN MWORD Addr,
					  IN USHORT PreviousSize,
					  IN USHORT BlockSize)
{
    DbgTrace("Adding free space %p PS %d BS %d to pool\n", (PVOID)Addr,
	     PreviousSize, BlockSize);
    PRTL_POOL_HEADER PoolHeader = (PRTL_POOL_HEADER)Addr;
    memset(PoolHeader, 0, sizeof(RTL_POOL_HEADER));
    PoolHeader->PreviousSize = PreviousSize;
    PoolHeader->BlockSize = BlockSize;
    PLIST_ENTRY FreeEntry = &RTL_POOL_HEADER_TO_BLOCK(Addr)->FreeListEntry;
    InsertHeadList(&Pool->FreeLists[BlockSize-1], FreeEntry);
}

/* Add the free page to the FreeLists */
static inline VOID RtlpAddPageToFreeLists(IN PRTL_SMALL_POOL Pool,
					  IN MWORD Addr)
{
    RtlpAddFreeSpaceToPool(Pool, Addr, 0, RTL_POOL_FREE_LISTS);
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
 * descriptors. This only matters if the code is part of the NT Executive.
 */
static MWORD RtlpRequestFreePage(IN PRTL_SMALL_POOL Pool,
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
	RtlpAddPageToFreeLists(Pool, PageAddr);
    }

    if (AvailablePages >= 4) {
	/* Still have plenty of free pages. Simply return. */
	return PageAddr;
    }

    /* We are running low on free pages, so we should allocate more before
     * we totally run out. Call the user-supplied function to do so. */
    ULONG Size = RtlPoolAllocateNewPages(Pool);
    if (!Size) {
	return PageAddr;
    }
    assert(IS_ALIGNED_BY(Size, PAGE_SIZE));
    Pool->TotalPages += Size >> PAGE_LOG2SIZE;
    /* Add the newly allocated pages to the free page list. */
    for (MWORD Offset = 0; Offset < Size; Offset += PAGE_SIZE) {
	PRTL_FREE_PAGE FreePage = (PRTL_FREE_PAGE)(Pool->HeapEnd + Offset);
	InsertTailList(&Pool->FreePageList, &FreePage->Link);
    }
    Pool->HeapEnd += Size;
    return PageAddr;
}

/* We require at least 3 consecutive pages mapped at HeapStart */
NTSTATUS RtlInitializeSmallPool(IN PRTL_SMALL_POOL Pool,
				IN MWORD HeapStart,
				IN LONG NumPages)
{
    InitializeListHead(&Pool->FreePageList);
    for (int i = 0; i < RTL_POOL_FREE_LISTS; i++) {
	InitializeListHead(&Pool->FreeLists[i]);
    }

    if (!IS_PAGE_ALIGNED(HeapStart) || NumPages < 3) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Add pages to the pool */
    Pool->TotalPages = NumPages;
    Pool->UsedPages = 1;
    Pool->HeapStart = HeapStart;
    Pool->HeapEnd = HeapStart + NumPages * PAGE_SIZE;
    RtlpAddPageToFreeLists(Pool, HeapStart);

    /* Add the remaining free pages to the free page list */
    for (LONG Page = 1; Page < NumPages; Page++) {
	PRTL_FREE_PAGE FreePage = (PRTL_FREE_PAGE)(HeapStart + PAGE_SIZE * Page);
	InsertTailList(&Pool->FreePageList, &FreePage->Link);
    }

    return STATUS_SUCCESS;
}


/*
 * If the request size is larger than one page, deny the allocation request.
 * If request size is larger than RTL_POOL_LARGEST_BLOCK but no greater than
 * one page, just allocate a whole page. Otherwise, allocate from the free list.
 *
 * Note: memory is cleared before returning.
 */
PVOID RtlAllocateSmallPoolWithTag(IN PRTL_SMALL_POOL Pool,
				  IN MWORD NumberOfBytes,
				  IN ULONG Tag)
{
    DbgTrace("Trying to allocate %zd bytes tag %c%c%c%c\n",
	     NumberOfBytes,
	     RTL_POOL_GET_TAG0(Tag),
	     RTL_POOL_GET_TAG1(Tag),
	     RTL_POOL_GET_TAG2(Tag),
	     RTL_POOL_GET_TAG3(Tag));
    if (NumberOfBytes == 0) {
	return NULL;
    }

    if (NumberOfBytes > RTL_POOL_LARGEST_BLOCK) {
	PVOID Page = (PVOID)RtlpRequestFreePage(Pool, FALSE);
	if (Page) {
	    memset(Page, 0, PAGE_SIZE);
	}
	return Page;
    }

    ULONG NumberOfBlocks = RtlDivCeilUnsigned(NumberOfBytes,
					      RTL_POOL_SMALLEST_BLOCK);
    NumberOfBytes = NumberOfBlocks * RTL_POOL_SMALLEST_BLOCK;
    ULONG FreeListIndex = NumberOfBlocks - 1;

    /* Search FreeLists for available space */
    while (IsListEmpty(&Pool->FreeLists[FreeListIndex])) {
	FreeListIndex++;
	if (FreeListIndex >= RTL_POOL_FREE_LISTS) {
	    break;
	}
    }

    /* If not found, try adding more pages to the pool and try again */
    if (FreeListIndex >= RTL_POOL_FREE_LISTS) {
	/* Request one free page from the list of free pages and add it
	 * to the pool. */
	MWORD PageAddr = RtlpRequestFreePage(Pool, TRUE);
	if (!PageAddr) {
	    return NULL;
	}
	FreeListIndex = NumberOfBlocks - 1;
	while (IsListEmpty(&Pool->FreeLists[FreeListIndex])) {
	    FreeListIndex++;
	    if (FreeListIndex >= RTL_POOL_FREE_LISTS) {
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
    PRTL_POOL_HEADER PoolHeader = RTL_POOL_BLOCK_TO_HEADER(BlockStart);
    DbgTrace("PoolHeader %p PS %d BS %d USED %s\n", PoolHeader,
	     PoolHeader->PreviousSize, PoolHeader->BlockSize,
	     PoolHeader->Used ? "TRUE" : "FALSE");
    assert(!PoolHeader->Used);
    RemoveEntryList(FreeEntry);
    InvalidateListEntry(FreeEntry);
    /* Note this is LONG not ULONG so it can be negative */
    LONG LeftOverBlocks = AvailableBlocks - NumberOfBlocks - 1;
    if (LeftOverBlocks > 0) {
	PRTL_POOL_HEADER Next = RtlpGetNextPoolHeader(PoolHeader);
	PoolHeader->BlockSize = NumberOfBlocks;
	RtlpAddFreeSpaceToPool(Pool, BlockStart + NumberOfBytes,
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
 * Free the given pointer from the given pool, assert if consistency was not
 * maintained (this includes the case where the tag does not match and the case
 * where internal data structure consistency has not been maintained).
 *
 * Since we check the Used bit of the block header and clear the memory on every
 * free, double free will result in an assertion.
 */
VOID RtlFreeSmallPoolWithTag(IN PRTL_SMALL_POOL Pool,
			     IN PCVOID Ptr,
			     IN ULONG Tag)
{
    /* If the pointer is page aligned, simpy add it to the list of free pages. */
    if (IS_PAGE_ALIGNED(Ptr)) {
	PRTL_FREE_PAGE Page = (PRTL_FREE_PAGE)Ptr;
	InsertHeadList(&Pool->FreePageList, &Page->Link);
	Pool->UsedPages--;
	return;
    }

    DbgTrace("Freeing %p tag %c%c%c%c\n", Ptr,
	     RTL_POOL_GET_TAG0(Tag),
	     RTL_POOL_GET_TAG1(Tag),
	     RTL_POOL_GET_TAG2(Tag),
	     RTL_POOL_GET_TAG3(Tag));
    PRTL_POOL_HEADER Header = RTL_POOL_BLOCK_TO_HEADER(Ptr);
    assert(Header->Used);
    /* Check if tag is correct */
    assert(Header->Tag == Tag);
    DbgTrace("Header %p PS %d BS %d\n", Header, Header->PreviousSize, Header->BlockSize);
    PRTL_POOL_HEADER Prev = RtlpGetPrevPoolHeader(Header);
    DbgTrace("Prev %p PS %d BS %d\n", Prev, Prev ? Prev->PreviousSize : 0,
	     Prev ? Prev->BlockSize : 0);
    PRTL_POOL_HEADER Next = RtlpGetNextPoolHeader(Header);
    DbgTrace("Next %p PS %d BS %d\n", Next, Next ? Next->PreviousSize : 0,
	     Next ? Next->BlockSize : 0);
    /* We also need to update the next block after Next in the case where we merge
     * the current free block with Next. */
    PRTL_POOL_HEADER NextNext = Next ? RtlpGetNextPoolHeader(Next) : NULL;
    DbgTrace("NextNext %p PS %d BS %d\n", NextNext,
	     NextNext ? NextNext->PreviousSize : 0,
	     NextNext ? NextNext->BlockSize : 0);
    /* If the previous block is free, merge it with the current block */
    if (Prev != NULL && !Prev->Used) {
	DbgTrace("Merging with Prev\n");
	RemoveEntryList(&RTL_POOL_HEADER_TO_BLOCK(Prev)->FreeListEntry);
	Prev->BlockSize += 1 + Header->BlockSize;
	Header = Prev;
	if (Next != NULL) {
	    Next->PreviousSize = Header->BlockSize;
	}
    }
    /* If the next block is free, merge it with the current block */
    if (Next != NULL && !Next->Used) {
	DbgTrace("Merging with Next\n");
	RemoveEntryList(&RTL_POOL_HEADER_TO_BLOCK(Next)->FreeListEntry);
	Header->BlockSize += 1 + Next->BlockSize;
	if (NextNext != NULL) {
	    NextNext->PreviousSize = Header->BlockSize;
	}
    }
    /* Clear the memory of the block */
    DbgTrace("clearing memory %p size 0x%llx\n", RTL_POOL_HEADER_TO_BLOCK(Header),
	     Header->BlockSize * RTL_POOL_SMALLEST_BLOCK);
    memset(RTL_POOL_HEADER_TO_BLOCK(Header), 0, Header->BlockSize * RTL_POOL_SMALLEST_BLOCK);
    /* Insert the block to the free list */
    Header->Used = FALSE;
    PLIST_ENTRY FreeEntry = &RTL_POOL_HEADER_TO_BLOCK(Header)->FreeListEntry;
    assert(Header->BlockSize <= RTL_POOL_FREE_LISTS);
    InsertHeadList(&Pool->FreeLists[Header->BlockSize - 1], FreeEntry);
    DbgTrace("Prev %p PS %d BS %d Header %p PS %d BS %d Next %p PS %d BS %d NextNext %p PS %d BS %d\n",
	     Prev, Prev ? Prev->PreviousSize : 0, Prev ? Prev->BlockSize : 0,
	     Header, Header ? Header->PreviousSize : 0, Header ? Header->BlockSize : 0,
	     Next, Next ? Next->PreviousSize : 0, Next ? Next->BlockSize : 0,
	     NextNext, NextNext ? NextNext->PreviousSize : 0,
	     NextNext ? NextNext->BlockSize : 0);
}
