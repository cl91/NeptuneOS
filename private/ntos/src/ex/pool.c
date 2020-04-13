#include <nt.h>
#include <ntos.h>

#define POOL_DATA_TAG	EX_POOL_TAG('p', 'o', 'o', 'l')

static EX_POOL EiGlobalPool;

static PVOID EiAllocatePoolWithTag(IN PEX_POOL Pool,
				   IN ULONG NumberOfBytes,
				   IN ULONG Tag);

static NTSTATUS EiInitializePool(PEX_POOL Pool,
				 PMM_PAGING_STRUCTURE Page)
{
    InitializeListHead(&Pool->ManagedPageRangeList);
    InitializeListHead(&Pool->UnmanagedPageRangeList);
    InitializeListHead(&Pool->FreePageRangeList);
    for (int i = 0; i < EX_POOL_FREE_LISTS; i++) {
	InitializeListHead(&Pool->FreeLists[i]);
    }

    /* Add page to pool */
    if (Page->Type == MM_PAGE_TYPE_PAGE) {
	Pool->TotalPages = 1;
	Pool->HeapEnd = Page->VirtualAddr + EX_PAGE_SIZE;
    } else if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	ULONG TotalPages = 1 << (EX_LARGE_PAGE_BITS - EX_PAGE_BITS);
	Pool->TotalPages = TotalPages;
	Pool->HeapEnd = Page->VirtualAddr + EX_LARGE_PAGE_SIZE;
    } else {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    /* Add free space to FreeLists */
    ULONG FreeListIndex = EX_POOL_FREE_LISTS - 1;
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) Page->VirtualAddr;
    MWORD FreeEntryStart = Page->VirtualAddr + EX_POOL_OVERHEAD;
    PLIST_ENTRY FreeEntry = (PLIST_ENTRY) FreeEntryStart;
    PoolHeader->PreviousSize = 0;
    PoolHeader->BlockSize = EX_POOL_LARGEST_BLOCK / EX_POOL_SMALLEST_BLOCK;
    InsertHeadList(&Pool->FreeLists[FreeListIndex], FreeEntry);

    /* Allocate maintenance structure and add to pool lists */
    PEX_POOL_PAGE_RANGE ManagedPages = (PEX_POOL_PAGE_RANGE)
	EiAllocatePoolWithTag(Pool, sizeof(EX_POOL_PAGE_RANGE), POOL_DATA_TAG);
    assert(ManagedPages != NULL);
    ManagedPages->FirstPageNum = Page->VirtualAddr >> EX_PAGE_BITS;
    ManagedPages->NumPages = 1;
    InsertHeadList(&Pool->ManagedPageRangeList, &ManagedPages->ListEntry);
    if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	PEX_POOL_PAGE_RANGE FreePages = (PEX_POOL_PAGE_RANGE)
	    EiAllocatePoolWithTag(Pool, sizeof(EX_POOL_PAGE_RANGE), POOL_DATA_TAG);
	assert(FreePages != NULL);
	FreePages->FirstPageNum = (Page->VirtualAddr >> EX_PAGE_BITS) + 1;
	FreePages->NumPages = (1 << (EX_LARGE_PAGE_BITS - EX_PAGE_BITS)) - 1;
	InsertHeadList(&Pool->FreePageRangeList, &FreePages->ListEntry);
    }

    return STATUS_SUCCESS;
}

NTSTATUS ExInitializePool(IN PMM_PAGING_STRUCTURE Page)
{
    return EiInitializePool(&EiGlobalPool, Page);
}

/* Returns the starting page number of the range of pages requested
 * Guaranteed to return exactly NumPages contiguous pages
 * Returns 0 if unable to satisfy request
 */
static MWORD EiRequestPoolPages(IN PEX_POOL Pool,
				IN ULONG NumPages)
{
    /* First look for contiguous pages in the free pages list */
    LoopOverList(Pages, &Pool->FreePageRangeList, EX_POOL_PAGE_RANGE, ListEntry) {
	if (Pages->NumPages >= NumPages) {
	    MWORD PageNum = Pages->FirstPageNum;
	    Pages->FirstPageNum += NumPages;
	    Pages->NumPages -= NumPages;
	    if (Pages->NumPages == 0) {
		RemoveEntryList(&Pages->ListEntry);
	    }
	    return PageNum;
	}
    }

    /* TODO: Request page from mm */
    return 0;
}

static PEX_POOL_PAGE_RANGE EiPoolFindPrevPageRange(PLIST_ENTRY ListHead,
						   MWORD FirstPageNum)
{
    ReverseLoopOverList(Pages, ListHead, EX_POOL_PAGE_RANGE, ListEntry) {
	if (Pages->FirstPageNum <= FirstPageNum) {
	    return Pages;
	}
    }
    return NULL;
}

/* If request size > EX_POOL_LARGEST_BLOCK, return pages
 * Else, allocate from the free list.
 * If no more space in free list, request one more page
 * Each managed page is headed by EX_POOL_PAGE
 */
static PVOID EiAllocatePoolWithTag(IN PEX_POOL Pool,
				   IN ULONG NumberOfBytes,
				   IN ULONG Tag)
{
    if (NumberOfBytes == 0) {
	return NULL;
    }

    if (NumberOfBytes > EX_POOL_LARGEST_BLOCK) {
	MWORD NumPages = RtlDivCeilUnsigned(NumberOfBytes, EX_PAGE_SIZE);
	MWORD PageNum = EiRequestPoolPages(Pool, NumPages);
	if (PageNum == 0) {
	    return NULL;
	} else {
	    /* Add pages to unmanaged list */
	    PEX_POOL_PAGE_RANGE PrevPageRange = EiPoolFindPrevPageRange(&Pool->UnmanagedPageRangeList,
									PageNum);
	    if (PrevPageRange != NULL && PrevPageRange->FirstPageNum + PrevPageRange->NumPages == PageNum) {
		PrevPageRange->NumPages += NumPages;
	    } else {
		PEX_POOL_PAGE_RANGE PageRange = (PEX_POOL_PAGE_RANGE)
		    EiAllocatePoolWithTag(Pool, sizeof(EX_POOL_PAGE_RANGE), POOL_DATA_TAG);
		if (PageRange == NULL) {
		    //EiFreePoolPages(Pool, PageNum, NumPages);
		    return NULL;
		}
		PageRange->FirstPageNum = PageNum;
		PageRange->NumPages = NumPages;
		if (PrevPageRange == NULL) {
		    InsertTailList(&Pool->UnmanagedPageRangeList, &PageRange->ListEntry);
		} else {
		    InsertHeadList(&PrevPageRange->ListEntry, &PageRange->ListEntry);
		}
	    }
	    return (PVOID) (PageNum << EX_PAGE_BITS);
	}
    }

    ULONG NumberOfBlocks = RtlDivCeilUnsigned(NumberOfBytes, EX_POOL_SMALLEST_BLOCK);
    NumberOfBytes = NumberOfBlocks * EX_POOL_SMALLEST_BLOCK;
    ULONG FreeListIndex = NumberOfBlocks - 1;

    while (IsListEmpty(&Pool->FreeLists[FreeListIndex])) {
	FreeListIndex++;
	if (FreeListIndex >= EX_POOL_FREE_LISTS) {
	    MWORD PageNum = EiRequestPoolPages(Pool, 1);
	    if (PageNum == 0) {
		return NULL;
	    }
	    /* Add page to the managed page list */
	    BOOLEAN NeedAlloc = TRUE;
	    PEX_POOL_PAGE_RANGE PrevPageRange = EiPoolFindPrevPageRange(&Pool->ManagedPageRangeList,
									PageNum);
	    if (PrevPageRange != NULL && PrevPageRange->FirstPageNum + PrevPageRange->NumPages == PageNum) {
		PrevPageRange->NumPages++;
		NeedAlloc = FALSE;
	    } else {
		NeedAlloc = TRUE;
	    }
	    MWORD PageVaddr = PageNum << EX_PAGE_BITS;
	    ULONG PageRangeStructBlocks = RtlDivCeilUnsigned(sizeof(EX_POOL_PAGE_RANGE), EX_POOL_SMALLEST_BLOCK);
	    if (NeedAlloc) {
		PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) PageVaddr;
		PoolHeader->PreviousSize = 0;
		PoolHeader->BlockSize = PageRangeStructBlocks;
		PEX_POOL_PAGE_RANGE PageRange = (PEX_POOL_PAGE_RANGE) (PageVaddr + EX_POOL_OVERHEAD);
		PageRange->FirstPageNum = PageNum;
		PageRange->NumPages = 1;
		if (PrevPageRange == NULL) {
		    InsertTailList(&Pool->ManagedPageRangeList, &PageRange->ListEntry);
		} else {
		    InsertHeadList(&PrevPageRange->ListEntry, &PageRange->ListEntry);
		}
	    }
	    /* Add the rest of the space to the FreeLists */
	    MWORD FreeSpaceStart = PageVaddr + (NeedAlloc ? (PageRangeStructBlocks + 1) * EX_POOL_SMALLEST_BLOCK : 0);
	    MWORD FreeBlockSize = EX_PAGE_SIZE / EX_POOL_SMALLEST_BLOCK - 1 - (NeedAlloc ? PageRangeStructBlocks + 1 : 0);
	    FreeListIndex = FreeBlockSize - 1;
	    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) FreeSpaceStart;
	    PoolHeader->PreviousSize = NeedAlloc ? PageRangeStructBlocks : 0;
	    PoolHeader->BlockSize = FreeBlockSize;
	    PLIST_ENTRY FreeEntry = (PLIST_ENTRY) (FreeSpaceStart + EX_POOL_OVERHEAD);
	    InsertHeadList(&Pool->FreeLists[FreeListIndex], FreeEntry);
	    break;
	}
    }

    ULONG AvailableBlocks = FreeListIndex + 1;
    PLIST_ENTRY FreeEntry = Pool->FreeLists[FreeListIndex].Flink;
    MWORD BlockStart = (MWORD) FreeEntry;
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) (BlockStart - EX_POOL_OVERHEAD);
    RemoveEntryList(FreeEntry);
    InvalidateListEntry(FreeEntry);
    ULONG LeftOverBlocks =  AvailableBlocks - NumberOfBlocks - EX_POOL_OVERHEAD / EX_POOL_SMALLEST_BLOCK;
    if (LeftOverBlocks > 0) {
	PoolHeader->BlockSize = NumberOfBlocks;
	MWORD NextPoolHeaderStart = BlockStart + NumberOfBytes;
	MWORD NextBlockStart = NextPoolHeaderStart + EX_POOL_OVERHEAD;
	PEX_POOL_HEADER NextPoolHeader = (PEX_POOL_HEADER) NextPoolHeaderStart;
	PLIST_ENTRY NextFreeEntry = (PLIST_ENTRY) NextBlockStart;
	NextPoolHeader->PreviousSize = NumberOfBlocks;
	NextPoolHeader->BlockSize = LeftOverBlocks;
	InsertHeadList(&Pool->FreeLists[LeftOverBlocks-1], NextFreeEntry);
    } else {
	PoolHeader->BlockSize = AvailableBlocks;
    }
    PoolHeader->Tag = Tag;

    return (PVOID) BlockStart;
}

PVOID ExAllocatePoolWithTag(IN ULONG NumberOfBytes,
			    IN ULONG Tag)
{
    return EiAllocatePoolWithTag(&EiGlobalPool, NumberOfBytes, Tag);
}
