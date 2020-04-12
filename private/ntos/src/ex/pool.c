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
    InitializeListHead(&Pool->LargePageList);
    for (int i = 0; i < EX_POOL_FREE_LISTS; i++) {
	InitializeListHead(&Pool->FreeLists[i]);
    }

    /* Add page to pool */
    if (Page->Type == MM_PAGE_TYPE_PAGE) {
	Pool->TotalPages = 1;
	Pool->TotalLargePages = 0;
	Pool->HeapEnd = Page->VirtualAddr + EX_POOL_PAGE_SIZE;
    } else if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	ULONG TotalPages = 1 << (EX_POOL_LARGE_PAGE_BITS - EX_POOL_PAGE_BITS);
	Pool->TotalPages = TotalPages;
	Pool->TotalLargePages = 1;
	Pool->HeapEnd = Page->VirtualAddr + EX_POOL_LARGE_PAGE_SIZE;
    } else {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    /* Add free space to FreeLists */
    ULONG FreeListIndex = EX_POOL_LARGEST_BLOCK / EX_POOL_SMALLEST_BLOCK - 1;
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) Page->VirtualAddr;
    MWORD FreeEntryStart = Page->VirtualAddr + EX_POOL_OVERHEAD;
    PLIST_ENTRY FreeEntry = (PLIST_ENTRY) FreeEntryStart;
    PoolHeader->PreviousSize = 0;
    PoolHeader->BlockSize = EX_POOL_LARGEST_BLOCK / EX_POOL_SMALLEST_BLOCK;
    InsertHeadList(&Pool->FreeLists[FreeListIndex], FreeEntry);

    /* Allocate maintenance structure and add to pool lists */
    if (Page->Type == MM_PAGE_TYPE_PAGE) {
	PEX_POOL_PAGE_RANGE ManagedPages = (PEX_POOL_PAGE_RANGE)
	    EiAllocatePoolWithTag(Pool, sizeof(EX_POOL_PAGE_RANGE), POOL_DATA_TAG);
	assert(ManagedPages != NULL);
	ManagedPages->StartingPageNumber = Page->VirtualAddr >> EX_POOL_PAGE_BITS;
	ManagedPages->NumberOfPages = 1;
	InsertHeadList(&Pool->ManagedPageRangeList, &ManagedPages->ListEntry);
    } else if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	PEX_POOL_PAGE_RANGE ManagedPages = (PEX_POOL_PAGE_RANGE)
	    EiAllocatePoolWithTag(Pool, sizeof(EX_POOL_PAGE_RANGE), POOL_DATA_TAG);
	assert(ManagedPages != NULL);
	ManagedPages->StartingPageNumber = Page->VirtualAddr >> EX_POOL_PAGE_BITS;
	ManagedPages->NumberOfPages = 1;
	InsertHeadList(&Pool->ManagedPageRangeList, &ManagedPages->ListEntry);
	PEX_POOL_PAGE_RANGE FreePages = (PEX_POOL_PAGE_RANGE)
	    EiAllocatePoolWithTag(Pool, sizeof(EX_POOL_PAGE_RANGE), POOL_DATA_TAG);
	assert(FreePages != NULL);
	FreePages->StartingPageNumber = (Page->VirtualAddr >> EX_POOL_PAGE_BITS) + 1;
	FreePages->NumberOfPages = (1 << (EX_POOL_LARGE_PAGE_BITS - EX_POOL_PAGE_BITS)) - 1;
	InsertHeadList(&Pool->FreePageRangeList, &FreePages->ListEntry);
	PEX_POOL_LARGE_PAGE LargePage = (PEX_POOL_LARGE_PAGE)
	    EiAllocatePoolWithTag(Pool, sizeof(EX_POOL_LARGE_PAGE), POOL_DATA_TAG);
	LargePage->StartingLargePageNumber = Page->VirtualAddr >> EX_POOL_LARGE_PAGE_BITS;
	assert(LargePage != NULL);
	InsertHeadList(&Pool->LargePageList, &LargePage->ListEntry);
    } else {
	return STATUS_NTOS_BUG;
    }

    return STATUS_SUCCESS;
}

NTSTATUS ExInitializePool(IN PMM_PAGING_STRUCTURE Page)
{
    return EiInitializePool(&EiGlobalPool, Page);
}

/* If request size > EX_POOL_LARGEST_BLOCK, return pages
 * Else, allocate from the free list.
 * If no more space in free list, request one more page (use large page if available)
 * Each managed (small) page is headed by EX_POOL_PAGE
 * Each managed large page goes into LargePageList
 */
static PVOID EiAllocatePoolWithTag(IN PEX_POOL Pool,
				   IN ULONG NumberOfBytes,
				   IN ULONG Tag)
{
    if (NumberOfBytes == 0) {
	return NULL;
    }

    if (NumberOfBytes > EX_POOL_LARGEST_BLOCK) {
    } else {
	NumberOfBytes += EX_POOL_SMALLEST_BLOCK - 1;
	NumberOfBytes /= EX_POOL_SMALLEST_BLOCK;
	NumberOfBytes *= EX_POOL_SMALLEST_BLOCK;
	ULONG NumberOfBlocks = NumberOfBytes / EX_POOL_SMALLEST_BLOCK;
	ULONG FreeListIndex = NumberOfBlocks - 1;
	while (IsListEmpty(&Pool->FreeLists[FreeListIndex])) {
	    FreeListIndex++;
	    if (FreeListIndex >= EX_POOL_FREE_LISTS) {
		/* TODO: Allocate page */
		return NULL;
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

    return NULL;
}

PVOID ExAllocatePoolWithTag(IN ULONG NumberOfBytes,
			    IN ULONG Tag)
{
    return EiAllocatePoolWithTag(&EiGlobalPool, NumberOfBytes, Tag);
}
