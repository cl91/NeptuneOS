#include <nt.h>
#include <ntos.h>

static EX_POOL_DESCRIPTOR EiGlobalPool;

static PVOID EiAllocatePoolWithTag(IN PEX_POOL_DESCRIPTOR Pool,
				   IN ULONG NumberOfBytes,
				   IN ULONG Tag);

static NTSTATUS EiInitializePool(PEX_POOL_DESCRIPTOR Pool,
				 PMM_PAGING_STRUCTURE_DESCRIPTOR Page)
{
    InitializeListHead(&Pool->UsedPageList);
    InitializeListHead(&Pool->FreePageList);
    InitializeListHead(&Pool->LargePageList);
    for (int i = 0; i < EX_POOL_FREE_LISTS; i++) {
	InitializeListHead(&Pool->FreeLists[i]);
    }

    /* Add page to pool */
    PEX_PAGE_DESCRIPTOR ExPage = (PEX_PAGE_DESCRIPTOR) Page->VirtualAddr;
    if (Page->Type == MM_PAGE) {
	Pool->TotalPages = 1;
	Pool->TotalLargePages = 0;
	Pool->HeapEnd = Page->VirtualAddr + EX_POOL_PAGE_SIZE;
	ExPage->Page = Page;
	InsertHeadList(&Pool->UsedPageList, &ExPage->PoolListEntry);
    } else if (Page->Type == MM_LARGE_PAGE) {
	ULONG TotalPages = 1 << (EX_POOL_LARGE_PAGE_BITS - EX_POOL_PAGE_BITS);
	Pool->TotalPages = TotalPages;
	Pool->TotalLargePages = 1;
	Pool->HeapEnd = Page->VirtualAddr + EX_POOL_LARGE_PAGE_SIZE;
	ExPage->Page = Page;
	InsertHeadList(&Pool->UsedPageList, &ExPage->PoolListEntry);
	for (ULONG Offset = 1; Offset < TotalPages; Offset++) {
	    ExPage = (PEX_PAGE_DESCRIPTOR) (Page->VirtualAddr + (Offset << EX_POOL_PAGE_BITS));
	    InsertTailList(&Pool->FreePageList, &ExPage->PoolListEntry);
	    ExPage->Page = Page;
	}
    } else {
	return STATUS_NTOS_EXEC_INVALID_ARGUMENT;
    }

    /* Add free space to FreeLists */
    ULONG FreeListIndex = EX_POOL_BUDDY_MAX / EX_POOL_SMALLEST_BLOCK - 1;
    MWORD PoolHeaderStart = Page->VirtualAddr + EX_POOL_OVERHEAD;
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) PoolHeaderStart;
    MWORD FreeEntryStart = PoolHeaderStart + sizeof(EX_PAGE_DESCRIPTOR);
    PLIST_ENTRY FreeEntry = (PLIST_ENTRY) FreeEntryStart;
    PoolHeader->PreviousSize = 0;
    PoolHeader->BlockSize = EX_POOL_LARGEST_BLOCK / EX_POOL_SMALLEST_BLOCK;
    InsertHeadList(&Pool->FreeLists[FreeListIndex], FreeEntry);

    /* If large page, allocate maintenance structure and add to pool */
    if (Page->Type == MM_LARGE_PAGE) {
	PEX_LARGE_PAGE_DESCRIPTOR LargePage = (PEX_LARGE_PAGE_DESCRIPTOR)
	    EiAllocatePoolWithTag(Pool, sizeof(EX_LARGE_PAGE_DESCRIPTOR), NTOS_EX_TAG);
	LargePage->Page = Page;
	InsertHeadList(&Pool->LargePageList, &LargePage->ListEntry);
    }

    return STATUS_SUCCESS;
}

NTSTATUS ExInitializePool(IN PMM_PAGING_STRUCTURE_DESCRIPTOR Page)
{
    return EiInitializePool(&EiGlobalPool, Page);
}

/* If request size > EX_POOL_BUDDY_MAX, return pages
 * Else, allocate from the free list.
 * If no more space in free list, request one more page (use large page if available)
 * Each managed (small) page is headed by EX_PAGE_DESCRIPTOR
 * Each managed large page goes into LargePageList
 */
static PVOID EiAllocatePoolWithTag(IN PEX_POOL_DESCRIPTOR Pool,
				   IN ULONG NumberOfBytes,
				   IN ULONG Tag)
{
    if (NumberOfBytes == 0) {
	return NULL;
    }

    if (NumberOfBytes > EX_POOL_BUDDY_MAX) {
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
	FreeEntry->Flink = FreeEntry->Blink = NULL;
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
