#include "ei.h"

static EX_POOL EiPool;

/* Add the free page to the FreeLists */
static VOID EiAddFreeSpaceToPool(IN PEX_POOL Pool,
				 IN MWORD Addr,
				 IN USHORT PreviousSize,
				 IN USHORT BlockSize)
{
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) Addr;
    PoolHeader->PreviousSize = PreviousSize;
    PoolHeader->BlockSize = BlockSize;
    PLIST_ENTRY FreeEntry = (PLIST_ENTRY) (Addr + EX_POOL_OVERHEAD);
    InsertHeadList(&Pool->FreeLists[BlockSize-1], FreeEntry);
}

/* Add the free page to the FreeLists */
static VOID EiAddPageToPool(IN PEX_POOL Pool,
			    IN MWORD Addr)
{
    EiAddFreeSpaceToPool(Pool, Addr, 0, EX_POOL_FREE_LISTS);
}

/* We require 3 consecutive initial pages mapped at EX_POOL_START */
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
	    if (Pool->HeapEnd >= EX_POOL_START + EX_POOL_MAX_SIZE) {
		return FALSE;
	    }
	    MM_MEM_PRESSURE MemPressure = MmQueryMemoryPressure();
	    LONG Size = PAGE_SIZE;
	    if (MemPressure == MM_MEM_PRESSURE_SUFFICIENT_MEMORY) {
		Size = LARGE_PAGE_SIZE;
	    } else if (MemPressure == MM_MEM_PRESSURE_LOW_MEMORY) {
		Size = 4 * PAGE_SIZE;
	    } /* Otherwise we are critically low on memory, just get one page only */
	    MWORD SatisfiedSize = 0;
	    /* Make sure we don't run over the end of ExPool space. */
	    if (Pool->HeapEnd + Size >= EX_POOL_START + EX_POOL_MAX_SIZE) {
		Size = EX_POOL_START + EX_POOL_MAX_SIZE - Pool->HeapEnd;
	    }
	    MmCommitAddrWindow(Pool->HeapEnd, Size, &SatisfiedSize);
	    if (SatisfiedSize < PAGE_SIZE) {
		return FALSE;
	    }
	    Pool->TotalPages += SatisfiedSize >> PAGE_LOG2SIZE;
	}
    }
    return TRUE;
}

/* If request size > EX_POOL_LARGEST_BLOCK, deny request
 * Else, allocate from the free list.
 * If no more space in free list, request one more page
 */
static PVOID EiAllocatePoolWithTag(IN PEX_POOL Pool,
				   IN MWORD NumberOfBytes,
				   IN ULONG Tag)
{
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
    PEX_POOL_HEADER PoolHeader = (PEX_POOL_HEADER) (BlockStart - EX_POOL_OVERHEAD);
    RemoveEntryList(FreeEntry);
    InvalidateListEntry(FreeEntry);
    LONG LeftOverBlocks =  AvailableBlocks - NumberOfBlocks - EX_POOL_OVERHEAD / EX_POOL_SMALLEST_BLOCK;
    if (LeftOverBlocks > 0) {
	PoolHeader->BlockSize = NumberOfBlocks;
	MWORD NextPoolHeaderStart = BlockStart + NumberOfBytes;
	EiAddFreeSpaceToPool(Pool, NextPoolHeaderStart, NumberOfBlocks, LeftOverBlocks);
    } else {
	PoolHeader->BlockSize = AvailableBlocks;
    }
    PoolHeader->Tag = Tag;

    return (PVOID) BlockStart;
}

static VOID EiFreePool(IN PEX_POOL Pool,
		       IN PVOID Ptr)
{
    /* TODO: Implement */
}

PVOID ExAllocatePoolWithTag(IN MWORD NumberOfBytes,
			    IN ULONG Tag)
{
    return EiAllocatePoolWithTag(&EiPool, NumberOfBytes, Tag);
}

VOID ExFreePool(IN PVOID Ptr)
{
    return EiFreePool(&EiPool, Ptr);
}
