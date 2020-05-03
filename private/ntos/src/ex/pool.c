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
			    IN MWORD PageNum)
{
    EiAddFreeSpaceToPool(Pool, PageNum << MM_PAGE_BITS, 0, EX_POOL_FREE_LISTS);
}

/* We require 3 consecutive initial pages mapped at EX_POOL_START */
NTSTATUS ExInitializePool(IN MWORD HeapStart,
			  IN LONG NumPages)
{
    /* Initialize FreeLists */
    for (int i = 0; i < EX_POOL_FREE_LISTS; i++) {
	InitializeListHead(&EiPool.FreeLists[i]);
    }

    if ((HeapStart & (MM_PAGE_SIZE-1)) != 0 || NumPages < 3) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    /* Add pages to pool */
    EiPool.TotalPages = NumPages;
    EiPool.UsedPages = 1;
    EiPool.HeapStart = HeapStart;
    EiPool.HeapEnd = HeapStart + MM_PAGE_SIZE;
    EiAddPageToPool(&EiPool, HeapStart >> MM_PAGE_BITS);

    return STATUS_SUCCESS;
}

/* Examine the number of available pages in the pool and optionally
 * request the memory management subcomponent for more pages.
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
static VOID EiRequestPoolPage(IN PEX_POOL Pool)
{
    LONG AvailablePages = Pool->TotalPages - Pool->UsedPages;
    if (AvailablePages >= 1) {
	/* Add one page to the pool */
	Pool->UsedPages++;
	EiAddPageToPool(Pool, Pool->HeapEnd >> MM_PAGE_BITS);
	Pool->HeapEnd += MM_PAGE_SIZE;
	if (AvailablePages >= 2) {
	    /* Plenty of resources here. Simply return */
	    return;
	} else {
	    /* We are running low on resources. Request more pages from mm */
	    MM_MEM_PRESSURE MemPressure = MmQueryMemoryPressure();
	    LONG NewPages = 1;
	    if (MemPressure == MM_MEM_PRESSURE_LOW) {
		NewPages = 4;
	    } else if (MemPressure == MM_MEM_PRESSURE_MEDIUM) {
		NewPages = 2;
	    }
	    MWORD SatisfiedPages = 0;
	    MmCommitPages(Pool->HeapEnd >> MM_PAGE_BITS,
			  NewPages, &SatisfiedPages, NULL);
	    Pool->TotalPages += SatisfiedPages;
	}
    }
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
	EiRequestPoolPage(Pool);
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
