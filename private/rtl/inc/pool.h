#pragma once

#include <services.h>
#include <util.h>

/*
 * For a free block, we keep the free list entry at the beginning of the block
 */
typedef struct _RTL_POOL_BLOCK {
    LIST_ENTRY FreeListEntry;
} RTL_POOL_BLOCK, *PRTL_POOL_BLOCK;

typedef struct _RTL_POOL_HEADER {
    union {
	struct {
	    struct {
		ULONG Used : 1;	/* Set if the block has been allocated. Cleared when this block is freed. */
		ULONG PreviousSize : 15; /* does not include PoolHeader, divided by RTL_POOL_SMALLEST_BLOCK */
		ULONG Dummy : 1;	 /* Reserved bit */
		ULONG BlockSize : 15; /* does not include PoolHeader, divided by RTL_POOL_SMALLEST_BLOCK */
	    };
	    ULONG Tag;
	} __packed;
	RTL_POOL_BLOCK Strut; /* Make sure POOL_HEADER has the same size as the smallest block */
    };
} RTL_POOL_HEADER, *PRTL_POOL_HEADER;

/*
 * Two machine words for smallest RTL_POOL_BLOCK. The unused lowest RTL_POOL_BLOCK_SHIFT
 * bits are used by the Object Manager to encode the flags of the global handle.
 */
#define RTL_POOL_BLOCK_SHIFT	(1 + MWORD_LOG2SIZE)
#define RTL_POOL_SMALLEST_BLOCK	(1ULL << RTL_POOL_BLOCK_SHIFT)

#define RTL_POOL_OVERHEAD	(sizeof(RTL_POOL_HEADER))
#define RTL_POOL_LARGEST_BLOCK	(PAGE_SIZE - RTL_POOL_OVERHEAD)
#define RTL_POOL_FREE_LISTS	(RTL_POOL_LARGEST_BLOCK / RTL_POOL_SMALLEST_BLOCK)

#define RTL_POOL_HEADER_TO_BLOCK(h)	((PRTL_POOL_BLOCK)((MWORD)(h) + RTL_POOL_OVERHEAD))
#define RTL_POOL_BLOCK_TO_HEADER(b)	((PRTL_POOL_HEADER)((MWORD)(b) - RTL_POOL_OVERHEAD))

C_ASSERT(RTL_POOL_OVERHEAD == RTL_POOL_SMALLEST_BLOCK);
C_ASSERT(sizeof(RTL_POOL_BLOCK) == RTL_POOL_SMALLEST_BLOCK);

typedef struct _RTL_FREE_PAGE {
    LIST_ENTRY Link;	 /* Must be the first member of this struct */
} RTL_FREE_PAGE, *PRTL_FREE_PAGE;

typedef struct _RTL_SMALL_POOL {
    LONG TotalPages;	/* Number of pages. Each page is PAGE_SIZE. */
    LONG UsedPages;	/* Always equals TotalPages - GetListLength(FreePageList) */
    MWORD HeapStart;
    MWORD HeapEnd;
    LIST_ENTRY FreePageList;		      /* List of RTL_FREE_PAGE. */
    LIST_ENTRY FreeLists[RTL_POOL_FREE_LISTS]; /* Indexed by (BlockSize - 1) */
} RTL_SMALL_POOL, *PRTL_SMALL_POOL;

NTSTATUS RtlInitializeSmallPool(IN PRTL_SMALL_POOL Pool,
				IN MWORD HeapStart,
				IN LONG NumPages);

PVOID RtlAllocateSmallPoolWithTag(IN PRTL_SMALL_POOL Pool,
				  IN MWORD NumberOfBytes,
				  IN ULONG Tag);

VOID RtlFreeSmallPoolWithTag(IN PRTL_SMALL_POOL Pool,
			     IN PCVOID Ptr,
			     IN ULONG Tag);

VOID RtlDbgDumpPool(IN PRTL_SMALL_POOL Pool);

/* User must supply these functions. */
ULONG RtlPoolAllocateNewPages(IN PRTL_SMALL_POOL Pool);

#if DBG
VOID RtlpAssertPool(IN PCSTR Expr,
		    IN PCSTR File,
		    IN ULONG Line);
#endif
