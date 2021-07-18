#pragma once

#include <ntos.h>

/* Two machine words for smallest EX_POOL_BLOCK */
#define EX_POOL_BLOCK_SHIFT	(1 + MWORD_LOG2SIZE)
#define EX_POOL_SMALLEST_BLOCK	(1 << EX_POOL_BLOCK_SHIFT)

typedef struct _EX_POOL_BLOCK {
    UCHAR Fill[EX_POOL_SMALLEST_BLOCK];
} EX_POOL_BLOCK, *PEX_POOL_BLOCK;

typedef struct _EX_POOL_HEADER {
    union {
	struct {
	    USHORT PreviousSize;	/* does not include PoolHeader, divided by EX_POOL_SMALLEST_BLOCK */
	    USHORT BlockSize;		/* does not include PoolHeader, divided by EX_POOL_SMALLEST_BLOCK */
	    ULONG Tag;
	} __packed;
	EX_POOL_BLOCK Block;
    };
} EX_POOL_HEADER, *PEX_POOL_HEADER;

#define EX_POOL_OVERHEAD	(sizeof(EX_POOL_HEADER))
#define EX_POOL_LARGEST_BLOCK	((1 << seL4_PageBits) - EX_POOL_OVERHEAD)
#define EX_POOL_FREE_LISTS	(EX_POOL_LARGEST_BLOCK / EX_POOL_SMALLEST_BLOCK)

COMPILE_ASSERT(EX_POOL_OVERHEAD_MUST_EQUAL_SMALLEST_BLOCK, EX_POOL_OVERHEAD == EX_POOL_SMALLEST_BLOCK);

typedef struct _EX_POOL {
    LONG TotalPages;		/* one large page is 2^10 pages */
    LONG UsedPages;		/* we always allocate page contiguously */
    MWORD HeapStart;
    MWORD HeapEnd;
    LIST_ENTRY FreeLists[EX_POOL_FREE_LISTS]; /* Indexed by (BlockSize - 1) */
} EX_POOL, *PEX_POOL;
