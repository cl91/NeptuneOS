#pragma once

#include <ntos.h>

/*
 * For a free block, we keep the free list entry at the beginning of the block
 */
typedef struct _EX_POOL_BLOCK {
    LIST_ENTRY FreeListEntry;
} EX_POOL_BLOCK, *PEX_POOL_BLOCK;

typedef struct _EX_POOL_HEADER {
    union {
	struct {
	    struct {
		ULONG Used : 1;	/* Set if the block has been allocated. Cleared when this block is freed. */
		ULONG PreviousSize : 15; /* does not include PoolHeader, divided by EX_POOL_SMALLEST_BLOCK */
		ULONG Dummy : 1;	 /* Reserved bit */
		ULONG BlockSize : 15; /* does not include PoolHeader, divided by EX_POOL_SMALLEST_BLOCK */
	    };
	    ULONG Tag;
	} __packed;
	EX_POOL_BLOCK Strut; /* Make sure POOL_HEADER has the same size as the smallest block */
    };
} EX_POOL_HEADER, *PEX_POOL_HEADER;

#define EX_POOL_OVERHEAD	(sizeof(EX_POOL_HEADER))
#define EX_POOL_LARGEST_BLOCK	(PAGE_SIZE - EX_POOL_OVERHEAD)
#define EX_POOL_FREE_LISTS	(EX_POOL_LARGEST_BLOCK / EX_POOL_SMALLEST_BLOCK)

#define EX_POOL_HEADER_TO_BLOCK(h)	((PEX_POOL_BLOCK)((MWORD)(h) + EX_POOL_OVERHEAD))
#define EX_POOL_BLOCK_TO_HEADER(b)	((PEX_POOL_HEADER)((MWORD)(b) - EX_POOL_OVERHEAD))

C_ASSERT(EX_POOL_OVERHEAD == EX_POOL_SMALLEST_BLOCK);
C_ASSERT(sizeof(EX_POOL_BLOCK) == EX_POOL_SMALLEST_BLOCK);

typedef struct _EX_POOL {
    LONG TotalPages;		/* number of 4K pages */
    LONG UsedPages;		/* we always allocate page contiguously */
    MWORD HeapStart;
    MWORD HeapEnd;
    LIST_ENTRY FreeLists[EX_POOL_FREE_LISTS]; /* Indexed by (BlockSize - 1) */
} EX_POOL, *PEX_POOL;

/* event.c */
NTSTATUS EiInitEventObject();
