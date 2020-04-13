#pragma once

#include <nt.h>
#include "mm.h"
#include "ntosdef.h"

#ifdef _M_IX86
#include "i386/ex.h"
#elif defined(_M_AMD64)
#include "amd64/ex.h"
#endif

/* Size of reserved address space starting from EX_POOL_START */
#define EX_POOL_RESERVED_SIZE	(512 * 1024 * 1024) /* 512MB */

#define EX_PAGE_BITS		(seL4_PageBits)
#define EX_LARGE_PAGE_BITS	(seL4_LargePageBits)
#define EX_PAGE_SIZE		(1 << EX_PAGE_BITS)
#define EX_LARGE_PAGE_SIZE	(1 << EX_LARGE_PAGE_BITS)
#define EX_POOL_BLOCK_SHIFT	(1 + MWORD_SHIFT)
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
#define EX_POOL_LARGEST_BLOCK	(EX_PAGE_SIZE - EX_POOL_OVERHEAD)
#define EX_POOL_FREE_LISTS	(EX_POOL_LARGEST_BLOCK / EX_POOL_SMALLEST_BLOCK)

COMPILE_ASSERT(EX_POOL_OVERHEAD_MUST_EQUAL_SMALLEST_BLOCK, EX_POOL_OVERHEAD == EX_POOL_SMALLEST_BLOCK);

typedef struct _EX_POOL {
    ULONG TotalPages;		/* one large page is 2^10 pages */
    LIST_ENTRY ManagedPagesList; /* pages managed by ExPool */
    LIST_ENTRY UnmanagedPagesList; /* pages handed out to clients */
    LIST_ENTRY FreePagesList;      /* unused pages */
    MWORD HeapEnd;
    LIST_ENTRY FreeLists[EX_POOL_FREE_LISTS]; /* Indexed by (BlockSize - 1) */
} EX_POOL, *PEX_POOL;

typedef struct _EX_POOL_PAGES {
    LIST_ENTRY ListEntry;
    MWORD FirstPageNum;
    MWORD NumPages;
} EX_POOL_PAGES, *PEX_POOL_PAGES;

#define EX_POOL_TAG(Tag0, Tag1, Tag2, Tag3)	((((Tag3) & 0x7fUL) << 24) \
						 | (((Tag2) & 0x7fUL) << 16) \
						 | (((Tag1) & 0x7fUL) << 8) \
						 | ((Tag0) & 0x7fUL))
#define EX_POOL_GET_TAG0(Tag)			((CHAR)(Tag & 0x7fUL))
#define EX_POOL_GET_TAG1(Tag)			((CHAR)(((Tag) >> 8) & 0x7fUL))
#define EX_POOL_GET_TAG2(Tag)			((CHAR)(((Tag) >> 16)& 0x7fUL))
#define EX_POOL_GET_TAG3(Tag)			((CHAR)(((Tag) >> 24) & 0x7fUL))

#define NTOS_EX_TAG				(EX_POOL_TAG('n','t','e','x'))

NTSTATUS ExInitializePool(IN PMM_PAGING_STRUCTURE Page);
PVOID ExAllocatePoolWithTag(IN ULONG NumberOfBytes,
			    IN ULONG Tag);
