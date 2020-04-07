#pragma once

#include <nt.h>
#include "mm.h"
#include "ntosdef.h"

#ifdef _M_IX86
#include "i386/ex.h"
#elif defined(_M_AMD64)
#include "amd64/ex.h"
#endif

#define EX_POOL_PAGE_BITS	(seL4_PageBits)
#define EX_POOL_LARGE_PAGE_BITS	(seL4_LargePageBits)
#define EX_POOL_PAGE_SIZE	(1 << EX_POOL_PAGE_BITS)
#define EX_POOL_LARGE_PAGE_SIZE	(1 << EX_POOL_LARGE_PAGE_BITS)
#define EX_POOL_BLOCK_SHIFT	(1 + MWORD_SHIFT)
#define EX_POOL_SMALLEST_BLOCK	(1 << EX_POOL_BLOCK_SHIFT)

typedef struct _EX_POOL_BLOCK {
    UCHAR Fill[EX_POOL_SMALLEST_BLOCK];
} EX_POOL_BLOCK, *PEX_POOL_BLOCK;

typedef struct _EX_POOL_HEADER {
    USHORT PreviousSize;	/* does not include PoolHeader, divided by EX_POOL_SMALLEST_BLOCK */
    USHORT BlockSize;		/* does not include PoolHeader, divided by EX_POOL_SMALLEST_BLOCK */
    ULONG Tag;
} __packed EX_POOL_HEADER, *PEX_POOL_HEADER;

typedef struct _EX_PAGE_DESCRIPTOR {
    union {
	struct {
	    LIST_ENTRY PoolListEntry;
	    PMM_PAGING_STRUCTURE_DESCRIPTOR Page;
	};
	EX_POOL_BLOCK Blocks[2];
    };
} EX_PAGE_DESCRIPTOR, *PEX_PAGE_DESCRIPTOR;

#define EX_POOL_OVERHEAD	(sizeof(EX_POOL_HEADER))
#define EX_POOL_LARGEST_BLOCK	(EX_POOL_PAGE_SIZE - EX_POOL_OVERHEAD - sizeof(EX_PAGE_DESCRIPTOR))
#define EX_POOL_BUDDY_MAX	(EX_POOL_LARGEST_BLOCK - EX_POOL_SMALLEST_BLOCK)

#define EX_POOL_FREE_LISTS	(EX_POOL_BUDDY_MAX / EX_POOL_SMALLEST_BLOCK)

typedef struct _EX_POOL_DESCRIPTOR {
    ULONG TotalPages;		/* one large page is 2^10 pages */
    ULONG TotalLargePages;
    LIST_ENTRY UsedPageList;
    LIST_ENTRY FreePageList;
    LIST_ENTRY LargePageList;
    MWORD HeapEnd;
    LIST_ENTRY FreeLists[EX_POOL_FREE_LISTS];
} EX_POOL_DESCRIPTOR, *PEX_POOL_DESCRIPTOR;

typedef struct _EX_LARGE_PAGE_DESCRIPTOR {
    LIST_ENTRY ListEntry;
    PMM_PAGING_STRUCTURE_DESCRIPTOR Page;
} EX_LARGE_PAGE_DESCRIPTOR, *PEX_LARGE_PAGE_DESCRIPTOR;

#define EX_POOL_TAG(Tag0, Tag1, Tag2, Tag3)	((((Tag3) & 0x7fUL) << 24) \
						 | (((Tag2) & 0x7fUL) << 16) \
						 | (((Tag1) & 0x7fUL) << 8) \
						 | ((Tag0) & 0x7fUL))
#define EX_POOL_GET_TAG0(Tag)			((CHAR)(Tag & 0x7fUL))
#define EX_POOL_GET_TAG1(Tag)			((CHAR)(((Tag) >> 8) & 0x7fUL))
#define EX_POOL_GET_TAG2(Tag)			((CHAR)(((Tag) >> 16)& 0x7fUL))
#define EX_POOL_GET_TAG3(Tag)			((CHAR)(((Tag) >> 24) & 0x7fUL))

#define NTOS_EX_TAG				(EX_POOL_TAG('n','t','e','x'))

NTSTATUS ExInitializePool(IN PMM_PAGING_STRUCTURE_DESCRIPTOR Page);
PVOID ExAllocatePoolWithTag(IN ULONG NumberOfBytes,
			    IN ULONG Tag);
