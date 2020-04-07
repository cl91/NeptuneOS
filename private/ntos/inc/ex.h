#pragma once

#include <nt.h>
#include "mm.h"
#include "ntosdef.h"

#ifdef _M_IX86
#include "i386/ex.h"
#elif defined(_M_AMD64)
#include "amd64/ex.h"
#endif

#define EX_POOL_TAG_BITS	(7)
#define EX_POOL_SIZE_BITS	(16 - EX_POOL_TAG_BITS)
#define EX_POOL_PAGE_BITS	(seL4_PageBits)
#define EX_POOL_LARGE_PAGE_BITS	(seL4_LargePageBits)
#define EX_POOL_PAGE_SIZE	(1 << EX_POOL_PAGE_BITS)

#if EX_POOL_PAGE_BITS - EX_POOL_SIZE_BITS <= 1 + MWORD_SHIFT
#define EX_POOL_BLOCK_SHIFT	(1 + MWORD_SHIFT)
#else
#define EX_POOL_BLOCK_SHIFT	(EX_POOL_PAGE_BITS - EX_POOL_SIZE_BITS)
#endif

#define EX_POOL_SMALLEST_BLOCK	(1 << EX_POOL_BLOCK_SHIFT)

typedef struct _EX_POOL_BLOCK {
    UCHAR Fill[EX_POOL_SMALLEST_BLOCK];
} EX_POOL_BLOCK, *PEX_POOL_BLOCK;

typedef struct _EX_POOL_HEADER {
    struct {
	USHORT PreviousSize : EX_POOL_SIZE_BITS;
	USHORT Tag0 : EX_POOL_TAG_BITS;
    };
    struct {
	USHORT BlockSize : EX_POOL_SIZE_BITS;
	USHORT Tag1 : EX_POOL_TAG_BITS;
    };
} __packed EX_POOL_HEADER, *PEX_POOL_HEADER;

#define EX_POOL_OVERHEAD	(sizeof(EX_POOL_HEADER))
#define EX_POOL_BUDDY_MAX	(EX_POOL_PAGE_SIZE - EX_POOL_OVERHEAD	\
				 - EX_POOL_SMALLEST_BLOCK - sizeof(EX_PAGE_DESCRIPTOR))

#define EX_POOL_FREE_LISTS	(EX_POOL_PAGE_SIZE / EX_POOL_SMALLEST_BLOCK)

typedef struct _EX_POOL_DESCRIPTOR {
    ULONG TotalPages;		/* total pages excluding large pages */
    ULONG TotalLargePages;
    LIST_ENTRY UsedPageList;
    LIST_ENTRY FreePageList;
    LIST_ENTRY UnmanagedPageList;
    LIST_ENTRY FreeLists[EX_POOL_FREE_LISTS];
} EX_POOL_DESCRIPTOR, *PEX_POOL_DESCRIPTOR;

typedef struct _EX_PAGE_DESCRIPTOR {
    LIST_ENTRY PoolListEntry;
    PMM_PAGING_STRUCTURE_DESCRIPTOR Page;
} EX_PAGE_DESCRIPTOR, *PEX_PAGE_DESCRIPTOR;

#define EX_POOL_TAG(Tag0, Tag1)	((USHORT)((((Tag1) & 0x7f) << 8) | ((Tag0) & 0x7f))
#define EX_POOL_GET_TAG0(Tag)		((CHAR)(Tag & 0x7f))
#define EX_POOL_GET_TAG1(Tag)		((CHAR)(((Tag) >> 8) & 0x7f))
