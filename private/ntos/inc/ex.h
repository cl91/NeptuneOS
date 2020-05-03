#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include "ke.h"
#include "mm.h"
#include "ntosdef.h"

#ifdef _M_IX86
#define EX_POOL_START	(0x80000000)
#elif defined(_M_AMD64)
#define EX_POOL_START	(0x80000000)
#endif

/* Size of reserved address space starting from EX_POOL_START */
#define EX_POOL_START_PN	(EX_POOL_START >> MM_PAGE_BITS)
#define EX_POOL_RESERVED_SIZE	(128 * 1024 * 1024) /* 128MB */
#define EX_POOL_RESERVED_PAGES	(EX_POOL_RESERVED_SIZE >> MM_PAGE_BITS)

#define EX_POOL_TAG(Tag0, Tag1, Tag2, Tag3)	((((Tag3) & 0x7fUL) << 24) \
						 | (((Tag2) & 0x7fUL) << 16) \
						 | (((Tag1) & 0x7fUL) << 8) \
						 | ((Tag0) & 0x7fUL))
#define EX_POOL_GET_TAG0(Tag)			((CHAR)(Tag & 0x7fUL))
#define EX_POOL_GET_TAG1(Tag)			((CHAR)(((Tag) >> 8) & 0x7fUL))
#define EX_POOL_GET_TAG2(Tag)			((CHAR)(((Tag) >> 16)& 0x7fUL))
#define EX_POOL_GET_TAG3(Tag)			((CHAR)(((Tag) >> 24) & 0x7fUL))

#define NTOS_EX_TAG				(EX_POOL_TAG('n','t','e','x'))

/* init.c */
NTSTATUS ExInitSystem(seL4_BootInfo *bootinfo);

/* pool.c */
NTSTATUS ExInitializePool(IN MWORD HeapStart,
			  IN LONG NumPages);
PVOID ExAllocatePoolWithTag(IN MWORD NumberOfBytes,
			    IN ULONG Tag);
VOID ExFreePool(IN PVOID Ptr);
