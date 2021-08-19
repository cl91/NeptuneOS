#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include "ke.h"
#include "mm.h"
#include "ntosdef.h"

/* All hard-coded addresses in the address space of the NTOS root task go here. */
#define VGA_VIDEO_PAGE_PADDR		(0x000b8000)
#define VGA_VIDEO_PAGE_VADDR		(0x000b8000)
/* Hyperspace is 16MB */
#define HYPERSPACE_START		(0x0f000000)
/* We have LARGE_PAGE_SIZE / PAGE_SIZE slots for 4K pages in the hyperspace */
#define HYPERSPACE_4K_PAGE_START	(HYPERSPACE_START)
#define HYPERSPACE_LARGE_PAGE_START	(HYPERSPACE_4K_PAGE_START + LARGE_PAGE_SIZE)
/* We have one slot for large page in the hyperspace */
#define HYPERSPACE_END			(HYPERSPACE_LARGE_PAGE_START + LARGE_PAGE_SIZE)
/* Region for the Executive pool. EX_POOL_MAX_SIZE must be a power of two. */
#define EX_POOL_START			(0x10000000)
#define EX_POOL_MAX_SIZE		(0x10000000)
/* Region of the dynamically managed Executive virtual address space */
#define EX_DYN_VSPACE_START		(EX_POOL_START + EX_POOL_MAX_SIZE)
#define EX_DYN_VSPACE_END		(0x80000000)

#if HYPERSPACE_END > EX_POOL_START
#error "Hyperspace too large."
#endif

/* Since we use the object header's offset from the start of Executive pool as the
 * unique global object handle (badge), and on i386 the seL4 kernel ignores the highest
 * four bits of a badge, the Executive pool cannot be larger than 256MB. */
#if defined(_M_IX86) && (EX_POOL_MAX_SIZE > 0x10000000)
#error "Executive pool too large"
#endif

/* Two machine words for smallest EX_POOL_BLOCK. The unused lowest EX_POOL_BLOCK_SHIFT
 * bits are used by the Object Manager to encode the flags of the global handle.
 */
#define EX_POOL_BLOCK_SHIFT	(1 + MWORD_LOG2SIZE)
#define EX_POOL_SMALLEST_BLOCK	(1ULL << EX_POOL_BLOCK_SHIFT)

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
NTSTATUS ExInitSystemPhase0(seL4_BootInfo *bootinfo);
NTSTATUS ExInitSystemPhase1();

/* pool.c */
NTSTATUS ExInitializePool(IN MWORD HeapStart,
			  IN LONG NumPages);
PVOID ExAllocatePoolWithTag(IN MWORD NumberOfBytes,
			    IN ULONG Tag);
VOID ExFreePool(IN PVOID Ptr);
