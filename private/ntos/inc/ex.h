#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include "ke.h"
#include "mm.h"
#include "ntosdef.h"

/* All hard-coded addresses in the address space of the NTOS root task go here. */
#define VGA_VIDEO_PAGE_PADDR		(0x000b8000)
#define VGA_VIDEO_PAGE_VADDR		(0x000b8000)
#define BOOT_MODULES_START		(0x08000000)
#define BOOT_MODULES_MAX_SIZE		(0x08000000)
#define EX_POOL_START			(0x10000000)
#define EX_POOL_MAX_SIZE		(0x30000000)

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
