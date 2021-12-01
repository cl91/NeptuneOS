#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include "ke.h"
#include "mm.h"
#include "ntosdef.h"

#ifdef _M_IX86
#define ADDRESS_SPACE_MULTIPLIER	(1)
#elif defined(_M_AMD64)
/* For amd64 build we make the ExPool and other hard-coded address spaces bigger */
#define ADDRESS_SPACE_MULTIPLIER	(0x100)
#else
#error "Unsupported architecture"
#endif

/* All hard-coded addresses in the address space of the NTOS root task go here. */
#define VGA_VIDEO_PAGE_PADDR		(0x000b8000ULL)
#define VGA_VIDEO_PAGE_VADDR		(0x000b8000ULL)
/* System thread region is 16MB. Each system thread gets one page of IPC buffer and
 * one 4K page of stack. Every page is seperated by an uncommitted page to catch
 * stack overflow and underflow.  */
#define SYSTEM_THREAD_REGION_START	(0x0e000000ULL)
#define SYSTEM_THREAD_REGION_SIZE	(0x01000000ULL)
#define SYSTEM_THREAD_REGION_END	(SYSTEM_THREAD_REGION_START + SYSTEM_THREAD_REGION_SIZE)
/* We can have a maximum of 16MB/16KB == 1024 system threads */
#define SYSTEM_THREAD_IPC_RESERVE	(2 * PAGE_SIZE)
#define SYSTEM_THREAD_IPC_COMMIT	(PAGE_SIZE)
#define SYSTEM_THREAD_STACK_RESERVE	(2 * PAGE_SIZE)
#define SYSTEM_THREAD_STACK_COMMIT	(PAGE_SIZE)
/* Hyperspace is 16MB */
#define HYPERSPACE_START		(SYSTEM_THREAD_REGION_END)
/* We have LARGE_PAGE_SIZE / PAGE_SIZE slots for 4K pages in the hyperspace */
#define HYPERSPACE_4K_PAGE_START	(HYPERSPACE_START)
/* We have one slot for large page in the hyperspace */
#define HYPERSPACE_LARGE_PAGE_START	(HYPERSPACE_4K_PAGE_START + LARGE_PAGE_SIZE)
#define HYPERSPACE_END			(HYPERSPACE_LARGE_PAGE_START + LARGE_PAGE_SIZE)
/* Region for the Executive pool. EX_POOL_MAX_SIZE must be a power of two.
 * Additionally, for amd64 EX_POOL_START must be within the first GB (since the initial
 * page directory and PDPT only cover the first GB). */
#define EX_POOL_START			(0x10000000ULL)
#define EX_POOL_MAX_SIZE		(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_POOL_END			(EX_POOL_START + EX_POOL_MAX_SIZE)
/* Region for the PEB/TEB pages mapped in root task address space */
#define EX_PEB_TEB_REGION_START		(EX_POOL_END)
#define EX_PEB_TEB_REGION_SIZE		(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_PEB_TEB_REGION_END		(EX_PEB_TEB_REGION_START + EX_PEB_TEB_REGION_SIZE)
/* Region where the client thread's ipc buffers are mapped */
#define EX_IPC_BUFFER_REGION_START	(EX_PEB_TEB_REGION_END)
#define EX_IPC_BUFFER_REGION_SIZE	(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_IPC_BUFFER_REGION_END	(EX_IPC_BUFFER_REGION_START + EX_IPC_BUFFER_REGION_SIZE)
/* Region where the client's loader shared data are mapped */
#define EX_LOADER_SHARED_REGION_START	(EX_IPC_BUFFER_REGION_END)
#define EX_LOADER_SHARED_REGION_SIZE	(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_LOADER_SHARED_REGION_END	(EX_LOADER_SHARED_REGION_START + EX_LOADER_SHARED_REGION_SIZE)
/* Region where the driver processes' IRP buffers are allocated */
#define EX_DRIVER_IRP_REGION_START	(EX_LOADER_SHARED_REGION_START)
#define EX_DRIVER_IRP_REGION_SIZE	(0x10000000ULL * ADDRESS_SPACE_MULTIPLIER)
#define EX_DRIVER_IRP_REGION_END	(EX_DRIVER_IRP_REGION_START + EX_DRIVER_IRP_REGION_SIZE)
/* Region of the dynamically managed Executive virtual address space */
#define EX_DYN_VSPACE_START		(EX_DRIVER_IRP_REGION_END)
#define EX_DYN_VSPACE_END		(seL4_UserTop)

#if HYPERSPACE_END > EX_POOL_START
#error "Hyperspace too large."
#endif

/* Since we use the object header's offset from the start of Executive pool as the
 * unique global object handle (badge), and on i386 the seL4 kernel ignores the highest
 * four bits of a badge, the Executive pool cannot be larger than 256MB. */
#if defined(_M_IX86) && (EX_POOL_MAX_SIZE > 0x10000000ULL)
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

#define ExAllocatePoolEx(Var, Type, Size, Tag, OnError)			\
    {} Type *Var = (Type *)ExAllocatePoolWithTag(Size, Tag);		\
    if ((Var) == NULL) {						\
	DbgPrint("Allocation of 0x%zx bytes for variable %s of type"	\
		 " (%s *) failed in function %s @ %s:%d\n",		\
		 (MWORD) Size, #Var, #Type, __func__, __FILE__, __LINE__); \
	{OnError;} return STATUS_NO_MEMORY; }


/*
 * Creation context for the timer object creation routine
 */
typedef struct _TIMER_OBJ_CREATE_CONTEXT {
    TIMER_TYPE Type;
} TIMER_OBJ_CREATE_CONTEXT, *PTIMER_OBJ_CREATE_CONTEXT;


/* init.c */
NTSTATUS ExInitSystemPhase0(seL4_BootInfo *bootinfo);
NTSTATUS ExInitSystemPhase1();

/* pool.c */
NTSTATUS ExInitializePool(IN MWORD HeapStart,
			  IN LONG NumPages);
PVOID ExAllocatePoolWithTag(IN MWORD NumberOfBytes,
			    IN ULONG Tag);
VOID ExFreePool(IN PCVOID Ptr);
