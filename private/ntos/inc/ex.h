#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include "ke.h"
#include "mm.h"
#include "ntosdef.h"

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
