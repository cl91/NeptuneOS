/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/heap.c
 * PURPOSE:         RTL Heap backend allocator
 * PROGRAMMERS:     Copyright 2010 Aleksey Bragin
 *                  Copyright 2020 Katayama Hirofumi MZ
 */

/* Useful references:
   http://msdn.microsoft.com/en-us/library/ms810466.aspx
   http://msdn.microsoft.com/en-us/library/ms810603.aspx
   http://www.securitylab.ru/analytics/216376.php
   http://binglongx.spaces.live.com/blog/cns!142CBF6D49079DE8!596.entry
   http://www.phreedom.org/research/exploits/asn1-bitstring/
   http://illmatics.com/Understanding_the_LFH.pdf
   http://www.alex-ionescu.com/?p=18
*/

/* INCLUDES *****************************************************************/

#include <ntdll.h>
#include "heap.h"
#include "rtlp.h"

static RTL_CRITICAL_SECTION RtlpProcessHeapListLock;

/*
 * This function assumes that it is running under usermode (which
 * we always are).
 */
static VOID RtlpAddHeapToProcessList(PHEAP Heap)
{
    PPEB Peb;

    /* Get PEB */
    Peb = RtlGetCurrentPeb();

    /* Acquire the lock */
    RtlEnterCriticalSection(&RtlpProcessHeapListLock);

    /* Check if max number of heaps reached */
    if (Peb->NumberOfHeaps >= Peb->MaximumNumberOfHeaps) {
        // TODO: Handle this case
        ASSERT(FALSE);
    }

    /* Add the heap to the process heaps */
    Peb->ProcessHeaps[Peb->NumberOfHeaps] = Heap;
    Peb->NumberOfHeaps++;
    Heap->ProcessHeapsListIndex = (USHORT)(Peb->NumberOfHeaps);

    /* Release the lock */
    RtlLeaveCriticalSection(&RtlpProcessHeapListLock);
}

/*
 * This function assumes that it is running under usermode (which
 * we always are).
 */
static VOID RtlpRemoveHeapFromProcessList(PHEAP Heap)
{
    PPEB Peb;
    PHEAP *Current, *Next;
    ULONG Count;

    /* Get PEB */
    Peb = RtlGetCurrentPeb();

    /* Acquire the lock */
    RtlEnterCriticalSection(&RtlpProcessHeapListLock);

    /* Check if we don't need anything to do */
    if ((Heap->ProcessHeapsListIndex == 0) ||
        (Heap->ProcessHeapsListIndex > Peb->NumberOfHeaps) ||
        (Peb->NumberOfHeaps == 0)) {
        /* Release the lock */
        RtlLeaveCriticalSection(&RtlpProcessHeapListLock);

        return;
    }

    /* The process actually has more than one heap.
       Use classic, lernt from university times algorithm for removing an entry
       from a static array */

    Current = (PHEAP *)&Peb->ProcessHeaps[Heap->ProcessHeapsListIndex - 1];
    Next = Current + 1;

    /* How many items we need to shift to the left */
    Count = Peb->NumberOfHeaps - (Heap->ProcessHeapsListIndex - 1);

    /* Move them all in a loop */
    while (--Count) {
        /* Copy it and advance next pointer */
        *Current = *Next;

        /* Update its index */
        (*Current)->ProcessHeapsListIndex -= 1;

        /* Advance pointers */
        Current++;
        Next++;
    }

    /* Decrease total number of heaps */
    Peb->NumberOfHeaps--;

    /* Zero last unused item */
    Peb->ProcessHeaps[Peb->NumberOfHeaps] = NULL;
    Heap->ProcessHeapsListIndex = 0;

    /* Release the lock */
    RtlLeaveCriticalSection(&RtlpProcessHeapListLock);
}

/* Bitmaps stuff */

/* How many least significant bits are clear */
UCHAR RtlpBitsClearLow[] = {
    8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
    4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};

FORCEINLINE UCHAR RtlpFindLeastSetBit(ULONG Bits)
{
    if (Bits & 0xFFFF) {
	if (Bits & 0xFF)
	    return RtlpBitsClearLow[Bits & 0xFF];	/* Lowest byte */
	else
	    return RtlpBitsClearLow[(Bits >> 8) & 0xFF] + 8;	/* 2nd byte */
    } else {
	if ((Bits >> 16) & 0xFF)
	    return RtlpBitsClearLow[(Bits >> 16) & 0xFF] + 16;	/* 3rd byte */
	else
	    return RtlpBitsClearLow[(Bits >> 24) & 0xFF] + 24;	/* Highest byte */
    }
}

/* Maximum size of a tail-filling pattern used for compare operation */
UCHAR FillPattern[HEAP_ENTRY_SIZE] = {
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL,
    HEAP_TAIL_FILL
};

static BOOLEAN RtlpIsLastCommittedEntry(PHEAP_ENTRY Entry)
{
    if (Entry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY)
	return TRUE;

    Entry = Entry + Entry->CommonEntry.Size;

    /* 1-sized busy last entry are the committed range guard entries */
    if ((Entry->CommonEntry.Flags != (HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY))
	|| (Entry->CommonEntry.Size != 1))
	return FALSE;

    /* This must be the last or the penultimate entry in the page  */
    ASSERT(((PVOID) PAGE_ROUND_UP(Entry) == (Entry + 1)) ||
	   ((PVOID) PAGE_ROUND_UP(Entry) == (Entry + 2)));
    return TRUE;
}

/* FUNCTIONS *****************************************************************/

NTSTATUS RtlpInitializeHeap(OUT PHEAP Heap,
			    IN ULONG Flags,
			    IN PHEAP_LOCK Lock OPTIONAL,
			    IN HANDLE HeapLockSemaphore OPTIONAL,
			    IN PRTL_HEAP_PARAMETERS Parameters)
{
    ULONG NumUCRs = 8;
    ULONG Index;
    SIZE_T HeaderSize;
    NTSTATUS Status;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    SIZE_T DeCommitFreeBlockThreshold;

    /* Preconditions */
    ASSERT(Heap != NULL);
    ASSERT(Parameters != NULL);
    ASSERT(!(Flags & HEAP_LOCK_USER_ALLOCATED));
    ASSERT(!(Flags & HEAP_NO_SERIALIZE) || (Lock == NULL));	/* HEAP_NO_SERIALIZE => no lock */

    /* Make sure we're not doing stupid things */
    DeCommitFreeBlockThreshold = Parameters->DeCommitFreeBlockThreshold >> HEAP_ENTRY_SHIFT;
    /* Start out with the size of a plain Heap header + our hints of free entries + the bitmap */
    HeaderSize = FIELD_OFFSET(HEAP, FreeHints[DeCommitFreeBlockThreshold])
	+ (ROUND_UP(DeCommitFreeBlockThreshold, RTL_BITS_OF(ULONG)) /
	   RTL_BITS_OF(ULONG)) * sizeof(ULONG);

    /* Check if space needs to be added for the Heap Lock */
    if (!(Flags & HEAP_NO_SERIALIZE)) {
	if (Lock != NULL) {
	    /* The user manages the Heap Lock */
	    Flags |= HEAP_LOCK_USER_ALLOCATED;
	} else {
	    /* In user mode (we always are), the Heap Lock trails the Heap header */
	    Lock = (PHEAP_LOCK) ((ULONG_PTR) (Heap) + HeaderSize);
	    HeaderSize += sizeof(HEAP_LOCK);
	}
    }

    /* Add space for the initial Heap UnCommitted Range Descriptor list */
    UcrDescriptor = (PHEAP_UCR_DESCRIPTOR) ((ULONG_PTR) (Heap) + HeaderSize);
    HeaderSize += NumUCRs * sizeof(HEAP_UCR_DESCRIPTOR);

    HeaderSize = ROUND_UP(HeaderSize, HEAP_ENTRY_SIZE);
    /* Sanity check */
    ASSERT(HeaderSize <= PAGE_SIZE);

    /* Initialise the Heap Entry header containing the Heap header */
    Heap->Entry.CommonEntry.Size = (USHORT) (HeaderSize >> HEAP_ENTRY_SHIFT);
    Heap->Entry.CommonEntry.Flags = HEAP_ENTRY_BUSY;
    Heap->Entry.CommonEntry.SmallTagIndex =
	LOBYTE(Heap->Entry.CommonEntry.Size) ^ HIBYTE(Heap->Entry.CommonEntry.Size)
	^ Heap->Entry.CommonEntry.Flags;
    Heap->Entry.CommonEntry.PreviousSize = 0;
    Heap->Entry.CommonEntry.SegmentOffset = 0;
    Heap->Entry.CommonEntry.UnusedBytes = 0;

    /* Initialise the Heap header */
    Heap->Signature = HEAP_SIGNATURE;
    Heap->Flags = Flags;
    Heap->ForceFlags = (Flags & (HEAP_NO_SERIALIZE |
				 HEAP_GENERATE_EXCEPTIONS |
				 HEAP_ZERO_MEMORY |
				 HEAP_REALLOC_IN_PLACE_ONLY |
				 HEAP_VALIDATE_PARAMETERS_ENABLED |
				 HEAP_VALIDATE_ALL_ENABLED |
				 HEAP_TAIL_CHECKING_ENABLED |
				 HEAP_CREATE_ALIGN_16 |
				 HEAP_FREE_CHECKING_ENABLED));

    /* Initialise the Heap parameters */
    Heap->VirtualMemoryThreshold = ROUND_UP(Parameters->VirtualMemoryThreshold,
					    sizeof(HEAP_ENTRY)) >> HEAP_ENTRY_SHIFT;
    Heap->SegmentReserve = Parameters->SegmentReserve;
    Heap->SegmentCommit = Parameters->SegmentCommit;
    Heap->DeCommitFreeBlockThreshold = DeCommitFreeBlockThreshold;
    Heap->DeCommitTotalFreeThreshold = Parameters->DeCommitTotalFreeThreshold >> HEAP_ENTRY_SHIFT;
    Heap->MaximumAllocationSize = Parameters->MaximumAllocationSize;
    Heap->CommitRoutine = Parameters->CommitRoutine;

    /* Initialise the Heap validation info */
    Heap->HeaderValidateCopy = NULL;
    Heap->HeaderValidateLength = (USHORT) HeaderSize;

    /* Initialise the Heap Lock */
    if (!(Flags & HEAP_NO_SERIALIZE) && !(Flags & HEAP_LOCK_USER_ALLOCATED)) {
	if (HeapLockSemaphore != NULL) {
	    Status = RtlpInitializeHeapLockEx(Lock, HeapLockSemaphore);
	} else {
	    Status = RtlpInitializeHeapLock(Lock);
	}
	if (!NT_SUCCESS(Status))
	    return Status;
    }
    Heap->LockVariable = Lock;

    /* Initialise the Heap alignment info */
    if (Flags & HEAP_CREATE_ALIGN_16) {
	Heap->AlignMask = (ULONG) ~ 15;
	Heap->AlignRound = 15 + sizeof(HEAP_ENTRY);
    } else {
	Heap->AlignMask = (ULONG) ~ (sizeof(HEAP_ENTRY) - 1);
	Heap->AlignRound = 2 * sizeof(HEAP_ENTRY) - 1;
    }

    if (Flags & HEAP_TAIL_CHECKING_ENABLED)
	Heap->AlignRound += sizeof(HEAP_ENTRY);

    /* Initialise the Heap Segment list */
    for (Index = 0; Index < HEAP_SEGMENTS; ++Index)
	Heap->Segments[Index] = NULL;

    /* Initialise the free entry lists. */
    InitializeListHead(&Heap->FreeLists);
    RtlInitializeBitMap(&Heap->FreeHintBitmap,
			(PULONG) &Heap->FreeHints[DeCommitFreeBlockThreshold],
			DeCommitFreeBlockThreshold);
    RtlClearAllBits(&Heap->FreeHintBitmap);
    RtlZeroMemory(&Heap->FreeHints[0],
		  sizeof(Heap->FreeHints[0]) * DeCommitFreeBlockThreshold);

    /* Initialise the Heap Virtual Allocated Blocks list */
    InitializeListHead(&Heap->VirtualAllocdBlocks);

    /* Initialise the Heap UnCommitted Region lists */
    InitializeListHead(&Heap->UCRSegments);
    InitializeListHead(&Heap->UCRList);

    /* Register the initial Heap UnCommitted Region Descriptors */
    for (Index = 0; Index < NumUCRs; ++Index) {
	InsertTailList(&Heap->UCRList, &UcrDescriptor[Index].ListEntry);
    }

    return STATUS_SUCCESS;
}

VOID RtlpInsertFreeBlockHelper(PHEAP Heap,
			       PHEAP_FREE_ENTRY FreeEntry,
			       SIZE_T BlockSize,
			       BOOLEAN NoFill)
{
    ULONG HintIndex, NextHintIndex;

    ASSERT(FreeEntry->CommonEntry.Size == BlockSize);

    /* Fill if it's not denied */
    if (!NoFill) {
	FreeEntry->CommonEntry.Flags &= ~(HEAP_ENTRY_FILL_PATTERN |
					  HEAP_ENTRY_EXTRA_PRESENT |
					  HEAP_ENTRY_BUSY);

	if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED) {
	    RtlFillMemoryUlong((PCHAR) (FreeEntry + 1),
			       (BlockSize << HEAP_ENTRY_SHIFT) -
			       sizeof(*FreeEntry), ARENA_FREE_FILLER);

	    FreeEntry->CommonEntry.Flags |= HEAP_ENTRY_FILL_PATTERN;
	}
    } else {
	/* Clear out all flags except the last entry one */
	FreeEntry->CommonEntry.Flags &= HEAP_ENTRY_LAST_ENTRY;
    }

    /* See if this should go to the dedicated list */
    if (BlockSize > Heap->DeCommitFreeBlockThreshold) {
	PLIST_ENTRY ListEntry = Heap->FreeHints[0];

	/* Check if we have a hint there */
	if (ListEntry == NULL) {
	    ASSERT(!RtlTestBit(&Heap->FreeHintBitmap, 0));
	    Heap->FreeHints[0] = &FreeEntry->FreeList;
	    RtlSetBit(&Heap->FreeHintBitmap, 0);
	    InsertTailList(&Heap->FreeLists, &FreeEntry->FreeList);
	    return;
	}

	ASSERT(RtlTestBit(&Heap->FreeHintBitmap, 0));

	while (ListEntry != &Heap->FreeLists) {
	    PHEAP_FREE_ENTRY PreviousEntry = CONTAINING_RECORD(ListEntry,
							       HEAP_FREE_ENTRY,
							       FreeList);
	    if (PreviousEntry->CommonEntry.Size >= BlockSize) {
		DPRINT("Inserting size %zu before %u.\n", BlockSize,
		       PreviousEntry->CommonEntry.Size);
		break;
	    }

	    ListEntry = ListEntry->Flink;
	}

	InsertTailList(ListEntry, &FreeEntry->FreeList);

	/* Update our hint if needed */
	if (Heap->FreeHints[0] == ListEntry)
	    Heap->FreeHints[0] = &FreeEntry->FreeList;

	return;
    }

    ASSERT(BlockSize >= 2);
    HintIndex = BlockSize - 1;

    if (Heap->FreeHints[HintIndex] != NULL) {
	ASSERT(RtlTestBit(&Heap->FreeHintBitmap, HintIndex));

	/* Insert it after our hint. */
	InsertHeadList(Heap->FreeHints[HintIndex], &FreeEntry->FreeList);

	return;
    }

    /* This is the first time we insert such an entry in the list. */
    ASSERT(!RtlTestBit(&Heap->FreeHintBitmap, HintIndex));
    if (IsListEmpty(&Heap->FreeLists)) {
	/* First entry inserted in this list ever */
	InsertHeadList(&Heap->FreeLists, &FreeEntry->FreeList);
	RtlSetBit(&Heap->FreeHintBitmap, HintIndex);
	Heap->FreeHints[HintIndex] = &FreeEntry->FreeList;
	return;
    }

    /* Find the closest one */
    NextHintIndex = RtlFindSetBits(&Heap->FreeHintBitmap, 1, HintIndex);
    ASSERT(NextHintIndex != 0xFFFFFFFF);
    if ((NextHintIndex == 0) || (NextHintIndex > HintIndex)) {
	/*
	 * We found a larger entry. Insert this one before.
	 * It is guaranteed to be our successor in the list.
	 */
	InsertTailList(Heap->FreeHints[NextHintIndex],
		       &FreeEntry->FreeList);
    } else {
	/* We only found an entry smaller than us. Then we will be the largest one. */
	ASSERT(CONTAINING_RECORD(Heap->FreeLists.Blink, HEAP_FREE_ENTRY,
				 FreeList)->CommonEntry.Size < BlockSize);
	InsertTailList(&Heap->FreeLists, &FreeEntry->FreeList);
    }

    /* Setup our hint */
    RtlSetBit(&Heap->FreeHintBitmap, HintIndex);
    Heap->FreeHints[HintIndex] = &FreeEntry->FreeList;
}

VOID RtlpInsertFreeBlock(PHEAP Heap,
			 PHEAP_FREE_ENTRY FreeEntry,
			 SIZE_T BlockSize)
{
    USHORT Size, PreviousSize;
    UCHAR SegmentOffset, Flags;
    PHEAP_SEGMENT Segment;

    DPRINT("RtlpInsertFreeBlock(%p %p %zx)\n", Heap, FreeEntry, BlockSize);

    /* Increase the free size counter */
    Heap->TotalFreeSize += BlockSize;

    /* Remember certain values */
    Flags = FreeEntry->CommonEntry.Flags;
    PreviousSize = FreeEntry->CommonEntry.PreviousSize;
    SegmentOffset = FreeEntry->CommonEntry.SegmentOffset;
    Segment = Heap->Segments[SegmentOffset];

    /* Process it */
    while (BlockSize) {
	/* Check for the max size */
	if (BlockSize > HEAP_MAX_BLOCK_SIZE) {
	    Size = HEAP_MAX_BLOCK_SIZE;

	    /* Special compensation if it goes above limit just by 1 */
	    if (BlockSize == (HEAP_MAX_BLOCK_SIZE + 1))
		Size -= 16;

	    FreeEntry->CommonEntry.Flags = 0;
	} else {
	    Size = (USHORT) BlockSize;
	    FreeEntry->CommonEntry.Flags = Flags;
	}

	/* Change its size and insert it into a free list */
	FreeEntry->CommonEntry.Size = Size;
	FreeEntry->CommonEntry.PreviousSize = PreviousSize;
	FreeEntry->CommonEntry.SegmentOffset = SegmentOffset;

	/* Call a helper to actually insert the block */
	RtlpInsertFreeBlockHelper(Heap, FreeEntry, Size, FALSE);

	/* Update sizes */
	PreviousSize = Size;
	BlockSize -= Size;

	/* Go to the next entry */
	FreeEntry = (PHEAP_FREE_ENTRY) ((PHEAP_ENTRY) FreeEntry + Size);

	/* Check if that's all */
	if ((PHEAP_ENTRY) FreeEntry >= Segment->LastValidEntry)
	    return;
    }

    /* Update previous size if needed */
    if (!(Flags & HEAP_ENTRY_LAST_ENTRY))
	FreeEntry->CommonEntry.PreviousSize = PreviousSize;
}

static VOID RtlpRemoveFreeBlock(PHEAP Heap,
				PHEAP_FREE_ENTRY FreeEntry,
				BOOLEAN NoFill)
{
    SIZE_T Result, RealSize;
    ULONG HintIndex;

    /* Remove the free block */
    if (FreeEntry->CommonEntry.Size > Heap->DeCommitFreeBlockThreshold)
	HintIndex = 0;
    else
	HintIndex = FreeEntry->CommonEntry.Size - 1;

    ASSERT(RtlTestBit(&Heap->FreeHintBitmap, HintIndex));

    /* Are we removing the hint entry for this size ? */
    if (Heap->FreeHints[HintIndex] == &FreeEntry->FreeList) {
	PHEAP_FREE_ENTRY NewHintEntry = NULL;
	if (FreeEntry->FreeList.Flink != &Heap->FreeLists) {
	    NewHintEntry = CONTAINING_RECORD(FreeEntry->FreeList.Flink,
					     HEAP_FREE_ENTRY, FreeList);
	    /*
	     * In non-dedicated list, we just put the next entry as hint.
	     * For the dedicated ones, we take care of putting entries of the right size hint.
	     */
	    if ((HintIndex != 0)
		&& (NewHintEntry->CommonEntry.Size != FreeEntry->CommonEntry.Size)) {
		/* Of course this must be a larger one after us */
		ASSERT(NewHintEntry->CommonEntry.Size > FreeEntry->CommonEntry.Size);
		NewHintEntry = NULL;
	    }
	}

	/* Replace the hint, if we can */
	if (NewHintEntry != NULL) {
	    Heap->FreeHints[HintIndex] = &NewHintEntry->FreeList;
	} else {
	    Heap->FreeHints[HintIndex] = NULL;
	    RtlClearBit(&Heap->FreeHintBitmap, HintIndex);
	}
    }

    RemoveEntryList(&FreeEntry->FreeList);

    /* Fill with pattern if necessary */
    if (!NoFill && (FreeEntry->CommonEntry.Flags & HEAP_ENTRY_FILL_PATTERN)) {
	RealSize =
	    (FreeEntry->CommonEntry.Size << HEAP_ENTRY_SHIFT) - sizeof(*FreeEntry);

	/* Deduct extra stuff from block's real size */
	if (FreeEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT &&
	    RealSize > sizeof(HEAP_FREE_ENTRY_EXTRA)) {
	    RealSize -= sizeof(HEAP_FREE_ENTRY_EXTRA);
	}

	/* Check if the free filler is intact */
	Result = RtlCompareMemoryUlong((PCHAR) (FreeEntry + 1),
				       RealSize, ARENA_FREE_FILLER);

	if (Result != RealSize) {
	    DPRINT1
		("Free heap block %p modified at %p after it was freed\n",
		 FreeEntry, (PCHAR) (FreeEntry + 1) + Result);
	}
    }
}

SIZE_T RtlpGetSizeOfBigBlock(PHEAP_ENTRY HeapEntry)
{
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;

    /* Get pointer to the containing record */
    VirtualEntry =
	CONTAINING_RECORD(HeapEntry, HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);
    ASSERT(VirtualEntry->BusyBlock.CommonEntry.Size >=
	   sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));

    /* Restore the real size */
    return VirtualEntry->CommitSize - HeapEntry->CommonEntry.Size;
}

PHEAP_UCR_DESCRIPTOR RtlpCreateUnCommittedRange(PHEAP_SEGMENT Segment)
{
    PLIST_ENTRY Entry;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    PHEAP_UCR_SEGMENT UcrSegment;
    PHEAP Heap = Segment->Heap;
    SIZE_T ReserveSize = 16 * PAGE_SIZE;
    SIZE_T CommitSize = 1 * PAGE_SIZE;
    NTSTATUS Status;

    DPRINT("RtlpCreateUnCommittedRange(%p)\n", Segment);

    /* Check if we have unused UCRs */
    if (IsListEmpty(&Heap->UCRList)) {
	/* Get a pointer to the first UCR segment */
	UcrSegment =
	    CONTAINING_RECORD(Heap->UCRSegments.Flink, HEAP_UCR_SEGMENT,
			      ListEntry);

	/* Check the list of UCR segments */
	if (IsListEmpty(&Heap->UCRSegments) ||
	    UcrSegment->ReservedSize == UcrSegment->CommittedSize) {
	    /* We need to create a new one. Reserve 16 pages for it */
	    UcrSegment = NULL;
	    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					     (PVOID *) & UcrSegment,
					     0,
					     &ReserveSize,
					     MEM_RESERVE, PAGE_READWRITE);

	    if (!NT_SUCCESS(Status))
		return NULL;

	    /* Commit one page */
	    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					     (PVOID *) & UcrSegment,
					     0,
					     &CommitSize,
					     MEM_COMMIT, PAGE_READWRITE);

	    if (!NT_SUCCESS(Status)) {
		/* Release reserved memory */
		NtFreeVirtualMemory(NtCurrentProcess(),
				    (PVOID *) & UcrSegment,
				    &ReserveSize, MEM_RELEASE);
		return NULL;
	    }

	    /* Set it's data */
	    UcrSegment->ReservedSize = ReserveSize;
	    UcrSegment->CommittedSize = CommitSize;

	    /* Add it to the head of the list */
	    InsertHeadList(&Heap->UCRSegments, &UcrSegment->ListEntry);

	    /* Get a pointer to the first available UCR descriptor */
	    UcrDescriptor = (PHEAP_UCR_DESCRIPTOR) (UcrSegment + 1);
	} else {
	    /* It's possible to use existing UCR segment. Commit one more page */
	    UcrDescriptor =
		(PHEAP_UCR_DESCRIPTOR) ((PCHAR) UcrSegment +
					UcrSegment->CommittedSize);
	    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					     (PVOID *) & UcrDescriptor, 0,
					     &CommitSize, MEM_COMMIT,
					     PAGE_READWRITE);

	    if (!NT_SUCCESS(Status))
		return NULL;

	    ASSERT((PCHAR) UcrDescriptor ==
		   ((PCHAR) UcrSegment + UcrSegment->CommittedSize));

	    /* Update sizes */
	    UcrSegment->CommittedSize += CommitSize;
	}

	/* There is a whole bunch of new UCR descriptors. Put them into the unused list */
	while ((PCHAR) (UcrDescriptor + 1) <=
	       (PCHAR) UcrSegment + UcrSegment->CommittedSize) {
	    InsertTailList(&Heap->UCRList, &UcrDescriptor->ListEntry);
	    UcrDescriptor++;
	}
    }

    /* There are unused UCRs, just get the first one */
    Entry = RemoveHeadList(&Heap->UCRList);
    UcrDescriptor =
	CONTAINING_RECORD(Entry, HEAP_UCR_DESCRIPTOR, ListEntry);
    return UcrDescriptor;
}

VOID RtlpDestroyUnCommittedRange(PHEAP_SEGMENT Segment,
				 PHEAP_UCR_DESCRIPTOR UcrDescriptor)
{
    /* Zero it out */
    UcrDescriptor->Address = NULL;
    UcrDescriptor->Size = 0;

    /* Put it into the heap's list of unused UCRs */
    InsertHeadList(&Segment->Heap->UCRList, &UcrDescriptor->ListEntry);
}

VOID RtlpInsertUnCommittedPages(PHEAP_SEGMENT Segment,
				ULONG_PTR Address,
				SIZE_T Size)
{
    PLIST_ENTRY Current;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;

    DPRINT("RtlpInsertUnCommittedPages(%p 0x%zx 0x%zx)\n", Segment, Address,
	   Size);

    /* Go through the list of UCR descriptors, they are sorted from lowest address
       to the highest */
    Current = Segment->UCRSegmentList.Flink;
    while (Current != &Segment->UCRSegmentList) {
	UcrDescriptor =
	    CONTAINING_RECORD(Current, HEAP_UCR_DESCRIPTOR, SegmentEntry);

	if ((ULONG_PTR) UcrDescriptor->Address > Address) {
	    /* Check for a really lucky case */
	    if ((Address + Size) == (ULONG_PTR) UcrDescriptor->Address) {
		/* Exact match */
		UcrDescriptor->Address = (PVOID) Address;
		UcrDescriptor->Size += Size;
		return;
	    }

	    /* We found the block before which the new one should go */
	    break;
	} else
	    if (((ULONG_PTR) UcrDescriptor->Address +
		 UcrDescriptor->Size) == Address) {
		/* Modify this entry */
		Address = (ULONG_PTR) UcrDescriptor->Address;
		Size += UcrDescriptor->Size;

		/* Advance to the next descriptor */
		Current = Current->Flink;

		/* Remove the current descriptor from the list and destroy it */
		RemoveEntryList(&UcrDescriptor->SegmentEntry);
		RtlpDestroyUnCommittedRange(Segment, UcrDescriptor);

		Segment->NumberOfUnCommittedRanges--;
	    } else {
		/* Advance to the next descriptor */
		Current = Current->Flink;
	    }
    }

    /* Create a new UCR descriptor */
    UcrDescriptor = RtlpCreateUnCommittedRange(Segment);
    if (!UcrDescriptor)
	return;

    UcrDescriptor->Address = (PVOID) Address;
    UcrDescriptor->Size = Size;

    /* "Current" is the descriptor before which our one should go */
    InsertTailList(Current, &UcrDescriptor->SegmentEntry);

    DPRINT("Added segment UCR with base 0x%zx, size 0x%zx\n", Address,
	   Size);

    /* Increase counters */
    Segment->NumberOfUnCommittedRanges++;
}

static PHEAP_FREE_ENTRY RtlpFindAndCommitPages(PHEAP Heap,
					       PHEAP_SEGMENT Segment,
					       PSIZE_T Size,
					       PVOID AddressRequested)
{
    PLIST_ENTRY Current;
    NTSTATUS Status;

    DPRINT("RtlpFindAndCommitPages(%p %p 0x%zx %p)\n",
	   Heap, Segment, *Size, AddressRequested);

    /* Go through UCRs in a segment */
    Current = Segment->UCRSegmentList.Flink;
    while (Current != &Segment->UCRSegmentList) {
	PHEAP_UCR_DESCRIPTOR UcrDescriptor = CONTAINING_RECORD(Current, HEAP_UCR_DESCRIPTOR, SegmentEntry);

	/* Check if we can use that one right away */
	if (UcrDescriptor->Size >= *Size &&
	    ((UcrDescriptor->Address == AddressRequested) || !AddressRequested)) {
	    PVOID Address = UcrDescriptor->Address;

	    /* Commit it */
	    if (Heap->CommitRoutine) {
		Status = Heap->CommitRoutine(Heap, &Address, Size);
	    } else {
		Status = NtAllocateVirtualMemory(NtCurrentProcess(),
						 &Address,
						 0,
						 Size,
						 MEM_COMMIT,
						 PAGE_READWRITE);
	    }

	    DPRINT("Committed 0x%zx bytes at base %p, UCR size is 0x%zx\n",
		   *Size, Address, UcrDescriptor->Size);

	    /* Fail in unsuccessful case */
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("Committing page failed with status 0x%08X\n", Status);
		return NULL;
	    }

	    /* Update tracking numbers */
	    Segment->NumberOfUnCommittedPages -= (ULONG) (*Size / PAGE_SIZE);

	    /* Update UCR descriptor */
	    UcrDescriptor->Address = (PVOID) ((ULONG_PTR) UcrDescriptor->Address + *Size);
	    UcrDescriptor->Size -= *Size;

	    /* Grab the previous guard entry */
	    PHEAP_ENTRY GuardEntry = (PHEAP_ENTRY) Address - 1;
	    ASSERT(GuardEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY);
	    ASSERT(GuardEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY);
	    ASSERT(GuardEntry->CommonEntry.Size == 1);

	    /* Did we have a double guard entry ? */
	    if (GuardEntry->CommonEntry.PreviousSize == 1) {
		/* Use the one before instead */
		GuardEntry--;

		ASSERT(GuardEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY);
		ASSERT(GuardEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY);
		ASSERT(GuardEntry->CommonEntry.Size == 1);

		/* We gain one slot more */
		*Size += HEAP_ENTRY_SIZE;
	    }

	    /* This will become our returned free entry.
	     * Now we can make it span the whole committed range.
	     * But we keep one slot for a guard entry, if needed.
	     */
	    PHEAP_ENTRY FreeEntry = GuardEntry;

	    FreeEntry->CommonEntry.Flags &= ~(HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY);
	    FreeEntry->CommonEntry.Size = (*Size) >> HEAP_ENTRY_SHIFT;

	    DPRINT("Updating UcrDescriptor %p, new Address %p, size 0x%zx\n",
		   UcrDescriptor, UcrDescriptor->Address, UcrDescriptor->Size);

	    /* Check if anything left in this UCR */
	    if (UcrDescriptor->Size == 0) {
		/* It's fully exhausted. Take the guard entry for us */
		FreeEntry->CommonEntry.Size++;
		*Size += HEAP_ENTRY_SIZE;

		ASSERT((FreeEntry + FreeEntry->CommonEntry.Size) == UcrDescriptor->Address);

		/* Check if this is the end of the segment */
		if (UcrDescriptor->Address == Segment->LastValidEntry) {
		    FreeEntry->CommonEntry.Flags = HEAP_ENTRY_LAST_ENTRY;
		} else {
		    PHEAP_ENTRY NextEntry = UcrDescriptor->Address;

		    /* We should not have a UCR right behind us */
		    ASSERT((UcrDescriptor->SegmentEntry.Flink == &Segment->UCRSegmentList)
			   || (CONTAINING_RECORD(UcrDescriptor->SegmentEntry.Flink,
						 HEAP_UCR_DESCRIPTOR,
						 SegmentEntry)->Address > UcrDescriptor->Address));

		    ASSERT(NextEntry->CommonEntry.PreviousSize == 0);
		    ASSERT(NextEntry == FreeEntry + FreeEntry->CommonEntry.Size);
		    NextEntry->CommonEntry.PreviousSize = FreeEntry->CommonEntry.Size;
		}

		/* This UCR needs to be removed because it became useless */
		RemoveEntryList(&UcrDescriptor->SegmentEntry);

		RtlpDestroyUnCommittedRange(Segment, UcrDescriptor);
		Segment->NumberOfUnCommittedRanges--;
	    } else {
		/* Setup a guard entry */
		GuardEntry = (PHEAP_ENTRY) UcrDescriptor->Address - 1;
		ASSERT(GuardEntry == FreeEntry + FreeEntry->CommonEntry.Size);
		GuardEntry->CommonEntry.Flags = HEAP_ENTRY_LAST_ENTRY | HEAP_ENTRY_BUSY;
		GuardEntry->CommonEntry.Size = 1;
		GuardEntry->CommonEntry.PreviousSize = FreeEntry->CommonEntry.Size;
		GuardEntry->CommonEntry.SegmentOffset = FreeEntry->CommonEntry.SegmentOffset;
		DPRINT("Setting %p as UCR guard entry (at line %d of %s) ",
		       GuardEntry, __LINE__, __FILE__);
		RtlpDbgDumpHeapEntry(GuardEntry);
	    }

	    /* We're done */
	    return (PHEAP_FREE_ENTRY) FreeEntry;
	}

	/* Advance to the next descriptor */
	Current = Current->Flink;
    }

    return NULL;
}

static PHEAP_FREE_ENTRY RtlpCoalesceFreeBlocks(PHEAP Heap,
					       PHEAP_FREE_ENTRY FreeEntry,
					       PSIZE_T FreeSize,
					       BOOLEAN Remove)
{
    assert(Heap != NULL);
    assert(FreeEntry != NULL);
    assert(FreeSize != NULL);
    DPRINT("Coalescing free blocks for heap %p free entry %p *FreeSize 0x%zx (actually 0x%zx) remove %s\n",
	   Heap, FreeEntry, *FreeSize, *FreeSize << HEAP_ENTRY_SHIFT, Remove ? "TRUE" : "FALSE");

    /* Get the previous entry */
    PHEAP_FREE_ENTRY CurrentEntry = (PHEAP_FREE_ENTRY)((PHEAP_ENTRY)FreeEntry - FreeEntry->CommonEntry.PreviousSize);

    /* Check it */
    if ((CurrentEntry != FreeEntry) && !(CurrentEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY) &&
	((*FreeSize + CurrentEntry->CommonEntry.Size) <= HEAP_MAX_BLOCK_SIZE)) {
	ASSERT(FreeEntry->CommonEntry.PreviousSize == CurrentEntry->CommonEntry.Size);

	/* Remove it if asked for */
	if (Remove) {
	    RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
	    Heap->TotalFreeSize -= FreeEntry->CommonEntry.Size;

	    /* Remove it only once! */
	    Remove = FALSE;
	}

	/* Remove previous entry too */
	RtlpRemoveFreeBlock(Heap, CurrentEntry, FALSE);

	/* Copy flags */
	CurrentEntry->CommonEntry.Flags = FreeEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY;

	/* Advance FreeEntry and update sizes */
	FreeEntry = CurrentEntry;
	*FreeSize = *FreeSize + CurrentEntry->CommonEntry.Size;
	Heap->TotalFreeSize -= CurrentEntry->CommonEntry.Size;
	FreeEntry->CommonEntry.Size = (USHORT) (*FreeSize);

	/* Also update previous size if needed */
	if (!(FreeEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY)) {
	    ((PHEAP_ENTRY) FreeEntry + *FreeSize)->CommonEntry.PreviousSize = (USHORT) (*FreeSize);
	} else {
	    ASSERT(FreeEntry->CommonEntry.SegmentOffset < HEAP_SEGMENTS);
	}
    }

    /* Check the next block if it exists */
    if (!(FreeEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY)) {
	PHEAP_FREE_ENTRY NextEntry = (PHEAP_FREE_ENTRY) ((PHEAP_ENTRY) FreeEntry + *FreeSize);

	if (!(NextEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY) &&
	    NextEntry->CommonEntry.Size + *FreeSize <= HEAP_MAX_BLOCK_SIZE) {
	    ASSERT(*FreeSize == NextEntry->CommonEntry.PreviousSize);

	    /* Remove it if asked for */
	    if (Remove) {
		RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
		Heap->TotalFreeSize -= FreeEntry->CommonEntry.Size;
	    }

	    /* Copy flags */
	    FreeEntry->CommonEntry.Flags = NextEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY;

	    /* Remove next entry now */
	    RtlpRemoveFreeBlock(Heap, NextEntry, FALSE);

	    /* Update sizes */
	    *FreeSize = *FreeSize + NextEntry->CommonEntry.Size;
	    Heap->TotalFreeSize -= NextEntry->CommonEntry.Size;
	    FreeEntry->CommonEntry.Size = (USHORT) (*FreeSize);

	    /* Also update previous size if needed */
	    if (!(FreeEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY)) {
		((PHEAP_ENTRY) FreeEntry + *FreeSize)->CommonEntry.PreviousSize =
		    (USHORT) (*FreeSize);
	    } else {
		ASSERT(FreeEntry->CommonEntry.SegmentOffset < HEAP_SEGMENTS);
	    }
	}
    }
    return FreeEntry;
}

static VOID RtlpDeCommitFreeBlock(PHEAP Heap,
				  PHEAP_FREE_ENTRY FreeEntry,
				  SIZE_T Size)
{
    PHEAP_SEGMENT Segment;
    PHEAP_ENTRY NextEntry, GuardEntry;
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    SIZE_T PrecedingSize, DecommitSize;
    ULONG_PTR DecommitBase, DecommitEnd;
    NTSTATUS Status;

    DPRINT("Decommitting %p %p %zx\n", Heap, FreeEntry, Size);

    /* We can't decommit if there is a commit routine! */
    if (Heap->CommitRoutine) {
	/* Just add it back the usual way */
	RtlpInsertFreeBlock(Heap, FreeEntry, Size);
	return;
    }

    /* Get the segment */
    Segment = Heap->Segments[FreeEntry->CommonEntry.SegmentOffset];

    /* Get the preceding entry */
    DecommitBase = ROUND_UP(FreeEntry, PAGE_SIZE);
    PrecedingSize = (PHEAP_ENTRY) DecommitBase - (PHEAP_ENTRY) FreeEntry;

    if (PrecedingSize == 0) {
	/* We need some space in order to insert our guard entry */
	DecommitBase += PAGE_SIZE;
	PrecedingSize += PAGE_SIZE >> HEAP_ENTRY_SHIFT;
    }

    /* Get the entry after this one. */

    /* Do we really have a next entry */
    if (RtlpIsLastCommittedEntry((PHEAP_ENTRY) FreeEntry)) {
	/* No, Decommit till the next UCR. */
	DecommitEnd =
	    PAGE_ROUND_UP((PHEAP_ENTRY) FreeEntry + FreeEntry->CommonEntry.Size);
	NextEntry = NULL;
    } else {
	NextEntry = (PHEAP_ENTRY) FreeEntry + Size;
	DecommitEnd = PAGE_ROUND_DOWN(NextEntry);

	/* Can we make a free entry out of what's left ? */
	if ((NextEntry - (PHEAP_ENTRY) DecommitEnd) == 1) {
	    /* Nope. Let's keep one page before this */
	    DecommitEnd -= PAGE_SIZE;
	}
    }

    if (DecommitEnd <= DecommitBase) {
	/* There's nothing left to decommit. */
	RtlpInsertFreeBlock(Heap, FreeEntry, Size);
	return;
    }

    DecommitSize = DecommitEnd - DecommitBase;

    /* A decommit is necessary. Create a UCR descriptor */
    UcrDescriptor = RtlpCreateUnCommittedRange(Segment);
    if (!UcrDescriptor) {
	DPRINT1("HEAP: Failed to create UCR descriptor\n");
	RtlpInsertFreeBlock(Heap, FreeEntry, PrecedingSize);
	return;
    }

    /* Decommit the memory */
    Status = NtFreeVirtualMemory(NtCurrentProcess(),
				 (PVOID *) & DecommitBase,
				 &DecommitSize, MEM_DECOMMIT);
    ASSERT((DecommitBase + DecommitSize) == DecommitEnd);

    /* Delete that UCR. This is needed to assure there is an unused UCR entry in the list */
    RtlpDestroyUnCommittedRange(Segment, UcrDescriptor);

    if (!NT_SUCCESS(Status)) {
	RtlpInsertFreeBlock(Heap, FreeEntry, Size);
	return;
    }

    /* Insert uncommitted pages */
    RtlpInsertUnCommittedPages(Segment, DecommitBase, DecommitSize);
    Segment->NumberOfUnCommittedPages +=
	(ULONG) (DecommitSize / PAGE_SIZE);

    /* Insert our guard entry before this */
    GuardEntry = (PHEAP_ENTRY) DecommitBase - 1;
    GuardEntry->CommonEntry.Size = 1;
    GuardEntry->CommonEntry.Flags = HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
    GuardEntry->CommonEntry.SegmentOffset = FreeEntry->CommonEntry.SegmentOffset;
    DPRINT("Setting %p as UCR guard entry (at line %d of %s).\n", GuardEntry, __LINE__, __FILE__);

    /* Now see what's really behind us */
    PrecedingSize--;
    switch (PrecedingSize) {
    case 1:
	/* No space left for a free entry. Make this another guard entry */
	GuardEntry->CommonEntry.PreviousSize = 1;
	GuardEntry--;
	GuardEntry->CommonEntry.Size = 1;
	GuardEntry->CommonEntry.Flags = HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
	GuardEntry->CommonEntry.SegmentOffset = FreeEntry->CommonEntry.SegmentOffset;
	/* Fall-through */
    case 0:
	/* There was just enough space four our guard entry */
	ASSERT((PHEAP_ENTRY) FreeEntry == GuardEntry);
	GuardEntry->CommonEntry.PreviousSize = FreeEntry->CommonEntry.PreviousSize;
	break;
    default:
	/* We can insert this as a free entry */
	GuardEntry->CommonEntry.PreviousSize = PrecedingSize;
	FreeEntry->CommonEntry.Size = PrecedingSize;
	FreeEntry->CommonEntry.Flags &= ~HEAP_ENTRY_LAST_ENTRY;
	FreeEntry = RtlpCoalesceFreeBlocks(Heap, FreeEntry, &PrecedingSize, FALSE);
	RtlpInsertFreeBlock(Heap, FreeEntry, PrecedingSize);
	break;
    }

    /* Now the next one */
    if (NextEntry) {
	ASSERT((PHEAP_ENTRY) DecommitEnd <= NextEntry);

	SIZE_T NextSize = NextEntry - (PHEAP_ENTRY) DecommitEnd;
	if (NextSize) {
	    PHEAP_FREE_ENTRY NextFreeEntry =
		(PHEAP_FREE_ENTRY) DecommitEnd;

	    /* Make sure this is all valid */
	    ASSERT((PHEAP_ENTRY) DecommitEnd < Segment->LastValidEntry);
	    ASSERT(NextSize >= 2);

	    /* Adjust size of this free entry and insert it */
	    NextFreeEntry->CommonEntry.Flags = 0;
	    NextFreeEntry->CommonEntry.PreviousSize = 0;
	    NextFreeEntry->CommonEntry.SegmentOffset = Segment->Entry.CommonEntry.SegmentOffset;
	    NextFreeEntry->CommonEntry.Size = (USHORT) NextSize;

	    NextEntry->CommonEntry.PreviousSize = NextSize;
	    ASSERT(NextEntry == (PHEAP_ENTRY) NextFreeEntry + NextFreeEntry->CommonEntry.Size);

	    NextFreeEntry = RtlpCoalesceFreeBlocks(Heap, NextFreeEntry, &NextSize, FALSE);
	    RtlpInsertFreeBlock(Heap, NextFreeEntry, NextSize);
	} else {
	    /* This one must be at the beginning of a page */
	    ASSERT(NextEntry == (PHEAP_ENTRY) PAGE_ROUND_DOWN(NextEntry));
	    /* And we must have a gap betwwen */
	    ASSERT(NextEntry > (PHEAP_ENTRY) DecommitBase);
	    NextEntry->CommonEntry.PreviousSize = 0;
	}
    }
}

static NTSTATUS RtlpInitializeHeapSegment(IN OUT PHEAP Heap,
					  OUT PHEAP_SEGMENT Segment,
					  IN UCHAR SegmentIndex,
					  IN ULONG SegmentFlags,
					  IN SIZE_T SegmentReserve,
					  IN SIZE_T SegmentCommit)
{
    /* Preconditions */
    ASSERT(Heap != NULL);
    ASSERT(Segment != NULL);
    ASSERT(SegmentCommit >= PAGE_SIZE);
    ASSERT(ROUND_DOWN(SegmentCommit, PAGE_SIZE) == SegmentCommit);
    ASSERT(SegmentReserve >= SegmentCommit);
    ASSERT(ROUND_DOWN(SegmentReserve, PAGE_SIZE) == SegmentReserve);

    DPRINT("RtlpInitializeHeapSegment(%p %p %x %x %zx %zx)\n", Heap,
	   Segment, SegmentIndex, SegmentFlags, SegmentReserve,
	   SegmentCommit);

    /* Initialise the Heap Entry header if this is not the first Heap Segment */
    if ((PHEAP_SEGMENT) (Heap) != Segment) {
	Segment->Entry.CommonEntry.Size =
	    ROUND_UP(sizeof(HEAP_SEGMENT),
		     sizeof(HEAP_ENTRY)) >> HEAP_ENTRY_SHIFT;
	Segment->Entry.CommonEntry.Flags = HEAP_ENTRY_BUSY;
	Segment->Entry.CommonEntry.SmallTagIndex =
	    LOBYTE(Segment->Entry.CommonEntry.Size) ^ HIBYTE(Segment->Entry.CommonEntry.
						 Size) ^ Segment->Entry.CommonEntry.
	    Flags;
	Segment->Entry.CommonEntry.PreviousSize = 0;
	Segment->Entry.CommonEntry.SegmentOffset = SegmentIndex;
	Segment->Entry.CommonEntry.UnusedBytes = 0;
    }

    /* Sanity check */
    ASSERT((Segment->Entry.CommonEntry.Size << HEAP_ENTRY_SHIFT) <= PAGE_SIZE);

    /* Initialise the Heap Segment header */
    Segment->SegmentSignature = HEAP_SEGMENT_SIGNATURE;
    Segment->SegmentFlags = SegmentFlags;
    Segment->Heap = Heap;
    Heap->Segments[SegmentIndex] = Segment;

    /* Initialise the Heap Segment location information */
    Segment->BaseAddress = Segment;
    Segment->NumberOfPages = (ULONG) (SegmentReserve >> PAGE_SHIFT);

    /* Initialise the Heap Entries contained within the Heap Segment */
    Segment->FirstEntry = &Segment->Entry + Segment->Entry.CommonEntry.Size;
    Segment->LastValidEntry =
	(PHEAP_ENTRY) ((ULONG_PTR) Segment + SegmentReserve);

    /* Initialise the Heap Segment UnCommitted Range information */
    Segment->NumberOfUnCommittedPages =
	(ULONG) ((SegmentReserve - SegmentCommit) >> PAGE_SHIFT);
    Segment->NumberOfUnCommittedRanges = 0;
    InitializeListHead(&Segment->UCRSegmentList);

    /* We must have space for a guard entry ! */
    ASSERT(((SegmentCommit >> HEAP_ENTRY_SHIFT) > Segment->Entry.CommonEntry.Size)
	   || (Segment->NumberOfUnCommittedPages == 0));

    if (((SIZE_T) Segment->Entry.CommonEntry.Size << HEAP_ENTRY_SHIFT) < SegmentCommit) {
	PHEAP_ENTRY FreeEntry = NULL;

	if (Segment->NumberOfUnCommittedPages != 0) {
	    /* Ensure we put our guard entry at the end of the last committed page */
	    PHEAP_ENTRY GuardEntry =
		&Segment->Entry + (SegmentCommit >> HEAP_ENTRY_SHIFT) - 1;

	    ASSERT(GuardEntry > &Segment->Entry);
	    GuardEntry->CommonEntry.Size = 1;
	    GuardEntry->CommonEntry.Flags = HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
	    GuardEntry->CommonEntry.SegmentOffset = SegmentIndex;
	    GuardEntry->CommonEntry.PreviousSize = GuardEntry - Segment->FirstEntry;

	    /* Chack what is left behind us */
	    switch (GuardEntry->CommonEntry.PreviousSize) {
	    case 1:
		/* There is not enough space for a free entry. Double the guard entry */
		GuardEntry--;
		GuardEntry->CommonEntry.Size = 1;
		GuardEntry->CommonEntry.Flags =
		    HEAP_ENTRY_BUSY | HEAP_ENTRY_LAST_ENTRY;
		GuardEntry->CommonEntry.SegmentOffset = SegmentIndex;
		DPRINT1("Setting %p as UCR guard entry (at line %d of %s).\n", GuardEntry, __LINE__, __FILE__);
		/* Fall through */
	    case 0:
		ASSERT(GuardEntry == Segment->FirstEntry);
		GuardEntry->CommonEntry.PreviousSize = Segment->Entry.CommonEntry.Size;
		break;
	    default:
		/* There will be a free entry between the segment and the guard entry */
		FreeEntry = Segment->FirstEntry;
		FreeEntry->CommonEntry.PreviousSize = Segment->Entry.CommonEntry.Size;
		FreeEntry->CommonEntry.SegmentOffset = SegmentIndex;
		FreeEntry->CommonEntry.Size = GuardEntry->CommonEntry.PreviousSize;
		FreeEntry->CommonEntry.Flags = 0;
		break;
	    }
	} else {
	    /* Prepare a Free Heap Entry header */
	    FreeEntry = Segment->FirstEntry;
	    FreeEntry->CommonEntry.PreviousSize = Segment->Entry.CommonEntry.Size;
	    FreeEntry->CommonEntry.SegmentOffset = SegmentIndex;
	    FreeEntry->CommonEntry.Flags = HEAP_ENTRY_LAST_ENTRY;
	    FreeEntry->CommonEntry.Size =
		(SegmentCommit >> HEAP_ENTRY_SHIFT) - Segment->Entry.CommonEntry.Size;
	}

	/* Register the Free Heap Entry */
	if (FreeEntry)
	    RtlpInsertFreeBlock(Heap, (PHEAP_FREE_ENTRY) FreeEntry,
				FreeEntry->CommonEntry.Size);
    }

    /* Register the UnCommitted Range of the Heap Segment */
    if (Segment->NumberOfUnCommittedPages != 0)
	RtlpInsertUnCommittedPages(Segment,
				   (ULONG_PTR) (Segment) + SegmentCommit,
				   SegmentReserve - SegmentCommit);

    return STATUS_SUCCESS;
}

static VOID RtlpDestroyHeapSegment(PHEAP_SEGMENT Segment)
{
    NTSTATUS Status;
    PVOID BaseAddress;
    SIZE_T Size = 0;

    /* Make sure it's not user allocated */
    if (Segment->SegmentFlags & HEAP_USER_ALLOCATED)
	return;

    BaseAddress = Segment->BaseAddress;
    DPRINT("Destroying segment %p, BA %p\n", Segment, BaseAddress);

    /* Release virtual memory */
    Status = NtFreeVirtualMemory(NtCurrentProcess(),
				 &BaseAddress, &Size, MEM_RELEASE);

    if (!NT_SUCCESS(Status)) {
	DPRINT1
	    ("HEAP: Failed to release segment's memory with status 0x%08X\n",
	     Status);
    }
}

static PHEAP_FREE_ENTRY RtlpCoalesceHeap(PHEAP Heap)
{
    UNIMPLEMENTED;
    return NULL;
}

static PHEAP_FREE_ENTRY RtlpExtendHeap(PHEAP Heap, SIZE_T Size)
{
    ULONG Pages;
    UCHAR Index, EmptyIndex;
    SIZE_T FreeSize, CommitSize, ReserveSize;
    PHEAP_SEGMENT Segment;
    PHEAP_FREE_ENTRY FreeEntry;
    NTSTATUS Status;

    DPRINT("RtlpExtendHeap(%p %zx)\n", Heap, Size);

    /* Calculate amount in pages */
    Pages = (ULONG) ((Size + PAGE_SIZE - 1) / PAGE_SIZE);
    FreeSize = Pages * PAGE_SIZE;
    DPRINT("Pages %x, FreeSize %zx. Going through segments...\n", Pages,
	   FreeSize);

    /* Find an empty segment */
    EmptyIndex = HEAP_SEGMENTS;
    for (Index = 0; Index < HEAP_SEGMENTS; Index++) {
	Segment = Heap->Segments[Index];

	if (Segment)
	    DPRINT("Segment[%u] %p with NOUCP %x\n", Index, Segment,
		   Segment->NumberOfUnCommittedPages);

	/* Check if its size suits us */
	if (Segment && Pages <= Segment->NumberOfUnCommittedPages) {
	    DPRINT("This segment is suitable\n");

	    /* Commit needed amount */
	    FreeEntry = RtlpFindAndCommitPages(Heap, Segment, &FreeSize, NULL);

	    /* Coalesce it with adjacent entries */
	    if (FreeEntry) {
		FreeSize = FreeSize >> HEAP_ENTRY_SHIFT;
		FreeEntry = RtlpCoalesceFreeBlocks(Heap, FreeEntry, &FreeSize, FALSE);
		RtlpInsertFreeBlock(Heap, FreeEntry, FreeSize);
		return FreeEntry;
	    }
	} else if (!Segment && EmptyIndex == HEAP_SEGMENTS) {
	    /* Remember the first unused segment index */
	    EmptyIndex = Index;
	}
    }

    /* No luck, need to grow the heap */
    if ((Heap->Flags & HEAP_GROWABLE) && (EmptyIndex != HEAP_SEGMENTS)) {
	Segment = NULL;

	/* Reserve the memory */
	if ((Size + PAGE_SIZE) <= Heap->SegmentReserve)
	    ReserveSize = Heap->SegmentReserve;
	else
	    ReserveSize = Size + PAGE_SIZE;

	Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					 (PVOID) & Segment,
					 0,
					 &ReserveSize,
					 MEM_RESERVE, PAGE_READWRITE);

	/* If it failed, retry again with a half division algorithm */
	while (!NT_SUCCESS(Status) && ReserveSize != Size + PAGE_SIZE) {
	    ReserveSize /= 2;

	    if (ReserveSize < (Size + PAGE_SIZE))
		ReserveSize = Size + PAGE_SIZE;

	    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					     (PVOID) & Segment,
					     0,
					     &ReserveSize,
					     MEM_RESERVE, PAGE_READWRITE);
	}

	/* Proceed only if it's success */
	if (NT_SUCCESS(Status)) {
	    Heap->SegmentReserve += ReserveSize;

	    /* Now commit the memory */
	    if ((Size + PAGE_SIZE) <= Heap->SegmentCommit)
		CommitSize = Heap->SegmentCommit;
	    else
		CommitSize = Size + PAGE_SIZE;

	    Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					     (PVOID) & Segment,
					     0,
					     &CommitSize,
					     MEM_COMMIT, PAGE_READWRITE);

	    DPRINT("Committed %zu bytes at base %p\n", CommitSize,
		   Segment);

	    /* Initialize heap segment if commit was successful */
	    if (NT_SUCCESS(Status))
		Status = RtlpInitializeHeapSegment(Heap, Segment, EmptyIndex, 0,
						   ReserveSize, CommitSize);

	    /* If everything worked - cool */
	    if (NT_SUCCESS(Status))
		return (PHEAP_FREE_ENTRY) Segment->FirstEntry;

	    DPRINT1("Committing failed with status 0x%08X\n", Status);

	    /* Nope, we failed. Free memory */
	    NtFreeVirtualMemory(NtCurrentProcess(),
				(PVOID) & Segment,
				&ReserveSize, MEM_RELEASE);
	} else {
	    DPRINT1("Reserving failed with status 0x%08X\n", Status);
	}
    }

    /* If coalescing on free is disabled in usermode (which we always are),
     * then do it here */
    if (Heap->Flags & HEAP_DISABLE_COALESCE_ON_FREE) {
	FreeEntry = RtlpCoalesceHeap(Heap);

	/* If it's a suitable one - return it */
	if (FreeEntry && FreeEntry->CommonEntry.Size >= Size) {
	    return FreeEntry;
	}
    }

    return NULL;
}

static NTSTATUS RtlpRegisterHeap(IN PHEAP Heap,
				 IN ULONG HeapFlags,
				 IN ULONG HeapSegmentFlags,
				 IN PVOID Lock,
				 IN HANDLE HeapLockSemaphore,
				 IN PRTL_HEAP_PARAMETERS Parameters,
				 IN SIZE_T TotalSize,
				 IN SIZE_T CommitSize)
{
    /* Initialize the heap */
    NTSTATUS Status = RtlpInitializeHeap(Heap, HeapFlags, Lock,
					 HeapLockSemaphore, Parameters);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to initialize heap (%x)\n", Status);
	return Status;
    }

    /* Initialize heap's first segment */
    Status = RtlpInitializeHeapSegment(Heap, (PHEAP_SEGMENT) (Heap), 0,
				       HeapSegmentFlags, TotalSize, CommitSize);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to initialize heap segment (%x)\n", Status);
	return Status;
    }

    DPRINT("Created heap %p, CommitSize %zx, ReserveSize %zx\n", Heap,
	   CommitSize, TotalSize);

    /* Add heap to process list (we are always a usermode heap) */
    RtlpAddHeapToProcessList(Heap);
    // FIXME: What about lookasides?

    return STATUS_SUCCESS;
}

/* A handy inline to distinguis normal heap, special "debug heap" and special "page heap" */
FORCEINLINE BOOLEAN RtlpHeapIsSpecial(ULONG Flags)
{
    if (Flags & HEAP_SKIP_VALIDATION_CHECKS)
	return FALSE;

    if (Flags & (HEAP_FLAG_PAGE_ALLOCS |
		 HEAP_VALIDATE_ALL_ENABLED |
		 HEAP_VALIDATE_PARAMETERS_ENABLED |
		 HEAP_CAPTURE_STACK_BACKTRACES |
		 HEAP_CREATE_ENABLE_TRACING)) {
	/* This is a special heap */
	return TRUE;
    }

    /* No need for a special treatment */
    return FALSE;
}

FORCEINLINE ULONG RtlpGetGlobalHeapFlags()
{
    ULONG NtGlobalFlags = RtlGetNtGlobalFlags();
    ULONG Flags = 0;

    /* Check global flags */
    if (NtGlobalFlags & FLG_HEAP_DISABLE_COALESCING)
	Flags |= HEAP_DISABLE_COALESCE_ON_FREE;

    if (NtGlobalFlags & FLG_HEAP_ENABLE_FREE_CHECK)
	Flags |= HEAP_FREE_CHECKING_ENABLED;

    if (NtGlobalFlags & FLG_HEAP_ENABLE_TAIL_CHECK)
	Flags |= HEAP_TAIL_CHECKING_ENABLED;

    /* Also check these flags if in usermode (which we always are) */
    if (NtGlobalFlags & FLG_HEAP_VALIDATE_ALL)
	Flags |= HEAP_VALIDATE_ALL_ENABLED;

    if (NtGlobalFlags & FLG_HEAP_VALIDATE_PARAMETERS)
	Flags |= HEAP_VALIDATE_PARAMETERS_ENABLED;

    if (NtGlobalFlags & FLG_USER_STACK_TRACE_DB)
	Flags |= HEAP_CAPTURE_STACK_BACKTRACES;

    return Flags;
}

FORCEINLINE VOID RtlpSetHeapParameters(IN PRTL_HEAP_PARAMETERS Parameters)
{
    PPEB Peb;

    /* Get PEB */
    Peb = RtlGetCurrentPeb();

    /* Apply defaults for non-set parameters */
    if (!Parameters->SegmentCommit) {
	Parameters->SegmentCommit = Peb->HeapSegmentCommit;
    }
    if (!Parameters->SegmentReserve) {
	Parameters->SegmentReserve = Peb->HeapSegmentReserve;
    }
    if (!Parameters->DeCommitFreeBlockThreshold) {
	Parameters->DeCommitFreeBlockThreshold = Peb->HeapDeCommitFreeBlockThreshold;
    }
    if (!Parameters->DeCommitTotalFreeThreshold) {
	Parameters->DeCommitTotalFreeThreshold = Peb->HeapDeCommitTotalFreeThreshold;
    }
}

static VOID RtlpNormalizeHeapParameters(IN OUT ULONG *Flags,
					IN PRTL_HEAP_PARAMETERS Parameters)
{
    /* Check validation flags */
    if (!(*Flags & HEAP_SKIP_VALIDATION_CHECKS) && (*Flags & ~HEAP_CREATE_VALID_MASK)) {
	DPRINT1("Invalid flags 0x%08x, fixing...\n", *Flags);
	*Flags &= HEAP_CREATE_VALID_MASK;
    }

    /* Apply global heap flags */
    *Flags |= RtlpGetGlobalHeapFlags();

    /* Set tunable parameters */
    RtlpSetHeapParameters(Parameters);

    /* Calculate max alloc size */
    if (!Parameters->MaximumAllocationSize) {
	Parameters->MaximumAllocationSize = HIGHEST_USER_ADDRESS - (ULONG_PTR) 0x10000 - PAGE_SIZE;
    }

    ULONG MaxBlockSize = 0x80000 - PAGE_SIZE;

    if (!Parameters->VirtualMemoryThreshold || Parameters->VirtualMemoryThreshold > MaxBlockSize) {
	Parameters->VirtualMemoryThreshold = MaxBlockSize;
    }

    if (Parameters->DeCommitFreeBlockThreshold != PAGE_SIZE) {
	DPRINT1("WARNING: Ignoring DeCommitFreeBlockThreshold 0x%zx, setting it to PAGE_SIZE.\n",
		Parameters->DeCommitFreeBlockThreshold);
	Parameters->DeCommitFreeBlockThreshold = PAGE_SIZE;
    }
}

static inline NTSTATUS LdrpCreateHeap(IN PVOID Heap,
				      IN ULONG HeapFlags,
				      IN SIZE_T HeapReserve,
				      IN SIZE_T HeapCommit,
				      IN HANDLE HeapLockSemaphore,
				      IN PRTL_HEAP_PARAMETERS Parameters)
{
    /* Set appropriate heap flags and heap parameters */
    RtlpNormalizeHeapParameters(&HeapFlags, Parameters);

    return RtlpRegisterHeap(Heap, HeapFlags, 0, NULL, HeapLockSemaphore,
			    Parameters, HeapReserve, HeapCommit);
}

/*
 * On process startup the NTOS root task maps two heap regions:
 * the private loader heap and the process heap. This function
 * sets up the RTL heap book keeping information for these.
 */
NTSTATUS LdrpInitializeHeapManager(IN PNTDLL_PROCESS_INIT_INFO InitInfo,
				   IN ULONG ProcessHeapFlags,
				   IN PRTL_HEAP_PARAMETERS ProcessHeapParams)
{
    PPEB Peb = RtlGetCurrentPeb();

    /* Initialize heap-related fields of PEB */
    Peb->NumberOfHeaps = 0;

    /* Initialize the process heaps list protecting lock */
    RtlpInitializeCriticalSection(&RtlpProcessHeapListLock, InitInfo->ProcessHeapListLockSemaphore, 0);

    DPRINT("Creating process heap\n");
    RET_ERR(LdrpCreateHeap((PVOID) InitInfo->ProcessHeapStart, ProcessHeapFlags,
			   InitInfo->ProcessHeapReserve,
			   InitInfo->ProcessHeapCommit,
			   InitInfo->ProcessHeapLockSemaphore,
			   ProcessHeapParams));
    Peb->ProcessHeap = (HANDLE) InitInfo->ProcessHeapStart;

    DPRINT("Creating loader heap\n");
    RTL_HEAP_PARAMETERS LoaderHeapParams;
    RtlZeroMemory(&LoaderHeapParams, sizeof(LoaderHeapParams));
    ULONG LoaderHeapFlags = HEAP_GROWABLE | HEAP_CLASS_1;
    LoaderHeapParams.Length = sizeof(LoaderHeapParams);
    RET_ERR(LdrpCreateHeap((PVOID) InitInfo->LoaderHeapStart, LoaderHeapFlags,
			   NTDLL_LOADER_HEAP_RESERVE, NTDLL_LOADER_HEAP_COMMIT,
			   InitInfo->LoaderHeapLockSemaphore,
			   &LoaderHeapParams));

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           RtlCreateHeap
 * RETURNS
 * Handle of heap: Success
 * NULL: Failure
 *
 * @implemented
 */
NTAPI HANDLE RtlCreateHeap(ULONG Flags,
			   PVOID Addr,
			   SIZE_T TotalSize,
			   SIZE_T CommitSize,
			   PVOID Lock,
			   PRTL_HEAP_PARAMETERS Parameters)
{
    PHEAP Heap = NULL;
    ULONG HeapSegmentFlags = 0;

    /* Check whether we want a page heap */
    if (RtlpPageHeapEnabled && (Addr != NULL) && (Lock != NULL)) {
	Heap = RtlpPageHeapCreate(Flags, Addr, TotalSize, CommitSize, Lock, Parameters);
	if (Heap) {
	    return Heap;
	}

	/* Reset a special Parameters == -1 hack */
	if ((ULONG_PTR) Parameters == (ULONG_PTR) - 1) {
	    Parameters = NULL;
	} else {
	    DPRINT1("Enabling page heap failed\n");
	}
    }

    /* Check reserve/commit sizes and set default values */
    if (!CommitSize) {
	CommitSize = PAGE_SIZE;
	if (TotalSize)
	    TotalSize = ROUND_UP(TotalSize, PAGE_SIZE);
	else
	    TotalSize = 64 * PAGE_SIZE;
    } else {
	/* Round up the commit size to be at least the page size */
	CommitSize = ROUND_UP(CommitSize, PAGE_SIZE);

	if (TotalSize)
	    TotalSize = ROUND_UP(TotalSize, PAGE_SIZE);
	else
	    TotalSize = ROUND_UP(CommitSize, 16 * PAGE_SIZE);
    }

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
	return RtlpDebugCreateHeap(Flags, Addr, TotalSize, CommitSize, Lock,
				   Parameters);

    /* Set appropriate heap flags and heap parameters */
    RtlpNormalizeHeapParameters(&Flags, Parameters);

    /* Without serialization, a lock makes no sense */
    if ((Flags & HEAP_NO_SERIALIZE) && (Lock != NULL))
	return NULL;

    /* See if we are already provided with an address for the heap */
    PVOID CommittedAddress = NULL, UncommittedAddress = NULL;
    if (Addr) {
	if (Parameters->CommitRoutine) {
	    /* There is a commit routine, so no problem here, check params */
	    if ((Flags & HEAP_GROWABLE) || !Parameters->InitialCommit || !Parameters->InitialReserve ||
		(Parameters->InitialCommit > Parameters->InitialReserve)) {
		/* Fail */
		return NULL;
	    }

	    /* Calculate committed and uncommitted addresses */
	    CommittedAddress = Addr;
	    UncommittedAddress = (PCHAR) Addr + Parameters->InitialCommit;
	    TotalSize = Parameters->InitialReserve;

	    /* Zero the initial page ourselves */
	    RtlZeroMemory(CommittedAddress, PAGE_SIZE);
	} else {
	    /* Commit routine is absent, so query how much memory caller reserved */
	    MEMORY_BASIC_INFORMATION MemoryInfo;
	    NTSTATUS Status = NtQueryVirtualMemory(NtCurrentProcess(),
						   Addr,
						   MemoryBasicInformation,
						   &MemoryInfo,
						   sizeof(MemoryInfo), NULL);

	    if (!NT_SUCCESS(Status)) {
		DPRINT1("Querying amount of user supplied memory failed with status 0x%08X\n",
			Status);
		return NULL;
	    }

	    /* Validate it */
	    if (MemoryInfo.BaseAddress != Addr || MemoryInfo.State == MEM_FREE) {
		return NULL;
	    }

	    /* Validation checks passed, set committed/uncommitted addresses */
	    CommittedAddress = Addr;

	    /* Check if it's committed or not */
	    if (MemoryInfo.State == MEM_COMMIT) {
		/* Zero it out because it's already committed */
		RtlZeroMemory(CommittedAddress, PAGE_SIZE);

		/* Calculate uncommitted address value */
		CommitSize = MemoryInfo.RegionSize;
		TotalSize = CommitSize;
		UncommittedAddress = (PCHAR) Addr + CommitSize;

		/* Check if uncommitted address is reserved */
		Status = NtQueryVirtualMemory(NtCurrentProcess(),
					      UncommittedAddress,
					      MemoryBasicInformation,
					      &MemoryInfo,
					      sizeof(MemoryInfo), NULL);

		if (NT_SUCCESS(Status) && MemoryInfo.State == MEM_RESERVE) {
		    /* It is, so add it up to the reserve size */
		    TotalSize += MemoryInfo.RegionSize;
		}
	    } else {
		/* It's not committed, inform following code that a commit is necessary */
		CommitSize = PAGE_SIZE;
		UncommittedAddress = Addr;
	    }
	}

	/* Mark this as a user-committed mem */
	HeapSegmentFlags = HEAP_USER_ALLOCATED;
	Heap = (PHEAP) Addr;
    } else {
	/* Check commit routine */
	if (Parameters->CommitRoutine)
	    return NULL;

	/* Reserve memory */
	NTSTATUS Status = NtAllocateVirtualMemory(NtCurrentProcess(),
						  (PVOID *) &Heap,
						  0, &TotalSize,
						  MEM_RESERVE, PAGE_READWRITE);

	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Failed to reserve memory with status 0x%08x\n",
		    Status);
	    return NULL;
	}

	/* Set base addresses */
	CommittedAddress = Heap;
	UncommittedAddress = Heap;
    }

    /* Check if we need to commit something */
    if (CommittedAddress == UncommittedAddress) {
	/* Commit the required size */
	NTSTATUS Status = NtAllocateVirtualMemory(NtCurrentProcess(),
						  &CommittedAddress,
						  0, &CommitSize,
						  MEM_COMMIT, PAGE_READWRITE);

	DPRINT("Committed 0x%zx bytes at base %p\n", CommitSize, CommittedAddress);

	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Failure, Status 0x%08X\n", Status);

	    /* Release memory if it was reserved */
	    if (!Addr) {
		NtFreeVirtualMemory(NtCurrentProcess(), (PVOID *) &Heap,
				    &TotalSize, MEM_RELEASE);
	    }

	    return NULL;
	}

	/* Calculate new uncommitted address */
	UncommittedAddress = (PCHAR) UncommittedAddress + CommitSize;
    }

    if (!NT_SUCCESS(RtlpRegisterHeap(Heap, Flags, HeapSegmentFlags, Lock, 0,
				     Parameters, TotalSize, CommitSize))) {
	return NULL;
    }

    return Heap;
}

/***********************************************************************
 *           RtlDestroyHeap
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 *
 * RETURNS
 *  Success: A NULL HANDLE, if heap is NULL or it was destroyed
 *  Failure: The Heap handle, if heap is the process heap.
 */
HANDLE RtlDestroyHeap(HANDLE HeapPtr)
{
    PHEAP Heap = (PHEAP) HeapPtr;
    PLIST_ENTRY Current;
    PHEAP_UCR_SEGMENT UcrSegment;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;
    PVOID BaseAddress;
    SIZE_T Size;
    LONG i;
    PHEAP_SEGMENT Segment;

    if (!HeapPtr)
	return NULL;

    /* Call page heap routine if required */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS)
	return RtlpPageHeapDestroy(HeapPtr);

    /* Call special heap */
    if (RtlpHeapIsSpecial(Heap->Flags)) {
	if (!RtlpDebugDestroyHeap(Heap))
	    return HeapPtr;
    }

    /* Check for a process heap */
    if (HeapPtr == NtCurrentPeb()->ProcessHeap)
	return HeapPtr;

    /* Free up all big allocations */
    Current = Heap->VirtualAllocdBlocks.Flink;
    while (Current != &Heap->VirtualAllocdBlocks) {
	VirtualEntry =
	    CONTAINING_RECORD(Current, HEAP_VIRTUAL_ALLOC_ENTRY, Entry);
	BaseAddress = (PVOID) VirtualEntry;
	Current = Current->Flink;
	Size = 0;
	NtFreeVirtualMemory(NtCurrentProcess(),
			    &BaseAddress, &Size, MEM_RELEASE);
    }

    /* Delete tags and remove heap from the process heaps list in user mode */
    // FIXME DestroyTags
    RtlpRemoveHeapFromProcessList(Heap);

    /* Delete the heap lock */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE)) {
	/* Delete it if it wasn't user allocated */
	if (!(Heap->Flags & HEAP_LOCK_USER_ALLOCATED))
	    RtlpDeleteHeapLock(Heap->LockVariable);

	/* Clear out the lock variable */
	Heap->LockVariable = NULL;
    }

    /* Free UCR segments if any were created */
    Current = Heap->UCRSegments.Flink;
    while (Current != &Heap->UCRSegments) {
	UcrSegment =
	    CONTAINING_RECORD(Current, HEAP_UCR_SEGMENT, ListEntry);

	/* Advance to the next descriptor */
	Current = Current->Flink;

	BaseAddress = (PVOID) UcrSegment;
	Size = 0;

	/* Release that memory */
	NtFreeVirtualMemory(NtCurrentProcess(),
			    &BaseAddress, &Size, MEM_RELEASE);
    }

    /* Go through segments and destroy them */
    for (i = HEAP_SEGMENTS - 1; i >= 0; i--) {
	Segment = Heap->Segments[i];
	if (Segment)
	    RtlpDestroyHeapSegment(Segment);
    }

    return NULL;
}

static PHEAP_ENTRY RtlpSplitEntry(PHEAP Heap,
				  ULONG Flags,
				  PHEAP_FREE_ENTRY FreeBlock,
				  SIZE_T AllocationSize,
				  SIZE_T Index,
				  SIZE_T Size)
{
    PHEAP_FREE_ENTRY SplitBlock, SplitBlock2;
    UCHAR FreeFlags, EntryFlags = HEAP_ENTRY_BUSY;
    PHEAP_ENTRY InUseEntry;
    SIZE_T FreeSize;
    UCHAR SegmentOffset;

    /* Add extra flags in case of settable user value feature is requested,
       or there is a tag (small or normal) or there is a request to
       capture stack backtraces */
    if ((Flags & HEAP_EXTRA_FLAGS_MASK) || Heap->PseudoTagEntries) {
	/* Add flag which means that the entry will have extra stuff attached */
	EntryFlags |= HEAP_ENTRY_EXTRA_PRESENT;

	/* NB! AllocationSize is already adjusted by RtlAllocateHeap */
    }

    /* Add settable user flags, if any */
    EntryFlags |= (Flags & HEAP_SETTABLE_USER_FLAGS) >> 4;

    /* Save flags, update total free size */
    FreeFlags = FreeBlock->CommonEntry.Flags;
    Heap->TotalFreeSize -= FreeBlock->CommonEntry.Size;

    /* Make this block an in-use one */
    InUseEntry = (PHEAP_ENTRY) FreeBlock;
    InUseEntry->CommonEntry.Flags = EntryFlags;
    InUseEntry->CommonEntry.SmallTagIndex = 0;

    /* Calculate the extra amount */
    FreeSize = InUseEntry->CommonEntry.Size - Index;

    /* Update it's size fields (we don't need their data anymore) */
    InUseEntry->CommonEntry.Size = (USHORT) Index;
    InUseEntry->CommonEntry.UnusedBytes = (UCHAR) (AllocationSize - Size);

    /* If there is something to split - do the split */
    if (FreeSize != 0) {
	/* Don't split if resulting entry can't contain any payload data
	   (i.e. being just HEAP_ENTRY_SIZE) */
	if (FreeSize == 1) {
	    /* Increase sizes of the in-use entry */
	    InUseEntry->CommonEntry.Size++;
	    InUseEntry->CommonEntry.UnusedBytes += sizeof(HEAP_ENTRY);
	} else {
	    /* Calculate a pointer to the new entry */
	    SplitBlock = (PHEAP_FREE_ENTRY) (InUseEntry + Index);

	    /* Initialize it */
	    SplitBlock->CommonEntry.Flags = FreeFlags;
	    SplitBlock->CommonEntry.SegmentOffset = InUseEntry->CommonEntry.SegmentOffset;
	    SplitBlock->CommonEntry.Size = (USHORT) FreeSize;
	    SplitBlock->CommonEntry.PreviousSize = (USHORT) Index;

	    /* Check if it's the last entry */
	    if (FreeFlags & HEAP_ENTRY_LAST_ENTRY) {
		/* Insert it to the free list if it's the last entry */
		RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize, FALSE);
		Heap->TotalFreeSize += FreeSize;
	    } else {
		/* Not so easy - need to update next's previous size too */
		SplitBlock2 = (PHEAP_FREE_ENTRY) ((PHEAP_ENTRY) SplitBlock + FreeSize);

		if (SplitBlock2->CommonEntry.Flags & HEAP_ENTRY_BUSY) {
		    SplitBlock2->CommonEntry.PreviousSize = (USHORT) FreeSize;
		    RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize, FALSE);
		    Heap->TotalFreeSize += FreeSize;
		} else {
		    /* Even more complex - the next entry is free, so we can merge them into one! */
		    SplitBlock->CommonEntry.Flags = SplitBlock2->CommonEntry.Flags;

		    /* Remove that next entry */
		    RtlpRemoveFreeBlock(Heap, SplitBlock2, FALSE);

		    /* Update sizes */
		    FreeSize += SplitBlock2->CommonEntry.Size;
		    Heap->TotalFreeSize -= SplitBlock2->CommonEntry.Size;

		    if (FreeSize <= HEAP_MAX_BLOCK_SIZE) {
			/* Insert it back */
			SplitBlock->CommonEntry.Size = (USHORT) FreeSize;

			/* Don't forget to update previous size of the next entry! */
			if (!(SplitBlock->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY)) {
			    ((PHEAP_FREE_ENTRY)
			     ((PHEAP_ENTRY) SplitBlock +
			      FreeSize))->CommonEntry.PreviousSize = (USHORT) FreeSize;
			}

			/* Actually insert it */
			RtlpInsertFreeBlockHelper(Heap, SplitBlock,
						  (USHORT) FreeSize,
						  FALSE);

			/* Update total size */
			Heap->TotalFreeSize += FreeSize;
		    } else {
			/* Resulting block is quite big */
			RtlpInsertFreeBlock(Heap, SplitBlock, FreeSize);
		    }
		}
	    }

	    /* Reset flags of the free entry */
	    FreeFlags = 0;
	    if (SplitBlock->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY) {
		SegmentOffset = SplitBlock->CommonEntry.SegmentOffset;
		ASSERT(SegmentOffset < HEAP_SEGMENTS);
	    }
	}
    }

    /* Set last entry flag */
    if (FreeFlags & HEAP_ENTRY_LAST_ENTRY)
	InUseEntry->CommonEntry.Flags |= HEAP_ENTRY_LAST_ENTRY;

    return InUseEntry;
}

static PVOID RtlpAllocateNonDedicated(PHEAP Heap,
				      ULONG Flags,
				      SIZE_T Size,
				      SIZE_T AllocationSize,
				      SIZE_T Index,
				      BOOLEAN HeapLocked)
{
    PHEAP_FREE_ENTRY FreeBlock;

    /* The entries in the list must be too small for us */
    ASSERT(IsListEmpty(&Heap->FreeLists) ||
	   (CONTAINING_RECORD(Heap->FreeLists.Blink, HEAP_FREE_ENTRY,
			      FreeList)->CommonEntry.Size < Index));

    /* Extend the heap */
    FreeBlock = RtlpExtendHeap(Heap, AllocationSize);

    /* Use the new biggest entry we've got */
    if (FreeBlock) {
	PHEAP_ENTRY InUseEntry;
	PHEAP_ENTRY_EXTRA Extra;

	RtlpRemoveFreeBlock(Heap, FreeBlock, TRUE);

	/* Split it */
	InUseEntry =  RtlpSplitEntry(Heap, Flags, FreeBlock, AllocationSize, Index,
				     Size);

	/* Release the lock */
	if (HeapLocked)
	    RtlpLeaveHeapLock(Heap->LockVariable);

	/* Zero memory if that was requested */
	if (Flags & HEAP_ZERO_MEMORY)
	    RtlZeroMemory(InUseEntry + 1, Size);
	else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED) {
	    /* Fill this block with a special pattern */
	    RtlFillMemoryUlong(InUseEntry + 1, Size & ~0x3,
			       ARENA_INUSE_FILLER);
	}

	/* Fill tail of the block with a special pattern too if requested */
	if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED) {
	    RtlFillMemory((PCHAR) (InUseEntry + 1) + Size,
			  sizeof(HEAP_ENTRY), HEAP_TAIL_FILL);
	    InUseEntry->CommonEntry.Flags |= HEAP_ENTRY_FILL_PATTERN;
	}

	/* Prepare extra if it's present */
	if (InUseEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
	    Extra = RtlpGetExtraStuffPointer(InUseEntry);
	    RtlZeroMemory(Extra, sizeof(HEAP_ENTRY_EXTRA));

	    // TODO: Tagging
	}

	/* Return pointer to the */
	return InUseEntry + 1;
    }

    /* Really unfortunate, out of memory condition */
    RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);

    /* Generate an exception */
    if (Flags & HEAP_GENERATE_EXCEPTIONS) {
	EXCEPTION_RECORD ExceptionRecord;

	ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
	ExceptionRecord.ExceptionRecord = NULL;
	ExceptionRecord.NumberParameters = 1;
	ExceptionRecord.ExceptionFlags = 0;
	ExceptionRecord.ExceptionInformation[0] = AllocationSize;

	RtlRaiseException(&ExceptionRecord);
    }

    /* Release the lock */
    if (HeapLocked)
	RtlpLeaveHeapLock(Heap->LockVariable);
    DPRINT1("HEAP: Allocation failed!\n");
    DPRINT1("Flags %x\n", Heap->Flags);
    return NULL;
}

/***********************************************************************
 *           HeapAlloc   (KERNEL32.334)
 * RETURNS
 * Pointer to allocated memory block
 * NULL: Failure
 * 0x7d030f60--invalid flags in RtlHeapAllocate
 * @implemented
 */
NTAPI PVOID RtlAllocateHeap(IN PVOID HeapPtr,
			    IN ULONG Flags,
			    IN SIZE_T Size)
{
    PHEAP Heap = (PHEAP) HeapPtr;
    SIZE_T AllocationSize;
    SIZE_T Index;
    UCHAR EntryFlags = HEAP_ENTRY_BUSY;
    BOOLEAN HeapLocked = FALSE;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualBlock = NULL;
    PHEAP_ENTRY_EXTRA Extra;
    NTSTATUS Status;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags)) {
	return RtlpDebugAllocateHeap(Heap, Flags, Size);
    }

    /* Check for the maximum size */
    if (Size >= 0x80000000) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);
	DPRINT1("HEAP: Allocation failed!\n");
	return NULL;
    }

    if (Flags & (HEAP_CREATE_ENABLE_TRACING)) {
	DPRINT1("HEAP: RtlAllocateHeap is called with unsupported flags %x, ignoring\n",
		Flags);
    }

    /* Calculate allocation size and index */
    if (Size)
	AllocationSize = Size;
    else
	AllocationSize = 1;
    AllocationSize = (AllocationSize + Heap->AlignRound) & Heap->AlignMask;

    /* Add extra flags in case of settable user value feature is requested,
       or there is a tag (small or normal) or there is a request to
       capture stack backtraces */
    if ((Flags & HEAP_EXTRA_FLAGS_MASK) || Heap->PseudoTagEntries) {
	/* Add flag which means that the entry will have extra stuff attached */
	EntryFlags |= HEAP_ENTRY_EXTRA_PRESENT;

	/* Account for extra stuff size */
	AllocationSize += sizeof(HEAP_ENTRY_EXTRA);
    }

    /* Add settable user flags, if any */
    EntryFlags |= (Flags & HEAP_SETTABLE_USER_FLAGS) >> 4;

    Index = AllocationSize >> HEAP_ENTRY_SHIFT;

    /* Acquire the lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
	HeapLocked = TRUE;
    }

    /* Depending on the size, the allocation is going to be done from dedicated,
       non-dedicated lists or a virtual block of memory */
    if (Index <= Heap->VirtualMemoryThreshold) {
	/* First quick check: Anybody here? */
	if (IsListEmpty(&Heap->FreeLists)) {
	    return RtlpAllocateNonDedicated(Heap, Flags, Size, AllocationSize,
					    Index, HeapLocked);
	}

	/* Second quick check: Is there someone for us ? */
	PHEAP_FREE_ENTRY FreeEntry = CONTAINING_RECORD(Heap->FreeLists.Blink,
						       HEAP_FREE_ENTRY, FreeList);
	if (FreeEntry->CommonEntry.Size < Index) {
	    /* Largest entry in the list doesnt fit. */
	    return RtlpAllocateNonDedicated(Heap, Flags, Size, AllocationSize,
					    Index, HeapLocked);
	}

	if (Index > Heap->DeCommitFreeBlockThreshold) {
	    /* Find an entry from the non dedicated list */
	    FreeEntry = CONTAINING_RECORD(Heap->FreeHints[0],
					  HEAP_FREE_ENTRY, FreeList);

	    while (FreeEntry->CommonEntry.Size < Index) {
		/* We made sure we had the right size available */
		ASSERT(FreeEntry->FreeList.Flink != &Heap->FreeLists);
		FreeEntry = CONTAINING_RECORD(FreeEntry->FreeList.Flink,
					      HEAP_FREE_ENTRY, FreeList);
	    }
	} else {
	    /* Get the free entry from the hint */
	    ULONG HintIndex = RtlFindSetBits(&Heap->FreeHintBitmap, 1, Index - 1);
	    ASSERT(HintIndex != 0xFFFFFFFF);
	    ASSERT((HintIndex >= (Index - 1)) || (HintIndex == 0));
	    FreeEntry = CONTAINING_RECORD(Heap->FreeHints[HintIndex],
					  HEAP_FREE_ENTRY, FreeList);
	}

	/* Remove the free block, split, profit. */
	RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
	PHEAP_ENTRY InUseEntry = RtlpSplitEntry(Heap, Flags, FreeEntry,
						AllocationSize, Index, Size);

	/* Release the lock */
	if (HeapLocked)
	    RtlpLeaveHeapLock(Heap->LockVariable);

	/* Zero memory if that was requested */
	if (Flags & HEAP_ZERO_MEMORY)
	    RtlZeroMemory(InUseEntry + 1, Size);
	else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED) {
	    /* Fill this block with a special pattern */
	    RtlFillMemoryUlong(InUseEntry + 1, Size & ~0x3,
			       ARENA_INUSE_FILLER);
	}

	/* Fill tail of the block with a special pattern too if requested */
	if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED) {
	    RtlFillMemory((PCHAR) (InUseEntry + 1) + Size,
			  sizeof(HEAP_ENTRY), HEAP_TAIL_FILL);
	    InUseEntry->CommonEntry.Flags |= HEAP_ENTRY_FILL_PATTERN;
	}

	/* Prepare extra if it's present */
	if (InUseEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
	    Extra = RtlpGetExtraStuffPointer(InUseEntry);
	    RtlZeroMemory(Extra, sizeof(HEAP_ENTRY_EXTRA));
	    // TODO: Tagging
	}

	/* User data starts right after the entry's header */
	return InUseEntry + 1;
    }

    if (Heap->Flags & HEAP_GROWABLE) {
	/* We've got a very big allocation request, satisfy it by directly allocating virtual memory */
	AllocationSize += sizeof(HEAP_VIRTUAL_ALLOC_ENTRY) - sizeof(HEAP_ENTRY);

	Status = NtAllocateVirtualMemory(NtCurrentProcess(),
					 (PVOID *) & VirtualBlock,
					 0,
					 &AllocationSize,
					 MEM_COMMIT, PAGE_READWRITE);

	if (!NT_SUCCESS(Status)) {
	    // Set STATUS!
	    /* Release the lock */
	    if (HeapLocked)
		RtlpLeaveHeapLock(Heap->LockVariable);
	    DPRINT1("HEAP: Allocation failed!\n");
	    return NULL;
	}

	/* Initialize the newly allocated block */
	VirtualBlock->BusyBlock.CommonEntry.Size = (USHORT) (AllocationSize - Size);
	ASSERT(VirtualBlock->BusyBlock.CommonEntry.Size >=
	       sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));
	VirtualBlock->BusyBlock.CommonEntry.Flags =
	    EntryFlags | HEAP_ENTRY_VIRTUAL_ALLOC |
	    HEAP_ENTRY_EXTRA_PRESENT;
	VirtualBlock->CommitSize = AllocationSize;
	VirtualBlock->ReserveSize = AllocationSize;

	/* Insert it into the list of virtual allocations */
	InsertTailList(&Heap->VirtualAllocdBlocks, &VirtualBlock->Entry);

	/* Release the lock */
	if (HeapLocked)
	    RtlpLeaveHeapLock(Heap->LockVariable);

	/* Return pointer to user data */
	return VirtualBlock + 1;
    }

    /* Generate an exception */
    if (Flags & HEAP_GENERATE_EXCEPTIONS) {
	EXCEPTION_RECORD ExceptionRecord;

	ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
	ExceptionRecord.ExceptionRecord = NULL;
	ExceptionRecord.NumberParameters = 1;
	ExceptionRecord.ExceptionFlags = 0;
	ExceptionRecord.ExceptionInformation[0] = AllocationSize;

	RtlRaiseException(&ExceptionRecord);
    }

    RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_BUFFER_TOO_SMALL);

    /* Release the lock */
    if (HeapLocked)
	RtlpLeaveHeapLock(Heap->LockVariable);
    DPRINT1("HEAP: Allocation failed!\n");
    return NULL;
}


/***********************************************************************
 *           HeapFree   (KERNEL32.338)
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN RtlFreeHeap(HANDLE HeapPtr,	/* [in] Handle of heap */
		    ULONG Flags,	/* [in] Heap freeing flags */
		    PVOID Ptr)	/* [in] Address of memory to free */
{
    PHEAP Heap;
    PHEAP_ENTRY HeapEntry;
    USHORT TagIndex = 0;
    SIZE_T BlockSize;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;
    BOOLEAN Locked = FALSE;
    NTSTATUS Status;

    /* Freeing NULL pointer is a legal operation */
    if (!Ptr)
	return TRUE;

    /* Get pointer to the heap and force flags */
    Heap = (PHEAP) HeapPtr;
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
	return RtlpDebugFreeHeap(Heap, Flags, Ptr);

    /* Get pointer to the heap entry */
    HeapEntry = (PHEAP_ENTRY) Ptr - 1;

    /* Protect with SEH in case the pointer is not valid */
    _SEH2_TRY {
	/* Check this entry, fail if it's invalid */
	if (!(HeapEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY) ||
	    (((ULONG_PTR) Ptr & 0x7) != 0) ||
	    (HeapEntry->CommonEntry.SegmentOffset >= HEAP_SEGMENTS)) {
	    /* This is an invalid block */
	    DPRINT1("HEAP: Trying to free an invalid address %p!\n", Ptr);
	    RtlSetLastWin32ErrorAndNtStatusFromNtStatus
		(STATUS_INVALID_PARAMETER);
	    _SEH2_YIELD(return FALSE);
	}
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	/* The pointer was invalid */
	DPRINT1("HEAP: Trying to free an invalid address %p!\n", Ptr);
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus
	    (STATUS_INVALID_PARAMETER);
	_SEH2_YIELD(return FALSE);
    }
    _SEH2_END;

    /* Lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
	Locked = TRUE;
    }

    if (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC) {
	/* Big allocation */
	VirtualEntry =
	    CONTAINING_RECORD(HeapEntry, HEAP_VIRTUAL_ALLOC_ENTRY,
			      BusyBlock);

	/* Remove it from the list */
	RemoveEntryList(&VirtualEntry->Entry);

	// TODO: Tagging

	BlockSize = 0;
	Status = NtFreeVirtualMemory(NtCurrentProcess(),
				     (PVOID *) & VirtualEntry,
				     &BlockSize, MEM_RELEASE);

	if (!NT_SUCCESS(Status)) {
	    DPRINT1
		("HEAP: Failed releasing memory with Status 0x%08X. Heap %p, ptr %p, base address %p\n",
		 Status, Heap, Ptr, VirtualEntry);
	    RtlSetLastWin32ErrorAndNtStatusFromNtStatus(Status);
	}
    } else {
	/* Normal allocation */
	BlockSize = HeapEntry->CommonEntry.Size;

	// TODO: Tagging

	/* Coalesce in kernel mode, and in usermode if it's not disabled */
	if (!(Heap->Flags & HEAP_DISABLE_COALESCE_ON_FREE)) {
	    HeapEntry = (PHEAP_ENTRY) RtlpCoalesceFreeBlocks(Heap,
							     (PHEAP_FREE_ENTRY)
							     HeapEntry, &BlockSize,
							     FALSE);
	}

	/* See if we should decommit this block */
	if ((BlockSize >= Heap->DeCommitFreeBlockThreshold) ||
	    (Heap->TotalFreeSize + BlockSize >=
	     Heap->DeCommitTotalFreeThreshold)) {
	    RtlpDeCommitFreeBlock(Heap, (PHEAP_FREE_ENTRY) HeapEntry,
				  BlockSize);
	} else {
	    /* Insert into the free list */
	    RtlpInsertFreeBlock(Heap, (PHEAP_FREE_ENTRY) HeapEntry,
				BlockSize);

	    if (TagIndex != 0) {
		// FIXME: Tagging
		UNIMPLEMENTED;
	    }
	}
    }

    /* Release the heap lock */
    if (Locked)
	RtlpLeaveHeapLock(Heap->LockVariable);

    return TRUE;
}

BOOLEAN RtlpGrowBlockInPlace(IN PHEAP Heap,
			     IN ULONG Flags,
			     IN PHEAP_ENTRY InUseEntry,
			     IN SIZE_T Size,
			     IN SIZE_T Index)
{
    UCHAR EntryFlags, RememberFlags;
    PHEAP_FREE_ENTRY FreeEntry, UnusedEntry, FollowingEntry;
    SIZE_T FreeSize, PrevSize, TailPart, AddedSize = 0;
    PHEAP_ENTRY_EXTRA OldExtra, NewExtra;
    UCHAR SegmentOffset;

    /* We can't grow beyond specified threshold */
    if (Index > Heap->VirtualMemoryThreshold)
	return FALSE;

    /* Get entry flags */
    EntryFlags = InUseEntry->CommonEntry.Flags;

    if (RtlpIsLastCommittedEntry(InUseEntry)) {
	/* There is no next block, just uncommitted space. Calculate how much is needed */
	FreeSize = (Index - InUseEntry->CommonEntry.Size) << HEAP_ENTRY_SHIFT;
	FreeSize = ROUND_UP(FreeSize, PAGE_SIZE);

	/* Find and commit those pages */
	FreeEntry = RtlpFindAndCommitPages(Heap,
					   Heap->Segments[InUseEntry->CommonEntry.SegmentOffset],
					   &FreeSize,
					   (PVOID) PAGE_ROUND_UP(InUseEntry + InUseEntry->CommonEntry.Size));

	/* Fail if it failed... */
	if (!FreeEntry)
	    return FALSE;

	/* It was successful, perform coalescing */
	FreeSize = FreeSize >> HEAP_ENTRY_SHIFT;
	FreeEntry = RtlpCoalesceFreeBlocks(Heap, FreeEntry, &FreeSize, FALSE);

	/* Check if it's enough */
	if (FreeSize + InUseEntry->CommonEntry.Size < Index) {
	    /* Still not enough */
	    RtlpInsertFreeBlock(Heap, FreeEntry, FreeSize);
	    Heap->TotalFreeSize += FreeSize;
	    return FALSE;
	}

	/* Remember flags of this free entry */
	RememberFlags = FreeEntry->CommonEntry.Flags;

	/* Sum up sizes */
	FreeSize += InUseEntry->CommonEntry.Size;
    } else {
	FreeEntry = (PHEAP_FREE_ENTRY) (InUseEntry + InUseEntry->CommonEntry.Size);

	/* The next block indeed exists. Check if it's free or in use */
	if (FreeEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY)
	    return FALSE;

	/* Next entry is free, check if it can fit the block we need */
	FreeSize = InUseEntry->CommonEntry.Size + FreeEntry->CommonEntry.Size;
	if (FreeSize < Index)
	    return FALSE;

	/* Remember flags of this free entry */
	RememberFlags = FreeEntry->CommonEntry.Flags;

	/* Remove this block from the free list */
	RtlpRemoveFreeBlock(Heap, FreeEntry, FALSE);
	Heap->TotalFreeSize -= FreeEntry->CommonEntry.Size;
    }

    PrevSize =
	(InUseEntry->CommonEntry.Size << HEAP_ENTRY_SHIFT) - InUseEntry->CommonEntry.UnusedBytes;
    FreeSize -= Index;

    /* Don't produce too small blocks */
    if (FreeSize <= 2) {
	Index += FreeSize;
	FreeSize = 0;
    }

    /* Process extra stuff */
    if (EntryFlags & HEAP_ENTRY_EXTRA_PRESENT) {
	/* Calculate pointers */
	OldExtra = (PHEAP_ENTRY_EXTRA) (InUseEntry + InUseEntry->CommonEntry.Size - 1);
	NewExtra = (PHEAP_ENTRY_EXTRA) (InUseEntry + Index - 1);

	/* Copy contents */
	*NewExtra = *OldExtra;

	// FIXME Tagging
    }

    /* Update sizes */
    InUseEntry->CommonEntry.Size = (USHORT) Index;
    InUseEntry->CommonEntry.UnusedBytes = (UCHAR) ((Index << HEAP_ENTRY_SHIFT) - Size);

    /* Check if there is a free space remaining after merging those blocks */
    if (!FreeSize) {
	/* Update flags and sizes */
	InUseEntry->CommonEntry.Flags |= RememberFlags & HEAP_ENTRY_LAST_ENTRY;

	/* Either update previous size of the next entry or mark it as a last
	   entry in the segment */
	if (!(RememberFlags & HEAP_ENTRY_LAST_ENTRY)) {
	    (InUseEntry + InUseEntry->CommonEntry.Size)->CommonEntry.PreviousSize =
		InUseEntry->CommonEntry.Size;
	} else {
	    SegmentOffset = InUseEntry->CommonEntry.SegmentOffset;
	    ASSERT(SegmentOffset < HEAP_SEGMENTS);
	}
    } else {
	/* Complex case, we need to split the block to give unused free space
	   back to the heap */
	UnusedEntry = (PHEAP_FREE_ENTRY) (InUseEntry + Index);
	UnusedEntry->CommonEntry.PreviousSize = (USHORT) Index;
	UnusedEntry->CommonEntry.SegmentOffset = InUseEntry->CommonEntry.SegmentOffset;

	/* Update the following block or set the last entry in the segment */
	if (RememberFlags & HEAP_ENTRY_LAST_ENTRY) {
	    SegmentOffset = UnusedEntry->CommonEntry.SegmentOffset;
	    ASSERT(SegmentOffset < HEAP_SEGMENTS);

	    /* Set flags and size */
	    UnusedEntry->CommonEntry.Flags = RememberFlags;
	    UnusedEntry->CommonEntry.Size = (USHORT) FreeSize;

	    /* Insert it to the heap and update total size  */
	    RtlpInsertFreeBlockHelper(Heap, UnusedEntry, FreeSize, FALSE);
	    Heap->TotalFreeSize += FreeSize;
	} else {
	    /* There is a block after this one  */
	    FollowingEntry =
		(PHEAP_FREE_ENTRY) ((PHEAP_ENTRY) UnusedEntry + FreeSize);

	    if (FollowingEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY) {
		/* Update flags and set size of the unused space entry */
		UnusedEntry->CommonEntry.Flags =
		    RememberFlags & (~HEAP_ENTRY_LAST_ENTRY);
		UnusedEntry->CommonEntry.Size = (USHORT) FreeSize;

		/* Update previous size of the following entry */
		FollowingEntry->CommonEntry.PreviousSize = (USHORT) FreeSize;

		/* Insert it to the heap and update total free size */
		RtlpInsertFreeBlockHelper(Heap, UnusedEntry, FreeSize,
					  FALSE);
		Heap->TotalFreeSize += FreeSize;
	    } else {
		/* That following entry is also free, what a fortune! */
		RememberFlags = FollowingEntry->CommonEntry.Flags;

		/* Remove it */
		RtlpRemoveFreeBlock(Heap, FollowingEntry, FALSE);
		Heap->TotalFreeSize -= FollowingEntry->CommonEntry.Size;

		/* And make up a new combined block */
		FreeSize += FollowingEntry->CommonEntry.Size;
		UnusedEntry->CommonEntry.Flags = RememberFlags;

		/* Check where to put it */
		if (FreeSize <= HEAP_MAX_BLOCK_SIZE) {
		    /* Fine for a dedicated list */
		    UnusedEntry->CommonEntry.Size = (USHORT) FreeSize;

		    if (!(RememberFlags & HEAP_ENTRY_LAST_ENTRY)) {
			((PHEAP_ENTRY) UnusedEntry +
			 FreeSize)->CommonEntry.PreviousSize = (USHORT) FreeSize;
		    } else {
			SegmentOffset = UnusedEntry->CommonEntry.SegmentOffset;
			ASSERT(SegmentOffset < HEAP_SEGMENTS);
		    }

		    /* Insert it back and update total size */
		    RtlpInsertFreeBlockHelper(Heap, UnusedEntry, FreeSize,
					      FALSE);
		    Heap->TotalFreeSize += FreeSize;
		} else {
		    /* The block is very large, leave all the hassle to the insertion routine */
		    RtlpInsertFreeBlock(Heap, UnusedEntry, FreeSize);
		}
	    }
	}
    }

    /* Properly "zero out" (and fill!) the space */
    if (Flags & HEAP_ZERO_MEMORY) {
	RtlZeroMemory((PCHAR) (InUseEntry + 1) + PrevSize,
		      Size - PrevSize);
    } else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED) {
	/* Calculate tail part which we need to fill */
	TailPart = PrevSize & (sizeof(ULONG) - 1);

	/* "Invert" it as usual */
	if (TailPart)
	    TailPart = 4 - TailPart;

	if (Size > (PrevSize + TailPart))
	    AddedSize =
		(Size - (PrevSize + TailPart)) & ~(sizeof(ULONG) - 1);

	if (AddedSize) {
	    RtlFillMemoryUlong((PCHAR) (InUseEntry + 1) + PrevSize +
			       TailPart, AddedSize, ARENA_INUSE_FILLER);
	}
    }

    /* Fill the new tail */
    if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED) {
	RtlFillMemory((PCHAR) (InUseEntry + 1) + Size,
		      HEAP_ENTRY_SIZE, HEAP_TAIL_FILL);
    }

    /* Copy user settable flags */
    InUseEntry->CommonEntry.Flags &= ~HEAP_ENTRY_SETTABLE_FLAGS;
    InUseEntry->CommonEntry.Flags |= ((Flags & HEAP_SETTABLE_USER_FLAGS) >> 4);

    /* Return success */
    return TRUE;
}

PHEAP_ENTRY_EXTRA RtlpGetExtraStuffPointer(PHEAP_ENTRY HeapEntry)
{
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualEntry;

    /* Check if it's a big block */
    if (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC) {
	VirtualEntry =
	    CONTAINING_RECORD(HeapEntry, HEAP_VIRTUAL_ALLOC_ENTRY,
			      BusyBlock);

	/* Return a pointer to the extra stuff */
	return &VirtualEntry->ExtraStuff;
    } else {
	/* This is a usual entry, which means extra stuff follows this block */
	return (PHEAP_ENTRY_EXTRA) (HeapEntry + HeapEntry->CommonEntry.Size - 1);
    }
}


/***********************************************************************
 *           RtlReAllocateHeap
 * PARAMS
 *   Heap   [in] Handle of heap block
 *   Flags    [in] Heap reallocation flags
 *   Ptr,    [in] Address of memory to reallocate
 *   Size     [in] Number of bytes to reallocate
 *
 * RETURNS
 * Pointer to reallocated memory block
 * NULL: Failure
 * 0x7d030f60--invalid flags in RtlHeapAllocate
 * @implemented
 */
PVOID NTAPI
RtlReAllocateHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr, SIZE_T Size)
{
    PHEAP Heap = (PHEAP) HeapPtr;
    PHEAP_ENTRY InUseEntry, NewInUseEntry;
    PHEAP_ENTRY_EXTRA OldExtra, NewExtra;
    SIZE_T AllocationSize, FreeSize, DecommitSize;
    BOOLEAN HeapLocked = FALSE;
    PVOID NewBaseAddress;
    PHEAP_FREE_ENTRY SplitBlock, SplitBlock2;
    SIZE_T OldSize, Index, OldIndex;
    UCHAR FreeFlags;
    NTSTATUS Status;
    PVOID DecommitBase;
    SIZE_T RemainderBytes, ExtraSize;
    PHEAP_VIRTUAL_ALLOC_ENTRY VirtualAllocBlock;
    EXCEPTION_RECORD ExceptionRecord;
    UCHAR SegmentOffset;

    /* Return success in case of a null pointer */
    if (!Ptr) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_SUCCESS);
	return NULL;
    }

    /* Force heap flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
	return RtlpDebugReAllocateHeap(Heap, Flags, Ptr, Size);

    /* Make sure size is valid */
    if (Size >= 0x80000000) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);
	return NULL;
    }

    /* Calculate allocation size and index */
    if (Size)
	AllocationSize = Size;
    else
	AllocationSize = 1;
    AllocationSize = (AllocationSize + Heap->AlignRound) & Heap->AlignMask;

    /* Add up extra stuff, if it is present anywhere */
    if (((((PHEAP_ENTRY) Ptr) - 1)->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) ||
	(Flags & HEAP_EXTRA_FLAGS_MASK) || Heap->PseudoTagEntries) {
	AllocationSize += sizeof(HEAP_ENTRY_EXTRA);
    }

    /* Acquire the lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
	HeapLocked = TRUE;
	/* Do not acquire the lock anymore for re-entrant call */
	Flags |= HEAP_NO_SERIALIZE;
    }

    /* Get the pointer to the in-use entry */
    InUseEntry = (PHEAP_ENTRY) Ptr - 1;

    /* If that entry is not really in-use, we have a problem */
    if (!(InUseEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY)) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus
	    (STATUS_INVALID_PARAMETER);

	/* Release the lock and return */
	if (HeapLocked)
	    RtlpLeaveHeapLock(Heap->LockVariable);
	return Ptr;
    }

    if (InUseEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC) {
	/* This is a virtually allocated block. Get its size */
	OldSize = RtlpGetSizeOfBigBlock(InUseEntry);

	/* Convert it to an index */
	OldIndex = (OldSize + InUseEntry->CommonEntry.Size) >> HEAP_ENTRY_SHIFT;

	/* Calculate new allocation size and round it to the page size */
	AllocationSize +=
	    FIELD_OFFSET(HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock);
	AllocationSize = ROUND_UP(AllocationSize, PAGE_SIZE);
    } else {
	/* Usual entry */
	OldIndex = InUseEntry->CommonEntry.Size;

	OldSize = (OldIndex << HEAP_ENTRY_SHIFT) - InUseEntry->CommonEntry.UnusedBytes;
    }

    /* Calculate new index */
    Index = AllocationSize >> HEAP_ENTRY_SHIFT;

    /* Check for 4 different scenarios (old size, new size, old index, new index) */
    if (Index <= OldIndex) {
	/* Difference must be greater than 1, adjust if it's not so */
	if (Index + 1 == OldIndex) {
	    Index++;
	    AllocationSize += sizeof(HEAP_ENTRY);
	}

	/* Calculate new size */
	if (InUseEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC) {
	    /* Simple in case of a virtual alloc - just an unused size */
	    InUseEntry->CommonEntry.Size = (USHORT) (AllocationSize - Size);
	    ASSERT(InUseEntry->CommonEntry.Size >= sizeof(HEAP_VIRTUAL_ALLOC_ENTRY));
	} else if (InUseEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
	    /* There is extra stuff, take it into account */
	    OldExtra =
		(PHEAP_ENTRY_EXTRA) (InUseEntry + InUseEntry->CommonEntry.Size - 1);
	    NewExtra = (PHEAP_ENTRY_EXTRA) (InUseEntry + Index - 1);
	    *NewExtra = *OldExtra;

	    // FIXME Tagging, TagIndex

	    /* Update unused bytes count */
	    InUseEntry->CommonEntry.UnusedBytes = (UCHAR) (AllocationSize - Size);
	} else {
	    // FIXME Tagging, SmallTagIndex
	    InUseEntry->CommonEntry.UnusedBytes = (UCHAR) (AllocationSize - Size);
	}

	/* If new size is bigger than the old size */
	if (Size > OldSize) {
	    /* Zero out that additional space if required */
	    if (Flags & HEAP_ZERO_MEMORY) {
		RtlZeroMemory((PCHAR) Ptr + OldSize, Size - OldSize);
	    } else if (Heap->Flags & HEAP_FREE_CHECKING_ENABLED) {
		/* Fill it on free if required */
		RemainderBytes = OldSize & (sizeof(ULONG) - 1);

		if (RemainderBytes)
		    RemainderBytes = 4 - RemainderBytes;

		if (Size > (OldSize + RemainderBytes)) {
		    /* Calculate actual amount of extra bytes to fill */
		    ExtraSize =
			(Size -
			 (OldSize + RemainderBytes)) & ~(sizeof(ULONG) -
							 1);

		    /* Fill them if there are any */
		    if (ExtraSize != 0) {
			RtlFillMemoryUlong((PCHAR) (InUseEntry + 1) +
					   OldSize + RemainderBytes,
					   ExtraSize, ARENA_INUSE_FILLER);
		    }
		}
	    }
	}

	/* Fill tail of the heap entry if required */
	if (Heap->Flags & HEAP_TAIL_CHECKING_ENABLED) {
	    RtlFillMemory((PCHAR) (InUseEntry + 1) + Size,
			  HEAP_ENTRY_SIZE, HEAP_TAIL_FILL);
	}

	/* Check if the difference is significant or not */
	if (Index != OldIndex) {
	    /* Save flags */
	    FreeFlags = InUseEntry->CommonEntry.Flags & ~HEAP_ENTRY_BUSY;

	    if (FreeFlags & HEAP_ENTRY_VIRTUAL_ALLOC) {
		/* This is a virtual block allocation */
		VirtualAllocBlock =
		    CONTAINING_RECORD(InUseEntry, HEAP_VIRTUAL_ALLOC_ENTRY,
				      BusyBlock);

		// FIXME Tagging!

		DecommitBase = (PCHAR) VirtualAllocBlock + AllocationSize;
		DecommitSize =
		    (OldIndex << HEAP_ENTRY_SHIFT) - AllocationSize;

		/* Release the memory */
		Status = NtFreeVirtualMemory(NtCurrentProcess(),
					     (PVOID *) & DecommitBase,
					     &DecommitSize, MEM_RELEASE);

		if (!NT_SUCCESS(Status)) {
		    DPRINT1
			("HEAP: Unable to release memory (pointer %p, size 0x%zx), Status %08x\n",
			 DecommitBase, DecommitSize, Status);
		} else {
		    /* Otherwise reduce the commit size */
		    VirtualAllocBlock->CommitSize -= DecommitSize;
		}
	    } else {
		/* Reduce size of the block and possibly split it */
		SplitBlock = (PHEAP_FREE_ENTRY) (InUseEntry + Index);

		/* Initialize this entry */
		SplitBlock->CommonEntry.Flags = FreeFlags;
		SplitBlock->CommonEntry.PreviousSize = (USHORT) Index;
		SplitBlock->CommonEntry.SegmentOffset = InUseEntry->CommonEntry.SegmentOffset;

		/* Remember free size */
		FreeSize = InUseEntry->CommonEntry.Size - Index;

		/* Set new size */
		InUseEntry->CommonEntry.Size = (USHORT) Index;
		InUseEntry->CommonEntry.Flags &= ~HEAP_ENTRY_LAST_ENTRY;

		/* Is that the last entry */
		if (FreeFlags & HEAP_ENTRY_LAST_ENTRY) {
		    SegmentOffset = SplitBlock->CommonEntry.SegmentOffset;
		    ASSERT(SegmentOffset < HEAP_SEGMENTS);

		    /* Set its size and insert it to the list */
		    SplitBlock->CommonEntry.Size = (USHORT) FreeSize;
		    RtlpInsertFreeBlockHelper(Heap, SplitBlock, FreeSize,
					      FALSE);

		    /* Update total free size */
		    Heap->TotalFreeSize += FreeSize;
		} else {
		    /* Get the block after that one */
		    SplitBlock2 =
			(PHEAP_FREE_ENTRY) ((PHEAP_ENTRY) SplitBlock +
					    FreeSize);

		    if (SplitBlock2->CommonEntry.Flags & HEAP_ENTRY_BUSY) {
			/* It's in use, add it here */
			SplitBlock->CommonEntry.Size = (USHORT) FreeSize;

			/* Update previous size of the next entry */
			((PHEAP_FREE_ENTRY)
			 ((PHEAP_ENTRY) SplitBlock +
			  FreeSize))->CommonEntry.PreviousSize = (USHORT) FreeSize;

			/* Insert it to the list */
			RtlpInsertFreeBlockHelper(Heap, SplitBlock,
						  FreeSize, FALSE);

			/* Update total size */
			Heap->TotalFreeSize += FreeSize;
		    } else {
			/* Next entry is free, so merge with it */
			SplitBlock->CommonEntry.Flags = SplitBlock2->CommonEntry.Flags;

			/* Remove it, update total size */
			RtlpRemoveFreeBlock(Heap, SplitBlock2, FALSE);
			Heap->TotalFreeSize -= SplitBlock2->CommonEntry.Size;

			/* Calculate total free size */
			FreeSize += SplitBlock2->CommonEntry.Size;

			if (FreeSize <= HEAP_MAX_BLOCK_SIZE) {
			    SplitBlock->CommonEntry.Size = (USHORT) FreeSize;

			    if (!
				(SplitBlock->CommonEntry.
				 Flags & HEAP_ENTRY_LAST_ENTRY)) {
				/* Update previous size of the next entry */
				((PHEAP_FREE_ENTRY)
				 ((PHEAP_ENTRY) SplitBlock +
				  FreeSize))->CommonEntry.PreviousSize =
				    (USHORT) FreeSize;
			    } else {
				SegmentOffset = SplitBlock->CommonEntry.SegmentOffset;
				ASSERT(SegmentOffset < HEAP_SEGMENTS);
			    }

			    /* Insert the new one back and update total size */
			    RtlpInsertFreeBlockHelper(Heap, SplitBlock,
						      FreeSize, FALSE);
			    Heap->TotalFreeSize += FreeSize;
			} else {
			    /* Just add it */
			    RtlpInsertFreeBlock(Heap, SplitBlock,
						FreeSize);
			}
		    }
		}
	    }
	}
    } else {
	/* We're growing the block */
	if ((InUseEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC) ||
	    !RtlpGrowBlockInPlace(Heap, Flags, InUseEntry, Size, Index)) {
	    /* Growing in place failed, so growing out of place */
	    if (Flags & HEAP_REALLOC_IN_PLACE_ONLY) {
		DPRINT1
		    ("Realloc in place failed, but it was the only option\n");
		Ptr = NULL;
	    } else {
		/* Clear tag bits */
		Flags &= ~HEAP_TAG_MASK;

		/* Process extra stuff */
		if (InUseEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
		    /* Preserve user settable flags */
		    Flags &= ~HEAP_SETTABLE_USER_FLAGS;

		    Flags |=
			HEAP_SETTABLE_USER_VALUE |
			((InUseEntry->CommonEntry.
			  Flags & HEAP_ENTRY_SETTABLE_FLAGS) << 4);

		    /* Get pointer to the old extra data */
		    OldExtra = RtlpGetExtraStuffPointer(InUseEntry);

		    /* Save tag index if it was set */
		    if (OldExtra->TagIndex &&
			!(OldExtra->TagIndex & HEAP_PSEUDO_TAG_FLAG)) {
			Flags |= OldExtra->TagIndex << HEAP_TAG_SHIFT;
		    }
		} else if (InUseEntry->CommonEntry.SmallTagIndex) {
		    /* Take small tag index into account */
		    Flags |= InUseEntry->CommonEntry.SmallTagIndex << HEAP_TAG_SHIFT;
		}

		/* Allocate new block from the heap */
		NewBaseAddress = RtlAllocateHeap(HeapPtr,
						 Flags & ~HEAP_ZERO_MEMORY,
						 Size);

		/* Proceed if it didn't fail */
		if (NewBaseAddress) {
		    /* Get new entry pointer */
		    NewInUseEntry = (PHEAP_ENTRY) NewBaseAddress - 1;

		    /* Process extra stuff if it exists */
		    if (NewInUseEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
			NewExtra = RtlpGetExtraStuffPointer(NewInUseEntry);

			if (InUseEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
			    OldExtra =
				RtlpGetExtraStuffPointer(InUseEntry);
			    NewExtra->Settable = OldExtra->Settable;
			} else {
			    RtlZeroMemory(NewExtra, sizeof(*NewExtra));
			}
		    }

		    /* Copy actual user bits */
		    if (Size < OldSize)
			RtlMoveMemory(NewBaseAddress, Ptr, Size);
		    else
			RtlMoveMemory(NewBaseAddress, Ptr, OldSize);

		    /* Zero remaining part if required */
		    if (Size > OldSize && (Flags & HEAP_ZERO_MEMORY)) {
			RtlZeroMemory((PCHAR) NewBaseAddress + OldSize,
				      Size - OldSize);
		    }

		    /* Free the old block */
		    RtlFreeHeap(HeapPtr, Flags, Ptr);
		}

		Ptr = NewBaseAddress;
	    }
	}
    }

    /* Did resizing fail? */
    if (!Ptr && (Flags & HEAP_GENERATE_EXCEPTIONS)) {
	/* Generate an exception if required */
	ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
	ExceptionRecord.ExceptionRecord = NULL;
	ExceptionRecord.NumberParameters = 1;
	ExceptionRecord.ExceptionFlags = 0;
	ExceptionRecord.ExceptionInformation[0] = AllocationSize;

	RtlRaiseException(&ExceptionRecord);
    }

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
	RtlpLeaveHeapLock(Heap->LockVariable);

    return Ptr;
}


/***********************************************************************
 *           RtlCompactHeap
 *
 * @unimplemented
 */
ULONG RtlCompactHeap(HANDLE Heap, ULONG Flags)
{
    UNIMPLEMENTED;
    return 0;
}


/***********************************************************************
 *           RtlLockHeap
 * Attempts to acquire the critical section object for a specified heap.
 *
 * PARAMS
 *   Heap  [in] Handle of heap to lock for exclusive access
 *
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN RtlLockHeap(IN HANDLE HeapPtr)
{
    PHEAP Heap = (PHEAP) HeapPtr;

    /* Check for page heap */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS) {
	return RtlpPageHeapLock(Heap);
    }

    /* Check if it's really a heap */
    if (Heap->Signature != HEAP_SIGNATURE)
	return FALSE;

    /* Lock if it's lockable */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
    }

    return TRUE;
}


/***********************************************************************
 *           RtlUnlockHeap
 * Releases ownership of the critical section object.
 *
 * PARAMS
 *   Heap  [in] Handle to the heap to unlock
 *
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN RtlUnlockHeap(HANDLE HeapPtr)
{
    PHEAP Heap = (PHEAP) HeapPtr;

    /* Check for page heap */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS) {
	return RtlpPageHeapUnlock(Heap);
    }

    /* Check if it's really a heap */
    if (Heap->Signature != HEAP_SIGNATURE)
	return FALSE;

    /* Unlock if it's lockable */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE)) {
	RtlpLeaveHeapLock(Heap->LockVariable);
    }

    return TRUE;
}


/***********************************************************************
 *           RtlSizeHeap
 * PARAMS
 *   Heap  [in] Handle of heap
 *   Flags   [in] Heap size control flags
 *   Ptr     [in] Address of memory to return size for
 *
 * RETURNS
 * Size in bytes of allocated memory
 * 0xffffffff: Failure
 *
 * @implemented
 */
SIZE_T RtlSizeHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr)
{
    PHEAP Heap = (PHEAP) HeapPtr;
    PHEAP_ENTRY HeapEntry;
    SIZE_T EntrySize;

    // FIXME This is a hack around missing SEH support!
    if (!Heap) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_INVALID_HANDLE);
	return (SIZE_T) - 1;
    }

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
	return RtlpDebugSizeHeap(Heap, Flags, Ptr);

    /* Get the heap entry pointer */
    HeapEntry = (PHEAP_ENTRY) Ptr - 1;

    /* Return -1 if that entry is free */
    if (!(HeapEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY)) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus
	    (STATUS_INVALID_PARAMETER);
	return (SIZE_T) - 1;
    }

    /* Get size of this block depending if it's a usual or a big one */
    if (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC) {
	EntrySize = RtlpGetSizeOfBigBlock(HeapEntry);
    } else {
	/* Calculate it */
	EntrySize =
	    (HeapEntry->CommonEntry.Size << HEAP_ENTRY_SHIFT) - HeapEntry->CommonEntry.UnusedBytes;
    }

    /* Return calculated size */
    return EntrySize;
}

BOOLEAN RtlpCheckInUsePattern(PHEAP_ENTRY HeapEntry)
{
    SIZE_T Size, Result;
    PCHAR TailPart;

    /* Calculate size */
    if (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
	Size = RtlpGetSizeOfBigBlock(HeapEntry);
    else
	Size =
	    (HeapEntry->CommonEntry.Size << HEAP_ENTRY_SHIFT) - HeapEntry->CommonEntry.UnusedBytes;

    /* Calculate pointer to the tail part of the block */
    TailPart = (PCHAR) (HeapEntry + 1) + Size;

    /* Compare tail pattern */
    Result = RtlCompareMemory(TailPart, FillPattern, HEAP_ENTRY_SIZE);

    if (Result != HEAP_ENTRY_SIZE) {
	DPRINT1("HEAP: Heap entry (size %zx) %p tail is modified at %p\n",
		Size, HeapEntry, TailPart + Result);
	return FALSE;
    }

    /* All is fine */
    return TRUE;
}

BOOLEAN RtlpValidateHeapHeaders(PHEAP Heap, BOOLEAN Recalculate)
{
    // We skip header validation for now
    return TRUE;
}

BOOLEAN RtlpValidateHeapEntry(PHEAP Heap, PHEAP_ENTRY HeapEntry)
{
    BOOLEAN BigAllocation, EntryFound = FALSE;
    PHEAP_SEGMENT Segment;
    ULONG SegmentOffset;

    /* Perform various consistency checks of this entry */
    if (!HeapEntry)
	goto invalid_entry;
    if ((ULONG_PTR) HeapEntry & (HEAP_ENTRY_SIZE - 1))
	goto invalid_entry;
    if (!(HeapEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY))
	goto invalid_entry;

    BigAllocation = HeapEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC;
    Segment = Heap->Segments[HeapEntry->CommonEntry.SegmentOffset];

    if (BigAllocation &&
	(((ULONG_PTR) HeapEntry & (PAGE_SIZE - 1)) !=
	 FIELD_OFFSET(HEAP_VIRTUAL_ALLOC_ENTRY, BusyBlock)))
	goto invalid_entry;

    if (!BigAllocation && (HeapEntry->CommonEntry.SegmentOffset >= HEAP_SEGMENTS ||
			   !Segment ||
			   HeapEntry < Segment->FirstEntry ||
			   HeapEntry >= Segment->LastValidEntry))
	goto invalid_entry;

    if ((HeapEntry->CommonEntry.Flags & HEAP_ENTRY_FILL_PATTERN) &&
	!RtlpCheckInUsePattern(HeapEntry))
	goto invalid_entry;

    /* Checks are done, if this is a virtual entry, that's all */
    if (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_VIRTUAL_ALLOC)
	return TRUE;

    /* Go through segments and check if this entry fits into any of them */
    for (SegmentOffset = 0; SegmentOffset < HEAP_SEGMENTS; SegmentOffset++) {
	Segment = Heap->Segments[SegmentOffset];
	if (!Segment)
	    continue;

	if ((HeapEntry >= Segment->FirstEntry) &&
	    (HeapEntry < Segment->LastValidEntry)) {
	    /* Got it */
	    EntryFound = TRUE;
	    break;
	}
    }

    /* Return our result of finding entry in the segments */
    return EntryFound;

 invalid_entry:
    DPRINT1("HEAP: Invalid heap entry %p in heap %p\n", HeapEntry, Heap);
    return FALSE;
}

BOOLEAN RtlpValidateHeapSegment(PHEAP Heap,
				PHEAP_SEGMENT Segment,
				UCHAR SegmentOffset,
				PULONG FreeEntriesCount,
				PSIZE_T TotalFreeSize,
				PSIZE_T TagEntries,
				PSIZE_T PseudoTagEntries)
{
    PHEAP_UCR_DESCRIPTOR UcrDescriptor;
    PLIST_ENTRY UcrEntry;
    SIZE_T ByteSize, Size, Result;
    PHEAP_ENTRY CurrentEntry;
    ULONG UnCommittedPages;
    ULONG UnCommittedRanges;
    ULONG PreviousSize;

    UnCommittedPages = 0;
    UnCommittedRanges = 0;

    if (IsListEmpty(&Segment->UCRSegmentList)) {
	UcrEntry = NULL;
	UcrDescriptor = NULL;
    } else {
	UcrEntry = Segment->UCRSegmentList.Flink;
	UcrDescriptor =
	    CONTAINING_RECORD(UcrEntry, HEAP_UCR_DESCRIPTOR, SegmentEntry);
    }

    if (Segment->BaseAddress == Heap)
	CurrentEntry = &Heap->Entry;
    else
	CurrentEntry = &Segment->Entry;

    while (CurrentEntry < Segment->LastValidEntry) {
	if (UcrDescriptor &&
	    ((PVOID) CurrentEntry >= UcrDescriptor->Address)) {
	    DPRINT1
		("HEAP: Entry %p is not inside uncommited range [%p .. %p)\n",
		 CurrentEntry, UcrDescriptor->Address,
		 (PCHAR) UcrDescriptor->Address + UcrDescriptor->Size);

	    return FALSE;
	}

	PreviousSize = 0;

	while (CurrentEntry < Segment->LastValidEntry) {
	    if (PreviousSize != CurrentEntry->CommonEntry.PreviousSize) {
		DPRINT1
		    ("HEAP: Entry %p has incorrect PreviousSize %x instead of %x\n",
		     CurrentEntry, CurrentEntry->CommonEntry.PreviousSize,
		     PreviousSize);

		return FALSE;
	    }

	    PreviousSize = CurrentEntry->CommonEntry.Size;
	    Size = CurrentEntry->CommonEntry.Size << HEAP_ENTRY_SHIFT;

	    if (CurrentEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY) {
		if (TagEntries) {
		    UNIMPLEMENTED;
		}

		/* Check fill pattern */
		if (CurrentEntry->CommonEntry.Flags & HEAP_ENTRY_FILL_PATTERN) {
		    if (!RtlpCheckInUsePattern(CurrentEntry))
			return FALSE;
		}
	    } else {
		/* The entry is free, increase free entries count and total free size */
		*FreeEntriesCount = *FreeEntriesCount + 1;
		*TotalFreeSize += CurrentEntry->CommonEntry.Size;

		if ((Heap->Flags & HEAP_FREE_CHECKING_ENABLED) &&
		    (CurrentEntry->CommonEntry.Flags & HEAP_ENTRY_FILL_PATTERN)) {
		    ByteSize = Size - sizeof(HEAP_FREE_ENTRY);

		    if ((CurrentEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) &&
			(ByteSize > sizeof(HEAP_FREE_ENTRY_EXTRA))) {
			ByteSize -= sizeof(HEAP_FREE_ENTRY_EXTRA);
		    }

		    Result =
			RtlCompareMemoryUlong((PCHAR)
					      ((PHEAP_FREE_ENTRY)
					       CurrentEntry + 1), ByteSize,
					      ARENA_FREE_FILLER);

		    if (Result != ByteSize) {
			DPRINT1
			    ("HEAP: Free heap block %p modified at %p after it was freed\n",
			     CurrentEntry,
			     (PCHAR) (CurrentEntry + 1) + Result);

			return FALSE;
		    }
		}
	    }

	    if (CurrentEntry->CommonEntry.SegmentOffset != SegmentOffset) {
		DPRINT1
		    ("HEAP: Heap entry %p SegmentOffset is incorrect %x (should be %x)\n",
		     CurrentEntry, SegmentOffset,
		     CurrentEntry->CommonEntry.SegmentOffset);
		return FALSE;
	    }

	    /* Check if it's the last entry */
	    if (CurrentEntry->CommonEntry.Flags & HEAP_ENTRY_LAST_ENTRY) {
		CurrentEntry = (PHEAP_ENTRY) ((PCHAR) CurrentEntry + Size);

		if (!UcrDescriptor) {
		    /* Check if it's not really the last one */
		    if (CurrentEntry != Segment->LastValidEntry) {
			DPRINT1
			    ("HEAP: Heap entry %p is not last block in segment (%p)\n",
			     CurrentEntry, Segment->LastValidEntry);
			return FALSE;
		    }
		} else if (CurrentEntry != UcrDescriptor->Address) {
		    DPRINT1
			("HEAP: Heap entry %p does not match next uncommitted address (%p)\n",
			 CurrentEntry, UcrDescriptor->Address);

		    return FALSE;
		} else {
		    UnCommittedPages +=
			(ULONG) (UcrDescriptor->Size / PAGE_SIZE);
		    UnCommittedRanges++;

		    CurrentEntry =
			(PHEAP_ENTRY) ((PCHAR) UcrDescriptor->Address +
				       UcrDescriptor->Size);

		    /* Go to the next UCR descriptor */
		    UcrEntry = UcrEntry->Flink;
		    if (UcrEntry == &Segment->UCRSegmentList) {
			UcrEntry = NULL;
			UcrDescriptor = NULL;
		    } else {
			UcrDescriptor =
			    CONTAINING_RECORD(UcrEntry,
					      HEAP_UCR_DESCRIPTOR,
					      SegmentEntry);
		    }
		}

		break;
	    }

	    /* Advance to the next entry */
	    CurrentEntry = (PHEAP_ENTRY) ((PCHAR) CurrentEntry + Size);
	}
    }

    /* Check total numbers of UCP and UCR */
    if (Segment->NumberOfUnCommittedPages != UnCommittedPages) {
	DPRINT1
	    ("HEAP: Segment %p NumberOfUnCommittedPages is invalid (%x != %x)\n",
	     Segment, Segment->NumberOfUnCommittedPages, UnCommittedPages);

	return FALSE;
    }

    if (Segment->NumberOfUnCommittedRanges != UnCommittedRanges) {
	DPRINT1
	    ("HEAP: Segment %p NumberOfUnCommittedRanges is invalid (%x != %x)\n",
	     Segment, Segment->NumberOfUnCommittedRanges,
	     UnCommittedRanges);

	return FALSE;
    }

    return TRUE;
}

BOOLEAN RtlpValidateHeap(PHEAP Heap, BOOLEAN ForceValidation)
{
    UCHAR SegmentOffset;
    SIZE_T TotalFreeSize;
    PLIST_ENTRY ListHead, NextEntry;
    ULONG FreeBlocksCount, FreeListEntriesCount;
    ULONG HintIndex;

    /* Check headers */
    if (!RtlpValidateHeapHeaders(Heap, FALSE))
	return FALSE;

    /* Skip validation if it's not needed */
    if (!ForceValidation && !(Heap->Flags & HEAP_VALIDATE_ALL_ENABLED))
	return TRUE;

    /* Check free list */
    FreeListEntriesCount = 0;
    ListHead = &Heap->FreeLists;
    NextEntry = ListHead->Flink;

    while (NextEntry != ListHead) {
	PHEAP_FREE_ENTRY FreeEntry = CONTAINING_RECORD(NextEntry, HEAP_FREE_ENTRY, FreeList);

	NextEntry = NextEntry->Flink;

	if (NextEntry != ListHead) {
	    PHEAP_FREE_ENTRY NextFreeEntry = CONTAINING_RECORD(NextEntry, HEAP_FREE_ENTRY, FreeList);
	    /* Free entries must be sorted */
	    if (FreeEntry->CommonEntry.Size > NextFreeEntry->CommonEntry.Size) {
		DPRINT1("Dedicated free entry %p of size %d is not put in order.\n",
			FreeEntry, FreeEntry->CommonEntry.Size);
	    }
	}

	/* Check that the hint is there */
	if (FreeEntry->CommonEntry.Size > Heap->DeCommitFreeBlockThreshold) {
	    if (Heap->FreeHints[0] == NULL) {
		DPRINT1("No hint pointing to the non-dedicated list although there is a free entry %p of size %d.\n",
			FreeEntry, FreeEntry->CommonEntry.Size);
	    }
	    if (!RtlTestBit(&Heap->FreeHintBitmap, 0)) {
		DPRINT1("Hint bit 0 is not set although there is a free entry %p of size %d.\n",
			FreeEntry, FreeEntry->CommonEntry.Size);
	    }
	} else {
	    if (Heap->FreeHints[FreeEntry->CommonEntry.Size - 1] == NULL) {
		DPRINT1("No hint pointing to the dedicated list although there is a free entry %p of size %d.\n",
			FreeEntry, FreeEntry->CommonEntry.Size);
	    }
	    if (!RtlTestBit(&Heap->FreeHintBitmap, FreeEntry->CommonEntry.Size - 1)) {
		DPRINT1("Hint bit 0 is not set although there is a free entry %p of size %d.\n",
			FreeEntry, FreeEntry->CommonEntry.Size);
	    }
	}

	/* If there is an in-use entry in a free list - that's quite a big problem */
	if (FreeEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY) {
	    DPRINT1("HEAP: Free element %p is marked in-use\n", FreeEntry);
	    return FALSE;
	}

	/* Add up to the total amount of free entries */
	FreeListEntriesCount++;
    }

    /* Check free list hints */
    for (HintIndex = 0; HintIndex < Heap->DeCommitFreeBlockThreshold; HintIndex++) {
	if (Heap->FreeHints[HintIndex] != NULL) {
	    PHEAP_FREE_ENTRY FreeEntry = CONTAINING_RECORD(Heap->FreeHints[HintIndex],
							   HEAP_FREE_ENTRY, FreeList);

	    if (!RtlTestBit(&Heap->FreeHintBitmap, HintIndex)) {
		DPRINT1("Hint bitmap bit at %u is not set, but there is a hint entry.\n",
			HintIndex);
	    }

	    if (HintIndex == 0) {
		if (FreeEntry->CommonEntry.Size <= Heap->DeCommitFreeBlockThreshold) {
		    DPRINT1("There is an entry %p of size %u, smaller than the decommit threshold %zu in the non-dedicated free list hint.\n",
			    FreeEntry, FreeEntry->CommonEntry.Size, Heap->DeCommitFreeBlockThreshold);
		}
	    } else {
		if (HintIndex != FreeEntry->CommonEntry.Size - 1) {
		    DPRINT1("There is an entry %p of size %u at the position %u in the free entry hint array.\n",
			    FreeEntry, FreeEntry->CommonEntry.Size, HintIndex);
		}

		if (FreeEntry->FreeList.Blink != &Heap->FreeLists) {
		    /* The entry right before the hint must be smaller. */
		    PHEAP_FREE_ENTRY PreviousFreeEntry = CONTAINING_RECORD(FreeEntry->FreeList.Blink,
									   HEAP_FREE_ENTRY, FreeList);
		    if (PreviousFreeEntry->CommonEntry.Size >= FreeEntry->CommonEntry.Size) {
			DPRINT1("Free entry hint %p of size %u is larger than the entry before it %p, which is of size %u.\n",
				FreeEntry, FreeEntry->CommonEntry.Size, PreviousFreeEntry,
				PreviousFreeEntry->CommonEntry.Size);
		    }
		}
	    }
	} else if (RtlTestBit(&Heap->FreeHintBitmap, HintIndex)) {
	    DPRINT1("Hint bitmap bit at %u is set, but there is no hint entry.\n",
		    HintIndex);
	}
    }

    /* Check big allocations */
    ListHead = &Heap->VirtualAllocdBlocks;
    NextEntry = ListHead->Flink;

    while (ListHead != NextEntry) {
	PHEAP_VIRTUAL_ALLOC_ENTRY VirtualAllocBlock = CONTAINING_RECORD(NextEntry, HEAP_VIRTUAL_ALLOC_ENTRY, Entry);

	/* We can only check the fill pattern */
	if (VirtualAllocBlock->BusyBlock.CommonEntry.Flags & HEAP_ENTRY_FILL_PATTERN) {
	    if (!RtlpCheckInUsePattern(&VirtualAllocBlock->BusyBlock))
		return FALSE;
	}

	NextEntry = NextEntry->Flink;
    }

    /* Check all segments */
    FreeBlocksCount = 0;
    TotalFreeSize = 0;

    for (SegmentOffset = 0; SegmentOffset < HEAP_SEGMENTS; SegmentOffset++) {
	PHEAP_SEGMENT Segment = Heap->Segments[SegmentOffset];

	/* Go to the next one if there is no segment */
	if (!Segment)
	    continue;

	if (!RtlpValidateHeapSegment(Heap, Segment, SegmentOffset, &FreeBlocksCount,
				     &TotalFreeSize, NULL, NULL)) {
	    return FALSE;
	}
    }

    if (FreeListEntriesCount != FreeBlocksCount) {
	DPRINT1("HEAP: Free blocks count in arena (%u) does not match free blocks number in the free lists (%u)\n",
		FreeBlocksCount, FreeListEntriesCount);
	return FALSE;
    }

    if (Heap->TotalFreeSize != TotalFreeSize) {
	DPRINT1("HEAP: Total size of free blocks in arena (0x%zx) does not equal to the one in heap header (0x%zx)\n",
		TotalFreeSize, Heap->TotalFreeSize);
	return FALSE;
    }

    return TRUE;
}

/***********************************************************************
 *           RtlValidateHeap
 * Validates a specified heap.
 *
 * PARAMS
 *   Heap  [in] Handle to the heap
 *   Flags   [in] Bit flags that control access during operation
 *   Block  [in] Optional pointer to memory block to validate
 *
 * NOTES
 * Flags is ignored.
 *
 * RETURNS
 * TRUE: Success
 * FALSE: Failure
 *
 * @implemented
 */
BOOLEAN RtlValidateHeap(HANDLE HeapPtr, ULONG Flags, PVOID Block)
{
    PHEAP Heap = (PHEAP) HeapPtr;
    BOOLEAN HeapLocked = FALSE;
    BOOLEAN HeapValid;

    /* Check for page heap */
    if (Heap->ForceFlags & HEAP_FLAG_PAGE_ALLOCS)
	return RtlpDebugPageHeapValidate(HeapPtr, Flags, Block);

    /* Check signature */
    if (Heap->Signature != HEAP_SIGNATURE) {
	DPRINT1("HEAP: Signature %x is invalid for heap %p\n",
		Heap->Signature, Heap);
	return FALSE;
    }

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Acquire the lock if necessary */
    if (!(Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
	HeapLocked = TRUE;
    }

    /* Either validate whole heap or just one entry */
    if (!Block)
	HeapValid = RtlpValidateHeap(Heap, TRUE);
    else
	HeapValid = RtlpValidateHeapEntry(Heap, (PHEAP_ENTRY) Block - 1);

    /* Unlock if it's lockable */
    if (HeapLocked) {
	RtlpLeaveHeapLock(Heap->LockVariable);
    }

    return HeapValid;
}

/*
 * @implemented
 */
NTSTATUS NTAPI
RtlEnumProcessHeaps(PHEAP_ENUMERATION_ROUTINE HeapEnumerationRoutine,
		    PVOID lParam)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}


/*
 * @implemented
 */
ULONG NTAPI RtlGetProcessHeaps(ULONG count, HANDLE * heaps)
{
    UNIMPLEMENTED;
    return 0;
}


/*
 * @implemented
 */
BOOLEAN NTAPI RtlValidateProcessHeaps(VOID)
{
    UNIMPLEMENTED;
    return TRUE;
}


/*
 * @unimplemented
 */
BOOLEAN NTAPI RtlZeroHeap(IN PVOID HeapHandle, IN ULONG Flags)
{
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @implemented
 */
BOOLEAN NTAPI RtlSetUserValueHeap(IN PVOID HeapHandle,
				  IN ULONG Flags,
				  IN PVOID BaseAddress,
				  IN PVOID UserValue)
{
    PHEAP Heap = (PHEAP) HeapHandle;
    PHEAP_ENTRY HeapEntry;
    PHEAP_ENTRY_EXTRA Extra;
    BOOLEAN HeapLocked = FALSE, ValueSet = FALSE;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
	return RtlpDebugSetUserValueHeap(Heap, Flags, BaseAddress,
					 UserValue);

    /* Lock if it's lockable */
    if (!(Heap->Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
	HeapLocked = TRUE;
    }

    /* Get a pointer to the entry */
    HeapEntry = (PHEAP_ENTRY) BaseAddress - 1;

    /* If it's a free entry - return error */
    if (!(HeapEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY)) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus
	    (STATUS_INVALID_PARAMETER);

	/* Release the heap lock if it was acquired */
	if (HeapLocked)
	    RtlpLeaveHeapLock(Heap->LockVariable);

	return FALSE;
    }

    /* Check if this entry has an extra stuff associated with it */
    if (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
	/* Use extra to store the value */
	Extra = RtlpGetExtraStuffPointer(HeapEntry);
	Extra->Settable = (ULONG_PTR) UserValue;

	/* Indicate that value was set */
	ValueSet = TRUE;
    }

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
	RtlpLeaveHeapLock(Heap->LockVariable);

    return ValueSet;
}

/*
 * @implemented
 */
BOOLEAN NTAPI RtlSetUserFlagsHeap(IN PVOID HeapHandle,
				  IN ULONG Flags,
				  IN PVOID BaseAddress,
				  IN ULONG UserFlagsReset,
				  IN ULONG UserFlagsSet)
{
    PHEAP Heap = (PHEAP) HeapHandle;
    PHEAP_ENTRY HeapEntry;
    BOOLEAN HeapLocked = FALSE;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
	return RtlpDebugSetUserFlagsHeap(Heap, Flags, BaseAddress,
					 UserFlagsReset, UserFlagsSet);

    /* Lock if it's lockable */
    if (!(Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
	HeapLocked = TRUE;
    }

    /* Get a pointer to the entry */
    HeapEntry = (PHEAP_ENTRY) BaseAddress - 1;

    /* If it's a free entry - return error */
    if (!(HeapEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY)) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus
	    (STATUS_INVALID_PARAMETER);

	/* Release the heap lock if it was acquired */
	if (HeapLocked)
	    RtlpLeaveHeapLock(Heap->LockVariable);

	return FALSE;
    }

    /* Set / reset flags */
    HeapEntry->CommonEntry.Flags &= ~(UserFlagsReset >> 4);
    HeapEntry->CommonEntry.Flags |= (UserFlagsSet >> 4);

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
	RtlpLeaveHeapLock(Heap->LockVariable);

    return TRUE;
}

/*
 * @implemented
 */
BOOLEAN NTAPI RtlGetUserInfoHeap(IN PVOID HeapHandle,
				 IN ULONG Flags,
				 IN PVOID BaseAddress,
				 OUT PVOID *UserValue,
				 OUT PULONG UserFlags)
{
    PHEAP Heap = (PHEAP) HeapHandle;
    PHEAP_ENTRY HeapEntry;
    PHEAP_ENTRY_EXTRA Extra;
    BOOLEAN HeapLocked = FALSE;

    /* Force flags */
    Flags |= Heap->ForceFlags;

    /* Call special heap */
    if (RtlpHeapIsSpecial(Flags))
	return RtlpDebugGetUserInfoHeap(Heap, Flags, BaseAddress, UserValue,
					UserFlags);

    /* Lock if it's lockable */
    if (!(Flags & HEAP_NO_SERIALIZE)) {
	RtlpEnterHeapLock(Heap->LockVariable, TRUE);
	HeapLocked = TRUE;
    }

    /* Get a pointer to the entry */
    HeapEntry = (PHEAP_ENTRY) BaseAddress - 1;

    /* If it's a free entry - return error */
    if (!(HeapEntry->CommonEntry.Flags & HEAP_ENTRY_BUSY)) {
	RtlSetLastWin32ErrorAndNtStatusFromNtStatus
	    (STATUS_INVALID_PARAMETER);

	/* Release the heap lock if it was acquired */
	if (HeapLocked)
	    RtlpLeaveHeapLock(Heap->LockVariable);

	return FALSE;
    }

    /* Check if this entry has an extra stuff associated with it */
    if (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_EXTRA_PRESENT) {
	/* Get pointer to extra data */
	Extra = RtlpGetExtraStuffPointer(HeapEntry);

	/* Pass user value */
	if (UserValue)
	    *UserValue = (PVOID) Extra->Settable;
    }

    /* Decode and return user flags */
    if (UserFlags)
	*UserFlags = (HeapEntry->CommonEntry.Flags & HEAP_ENTRY_SETTABLE_FLAGS) << 4;

    /* Release the heap lock if it was acquired */
    if (HeapLocked)
	RtlpLeaveHeapLock(Heap->LockVariable);

    return TRUE;
}

/*
 * @unimplemented
 */
NTSTATUS NTAPI RtlUsageHeap(IN HANDLE Heap,
			    IN ULONG Flags,
			    OUT PRTL_HEAP_USAGE Usage)
{
    /* TODO */
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

PWSTR NTAPI RtlQueryTagHeap(IN PVOID HeapHandle,
			    IN ULONG Flags,
			    IN USHORT TagIndex,
			    IN BOOLEAN ResetCounters,
			    OUT PRTL_HEAP_TAG_INFO HeapTagInfo)
{
    /* TODO */
    UNIMPLEMENTED;
    return NULL;
}

ULONG NTAPI RtlExtendHeap(IN HANDLE Heap,
			  IN ULONG Flags,
			  IN PVOID P,
			  IN SIZE_T Size)
{
    /* TODO */
    UNIMPLEMENTED;
    return 0;
}

ULONG NTAPI RtlCreateTagHeap(IN HANDLE HeapHandle,
			     IN ULONG Flags,
			     IN PWSTR TagName,
			     IN PWSTR TagSubName)
{
    /* TODO */
    UNIMPLEMENTED;
    return 0;
}

NTSTATUS NTAPI RtlWalkHeap(IN HANDLE HeapHandle,
			   IN PVOID HeapEntry)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

PVOID NTAPI RtlProtectHeap(IN PVOID HeapHandle,
			   IN BOOLEAN ReadOnly)
{
    UNIMPLEMENTED;
    return NULL;
}

/*
 * @implemented
 */
NTSTATUS NTAPI RtlSetHeapInformation(IN HANDLE HeapHandle OPTIONAL,
				     IN HEAP_INFORMATION_CLASS HeapInformationClass,
				     IN PVOID HeapInformation,
				     IN SIZE_T HeapInformationLength)
{
    /* Setting heap information is not really supported except for enabling LFH */
    if (HeapInformationClass == HeapCompatibilityInformation) {
	/* Check buffer length */
	if (HeapInformationLength < sizeof(ULONG)) {
	    /* The provided buffer is too small */
	    return STATUS_BUFFER_TOO_SMALL;
	}

	/* Check for a special magic value for enabling LFH */
	if (*(PULONG) HeapInformation != 2) {
	    return STATUS_UNSUCCESSFUL;
	}

	DPRINT1("RtlSetHeapInformation() needs to enable LFH\n");
	return STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTSTATUS NTAPI RtlQueryHeapInformation(HANDLE HeapHandle,
				       HEAP_INFORMATION_CLASS HeapInformationClass,
				       PVOID HeapInformation,
				       SIZE_T HeapInformationLength,
				       PSIZE_T ReturnLength OPTIONAL)
{
    PHEAP Heap = (PHEAP) HeapHandle;

    /* Only HeapCompatibilityInformation is supported */
    if (HeapInformationClass == HeapCompatibilityInformation) {
	/* Set result length */
	if (ReturnLength)
	    *ReturnLength = sizeof(ULONG);

	/* Check buffer length */
	if (HeapInformationLength < sizeof(ULONG)) {
	    /* It's too small, return needed length */
	    return STATUS_BUFFER_TOO_SMALL;
	}

	/* Return front end heap type */
	*(PULONG) HeapInformation = Heap->FrontEndHeapType;

	return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

/*
 * @implemented
 */
ULONG NTAPI RtlMultipleAllocateHeap(IN PVOID HeapHandle,
				    IN ULONG Flags,
				    IN SIZE_T Size,
				    IN ULONG Count,
				    OUT PVOID * Array)
{
    ULONG Index;
    EXCEPTION_RECORD ExceptionRecord;

    for (Index = 0; Index < Count; ++Index) {
	Array[Index] = RtlAllocateHeap(HeapHandle, Flags, Size);
	if (Array[Index] == NULL) {
	    /* ERROR_NOT_ENOUGH_MEMORY */
	    RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);

	    if (Flags & HEAP_GENERATE_EXCEPTIONS) {
		ExceptionRecord.ExceptionCode = STATUS_NO_MEMORY;
		ExceptionRecord.ExceptionRecord = NULL;
		ExceptionRecord.NumberParameters = 0;
		ExceptionRecord.ExceptionFlags = 0;

		RtlRaiseException(&ExceptionRecord);
	    }
	    break;
	}
    }

    return Index;
}

/* @implemented */
ULONG NTAPI RtlMultipleFreeHeap(IN PVOID HeapHandle,
				IN ULONG Flags,
				IN ULONG Count,
				OUT PVOID *Array)
{
    ULONG Index;

    for (Index = 0; Index < Count; ++Index) {
	if (Array[Index] == NULL)
	    continue;

	_SEH2_TRY {
	    if (!RtlFreeHeap(HeapHandle, Flags, Array[Index])) {
		/* ERROR_INVALID_PARAMETER */
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus
		    (STATUS_INVALID_PARAMETER);
		break;
	    }
	}
	_SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	    /* ERROR_INVALID_PARAMETER */
	    RtlSetLastWin32ErrorAndNtStatusFromNtStatus
		(STATUS_INVALID_PARAMETER);
	    break;
	}
	_SEH2_END;
    }

    return Index;
}

/*
 * Info:
 * - https://securityxploded.com/enumheaps.php
 * - https://evilcodecave.wordpress.com/2009/04/14/rtlqueryprocessheapinformation-as-anti-dbg-trick/
 */
struct _DEBUG_BUFFER;

/*
 * @unimplemented
 */
NTSTATUS NTAPI RtlQueryProcessHeapInformation(IN struct _DEBUG_BUFFER *DebugBuffer)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}
