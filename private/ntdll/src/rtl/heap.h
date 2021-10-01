/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS System Libraries
 * FILE:            lib/rtl/heap.h
 * PURPOSE:         Run-Time Libary Heap Manager header
 * PROGRAMMER:      Aleksey Bragin
 */

/* INCLUDES ******************************************************************/

#pragma once

C_ASSERT(HEAP_CREATE_VALID_MASK == 0x0007F0FF);

/* Core heap definitions */
#define HEAP_SEGMENTS 64

#define HEAP_ENTRY_SIZE ((ULONG)sizeof(HEAP_ENTRY))
#ifdef _WIN64
#define HEAP_ENTRY_SHIFT 4
#else
#define HEAP_ENTRY_SHIFT 3
#endif
#define HEAP_MAX_BLOCK_SIZE ((0x80000 - PAGE_SIZE) >> HEAP_ENTRY_SHIFT)

#define ARENA_INUSE_FILLER     0xBAADF00D
#define ARENA_FREE_FILLER      0xFEEEFEEE
#define HEAP_TAIL_FILL         0xab

// from ntifs.h, should go to another header!
#define HEAP_GLOBAL_TAG                 0x0800
#define HEAP_PSEUDO_TAG_FLAG            0x8000
#define HEAP_TAG_MASK                  (HEAP_MAXIMUM_TAG << HEAP_TAG_SHIFT)
#define HEAP_TAGS_MASK                 (HEAP_TAG_MASK ^ (0xFF << HEAP_TAG_SHIFT))

#define HEAP_EXTRA_FLAGS_MASK (HEAP_CAPTURE_STACK_BACKTRACES |	\
                               HEAP_SETTABLE_USER_VALUE |	\
                               HEAP_TAGS_MASK)

/* Heap entry flags */
#define HEAP_ENTRY_BUSY           0x01
#define HEAP_ENTRY_EXTRA_PRESENT  0x02
#define HEAP_ENTRY_FILL_PATTERN   0x04
#define HEAP_ENTRY_VIRTUAL_ALLOC  0x08
#define HEAP_ENTRY_LAST_ENTRY     0x10
#define HEAP_ENTRY_SETTABLE_FLAG1 0x20
#define HEAP_ENTRY_SETTABLE_FLAG2 0x40
#define HEAP_ENTRY_SETTABLE_FLAG3 0x80
#define HEAP_ENTRY_SETTABLE_FLAGS (HEAP_ENTRY_SETTABLE_FLAG1 | HEAP_ENTRY_SETTABLE_FLAG2 | HEAP_ENTRY_SETTABLE_FLAG3)

/* Signatures */
#define HEAP_SIGNATURE         0xeefeeff
#define HEAP_SEGMENT_SIGNATURE 0xffeeffee

/* Segment flags */
#define HEAP_USER_ALLOCATED    0x1

/* Heap structures */
struct _HEAP_COMMON_ENTRY {
#ifdef _M_AMD64
    PVOID PreviousBlockPrivateData;
#endif
    union {
	struct {
	    USHORT Size;
	    UCHAR Flags;
	    UCHAR SmallTagIndex;
	};
	struct {
#ifndef _M_AMD64
	    PVOID SubSegmentCode;
#else
	    ULONG SubSegmentCodeDummy;
#endif
	    USHORT PreviousSize;
	    union {
		UCHAR SegmentOffset;
		UCHAR LFHFlags;
	    };
	    UCHAR UnusedBytes;
	};
	struct {
	    USHORT FunctionIndex;
	    USHORT ContextValue;
	};
	struct {
	    ULONG InterceptorValue;
	    USHORT UnusedBytesLength;
	    UCHAR EntryOffset;
	    UCHAR ExtendedBlockSignature;
	};
	struct {
	    ULONG Code1;
	    USHORT Code2;
	    UCHAR Code3;
	    UCHAR Code4;
	};
	ULONGLONG AgregateCode;
    };
};

typedef struct _HEAP_FREE_ENTRY {
    struct _HEAP_COMMON_ENTRY CommonEntry;
    LIST_ENTRY FreeList;
} HEAP_FREE_ENTRY, *PHEAP_FREE_ENTRY;

typedef struct _HEAP_ENTRY {
    struct _HEAP_COMMON_ENTRY CommonEntry;
} HEAP_ENTRY, *PHEAP_ENTRY;

#ifdef _WIN64
C_ASSERT(sizeof(HEAP_ENTRY) == 16);
#else
C_ASSERT(sizeof(HEAP_ENTRY) == 8);
#endif
C_ASSERT((1 << HEAP_ENTRY_SHIFT) == sizeof(HEAP_ENTRY));
C_ASSERT((2 << HEAP_ENTRY_SHIFT) == sizeof(HEAP_FREE_ENTRY));

typedef struct _HEAP_TAG_ENTRY {
    ULONG Allocs;
    ULONG Frees;
    ULONG Size;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
} HEAP_TAG_ENTRY, *PHEAP_TAG_ENTRY;

typedef struct _HEAP_PSEUDO_TAG_ENTRY {
    ULONG Allocs;
    ULONG Frees;
    SIZE_T Size;
} HEAP_PSEUDO_TAG_ENTRY, *PHEAP_PSEUDO_TAG_ENTRY;

typedef struct _HEAP_COUNTERS {
    SIZE_T TotalMemoryReserved;
    SIZE_T TotalMemoryCommitted;
    SIZE_T TotalMemoryLargeUCR;
    SIZE_T TotalSizeInVirtualBlocks;
    ULONG TotalSegments;
    ULONG TotalUCRs;
    ULONG CommittOps;
    ULONG DeCommitOps;
    ULONG LockAcquires;
    ULONG LockCollisions;
    ULONG CommitRate;
    ULONG DecommittRate;
    ULONG CommitFailures;
    ULONG InBlockCommitFailures;
    ULONG CompactHeapCalls;
    ULONG CompactedUCRs;
    ULONG InBlockDeccommits;
    SIZE_T InBlockDeccomitSize;
} HEAP_COUNTERS, *PHEAP_COUNTERS;

typedef struct _HEAP_TUNING_PARAMETERS {
    ULONG CommittThresholdShift;
    SIZE_T MaxPreCommittThreshold;
} HEAP_TUNING_PARAMETERS, *PHEAP_TUNING_PARAMETERS;

typedef struct _HEAP_LIST_LOOKUP {
    struct _HEAP_LIST_LOOKUP *ExtendedLookup;
    ULONG ArraySize;
    ULONG ExtraItem;
    ULONG ItemCount;
    ULONG OutOfRangeItems;
    ULONG BaseIndex;
    PLIST_ENTRY ListHead;
    PULONG ListsInUseUlong;
    PLIST_ENTRY *ListHints;
} HEAP_LIST_LOOKUP, *PHEAP_LIST_LOOKUP;

typedef struct _HEAP_LOCK
{
    RTL_CRITICAL_SECTION CriticalSection;
} HEAP_LOCK, *PHEAP_LOCK;

#define HEAP_SEGMENT_MEMBERS			\
    HEAP_ENTRY Entry;				\
    ULONG SegmentSignature;			\
    ULONG SegmentFlags;				\
    LIST_ENTRY SegmentListEntry;		\
    struct _HEAP *Heap;				\
    PVOID BaseAddress;				\
    ULONG NumberOfPages;			\
    PHEAP_ENTRY FirstEntry;			\
    PHEAP_ENTRY LastValidEntry;			\
    ULONG NumberOfUnCommittedPages;		\
    ULONG NumberOfUnCommittedRanges;		\
    USHORT SegmentAllocatorBackTraceIndex;	\
    USHORT Reserved;				\
    LIST_ENTRY UCRSegmentList

typedef struct _HEAP {
    HEAP_SEGMENT_MEMBERS;

    ULONG Flags;
    ULONG ForceFlags;
    ULONG CompatibilityFlags;
    ULONG EncodeFlagMask;
    HEAP_ENTRY Encoding;
    ULONG_PTR PointerKey;
    ULONG Interceptor;
    ULONG VirtualMemoryThreshold;
    ULONG Signature;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T TotalFreeSize;
    SIZE_T MaximumAllocationSize;
    USHORT ProcessHeapsListIndex;
    USHORT HeaderValidateLength;
    PVOID HeaderValidateCopy;
    USHORT NextAvailableTagIndex;
    USHORT MaximumTagIndex;
    PHEAP_TAG_ENTRY TagEntries;
    LIST_ENTRY UCRList;
    LIST_ENTRY UCRSegments;	// FIXME: non-Vista
    ULONG_PTR AlignRound;
    ULONG_PTR AlignMask;
    LIST_ENTRY VirtualAllocdBlocks;
    LIST_ENTRY SegmentList;
    struct _HEAP_SEGMENT *Segments[HEAP_SEGMENTS];	//FIXME: non-Vista
    USHORT AllocatorBackTraceIndex;
    ULONG NonDedicatedListLength;
    PVOID BlocksIndex;		// HEAP_LIST_LOOKUP
    PVOID UCRIndex;
    PHEAP_PSEUDO_TAG_ENTRY PseudoTagEntries;
    LIST_ENTRY FreeLists;
    PHEAP_LOCK LockVariable;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    PVOID FrontEndHeap;
    USHORT FrontHeapLockCount;
    UCHAR FrontEndHeapType;
    HEAP_COUNTERS Counters;
    HEAP_TUNING_PARAMETERS TuningParameters;
    RTL_BITMAP FreeHintBitmap;	// FIXME: non-Vista
    PLIST_ENTRY FreeHints[ANYSIZE_ARRAY];	// FIXME: non-Vista
} HEAP, *PHEAP;

typedef struct _HEAP_SEGMENT {
    HEAP_SEGMENT_MEMBERS;
} HEAP_SEGMENT, *PHEAP_SEGMENT;

typedef struct _HEAP_UCR_DESCRIPTOR {
    LIST_ENTRY ListEntry;
    LIST_ENTRY SegmentEntry;
    PVOID Address;
    SIZE_T Size;
} HEAP_UCR_DESCRIPTOR, *PHEAP_UCR_DESCRIPTOR;

typedef struct _HEAP_UCR_SEGMENT {
    LIST_ENTRY ListEntry;
    SIZE_T ReservedSize;
    SIZE_T CommittedSize;
} HEAP_UCR_SEGMENT, *PHEAP_UCR_SEGMENT;

typedef struct _HEAP_ENTRY_EXTRA {
    union {
	struct {
	    USHORT AllocatorBackTraceIndex;
	    USHORT TagIndex;
	    ULONG_PTR Settable;
	};
	UINT64 ZeroInit;
    };
} HEAP_ENTRY_EXTRA, *PHEAP_ENTRY_EXTRA;

typedef HEAP_ENTRY_EXTRA HEAP_FREE_ENTRY_EXTRA, *PHEAP_FREE_ENTRY_EXTRA;

typedef struct _HEAP_VIRTUAL_ALLOC_ENTRY {
    LIST_ENTRY Entry;
    HEAP_ENTRY_EXTRA ExtraStuff;
    SIZE_T CommitSize;
    SIZE_T ReserveSize;
    HEAP_ENTRY BusyBlock;
} HEAP_VIRTUAL_ALLOC_ENTRY, *PHEAP_VIRTUAL_ALLOC_ENTRY;


/* Global variables */
extern BOOLEAN RtlpPageHeapEnabled;

/* Inline functions */
static inline NTSTATUS RtlpInitializeHeapLock(IN OUT PHEAP_LOCK *Lock)
{
    return RtlInitializeCriticalSection(&(*Lock)->CriticalSection);
}

static inline NTSTATUS RtlpEnterHeapLock(IN OUT PHEAP_LOCK Lock,
					 IN BOOLEAN Exclusive)
{
    UNREFERENCED_PARAMETER(Exclusive);

    return RtlEnterCriticalSection(&Lock->CriticalSection);
}

static inline NTSTATUS RtlpLeaveHeapLock(IN OUT PHEAP_LOCK Lock)
{
    return RtlLeaveCriticalSection(&Lock->CriticalSection);
}

static inline BOOLEAN RtlpTryEnterHeapLock(IN OUT PHEAP_LOCK Lock,
					   IN BOOLEAN Exclusive)
{
    UNREFERENCED_PARAMETER(Exclusive);

    return RtlTryEnterCriticalSection(&Lock->CriticalSection);
}

static inline NTSTATUS RtlpDeleteHeapLock(IN OUT PHEAP_LOCK Lock)
{
    return RtlDeleteCriticalSection(&Lock->CriticalSection);
}

/* Functions declarations */

/* heap.c */
VOID RtlpAddHeapToProcessList(PHEAP Heap);
VOID RtlpRemoveHeapFromProcessList(PHEAP Heap);
PHEAP_FREE_ENTRY RtlpCoalesceFreeBlocks(PHEAP Heap,
					PHEAP_FREE_ENTRY FreeEntry,
					PSIZE_T FreeSize, BOOLEAN Remove);
PHEAP_ENTRY_EXTRA RtlpGetExtraStuffPointer(PHEAP_ENTRY HeapEntry);
BOOLEAN RtlpValidateHeap(PHEAP Heap, BOOLEAN ForceValidation);
BOOLEAN RtlpValidateHeapEntry(PHEAP Heap, PHEAP_ENTRY HeapEntry);
BOOLEAN RtlpValidateHeapHeaders(PHEAP Heap, BOOLEAN Recalculate);

/* heapdbg.c */
HANDLE RtlpDebugCreateHeap(ULONG Flags,
			   PVOID Addr,
			   SIZE_T TotalSize,
			   SIZE_T CommitSize,
			   PVOID Lock,
			   PRTL_HEAP_PARAMETERS Parameters);
BOOLEAN RtlpDebugDestroyHeap(HANDLE HeapPtr);
PVOID RtlpDebugAllocateHeap(PVOID HeapPtr, ULONG Flags, SIZE_T Size);
PVOID RtlpDebugReAllocateHeap(HANDLE HeapPtr,
			      ULONG Flags,
			      PVOID Ptr,
			      SIZE_T Size);
BOOLEAN RtlpDebugFreeHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr);
BOOLEAN RtlpDebugGetUserInfoHeap(PVOID HeapHandle,
				 ULONG Flags,
				 PVOID BaseAddress,
				 PVOID *UserValue,
				 PULONG UserFlags);
BOOLEAN RtlpDebugSetUserValueHeap(PVOID HeapHandle,
				  ULONG Flags,
				  PVOID BaseAddress,
				  PVOID UserValue);
BOOLEAN RtlpDebugSetUserFlagsHeap(PVOID HeapHandle,
				  ULONG Flags,
				  PVOID BaseAddress,
				  ULONG UserFlagsReset,
				  ULONG UserFlagsSet);
SIZE_T RtlpDebugSizeHeap(HANDLE HeapPtr, ULONG Flags, PVOID Ptr);

/* heappage.c */
HANDLE RtlpPageHeapCreate(ULONG Flags,
			  PVOID Addr,
			  SIZE_T TotalSize,
			  SIZE_T CommitSize,
			  PVOID Lock,
			  PRTL_HEAP_PARAMETERS Parameters);
PVOID RtlpPageHeapDestroy(HANDLE HeapPtr);
PVOID RtlpPageHeapAllocate(IN PVOID HeapPtr,
			   IN ULONG Flags,
			   IN SIZE_T Size);
BOOLEAN RtlpPageHeapFree(HANDLE HeapPtr,
			 ULONG Flags,
			 PVOID Ptr);
PVOID RtlpPageHeapReAllocate(HANDLE HeapPtr,
			     ULONG Flags,
			     PVOID Ptr,
			     SIZE_T Size);
BOOLEAN RtlpPageHeapLock(HANDLE HeapPtr);
BOOLEAN RtlpPageHeapUnlock(HANDLE HeapPtr);
BOOLEAN RtlpPageHeapGetUserInfo(PVOID HeapHandle,
				ULONG Flags,
				PVOID BaseAddress,
				PVOID *UserValue,
				PULONG UserFlags);
BOOLEAN RtlpPageHeapSetUserValue(PVOID HeapHandle,
				 ULONG Flags,
				 PVOID BaseAddress,
				 PVOID UserValue);
BOOLEAN RtlpPageHeapSetUserFlags(PVOID HeapHandle,
				 ULONG Flags,
				 PVOID BaseAddress,
				 ULONG UserFlagsReset,
				 ULONG UserFlagsSet);
BOOLEAN RtlpDebugPageHeapValidate(PVOID HeapPtr,
				  ULONG Flags,
				  PVOID Block);
SIZE_T RtlpPageHeapSize(HANDLE HeapPtr,
			ULONG Flags,
			PVOID Ptr);
