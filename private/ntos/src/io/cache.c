/*++

Copyright (c) 2024  Dr. Chang Liu, PhD.

Module Name:

    cache.c

Abstract:

    Neptune OS Cache Manager (Server-side routines)

    This file implements the server-side portion of Neptune OS
    cache manager. The basic design here is that files are cached
    in 256KB (for 4K-page architectures) views, just like on Windows.
    Virtual address space is divided into views and are addressed
    using view tables which have 1024 or 512 views on i686 and amd64
    respectively. 32-bit architectures have only one level of view
    tables. 64-bit architectures have two. If possible, cache pages
    from the underlying volume device are shared with the cache pages
    of the file system file objects. We try very hard to maintain
    cache consistency so that all drivers and NT clients always see
    the same up-to-date data at all times. This requires special
    treatment for the case where the cluster size of the file system
    is smaller than the page size of the architecture.

Revision History:

    2024-02-14  File created

--*/
#include "iop.h"

#define NTOS_CC_TAG	(EX_POOL_TAG('n','t','c','c'))

#define CiAllocatePool(Size)	ExAllocatePoolWithTag((Size), NTOS_CC_TAG)
#define CiFreePool(Size)	ExFreePoolWithTag((Size), NTOS_CC_TAG)

struct _CC_VIEW;
struct _QUEUED_CALLBACK;

/*
 * An L1 view table describes an aligned virtual memory area with
 * PAGE_SIZE/sizeof(PVOID) views. Each view may belong to different file
 * objects. An L2 view table describes an aligned virtual memory area
 * with PAGE_SIZE/sizeof(PVOID) view tables. 32-bit architectures only
 * have L1 view tables. 64-bit architectures have both.
 */
typedef struct _CC_VIEW_TABLE {
    union {
	struct _CC_VIEW_TABLE *Parent; /* For lower-level view tables. */
	struct _CC_VIEW_TABLE *Next;   /* For top-level view tables. */
    };
    ULONG_PTR MappedAddress; /* Lowest bit set == L2. Lowest bit cleared == L1. */
    union {
	struct _CC_VIEW **Views; /* For L1 view tables */
	struct _CC_VIEW_TABLE **ViewTables; /* For L2 view tables */
    };
    MWORD Bitmap[VIEW_TABLE_BITMAP_SIZE]; /* Bitmap of allocation status. For L2 view
					   * tables, a set bit means the corresponding L1
					   * view table is fully used. */
} CC_VIEW_TABLE, *PCC_VIEW_TABLE;

FORCEINLINE BOOLEAN CiViewTableIsL2(IN PCC_VIEW_TABLE Table)
{
    assert(Table);
    return Table->MappedAddress & 1;
}

#ifdef _WIN64
FORCEINLINE VOID CiViewTableSetL2(IN PCC_VIEW_TABLE Table)
{
    Table->MappedAddress |= 1;
}
#endif

FORCEINLINE ULONG64 CiViewTableVirtualSize(IN PCC_VIEW_TABLE Table)
{
    ULONG64 L1ViewTableVirtualSize = VIEWS_PER_TABLE * VIEW_SIZE;
    ULONG64 L2ViewTableVirtualSize = VIEWS_PER_TABLE * L1ViewTableVirtualSize;
    return CiViewTableIsL2(Table) ? L2ViewTableVirtualSize : L1ViewTableVirtualSize;
}

FORCEINLINE ULONG64 CiViewTableAddressZeroBits(IN PCC_VIEW_TABLE Table)
{
    ULONG64 L1ViewTableZeroBits = VIEW_TABLE_ADDRESS_BITS + VIEW_LOG2SIZE;
    ULONG64 L2ViewTableZeroBits = VIEW_TABLE_ADDRESS_BITS + L1ViewTableZeroBits;
    return CiViewTableIsL2(Table) ? L2ViewTableZeroBits : L1ViewTableZeroBits;
}

FORCEINLINE VOID CiViewTableSetMappedAddress(IN PCC_VIEW_TABLE Table,
					     IN MWORD MappedAddress)
{
    assert(!(MappedAddress & 1));
    assert(IS_ALIGNED_BY(MappedAddress, CiViewTableVirtualSize(Table)));
    Table->MappedAddress |= MappedAddress;
}

FORCEINLINE MWORD CiViewTableGetMappedAddress(IN PCC_VIEW_TABLE Table)
{
    MWORD MappedAddress = Table->MappedAddress & ~1ULL;
    assert(IS_ALIGNED_BY(MappedAddress, CiViewTableVirtualSize(Table)));
    return MappedAddress;
}

/*
 * The cache mapping for a given file control block.
 */
typedef struct _CC_CACHE_MAP {
    PIO_FILE_CONTROL_BLOCK Fcb;
    struct _CC_CACHE_SPACE *CacheSpace;
    AVL_TREE ViewTree;		/* Tree of CC_VIEW.Node */
    union {
	struct {
	    LIST_ENTRY Link; /* List link for Fcb->PrivateCacheMaps. */
	} PrivateMap;
	struct {
	    ULONG Persistent : 1; /* TRUE if all pages in the shared map
				   * are always pinned in memory. */
	} SharedMap;
    };
} CC_CACHE_MAP, *PCC_CACHE_MAP;

/*
 * A cache space is the collection of the view tables in either the NT executive
 * address space or a driver address space.
 */
typedef struct _CC_CACHE_SPACE {
    PCC_VIEW_TABLE ViewTable;	/* For 32-bit arch, this is the first L1 view table.
				 * For 64-bit arch, this is the first L2 view table. */
    PVIRT_ADDR_SPACE AddrSpace;	/* Address space that this cache space belongs to. */
} CC_CACHE_SPACE, *PCC_CACHE_SPACE;

/*
 * This structure records the mapping from the file offset of a file system
 * file object to the file offset of the underlying volume object.
 */
typedef struct _FILE_OFFSET_MAPPING {
    AVL_NODE Node; /* Key is the starting file offset of the file region of the FS file
		    * object with respect to the starting file offset of the view. */
    ULONG64 VolumeFileOffset; /* Starting offset of the corresponding volume file region. */
    union {
	struct _QUEUED_CALLBACK *QueuedCallback;
	struct _CC_VIEW *View;
    };
    ULONG Length; /* Length of the file region. Cluster size aligned. */
} FILE_OFFSET_MAPPING, *PFILE_OFFSET_MAPPING;

#define AVL_NODE_TO_FILE_OFFSET_MAPPING(p)				\
    ((p) ? CONTAINING_RECORD(p, FILE_OFFSET_MAPPING, Node) : NULL)

/*
 * A view is an area of the virtual memory space that spans 64 pages (256KB
 * on architectures with 4K pages) that maps a (64*PAGE_SIZE)-aligned file
 * region of a cached file. The virtual memory area is always aligned by
 * 64 * PAGE_SIZE. When loading data from the disk we always load the full
 * view, unless the view maps the last region of the file, in which case only
 * the file region up till the end of file is loaded.
 */
typedef struct _CC_VIEW {
    AVL_NODE Node; /* Key is the starting file offset of this view. */
    ULONG64 DirtyMap;	/* Bitmap of the dirty status of each page. */
    MWORD MappedAddress; /* This is in the address space of the cache map */
    PCC_CACHE_MAP CacheMap; /* Cache map that this view belongs to. */
    AVL_TREE FileOffsetMapping;	/* AVL tree of FILE_OFFSET_MAPPING. This is
				 * unused if the view is for the volume file. */
    PPENDING_IRP PendingIrp;  /* Queued READ request for this view. */
    LIST_ENTRY QueuedCallbacks;	/* List of QUEUED_CALLBACKs for this view. */
    BOOLEAN Loaded; /* TRUE if file data have been loaded from disk. */
} CC_VIEW, *PCC_VIEW;

#define AVL_NODE_TO_VIEW(p)	((p) ? CONTAINING_RECORD(p, CC_VIEW, Node) : NULL)

#define LoopOverView(View, CacheMap)					\
    for (PCC_VIEW View = AVL_NODE_TO_VIEW(AvlGetFirstNode(&CacheMap->ViewTree)); \
	 View != NULL; View = AVL_NODE_TO_VIEW(AvlGetNextNode(&View->Node)))

static CC_CACHE_SPACE CiNtosCacheSpace;

static NTSTATUS CiInitializeCacheSpace(IN PIO_DRIVER_OBJECT DriverObject,
				       OUT PCC_CACHE_SPACE *pCacheSpace)
{
    assert(DriverObject);
    assert(pCacheSpace);
    PCC_CACHE_SPACE CacheSpace = CiAllocatePool(sizeof(CC_CACHE_SPACE));
    if (!CacheSpace) {
	return STATUS_NO_MEMORY;
    }
    assert(DriverObject->DriverProcess);
    CacheSpace->AddrSpace = &DriverObject->DriverProcess->VSpace;
    *pCacheSpace = CacheSpace;
    return STATUS_SUCCESS;
}

NTSTATUS CcInitializeCacheManager()
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    CiNtosCacheSpace.AddrSpace = &MiNtosVaddrSpace;
    return STATUS_SUCCESS;
}

/*
 * ROUTINE DESCRIPTION:
 *     Initializes caching for a file object. If DriverObject is NULL,
 *     this routine will initialize the shared cache map of the file.
 *     Otherwise, the private cache map belonging to the driver object
 *     is initialized. On success, the initialized cache map is returned.
 *
 * ARGUMENTS:
 *     Fcb          - File control block for the file object.
 *     DriverObject - Driver object to enable caching for.
 *     pCacheMap    - If not NULL, will contain the cache map that was
 *                    initialized.
 *
 * RETURNS:
 *     STATUS_SUCCESS if caching is successfully enabled. Error status if
 *     an error has occurred.
 */
NTSTATUS CcInitializeCacheMap(IN PIO_FILE_CONTROL_BLOCK Fcb,
			      IN OPTIONAL PIO_DRIVER_OBJECT DriverObject,
			      OUT OPTIONAL PCC_CACHE_MAP *pCacheMap)
{
    assert(Fcb);
    PCC_CACHE_MAP CacheMap = NULL;
    if (!DriverObject) {
	CacheMap = Fcb->SharedCacheMap;
    } else {
	if (!DriverObject->CacheSpace) {
	    PCC_CACHE_SPACE CacheSpace = NULL;
	    NTSTATUS Status = CiInitializeCacheSpace(DriverObject, &CacheSpace);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	    assert(CacheSpace);
	    DriverObject->CacheSpace = CacheSpace;
	    goto alloc;
	}
	LoopOverList(Map, &Fcb->PrivateCacheMaps, CC_CACHE_MAP, PrivateMap.Link) {
	    assert(Map->CacheSpace);
	    if (Map->CacheSpace == DriverObject->CacheSpace) {
		CacheMap = Map;
		break;
	    }
	}
    }
    if (CacheMap) {
	if (pCacheMap) {
	    *pCacheMap = CacheMap;
	}
	return STATUS_SUCCESS;
    }

alloc:
    CacheMap = CiAllocatePool(sizeof(CC_CACHE_MAP));
    if (!CacheMap) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    CacheMap->Fcb = Fcb;
    AvlInitializeTree(&CacheMap->ViewTree);
    if (!DriverObject) {
	CacheMap->CacheSpace = &CiNtosCacheSpace;
	Fcb->SharedCacheMap = CacheMap;
	/* For device-less files, the share cache map is always persistent. */
	CacheMap->SharedMap.Persistent = !Fcb->Vcb;
    } else {
	assert(DriverObject->CacheSpace);
	CacheMap->CacheSpace = DriverObject->CacheSpace;
	InsertHeadList(&Fcb->PrivateCacheMaps, &CacheMap->PrivateMap.Link);
    }
    if (pCacheMap) {
	*pCacheMap = CacheMap;
    }
    return STATUS_SUCCESS;
}

VOID CcUninitializeCacheMap(IN PIO_FILE_CONTROL_BLOCK Fcb)
{
    /* TODO */
}

VOID CcSetFileSize(IN PIO_FILE_CONTROL_BLOCK Fcb,
		   IN ULONG64 FileSize)
{
    assert(Fcb);
    assert(FileSize);
    assert(!Fcb->FileSize);
    Fcb->FileSize = FileSize;
    /* TODO: Size changes */
}

static PCC_VIEW_TABLE CiAllocateViewTable()
{
    PCC_VIEW_TABLE Table = CiAllocatePool(sizeof(CC_VIEW_TABLE));
    if (!Table) {
	return NULL;
    }
    Table->Views = (PCC_VIEW *)CiAllocatePool(PAGE_SIZE);
    if (!Table->Views) {
	CiFreePool(Table);
	return NULL;
    }
    return Table;
}

static NTSTATUS CiMapViewTable(IN PCC_CACHE_SPACE CacheSpace,
			       IN PCC_VIEW_TABLE Table)
{
#ifdef _WIN64
    CiViewTableSetL2(Table);
#endif
    MWORD StartAddr = (CacheSpace == &CiNtosCacheSpace) ? EX_DYN_VSPACE_START : 0;
    MWORD EndAddr = (CacheSpace == &CiNtosCacheSpace) ? EX_DYN_VSPACE_END : USER_ADDRESS_END;
    ULONG64 VirtualSize = CiViewTableVirtualSize(Table);
    PMMVAD Vad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(CacheSpace->AddrSpace, StartAddr, EndAddr,
				     VirtualSize, CiViewTableAddressZeroBits(Table), 0,
				     MEM_RESERVE_CACHE_MAP, &Vad));
    CiViewTableSetMappedAddress(Table, Vad->AvlNode.Key);
    return STATUS_SUCCESS;
}

static NTSTATUS CiAllocateView(IN PCC_CACHE_SPACE CacheSpace,
			       OUT PCC_VIEW *pView)
{
    assert(CacheSpace);
    assert(pView);
    PCC_VIEW View = CiAllocatePool(sizeof(CC_VIEW));
    if (!View) {
	return STATUS_NO_MEMORY;
    }

    /* Find an empty slot in the view tables to insert the view into.
     * Note 64-bit arch has two levels of view tables */
    PCC_VIEW_TABLE Table = CacheSpace->ViewTable;
    LONG Position = -1;
    while (Table) {
#ifdef _WIN64
	assert(CiViewTableIsL2(Table));
#endif
	Position = GetFirstZeroBit(Table->Bitmap, VIEWS_PER_TABLE);
	if (Position >= 0) {
	    break;
	}
	Table = Table->Next;
    }
    if (Position < 0) {
	Table = CiAllocateViewTable();
	if (!Table) {
	    CiFreePool(View);
	    return STATUS_NO_MEMORY;
	}
	RET_ERR_EX(CiMapViewTable(CacheSpace, Table),
		   CiFreePool(View));
	Table->Next = CacheSpace->ViewTable;
	CacheSpace->ViewTable = Table;
	Position = 0;
    }

#ifdef _WIN64
    PCC_VIEW_TABLE L2Table = Table;
    Table = Table->ViewTables[Position];
    if (Table) {
	assert(!CiViewTableIsL2(Table));
	LONG L2Position = Position;
	Position = GetFirstZeroBit(Table->Bitmap, VIEWS_PER_TABLE);
	assert(Position >= 0);
	assert(!GetBit(Table->Bitmap, Position));
	SetBit(Table->Bitmap, Position);
	if (GetFirstZeroBit(Table->Bitmap, VIEWS_PER_TABLE) < 0) {
	    SetBit(L2Table->Bitmap, L2Position);
	}
	ClearBit(Table->Bitmap, Position);
    } else {
	Table = CiAllocateViewTable();
	if (!Table) {
	    CiFreePool(View);
	    return STATUS_NO_MEMORY;
	}
	Table->Parent = L2Table;
	MWORD L2Address = CiViewTableGetMappedAddress(L2Table);
	CiViewTableSetMappedAddress(Table, L2Address + (MWORD)Position * VIEW_SIZE);
	L2Table->ViewTables[Position] = Table;
	Position = 0;
    }
#endif

    assert(Table);
    assert(Position >= 0);
    assert(!GetBit(Table->Bitmap, Position));
    assert(!Table->Views[Position]);
    SetBit(Table->Bitmap, Position);
    Table->Views[Position] = View;
    MWORD MappedAddress = CiViewTableGetMappedAddress(Table);
    View->MappedAddress = MappedAddress + (MWORD)Position * VIEW_SIZE;
    *pView = View;
    return STATUS_SUCCESS;
}

static NTSTATUS CiGetView(IN PIO_FILE_CONTROL_BLOCK Fcb,
			  IN PIO_DRIVER_OBJECT DriverObject,
			  IN ULONG64 FileOffset,
			  IN BOOLEAN Create,
			  OUT PCC_VIEW *pView)
{
    assert(Fcb);
    PCC_CACHE_MAP CacheMap = NULL;
    if (DriverObject) {
	assert(DriverObject->CacheSpace);
	LoopOverList(Map, &Fcb->PrivateCacheMaps, CC_CACHE_MAP, PrivateMap.Link) {
	    assert(Map->CacheSpace);
	    if (Map->CacheSpace == DriverObject->CacheSpace) {
		CacheMap = Map;
		break;
	    }
	}
    } else {
	assert(Fcb->SharedCacheMap);
	assert(Fcb->SharedCacheMap->Fcb == Fcb);
	CacheMap = Fcb->SharedCacheMap;
    }
    if (!CacheMap) {
	assert(FALSE);
	return STATUS_NONE_MAPPED;
    }
    ULONG64 AlignedOffset = VIEW_ALIGN64(FileOffset);
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(&CacheMap->ViewTree, AlignedOffset);
    PAVL_NODE Node = (Parent && Parent->Key == AlignedOffset) ? Parent : NULL;
    if (!Node && Create) {
	PCC_VIEW View = NULL;
	RET_ERR(CiAllocateView(CacheMap->CacheSpace, &View));
	assert(View);
	Node = &View->Node;
	View->Node.Key = AlignedOffset;
	View->CacheMap = CacheMap;
	AvlInitializeTree(&View->FileOffsetMapping);
	AvlTreeInsertNode(&CacheMap->ViewTree, Parent, Node);
	InitializeListHead(&View->QueuedCallbacks);
    }
    *pView = AVL_NODE_TO_VIEW(Node);
    return Node ? STATUS_SUCCESS : STATUS_NONE_MAPPED;
}

typedef struct _PIN_DATA_CALLBACK_CONTEXT {
    ULONG64 PinnedLength;
    KEVENT Event;
    NTSTATUS Status;
} PIN_DATA_CALLBACK_CONTEXT, *PPIN_DATA_CALLBACK_CONTEXT;

static VOID CiPinDataCallback(IN PIO_FILE_CONTROL_BLOCK Fcb,
			      IN ULONG64 FileOffset,
			      IN ULONG64 Length,
			      IN NTSTATUS Status,
			      IN ULONG64 PinnedLength,
			      IN OUT PVOID Ctx)
{
    PPIN_DATA_CALLBACK_CONTEXT Context = Ctx;
    Context->PinnedLength = PinnedLength;
    Context->Status = Status;
    KeSetEvent(&Context->Event);
}

/*
 * ROUTINE DESCRIPTION:
 *     Populate the shared cache map for the given file region of the
 *     file object. Once populated, the data stay in the cache until
 *     CcUnpinData is called.
 *
 * ARGUMENTS:
 *     State          - Asynchronous routine state.
 *     Thread         - Thread context for the asynchronous routine.
 *     Fcb            - File control block for the file object.
 *     FileOffset     - Starting offset of the file region.
 *     Length         - Length of the file region.
 *
 * RETURNS:
 *     STATUS_SUCCESS if all data have been successfully loaded. Error
 *     status if an error has occurred.
 */
NTSTATUS CcPinData(IN ASYNC_STATE State,
		   IN PTHREAD Thread,
		   IN PIO_FILE_CONTROL_BLOCK Fcb,
		   IN ULONG64 FileOffset,
		   IN ULONG64 Length)
{
    ASYNC_BEGIN(State, Locals, {
	    PPIN_DATA_CALLBACK_CONTEXT Context;
	});

    Locals.Context = CiAllocatePool(sizeof(PIN_DATA_CALLBACK_CONTEXT));
    if (!Locals.Context) {
	ASYNC_RETURN(State, STATUS_INSUFFICIENT_RESOURCES);
    }
    KeInitializeEvent(&Locals.Context->Event, NotificationEvent);
    CcPinDataEx(Fcb, FileOffset, Length, CiPinDataCallback, Locals.Context);

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.Context->Event.Header, FALSE, NULL);

    NTSTATUS Status = Locals.Context->Status;
    KeUninitializeEvent(&Locals.Context->Event);
    CiFreePool(Locals.Context);
    ASYNC_END(State, Status);
}

typedef struct _PIN_DATA_EX_CALLBACK {
    ULONG64 OriginalFileOffset;
    ULONG64 OriginalLength;
    ULONG TotalIrpCount;      /* Callback will be called when */
    ULONG CompletedIrpCount;  /* TotalIrpCount == CompletedIrpCount */
    PCC_PIN_DATA_CALLBACK Callback;
    PVOID Context;
    NTSTATUS Status;
} PIN_DATA_EX_CALLBACK, *PPIN_DATA_EX_CALLBACK;

typedef struct _QUEUED_CALLBACK {
    PVOID CallbackInfo;
    PCC_VIEW View;
    LIST_ENTRY Link;		/* List link for View->QueuedCallbacks */
    ULONG MappedViewSize;
    ULONG MappedLength;	   /* Not used in the case of volume files. */
    NTSTATUS Status;	   /* Not used in the case of volume files. */
} QUEUED_CALLBACK, *PQUEUED_CALLBACK;

static VOID CiCompleteQueuedCallbacks(IN PCC_VIEW View,
				      IN NTSTATUS Status)
{
    LoopOverList(QueuedCallback, &View->QueuedCallbacks, QUEUED_CALLBACK, Link) {
	PPIN_DATA_EX_CALLBACK CallbackInfo = QueuedCallback->CallbackInfo;
	if (!NT_SUCCESS(Status)) {
	    CallbackInfo->Status = Status;
	}
	CallbackInfo->CompletedIrpCount++;
	if (CallbackInfo->CompletedIrpCount == CallbackInfo->TotalIrpCount) {
	    PIO_FILE_CONTROL_BLOCK Fcb = QueuedCallback->View->CacheMap->Fcb;
	    ULONG64 PinnedLength = NT_SUCCESS(CallbackInfo->Status) ?
		CallbackInfo->OriginalLength : 0;
	    CallbackInfo->Callback(Fcb, CallbackInfo->OriginalFileOffset,
				   CallbackInfo->OriginalLength, CallbackInfo->Status,
				   PinnedLength, CallbackInfo->Context);
	    CiFreePool(CallbackInfo);
	}
	RemoveEntryList(&QueuedCallback->Link);
	CiFreePool(QueuedCallback);
    }
}

static VOID CiFileOffsetMappingCallback(IN PIO_FILE_CONTROL_BLOCK VolumeFcb,
					IN ULONG64 VolumeFileOffset,
					IN ULONG64 Length,
					IN NTSTATUS Status,
					IN ULONG64 PinnedLength,
					IN OUT PVOID Context)
{
    PFILE_OFFSET_MAPPING Mapping = Context;
    PQUEUED_CALLBACK QueuedCallback = Mapping->QueuedCallback;
    PCC_VIEW View = QueuedCallback->View;
    PIO_FILE_CONTROL_BLOCK Fcb = View->CacheMap->Fcb;
    assert(Fcb != Fcb->Vcb->VolumeFcb);
    assert(VolumeFcb == Fcb->Vcb->VolumeFcb);
    assert(VolumeFileOffset == Mapping->VolumeFileOffset);
    assert(Length == Mapping->Length);
    assert(View->MappedAddress);

    if (!NT_SUCCESS(QueuedCallback->Status)) {
	Status = QueuedCallback->Status;
    }
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    assert(PinnedLength == Length);

    ULONG ViewOffset = Mapping->Node.Key;
    assert(ViewOffset < VIEW_SIZE);
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(&View->FileOffsetMapping,
					       ViewOffset);
    if (Parent && Parent->Key == ViewOffset) {
	/* This can happen if the FS driver sent multiple IRPs with
	 * the same file offset. */
	assert(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto out;
    }

    /* For the unaligned head and tail of the view region we ignore the
     * STATUS_ALREADY_COMMITTED error since another call of this routine
     * may have already committed the pages there. */
    ULONG AlignedOffset = PAGE_ALIGN_UP(ViewOffset);
    if (ViewOffset < AlignedOffset) {
	Status = MmCommitOwnedMemory(View->MappedAddress + PAGE_ALIGN(ViewOffset),
				     PAGE_SIZE, MM_RIGHTS_RW, FALSE);
	if (!NT_SUCCESS(Status) && Status != STATUS_ALREADY_COMMITTED) {
	    goto out;
	}
	ULONG MappedLength = 0;
	PVOID Buffer = NULL;
	Status = CcMapData(VolumeFcb, VolumeFileOffset,
			   AlignedOffset - ViewOffset, &MappedLength, &Buffer);
	if (!NT_SUCCESS(Status) || MappedLength != (AlignedOffset - ViewOffset)) {
	    assert(FALSE);
	    goto out;
	}
	assert(Buffer);
	RtlCopyMemory((PVOID)(View->MappedAddress + ViewOffset),
		      Buffer, MappedLength);
    }
    ULONG AlignedEndOffset = PAGE_ALIGN(ViewOffset + Length);
    assert(AlignedOffset <= AlignedEndOffset);
    if (AlignedOffset < AlignedEndOffset) {
	ULONG AlignedLength = AlignedEndOffset - AlignedOffset;
	if (IS_PAGE_ALIGNED(ViewOffset - VolumeFileOffset)) {
	    /* If the difference between the view offset and the volume file offset is
	     * page-aligned, we can share the pages with the volume cache map. */
	    ULONG MappedLength = 0;
	    while (MappedLength < AlignedLength) {
		MWORD MappedAddress = View->MappedAddress + ViewOffset + MappedLength;
		ULONG WindowSize = 0;
		PVOID Buffer = NULL;
		IF_ERR_GOTO(out, Status, CcMapData(VolumeFcb, VolumeFileOffset + MappedLength,
						   AlignedLength - MappedLength,
						   &WindowSize, &Buffer));
		assert(WindowSize);
		assert(IS_PAGE_ALIGNED(WindowSize));
		assert(Buffer);
		IF_ERR_GOTO(out, Status,
			    MmMapMirroredMemory(CiNtosCacheSpace.AddrSpace, (MWORD)Buffer,
						CiNtosCacheSpace.AddrSpace, MappedAddress,
						WindowSize, MM_RIGHTS_RW));
		MappedLength += WindowSize;
	    }
	    assert(MappedLength == AlignedLength);
	} else {
	    /* Otherwise, we need to create private pages. */
	    IF_ERR_GOTO(out, Status,
			MmCommitOwnedMemory(View->MappedAddress + AlignedOffset,
					    AlignedLength, MM_RIGHTS_RW, FALSE));
	}
    }
    if (AlignedEndOffset < ViewOffset + Length) {
	Status = MmCommitOwnedMemory(View->MappedAddress + AlignedEndOffset,
				     PAGE_SIZE, MM_RIGHTS_RW, FALSE);
	if (!NT_SUCCESS(Status) && Status != STATUS_ALREADY_COMMITTED) {
	    goto out;
	}
    }

    /* Skip the unaligned head which we already copied above. */
    VolumeFileOffset += AlignedOffset - ViewOffset;
    Length -= AlignedOffset - ViewOffset;

    /* Skip the shared pages mapped above so the code below won't do unneeded copy. */
    if (IS_PAGE_ALIGNED(ViewOffset - VolumeFileOffset)) {
	Length -= AlignedEndOffset - AlignedOffset;
	VolumeFileOffset += AlignedEndOffset - AlignedOffset;
	ViewOffset = AlignedEndOffset;
    }

    ULONG LengthCopied = 0;
    while (LengthCopied < Length) {
	ULONG MappedLength = 0;
	PVOID Buffer = NULL;
	Status = CcMapData(VolumeFcb, VolumeFileOffset + LengthCopied,
			   Length - LengthCopied, &MappedLength, &Buffer);
	if (!NT_SUCCESS(Status)) {
	    assert(FALSE);
	    goto out;
	}
	assert(Buffer);
	assert(ViewOffset + LengthCopied < VIEW_SIZE);
	RtlCopyMemory((PVOID)(View->MappedAddress + ViewOffset + LengthCopied),
		      Buffer, MappedLength);
	LengthCopied += MappedLength;
    }

    AvlTreeInsertNode(&View->FileOffsetMapping, Parent, &Mapping->Node);
    Mapping->View = View;

out:
    QueuedCallback->MappedLength += Mapping->Length;
    if (!NT_SUCCESS(Status)) {
	QueuedCallback->Status = Status;
	CiFreePool(Mapping);
	/* Free all the FILE_OFFSET_MAPPINGs of the view */
	PAVL_NODE Node;
	while ((Node = AvlGetFirstNode(&View->FileOffsetMapping)) != NULL) {
	    AvlTreeRemoveNode(&View->FileOffsetMapping, Node);
	    CiFreePool(AVL_NODE_TO_FILE_OFFSET_MAPPING(Node));
	}
	/* Uncommit all pages in this view */
	MmUncommitVirtualMemory(View->MappedAddress, VIEW_SIZE);
    }
    if (QueuedCallback->MappedLength >= QueuedCallback->MappedViewSize) {
	assert(QueuedCallback->MappedLength ==
	       ALIGN_UP_BY(QueuedCallback->MappedViewSize, Fcb->Vcb->ClusterSize));
	if (NT_SUCCESS(Status)) {
	    assert(NT_SUCCESS(QueuedCallback->Status));
	    View->Loaded = TRUE;
	}
	CiCompleteQueuedCallbacks(View, Status);
    }
}

static BOOLEAN CiPagedReadCallback(IN PPENDING_IRP PendingIrp,
				   IN OUT PVOID Context,
				   IN BOOLEAN Completion)
{
    PQUEUED_CALLBACK QueuedCallback = Context;
    PCC_VIEW View = QueuedCallback->View;
    PIO_FILE_CONTROL_BLOCK Fcb = View->CacheMap->Fcb;
    BOOLEAN IsVolume = Fcb == Fcb->Vcb->VolumeFcb;
    NTSTATUS Status = PendingIrp->IoResponseStatus.Status;
    if (IsVolume) {
	if (!Completion) {
	    return TRUE;
	}
	if (NT_SUCCESS(Status)) {
	    View->Loaded = TRUE;
	} else {
	    MmUncommitVirtualMemory(View->MappedAddress, QueuedCallback->MappedViewSize);
	}
	IopCleanupPendingIrp(PendingIrp);
    } else {
	if (Completion) {
	    return FALSE;
	}
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	PIO_REQUEST_PARAMETERS Irp = &PendingIrp->IoPacket->Request;
	if (Irp->MajorFunction != IRP_MJ_READ) {
	    assert(FALSE);
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    goto out;
	}
	ULONG64 ViewOffset = Irp->OutputBuffer;
	ULONG64 VolumeFileOffset = Irp->Read.ByteOffset.QuadPart;
	ULONG Length = Irp->OutputBufferLength;
	/* File offset mapping must be within the same view and aligned
	 * by cluster size. */
	if (ViewOffset >= VIEW_SIZE || Length >= VIEW_SIZE ||
	    !IS_ALIGNED_BY(ViewOffset, Fcb->Vcb->ClusterSize) ||
	    !IS_ALIGNED_BY(Length, Fcb->Vcb->ClusterSize)) {
	    assert(FALSE);
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    goto out;
	}
	PFILE_OFFSET_MAPPING Mapping = CiAllocatePool(sizeof(FILE_OFFSET_MAPPING));
	if (!Mapping) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	Mapping->Node.Key = ViewOffset;
	Mapping->VolumeFileOffset = VolumeFileOffset;
	Mapping->Length = Length;
	Mapping->QueuedCallback = QueuedCallback;
	IoDbgDumpIoPacket(PendingIrp->IoPacket, FALSE);
	CcPinDataEx(Fcb->Vcb->VolumeFcb, VolumeFileOffset, Length,
		    CiFileOffsetMappingCallback, Mapping);
	goto done;
    }

out:
    CiCompleteQueuedCallbacks(View, Status);
done:
    if (!IsVolume) {
	IopCompletePendingIrp(PendingIrp, PendingIrp->IoResponseStatus, NULL, 0);
    }
    View->PendingIrp = NULL;
    return FALSE;
}

/*
 * ROUTINE DESCRIPTION:
 *     Populate the shared cache map for the given file region of the
 *     file object. Once populated, the data stay in the cache until
 *     CcUnpinData is called.
 *
 * ARGUMENTS:
 *     Fcb        - File control block for the file object.
 *     FileOffset - Starting offset of the file region.
 *     Callback   - Callback function to call when IO is completed.
 *     Context    - Context for the callback function.
 *
 * REMAKRS:
 *     Note that for purely in-memory file objects, this function is
 *     synchronous and simply populates the cache pages (with zero)
 *     of the file.
 */
VOID CcPinDataEx(IN PIO_FILE_CONTROL_BLOCK Fcb,
		 IN ULONG64 FileOffset,
		 IN ULONG64 Length,
		 IN PCC_PIN_DATA_CALLBACK Callback,
		 IN OPTIONAL PVOID Context)
{
    assert(Fcb);
    assert(Callback);

    PIO_VOLUME_CONTROL_BLOCK Vcb = Fcb->Vcb;
    NTSTATUS Status;

    /* If the FileSize of the FCB is not set, we skip the end-of-file checks and
     * assume the file is infinitely long. */
    ULONG64 FileSize = Fcb->FileSize ? Fcb->FileSize : ~0ULL;
    if (FileSize <= FileOffset || Length == 0) {
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }
    if (FileOffset + Length > FileSize) {
	Length = FileSize - FileOffset;
    }

    /* Since we are dealing with asynchronous IO and don't have the convenient
     * ASYNC_STATE with which we can simply wait for the IOs to complete, construct
     * a PIN_DATA_EX_CALLBACK structure which packs all the information we need
     * when the IOs are completed. */
    PPIN_DATA_EX_CALLBACK CallbackInfo = CiAllocatePool(sizeof(PIN_DATA_EX_CALLBACK));
    if (!CallbackInfo) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    CallbackInfo->OriginalFileOffset = FileOffset;
    CallbackInfo->OriginalLength = Length;
    /* Align the file region by view size (256KB on x86) */
    ULONG64 AlignedOffset = VIEW_ALIGN64(FileOffset);
    ULONG64 EndOffset = VIEW_ALIGN_UP64(FileOffset + Length);
    CallbackInfo->Callback = Callback;
    CallbackInfo->Context = Context;

    /* Get the view object for each file segment, and queue the READ request if the
     * file segment is not loaded into memory. */
    ULONG64 ProcessedLength = 0;
    while (ProcessedLength < EndOffset - AlignedOffset) {
	ULONG64 CurrentOffset = AlignedOffset + ProcessedLength;
	ProcessedLength += VIEW_SIZE;
	assert(CurrentOffset < FileSize);
	PCC_VIEW View = NULL;
	PQUEUED_CALLBACK QueuedCallback = NULL;
	IF_ERR_GOTO(fail, Status, CiGetView(Fcb, NULL, CurrentOffset, TRUE, &View));
	/* We always map the entire view except for the last view of a file, in
	 * which case the view size is adjusted to the end of the file. */
	ULONG MappedViewSize = VIEW_SIZE;
	if (CurrentOffset + VIEW_SIZE > FileSize) {
	    MappedViewSize = FileSize - CurrentOffset;
	}
	/* If the view is mapped, simply continue. */
	if (View->Loaded) {
	    continue;
	}
	/* For the volume device or purely in-memory file objects, if the view is not
	 * mapped, we need to allocate private pages for the view. */
	BOOLEAN IsVolume = Vcb && (Fcb == Vcb->VolumeFcb);
	if (!Vcb || IsVolume) {
	    IF_ERR_GOTO(fail, Status,
			MmCommitOwnedMemory(View->MappedAddress,
					    PAGE_ALIGN_UP(MappedViewSize),
					    MM_RIGHTS_RW, FALSE));
	}
	/* For purely in-memory file objects, we don't need to send IO requests. */
	if (!Vcb) {
	    View->Loaded = TRUE;
	    assert(!CallbackInfo->TotalIrpCount);
	    assert(!CallbackInfo->CompletedIrpCount);
	    continue;
	}
	/* Allocate a QUEUED_CALLBACK so we can queue the callback on the IRP
	 * in order for it to be called later when the IO is completed. */
	QueuedCallback = CiAllocatePool(sizeof(QUEUED_CALLBACK));
	if (!QueuedCallback) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto fail;
	}
	QueuedCallback->CallbackInfo = CallbackInfo;
	QueuedCallback->View = View;
	QueuedCallback->MappedViewSize = MappedViewSize;
	if (!View->PendingIrp) {
	    PIO_DEVICE_OBJECT DevObj = IsVolume ? Vcb->StorageDevice : Vcb->VolumeDevice;
	    if (!DevObj) {
		/* This should not happen since clients should not be able to make IO
		 * requests to FS file objects before the volume is mounted. */
		assert(FALSE);
		Status = STATUS_INTERNAL_ERROR;
		goto fail;
	    }
	    assert(IsVolume || Fcb->MasterFileObject);
	    ULONG ReadLength = (CurrentOffset + VIEW_SIZE > FileSize)
		? (FileSize - CurrentOffset) : VIEW_SIZE;
	    IO_REQUEST_PARAMETERS Irp = {
		.Flags = IOP_IRP_COMPLETION_CALLBACK,
		.Device.Object = DevObj,
		.File.Object = IsVolume ? NULL : Fcb->MasterFileObject,
		.MajorFunction = IRP_MJ_READ,
		.OutputBuffer = IsVolume ? (MWORD)View->MappedAddress : 0,
		.OutputBufferLength = ReadLength,
		.Read.ByteOffset.QuadPart = CurrentOffset,
		.ServerPrivate = {
		    .Callback = CiPagedReadCallback,
		    .Context = QueuedCallback
		}
	    };
	    if (!IsVolume) {
		Irp.Flags |= IOP_IRP_INTERCEPTION_CALLBACK;
	    }
	    IF_ERR_GOTO(fail, Status, IopCallDriver(IOP_PAGING_IO_REQUESTOR,
						    &Irp, &View->PendingIrp));
	}
	InsertTailList(&View->QueuedCallbacks, &QueuedCallback->Link);
	CallbackInfo->TotalIrpCount++;
	continue;
    fail:
	CallbackInfo->Status = Status;
	MmUncommitVirtualMemory(View->MappedAddress, VIEW_SIZE);
	if (QueuedCallback) {
	    CiFreePool(QueuedCallback);
	}
	break;
    }

    assert(Vcb || !CallbackInfo->TotalIrpCount);
    if (!CallbackInfo->TotalIrpCount) {
	Status = CallbackInfo->Status;
	CiFreePool(CallbackInfo);
	goto out;
    }
    return;

out:
    Callback(Fcb, FileOffset, Length, Status,
	     NT_SUCCESS(Status) ? Length : 0, Context);
}

VOID CcUnpinData(IN PIO_FILE_CONTROL_BLOCK Fcb,
		 IN ULONG64 FileOffset,
		 IN ULONG Length)
{
    /* TODO */
}

VOID CcSetDirtyData(IN PIO_DRIVER_OBJECT DriverObject,
		    IN MWORD ViewAddress,
		    IN ULONG64 DirtyBits)
{
    assert(DriverObject);
    assert(ViewAddress);
    assert(IS_VIEW_ALIGNED(ViewAddress));
    assert(DirtyBits);
    PCC_CACHE_SPACE CacheSpace = DriverObject->CacheSpace;
    if (!CacheSpace) {
	assert(FALSE);
	return;
    }
    PCC_VIEW View = NULL;
    PCC_VIEW_TABLE ViewTable = CacheSpace->ViewTable;
    while (ViewTable) {
	MWORD ViewTableAddress = CiViewTableGetMappedAddress(ViewTable);
	MWORD AlignedAddress = ALIGN_DOWN_BY(ViewAddress,
					     CiViewTableVirtualSize(ViewTable));
	if (AlignedAddress == ViewTableAddress) {
	    ULONG Idx = (ViewAddress >> VIEW_LOG2SIZE) & ((1UL << VIEW_TABLE_ADDRESS_BITS) - 1);
#ifdef _WIN64
	    ULONG L2Idx = (ViewAddress >> (VIEW_LOG2SIZE + VIEW_TABLE_ADDRESS_BITS)) &
		((1UL << VIEW_TABLE_ADDRESS_BITS) - 1);
	    ViewTable = ViewTable->ViewTables[L2Idx];
	    if (!ViewTable) {
		break;
	    }
#endif
	    View = ViewTable->Views[Idx];
	    break;
	}
	ViewTable = ViewTable->Next;
    }
    if (!View) {
	assert(FALSE);
	return;
    }
    View->DirtyMap |= DirtyBits;
}

static VOID CiFlushDirtyDataToVolume(IN PIO_FILE_CONTROL_BLOCK Fcb)
{
    PCC_CACHE_MAP CacheMap = Fcb->SharedCacheMap;
    assert(CacheMap);
    assert(CacheMap->Fcb);
    assert(CacheMap->Fcb == Fcb);
    assert(Fcb->Vcb);
    PIO_FILE_CONTROL_BLOCK VolumeFcb = Fcb->Vcb->VolumeFcb;
    assert(VolumeFcb);
    LoopOverView(View, CacheMap) {
	for (ULONG i = 0; i < PAGES_IN_VIEW; i++) {
	    if (!GetBit64(View->DirtyMap, i)) {
		continue;
	    }
	    ClearBit64(View->DirtyMap, i);
	    ULONG ViewOffset = i * PAGE_SIZE;
	    while (ViewOffset < min((i+1)*PAGE_SIZE, Fcb->FileSize-View->Node.Key)) {
		PAVL_NODE Node = AvlTreeFindNodeOrPrev(&View->FileOffsetMapping,
						       ViewOffset);
		assert(Node);
		assert(Node->Key <= ViewOffset);
		PFILE_OFFSET_MAPPING Mapping = AVL_NODE_TO_FILE_OFFSET_MAPPING(Node);
		ULONG64 FileOffset = Mapping->VolumeFileOffset + ViewOffset - Node->Key;
		assert(Node->Key + Mapping->Length >= ViewOffset);
		ULONG NextOffset = min(PAGE_ALIGN(ViewOffset + PAGE_SIZE),
				       Node->Key + Mapping->Length);
		ULONG Length = NextOffset - ViewOffset;
		assert(Length);
		if (IS_PAGE_ALIGNED(FileOffset) && IS_PAGE_ALIGNED(Node->Key) &&
		    Length == PAGE_SIZE) {
		    PCC_VIEW VolumeView = NULL;
		    CiGetView(VolumeFcb, NULL, VIEW_ALIGN64(FileOffset), FALSE, &VolumeView);
		    if (VolumeView) {
			SetBit64(View->DirtyMap,
				 (FileOffset - VIEW_ALIGN64(FileOffset)) >> PAGE_LOG2SIZE);
		    } else {
			assert(FALSE);
		    }
		} else {
		    CcCopyWrite(VolumeFcb, FileOffset, Length,
				(PUCHAR)View->MappedAddress + ViewOffset);
		}
		ViewOffset = NextOffset;
	    }
	}
    }
}

/* Propagate the dirty maps of the private cache maps of the given FCB to
 * its shared cache map and clear the private dirty maps. */
static VOID CiFlushPrivateCacheToShared(IN PIO_FILE_CONTROL_BLOCK Fcb)
{
    assert(Fcb);
    LoopOverList(CacheMap, &Fcb->PrivateCacheMaps, CC_CACHE_MAP, PrivateMap.Link) {
	LoopOverView(PrivateView, CacheMap) {
	    PAVL_NODE Node = AvlTreeFindNode(&Fcb->SharedCacheMap->ViewTree,
					     PrivateView->Node.Key);
	    assert(Node);
	    PCC_VIEW SharedView = AVL_NODE_TO_VIEW(Node);
	    SharedView->DirtyMap |= PrivateView->DirtyMap;
	    PrivateView->DirtyMap = 0;
	}
    }
}

typedef struct _FLUSH_CACHE_CALLBACK_INFO {
    ULONG64 TotalIrpCount;	/* Callback will be called when */
    ULONG64 CompletedIrpCount;	/* TotalIrpCount == CompletedIrpCount */
    PIO_DEVICE_OBJECT VolumeDevice;
    PIO_FILE_OBJECT FileObject;
    PCC_CACHE_FLUSHED_CALLBACK Callback;
    PVOID Context;
    IO_STATUS_BLOCK IoStatus;
} FLUSH_CACHE_CALLBACK_INFO, *PFLUSH_CACHE_CALLBACK_INFO;

static BOOLEAN CiPagedWriteCallback(IN PPENDING_IRP PendingIrp,
				    IN OUT PVOID Context,
				    IN BOOLEAN Completion)
{
    assert(PendingIrp);
    assert(Context);
    assert(Completion);
    NTSTATUS Status = PendingIrp->IoResponseStatus.Status;
    PCC_VIEW View = ((PQUEUED_CALLBACK)Context)->View;
    assert(View);
    LoopOverList(QueuedCallback, &View->QueuedCallbacks, QUEUED_CALLBACK, Link) {
	PFLUSH_CACHE_CALLBACK_INFO CallbackInfo = QueuedCallback->CallbackInfo;
	if (!NT_SUCCESS(Status)) {
	    CallbackInfo->IoStatus = PendingIrp->IoResponseStatus;
	}
	CallbackInfo->CompletedIrpCount++;
	if (CallbackInfo->CompletedIrpCount == CallbackInfo->TotalIrpCount) {
	    CallbackInfo->Callback(CallbackInfo->VolumeDevice, CallbackInfo->FileObject,
				   CallbackInfo->IoStatus, CallbackInfo->Context);
	    CiFreePool(CallbackInfo);
	}
	RemoveEntryList(&QueuedCallback->Link);
	CiFreePool(QueuedCallback);
    }
    IopCleanupPendingIrp(PendingIrp);
    View->PendingIrp = NULL;
    return FALSE;
}

VOID CcFlushCache(IN PIO_DEVICE_OBJECT VolumeDevice,
		  IN PIO_FILE_OBJECT FileObject,
		  IN PCC_CACHE_FLUSHED_CALLBACK Callback,
		  IN OUT PVOID Context)
{
    assert(FileObject);
    PIO_FILE_CONTROL_BLOCK Fcb = FileObject->Fcb;
    assert(Fcb);
    /* If the file object has caching enabled, propagate its dirty maps to the volume FCB. */
    if (Fcb->SharedCacheMap) {
	CiFlushPrivateCacheToShared(Fcb);
	CiFlushDirtyDataToVolume(Fcb);
    }
    PIO_FILE_CONTROL_BLOCK VolumeFcb = Fcb->Vcb->VolumeFcb;
    assert(VolumeFcb);
    CiFlushPrivateCacheToShared(VolumeFcb);
    /* At this point all dirty bits should have been migrated to the volume FCB shared map. */
    if (Fcb != VolumeFcb && Fcb->SharedCacheMap) {
	LoopOverView(View, Fcb->SharedCacheMap) {
	    assert(!View->DirtyMap);
	}
    }
    LoopOverList(CacheMap, &Fcb->PrivateCacheMaps, CC_CACHE_MAP, PrivateMap.Link) {
	LoopOverView(View, CacheMap) {
	    assert(!View->DirtyMap);
	}
    }
    LoopOverList(CacheMap, &VolumeFcb->PrivateCacheMaps, CC_CACHE_MAP, PrivateMap.Link) {
	LoopOverView(View, CacheMap) {
	    assert(!View->DirtyMap);
	}
    }

    NTSTATUS Status = STATUS_NTOS_BUG;
    PFLUSH_CACHE_CALLBACK_INFO CallbackInfo = CiAllocatePool(sizeof(PIN_DATA_EX_CALLBACK));
    if (!CallbackInfo) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    CallbackInfo->VolumeDevice = VolumeDevice;
    CallbackInfo->FileObject = FileObject;
    CallbackInfo->Callback = Callback;
    CallbackInfo->Context = Context;

    /* For each dirty view of the volume fcb, generate a WRITE IRP for the disk. */
    assert(VolumeFcb->SharedCacheMap);
    LoopOverView(View, VolumeFcb->SharedCacheMap) {
	if (!View->DirtyMap) {
	    continue;
	}
	PQUEUED_CALLBACK QueuedCallback = CiAllocatePool(sizeof(QUEUED_CALLBACK));
	if (!QueuedCallback) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto fail;
	}
	ULONG DirtyBitStart = RtlFindLeastSignificantBit(View->DirtyMap);
	assert(DirtyBitStart < 64);
	ULONG DirtyBitEnd = RtlFindMostSignificantBit(View->DirtyMap);
	assert(DirtyBitEnd < 64);
	assert(DirtyBitEnd >= DirtyBitStart);
	ULONG ViewOffset = DirtyBitStart * PAGE_SIZE;
	MWORD DirtyAddress = (MWORD)View->MappedAddress + ViewOffset;
	ULONG WriteLength = (DirtyBitEnd - DirtyBitStart + 1) * PAGE_SIZE;
	QueuedCallback->CallbackInfo = CallbackInfo;
	QueuedCallback->View = View;
	if (!View->PendingIrp) {
	    IO_REQUEST_PARAMETERS Irp = {
		.Flags = IOP_IRP_COMPLETION_CALLBACK,
		.Device.Object = Fcb->Vcb->StorageDevice,
		.File.Object = NULL,
		.MajorFunction = IRP_MJ_WRITE,
		.InputBuffer = DirtyAddress,
		.InputBufferLength = WriteLength,
		.Write.ByteOffset.QuadPart = View->Node.Key + ViewOffset,
		.ServerPrivate = {
		    .Callback = CiPagedWriteCallback,
		    .Context = QueuedCallback
		}
	    };
	    IF_ERR_GOTO(fail, Status, IopCallDriver(IOP_PAGING_IO_REQUESTOR,
						    &Irp, &View->PendingIrp));
	} else {
	    IoDbgDumpIoPacket(View->PendingIrp->IoPacket, FALSE);
	    assert(View->PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	    assert(View->PendingIrp->IoPacket->Request.MajorFunction == IRP_MJ_WRITE);
	}
	InsertTailList(&View->QueuedCallbacks, &QueuedCallback->Link);
	CallbackInfo->TotalIrpCount++;
	continue;
    fail:
	CallbackInfo->IoStatus.Status = Status;
	break;
    }

out:
    if (CallbackInfo && !NT_SUCCESS(CallbackInfo->IoStatus.Status)) {
	Status = CallbackInfo->IoStatus.Status;
    }
    if (!CallbackInfo || !CallbackInfo->TotalIrpCount) {
	IO_STATUS_BLOCK IoStatus = { .Status = Status };
	Callback(VolumeDevice, FileObject, IoStatus, Context);
    }
}

/*
 * ROUTINE DESCRIPTION:
 *     If DriverObject is not NULL, this routine will map the specified
 *     file region from the shared cache map to the private cache map for
 *     the driver process. If DriverObject is NULL, this routine returns
 *     the pointer to the beginning of the file region in the shared cache
 *     map. *MappedLength will be set to the length of the successfully
 *     mapped region. Note the maximum length that will be mapped in one
 *     single call to CcMapDataEx is the view size (256KB on x86). Before
 *     calling this routine, the caller must call CcPinData to populate the
 *     shared cache map for the file region.
 *
 * ARGUMENTS:
 *     DriverObject   - Driver object for the private cache map.
 *     Fcb            - File control block for the file object.
 *     FileOffset     - Starting offset of the file region.
 *     Length         - Length of the file region. File region will
 *                      be truncated to view boundary.
 *     *pMappedLength - Length of the successfully mapped region.
 *     *Buffer        - Mapped buffer in the cache map.
 *                      Note if DriverObject is not NULL, this is a
 *                      pointer within the driver address space.
 *     MarkDirty      - If TRUE, will mark the mapped pages as dirty.
 *
 * RETURNS:
 *     STATUS_SUCCESS if all data have been successfully mapped.
 *     STATUS_NONE_MAPPED if no data have been mapped.
 *     STATUS_SOME_NOT_MAPPED if some data have been partially mapped.
 *
 * REMARKS:
 *     Note STATUS_SOME_NOT_MAPPED is an NT_SUCCESS status.
 */
NTSTATUS CcMapDataEx(IN OPTIONAL PIO_DRIVER_OBJECT DriverObject,
		     IN PIO_FILE_CONTROL_BLOCK Fcb,
		     IN ULONG64 FileOffset,
		     IN ULONG Length,
		     OUT ULONG *pMappedLength,
		     OUT PVOID *Buffer,
		     IN BOOLEAN MarkDirty)
{
    assert(Fcb);
    if (pMappedLength) {
	*pMappedLength = 0;
    }
    if (!Length) {
	return STATUS_SUCCESS;
    }
    /* If the FileSize of the FCB is not set, we skip the end-of-file checks and
     * assume the file is infinitely long. */
    ULONG64 FileSize = Fcb->FileSize ? Fcb->FileSize : ~0ULL;
    if (FileOffset >= FileSize) {
	return STATUS_INVALID_PARAMETER;
    }
    ULONG MappedLength = Length;
    if (FileOffset + Length > FileSize) {
	MappedLength = FileSize - FileOffset;
    }

    /* If we are mapping a private cache, make sure the cache map is initialized. */
    if (DriverObject) {
	RET_ERR(CcInitializeCacheMap(Fcb, DriverObject, NULL));
    }

    /* Get the view in the cache map corresponding to this file region. If we
     * are mapping a private cache map and the view does not exist, create it. */
    PCC_VIEW View = NULL;
    RET_ERR(CiGetView(Fcb, DriverObject, FileOffset, DriverObject != NULL, &View));
    assert(View);

    ULONG64 AlignedOffset = VIEW_ALIGN64(FileOffset);
    assert(AlignedOffset == View->Node.Key);
    ULONG64 EndOffset = AlignedOffset + VIEW_SIZE;
    if (EndOffset > FileSize) {
	EndOffset = FileSize;
    }
    if (FileOffset + MappedLength > EndOffset) {
	assert(EndOffset > FileOffset);
	MappedLength = EndOffset - FileOffset;
    }
    ULONG MappedViewSize = EndOffset - AlignedOffset;
    if (!View->Loaded) {
	if (DriverObject) {
	    ULONG WindowSize = 0;
	    PVOID Buffer = NULL;
	    NTSTATUS Status = CcMapData(Fcb, AlignedOffset, VIEW_SIZE, &WindowSize, &Buffer);
	    if (!NT_SUCCESS(Status)) {
		MappedLength = 0;
		goto out;
	    }
	    assert(WindowSize == MappedViewSize);
	    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
	    Status = MmMapMirroredMemory(&MiNtosVaddrSpace, (MWORD)Buffer,
					 View->CacheMap->CacheSpace->AddrSpace,
					 View->MappedAddress, MappedViewSize, MM_RIGHTS_RW);
	    if (NT_SUCCESS(Status)) {
		View->Loaded = TRUE;
	    } else {
		MappedLength = 0;
	    }
	} else {
	    MappedLength = 0;
	}
    }

out:
    if (!MappedLength) {
	*Buffer = NULL;
	return STATUS_NONE_MAPPED;
    } else if (MarkDirty) {
	ULONG ViewOffset = FileOffset - AlignedOffset;
	ULONG StartPage = ViewOffset >> PAGE_LOG2SIZE;
	ULONG EndPage = PAGE_ALIGN_UP(ViewOffset + MappedLength) >> PAGE_LOG2SIZE;
	assert(StartPage < PAGES_IN_VIEW);
	assert(EndPage <= PAGES_IN_VIEW);
	for (ULONG i = StartPage; i < EndPage; i++) {
	    SetBit64(View->DirtyMap, i);
	}
    }
    *Buffer = (PUCHAR)View->MappedAddress + (FileOffset - AlignedOffset);
    if (pMappedLength) {
	*pMappedLength = MappedLength;
	return MappedLength == Length ? STATUS_SUCCESS : STATUS_SOME_NOT_MAPPED;
    } else {
	return MappedLength == Length ? STATUS_SUCCESS : STATUS_NONE_MAPPED;
    }
}

/*
 * Map the given length of the file object and copy to/from the given buffer.
 * Write == TRUE means copying from the buffer to the cache.
 * For partial copies, an error status is returned.
 */
static NTSTATUS CiCopyReadWrite(IN PIO_FILE_CONTROL_BLOCK Fcb,
				IN ULONG64 FileOffset,
				IN ULONG64 Length,
				IN BOOLEAN Write,
				OUT OPTIONAL ULONG64 *pBytesCopied,
				OUT PVOID Buffer)
{
    assert(Fcb);
    assert(Length);
    assert(Buffer);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG64 BytesCopied = 0;
    while ((LONG64)Length > 0) {
	ULONG MappedLength = 0;
	PVOID MappedBuffer = NULL;
	Status = CcMapDataEx(NULL, Fcb, FileOffset, Length,
			     &MappedLength, &MappedBuffer, Write);
	if (!NT_SUCCESS(Status)) {
	    break;
	}
	assert(MappedLength);
	assert(MappedLength <= Length);
	if (Write) {
	    memcpy(MappedBuffer, Buffer, MappedLength);
	} else {
	    memcpy(Buffer, MappedBuffer, MappedLength);
	}
	Length -= MappedLength;
	FileOffset += MappedLength;
	Buffer = (PUCHAR)Buffer + MappedLength;
    }

    if (pBytesCopied) {
	*pBytesCopied = BytesCopied;
    }
    return (Length == 0) ? STATUS_SUCCESS : Status;
}

/*
 * ROUTINE DESCRIPTION:
 *     Copy the data in the shared file cache to the given buffer.
 *
 * ARGUMENTS:
 *     Fcb         - File control block of the file object to copy into.
 *     FileOffset  - Starting offset of the file region.
 *     Length      - Length of the file region.
 *     *pBytesRead - Length of the successfully copied region.
 *     Buffer      - Destination buffer to copy into.
 *
 * RETURNS:
 *     STATUS_SUCCESS if all data have been successfully loaded. Error
 *     status if an error has occurred.
 */
NTSTATUS CcCopyReadEx(IN PIO_FILE_CONTROL_BLOCK Fcb,
		      IN ULONG64 FileOffset,
		      IN ULONG64 Length,
		      OUT OPTIONAL ULONG64 *pBytesRead,
		      OUT PVOID Buffer)
{
    return CiCopyReadWrite(Fcb, FileOffset, Length, FALSE, pBytesRead, Buffer);
}

/*
 * ROUTINE DESCRIPTION:
 *     Copy the data from the given buffer to the shared file cache.
 *
 * ARGUMENTS:
 *     Fcb         - File control block of the file object to copy into.
 *     FileOffset  - Starting offset of the file region.
 *     Length      - Length of the file region.
 *     *pBytesRead - Length of the successfully copied region.
 *     Buffer      - Destination buffer to copy into.
 *
 * RETURNS:
 *     STATUS_SUCCESS if all data have been successfully loaded. Error
 *     status if an error has occurred.
 */
NTSTATUS CcCopyWriteEx(IN PIO_FILE_CONTROL_BLOCK Fcb,
		       IN ULONG64 FileOffset,
		       IN ULONG64 Length,
		       OUT OPTIONAL ULONG64 *pBytesWritten,
		       IN PVOID Buffer)
{
    return CiCopyReadWrite(Fcb, FileOffset, Length, TRUE, pBytesWritten, Buffer);
}
