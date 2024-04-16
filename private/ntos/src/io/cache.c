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
    of the file system file objects. Cache pages are mapped directly
    into driver address spaces so client drivers always see the same
    up-to-date data at all times.

Revision History:

    2024-02-14  File created

--*/
#include "iop.h"

#define NTOS_CC_TAG	(EX_POOL_TAG('n','t','c','c'))

#define CiAllocatePool(Size)	ExAllocatePoolWithTag((Size), NTOS_CC_TAG)
#define CiFreePool(Size)	ExFreePoolWithTag((Size), NTOS_CC_TAG)

struct _CC_VIEW;
struct _QUEUED_IO_REQUEST;

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
    AVL_NODE Node; /* Key is the starting file offset of the file region in the FS file. */
    ULONG64 VolumeFileOffset; /* Starting offset of the corresponding volume file region. */
    ULONG64 Length; /* Length of the file region. Cluster size aligned except for the
		     * last file block. */
    struct _CC_CACHE_MAP *CacheMap;
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
    struct _QUEUED_IO_REQUEST *IoReq; /* IO request queued to load the file data
				       * for this view. Note multiple views can
				       * point to the same QUEUED_IO_REQUEST. */
    ULONG MappedSize; /* Number of bytes with valid data in this view. */
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
	AvlTreeInsertNode(&CacheMap->ViewTree, Parent, Node);
    }
    *pView = AVL_NODE_TO_VIEW(Node);
    return Node ? STATUS_SUCCESS : STATUS_NONE_MAPPED;
}

typedef struct _PIN_DATA_CALLBACK_CONTEXT {
    KEVENT Event;
    NTSTATUS Status;
} PIN_DATA_CALLBACK_CONTEXT, *PPIN_DATA_CALLBACK_CONTEXT;

static VOID CiPinDataCallback(IN PIO_FILE_CONTROL_BLOCK Fcb,
			      IN ULONG64 FileOffset,
			      IN ULONG64 Length,
			      IN NTSTATUS Status,
			      IN OUT PVOID Ctx)
{
    PPIN_DATA_CALLBACK_CONTEXT Context = Ctx;
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
    CcPinDataEx(Fcb, FileOffset, Length, FALSE, CiPinDataCallback, Locals.Context);

    AWAIT(KeWaitForSingleObject, State, Locals, Thread,
	  &Locals.Context->Event.Header, FALSE, NULL);

    NTSTATUS Status = Locals.Context->Status;
    KeUninitializeEvent(&Locals.Context->Event);
    CiFreePool(Locals.Context);
    ASYNC_END(State, Status);
}

typedef struct _PIN_DATA_EX_CALLBACK_INFO {
    LIST_ENTRY ReqList;	 /* List of IO requests queued for this callback */
    PCC_PIN_DATA_CALLBACK Callback; /* Callback function to call when all IO is completed. */
    PVOID Context;  /* Context of the callback function. */
    ULONG64 OriginalFileOffset;
    ULONG64 OriginalLength;
    PIO_FILE_CONTROL_BLOCK Fcb;
    IO_STATUS_BLOCK IoStatus; /* The final aggregated IO status of all IO requests.
			       * If all IO requests completed succesfully, this will
			       * be set to the total length of the IO requests. If
			       * some IO requests fail, this will be set to the IO
			       * status block of the first failed IO request. */
    BOOLEAN Write;
} PIN_DATA_EX_CALLBACK_INFO, *PPIN_DATA_EX_CALLBACK_INFO;

typedef struct _QUEUED_IO_REQUEST {
    PPIN_DATA_EX_CALLBACK_INFO CallbackInfo;
    PCC_VIEW View; /* View object of the starting file offset of the IO request. */
    MWORD Length;  /* Request length of the IO request. Note this may not be equal to
		    * the IO buffer length in the PendingIrp below, since drivers can
		    * change the ByteOffset and Length when forwarding an IRP. */
    PPENDING_IRP PendingIrp; /* When this is NULL, the QUEUED_IO_REQUEST is a slave
			      * waiting for the master QUEUED_IO_REQUEST to finish. */
    LIST_ENTRY Link;   /* List entry for PIN_DATA_EX_CALLBACK_INFO::ReqList */
    LIST_ENTRY Slaves; /* Chains all slave QUEUED_IO_REQUESTs waiting on the completion
			* of the master QUEUED_IO_REQUEST. */
} QUEUED_IO_REQUEST, *PQUEUED_IO_REQUEST;

FORCEINLINE ULONG64 CiGetIrpByteOffset(IN PQUEUED_IO_REQUEST Req)
{
    PIO_REQUEST_PARAMETERS Irp = &Req->PendingIrp->IoPacket->Request;
    BOOLEAN Write = Irp->MajorFunction == IRP_MJ_WRITE;
    assert(Write || Irp->MajorFunction == IRP_MJ_READ);
    return Write ? Irp->Write.ByteOffset.QuadPart : Irp->Read.ByteOffset.QuadPart;
}

FORCEINLINE MWORD CiGetIrpRequestLength(IN PQUEUED_IO_REQUEST Req)
{
    PIO_REQUEST_PARAMETERS Irp = &Req->PendingIrp->IoPacket->Request;
    BOOLEAN Write = Irp->MajorFunction == IRP_MJ_WRITE;
    assert(Write || Irp->MajorFunction == IRP_MJ_READ);
    return Write ? Irp->InputBufferLength : Irp->OutputBufferLength;
}

FORCEINLINE MWORD CiGetIrpUserBuffer(IN PQUEUED_IO_REQUEST Req)
{
    PIO_REQUEST_PARAMETERS Irp = &Req->PendingIrp->IoPacket->Request;
    BOOLEAN Write = Irp->MajorFunction == IRP_MJ_WRITE;
    assert(Write || Irp->MajorFunction == IRP_MJ_READ);
    return Write ? Irp->InputBuffer : Irp->OutputBuffer;
}

static VOID CiCompleteQueuedIoReq(IN PQUEUED_IO_REQUEST Req,
				  IN NTSTATUS Status)
{
    /* You can only call this routine on a master QUEUED_IO_REQUEST. */
    assert(Req->PendingIrp);
    assert(Req->View->IoReq == Req);
    IO_STATUS_BLOCK IoStatus = Req->PendingIrp->IoResponseStatus;
    if (!NT_SUCCESS(Status)) {
	IoStatus.Status = Status;
	IoStatus.Information = 0;
    }
    if (!NT_SUCCESS(IoStatus.Status)) {
	Req->CallbackInfo->IoStatus = IoStatus;
    }
    ULONG64 FileOffset = Req->View->Node.Key;
    assert(IS_VIEW_ALIGNED64(FileOffset));
    for (MWORD Length = 0; Length < Req->Length; Length += VIEW_SIZE) {
	PCC_VIEW View = NULL;
	CiGetView(Req->View->CacheMap->Fcb, NULL, FileOffset + Length, FALSE, &View);
	assert(View);
	if (View) {
	    assert(Length || View == Req->View);
	    assert(View->IoReq == Req);
	    View->IoReq = NULL;
	    if (NT_SUCCESS(IoStatus.Status)) {
		View->MappedSize = min(VIEW_SIZE, Req->Length - Length);
	    } else {
		MmUncommitVirtualMemory(View->MappedAddress, VIEW_SIZE);
	    }
	}
    }
    LoopOverList(Slave, &Req->Slaves, QUEUED_IO_REQUEST, Slaves) {
	assert(!Slave->PendingIrp);
	RemoveEntryList(&Slave->Slaves);
	RemoveEntryList(&Slave->Link);
	if (!NT_SUCCESS(IoStatus.Status)) {
	    Slave->CallbackInfo->IoStatus = IoStatus;
	}
	if (IsListEmpty(&Slave->CallbackInfo->ReqList)) {
	    Slave->CallbackInfo->Callback(Slave->CallbackInfo->Fcb,
					  Slave->CallbackInfo->OriginalFileOffset,
					  Slave->CallbackInfo->OriginalLength,
					  Slave->CallbackInfo->IoStatus.Status,
					  Slave->CallbackInfo->Context);
	    CiFreePool(Slave->CallbackInfo);
	}
	CiFreePool(Slave);
    }
    RemoveEntryList(&Req->Link);
    if (IsListEmpty(&Req->CallbackInfo->ReqList)) {
	Req->CallbackInfo->Callback(Req->CallbackInfo->Fcb,
				    Req->CallbackInfo->OriginalFileOffset,
				    Req->CallbackInfo->OriginalLength,
				    Req->CallbackInfo->IoStatus.Status,
				    Req->CallbackInfo->Context);
	CiFreePool(Req->CallbackInfo);
    }
}

/* Free all the FILE_OFFSET_MAPPINGs of the specified file region */
static VOID CiFreeFileOffsetMappings(IN PIO_FILE_CONTROL_BLOCK Fcb,
				     IN ULONG64 FileOffset,
				     IN ULONG64 Length)
{
    PFILE_OFFSET_MAPPING Node =
	AVL_NODE_TO_FILE_OFFSET_MAPPING(AvlTreeFindNodeOrParent(&Fcb->FileOffsetMappings,
								FileOffset));
    while (Node) {
	PAVL_NODE Next = AvlGetNextNode(&Node->Node);
	if (FileOffset <= Node->Node.Key && Node->Node.Key + Length <= FileOffset + Length) {
	    AvlTreeRemoveNode(&Fcb->FileOffsetMappings, &Node->Node);
	    CiFreePool(Node);
	}
	Node = AVL_NODE_TO_FILE_OFFSET_MAPPING(Next);
    }
}

typedef struct _FILE_OFFSET_MAPPING_CALLBACK_CONTEXT {
    PQUEUED_IO_REQUEST IoReq; /* This must be a master QUEUED_IO_REQUEST object */
    PPENDING_IRP PendingIrp;
    MWORD CompletedLength;
} FILE_OFFSET_MAPPING_CALLBACK_CONTEXT, *PFILE_OFFSET_MAPPING_CALLBACK_CONTEXT;

static VOID CiFileOffsetMappingCallback(IN PIO_FILE_CONTROL_BLOCK VolumeFcb,
					IN ULONG64 VolumeFileOffset,
					IN ULONG64 Length,
					IN NTSTATUS Status,
					IN OUT PVOID Ctx)
{
    PFILE_OFFSET_MAPPING_CALLBACK_CONTEXT Context = Ctx;
    PQUEUED_IO_REQUEST IoReq = Context->IoReq;
    assert(IoReq->PendingIrp);
    PCC_CACHE_MAP CacheMap = IoReq->View->CacheMap;
    PIO_FILE_CONTROL_BLOCK Fcb = CacheMap->Fcb;
    assert(Fcb != Fcb->Vcb->VolumeFcb);
    assert(VolumeFcb == Fcb->Vcb->VolumeFcb);
    BOOLEAN Extend = FALSE;
    PFILE_OFFSET_MAPPING Mapping = NULL;
    ULONG64 RequestLength = Length;

    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* The file offset of the FS file object is obtained by adding the original file
     * offset of the IO request, obtained from the leading view object associated with
     * the QUEUED_IO_REQUEST, and the offset supplied by the driver in the UserBuffer
     * member of the IRP. */
    ULONG64 FileOffset = IoReq->View->Node.Key + CiGetIrpUserBuffer(IoReq);

    /* If the Length exceeds the file size, adjust it to the end of the file. Note
     * that if we are extending the file, by this time the file size will have been
     * updated to the new file size. */
    if (FileOffset >= Fcb->FileSize) {
	assert(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto out;
    }
    if (FileOffset + Length > Fcb->FileSize) {
	RequestLength = Length = Fcb->FileSize - FileOffset;
    }

    PFILE_OFFSET_MAPPING Parent =
	AVL_NODE_TO_FILE_OFFSET_MAPPING(AvlTreeFindNodeOrParent(&Fcb->FileOffsetMappings,
								FileOffset));
    if (Parent) {
	/* File system driver cannot return an overlapping file offset mapping. */
	if ((Parent->Node.Key < FileOffset && FileOffset < Parent->Node.Key + Parent->Length) ||
	    (FileOffset < Parent->Node.Key && FileOffset + Length > Parent->Node.Key)) {
	    Status = STATUS_INTERNAL_ERROR;
	    goto out;
	}
	if (Parent->Node.Key == FileOffset) {
	    if (Length < Parent->Length || Parent->VolumeFileOffset != VolumeFileOffset) {
		/* If a file system driver resends an existing file offset mapping, it
		 * cannot be shrinking it, or change the starting volume file offset. */
		Status = STATUS_INTERNAL_ERROR;
		goto out;
	    }
	    if (Length == Parent->Length) {
		/* If a file system driver resends an identical file offset mapping,
		 * do nothing and return success. */
		Status = STATUS_SUCCESS;
		goto out;
	    }
	    /* We are extending a file offset mapping, so skip the part already mapped.
	     * Note if the cache pages are shared with the volume cache pages, we need
	     * to skip whole pages. */
	    ULONG64 LengthToSkip = Parent->Length;
	    if (IS_PAGE_ALIGNED(FileOffset - VolumeFileOffset)) {
		LengthToSkip = PAGE_ALIGN_UP64(FileOffset + Parent->Length) - FileOffset;
	    }
	    if (Length <= LengthToSkip) {
		Parent->Length = Length;
		Status = STATUS_SUCCESS;
		goto out;
	    }
	    FileOffset += LengthToSkip;
	    VolumeFileOffset += LengthToSkip;
	    Length -= LengthToSkip;
	    Extend = TRUE;
	}
    }

    /* Allocate the mapping object and record FileOffset, Length, and VolumeFileOffset,
     * because we will be changing these in the code below. */
    if (!Extend) {
	Mapping = CiAllocatePool(sizeof(FILE_OFFSET_MAPPING));
	if (!Mapping) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	Mapping->Node.Key = FileOffset;
	Mapping->Length = Length;
	Mapping->VolumeFileOffset = VolumeFileOffset;
    }

    /* For the unaligned head and tail of the view region we ignore the
     * STATUS_ALREADY_COMMITTED error since another call of this routine
     * may have already committed the pages there. */
    if (FileOffset < PAGE_ALIGN_UP64(FileOffset)) {
	/* Find the view corresponding to the file offset. */
	PCC_VIEW View = NULL;
	CiGetView(Fcb, NULL, FileOffset, FALSE, &View);
	if (!View) {
	    assert(FALSE);
	    Status = STATUS_NTOS_BUG;
	    goto out;
	}
	ULONG ViewOffset = FileOffset - View->Node.Key;
	Status = MmCommitOwnedMemory(View->MappedAddress + PAGE_ALIGN(ViewOffset),
				     PAGE_SIZE, MM_RIGHTS_RW, FALSE);
	if (!NT_SUCCESS(Status) && Status != STATUS_ALREADY_COMMITTED) {
	    goto out;
	}
	/* If we are writing to a file, don't bother copying the data from the volume file. */
	ULONG LengthToCopy = min(PAGE_ALIGN_UP64(FileOffset) - FileOffset, Length);
	if (!IoReq->CallbackInfo->Write) {
	    ULONG MappedLength = 0;
	    PVOID Buffer = NULL;
	    Status = CcMapData(VolumeFcb, VolumeFileOffset, LengthToCopy,
			       &MappedLength, &Buffer);
	    if (!NT_SUCCESS(Status) || MappedLength != LengthToCopy) {
		assert(FALSE);
		Status = STATUS_NTOS_BUG;
		goto out;
	    }
	    assert(Buffer);
	    RtlCopyMemory((PVOID)(View->MappedAddress + ViewOffset),
			  Buffer, MappedLength);
	}
	/* Skip the part we copied above so the code below will not do unneeded copy. */
	Parent->Length += LengthToCopy;
	FileOffset += LengthToCopy;
	VolumeFileOffset += LengthToCopy;
	Length -= LengthToCopy;
    }

    /* For the whole pages in the file block, we either map the volume page caches
     * if possible, or create new pages and copy the data from the volume file. */
    assert(IS_PAGE_ALIGNED(FileOffset));
    ULONG64 AlignedEndOffset = PAGE_ALIGN64(FileOffset + Length);
    assert(FileOffset <= AlignedEndOffset);
    ULONG64 CurrentOffset = FileOffset;
    while (CurrentOffset < AlignedEndOffset) {
	assert(IS_PAGE_ALIGNED(CurrentOffset));
	/* Find the view corresponding to the file offset. */
	PCC_VIEW View = NULL;
	CiGetView(Fcb, NULL, CurrentOffset, FALSE, &View);
	if (!View) {
	    assert(FALSE);
	    Status = STATUS_NTOS_BUG;
	    goto out;
	}
	ULONG ViewOffset = CurrentOffset - View->Node.Key;
	ULONG LengthToMap = min(VIEW_ALIGN64(CurrentOffset + VIEW_SIZE) - CurrentOffset,
				AlignedEndOffset - CurrentOffset);
	if (IS_PAGE_ALIGNED(FileOffset - VolumeFileOffset)) {
	    /* If the difference between the view offset and the volume file offset is
	     * page-aligned, we can share the pages with the volume cache map. */
	    ULONG MappedLength = 0;
	    while (MappedLength < LengthToMap) {
		MWORD MappedAddress = View->MappedAddress + ViewOffset + MappedLength;
		ULONG WindowSize = 0;
		PVOID Buffer = NULL;
		IF_ERR_GOTO(out, Status, CcMapData(VolumeFcb, VolumeFileOffset + MappedLength,
						   LengthToMap - MappedLength,
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
	    assert(MappedLength == LengthToMap);
	} else {
	    /* Otherwise, we need to create private pages. */
	    IF_ERR_GOTO(out, Status,
			MmCommitOwnedMemory(View->MappedAddress + ViewOffset,
					    LengthToMap, MM_RIGHTS_RW, FALSE));
	}
	CurrentOffset += LengthToMap;
    }

    /* For the unaligned tail of the file block, commit the cache page. Note we ignore
     * the STATUS_ALREADY_COMMITTED error. */
    assert(CurrentOffset == AlignedEndOffset);
    if (AlignedEndOffset < FileOffset + Length) {
	PCC_VIEW View = NULL;
	CiGetView(Fcb, NULL, AlignedEndOffset, FALSE, &View);
	if (!View) {
	    assert(FALSE);
	    Status = STATUS_NTOS_BUG;
	    goto out;
	}
	ULONG ViewOffset = AlignedEndOffset - View->Node.Key;
	Status = MmCommitOwnedMemory(View->MappedAddress + ViewOffset,
				     PAGE_SIZE, MM_RIGHTS_RW, FALSE);
	if (!NT_SUCCESS(Status) && Status != STATUS_ALREADY_COMMITTED) {
	    goto out;
	}
    }

    /* If we are reading from the file, copy the volume file data if needed. */
    if (!IoReq->CallbackInfo->Write) {
	/* Skip the shared pages mapped above so the code below won't do unneeded copy. */
	if (IS_PAGE_ALIGNED(FileOffset - VolumeFileOffset)) {
	    Length -= AlignedEndOffset - FileOffset;
	    VolumeFileOffset += AlignedEndOffset - FileOffset;
	    FileOffset = AlignedEndOffset;
	    if (Extend) {
		Parent->Length += AlignedEndOffset - FileOffset;
	    }
	}

	CurrentOffset = FileOffset;
	while (CurrentOffset < FileOffset + Length) {
	    /* Find the view corresponding to the file offset. */
	    PCC_VIEW View = NULL;
	    CiGetView(Fcb, NULL, CurrentOffset, FALSE, &View);
	    if (!View) {
		assert(FALSE);
		Status = STATUS_NTOS_BUG;
		goto out;
	    }
	    ULONG ViewOffset = CurrentOffset - View->Node.Key;
	    ULONG LengthToCopy = min(VIEW_ALIGN64(CurrentOffset + VIEW_SIZE) - CurrentOffset,
				     FileOffset + Length - CurrentOffset);
	    ULONG LengthCopied = 0;
	    while (LengthCopied < LengthToCopy) {
		ULONG MappedLength = 0;
		PVOID Buffer = NULL;
		Status = CcMapData(VolumeFcb,
				   VolumeFileOffset + CurrentOffset - FileOffset + LengthCopied,
				   LengthToCopy - LengthCopied, &MappedLength, &Buffer);
		if (!NT_SUCCESS(Status)) {
		    assert(FALSE);
		    goto out;
		}
		assert(Buffer);
		assert(ViewOffset + LengthCopied + MappedLength <= VIEW_SIZE);
		RtlCopyMemory((PVOID)(View->MappedAddress + ViewOffset + LengthCopied),
			      Buffer, MappedLength);
		LengthCopied += MappedLength;
	    }
	    assert(LengthCopied == LengthToCopy);
	    CurrentOffset += LengthCopied;
	}
    }

    if (Extend) {
	assert(Parent->Node.Key == Mapping->Node.Key);
	assert(Parent->VolumeFileOffset == Mapping->VolumeFileOffset);
	Parent->Length += Length;
    } else {
	assert(!Parent || Mapping->Node.Key != Parent->Node.Key);
	AvlTreeInsertNode(&Fcb->FileOffsetMappings, &Parent->Node, &Mapping->Node);
    }

out:
    Context->CompletedLength += RequestLength;
    if (!NT_SUCCESS(Status)) {
	if (Mapping) {
	    CiFreePool(Mapping);
	}
	CiFreeFileOffsetMappings(Fcb, IoReq->View->Node.Key, IoReq->Length);
	/* The cache pages mapped above will be freed in CiCompleteQueuedIoReq. */
	IoReq->CallbackInfo->IoStatus.Status = Status;
    }
    if (Context->CompletedLength >= IoReq->Length) {
	assert(Context->CompletedLength == IoReq->Length);
	CiCompleteQueuedIoReq(IoReq, Status);
    }
    IO_STATUS_BLOCK IoStatus = {
	.Status = Status,
	.Information = NT_SUCCESS(Status) ? RequestLength : 0
    };
    IopCompletePendingIrp(Context->PendingIrp, IoStatus, NULL, 0);
}

static BOOLEAN CiPagedIoCallback(IN PPENDING_IRP PendingIrp,
				 IN OUT PVOID Context,
				 IN BOOLEAN Completion)
{
    PQUEUED_IO_REQUEST IoReq = Context;
    ULONG64 FileOffset = CiGetIrpByteOffset(IoReq);
    MWORD RequestLength = CiGetIrpRequestLength(IoReq);

    PIO_FILE_CONTROL_BLOCK Fcb = IoReq->View->CacheMap->Fcb;
    assert(Fcb->SharedCacheMap == IoReq->View->CacheMap);
    BOOLEAN IsVolume = Fcb == Fcb->Vcb->VolumeFcb;
    NTSTATUS Status = PendingIrp->IoResponseStatus.Status;

    if (IsVolume) {
	/* If the target of the IO is the volume file object, allow it
	 * to pass on to the lower driver. */
	if (!Completion) {
	    return TRUE;
	}
    } else {
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	if (Completion) {
	    /* For the master IRP we should call IopCleanupPendingIrp and free
	     * the IoReq because we originally allocated the IoReq and requested
	     * the IRP (in CcPinDataEx). */
	    if (PendingIrp == IoReq->PendingIrp) {
		goto cleanup;
	    }
	    /* For associated IRPs we should not call IopCleanupPendingIrp as
	     * the system does the clean up for us (in IopCompletePendingIrp). */
	    return FALSE;
	}
	/* File offset mapping must be aligned by cluster size. */
	if (!IS_ALIGNED_BY(FileOffset, Fcb->Vcb->ClusterSize) ||
	    !IS_ALIGNED_BY(RequestLength, Fcb->Vcb->ClusterSize)) {
	    assert(FALSE);
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    goto out;
	}
	PFILE_OFFSET_MAPPING_CALLBACK_CONTEXT FileOffsetMappingCallbackContext =
	    CiAllocatePool(sizeof(FILE_OFFSET_MAPPING_CALLBACK_CONTEXT));
	if (!FileOffsetMappingCallbackContext) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	FileOffsetMappingCallbackContext->IoReq = IoReq;
	FileOffsetMappingCallbackContext->PendingIrp = PendingIrp;
	/* Note that since the IRP forwarding code updates the ByteOffset and the
	 * Length members of the IRP, the FileOffset above is in fact the volume
	 * file offset (not the file offset of the original file object), and the
	 * RequestLength is in fact the length of the file offset mapping (not the
	 * length of the original IO request). */
	CcPinDataEx(Fcb->Vcb->VolumeFcb, FileOffset, RequestLength, FALSE,
		    CiFileOffsetMappingCallback, FileOffsetMappingCallbackContext);
	return FALSE;
    }

out:
    CiCompleteQueuedIoReq(IoReq, Status);
cleanup:
    IopCleanupPendingIrp(IoReq->PendingIrp);
    CiFreePool(IoReq);
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
 *     Write      - If TRUE, the file object will be extended when
 *                  the file region exceeds the end of file mark and
 *                  data from the underlying volume file will NOT be
 *                  copied, since the caller is assumed to be writing
 *                  to the file region.
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
		 IN BOOLEAN Write,
		 IN PCC_PIN_DATA_CALLBACK Callback,
		 IN OPTIONAL PVOID Context)
{
    assert(Fcb);
    assert(Callback);

    ULONG64 OriginalFileOffset = FileOffset;
    ULONG64 OriginalLength = Length;
    NTSTATUS Status;
    if (Length == 0) {
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }

    PIO_VOLUME_CONTROL_BLOCK Vcb = Fcb->Vcb;
    BOOLEAN IsVolume = Vcb && (Fcb == Vcb->VolumeFcb);

    /* If the FileSize of the FCB is not set, we skip the end-of-file checks and
     * assume the file is infinitely long. */
    ULONG64 FileSize = Fcb->FileSize ? Fcb->FileSize : ~0ULL;
    ULONG64 EndOffset = FileOffset + Length;
    BOOLEAN Extend = FALSE;
    if (Write && FileSize < EndOffset) {
	FileSize = EndOffset;
	FileOffset = min(FileOffset, Fcb->FileSize);
	Extend = TRUE;
    } else if (FileOffset >= FileSize) {
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    } else if (EndOffset > FileSize) {
	EndOffset = FileSize;
    }
    assert(EndOffset > FileOffset);
    Length = EndOffset - FileOffset;

    /* Volume FCB cannot be extended. */
    if (IsVolume & Extend) {
	assert(FALSE);
	Status = STATUS_NTOS_BUG;
	goto out;
    }
    /* If the file object needs to be extended, you must wait for WritePending to
     * become FALSE before calling this routine. */
    if (Extend && Fcb->WritePending) {
	assert(FALSE);
	Status = STATUS_NTOS_BUG;
	goto out;
    }

    /* Since we are dealing with asynchronous IO and don't have the convenient
     * ASYNC_STATE with which we can simply wait for the IOs to complete, construct
     * a PIN_DATA_EX_CALLBACK_INFO structure which packs all the information we need
     * when the IOs are completed. */
    PPIN_DATA_EX_CALLBACK_INFO CallbackInfo = CiAllocatePool(sizeof(PIN_DATA_EX_CALLBACK_INFO));
    if (!CallbackInfo) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    InitializeListHead(&CallbackInfo->ReqList);
    CallbackInfo->Callback = Callback;
    CallbackInfo->Context = Context;
    CallbackInfo->Fcb = Fcb;
    CallbackInfo->OriginalFileOffset = OriginalFileOffset;
    CallbackInfo->OriginalLength = OriginalLength;
    CallbackInfo->Write = Write;

    PQUEUED_IO_REQUEST IoReq = NULL;
    ULONG64 CurrentOffset = VIEW_ALIGN64(FileOffset);
    /* Get the view object for each file segment, and queue the IO request if the
     * file segment is not loaded into memory. */
    while (CurrentOffset < EndOffset) {
	assert(IS_VIEW_ALIGNED64(CurrentOffset));
	assert(CurrentOffset < FileSize);
	PCC_VIEW View = NULL;
	IF_ERR_GOTO(out, Status, CiGetView(Fcb, NULL, CurrentOffset, TRUE, &View));
	/* We always map the entire view except for the last view of a file, in
	 * which case the view size is adjusted to the end of the file. */
	ULONG SizeToMap = min(VIEW_SIZE, FileSize - CurrentOffset);
	CurrentOffset += SizeToMap;
	/* If the view is fully mapped, simply continue. Note we need to set IoReq to
	 * NULL so when processing the next view region, we will not try to extend the
	 * existing IoReq. */
	if (View->MappedSize >= SizeToMap) {
	    IoReq = NULL;
	    continue;
	}
	/* For the volume device or purely in-memory file objects, if the view is not
	 * mapped, we need to allocate private pages for the view. */
	if (!Vcb || IsVolume) {
	    Status = MmCommitOwnedMemory(View->MappedAddress, PAGE_ALIGN_UP(SizeToMap),
					 MM_RIGHTS_RW, FALSE);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }
	}
	/* For purely in-memory file objects, we don't need to send IO requests. */
	if (!Vcb) {
	    View->MappedSize = SizeToMap;
	    assert(!IoReq);
	    continue;
	}
	/* If IoReq is not NULL, it means that the previous IO request can potentially
	 * be extended to include this view region. For volume file objects, we further
	 * require that the cache pages are virtually contiguous with the previous view. */
	if (IoReq && !!IoReq->PendingIrp == !View->IoReq &&
	    (!IsVolume || View->MappedAddress == IoReq->View->MappedAddress + IoReq->Length)) {
	    assert(View->Node.Key == IoReq->View->Node.Key + IoReq->Length);
	    IoReq->Length += SizeToMap;
	    continue;
	}
	/* Otherwise, we need to allocate a new QUEUED_IO_REQUEST. */
	IoReq = CiAllocatePool(sizeof(QUEUED_IO_REQUEST));
	if (!IoReq) {
	    if (IsVolume) {
		MmUncommitVirtualMemory(View->MappedAddress, VIEW_SIZE);
	    }
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}
	IoReq->CallbackInfo = CallbackInfo;
	IoReq->View = View;
	IoReq->Length = SizeToMap;
	if (View->IoReq) {
	    /* If the view already has an IO request queued, we need to link our IoReq as
	     * a slave to the existing master QUEUED_IO_REQUEST. */
	    InsertTailList(&View->IoReq->Slaves, &IoReq->Slaves);
	} else {
	    /* Otherwise, we need to mark the PendingIrp of the IoReq with a non-NULL
	     * value so we know it is a master QUEUED_IO_REQUEST. */
	    IoReq->PendingIrp = (PVOID)(ULONG_PTR)(-1);
	    InitializeListHead(&IoReq->Slaves);
	}
	InsertTailList(&CallbackInfo->ReqList, &IoReq->Link);
    }

    if (!NT_SUCCESS(Status)) {
	CallbackInfo->IoStatus.Status = Status;
    }

    LoopOverList(IoReq, &CallbackInfo->ReqList, QUEUED_IO_REQUEST, Link) {
	/* If this is not a master QUEUED_IO_REQUEST, simply continue */
	if (!IoReq->PendingIrp) {
	    continue;
	}
	/* Otherwise, we are a master IO request. Queue the IO. Note if the FCB is
	 * not the volume FCB, it must have a master file object is used as the target
	 * file object of the IRP call. */
	assert(IsVolume || Fcb->MasterFileObject);
	PIO_DEVICE_OBJECT DevObj = IsVolume ? Vcb->StorageDevice : Vcb->VolumeDevice;
	if (!DevObj) {
	    /* This should not happen since clients should not be able to make IO
	     * requests to FS file objects before the volume is mounted. */
	    assert(FALSE);
	    Status = STATUS_NTOS_BUG;
	    goto out;
	}
	IO_REQUEST_PARAMETERS Irp = {
	    .Flags = IOP_IRP_COMPLETION_CALLBACK,
	    .Device.Object = DevObj,
	    .File.Object = IsVolume ? NULL : Fcb->MasterFileObject,
	    .MajorFunction = Extend ? IRP_MJ_WRITE : IRP_MJ_READ,
	    .ServerPrivate = {
		.Callback = CiPagedIoCallback,
		.Context = IoReq
	    }
	};
	if (Extend) {
	    Irp.InputBufferLength = IoReq->Length;
	    Irp.Write.ByteOffset.QuadPart = IoReq->View->Node.Key;
	} else {
	    Irp.OutputBuffer = IsVolume ? (MWORD)IoReq->View->MappedAddress : 0;
	    Irp.OutputBufferLength = IoReq->Length;
	    Irp.Read.ByteOffset.QuadPart = IoReq->View->Node.Key;
	}
	if (!IsVolume) {
	    Irp.Flags |= IOP_IRP_INTERCEPTION_CALLBACK;
	}
	Status = IopCallDriver(IOP_PAGING_IO_REQUESTOR, &Irp, &IoReq->PendingIrp);
	if (NT_SUCCESS(Status)) {
	    IoReq->View->IoReq = IoReq;
	    for (ULONG Offset = VIEW_SIZE; Offset < IoReq->Length; Offset += VIEW_SIZE) {
		PCC_VIEW View = NULL;
		CiGetView(Fcb, NULL, IoReq->View->Node.Key + Offset, FALSE, &View);
		assert(View);
		if (View) {
		    View->IoReq = IoReq;
		}
	    }
	} else {
	    CallbackInfo->IoStatus.Status = Status;
	    /* Detach the IoReq from the CallbackInfo's request list and free it */
	    assert(IsListEmpty(&IoReq->Slaves));
	    RemoveEntryList(&IoReq->Link);
	    CiFreePool(IoReq);
	    break;
	}
    }

    /* For purely in-memory file objects, ReqList should be empty. */
    assert(Vcb || IsListEmpty(&CallbackInfo->ReqList));
    if (IsListEmpty(&CallbackInfo->ReqList)) {
	Status = CallbackInfo->IoStatus.Status;
	CiFreePool(CallbackInfo);
	goto out;
    }
    if (Extend) {
	Fcb->WritePending = TRUE;
    }
    return;

out:
    Callback(Fcb, OriginalFileOffset, OriginalLength, Status, Context);
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
	    while (ViewOffset < min((i+1) * PAGE_SIZE, Fcb->FileSize - View->Node.Key)) {
		ULONG FileOffset = View->Node.Key + ViewOffset;
		PFILE_OFFSET_MAPPING Mapping = AVL_NODE_TO_FILE_OFFSET_MAPPING(
		    AvlTreeFindNodeOrPrev(&Fcb->FileOffsetMappings, FileOffset));
		assert(Mapping);
		assert(FileOffset >= Mapping->Node.Key);
		assert(Mapping->Node.Key + Mapping->Length >= FileOffset);
		ULONG64 VolumeFileOffset = Mapping->VolumeFileOffset +
		    FileOffset - Mapping->Node.Key;
		ULONG NextOffset = min(PAGE_ALIGN(FileOffset + PAGE_SIZE),
				       Mapping->Node.Key + Mapping->Length);
		assert(NextOffset > FileOffset);
		ULONG Length = NextOffset - FileOffset;
		if (IS_PAGE_ALIGNED(FileOffset) && IS_PAGE_ALIGNED(VolumeFileOffset) &&
		    Length == PAGE_SIZE) {
		    PCC_VIEW VolumeView = NULL;
		    CiGetView(VolumeFcb, NULL, VolumeFileOffset, FALSE, &VolumeView);
		    if (VolumeView) {
			SetBit64(VolumeView->DirtyMap,
				 (VolumeFileOffset - VIEW_ALIGN64(VolumeFileOffset))
				 >> PAGE_LOG2SIZE);
		    } else {
			assert(FALSE);
		    }
		} else {
		    CcCopyWrite(VolumeFcb, VolumeFileOffset, Length,
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

static VOID CiSetSharedMapDirtyBits(IN PIO_FILE_CONTROL_BLOCK Fcb,
				    IN ULONG64 FileOffset,
				    IN ULONG64 Length,
				    IN BOOLEAN Set)
{
    ULONG64 CurrentOffset = FileOffset;
    while (CurrentOffset < FileOffset + Length) {
	PCC_VIEW View = NULL;
	CiGetView(Fcb, NULL, CurrentOffset, FALSE, &View);
	if (View) {
	    ULONG MappedLength = min(FileOffset + Length - CurrentOffset,
				     VIEW_ALIGN64(CurrentOffset + VIEW_SIZE) - CurrentOffset);
	    ULONG ViewOffset = CurrentOffset - View->Node.Key;
	    ULONG StartPage = ViewOffset >> PAGE_LOG2SIZE;
	    ULONG EndPage = PAGE_ALIGN_UP(ViewOffset + MappedLength) >> PAGE_LOG2SIZE;
	    assert(StartPage < PAGES_IN_VIEW);
	    assert(EndPage <= PAGES_IN_VIEW);
	    for (ULONG i = StartPage; i < EndPage; i++) {
		if (Set) {
		    SetBit64(View->DirtyMap, i);
		} else {
		    ClearBit64(View->DirtyMap, i);
		}
	    }
	}
	CurrentOffset = VIEW_ALIGN64(CurrentOffset + VIEW_SIZE);
    }
}

typedef struct _FLUSH_CACHE_CALLBACK_INFO {
    LIST_ENTRY ReqList;
    PCC_CACHE_FLUSHED_CALLBACK Callback;
    PVOID Context;
    PIO_DEVICE_OBJECT VolumeDevice;
    PIO_FILE_OBJECT FileObject;
    IO_STATUS_BLOCK IoStatus;
} FLUSH_CACHE_CALLBACK_INFO, *PFLUSH_CACHE_CALLBACK_INFO;

typedef struct _PAGED_WRITE_REQUEST {
    LIST_ENTRY Link;
    ULONG64 VolumeFileOffset;
    ULONG64 Length;
    MWORD MappedAddress;
    PFLUSH_CACHE_CALLBACK_INFO CallbackInfo;
    PPENDING_IRP PendingIrp;
} PAGED_WRITE_REQUEST, *PPAGED_WRITE_REQUEST;

static BOOLEAN CiPagedWriteCallback(IN PPENDING_IRP PendingIrp,
				    IN OUT PVOID Context,
				    IN BOOLEAN Completion)
{
    assert(PendingIrp);
    assert(Context);
    assert(Completion);
    IO_STATUS_BLOCK IoStatus = PendingIrp->IoResponseStatus;
    PPAGED_WRITE_REQUEST Req = Context;
    assert(Req->PendingIrp == PendingIrp);

    RemoveEntryList(&Req->Link);
    if (!NT_SUCCESS(IoStatus.Status)) {
	Req->CallbackInfo->IoStatus = IoStatus;
	CiSetSharedMapDirtyBits(Req->CallbackInfo->VolumeDevice->Vcb->VolumeFcb,
				Req->VolumeFileOffset, Req->Length, TRUE);
    }
    if (IsListEmpty(&Req->CallbackInfo->ReqList)) {
	Req->CallbackInfo->Callback(Req->CallbackInfo->VolumeDevice,
				    Req->CallbackInfo->FileObject,
				    Req->CallbackInfo->IoStatus,
				    Req->CallbackInfo->Context);
	CiFreePool(Req->CallbackInfo);
    }
    IopCleanupPendingIrp(PendingIrp);
    CiFreePool(Req);
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
    PFLUSH_CACHE_CALLBACK_INFO CallbackInfo = CiAllocatePool(sizeof(FLUSH_CACHE_CALLBACK_INFO));
    if (!CallbackInfo) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    InitializeListHead(&CallbackInfo->ReqList);
    CallbackInfo->VolumeDevice = VolumeDevice;
    CallbackInfo->FileObject = FileObject;
    CallbackInfo->Callback = Callback;
    CallbackInfo->Context = Context;

    /* For each dirty file block of the volume FCB, generate a WRITE IRP for the disk. */
    PPAGED_WRITE_REQUEST Req = NULL;
    assert(VolumeFcb->SharedCacheMap);
    LoopOverView(View, VolumeFcb->SharedCacheMap) {
	if (!View->DirtyMap) {
	    continue;
	}
	ULONG DirtyBitStart = RtlFindLeastSignificantBit(View->DirtyMap);
	assert(DirtyBitStart < 64);
	ULONG DirtyBitEnd = RtlFindMostSignificantBit(View->DirtyMap);
	assert(DirtyBitEnd < 64);
	assert(DirtyBitEnd >= DirtyBitStart);
	ULONG ViewOffset = DirtyBitStart * PAGE_SIZE;
	ULONG64 VolumeFileOffset = View->Node.Key + ViewOffset;
	MWORD MappedAddress = (MWORD)View->MappedAddress + ViewOffset;
	ULONG WriteLength = (DirtyBitEnd - DirtyBitStart + 1) * PAGE_SIZE;
	/* If the current write request is contiguous with the previous one, simply
	 * extend the previous write request. */
	if (Req && Req->MappedAddress + Req->Length == MappedAddress) {
	    assert(Req->VolumeFileOffset + Req->Length == VolumeFileOffset);
	    Req->Length += WriteLength;
	    /* Clear the dirty bits so future calls to this routine won't generate
	     * unnecessary WRITE (unless pages are dirty again, or if WRITE failed). */
	    CiSetSharedMapDirtyBits(VolumeFcb, VolumeFileOffset, WriteLength, FALSE);
	    continue;
	}
	/* Otherwise, we need to allocate a new PAGED_WRITE_REQUEST. */
	Req = CiAllocatePool(sizeof(PAGED_WRITE_REQUEST));
	if (!Req) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    CallbackInfo->IoStatus.Status = Status;
	    break;
	}
	InsertTailList(&CallbackInfo->ReqList, &Req->Link);
	Req->CallbackInfo = CallbackInfo;
	Req->VolumeFileOffset = VolumeFileOffset;
	Req->Length = WriteLength;
	Req->MappedAddress = MappedAddress;
	CiSetSharedMapDirtyBits(VolumeFcb, VolumeFileOffset, WriteLength, FALSE);
    }

    LoopOverList(Req, &CallbackInfo->ReqList, PAGED_WRITE_REQUEST, Link) {
	IO_REQUEST_PARAMETERS Irp = {
	    .Flags = IOP_IRP_COMPLETION_CALLBACK,
	    .Device.Object = Fcb->Vcb->StorageDevice,
	    .File.Object = NULL,
	    .MajorFunction = IRP_MJ_WRITE,
	    .InputBuffer = Req->MappedAddress,
	    .InputBufferLength = Req->Length,
	    .Write.ByteOffset.QuadPart = Req->VolumeFileOffset,
	    .ServerPrivate = {
		.Callback = CiPagedWriteCallback,
		.Context = Req
	    }
	};
	Status = IopCallDriver(IOP_PAGING_IO_REQUESTOR, &Irp, &Req->PendingIrp);
	if (!NT_SUCCESS(Status)) {
	    CallbackInfo->IoStatus.Status = Status;
	    CiSetSharedMapDirtyBits(VolumeFcb, Req->VolumeFileOffset, Req->Length, TRUE);
	    RemoveEntryList(&Req->Link);
	    CiFreePool(Req);
	}
    }

out:
    if (CallbackInfo && !NT_SUCCESS(CallbackInfo->IoStatus.Status)) {
	Status = CallbackInfo->IoStatus.Status;
    }
    if (!CallbackInfo || IsListEmpty(&CallbackInfo->ReqList)) {
	IO_STATUS_BLOCK IoStatus = { .Status = Status };
	Callback(VolumeDevice, FileObject, IoStatus, Context);
	if (CallbackInfo) {
	    CiFreePool(CallbackInfo);
	}
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
    ULONG64 EndOffset = min(AlignedOffset + VIEW_SIZE, FileSize);
    ULONG MappedViewSize = EndOffset - AlignedOffset;
    ULONG MappedLength = 0;
    if (View->MappedSize < MappedViewSize && DriverObject) {
	ULONG WindowSize = 0;
	PVOID Buffer = NULL;
	NTSTATUS Status = CcMapData(Fcb, AlignedOffset, VIEW_SIZE, &WindowSize, &Buffer);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	assert(WindowSize == MappedViewSize);
	extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
	Status = MmMapMirroredMemory(&MiNtosVaddrSpace, (MWORD)Buffer,
				     View->CacheMap->CacheSpace->AddrSpace,
				     View->MappedAddress, MappedViewSize, MM_RIGHTS_RW);
	if (NT_SUCCESS(Status)) {
	    View->MappedSize = MappedViewSize;
	}
    }
    MappedLength = min(AlignedOffset + View->MappedSize - FileOffset, Length);

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

typedef enum _COPY_TYPE {
    CopyRead,
    CopyWrite,
    CopyZero
} COPY_TYPE;

/*
 * Map the given length of the file object and copy to/from the given buffer.
 * Write == TRUE means copying from the buffer to the cache.
 * For partial copies, an error status is returned.
 */
static NTSTATUS CiCopyReadWrite(IN PIO_FILE_CONTROL_BLOCK Fcb,
				IN ULONG64 FileOffset,
				IN ULONG64 Length,
				IN COPY_TYPE Type,
				OUT OPTIONAL ULONG64 *pBytesCopied,
				OUT PVOID Buffer)
{
    assert(Fcb);
    assert(Length);
    assert(Type == CopyZero || Buffer);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG64 BytesCopied = 0;
    while ((LONG64)Length > 0) {
	ULONG MappedLength = 0;
	PVOID MappedBuffer = NULL;
	Status = CcMapDataEx(NULL, Fcb, FileOffset, Length,
			     &MappedLength, &MappedBuffer, Type != CopyRead);
	if (!NT_SUCCESS(Status)) {
	    break;
	}
	assert(MappedLength);
	assert(MappedLength <= Length);
	if (Type == CopyWrite) {
	    memcpy(MappedBuffer, Buffer, MappedLength);
	} else if (Type == CopyRead) {
	    memcpy(Buffer, MappedBuffer, MappedLength);
	} else {
	    assert(Type == CopyZero);
	    memset(MappedBuffer, 0, MappedLength);
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
    return CiCopyReadWrite(Fcb, FileOffset, Length, CopyRead, pBytesRead, Buffer);
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
    return CiCopyReadWrite(Fcb, FileOffset, Length, CopyWrite, pBytesWritten, Buffer);
}

NTSTATUS CcZeroData(IN PIO_FILE_CONTROL_BLOCK Fcb,
		    IN ULONG64 FileOffset,
		    IN ULONG64 Length)
{
    return CiCopyReadWrite(Fcb, FileOffset, Length, CopyZero, NULL, NULL);
}
