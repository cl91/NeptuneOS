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

#define VIEWS_PER_TABLE		(PAGE_SIZE / sizeof(PVOID))
#define VIEW_TABLE_ADDRESS_BITS	(PAGE_LOG2SIZE - MWORD_LOG2SIZE)
#define VIEW_TABLE_BITMAP_SIZE	(VIEWS_PER_TABLE / MWORD_BITS)
#define PAGES_IN_VIEW		(64)
#define VIEW_SIZE		(PAGE_SIZE * PAGES_IN_VIEW)
#define VIEW_LOG2SIZE		(PAGE_LOG2SIZE + 6)
#define VIEW_ALIGN64(p)		((ULONG64)(p) & ~((ULONG64)VIEW_SIZE - 1))
#define VIEW_ALIGN_UP64(p)	(VIEW_ALIGN64((ULONG64)(p) + VIEW_SIZE - 1))

#define CiAllocatePool(Size)	ExAllocatePoolWithTag((Size), NTOS_CC_TAG)
#define CiFreePool(Size)	ExFreePoolWithTag((Size), NTOS_CC_TAG)

/*
 * An L1 view table describes an aligned virtual memory area with
 * PAGE_SIZE/sizeof(PVOID) views. Each view may belong to different file
 * objects. An L2 view table describes an aligned virtual memory area
 * with PAGE_SIZE/sizeof(PVOID) view tables. 32-bit architectures only
 * have L1 view tables. 64-bit architectures have both.
 */
struct _CC_VIEW;
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
typedef struct _CI_FILE_OFFSET_MAPPING {
    AVL_NODE Node; /* Key is the starting file offset of the file system file object. */
    ULONG64 VolumeFileOffset; /* Starting offset of the corresponding volume file region. */
    ULONG Length; /* Length of the file region. Must be divisible by the cluster size. */
} CI_FILE_OFFSET_MAPPING, *PCI_FILE_OFFSET_MAPPING;

/*
 * A view is an area of the virtual memory space that spans 64 pages (256KB
 * on architectures with 4K pages) that maps a (64*PAGE_SIZE)-aligned file
 * region of a cached file. The virtual memory area is always aligned by
 * 64 * PAGE_SIZE. Each page in the view always maps a full PAGE-SIZE'd file
 * region.
 */
typedef struct _CC_VIEW {
    ULONG64 Bitmap;		/* Bitmap of the allocation status. */
    MWORD MappedAddress; /* This is in the address space of the cache map */
    AVL_NODE Node; /* Key is the starting file offset of this view. */
    PCC_CACHE_MAP CacheMap; /* Cache map that this view belongs to. */
    AVL_TREE FileOffsetMapping;	/* AVL tree of CI_FILE_OFFSET_MAPPING. */
} CC_VIEW, *PCC_VIEW;

#define AVL_NODE_TO_VIEW(p)	((p) ? CONTAINING_RECORD(p, CC_VIEW, Node) : NULL)

static CC_CACHE_SPACE CiNtosCacheSpace;

static NTSTATUS CiInitializeCacheSpace(IN PIO_DRIVER_OBJECT DriverObject,
				       OUT OPTIONAL PCC_CACHE_SPACE *pCacheSpace)
{
    assert(DriverObject);
    PCC_CACHE_SPACE CacheSpace = CiAllocatePool(sizeof(CC_CACHE_SPACE));
    if (!CacheSpace) {
	return STATUS_NO_MEMORY;
    }
    assert(DriverObject->DriverProcess);
    CacheSpace->AddrSpace = &DriverObject->DriverProcess->VSpace;
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
    }
    *pView = AVL_NODE_TO_VIEW(Node);
    return Node ? STATUS_SUCCESS : STATUS_NONE_MAPPED;
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
 *     *pPinnedLength - Length of the successfully pinned region.
 *
 * RETURNS:
 *     STATUS_SUCCESS if all data have been successfully loaded. Error
 *     status if an error has occurred. If only part of the file region
 *     is pinned, there are two cases:
 *       (1) If the caller specified a non-NULL pPinnedLength, we return
 *           STATUS_SOME_NOT_MAPPED. Note this is an NT_SUCCESS status.
 *       (2) If the caller did not specify a pPinnedLength, we return
 *           STATUS_NONE_MAPPED.
 */
NTSTATUS CcPinData(IN ASYNC_STATE State,
		   IN PTHREAD Thread,
		   IN PIO_FILE_CONTROL_BLOCK Fcb,
		   IN ULONG64 FileOffset,
		   IN ULONG64 Length,
		   OUT OPTIONAL ULONG64 *pPinnedLength)
{
    NTSTATUS Status;

    ASYNC_BEGIN(State, Locals, {
	    ULONG64 PinnedLength;
	});

    Locals.PinnedLength = 0;

    /* Since deviceless files are purely in-memory objects, all we need to do
     * is allocating the cache pages if they have not been allocated. */
    if (!Fcb->Vcb) {
	while (Locals.PinnedLength < Length) {
	    ULONG MappedLength = 0;
	    PVOID Buffer;
	    Status = CcMapData(Fcb, FileOffset + Locals.PinnedLength,
			       Length - Locals.PinnedLength, &MappedLength, &Buffer);
	    if (!NT_SUCCESS(Status)) {
		goto out;
	    }
	    Locals.PinnedLength += MappedLength;
	}
	Status = STATUS_SUCCESS;
	goto out;
    }

    /* UNIMPLEMENTED! */
    assert(FALSE);

out:
    if (pPinnedLength) {
	*pPinnedLength = Locals.PinnedLength;
	if (!NT_SUCCESS(Status)) {
	    Status = Locals.PinnedLength ? STATUS_SOME_NOT_MAPPED : STATUS_NONE_MAPPED;
	} else {
	    Status = STATUS_SUCCESS;
	}
    } else {
	Status = Locals.PinnedLength == Length ? STATUS_SUCCESS : STATUS_NONE_MAPPED;
    }
    ASYNC_END(State, Status);
}

VOID CcUnpinData(IN PIO_FILE_CONTROL_BLOCK Fcb,
		     IN ULONG64 FileOffset,
		     IN ULONG Length)
{
}

/*
 * ROUTINE DESCRIPTION:
 *     This routine returns the pointer to the beginning of the specified
 *     file region mapped in the shared cache map and sets *MappedLength
 *     to the mapped length (within the same view). Before calling this
 *     routine, the caller must call CcPinData to populate the shared cache
 *     map for the file region (this does not apply to deviceless file
 *     objects, as these do not have a backing file system and are simply
 *     in-memory buffers).
 *
 * ARGUMENTS:
 *     Fcb            - File control block for the file object.
 *     FileOffset     - Starting offset of the file region.
 *     Length         - Length of the file region.
 *     *pMappedLength - The length of the successfully mapped region.
 *     *Buffer        - The mapped buffer in the cache map.
 *
 * RETURNS:
 *     STATUS_SUCCESS if all data have been successfully mapped.
 *     STATUS_NONE_MAPPED if no data have been mapped or if some data have
 *       been partially mapped but the caller did not specify pMappedLength.
 *     STATUS_SOME_NOT_MAPPED if some data have been partially mapped and
 *       the caller has specified a valid pMappedLength pointer.
 *
 * REMARKS:
 *     Note STATUS_SOME_NOT_MAPPED is an NT_SUCCESS status. If pMappedLength
 *     is not specified, the routine will return failure in the case of partial
 *     mapping.
 */
NTSTATUS CcMapData(IN PIO_FILE_CONTROL_BLOCK Fcb,
		   IN ULONG64 FileOffset,
		   IN ULONG Length,
		   OUT OPTIONAL ULONG *pMappedLength,
		   OUT PVOID *Buffer)
{
    assert(Fcb);
    if (pMappedLength) {
	*pMappedLength = 0;
    }
    if (!Length) {
	return STATUS_SUCCESS;
    }
    /* Get the view in the shared cache map corresponding to this file region.
     * If the view is not mapped, for device-less files it is automatically
     * created, and in other cases an error is returned. */
    PCC_VIEW View = NULL;
    RET_ERR(CiGetView(Fcb, NULL, FileOffset, !Fcb->Vcb, &View));
    assert(View);
    ULONG64 AlignedOffset = VIEW_ALIGN64(FileOffset);
    assert(AlignedOffset == View->Node.Key);
    ULONG MappedLength = Length;
    if ((VIEW_ALIGN_UP64(FileOffset + Length) - AlignedOffset) > VIEW_SIZE) {
	MappedLength = AlignedOffset + VIEW_SIZE - FileOffset;
    }
    ULONG ViewOffset = FileOffset - AlignedOffset;
    ULONG StartPage = ViewOffset >> PAGE_LOG2SIZE;
    ULONG EndPage = PAGE_ALIGN_UP(ViewOffset + MappedLength) >> PAGE_LOG2SIZE;
    assert(StartPage < PAGES_IN_VIEW);
    assert(EndPage <= PAGES_IN_VIEW);
    for (ULONG i = StartPage; i < EndPage; i++) {
	if (!GetBit64(View->Bitmap, i)) {
	    if (Fcb->Vcb) {
		/* For files with a backing file system, if the view pages are not
		 * mapped, adjust the mapped length and return. */
		if (i == StartPage) {
		    MappedLength = 0;
		} else {
		    MappedLength = (i << PAGE_LOG2SIZE) - ViewOffset;
		}
		break;
	    } else {
		/* We are dealing with a device-less file. These are file objects
		 * that do not have a backing file system and are purely in-memory
		 * objects. In this case if the view pages are not mapped we simply
		 * allocate them. */
		NTSTATUS Status = MmCommitOwnedMemory(CiNtosCacheSpace.AddrSpace,
						      View->MappedAddress + PAGE_SIZE * i,
						      PAGE_SIZE, MM_RIGHTS_RW, FALSE, NULL, 0);
		if (!NT_SUCCESS(Status)) {
		    break;
		}
		SetBit64(View->Bitmap, i);
	    }
	}
    }
    if (!MappedLength) {
	*Buffer = NULL;
	return STATUS_NONE_MAPPED;
    }
    *Buffer = (PUCHAR)View->MappedAddress + ViewOffset;
    if (pMappedLength) {
	*pMappedLength = MappedLength;
	return MappedLength == Length ? STATUS_SUCCESS : STATUS_SOME_NOT_MAPPED;
    } else {
	return MappedLength == Length ? STATUS_SUCCESS : STATUS_NONE_MAPPED;
    }
}

/*
 * ROUTINE DESCRIPTION:
 *     If DriverObject is not NULL, this routine will map the specified
 *     file region from the shared cache map to the private cache map for
 *     the driver process. If DriverObject is NULL, this routine returns
 *     the pointer to the beginning of the file region in the shared cache
 *     map. *MappedLength will be set to the length of the successfully
 *     mapped region (within the same view). Before calling this routine,
 *     the caller must call CcPinData to populate the shared cache map for
 *     the file region.
 *
 * ARGUMENTS:
 *     DriverObject  - Driver object for the private cache map.
 *     Fcb           - File control block for the file object.
 *     FileOffset    - Starting offset of the file region.
 *     Length        - Length of the file region.
 *     *MappedLength - Length of the successfully mapped region.
 *     *Buffer       - Mapped buffer in the cache map.
 *                     Note if DriverObject is not NULL, this is a
 *                     pointer within the driver address space.
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
		     OUT ULONG *MappedLength,
		     OUT PVOID *Buffer)
{
    if (!DriverObject) {
	return CcMapData(Fcb, FileOffset, Length, MappedLength, Buffer);
    }
    UNIMPLEMENTED;
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
    assert_ret(Fcb);
    assert(Length);
    assert(Buffer);
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG64 BytesCopied = 0;
    while ((LONG64)Length > 0) {
	ULONG MappedLength = 0;
	PVOID MappedBuffer = NULL;
	Status = CcMapData(Fcb, FileOffset, Length,
			   &MappedLength, &MappedBuffer);
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
NTSTATUS CcCopyWriteEx(IN PIO_FILE_CONTROL_BLOCK Fcb,
		       IN ULONG64 FileOffset,
		       IN ULONG64 Length,
		       OUT OPTIONAL ULONG64 *pBytesWritten,
		       IN PVOID Buffer)
{
    return CiCopyReadWrite(Fcb, FileOffset, Length, TRUE, pBytesWritten, Buffer);
}
