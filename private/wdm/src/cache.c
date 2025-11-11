#include <wdmp.h>
#include <avltree.h>

static LIST_ENTRY CiDirtyBufferList;
static LIST_ENTRY CiFlushCacheRequestList;

VOID CiInitialzeCacheManager()
{
    InitializeListHead(&CiDirtyBufferList);
    InitializeListHead(&CiFlushCacheRequestList);
}

/*
 * Cache Map.
 *
 * This structure describes the cache mapping of a file control block, with all
 * buffer control blocks (see below) organized as an AVL tree.
 */
typedef struct _CACHE_MAP {
    PFSRTL_COMMON_FCB_HEADER Fcb; /* Pointer to the FCB of the file object being cached. */
    PVPB Vpb;	   /* Volume parameter block of the mounted volume. */
    AVL_TREE BcbTree; /* Tree of buffer control blocks, ordered by starting file offset. */
    LIST_ENTRY Link;  /* List link for the list of all cache maps */
} CACHE_MAP, *PCACHE_MAP;

/*
 * Buffer Control Block.
 *
 * A buffer control block (BCB) describes a contiguous region of a cache-enabled file
 * object that is mapped contiguously in virtual memory. The server caches file objects
 * in terms of view blocks which are 256KB (assuming the page size is 4K) contiguous
 * file blocks. These file blocks are mapped into the driver address space with 256KB
 * (for 4K page size)-aligned address windows. The server-side file objects include
 * ordinary file objects created as a result of a CREATE IRP call to the file system
 * and the volume file object that represents the entire data stream of the underlying
 * volume device object.
 *
 * Additionally, file system drivers make extensive usage of the so-called "stream file
 * objects" in order to access on-disk FS metadata with the benefit of caching. These
 * stream file objects are purely client-side objects and do not have a corresponding
 * server-side object. Instead they are simply a collection of remapped file blocks
 * of the volume file object. When the file system drive requests the cache manager
 * to map these stream file objects for cached access, the cache manager will generate
 * a READ IRP for the file block to be mapped, which will be dispatched locally back
 * to the file system driver. The file system driver will then translate the READ IRP
 * for the stream file into a series of READ IRPs for the volume file object, and
 * forward these IRPs to the server. The server will then map the volume file blocks
 * (using the 256KB views described above) into the client. In this case, if the FS
 * cluster size is smaller than PAGE_SIZE, a mapped page of the stream file object may
 * contain data from other (possibly non-stream) file objects. A schematic diagram of
 * such file mappings may look like:
 *
 *     |-------------------------------------------------------------------|
 *     |   Cluster0  |   Cluster1  ,         Cluster2        |   Cluster3  |
 *     |   FileObj0  |   FileObj1  ,         FileObj1        |   FileObj2  |
 *     | FileOffset0 | FileOffset1 , FileOffset1+ClusterSize | FileOffset2 |
 *     |-------------------------------------------------------------------|
 *     ^             ^                                       ^             ^
 *     Page start    MappedAddress                           |             Page end
 *                                            (MappedAddress + 2*ClusterSize)
 *
 * In the scenario above, one page contains four FS clusters. This particular
 * page contains clusters from three different file objects. The BCB describing
 * the file region [FileOffset1, FileOffset1 + 2*ClusterSize) for FileObj1 will
 * have Node.Key == FileOffset1 with Length == 2*ClusterSize, and MappedAddress
 * == PageStart + ClusterSize.
 */
typedef struct _BUFFER_CONTROL_BLOCK {
    AVL_NODE Node; /* Key is the starting file offset of the buffer.
		    * This is always aligned by FS cluster size.
		    * Must be the first member in this struct. */
    PVOID MappedAddress; /* Where the buffer is mapped to in memory.
			  * Always cluster size aligned. */
    MWORD Length;     /* Length of the buffer in terms of file offset.
		       * Always cluster size aligned. */
    PCACHE_MAP CacheMap;   /* The cache map this BCB belongs to. */
    LIST_ENTRY PinList;	 /* List of pinned sub-buffers of this BCB. */
} BUFFER_CONTROL_BLOCK, *PBUFFER_CONTROL_BLOCK;

/* We set the cache readahead size to the view size because server always map
 * a full view. */
#define READAHEAD_SIZE	(VIEW_SIZE)

FORCEINLINE VOID CiInitializeBcb(IN PBUFFER_CONTROL_BLOCK Bcb,
				 IN ULONG64 FileOffset,
				 IN PVOID MappedAddress,
				 IN MWORD Length,
				 IN PCACHE_MAP CacheMap)
{
    AvlInitializeNode(&Bcb->Node, FileOffset);
    Bcb->MappedAddress = MappedAddress;
    Bcb->Length = Length;
    Bcb->CacheMap = CacheMap;
    InitializeListHead(&Bcb->PinList);
}

/*
 * This structure describes a pinned sub-buffer of a parent BCB. We hand this
 * to the client driver so CcUnpinData has all the information to unpin the
 * sub-buffer.
 */
typedef struct _PINNED_BUFFER {
    PBUFFER_CONTROL_BLOCK Bcb; /* Not NULL only if Link is in PinList of BCB */
    ULONG64 FileOffset;
    PVOID MappedAddress;
    MWORD Length;
    LIST_ENTRY Link;
    BOOLEAN Dirty;	 /* If TRUE, data need to be flushed. */
} PINNED_BUFFER, *PPINNED_BUFFER;

#define AVL_NODE_TO_BCB(_Node)					\
    ({								\
	PAVL_NODE __node = (_Node);				\
	__node ? CONTAINING_RECORD(__node,			\
				   BUFFER_CONTROL_BLOCK,	\
				   Node) : NULL;		\
    })

#define NEXT_BCB(_Node)					\
    AVL_NODE_TO_BCB(AvlGetNextNodeSafe(&(_Node)->Node))

/*
 * READ request that is generated to fill the given BCB.
 */
typedef struct _READ_REQUEST {
    PIRP Irp;
    PBUFFER_CONTROL_BLOCK Bcb;
    LIST_ENTRY Link;
} READ_REQUEST, *PREAD_REQUEST;

/*
 * ROUTINE DESCRIPTION:
 *     Initializes caching for a file object.
 *
 * ARGUMENTS:
 *     FileObject - A pointer to the file object to enable caching for.
 *
 * RETURNS:
 *     STATUS_SUCCESS if caching is successfully enabled. Error status if
 *     an error has occurred.
 *
 * REMARKS:
 *     Driver should set the FsContext member of the FILE_OBJECT to the
 *     file control block (with FSRTL_COMMON_FCB_HEADER at the beginning)
 *     and set the FileSizes of the common FCB header appropriately before
 *     calling this routine. Additionally, the underlying volume device
 *     needs to be mounted before initializing cache support.
 */
NTAPI NTSTATUS CcInitializeCacheMap(IN PFILE_OBJECT FileObject)
{
    assert(FileObject);
    PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    assert(DeviceObject);
    PVPB Vpb = DeviceObject->Vpb;
    if (!Vpb || !Vpb->RealDevice) {
	/* Volume device must be mounted before calling this routine. */
	assert(FALSE);
	return STATUS_INVALID_DEVICE_REQUEST;
    }
    PFSRTL_COMMON_FCB_HEADER Fcb = FileObject->FsContext;
    if (!Fcb) {
	assert(FALSE);
	return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (Fcb->CacheMap) {
	assert(FALSE);
	return STATUS_ALREADY_INITIALIZED;
    }
    PCACHE_MAP CacheMap = ExAllocatePool(NonPagedPool, sizeof(CACHE_MAP));
    if (!CacheMap) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    CacheMap->Fcb = Fcb;
    CacheMap->Vpb = Vpb;
    AvlInitializeTree(&CacheMap->BcbTree);
    Fcb->CacheMap = CacheMap;
    return STATUS_SUCCESS;
}

NTAPI BOOLEAN CcUninitializeCacheMap(IN PFILE_OBJECT FileObject,
				     IN OPTIONAL PLARGE_INTEGER TruncateSize)
{
    assert(FileObject);
    PFSRTL_COMMON_FCB_HEADER Fcb = FileObject->FsContext;
    /* If the file object does not have caching initialized, return success. */
    if (!Fcb || !Fcb->CacheMap) {
	return TRUE;
    }
    assert(FileObject->DeviceObject);
    PCACHE_MAP CacheMap = Fcb->CacheMap;
    PAVL_NODE Node = NULL;
    while ((Node = AvlGetFirstNode(&CacheMap->BcbTree)) != NULL) {
	PBUFFER_CONTROL_BLOCK Bcb = AVL_NODE_TO_BCB(Node);
	LoopOverList(Buf, &Bcb->PinList, PINNED_BUFFER, Link) {
	    /* Cache map should not have any pinned buffer at this point.
	     * On release build we simply delete them. */
	    assert(FALSE);
	    RemoveEntryList(&Buf->Link);
	    ExFreePool(Buf);
	}
	AvlTreeRemoveNode(&CacheMap->BcbTree, Node);
	ExFreePool(Bcb);
    }
    ExFreePool(CacheMap);
    Fcb->CacheMap = NULL;
    return TRUE;
}

static NTSTATUS NTAPI CiReadCompleted(IN PDEVICE_OBJECT DeviceObject,
				      IN PIRP Irp,
				      IN OPTIONAL PVOID Context)
{
    PREAD_REQUEST Req = Context;
    assert(Req);
    PIO_STACK_LOCATION Stack = IoGetNextIrpStackLocation(Irp);
    if (!NT_SUCCESS(Irp->IoStatus.Status)) {
	DPRINT("IO failed!!! Error code: %x, FileObj %p DeviceObj %p, "
	       "ReadOffset 0x%llx, ReadLength 0x%x\n",
	       Irp->IoStatus.Status, Stack->FileObject, Stack->DeviceObject,
	       Stack->Parameters.Read.ByteOffset.QuadPart,
	       Stack->Parameters.Read.Length);
	return STATUS_CONTINUE_COMPLETION;
    }
    DPRINT("Block request succeeded for %p. Requested length 0x%x fulfilled length 0x%zx\n",
	   Irp, Stack->Parameters.Read.Length, Irp->IoStatus.Information);
    assert(Irp->IoStatus.Information);
    assert(Irp->IoStatus.Information <= Stack->Parameters.Read.Length);
    /* Adjust the BCB to the actual length mapped. */
    PMDL Mdl = Irp->MdlAddress;
    assert(Mdl);
    Req->Bcb->MappedAddress = Mdl->MappedSystemVa;
    Req->Bcb->Length = Mdl->ByteCount;
    /* If there are additional MDLs in the MDL chain, create new BCBs and insert
     * them after this BCB. */
    ULONG64 FileOffset = Req->Bcb->Node.Key + Req->Bcb->Length;
    while ((Mdl = Mdl->Next) != NULL) {
	PREAD_REQUEST NewReq = ExAllocatePool(NonPagedPool, sizeof(READ_REQUEST));
	if (!NewReq) {
	    break;
	}
	PBUFFER_CONTROL_BLOCK NewBcb = ExAllocatePool(NonPagedPool,
						      sizeof(BUFFER_CONTROL_BLOCK));
	if (!NewBcb) {
	    ExFreePool(NewReq);
	    break;
	}
	NewReq->Bcb = NewBcb;
	CiInitializeBcb(NewBcb, FileOffset, Mdl->MappedSystemVa, Mdl->ByteCount,
			Req->Bcb->CacheMap);
	InsertHeadList(&Req->Link, &NewReq->Link);
	FileOffset += Mdl->ByteCount;
    }
    return STATUS_CONTINUE_COMPLETION;
}

/*
 * Returns true if Prev and Bcb are adjacent in both file offset and mapped addresses.
 * These BCBs will be merged when mapping file objects for cached access. It is important
 * to stress that BCBs that are only adjacent in file offsets but not in mapped addresses
 * will NOT be merged.
 */
FORCEINLINE BOOLEAN CiAdjacentBcbs(IN PBUFFER_CONTROL_BLOCK Prev,
				   IN PBUFFER_CONTROL_BLOCK Bcb)
{
    return ((Prev->Node.Key + Prev->Length) == Bcb->Node.Key)
	&& (((PUCHAR)Prev->MappedAddress + Prev->Length) == Bcb->MappedAddress);
}

/*
 * ROUTINE DESCRIPTION:
 *     Map a contiguous region of a file object into memory.
 *
 * ARGUMENTS:
 *     FileObject   - A pointer to a file object with caching enabled
 *                    that is to be mapped.
 *     FileOffset   - A pointer to a variable that specifies the starting
 *                    byte offset within the cached file.
 *     Length       - The length in bytes of the data to be mapped.
 *     Flags        - If zero, the routine will return immediately with
 *                    an error status if the region to be mapped have not
 *                    already been mapped into local memory. If set to
 *                    MAP_WAIT, the routine will make the necessary server
 *                    calls to map the required data.
 *     MappedLength - Length that is successfully mapped.
 *     Bcb          - A pointer to the buffer control block representing
 *                    the mapped data.
 *     pBuffer      - The starting address of the mapped buffer.
 *
 * RETURNS:
 *     STATUS_SUCCESS if the data region [FileOffset, FileOffset+Length)
 *     has been successfully mapped. STATUS_SOME_NOT_MAPPED if part of the
 *     specified file region (starting from FileOffset) has been mapped,
 *     in which case *MappedLength contains the successfully mapped length.
 *     In this case the caller should call CcMapData again to map the region
 *     from FileOffset + *MappedLength. Error status if an IO error has
 *     occurred.
 *
 * REMARKS:
 *     Due to the alias-free design (see the Developer Guide for details),
 *     of the Neptune OS cache manager, the CcMapData will only map the
 *     specified file region up till the point where it is contiguous on the
 *     underlying disk storage. If the entire region specified by FileOffset
 *     and Length is contiguous on the disk, CcMapData returns STATUS_SUCCESS
 *     if mapping is successful. Otherwise, it returns STATUS_SOME_NOT_MAPPED,
 *     and *MappedLength will contain the number of bytes mapped.
 *
 *     Note that STATUS_SOME_NOT_MAPPED is an NT_SUCCESS status.
 */
NTAPI NTSTATUS CcMapData(IN PFILE_OBJECT FileObject,
			 IN PLARGE_INTEGER FileOffset,
			 IN ULONG Length,
			 IN ULONG Flags,
			 OUT ULONG *MappedLength,
			 OUT PVOID *pBcb,
			 OUT PVOID *pBuffer)
{
    assert(FileObject);
    PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    assert(DeviceObject);
    PVPB Vpb = DeviceObject->Vpb;
    if (!Vpb || !Vpb->RealDevice || !Vpb->DeviceObject) {
	/* Volume device must be mounted before calling this routine. */
	assert(FALSE);
	return STATUS_INVALID_DEVICE_REQUEST;
    }
    PFSRTL_COMMON_FCB_HEADER Fcb = FileObject->FsContext;
    if (!Fcb) {
	assert(FALSE);
	return STATUS_INVALID_DEVICE_REQUEST;
    }
    PCACHE_MAP CacheMap = Fcb->CacheMap;
    if (!CacheMap) {
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* In order to reduce the number of IRPs we need to send below, we align the read
     * to the view size. */
    ULONG64 AlignedOffset = ALIGN_DOWN_64(FileOffset->QuadPart, READAHEAD_SIZE);
    ULONG64 EndOffset = ALIGN_UP_64(FileOffset->QuadPart + Length, READAHEAD_SIZE);
    if (EndOffset > Fcb->FileSizes.FileSize.QuadPart) {
	EndOffset = Fcb->FileSizes.FileSize.QuadPart;
    }

    /* Build a list of file regions for which locally cached file data do not exist
     * and therefore a server call is needed to get the file data. */
    LIST_ENTRY ReqList;
    InitializeListHead(&ReqList);

    /* If the caller did not specify MAP_WAIT, do not call server. */
    if (!(Flags & MAP_WAIT)) {
	goto map;
    }

    /* Allocate a BCB for each unmapped sub-region. For each new BCB, generate a
     * REAR IRP. The first IRP is the master IRP, and all subsequent IRPs are
     * marked as its associated IRPs. The minor code will be set to IRP_MN_MDL so
     * the server will return the MDL for the memory pages. */
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG64 CurrentOffset = AlignedOffset;
    PBUFFER_CONTROL_BLOCK CurrentBcb = AVL_NODE_TO_BCB(
	AvlTreeFindNodeOrPrev(&CacheMap->BcbTree, AlignedOffset));
    PIRP FirstIrp = NULL;
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    while (CurrentOffset < EndOffset) {
	/* Determine the starting file offset of the new BCB. */
	if (CurrentBcb && AvlNodeContainsAddr(&CurrentBcb->Node,
					      CurrentBcb->Length, CurrentOffset)) {
	    CurrentOffset += CurrentBcb->Length;
	}
	if (CurrentOffset >= EndOffset) {
	    break;
	}
	/* Determine the length of the current segment of the IO transfer. */
	ULONG CurrentLength = EndOffset - CurrentOffset;
	PBUFFER_CONTROL_BLOCK NextBcb = AVL_NODE_TO_BCB(AvlGetNextNodeSafe(&CurrentBcb->Node));
	if (NextBcb && EndOffset > NextBcb->Node.Key) {
	    CurrentLength = NextBcb->Node.Key - CurrentOffset;
	}
	PBUFFER_CONTROL_BLOCK NewBcb = ExAllocatePool(NonPagedPool,
						      sizeof(BUFFER_CONTROL_BLOCK));
	if (!NewBcb) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	CiInitializeBcb(NewBcb, CurrentOffset, NULL, 0, CacheMap);
	PREAD_REQUEST Req = ExAllocatePool(NonPagedPool, sizeof(READ_REQUEST));
	if (!Req) {
	    ExFreePool(NewBcb);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	Req->Bcb = NewBcb;
	LARGE_INTEGER ReadOffset = { .QuadPart = CurrentOffset };
	DPRINT("CcMapData(FileObj %p, DeviceObj %p, FileOffset 0x%llx, Length 0x%x)"
	       "Building IRP ReadOffset 0x%llx, ReadLength 0x%x\n",
	       FileObject, Vpb->DeviceObject, FileOffset->QuadPart, Length,
	       CurrentOffset, CurrentLength);
	Req->Irp = IoBuildAsynchronousFsdRequest(IRP_MJ_READ, Vpb->DeviceObject, NULL,
						 CurrentLength, &ReadOffset, NULL);
	if (!Req->Irp) {
	    ExFreePool(NewBcb);
	    ExFreePool(Req);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	if (FirstIrp) {
	    Req->Irp->MasterIrp = FirstIrp;
	} else {
	    FirstIrp = Req->Irp;
	    FirstIrp->UserEvent = &Event;
	}
	PIO_STACK_LOCATION Stack = IoGetNextIrpStackLocation(Req->Irp);
	Stack->FileObject = FileObject;
	ObReferenceObject(FileObject);
	IoSetCompletionRoutine(Req->Irp, CiReadCompleted, Req, TRUE, TRUE, TRUE);
	InsertTailList(&ReqList, &Req->Link);
	CurrentBcb = NextBcb;
	CurrentOffset += CurrentLength;
    }

    /* Forward the IRPs to the lower driver. Wait on the first IRP. */
    LoopOverList(Req, &ReqList, READ_REQUEST, Link) {
	DPRINT("Calling storage device driver with irp %p\n", Req->Irp);
	Status = IoCallDriver(Vpb->DeviceObject, Req->Irp);
	if (!NT_SUCCESS(Status)) {
	    DPRINT("IoCallDriver failed with error code %x\n", Status);
	    Req->Bcb->Length = 0;
	}
    }

    /* Wait for the IO to complete. Note this event is only signaled if all IRPs
     * have been completed. */
    if (!IsListEmpty(&ReqList)) {
	KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
    }

    /* Now that all IO operations are done, insert the BCBs into the cache map.
     * We need to see if any of the resulting BCBs are adjacent (in both file
     * offset and mapped address) with existing BCBs, in which case we merge
     * them. */
    LoopOverList(Req, &ReqList, READ_REQUEST, Link) {
	/* If the IO errored out, do nothing and simply clean up this BCB. */
	if (!Req->Bcb->Length) {
	    goto free;
	}
	PAVL_NODE Parent = NULL;
	PBUFFER_CONTROL_BLOCK Prev = AVL_NODE_TO_BCB(
	    AvlTreeFindNodeOrPrevEx(&CacheMap->BcbTree, Req->Bcb->Node.Key, &Parent));
	PBUFFER_CONTROL_BLOCK Next = NEXT_BCB(Prev);
	if (Prev && CiAdjacentBcbs(Prev, Req->Bcb)) {
	    Prev->Length += Req->Bcb->Length;
	    /* If after merging the previous BCB and current BCB, the new BCB
	     * is adjacent to the next BCB, we should detach the next BCB from
	     * the cache map and merge it with the newly merged BCB. */
	    if (Next && CiAdjacentBcbs(Prev, Next)) {
		AvlTreeRemoveNode(&CacheMap->BcbTree, &Next->Node);
		Prev->Length += Next->Length;
		/* Move the pinned buffer objects from Next to Prev */
		LoopOverList(Pinned, &Next->PinList, PINNED_BUFFER, Link) {
		    Pinned->Bcb = Prev;
		    RemoveEntryList(&Pinned->Link);
		    InsertTailList(&Prev->PinList, &Pinned->Link);
		}
		ExFreePool(Next);
	    }
	} else if (Next && CiAdjacentBcbs(Req->Bcb, Next)) {
	    Next->Node.Key = Req->Bcb->Node.Key;
	    Next->MappedAddress = Req->Bcb->MappedAddress;
	    Next->Length += Req->Bcb->Length;
	} else {
	    /* Neither the previous BCB or the next BCB is adjacent to the
	     * current BCB. Insert it into the tree. */
	    AvlTreeInsertNode(&CacheMap->BcbTree, Parent, &Req->Bcb->Node);
	    Req->Bcb = NULL;
	}
    free:
	RemoveEntryList(&Req->Link);
	/* For IRPs that we have called IoCallDriver on (regardless of whether
	 * it succeeded), it is freed by the system automatically when completing
	 * the IRP, so we don't free it manually. */
	Req->Irp = NULL;
	if (Req->Bcb) {
	    ExFreePool(Req->Bcb);
	}
	ExFreePool(Req);
    }

map:
    PBUFFER_CONTROL_BLOCK Bcb = AVL_NODE_TO_BCB(AvlTreeFindNodeOrPrev(&CacheMap->BcbTree,
								      AlignedOffset));
    if (!Bcb || !AvlNodeContainsAddr(&Bcb->Node, Bcb->Length, AlignedOffset)) {
	return NT_SUCCESS(Status) ? STATUS_NONE_MAPPED : Status;
    }
    PPINNED_BUFFER PinnedBuf = ExAllocatePool(NonPagedPool, sizeof(PINNED_BUFFER));
    if (!PinnedBuf) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    *MappedLength = min(Length, Bcb->Length - (FileOffset->QuadPart - Bcb->Node.Key));
    *pBuffer = (PUCHAR)Bcb->MappedAddress + (FileOffset->QuadPart - Bcb->Node.Key);
    *pBcb = PinnedBuf;
    PinnedBuf->Bcb = Bcb;
    PinnedBuf->FileOffset = FileOffset->QuadPart;
    PinnedBuf->MappedAddress = *pBuffer;
    PinnedBuf->Length = *MappedLength;
    InsertHeadList(&Bcb->PinList, &PinnedBuf->Link);
    if (NT_SUCCESS(Status)) {
	Status = (*MappedLength == Length) ? STATUS_SUCCESS : STATUS_SOME_NOT_MAPPED;
    }

out:
    /* Free all the allocated BCBs that have not been inserted into the cache map. */
    LoopOverList(Req, &ReqList, READ_REQUEST, Link) {
	if (Req->Bcb) {
	    ExFreePool(Req->Bcb);
	}
	if (Req->Irp) {
	    ExFreePool(Req->Irp);
	}
	ExFreePool(Req);
    }
    return Status;
}

NTAPI VOID CcSetDirtyData(IN PVOID Context)
{
    PPINNED_BUFFER PinnedBuf = Context;
    assert(PinnedBuf);
    PinnedBuf->Dirty = TRUE;
}

NTAPI VOID CcUnpinData(IN PVOID Context)
{
    PPINNED_BUFFER PinnedBuf = Context;
    assert(PinnedBuf);
    RemoveEntryList(&PinnedBuf->Link);
    /* If the PINNED_BUFFER is marked dirty, we need to add it to the dirty buffer
     * list so we can inform the server of the dirty status. */
    if (PinnedBuf->Dirty) {
	PinnedBuf->Bcb = NULL;
	InsertHeadList(&CiDirtyBufferList, &PinnedBuf->Link);
    } else {
	ExFreePool(PinnedBuf);
    }
}

ULONG CiProcessDirtyBufferList(IN ULONG RemainingBufferSize,
			       IN PIO_PACKET DestIrp)
{
    ULONG MaxMsgCount = RemainingBufferSize / sizeof(IO_PACKET);
    if (!MaxMsgCount) {
	return 0;
    }
    ULONG MsgCount = 0;
    ULONG BufCount = 0;
    LoopOverList(PinnedBuf, &CiDirtyBufferList, PINNED_BUFFER, Link) {
	MWORD ProcessedLength = 0;
	while (ProcessedLength < PinnedBuf->Length) {
	    MWORD ViewAddress = VIEW_ALIGN(PinnedBuf->MappedAddress);
	    ULONG ViewLength = min(ViewAddress + VIEW_SIZE - (MWORD)PinnedBuf->MappedAddress,
				   PinnedBuf->Length - ProcessedLength);
	    ULONG ViewOffset = (MWORD)PinnedBuf->MappedAddress - ViewAddress;
	    assert(ViewOffset < VIEW_SIZE);
	    ULONG StartPage = ViewOffset >> PAGE_LOG2SIZE;
	    ULONG EndPage = PAGE_ALIGN_UP(ViewOffset + ViewLength) >> PAGE_LOG2SIZE;
	    assert(StartPage < PAGES_IN_VIEW);
	    assert(EndPage <= PAGES_IN_VIEW);
	    ULONG64 DirtyBits = 0;
	    for (ULONG i = StartPage; i < EndPage; i++) {
		SetBit64(DirtyBits, i);
	    }

	    /* If the view address has already been recorded, update its dirty bits. */
	    for (ULONG i = 0; i <= MsgCount; i++) {
		for (ULONG j = 0; j < BufCount; j++) {
		    if (DestIrp[i].ClientMsg.DirtyBuffers[j].ViewAddress == ViewAddress) {
			DestIrp[i].ClientMsg.DirtyBuffers[j].DirtyBits |= DirtyBits;
			goto next;
		    }
		}
	    }

	    /* Otherwise, add a new entry for the view in the message. */
	    DestIrp[MsgCount].ClientMsg.DirtyBuffers[BufCount].ViewAddress = ViewAddress;
	    DestIrp[MsgCount].ClientMsg.DirtyBuffers[BufCount].DirtyBits = DirtyBits;
	    BufCount++;
	next:
	    ProcessedLength += ViewLength;
	    if (BufCount >= IO_CLI_MSG_MAX_DIRTY_BUFFER_COUNT) {
		assert(BufCount == IO_CLI_MSG_MAX_DIRTY_BUFFER_COUNT);
		MsgCount++;
		BufCount = 0;
		if (MsgCount >= MaxMsgCount) {
		    assert(MsgCount == MaxMsgCount);
		    break;
		}
	    }
	}
	assert(ProcessedLength <= PinnedBuf->Length);
	if (ProcessedLength >= PinnedBuf->Length) {
	    assert(ProcessedLength == PinnedBuf->Length);
	    RemoveEntryList(&PinnedBuf->Link);
	    ExFreePool(PinnedBuf);
	}
	if (MsgCount >= MaxMsgCount) {
	    assert(MsgCount == MaxMsgCount);
	    break;
	}
    }
    assert(BufCount < IO_CLI_MSG_MAX_DIRTY_BUFFER_COUNT);
    if (BufCount) {
	MsgCount++;
    }
    assert(MsgCount <= MaxMsgCount);
    for (ULONG i = 0; i < MsgCount; i++) {
	DestIrp[i].Type = IoPacketTypeClientMessage;
	DestIrp[i].Size = sizeof(IO_PACKET);
	DestIrp[i].ClientMsg.Type = IoCliMsgDirtyBuffers;
    }
    if (BufCount) {
	DestIrp[MsgCount-1].ClientMsg.DirtyBuffers[BufCount].ViewAddress = 0;
	DestIrp[MsgCount-1].ClientMsg.DirtyBuffers[BufCount].DirtyBits = 0;
    }
    return MsgCount;
}

static NTSTATUS CiCopyReadWrite(IN PFILE_OBJECT FileObject,
				IN PLARGE_INTEGER FileOffset,
				IN ULONG Length,
				IN BOOLEAN Wait,
				IN OUT PVOID Buffer,
				OUT ULONG *BytesCopied,
				IN BOOLEAN Write)
{
    assert(FileObject);
    assert(FileOffset);
    assert(Buffer);
    assert(BytesCopied);
    *BytesCopied = 0;

    while (*BytesCopied < Length) {
	ULONG RemainingBytes = Length - *BytesCopied;
	LARGE_INTEGER ByteOffset = { .QuadPart = FileOffset->QuadPart + *BytesCopied };
	ULONG MappedLength = 0;
	PVOID Bcb = NULL;
	PVOID CacheBuffer = NULL;
	NTSTATUS Status = CcMapData(FileObject, &ByteOffset, RemainingBytes,
				    Wait ? MAP_WAIT : 0,
				    &MappedLength, &Bcb, &CacheBuffer);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
	assert(Bcb);
	assert(CacheBuffer);

	ULONG BytesToCopy = min(MappedLength, RemainingBytes);
	if (Write) {
	    RtlCopyMemory(CacheBuffer, (PUCHAR)Buffer + *BytesCopied, BytesToCopy);
	} else {
	    RtlCopyMemory((PUCHAR)Buffer + *BytesCopied, CacheBuffer, BytesToCopy);
	}
	*BytesCopied += BytesToCopy;
	if (Write) {
	    CcSetDirtyData(Bcb);
	}
	CcUnpinData(Bcb);
    }
    return STATUS_SUCCESS;
}

/*
 * ROUTINE DESCRIPTION:
 *     Copies data from a cached file to a user buffer.
 *
 * ARGUMENTS:
 *     FileObject   - A pointer to a file object for the cached file from
 *                    which the data is to be read.
 *     FileOffset   - A pointer to a variable that specifies the starting
 *                    byte offset within the cached file.
 *     Length       - The length in bytes of the data to be read.
 *     Wait         - If set to FALSE, the routine will return immediately
 *                    with error if the data to be read have not already
 *                    been loaded into local memory. If set to TRUE, the
 *                    routine will make the necessary server calls to load
 *                    the required data.
 *     Buffer       - A pointer to a buffer into which the data are to be copied.
 *     BytesRead    - The actual number of bytes that were copied. On success
 *                    this equals Length.
 *
 * RETURNS:
 *     STATUS_SUCCESS is the read has been completed successfully. Error
 *     status if otherwise.
 */
NTAPI NTSTATUS CcCopyRead(IN PFILE_OBJECT FileObject,
			  IN PLARGE_INTEGER FileOffset,
			  IN ULONG Length,
			  IN BOOLEAN Wait,
			  OUT PVOID Buffer,
			  OUT ULONG *BytesRead)
{
    return CiCopyReadWrite(FileObject, FileOffset, Length, Wait, Buffer, BytesRead, FALSE);
}

/*
 * ROUTINE DESCRIPTION:
 *     Copies data from a user buffer to a cached file.
 *
 * ARGUMENTS:
 *     FileObject   - A pointer to a file object for the cached file from
 *                    which the data is to be written.
 *     FileOffset   - A pointer to a variable that specifies the starting
 *                    byte offset within the cached file.
 *     Length       - The length in bytes of the data to be written.
 *     Wait         - If set to FALSE, the routine will return immediately
 *                    with error if the pages to be written have not already
 *                    been loaded into local memory. If set to TRUE, the
 *                    routine will make the necessary server calls to load
 *                    the required pages.
 *     Buffer       - A pointer to a buffer from which the data is to be copied.
 *     BytesWritten - The actual number of bytes that were written. On success
 *                    this equals Length.
 *
 * RETURNS:
 *     STATUS_SUCCESS is the write has been completed successfully. Error
 *     status if otherwise.
 */
NTAPI NTSTATUS CcCopyWrite(IN PFILE_OBJECT FileObject,
			   IN PLARGE_INTEGER FileOffset,
			   IN ULONG Length,
			   IN BOOLEAN Wait,
			   IN PVOID Buffer,
			   OUT ULONG *BytesWritten)
{
    return CiCopyReadWrite(FileObject, FileOffset, Length, Wait, Buffer, BytesWritten, TRUE);
}

/*
 * ROUTINE DESCRIPTION:
 *     Map the given file region and construct the MDL chain describing
 *     the mapping.
 *
 * ARGUMENTS:
 *     FileObject - A pointer to the file object to be mapped.
 *     FileOffset - A pointer to a variable that specifies the starting
 *                  byte offset within the cached file.
 *     Length     - The length in bytes of the data to be mapped.
 *     MdlChain   - A pointer to the MDL chain.
 *     IoStatus   - A pointer to the IO status block.
 *
 * RETURNS:
 *     STATUS_SUCCESS is the mapping has been completed successfully. Error
 *     status if otherwise. The IO information will be written to the given
 *     IO status block.
 */
NTAPI NTSTATUS CcMdlRead(IN PFILE_OBJECT FileObject,
			 IN PLARGE_INTEGER FileOffset,
			 IN ULONG Length,
			 OUT PMDL *MdlChain,
			 OUT PIO_STATUS_BLOCK IoStatus)
{
    assert(MdlChain);
    assert(IoStatus);
    ULONG MappedLength = 0;
    PPINNED_BUFFER PinnedBuf = NULL;
    PVOID Buffer = NULL;
    NTSTATUS Status = CcMapData(FileObject, FileOffset, Length, MAP_WAIT,
				&MappedLength, (PVOID *)&PinnedBuf, &Buffer);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    assert(PinnedBuf);
    assert(Buffer);
    PBUFFER_CONTROL_BLOCK Bcb = PinnedBuf->Bcb;
    CcUnpinData(PinnedBuf);
    *MdlChain = NULL;
    PMDL Mdl = ExAllocatePool(NonPagedPool, sizeof(MDL));
    if (!Mdl) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    Mdl->MappedSystemVa = Buffer;
    Mdl->ByteCount = MappedLength;
    *MdlChain = Mdl;
    assert(MappedLength <= Length);
    assert(MappedLength == Length ||
	   Bcb->Node.Key + Bcb->Length == FileOffset->QuadPart + MappedLength);
    while (MappedLength < Length) {
	Bcb = NEXT_BCB(Bcb);
	if (!Bcb || Bcb->Node.Key > FileOffset->QuadPart + MappedLength) {
	    Status = STATUS_SOME_NOT_MAPPED;
	    goto out;
	}
	PMDL NextMdl = ExAllocatePool(NonPagedPool, sizeof(MDL));
	if (!NextMdl) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	NextMdl->MappedSystemVa = Bcb->MappedAddress;
	NextMdl->ByteCount = min(Length - MappedLength, Bcb->Length);
	MappedLength += NextMdl->ByteCount;
	Mdl->Next = NextMdl;
	Mdl = NextMdl;
    }
    Status = STATUS_SUCCESS;
out:
    IoStatus->Status = Status;
    IoStatus->Information = MappedLength;
    return Status;
}

NTAPI VOID CcSetFileSizes(IN PFILE_OBJECT FileObject,
			  IN PCC_FILE_SIZES FileSizes)
{
    /* TODO! */
}

typedef struct _FLUSH_CACHE_REQUEST {
    PIOP_EXEC_ENV EnvToWakeUp;
    GLOBAL_HANDLE DeviceHandle;
    GLOBAL_HANDLE FileHandle;
    LIST_ENTRY Link;
    IO_STATUS_BLOCK IoStatus;
    BOOLEAN MsgSent;
} FLUSH_CACHE_REQUEST, *PFLUSH_CACHE_REQUEST;

NTAPI VOID CcFlushCache(IN PFILE_OBJECT FileObject,
			IN OPTIONAL PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			OUT OPTIONAL PIO_STATUS_BLOCK IoStatus)
{
    /* This routine should be called in a context where we are allowed to sleep. */
    assert(KiCurrentCoroutineStackTop);

    PFLUSH_CACHE_REQUEST Req = ExAllocatePool(NonPagedPool,
					      sizeof(FLUSH_CACHE_REQUEST));
    if (!Req) {
	if (IoStatus) {
	    IoStatus->Status = STATUS_INSUFFICIENT_RESOURCES;
	}
	return;
    }
    PFSRTL_COMMON_FCB_HEADER Fcb = FileObject->FsContext;
    PVPB Vpb = NULL;
    if (Fcb && Fcb->CacheMap) {
	Vpb = ((PCACHE_MAP)Fcb->CacheMap)->Vpb;
    } else if (FileObject->DeviceObject) {
	Vpb = FileObject->DeviceObject->Vpb;
    }
    if (!Vpb) {
	if (IoStatus) {
	    IoStatus->Status = STATUS_INVALID_PARAMETER;
	}
	return;
    }
    assert(Vpb->DeviceObject);
    Req->DeviceHandle = Vpb->DeviceObject->Header.GlobalHandle;
    Req->FileHandle = FileObject->Header.GlobalHandle;
    Req->EnvToWakeUp = IopCurrentEnv;
    InsertTailList(&CiFlushCacheRequestList, &Req->Link);

    DbgTrace("Suspending coroutine stack %p\n", KiCurrentCoroutineStackTop);
    KiYieldCoroutine();

    if (IoStatus) {
	*IoStatus = Req->IoStatus;
    }
    /* List entry is removed in CiHandleCacheFlushedServerMessage */
    ExFreePool(Req);
}

ULONG CiProcessFlushCacheRequestList(IN ULONG RemainingBufferSize,
				     IN PIO_PACKET DestIrp)
{
    ULONG MaxMsgCount = RemainingBufferSize / sizeof(IO_PACKET);
    if (!MaxMsgCount) {
	return 0;
    }
    ULONG MsgCount = 0;
    LoopOverList(Req, &CiFlushCacheRequestList, FLUSH_CACHE_REQUEST, Link) {
	if (Req->MsgSent) {
	    continue;
	}
	Req->MsgSent = TRUE;
	RtlZeroMemory(DestIrp, sizeof(IO_PACKET));
	DestIrp->Type = IoPacketTypeClientMessage;
	DestIrp->Size = sizeof(IO_PACKET);
	DestIrp->ClientMsg.Type = IoCliMsgFlushCache;
	DestIrp->ClientMsg.FlushCache.DeviceObject = Req->DeviceHandle;
	DestIrp->ClientMsg.FlushCache.FileObject = Req->FileHandle;
	MsgCount++;
	DestIrp++;
	if (MsgCount >= MaxMsgCount) {
	    assert(MsgCount == MaxMsgCount);
	    break;
	}
    }
    return MsgCount;
}

VOID CiHandleCacheFlushedServerMessage(PIO_PACKET SrvMsg)
{
    assert(SrvMsg != NULL);
    assert(SrvMsg->Type == IoPacketTypeServerMessage);
    assert(SrvMsg->ServerMsg.Type == IoSrvMsgCacheFlushed);
    ReverseLoopOverList(Req, &CiFlushCacheRequestList, FLUSH_CACHE_REQUEST, Link) {
	if (Req->DeviceHandle == SrvMsg->ServerMsg.CacheFlushed.DeviceObject &&
	    Req->FileHandle == SrvMsg->ServerMsg.CacheFlushed.FileObject) {
	    assert(Req->MsgSent);
	    assert(Req->EnvToWakeUp);
	    Req->EnvToWakeUp->Suspended = FALSE;
	    RemoveEntryList(&Req->Link);
	}
    }
}
