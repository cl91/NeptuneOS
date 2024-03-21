#include <wdmp.h>
#include <avltree.h>

/*
 * Cache Map.
 *
 * This structure describes the cache mapping of a file control block, with all
 * buffer control blocks (see below) organized as an AVL tree.
 */
typedef struct _CI_CACHE_MAP {
    PFSRTL_COMMON_FCB_HEADER Fcb; /* Pointer to the FCB of the file object being cached. */
    AVL_TREE BcbTree; /* Tree of buffer control blocks, ordered by starting file offset. */
} CI_CACHE_MAP, *PCI_CACHE_MAP;

/*
 * Buffer Control Block.
 *
 * A buffer control block (BCB) describes a contiguous region of a cache-enabled
 * file object that is mapped contiguously in virtual memory. All offsets, addresses,
 * and buffer lengths are aligned by FS cluster size. The server caches file objects
 * in terms of view blocks which are 256KB (assuming the page size is 4K) contiguous
 * file blocks. These file blocks are mapped into the driver address space with 256KB
 * (for 4K page size)-aligned address windows. The server-side file objects include
 * ordinary file objects created as a result of a CREATE IRP call to the file system
 * and the volume file object that represents the entire data stream of the underlying
 * volume device object.
 *
 * However, file system drivers make extensive usage of the so-called "stream file
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
typedef struct _CI_BUFFER_CONTROL_BLOCK {
    AVL_NODE Node; /* Key is the starting file offset of the buffer.
		    * This is always aligned by FS cluster size.
		    * Must be the first member in this struct. */
    PVOID MappedAddress; /* Where the buffer is mapped to in memory.
			  * Always cluster size aligned. */
    ULONG Length;   /* Length of the buffer in terms of file offset.
		     * Always cluster size aligned. */
    PCI_CACHE_MAP CacheMap;   /* The cache map this BCB belongs to. */
    LIST_ENTRY PinList;	 /* List of pinned sub-buffers of this BCB. */
    BOOLEAN Dirty;	 /* If TRUE, data need to be flushed. */
} CI_BUFFER_CONTROL_BLOCK, *PCI_BUFFER_CONTROL_BLOCK;

FORCEINLINE VOID CiInitializeBcb(IN PCI_BUFFER_CONTROL_BLOCK Bcb,
				 IN ULONG64 FileOffset,
				 IN PVOID MappedAddress,
				 IN ULONG Length,
				 IN PCI_CACHE_MAP CacheMap)
{
    AvlInitializeNode(&Bcb->Node, FileOffset);
    Bcb->MappedAddress = MappedAddress;
    Bcb->Length = Length;
    Bcb->CacheMap = CacheMap;
    InitializeListHead(&Bcb->PinList);
    Bcb->Dirty = FALSE;
}

/*
 * This structure describes a pinned sub-buffer of a parent BCB. We hand this
 * to the client driver so CcUnpinData has all the information to unpin the
 * sub-buffer.
 */
typedef struct _CI_PINNED_BUFFER {
    PCI_BUFFER_CONTROL_BLOCK Bcb;
    ULONG64 FileOffset;
    ULONG Length;
    LIST_ENTRY Link;
} CI_PINNED_BUFFER, *PCI_PINNED_BUFFER;

#define AVL_NODE_TO_BCB(_Node)					\
    ({								\
	PAVL_NODE __node = (_Node);				\
	__node ? CONTAINING_RECORD(__node,			\
				   CI_BUFFER_CONTROL_BLOCK,	\
				   Node) : NULL;		\
    })

/*
 * READ request that is generated to fill the given BCB.
 */
typedef struct _CI_READ_REQUEST {
    PIRP Irp;
    PCI_BUFFER_CONTROL_BLOCK Bcb;
    LIST_ENTRY Link;
} CI_READ_REQUEST, *PCI_READ_REQUEST;

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
    if (!Vpb || !Vpb->RealDevice || !Vpb->ClusterSize) {
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
    PCI_CACHE_MAP CacheMap = ExAllocatePool(sizeof(CI_CACHE_MAP));
    if (!CacheMap) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    CacheMap->Fcb = Fcb;
    AvlInitializeTree(&CacheMap->BcbTree);
    Fcb->CacheMap = CacheMap;
    return STATUS_SUCCESS;
}

NTAPI BOOLEAN CcUninitializeCacheMap(IN PFILE_OBJECT FileObject,
				     IN OPTIONAL PLARGE_INTEGER TruncateSize)
{
    /* TODO */
    return TRUE;
}

static NTSTATUS NTAPI CiReadCompleted(IN PDEVICE_OBJECT DeviceObject,
				      IN PIRP Irp,
				      IN OPTIONAL PVOID Context)
{
    PCI_READ_REQUEST Req = Context;
    assert(Req);
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
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
    assert(Irp->IoStatus.Information < Stack->Parameters.Read.Length);
    /* Adjust the BCB to the actual length mapped. */
    PMDL Mdl = Irp->MdlAddress;
    assert(Mdl);
    Req->Bcb->MappedAddress = Mdl->MappedSystemVa;
    Req->Bcb->Length = Mdl->ByteCount;
    /* If there are additional MDLs in the MDL chain, create new BCBs and insert
     * them after this BCB. */
    ULONG64 FileOffset = Req->Bcb->Node.Key + Req->Bcb->Length;
    while ((Mdl = Mdl->Next) != NULL) {
	PCI_READ_REQUEST NewReq = ExAllocatePool(sizeof(CI_READ_REQUEST));
	if (!NewReq) {
	    break;
	}
	PCI_BUFFER_CONTROL_BLOCK NewBcb = ExAllocatePool(sizeof(CI_BUFFER_CONTROL_BLOCK));
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
FORCEINLINE BOOLEAN CiAdjacentBcbs(IN PCI_BUFFER_CONTROL_BLOCK Prev,
				   IN PCI_BUFFER_CONTROL_BLOCK Bcb)
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
 *     Due to the alias-free design (see the Developers' Guide for details),
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
    if (!Vpb || !Vpb->RealDevice || !Vpb->DeviceObject || !Vpb->ClusterSize) {
	/* Volume device must be mounted before calling this routine. */
	assert(FALSE);
	return STATUS_INVALID_DEVICE_REQUEST;
    }
    PFSRTL_COMMON_FCB_HEADER Fcb = FileObject->FsContext;
    if (!Fcb) {
	assert(FALSE);
	return STATUS_INVALID_DEVICE_REQUEST;
    }
    PCI_CACHE_MAP CacheMap = Fcb->CacheMap;

    /* Align the read to the cluster size of the FS. */
    ULONG64 AlignedOffset = ALIGN_DOWN_64(FileOffset->QuadPart, Vpb->ClusterSize);
    ULONG AlignedLength = ALIGN_UP_64(FileOffset->QuadPart + Length, Vpb->ClusterSize)
	- AlignedOffset;

    /* Build a list of file regions for which locally cached file data do not exist
     * and therefore we need to call server to get the file data. */
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
    ULONG64 EndOffset = AlignedOffset + AlignedLength;
    PCI_BUFFER_CONTROL_BLOCK CurrentBcb = AVL_NODE_TO_BCB(
	AvlTreeFindNodeOrPrev(&CacheMap->BcbTree, AlignedOffset));
    PIRP FirstIrp = NULL;
    IO_STATUS_BLOCK IoStatus;
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
	PCI_BUFFER_CONTROL_BLOCK NextBcb = AVL_NODE_TO_BCB(AvlGetNextNodeSafe(&CurrentBcb->Node));
	if (NextBcb && EndOffset > NextBcb->Node.Key) {
	    CurrentLength = NextBcb->Node.Key - CurrentOffset;
	}
	PCI_BUFFER_CONTROL_BLOCK NewBcb = ExAllocatePool(sizeof(CI_BUFFER_CONTROL_BLOCK));
	if (!NewBcb) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	CiInitializeBcb(NewBcb, CurrentOffset, NULL, 0, CacheMap);
	PCI_READ_REQUEST Req = ExAllocatePool(sizeof(CI_READ_REQUEST));
	if (!Req) {
	    ExFreePool(NewBcb);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	Req->Bcb = NewBcb;
	LARGE_INTEGER ReadOffset = { .QuadPart = CurrentOffset };
	DPRINT("CcMapData(FileObj %p, DeviceObj %p, FileOffset 0x%llx, Length 0x%x, "
	       "ClusterSize %d) Building IRP ReadOffset 0x%llx, ReadLength 0x%x\n",
	       FileObject, Vpb->DeviceObject, FileOffset->QuadPart, Length,
	       Vpb->ClusterSize, CurrentOffset, CurrentLength);
	Req->Irp = IoBuildAsynchronousFsdRequest(IRP_MJ_READ, Vpb->DeviceObject, NULL,
						 CurrentLength, &ReadOffset);
	if (!Req->Irp) {
	    ExFreePool(NewBcb);
	    ExFreePool(Req);
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto out;
	}
	if (FirstIrp) {
	    Req->Irp->AssociatedIrp.MasterIrp = FirstIrp;
	    FirstIrp->AssociatedIrp.IrpCount++;
	} else {
	    FirstIrp = Req->Irp;
	    FirstIrp->UserIosb = &IoStatus;
	}
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Req->Irp);
	Stack->FileObject = FileObject;
	IoSetCompletionRoutine(Req->Irp, CiReadCompleted, Req, TRUE, TRUE, TRUE);
	InsertTailList(&ReqList, &Req->Link);
	CurrentBcb = NextBcb;
	CurrentOffset += CurrentLength;
    }

    /* Forward the IRPs to the lower driver. Wait on the first IRP. */
    ReverseLoopOverList(Req, &ReqList, CI_READ_REQUEST, Link) {
	DPRINT("Calling storage device driver with irp %p\n", Req->Irp);
	Status = IoCallDriver(Vpb->DeviceObject, Req->Irp);
	if (!NT_SUCCESS(Status)) {
	    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Req->Irp);
	    DPRINT("IO failed!!! Error code: %x, FileObj %p DeviceObj %p, "
		   "ReadOffset 0x%llx, ReadLength 0x%x, Status 0x%x Info 0x%x\n",
		   Status, Stack->FileObject, Stack->DeviceObject,
		   Stack->Parameters.Read.ByteOffset.QuadPart,
		   Stack->Parameters.Read.Length, Req->Irp->IoStatus.Status,
		   Req->Irp->IoStatus.Information);
	    Req->Bcb->Length = 0;
	}
    }

    /* Now that all IO operations are done, insert the BCBs into the cache map.
     * We need to see if any of the resulting BCBs are adjacent (in both file
     * offset and mapped address) with existing BCBs, in which case we merge
     * them. */
    LoopOverList(Req, &ReqList, CI_READ_REQUEST, Link) {
	/* If the IO errored out, do nothing and simply clean up this BCB. */
	if (!Req->Bcb->Length) {
	    goto free;
	}
	PAVL_NODE Parent = NULL;
	PCI_BUFFER_CONTROL_BLOCK Prev = AVL_NODE_TO_BCB(
	    AvlTreeFindNodeOrPrevEx(&CacheMap->BcbTree, Req->Bcb->Node.Key, &Parent));
	PCI_BUFFER_CONTROL_BLOCK Next = AVL_NODE_TO_BCB(AvlGetNextNodeSafe(&Prev->Node));
	if (Prev && CiAdjacentBcbs(Prev, Req->Bcb)) {
	    Prev->Length += Req->Bcb->Length;
	    /* If after merging the previous BCB and current BCB, the new BCB
	     * is adjacent to the next BCB, we should detach the next BCB from
	     * the cache map and merge it with the newly merged BCB. */
	    if (Next && CiAdjacentBcbs(Prev, Next)) {
		AvlTreeRemoveNode(&CacheMap->BcbTree, &Next->Node);
		Prev->Length += Next->Length;
		/* Move the pinned buffer objects from Next to Prev */
		LoopOverList(Pinned, &Next->PinList, CI_PINNED_BUFFER, Link) {
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
    PCI_BUFFER_CONTROL_BLOCK Bcb = AVL_NODE_TO_BCB(AvlTreeFindNodeOrPrev(&CacheMap->BcbTree,
									 AlignedOffset));
    if (!Bcb || !AvlNodeContainsAddr(&Bcb->Node, Bcb->Length, AlignedOffset)) {
	return STATUS_NONE_MAPPED;
    }
    PCI_PINNED_BUFFER PinnedBuf = ExAllocatePool(sizeof(CI_PINNED_BUFFER));
    if (!PinnedBuf) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto out;
    }
    *MappedLength = min(Length, Bcb->Length - (FileOffset->QuadPart - Bcb->Node.Key));
    *pBuffer = (PUCHAR)Bcb->MappedAddress + (FileOffset->QuadPart - Bcb->Node.Key);
    *pBcb = PinnedBuf;
    PinnedBuf->Bcb = Bcb;
    PinnedBuf->FileOffset = FileOffset->QuadPart;
    PinnedBuf->Length = *MappedLength;
    InsertHeadList(&Bcb->PinList, &PinnedBuf->Link);
    Status = (*MappedLength == Length) ? STATUS_SUCCESS : STATUS_SOME_NOT_MAPPED;

out:
    /* Free all the allocated BCBs that have not been inserted into the cache map. */
    LoopOverList(Req, &ReqList, CI_READ_REQUEST, Link) {
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

NTAPI VOID CcSetDirtyData(IN PVOID Bcb)
{
    PCI_PINNED_BUFFER PinnedBuf = Bcb;
    assert(PinnedBuf);
    assert(PinnedBuf->Bcb);
    PinnedBuf->Bcb->Dirty = TRUE;
}

NTAPI VOID CcUnpinData(IN PVOID Bcb)
{
    PCI_PINNED_BUFFER PinnedBuf = Bcb;
    assert(PinnedBuf);
    RemoveEntryList(&PinnedBuf->Link);
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
    assert(FileObject);
    assert(FileOffset);
    assert(Buffer);
    assert(BytesRead);
    *BytesRead = 0;

    while (*BytesRead < Length) {
	ULONG RemainingBytes = Length - *BytesRead;
	LARGE_INTEGER ReadOffset = { .QuadPart = FileOffset->QuadPart + *BytesRead };
	ULONG MappedLength = 0;
	PVOID Bcb = NULL;
	PVOID SrcBuffer = NULL;
	NTSTATUS Status = CcMapData(FileObject, &ReadOffset, RemainingBytes,
				    Wait ? MAP_WAIT : 0,
				    &MappedLength, &Bcb, &SrcBuffer);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
	assert(Bcb);
	assert(SrcBuffer);

	ULONG BytesToCopy = min(MappedLength, RemainingBytes);
	RtlCopyMemory((PUCHAR)Buffer + *BytesRead, SrcBuffer, BytesToCopy);
	*BytesRead += BytesToCopy;
	CcUnpinData(Bcb);
    }
    return STATUS_SUCCESS;
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
    UNIMPLEMENTED;
}

NTAPI NTSTATUS CcMdlRead(IN PFILE_OBJECT FileObject,
			 IN PLARGE_INTEGER FileOffset,
			 IN ULONG Length,
			 OUT PMDL *MdlChain,
			 OUT PIO_STATUS_BLOCK IoStatus)
{
    assert(MdlChain);
    assert(IoStatus);
    IoStatus->Status = STATUS_NOT_IMPLEMENTED;
    IoStatus->Information = 0;
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI NTSTATUS CcZeroData(IN PFILE_OBJECT FileObject,
			  IN PLARGE_INTEGER StartOffset,
			  IN PLARGE_INTEGER EndOffset,
			  IN BOOLEAN Wait)
{
    UNIMPLEMENTED;
}

NTAPI VOID CcSetFileSizes(IN PFILE_OBJECT FileObject,
			  IN PCC_FILE_SIZES FileSizes)
{
    /* TODO! */
}
