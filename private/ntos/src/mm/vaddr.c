/*
 * Routines for virtual address space management
 */

#include "mi.h"

#define LOW_BITMAP_MAX_LOG2SIZE	(PAGE_LOG2SIZE + 3)
#define LOW_BITMAP_MAXSIZE	(1ULL << LOW_BITMAP_MAX_LOG2SIZE)

VOID MiInitializeVSpace(IN PVIRT_ADDR_SPACE Self,
			IN PPAGING_STRUCTURE RootPagingStructure)
{
    assert(Self != NULL);
    assert(RootPagingStructure != NULL);
    assert(RootPagingStructure->TreeNode.Cap != 0);
    RootPagingStructure->VSpaceCap = RootPagingStructure->TreeNode.Cap;
    Self->VSpaceCap = RootPagingStructure->TreeNode.Cap;
    Self->RootPagingStructure = RootPagingStructure;
    Self->ASIDPool = 0;
    AvlInitializeTree(&Self->VadTree);
    InitializeListHead(&Self->ViewerList);
}

NTSTATUS MmCreateVSpace(IN PVIRT_ADDR_SPACE Self)
{
    assert(Self != NULL);
    MiAllocatePool(RootPagingStructure, PAGING_STRUCTURE);
    PUNTYPED VSpaceUntyped = NULL;
    RET_ERR_EX(MmRequestUntyped(seL4_VSpaceBits, &VSpaceUntyped),
	       MiFreePool(RootPagingStructure));
    MiInitializePagingStructure(RootPagingStructure, NULL, NULL, 0,
				0, 0, PAGING_TYPE_ROOT_PAGING_STRUCTURE,
				TRUE, MM_RIGHTS_RW, MM_ATTRIBUTES_DEFAULT);
    RET_ERR_EX(MmRetypeIntoObject(VSpaceUntyped, seL4_VSpaceObject,
				  seL4_VSpaceBits, &RootPagingStructure->TreeNode),
	       {
		   MmReleaseUntyped(VSpaceUntyped);
		   MiFreePool(RootPagingStructure);
	       });
    MiInitializeVSpace(Self, RootPagingStructure);
    return STATUS_SUCCESS;
}

/*
 * Delete all paging structures in the VSpace (including the root paging
 * structure) but do NOT free the pool memory of Self.
 *
 * NOTE: We always use the term 'destroy' to refer to releasing resources
 * of an object WITHOUT freeing its pool memory. The term 'delete' is used
 * for the case where we release its resources AND free its pool memory.
 */
VOID MmDestroyVSpace(IN PVIRT_ADDR_SPACE Self)
{
    /* Delete all the VADs of this VSpace. */
    PAVL_NODE Node;
    while ((Node = AvlGetFirstNode(&Self->VadTree))) {
	MmDeleteVad(AVL_NODE_TO_VAD(Node));
    }
    MmDbgDumpVSpace(Self);
    /* At this point the VSpace should be empty. */
    assert(!Self->RootPagingStructure->SubStructureTree.BalancedRoot);
    MiDeletePage(Self->RootPagingStructure);
    Self->RootPagingStructure = NULL;
    /* Delete all VADs (in foreign VSpaces) mirroring (parts of) this VSpace. */
    LoopOverList(Vad, &Self->ViewerList, MMVAD, MirroredMemory.ViewerLink) {
	assert(Vad->Flags.MirroredMemory);
	MmDeleteVad(Vad);
    }
    Self->VSpaceCap = 0;
    /* ASID is automatically disassociated when the VSpace cap was deleted
     * (by MiDeletePage). */
    Self->ASIDPool = 0;
}

/*
 * Search for an ASID pool with a free ASID slot and assign an ASID
 * for the virtual address space. An ASID must be assigned before the
 * virtual address space can be used for mapping.
 */
NTSTATUS MmAssignASID(IN PVIRT_ADDR_SPACE VaddrSpace)
{
    /* TODO: Create ASID pool if there are not enough ASID slots */
    int Error = seL4_ASIDPool_Assign(seL4_CapInitThreadASIDPool,
				     VaddrSpace->VSpaceCap);

    if (Error != 0) {
	return SEL4_ERROR(Error);
    }

    VaddrSpace->ASIDPool = seL4_CapInitThreadASIDPool;
    return STATUS_SUCCESS;
}

/*
 * Returns TRUE if the supplied address is within the address range
 * represented by the VAD node
 */
static inline BOOLEAN MiVadNodeContainsAddr(IN PMMVAD Vad,
					    IN MWORD Addr)
{
    assert(Vad != NULL);
    return AddrWindowContainsAddr(Vad->AvlNode.Key, Vad->WindowSize, Addr);
}

/*
 * Returns the VAD node that contains the supplied virtual address.
 */
PMMVAD MiVSpaceFindVadNode(IN PVIRT_ADDR_SPACE VSpace,
			   IN MWORD VirtAddr)
{
    PAVL_TREE Tree = &VSpace->VadTree;
    PMMVAD Node = AVL_NODE_TO_VAD(AvlTreeFindNodeOrPrev(Tree, VirtAddr));
    if (Node != NULL && MiVadNodeContainsAddr(Node, VirtAddr)) {
	return Node;
    }
    return NULL;
}

/*
 * Returns the next node in the VAD tree following the given Vad node
 *
 * Returns NULL if Vad is the last node in the VAD tree
 */
static inline PMMVAD MiVadGetNextNode(IN PMMVAD Vad)
{
    assert(Vad != NULL);
    assert(Vad->VSpace != NULL);
    return AVL_NODE_TO_VAD(AvlGetNextNode(&Vad->AvlNode));
}

/*
 * Returns the previous node of the given Vad node in the Vad tree
 *
 * Returns NULL if Vad is the first node in the VAD tree
 */
static inline PMMVAD MiVadGetPrevNode(IN PMMVAD Vad)
{
    assert(Vad != NULL);
    assert(Vad->VSpace != NULL);
    return AVL_NODE_TO_VAD(AvlGetPrevNode(&Vad->AvlNode));
}

/*
 * Search for an unused address window of given size within [StartAddr, EndAddr),
 * create a VAD of this address window and insert into the virtual address
 * space's VAD tree, optionally returning the pointer to the newly created
 * VAD.
 *
 * If specified, will search from top down (ie. from higher address to lower addr)
 *
 * For MEM_RESERVE_BITMAP_MANAGED, LowZeroBits specifies the granularity of the
 * commitment status tracking. Commitment status is tracked in units of 1 << LowZeroBits.
 * In this case LowZeroBits must be no less than PAGE_SHIFT (if the caller specified
 * a LowZeroBits less than PAGE_SHIFT, it will be slightly adjusted to PAGE_SHIFT).
 * Otherwise, LowZeroBits specifies the alignment of the address window. In this case
 * LowZeroBits cannot be less than MM_MINIMAL_LOW_ZERO_BITS (again it will be silently
 * adjusted if less than MM_MINIMAL_LOW_ZERO_BITS), unless we are reserving an image
 * map VAD (ie. unless the VAD describes a PE/ELF section).
 *
 * If unspecified (ie. zero), EndAddr will be set to StartAddr + WindowSize
 *
 * If the MEM_RESERVE_LARGE_PAGES flag is specified and WindowSize is at least
 * one large page size, then we will attempt to locate an address window that
 * starts at the large page boundary (failing so, a regular search will be conducted).
 *
 */
NTSTATUS MmReserveVirtualMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				  IN MWORD StartAddr,
				  IN OPTIONAL MWORD EndAddr,
				  IN MWORD WindowSize,
				  IN ULONG LowZeroBits,
				  IN ULONG HighZeroBits,
				  IN MWORD Flags,
				  OUT OPTIONAL PMMVAD *pVad)
{
#ifdef CONFIG_DEBUG_BUILD
    assert(VSpace != NULL);
    assert(WindowSize != 0);
    /* At least one flag must be set. */
    assert(Flags);
    /* Thw following "reserve type" flags are mutually exclusive. */
    MWORD TypeFlags = MEM_RESERVE_IMAGE_MAP | MEM_RESERVE_FILE_MAP | MEM_RESERVE_CACHE_MAP
	| MEM_RESERVE_PHYSICAL_MAPPING | MEM_RESERVE_BITMAP_MANAGED
	| MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_MIRRORED_MEMORY;
    assert(IsPow2OrZero(Flags & TypeFlags));
    /* Unless NO_ACCESS or NO_INSERT is set, at least one of the "reserve type"
     * flags above must be set. */
    assert((Flags & (MEM_RESERVE_NO_ACCESS | MEM_RESERVE_NO_INSERT))
	   || (Flags & TypeFlags));
    /* NO_ACCESS and READ_ONLY are mutually exclusive. */
    assert(IsPow2OrZero(Flags & (MEM_RESERVE_NO_ACCESS | MEM_RESERVE_READ_ONLY)));
    /* COMMIT_ON_DEMAND can only be set for OWNED_MEMORY */
    assert(!(Flags & MEM_COMMIT_ON_DEMAND) || (Flags & MEM_RESERVE_OWNED_MEMORY));
#endif

    if (Flags & (MEM_RESERVE_BITMAP_MANAGED | MEM_RESERVE_IMAGE_MAP
		 | MEM_RESERVE_PHYSICAL_MAPPING)) {
	LowZeroBits = max(LowZeroBits, PAGE_LOG2SIZE);
    } else {
	LowZeroBits = max(LowZeroBits, MM_MINIMUM_LOW_ZERO_BITS);
    }

    MWORD VirtAddr;
    PMMVAD Parent;
    /* These will be used in the large page case when we re-attempt a regular search */
    MWORD OrigStartAddr = StartAddr;
    MWORD OrigWindowSize = WindowSize;
    BOOLEAN TryLargePages = (Flags & MEM_RESERVE_LARGE_PAGES) &&
	(WindowSize >= LARGE_PAGE_SIZE);

    ULONG PageLog2Size;
    MWORD PageAlignment;
    MWORD Alignment;
retry:
    /* Use LowZeroBits and the relevant page size (whichever is larger) to determine
     * address alignment requirement. */
    PageLog2Size = TryLargePages ? LARGE_PAGE_LOG2SIZE : PAGE_LOG2SIZE;
    PageAlignment = 1ULL << PageLog2Size;
    Alignment = 1ULL << (LowZeroBits > PageLog2Size ? LowZeroBits : PageLog2Size);
    StartAddr = ALIGN_UP_BY(StartAddr, Alignment);
    WindowSize = ALIGN_UP_BY(WindowSize, PageAlignment);

    /* If after alignment, the address window to search becomes empty, then
     * we won't try large pages. */
    if (EndAddr && (StartAddr + WindowSize > EndAddr)) {
	if (TryLargePages) {
	    TryLargePages = FALSE;
	    StartAddr = OrigStartAddr;
	    WindowSize = OrigWindowSize;
	    goto retry;
	} else {
	    return STATUS_CONFLICTING_ADDRESSES;
	}
    }

    /* We shouldn't align EndAddr since EndAddr might be MAX_ULONGPTR */
    if (Flags & MEM_RESERVE_TOP_DOWN) {
	assert(EndAddr != 0);
	assert(EndAddr > WindowSize);
    } else if (!EndAddr) {
	EndAddr = StartAddr + WindowSize;
    }

    if (HighZeroBits > MM_MAXIMUM_HIGH_ZERO_BITS) {
	return STATUS_INVALID_PARAMETER;
    }

    if (HighZeroBits) {
	MWORD MaxAddr = 1ULL << (MWORD_BITS - HighZeroBits);
	if (EndAddr > MaxAddr) {
	    EndAddr = MaxAddr;
	}
    }

    assert(StartAddr + WindowSize > StartAddr);
    if (StartAddr + WindowSize > EndAddr) {
	return STATUS_CONFLICTING_ADDRESSES;
    }

    MmDbg("Trying to find an addr window of size 0x%zx "
	  "(LowZeroBits %d HighZeroBits %d) within [%p, %p) "
	  "for vspacecap 0x%zx\n", WindowSize,
	  LowZeroBits, HighZeroBits, (PVOID)StartAddr,
	  (PVOID)EndAddr, VSpace ? VSpace->VSpaceCap : 0);

    /* Locate the first unused address window */
    VirtAddr = (Flags & MEM_RESERVE_TOP_DOWN) ? EndAddr : StartAddr;
    Parent = AVL_NODE_TO_VAD(AvlTreeFindNodeOrParent(&VSpace->VadTree,
						     VirtAddr));
    /* Address space is empty. */
    if (Parent == NULL) {
	goto insert;
    }

    if (Flags & MEM_RESERVE_TOP_DOWN) {
	/* If the EndAddr is smaller than or equal to Parent, then we can just
	 * start searching at Parent. However if not, we need to see if there
	 * is enough space between Parent and EndAddr. If there is, we can just
	 * insert there. */
	if (Parent->AvlNode.Key < EndAddr) {
	    MWORD CurrentAddr = EndAddr - WindowSize;
	    CurrentAddr = ALIGN_DOWN_BY(CurrentAddr, Alignment);
	    if (Parent->AvlNode.Key + Parent->WindowSize <= CurrentAddr) {
		/* There is enough space between Parent and EndAddr. Insert
		 * after Parent. */
		VirtAddr = CurrentAddr;
		goto insert;
	    } else {
		/* Else, retreat to the address immediately before Parent. */
		VirtAddr = Parent->AvlNode.Key;
	    }
	}
	/* Now start searching from higher address to lower address
	 * for an unused address window till we reach StartAddr */
	while (VirtAddr - WindowSize >= StartAddr) {
	    if (VirtAddr - WindowSize >= VirtAddr) {
		/* addr window underflows */
		return STATUS_INVALID_PARAMETER;
	    }
	    PMMVAD Prev = MiVadGetPrevNode(Parent);
	    if (Prev == NULL) {
		/* Everything from StartAddr to VirtAddr is unused.
		 * Simply insert before Parent. */
		VirtAddr -= WindowSize;
		VirtAddr = ALIGN_DOWN_BY(VirtAddr, Alignment);
		goto insert;
	    }
	    /* VAD windows should never overlap */
	    assert((Prev->AvlNode.Key + Prev->WindowSize) <= Parent->AvlNode.Key);
	    MWORD CurrentAddr = VirtAddr - WindowSize;
	    CurrentAddr = ALIGN_DOWN_BY(CurrentAddr, Alignment);
	    if (Prev->AvlNode.Key + Prev->WindowSize <= CurrentAddr) {
		/* Found an unused address window. Now determine whether we insert
		 * as the right child of Prev or as left child of Parent */
		if (Parent->AvlNode.LeftChild != NULL) {
		    assert(Prev->AvlNode.RightChild == NULL);
		    Parent = Prev;
		}
		VirtAddr = CurrentAddr;
		goto insert;
	    }
	    /* Otherwise keep going */
	    Parent = Prev;
	    VirtAddr = Prev->AvlNode.Key;
	}
    } else {
	/* If StartAddr is larger than or equal to Parent, we can just
	 * start searching at Parent. Otherwise, check if there is enough
	 * space between StartAddr and Parent, and insert there if there is. */
	if (StartAddr < Parent->AvlNode.Key + Parent->WindowSize) {
	    if (StartAddr + WindowSize <= Parent->AvlNode.Key) {
		goto insert;
	    } else {
		/* Else, advance to the address immediately after Parent */
		VirtAddr = Parent->AvlNode.Key + Parent->WindowSize;
	    }
	}
	/* Now start searching for unused window till we reach EndAddr */
	while (VirtAddr + WindowSize <= EndAddr) {
	    if (VirtAddr + WindowSize < VirtAddr) {
		/* addr window overflows */
		return STATUS_INVALID_PARAMETER;
	    }
	    PMMVAD Next = MiVadGetNextNode(Parent);
	    if (Next == NULL) {
		/* Everything from VirtAddr to EndAddr is unused.
		 * Simply insert after Parent. */
		goto insert;
	    }
	    /* VAD windows should never overlap */
	    assert((Parent->AvlNode.Key + Parent->WindowSize) <= Next->AvlNode.Key);
	    if (Next->AvlNode.Key >= VirtAddr + WindowSize) {
		/* Found an unused address window. If the right child of Parent
		 * is NULL, insert there. Otherwise insert as the left child of Next */
		if (Parent->AvlNode.RightChild != NULL) {
		    Parent = Next;
		    assert(Next->AvlNode.LeftChild == NULL);
		}
		goto insert;
	    }
	    Parent = Next;
	    VirtAddr = ALIGN_UP_BY(Next->AvlNode.Key + Next->WindowSize, Alignment);
	}
    }

    /* Unable to find an unused address window. Now try without large pages */
    if (TryLargePages) {
	TryLargePages = FALSE;
	StartAddr = OrigStartAddr;
	WindowSize = OrigWindowSize;
	goto retry;
    }
    /* Now we really don't have any free address window. Return error. */
    MmDbgDumpVSpace(VSpace);
    return STATUS_CONFLICTING_ADDRESSES;

insert:
    assert(VirtAddr >= StartAddr);
    assert(VirtAddr + WindowSize <= EndAddr);
    MiAllocatePool(Vad, MMVAD);
    MWORD *Bitmap = NULL;
    if ((Flags & MEM_RESERVE_BITMAP_MANAGED) && !(Flags & MEM_RESERVE_NO_INSERT)) {
	if (LowZeroBits < PageLog2Size) {
	    LowZeroBits = PageLog2Size;
	}
	MWORD AllocationUnits = WindowSize >> LowZeroBits;
	if (!AllocationUnits) {
	    MiFreePool(Vad);
	    return STATUS_INVALID_PARAMETER;
	}
	if (AllocationUnits > LOW_BITMAP_MAXSIZE) {
	    MWORD HighBitmapSize = AllocationUnits / LOW_BITMAP_MAXSIZE;
	    Bitmap = ExAllocatePoolWithTag(HighBitmapSize * sizeof(PVOID), NTOS_MM_TAG);
	} else {
	    Bitmap = ExAllocatePoolWithTag(AllocationUnits / 8, NTOS_MM_TAG);
	}
	if (!Bitmap) {
	    MiFreePool(Vad);
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
    }
    MMVAD_FLAGS VadFlags;
    VadFlags.Word = 0;
    VadFlags.NoAccess = !!(Flags & MEM_RESERVE_NO_ACCESS);
    VadFlags.ReadOnly = !!(Flags & MEM_RESERVE_READ_ONLY);
    VadFlags.ImageMap = !!(Flags & MEM_RESERVE_IMAGE_MAP);
    VadFlags.FileMap = !!(Flags & MEM_RESERVE_FILE_MAP);
    VadFlags.CacheMap = !!(Flags & MEM_RESERVE_CACHE_MAP);
    VadFlags.PhysicalMapping = !!(Flags & MEM_RESERVE_PHYSICAL_MAPPING);
    VadFlags.BitmapManaged = !!(Flags & MEM_RESERVE_BITMAP_MANAGED);
    VadFlags.LargePages = !!(Flags & MEM_RESERVE_LARGE_PAGES) && TryLargePages;
    VadFlags.OwnedMemory = !!(Flags & MEM_RESERVE_OWNED_MEMORY);
    VadFlags.MirroredMemory = !!(Flags & MEM_RESERVE_MIRRORED_MEMORY);
    VadFlags.CommitOnDemand = !!(Flags & MEM_COMMIT_ON_DEMAND);
    MiInitializeVadNode(Vad, VSpace, VirtAddr, WindowSize, VadFlags);
    if (VadFlags.CommitOnDemand) {
	MmDbg("Commit on demand\n");
    }

    if (pVad != NULL) {
	*pVad = Vad;
    }

    if (Flags & MEM_RESERVE_NO_INSERT) {
	return STATUS_SUCCESS;
    }

    Vad->CommitmentStatus.Bitmap = Bitmap;
    Vad->CommitmentStatus.LowZeroBits = LowZeroBits;
    AvlTreeInsertNode(&VSpace->VadTree, &Parent->AvlNode, &Vad->AvlNode);

    MmDbg("Successfully reserved [%p, %p) for vspacecap 0x%zx\n",
	  (PVOID)Vad->AvlNode.Key,
	  (PVOID)(Vad->AvlNode.Key + Vad->WindowSize),
	  VSpace ? VSpace->VSpaceCap : 0);
    return STATUS_SUCCESS;
}

/*
 * Find an uncommitted allocation unit in the bitmap managed memory region.
 * If full, or if the VAD does not describe a bitmap managed memory region,
 * return zero.
 */
MWORD MmFindAndMarkUncommittedSubregion(IN PMMVAD Vad)
{
    if (!Vad->Flags.BitmapManaged) {
	assert(FALSE);
	return 0;
    }
    if (!Vad->CommitmentStatus.Bitmaps) {
	assert(FALSE);
	return 0;
    }
    MWORD AllocationUnits = Vad->WindowSize >> Vad->CommitmentStatus.LowZeroBits;
    if (!AllocationUnits) {
	assert(FALSE);
	return 0;
    }
    if (AllocationUnits > LOW_BITMAP_MAXSIZE) {
	MWORD HighBitmapSize = AllocationUnits / LOW_BITMAP_MAXSIZE;
	for (MWORD i = 0; i < HighBitmapSize; i++) {
	    if (Vad->CommitmentStatus.Bitmaps[i]) {
		for (MWORD j = 0; j < LOW_BITMAP_MAXSIZE; j++) {
		    if (!GetBit(Vad->CommitmentStatus.Bitmaps[i], j)) {
			SetBit(Vad->CommitmentStatus.Bitmaps[i], j);
			MWORD Offset = (i << LOW_BITMAP_MAX_LOG2SIZE) | j;
			return Vad->AvlNode.Key + (Offset << Vad->CommitmentStatus.LowZeroBits);
		    }
		}
	    } else {
		Vad->CommitmentStatus.Bitmaps[i] = ExAllocatePoolWithTag(LOW_BITMAP_MAXSIZE / 8,
									 NTOS_MM_TAG);
		if (!Vad->CommitmentStatus.Bitmaps[i]) {
		    return 0;
		}
		SetBit(Vad->CommitmentStatus.Bitmaps[i], 0);
		return Vad->AvlNode.Key + (i << (LOW_BITMAP_MAX_LOG2SIZE +
						 Vad->CommitmentStatus.LowZeroBits));
	    }
	}
    } else {
	for (MWORD i = 0; i < AllocationUnits; i++) {
	    if (!GetBit(Vad->CommitmentStatus.Bitmap, i)) {
		SetBit(Vad->CommitmentStatus.Bitmap, i);
		return Vad->AvlNode.Key + (i << Vad->CommitmentStatus.LowZeroBits);
	    }
	}
    }
    return 0;
}

/*
 * Unset the bitmap corresponding to the address of the committed unit in a
 * bitmap managed memory region.
 */
static VOID MiUnmarkCommittedSubregion(IN PMMVAD Vad, IN MWORD Addr)
{
    if (!Vad->Flags.BitmapManaged) {
	assert(FALSE);
	return;
    }
    if (!Vad->CommitmentStatus.Bitmaps) {
	assert(FALSE);
	return;
    }
    if (Addr < Vad->AvlNode.Key) {
	assert(FALSE);
	return;
    }
    MWORD Offset = Addr - Vad->AvlNode.Key;
    if (Offset >= Vad->WindowSize) {
	assert(FALSE);
	return;
    }
    Offset >>= Vad->CommitmentStatus.LowZeroBits;
    MWORD AllocationUnits = Vad->WindowSize >> Vad->CommitmentStatus.LowZeroBits;
    if (!AllocationUnits) {
	assert(FALSE);
	return;
    }
    if (AllocationUnits > LOW_BITMAP_MAXSIZE) {
	MWORD *Bitmap = Vad->CommitmentStatus.Bitmaps[Offset >> LOW_BITMAP_MAX_LOG2SIZE];
	if (!Bitmap) {
	    assert(FALSE);
	    return;
	}
	ClearBit(Bitmap, Offset & ((1ULL << LOW_BITMAP_MAX_LOG2SIZE) - 1));
    } else {
	ClearBit(Vad->CommitmentStatus.Bitmap, Offset);
    }
}

/*
 * Add the mirrored memory VAD to the master vspace's viewer list. The mirrored
 * memory will map a memory window of the master vspace to the viewer vspace.
 * The start address of the master vspace memory window is given by StartAddr.
 * The window size of the Viewer VAD's window size.
 */
VOID MmRegisterMirroredMemory(IN PMMVAD Viewer,
			      IN PVIRT_ADDR_SPACE Master,
			      IN MWORD StartAddr,
			      IN MEMORY_CACHING_TYPE CacheType)
{
    assert(Viewer != NULL);
    assert(Master != NULL);
    assert(Viewer->Flags.MirroredMemory);
    Viewer->MirroredMemory.Master = Master;
    Viewer->MirroredMemory.StartAddr = StartAddr;
    Viewer->MirroredMemory.CacheType = CacheType;
    InsertTailList(&Master->ViewerList, &Viewer->MirroredMemory.ViewerLink);
}

/*
 * Register the viewer VAD to map the master VAD. The master VAD must have
 * the same window size as the viewer VAD.
 */
VOID MmRegisterMirroredVad(IN PMMVAD Viewer,
			   IN PMMVAD MasterVad,
			   IN MEMORY_CACHING_TYPE CacheType)
{
    assert(Viewer != NULL);
    assert(MasterVad != NULL);
    assert(Viewer->WindowSize == MasterVad->WindowSize);
    assert(MasterVad->VSpace != NULL);
    MmRegisterMirroredMemory(Viewer, MasterVad->VSpace, MasterVad->AvlNode.Key, CacheType);
}

/*
 * This routine is called by MmHandleThreadVmFault and MmCommitVirtualMemory to map the
 * view range of the data file section. Prior to calling this routine, the relevant file
 * range of the data file must be paged into memory (via CcPinData or CcPinDataEx). For
 * page-file-backed section, this routine maps the pages according to the VAD's protection
 * attributes. For non-page-file-backed data sections, this routine always map the pages
 * as read-only.
 */
static NTSTATUS MiMapFileVad(IN PMMVAD Vad,
			     IN MWORD StartAddr,
			     IN MWORD SizeToMap)
{
    SizeToMap = PAGE_ALIGN_UP(StartAddr + SizeToMap) - PAGE_ALIGN(StartAddr);
    StartAddr = PAGE_ALIGN(StartAddr);
    assert(StartAddr >= Vad->AvlNode.Key);
    assert(StartAddr + SizeToMap <= Vad->AvlNode.Key + Vad->WindowSize);
    assert(SizeToMap);
    PSECTION Section = Vad->Section;
    assert(Section);
    assert(Section->Flags.File);
    PDATA_SECTION_OBJECT DataSection = Section->DataSectionObject;
    assert(DataSection);
    PIO_FILE_CONTROL_BLOCK Fcb = DataSection->Fcb;
    assert(Fcb);
    /* TODO: for read-only page-file mappings, map the common zero-page rather than
     * using new pages. NT semantics forbid one from later changing it to writable,
     * so we do not need to worry about committing memory in this case. */
    PAGING_RIGHTS Rights = Section->Flags.PageFile ?
	(Vad->Flags.ReadOnly ? MM_RIGHTS_RO : MM_RIGHTS_RW) : MM_RIGHTS_RO;
    ULONG64 FileOffset = StartAddr - Vad->AvlNode.Key + Vad->DataSectionView.SectionOffset;
    MWORD MappedSize = 0;
    while (MappedSize < SizeToMap) {
	PVOID Buffer = NULL;
	ULONG BufferLength = 0;
	RET_ERR(CcMapData(Fcb, FileOffset + MappedSize, SizeToMap - MappedSize,
			  &BufferLength, &Buffer));
	assert(Buffer);
	assert(BufferLength);
	assert(IS_PAGE_ALIGNED(BufferLength) ||
	       BufferLength == (Fcb->FileSize - FileOffset - MappedSize));
	RET_ERR(MmMapMirroredMemory(&MiNtosVaddrSpace, (MWORD)Buffer, Vad->VSpace,
				    StartAddr + MappedSize, PAGE_ALIGN_UP(BufferLength),
				    Rights, MM_ATTRIBUTES_DEFAULT, TRUE));
	MappedSize += PAGE_ALIGN_UP(BufferLength);
    }
    return STATUS_SUCCESS;
}

FORCEINLINE PAGING_ATTRIBUTES MiGetPagingAttributesFromCacheType(MEMORY_CACHING_TYPE CacheType)
{
    PAGING_ATTRIBUTES Attributes = MM_ATTRIBUTES_DEFAULT;
    if (CacheType == MmNonCached) {
	MmApplyNoCacheAttribute(&Attributes);
    } else if (CacheType == MmWriteCombined) {
	MmApplyWriteCombineAttribute(&Attributes);
    } else if (CacheType == MmWriteThrough) {
	MmApplyWriteThroughAttribute(&Attributes);
    }
    return Attributes;
}

/*
 * Commit the virtual memory window [StartAddr, StartAddr + WindowSize). The
 * address window must have been already reserved and have not been committed
 * previously (ie. none of the memory pages within the address window is mapped).
 *
 * If unaligned, address window is expanded to align at page boundary.
 */
NTSTATUS MmCommitVirtualMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				 IN MWORD StartAddr,
				 IN MWORD WindowSize)
{
    assert(VSpace != NULL);
    assert(WindowSize > 0);
    MmDbg("Trying to commit [%p, %p)\n", (PVOID)StartAddr, (PVOID)(StartAddr + WindowSize));
    StartAddr = PAGE_ALIGN(StartAddr);
    WindowSize = PAGE_ALIGN_UP(WindowSize);
    assert(StartAddr + WindowSize > StartAddr);

    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, StartAddr);
    if (Vad == NULL) {
	MmDbg("Error: Must reserve address window before committing.\n");
	MmDbgDumpVSpace(VSpace);
	return STATUS_INVALID_PARAMETER;
    }

    if (Vad->Flags.NoAccess) {
	MmDbg("Error: Committing a NoAccess Vad.\n");
	MmDbgDumpVSpace(VSpace);
	return STATUS_INVALID_PARAMETER;
    }

    /* VADs marked as cache map are managed by the cache manager and you cannot
     * call MmCommitVirtualMemory on it. */
    if (Vad->Flags.CacheMap) {
	MmDbg("Error: Cache map is managed by the cache manager.\n");
	MmDbgDumpVSpace(VSpace);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* If the VAD is a mapped view of a pagefile-backed data section, commit the
     * specified memory region. Otherwise, return error. */
    if (Vad->Flags.FileMap) {
	PSECTION Section = Vad->Section;
	assert(Section->Flags.File);
	if (!Section->Flags.PageFile) {
	    return STATUS_INVALID_PARAMETER;
	}
	if (StartAddr + WindowSize > Vad->AvlNode.Key + Vad->WindowSize) {
	    return STATUS_INVALID_PARAMETER;
	}
	return MiMapFileVad(Vad, StartAddr, WindowSize);
    }

    /* VADs marked as image map are mapped using MmMapViewOfSection and you cannot
     * call MmCommitVirtualMemory on it. */
    if (Vad->Flags.ImageMap) {
	MmDbg("Error: Call MmMapViewOfSection to commit image VAD.\n");
	MmDbgDumpVSpace(VSpace);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* VADs marked as physical mapping are mapped using MmMapViewOfSection or
     * MmMapIoSpace and you cannot call MmCommitVirtualMemory on it. */
    if (Vad->Flags.PhysicalMapping) {
	MmDbg("Error: Call MmMapViewOfSection to commit physical mapping.\n");
	MmDbgDumpVSpace(VSpace);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* NT semantics require that memory region to be committed belows to the same VAD. */
    if ((StartAddr < Vad->AvlNode.Key) ||
	(StartAddr + WindowSize > Vad->AvlNode.Key + Vad->WindowSize)) {
	MmDbg("Committing addresses spanning multiple VADs is not allowed in NT "
	      "(requested [%p, %p) found VAD [%p, %p))\n",
	      (PVOID)StartAddr, (PVOID)(StartAddr + WindowSize),
	      (PVOID)Vad->AvlNode.Key, (PVOID)(Vad->AvlNode.Key + Vad->WindowSize));
	return STATUS_INVALID_PARAMETER;
    }

    PAGING_RIGHTS Rights = (Vad->Flags.ReadOnly) ? MM_RIGHTS_RO : MM_RIGHTS_RW;

    if (Vad->Flags.MirroredMemory) {
	assert(Vad->MirroredMemory.Master != NULL);
	assert(IS_PAGE_ALIGNED(Vad->MirroredMemory.StartAddr));
	PAGING_ATTRIBUTES Attrs =
	    MiGetPagingAttributesFromCacheType(Vad->MirroredMemory.CacheType);
	RET_ERR(MmMapMirroredMemory(Vad->MirroredMemory.Master, Vad->MirroredMemory.StartAddr,
				    Vad->VSpace, StartAddr, WindowSize, Rights, Attrs, FALSE));
    } else if (Vad->Flags.OwnedMemory) {
	RET_ERR(MmCommitOwnedMemoryEx(Vad->VSpace, StartAddr, WindowSize, Rights,
				      MM_ATTRIBUTES_DEFAULT, Vad->Flags.LargePages, NULL, 0));
    } else {
	/* Should never reach this */
	MmDbgDumpVSpace(VSpace);
	assert(FALSE);
	return STATUS_NTOS_BUG;
    }

    return STATUS_SUCCESS;
}

/*
 * Returns the PAGING_STRUCTURE pointer to the page at given virtual address.
 * If LargePage is specified, paging structure can be a page or a large page.
 * Otherwise the paging structure must be the lowest level page (4K in x86).
 * Returns NULL if no such paging structure is unmapped at the given address.
 */
PPAGING_STRUCTURE MmQueryPageEx(IN PVIRT_ADDR_SPACE VSpace,
				IN MWORD VirtAddr,
				IN BOOLEAN LargePage)
{
    assert(VSpace != NULL);

    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, VirtAddr);
    if (Vad == NULL) {
	return NULL;
    }

    PPAGING_STRUCTURE Page = MiQueryVirtualAddress(VSpace, VirtAddr);

    if (Page == NULL) {
	return FALSE;
    }

    if (LargePage) {
	return MiPagingTypeIsPageOrLargePage(Page->Type) ? Page : NULL;
    } else {
	return MiPagingTypeIsPage(Page->Type) ? Page : NULL;
    }
}

ULONG_PTR MmGetPhysicalAddress(IN PVIRT_ADDR_SPACE VSpace,
			       IN MWORD VirtBase)
{
    PPAGING_STRUCTURE Page = MmQueryPageEx(VSpace, VirtBase, TRUE);
    if (!Page) {
	return 0;
    }
    assert(Page->AvlNode.Key);
    ULONG_PTR PhyAddr = MiGetPhysicalAddress(Page);
    assert(PhyAddr);
    assert(IS_PAGE_ALIGNED(PhyAddr));
    return PhyAddr;
}

/*
 * Query the paging structures to generate the page frame database.
 *
 * If PfnDb is not NULL, the PFN database will be written.
 * If pPfnCount is not NULL, the PFN count will be written.
 *
 * If the buffer is fully mapped in the specified process address
 * space prior to calling this function, FALSE is returned. Note
 * here Buffer is the (client-side) virtual address in the address
 * space of the specified process.
 */
BOOLEAN MmGeneratePageFrameDatabase(IN OPTIONAL PULONG_PTR PfnDb,
				    IN PVIRT_ADDR_SPACE VSpace,
				    IN MWORD Buffer,
				    IN MWORD BufferLength,
				    IN MEMORY_CACHING_TYPE CacheType,
				    OUT OPTIONAL ULONG *pPfnCount)
{
    if (pPfnCount) {
	*pPfnCount = 0;
    }
    if (!Buffer || !BufferLength) {
	return TRUE;
    }
    /* We never map the zeroth-page in any address space so Buffer cannot
     * be less than PAGE_SIZE. */
    assert(Buffer >= PAGE_SIZE);
    ULONG PageCount = 0;
    ULONG PfnCount = 0;
    MWORD VirtAddr = Buffer;
    MWORD PhyAddrStart = 0;
    MWORD PhyAddrEnd = 0;
    PAGING_STRUCTURE_TYPE PrevPageType = -1;
    while (TRUE) {
	BOOLEAN Exit = (VirtAddr >= Buffer + BufferLength);
	MWORD PhyAddr = 0;
	PPAGING_STRUCTURE Page = NULL;
	if (Exit) {
	    goto out;
	}
	Page = MmQueryPageEx(VSpace, VirtAddr, TRUE);
	if (!Page) {
	    return FALSE;
	}
	assert(Page->AvlNode.Key);
	PhyAddr = MiGetPhysicalAddress(Page);
	assert(PhyAddr);
	assert(IS_PAGE_ALIGNED(PhyAddr));

	if (!PageCount) {
	    PhyAddrStart = PhyAddr;
	    PrevPageType = Page->Type;
	}
	if (!PageCount || (PhyAddrEnd == PhyAddr && Page->Type == PrevPageType &&
			   PageCount < (1UL << MDL_PFN_PAGE_COUNT_BITS))) {
	    /* Page is physically contiguous with previous page (and page count is
	     * not larger than what can be stored in one PFN entry). In this case
	     * we simply increase the page count in the current PFN. */
	    PageCount++;
	    PhyAddrEnd = PhyAddr + MiPagingWindowSize(Page->Type);
	} else {
	out:
	    /* Page is physically discontiguous with the previous page, in which
	     * case we must write the current PFN and start a new one. */
	    assert(PageCount);
	    assert(MiPagingTypeIsPageOrLargePage(PrevPageType));
	    assert(PhyAddrStart);
	    assert(PhyAddrEnd);
	    if (PfnDb) {
		PfnDb[PfnCount] = MDL_FORM_PFN(PhyAddrStart, PageCount, CacheType,
					       MiPagingTypeIsLargePage(PrevPageType));
	    }
	    PfnCount++;
	    if (Exit) {
		break;
	    }
	    assert(Page);
	    assert(PhyAddr);
	    PhyAddrStart = PhyAddr;
	    PhyAddrEnd = PhyAddr + MiPagingWindowSize(Page->Type);
	    PageCount = 1;
	}
	VirtAddr = Page->AvlNode.Key + MiPagingWindowSize(Page->Type);
    }
    if (pPfnCount) {
	*pPfnCount = PfnCount;
    }
    return TRUE;
}

/*
 * Check if the address window in the given VSpace is fully mapped
 *
 * If Writeable is TRUE, pages must be mapped read-write.
 * If Writable is FALSE, pages can be mapped with any rights
 *
 * On success, the address window will be rounded to the nearest
 * boundary of the underlying lowest-level paging structure.
 */
static NTSTATUS MiEnsureWindowMapped(IN PVIRT_ADDR_SPACE VSpace,
				     IN OUT MWORD *pStartAddr,
				     IN OUT MWORD *pWindowSize,
				     IN BOOLEAN Writable)
{
    assert(VSpace != NULL);
    assert(pStartAddr != NULL);
    assert(pWindowSize != NULL);
    MWORD StartAddr = *pStartAddr;
    MWORD EndAddr = PAGE_ALIGN_UP(StartAddr + *pWindowSize);
    assert(StartAddr < EndAddr);
    PPAGING_STRUCTURE Page = MiQueryVirtualAddress(VSpace, StartAddr);
    if (Page != NULL) {
	StartAddr = Page->AvlNode.Key;
    }
    MWORD CurrentAddr = StartAddr;
    while (CurrentAddr < EndAddr) {
	if (Page == NULL) {
	    return STATUS_NOT_COMMITTED;
	}
	if (!Page->Mapped) {
	    /* We should never put an unmapped page in a paging substructure tree */
	    assert(FALSE);
	    return STATUS_NOT_COMMITTED;
	}
	if (!MiPagingTypeIsPageOrLargePage(Page->Type)) {
	    return STATUS_NOT_COMMITTED;
	}
	if (Writable && !MmPageIsWritable(Page)) {
	    return STATUS_INVALID_PAGE_PROTECTION;
	}
	MWORD PageEndAddr = Page->AvlNode.Key + MiPagingWindowSize(Page->Type);
	/* Make sure we don't overflow */
	assert(CurrentAddr <= PageEndAddr);
	CurrentAddr = PageEndAddr;
	Page = MiGetNextPagingStructure(Page);
    }
    *pStartAddr = StartAddr;
    *pWindowSize = CurrentAddr - StartAddr;
    return STATUS_SUCCESS;
}

/*
 * Check if the specified address window [StartAddr, EndAddr) is committed
 * with read-write access. If not, try to commit the address window with
 * read-write access.
 */
NTSTATUS MmTryCommitWindowRW(IN PVIRT_ADDR_SPACE VSpace,
			     IN MWORD StartAddr,
			     IN MWORD WindowSize)
{
    MWORD EndAddr = PAGE_ALIGN_UP(StartAddr + WindowSize);
    StartAddr = PAGE_ALIGN(StartAddr);
    assert(StartAddr < EndAddr);
    MWORD CurrentAddr = StartAddr;
    while (CurrentAddr < EndAddr) {
	NTSTATUS Status = MmCommitVirtualMemoryEx(VSpace, CurrentAddr, PAGE_SIZE);
	if (!NT_SUCCESS(Status) && (Status != STATUS_ALREADY_COMMITTED)) {
	    return Status;
	}
	CurrentAddr += PAGE_SIZE;
    }
    /* We need to call MiEnsureWindowMapped because the memory committed
     * above might be read-only. */
    return MiEnsureWindowMapped(VSpace, &StartAddr, &WindowSize, TRUE);
}

/*
 * Unmap the given address window. The actual unmapped window is returned.
 * If there is no outstanding reference to the page, the page will be
 * de-committed and its parent untyped memory will be released (recursively).
 */
VOID MiUnmapWindow(IN PVIRT_ADDR_SPACE VSpace,
		   IN OUT MWORD *pStartAddr,
		   IN OUT MWORD *WindowSize)
{
    MWORD EndAddr = PAGE_ALIGN_UP(*pStartAddr + *WindowSize);
    MWORD StartAddr = PAGE_ALIGN(*pStartAddr);
    *pStartAddr = StartAddr;
    *WindowSize = EndAddr - StartAddr;
    PPAGING_STRUCTURE Page = VSpace->RootPagingStructure;
    /* Address space is empty, so exit. */
    if (!Page) {
	return;
    }
    /* Descend through the multi-level trees and find the first page or
     * large page that is mapped at or after the starting address. */
    while (!MiPagingTypeIsPageOrLargePage(Page->Type)) {
	MWORD AlignedAddr = MiSanitizeAlignment(MiPagingSubStructureType(Page->Type),
						StartAddr);
	PAVL_TREE Tree = &Page->SubStructureTree;
	PAVL_NODE Node = AvlTreeFindNodeOrNext(Tree, AlignedAddr);
	PPAGING_STRUCTURE SubStructure = AVL_NODE_TO_PAGING_STRUCTURE(Node);
	if (!SubStructure) {
	    break;
	}
	Page = SubStructure;
	if (!MiPagingStructureContainsAddr(Page, StartAddr)) {
	    break;
	}
    }
    if (!MiPagingTypeIsPageOrLargePage(Page->Type)) {
	if (Page->AvlNode.Key >= StartAddr) {
	    /* If Page is an empty paging structure, this is a no-op. */
	    Page = MiGetFirstPage(Page);
	} else {
	    /* In this case the page table contains no pages with an address
	     * greater than or equal to StartAddr, so go to the next page. */
	    Page = MiGetNextPagingStructure(Page);
	}
    }
    /* Delete all the paging structures till EndAddr is reached. */
    while (Page && Page->AvlNode.Key < EndAddr) {
	PPAGING_STRUCTURE NextPage = MiGetNextPagingStructure(Page);
	/* MiDeletePage will delete the parent paging structure if
	 * it becomes empty. */
	MiDeletePage(Page);
	Page = NextPage;
    }
}

/*
 * Uncommit the given VAD. This does not delete the VAD itself.
 */
static VOID MiUncommitVad(IN PMMVAD Vad)
{
    assert(Vad != NULL);
    assert(Vad->VSpace != NULL);
    MWORD StartAddr = Vad->AvlNode.Key;
    MWORD WindowSize = Vad->WindowSize;
    MiUnmapWindow(Vad->VSpace, &StartAddr, &WindowSize);
    if (Vad->Flags.BitmapManaged && Vad->CommitmentStatus.Bitmaps) {
	MWORD AllocationUnits = Vad->WindowSize >> Vad->CommitmentStatus.LowZeroBits;
	if (AllocationUnits > LOW_BITMAP_MAXSIZE) {
	    for (MWORD i = 0; i < AllocationUnits / LOW_BITMAP_MAXSIZE; i++) {
		if (Vad->CommitmentStatus.Bitmaps[i]) {
		    MiFreePool(Vad->CommitmentStatus.Bitmaps[i]);
		}
	    }
	}
	MiFreePool(Vad->CommitmentStatus.Bitmaps);
	Vad->CommitmentStatus.Bitmaps = NULL;
    }
}

/*
 * Uncommit the pages in the VAD, detach it from its VSpace (and its master
 * VSpace if there is one) and free the Vad data structure from the ExPool.
 *
 * NOTE: If there are viewers (whether in this VSpace or in a different one)
 * mirroring pages of this VAD, those mirrored pages will NOT be uncommitted.
 */
VOID MmDeleteVad(IN PMMVAD Vad)
{
    MmDbg("Deleting vad %p key %p\n", Vad, (PVOID)Vad->AvlNode.Key);
    assert(Vad != NULL);
    assert(Vad->VSpace != NULL);
    assert(MiVSpaceFindVadNode(Vad->VSpace, Vad->AvlNode.Key) == Vad);
    MiUncommitVad(Vad);
    AvlTreeRemoveNode(&Vad->VSpace->VadTree, &Vad->AvlNode);
    if (Vad->Section) {
	assert(Vad->SectionLink.Flink != NULL);
	assert(Vad->SectionLink.Blink != NULL);
	assert(ListHasEntry(&Vad->Section->VadList, &Vad->SectionLink));
	RemoveEntryList(&Vad->SectionLink);
	ObDereferenceObject(Vad->Section);
    }
    if (Vad->Flags.MirroredMemory) {
	assert(Vad->MirroredMemory.ViewerLink.Flink != NULL);
	assert(Vad->MirroredMemory.ViewerLink.Blink != NULL);
	assert(!IsListEmpty(&Vad->MirroredMemory.ViewerLink));
	RemoveEntryList(&Vad->MirroredMemory.ViewerLink);
    }
    MiFreePool(Vad);
}

/*
 * This is the raw unmap routine that operates at the page level and does not
 * touch the VAD. Only the cache manager should call this routine to unmap the
 * pages in the cache view space managed by bitmaps.
 */
VOID MmUnmapWindowEx(IN PVIRT_ADDR_SPACE VSpace,
		     IN MWORD StartAddr,
		     IN MWORD WindowSize)
{
    MiUnmapWindow(VSpace, &StartAddr, &WindowSize);
}

/*
 * Search for a suitable address window in the specified region of the target
 * address space and map the source window into it (up to the specified commit
 * size), returning the resulting VAD in the target address space.
 *
 * If TargetCommitSize is zero, the region will be reserved but not committed.
 */
static NTSTATUS MiMapSharedRegion(IN PVIRT_ADDR_SPACE SrcVSpace,
				  IN MWORD SrcWindowStart,
				  IN MWORD SrcWindowSize,
				  IN PVIRT_ADDR_SPACE TargetVSpace,
				  IN MWORD TargetVaddrStart,
				  IN MWORD TargetVaddrEnd,
				  IN MWORD TargetReserveFlag,
				  IN MWORD TargetCommitSize,
				  IN MEMORY_CACHING_TYPE CacheType,
				  OUT PMMVAD *pTargetVad)
{
    assert(pTargetVad != NULL);
    PMMVAD TargetVad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(TargetVSpace,
				     TargetVaddrStart,
				     TargetVaddrEnd,
				     SrcWindowSize,
				     0, 0,
				     MEM_RESERVE_MIRRORED_MEMORY | TargetReserveFlag,
				     &TargetVad));
    assert(TargetVad != NULL);
    assert(TargetVad->WindowSize == SrcWindowSize);

    MmRegisterMirroredMemory(TargetVad, SrcVSpace, SrcWindowStart, CacheType);
    if (TargetCommitSize) {
	RET_ERR_EX(MmCommitVirtualMemoryEx(TargetVSpace, TargetVad->AvlNode.Key,
					   TargetCommitSize),
		   MmDeleteVad(TargetVad));
    }

    *pTargetVad = TargetVad;
    return STATUS_SUCCESS;
}

/*
 * Maps the user buffer in the given virt addr space into another
 * virt addr space, returning the starting virtual address of the
 * buffer in the target virt addr space. The buffer address and
 * buffer length do not need to be page-aligned.
 *
 * If ReadOnly is TRUE, the target pages will be mapped read-only.
 * Otherwise the target pages will be mapped read-write.
 *
 * If ReadOnly is FALSE, the user buffer must be writable by the user.
 * Otherwise STATUS_INVALID_PAGE_PROTECTION is returned.
 *
 * If ReserveOnly is TRUE, the target virtual address region will be
 * reserved, but no pages will actually be committed.
 */
NTSTATUS MmMapUserBufferEx(IN PVIRT_ADDR_SPACE VSpace,
			   IN MWORD BufferStart,
			   IN MWORD BufferLength,
			   IN PVIRT_ADDR_SPACE TargetVSpace,
			   IN MWORD TargetVaddrStart,
			   IN MWORD TargetVaddrEnd,
			   OUT MWORD *TargetStartAddr,
			   IN ULONG Flags,
			   IN MEMORY_CACHING_TYPE CacheType)
{
    assert(VSpace != NULL);
    assert(TargetVSpace != NULL);
    assert(TargetStartAddr != NULL);
    MWORD UserWindowStart = BufferStart;
    MWORD WindowSize = BufferLength;
    BOOLEAN ReadOnly = !!(Flags & MM_MAP_USER_BUFFER_READ_ONLY);
    BOOLEAN ReserveOnly = !!(Flags & MM_MAP_USER_BUFFER_RESERVE_ONLY);
    RET_ERR_EX(MiEnsureWindowMapped(VSpace, &UserWindowStart, &WindowSize, !ReadOnly),
	       {
		   MmDbg("User window not mapped [%p, %p)\n",
			 (PVOID)UserWindowStart, (PVOID)(UserWindowStart+WindowSize));
		   MmDbgDumpVSpace(VSpace);
	       });

    PMMVAD TargetBufferVad = NULL;
    /* We should always try reserving a large-page aligned window just in case
     * the original region is mapped using large pages. */
    ULONG ReserveFlags = MEM_RESERVE_LARGE_PAGES;
    if (ReadOnly) {
	ReserveFlags |= MEM_RESERVE_READ_ONLY;
    }
    RET_ERR(MiMapSharedRegion(VSpace, UserWindowStart, WindowSize, TargetVSpace,
			      TargetVaddrStart, TargetVaddrEnd, ReserveFlags,
			      ReserveOnly ? 0 : WindowSize, CacheType, &TargetBufferVad));
    *TargetStartAddr = BufferStart - UserWindowStart + TargetBufferVad->AvlNode.Key;
    return STATUS_SUCCESS;
}

/*
 * Unmap the memory region that was previously mapped into the target
 * address space.
 */
VOID MmUnmapRegion(IN PVIRT_ADDR_SPACE VSpace,
		   IN MWORD StartAddr)
{
    MmDbg("Unmapping region starting %p for vspace cap 0x%zx\n",
	  (PVOID)StartAddr, VSpace->VSpaceCap);
    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, StartAddr);
    if (!Vad) {
	assert(FALSE);
	return;
    }
    assert(MiVadNodeContainsAddr(Vad, StartAddr));
    if (Vad->Flags.BitmapManaged) {
	ULONG LowZeroBits = Vad->CommitmentStatus.LowZeroBits;
	StartAddr >>= LowZeroBits;
	StartAddr <<= LowZeroBits;
	MiUnmarkCommittedSubregion(Vad, StartAddr);
	MmUnmapWindowEx(VSpace, StartAddr, 1ULL << LowZeroBits);
    } else {
	MmDeleteVad(Vad);
    }
}

/*
 * Map the client page at the specified address into the hyperspace
 * so the server can access it. If the page is a large page, the large
 * page hyperspace will be used. Otherwise the page is mapped at the
 * regular page (4K on x86) hyperspace.
 */
NTSTATUS MmMapHyperspacePage(IN PVIRT_ADDR_SPACE VSpace,
			     IN MWORD Address,
			     IN BOOLEAN Write,
			     OUT PVOID *MappedAddress,
			     OUT ULONG *MappedLength)
{
    PPAGING_STRUCTURE Page = MmQueryPageEx(VSpace, Address, TRUE);
    if (!Page) {
	return STATUS_INVALID_ADDRESS;
    }
    if (Write && !MmPageIsWritable(Page)) {
	return STATUS_INVALID_PAGE_PROTECTION;
    }
    assert(MiPagingTypeIsPageOrLargePage(Page->Type));
    assert(Page->Mapped);
    MWORD HyperspaceAddr = MiPagingTypeIsPage(Page->Type) ?
	HYPERSPACE_4K_PAGE_START : HYPERSPACE_LARGE_PAGE_START;
    MWORD Offset = Address - Page->AvlNode.Key;
    assert(Offset < MiPagingWindowSize(Page->Type));
    RET_ERR(MmMapMirroredMemory(VSpace, Page->AvlNode.Key, &MiNtosVaddrSpace,
				HyperspaceAddr, MiPagingWindowSize(Page->Type),
				Write ? MM_RIGHTS_RW : MM_RIGHTS_RO,
				MM_ATTRIBUTES_DEFAULT, FALSE));
    *MappedAddress = (PVOID)(HyperspaceAddr + Offset);
    *MappedLength = MiPagingWindowSize(Page->Type) - Offset;
    return STATUS_SUCCESS;
}

/*
 * Unmap the hyperspace page at the given address.
 */
VOID MmUnmapHyperspacePage(IN PVOID MappedAddress)
{
    MmUnmapWindow((MWORD)MappedAddress, 1);
}

/* ARM64 ESR Bits */
#define ARM_ESR_RW_BIT        (1 << 6)   /* Bit 6: 0=Read, 1=Write */
#define ARM_ESR_EC_MASK       (0x3F)     /* EC is Bits [31:26] */
#define ARM_ESR_EC_SHIFT      (26)

/* Exception Classes for Aborts */
#define EC_INSTRUCTION_ABORT_LOWER 0x20
#define EC_INSTRUCTION_ABORT_SAME  0x21
#define EC_DATA_ABORT_LOWER        0x24
#define EC_DATA_ABORT_SAME         0x25

FORCEINLINE BOOLEAN MiIsPermissionFault(IN MWORD Fsr)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    return Fsr & 0x1;
#elif defined(_M_ARM64)
    return ((Fsr >> 2) & 0xf) == 3;
#else
#error "Unsupported architecture"
#endif
}

FORCEINLINE BOOLEAN MiIsWriteFault(IN MWORD Fsr)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    return Fsr & 0x2;
#elif defined(_M_ARM64)
    ULONG Ec = (Fsr >> ARM_ESR_EC_SHIFT) & ARM_ESR_EC_MASK;
    /* Only Data Aborts have a valid WnR bit.
     * Instruction aborts are never "writes". */
    if (Ec == EC_DATA_ABORT_LOWER || Ec == EC_DATA_ABORT_SAME) {
        return (Fsr & ARM_ESR_RW_BIT) != 0;
    }
    return FALSE;
#else
#error "Unsupported architecture"
#endif
}

FORCEINLINE BOOLEAN MiIsExecuteFault(IN MWORD Fsr)
{
#if defined(_M_IX86) || defined(_M_AMD64)
    return Fsr & 0x10;
#elif defined(_M_ARM64)
    ULONG Ec = (Fsr >> ARM_ESR_EC_SHIFT) & ARM_ESR_EC_MASK;
    /* If the Exception Class is an Instruction Abort, it's an execute fault. */
    return (Ec == EC_INSTRUCTION_ABORT_LOWER || Ec == EC_INSTRUCTION_ABORT_SAME);
#else
#error "Unsupported architecture"
#endif
}

/* Remap the specified address window with the new access rights. Note that
 * since all page caps are derived with full seL4 rights, we can simply unmap
 * the page cap and remap the same page cap using the new access rights. In
 * other words, the paging rights (RWX) of the mapping is set at mapping time,
 * not at page cap creation time. The unmapped region in the specified window
 * is ignored (no error is generated for unmapped pages in the region). */
static NTSTATUS MiRemapVirtualMemory(IN PVIRT_ADDR_SPACE VSpace,
				     IN MWORD StartAddr,
				     IN MWORD WindowSize,
				     IN PAGING_RIGHTS Rights)
{
    assert(IS_PAGE_ALIGNED(StartAddr));
    assert(IS_PAGE_ALIGNED(WindowSize));
    UNIMPLEMENTED;
}

static VOID MiDispatchUserException(IN PTHREAD Thread,
				    IN MWORD Addr,
				    IN MWORD Ip,
				    IN MWORD FaultStatusRegister)
{
    MmDbgDumpVSpace(&Thread->Process->VSpace);
    /* For VM fault, the first exception parameter is the type of the fault (read = 0,
     * write = 1, no-execute = 8). The second exception parameter is the vm address
     * that the client was trying to access. */
    MWORD ExceptionParameters[] = {
	MiIsExecuteFault(FaultStatusRegister) ? 8 : MiIsWriteFault(FaultStatusRegister),
	Addr
    };
    NTSTATUS Status = KeDispatchUserException(Thread, STATUS_ACCESS_VIOLATION, Ip,
					      ARRAYSIZE(ExceptionParameters),
					      ExceptionParameters);
    if (!NT_SUCCESS(Status)) {
	MmDbg("Failed to dispatch user exception (status 0x%x), terminating thread.\n",
	      Status);
	PsTerminateThread(Thread, Status);
    }
}

typedef struct _FILE_MAP_PIN_DATA_CONTEXT {
    PTHREAD Thread;
    MWORD Addr;
    MWORD Ip;
    MWORD FaultStatusRegister;
    PSECTION Section;
} FILE_MAP_PIN_DATA_CONTEXT, *PFILE_MAP_PIN_DATA_CONTEXT;

static VOID MiFileMapPinDataCallback(IN PIO_FILE_CONTROL_BLOCK Fcb,
				     IN ULONG64 FileOffset,
				     IN ULONG64 Length,
				     IN NTSTATUS Status,
				     IN OUT PVOID Context)
{
    PFILE_MAP_PIN_DATA_CONTEXT Ctx = Context;
    assert(Ctx);
    MmDbg("File mapping callback, file offset 0x%llx, length 0x%llx, status 0x%x, "
	  "thread %p (%s), address %p, ip %p\n", FileOffset, Length, Status,
	  Ctx->Thread, KEDBG_THREAD_TO_FILENAME(Ctx->Thread),
	  (PVOID)Ctx->Addr, (PVOID)Ctx->Ip);
    if (!NT_SUCCESS(Status)) {
	goto err;
    }
    /* Vad may no longer be valid when this routine is called, so we need to check. */
    PMMVAD Vad = MiVSpaceFindVadNode(&Ctx->Thread->Process->VSpace, Ctx->Addr);
    if (!Vad || !Vad->Flags.FileMap || Vad->Section != Ctx->Section) {
	goto err;
    }
    MWORD Alignment = 1ULL << MM_MINIMUM_LOW_ZERO_BITS;
    assert(Vad->AvlNode.Key <= ALIGN_DOWN_BY(Ctx->Addr, Alignment));
    MWORD WindowAddr = max(ALIGN_DOWN_BY(Ctx->Addr, Alignment), Vad->AvlNode.Key);
    MWORD WindowSize = min(Alignment, Vad->AvlNode.Key + Vad->WindowSize - WindowAddr);
    if (NT_SUCCESS(MiMapFileVad(Vad, WindowAddr, WindowSize))) {
	PsResumeThread(Ctx->Thread);
	goto out;
    }
err:
    MiDispatchUserException(Ctx->Thread, Ctx->Addr, Ctx->Ip, Ctx->FaultStatusRegister);
out:
    ObDereferenceObject(Ctx->Thread);
    ObDereferenceObject(Ctx->Section);
    ExFreePoolWithTag(Ctx, NTOS_MM_TAG);
}

/*
 * Try to handle the thread VM fault. If successful, resume the
 * thread. Otherwise, call KeDispatchUserException to dispatch SEH.
 * In the case that the page fault handler needs to wait for IO,
 * thread resumption is done asynchronously (ie. thread is not
 * resumed immediately, but only after data become available). If
 * an IO error occurred during page fault handling, SEH will be
 * dispatched.
 */
VOID MmHandleThreadVmFault(IN PTHREAD Thread,
			   IN MWORD Addr,
			   IN MWORD Ip,
			   IN MWORD FaultStatusRegister)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    MmDbg("Attempt to handle VM-FAULT of thread %s at %p\n",
	  Thread->DebugName, (PVOID)Addr);
    PMMVAD Vad = MiVSpaceFindVadNode(&Thread->Process->VSpace, Addr);
    if (Vad == NULL) {
	goto err;
    }

    /* Vad is a view of a data section. For file-backed (including page-file-backed) data
     * sections, initially the view region is unmapped and we should load the file from disk
     * (no-op in the case of page-file) and map the view region, but for non-page-file-backed
     * data sections this mapping is read-only (for page-file-backed data sections, this is
     * read-write if allowed by section protection). For writable views, the next write will
     * trigger another VM fault at which time we remap the pages as writable. For readonly
     * views, writing leads to SEH dispatch. */
    if (Vad->Flags.FileMap) {
	PSECTION Section = Vad->Section;
	assert(Section->Flags.File);
	if (MiIsPermissionFault(FaultStatusRegister)) {
	    if (Vad->Flags.ReadOnly || Section->Flags.PageFile) {
		goto err;
	    }
	    /* Page is present but mapped read-only. We will remap the page as readwrite.
	     * We do this for the entire 64KB-aligned window that contains the address,
	     * ignoring the unmapped pages in the window. */
	    MWORD Alignment = 1ULL << MM_MINIMUM_LOW_ZERO_BITS;
	    assert(Vad->AvlNode.Key <= ALIGN_DOWN_BY(Addr, Alignment));
	    MWORD WindowAddr = max(ALIGN_DOWN_BY(Addr, Alignment), Vad->AvlNode.Key);
	    MWORD WindowSize = min(Alignment, Vad->AvlNode.Key + Vad->WindowSize - WindowAddr);
	    if (!NT_SUCCESS(MiRemapVirtualMemory(&Thread->Process->VSpace,
						 WindowAddr, WindowSize,
						 MM_RIGHTS_RW))) {
		goto err;
	    }
	    ULONG64 FileOffset =
		WindowAddr - Vad->AvlNode.Key + Vad->DataSectionView.SectionOffset;
	    CcSetSharedMapDirtyBits(Section->DataSectionObject->Fcb, FileOffset,
				    WindowSize, TRUE);
	    return;
	}
	PDATA_SECTION_OBJECT DataSection = Section->DataSectionObject;
	assert(DataSection);
	PIO_FILE_CONTROL_BLOCK Fcb = DataSection->Fcb;
	if (!Fcb) {
	    assert(Section->Flags.PageFile);
	    /* We are a pagefile-backed section without SEC_COMMIT, so always fail. */
	    goto err;
	}
	/* Page is not present. We need to load the data file from disk and map the pages. */
	PFILE_MAP_PIN_DATA_CONTEXT Context =
	    ExAllocatePoolWithTag(sizeof(FILE_MAP_PIN_DATA_CONTEXT), NTOS_MM_TAG);
	if (!Context) {
	    goto err;
	}
	Context->Addr = Addr;
	Context->Ip = Ip;
	Context->FaultStatusRegister = FaultStatusRegister;
	Context->Section = Section;
	ObReferenceObjectByPointer(Section);
	Context->Thread = Thread;
	ObReferenceObjectByPointer(Thread);
	ULONG64 FileOffset = VIEW_ALIGN(PAGE_ALIGN(Addr) - Vad->AvlNode.Key +
					Vad->DataSectionView.SectionOffset);
	ULONG WindowSize = min(VIEW_SIZE, Fcb->FileSize - FileOffset);
	CcPinDataEx(Fcb, FileOffset, WindowSize, FALSE, MiFileMapPinDataCallback, Context);
	return;
    }
    if (Vad->Flags.CommitOnDemand) {
	if (!NT_SUCCESS(MmCommitVirtualMemoryEx(&Thread->Process->VSpace,
						PAGE_ALIGN(Addr), PAGE_SIZE))) {
	    goto err;
	}
	PsResumeThread(Thread);
	return;
    }
    /* For unhandled VM fault, we dispatch user SEH. */
err:
    MiDispatchUserException(Thread, Addr, Ip, FaultStatusRegister);
}

NTSTATUS MmMapIoSpaceEx(IN PVIRT_ADDR_SPACE VSpace,
			IN MWORD WindowStart,
			IN MWORD WindowEnd,
			IN MWORD WindowSize,
			IN ULONG LowZeroBits,
			IN MWORD PhyAddr,
			IN MEMORY_CACHING_TYPE CacheType,
			IN ULONG Flags,
			OUT MWORD *pVirtAddr,
			OUT OPTIONAL PMMVAD *pVad)
{
    assert(WindowSize);
    MWORD PageOffset = PhyAddr - PAGE_ALIGN(PhyAddr);
    PhyAddr = PAGE_ALIGN(PhyAddr);
    WindowSize = PAGE_ALIGN_UP(WindowSize + PageOffset);
    assert(IS_PAGE_ALIGNED(WindowStart));
    assert(IS_PAGE_ALIGNED(WindowEnd));
    PMMVAD Vad = NULL;
    ULONG ReserveFlags = MEM_RESERVE_PHYSICAL_MAPPING;
    if (Flags & MM_MAP_IO_SPACE_READ_ONLY) {
	ReserveFlags |= MEM_RESERVE_READ_ONLY;
    }
    if (Flags & MM_MAP_IO_SPACE_LARGE_PAGE) {
	ReserveFlags |= MEM_RESERVE_LARGE_PAGES;
    }
    BOOLEAN Retry = TRUE;
retry:
    RET_ERR(MmReserveVirtualMemoryEx(VSpace, WindowStart, WindowEnd, WindowSize,
				     LowZeroBits, 0, ReserveFlags, &Vad));
    Vad->PhysicalSectionView.SectionOffset = 0;

    PAGING_ATTRIBUTES Attributes = MiGetPagingAttributesFromCacheType(CacheType);
    MWORD VirtAddr = Vad->AvlNode.Key;
    PAGING_RIGHTS PagingRights =
	(Flags & MM_MAP_IO_SPACE_READ_ONLY) ? MM_RIGHTS_RO : MM_RIGHTS_RW;
    BOOLEAN UseLargePage = !!(Flags & MM_MAP_IO_SPACE_LARGE_PAGE) &&
	IS_LARGE_PAGE_ALIGNED(PhyAddr) && IS_LARGE_PAGE_ALIGNED(VirtAddr);
    NTSTATUS Status = MiMapIoMemory(VSpace, PhyAddr, VirtAddr, WindowSize, PagingRights,
				    Attributes, UseLargePage);
    if (!NT_SUCCESS(Status)) {
	MmDeleteVad(Vad);
	/* If we failed to map the IO page due to the physical region having already
	 * been mapped using large pages, retry with a larger region size. */
	if (Status == STATUS_RESOURCE_IN_USE && Retry) {
	    Retry = FALSE;
	    PageOffset += PhyAddr - LARGE_PAGE_ALIGN(PhyAddr);
	    PhyAddr = LARGE_PAGE_ALIGN(PhyAddr);
	    WindowSize = LARGE_PAGE_ALIGN_UP(WindowSize + PageOffset);
	    assert(IS_LARGE_PAGE_ALIGNED(WindowStart));
	    assert(IS_LARGE_PAGE_ALIGNED(WindowEnd));
	    goto retry;
	}
    }
    *pVirtAddr = VirtAddr + PageOffset;
    if (pVad) {
	*pVad = Vad;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmMapPhysicalMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
			       IN MWORD WindowStart,
			       IN MWORD WindowEnd,
			       IN ULONG LowZeroBits,
			       IN PULONG_PTR PfnDb,
			       IN ULONG PfnCount,
			       IN BOOLEAN ReadOnly,
			       OUT MWORD *VirtBase)
{
    *VirtBase = 0;
    if (!PfnCount) {
	return STATUS_INVALID_PARAMETER;
    }
    MWORD WindowSize = 0;
    for (ULONG i = 0; i < PfnCount; i++) {
	WindowSize += MDL_PFN_WINDOW_SIZE(PfnDb[i]);
    }
    PMMVAD Vad = NULL;
    ULONG Flags = MEM_RESERVE_PHYSICAL_MAPPING;
    if (PfnDb[0] & MDL_PFN_ATTR_LARGE_PAGE) {
	Flags |= MEM_RESERVE_LARGE_PAGES;
    }
    RET_ERR(MmReserveVirtualMemoryEx(VSpace, WindowStart, WindowEnd, WindowSize,
				     LowZeroBits, 0, Flags, &Vad));
    Vad->PhysicalSectionView.SectionOffset = 0;
    MWORD VirtAddr = Vad->AvlNode.Key;
    PAGING_RIGHTS PagingRights = ReadOnly ? MM_RIGHTS_RO : MM_RIGHTS_RW;
    for (ULONG i = 0; i < PfnCount; i++) {
	MWORD PhyAddr = MDL_PFN_PAGE_ADDRESS(PfnDb[i]);
	MWORD WindowSize = MDL_PFN_WINDOW_SIZE(PfnDb[i]);
	BOOLEAN UseLargePage = (PfnDb[i] & MDL_PFN_ATTR_LARGE_PAGE) &&
	    IS_LARGE_PAGE_ALIGNED(VirtAddr);
	RET_ERR_EX(MiMapIoMemory(VSpace, PhyAddr, VirtAddr, WindowSize, PagingRights,
				 MiGetPagingAttributesFromCacheType(MmGetPfnCacheType(PfnDb[i])),
				 UseLargePage),
		   MmDeleteVad(Vad));
	VirtAddr += WindowSize;
    }
    *VirtBase = Vad->AvlNode.Key;
    assert(VirtAddr - *VirtBase == WindowSize);
    return STATUS_SUCCESS;
}

/*
 * Allocate physically contiguous memory of given size. Memory allocated is
 * always aligned on the smallest power of two that is at least the given size.
 * In other words, let n be the smallest n such that 2^n >= Length, then both
 * the returned physical address and virtual address are always aligned by 2^n.
 */
NTSTATUS MmAllocatePhysicallyContiguousMemory(IN PVIRT_ADDR_SPACE VSpace,
					      IN MWORD Length,
					      IN MWORD HighestPhyAddr,
					      IN MEMORY_CACHING_TYPE CacheType,
					      IN BOOLEAN UseLargePage,
					      OUT MWORD *VirtAddr,
					      OUT MWORD *pPhyAddr)
{
    Length = PAGE_ALIGN_UP(Length);
    ULONG Log2Size = 0;
    while ((1ULL << Log2Size) < Length) {
	Log2Size++;
    }
    PUNTYPED Untyped = NULL;
    RET_ERR(MmRequestUntypedEx(Log2Size, HighestPhyAddr, &Untyped));
    MWORD PhyAddr = Untyped->AvlNode.Key;
    RET_ERR_EX(MmMapIoSpaceEx(VSpace, USER_IMAGE_REGION_START, USER_ADDRESS_END, Length,
			      Log2Size, PhyAddr, CacheType,
			      UseLargePage ? MM_MAP_IO_SPACE_LARGE_PAGE : 0,
			      VirtAddr, NULL),
	       MmReleaseUntyped(Untyped));
    *pPhyAddr = PhyAddr;
    return STATUS_SUCCESS;
}

VOID MmUnmapIoSpaceEx(IN PVIRT_ADDR_SPACE VSpace,
		      IN MWORD VirtAddr)
{
    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, VirtAddr);
    if (!Vad) {
	assert(FALSE);
	return;
    }
    assert(MiVadNodeContainsAddr(Vad, VirtAddr));
    assert(Vad->Flags.PhysicalMapping);
    MmDeleteVad(Vad);
}

NTSTATUS MmFreePhysicallyContiguousMemory(IN PVIRT_ADDR_SPACE VSpace,
					  IN MWORD VirtAddr,
					  IN MWORD Length,
					  IN MEMORY_CACHING_TYPE CacheType)
{
#if DBG
    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, VirtAddr);
    if (!Vad) {
	MmDbg("Invalid base address %p\n", (PVOID)VirtAddr);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER_1;
    }
    assert(VirtAddr == Vad->AvlNode.Key);
    assert(Length == Vad->WindowSize);
    assert(Vad->Flags.PhysicalMapping);
#endif
    MmUnmapIoSpaceEx(VSpace, VirtAddr);
    return STATUS_SUCCESS;
}

NTSTATUS NtAllocateVirtualMemory(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
                                 IN HANDLE ProcessHandle,
                                 IN OUT OPTIONAL PVOID *BaseAddress,
                                 IN ULONG_PTR HighZeroBits,
                                 IN OUT SIZE_T *RegionSize,
                                 IN ULONG AllocationType,
                                 IN ULONG Protect)
{
    PPROCESS Process = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, ProcessHandle,
				      OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    assert(Process != NULL);
    PVIRT_ADDR_SPACE VSpace = &Process->VSpace;
    MmDbg("Process %s VSpace cap 0x%zx base address %p highzerobits 0x%zx "
	  "region size 0x%zx allocation type 0x%x protect 0x%x\n",
	  KEDBG_PROCESS_TO_FILENAME(Process),
	  VSpace->VSpaceCap, BaseAddress ? *BaseAddress : NULL, (MWORD)HighZeroBits,
	  RegionSize ? (MWORD)*RegionSize : 0, AllocationType, Protect);

    if (AllocationType & MEM_PHYSICAL) {
	/* seL4 does not support Address Windowing Extensions on i386, so fail. */
	return STATUS_NOT_SUPPORTED;
    }

    /* On 64-bit systems the HighZeroBits parameter is interpreted as a bit mask if
     * it is greater than or equal to 32. Convert the bit mask to the number of bits
     * in this case. */
#ifdef _WIN64
    if (HighZeroBits >= 32) {
        HighZeroBits = 64 - RtlFindMostSignificantBit(HighZeroBits) - 1;
    } else if (HighZeroBits) {
	/* The high 32-bits of the allocated address are also required to be zero,
	 * in order to retain compatibility with 32-bit systems. Therefore we need
	 * to increase HighZeroBits by 32. */
	HighZeroBits += 32;
    }
#endif

    NTSTATUS Status = STATUS_INTERNAL_ERROR;
    if (HighZeroBits > MM_MAXIMUM_HIGH_ZERO_BITS) {
        Status = STATUS_INVALID_PARAMETER_3;
	goto out;
    }

    /* Determine the address window in which we would like to search for unused region */
    if (RegionSize == NULL || *RegionSize == 0) {
        Status = STATUS_INVALID_PARAMETER_4;
	goto out;
    }
    MWORD WindowSize = PAGE_ALIGN_UP(*RegionSize);
    MWORD StartAddr = LOWEST_USER_ADDRESS;
    MWORD EndAddr = HIGHEST_USER_ADDRESS;
    if (BaseAddress != NULL && *BaseAddress != NULL) {
	StartAddr = (MWORD)(*BaseAddress);
	EndAddr = StartAddr + WindowSize;
	/* Make sure specified address window is with client manageable region */
	if (StartAddr > HIGHEST_USER_ADDRESS) {
	    Status = STATUS_INVALID_PARAMETER_2;
	    goto out;
	}
	if (EndAddr > HIGHEST_USER_ADDRESS) {
	    Status = STATUS_INVALID_PARAMETER_4;
	    goto out;
	}
    }

    /* Validate the AllocationType argument */
    if ((AllocationType & (MEM_COMMIT | MEM_RESERVE | MEM_RESET)) == 0) {
        Status = STATUS_INVALID_PARAMETER_5;
	goto out;
    }
    if ((AllocationType & MEM_RESET) && (AllocationType != MEM_RESET)) {
        Status = STATUS_INVALID_PARAMETER_5;
	goto out;
    }
    if (AllocationType & MEM_LARGE_PAGES) {
        /* Large page allocations MUST be committed */
        if (!(AllocationType & MEM_COMMIT)) {
            Status = STATUS_INVALID_PARAMETER_5;
	    goto out;
        }
        /* These flags are not allowed with large page allocations */
        if (AllocationType & (MEM_PHYSICAL | MEM_RESET | MEM_WRITE_WATCH)) {
            Status = STATUS_INVALID_PARAMETER_5;
	    goto out;
        }
    }
    if (AllocationType & MEM_COMMIT_ON_DEMAND) {
	if (!(AllocationType & MEM_RESERVE) || (AllocationType & MEM_COMMIT) ||
	    (AllocationType & MEM_RESET) || (AllocationType & MEM_PHYSICAL) ||
	    (AllocationType & MEM_WRITE_WATCH)) {
            Status = STATUS_INVALID_PARAMETER_5;
	    goto out;
	}
    }
    /* These are not implemented yet */
    if ((AllocationType & (MEM_RESET | MEM_WRITE_WATCH))) {
        UNIMPLEMENTED;
    }

    PMMVAD Vad = NULL;
    if ((AllocationType & MEM_RESERVE) || BaseAddress == NULL || *BaseAddress == NULL) {
	MWORD Flags = MEM_RESERVE_OWNED_MEMORY;
	if (AllocationType & MEM_LARGE_PAGES) {
	    Flags |= MEM_RESERVE_LARGE_PAGES;
	}
	if (AllocationType & MEM_TOP_DOWN) {
	    Flags |= MEM_RESERVE_TOP_DOWN;
	}
	if (AllocationType & MEM_COMMIT_ON_DEMAND) {
	    MmDbg("Commit on demand\n");
	    Flags |= MEM_COMMIT_ON_DEMAND;
	}
	IF_ERR_GOTO(out, Status,
		    MmReserveVirtualMemoryEx(VSpace, StartAddr, EndAddr, WindowSize,
					     0, HighZeroBits, Flags, &Vad));
	StartAddr = Vad->AvlNode.Key;
	WindowSize = Vad->WindowSize;
	EndAddr = StartAddr + WindowSize;
    }

    if (AllocationType & MEM_COMMIT) {
	IF_ERR_GOTO(out, Status,
		    MmCommitVirtualMemoryEx(VSpace, StartAddr, WindowSize));
    }

    if (BaseAddress != NULL) {
	*BaseAddress = (PVOID) StartAddr;
    }

    *RegionSize = WindowSize;

    Status = STATUS_SUCCESS;
out:
    if (!NT_SUCCESS(Status) && (Vad != NULL) && (AllocationType & MEM_RESERVE)) {
	MmDeleteVad(Vad);
    }
    assert(Process != NULL);
    ObDereferenceObject(Process);
    return Status;
}

NTSTATUS NtFreeVirtualMemory(IN ASYNC_STATE State,
			     IN PTHREAD Thread,
                             IN HANDLE ProcessHandle,
                             IN OUT PVOID *BaseAddress,
                             IN OUT SIZE_T *RegionSize,
                             IN ULONG FreeType)
{
    assert(Thread != NULL);
    assert(BaseAddress != NULL);
    assert(RegionSize != NULL);

    /*
     * Only two flags are supported, exclusively.
     */
    if (FreeType != MEM_RELEASE && FreeType != MEM_DECOMMIT) {
        DPRINT1("Invalid FreeType (0x%08x)\n", FreeType);
        return STATUS_INVALID_PARAMETER_4;
    }

    /* You can only free memory pages within the client manageable region */
    if ((MWORD)(*BaseAddress) > HIGHEST_USER_ADDRESS) {
        DPRINT1("Base address above user address space\n");
	return STATUS_INVALID_PARAMETER_2;
    }

    /* Get the process object refereed by ProcessHandle */
    PPROCESS Process = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, ProcessHandle,
				      OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    assert(Process != NULL);
    PVIRT_ADDR_SPACE VSpace = &Process->VSpace;
    MmDbg("Process %s VSpace cap 0x%zx base address %p region size 0x%zx free type 0x%x\n",
	  KEDBG_PROCESS_TO_FILENAME(Process),
	  VSpace->VSpaceCap, *BaseAddress, (MWORD)*RegionSize, FreeType);

    NTSTATUS Status = STATUS_NTOS_BUG;
    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, (MWORD)*BaseAddress);
    if (Vad == NULL) {
	MmDbg("Invalid base address %p\n", *BaseAddress);
	Status = STATUS_INVALID_PARAMETER_2;
	goto out;
    }

    if (FreeType == MEM_RELEASE) {
	/* According to M$ documentation if free type is MEM_RELEASE, the
	 * *BaseAddress parameter must be the exact same address that was
	 * originally returned by NtAllocateVirtualMemory (ie. it must equal
	 * the starting address of the VAD representing the reserved space).
	 * Additionally, *RegionSize must be zero. */
	if ((MWORD)*BaseAddress != Vad->AvlNode.Key) {
	    MmDbg("Base address does not equal start of reserved space %p\n",
		  (PVOID)Vad->AvlNode.Key);
	    Status = STATUS_INVALID_PARAMETER_2;
	    goto out;
	}
	if (*RegionSize != 0) {
	    MmDbg("Region size must be zero\n");
	    Status = STATUS_INVALID_PARAMETER_3;
	    goto out;
	}
	*RegionSize = Vad->WindowSize;
	MmDeleteVad(Vad);
    } else if (*BaseAddress == (PVOID)Vad->AvlNode.Key && *RegionSize == 0) {
	assert(FreeType == MEM_DECOMMIT);
	*RegionSize = Vad->WindowSize;
	MiUncommitVad(Vad);
    } else {
	assert(FreeType == MEM_DECOMMIT);
	MiUnmapWindow(VSpace, (MWORD *)BaseAddress, (MWORD *)RegionSize);
    }

    Status = STATUS_SUCCESS;

out:
    assert(Process != NULL);
    ObDereferenceObject(Process);
    if (!NT_SUCCESS(Status)) {
	MmDbg("NtFreeVirtualMemory failed with status 0x%x\n", Status);
	MmDbgDumpVSpace(VSpace);
    }
    return Status;
}

NTSTATUS NtWriteVirtualMemory(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
                              IN HANDLE ProcessHandle,
                              IN PVOID BaseAddress,
                              IN PVOID Buffer,
                              IN SIZE_T NumberOfBytesToWrite,
                              OUT OPTIONAL SIZE_T *NumberOfBytesWritten)
{
    assert(Buffer != NULL);
    assert(NumberOfBytesToWrite != 0);
    PPROCESS Process = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, ProcessHandle,
				      OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    assert(Process != NULL);
    PVIRT_ADDR_SPACE TargetVSpace = &Process->VSpace;
    MmDbg("Target process %s (VSpace cap 0x%zx) base address %p buffer %p length 0x%zx\n",
	  KEDBG_PROCESS_TO_FILENAME(Process),
	  TargetVSpace->VSpaceCap, BaseAddress, Buffer, (MWORD)NumberOfBytesToWrite);
    PVOID MappedTargetBuffer = NULL;
    NTSTATUS Status;
    IF_ERR_GOTO(out, Status,
		MmMapUserBuffer(TargetVSpace, (MWORD)BaseAddress,
				NumberOfBytesToWrite, &MappedTargetBuffer));
    assert(MappedTargetBuffer != NULL);
    memcpy(MappedTargetBuffer, Buffer, NumberOfBytesToWrite);
    if (NumberOfBytesWritten != NULL) {
	*NumberOfBytesWritten = NumberOfBytesToWrite;
    }
    Status = STATUS_SUCCESS;
out:
    if (MappedTargetBuffer != NULL) {
	MmUnmapUserBuffer(MappedTargetBuffer);
    }
    assert(Process != NULL);
    ObDereferenceObject(Process);
    return Status;
}


NTSTATUS NtReadVirtualMemory(IN ASYNC_STATE State,
			     IN PTHREAD Thread,
                             IN HANDLE ProcessHandle,
                             IN PVOID BaseAddress,
                             OUT PVOID Buffer,
                             IN SIZE_T NumberOfBytesToRead,
                             OUT SIZE_T *NumberOfBytesRead)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryVirtualMemory(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
                              IN HANDLE ProcessHandle,
                              IN PVOID BaseAddress,
                              IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
                              IN PVOID MemoryInformationBuffer,
                              IN ULONG MemoryInformationLength,
                              OUT OPTIONAL ULONG *ReturnLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtProtectVirtualMemory(IN ASYNC_STATE State,
				IN PTHREAD Thread,
                                IN HANDLE ProcessHandle,
                                IN OUT PVOID *BaseAddress,
                                IN OUT SIZE_T *NumberOfBytesToProtect,
                                IN ULONG NewAccessProtection,
                                OUT OPTIONAL ULONG *OldAccessProtection)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WdmMapIoSpace(IN ASYNC_STATE AsyncState,
		       IN PTHREAD Thread,
		       IN ULONG64 PhyAddr,
		       IN MWORD WindowSize,
		       IN MEMORY_CACHING_TYPE CacheType,
		       OUT PVOID *VirtAddr)
{
    assert(Thread);
    assert(Thread->Process);
    assert(IoGetDriverObjectFromProcess(Thread->Process));
    return MmMapIoSpaceEx(&Thread->Process->VSpace, USER_IMAGE_REGION_START,
			  USER_ADDRESS_END, WindowSize, 0, PhyAddr,
			  CacheType, MM_MAP_IO_SPACE_LARGE_PAGE, (MWORD *)VirtAddr, NULL);
}

NTSTATUS WdmUnmapIoSpace(IN ASYNC_STATE AsyncState,
			 IN PTHREAD Thread,
			 IN PVOID VirtualBase,
			 IN MWORD WindowSize)
{
    assert(Thread);
    assert(Thread->Process);
    assert(IoGetDriverObjectFromProcess(Thread->Process));
    MmUnmapIoSpaceEx(&Thread->Process->VSpace, (MWORD)VirtualBase);
    return STATUS_SUCCESS;
}

NTSTATUS WdmMapPhysicalMemory(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      IN PULONG_PTR PfnDb,
			      IN ULONG PfnCount,
			      OUT PVOID *VirtualAddress)
{
    assert(Thread);
    assert(Thread->Process);
    assert(IoGetDriverObjectFromProcess(Thread->Process));
    MmMapPhysicalMemoryEx(&Thread->Process->VSpace, USER_IMAGE_REGION_START, USER_ADDRESS_END,
			0, PfnDb, PfnCount, FALSE, (MWORD *)VirtualAddress);
    return STATUS_SUCCESS;
}

VOID MmDbgDumpVad(PMMVAD Vad)
{
#ifdef MMDBG
    MmDbgPrint("Dumping vad at %p\n", Vad);
    if (Vad == NULL) {
	MmDbgPrint("    (nil)\n");
	return;
    }

    MmDbgPrint("    vaddr start = %p  window size = 0x%zx\n"
	       "   %s%s%s%s%s%s%s%s%s%s%s\n",
	       (PVOID) Vad->AvlNode.Key, Vad->WindowSize,
	       Vad->Flags.NoAccess ? " no-access" : "",
	       Vad->Flags.ReadOnly ? " read-only" : "",
	       Vad->Flags.ImageMap ? " image-map" : "",
	       Vad->Flags.FileMap ? " file-map" : "",
	       Vad->Flags.CacheMap ? " cache-map" : "",
	       Vad->Flags.PhysicalMapping ? " physical-mapping" : "",
	       Vad->Flags.BitmapManaged ? " bitmap-managed" : "",
	       Vad->Flags.LargePages ? " large-pages" : "",
	       Vad->Flags.OwnedMemory ? " owned-memory" : "",
	       Vad->Flags.MirroredMemory ? " mirrored-memory" : "",
	       Vad->Flags.CommitOnDemand ? " commit-on-demand" : "");
    MmDbgPrint("    section = %p\n", Vad->Section);
    if (Vad->Flags.ImageMap) {
	MmDbgPrint("    subsection = %p\n", Vad->ImageSectionView.SubSection);
    }
    if (Vad->Flags.FileMap) {
	MmDbgPrint("    section offset = %p\n", (PVOID)Vad->DataSectionView.SectionOffset);
    }
    if (Vad->Flags.PhysicalMapping) {
	MmDbgPrint("    section offset = %p\n", (PVOID)Vad->PhysicalSectionView.SectionOffset);
    }
    if (Vad->Flags.MirroredMemory) {
	MmDbgPrint("    master vspace = %p\n", Vad->MirroredMemory.Master);
	MmDbgPrint("    start vaddr in master vspace = 0x%zx\n", Vad->MirroredMemory.StartAddr);
    }
    if (Vad->Flags.BitmapManaged) {
	MmDbgPrint("    bitmap(s) = %p\n", Vad->CommitmentStatus.Bitmap);
	MmDbgPrint("    low zero bits = %d\n", Vad->CommitmentStatus.LowZeroBits);
    }
#endif
}

VOID MmDbgDumpVSpace(PVIRT_ADDR_SPACE VSpace)
{
#ifdef MMDBG
    MmDbgPrint("Dumping virtual address space %p\n", VSpace);
    if (VSpace == NULL) {
	MmDbgPrint("    (nil)\n");
	return;
    }

    MmDbgPrint("    vspacecap = 0x%zx    asidpool = 0x%zx\n",
	       VSpace->VSpaceCap, VSpace->ASIDPool);
    MmDbgPrint("    root paging structure %p:\n", VSpace->RootPagingStructure);
    MmDbgDumpPagingStructure(VSpace->RootPagingStructure);
    MmDbgPrint("Dumping virtual address space %p vad tree %p\n    linearly:  ",
	       VSpace, &VSpace->VadTree);
    AvlDumpTreeLinear(&VSpace->VadTree);
    MmDbgPrint("\n    vad tree %p:\n", &VSpace->VadTree);
    AvlDumpTree(&VSpace->VadTree);
    MmDbgPrint("    vad tree content:\n");
    LoopOverVadTree(Vad, VSpace, MmDbgDumpVad(Vad));
    MmDbgPrint("Dumping virtual address space %p page mappings:\n", VSpace);
    MmDbgDumpPagingStructureRecursively(VSpace->RootPagingStructure);
#endif
}
