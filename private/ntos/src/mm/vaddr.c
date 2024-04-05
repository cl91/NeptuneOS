/*
 * Routines for virtual address space management
 */

#include "mi.h"

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
				TRUE, MM_RIGHTS_RW);
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
NTSTATUS MmDestroyVSpace(IN PVIRT_ADDR_SPACE Self)
{
    UNIMPLEMENTED;
}

/*
 * Search for an ASID pool with a free ASID slot and assign an ASID
 * for the virtual address space. An ASID must be assigned before the
 * virtual address space can be used for mapping.
 */
NTSTATUS MmAssignASID(IN PVIRT_ADDR_SPACE VaddrSpace)
{
    /* TODO: Create ASID pool if there are not enough ASID slots */
    int Error = seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool,
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
static PMMVAD MiVSpaceFindVadNode(IN PVIRT_ADDR_SPACE VSpace,
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
 * If unaligned, address window will be aligned at 4K page boundary.
 *
 * If unspecified (ie. zero), EndAddr will be set to StartAddr + WindowSize
 *
 * If the MEM_RESERVE_LARGE_PAGES flag is specified and WindowSize is at least
 * one large page size, then we will attempt to locate an address window that
 * starts at the large page boundary (failing so, a regular search will be conducted).
 *
 * If LowZeroBits is larger than PAGE_LOG2SIZE, the address window will be aligned
 * such that the lowest LowZeroBits bits of the starting address are zero.
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
    assert(VSpace != NULL);
    assert(WindowSize != 0);
    /* At least one flag must be set. */
    assert(Flags);
    /* Thw following "reserve type" flags are mutually exclusive. */
    MWORD TypeFlags = MEM_RESERVE_IMAGE_MAP | MEM_RESERVE_FILE_MAP
	| MEM_RESERVE_CACHE_MAP | MEM_RESERVE_PHYSICAL_MAPPING
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

    if (HighZeroBits > MM_MAXIMUM_ZERO_HIGH_BITS) {
	return STATUS_INVALID_PARAMETER;
    }

    if (HighZeroBits) {
	MWORD MaxAddr = 1 << (MWORD_BITS - HighZeroBits);
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
		goto insert;
	    } else {
		/* Else, retreat to the address immediately before Parent,
		 * unless EndAddr is already smaller than start of Parent */
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
    MiAllocatePool(Vad, MMVAD);
    MMVAD_FLAGS VadFlags;
    VadFlags.Word = 0;
    VadFlags.NoAccess = !!(Flags & MEM_RESERVE_NO_ACCESS);
    VadFlags.ReadOnly = !!(Flags & MEM_RESERVE_READ_ONLY);
    VadFlags.ImageMap = !!(Flags & MEM_RESERVE_IMAGE_MAP);
    VadFlags.FileMap = !!(Flags & MEM_RESERVE_FILE_MAP);
    VadFlags.CacheMap = !!(Flags & MEM_RESERVE_CACHE_MAP);
    VadFlags.PhysicalMapping = !!(Flags & MEM_RESERVE_PHYSICAL_MAPPING);
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

    AvlTreeInsertNode(&VSpace->VadTree, &Parent->AvlNode, &Vad->AvlNode);

    MmDbg("Successfully reserved [%p, %p) for vspacecap 0x%zx\n",
	  (PVOID)Vad->AvlNode.Key,
	  (PVOID)(Vad->AvlNode.Key + Vad->WindowSize),
	  VSpace ? VSpace->VSpaceCap : 0);
    return STATUS_SUCCESS;
}

/*
 * Add the mirrored memory VAD to the master vspace's viewer list. The mirrored
 * memory will map a memory window of the master vspace to the viewer vspace.
 * The start address of the master vspace memory window is given by StartAddr.
 * The window size of the Viewer VAD's window size.
 */
VOID MmRegisterMirroredMemory(IN PMMVAD Viewer,
			      IN PVIRT_ADDR_SPACE Master,
			      IN MWORD StartAddr)
{
    assert(Viewer != NULL);
    assert(Master != NULL);
    assert(Viewer->Flags.MirroredMemory);
    Viewer->MirroredMemory.Master = Master;
    Viewer->MirroredMemory.StartAddr = StartAddr;
    InsertTailList(&Master->ViewerList, &Viewer->MirroredMemory.ViewerLink);
}

/*
 * Register the viewer VAD to map the master VAD. The master VAD must have
 * the same window size as the viewer VAD.
 */
VOID MmRegisterMirroredVad(IN PMMVAD Viewer,
			   IN PMMVAD MasterVad)
{
    assert(Viewer != NULL);
    assert(MasterVad != NULL);
    assert(Viewer->WindowSize == MasterVad->WindowSize);
    assert(MasterVad->VSpace != NULL);
    MmRegisterMirroredMemory(Viewer, MasterVad->VSpace, MasterVad->AvlNode.Key);
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

    /* VADs marked as file map are committed lazily (ie. when a thread accesses a page
     * and generates a VM fault) and you cannot call MmCommitVirtualMemory on it. */
    if (Vad->Flags.FileMap) {
	MmDbg("Error: File map is committed lazily.\n");
	MmDbgDumpVSpace(VSpace);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* VADs marked as image map are mapped using MmMapViewOfSection and you cannot
     * call MmCommitVirtualMemory on it. */
    if (Vad->Flags.ImageMap) {
	MmDbg("Error: Call MmMapViewOfSection to commit image VAD.\n");
	MmDbgDumpVSpace(VSpace);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* VADs marked as physical mapping are mapped using MmMapViewOfSection and you cannot
     * call MmCommitVirtualMemory on it. */
    if (Vad->Flags.PhysicalMapping) {
	MmDbg("Error: Call MmMapViewOfSection to commit physical mapping.\n");
	MmDbgDumpVSpace(VSpace);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    /* TODO: We need to determine if we allow committing multiple VADs in one call. */
    if ((StartAddr < Vad->AvlNode.Key) ||
	(StartAddr + WindowSize > Vad->AvlNode.Key + Vad->WindowSize)) {
	MmDbg("Committing addresses spanning multiple VADs is not implemented yet "
	      "(requested [%p, %p) found VAD [%p, %p))\n",
	      (PVOID)StartAddr, (PVOID)(StartAddr + WindowSize),
	      (PVOID)Vad->AvlNode.Key, (PVOID)(Vad->AvlNode.Key + Vad->WindowSize));
	UNIMPLEMENTED;
    }

    PAGING_RIGHTS Rights = (Vad->Flags.ReadOnly) ? MM_RIGHTS_RO : MM_RIGHTS_RW;

    if (Vad->Flags.MirroredMemory) {
	assert(Vad->MirroredMemory.Master != NULL);
	assert(IS_PAGE_ALIGNED(Vad->MirroredMemory.StartAddr));
	RET_ERR(MmMapMirroredMemory(Vad->MirroredMemory.Master, Vad->MirroredMemory.StartAddr,
				    Vad->VSpace, StartAddr, WindowSize, Rights));
    } else if (Vad->Flags.OwnedMemory) {
	RET_ERR(MmCommitOwnedMemory(Vad->VSpace, StartAddr, WindowSize, Rights,
				    Vad->Flags.LargePages, NULL, 0));
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

/*
 * Query the paging structures to generate the page frame database.
 *
 * If PfnDb is not NULL, the PFN database will be written there.
 * If pPfnCount is not NULL, the PFN count will be written there.
 *
 * If the buffer is fully mapped in the specified process address
 * space prior to calling this function, FALSE is returned. Note
 * here Buffer is the (client-side) virtual address in the address
 * space of the specified process.
 */
BOOLEAN MmGeneratePageFrameDatabase(IN OPTIONAL PULONG_PTR PfnDb,
				    IN PPROCESS Process,
				    IN MWORD Buffer,
				    IN MWORD BufferLength,
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
	if (Exit) {
	    goto out;
	}
	PPAGING_STRUCTURE Page = MmQueryPageEx(&Process->VSpace, VirtAddr, TRUE);
	if (!Page) {
	    return FALSE;
	}
	assert(Page->AvlNode.Key);
	MWORD PhyAddr = MiGetPhysicalAddress(Page);
	assert(PhyAddr);
	assert(IS_PAGE_ALIGNED(PhyAddr));

	if (!PageCount) {
	    PhyAddrStart = PhyAddr;
	    PrevPageType = Page->Type;
	}
	if (!PageCount || (PhyAddrEnd == PhyAddr && Page->Type == PrevPageType)) {
	    /* Page is physically contiguous with previous page. In this case
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
		if (MiPagingTypeIsLargePage(PrevPageType)) {
		    PhyAddrStart |= MDL_PFN_ATTR_LARGE_PAGE;
		}
		PfnDb[PfnCount] = PhyAddrStart | (PageCount << MDL_PFN_ATTR_BITS);
	    }
	    PfnCount++;
	    if (Exit) {
		break;
	    }
	    PhyAddrStart = PhyAddrEnd = 0;
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
	if (Writable && !MmPagingRightsAreEqual(Page->Rights, MM_RIGHTS_RW)) {
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
 * De-commit the given address window. The actual StartAddr and WindowSize are returned.
 */
static VOID MiUncommitWindow(IN PVIRT_ADDR_SPACE VSpace,
			     IN OUT MWORD *StartAddr,
			     IN OUT MWORD *WindowSize)
{
    *StartAddr = PAGE_ALIGN(*StartAddr);
    MWORD EndAddr = PAGE_ALIGN_UP(*StartAddr + *WindowSize);
    /* Note that despite the name, Page can be any level of paging structure, ie.
     * page table, page directory, PDPT, or PML4 */
    PPAGING_STRUCTURE Page = MiQueryVirtualAddress(VSpace, *StartAddr);
    /* We never de-commit root paging structures */
    if (Page == NULL || MiPagingTypeIsRoot(Page->Type)) {
	/* Do nothing as the virtual address space is empty */
	return;
    }
    if (MiPagingTypeIsPageOrLargePage(Page->Type)) {
	*StartAddr = Page->AvlNode.Key;
    } else {
	Page = MiGetFirstPage(Page);
	if (!MiPagingTypeIsPageOrLargePage(Page->Type)) {
	    Page = MiGetNextPagingStructure(Page);
	}
    }
    while (Page != NULL && Page->AvlNode.Key < EndAddr) {
	PPAGING_STRUCTURE Next = MiGetNextPagingStructure(Page);
	if (Next == NULL) {
	    *WindowSize = Page->AvlNode.Key + MiPagingWindowSize(Page->Type) - *StartAddr;
	}
	MiDeletePage(Page);
	Page = Next;
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
    MiUncommitWindow(Vad->VSpace, &StartAddr, &WindowSize);
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
    if (Vad->SectionLink.Flink != NULL) {
	assert(Vad->SectionLink.Blink != NULL);
	RemoveEntryList(&Vad->SectionLink);
    }
    if (Vad->Flags.MirroredMemory) {
	assert(Vad->MirroredMemory.ViewerLink.Flink != NULL);
	assert(Vad->MirroredMemory.ViewerLink.Blink != NULL);
	assert(!IsListEmpty(&Vad->MirroredMemory.ViewerLink));
	RemoveEntryList(&Vad->MirroredMemory.ViewerLink);
    } else if (Vad->Flags.PhysicalMapping && Vad->PhysicalSectionView.RootUntyped) {
	/* MiUncommitVad should have already freed the untyped, so just check that. */
	assert(MiUntypedIsInFreeLists(Vad->PhysicalSectionView.RootUntyped));
    }
    MiFreePool(Vad);
}

/*
 * Search for a suitable address window in the specified region of the target
 * address space and map the source window into it (up to the specified commit
 * size), returning the resulting VAD in the target address space.
 */
NTSTATUS MmMapSharedRegion(IN PVIRT_ADDR_SPACE SrcVSpace,
			   IN MWORD SrcWindowStart,
			   IN MWORD SrcWindowSize,
			   IN PVIRT_ADDR_SPACE TargetVSpace,
			   IN MWORD TargetVaddrStart,
			   IN MWORD TargetVaddrEnd,
			   IN MWORD TargetReserveFlag,
			   IN MWORD TargetCommitSize,
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

    MmRegisterMirroredMemory(TargetVad, SrcVSpace, SrcWindowStart);
    RET_ERR_EX(MmCommitVirtualMemoryEx(TargetVSpace, TargetVad->AvlNode.Key,
				       TargetCommitSize),
	       MmDeleteVad(TargetVad));

    *pTargetVad = TargetVad;
    return STATUS_SUCCESS;
}

/*
 * Maps the user buffer in the given virt addr space into another
 * virt addr space, returning the starting virtual address of the
 * buffer in the target virt addr space.
 *
 * If ReadOnly is TRUE, the target pages will be mapped read-only.
 * Otherwise the target pages will be mapped read-write.
 *
 * If ReadOnly is FALSE, the user buffer must be writable by the user.
 * Otherwise STATUS_INVALID_PAGE_PROTECTION is returned.
 */
NTSTATUS MmMapUserBufferEx(IN PVIRT_ADDR_SPACE VSpace,
			   IN MWORD BufferStart,
			   IN MWORD BufferLength,
			   IN PVIRT_ADDR_SPACE TargetVSpace,
			   IN MWORD TargetVaddrStart,
			   IN MWORD TargetVaddrEnd,
			   OUT MWORD *TargetStartAddr,
			   IN BOOLEAN ReadOnly)
{
    assert(VSpace != NULL);
    assert(TargetVSpace != NULL);
    assert(TargetStartAddr != NULL);
    MWORD UserWindowStart = BufferStart;
    MWORD WindowSize = BufferLength;
    RET_ERR_EX(MiEnsureWindowMapped(VSpace, &UserWindowStart, &WindowSize, !ReadOnly),
	       {
		   MmDbg("User window not mapped [%p, %p)\n",
			 (PVOID)UserWindowStart, (PVOID)WindowSize);
		   MmDbgDumpVSpace(VSpace);
	       });

    PMMVAD TargetBufferVad = NULL;
    RET_ERR(MmMapSharedRegion(VSpace, UserWindowStart, WindowSize,
			      TargetVSpace, TargetVaddrStart,
			      TargetVaddrEnd,
			      ReadOnly ? MEM_RESERVE_READ_ONLY : 0,
			      WindowSize, &TargetBufferVad));
    *TargetStartAddr = BufferStart - UserWindowStart + TargetBufferVad->AvlNode.Key;
    return STATUS_SUCCESS;
}

/*
 * Unmap the memory region that was previously mapped into the target
 * address space.
 */
VOID MmUnmapRegion(IN PVIRT_ADDR_SPACE MappedVSpace,
		   IN MWORD MappedRegionStart)
{
    MmDbg("Unmapping region starting %p for vspace cap 0x%zx\n",
	  (PVOID)MappedRegionStart, MappedVSpace->VSpaceCap);
    PMMVAD Vad = MiVSpaceFindVadNode(MappedVSpace, MappedRegionStart);
    assert(Vad != NULL);
    assert(MiVadNodeContainsAddr(Vad, MappedRegionStart));
    if (Vad != NULL) {
	MmDeleteVad(Vad);
    }
}

/*
 * Check the process VSpace to see if the faulting address is in
 * a COMMIT_ON_DEMAND page. If it is, try to commit the page and
 * if successful, return TRUE so the thread can be resumed.
 *
 * Otherwise return FALSE.
 */
BOOLEAN MmHandleThreadVmFault(IN PTHREAD Thread,
			      IN MWORD Addr)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    MmDbg("Attempt to handle VM-FAULT of thread %s at %p\n",
	  Thread->DebugName, (PVOID)Addr);
    PMMVAD Vad = MiVSpaceFindVadNode(&Thread->Process->VSpace, Addr);
    if (Vad == NULL || !Vad->Flags.CommitOnDemand) {
	MmDbgDumpVSpace(&Thread->Process->VSpace);
	return FALSE;
    }
    return NT_SUCCESS(MmCommitVirtualMemoryEx(&Thread->Process->VSpace,
					      PAGE_ALIGN(Addr), PAGE_SIZE));
}

/*
 * Allocate physically contiguous memory of given size. The physical memory
 * allocated is always aligned on the smallest power of two that is at least
 * the given size. In other words, let n be the smallest n such that
 * 2^n >= Length, then the returned physical address is always aligned by 2^n.
 */
NTSTATUS MmAllocatePhysicallyContiguousMemory(IN PVIRT_ADDR_SPACE VSpace,
					      IN ULONG Length,
					      IN MWORD HighestPhyAddr,
					      OUT MWORD *VirtAddr,
					      OUT MWORD *PhyAddr)
{
    ULONG Flags = MEM_RESERVE_PHYSICAL_MAPPING | MEM_RESERVE_LARGE_PAGES;
    PMMVAD Vad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(VSpace, USER_IMAGE_REGION_START,
				     USER_IMAGE_REGION_END, Length, 0, 0, Flags, &Vad));
    assert(Vad != NULL);
    PUNTYPED Untyped = NULL;
    ULONG Log2Size = 0;
    while ((1ULL << Log2Size) < Length) {
	Log2Size++;
    }
    RET_ERR_EX(MmRequestUntypedEx(Log2Size, HighestPhyAddr, &Untyped),
	       MmDeleteVad(Vad));
    assert(Vad->Flags.PhysicalMapping);
    Vad->PhysicalSectionView.PhysicalBase = Untyped->AvlNode.Key;
    Vad->PhysicalSectionView.RootUntyped = Untyped;
    RET_ERR_EX(MiMapIoMemory(VSpace, Untyped->AvlNode.Key, Vad->AvlNode.Key,
			     Length, MM_RIGHTS_RW, FALSE),
	       MmDeleteVad(Vad));
    *VirtAddr = Vad->AvlNode.Key;
    *PhyAddr = Untyped->AvlNode.Key;
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
    if (HighZeroBits > MM_MAXIMUM_ZERO_HIGH_BITS) {
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
    if ((AllocationType & (MEM_RESET | MEM_PHYSICAL | MEM_WRITE_WATCH))) {
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
	MiUncommitWindow(VSpace, (MWORD *)BaseAddress, (MWORD *)RegionSize);
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
    UNIMPLEMENTED;
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
	       "   %s%s%s%s%s\n",
	       (PVOID) Vad->AvlNode.Key, Vad->WindowSize,
	       Vad->Flags.ImageMap ? " image-map" : "",
	       Vad->Flags.LargePages ? " large-pages" : "",
	       Vad->Flags.PhysicalMapping ? " physical-mapping" : "",
	       Vad->Flags.OwnedMemory ? " owned-memory" : "",
	       Vad->Flags.MirroredMemory ? " mirrored-memory" : "");
    if (Vad->Flags.ImageMap) {
	MmDbgPrint("    subsection = %p\n", Vad->ImageSectionView.SubSection);
    }
    if (Vad->Flags.FileMap) {
	MmDbgPrint("    section = %p\n", Vad->DataSectionView.Section);
	MmDbgPrint("    section offset = %p\n", (PVOID) Vad->DataSectionView.SectionOffset);
    }
    if (Vad->Flags.PhysicalMapping) {
	MmDbgPrint("    physical base = %p\n", (PVOID) Vad->PhysicalSectionView.PhysicalBase);
    }
    if (Vad->Flags.MirroredMemory) {
	MmDbgPrint("    master vspace = %p\n", Vad->MirroredMemory.Master);
	MmDbgPrint("    start vaddr in master vspace = 0x%zx\n", Vad->MirroredMemory.StartAddr);
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
