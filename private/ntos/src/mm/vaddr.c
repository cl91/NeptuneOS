/* Routines for virtual address space management */

#include "mi.h"

/* Change this to 0 to enable debug tracing */
#if 1
#undef DbgTrace
#define DbgTrace(...)
#define DbgPrint(...)
#else
#include <dbgtrace.h>
#endif

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
    MmAvlInitializeTree(&Self->VadTree);
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
 * NOTE: We always use the term 'Destroy' to refer to releasing resources
 * of an object WITHOUT freeing its pool memory. The term 'Delete' is used
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
    /* TODO: Create ASID pool if not enough ASID slots */
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
    return MiAddrWindowContainsAddr(Vad->AvlNode.Key, Vad->WindowSize, Addr);
}

/*
 * Returns the VAD node that contains the supplied virtual address.
 */
static PMMVAD MiVSpaceFindVadNode(IN PVIRT_ADDR_SPACE VSpace,
				  IN MWORD VirtAddr)
{
    PMM_AVL_TREE Tree = &VSpace->VadTree;
    PMMVAD Node = MM_AVL_NODE_TO_VAD(MiAvlTreeFindNodeOrPrev(Tree, VirtAddr));
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
    return MM_AVL_NODE_TO_VAD(MiAvlGetNextNode(&Vad->AvlNode));
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
    return MM_AVL_NODE_TO_VAD(MiAvlGetPrevNode(&Vad->AvlNode));
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
 */
NTSTATUS MmReserveVirtualMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				  IN MWORD StartAddr,
				  IN OPTIONAL MWORD EndAddr,
				  IN MWORD WindowSize,
				  IN MWORD Flags,
				  OUT OPTIONAL PMMVAD *pVad)
{
    assert(VSpace != NULL);
    assert(WindowSize != 0);
    StartAddr = PAGE_ALIGN(StartAddr);
    WindowSize = PAGE_ALIGN_UP(WindowSize);
    /* We shouldn't align EndAddr since EndAddr might be MAX_ULONGPTR */
    if (Flags & MEM_RESERVE_TOP_DOWN) {
	assert(EndAddr != 0);
	assert(EndAddr > WindowSize);
    } else {
	if (EndAddr == 0) {
	    EndAddr = StartAddr + WindowSize;
	}
    }
    DbgTrace("Finding an address window of size 0x%zx within [%p, %p) for vspacecap 0x%zx\n",
	     WindowSize, (PVOID) StartAddr, (PVOID) EndAddr, VSpace ? VSpace->VSpaceCap : 0);
    assert(StartAddr < EndAddr);
    assert(StartAddr + WindowSize > StartAddr);
    assert(StartAddr + WindowSize <= EndAddr);
    assert((Flags & MEM_RESERVE_NO_ACCESS)
	   || (Flags & MEM_RESERVE_NO_INSERT)
	   || (Flags & MEM_RESERVE_OWNED_MEMORY)
	   || (Flags & MEM_RESERVE_MIRRORED_MEMORY)
	   || (Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    /* There might be a shorter way to write this, but this is the clearest */
    if (Flags & MEM_RESERVE_NO_ACCESS) {
	assert(!(Flags & MEM_RESERVE_NO_INSERT));
	assert(!(Flags & MEM_RESERVE_OWNED_MEMORY));
	assert(!(Flags & MEM_RESERVE_MIRRORED_MEMORY));
	assert(!(Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    }
    if (Flags & MEM_RESERVE_OWNED_MEMORY) {
	assert(!(Flags & MEM_RESERVE_NO_ACCESS));
	assert(!(Flags & MEM_RESERVE_NO_INSERT));
	assert(!(Flags & MEM_RESERVE_MIRRORED_MEMORY));
	assert(!(Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    }
    if (Flags & MEM_RESERVE_MIRRORED_MEMORY) {
	assert(!(Flags & MEM_RESERVE_NO_ACCESS));
	assert(!(Flags & MEM_RESERVE_NO_INSERT));
	assert(!(Flags & MEM_RESERVE_OWNED_MEMORY));
	assert(!(Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    }
    if (Flags & MEM_RESERVE_PHYSICAL_MAPPING) {
	assert(!(Flags & MEM_RESERVE_NO_ACCESS));
	assert(!(Flags & MEM_RESERVE_NO_INSERT));
	assert(!(Flags & MEM_RESERVE_OWNED_MEMORY));
	assert(!(Flags & MEM_RESERVE_MIRRORED_MEMORY));
	assert(!(Flags & MEM_RESERVE_FILE_MAP));
	assert(!(Flags & MEM_RESERVE_IMAGE_MAP));
    }
    if (Flags & MEM_RESERVE_NO_INSERT) {
	assert(!(Flags & MEM_RESERVE_NO_ACCESS));
	assert(!(Flags & MEM_RESERVE_OWNED_MEMORY));
	assert(!(Flags & MEM_RESERVE_MIRRORED_MEMORY));
	assert(!(Flags & MEM_RESERVE_PHYSICAL_MAPPING));
	assert(!(Flags & MEM_RESERVE_FILE_MAP));
	assert(!(Flags & MEM_RESERVE_IMAGE_MAP));
    }

    /* Locate the first unused address window */
    MWORD VirtAddr = (Flags & MEM_RESERVE_TOP_DOWN) ? EndAddr : StartAddr;
    PMM_AVL_TREE Tree = &VSpace->VadTree;
    PMMVAD Parent = MM_AVL_NODE_TO_VAD(MiAvlTreeFindNodeOrParent(Tree, VirtAddr));
    if (Parent == NULL) {
	goto Insert;
    }

    if (Flags & MEM_RESERVE_TOP_DOWN) {
	/* If there is enough space between Parent and EndAddr,
	 * insert after Parent. */
	if (Parent->AvlNode.Key + Parent->WindowSize <= EndAddr) {
	    goto Insert;
	}
	/* Else, retreat to the address immediately before Parent,
	 * unless EndAddr is already smaller than start of Parent */
	if (EndAddr >= Parent->AvlNode.Key) {
	    VirtAddr = Parent->AvlNode.Key;
	}
	/* And start searching from higher address to lower address
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
		goto Insert;
	    }
	    /* VAD windows should never overlap */
	    assert((Prev->AvlNode.Key + Prev->WindowSize) <= Parent->AvlNode.Key);
	    if (Prev->AvlNode.Key + Prev->WindowSize <= VirtAddr - WindowSize) {
		/* Found an unused address window. Now determine whether we insert
		 * as the right child of Prev or as left child of Parent */
		if (Parent->AvlNode.LeftChild != NULL) {
		    assert(Prev->AvlNode.RightChild == NULL);
		    Parent = Prev;
		}
		VirtAddr -= WindowSize;
		goto Insert;
	    }
	    /* Otherwise keep going */
	    Parent = Prev;
	    VirtAddr = Prev->AvlNode.Key;
	}
    } else {
	/* If there is enough space between StartAddr and Parent,
	 * insert before Parent. */
	if (StartAddr + WindowSize <= Parent->AvlNode.Key) {
	    goto Insert;
	}
	/* Else, advance to the address immediately after Parent, unless
	 * StartAddr is already bigger than the end of Parent VAD */
	if (StartAddr < Parent->AvlNode.Key + Parent->WindowSize) {
	    VirtAddr = Parent->AvlNode.Key + Parent->WindowSize;
	}
	/* And start searching for unused window till we reach EndAddr */
	while (VirtAddr + WindowSize <= EndAddr) {
	    if (VirtAddr + WindowSize < VirtAddr) {
		/* addr window overflows */
		return STATUS_INVALID_PARAMETER;
	    }
	    PMMVAD Next = MiVadGetNextNode(Parent);
	    if (Next == NULL) {
		/* Everything from VirtAddr to EndAddr is unused.
		 * Simply insert after Parent. */
		goto Insert;
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
		goto Insert;
	    }
	    Parent = Next;
	    VirtAddr = Next->AvlNode.Key + Next->WindowSize;
	}
    }

    /* Unable to find an unused address window */
    MmDbgDumpVSpace(VSpace);
    return STATUS_CONFLICTING_ADDRESSES;

Insert:
    MiAllocatePool(Vad, MMVAD);
    MMVAD_FLAGS VadFlags;
    VadFlags.Word = 0;
    VadFlags.NoAccess = !!(Flags & MEM_RESERVE_NO_ACCESS);
    VadFlags.ReadOnly = !!(Flags & MEM_RESERVE_READ_ONLY);
    VadFlags.ImageMap = !!(Flags & MEM_RESERVE_IMAGE_MAP);
    VadFlags.FileMap = !!(Flags & MEM_RESERVE_FILE_MAP);
    VadFlags.PhysicalMapping = !!(Flags & MEM_RESERVE_PHYSICAL_MAPPING);
    VadFlags.LargePages = !!(Flags & MEM_RESERVE_LARGE_PAGES);
    VadFlags.OwnedMemory = !!(Flags & MEM_RESERVE_OWNED_MEMORY);
    VadFlags.MirroredMemory = !!(Flags & MEM_RESERVE_MIRRORED_MEMORY);
    VadFlags.CommitOnDemand = !!(Flags & MEM_COMMIT_ON_DEMAND);
    MiInitializeVadNode(Vad, VSpace, VirtAddr, WindowSize, VadFlags);
    if (VadFlags.CommitOnDemand) {
	DbgTrace("Commit on demand\n");
    }

    if (pVad != NULL) {
	*pVad = Vad;
    }

    if (Flags & MEM_RESERVE_NO_INSERT) {
	return STATUS_SUCCESS;
    }

    MiAvlTreeInsertNode(&VSpace->VadTree, &Parent->AvlNode, &Vad->AvlNode);

    DbgTrace("Successfully reserved [%p, %p) for vspacecap 0x%zx\n",
	     (PVOID) Vad->AvlNode.Key,
	     (PVOID) (Vad->AvlNode.Key + Vad->WindowSize),
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

NTSTATUS MiCommitImageVad(IN PMMVAD Vad)
{
    assert(Vad != NULL);
    assert(Vad->VSpace != NULL);
    assert(Vad->Flags.ImageMap);
    assert(Vad->Flags.OwnedMemory || Vad->Flags.MirroredMemory);
    assert(IS_PAGE_ALIGNED(Vad->AvlNode.Key));
    assert(IS_PAGE_ALIGNED(Vad->WindowSize));
    assert(Vad->AvlNode.Key + Vad->WindowSize > Vad->AvlNode.Key);
    assert(Vad->ImageSectionView.SubSection != NULL);
    assert(Vad->ImageSectionView.SubSection->ImageSection != NULL);
    assert(Vad->ImageSectionView.SubSection->ImageSection->FileObject != NULL);

    PAGING_RIGHTS Rights = Vad->Flags.ReadOnly ? MM_RIGHTS_RO : MM_RIGHTS_RW;
    PVOID FileBuffer = Vad->ImageSectionView.SubSection->ImageSection->FileObject->BufferPtr;
    PVOID DataBuffer = FileBuffer + Vad->ImageSectionView.SubSection->FileOffset;
    MWORD DataSize = Vad->ImageSectionView.SubSection->RawDataSize;
    /* TODO: Use shared pages for PE headers and read-only sections. */
    if (Vad->Flags.OwnedMemory) {
	RET_ERR(MiCommitOwnedMemory(Vad->VSpace, Vad->AvlNode.Key, Vad->WindowSize, Rights,
				    Vad->Flags.LargePages, DataSize ? DataBuffer : NULL,
				    DataSize));
    } else {
	assert(Vad->MirroredMemory.Master != NULL);
	assert(IS_PAGE_ALIGNED(Vad->MirroredMemory.StartAddr));
	RET_ERR(MiMapMirroredMemory(Vad->MirroredMemory.Master, Vad->MirroredMemory.StartAddr,
				    Vad->VSpace, Vad->AvlNode.Key, Vad->WindowSize, Rights));
    }

    return STATUS_SUCCESS;
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
    DbgTrace("Trying to commit [%p, %p)\n", (PVOID)StartAddr, (PVOID)(StartAddr + WindowSize));
    StartAddr = PAGE_ALIGN(StartAddr);
    WindowSize = PAGE_ALIGN_UP(WindowSize);
    assert_ret(StartAddr + WindowSize > StartAddr);

    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, StartAddr);
    if (Vad == NULL) {
	DbgTrace("Error: Must reserve address window before committing.\n");
	MmDbgDumpVSpace(VSpace);
	return STATUS_INVALID_PARAMETER;
    }
    if (Vad->Flags.NoAccess) {
	DbgTrace("Error: Committing a NoAccess Vad.\n");
	MmDbgDumpVSpace(VSpace);
	return STATUS_INVALID_PARAMETER;
    }

    if ((StartAddr < Vad->AvlNode.Key) ||
	(StartAddr + WindowSize > Vad->AvlNode.Key + Vad->WindowSize)) {
	DbgTrace("Committing addresses spanning multiple VADs is not implemented yet "
		 "(requested [%p, %p) found VAD [%p, %p))\n",
		 (PVOID) StartAddr, (PVOID)(StartAddr + WindowSize),
		 (PVOID) Vad->AvlNode.Key, (PVOID) (Vad->AvlNode.Key + Vad->WindowSize));
	UNIMPLEMENTED;
    }

    PAGING_RIGHTS Rights = (Vad->Flags.ReadOnly) ? MM_RIGHTS_RO : MM_RIGHTS_RW;

    if (Vad->Flags.ImageMap) {
	/* This will set CommitmentSize to the size of the VAD */
	RET_ERR(MiCommitImageVad(Vad));
    } else if (Vad->Flags.FileMap) {
	UNIMPLEMENTED;
    } else if (Vad->Flags.PhysicalMapping) {
	for (MWORD Committed = 0; Committed < WindowSize; Committed += PAGE_SIZE) {
	    MWORD PhyAddr = StartAddr - Vad->AvlNode.Key +
		Vad->PhysicalSectionView.PhysicalBase + Committed;
	    RET_ERR(MiCommitIoPage(Vad->VSpace, PhyAddr, StartAddr + Committed, Rights));
	}
    } else if (Vad->Flags.MirroredMemory) {
	assert(Vad->MirroredMemory.Master != NULL);
	assert(IS_PAGE_ALIGNED(Vad->MirroredMemory.StartAddr));
	RET_ERR(MiMapMirroredMemory(Vad->MirroredMemory.Master, Vad->MirroredMemory.StartAddr,
				    Vad->VSpace, StartAddr, WindowSize, Rights));
    } else if (Vad->Flags.OwnedMemory) {
	RET_ERR(MiCommitOwnedMemory(Vad->VSpace, StartAddr, WindowSize, Rights,
				    Vad->Flags.LargePages, NULL, 0));
    } else {
	/* Should never reach this */
	return STATUS_NTOS_BUG;
    }

    return STATUS_SUCCESS;
}

/*
 * Returns the PAGING_STRUCTURE pointer to the 4K page at given virtual address.
 *
 * Returns NULL if no 4K page is unmapped at the given address.
 */
PPAGING_STRUCTURE MmQueryPage(IN PVIRT_ADDR_SPACE VSpace,
			      IN MWORD VirtAddr)
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

    return MiPagingTypeIsPage(Page->Type) ? Page : NULL;
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
    DbgTrace("Deleting vad %p key %p\n", Vad, (PVOID)Vad->AvlNode.Key);
    assert(Vad != NULL);
    assert(Vad->VSpace != NULL);
    assert(MiVSpaceFindVadNode(Vad->VSpace, Vad->AvlNode.Key) == Vad);
    MiUncommitVad(Vad);
    MiAvlTreeRemoveNode(&Vad->VSpace->VadTree, &Vad->AvlNode);
    if (Vad->SectionLink.Flink != NULL) {
	assert(Vad->SectionLink.Blink != NULL);
	RemoveEntryList(&Vad->SectionLink);
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
		   DbgTrace("User window not mapped [%p, %p)\n",
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
    DbgTrace("Attempt to handle VM-FAULT of thread %s at %p\n",
	     Thread->DebugName, (PVOID)Addr);
    PMMVAD Vad = MiVSpaceFindVadNode(&Thread->Process->VSpace, Addr);
    if (Vad == NULL || !Vad->Flags.CommitOnDemand) {
	MmDbgDumpVSpace(&Thread->Process->VSpace);
	return FALSE;
    }
    return NT_SUCCESS(MmCommitVirtualMemoryEx(&Thread->Process->VSpace,
					      PAGE_ALIGN(Addr), PAGE_SIZE));
}

NTSTATUS NtAllocateVirtualMemory(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
                                 IN HANDLE ProcessHandle,
                                 IN OUT OPTIONAL PVOID *BaseAddress,
                                 IN ULONG_PTR ZeroBits,
                                 IN OUT SIZE_T *RegionSize,
                                 IN ULONG AllocationType,
                                 IN ULONG Protect)
{
    PPROCESS Process = NULL;
    if (ProcessHandle != NtCurrentProcess()) {
	RET_ERR(ObReferenceObjectByHandle(Thread->Process, ProcessHandle,
					  OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    } else {
	Process = Thread->Process;
    }
    assert(Process != NULL);
    PVIRT_ADDR_SPACE VSpace = &Process->VSpace;
    DbgTrace("Process %s VSpace cap 0x%zx base address %p zerobits 0x%zx "
	     "region size 0x%zx allocation type 0x%x protect 0x%x\n",
	     Process->ImageFile ? Process->ImageFile->FileName : "",
	     VSpace->VSpaceCap, BaseAddress ? *BaseAddress : NULL, (MWORD)ZeroBits,
	     RegionSize ? (MWORD)*RegionSize : 0, AllocationType, Protect);

    /* On 64-bit systems the ZeroBits parameter is interpreted as a bit mask if it is
     * greater than 32. Convert the bit mask to the number of bits in that case. */
#ifdef _WIN64
    if (ZeroBits >= 32) {
        ZeroBits = 64 - RtlFindMostSignificantBit(ZeroBits) - 1;
    } else if (ZeroBits) {
	/* For ZeroBits < 32, on x64 this is interpreted as the number of highest
	 * zero bits in the lower 32 bit part of the full 64 bit virtual address */
        ZeroBits += 32;
    }
#endif

    NTSTATUS Status = STATUS_INTERNAL_ERROR;
    if (ZeroBits > MM_MAXIMUM_ZERO_BITS) {
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
	    DbgTrace("Commit on demand\n");
	    Flags |= MEM_COMMIT_ON_DEMAND;
	}
	IF_ERR_GOTO(out, Status,
		    MmReserveVirtualMemoryEx(VSpace, StartAddr, EndAddr,
					     WindowSize, Flags, &Vad));
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
    if (ProcessHandle != NtCurrentProcess()) {
	assert(Process != NULL);
	ObDereferenceObject(Process);
    }
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
    if (ProcessHandle != NtCurrentProcess()) {
	RET_ERR(ObReferenceObjectByHandle(Thread->Process, ProcessHandle,
					  OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    } else {
	Process = Thread->Process;
    }
    assert(Process != NULL);
    PVIRT_ADDR_SPACE VSpace = &Process->VSpace;
    DbgTrace("Process %s VSpace cap 0x%zx base address %p region size 0x%zx free type 0x%x\n",
	     Process->ImageFile ? Process->ImageFile->FileName : "",
	     VSpace->VSpaceCap, *BaseAddress, *RegionSize, FreeType);

    NTSTATUS Status = STATUS_NTOS_BUG;
    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, (MWORD)*BaseAddress);
    if (Vad == NULL) {
	DbgTrace("Invalid base address %p\n", *BaseAddress);
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
	    DbgTrace("Base address does not equal start of reserved space %p\n",
		     (PVOID)Vad->AvlNode.Key);
	    Status = STATUS_INVALID_PARAMETER_2;
	    goto out;
	}
	if (*RegionSize != 0) {
	    DbgTrace("Region size must be zero\n");
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
    if (ProcessHandle != NtCurrentProcess()) {
	assert(Process != NULL);
	ObDereferenceObject(Process);
    }
    if (!NT_SUCCESS(Status)) {
	DbgTrace("NtFreeVirtualMemory failed with status 0x%x\n", Status);
	MmDbgDumpVSpace(VSpace);
    }
    return Status;
}

NTSTATUS NtWriteVirtualMemory(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
                              IN HANDLE ProcessHandle,
                              IN PVOID BaseAddress,
                              IN PVOID Buffer,
                              IN ULONG NumberOfBytesToWrite,
                              OUT OPTIONAL ULONG *NumberOfBytesWritten)
{
    PPROCESS Process = NULL;
    if (ProcessHandle != NtCurrentProcess()) {
	RET_ERR(ObReferenceObjectByHandle(Thread->Process, ProcessHandle,
					  OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    } else {
	Process = Thread->Process;
    }
    assert(Process != NULL);
    PVIRT_ADDR_SPACE TargetVSpace = &Process->VSpace;
    DbgTrace("Target process %s (VSpace cap 0x%zx) base address %p buffer %p length 0x%x\n",
	     Process->ImageFile ? Process->ImageFile->FileName : "",
	     TargetVSpace->VSpaceCap, BaseAddress, Buffer, NumberOfBytesToWrite);
    PVOID MappedSourceBuffer = NULL;
    NTSTATUS Status = STATUS_INTERNAL_ERROR;
    IF_ERR_GOTO(out, Status,
		MmMapUserBuffer(&Thread->Process->VSpace, (MWORD)Buffer,
				NumberOfBytesToWrite, &MappedSourceBuffer));
    assert(MappedSourceBuffer != NULL);
    PVOID MappedTargetBuffer = NULL;
    IF_ERR_GOTO(out, Status,
		MmMapUserBuffer(TargetVSpace, (MWORD)BaseAddress,
				NumberOfBytesToWrite, &MappedTargetBuffer));
    assert(MappedTargetBuffer != NULL);
    memcpy(MappedTargetBuffer, MappedSourceBuffer, NumberOfBytesToWrite);
    if (NumberOfBytesWritten != NULL) {
	*NumberOfBytesWritten = NumberOfBytesToWrite;
    }
    Status = STATUS_SUCCESS;
out:
    if (MappedTargetBuffer != NULL) {
	MmUnmapUserBuffer(MappedTargetBuffer);
    }
    if (MappedSourceBuffer != NULL) {
	MmUnmapUserBuffer(MappedSourceBuffer);
    }
    if (ProcessHandle != NtCurrentProcess()) {
	assert(Process != NULL);
	ObDereferenceObject(Process);
    }
    return Status;
}


NTSTATUS NtReadVirtualMemory(IN ASYNC_STATE State,
			     IN PTHREAD Thread,
                             IN HANDLE ProcessHandle,
                             IN PVOID BaseAddress,
                             IN PVOID Buffer,
                             IN ULONG NumberOfBytesToRead,
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

#ifdef CONFIG_DEBUG_BUILD
VOID MmDbgDumpVad(PMMVAD Vad)
{
    DbgPrint("Dumping vad at %p\n", Vad);
    if (Vad == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }

    DbgPrint("    vaddr start = %p  window size = 0x%zx\n"
	     "   %s%s%s%s%s\n",
	     (PVOID) Vad->AvlNode.Key, Vad->WindowSize,
	     Vad->Flags.ImageMap ? " image-map" : "",
	     Vad->Flags.LargePages ? " large-pages" : "",
	     Vad->Flags.PhysicalMapping ? " physical-mapping" : "",
	     Vad->Flags.OwnedMemory ? " owned-memory" : "",
	     Vad->Flags.MirroredMemory ? " mirrored-memory" : "");
    if (Vad->Flags.ImageMap) {
	    DbgPrint("    subsection = %p\n", Vad->ImageSectionView.SubSection);
    }
    if (Vad->Flags.FileMap) {
	DbgPrint("    section = %p\n", Vad->DataSectionView.Section);
	DbgPrint("    section offset = %p\n", (PVOID) Vad->DataSectionView.SectionOffset);
    }
    if (Vad->Flags.PhysicalMapping) {
	DbgPrint("    physical base = %p\n", (PVOID) Vad->PhysicalSectionView.PhysicalBase);
    }
    if (Vad->Flags.MirroredMemory) {
	DbgPrint("    master vspace = %p\n", Vad->MirroredMemory.Master);
	DbgPrint("    start vaddr in master vspace = 0x%zx\n", Vad->MirroredMemory.StartAddr);
    }
}

VOID MmDbgDumpVSpace(PVIRT_ADDR_SPACE VSpace)
{
    DbgPrint("Dumping virtual address space %p\n", VSpace);
    if (VSpace == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }

    DbgPrint("    vspacecap = 0x%zx    asidpool = 0x%zx\n",
	     VSpace->VSpaceCap, VSpace->ASIDPool);
    DbgPrint("    root paging structure %p:\n", VSpace->RootPagingStructure);
    MmDbgDumpPagingStructure(VSpace->RootPagingStructure);
    DbgPrint("Dumping virtual address space %p vad tree %p\n    linearly:  ",
	     VSpace, &VSpace->VadTree);
    MmAvlDumpTreeLinear(&VSpace->VadTree);
    DbgPrint("\n    vad tree %p:\n", &VSpace->VadTree);
    MmAvlDumpTree(&VSpace->VadTree);
    DbgPrint("    vad tree content:\n");
    LoopOverVadTree(Vad, VSpace, MmDbgDumpVad(Vad));
    DbgPrint("Dumping virtual address space %p page mappings:\n", VSpace);
    MmDbgDumpPagingStructureRecursively(VSpace->RootPagingStructure);
}
#endif
