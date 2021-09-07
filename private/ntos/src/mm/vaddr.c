/* Routines for virtual address space management */

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
    Self->CachedVad = NULL;
    MiAvlInitializeTree(&Self->VadTree);
}

NTSTATUS MmCreateVSpace(IN PVIRT_ADDR_SPACE Self)
{
    assert(Self != NULL);
    MiAllocatePool(RootPagingStructure, PAGING_STRUCTURE);
    PUNTYPED VSpaceUntyped = NULL;
    RET_ERR_EX(MmRequestUntyped(seL4_VSpaceBits, &VSpaceUntyped),
	       ExFreePool(RootPagingStructure));
    MiInitializePagingStructure(RootPagingStructure, NULL, NULL, 0,
				0, 0, PAGING_TYPE_ROOT_PAGING_STRUCTURE,
				TRUE, MM_RIGHTS_RW);
    RET_ERR_EX(MmRetypeIntoObject(VSpaceUntyped, seL4_VSpaceObject,
				  seL4_VSpaceBits, &RootPagingStructure->TreeNode),
	       {
		   MmReleaseUntyped(VSpaceUntyped);
		   ExFreePool(RootPagingStructure);
	       });
    MiInitializeVSpace(Self, RootPagingStructure);
    return STATUS_SUCCESS;
}

NTSTATUS MmDestroyVSpace(IN PVIRT_ADDR_SPACE Self)
{
    return STATUS_NTOS_UNIMPLEMENTED;
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
    if (VSpace->CachedVad != NULL &&
	MiVadNodeContainsAddr(VSpace->CachedVad, VirtAddr)) {
	return VSpace->CachedVad;
    }
    PMMVAD Parent = MM_AVL_NODE_TO_VAD(MiAvlTreeFindNodeOrParent(Tree, VirtAddr));
    if (Parent != NULL && MiVadNodeContainsAddr(Parent, VirtAddr)) {
	VSpace->CachedVad = Parent;
	return Parent;
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
    return MM_AVL_NODE_TO_VAD(MiAvlGetNextNode(&Vad->VSpace->VadTree, &Vad->AvlNode));
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
    return MM_AVL_NODE_TO_VAD(MiAvlGetPrevNode(&Vad->VSpace->VadTree, &Vad->AvlNode));
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
    DbgTrace("Finding an address window of size 0x%zx within [%p, %p) for vspace %p\n",
	     WindowSize, (PVOID) StartAddr, (PVOID) EndAddr, (PVOID) VSpace);
    assert(StartAddr < EndAddr);
    assert(StartAddr + WindowSize > StartAddr);
    assert(StartAddr + WindowSize <= EndAddr);
    assert((Flags & MEM_RESERVE_NO_ACCESS)
	   || (Flags & MEM_RESERVE_OWNED_MEMORY)
	   || (Flags & MEM_RESERVE_MIRRORED_MEMORY)
	   || (Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    /* There might be a shorter way to write this, but this is the clearest */
    if (Flags & MEM_RESERVE_NO_ACCESS) {
	assert(!(Flags & MEM_RESERVE_OWNED_MEMORY));
	assert(!(Flags & MEM_RESERVE_MIRRORED_MEMORY));
	assert(!(Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    }
    if (Flags & MEM_RESERVE_OWNED_MEMORY) {
	assert(!(Flags & MEM_RESERVE_NO_ACCESS));
	assert(!(Flags & MEM_RESERVE_MIRRORED_MEMORY));
	assert(!(Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    }
    if (Flags & MEM_RESERVE_MIRRORED_MEMORY) {
	assert(!(Flags & MEM_RESERVE_NO_ACCESS));
	assert(!(Flags & MEM_RESERVE_OWNED_MEMORY));
	assert(!(Flags & MEM_RESERVE_PHYSICAL_MAPPING));
    }
    if (Flags & MEM_RESERVE_PHYSICAL_MAPPING) {
	assert(!(Flags & MEM_RESERVE_NO_ACCESS));
	assert(!(Flags & MEM_RESERVE_OWNED_MEMORY));
	assert(!(Flags & MEM_RESERVE_MIRRORED_MEMORY));
    }
    if (Flags & MEM_RESERVE_PHYSICAL_MAPPING) {
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
    MiInitializeVadNode(Vad, VSpace, VirtAddr, WindowSize, VadFlags);
    MiAvlTreeInsertNode(&VSpace->VadTree, &Parent->AvlNode, &Vad->AvlNode);

    if (VadFlags.ImageMap) {
	Vad->ImageSectionView.SubSection = NULL;
    }

    if (VadFlags.FileMap) {
	Vad->DataSectionView.Section = NULL;
	Vad->DataSectionView.SectionOffset = 0;
    }

    if (VadFlags.PhysicalMapping) {
	Vad->PhysicalSectionView.PhysicalBase = 0;
    }

    if (VadFlags.OwnedMemory) {
	Vad->OwnedMemory.CommitmentSize = 0;
	InitializeListHead(&Vad->OwnedMemory.ViewerList);
    }

    if (VadFlags.MirroredMemory) {
	Vad->MirroredMemory.OwnerVad = NULL;
	Vad->MirroredMemory.Offset = 0;
	InitializeListHead(&Vad->MirroredMemory.ViewerLink);
    }

    if (pVad != NULL) {
	*pVad = Vad;
    }

    DbgTrace("Successfully reserved [%p, %p) for vspace %p\n",
	     (PVOID) Vad->AvlNode.Key,
	     (PVOID) (Vad->AvlNode.Key + Vad->WindowSize),
	     (PVOID) VSpace);
    return STATUS_SUCCESS;
}

/*
 * Add the mirrored memory VAD to the owner VAD's viewer list
 */
VOID MmRegisterMirroredMemory(IN PMMVAD Viewer,
			      IN PMMVAD Owner,
			      IN MWORD Offset)
{
    assert(Viewer != NULL);
    assert(Owner != NULL);
    assert(Viewer->Flags.MirroredMemory);
    assert(Owner->Flags.OwnedMemory);
    Viewer->MirroredMemory.OwnerVad = Owner;
    Viewer->MirroredMemory.Offset = Offset;
    InsertTailList(&Owner->OwnedMemory.ViewerList, &Viewer->MirroredMemory.ViewerLink);
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

    if (Vad->Flags.Committed) {
	return STATUS_SUCCESS;
    }

    PAGING_RIGHTS Rights = Vad->Flags.ReadOnly ? MM_RIGHTS_RO : MM_RIGHTS_RW;
    PVOID FileBuffer = Vad->ImageSectionView.SubSection->ImageSection->FileObject->BufferPtr;
    PVOID DataBuffer = FileBuffer + Vad->ImageSectionView.SubSection->FileOffset;
    MWORD DataSize = Vad->ImageSectionView.SubSection->RawDataSize;
    /* TODO: Use shared pages for PE headers and read-only sections. */
    if (Vad->Flags.OwnedMemory) {
	RET_ERR(MiCommitOwnedMemory(Vad->VSpace, Vad->AvlNode.Key, Vad->WindowSize, Rights,
				    Vad->Flags.LargePages, DataSize ? DataBuffer : NULL,
				    DataSize));
	Vad->OwnedMemory.CommitmentSize = Vad->WindowSize;
    } else {
	PMMVAD OwnerVad = Vad->MirroredMemory.OwnerVad;
	assert(OwnerVad != NULL);
	assert(OwnerVad->Flags.OwnedMemory);
	assert(IS_PAGE_ALIGNED(OwnerVad->AvlNode.Key));
	assert(IS_PAGE_ALIGNED(Vad->MirroredMemory.Offset));
	MWORD OwnerStartAddr = OwnerVad->AvlNode.Key + Vad->MirroredMemory.Offset;
	assert(OwnerStartAddr + Vad->WindowSize <=
	       OwnerVad->AvlNode.Key + OwnerVad->WindowSize);
	RET_ERR(MiMapMirroredMemory(OwnerVad->VSpace, OwnerStartAddr, Vad->VSpace,
				    Vad->AvlNode.Key, Vad->WindowSize, Rights));
    }
    Vad->Flags.Committed = TRUE;

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
				 IN MWORD WindowSize,
				 IN MWORD CommitFlags)
{
    assert(VSpace != NULL);
    assert(WindowSize > 0);
    StartAddr = PAGE_ALIGN(StartAddr);
    WindowSize = PAGE_ALIGN_UP(WindowSize);
    assert(StartAddr + WindowSize > StartAddr);

    PMMVAD Vad = MiVSpaceFindVadNode(VSpace, StartAddr);
    if ((Vad == NULL) || Vad->Flags.NoAccess) {
	return STATUS_INVALID_PARAMETER;
    }

    if ((StartAddr < Vad->AvlNode.Key) ||
	(StartAddr + WindowSize > Vad->AvlNode.Key + Vad->WindowSize)) {
	return STATUS_INVALID_PARAMETER;
    }

    PAGING_RIGHTS Rights = (Vad->Flags.ReadOnly) ? MM_RIGHTS_RO : MM_RIGHTS_RW;

    if (Vad->Flags.ImageMap) {
	RET_ERR(MiCommitImageVad(Vad));
    } else if (Vad->Flags.FileMap) {
	return STATUS_NTOS_UNIMPLEMENTED;
    } else if (Vad->Flags.PhysicalMapping) {
	for (MWORD Committed = 0; Committed < WindowSize; Committed += PAGE_SIZE) {
	    MWORD PhyAddr = StartAddr - Vad->AvlNode.Key +
		Vad->PhysicalSectionView.PhysicalBase + Committed;
	    RET_ERR(MiCommitIoPage(Vad->VSpace, PhyAddr, StartAddr + Committed, Rights));
	}
    } else if (Vad->Flags.MirroredMemory) {
	PMMVAD OwnerVad = Vad->MirroredMemory.OwnerVad;
	assert(OwnerVad != NULL);
	assert(OwnerVad->Flags.OwnedMemory);
	assert(IS_PAGE_ALIGNED(OwnerVad->AvlNode.Key));
	assert(IS_PAGE_ALIGNED(Vad->MirroredMemory.Offset));
	MWORD OwnerStartAddr = OwnerVad->AvlNode.Key + Vad->MirroredMemory.Offset;
	assert(OwnerStartAddr + Vad->WindowSize <=
	       OwnerVad->AvlNode.Key + OwnerVad->WindowSize);
	RET_ERR(MiMapMirroredMemory(OwnerVad->VSpace, OwnerStartAddr, Vad->VSpace,
				    StartAddr, WindowSize, Rights));
    } else if (Vad->Flags.OwnedMemory) {
	RET_ERR(MiCommitOwnedMemory(Vad->VSpace, StartAddr, WindowSize, Rights,
				    Vad->Flags.LargePages, NULL, 0));
	Vad->OwnedMemory.CommitmentSize += WindowSize;
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

    return MiPagingTypeIsPage(Page->Type) ? Page : NULL;
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
	     "   %s%s%s%s%s%s\n",
	     (PVOID) Vad->AvlNode.Key, Vad->WindowSize,
	     Vad->Flags.ImageMap ? " image-map" : "",
	     Vad->Flags.LargePages ? " large-pages" : "",
	     Vad->Flags.Committed ? " committed" : " not-committed",
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
    if (Vad->Flags.OwnedMemory) {
	DbgPrint("    commitment size = 0x%zx\n", Vad->OwnedMemory.CommitmentSize);
	DbgPrint("    viewers =");
	LoopOverList(Viewer, &Vad->OwnedMemory.ViewerList, MMVAD, MirroredMemory.ViewerLink) {
	    DbgPrint(" %p", Viewer);
	}
	DbgPrint("\n");
    }
    if (Vad->Flags.MirroredMemory) {
	DbgPrint("    owner vad = %p\n", Vad->MirroredMemory.OwnerVad);
	DbgPrint("    offset from owner vad window = 0x%zx\n", Vad->MirroredMemory.Offset);
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
    DbgPrint("    vad tree %p linearly:  ", &VSpace->VadTree);
    MmAvlDumpTreeLinear(&VSpace->VadTree);
    DbgPrint("\n    vad tree %p:\n", &VSpace->VadTree);
    MmAvlDumpTree(&VSpace->VadTree);
    DbgPrint("    vad tree content:\n");
    LoopOverVadTree(Vad, VSpace, MmDbgDumpVad(Vad));
    DbgPrint("    page mappings:\n");
    MmDbgDumpPagingStructureRecursively(VSpace->RootPagingStructure);
}
#endif
