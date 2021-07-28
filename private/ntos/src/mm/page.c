#include "mi.h"

/*
 * Returns the log2size of the address window that the paging structure represents
 */
static inline LONG MiPagingAddrWindowBits(PAGING_STRUCTURE_TYPE Type)
{
    if (Type == PAGING_TYPE_PAGE) {
	return PAGE_LOG2SIZE;
    } else if (Type == PAGING_TYPE_LARGE_PAGE) {
	return LARGE_PAGE_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PAGE_TABLE) {
	return PAGE_TABLE_WINDOW_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return PAGE_DIRECTORY_WINDOW_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PDPT) {
	return PDPT_WINDOW_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PML4) {
	return PML4_WINDOW_LOG2SIZE;
    }
    assert(FALSE);
    return 0;
}

static inline PCSTR MiPagingTypeToStr(PAGING_STRUCTURE_TYPE Type)
{
    if (Type == PAGING_TYPE_PAGE) {
	return "PAGE";
    } else if (Type == PAGING_TYPE_LARGE_PAGE) {
	return "LARGE PAGE";
    } else if (Type == PAGING_TYPE_PAGE_TABLE) {
	return "PAGE TABLE";
    } else if (Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return "PAGE DIRECTORY";
    } else if (Type == PAGING_TYPE_PDPT) {
	return "PDPT";
    } else if (Type == PAGING_TYPE_PML4) {
	return "PML4";
    }
    assert(FALSE);
    return 0;
}

/*
 * Sanitize the virtual address such that it is aligned with
 * the boundary of the address window of the paging structure
 */
static inline MWORD MiSanitizeAlignment(IN PAGING_STRUCTURE_TYPE Type,
					IN MWORD VirtAddr)
{
    return VirtAddr & ~((1ULL << MiPagingAddrWindowBits(Type)) - 1);
}

#define ASSERT_ALIGNMENT(Page)						\
    assert(MiSanitizeAlignment(Page->Type, Page->AvlNode.Key) == Page->AvlNode.Key)

/*
 * Returns the log2size of the seL4 kernel object representing the paging structure
 *
 * Note: Not to be confused with the log2size of the address window it represents
 */
static inline LONG MiPagingObjLog2Size(PAGING_STRUCTURE_TYPE Type)
{
    if (Type == PAGING_TYPE_PAGE) {
	return PAGE_LOG2SIZE;
    } else if (Type == PAGING_TYPE_LARGE_PAGE) {
	return LARGE_PAGE_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PAGE_TABLE) {
	return PAGE_TABLE_OBJ_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return PAGE_DIRECTORY_OBJ_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PDPT) {
	return PDPT_OBJ_LOG2SIZE;
    } else if (Type == PAGING_TYPE_PML4) {
	return PML4_OBJ_LOG2SIZE;
    }
    assert(FALSE);
    return 0;
}

/*
 * Returns the type of the seL4 kernel object representing the paging structure
 * that is one layer below the specified paging structure. In other words, for page
 * tables we return page, etc.
 *
 * Note that multiple paging structure types can share the same super-structure
 * (for instance, both page tables and large pages have page directory as parent),
 * and MiPagingSubStructureType returns the intermediate mapping structure (ie.
 * page table, page directory, and PDPT), not the large/huge page types.
 */
static inline PAGING_STRUCTURE_TYPE MiPagingSubStructureType(PPAGING_STRUCTURE Page)
{
    if (Page->Type == PAGING_TYPE_PAGE_TABLE) {
	return PAGING_TYPE_PAGE;
    } else if (Page->Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return PAGING_TYPE_PAGE_TABLE;
    } else if (Page->Type == PAGING_TYPE_PDPT) {
	return PAGING_TYPE_PAGE_DIRECTORY;
    } else if (Page->Type == PAGING_TYPE_PML4) {
	return PAGING_TYPE_PDPT;
    }
    assert(FALSE);
    return 0;
}

/*
 * Returns the type of the seL4 kernel object representing the paging structure
 * that is one layer below the specified paging structure. In other words, for page
 * tables we return page, etc.
 */
static inline PAGING_STRUCTURE_TYPE MiPagingSuperStructureType(PPAGING_STRUCTURE Page)
{
    if (Page->Type == PAGING_TYPE_PAGE) {
	return PAGING_TYPE_PAGE_TABLE;
    } else if (Page->Type == PAGING_TYPE_PAGE_TABLE) {
	return PAGING_TYPE_PAGE_DIRECTORY;
    } else if (Page->Type == PAGING_TYPE_LARGE_PAGE) {
	return PAGING_TYPE_PAGE_DIRECTORY;
    }
#ifdef _M_AMD64
    if (Page->Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return PAGING_TYPE_PDPT;
    } else if (Page->Type == PAGING_TYPE_PDPT) {
	return PAGING_TYPE_PML4;
    }
#endif
    assert(FALSE);
    return 0;
}

/*
 * Returns TRUE if the address window that the paging structure represents
 * contains the given virtual address
 */
static inline BOOLEAN MiPagingStructureContainsAddr(IN PPAGING_STRUCTURE Paging,
						    IN MWORD VirtAddr)
{
    return MiAvlNodeContainsAddr(&Paging->AvlNode,
				 1ULL << MiPagingAddrWindowBits(Paging->Type), VirtAddr);
}

/*
 * Initialize the PAGING_STRUCTURE with the given parameters. The virtual address
 * is rounded down to the correct alignment.
 */
VOID MiInitializePagingStructure(IN PPAGING_STRUCTURE Page,
				 IN PCAP_TREE_NODE ParentNode,
				 IN PPAGING_STRUCTURE SuperStructure,
				 IN MWORD VSpaceCap,
				 IN MWORD Cap,
				 IN MWORD VirtAddr,
				 IN PAGING_STRUCTURE_TYPE Type,
				 IN BOOLEAN Mapped,
				 IN PAGING_RIGHTS Rights)
{
    MiInitializeCapTreeNode(&Page->TreeNode, CAP_TREE_NODE_PAGING_STRUCTURE,
			    Cap, ParentNode);
    MiAvlInitializeNode(&Page->AvlNode, MiSanitizeAlignment(Type, VirtAddr));
    Page->SuperStructure = SuperStructure;
    MiAvlInitializeTree(&Page->SubStructureTree);
    Page->VSpaceCap = VSpaceCap;
    Page->Type = Type;
    Page->Mapped = Mapped;
    Page->Rights = Rights;
    /* TODO: Implement page attributes */
    Page->Attributes = seL4_X86_Default_VMAttributes;
}

/*
 * Find the substructure within the given paging structure that contains
 * the given virtual address.
 */
PPAGING_STRUCTURE MiPagingFindSubstructure(IN PPAGING_STRUCTURE Paging,
					   IN MWORD VirtAddr)
{
    assert(Paging != NULL);
    VirtAddr = MiSanitizeAlignment(MiPagingSubStructureType(Paging), VirtAddr);
    PMM_AVL_TREE Tree = &Paging->SubStructureTree;
    PMM_AVL_NODE Parent = MiAvlTreeFindNodeOrParent(Tree, VirtAddr);
    PPAGING_STRUCTURE Super = MM_AVL_NODE_TO_PAGING_STRUCTURE(Parent);
    if (Super != NULL && MiPagingStructureContainsAddr(Super, VirtAddr)) {
	return Super;
    }
    return NULL;
}

/*
 * Insert the given substructure into the given paging structure.
 * Both the paging structure and the substructure must be mapped.
 * Otherwise it is a programming bug. We enforce this on debug build.
 *
 * The paging structure must not already contain an overlapping substructure.
 * It is a programming bug if this has not been enforced.
 *
 */
static VOID MiPagingInsertSubStructure(IN PPAGING_STRUCTURE Self,
				       IN PPAGING_STRUCTURE SubStructure)
{
    assert(Self != NULL);
    assert(SubStructure != NULL);
    assert(Self->Mapped);
    assert(SubStructure->Mapped);
    PMM_AVL_TREE Tree = &Self->SubStructureTree;
    MWORD VirtAddr = SubStructure->AvlNode.Key;
    PMM_AVL_NODE Super = MiAvlTreeFindNodeOrParent(Tree, VirtAddr);
    if (Super != NULL && MiPagingStructureContainsAddr(
	    MM_AVL_NODE_TO_PAGING_STRUCTURE(Super), VirtAddr)) {
	assert(FALSE);
    }
    MiAvlTreeInsertNode(Tree, Super, &SubStructure->AvlNode);
    SubStructure->SuperStructure = Self;
}

/*
 * Recursively insert the given paging structure into the virtual address
 * space, starting from its root paging structure. All the intermediate paging
 * structures must already have been mapped prior to calling this function.
 */
NTSTATUS MiVSpaceInsertPagingStructure(IN PVIRT_ADDR_SPACE VSpace,
				       IN PPAGING_STRUCTURE Paging)
{
    PPAGING_STRUCTURE Super = &VSpace->RootPagingStructure;
    assert(Super != NULL);
    while (Super->Type != MiPagingSuperStructureType(Paging)) {
	Super = MiPagingFindSubstructure(Super, Paging->AvlNode.Key);
	if (Super == NULL) {
	    return STATUS_NTOS_BUG;
	}
    }
    MiPagingInsertSubStructure(Super, Paging);
    return STATUS_SUCCESS;
}

static NTSTATUS MiRetypeIntoPagingStructure(PPAGING_STRUCTURE Page)
{
    if (Page->Mapped || (Page->TreeNode.Cap != 0)) {
	return STATUS_NTOS_BUG;
    }

    PUNTYPED Untyped = (PUNTYPED) Page->TreeNode.Parent;
    if (Untyped == NULL) {
	return STATUS_NTOS_BUG;
    }

    return MmRetypeIntoObject(Untyped, Page->Type,
			      MiPagingObjLog2Size(Page->Type),
			      &Page->TreeNode.Cap);
}

static NTSTATUS MiMapPagingStructure(PPAGING_STRUCTURE Page)
{
    assert(Page != NULL);
    ASSERT_ALIGNMENT(Page);

    if (Page->SuperStructure == NULL) {
	return STATUS_NTOS_BUG;
    }

    RET_ERR(MiRetypeIntoPagingStructure(Page));

    int Error = 0;
    if (Page->Type == PAGING_TYPE_PAGE || Page->Type == PAGING_TYPE_LARGE_PAGE) {
#if CONFIG_DEBUG_BUILD
	seL4_X86_Page_GetAddress_t Reply = seL4_X86_Page_GetAddress(Page->TreeNode.Cap);
	DbgTrace("Mapping %spage cap 0x%zx (paddr %p%s) into vspacecap 0x%zx at vaddr %p\n",
		 (Page->Type == PAGING_TYPE_LARGE_PAGE) ? "large " : "",
		 Page->TreeNode.Cap, (PVOID) Reply.paddr, (Reply.error == 0) ? "" : " ???",
		 Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
#endif
	Error = seL4_X86_Page_Map(Page->TreeNode.Cap,
				  Page->VSpaceCap,
				  Page->AvlNode.Key,
				  Page->Rights,
				  Page->Attributes);
    } else if (Page->Type == PAGING_TYPE_PAGE_TABLE) {
	DbgTrace("Mapping page table cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
		 Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PageTable_Map(Page->TreeNode.Cap,
				       Page->VSpaceCap,
				       Page->AvlNode.Key,
				       Page->Attributes);
#ifdef _M_AMD64
    } else if (Page->Type == PAGING_TYPE_PAGE_DIRECTORY) {
	DbgTrace("Mapping page directory cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
		 Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PageDirectory_Map(Page->TreeNode.Cap,
					   Page->VSpaceCap,
					   Page->AvlNode.Key,
					   Page->Attributes);
    } else if (Page->Type == PAGING_TYPE_PDPT) {
	DbgTrace("Mapping PDPT cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
		 Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PDPT_Map(Page->TreeNode.Cap,
				  Page->VSpaceCap,
				  Page->AvlNode.Key,
				  Page->Attributes);
#endif
    } else {
	return STATUS_INVALID_PARAMETER;
    }

    if (Error) {
	DbgTrace("Failed to map cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
		 Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	seL4_CNode_Delete(ROOT_CNODE_CAP, Page->TreeNode.Cap, 0);
	MmDeallocateCap(Page->TreeNode.Cap);
	Page->TreeNode.Cap = 0;
	return SEL4_ERROR(Error);
    }

    Page->Mapped = TRUE;
    MiPagingInsertSubStructure(Page->SuperStructure, Page);

    DbgTrace("Successfully mapped cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
	     Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
    return STATUS_SUCCESS;
}

MM_MEM_PRESSURE MmQueryMemoryPressure()
{
    return MM_MEM_PRESSURE_SUFFICIENT_MEMORY;
}

/*
 * Create a paging structure of the given type from the supplied untyped cap
 * and initialize the paging structure. The virtual address is rounded down
 * to the correct alignment.
 */
NTSTATUS MiCreatePagingStructure(IN PAGING_STRUCTURE_TYPE Type,
				 IN PUNTYPED Untyped,
				 IN PPAGING_STRUCTURE ParentPaging,
				 IN MWORD VirtAddr,
				 IN MWORD VSpaceCap,
				 IN PAGING_RIGHTS Rights,
				 OUT PPAGING_STRUCTURE *pPaging)
{
    assert(pPaging);

    MiAllocatePool(Paging, PAGING_STRUCTURE);
    MiInitializePagingStructure(Paging, &Untyped->TreeNode, ParentPaging,
				VSpaceCap, 0, VirtAddr, Type, FALSE, Rights);

    *pPaging = Paging;
    return STATUS_SUCCESS;
}

/*
 * Ensure that all levels of super-structures of the given paging structure are mapped,
 * Optionally returning the pointer to the immediate super-structure.
 *
 * The mapped intermediate structures inherit their super structure's access rights.
 *
 * All super-structures are allocated from the available untyped memory of the root task.
 */
static NTSTATUS MiMapSuperStructure(IN PPAGING_STRUCTURE Paging,
				    IN PVIRT_ADDR_SPACE VSpace,
				    OUT PPAGING_STRUCTURE *pSuperStructure)
{
    assert(Paging != NULL);
    assert(VSpace != NULL);

    /* The MiInitializePagingStructure routine will round the virtual address
     * to the correct alignment when mapping super structures. */
    MWORD VirtAddr = Paging->AvlNode.Key;
    PPAGING_STRUCTURE SuperStructure = &VSpace->RootPagingStructure;

    while (SuperStructure->Type != MiPagingSuperStructureType(Paging)) {
	assert(SuperStructure->VSpaceCap == VSpace->VSpaceCap);
	PPAGING_STRUCTURE SubStructure =
	    MiPagingFindSubstructure(SuperStructure, VirtAddr);
	if (SubStructure == NULL) {
	    PAGING_STRUCTURE_TYPE Subtype = MiPagingSubStructureType(SuperStructure);
	    PUNTYPED Untyped = NULL;
	    RET_ERR(MmRequestUntyped(MiPagingObjLog2Size(Subtype), &Untyped));
	    RET_ERR_EX(MiCreatePagingStructure(Subtype, Untyped, SuperStructure,
					       VirtAddr, VSpace->VSpaceCap,
					       SuperStructure->Rights, &SubStructure),
		       MmReleaseUntyped(Untyped));
	    /* On error, MmReleaseUntyped will call ExFreePool on the UNTYPED */
	    RET_ERR_EX(MiMapPagingStructure(SubStructure), MmReleaseUntyped(Untyped));
	}
	assert(SubStructure != NULL);
	SuperStructure = SubStructure;
    }

    assert(SuperStructure != NULL);
    Paging->SuperStructure = SuperStructure;
    if (pSuperStructure != NULL) {
	*pSuperStructure = SuperStructure;
    }

    return STATUS_SUCCESS;
}

/*
 * Allocate and map pages that cover the address window [VirtAddr, VirtAddr+Size),
 *
 * Address window must be aligned at page boundary.
 *
 * If specified, will attempt to use large pages when mapping.
 */
NTSTATUS MiCommitPrivateMemory(IN PVIRT_ADDR_SPACE VaddrSpace,
			       IN MWORD VirtAddr,
			       IN MWORD Size,
			       IN PAGING_RIGHTS Rights,
			       IN BOOLEAN UseLargePage)
{
    DbgTrace("Committing vaddr window [%p, %p) for vaddrcap 0x%zx\n",
	     (PVOID) VirtAddr, (PVOID)(VirtAddr+Size), VaddrSpace->VSpaceCap);
    assert(IS_PAGE_ALIGNED(VirtAddr));
    assert(IS_PAGE_ALIGNED(Size));

    if (VirtAddr + Size < VirtAddr) {
	/* Integer overflow */
	return STATUS_INVALID_PARAMETER;
    }
 
    PPAGING_STRUCTURE SuperStructure = NULL;
    MWORD CurVaddr = VirtAddr;
    while (CurVaddr < VirtAddr + Size) {
	PUNTYPED Untyped = NULL;
	PAGING_STRUCTURE_TYPE Type = PAGING_TYPE_PAGE;
	if (UseLargePage && IS_LARGE_PAGE_ALIGNED(CurVaddr)
	    && (VirtAddr + Size - CurVaddr) >= LARGE_PAGE_SIZE) {
	    Type = PAGING_TYPE_LARGE_PAGE;
	}
	RET_ERR(MmRequestUntyped(MiPagingObjLog2Size(Type), &Untyped));
	PPAGING_STRUCTURE Page = NULL;
	RET_ERR_EX(MiCreatePagingStructure(Type, Untyped, SuperStructure, CurVaddr,
					   VaddrSpace->VSpaceCap, Rights, &Page),
		   MmReleaseUntyped(Untyped));
	assert(Page != NULL);
	if (SuperStructure == NULL) {
	    RET_ERR(MiMapSuperStructure(Page, VaddrSpace, &SuperStructure));
	    assert(SuperStructure != NULL);
	}
	RET_ERR(MiMapPagingStructure(Page));
	CurVaddr += 1ULL << MiPagingAddrWindowBits(Page->Type);
	/* When we cross a large page boundary, reset the SuperStructure pointer
	 * to make sure that there is a page table for the new page. */
	if (IS_LARGE_PAGE_ALIGNED(CurVaddr)) {
	    SuperStructure = NULL;
	}
    }

    DbgTrace("Successfully committed vaddr window [%p, %p) for vaddrcap 0x%zx\n",
	     (PVOID) VirtAddr, (PVOID) (VirtAddr+Size), VaddrSpace->VSpaceCap);

    return STATUS_SUCCESS;
}

/*
 * Map one page of physical memory at specified physical address into the specified
 * virtual address, optionally returning the paging structure pointer.
 */
NTSTATUS MmCommitIoPageEx(IN PVIRT_ADDR_SPACE VaddrSpace,
			  IN MWORD PhyAddr,
			  IN MWORD VirtAddr,
			  IN PAGING_RIGHTS Rights,
			  OUT OPTIONAL PPAGING_STRUCTURE *pPage)
{
    assert(IS_PAGE_ALIGNED(PhyAddr));
    assert(IS_PAGE_ALIGNED(VirtAddr));
    PhyAddr = PAGE_ALIGN(PhyAddr);
    VirtAddr = PAGE_ALIGN(VirtAddr);

    PUNTYPED IoUntyped;
    RET_ERR(MiRequestIoUntyped(&MiPhyMemDescriptor, PhyAddr, &IoUntyped));
    if (IoUntyped->Log2Size != PAGE_LOG2SIZE) {
	return STATUS_NTOS_BUG;
    }

    PPAGING_STRUCTURE Page = NULL;
    RET_ERR_EX(MiCreatePagingStructure(PAGING_TYPE_PAGE, IoUntyped, NULL, VirtAddr,
				       VaddrSpace->VSpaceCap, Rights, &Page),
	       MmReleaseUntyped(IoUntyped));
    assert(Page != NULL);
    RET_ERR_EX(MiMapSuperStructure(Page, VaddrSpace, NULL), MmReleaseUntyped(IoUntyped));
    RET_ERR(MiMapPagingStructure(Page));

    if (pPage != NULL) {
	*pPage = Page;
    }

    return STATUS_SUCCESS;
}

VOID MmDbgDumpPagingStructure(IN PPAGING_STRUCTURE Paging)
{
    DbgPrint("Dumping paging structure (PPAGING_STRUCTURE = %p)\n", Paging);
    if (Paging == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }

    DbgPrint("    Virtual address %p  Type %s  VSpaceCap 0x%zx\n",
	     (PVOID) Paging->AvlNode.Key, MiPagingTypeToStr(Paging->Type), Paging->VSpaceCap);
    DbgPrint("    ");
    MmDbgDumpCapTreeNode(&Paging->TreeNode);
    DbgPrint("  Cap Tree Parent ");
    MmDbgDumpCapTreeNode(Paging->TreeNode.Parent);
    DbgPrint("\n    Parent Paging Structure ");
    if (Paging->SuperStructure != NULL) {
	DbgPrint("Vaddr %p Type %s", (PVOID) Paging->SuperStructure->AvlNode.Key,
		 MiPagingTypeToStr(Paging->SuperStructure->Type));
    } else {
	DbgPrint("(nil)");
    }
    DbgPrint("\n    ");
    if (Paging->Mapped) {
	DbgPrint("Mapped");
    } else {
	DbgPrint("Not mapped");
    }
    DbgPrint("\n    Sub-structures linearly:  ");
    MmAvlDumpTreeLinear(&Paging->SubStructureTree);
    DbgPrint("\n    Sub-structures as a tree:\n");
    MmAvlDumpTree(&Paging->SubStructureTree);
}
