#include "mi.h"

#ifdef MMDBG
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
#endif

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
 */
static inline PAGING_STRUCTURE_TYPE MiPagingSuperStructureType(PAGING_STRUCTURE_TYPE Type)
{
    if (Type == PAGING_TYPE_PAGE) {
	return PAGING_TYPE_PAGE_TABLE;
    } else if (Type == PAGING_TYPE_PAGE_TABLE) {
	return PAGING_TYPE_PAGE_DIRECTORY;
    } else if (Type == PAGING_TYPE_LARGE_PAGE) {
	return PAGING_TYPE_PAGE_DIRECTORY;
    }
#ifdef _M_AMD64
    if (Type == PAGING_TYPE_PAGE_DIRECTORY) {
	return PAGING_TYPE_PDPT;
    } else if (Type == PAGING_TYPE_PDPT) {
	return PAGING_TYPE_PML4;
    }
#endif
    assert(FALSE);
    return 0;
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
				 IN PAGING_RIGHTS Rights,
    				 IN PAGING_ATTRIBUTES Attributes)
{
    MmInitializeCapTreeNode(&Page->TreeNode, CAP_TREE_NODE_PAGING_STRUCTURE,
			    Cap, &MiNtosCNode, ParentNode);
    AvlInitializeNode(&Page->AvlNode, MiSanitizeAlignment(Type, VirtAddr));
    Page->SuperStructure = SuperStructure;
    AvlInitializeTree(&Page->SubStructureTree);
    Page->VSpaceCap = VSpaceCap;
    Page->Type = Type;
    Page->Mapped = Mapped;
    Page->Rights = Rights;
    Page->Attributes = Attributes;
}

/*
 * Find the substructure within the given paging structure that contains
 * the given virtual address.
 */
static PPAGING_STRUCTURE MiPagingFindSubstructure(IN PPAGING_STRUCTURE Paging,
						  IN MWORD VirtAddr)
{
    assert(Paging != NULL);
    VirtAddr = MiSanitizeAlignment(MiPagingSubStructureType(Paging->Type), VirtAddr);
    PAVL_TREE Tree = &Paging->SubStructureTree;
    PAVL_NODE Node = AvlTreeFindNodeOrParent(Tree, VirtAddr);
    PPAGING_STRUCTURE SubStructure = AVL_NODE_TO_PAGING_STRUCTURE(Node);
    if (SubStructure && MiPagingStructureContainsAddr(SubStructure, VirtAddr)) {
	return SubStructure;
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
    PAVL_TREE Tree = &Self->SubStructureTree;
    MWORD VirtAddr = SubStructure->AvlNode.Key;
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(Tree, VirtAddr);
    if (Parent != NULL &&
	MiPagingStructureContainsAddr(AVL_NODE_TO_PAGING_STRUCTURE(Parent), VirtAddr)) {
	MmDbg("Assertion triggered. Dumping PAGING_STRUCTURE Super:\n");
	MmDbgDumpPagingStructure(AVL_NODE_TO_PAGING_STRUCTURE(Parent));
	MmDbg("Dumping PAGING_STRUCTURE SubStructure:\n");
	MmDbgDumpPagingStructure(SubStructure);
	assert(FALSE);
    }
    AvlTreeInsertNode(Tree, Parent, &SubStructure->AvlNode);
    SubStructure->SuperStructure = Self;
}

/*
 * Remove the given paging structure from its parent structure (if available).
 */
static inline VOID MiPagingRemoveFromParentStructure(IN PPAGING_STRUCTURE Self)
{
    assert(Self != NULL);
    PPAGING_STRUCTURE Parent = Self->SuperStructure;
    if (Parent == NULL) {
	return;
    }

    AvlTreeRemoveNode(&Parent->SubStructureTree, &Self->AvlNode);
    Self->SuperStructure = NULL;
}

/*
 * Recursively insert the given paging structure into the virtual address
 * space, starting from its root paging structure. All the intermediate paging
 * structures must already have been mapped prior to calling this function.
 */
NTSTATUS MiVSpaceInsertPagingStructure(IN PVIRT_ADDR_SPACE VSpace,
				       IN PPAGING_STRUCTURE Paging)
{
    PPAGING_STRUCTURE Super = VSpace->RootPagingStructure;
    assert(Super != NULL);
    while (Super->Type != MiPagingSuperStructureType(Paging->Type)) {
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
    if (Page->TreeNode.Cap != 0) {
	return STATUS_SUCCESS;
    }
    PUNTYPED Untyped = (PUNTYPED) Page->TreeNode.Parent;
    assert(Untyped != NULL);
    return MmRetypeIntoObject(Untyped, Page->Type,
			      MiPagingObjLog2Size(Page->Type),
			      &Page->TreeNode);
}

static VOID MiFreePagingStructure(PPAGING_STRUCTURE Page)
{
    MiCapTreeRemoveFromParent(&Page->TreeNode);
    assert(AvlTreeIsEmpty(&Page->SubStructureTree));
    if (Page->SuperStructure) {
	AvlTreeRemoveNode(&Page->SuperStructure->SubStructureTree, &Page->AvlNode);
	Page->SuperStructure = NULL;
    }
    MiFreePool(Page);
}

static NTSTATUS MiMapPagingStructure(PPAGING_STRUCTURE Page)
{
    assert(Page != NULL);
    ASSERT_ALIGNMENT(Page);

    if (Page->Mapped) {
	return STATUS_NTOS_BUG;
    }

    if (Page->SuperStructure == NULL) {
	return STATUS_NTOS_BUG;
    }

    RET_ERR(MiRetypeIntoPagingStructure(Page));

    int Error = 0;
    if (Page->Type == PAGING_TYPE_PAGE || Page->Type == PAGING_TYPE_LARGE_PAGE) {
#ifdef MMDBG
	seL4_X86_Page_GetAddress_t Reply = seL4_X86_Page_GetAddress(Page->TreeNode.Cap);
	MmDbg("Mapping %spage cap 0x%zx (paddr %p%s) into vspacecap 0x%zx at vaddr %p\n",
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
	MmDbg("Mapping page table cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
	      Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PageTable_Map(Page->TreeNode.Cap,
				       Page->VSpaceCap,
				       Page->AvlNode.Key,
				       Page->Attributes);
#ifdef _M_AMD64
    } else if (Page->Type == PAGING_TYPE_PAGE_DIRECTORY) {
	MmDbg("Mapping page directory cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
	      Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PageDirectory_Map(Page->TreeNode.Cap,
					   Page->VSpaceCap,
					   Page->AvlNode.Key,
					   Page->Attributes);
    } else if (Page->Type == PAGING_TYPE_PDPT) {
	MmDbg("Mapping PDPT cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
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
	MmDbg("Failed to map cap 0x%zx into vspacecap 0x%zx at vaddr %p\n",
	      Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	return SEL4_ERROR(Error);
    }

    Page->Mapped = TRUE;
    MiPagingInsertSubStructure(Page->SuperStructure, Page);

    MmDbg("Successfully mapped cap 0x%zx (parent cap 0x%zx) into "
	  "vspacecap 0x%zx at vaddr %p\n",
	  Page->TreeNode.Cap, Page->TreeNode.Parent->Cap,
	  Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
    return STATUS_SUCCESS;
}

static NTSTATUS MiUnmapPagingStructure(PPAGING_STRUCTURE Page)
{
    assert(Page != NULL);

    if (!Page->Mapped) {
	return STATUS_NTOS_BUG;
    }

    int Error = 0;
    if (Page->Type == PAGING_TYPE_PAGE || Page->Type == PAGING_TYPE_LARGE_PAGE) {
#ifdef MMDBG
	seL4_X86_Page_GetAddress_t Reply = seL4_X86_Page_GetAddress(Page->TreeNode.Cap);
	MmDbg("Unmapping %spage cap 0x%zx (paddr %p%s) from vspacecap 0x%zx originally at vaddr %p\n",
	      (Page->Type == PAGING_TYPE_LARGE_PAGE) ? "large " : "",
	      Page->TreeNode.Cap, (PVOID) Reply.paddr, (Reply.error == 0) ? "" : " ???",
	      Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
#endif
	Error = seL4_X86_Page_Unmap(Page->TreeNode.Cap);
    } else if (Page->Type == PAGING_TYPE_PAGE_TABLE) {
	MmDbg("Unmapping page table cap 0x%zx from vspacecap 0x%zx originally at vaddr %p\n",
	      Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PageTable_Unmap(Page->TreeNode.Cap);
#ifdef _M_AMD64
    } else if (Page->Type == PAGING_TYPE_PAGE_DIRECTORY) {
	MmDbg("Unmapping page directory cap 0x%zx from vspacecap 0x%zx originally at vaddr %p\n",
	      Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PageDirectory_Unmap(Page->TreeNode.Cap);
    } else if (Page->Type == PAGING_TYPE_PDPT) {
	MmDbg("Unmapping PDPT cap 0x%zx from vspacecap 0x%zx originally at vaddr %p\n",
	      Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	Error = seL4_X86_PDPT_Unmap(Page->TreeNode.Cap);
#endif
    } else {
	return STATUS_INVALID_PARAMETER;
    }

    if (Error) {
	MmDbg("Failed to unmap cap 0x%zx from vspacecap 0x%zx originally at vaddr %p\n",
	      Page->TreeNode.Cap, Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
	return SEL4_ERROR(Error);
    }

    /* Remove the paging structure from its parent paging structure (if available) */
    Page->Mapped = FALSE;
    MiPagingRemoveFromParentStructure(Page);

    MmDbg("Successfully unmapped cap 0x%zx (parent cap 0x%zx) "
	  "from vspacecap 0x%zx originally at vaddr %p\n",
	  Page->TreeNode.Cap, Page->TreeNode.Parent->Cap,
	  Page->VSpaceCap, (PVOID) Page->AvlNode.Key);
    return STATUS_SUCCESS;
}

/*
 * Unmap the page and delete its page cap. Detach the cap tree node of
 * the page object from the cap derivation tree. If the page cap has any
 * derived cap tree node, the cap tree children are re-parented as the
 * children of the parent of the cap node. If the parent untyped of the
 * page cap has no children left, it is released. Finally, pool memory
 * for the paging structure is freed, and if the parent paging structure
 * (ie. for page it's page table, etc) is empty, destroy it too. This
 * is recursive, until we reach the root paging structure, which is NOT
 * deleted.
 *
 * Page can be a PAGE or LARGE_PAGE, or any leaf paging structure (eg.
 * an empty page table).
 */
VOID MiDeletePage(IN PPAGING_STRUCTURE Page)
{
    assert(Page != NULL);
    /* Leaf-level paging structure should not have substructures */
    assert(Page->SubStructureTree.BalancedRoot == NULL);
    MmDbg("Deleting page cap 0x%zx of vspace cap 0x%zx\n",
	  Page->TreeNode.Cap, Page->VSpaceCap);
    PPAGING_STRUCTURE ParentPaging = Page->SuperStructure;
    /* Remove the AVL node of the page from its AVL tree */
    MiPagingRemoveFromParentStructure(Page);
    /* Delete the page cap and deallocate the cap slot in the cspace.
     * This will automatically unmap it from the VSpace (if mapped).
     * This will also release the parent untyped cap if the page cap
     * is the only reference to the page */
    MmCapTreeDeleteNode(&Page->TreeNode);
    /* Free the pool memory */
    MiFreePool(Page);
    if (ParentPaging != NULL &&
	ParentPaging->Type != PAGING_TYPE_ROOT_PAGING_STRUCTURE &&
	ParentPaging->SubStructureTree.BalancedRoot == NULL) {
	MiDeletePage(ParentPaging);
    }
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
				 IN PAGING_ATTRIBUTES Attributes,
				 OUT PPAGING_STRUCTURE *pPaging)
{
    assert(pPaging);

    MiAllocatePool(Paging, PAGING_STRUCTURE);
    MiInitializePagingStructure(Paging, &Untyped->TreeNode, ParentPaging, VSpaceCap,
				0, VirtAddr, Type, FALSE, Rights, Attributes);

    *pPaging = Paging;
    return STATUS_SUCCESS;
}

/*
 * Copy the capability of the given page to a new capability slot in the
 * root task CSpace, possibly setting a different access rights, and return
 * the paging structure pointer to the new paging structure.
 */
static NTSTATUS MiCreateSharedPage(IN PPAGING_STRUCTURE OldPage,
				   IN PVIRT_ADDR_SPACE NewVSpace,
				   IN MWORD NewVirtAddr,
				   IN PAGING_RIGHTS NewRights,
				   IN PAGING_ATTRIBUTES NewAttributes,
				   OUT PPAGING_STRUCTURE *pNewPage)
{
    assert(OldPage);
    assert(NewVSpace);
    assert(pNewPage);
    assert(OldPage->TreeNode.Parent != NULL);

    if (!MiPagingTypeIsPageOrLargePage(OldPage->Type)) {
	return STATUS_NTOS_BUG;
    }

    if (OldPage->TreeNode.Cap == 0) {
	return STATUS_NTOS_BUG;
    }

    if (MmPagingRightsAreEqual(OldPage->Rights, MM_RIGHTS_RO) &&
	MmPagingRightsAreEqual(NewRights, MM_RIGHTS_RW)) {
	MmDbg("Warning: silently downgrading page rights\n");
	MmDbgDumpPagingStructure(OldPage);
	assert(FALSE);
    }

    MiAllocatePool(NewPage, PAGING_STRUCTURE);
    MiInitializePagingStructure(NewPage, NULL, NULL,
				NewVSpace->VSpaceCap, 0, NewVirtAddr,
				OldPage->Type, FALSE, NewRights, NewAttributes);
    /* Note that the new page cap has the same rights as the old page cap.
     * The page access rights (RW/RO) are set when we map the page. */
    RET_ERR_EX(MmCapTreeCopyNode(&NewPage->TreeNode, &OldPage->TreeNode,
				 seL4_AllRights),
	       MiFreePagingStructure(NewPage));
    *pNewPage = NewPage;

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
				    OUT OPTIONAL PPAGING_STRUCTURE *pSuperStructure)
{
    assert(Paging != NULL);
    assert(VSpace != NULL);

    /* The MiInitializePagingStructure routine will round the virtual address
     * to the correct alignment when mapping super structures. */
    MWORD VirtAddr = Paging->AvlNode.Key;
    PPAGING_STRUCTURE SuperStructure = VSpace->RootPagingStructure;

    while (SuperStructure->Type != MiPagingSuperStructureType(Paging->Type)) {
	assert(SuperStructure->VSpaceCap == VSpace->VSpaceCap);
	PPAGING_STRUCTURE SubStructure =
	    MiPagingFindSubstructure(SuperStructure, VirtAddr);
	if (SubStructure == NULL) {
	    PAGING_STRUCTURE_TYPE Subtype = MiPagingSubStructureType(SuperStructure->Type);
	    PUNTYPED Untyped = NULL;
	    RET_ERR(MmRequestUntyped(MiPagingObjLog2Size(Subtype), &Untyped));
	    RET_ERR_EX(MiCreatePagingStructure(Subtype, Untyped, SuperStructure,
					       VirtAddr, VSpace->VSpaceCap,
					       SuperStructure->Rights,
					       SuperStructure->Attributes,
					       &SubStructure),
		       MmReleaseUntyped(Untyped));
	    RET_ERR_EX(MiMapPagingStructure(SubStructure),
		       {
			   MiFreePagingStructure(SubStructure);
			   MmReleaseUntyped(Untyped);
		       });
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

static NTSTATUS MiCreateInitializedPage(IN PAGING_STRUCTURE_TYPE Type,
					IN PUNTYPED Untyped,
					IN PPAGING_STRUCTURE ParentPaging,
					IN MWORD VirtAddr,
					IN MWORD VSpaceCap,
					IN PAGING_RIGHTS Rights,
					IN PAGING_ATTRIBUTES Attributes,
					IN PVOID DataStart,
					IN MWORD DataSize,
					OUT PPAGING_STRUCTURE *pPaging)
{
    assert(DataSize <= MiPagingWindowSize(Type));
    assert(pPaging != NULL);
    assert(MiPagingTypeIsPageOrLargePage(Type));

    /* Create a new page and map it on the hyperspace address. */
    MWORD HyperspaceAddr = HYPERSPACE_4K_PAGE_START;
    if (Type == PAGING_TYPE_LARGE_PAGE) {
	HyperspaceAddr = HYPERSPACE_LARGE_PAGE_START;
    }
    PPAGING_STRUCTURE Page = NULL;
    RET_ERR(MiCreatePagingStructure(Type, Untyped, NULL, HyperspaceAddr,
				    NTOS_VSPACE_CAP, MM_RIGHTS_RW,
				    MM_ATTRIBUTES_DEFAULT, &Page));
    assert(Page != NULL);
    RET_ERR_EX(MiMapSuperStructure(Page, &MiNtosVaddrSpace, NULL),
	       MiFreePagingStructure(Page));
    RET_ERR_EX(MiMapPagingStructure(Page), MiFreePagingStructure(Page));

    /* Copy the data buffer into the new page */
    memcpy((PVOID)HyperspaceAddr, DataStart, DataSize);

    /* Unmap the page and modify the paging structure to have the new parameters */
    RET_ERR_EX(MiUnmapPagingStructure(Page), MiFreePagingStructure(Page));
    /* This is necessary because MmCapTreeNodeSetParent requires empty parent */
    MiCapTreeRemoveFromParent(&Page->TreeNode);
    MiInitializePagingStructure(Page, &Untyped->TreeNode, ParentPaging, VSpaceCap,
				Page->TreeNode.Cap, VirtAddr, Type, FALSE, Rights,
				Attributes);

    *pPaging = Page;

    return STATUS_SUCCESS;
}


/*
 * Returns the lowest-level PAGING_STRUCTURE pointer to the page at given virtual address.
 *
 * Returns NULL if virtual address is unmapped. Otherwise this routine never returns NULL.
 */
PPAGING_STRUCTURE MiQueryVirtualAddress(IN PVIRT_ADDR_SPACE VSpace,
					IN MWORD VirtAddr)
{
    assert(VSpace != NULL);

    PPAGING_STRUCTURE Paging = VSpace->RootPagingStructure;

    if (Paging == NULL) {
	return NULL;
    }

    while (!MiPagingTypeIsPageOrLargePage(Paging->Type)) {
	PPAGING_STRUCTURE SubStructure = MiPagingFindSubstructure(Paging, VirtAddr);
	if (SubStructure == NULL) {
	    return Paging;
	}
	Paging = SubStructure;
    }
    assert(Paging != NULL);

    return Paging;
}

/*
 * Get the first page within the given paging structure (page table, etc.).
 *
 * If the given paging structure it a leaf node (ie. a page, large page, or an
 * empty page table, etc), return itself.
 */
PPAGING_STRUCTURE MiGetFirstPage(IN PPAGING_STRUCTURE Page)
{
    assert(Page != NULL);
    while (AvlGetFirstNode(&Page->SubStructureTree) != NULL) {
	Page = AVL_NODE_TO_PAGING_STRUCTURE(AvlGetFirstNode(&Page->SubStructureTree));
    }
    assert(Page != NULL);
    return Page;
}

/*
 * For pages or large pages, this function returns its physical address.
 * For non-leaf paging structures, this function returns the physical address
 * of the untyped memory from which this paging structure was derived.
 */
MWORD MiGetPhysicalAddress(IN PPAGING_STRUCTURE Page)
{
    PCAP_TREE_NODE Parent = Page->TreeNode.Parent;
    while (Parent != NULL) {
	if (Parent->Type == CAP_TREE_NODE_UNTYPED) {
	    break;
	}
	Parent = Parent->Parent;
    }
    if (!Parent) {
	assert(FALSE);
	return 0;
    }
    return TREE_NODE_TO_UNTYPED(Parent)->AvlNode.Key;
}

/*
 * Get the next adjacent lowest-level paging structure. In other words, suppose
 * we have
 *
 *       |----------------|
 *       | PAGE DIRECTORY |
 *       |----------------|
 *          |         |  |_____________________
 *          |         |                       |
 *   |------------|  |------------|    |------------|
 *   |PAGE TABLE 0|  |PAGE TABLE 1|    |PAGE TABLE 2|
 *   |------------|  |------------|    |------------|
 *     |     |             |                 |
 * |-----| |-----|      |-----|           |-----|
 * |PAGE0| |PAGE1|      |PAGE2|           |PAGE3|
 * |-----| |-----|      |-----|           |-----|
 *
 * Calling MiGetNextPagingStructure on Page0 will return Page1. Calling it
 * on Page1 will return Page2. Calling it on PageTable1 will return Page3.
 * Calling it on PageTable0 will return Page2.
 */
PPAGING_STRUCTURE MiGetNextPagingStructure(IN PPAGING_STRUCTURE Page)
{
    PPAGING_STRUCTURE Next;
    do {
	if (Page == NULL) {
	    return NULL;
	}
	Next = AVL_NODE_TO_PAGING_STRUCTURE(AvlGetNextNode(&Page->AvlNode));
	Page = Page->SuperStructure;
    } while (Next == NULL);
    return Next ? MiGetFirstPage(Next) : NULL;
}

static NTSTATUS MiCommitPrivatePage(IN PVIRT_ADDR_SPACE VSpace,
				    IN MWORD VirtAddr,
				    IN PAGING_RIGHTS Rights,
				    IN PAGING_ATTRIBUTES Attributes,
				    IN BOOLEAN LargePage,
				    IN OPTIONAL PVOID DataBuffer,
				    IN OPTIONAL MWORD DataSize)
{
    assert(VSpace != NULL);
    assert(IS_PAGE_ALIGNED(VirtAddr));
    assert(!LargePage || IS_LARGE_PAGE_ALIGNED(VirtAddr));

    PPAGING_STRUCTURE SuperStructure = MiQueryVirtualAddress(VSpace, VirtAddr);
    if (MiPagingTypeIsPageOrLargePage(SuperStructure->Type)) {
	return STATUS_ALREADY_COMMITTED;
    }
    if (LargePage && (SuperStructure->Type == PAGING_TYPE_PAGE_TABLE)) {
	return STATUS_ALREADY_COMMITTED;
    }

    PAGING_STRUCTURE_TYPE Type = LargePage ? PAGING_TYPE_LARGE_PAGE : PAGING_TYPE_PAGE;

    PUNTYPED Untyped = NULL;
    RET_ERR(MmRequestUntyped(MiPagingObjLog2Size(Type), &Untyped));
    assert(Untyped != NULL);

    PPAGING_STRUCTURE Page = NULL;
    if ((DataBuffer != NULL) && (DataSize != 0)) {
	/* If we are mapping a owned page with initial data (for instance, from
	 * a .data PE image section), first map the page to the "hyperspace" of
	 * the NTOS root task, and copy the data over */
	RET_ERR_EX(MiCreateInitializedPage(Type, Untyped, SuperStructure, VirtAddr,
					   VSpace->VSpaceCap, Rights, Attributes,
					   DataBuffer, DataSize, &Page),
		   MmReleaseUntyped(Untyped));
    } else {
	/* If the SuperStructure pointer isn't correct we will fix it below */
	RET_ERR_EX(MiCreatePagingStructure(Type, Untyped, SuperStructure, VirtAddr,
					   VSpace->VSpaceCap, Rights, Attributes, &Page),
		   MmReleaseUntyped(Untyped));
    }
    assert(Page != NULL);
    if (SuperStructure->Type != MiPagingSuperStructureType(Type)) {
	/* This will update the SuperStructure pointer of Page */
	RET_ERR(MiMapSuperStructure(Page, VSpace, NULL));
    }
    RET_ERR(MiMapPagingStructure(Page));

    return STATUS_SUCCESS;
}

NTSTATUS MmCommitOwnedMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
			       IN MWORD StartAddr,
			       IN MWORD WindowSize,
			       IN PAGING_RIGHTS Rights,
			       IN PAGING_ATTRIBUTES Attributes,
			       IN BOOLEAN UseLargePages,
			       IN OPTIONAL PVOID DataBuffer,
			       IN OPTIONAL MWORD BufferSize)
{
    assert(IS_PAGE_ALIGNED(StartAddr));
    assert(IS_PAGE_ALIGNED(WindowSize));
    assert(StartAddr + WindowSize > StartAddr);
    assert((DataBuffer == NULL) || (BufferSize != 0));
    MmDbg("Committing owned memory [%p, %p) for vaddrcap 0x%zx"
	  " (data buffer = %p, data size = 0x%zx)\n",
	  (PVOID)StartAddr, (PVOID)(StartAddr+WindowSize), VSpace->VSpaceCap,
	  DataBuffer, BufferSize);

    MWORD RemainingDataSize = BufferSize;
    MWORD CurVaddr = StartAddr;
    MWORD DataStart = (MWORD) DataBuffer;
    NTSTATUS Status;
    while (CurVaddr < StartAddr + WindowSize) {
	BOOLEAN LargePage = FALSE;
	if (UseLargePages && IS_LARGE_PAGE_ALIGNED(CurVaddr)
	    && ((StartAddr + WindowSize) >= (LARGE_PAGE_SIZE + CurVaddr))) {
	    LargePage = TRUE;
	}
	MWORD PageSize = LargePage ? LARGE_PAGE_SIZE : PAGE_SIZE;
	MWORD DataSize = RemainingDataSize;
	if (RemainingDataSize > PageSize) {
	    DataSize = PageSize;
	    RemainingDataSize -= DataSize;
	} else {
	    RemainingDataSize = 0;
	}
	Status = MiCommitPrivatePage(VSpace, CurVaddr, Rights, Attributes,
				     LargePage, (PVOID)DataStart, DataSize);
	if (!NT_SUCCESS(Status)) {
	    goto err;
	}
	DataStart += DataSize;
	CurVaddr += PageSize;
    }

    MmDbg("Successfully committed memory window [%p, %p) for vaddrcap 0x%zx\n",
	  (PVOID)StartAddr, (PVOID)(StartAddr+WindowSize), VSpace->VSpaceCap);
    return STATUS_SUCCESS;
err:
    if (CurVaddr > StartAddr) {
	MmDbg("Failed to commit memory window [%p, %p) for vaddrcap 0x%zx. "
	      "Uncommitting [%p, %p)\n",
	      (PVOID)StartAddr, (PVOID)(StartAddr+WindowSize), VSpace->VSpaceCap,
	      (PVOID)StartAddr, (PVOID)CurVaddr);
	/* Decommit the successfully committed area */
	MWORD WindowSize = CurVaddr - StartAddr;
	MiUncommitWindow(VSpace, &StartAddr, &WindowSize);
    }
    return Status;
}

static NTSTATUS MiMapSharedPage(IN PVIRT_ADDR_SPACE OwnerVSpace,
				IN MWORD OwnerAddr,
				IN PVIRT_ADDR_SPACE ViewerVSpace,
				IN MWORD ViewerAddr,
				IN PAGING_RIGHTS NewRights,
				IN PAGING_ATTRIBUTES NewAttributes,
				OUT OPTIONAL PPAGING_STRUCTURE *pNewPage)
{
    PPAGING_STRUCTURE Page = MiQueryVirtualAddress(OwnerVSpace, OwnerAddr);
    if (Page == NULL || !MiPagingTypeIsPageOrLargePage(Page->Type)) {
	return STATUS_NOT_COMMITTED;
    }

    PPAGING_STRUCTURE ViewerPage = MiQueryVirtualAddress(ViewerVSpace, ViewerAddr);
    if (ViewerPage != NULL && MiPagingTypeIsPageOrLargePage(ViewerPage->Type)) {
	return STATUS_CONFLICTING_ADDRESSES;
    }

    PPAGING_STRUCTURE NewPage = NULL;
    RET_ERR(MiCreateSharedPage(Page, ViewerVSpace, ViewerAddr,
			       NewRights, NewAttributes, &NewPage));
    assert(NewPage != NULL);

    RET_ERR_EX(MiMapSuperStructure(NewPage, ViewerVSpace, NULL),
	       MiFreePagingStructure(NewPage));
    RET_ERR_EX(MiMapPagingStructure(NewPage), MiFreePagingStructure(NewPage));

    if (pNewPage != NULL) {
	*pNewPage = NewPage;
    }

    return STATUS_SUCCESS;
}

/*
 * Map an address window from the owner VSpace to the viewer VSpace,
 * possibly setting new access rights.
 */
NTSTATUS MmMapMirroredMemory(IN PVIRT_ADDR_SPACE OwnerVSpace,
			     IN MWORD OwnerStartAddr,
			     IN PVIRT_ADDR_SPACE ViewerVSpace,
			     IN MWORD ViewerStartAddr,
			     IN MWORD WindowSize,
			     IN PAGING_RIGHTS NewRights,
			     IN PAGING_ATTRIBUTES NewAttributes)
{
    assert(OwnerVSpace != NULL);
    assert(ViewerVSpace != NULL);
    assert(IS_PAGE_ALIGNED(OwnerStartAddr));
    assert(IS_PAGE_ALIGNED(ViewerStartAddr));
    assert(IS_PAGE_ALIGNED(WindowSize));
    assert(OwnerStartAddr + WindowSize > OwnerStartAddr);
    assert(ViewerStartAddr + WindowSize > ViewerStartAddr);
    MmDbg("Mapping mirrored pages from [%p, %p) of vaddrcap"
	  " 0x%zx to [%p, %p) in vaddrcap 0x%zx\n",
	  (PVOID)OwnerStartAddr, (PVOID)(OwnerStartAddr + WindowSize),
	  OwnerVSpace->VSpaceCap, (PVOID)ViewerStartAddr,
	  (PVOID)(ViewerStartAddr + WindowSize), ViewerVSpace->VSpaceCap);

    MWORD Offset = 0;
    NTSTATUS Status;
    while (Offset < WindowSize) {
	PPAGING_STRUCTURE NewPage = NULL;
	Status = MiMapSharedPage(OwnerVSpace, OwnerStartAddr + Offset,
				 ViewerVSpace, ViewerStartAddr + Offset,
				 NewRights, NewAttributes, &NewPage);
	if (!NT_SUCCESS(Status)) {
	    goto err;
	}
	assert(NewPage != NULL);
	Offset += MiPagingWindowSize(NewPage->Type);
    }

    MmDbg("Successfully mapped mirrored pages from [%p, %p)"
	  " of vaddrcap 0x%zx to [%p, %p) in vaddrcap 0x%zx\n",
	  (PVOID)OwnerStartAddr, (PVOID)(OwnerStartAddr + WindowSize),
	  OwnerVSpace->VSpaceCap, (PVOID)ViewerStartAddr,
	  (PVOID)(ViewerStartAddr + WindowSize), ViewerVSpace->VSpaceCap);
    return STATUS_SUCCESS;
err:
    if (Offset) {
	MmDbg("Failed to map mirrored pages from [%p, %p) of vaddrcap"
	      " 0x%zx to [%p, %p) in vaddrcap 0x%zx. Uncommitting [%p, %p)\n",
	      (PVOID)OwnerStartAddr, (PVOID)(OwnerStartAddr + WindowSize),
	      OwnerVSpace->VSpaceCap, (PVOID)ViewerStartAddr,
	      (PVOID)(ViewerStartAddr + WindowSize), ViewerVSpace->VSpaceCap,
	      (PVOID)ViewerStartAddr, (PVOID)(ViewerStartAddr + Offset));
	/* Decommit the successfully mapped area */
	MiUncommitWindow(ViewerVSpace, &ViewerStartAddr, &Offset);
    }
    return Status;
}

/*
 * Map one page of physical memory at specified physical address into the specified
 * virtual address. If *UseLargePage is TRUE, then we will attempt to map one large
 * page will be mapped. If unsuccessful, a 4K page will be mapped, and *UseLargePage
 * is set to FALSE on return.
 */
static NTSTATUS MiMapIoPage(IN PVIRT_ADDR_SPACE VSpace,
			    IN MWORD PhyAddr,
			    IN MWORD VirtAddr,
			    IN PAGING_RIGHTS Rights,
			    IN PAGING_ATTRIBUTES Attributes,
			    IN OUT BOOLEAN *LargePage)
{
    assert(IS_PAGE_ALIGNED(PhyAddr));
    assert(IS_PAGE_ALIGNED(VirtAddr));

    /* Make sure the target virtual address does not already have a page mapped there. */
    if (MmQueryPageEx(VSpace, VirtAddr, TRUE)) {
	return STATUS_ALREADY_COMMITTED;
    }

    if (*LargePage) {
	*LargePage = IS_LARGE_PAGE_ALIGNED(PhyAddr) && IS_LARGE_PAGE_ALIGNED(VirtAddr);
    }

    PUNTYPED Untyped;
retry:
    RET_ERR(MiGetUntypedAtPhyAddr(&MiPhyMemDescriptor, PhyAddr,
				  *LargePage ? LARGE_PAGE_LOG2SIZE : PAGE_LOG2SIZE,
				  &Untyped));
    /* We need to make sure that if the untyped has cap tree descendants, they can
     * only be page caps. In particular, untyped caps with untyped descendants cannot
     * be retyped into page caps so the mapping below will fail. */
    if (MmCapTreeNodeHasChildren(&Untyped->TreeNode)) {
	PCAP_TREE_NODE Child = MiCapTreeNodeGetFirstChild(&Untyped->TreeNode);
	if (Child->Type != CAP_TREE_NODE_PAGING_STRUCTURE) {
	    if (*LargePage && (Child->Type == CAP_TREE_NODE_UNTYPED)) {
		/* In the large page case, we will attempt to map a 4K page instead */
		*LargePage = FALSE;
		goto retry;
	    } else {
		/* In the 4K page case, the untyped caps with non-Page descendants are
		 * used by the system internally. We do not allow clients to map them. */
		return STATUS_INVALID_PARAMETER;
	    }
	}
    }

    PPAGING_STRUCTURE Page = NULL;
    PAGING_STRUCTURE_TYPE PageTy = *LargePage ? PAGING_TYPE_LARGE_PAGE : PAGING_TYPE_PAGE;
    if (!MmCapTreeNodeHasChildren(&Untyped->TreeNode)) {
	/* TODO: If Rights != MM_RIGHTS_RW, first create a page cap with full rights,
	 * and then derive the cap with less rights. This is to make sure that future
	 * calls to MiMapIoPage with higher rights do not fail.
	 *
	 * Note that this is different from the case with owned memory. For owned
	 * memory we don't do this because owners should have authority over how
	 * its memory can be mapped by viewers. In other words if owner maps the page
	 * as read-only, no viewer should be able to modify it. */
	RET_ERR(MiCreatePagingStructure(PageTy, Untyped, NULL, VirtAddr,
					VSpace->VSpaceCap, Rights, Attributes, &Page));
    } else if (MiCapTreeNodeGetFirstChild(&Untyped->TreeNode)->Type
	       == CAP_TREE_NODE_PAGING_STRUCTURE) {
	PPAGING_STRUCTURE OldPage = MiCapTreeGetFirstChildTyped(Untyped,
								PAGING_STRUCTURE);
	if (OldPage->Type != PageTy) {
	    return STATUS_INVALID_PARAMETER;
	}
	RET_ERR(MiCreateSharedPage(OldPage, VSpace, VirtAddr, Rights, Attributes, &Page));
    } else {
	/* This cannot happen since we checked above, but return error anyway. */
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }

    assert(Page != NULL);
    RET_ERR_EX(MiMapSuperStructure(Page, VSpace, NULL), MiFreePagingStructure(Page));
    RET_ERR_EX(MiMapPagingStructure(Page), MiFreePagingStructure(Page));
    Untyped->Requested = TRUE;

    return STATUS_SUCCESS;
}

/* Map the physical memory window into the given VSpace. */
NTSTATUS MiMapIoMemory(IN PVIRT_ADDR_SPACE VSpace,
		       IN MWORD PhyAddr,
		       IN MWORD VirtAddr,
		       IN MWORD WindowSize,
		       IN PAGING_RIGHTS Rights,
		       IN PAGING_ATTRIBUTES Attributes,
		       IN BOOLEAN LargePage,
		       IN BOOLEAN IgnoreConflict)
{
    assert(VSpace != NULL);
    assert(WindowSize != 0);
    NTSTATUS Status;
    MWORD MappedSize = 0;
    while (MappedSize < WindowSize) {
	if (WindowSize - MappedSize < LARGE_PAGE_SIZE) {
	    LargePage = FALSE;
	}
	Status = MiMapIoPage(VSpace, PhyAddr + MappedSize, VirtAddr + MappedSize,
			     Rights, Attributes, &LargePage);
	if (!(NT_SUCCESS(Status) || (IgnoreConflict && Status == STATUS_ALREADY_COMMITTED))) {
	    goto err;
	}
	MappedSize += (LargePage ? LARGE_PAGE_SIZE : PAGE_SIZE);
    }
    return STATUS_SUCCESS;
err:
    if (MappedSize) {
	MmDbg("Failed to map physical memory [%p, %p) to virtual memory [%p, %p) "
	      "of vaddrcap 0x%zx. Uncommitting virtual memory [%p, %p)\n",
	      (PVOID)PhyAddr, (PVOID)(PhyAddr + WindowSize),
	      (PVOID)VirtAddr, (PVOID)(VirtAddr + WindowSize),
	      VSpace->VSpaceCap, (PVOID)VirtAddr,
	      (PVOID)(VirtAddr + MappedSize));
	/* Decommit the successfully mapped area */
	MiUncommitWindow(VSpace, &VirtAddr, &MappedSize);
    }
    return Status;
}

VOID MmDbgDumpPagingStructure(IN PPAGING_STRUCTURE Paging)
{
#ifdef MMDBG
    MmDbgPrint("Dumping paging structure (PPAGING_STRUCTURE = %p)\n", Paging);
    if (Paging == NULL) {
	MmDbgPrint("    (nil)\n");
	return;
    }

    MmDbgPrint("    Virtual address %p  Type %s  VSpaceCap 0x%zx  Rights %s  Attributes 0x%x\n",
	       (PVOID)Paging->AvlNode.Key, MiPagingTypeToStr(Paging->Type), Paging->VSpaceCap,
	       MmPageIsWritable(Paging) ? "RW" : "RO", (ULONG)Paging->Attributes);
    MmDbgPrint("    ");
    MmDbgDumpCapTreeNode(&Paging->TreeNode);
    MmDbgPrint("  Cap Tree Parent ");
    MmDbgDumpCapTreeNode(Paging->TreeNode.Parent);
    MmDbgPrint("\n    Parent Paging Structure ");
    if (Paging->SuperStructure != NULL) {
	MmDbgPrint("Vaddr %p Type %s", (PVOID) Paging->SuperStructure->AvlNode.Key,
		   MiPagingTypeToStr(Paging->SuperStructure->Type));
    } else {
	MmDbgPrint("(nil)");
    }
    MmDbgPrint("\n    ");
    if (Paging->Mapped) {
	MmDbgPrint("Mapped");
    } else {
	MmDbgPrint("Not mapped");
    }
    MmDbgPrint("\n    Sub-structures linearly:  ");
    AvlDumpTreeLinear(&Paging->SubStructureTree);
    MmDbgPrint("\n    Sub-structures as a tree:\n");
    AvlDumpTree(&Paging->SubStructureTree);
#endif
}

#ifdef MMDBG
static VOID MiDbgDumpPagingStructureVisitor(IN PAVL_NODE Node)
{
    MmDbgDumpPagingStructureRecursively(AVL_NODE_TO_PAGING_STRUCTURE(Node));
}
#endif

VOID MmDbgDumpPagingStructureRecursively(IN PPAGING_STRUCTURE Paging)
{
#ifdef MMDBG
    MmDbgPrint("    Virtual address %p  Type %s",
	       (PVOID) Paging->AvlNode.Key, MiPagingTypeToStr(Paging->Type));
    if (MiPagingTypeIsPageOrLargePage(Paging->Type)) {
	MmDbgPrint("  Physical address ");
	seL4_X86_Page_GetAddress_t Reply = seL4_X86_Page_GetAddress(Paging->TreeNode.Cap);
	if (Reply.error == 0) {
	    MmDbgPrint("%p", (PVOID) Reply.paddr);
	} else {
	    MmDbgPrint("(error)");
	}
	MmDbgPrint("  == %p", (PVOID)MiGetPhysicalAddress(Paging));
    }
    MmDbgPrint("\n");
    AvlVisitTreeLinear(&Paging->SubStructureTree, MiDbgDumpPagingStructureVisitor);
#endif
}
