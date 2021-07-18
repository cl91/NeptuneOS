#include "mi.h"

static VOID MiInitializePagingStructure(IN PMM_PAGING_STRUCTURE Page,
					IN PMM_UNTYPED Parent,
					IN PMM_VADDR_SPACE VaddrSpace,
					IN MWORD Cap,
					IN MWORD VirtPageNum,
					IN MM_PAGING_STRUCTURE_TYPE Type,
					IN BOOLEAN Mapped,
					IN seL4_CapRights_t Rights)
{
    MiInitializeCapTreeNode(&Page->TreeNode, MM_CAP_TREE_NODE_PAGING_STRUCTURE,
			    Cap, &Parent->TreeNode);
    Page->VSpaceCap = VaddrSpace->VSpaceCap;
    Page->Type = Type;
    Page->Mapped = Mapped;
    Page->VirtPageNum = VirtPageNum;
    Page->Rights = Rights;
    /* TODO: Implement page attributes */
    Page->Attributes = seL4_X86_Default_VMAttributes;
}

VOID MiInitializePage(IN PMM_PAGE Page,
		      IN PMM_UNTYPED Parent,
		      IN PMM_VADDR_SPACE VaddrSpace,
		      IN MWORD Cap,
		      IN MWORD VirtPageNum,
		      IN BOOLEAN Mapped,
		      IN seL4_CapRights_t Rights)
{
    MiInitializePagingStructure(&Page->PagingStructure, Parent,
				VaddrSpace, Cap, VirtPageNum,
				MM_PAGE_TYPE_PAGE, Mapped, Rights);
    MiAvlInitializeNode(&Page->AvlNode, VirtPageNum);
}

VOID MiInitializeLargePage(IN PMM_LARGE_PAGE LargePage,
			   IN PMM_UNTYPED Parent,
			   IN PMM_VADDR_SPACE VaddrSpace,
			   IN MWORD Cap,
			   IN MWORD VirtPTNum,
			   IN BOOLEAN Mapped,
			   IN seL4_CapRights_t Rights)
{
    MiInitializePagingStructure(&LargePage->PagingStructure, Parent,
				VaddrSpace, Cap, VirtPTNum << LARGE_PN_SHIFT,
				MM_PAGE_TYPE_LARGE_PAGE, Mapped, Rights);
    MiAvlInitializeNode(&LargePage->AvlNode, VirtPTNum);
}

VOID MiInitializePageTable(IN PMM_PAGE_TABLE PageTable,
			   IN PMM_UNTYPED Parent,
			   IN PMM_VADDR_SPACE VaddrSpace,
			   IN MWORD Cap,
			   IN MWORD VirtPTNum,
			   IN BOOLEAN Mapped)
{
    MiInitializePagingStructure(&PageTable->PagingStructure, Parent,
				VaddrSpace, Cap, VirtPTNum << LARGE_PN_SHIFT,
				MM_PAGE_TYPE_PAGE_TABLE, Mapped, MM_RIGHTS_RW);
    MiAvlInitializeNode(&PageTable->AvlNode, VirtPTNum);
    MiAvlInitializeTree(&PageTable->MappedPages);
}

static LONG MiPageGetLog2Size(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Type == MM_PAGE_TYPE_PAGE) {
	return seL4_PageBits;
    } else if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	return seL4_LargePageBits;
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	return seL4_LargePageBits;
    } else {
	return 0;
    }
}

static MWORD MiPageGetSel4Type(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Type == MM_PAGE_TYPE_PAGE) {
	return seL4_X86_4K;
    } else if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	return seL4_X86_LargePageObject;
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	return seL4_X86_PageTableObject;
    } else {
	return 0;
    }
}

static NTSTATUS MiRetypeIntoPagingStructure(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Mapped || (Page->TreeNode.Cap != 0)) {
	return STATUS_INVALID_PARAMETER;
    }

    PMM_UNTYPED Untyped = (PMM_UNTYPED) Page->TreeNode.Parent;
    if (Untyped == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    MWORD Cap;
    RET_ERR(MmAllocateCap(&Cap));
    Page->TreeNode.Cap = Cap;
    int Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				    MiPageGetSel4Type(Page),
				    MiPageGetLog2Size(Page),
				    ROOT_CNODE_CAP,
				    0, // node_index
				    0, // node_depth
				    Cap,
				    1 // num_caps
				    );
    if (Error) {
	MmDeallocateCap(Cap);
	Page->TreeNode.Cap = 0;
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS MiMapPagingStructure(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Mapped) {
	return STATUS_INVALID_PARAMETER;
    }

    Page->VirtPageNum &= (~0) << (MiPageGetLog2Size(Page) - PAGE_LOG2SIZE);

    if (Page->TreeNode.Cap == 0) {
	RET_ERR(MiRetypeIntoPagingStructure(Page));
    }

    int Error = 0;
    if (Page->Type == MM_PAGE_TYPE_PAGE || Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
#if CONFIG_DEBUG_BUILD
	seL4_X86_Page_GetAddress_t Reply = seL4_X86_Page_GetAddress(Page->TreeNode.Cap);
	DbgPrint("MiMapPagingStructure: Mapping %spage cap 0x%x (paddr %p%s) for vspacecap 0x%x at vaddr %p\n",
		 (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) ? "large " : "",
		 Page->TreeNode.Cap, Reply.paddr, (Reply.error == 0) ? "" : " ???",
		 Page->VSpaceCap, Page->VirtPageNum << PAGE_LOG2SIZE);
#endif
	Error = seL4_X86_Page_Map(Page->TreeNode.Cap,
				  Page->VSpaceCap,
				  Page->VirtPageNum << PAGE_LOG2SIZE,
				  Page->Rights,
				  Page->Attributes);
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	DbgPrint("MiMapPagingStructure: Mapping page table cap 0x%x for vspacecap 0x%x at vaddr %p\n",
		 Page->TreeNode.Cap, Page->VSpaceCap, Page->VirtPageNum << PAGE_LOG2SIZE);
	Error = seL4_X86_PageTable_Map(Page->TreeNode.Cap,
				       Page->VSpaceCap,
				       Page->VirtPageNum << PAGE_LOG2SIZE,
				       Page->Attributes);
    } else {
	return STATUS_INVALID_PARAMETER;
    }

    if (Error) {
	DbgPrint("MiMapPagingStructure: Mapping failed for page/table cap 0x%x for vspacecap 0x%x at vaddr %p\n",
		 Page->TreeNode.Cap, Page->VSpaceCap, Page->VirtPageNum << PAGE_LOG2SIZE);
	seL4_CNode_Delete(ROOT_CNODE_CAP, Page->TreeNode.Cap,
			  0); /* TODO: fix the depth argument here */
	MmDeallocateCap(Page->TreeNode.Cap);
	Page->TreeNode.Cap = 0;
	return SEL4_ERROR(Error);
    }

    Page->Mapped = TRUE;
    return STATUS_SUCCESS;
}

MM_MEM_PRESSURE MmQueryMemoryPressure()
{
    return MM_MEM_PRESSURE_SUFFICIENT_MEMORY;
}

static NTSTATUS MiBuildAndMapPageTable(IN PMM_VADDR_SPACE Vspace,
				       IN PMM_VAD Vad,
				       IN MWORD PageTableNum,
				       OUT OPTIONAL PMM_PAGE_TABLE *PTNode)
{
    PMM_UNTYPED Untyped;
    RET_ERR(MmRequestUntyped(PAGE_TABLE_LOG2SIZE, &Untyped));

    MiAllocatePoolEx(PageTable, MM_PAGE_TABLE, MmReleaseUntyped(Untyped));
    MiInitializePageTable(PageTable, Untyped, Vspace, 0, PageTableNum, FALSE);
    RET_ERR_EX(MiMapPagingStructure(&PageTable->PagingStructure),
	       {
		   MmReleaseUntyped(Untyped);
		   ExFreePool(PageTable);
	       });

    RET_ERR_EX(MiVspaceInsertPageTable(Vspace, Vad, PageTable),
	       {
		   MmReleaseUntyped(Untyped);
		   ExFreePool(PageTable);
		   /* TODO: Unmap Paging Structure */
	       });

    if (PTNode != NULL) {
	*PTNode = PageTable;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MiBuildAndMapPage(IN PMM_VADDR_SPACE Vspace,
				  IN PMM_UNTYPED Untyped,
				  IN PMM_PAGE_TABLE PageTable,
				  IN MWORD PageNum,
				  OUT OPTIONAL PMM_PAGE *PageNode)
{
    MiAllocatePool(Page, MM_PAGE);
    MiInitializePage(Page, Untyped, Vspace, 0, PageNum, FALSE, MM_RIGHTS_RW);

    RET_ERR_EX(MiMapPagingStructure(&Page->PagingStructure),
	       ExFreePool(Page));

    RET_ERR_EX(MiPageTableInsertPage(PageTable, Page),
	       {
		   ExFreePool(Page);
		   /* TODO: Unmap paging structure */
	       });

    if (PageNode != NULL) {
	*PageNode = Page;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmCommitPagesEx(IN PMM_VADDR_SPACE VaddrSpace,
			 IN MWORD FirstPageNum,
			 IN MWORD NumPages,
			 OUT MWORD *SatisfiedPages,
			 OUT OPTIONAL PMM_PAGE *Pages)
{
    DbgPrint("MmCommitPagesEx: Committing %d page(s) for vaddrcap 0x%x at vaddr %p\n",
	     NumPages, VaddrSpace->VSpaceCap, FirstPageNum << PAGE_LOG2SIZE);
    PMM_VAD Vad = MiVspaceFindVadNode(VaddrSpace, FirstPageNum, NumPages);
    if (Vad == NULL) {
	return STATUS_INVALID_PARAMETER;
    }
    MWORD LastPageNum = FirstPageNum + NumPages - 1;
    MWORD FirstPTNum = FirstPageNum >> LARGE_PN_SHIFT;
    MWORD LastPTNum = LastPageNum >> LARGE_PN_SHIFT;
    MWORD PageNum = FirstPageNum;
    *SatisfiedPages = 0;
    for (MWORD PTNum = FirstPTNum; PTNum <= LastPTNum; PTNum++) {
	PMM_AVL_NODE Node = MiVspaceFindPageTableOrLargePage(VaddrSpace, PTNum);
	if (MiPTNodeIsLargePage(Node)) {
	    continue;
	}
	PMM_PAGE_TABLE PageTable = (PMM_PAGE_TABLE) Node;
	if (PageTable == NULL) {
	    RET_ERR(MiBuildAndMapPageTable(VaddrSpace, Vad, PTNum, &PageTable));
	}
	MWORD LastPageNumInPageTable = (PTNum + 1) << LARGE_PN_SHIFT;
	while (PageNum <= LastPageNumInPageTable && *SatisfiedPages < NumPages) {
	    PMM_PAGE Page = MiPageTableFindPage(PageTable, PageNum);
	    if (Page == NULL) {
		PMM_UNTYPED Untyped;
		RET_ERR_EX(MmRequestUntyped(PAGE_LOG2SIZE, &Untyped),
			   {
			       /* TODO: Error path */
			   });
		PMM_PAGE *PageOut = Pages ? &Pages[*SatisfiedPages] : NULL;
		RET_ERR_EX(MiBuildAndMapPage(VaddrSpace, Untyped, PageTable, PageNum, PageOut),
			   {
			       /* TODO: Error path */
			   });
	    } else if (Pages != NULL) {
		Pages[*SatisfiedPages] = Page;
	    }
	    PageNum++;
	    *SatisfiedPages += 1;
	}
    }
    DbgPrint("MmCommitPagesEx: Successfully committed %d page(s) for vaddrcap 0x%x at vaddr %p\n",
	     *SatisfiedPages, VaddrSpace->VSpaceCap, FirstPageNum << PAGE_LOG2SIZE);

    if (*SatisfiedPages == 0) {
	return STATUS_NO_MEMORY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmCommitPages(IN MWORD FirstPageNum,
		       IN MWORD NumPages,
		       OUT MWORD *SatisfiedPages,
		       OUT OPTIONAL PMM_PAGE *Pages)
{
    return MmCommitPagesEx(&MiNtosVaddrSpace, FirstPageNum, NumPages, SatisfiedPages, Pages);
}

NTSTATUS MmCommitIoPageEx(IN PMM_VADDR_SPACE VaddrSpace,
			  IN PMM_PHY_MEM PhyMem,
			  IN MWORD PhyPageNum,
			  IN MWORD VirtPageNum)
{
    PMM_VAD Vad = MiVspaceFindVadNode(VaddrSpace, VirtPageNum, 1);
    if (Vad == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    PMM_UNTYPED IoUntyped;
    RET_ERR(MiRequestIoUntyped(PhyMem, PhyPageNum, &IoUntyped));
    if (IoUntyped->Log2Size < PAGE_LOG2SIZE) {
	return STATUS_INVALID_PARAMETER;
    }

    MWORD PTNum = VirtPageNum >> LARGE_PN_SHIFT;
    PMM_AVL_NODE Node = MiVspaceFindPageTableOrLargePage(VaddrSpace, PTNum);
    if (MiPTNodeIsLargePage(Node)) {
	return STATUS_INVALID_PARAMETER;
    }
    PMM_PAGE_TABLE PageTable = (PMM_PAGE_TABLE) Node;
    if (PageTable == NULL) {
	RET_ERR(MiBuildAndMapPageTable(VaddrSpace, Vad, PTNum, &PageTable));
    }

    if (MiPageTableFindPage(PageTable, VirtPageNum) != NULL) {
	/* Unmap page? */
	return STATUS_INVALID_PARAMETER;
    }

    RET_ERR(MiBuildAndMapPage(VaddrSpace, IoUntyped, PageTable, VirtPageNum, NULL));

    return STATUS_SUCCESS;
}

NTSTATUS MmCommitIoPage(IN MWORD PhyPageNum,
			IN MWORD VirtPageNum)
{
    return MmCommitIoPageEx(&MiNtosVaddrSpace, &MiPhyMemDescriptor,
			    PhyPageNum, VirtPageNum);
}
