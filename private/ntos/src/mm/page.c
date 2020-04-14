#include "mi.h"

LONG MiPageGetLog2Size(PMM_PAGING_STRUCTURE Page)
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

MWORD MiPageGetSel4Type(PMM_PAGING_STRUCTURE Page)
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

NTSTATUS MiRetypeIntoPagingStructure(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Mapped || (Page->TreeNode.Cap != 0)) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    PMM_UNTYPED Untyped = (PMM_UNTYPED) Page->TreeNode.Parent;
    if (Untyped == NULL) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    MWORD Cap;
    RET_IF_ERR(MiCapSpaceAllocCap(Page->TreeNode.CapSpace, &Cap));
    Page->TreeNode.Cap = Cap;
    int Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				    MiPageGetSel4Type(Page),
				    MiPageGetLog2Size(Page),
				    Page->TreeNode.CapSpace->RootCap,
				    0, // node_index
				    0, // node_depth
				    Cap,
				    1 // num_caps
				    );
    if (Error) {
	MiCapSpaceDeallocCap(Page->TreeNode.CapSpace, Cap);
	Page->TreeNode.Cap = 0;
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS MiMapPagingStructure(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Mapped) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    Page->VirtualAddr &= (~0) << MiPageGetLog2Size(Page);

    if (Page->TreeNode.Cap == 0) {
	RET_IF_ERR(MiRetypeIntoPagingStructure(Page));
    }

    int Error = 0;
    if (Page->Type == MM_PAGE_TYPE_PAGE || Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	Error = seL4_X86_Page_Map(Page->TreeNode.Cap,
				  Page->VSpaceCap,
				  Page->VirtualAddr,
				  Page->Rights,
				  Page->Attributes);
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	Error = seL4_X86_PageTable_Map(Page->TreeNode.Cap,
				       Page->VSpaceCap,
				       Page->VirtualAddr,
				       Page->Attributes);
    } else {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    if (Error) {
	int RevokeError = seL4_CNode_Revoke(Page->TreeNode.CapSpace->RootCap,
					    Page->TreeNode.Cap,
					    0); /* FIXME: depth */
	if (RevokeError) {
	    return SEL4_ERROR(RevokeError);
	}
	return SEL4_ERROR(Error);
    }

    Page->Mapped = TRUE;
    return STATUS_SUCCESS;
}

MM_MEM_PRESSURE MmQueryMemoryPressure()
{
    return MM_MEM_PRESSURE_LOW;
}

NTSTATUS MiBuildAndMapPageTable(IN PMM_VADDR_SPACE Vspace,
				IN PMM_VAD Vad,
				IN MWORD PageTableNum,
				OUT OPTIONAL PMM_PAGE_TABLE *PTNode)
{
    PMM_UNTYPED Untyped;
    RET_IF_ERR(MiRequestUntyped(Vspace, MM_PAGE_TABLE_BITS, &Untyped));

    MiAllocatePool(Paging, MM_PAGING_STRUCTURE);
    Paging->TreeNode.CapSpace = &Vspace->CapSpace;
    Paging->TreeNode.Cap = 0;
    Paging->TreeNode.Parent = &Untyped->TreeNode;
    Paging->TreeNode.LeftChild = NULL;
    Paging->TreeNode.RightChild = NULL;
    Paging->TreeNode.Type = MM_CAP_TREE_NODE_PAGING_STRUCTURE;
    Paging->VSpaceCap = Vspace->VSpaceCap;
    Paging->Type = MM_PAGE_TYPE_PAGE_TABLE;
    Paging->Mapped = FALSE;
    Paging->VirtualAddr = PageTableNum << MM_LARGE_PAGE_BITS;
    Paging->Rights = MM_RIGHTS_RW;
    Paging->Attributes = seL4_X86_Default_VMAttributes;
    RET_IF_ERR(MiMapPagingStructure(Paging));

    MiAllocatePool(PageTable, MM_PAGE_TABLE);
    MiInitializePageTableNode(PageTable, Paging);
    RET_IF_ERR(MiVspaceInsertPageTable(Vspace, Vad, PageTable));

    if (PTNode != NULL) {
	*PTNode = PageTable;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiBuildAndMapPage(IN PMM_VADDR_SPACE Vspace,
			   IN PMM_PAGE_TABLE PageTable,
			   IN MWORD PageNum,
			   OUT OPTIONAL PMM_PAGE *PageNode)
{
    PMM_UNTYPED Untyped;
    RET_IF_ERR(MiRequestUntyped(Vspace, MM_PAGE_BITS, &Untyped));

    MiAllocatePool(Paging, MM_PAGING_STRUCTURE);
    Paging->TreeNode.CapSpace = &Vspace->CapSpace;
    Paging->TreeNode.Cap = 0;
    Paging->TreeNode.Parent = &Untyped->TreeNode;
    Paging->TreeNode.LeftChild = NULL;
    Paging->TreeNode.RightChild = NULL;
    Paging->TreeNode.Type = MM_CAP_TREE_NODE_PAGING_STRUCTURE;
    Paging->VSpaceCap = Vspace->VSpaceCap;
    Paging->Type = MM_PAGE_TYPE_PAGE;
    Paging->Mapped = FALSE;
    Paging->VirtualAddr = PageNum << MM_PAGE_BITS;
    Paging->Rights = MM_RIGHTS_RW;
    Paging->Attributes = seL4_X86_Default_VMAttributes;
    RET_IF_ERR(MiMapPagingStructure(Paging));

    MiAllocatePool(Page, MM_PAGE);
    MiInitializePageNode(Page, Paging);
    RET_IF_ERR(MiPageTableInsertPage(PageTable, Page));

    if (PageNode != NULL) {
	*PageNode = Page;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmCommitPages(IN PMM_VADDR_SPACE VaddrSpace,
		       IN MWORD FirstPageNum,
		       IN MWORD NumPages,
		       OUT MWORD *SatisfiedPages)
{
    PMM_VAD Vad = MiVspaceFindVadNode(VaddrSpace, FirstPageNum, NumPages);
    if (Vad == NULL) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MWORD LastPageNum = FirstPageNum + NumPages - 1;
    MWORD FirstPTNum = FirstPageNum >> MM_LARGE_PN_SHIFT;
    MWORD LastPTNum = LastPageNum >> MM_LARGE_PN_SHIFT;
    MWORD PageNum = FirstPageNum;
    *SatisfiedPages = 0;
    for (MWORD PTNum = FirstPTNum; PTNum <= LastPTNum; PTNum++) {
	PMM_AVL_NODE Node = MiVspaceFindPageTableOrLargePage(VaddrSpace, PTNum);
	if (MiPTNodeIsLargePage(Node)) {
	    continue;
	}
	PMM_PAGE_TABLE PageTable = (PMM_PAGE_TABLE) Node;
	if (PageTable == NULL) {
	    RET_IF_ERR(MiBuildAndMapPageTable(VaddrSpace, Vad, PTNum, &PageTable));
	}
	MWORD LastPageNumInPageTable = (PTNum + 1) << MM_LARGE_PN_SHIFT;
	while (PageNum <= LastPageNumInPageTable && *SatisfiedPages < NumPages) {
	    RET_IF_ERR(MiBuildAndMapPage(VaddrSpace, PageTable, PageNum, NULL));
	    PageNum++;
	    *SatisfiedPages += 1;
	}
    }

    if (*SatisfiedPages == 0) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }
    return STATUS_SUCCESS;
}
