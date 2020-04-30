#include "mi.h"

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
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    PMM_UNTYPED Untyped = (PMM_UNTYPED) Page->TreeNode.Parent;
    if (Untyped == NULL) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    MWORD Cap;
    RET_IF_ERR(MmAllocateCap(&Cap));
    Page->TreeNode.Cap = Cap;
    int Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				    MiPageGetSel4Type(Page),
				    MiPageGetLog2Size(Page),
				    MmRootCspaceCap(),
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
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    Page->VirtPageNum &= (~0) << (MiPageGetLog2Size(Page) - MM_PAGE_BITS);

    if (Page->TreeNode.Cap == 0) {
	RET_IF_ERR(MiRetypeIntoPagingStructure(Page));
    }

    int Error = 0;
    if (Page->Type == MM_PAGE_TYPE_PAGE || Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	Error = seL4_X86_Page_Map(Page->TreeNode.Cap,
				  Page->VSpaceCap,
				  Page->VirtPageNum << MM_PAGE_BITS,
				  Page->Rights,
				  Page->Attributes);
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	Error = seL4_X86_PageTable_Map(Page->TreeNode.Cap,
				       Page->VSpaceCap,
				       Page->VirtPageNum << MM_PAGE_BITS,
				       Page->Attributes);
    } else {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    if (Error) {
	int RevokeError = seL4_CNode_Revoke(MmRootCspaceCap(),
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

static NTSTATUS MiBuildAndMapPageTable(IN PMM_VADDR_SPACE Vspace,
				       IN PMM_VAD Vad,
				       IN MWORD PageTableNum,
				       OUT OPTIONAL PMM_PAGE_TABLE *PTNode)
{
    PMM_UNTYPED Untyped;
    RET_IF_ERR(MmRequestUntyped(MM_PAGE_TABLE_BITS, &Untyped));

    MiAllocatePool(PageTable, MM_PAGE_TABLE);
    MiInitializePageTable(PageTable, Untyped, Vspace, 0, PageTableNum, FALSE);
    RET_IF_ERR(MiMapPagingStructure(&PageTable->PagingStructure));
    RET_IF_ERR(MiVspaceInsertPageTable(Vspace, Vad, PageTable));

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
    RET_IF_ERR(MiMapPagingStructure(&Page->PagingStructure));
    RET_IF_ERR(MiPageTableInsertPage(PageTable, Page));

    if (PageNode != NULL) {
	*PageNode = Page;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmCommitPagesEx(IN PMM_VADDR_SPACE VaddrSpace,
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
	    if (MiPageTableFindPage(PageTable, PageNum) == NULL) {
		PMM_UNTYPED Untyped;
		RET_IF_ERR(MmRequestUntyped(MM_PAGE_BITS, &Untyped));
		RET_IF_ERR(MiBuildAndMapPage(VaddrSpace, Untyped, PageTable, PageNum, NULL));
	    }
	    PageNum++;
	    *SatisfiedPages += 1;
	}
    }

    if (*SatisfiedPages == 0) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmCommitPages(IN MWORD FirstPageNum,
		       IN MWORD NumPages,
		       OUT MWORD *SatisfiedPages)
{
    return MmCommitPagesEx(&MiNtosVaddrSpace, FirstPageNum, NumPages, SatisfiedPages);
}

NTSTATUS MmCommitIoPageEx(IN PMM_VADDR_SPACE VaddrSpace,
			  IN PMM_PHY_MEM PhyMem,
			  IN MWORD PhyPageNum,
			  IN MWORD VirtPageNum)
{
    PMM_VAD Vad = MiVspaceFindVadNode(VaddrSpace, VirtPageNum, 1);
    if (Vad == NULL) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    PMM_IO_UNTYPED RootIoUntyped = MiFindRootIoUntyped(PhyMem, PhyPageNum);
    if (RootIoUntyped == NULL) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    PMM_IO_UNTYPED IoUntyped;
    RET_IF_ERR(MiRequestIoUntyped(RootIoUntyped, PhyPageNum, &IoUntyped));
    MWORD PTNum = VirtPageNum >> MM_LARGE_PN_SHIFT;
    PMM_AVL_NODE Node = MiVspaceFindPageTableOrLargePage(VaddrSpace, PTNum);
    if (MiPTNodeIsLargePage(Node)) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    PMM_PAGE_TABLE PageTable = (PMM_PAGE_TABLE) Node;
    if (PageTable == NULL) {
	    RET_IF_ERR(MiBuildAndMapPageTable(VaddrSpace, Vad, PTNum, &PageTable));
    }

    if (MiPageTableFindPage(PageTable, VirtPageNum) != NULL) {
	/* Unmap page? */
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    RET_IF_ERR(MiBuildAndMapPage(VaddrSpace, &IoUntyped->Untyped, PageTable, VirtPageNum, NULL));

    return STATUS_SUCCESS;
}

NTSTATUS MmCommitIoPage(IN MWORD PhyPageNum,
			IN MWORD VirtPageNum)
{
    return MmCommitIoPageEx(&MiNtosVaddrSpace, &MiPhyMemDescriptor,
			    PhyPageNum, VirtPageNum);
}
