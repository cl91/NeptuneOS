#include "../mi.h"

NTSTATUS MiPrepareInitialUntyped(IN PMM_INIT_INFO InitInfo)
{
    MWORD RootCap = InitInfo->RootCNodeCap;
    MWORD DestCap = InitInfo->RootCNodeFreeCapStart;
    MWORD UntypedCap = InitInfo->InitUntypedCap;
    LONG Log2Size = InitInfo->InitUntypedLog2Size;
    LONG NumSplits = Log2Size - MM_PAGE_BITS;
    for (int i = 0; i < NumSplits; i++) {
	RET_IF_ERR(MiSplitInitialUntyped(RootCap, UntypedCap, Log2Size, DestCap));
	UntypedCap = DestCap;
	DestCap += 2;
	Log2Size--;
    }
    MWORD SrcCap = InitInfo->RootCNodeFreeCapStart + 2*NumSplits - 3;
    return MiSplitInitialUntyped(RootCap, SrcCap, Log2Size+1, DestCap);
}

NTSTATUS MiInitMapInitialHeap(IN PMM_INIT_INFO InitInfo,
			      OUT LONG *PoolPages,
			      OUT MWORD *FreeCapStart)
{
    /* We require at least three pages to initialize ExPool */
    if (InitInfo->InitUntypedLog2Size < seL4_PageBits + 2) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }

    /* Map initial pages for ExPool */
    RET_IF_ERR(MiPrepareInitialUntyped(InitInfo));
    LONG NumSplits = InitInfo->InitUntypedLog2Size - MM_PAGE_BITS;
    MWORD Page0Untyped = InitInfo->RootCNodeFreeCapStart + 2*NumSplits - 2;
    MWORD Page1Untyped = Page0Untyped + 1;
    MWORD Page2Untyped = Page0Untyped + 2;
    MWORD PageTableUntyped = Page0Untyped + 3;
    MWORD Page0Cap = Page0Untyped + 4;
    MWORD Page1Cap = Page0Untyped + 5;
    MWORD Page2Cap = Page0Untyped + 6;
    MWORD PageTableCap = Page0Untyped + 7;
    RET_IF_ERR(MiInitMapPage(InitInfo, PageTableUntyped, PageTableCap,
			     EX_POOL_START, seL4_X86_PageTableObject));
    RET_IF_ERR(MiInitMapPage(InitInfo, Page0Untyped, Page0Cap,
			     EX_POOL_START, seL4_X86_4K));
    RET_IF_ERR(MiInitMapPage(InitInfo, Page1Untyped, Page1Cap,
			     EX_POOL_START + MM_PAGE_SIZE, seL4_X86_4K));
    RET_IF_ERR(MiInitMapPage(InitInfo, Page2Untyped, Page2Cap,
			     EX_POOL_START + 2*MM_PAGE_SIZE, seL4_X86_4K));

    *PoolPages = 3;
    *FreeCapStart = PageTableCap + 1;
    return STATUS_SUCCESS;
}

NTSTATUS MiInitHeapVad(IN PMM_INIT_INFO InitInfo,
		       IN PMM_VADDR_SPACE VaddrSpace,
		       IN PMM_VAD ExPoolVad)
{
    MiAllocatePool(RootUntyped, MM_UNTYPED);
    MiInitializeUntyped(RootUntyped, NULL, VaddrSpace,
			InitInfo->InitUntypedCap,
			InitInfo->InitUntypedLog2Size);

    PMM_UNTYPED ParentUntyped = RootUntyped;
    LONG NumSplits = InitInfo->InitUntypedLog2Size - MM_PAGE_BITS;
    PMM_PAGE_TABLE PageTableNode = NULL;
    for (int i = 0; i < NumSplits; i++) {
	MiAllocatePool(LeftChildUntyped, MM_UNTYPED);
	MiAllocatePool(RightChildUntyped, MM_UNTYPED);

	LONG ChildLog2Size = InitInfo->InitUntypedLog2Size - 1 - i;
	MWORD LeftChildCap = InitInfo->RootCNodeFreeCapStart + 2*i;
	MWORD RigthChildCap = LeftChildCap + 1;
	MiInitializeUntyped(LeftChildUntyped, ParentUntyped, VaddrSpace,
			    LeftChildCap, ChildLog2Size);
	MiInitializeUntyped(RightChildUntyped, ParentUntyped, VaddrSpace,
			    RigthChildCap, ChildLog2Size);

	ParentUntyped->TreeNode.LeftChild = &LeftChildUntyped->TreeNode;
	ParentUntyped->TreeNode.RightChild = &RightChildUntyped->TreeNode;

	if (i < NumSplits-2) {
	    MiInsertFreeUntyped(VaddrSpace, RightChildUntyped);
	} else if (i == NumSplits-2) {
	    MiAllocatePool(Page2Untyped, MM_UNTYPED);
	    MiAllocatePool(PageTableUntyped, MM_UNTYPED);
	    assert(InitInfo->InitUntypedLog2Size - NumSplits == MM_PAGE_BITS);
	    MWORD Page2UntypedCap = InitInfo->RootCNodeFreeCapStart + 2*NumSplits;
	    MWORD PageTableUntypedCap = Page2UntypedCap + 1;
	    MiInitializeUntyped(Page2Untyped, RightChildUntyped, VaddrSpace,
				Page2UntypedCap, MM_PAGE_BITS);
	    MiInitializeUntyped(PageTableUntyped, RightChildUntyped, VaddrSpace,
				PageTableUntypedCap, MM_PAGE_BITS);
	    MiAllocatePool(Page2, MM_PAGING_STRUCTURE);
	    MiAllocatePool(PageTable, MM_PAGING_STRUCTURE);
	    MiInitHeapPagingStructure(Page2, Page2Untyped, VaddrSpace,
				      InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 4,
				      EX_POOL_START + 2*MM_PAGE_SIZE,
				      MM_PAGE_TYPE_PAGE,
				      InitInfo);
	    MiInitHeapPagingStructure(PageTable, PageTableUntyped, VaddrSpace,
				      InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 5,
				      EX_POOL_START,
				      MM_PAGE_TYPE_PAGE_TABLE,
				      InitInfo);
	    MiAllocatePool(Page2Node, MM_PAGE);
	    MiAllocatePool(pPageTableNode, MM_PAGE_TABLE);
	    PageTableNode = pPageTableNode;
	    MiInitializePageNode(Page2Node, Page2);
	    MiInitializePageTableNode(PageTableNode, PageTable);
	    RET_IF_ERR(MiVspaceInsertPageTable(VaddrSpace, ExPoolVad, PageTableNode));
	    ExPoolVad->FirstPageTable = &PageTableNode->AvlNode;
	    ExPoolVad->LastPageTable = &PageTableNode->AvlNode;
	    RET_IF_ERR(MiPageTableInsertPage(PageTableNode, Page2Node));
	} else {		/* i == NumSplits-1 */
	    MiAllocatePool(Page0, MM_PAGING_STRUCTURE);
	    MiAllocatePool(Page1, MM_PAGING_STRUCTURE);
	    MiInitHeapPagingStructure(Page0, LeftChildUntyped, VaddrSpace,
				      InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 2,
				      EX_POOL_START,
				      MM_PAGE_TYPE_PAGE,
				      InitInfo);
	    MiInitHeapPagingStructure(Page1, RightChildUntyped, VaddrSpace,
				      InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 3,
				      EX_POOL_START + MM_PAGE_SIZE,
				      MM_PAGE_TYPE_PAGE,
				      InitInfo);
	    MiAllocatePool(Page0Node, MM_PAGE);
	    MiAllocatePool(Page1Node, MM_PAGE);
	    MiInitializePageNode(Page0Node, Page0);
	    MiInitializePageNode(Page1Node, Page1);
	    RET_IF_ERR(MiPageTableInsertPage(PageTableNode, Page0Node));
	    RET_IF_ERR(MiPageTableInsertPage(PageTableNode, Page1Node));
	}
	ParentUntyped = LeftChildUntyped;
    }

    return STATUS_SUCCESS;
}
