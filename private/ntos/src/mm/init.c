#include "mi.h"
#include <ctype.h>

/* FIXME: Only works for x86! */
NTSTATUS MmRegisterClass(IN PMM_INIT_INFO_CLASS InitInfo)
{
    /* Build initial cap space descriptor on the stack
     * Once ExPool is initialized we will move these to the ExPool
     */
    MM_CAPSPACE InitCapSpace;
    MM_CNODE InitCNode =
	{
	 .TreeNode = {
		      .CapSpace = &InitCapSpace,
		      .Type = MM_CAP_TREE_NODE_CNODE
		      },
	 .Log2Size = InitInfo->RootCNodeLog2Size,
	 .FirstChild = NULL,
	 .Policy = MM_CNODE_TAIL_DEALLOC_ONLY
	};
    InitCapSpace.RootCap = InitInfo->RootCNodeCap;
    InitCapSpace.RootCNode = &InitCNode;
    InitializeListHead(&InitCNode.SiblingList);
    InitCNode.FreeRange.StartCap = InitInfo->RootCNodeFreeCapStart;
    InitCNode.FreeRange.Number = InitInfo->RootCNodeFreeCapNumber;

    /* Find some space for ExPool */
    MM_UNTYPED UntypedDescs[32] =
	{
	 {
	 .TreeNode = {
		      .CapSpace = &InitCapSpace,
		      .Type = MM_CAP_TREE_NODE_UNTYPED
		      },	
	  .Cap = InitInfo->InitUntypedCap,
	  .Log2Size = InitInfo->InitUntypedLog2Size,
	 }
	};
    LONG NumberSplits = 0;
    if (InitInfo->InitUntypedLog2Size >= seL4_LargePageBits) {
	/* Split the untyped until we have exactly one large page */
	NumberSplits = UntypedDescs[0].Log2Size - seL4_LargePageBits;
    } else if (InitInfo->InitUntypedLog2Size >= (seL4_PageBits + 1)) {
	/* Split the untyped until we have exactly one page plus one page directory */
	NumberSplits = UntypedDescs[0].Log2Size - seL4_PageBits;
    } else {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    for (int i = 0; i < NumberSplits; i++) {
	RET_IF_ERR(MiSplitUntyped(&UntypedDescs[2*i], &UntypedDescs[2*i+2], &UntypedDescs[2*i+3]));
    }

    /* Map initial ExPool page and initialize ExPool */
    MM_PAGING_STRUCTURE InitialPage =
	{
	 .TreeNode = {
		      .CapSpace = &InitCapSpace,
		      .Parent = &UntypedDescs[2*NumberSplits].TreeNode,
		      .Type = MM_CAP_TREE_NODE_PAGING_STRUCTURE
		      },
	 .Cap = 0,
	 .VSpaceCap = InitInfo->InitVSpaceCap,
	 .Mapped = FALSE,
	 .VirtualAddr = EX_POOL_START,
	 .Rights = MM_RIGHTS_RW,
	 .Attributes = seL4_X86_Default_VMAttributes
	};
    MM_PAGING_STRUCTURE PageTable =
	{
	 .TreeNode = {
		      .CapSpace = &InitCapSpace,
		      .Parent = &UntypedDescs[2*NumberSplits+1].TreeNode,
		      .Type = MM_CAP_TREE_NODE_PAGING_STRUCTURE
		      },
	 .Cap = 0,
	 .VSpaceCap = InitInfo->InitVSpaceCap,
	 .Type = MM_PAGE_TYPE_PAGE_TABLE,
	 .Mapped = FALSE,
	 .VirtualAddr = EX_POOL_START,
	 .Rights = 0,
	 .Attributes = seL4_X86_Default_VMAttributes
	};
    if (InitInfo->InitUntypedLog2Size < seL4_LargePageBits) {
	RET_IF_ERR(MiMapPagingStructure(&PageTable));
	InitialPage.Type = MM_PAGE_TYPE_PAGE;
    } else {
	InitialPage.Type = MM_PAGE_TYPE_LARGE_PAGE;
    }
    RET_IF_ERR(MiMapPagingStructure(&InitialPage));
    RET_IF_ERR(ExInitializePool(&InitialPage));

    /* Allocate memory for the virtual address space descriptor
     * ExPool is usable now so we can allocate pool memory
     */
    MiAllocatePool(VaddrSpace, MM_VADDR_SPACE);
    PEPROCESS EProcess = InitInfo->EProcess;
    EProcess->VaddrSpace = VaddrSpace;

    /* Allocate CNode on ExPool and Copy InitCNode over */
    VaddrSpace->CapSpace.RootCap = InitInfo->RootCNodeCap;
    MiAllocatePool(RootCNode, MM_CNODE);
    VaddrSpace->CapSpace.RootCNode = RootCNode;
    RootCNode->TreeNode.CapSpace = &VaddrSpace->CapSpace;
    RootCNode->TreeNode.Parent = NULL;
    RootCNode->TreeNode.LeftChild = NULL;
    RootCNode->TreeNode.RightChild = NULL;
    RootCNode->TreeNode.Type = MM_CAP_TREE_NODE_UNTYPED;
    RootCNode->Log2Size = InitInfo->RootCNodeLog2Size;
    RootCNode->FirstChild = NULL;
    InitializeListHead(&RootCNode->SiblingList);
    RootCNode->Policy = MM_CNODE_TAIL_DEALLOC_ONLY;
    RootCNode->FreeRange = InitCNode.FreeRange;

    /* Build the tree of untyped's derived above during mapping of initial heap */
    InitializeListHead(&VaddrSpace->SmallUntypedList);
    InitializeListHead(&VaddrSpace->MediumUntypedList);
    InitializeListHead(&VaddrSpace->LargeUntypedList);
    InitializeListHead(&VaddrSpace->RootUntypedList);
    MiAllocatePool(RootUntyped, MM_UNTYPED);
    *RootUntyped = UntypedDescs[0];
    RootUntyped->TreeNode.CapSpace = &VaddrSpace->CapSpace;
    RootUntyped->TreeNode.Parent = NULL;
    InsertHeadList(&VaddrSpace->RootUntypedList, &RootUntyped->RootListEntry);
    for (int i = 1; i <= NumberSplits; i++) {
	MiAllocatePool(LeftChildUntyped, MM_UNTYPED);
	MiAllocatePool(RightChildUntyped, MM_UNTYPED);
	*LeftChildUntyped = UntypedDescs[2*i];
	*RightChildUntyped = UntypedDescs[2*i+1];
	LeftChildUntyped->TreeNode.CapSpace = &VaddrSpace->CapSpace;
	RightChildUntyped->TreeNode.CapSpace = &VaddrSpace->CapSpace;
	LeftChildUntyped->TreeNode.Parent = &RootUntyped->TreeNode;
	RightChildUntyped->TreeNode.Parent = &RootUntyped->TreeNode;
	RootUntyped->TreeNode.LeftChild = &LeftChildUntyped->TreeNode;
	RootUntyped->TreeNode.RightChild = &RightChildUntyped->TreeNode;
	MiInsertFreeUntyped(VaddrSpace, RightChildUntyped);
	RootUntyped = LeftChildUntyped;
    }

    /* Build MM_PAGING_STRUCTURE of initial heap pages */
    MiAllocatePool(InitialPageHeap, MM_PAGING_STRUCTURE);
    *InitialPageHeap = InitialPage;
    InitialPageHeap->TreeNode.CapSpace = &VaddrSpace->CapSpace;
    InitialPageHeap->TreeNode.Parent = &RootUntyped->TreeNode;
    InitialPageHeap->TreeNode.LeftChild = NULL;
    InitialPageHeap->TreeNode.RightChild = NULL;

    /* Build the Vad tree of the given EProcess */
    MiAvlInitializeTree(&VaddrSpace->VadTree);
    MiAllocatePool(ExPoolVad, MM_VAD);
    MiInitializeVadNode(ExPoolVad, EX_POOL_START >> EX_PAGE_BITS, EX_POOL_RESERVED_SIZE >> EX_PAGE_BITS);
    MiAvlInitializeTree(&VaddrSpace->PageTableTree);
    if (InitialPageHeap->Type == MM_PAGE_TYPE_PAGE) {
	MiAllocatePool(InitialPageTableHeap, MM_PAGING_STRUCTURE);
	*InitialPageTableHeap = PageTable;
	InitialPageTableHeap->TreeNode.CapSpace = &VaddrSpace->CapSpace;
	InitialPageTableHeap->TreeNode.Parent = RootUntyped->TreeNode.Parent->RightChild;
	InitialPageTableHeap->TreeNode.LeftChild = NULL;
	InitialPageTableHeap->TreeNode.RightChild = NULL;
	MiAllocatePool(PageNode, MM_PAGE);
	MiAllocatePool(PageTableNode, MM_PAGE_TABLE);
	MiInitializePageNode(PageNode, InitialPageHeap);
	MiInitializePageTableNode(PageTableNode, InitialPageTableHeap);
	MmVspaceInsertMappedPageTable(VaddrSpace, PageTableNode);
	ExPoolVad->FirstLargePage = &PageTableNode->AvlNode;
	ExPoolVad->LastLargePage = &PageTableNode->AvlNode;
    } else {
	MiAllocatePool(LargePageNode, MM_LARGE_PAGE);
	MiInitializeLargePageNode(LargePageNode, InitialPageHeap);
	MmVspaceInsertMappedLargePage(VaddrSpace, LargePageNode);
	ExPoolVad->FirstLargePage = &LargePageNode->AvlNode;
	ExPoolVad->LastLargePage = &LargePageNode->AvlNode;
    }

    return STATUS_SUCCESS;
}
