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
	  .Split = FALSE
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
    if (InitInfo->InitUntypedLog2Size < seL4_LargePageBits) {
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
	RET_IF_ERR(MiMapPagingStructure(&PageTable));
	InitialPage.Type = MM_PAGE_TYPE_PAGE;
    } else {
	InitialPage.Type = MM_PAGE_TYPE_LARGE_PAGE;
    }
    RET_IF_ERR(MiMapPagingStructure(&InitialPage));
    RET_IF_ERR(ExInitializePool(&InitialPage));

    /* Build the virtual address space descriptor
     * ExPool is usable now so we can allocate pool memory
     */
    PMM_VADDR_SPACE VaddrSpace = (PMM_VADDR_SPACE) ExAllocatePoolWithTag(sizeof(MM_VADDR_SPACE), EX_POOL_TAG('v', 'a', 's', 'p'));
    if (VaddrSpace == NULL) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }
    PEPROCESS EProcess = InitInfo->EProcess;
    EProcess->VaddrSpace = VaddrSpace;

    /* Allocate CNode on ExPool and Copy InitCNode over */
    VaddrSpace->CapSpace.RootCap = InitInfo->RootCNodeCap;
    PMM_CNODE RootCNode = (PMM_CNODE) ExAllocatePoolWithTag(sizeof(MM_CNODE), EX_POOL_TAG('r', 'c', 'n', 'd'));
    if (RootCNode == NULL) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }
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
    return STATUS_SUCCESS;
}
