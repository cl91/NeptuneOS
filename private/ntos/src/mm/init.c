#include "mi.h"
#include <ctype.h>

/* FIXME: Only works for x86! */
NTSTATUS MmRegisterClass(IN PMM_INIT_INFO_CLASS InitInfo)
{
    CAPSPACE_DESCRIPTOR InitCapSpace;
    CAPSPACE_CNODE_DESCRIPTOR InitCNode =
	{
	 .CapSpace = &InitCapSpace,
	 .Log2Size = InitInfo->RootCNodeLog2Size,
	 .FirstChild = NULL,
	 .Policy = CAPSPACE_TYPE_TAIL_DEALLOC_ONLY
	};
    InitCapSpace.Root = InitInfo->RootCNodeCap;
    InitCapSpace.RootCNode = &InitCNode;
    InitializeListHead(&InitCNode.SiblingList);
    InitCNode.FreeRange.StartCap = InitInfo->RootCNodeFreeCapStart;
    InitCNode.FreeRange.Number = InitInfo->RootCNodeFreeCapNumber;

    UNTYPED_DESCRIPTOR UntypedDescs[32] =
	{
	 {
	  .CapSpace = &InitCapSpace,
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
	return STATUS_NTOS_EXEC_INVALID_ARGUMENT;
    }
    for (int i = 0; i < NumberSplits; i++) {
	RET_IF_ERR(MiSplitUntyped(&UntypedDescs[2*i], &UntypedDescs[2*i+2], &UntypedDescs[2*i+3]));
    }

    PMM_PAGING_STRUCTURE_DESCRIPTOR InitialPage;
    if (InitInfo->InitUntypedLog2Size >= seL4_LargePageBits) {
	MM_PAGING_STRUCTURE_DESCRIPTOR Page =
	    {
	     .Untyped = &UntypedDescs[2*NumberSplits],
	     .CapSpace = &InitCapSpace,
	     .Cap = 0,
	     .VSpaceCap = InitInfo->InitVSpaceCap,
	     .Type = MM_LARGE_PAGE,
	     .Mapped = FALSE,
	     .VirtualAddr = EX_POOL_START,
	     .Rights = MM_RIGHTS_RW,
	     .Attributes = seL4_X86_Default_VMAttributes
	    };
	RET_IF_ERR(MiMapPagingStructure(&Page));
	InitialPage = &Page;
    } else {
	MM_PAGING_STRUCTURE_DESCRIPTOR PageTable =
	    {
	     .Untyped = &UntypedDescs[2*NumberSplits],
	     .CapSpace = &InitCapSpace,
	     .Cap = 0,
	     .VSpaceCap = InitInfo->InitVSpaceCap,
	     .Type = MM_PAGE_TABLE,
	     .Mapped = FALSE,
	     .VirtualAddr = EX_POOL_START,
	     .Rights = 0,
	     .Attributes = seL4_X86_Default_VMAttributes
	    };
	RET_IF_ERR(MiMapPagingStructure(&PageTable));
	MM_PAGING_STRUCTURE_DESCRIPTOR Page =
	    {
	     .Untyped = &UntypedDescs[2*NumberSplits+1],
	     .CapSpace = &InitCapSpace,
	     .Cap = 0,
	     .VSpaceCap = InitInfo->InitVSpaceCap,
	     .Type = MM_PAGE,
	     .Mapped = FALSE,
	     .VirtualAddr = EX_POOL_START,
	     .Rights = MM_RIGHTS_RW,
	     .Attributes = seL4_X86_Default_VMAttributes
	    };
	RET_IF_ERR(MiMapPagingStructure(&Page));
	InitialPage = &Page;
    }

    RET_IF_ERR(ExInitializePool(InitialPage));

    return STATUS_SUCCESS;
}
