#include "mi.h"
#include <ctype.h>

NTSTATUS MiSplitInitialUntyped(IN MWORD RootCap,
			       IN MWORD SrcCap,
			       IN LONG SrcLog2Size,
			       IN MWORD DestCap)
{
    MWORD Error = seL4_Untyped_Retype(SrcCap,
				      seL4_UntypedObject,
				      SrcLog2Size-1,
				      RootCap,
				      0, // node_index
				      0, // node_depth
				      DestCap, // node_offset
				      2);
    if (Error) {
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiInitRetypeIntoPage(IN MWORD RootCap,
			      IN MWORD Untyped,
			      IN MWORD PageCap,
			      IN MWORD Type)
{
    int Error = seL4_Untyped_Retype(Untyped,
				    Type,
				    MM_PAGE_BITS,
				    RootCap,
				    0, // node_index
				    0, // node_depth
				    PageCap,
				    1 // num_caps
				    );
    if (Error) {
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS MiInitMapPage(IN PMM_INIT_INFO_CLASS InitInfo,
		       IN MWORD Untyped,
		       IN MWORD PageCap,
		       IN MWORD Vaddr,
		       IN MWORD Type)
{
    MWORD RootCap = InitInfo->RootCNodeCap;
    RET_IF_ERR(MiInitRetypeIntoPage(RootCap, Untyped, PageCap, Type));

    MWORD VSpaceCap = InitInfo->InitVSpaceCap;
    int Error;
    if (Type == seL4_X86_4K) {
	Error = seL4_X86_Page_Map(PageCap,
				  VSpaceCap,
				  Vaddr,
				  MM_RIGHTS_RW,
				  seL4_X86_Default_VMAttributes);
    } else if (Type == seL4_X86_PageTableObject) {
	Error = seL4_X86_PageTable_Map(PageCap,
				       VSpaceCap,
				       Vaddr,
				       seL4_X86_Default_VMAttributes);
    } else {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    if (Error) {
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

VOID MiInitializeUntyped(IN PMM_UNTYPED Untyped,
			 IN PMM_UNTYPED Parent,
			 IN PMM_VADDR_SPACE VaddrSpace,
			 IN MWORD Cap,
			 IN LONG Log2Size)
{
    Untyped->TreeNode.CapSpace = &VaddrSpace->CapSpace;
    Untyped->TreeNode.Parent = &Parent->TreeNode;
    Untyped->TreeNode.Type = MM_CAP_TREE_NODE_UNTYPED;
    Untyped->TreeNode.Cap = Cap;
    Untyped->Log2Size = Log2Size;
    InvalidateListEntry(&Untyped->RootListEntry);
    InvalidateListEntry(&Untyped->FreeListEntry);
}

VOID MiInitHeapPagingStructure(IN PMM_PAGING_STRUCTURE Page,
			       IN PMM_UNTYPED Parent,
			       IN PMM_VADDR_SPACE VaddrSpace,
			       IN MWORD Cap,
			       IN MWORD Vaddr,
			       IN MM_PAGING_STRUCTURE_TYPE Type,
			       IN PMM_INIT_INFO_CLASS InitInfo)
{
    Page->TreeNode.CapSpace = &VaddrSpace->CapSpace;
    Page->TreeNode.Parent = &Parent->TreeNode;
    Page->TreeNode.LeftChild = NULL;
    Page->TreeNode.RightChild = NULL;
    Page->TreeNode.Cap = Cap;
    Page->TreeNode.Type = MM_CAP_TREE_NODE_PAGING_STRUCTURE;
    Page->VSpaceCap = InitInfo->InitVSpaceCap;
    Page->Type = Type;
    Page->Mapped = TRUE;
    Page->VirtualAddr = Vaddr;
    Page->Rights = MM_RIGHTS_RW;
    Page->Attributes = seL4_X86_Default_VMAttributes;
    Parent->TreeNode.LeftChild = &Page->TreeNode;
    Parent->TreeNode.RightChild = NULL;
}

NTSTATUS MmRegisterClass(IN PMM_INIT_INFO_CLASS InitInfo)
{
    /* Map initial pages for ExPool */
    LONG PoolPages;
    MWORD FreeCapStart;
    RET_IF_ERR(MiInitMapInitialHeap(InitInfo, &PoolPages, &FreeCapStart));

    /* Initialize ExPool */
    PEPROCESS EProcess = InitInfo->EProcess;
    RET_IF_ERR(ExInitializePool(EProcess, EX_POOL_START, PoolPages));
    PMM_VADDR_SPACE VaddrSpace = &EProcess->VaddrSpace;

    /* Allocate memory for CNode on ExPool and Copy InitCNode over */
    VaddrSpace->CapSpace.RootCap = InitInfo->RootCNodeCap;
    VaddrSpace->VSpaceCap = InitInfo->InitVSpaceCap;
    MiAllocatePool(RootCNode, MM_CNODE);
    VaddrSpace->CapSpace.RootCNode = RootCNode;
    RootCNode->TreeNode.CapSpace = &VaddrSpace->CapSpace;
    RootCNode->TreeNode.Parent = NULL;
    RootCNode->TreeNode.LeftChild = NULL;
    RootCNode->TreeNode.RightChild = NULL;
    RootCNode->TreeNode.Cap = InitInfo->RootCNodeCap;
    RootCNode->TreeNode.Type = MM_CAP_TREE_NODE_UNTYPED;
    RootCNode->Log2Size = InitInfo->RootCNodeLog2Size;
    RootCNode->FirstChild = NULL;
    InitializeListHead(&RootCNode->SiblingList);
    RootCNode->Policy = MM_CNODE_TAIL_DEALLOC_ONLY;
    RootCNode->FreeRange.StartCap = FreeCapStart;
    RootCNode->FreeRange.Number = (1 << InitInfo->RootCNodeLog2Size) - FreeCapStart;

    /* Build the Vad tree of the global EProcess */
    MiAvlInitializeTree(&VaddrSpace->VadTree);
    MiAllocatePool(ExPoolVad, MM_VAD);
    MiInitializeVadNode(ExPoolVad, EX_POOL_START >> MM_PAGE_BITS, EX_POOL_RESERVED_SIZE >> MM_PAGE_BITS);
    MiVspaceInsertVadNode(VaddrSpace, ExPoolVad);
    MiAvlInitializeTree(&VaddrSpace->PageTableTree);

    /* Add untyped and paging structure built during mapping of initial heap */
    InitializeListHead(&VaddrSpace->SmallUntypedList);
    InitializeListHead(&VaddrSpace->MediumUntypedList);
    InitializeListHead(&VaddrSpace->LargeUntypedList);
    InitializeListHead(&VaddrSpace->RootUntypedList);
    RET_IF_ERR(MiInitHeapVad(InitInfo, VaddrSpace, ExPoolVad));

    return STATUS_SUCCESS;
}

NTSTATUS MmRegisterRootUntyped(IN PMM_VADDR_SPACE VaddrSpace,
			       IN MWORD Cap,
			       IN LONG Log2Size)
{
    MiAllocatePool(Untyped, MM_UNTYPED);
    MiInitializeUntyped(Untyped, NULL, VaddrSpace, Cap, Log2Size);
    InsertTailList(&VaddrSpace->RootUntypedList, &Untyped->RootListEntry);
    MiInsertFreeUntyped(VaddrSpace, Untyped);
    return STATUS_SUCCESS;
}

NTSTATUS MmRegisterDeviceUntyped(IN PMM_VADDR_SPACE VaddrSpace,
				 IN MWORD Cap,
				 IN MWORD PhyAddr,
				 IN LONG Log2Size)
{
    return STATUS_SUCCESS;
}
