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

NTSTATUS MiInitMapPage(IN PMM_INIT_INFO InitInfo,
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

static VOID MiInitializePagingStructure(IN PMM_PAGING_STRUCTURE Page,
					IN PMM_UNTYPED Parent,
					IN PMM_VADDR_SPACE VaddrSpace,
					IN MWORD Cap,
					IN MWORD VirtPageNum,
					IN MM_PAGING_STRUCTURE_TYPE Type,
					IN BOOLEAN Mapped,
					IN seL4_CapRights_t Rights)
{
    if (Parent != NULL) {
	Parent->TreeNode.LeftChild = &Page->TreeNode;
	Parent->TreeNode.RightChild = NULL;
    }
    Page->TreeNode.CapSpace = &VaddrSpace->CapSpace;
    Page->TreeNode.Parent = &Parent->TreeNode;
    Page->TreeNode.LeftChild = NULL;
    Page->TreeNode.RightChild = NULL;
    Page->TreeNode.Cap = Cap;
    Page->TreeNode.Type = MM_CAP_TREE_NODE_PAGING_STRUCTURE;
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
    MiInitializePagingStructure(&Page->PagingStructure,
				Parent, VaddrSpace, Cap,
				VirtPageNum,
				MM_PAGE_TYPE_PAGE,
				Mapped, Rights);
    MiAvlInitializeNode(&Page->AvlNode, VirtPageNum);
}

VOID MiInitializeMappedLargePage(IN PMM_LARGE_PAGE LargePage,
				 IN PMM_UNTYPED Parent,
				 IN PMM_VADDR_SPACE VaddrSpace,
				 IN MWORD Cap,
				 IN MWORD VirtPTNum,
				 IN BOOLEAN Mapped,
				 IN seL4_CapRights_t Rights)
{
    MiInitializePagingStructure(&LargePage->PagingStructure,
				Parent, VaddrSpace, Cap,
				VirtPTNum << MM_LARGE_PN_SHIFT,
				MM_PAGE_TYPE_LARGE_PAGE,
				Mapped, Rights);
    MiAvlInitializeNode(&LargePage->AvlNode, VirtPTNum);
}

VOID MiInitializePageTable(IN PMM_PAGE_TABLE PageTable,
			   IN PMM_UNTYPED Parent,
			   IN PMM_VADDR_SPACE VaddrSpace,
			   IN MWORD Cap,
			   IN MWORD VirtPTNum,
			   IN BOOLEAN Mapped)
{
    MiInitializePagingStructure(&PageTable->PagingStructure,
				Parent, VaddrSpace, Cap,
				VirtPTNum << MM_LARGE_PN_SHIFT,
				MM_PAGE_TYPE_PAGE_TABLE,
				Mapped, MM_RIGHTS_RW);
    MiAvlInitializeNode(&PageTable->AvlNode, VirtPTNum);
    MiAvlInitializeTree(&PageTable->MappedPages);
}

NTSTATUS MmRegisterClass(IN PMM_INIT_INFO InitInfo)
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
    VaddrSpace->Caches.Vad = NULL;
    VaddrSpace->Caches.RootIoUntyped = NULL;
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
    RET_IF_ERR(MmReserveVirtualMemory(VaddrSpace, EX_POOL_START_PN, EX_POOL_RESERVED_PAGES));
    MiAvlInitializeTree(&VaddrSpace->PageTableTree);
    MiAvlInitializeTree(&VaddrSpace->RootIoUntypedTree);
    PMM_VAD ExPoolVad = MiVspaceFindVadNode(VaddrSpace, EX_POOL_START_PN, 1);
    if (ExPoolVad == NULL) {
	return STATUS_NTOS_BUG;
    }

    /* Add untyped and paging structure built during mapping of initial heap */
    InitializeListHead(&VaddrSpace->SmallUntypedList);
    InitializeListHead(&VaddrSpace->MediumUntypedList);
    InitializeListHead(&VaddrSpace->LargeUntypedList);
    InitializeListHead(&VaddrSpace->RootUntypedList);
    RET_IF_ERR(MiInitRecordUntypedAndPages(InitInfo, VaddrSpace, ExPoolVad));

    /* Build Vad for initial image */
    RET_IF_ERR(MmReserveVirtualMemory(VaddrSpace, InitInfo->UserStartPageNum, InitInfo->NumUserPages));
    PMM_VAD UserImageVad = MiVspaceFindVadNode(VaddrSpace, InitInfo->UserStartPageNum, InitInfo->NumUserPages);
    if (UserImageVad == NULL) {
	return STATUS_NTOS_BUG;
    }
    RET_IF_ERR(MiInitRecordUserImagePaging(InitInfo, VaddrSpace, UserImageVad));

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

NTSTATUS MmRegisterRootIoUntyped(IN PMM_VADDR_SPACE VaddrSpace,
			     IN MWORD Cap,
			     IN MWORD PhyAddr,
			     IN LONG Log2Size)
{
    if (Log2Size < MM_PAGE_BITS || (PhyAddr & (MM_PAGE_SIZE - 1)) != 0) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MiAllocatePool(RootIoUntyped, MM_IO_UNTYPED);
    MiInitializeUntyped(&RootIoUntyped->Untyped, NULL, VaddrSpace, Cap, Log2Size);
    RootIoUntyped->AvlNode.Key = PhyAddr >> MM_PAGE_BITS;
    RET_IF_ERR(MiVspaceInsertRootIoUntyped(VaddrSpace, RootIoUntyped));
    return STATUS_SUCCESS;
}
