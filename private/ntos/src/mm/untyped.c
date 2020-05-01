#include "mi.h"

VOID MiInitializeUntyped(IN PMM_UNTYPED Untyped,
			 IN PMM_UNTYPED Parent,
			 IN BOOLEAN IsLeft,
			 IN MWORD Cap,
			 IN MWORD PhyAddr,
			 IN LONG Log2Size,
			 IN BOOLEAN IsDevice)
{
    assert((PhyAddr & ((1 << Log2Size) - 1)) == 0);
    Untyped->TreeNode.Parent = &Parent->TreeNode;
    if (Parent != NULL) {
	if (IsLeft) {
	    Parent->TreeNode.LeftChild = &Untyped->TreeNode;
	} else {
	    Parent->TreeNode.RightChild = &Untyped->TreeNode;
	}
    }
    Untyped->TreeNode.Type = MM_CAP_TREE_NODE_UNTYPED;
    Untyped->TreeNode.Cap = Cap;
    Untyped->Log2Size = Log2Size;
    Untyped->IsDevice = IsDevice;
    InvalidateListEntry(&Untyped->FreeListEntry);
    MiAvlInitializeNode(&Untyped->AvlNode, PhyAddr);
}

NTSTATUS MiSplitUntyped(IN PMM_UNTYPED Src,
			OUT PMM_UNTYPED Dest1,
			OUT PMM_UNTYPED Dest2)
{
    if ((Src->TreeNode.LeftChild != NULL) || (Src->TreeNode.RightChild != NULL)) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    MWORD NewCap = 0;
    RET_IF_ERR(MmAllocateCaps(&NewCap, 2));

    MWORD Error = seL4_Untyped_Retype(Src->TreeNode.Cap,
				      seL4_UntypedObject,
				      Src->Log2Size - 1,
				      MmRootCspaceCap(),
				      0, // node_index
				      0, // node_depth
				      NewCap, // node_offset
				      2);
    if (Error != seL4_NoError) {
	RET_IF_ERR(MmDeallocateCap(NewCap+1));
	RET_IF_ERR(MmDeallocateCap(NewCap));
	return SEL4_ERROR(Error);
    }

    MiInitializeUntyped(Dest1, Src, TRUE, NewCap, Src->AvlNode.Key,
			Src->Log2Size - 1, Src->IsDevice);
    MiInitializeUntyped(Dest2, Src, FALSE, NewCap + 1,
			Src->AvlNode.Key + (1 << Dest1->Log2Size),
			Src->Log2Size - 1, Src->IsDevice);

    return STATUS_SUCCESS;
}

VOID MiInsertFreeUntyped(IN PMM_PHY_MEM PhyMem,
			 IN PMM_UNTYPED Untyped)
{
    PLIST_ENTRY List;
    if (Untyped->Log2Size >= MM_LARGE_PAGE_BITS) {
	List = &PhyMem->LargeUntypedList;
    } else if (Untyped->Log2Size >= MM_PAGE_BITS) {
	List = &PhyMem->MediumUntypedList;
    } else {
	List = &PhyMem->SmallUntypedList;
    }
    InsertHeadList(List, &Untyped->FreeListEntry);
}

NTSTATUS MmRequestFreeUntyped(IN LONG Log2Size,
			      OUT PMM_UNTYPED *pUntyped)
{
    PLIST_ENTRY List = NULL;
    if (Log2Size >= MM_LARGE_PAGE_BITS && !IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    } else if (Log2Size >= MM_PAGE_BITS && !IsListEmpty(&MiPhyMemDescriptor.MediumUntypedList)) {
	List = &MiPhyMemDescriptor.MediumUntypedList;
    } else if (Log2Size >= MM_PAGE_BITS && !IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.SmallUntypedList)) {
	List = &MiPhyMemDescriptor.SmallUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.MediumUntypedList)) {
	List = &MiPhyMemDescriptor.MediumUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    }
    if (List == NULL) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }
    PMM_UNTYPED Untyped = CONTAINING_RECORD(List->Flink, MM_UNTYPED, FreeListEntry);
    LONG NumSplits = Untyped->Log2Size - Log2Size;
    assert(NumSplits >= 0);
    RemoveEntryList(List->Flink);
    for (LONG i = 0; i < NumSplits; i++) {
	MWORD LeftCap, RightCap;
	MiAllocatePool(LeftChild, MM_UNTYPED);
	MiAllocatePool(RightChild, MM_UNTYPED);
	RET_IF_ERR(MiSplitUntyped(Untyped, LeftChild, RightChild));
	MiInsertFreeUntyped(&MiPhyMemDescriptor, RightChild);
	Untyped = LeftChild;
    }

    *pUntyped = Untyped;
    assert(Untyped->IsDevice == FALSE);

    return STATUS_SUCCESS;
}

static PMM_UNTYPED MiFindRootUntyped(IN PMM_PHY_MEM PhyMem,
				     IN MWORD PhyAddr)
{
    PMM_AVL_TREE Tree = &PhyMem->RootUntypedTree;
    if (PhyMem->CachedRootUntyped != NULL && (PhyAddr >= PhyMem->CachedRootUntyped->AvlNode.Key)
	&& (PhyAddr < PhyMem->CachedRootUntyped->AvlNode.Key +
	    (1 << PhyMem->CachedRootUntyped->Log2Size))) {
	return PhyMem->CachedRootUntyped;
    }
    PMM_AVL_NODE Node = MiAvlTreeFindNodeOrParent(Tree, PhyAddr);
    PMM_UNTYPED Parent = Node ? CONTAINING_RECORD(Node, MM_UNTYPED, AvlNode) : NULL;
    if (Parent != NULL && (PhyAddr >= Parent->AvlNode.Key)
	&& (PhyAddr < Parent->AvlNode.Key + (1 << Parent->Log2Size))) {
	PhyMem->CachedRootUntyped = Parent;
	return Parent;
    }
    return NULL;
}

static PMM_UNTYPED MiFindRootIoUntyped(IN PMM_PHY_MEM PhyMem,
				       IN MWORD PhyAddr)
{
    PMM_UNTYPED Untyped = MiFindRootUntyped(PhyMem, PhyAddr);
    if ((Untyped == NULL) || (Untyped->IsDevice == FALSE)) {
	return NULL;
    }
    return Untyped;
}

NTSTATUS MiRequestIoUntyped(IN PMM_PHY_MEM PhyMem,
			    IN MWORD PhyPageNum,
			    OUT PMM_UNTYPED *IoUntyped)
{
    MWORD PhyAddr = PhyPageNum << MM_PAGE_BITS;
    PMM_UNTYPED RootIoUntyped = MiFindRootIoUntyped(PhyMem, PhyAddr);
    if (RootIoUntyped == NULL) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    *IoUntyped = RootIoUntyped;
    LONG NumSplits = RootIoUntyped->Log2Size - MM_PAGE_BITS;
    for (LONG i = NumSplits-1; i >= 0; i--) {
	if ((*IoUntyped)->TreeNode.LeftChild == NULL) {
	    MiAllocatePool(LeftChild, MM_UNTYPED);
	    MiAllocatePool(RightChild, MM_UNTYPED);
	    RET_IF_ERR(MiSplitUntyped(*IoUntyped,
				      LeftChild,
				      RightChild));
	}
	MWORD Bit = PhyPageNum & (1 << i);
	PMM_UNTYPED Child;
	if (Bit) {
	    Child = (PMM_UNTYPED) (*IoUntyped)->TreeNode.RightChild;
	} else {
	    Child = (PMM_UNTYPED) (*IoUntyped)->TreeNode.LeftChild;
	}
	*IoUntyped = Child;
    }

    return STATUS_SUCCESS;
}

NTSTATUS MiInsertRootUntyped(IN PMM_PHY_MEM PhyMem,
			     IN PMM_UNTYPED RootUntyped)
{
    MWORD StartPhyAddr = RootUntyped->AvlNode.Key;
    MWORD EndPhyAddr = StartPhyAddr + (1 << RootUntyped->Log2Size);
    PMM_AVL_TREE Tree = &PhyMem->RootUntypedTree;
    PMM_AVL_NODE Node = MiAvlTreeFindNodeOrParent(Tree, StartPhyAddr);
    PMM_UNTYPED Parent = Node ? CONTAINING_RECORD(Node, MM_UNTYPED, AvlNode) : NULL;
    if (Parent != NULL && (StartPhyAddr >= Parent->AvlNode.Key)
	&& (EndPhyAddr <= Parent->AvlNode.Key + (1 << Parent->Log2Size))) {
	/* EndPageNum <= ...: Here the equal sign is important! */
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    MiAvlTreeInsertNode(Tree, &Parent->AvlNode, &RootUntyped->AvlNode);
    return STATUS_SUCCESS;
}
