#include "mi.h"

VOID MiInitializeUntyped(IN PMM_UNTYPED Untyped,
			 IN PMM_UNTYPED Parent,
			 IN MWORD Cap,
			 IN MWORD PhyAddr,
			 IN LONG Log2Size,
			 IN BOOLEAN IsDevice)
{
    assert((PhyAddr & ((1 << Log2Size) - 1)) == 0);
    MiInitializeCapTreeNode(&Untyped->TreeNode, MM_CAP_TREE_NODE_UNTYPED,
			    Cap, &Parent->TreeNode);
    Untyped->Log2Size = Log2Size;
    Untyped->IsDevice = IsDevice;
    InvalidateListEntry(&Untyped->FreeListEntry);
    MiAvlInitializeNode(&Untyped->AvlNode, PhyAddr);
}

/*
 * Retype the untyped memory into a seL4 kernel object.
 */
NTSTATUS MmRetypeIntoObject(IN PMM_UNTYPED Untyped,
			    IN MWORD ObjType,
			    IN MWORD ObjBits,
			    OUT MWORD *ObjCap)
{
    assert(Untyped != NULL);
    assert(ObjCap != NULL);
    RET_ERR(MmAllocateCap(ObjCap));
    MWORD Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				      ObjType,
				      ObjBits,
				      ROOT_CNODE_CAP,
				      0, // node_index
				      0, // node_depth
				      *ObjCap, // node_offset
				      1);
    if (Error != seL4_NoError) {
	MmDeallocateCap(*ObjCap);
	*ObjCap = 0;
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiSplitUntypedCap(IN MWORD SrcCap,
			   IN LONG SrcLog2Size,
			   IN MWORD DestCap)
{
    MWORD Error = seL4_Untyped_Retype(SrcCap,
				      seL4_UntypedObject,
				      SrcLog2Size-1,
				      ROOT_CNODE_CAP,
				      0, // node_index
				      0, // node_depth
				      DestCap, // node_offset
				      2);
    if (Error) {
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiSplitUntyped(IN PMM_UNTYPED Src,
			OUT PMM_UNTYPED LeftChild,
			OUT PMM_UNTYPED RightChild)
{
    if (MiCapTreeNodeHasChildren(&Src->TreeNode)) {
	return STATUS_INVALID_PARAMETER;
    }

    MWORD NewCap = 0;
    RET_ERR(MmAllocateCapRange(&NewCap, 2));
    RET_ERR_EX(MiSplitUntypedCap(Src->TreeNode.Cap, Src->Log2Size, NewCap),
	       {
		   MmDeallocateCap(NewCap+1);
		   MmDeallocateCap(NewCap);
	       });

    MiInitializeUntyped(LeftChild, Src, NewCap, Src->AvlNode.Key,
			Src->Log2Size - 1, Src->IsDevice);
    MiInitializeUntyped(RightChild, Src, NewCap + 1,
			Src->AvlNode.Key + (1 << LeftChild->Log2Size),
			Src->Log2Size - 1, Src->IsDevice);

    return STATUS_SUCCESS;
}

VOID MiInsertFreeUntyped(IN PMM_PHY_MEM PhyMem,
			 IN PMM_UNTYPED Untyped)
{
    PLIST_ENTRY List;
    if (Untyped->Log2Size >= LARGE_PAGE_LOG2SIZE) {
	List = &PhyMem->LargeUntypedList;
    } else if (Untyped->Log2Size >= PAGE_LOG2SIZE) {
	List = &PhyMem->MediumUntypedList;
    } else {
	List = &PhyMem->SmallUntypedList;
    }
    InsertHeadList(List, &Untyped->FreeListEntry);
}

NTSTATUS MmRequestUntyped(IN LONG Log2Size,
			  OUT PMM_UNTYPED *pUntyped)
{
    PLIST_ENTRY List = NULL;
    if (Log2Size >= LARGE_PAGE_LOG2SIZE && !IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    } else if (Log2Size >= PAGE_LOG2SIZE && !IsListEmpty(&MiPhyMemDescriptor.MediumUntypedList)) {
	List = &MiPhyMemDescriptor.MediumUntypedList;
    } else if (Log2Size >= PAGE_LOG2SIZE && !IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.SmallUntypedList)) {
	List = &MiPhyMemDescriptor.SmallUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.MediumUntypedList)) {
	List = &MiPhyMemDescriptor.MediumUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    }
    if (List == NULL) {
	return STATUS_NO_MEMORY;
    }

    PMM_UNTYPED Untyped = CONTAINING_RECORD(List->Flink, MM_UNTYPED, FreeListEntry);
    LONG NumSplits = Untyped->Log2Size - Log2Size;
    assert(NumSplits >= 0);
    RemoveEntryList(List->Flink);
    for (LONG i = 0; i < NumSplits; i++) {
	MWORD LeftCap, RightCap;
	MiAllocatePool(LeftChild, MM_UNTYPED);
	MiAllocatePoolEx(RightChild, MM_UNTYPED, ExFreePool(LeftChild));
	RET_ERR_EX(MiSplitUntyped(Untyped, LeftChild, RightChild),
		   {
		       ExFreePool(LeftChild);
		       ExFreePool(RightChild);
		   });
	MiInsertFreeUntyped(&MiPhyMemDescriptor, RightChild);
	Untyped = LeftChild;
    }

    *pUntyped = Untyped;
    assert(Untyped->IsDevice == FALSE);

    return STATUS_SUCCESS;
}

/* Returns true if the supplied physical address is bounded
 * by the untyped memory's starting and ending physical address
 */
static inline BOOLEAN MiUntypedContainsPhyAddr(IN PMM_UNTYPED Untyped,
					       IN MWORD PhyAddr)
{
    MWORD StartAddr = Untyped->AvlNode.Key;
    MWORD EndAddr = StartAddr + (1 << Untyped->Log2Size);
    return (PhyAddr >= StartAddr) && (PhyAddr < EndAddr);
}

static PMM_UNTYPED MiFindRootUntyped(IN PMM_PHY_MEM PhyMem,
				     IN MWORD PhyAddr)
{
    PMM_AVL_TREE Tree = &PhyMem->RootUntypedForest;
    if (PhyMem->CachedRootUntyped != NULL
	&& MiUntypedContainsPhyAddr(PhyMem->CachedRootUntyped, PhyAddr)) {
	return PhyMem->CachedRootUntyped;
    }
    PMM_AVL_NODE Node = MiAvlTreeFindNodeOrParent(Tree, PhyAddr);
    PMM_UNTYPED Parent = Node ? CONTAINING_RECORD(Node, MM_UNTYPED, AvlNode) : NULL;
    if (Parent != NULL && MiUntypedContainsPhyAddr(Parent, PhyAddr)) {
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
    MWORD PhyAddr = PhyPageNum << PAGE_LOG2SIZE;
    PMM_UNTYPED RootIoUntyped = MiFindRootIoUntyped(PhyMem, PhyAddr);
    if (RootIoUntyped == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    *IoUntyped = RootIoUntyped;
    LONG NumSplits = RootIoUntyped->Log2Size - PAGE_LOG2SIZE;
    for (LONG i = NumSplits-1; i >= 0; i--) {
	if (!MiCapTreeNodeHasChildren(&(*IoUntyped)->TreeNode)) {
	    MiAllocatePool(Child0, MM_UNTYPED);
	    MiAllocatePoolEx(Child1, MM_UNTYPED, ExFreePool(Child0));
	    RET_ERR_EX(MiSplitUntyped(*IoUntyped, Child0, Child1),
		       {
			   ExFreePool(Child0);
			   ExFreePool(Child1);
		       });
	}
	assert(MiCapTreeNodeChildrenCount(&(*IoUntyped)->TreeNode) == 2);
	PMM_UNTYPED Child0 = MiCapTreeGetFirstChildTyped(*IoUntyped, MM_UNTYPED);
	PMM_UNTYPED Child1 = MiCapTreeGetSecondChildTyped(*IoUntyped, MM_UNTYPED);
	if (MiUntypedContainsPhyAddr(Child0, PhyAddr)) {
	    *IoUntyped = Child0;
	} else {
	    assert(MiUntypedContainsPhyAddr(Child1, PhyAddr));
	    *IoUntyped = Child1;
	}
    }

    return STATUS_SUCCESS;
}

NTSTATUS MiInsertRootUntyped(IN PMM_PHY_MEM PhyMem,
			     IN PMM_UNTYPED RootUntyped)
{
    MWORD StartPhyAddr = RootUntyped->AvlNode.Key;
    MWORD EndPhyAddr = StartPhyAddr + (1 << RootUntyped->Log2Size);
    PMM_AVL_TREE Tree = &PhyMem->RootUntypedForest;
    PMM_AVL_NODE Node = MiAvlTreeFindNodeOrParent(Tree, StartPhyAddr);
    PMM_UNTYPED Parent = Node ? CONTAINING_RECORD(Node, MM_UNTYPED, AvlNode) : NULL;

    /* Reject the insertion if the root untyped to be inserted overlaps
     * with its parent node. This should never happen and in case it did,
     * it would be due to a programming error. We therefore trigger an
     * assertion on debug build in this case.
     */
    if (Parent != NULL && (StartPhyAddr >= Parent->AvlNode.Key)
	&& (EndPhyAddr <= Parent->AvlNode.Key + (1 << Parent->Log2Size))) {
	/* EndPhyAddr <= ...: Here the equal sign is important! */
	assert(FALSE);
	return STATUS_NTOS_BUG;
    }
    MiAvlTreeInsertNode(Tree, &Parent->AvlNode, &RootUntyped->AvlNode);
    return STATUS_SUCCESS;
}

/*
 * Revoke all child objects of the specified untyped and return
 * the untyped to the free untyped lists, possibly merging with
 * sibling untyped memories.
 */
NTSTATUS MmReleaseUntyped(IN PMM_UNTYPED Untyped)
{
    /* TODO: Revoke child objects */
    /* TODO: Merge untyped recursively if possible and add to free list */
    return STATUS_SUCCESS;
}
