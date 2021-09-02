#include "mi.h"

VOID MiInitializeUntyped(IN PUNTYPED Untyped,
			 IN PCNODE CSpace,
			 IN OPTIONAL PUNTYPED Parent,
			 IN MWORD Cap,
			 IN MWORD PhyAddr,
			 IN LONG Log2Size,
			 IN BOOLEAN IsDevice)
{
    MmInitializeCapTreeNode(&Untyped->TreeNode, CAP_TREE_NODE_UNTYPED,
			    Cap, CSpace, Parent ? &Parent->TreeNode : NULL);
    Untyped->Log2Size = Log2Size;
    Untyped->IsDevice = IsDevice;
    InvalidateListEntry(&Untyped->FreeListEntry);
    MiAvlInitializeNode(&Untyped->AvlNode, PhyAddr);
}

VOID MiInitializePhyMemDescriptor(PPHY_MEM_DESCRIPTOR PhyMem)
{
    MiAvlInitializeTree(&PhyMem->RootUntypedForest);
    PhyMem->CachedRootUntyped = NULL;
    InitializeListHead(&PhyMem->SmallUntypedList);
    InitializeListHead(&PhyMem->MediumUntypedList);
    InitializeListHead(&PhyMem->LargeUntypedList);
}

/*
 * Retype the untyped memory into a seL4 kernel object.
 */
NTSTATUS MmRetypeIntoObject(IN PUNTYPED Untyped,
			    IN MWORD ObjType,
			    IN MWORD ObjBits,
			    IN PCAP_TREE_NODE TreeNode)
{
    assert(Untyped != NULL);
    assert(Untyped->TreeNode.CSpace != NULL);
    assert(TreeNode->CSpace != NULL);
    assert(TreeNode->Cap == 0);
    assert((TreeNode->Parent == NULL) ||
	   (TreeNode->Parent == &Untyped->TreeNode));

    MWORD ObjCap = 0;
    RET_ERR(MmAllocateCapRange(TreeNode->CSpace, &ObjCap, 1));
    assert(ObjCap);
    MWORD Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				      ObjType, ObjBits,
				      ROOT_CNODE_CAP,
				      TreeNode->CSpace->TreeNode.Cap,
				      0, ObjCap, 1);
    if (Error != seL4_NoError) {
	MmDeallocateCap(TreeNode->CSpace, ObjCap);
	return SEL4_ERROR(Error);
    }
    TreeNode->Cap = ObjCap;
    MmCapTreeNodeSetParent(TreeNode, &Untyped->TreeNode);
    return STATUS_SUCCESS;
}

NTSTATUS MiSplitUntypedCap(IN MWORD SrcCap,
			   IN LONG SrcLog2Size,
			   IN MWORD DestCSpace,
			   IN MWORD DestCap)
{
    MWORD Error = seL4_Untyped_Retype(SrcCap, seL4_UntypedObject,
				      SrcLog2Size-1, ROOT_CNODE_CAP,
				      DestCSpace, 0, DestCap, 2);
    if (Error) {
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiSplitUntyped(IN PUNTYPED Src,
			OUT PUNTYPED LeftChild,
			OUT PUNTYPED RightChild)
{
    assert(Src != NULL);
    assert(LeftChild != NULL);
    assert(RightChild != NULL);
    assert(Src->TreeNode.CSpace != NULL);

    if (MiCapTreeNodeHasChildren(&Src->TreeNode)) {
	return STATUS_INVALID_PARAMETER;
    }

    MWORD NewCap = 0;
    RET_ERR(MmAllocateCapRange(Src->TreeNode.CSpace, &NewCap, 2));
    RET_ERR_EX(MiSplitUntypedCap(Src->TreeNode.Cap, Src->Log2Size,
				 Src->TreeNode.CSpace->TreeNode.Cap, NewCap),
	       {
		   MmDeallocateCap(Src->TreeNode.CSpace, NewCap+1);
		   MmDeallocateCap(Src->TreeNode.CSpace, NewCap);
	       });

    MiInitializeUntyped(LeftChild, Src->TreeNode.CSpace, Src, NewCap, Src->AvlNode.Key,
			Src->Log2Size - 1, Src->IsDevice);
    MiInitializeUntyped(RightChild, Src->TreeNode.CSpace, Src, NewCap + 1,
			Src->AvlNode.Key + (1ULL << LeftChild->Log2Size),
			Src->Log2Size - 1, Src->IsDevice);

    return STATUS_SUCCESS;
}

VOID MiInsertFreeUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			 IN PUNTYPED Untyped)
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

/* Find the smallest untyped that is at least of the given log2size. */
static PUNTYPED MiFindSmallestUntypedOfLog2Size(IN PLIST_ENTRY ListHead,
						   IN LONG Log2Size)
{
    LONG SmallestLog2Size = 255;
    PUNTYPED DesiredUntyped = NULL;
    LoopOverList(Untyped, ListHead, UNTYPED, FreeListEntry) {
	assert(!Untyped->IsDevice);
	if (Untyped->Log2Size >= Log2Size && Untyped->Log2Size < SmallestLog2Size) {
	    DesiredUntyped = Untyped;
	    SmallestLog2Size = Untyped->Log2Size;
	}
    }
    return DesiredUntyped;
}

NTSTATUS MmRequestUntyped(IN LONG Log2Size,
			  OUT PUNTYPED *pUntyped)
{
    PUNTYPED Untyped = NULL;
    if (Log2Size >= LARGE_PAGE_LOG2SIZE) {
	Untyped = MiFindSmallestUntypedOfLog2Size(&MiPhyMemDescriptor.LargeUntypedList,
						  Log2Size);
    } else if (Log2Size >= PAGE_LOG2SIZE) {
	Untyped = MiFindSmallestUntypedOfLog2Size(&MiPhyMemDescriptor.MediumUntypedList,
						  Log2Size);
	if (Untyped == NULL) {
	    Untyped = MiFindSmallestUntypedOfLog2Size(&MiPhyMemDescriptor.LargeUntypedList,
						      Log2Size);
	}
    } else {
	Untyped = MiFindSmallestUntypedOfLog2Size(&MiPhyMemDescriptor.SmallUntypedList,
						  Log2Size);
	if (Untyped == NULL) {
	    Untyped = MiFindSmallestUntypedOfLog2Size(&MiPhyMemDescriptor.MediumUntypedList,
						      Log2Size);
	}
	if (Untyped == NULL) {
	    Untyped = MiFindSmallestUntypedOfLog2Size(&MiPhyMemDescriptor.LargeUntypedList,
						      Log2Size);
	}
    }
    if (Untyped == NULL) {
	return STATUS_NO_MEMORY;
    }

    LONG NumSplits = Untyped->Log2Size - Log2Size;
    assert(NumSplits >= 0);
    RemoveEntryList(&Untyped->FreeListEntry);
    for (LONG i = 0; i < NumSplits; i++) {
	MWORD LeftCap, RightCap;
	MiAllocatePool(LeftChild, UNTYPED);
	MiAllocatePoolEx(RightChild, UNTYPED, ExFreePool(LeftChild));
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
static inline BOOLEAN MiUntypedContainsPhyAddr(IN PUNTYPED Untyped,
					       IN MWORD PhyAddr)
{
    return MiAvlNodeContainsAddr(&Untyped->AvlNode, 1ULL << Untyped->Log2Size, PhyAddr);
}

static PUNTYPED MiFindRootUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
				     IN MWORD PhyAddr)
{
    PMM_AVL_TREE Tree = &PhyMem->RootUntypedForest;
    if (PhyMem->CachedRootUntyped != NULL
	&& MiUntypedContainsPhyAddr(PhyMem->CachedRootUntyped, PhyAddr)) {
	return PhyMem->CachedRootUntyped;
    }
    PMM_AVL_NODE Node = MiAvlTreeFindNodeOrParent(Tree, PhyAddr);
    PUNTYPED Parent = MM_AVL_NODE_TO_UNTYPED(Node);
    if (Parent != NULL && MiUntypedContainsPhyAddr(Parent, PhyAddr)) {
	PhyMem->CachedRootUntyped = Parent;
	return Parent;
    }
    return NULL;
}

static PUNTYPED MiFindRootIoUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
				       IN MWORD PhyAddr)
{
    PUNTYPED Untyped = MiFindRootUntyped(PhyMem, PhyAddr);
    if ((Untyped == NULL) || (Untyped->IsDevice == FALSE)) {
	return NULL;
    }
    return Untyped;
}

NTSTATUS MiRequestIoUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			    IN MWORD PhyAddr,
			    OUT PUNTYPED *IoUntyped)
{
    assert(PhyMem != NULL);
    assert(IoUntyped != NULL);
    PUNTYPED RootIoUntyped = MiFindRootIoUntyped(PhyMem, PhyAddr);
    if (RootIoUntyped == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    *IoUntyped = RootIoUntyped;
    LONG NumSplits = RootIoUntyped->Log2Size - PAGE_LOG2SIZE;
    for (LONG i = NumSplits-1; i >= 0; i--) {
	if (!MiCapTreeNodeHasChildren(&(*IoUntyped)->TreeNode)) {
	    MiAllocatePool(Child0, UNTYPED);
	    MiAllocatePoolEx(Child1, UNTYPED, ExFreePool(Child0));
	    RET_ERR_EX(MiSplitUntyped(*IoUntyped, Child0, Child1),
		       {
			   ExFreePool(Child0);
			   ExFreePool(Child1);
		       });
	}
	assert(MiCapTreeNodeChildrenCount(&(*IoUntyped)->TreeNode) == 2);
	PUNTYPED Child0 = MiCapTreeGetFirstChildTyped(*IoUntyped, UNTYPED);
	PUNTYPED Child1 = MiCapTreeGetSecondChildTyped(*IoUntyped, UNTYPED);
	if (MiUntypedContainsPhyAddr(Child0, PhyAddr)) {
	    *IoUntyped = Child0;
	} else {
	    assert(MiUntypedContainsPhyAddr(Child1, PhyAddr));
	    *IoUntyped = Child1;
	}
    }

    return STATUS_SUCCESS;
}

NTSTATUS MiInsertRootUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			     IN PUNTYPED RootUntyped)
{
    MWORD StartPhyAddr = RootUntyped->AvlNode.Key;
    PMM_AVL_TREE Tree = &PhyMem->RootUntypedForest;
    PMM_AVL_NODE Node = MiAvlTreeFindNodeOrParent(Tree, StartPhyAddr);
    PUNTYPED Parent = Node ? CONTAINING_RECORD(Node, UNTYPED, AvlNode) : NULL;

    /* Reject the insertion if the root untyped to be inserted overlaps
     * with its parent node within the AVL tree. This should never happen
     * and in case it did, it would be a programming error.
     */
    if (Parent != NULL &&
	MiAvlNodeOverlapsAddrWindow(Node, 1ULL << Parent->Log2Size,
				    StartPhyAddr, 1ULL << RootUntyped->Log2Size)) {
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
NTSTATUS MmReleaseUntyped(IN PUNTYPED Untyped)
{
    /* TODO: Revoke child objects */
    /* TODO: Merge untyped recursively if possible and add to free list */
    return STATUS_SUCCESS;
}

#ifdef CONFIG_DEBUG_BUILD
VOID MmDbgDumpUntypedInfo()
{
    PLIST_ENTRY SmallUntypedList = &MiPhyMemDescriptor.SmallUntypedList;
    DbgPrint("Dumping untyped information:\n");
    DbgPrint("  Small free untyped:\n");
    LoopOverList(Untyped, SmallUntypedList, UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %zd  log2(size) = %d\n",
		 Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY MediumUntypedList = &MiPhyMemDescriptor.MediumUntypedList;
    DbgPrint("  Medium free untyped:\n");
    LoopOverList(Untyped, MediumUntypedList, UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %zd  log2(size) = %d\n",
		 Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY LargeUntypedList = &MiPhyMemDescriptor.LargeUntypedList;
    DbgPrint("  Large free untyped:\n");
    LoopOverList(Untyped, LargeUntypedList, UNTYPED, FreeListEntry) {
	DbgPrint("    cap = %zd  log2(size) = %d\n",
		 Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    DbgPrint("  Root untyped forest linearly:\n");
    MmAvlDumpTreeLinear(&MiPhyMemDescriptor.RootUntypedForest);
    DbgPrint("  Root untyped forest as an AVL tree ordered by physical address:\n");
    MmAvlDumpTree(&MiPhyMemDescriptor.RootUntypedForest);
}
#endif
