#include "mi.h"

static MM_MEM_PRESSURE MiCurrentMemoryPressure;

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
    AvlInitializeNode(&Untyped->AvlNode, PhyAddr);
}

VOID MiInitializePhyMemDescriptor(PPHY_MEM_DESCRIPTOR PhyMem)
{
    AvlInitializeTree(&PhyMem->RootUntypedForest);
    InitializeListHead(&PhyMem->LowMemUntypedList);
    InitializeListHead(&PhyMem->SmallUntypedList);
    InitializeListHead(&PhyMem->MediumUntypedList);
    InitializeListHead(&PhyMem->LargeUntypedList);
}

/*
 * Retype the untyped memory into a seL4 kernel object. The untyped
 * must either not have any children or only have the new TreeNode
 * as the sole child node.
 */
NTSTATUS MmRetypeIntoObject(IN PUNTYPED Untyped,
			    IN MWORD ObjType,
			    IN MWORD ObjBits,
			    IN PCAP_TREE_NODE TreeNode)
{
    assert(Untyped != NULL);
    assert(Untyped->TreeNode.CNode != NULL);
    assert(Untyped->TreeNode.Cap != 0);
    assert(TreeNode->CNode != NULL);
    assert(TreeNode->Cap == 0);
    if (TreeNode->Parent == NULL) {
	assert(!MmCapTreeNodeHasChildren(&Untyped->TreeNode));
    } else {
	assert(TreeNode->Parent == &Untyped->TreeNode);
    }

    MWORD ObjCap = 0;
    RET_ERR(MmAllocateCapRange(TreeNode->CNode, &ObjCap, 1));
    assert(ObjCap);
    MWORD Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				      ObjType, ObjBits,
				      TreeNode->CNode->TreeNode.Cap,
				      0, 0, ObjCap, 1);
    if (Error != seL4_NoError) {
	MmDbgDumpCapTree(&Untyped->TreeNode, 0);
	MmDbgDumpCNode(TreeNode->CNode);
	MmDbgDumpUntypedForest();
	KeDbgDumpIPCError(Error);
	MmDeallocateCap(TreeNode->CNode, ObjCap);
	return SEL4_ERROR(Error);
    }
    TreeNode->Cap = ObjCap;
    if (TreeNode->Parent == NULL) {
	MiCapTreeNodeSetParent(TreeNode, &Untyped->TreeNode);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MiSplitUntypedCap(IN MWORD SrcCap,
			   IN LONG SrcLog2Size,
			   IN MWORD DestCSpace,
			   IN MWORD DestCap)
{
    MWORD Error = seL4_Untyped_Retype(SrcCap, seL4_UntypedObject,
				      SrcLog2Size-1, NTOS_CNODE_CAP,
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
    assert(Src->TreeNode.CNode != NULL);
    assert(!MmCapTreeNodeHasChildren(&Src->TreeNode));

    MWORD NewCap = 0;
    RET_ERR(MmAllocateCapRange(Src->TreeNode.CNode, &NewCap, 2));
    RET_ERR_EX(MiSplitUntypedCap(Src->TreeNode.Cap, Src->Log2Size,
				 Src->TreeNode.CNode->TreeNode.Cap, NewCap),
	       {
		   MmDeallocateCap(Src->TreeNode.CNode, NewCap+1);
		   MmDeallocateCap(Src->TreeNode.CNode, NewCap);
	       });

    Src->Requested = TRUE;
    MiInitializeUntyped(LeftChild, Src->TreeNode.CNode, Src, NewCap, Src->AvlNode.Key,
			Src->Log2Size - 1, Src->IsDevice);
    MiInitializeUntyped(RightChild, Src->TreeNode.CNode, Src, NewCap + 1,
			Src->AvlNode.Key + (1ULL << LeftChild->Log2Size),
			Src->Log2Size - 1, Src->IsDevice);

    return STATUS_SUCCESS;
}

/*
 * Insert this untyped into one of the free lists if it is unused.
 * Otherwise, check if its children are free and insert them instead.
 * This is recursive. Calling this on a non-free untyped will insert
 * all its free descendants. Lists are ordered by the physical
 * address of the untyped.
 */
VOID MiInsertFreeUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			 IN PUNTYPED Untyped)
{
    assert(!Untyped->IsDevice);
    assert(!Untyped->Requested);
    if (MmCapTreeNodeHasChildren(&Untyped->TreeNode)) {
	CapTreeLoopOverChildren(Child, &Untyped->TreeNode) {
	    if (Child->Type == CAP_TREE_NODE_UNTYPED) {
		MiInsertFreeUntyped(PhyMem, TREE_NODE_TO_UNTYPED(Child));
	    }
	}
    } else {
	MWORD PhyAddrEnd = Untyped->AvlNode.Key + (1ULL << Untyped->Log2Size);
	PLIST_ENTRY List;
	if (PhyAddrEnd <= MM_ISA_DMA_LIMIT) {
	    List = &PhyMem->LowMemUntypedList;
	} else if (Untyped->Log2Size >= LARGE_PAGE_LOG2SIZE) {
	    List = &PhyMem->LargeUntypedList;
	} else if (Untyped->Log2Size >= PAGE_LOG2SIZE) {
	    List = &PhyMem->MediumUntypedList;
	} else {
	    List = &PhyMem->SmallUntypedList;
	}
	/* Insert into the list, ordered by physical address */
	PLIST_ENTRY NodeToInsert = List;
	LoopOverList(Entry, List, UNTYPED, FreeListEntry) {
	    if (Entry->AvlNode.Key >= PhyAddrEnd) {
		break;
	    }
	    NodeToInsert = &Entry->FreeListEntry;
	}
	InsertHeadList(NodeToInsert, &Untyped->FreeListEntry);
    }
}

/* Remove the given untyped from the free lists. If they are not in any
 * of the free lists, do nothing. */
static VOID MiRemoveFreeUntyped(IN PUNTYPED Untyped)
{
    if (MiUntypedIsInFreeLists(Untyped)) {
	RemoveEntryList(&Untyped->FreeListEntry);
    }
}

/* Find the smallest untyped that is at least of the given log2size and
 * does not exceed the highest physical address (if specified). Since the
 * free lists are ordered in the physical address of the untyped, we loop
 * through the list backwards so untyped with higher physical address gets
 * allocated first. */
static PUNTYPED MiFindSmallestUntyped(IN PLIST_ENTRY ListHead,
				      IN LONG Log2Size,
				      IN MWORD HighestPhyAddr)
{
    LONG SmallestLog2Size = 255;
    PUNTYPED DesiredUntyped = NULL;
    ReverseLoopOverList(Untyped, ListHead, UNTYPED, FreeListEntry) {
	assert(!Untyped->IsDevice);
	if (HighestPhyAddr && (Untyped->AvlNode.Key >= HighestPhyAddr)) {
	    continue;
	}
	if (Untyped->Log2Size >= Log2Size && Untyped->Log2Size < SmallestLog2Size) {
	    DesiredUntyped = Untyped;
	    SmallestLog2Size = Untyped->Log2Size;
	}
    }
    return DesiredUntyped;
}

MM_MEM_PRESSURE MmQueryMemoryPressure()
{
    return MiCurrentMemoryPressure;
}

/*
 * Find an unused untyped cap in the free untyped lists, remove it from the
 * free list and if necessary, split it until the log2size is exactly the
 * desired size (the remainders will be added back to the free list). Return
 * the final untyped after the split.
 *
 * Additionally, if the HighestPhyAddr is not 0, we will ensure that the
 * returned untyped memory has an ending physical address that does not exceed
 * the given physical address.
 */
NTSTATUS MmRequestUntypedEx(IN LONG Log2Size,
			    IN MWORD HighestPhyAddr,
			    OUT PUNTYPED *pUntyped)
{
    PUNTYPED Untyped = NULL;
    if (HighestPhyAddr && (HighestPhyAddr <= MM_ISA_DMA_LIMIT)) {
	Untyped = MiFindSmallestUntyped(&MiPhyMemDescriptor.LowMemUntypedList,
					Log2Size, HighestPhyAddr);
    } else if (Log2Size >= LARGE_PAGE_LOG2SIZE) {
	Untyped = MiFindSmallestUntyped(&MiPhyMemDescriptor.LargeUntypedList,
					Log2Size, HighestPhyAddr);
    } else if (Log2Size >= PAGE_LOG2SIZE) {
	Untyped = MiFindSmallestUntyped(&MiPhyMemDescriptor.MediumUntypedList,
					Log2Size, HighestPhyAddr);
	if (Untyped == NULL) {
	    Untyped = MiFindSmallestUntyped(&MiPhyMemDescriptor.LargeUntypedList,
					    Log2Size, HighestPhyAddr);
	}
    } else {
	Untyped = MiFindSmallestUntyped(&MiPhyMemDescriptor.SmallUntypedList,
					Log2Size, HighestPhyAddr);
	if (Untyped == NULL) {
	    Untyped = MiFindSmallestUntyped(&MiPhyMemDescriptor.MediumUntypedList,
					    Log2Size, HighestPhyAddr);
	}
	if (Untyped == NULL) {
	    Untyped = MiFindSmallestUntyped(&MiPhyMemDescriptor.LargeUntypedList,
					    Log2Size, HighestPhyAddr);
	}
    }
    if (Untyped == NULL) {
	MiCurrentMemoryPressure = MM_MEM_PRESSURE_CRITICALLY_LOW_MEMORY;
	/* TODO: For certain critical system components (such as the Executive Pool),
	 * we should use the low memory to satisfy their allocation requests. */
	return STATUS_NO_MEMORY;
    }
    MmDbgDumpCapTree(&Untyped->TreeNode, 0);

    LONG NumSplits = Untyped->Log2Size - Log2Size;
    assert(NumSplits >= 0);
    RemoveEntryList(&Untyped->FreeListEntry);
    for (LONG i = 0; i < NumSplits; i++) {
	MiAllocatePool(LeftChild, UNTYPED);
	MiAllocatePoolEx(RightChild, UNTYPED, MiFreePool(LeftChild));
	RET_ERR_EX(MiSplitUntyped(Untyped, LeftChild, RightChild),
		   {
		       MiFreePool(LeftChild);
		       MiFreePool(RightChild);
		   });
	MiInsertFreeUntyped(&MiPhyMemDescriptor, RightChild);
	Untyped = LeftChild;
    }

    Untyped->Requested = TRUE;
    *pUntyped = Untyped;
    assert(!Untyped->IsDevice);

    return STATUS_SUCCESS;
}

/* Returns true if the supplied physical address is bounded
 * by the untyped memory's starting and ending physical address
 */
static inline BOOLEAN MiUntypedContainsPhyAddr(IN PUNTYPED Untyped,
					       IN MWORD PhyAddr)
{
    return AvlNodeContainsAddr(&Untyped->AvlNode,
				 1ULL << Untyped->Log2Size, PhyAddr);
}

static PUNTYPED MiFindRootUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
				  IN MWORD PhyAddr)
{
    PAVL_TREE Tree = &PhyMem->RootUntypedForest;
    PAVL_NODE Node = AvlTreeFindNodeOrPrev(Tree, PhyAddr);
    PUNTYPED Parent = AVL_NODE_TO_UNTYPED(Node);
    if (Parent != NULL && MiUntypedContainsPhyAddr(Parent, PhyAddr)) {
	return Parent;
    }
    return NULL;
}

/* Returns the untyped memory of the specified log2size that contains
 * the specified physical address. Untyped caps may be split during
 * this process, but the remainders are not added back to the free
 * lists, unlike MmRequestUntyped. This should only be called when
 * mapping physical sections. */
NTSTATUS MiGetUntypedAtPhyAddr(IN PPHY_MEM_DESCRIPTOR PhyMem,
			       IN MWORD PhyAddr,
			       IN LONG Log2Size,
			       OUT PUNTYPED *Untyped)
{
    assert(PhyMem != NULL);
    assert(Untyped != NULL);
    PUNTYPED RootUntyped = MiFindRootUntyped(PhyMem, PhyAddr);
    if (RootUntyped == NULL || RootUntyped->Log2Size < Log2Size) {
	return STATUS_INVALID_PARAMETER;
    }

    *Untyped = RootUntyped;
    LONG NumSplits = RootUntyped->Log2Size - Log2Size;
    for (LONG i = NumSplits-1; i >= 0; i--) {
	if (!MmCapTreeNodeHasChildren(&(*Untyped)->TreeNode)) {
	    /* Note since MmAllocatePhysicallyContiguousMemory calls
	     * MmRequestUntypedEx before calling us, (*Untyped)->Requested
	     * may be TRUE without the untyped having any children. This
	     * is perfectly OK. */
	    MiAllocatePool(Child0, UNTYPED);
	    MiAllocatePoolEx(Child1, UNTYPED, MiFreePool(Child0));
	    RET_ERR_EX(MiSplitUntyped(*Untyped, Child0, Child1),
		       {
			   MiFreePool(Child0);
			   MiFreePool(Child1);
		       });
	}
	assert(MmCapTreeNodeChildrenCount(&(*Untyped)->TreeNode) == 2);
	PUNTYPED Child0 = MiCapTreeGetFirstChildTyped(*Untyped, UNTYPED);
	PUNTYPED Child1 = MiCapTreeGetSecondChildTyped(*Untyped, UNTYPED);
	if (MiUntypedContainsPhyAddr(Child0, PhyAddr)) {
	    *Untyped = Child0;
	} else {
	    assert(MiUntypedContainsPhyAddr(Child1, PhyAddr));
	    *Untyped = Child1;
	}
    }

    return STATUS_SUCCESS;
}

NTSTATUS MiInsertRootUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
			     IN PUNTYPED RootUntyped)
{
    MWORD StartPhyAddr = RootUntyped->AvlNode.Key;
    PAVL_TREE Tree = &PhyMem->RootUntypedForest;
    PAVL_NODE Parent = AvlTreeFindNodeOrParent(Tree, StartPhyAddr);
    PUNTYPED ParentUntyped = CONTAINING_RECORD(Parent, UNTYPED, AvlNode);

    /* Reject the insertion if the root untyped to be inserted overlaps
     * with its parent node within the AVL tree. This should never happen
     * and in case it did, it would be a programming error. */
    if (Parent != NULL &&
	AvlNodeOverlapsAddrWindow(Parent, 1ULL << ParentUntyped->Log2Size,
				    StartPhyAddr, 1ULL << RootUntyped->Log2Size)) {
	return STATUS_NTOS_BUG;
    }
    AvlTreeInsertNode(Tree, Parent, &RootUntyped->AvlNode);
    return STATUS_SUCCESS;
}

/*
 * If the sibling of the given untyped cap has any derived cap, or if
 * the parent node of the untyped cap node is NULL, simply return the
 * untyped to the free untyped list (unless the untyped cap is an IO
 * untyped, aka device untyped, in which case we do nothing).
 *
 * Otherwise, detach the sibling from the free list, revoke the parent
 * cap (this will delete both the given untyped cap and its sibling but
 * does not delete the parent cap itself), detach both untyped cap node
 * from the cap tree, free their pool memory, and recursively call this
 * routine on the parent.
 *
 * IMPORTANT: The given Untyped must not have any derived cap. After
 * calling this routine, Untyped may have been freed and you should
 * NOT access it.
 */
VOID MmReleaseUntyped(IN PUNTYPED Untyped)
{
    assert(Untyped != NULL);
    assert(Untyped->Requested);
    assert(!MmCapTreeNodeHasChildren(&Untyped->TreeNode));
    assert(MmCapTreeNodeSiblingCount(&Untyped->TreeNode) <= 2);
    assert(!MiUntypedIsInFreeLists(Untyped));
    MmDbg("Releasing untyped cap 0x%zx\n", Untyped->TreeNode.Cap);
    MmDbgDumpCapTree(&Untyped->TreeNode, 0);
    /* It appears that we have to call Revoke on the untyped cap, regardless
     * of whether the children of the untyped have been deleted (we always
     * delete the children before releasing the untyped, but it seems that
     * just deleting the children is insufficient for releasing the untyped.
     * seL4 actually seems to require you to call Revoke on the untyped itself).
     * If any one is familiar with seL4, please let me know if this is correct. */
    MiCapTreeRevokeNode(&Untyped->TreeNode);
    PCAP_TREE_NODE SiblingNode = MiCapTreeGetNextSibling(&Untyped->TreeNode);
    if (SiblingNode != NULL) {
	PUNTYPED SiblingUntyped = TREE_NODE_TO_UNTYPED(SiblingNode);
	if (SiblingUntyped->Requested) {
	    goto insert;
	}
	assert(Untyped->TreeNode.Parent != NULL);
	assert(Untyped->TreeNode.Parent->Type == CAP_TREE_NODE_UNTYPED);
	assert(SiblingNode->Type == CAP_TREE_NODE_UNTYPED);
	assert(SiblingNode->Parent != NULL);
	assert(SiblingNode->Parent == Untyped->TreeNode.Parent);
	assert(!MmCapTreeNodeHasChildren(SiblingNode));
	PUNTYPED ParentUntyped = TREE_NODE_TO_UNTYPED(SiblingNode->Parent);
	assert(SiblingUntyped->IsDevice == Untyped->IsDevice);
	/* This will deallocate both the Untyped cap and the SiblingNode cap */
	MiCapTreeRevokeNode(Untyped->TreeNode.Parent);
	MiCapTreeRemoveFromParent(&Untyped->TreeNode);
	MiCapTreeRemoveFromParent(SiblingNode);
	/* This will not do anything if SiblingUntyped is not in the free lists. */
	MiRemoveFreeUntyped(SiblingUntyped);
	MiFreePool(Untyped);
	MiFreePool(SiblingUntyped);
	MmReleaseUntyped(ParentUntyped);
	return;
    }

insert:
    Untyped->Requested = FALSE;
    if (!Untyped->IsDevice) {
	MiInsertFreeUntyped(&MiPhyMemDescriptor, Untyped);
    }
}

#ifdef MMDBG
static VOID MiDbgDumpUntyped(IN PAVL_NODE Node)
{
    PUNTYPED Untyped = AVL_NODE_TO_UNTYPED(Node);
    MmDbgDumpCapTree(&Untyped->TreeNode, 4);
}
#endif

VOID MmDbgDumpUntypedForest()
{
#ifdef MMDBG
    PLIST_ENTRY SmallUntypedList = &MiPhyMemDescriptor.SmallUntypedList;
    MmDbgPrint("Dumping all untyped caps:\n");
    MmDbgPrint("  Small free untyped:\n");
    LoopOverList(Untyped, SmallUntypedList, UNTYPED, FreeListEntry) {
	MmDbgPrint("    cap = 0x%zx  log2(size) = %d\n",
		   Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY MediumUntypedList = &MiPhyMemDescriptor.MediumUntypedList;
    MmDbgPrint("  Medium free untyped:\n");
    LoopOverList(Untyped, MediumUntypedList, UNTYPED, FreeListEntry) {
	MmDbgPrint("    cap = 0x%zx  log2(size) = %d\n",
		   Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    PLIST_ENTRY LargeUntypedList = &MiPhyMemDescriptor.LargeUntypedList;
    MmDbgPrint("  Large free untyped:\n");
    LoopOverList(Untyped, LargeUntypedList, UNTYPED, FreeListEntry) {
	MmDbgPrint("    cap = 0x%zx  log2(size) = %d\n",
		   Untyped->TreeNode.Cap, Untyped->Log2Size);
    }
    MmDbgPrint("  Root untyped forest:\n");
    AvlVisitTreeLinear(&MiPhyMemDescriptor.RootUntypedForest,
		       MiDbgDumpUntyped);
    MmDbgPrint("  Root untyped forest as an AVL tree ordered by physical address:\n");
    AvlDumpTree(&MiPhyMemDescriptor.RootUntypedForest);
#endif
}
