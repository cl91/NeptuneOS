/*++

Copyright (c) 2022  Dr. Chang Liu, PhD.

Module Name:

    cap.c

Abstract:

    Capability space and CNode management

    The basic design here is to have a large initial root
    CNode as the CSpace of the root task, which contains
    all the seL4 kernel objects being managed. The size of the
    initial root CNode is specified at compile time by the
    cmake option KernelRootCNodeSizeBits. Assuming the main
    source of cnode slot usage is from page management (for
    each virtual address space, all mapped pages need their
    own capabilities since sharing pages require duplicating
    page capabilities), for each 4K page we assess four slots
    on x32 and one slot on x64 (since x64 is more likely to
    use large pages often), and determine the initial cnode
    size from the typical memory sizes for each architecture.
    This is 256MB for x32 and 4G for x64. Users with larger
    or smaller RAM should adjust the numbers accordingly.

    Each process will have a CSpace with only a single level
    of CNode, namely the root CNode of the CSpace. The NTOS
    root task has a large root CNode (with, say 2^16 slots),
    since all capabilities to kernel objects are stored in
    the NTOS CSpace. These include all TCBs, all pages, and
    all untyped caps. Client processes will have a much smaller
    root CNode (of order, say 16 slots), since we only store
    the relevant per-process endpoint capabilities there.

    Each CNode has a bitmap to keep track of the slot usage.
    Allocation and deallocation of a cap slot modify the
    corresponding bit in the bitmap. To speed up free bit
    lookup we keep a pointer to the most recently freed bit.

Revision History:

    2021-07-16  Revised the design to use a large root CNode
                for the root task CSpace and a small CNode
                for each client process.

--*/

#include "mi.h"

VOID MmDbgDumpCapTreeNode(IN PCAP_TREE_NODE Node)
{
#if defined(MMDBG) && defined(CONFIG_DEBUG_BUILD)
    if (Node == NULL) {
	MmDbgPrint("(nil)");
	return;
    }

    PCSTR Type = "Unknown";
    if (Node->Type == CAP_TREE_NODE_CNODE) {
	Type = "CNODE";
    } else if (Node->Type == CAP_TREE_NODE_UNTYPED) {
	Type = "UNTYPED";
    } else if (Node->Type == CAP_TREE_NODE_TCB) {
	Type = "TCB";
    } else if (Node->Type == CAP_TREE_NODE_PAGING_STRUCTURE) {
	Type = "PAGING";
    } else if (Node->Type == CAP_TREE_NODE_ENDPOINT) {
	Type = "ENDPOINT";
    } else if (Node->Type == CAP_TREE_NODE_NOTIFICATION) {
	Type = "NOTIFICATION";
    } else if (Node->Type == CAP_TREE_NODE_X86_IOPORT) {
	Type = "X86_IOPORT";
    } else if (Node->Type == CAP_TREE_NODE_IRQ_HANDLER) {
	Type = "IRQ_HANDLER";
    }
    PCSTR CapType = RtlDbgCapTypeToStr(seL4_DebugCapIdentify(Node->Cap));
    if (Node->CSpace != &MiNtosCNode) {
	CapType = "in client process's CSpace";
    }
    MmDbgPrint("Cap 0x%zx (Type %s seL4 Cap %s)", Node->Cap, Type, CapType);
#endif
}

VOID MmDbgDumpCNode(IN PCNODE CNode)
{
#if defined(MMDBG) && defined(CONFIG_DEBUG_BUILD)
    MmDbg("Dumping CNode %p\n", CNode);
    MmDbgPrint("    TREE-NODE ");
    MmDbgDumpCapTreeNode(&CNode->TreeNode);
    MmDbgPrint("\n    Log2Size %d  Depth %d\n  TotalUsed %d\n    UsedMap",
	     CNode->Log2Size, CNode->Depth, CNode->TotalUsed);
    for (ULONG i = 0; i < (1 << CNode->Log2Size) / MWORD_BITS; i++) {
	MmDbgPrint("  %p", (PVOID)CNode->UsedMap[i]);
    }
    MmDbgPrint("\n");
    if (CNode->TreeNode.CSpace == &MiNtosCNode) {
	for (ULONG i = 0; i < (1 << CNode->Log2Size); i++) {
	    if (GetBit(CNode->UsedMap, i)) {
		MmDbgPrint("Cap 0x%x Type %s\n", i,
			   RtlDbgCapTypeToStr(seL4_DebugCapIdentify(i)));
	    }
	}
    }
#endif
}

#define MI_DBG_CAP_TREE_INDENTATION	2

VOID MmDbgDumpCapTree(IN PCAP_TREE_NODE Node,
		      IN LONG Indentation)
{
#ifdef MMDBG
    RtlDbgPrintIndentation(Indentation);
    MmDbgPrint("Node %p, CL.FL %p CL.BL %p SL.FL %p SL.BL %p   ",
	     Node, Node->ChildrenList.Flink, Node->ChildrenList.Blink,
	     Node->SiblingLink.Flink, Node->SiblingLink.Blink);
    MmDbgDumpCapTreeNode(Node);
    MmDbgPrint("\n");
    CapTreeLoopOverChildren(Child, Node) {
	MmDbgDumpCapTree(Child, Indentation + MI_DBG_CAP_TREE_INDENTATION);
    }
#endif
}

/* Allocate a contiguous range of capability slots */
NTSTATUS MmAllocateCapRange(IN PCNODE CNode,
			    OUT MWORD *StartCap,
			    IN LONG NumberRequested)
{
    assert(CNode != NULL);
    assert(StartCap != NULL);
    *StartCap = 0;

    ULONG CNodeSize = 1ULL << CNode->Log2Size;
    MWORD CNodeMask = CNodeSize - 1;
    /* This usually indicate a memory leak or resource leak.
     * We assert in debug build */
    if (CNode->TotalUsed >= CNodeSize) {
	MmDbgDumpCNode(CNode);
	assert(FALSE);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Starting from the RecentFree bit, search for
     * consecutive free slots of the required number.
     * If Index exceeds CNodeSize, wrap back to 0. */
    ULONG Index = CNode->RecentFree;
    ULONG MaxIndex = CNodeSize + CNode->RecentFree;

Lookup:
    /* Skip the bits that are used */
    while (Index < MaxIndex) {
	if (!GetBit(CNode->UsedMap, Index & CNodeMask)) {
	    break;
	}
	Index++;
    }
    /* We don't have enough free slots. This usually indicate a memory
     * leak or resource leak. We assert in debug build. */
    if (Index >= MaxIndex) {
	MmDbgDumpCNode(CNode);
	assert(FALSE);
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Check whether the next (NumberRequested-1) bits are
     * free (the bit pointed by Index is already free) */
    for (ULONG i = 1; i < NumberRequested; i++) {
	Index++;
	if (GetBit(CNode->UsedMap, Index & CNodeMask)) {
	    /* Not enough consecutive free bits here, go back */
	    goto Lookup;
	}
    }
    /* We found enough free slots. Index now points to the last bit
     * in the consecutive free slots. However, it might be the case
     * that Index & CNodeMask has wrapped back to zero while the index
     * to the first bit (Index-NumberRequested+1) has not, and the
     * slots are not actually consecutive. Go back in this case. */
    if ((Index-NumberRequested+1) < CNodeSize && Index >= CNodeSize) {
	goto Lookup;
    }
    /* We found enough free slots that are actually consecutive.
     * Mark them as used and return them to the user. */
    CNode->TotalUsed += NumberRequested;
    *StartCap = (Index-NumberRequested+1) & CNodeMask;
    for (ULONG i = Index-NumberRequested+1; i <= Index; i++) {
	assert(!GetBit(CNode->UsedMap, i & CNodeMask)); /* Bug if asserted. */
	SetBit(CNode->UsedMap, i & CNodeMask);
    }
    /* To speed up lookup, we advance the RecentFree to point to
     * the bit after Index, since the old RecentFree no longer
     * points to a free bit. */
    CNode->RecentFree = (Index+1) & CNodeMask;

    MmDbg("Allocated %d cap(s) starting 0x%zx\n", NumberRequested, *StartCap);
    return STATUS_SUCCESS;
}

/* Mark the capability slot of the given CNode as free */
VOID MmDeallocateCap(IN PCNODE CNode,
		     IN MWORD Cap)
{
    assert(CNode != NULL);
    assert(Cap < (1ULL << CNode->Log2Size));
    assert(CNode->UsedMap != NULL);
    assert(GetBit(CNode->UsedMap, Cap) == TRUE);
    assert(Cap != 0);		/* Freeing the null cap is a bug. */
    MmDbg("Decallocating 0x%zx\n", Cap);

    ClearBit(CNode->UsedMap, Cap);
    CNode->RecentFree = Cap;
    CNode->TotalUsed--;
}

/*
 * Request a suitably sized untyped memory and retype it into a CNode
 * object, allocating the required book-keeping information on ExPool
 */
NTSTATUS MmCreateCNode(IN ULONG Log2Size,
		       OUT PCNODE *pCNode)
{
    assert(pCNode != NULL);

    PUNTYPED Untyped = NULL;
    ULONG Log2SizeUntyped = Log2Size + LOG2SIZE_PER_CNODE_SLOT;
    RET_ERR(MmRequestUntyped(Log2SizeUntyped, &Untyped));
    assert(Untyped->TreeNode.CSpace == &MiNtosCNode);

    MiAllocatePoolEx(CNode, CNODE, MmReleaseUntyped(Untyped));
    MiAllocateArray(UsedMap, MWORD, (MWORD)((1ULL << Log2Size) / MWORD_BITS),
		    {
			MmReleaseUntyped(Untyped);
			MiFreePool(CNode);
		    });
    MiInitializeCNode(CNode, 0, Log2Size, Log2Size, &MiNtosCNode, NULL, UsedMap);
    RET_ERR_EX(MmRetypeIntoObject(Untyped, seL4_CapTableObject,
				  Log2Size, &CNode->TreeNode),
	       {
		   MiFreePool(UsedMap);
		   MmReleaseUntyped(Untyped);
	       });
    *pCNode = CNode;

    return STATUS_SUCCESS;
}

/*
 * Delete the capability of the specified CNode and release its untyped memory
 * for reuse. Delete its book-keeping information.
 *
 * The initial root task CNode should never be destroyed.
 */
VOID MmDeleteCNode(IN PCNODE CNode)
{
    /* A CNode should always be the leaf node of a capability derivation tree.
     * On debug build we assert if this requirement has not been maintained. */
    assert(!MmCapTreeNodeHasChildren(&CNode->TreeNode));
    /* We should never delete the root task CNode */
    assert(CNode != &MiNtosCNode);
    /* All CNode are retyped from the untyped memory, so must have a parent */
    assert(CNode->TreeNode.Parent != NULL);
    /* The parent of a CNode should always be an untyped. */
    assert(CNode->TreeNode.Parent->Type == CAP_TREE_NODE_UNTYPED);

    MiFreePool(CNode->UsedMap);
    /* Delete the cap tree node. This will release the untyped cap from which
     * the cnode cap is derived. */
    MmCapTreeDeleteNode(&CNode->TreeNode);
    /* Free the pool memory of the CNode structure */
    MiFreePool(CNode);
}

/*
 * Copy a capability into a new slot in the root task's CSpace, setting
 * the access rights of the new capability
 */
static NTSTATUS MiCopyCap(IN PCNODE DestCSpace,
			  IN MWORD DestCap,
			  IN PCNODE SrcCSpace,
			  IN MWORD SrcCap,
			  IN seL4_CapRights_t NewRights)
{
    assert(DestCSpace != NULL);
    assert(DestCSpace->TreeNode.Cap != 0);
    assert(SrcCSpace != NULL);
    assert(SrcCSpace->TreeNode.Cap != 0);
    assert(DestCap != 0);
    assert(SrcCap != 0);
    int Error = seL4_CNode_Copy(DestCSpace->TreeNode.Cap, DestCap, DestCSpace->Depth,
				SrcCSpace->TreeNode.Cap, SrcCap, SrcCSpace->Depth,
				NewRights);

    if (Error != 0) {
	MmDbg("CNode_Copy(0x%zx, 0x%zx, %d, 0x%zx, 0x%zx, %d, 0x%zx) failed with error %d\n",
	      DestCSpace->TreeNode.Cap, DestCap, DestCSpace->Depth,
	      SrcCSpace->TreeNode.Cap, SrcCap, SrcCSpace->Depth,
	      NewRights.words[0], Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS MiMintCap(IN PCNODE DestCSpace,
			  IN MWORD DestCap,
			  IN PCNODE SrcCSpace,
			  IN MWORD SrcCap,
			  IN seL4_CapRights_t Rights,
			  IN MWORD Badge)
{
    assert(DestCSpace != NULL);
    assert(DestCSpace->TreeNode.Cap != 0);
    assert(SrcCSpace != NULL);
    assert(SrcCSpace->TreeNode.Cap != 0);
    assert(DestCap != 0);
    assert(SrcCap != 0);
    int Error = seL4_CNode_Mint(DestCSpace->TreeNode.Cap, DestCap, DestCSpace->Depth,
				SrcCSpace->TreeNode.Cap, SrcCap, SrcCSpace->Depth,
				Rights, Badge);

    if (Error != 0) {
	MmDbg("CNode_Mint(0x%zx, 0x%zx, %d, 0x%zx, 0x%zx, %d, 0x%zx, 0x%zx) failed with error %d\n",
	      DestCSpace->TreeNode.Cap, DestCap, DestCSpace->Depth,
	      SrcCSpace->TreeNode.Cap, SrcCap, SrcCSpace->Depth,
	      Rights.words[0], Badge, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

/*
 * Invoke seL4_CNode_Delete on a cap node.
 *
 * Note: for a TCB or CNODE cap, this will delete all the caps in the CNODE
 * or TCB. Otherwise, it only delete the cap itself (but not its CDT children).
 */
static NTSTATUS MiDeleteCap(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    PCNODE CSpace = Node->CSpace;
    MmDbg("Deleting cap 0x%zx for cspace 0x%zx\n", Node->Cap, CSpace->TreeNode.Cap);
    int Error = seL4_CNode_Delete(CSpace->TreeNode.Cap, Node->Cap, CSpace->Depth);
    if (Error != 0) {
	MmDbg("CNode_Delete(0x%zx, 0x%zx, %d) failed with error %d\n",
	      CSpace->TreeNode.Cap, Node->Cap, CSpace->Depth, Error);
	KeDbgDumpIPCError(Error);
	/* This should always succeed. On debug build we assert if it didn't. */
	assert(FALSE);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

/*
 * Invoke seL4_CNode_Revoke on a cap node. This will recursively delete
 * all the derived capabilities of the given cap but not the cap itself.
 */
static NTSTATUS MiRevokeCap(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    PCNODE CSpace = Node->CSpace;
    int Error = seL4_CNode_Revoke(CSpace->TreeNode.Cap, Node->Cap, CSpace->Depth);
    MmDbg("Revoking cap 0x%zx for cspace 0x%zx\n", Node->Cap, CSpace->TreeNode.Cap);
    if (Error != 0) {
	MmDbg("CNode_Revoke(0x%zx, 0x%zx, %d) failed with error %d\n",
	      CSpace->TreeNode.Cap, Node->Cap, CSpace->Depth, Error);
	KeDbgDumpIPCError(Error);
	/* This should always succeed. On debug build we assert if it didn't. */
	assert(FALSE);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

/*
 * Detach the cap node from its cap tree parent and invoke CNode_Delete
 * on the cap node. If the node has any cap tree children, the children
 * are re-parented as the children of the parent of the cap node. Finally,
 * if the parent is an untyped node and the untyped node now has no children,
 * we release the untyped node. This will recursively merge all unused
 * adjacent untyped caps.
 */
VOID MmCapTreeDeleteNode(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    MmDbg("Before deleting cap 0x%zx\n", Node->Cap);
    if (Node->Parent != NULL) {
	MmDbgDumpCapTree(Node->Parent, 0);
    } else {
	MmDbgDumpCapTree(Node, 0);
    }
    MiDeleteCap(Node);
    MmDeallocateCap(Node->CSpace, Node->Cap);
    Node->Cap = 0;
    PCAP_TREE_NODE Parent = Node->Parent;
    if (Parent != NULL) {
	MiCapTreeRemoveFromParent(Node);
    }
    CapTreeLoopOverChildren(Child, Node) {
	MiCapTreeRemoveFromParent(Child);
	if (Parent != NULL) {
	    MiCapTreeNodeSetParent(Child, Parent);
	}
    }
    MmDbg("After deletion: ");
    if (Parent != NULL) {
	MmDbgDumpCapTree(Parent, 0);
    } else {
	MmDbg("Node had no parent\n");
    }
    /* If the parent cap tree node is an untyped cap and it has no children,
       release it */
    if (Parent != NULL && Parent->Type == CAP_TREE_NODE_UNTYPED
	&& !MmCapTreeNodeHasChildren(Parent)) {
	MmReleaseUntyped(TREE_NODE_TO_UNTYPED(Parent));
    }
}

static VOID MiCapTreeDeallocateCapRecursively(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    MmDeallocateCap(Node->CSpace, Node->Cap);
    Node->Cap = 0;
    CapTreeLoopOverChildren(Child, Node) {
	MiCapTreeDeallocateCapRecursively(Child);
    }
}

/*
 * Invoke CNode_Revoke on the node cap and deallocate the cap slots of all its
 * cap tree descendants (but not the node itself). Note that we don't modify
 * the cap tree structure itself as this would prevent the upstream caller from
 * accessing the children.
 */
VOID MiCapTreeRevokeNode(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    /* This should always succeed. On debug build we assert if it didn't. */
    UNUSED NTSTATUS Status = MiRevokeCap(Node);
    assert(NT_SUCCESS(Status));
    CapTreeLoopOverChildren(Child, Node) {
	MiCapTreeDeallocateCapRecursively(Child);
    }
}

/*
 * Allocate a new cap slot and copy the old cap into the new cap slot.
 * The new node must have already been initialized (via MmInitializeCapTreeNode)
 * with the desired CSpace to copy the old cap into.
 *
 * IMPORTANT NOTES:
 *
 * The way that seL4 builds capability derivation trees is quite subtle
 * in certain cases: for instance, if an original cap to an object (the
 * cap that you get from Untyped_Retype) is copied, the new cap is a CDT
 * (capability derivation tree) child of the original cap. However, further
 * copies of both the original cap and the copy would create siblings of
 * the copied cap (ie. children of the original cap). This however does
 * not apply to untyped caps. Copying an untyped cap always creates a CDT
 * child of the untyped cap. Additionally, once an untyped cap has a CDT
 * child it cannot be derived any further. This implies that if one copies
 * Untyped0 to Untyped1, further attempts to copy Untyped0 will result
 * in error (IPC Error code 9: Revoke first). Likewise, trying to retype
 * the original cap Untyped0 will result in IPC error 10: Not enough memory
 * once it has been copied to Untyped1.
 *
 * One further exception to the general rule above is that IPC endpoints
 * and notification caps both support an additional layer of capability
 * derivation tree, via the badged cap. Badging an endpoint or notification
 * creates a CDT child node of the original unbadged cap node. See the
 * comments in MmCapTreeDeriveBadgedNode for details.
 *
 * In NeptuneOS, to simplify system construction we explicitly disallow
 * copying untyped caps. Furthermore, since copying the original cap
 * creates children, while copying the derived cap creates siblings, we
 * need to distinguish original caps from their copies. This can be done
 * by noting that for unbadged caps, the original cap must be the sole
 * descendant of an untyped cap, while the derived cap must be a descendant
 * of a typed cap (ie. any cap that is not an untyped cap). For badged caps,
 * the original cap must be a descendant of an unbadged cap of the same type,
 * while further copies of the badged cap are descendants of a badged cap
 * of the same type.
 *
 * The simple rules above to distinguish original caps are in fact NOT
 * correct after the original cap node has been deleted, in which case
 * copying a derived cap will create a child node of the derived node (instead
 * of a sibling). This is only problematic when we try to revoke the derived
 * node (it would not work since the original cap has been deleted. Revoking
 * only works on original caps). In practice the only time we call revoke
 * is on untyped caps (in MmReleaseUntyped), so this is not a problem.
 */
NTSTATUS MmCapTreeCopyNode(IN PCAP_TREE_NODE NewNode,
			   IN PCAP_TREE_NODE OldNode,
			   IN seL4_CapRights_t NewRights)
{
    assert(NewNode != NULL);
    assert(OldNode != NULL);
    assert(NewNode->CSpace != NULL);
    assert(OldNode->CSpace != NULL);
    assert(NewNode->Cap == 0);
    /* We never copy untyped caps so OldNode always have a parent */
    assert(OldNode->Parent != NULL);
    /* NewNode cannot have a parent */
    assert(NewNode->Parent == NULL);
    /* We explicitly disallow copying untyped caps */
    assert(OldNode->Type != CAP_TREE_NODE_UNTYPED);
    /* We also explicitly disallow copying cnode caps because we never
     * need to do that. */
    assert(OldNode->Type != CAP_TREE_NODE_CNODE);

    MWORD NewCap = 0;
    RET_ERR(MmAllocateCapRange(NewNode->CSpace, &NewCap, 1));
    assert(NewCap != 0);

    RET_ERR_EX(MiCopyCap(NewNode->CSpace, NewCap, OldNode->CSpace,
			 OldNode->Cap, NewRights),
	       MmDeallocateCap(NewNode->CSpace, NewCap));
    NewNode->Cap = NewCap;
    NewNode->Type = OldNode->Type;

    /* Check whether the old node is an original cap */
    BOOLEAN AddAsSibling = (OldNode->Badge == 0) ?
	(OldNode->Parent->Type != CAP_TREE_NODE_UNTYPED) :
	(OldNode->Parent->Badge != 0);
    /* For badged node the parent should have the same node type */
    assert(OldNode->Badge == 0 || OldNode->Parent->Type == OldNode->Type);

    if (AddAsSibling) {
	/* Make sure the old node has the same type as its parent */
	assert(OldNode->Parent->Type == OldNode->Type);
	/* Add new node as the sibling of the old node */
	MiCapTreeNodeSetParent(NewNode, OldNode->Parent);
    } else {
	/* Add new node as the child of the old node. */
	MiCapTreeNodeSetParent(NewNode, OldNode);
    }

    return STATUS_SUCCESS;
}

/*
 * Allocate a cap slot and mint the old node into the new cap slot
 * with a new badge.
 *
 * We enforce the following rules:
 *
 *   1. Badge cannot be zero. To derive into an unbadged node, use
 *      MmCapTreeCopyNode.
 *   2. The old node must not have already been badged.
 *   3. Only IPC endpoint and notification caps can be badged.
 *   4. Only the original cap can be badged. In other words, if you
 *      copy original endpoint cap Ep0 to Ep1, you cannot badge Ep1.
 *      This is not a seL4 restriction but to simplify our algorithms.
 *
 * See also comments on MmCapTreeCopyNode. As opposed to copying a
 * node, badging a node always creates a CDT child node of the original
 * unbadged node.
 */
NTSTATUS MmCapTreeDeriveBadgedNode(IN PCAP_TREE_NODE NewNode,
				   IN PCAP_TREE_NODE OldNode,
				   IN seL4_CapRights_t NewRights,
				   IN MWORD Badge)
{
    assert(NewNode != NULL);
    assert(OldNode != NULL);
    assert(OldNode->Type == CAP_TREE_NODE_ENDPOINT ||
	   OldNode->Type == CAP_TREE_NODE_NOTIFICATION);
    assert(NewNode->CSpace != NULL);
    assert(OldNode->CSpace != NULL);
    assert(NewNode->Cap == 0);
    assert(OldNode->Badge == 0);
    assert(NewNode->Badge == 0);
    assert(OldNode->Parent != NULL);
    assert(OldNode->Parent->Type == CAP_TREE_NODE_UNTYPED);
    assert(NewNode->Parent == NULL || NewNode->Parent == OldNode);
    assert(Badge != 0);

    MWORD NewCap = 0;
    RET_ERR(MmAllocateCapRange(NewNode->CSpace, &NewCap, 1));
    assert(NewCap != 0);

    RET_ERR_EX(MiMintCap(NewNode->CSpace, NewCap, OldNode->CSpace,
			 OldNode->Cap, NewRights, Badge),
	       MmDeallocateCap(NewNode->CSpace, NewCap));
    NewNode->Cap = NewCap;
    NewNode->Type = OldNode->Type;
    NewNode->Badge = Badge;

    /* Add new node as the child of the old node. Note that since we
     * disallow badging derived nodes, the badged node is always the
     * CDT child of the unbadged node. (If we instead allow badging
     * derived nodes, we need to perform the same algorithm as in
     * MmCapTreeCopyNode to determine if the unbadged node is the
     * original cap or a derived cap.) */
    if (NewNode->Parent == NULL) {
	MiCapTreeNodeSetParent(NewNode, OldNode);
    }

    return STATUS_SUCCESS;
}
