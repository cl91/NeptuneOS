/*++

Copyright (c) 2077  Definitely-Not-Micro$oft Corporation

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

/* Change this to 0 to enable debug tracing */
#if 1
#undef DbgTrace
#define DbgTrace(...)
#define DbgPrint(...)
#else
#include <dbgtrace.h>
#endif

#ifdef CONFIG_DEBUG_BUILD
VOID MmDbgDumpCapTreeNode(IN PCAP_TREE_NODE Node)
{
    if (Node == NULL) {
	DbgPrint("(nil)");
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
    DbgPrint("Cap 0x%zx (Type %s seL4 Cap %s)", Node->Cap, Type, CapType);
}

VOID MmDbgDumpCNode(IN PCNODE CNode)
{
    DbgTrace("Dumping CNode %p\n", CNode);
    DbgPrint("    TREE-NODE ");
    MmDbgDumpCapTreeNode(&CNode->TreeNode);
    DbgPrint("\n    Log2Size %d  Depth %d\n  TotalUsed %d\n    UsedMap",
	     CNode->Log2Size, CNode->Depth, CNode->TotalUsed);
    for (ULONG i = 0; i < (1 << CNode->Log2Size) / MWORD_BITS; i++) {
	DbgPrint("  %p", (PVOID)CNode->UsedMap[i]);
    }
    DbgPrint("\n");
}

#define MI_DBG_CAP_TREE_INDENTATION	2

VOID MmDbgDumpCapTree(IN PCAP_TREE_NODE Node,
		      IN LONG Indentation)
{
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Node %p, CL.FL %p CL.BL %p SL.FL %p SL.BL %p   ",
	     Node, Node->ChildrenList.Flink, Node->ChildrenList.Blink,
	     Node->SiblingLink.Flink, Node->SiblingLink.Blink);
    MmDbgDumpCapTreeNode(Node);
    DbgPrint("\n");
    LoopOverList(Child, &Node->ChildrenList, CAP_TREE_NODE, SiblingLink) {
	MmDbgDumpCapTree(Child, Indentation + MI_DBG_CAP_TREE_INDENTATION);
    }
}
#endif

/* Allocate a continuous range of capability slots */
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
    /* The parent of a CNode should always be an untyped. BUG! */
    assert(CNode->TreeNode.Parent->Type == CAP_TREE_NODE_UNTYPED);

    MiFreePool(CNode->UsedMap);
    /* This will free the CNode struct itself from the ExPool */
    MmReleaseUntyped(TREE_NODE_TO_UNTYPED(CNode->TreeNode.Parent));
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
	DbgTrace("CNode_Copy(0x%zx, 0x%zx, %d, 0x%zx, 0x%zx, %d, 0x%zx) failed with error %d\n",
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
	DbgTrace("CNode_Mint(0x%zx, 0x%zx, %d, 0x%zx, 0x%zx, %d, 0x%zx, 0x%zx) failed with error %d\n",
		 DestCSpace->TreeNode.Cap, DestCap, DestCSpace->Depth,
		 SrcCSpace->TreeNode.Cap, SrcCap, SrcCSpace->Depth,
		 Rights.words[0], Badge, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

/*
 * Invoke seL4_CNode_Delete on a cap node. This will recursively delete
 * all the derived capabilities of the given cap in addition to the node
 * itself.
 *
 * NOTE: CNode_Revoke will delete all the derived caps but not the cap
 * itself. CNode_Delete will delete the cap itself as well as all its
 * children.
 */
static NTSTATUS MiDeleteCap(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    PCNODE CSpace = Node->CSpace;
    int Error = seL4_CNode_Delete(CSpace->TreeNode.Cap, Node->Cap, CSpace->Depth);
    if (Error != 0) {
	DbgTrace("CNode_Delete(0x%zx, 0x%zx, %d) failed with error %d\n",
		 CSpace->TreeNode.Cap, Node->Cap, CSpace->Depth, Error);
	KeDbgDumpIPCError(Error);
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
    if (Error != 0) {
	DbgTrace("CNode_Revoke(0x%zx, 0x%zx, %d) failed with error %d\n",
		 CSpace->TreeNode.Cap, Node->Cap, CSpace->Depth, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static VOID MiCapTreeDeallocateCap(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    MmDeallocateCap(Node->CSpace, Node->Cap);
    Node->Cap = 0;
    LoopOverList(Child, &Node->ChildrenList, CAP_TREE_NODE, SiblingLink) {
	MiCapTreeDeallocateCap(Child);
    }
}

/*
 * Invoke CNode_Delete on the node cap and deallocate the node cap and all its cap
 * tree descendants. Note that we don't modify the cap tree structure itself as this
 * would prevent the upstream caller from accessing the children.
 */
VOID MmCapTreeDeleteNode(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    /* This should always succeed. On debug build we assert if it didn't. */
    NTSTATUS Status = MiDeleteCap(Node);
    assert(NT_SUCCESS(Status));
    MiCapTreeDeallocateCap(Node);
}

/*
 * Invoke CNode_Revoke on the node cap and deallocate the cap slots of all its
 * cap tree descendants (but not the node itself). Note that we don't modify
 * the cap tree structure itself as this would prevent the upstream caller from
 * accessing the children.
 */
VOID MmCapTreeRevokeNode(IN PCAP_TREE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CSpace != NULL);
    assert(Node->Cap);
    /* This should always succeed. On debug build we assert if it didn't. */
    NTSTATUS Status = MiRevokeCap(Node);
    assert(NT_SUCCESS(Status));
    LoopOverList(Child, &Node->ChildrenList, CAP_TREE_NODE, SiblingLink) {
	MiCapTreeDeallocateCap(Child);
    }
}

NTSTATUS MmCapTreeDeriveBadgedNode(IN PCAP_TREE_NODE NewNode,
				   IN PCAP_TREE_NODE OldNode,
				   IN seL4_CapRights_t NewRights,
				   IN MWORD Badge)
{
    assert(NewNode != NULL);
    assert(OldNode != NULL);
    assert(NewNode->CSpace != NULL);
    assert(OldNode->CSpace != NULL);
    assert(NewNode->Cap == 0);
    assert(NewNode->Parent == NULL || NewNode->Parent == OldNode);

    MWORD NewCap = 0;
    RET_ERR(MmAllocateCapRange(NewNode->CSpace, &NewCap, 1));
    assert(NewCap != 0);

    if (Badge == 0) {
	RET_ERR_EX(MiCopyCap(NewNode->CSpace, NewCap, OldNode->CSpace,
			     OldNode->Cap, NewRights),
		   MmDeallocateCap(NewNode->CSpace, NewCap));
    } else {
	RET_ERR_EX(MiMintCap(NewNode->CSpace, NewCap, OldNode->CSpace,
			     OldNode->Cap, NewRights, Badge),
		   MmDeallocateCap(NewNode->CSpace, NewCap));
    }
    NewNode->Cap = NewCap;
    NewNode->Type = OldNode->Type;

    /* Add new node as the child of the old node. */
    if (NewNode->Parent == NULL) {
	MmCapTreeNodeSetParent(NewNode, OldNode);
    }

    return STATUS_SUCCESS;
}
