#include "../tests.h"

VOID MmRunAvlTreeTests();
VOID MmRunUntypedTests();

static inline NTSTATUS MiTestMapPage(IN MWORD PageCap,
				     IN MWORD Addr,
				     IN PAGING_RIGHTS Rights)
{
    int Error = seL4_Page_Map(PageCap,
			      NTOS_VSPACE_CAP,
			      Addr,
			      Rights,
			      MM_ATTRIBUTES_DEFAULT);
    if (Error != 0) {
	DbgTrace("seL4_Page_Map(%zd, %d, 0x%zx, 0x%zx, 0x%zx) failed with error %d\n",
		 PageCap, NTOS_VSPACE_CAP, Addr, Rights.words[0],
		 MM_ATTRIBUTES_DEFAULT, Error);
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static inline NTSTATUS MiTestDeleteCap(IN PCAP_TREE_NODE Node)
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

static inline NTSTATUS MiTestRevokeCap(IN PCAP_TREE_NODE Node)
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

/*
 * This test runs the following procedure:
 *
 *   1. Create a 4K page Page0 and map it
 *   2. Copy Page0 cap into Page1
 *   3. Copy Page1 into Page2 with read-only rights
 *   4. Copy Page2 into Page3 and map Page3
 *   6. Delete Page0
 *   7. Delete Page1
 *   8. Try to access Page3
 *   9. Delete Page 2 and try to access Page 3
 *
 * The point here is to demonstrate that creating a copy of the original
 * cap creates a cap tree child node of the original node, and further
 * copy creates siblings of the derived node (ie. children of the original
 * cap). Revoking the original cap deletes all children. However, deleting
 * the original node simply deletes the original cap and does NOT delete
 * the cap tree children. Instead the children are simply re-parented as
 * children of the parent of the original cap.
 */
NTSTATUS MmRunPagingTests()
{
    PUNTYPED Untyped0 = NULL;
    RET_ERR(MmRequestUntyped(PAGE_LOG2SIZE, &Untyped0));
    CAP_TREE_NODE Untyped1, Untyped2, Page0, Page1, Page2, Page3;
    memset(&Untyped1, 0, sizeof(CAP_TREE_NODE));
    memset(&Untyped2, 0, sizeof(CAP_TREE_NODE));
    memset(&Page0, 0, sizeof(CAP_TREE_NODE));
    memset(&Page1, 0, sizeof(CAP_TREE_NODE));
    memset(&Page2, 0, sizeof(CAP_TREE_NODE));
    memset(&Page3, 0, sizeof(CAP_TREE_NODE));
    MmInitializeCapTreeNode(&Untyped1, CAP_TREE_NODE_UNTYPED,
			    0, Untyped0->TreeNode.CSpace, NULL);
    MmInitializeCapTreeNode(&Untyped2, CAP_TREE_NODE_UNTYPED,
			    0, Untyped0->TreeNode.CSpace, NULL);
    MmInitializeCapTreeNode(&Page0, CAP_TREE_NODE_PAGING_STRUCTURE,
			    0, Untyped0->TreeNode.CSpace, NULL);
    MmInitializeCapTreeNode(&Page1, CAP_TREE_NODE_PAGING_STRUCTURE,
			    0, Untyped0->TreeNode.CSpace, NULL);
    MmInitializeCapTreeNode(&Page2, CAP_TREE_NODE_PAGING_STRUCTURE,
			    0, Untyped0->TreeNode.CSpace, NULL);
    MmInitializeCapTreeNode(&Page3, CAP_TREE_NODE_PAGING_STRUCTURE,
			    0, Untyped0->TreeNode.CSpace, NULL);
    /* If we uncomment this, we get an error when we retype untyped0 into
     * page0, with error "IPC Error code 10 (Not enough memory)". */
//    RET_ERR(MmCapTreeCopyNode(&Untyped1, &Untyped0->TreeNode, seL4_AllRights));
    /* If we change the following to copy Untyped0 into Untyped 2, we get an
     * error "IPC Error code 9 (Revoke first)". */
//    RET_ERR(MmCapTreeCopyNode(&Untyped2, &Untyped1, seL4_AllRights));
    RET_ERR(MmRetypeIntoObject(Untyped0, PAGING_TYPE_PAGE,
			       PAGE_LOG2SIZE, &Page0));
    RET_ERR(MiTestMapPage(Page0.Cap, HYPERSPACE_START, seL4_AllRights));
    *((MWORD *)HYPERSPACE_START) = 0xdeadbeef;
    DbgTrace("Data word is 0x%zx\n", *((MWORD *)HYPERSPACE_START));
    RET_ERR(MmCapTreeCopyNode(&Page1, &Page0, seL4_AllRights));
    RET_ERR(MiTestMapPage(Page1.Cap, HYPERSPACE_START + PAGE_SIZE, seL4_AllRights));
    *((MWORD *)(HYPERSPACE_START + PAGE_SIZE)) = 0xabcdefff;
    DbgTrace("Data word is 0x%zx\n", *((MWORD *)HYPERSPACE_START));
    RET_ERR(MmCapTreeCopyNode(&Page2, &Page1, seL4_CanRead));
    RET_ERR(MiTestMapPage(Page2.Cap, HYPERSPACE_START + 2*PAGE_SIZE, seL4_AllRights));
    /* Deleting the original cap does NOT delete the CDT (capability derivation tree) children. */
    RET_ERR(MiTestDeleteCap(&Page0));
    /* Now if we revoke Page0, it does nothing because Page0 has been deleted.
     * However, it does not generate an error. */
    RET_ERR(MiTestRevokeCap(&Page0));
    RET_ERR(MiTestRevokeCap(&Page1));
    RET_ERR(MmCapTreeCopyNode(&Page3, &Page2, seL4_AllRights));
    RET_ERR(MiTestMapPage(Page3.Cap, HYPERSPACE_START + 3*PAGE_SIZE, seL4_AllRights));
    RET_ERR(MiTestRevokeCap(&Page2));
    /* If we revoke the untyped cap, all its CDT children will be deleted.
     * However, deleting the untyped cap does NOT delete any of its CDT children. */
    RET_ERR(MiTestDeleteCap(&Untyped0->TreeNode));
    DbgTrace("Data word is 0x%zx\n", *((MWORD *)(HYPERSPACE_START + 2*PAGE_SIZE)));
    DbgTrace("Data word is 0x%zx\n", *((MWORD *)(HYPERSPACE_START + 3*PAGE_SIZE)));
    DbgTrace("Success.\n");
    return STATUS_SUCCESS;
}

VOID MmRunTests()
{
//    MmRunAvlTreeTests();
//    MmRunUntypedTests();
    BUGCHECK_IF_ERR(MmRunPagingTests());
}
