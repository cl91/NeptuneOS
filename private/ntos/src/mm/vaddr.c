/* Routines for virtual address space management */

#include "mi.h"

VOID MmInitializeVaddrSpace(IN PVIRT_ADDR_SPACE Self,
			    IN MWORD VSpaceCap)
{
    Self->VSpaceCap = VSpaceCap;
    Self->ASIDPool = 0;
    Self->CachedVad = NULL;
    MiAvlInitializeTree(&Self->VadTree);
    MiInitializePagingStructure(&Self->RootPagingStructure, NULL, NULL, VSpaceCap,
				VSpaceCap, 0, PAGING_TYPE_ROOT_PAGING_STRUCTURE,
				TRUE, MM_RIGHTS_RW);
}

/*
 * Search for an ASID pool with a free ASID slot and assign an ASID
 * for the virtual address space. An ASID must be assigned before the
 * virtual address space can be used for mapping.
 */
NTSTATUS MmAssignASID(IN PVIRT_ADDR_SPACE VaddrSpace)
{
    /* TODO: Create ASID pool if not enough ASID slots */
    int Error = seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool,
					 VaddrSpace->VSpaceCap);

    if (Error != 0) {
	return SEL4_ERROR(Error);
    }

    VaddrSpace->ASIDPool = seL4_CapInitThreadASIDPool;
    return STATUS_SUCCESS;
}

/* Returns TRUE if the supplied VAD node overlaps with the address window */
static inline BOOLEAN MiVadNodeOverlapsAddrWindow(IN PVAD Node,
						  IN MWORD VirtAddr,
						  IN MWORD WindowSize)
{
    return MiAvlNodeOverlapsAddrWindow(&Node->AvlNode, Node->WindowSize,
				       VirtAddr, WindowSize);
}

/* Returns TRUE if two VAD nodes have non-zero overlap */
static inline BOOLEAN MiVadNodeOverlapsVad(IN PVAD Node0,
					   IN PVAD Node1)
{
    return MiVadNodeOverlapsAddrWindow(Node0, Node1->AvlNode.Key, Node1->WindowSize);
}

/*
 * Insert the given VAD node into the virtual address space
 */
static NTSTATUS MiVSpaceInsertVadNode(IN PVIRT_ADDR_SPACE VSpace,
				      IN PVAD VadNode)
{
    PMM_AVL_TREE Tree = &VSpace->VadTree;
    PMM_AVL_NODE ParentNode = MiAvlTreeFindNodeOrParent(Tree, VadNode->AvlNode.Key);
    PVAD ParentVad = MM_AVL_NODE_TO_VAD(ParentNode);

    /* Vad nodes within a VAD tree should never overlap. Is a bug if it does. */
    if (ParentVad != NULL && MiVadNodeOverlapsVad(VadNode, ParentVad)) {
	return STATUS_NTOS_BUG;
    }
    MiAvlTreeInsertNode(Tree, ParentNode, &VadNode->AvlNode);
    return STATUS_SUCCESS;
}

/*
 * Returns the VAD node that overlaps with the supplied address window.
 * If multiple VADs overlap with the given address window, return the VAD
 * with the lowest address.
 */
static PVAD MiVSpaceFindOverlappingVadNode(IN PVIRT_ADDR_SPACE VSpace,
					      IN MWORD VirtAddr,
					      IN MWORD WindowSize)
{
    PMM_AVL_TREE Tree = &VSpace->VadTree;
    if (VSpace->CachedVad != NULL &&
	MiVadNodeOverlapsAddrWindow(VSpace->CachedVad, VirtAddr, WindowSize)) {
	return VSpace->CachedVad;
    }
    PVAD Parent = MM_AVL_NODE_TO_VAD(MiAvlTreeFindNodeOrParent(Tree, VirtAddr));
    if (Parent != NULL && MiVadNodeOverlapsAddrWindow(Parent, VirtAddr, WindowSize)) {
	VSpace->CachedVad = Parent;
	return Parent;
    }
    return NULL;
}

NTSTATUS MmReserveVirtualMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				  IN MWORD VirtAddr,
				  IN MWORD WindowSize)
{
    assert(IS_PAGE_ALIGNED(VirtAddr));
    if (MiVSpaceFindOverlappingVadNode(VSpace, VirtAddr, WindowSize) != NULL) {
	/* Enlarge VAD? */
	return STATUS_INVALID_PARAMETER;
    }

    MiAllocatePool(Vad, VAD);
    MiInitializeVadNode(Vad, VirtAddr, WindowSize);
    MiVSpaceInsertVadNode(VSpace, Vad);
    return STATUS_SUCCESS;
}
