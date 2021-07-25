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
static inline BOOLEAN MiVadNodeOverlapsAddrWindow(IN PMMVAD Node,
						  IN MWORD VirtAddr,
						  IN MWORD WindowSize)
{
    return MiAvlNodeOverlapsAddrWindow(&Node->AvlNode, Node->WindowSize,
				       VirtAddr, WindowSize);
}

/* Returns TRUE if two VAD nodes have non-zero overlap */
static inline BOOLEAN MiVadNodeOverlapsVad(IN PMMVAD Node0,
					   IN PMMVAD Node1)
{
    return MiVadNodeOverlapsAddrWindow(Node0, Node1->AvlNode.Key, Node1->WindowSize);
}

/*
 * Insert the given VAD node into the virtual address space
 */
static NTSTATUS MiVSpaceInsertVadNode(IN PVIRT_ADDR_SPACE VSpace,
				      IN PMMVAD VadNode)
{
    PMM_AVL_TREE Tree = &VSpace->VadTree;
    PMM_AVL_NODE ParentNode = MiAvlTreeFindNodeOrParent(Tree, VadNode->AvlNode.Key);
    PMMVAD ParentVad = MM_AVL_NODE_TO_VAD(ParentNode);

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
static PMMVAD MiVSpaceFindOverlappingVadNode(IN PVIRT_ADDR_SPACE VSpace,
					      IN MWORD VirtAddr,
					      IN MWORD WindowSize)
{
    PMM_AVL_TREE Tree = &VSpace->VadTree;
    if (VSpace->CachedVad != NULL &&
	MiVadNodeOverlapsAddrWindow(VSpace->CachedVad, VirtAddr, WindowSize)) {
	return VSpace->CachedVad;
    }
    PMMVAD Parent = MM_AVL_NODE_TO_VAD(MiAvlTreeFindNodeOrParent(Tree, VirtAddr));
    if (Parent != NULL && MiVadNodeOverlapsAddrWindow(Parent, VirtAddr, WindowSize)) {
	VSpace->CachedVad = Parent;
	return Parent;
    }
    return NULL;
}

NTSTATUS MiReserveVirtualMemory(IN PVIRT_ADDR_SPACE VSpace,
				IN MWORD VirtAddr,
				IN MWORD WindowSize,
				IN MWORD Attribute)
{
    assert(IS_PAGE_ALIGNED(VirtAddr));
    assert(IS_PAGE_ALIGNED(WindowSize));
    if (MiVSpaceFindOverlappingVadNode(VSpace, VirtAddr, WindowSize) != NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    MiAllocatePool(Vad, MMVAD);
    MiInitializeVadNode(Vad, VirtAddr, WindowSize);
    if (Attribute & MEM_PRIVATE) {
	Vad->Flags.PrivateMemory = TRUE;
    }
    MiVSpaceInsertVadNode(VSpace, Vad);
    return STATUS_SUCCESS;
}

/*
 * Allocate private memory of given size and map at given virtual address.
 * If unaligned, address window is expanded to align at page boundary.
 */
NTSTATUS MmAllocatePrivateMemoryEx(IN PVIRT_ADDR_SPACE VSpace,
				   IN MWORD VirtAddr,
				   IN MWORD WindowSize,
				   IN MWORD AllocationType,
				   IN MWORD Protect)
{
    VirtAddr = PAGE_ALIGN(VirtAddr);
    WindowSize = PAGE_ALIGN_UP(WindowSize);

    /* You must either reserve or commit virtual memory */
    if (!(AllocationType & (MEM_COMMIT | MEM_RESERVE))) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Large pages must be committed */
    if ((AllocationType & MEM_LARGE_PAGES) && !(AllocationType & MEM_COMMIT)) {
        return STATUS_INVALID_PARAMETER;
    }

    /* We haven't implemented page access rights yet */
    if ((Protect & PAGE_READWRITE) == 0) {
        return STATUS_NTOS_UNIMPLEMENTED;
    }

    if (AllocationType & MEM_RESERVE) {
	RET_ERR(MiReserveVirtualMemory(VSpace, VirtAddr, WindowSize, MEM_PRIVATE));
    }

    if (AllocationType & MEM_COMMIT) {
	PMMVAD Vad = MiVSpaceFindOverlappingVadNode(VSpace, VirtAddr, WindowSize);
	if (Vad == NULL) {
	    return STATUS_INVALID_PARAMETER;
	}
	/* TODO: Split MMVAD when partially committing a VAD */
	RET_ERR(MiCommitPrivateMemory(VSpace, VirtAddr, WindowSize, MM_RIGHTS_RW,
				      AllocationType & MEM_LARGE_PAGES));
	if (AllocationType & MEM_LARGE_PAGES) {
	    Vad->Flags.LargePages = TRUE;
	}
	Vad->Flags.MemCommit = TRUE;
    }

    return STATUS_SUCCESS;
}

/*
 * Returns the PAGING_STRUCTURE pointer to the page at given virtual address.
 * Returns NULL if virtual address is unmapped.
 */
NTSTATUS MmQueryVirtualAddress(IN PVIRT_ADDR_SPACE VSpace,
			       IN MWORD VirtAddr,
			       OUT PPAGING_STRUCTURE *pPage)
{
    assert(VSpace != NULL);
    assert(pPage != NULL);

    *pPage = NULL;

    PMMVAD Vad = MiVSpaceFindOverlappingVadNode(VSpace, VirtAddr, PAGE_SIZE);
    if (Vad == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    PPAGING_STRUCTURE Paging = &VSpace->RootPagingStructure;

    while (Paging != NULL) {
	if (Paging->Type == PAGING_TYPE_PAGE || Paging->Type == PAGING_TYPE_LARGE_PAGE) {
	    break;
	}
	Paging = MiPagingFindSubstructure(Paging, VirtAddr);
    }

    if (Paging == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    *pPage = Paging;
    return STATUS_SUCCESS;
}

VOID MmDbgDumpVad(PMMVAD Vad)
{
    DbgPrint("Dumping vad at %p\n", Vad);
    if (Vad == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }

    DbgPrint("    vaddr start = %p  window size = 0x%zx\n"
	     "    %s%s%s%s%s\n"
	     "    section = %p\n",
	     (PVOID) Vad->AvlNode.Key, Vad->WindowSize,
	     Vad->Flags.PrivateMemory ? "private memory" : "",
	     Vad->Flags.ImageMap ? ", image map" : "",
	     Vad->Flags.LargePages ? ", large pages" : "",
	     Vad->Flags.MemCommit ? ", committed" : "",
	     Vad->Flags.PhysicalMapping ? ", physical mapping" : "",
	     Vad->Section);
}

VOID MmDbgDumpVSpace(PVIRT_ADDR_SPACE VSpace)
{
    DbgPrint("Dumping virtual address space %p\n", VSpace);
    if (VSpace == NULL) {
	DbgPrint("    (nil)\n");
	return;
    }

    DbgPrint("    vspacecap = 0x%zx    asidpool = 0x%zx\n",
	     VSpace->VSpaceCap, VSpace->ASIDPool);
    DbgPrint("    root paging structure %p:\n", &VSpace->RootPagingStructure);
    MmDbgDumpPagingStructure(&VSpace->RootPagingStructure);
    DbgPrint("    vad tree %p linearly:  ", &VSpace->VadTree);
    MmAvlDumpTreeLinear(&VSpace->VadTree);
    DbgPrint("\n    vad tree %p:\n", &VSpace->VadTree);
    MmAvlDumpTree(&VSpace->VadTree);
    DbgPrint("    vad tree content:\n");
    LoopOverVadTree(Vad, VSpace, MmDbgDumpVad(Vad));
}
