#include "mi.h"

VIRT_ADDR_SPACE MiNtosVaddrSpace;
PHY_MEM_DESCRIPTOR MiPhyMemDescriptor;
CNODE MiNtosCNode;
static MWORD MiNtosCNodeUsedMap[(1 << ROOT_CNODE_LOG2SIZE) / MWORD_BITS] PAGE_ALIGNED_DATA;

static NTSTATUS MiInitRetypeIntoLargePage(IN MWORD Untyped,
					  IN MWORD PageCap)
{
    int Error = seL4_Untyped_Retype(Untyped,
				    PAGING_TYPE_LARGE_PAGE,
				    LARGE_PAGE_LOG2SIZE,
				    ROOT_CNODE_CAP,
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

static NTSTATUS MiInitMapLargePage(IN MWORD Untyped,
				   IN MWORD PageCap,
				   IN MWORD Vaddr)
{
    assert(IS_LARGE_PAGE_ALIGNED(Vaddr));
    RET_ERR(MiInitRetypeIntoLargePage(Untyped, PageCap));

    int Error = seL4_X86_Page_Map(PageCap,
				  ROOT_VSPACE_CAP,
				  Vaddr,
				  MM_RIGHTS_RW,
				  seL4_X86_Default_VMAttributes);

    if (Error) {
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}


/*
 * Split the initial untyped cap until the leaf node is exactly the
 * same size as one large page, taking the left child at every step.
 * The new untyped caps start from the first free cap slot in the
 * root CNode. The total number of new untyped caps equals two times
 * the number of splits needed to split the initial untyped cap into
 * large page size.
 */
static NTSTATUS MiSplitInitialUntyped(IN PMM_INIT_INFO InitInfo)
{
    MWORD DestCap = InitInfo->RootCNodeFreeCapStart;
    MWORD UntypedCap = InitInfo->InitUntypedCap;
    LONG Log2Size = InitInfo->InitUntypedLog2Size;
    LONG NumSplits = Log2Size - LARGE_PAGE_LOG2SIZE;
    for (int i = 0; i < NumSplits; i++) {
	RET_ERR(MiSplitUntypedCap(UntypedCap, Log2Size--, ROOT_CNODE_CAP, DestCap));
	UntypedCap = DestCap;
	DestCap += 2;
    }
    return STATUS_SUCCESS;
}

/*
 * Split the initial untyped, taking left child at every turn,
 * and map the last left child at EX_POOL_START
 */
static NTSTATUS MiInitMapInitialHeap(IN PMM_INIT_INFO InitInfo,
				     OUT MWORD *FreeCapStart)
{
    /* We require one large page to initialize ExPool */
    if (InitInfo->InitUntypedLog2Size < LARGE_PAGE_LOG2SIZE) {
	return STATUS_NO_MEMORY;
    }

    /* Map initial pages for ExPool */
    RET_ERR(MiSplitInitialUntyped(InitInfo));
    LONG NumSplits = InitInfo->InitUntypedLog2Size - LARGE_PAGE_LOG2SIZE;
    MWORD PageUntyped = InitInfo->InitUntypedCap;
    if (NumSplits > 0) {
	PageUntyped = InitInfo->RootCNodeFreeCapStart + 2*NumSplits - 2;
    }
    MWORD PageCap = InitInfo->RootCNodeFreeCapStart + 2*NumSplits;
    RET_ERR(MiInitMapLargePage(PageUntyped, PageCap, EX_POOL_START));

    *FreeCapStart = PageCap + 1;
    return STATUS_SUCCESS;
}

static inline NTSTATUS MiInitCreatePagingStructure(IN PAGING_STRUCTURE_TYPE Type,
						   IN PUNTYPED Untyped,
						   IN MWORD Cap,
						   IN MWORD VirtAddr,
						   OUT PPAGING_STRUCTURE *pPaging)
{
    assert(pPaging != NULL);
    RET_ERR(MiCreatePagingStructure(Type, Untyped, NULL, VirtAddr, ROOT_VSPACE_CAP,
				    MM_RIGHTS_RW, pPaging));
    assert(*pPaging != NULL);
    (*pPaging)->TreeNode.Cap = Cap;
    (*pPaging)->Mapped = TRUE;

    return STATUS_SUCCESS;
}

/*
 * The capability derivation tree after mapping the initial heap is
 *
 *                    (ParentUntyped)				i == 0
 *                    (InitUntypedCap)
 *                      /           \
 *        (LeftChildUntyped)     (RightChilduntyped)            i == 1
 *     (RootCNodeFreeCapStart)  (RootCNodeFreeCapStart+1)
 *            /        \
 *           (L)       (R)                                      i == 2
 *          (CS+2)     (CS+3)      CS == RootCNodeFreeCapStart
 *        ...........
 *       /           \
 *      (L)         (R)                                         i == NS-1
 * (CS+(NS-1)*2) (CS+NS*2-1)       NS == NumSplits
 *       |
 * (LargePageCap)     LargePageCap == CS+NS*2                   i == NS
 *
 *  FreeCapStart == LargePageCap + 1
 */
static NTSTATUS MiInitAddUntypedAndLargePage(IN PMM_INIT_INFO InitInfo)
{
    MiAllocatePool(RootUntyped, UNTYPED);
    MiInitializeUntyped(RootUntyped, &MiNtosCNode, NULL, InitInfo->InitUntypedCap,
			InitInfo->InitUntypedPhyAddr,
			InitInfo->InitUntypedLog2Size, FALSE);

    PUNTYPED ParentUntyped = RootUntyped;
    LONG NumSplits = InitInfo->InitUntypedLog2Size - LARGE_PAGE_LOG2SIZE;
    for (int i = 0; i < NumSplits; i++) {
	MiAllocatePool(LeftChildUntyped, UNTYPED);
	MiAllocatePool(RightChildUntyped, UNTYPED);

	LONG ChildLog2Size = InitInfo->InitUntypedLog2Size - 1 - i;
	MWORD LeftChildCap = InitInfo->RootCNodeFreeCapStart + 2*i;
	MWORD RigthChildCap = LeftChildCap + 1;
	MiInitializeUntyped(LeftChildUntyped, &MiNtosCNode, ParentUntyped,
			    LeftChildCap, InitInfo->InitUntypedPhyAddr,
			    ChildLog2Size, FALSE);
	MiInitializeUntyped(RightChildUntyped, &MiNtosCNode, ParentUntyped, RigthChildCap,
			    InitInfo->InitUntypedPhyAddr + (1 << ChildLog2Size),
			    ChildLog2Size, FALSE);
	MiInsertFreeUntyped(&MiPhyMemDescriptor, RightChildUntyped);
	ParentUntyped = LeftChildUntyped;
    }

    PPAGING_STRUCTURE Page = NULL;
    RET_ERR(MiInitCreatePagingStructure(PAGING_TYPE_LARGE_PAGE, ParentUntyped,
					InitInfo->RootCNodeFreeCapStart + 2 * NumSplits,
					EX_POOL_START, &Page));
    assert(Page != NULL);
    RET_ERR(MiVSpaceInsertPagingStructure(&MiNtosVaddrSpace, Page));
    RET_ERR(MmReserveVirtualMemory(EX_POOL_START, 0, EX_POOL_MAX_SIZE,
				   MEM_RESERVE_OWNED_MEMORY, NULL));
    /* TODO: Commit */

    return STATUS_SUCCESS;
}

/*
 * Add the initial root task user image paging structures to the virtual address
 * space descriptor of the root task.
 *
 * For amd64, the first paging structure cap is the PDPT cap, and the rest are
 * page table caps.
 *
 * Fox i386, the paging structure caps are page table caps.
 */
static NTSTATUS MiInitAddUserImagePaging(IN PMM_INIT_INFO InitInfo)
{
    MWORD StartPageCap = InitInfo->UserImageFrameCapStart;
    MWORD EndPageCap = StartPageCap + InitInfo->NumUserImageFrames;
    MWORD PageTableCapStart = InitInfo->UserPagingStructureCapStart;

#ifdef _M_AMD64
    PPAGING_STRUCTURE PDPT = NULL;
    RET_ERR(MiInitCreatePagingStructure(PAGING_TYPE_PDPT, NULL, PageTableCapStart++,
					InitInfo->UserImageStartVirtAddr, &PDPT));
    assert(PDPT != NULL);
    RET_ERR(MiVSpaceInsertPagingStructure(&MiNtosVaddrSpace, PDPT));
    PPAGING_STRUCTURE PD = NULL;
    RET_ERR(MiInitCreatePagingStructure(PAGING_TYPE_PAGE_DIRECTORY, NULL,
					PageTableCapStart++,
					InitInfo->UserImageStartVirtAddr, &PD));
    assert(PD != NULL);
    RET_ERR(MiVSpaceInsertPagingStructure(&MiNtosVaddrSpace, PD));
#endif

    /* Insert all the page tables used to map the root task user image */
    MWORD StartPTNum = InitInfo->UserImageStartVirtAddr >> PAGE_TABLE_WINDOW_LOG2SIZE;
    MWORD EndPTNum = StartPTNum + InitInfo->NumUserPagingStructureCaps;
    for (MWORD PTNum = StartPTNum; PTNum < EndPTNum; PTNum++) {
	PPAGING_STRUCTURE PageTable = NULL;
	RET_ERR(MiInitCreatePagingStructure(PAGING_TYPE_PAGE_TABLE, NULL,
					    PageTableCapStart + PTNum - StartPTNum,
					    PTNum << PAGE_TABLE_WINDOW_LOG2SIZE,
					    &PageTable));
	assert(PageTable != NULL);
	RET_ERR(MiVSpaceInsertPagingStructure(&MiNtosVaddrSpace, PageTable));
    }

    /* Insert all the page frames used to map the root task user image */
    MWORD StartPN = InitInfo->UserImageStartVirtAddr >> PAGE_LOG2SIZE;
    MWORD EndPN = StartPN + InitInfo->NumUserImageFrames;
    for (MWORD PN = StartPN; PN < EndPN; PN++) {
	PPAGING_STRUCTURE Page = NULL;
	RET_ERR(MiInitCreatePagingStructure(PAGING_TYPE_PAGE, NULL,
					    InitInfo->UserImageFrameCapStart + PN - StartPN,
					    PN << PAGE_LOG2SIZE, &Page));
	assert(Page != NULL);
	RET_ERR(MiVSpaceInsertPagingStructure(&MiNtosVaddrSpace, Page));
    }
    RET_ERR(MmReserveVirtualMemory(InitInfo->UserImageStartVirtAddr, 0,
				   InitInfo->NumUserImageFrames * PAGE_SIZE,
				   MEM_RESERVE_OWNED_MEMORY, NULL));

    return STATUS_SUCCESS;
}

/*
 * Map the initial ExPool heap and build the book-keeping data structures
 * for the root task.
 */
static NTSTATUS MiInitializeRootTask(IN PMM_INIT_INFO InitInfo)
{
    /* Map initial pages for ExPool */
    MWORD FreeCapStart = 0;
    RET_ERR(MiInitMapInitialHeap(InitInfo, &FreeCapStart));

    /* Initialize ExPool */
    RET_ERR(ExInitializePool(EX_POOL_START, LARGE_PAGE_SIZE / PAGE_SIZE));

    /* Initialize root CNode. Record used cap slots at this point. */
    MiInitializeCNode(&MiNtosCNode, ROOT_CNODE_CAP, ROOT_CNODE_LOG2SIZE, MWORD_BITS,
		      &MiNtosCNode, NULL, MiNtosCNodeUsedMap);
    for (ULONG i = 0; i < FreeCapStart; i++) {
	SetBit(MiNtosCNode.UsedMap, i);
    }
    MiNtosCNode.TotalUsed = FreeCapStart;
    MiNtosCNode.RecentFree = FreeCapStart;

    /* Initialize the virtual address space struct for the root task. */
    MiAllocatePool(RootPagingStructure, PAGING_STRUCTURE);
    MiInitializePagingStructure(RootPagingStructure, NULL, NULL, ROOT_VSPACE_CAP,
				ROOT_VSPACE_CAP, 0, PAGING_TYPE_ROOT_PAGING_STRUCTURE,
				TRUE, MM_RIGHTS_RW);
    MiInitializeVSpace(&MiNtosVaddrSpace, RootPagingStructure);

    /* Add the paging structures for the root task image. */
    RET_ERR(MiInitAddUserImagePaging(InitInfo));

    /* Register the initial root untyped used for mapping the initial ExPool heap.
     * Add all the intermediate untyped caps built during mapping of initial heap,
     * as well as the large page for the initial ExPool heap. */
    MiInitializePhyMemDescriptor(&MiPhyMemDescriptor);
    RET_ERR(MiInitAddUntypedAndLargePage(InitInfo));

    return STATUS_SUCCESS;
}

static NTSTATUS MiRegisterRootUntyped(IN PPHY_MEM_DESCRIPTOR PhyMem,
				      IN MWORD Cap,
				      IN MWORD PhyAddr,
				      IN LONG Log2Size,
				      IN BOOLEAN IsDevice)
{
    MiAllocatePool(Untyped, UNTYPED);
    MiInitializeUntyped(Untyped, &MiNtosCNode, NULL, Cap, PhyAddr, Log2Size, IsDevice);
    RET_ERR_EX(MiInsertRootUntyped(PhyMem, Untyped), ExFreePool(Untyped));
    if (!IsDevice) {
	MiInsertFreeUntyped(PhyMem, Untyped);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmInitSystemPhase0(seL4_BootInfo *bootinfo)
{
    extern char _text_start[];
    seL4_SlotRegion UntypedCaps = bootinfo->untyped;
    MWORD InitUntyped = 0;
    MWORD InitUntypedPhyAddr = 0;
    LONG Log2Size = 128;

    /* Find the smallest untyped that is at least one large page sized. */
    LoopOverUntyped(cap, desc, bootinfo) {
	if (!desc->isDevice && desc->sizeBits >= LARGE_PAGE_LOG2SIZE
	    && desc->sizeBits < Log2Size) {
	    InitUntyped = cap;
	    InitUntypedPhyAddr = desc->paddr;
	    Log2Size = desc->sizeBits;
	}
    }
    if (InitUntyped == 0) {
	return STATUS_NO_MEMORY;
    }

    MM_INIT_INFO InitInfo =
	{
	 .InitUntypedCap = InitUntyped,
	 .InitUntypedPhyAddr = InitUntypedPhyAddr,
	 .InitUntypedLog2Size = Log2Size,
	 .RootCNodeFreeCapStart = bootinfo->empty.start,
	 .UserImageStartVirtAddr = (MWORD) (&_text_start[0]),
	 .UserImageFrameCapStart = bootinfo->userImageFrames.start,
	 .NumUserImageFrames = bootinfo->userImageFrames.end - bootinfo->userImageFrames.start,
	 .UserPagingStructureCapStart = bootinfo->userImagePaging.start,
	 .NumUserPagingStructureCaps = bootinfo->userImagePaging.end - bootinfo->userImagePaging.start
	};
    RET_ERR(MiInitializeRootTask(&InitInfo));

    LoopOverUntyped(cap, desc, bootinfo) {
	/* For device memory we need to skip all device memories smaller than
	 * one page since we map device memories as pages */
	if (desc->isDevice && desc->sizeBits < PAGE_LOG2SIZE) {
	    continue;
	}
	if (cap != InitUntyped) {
	    RET_ERR(MiRegisterRootUntyped(&MiPhyMemDescriptor, cap, desc->paddr,
					  desc->sizeBits, desc->isDevice));
	}
    }

    return STATUS_SUCCESS;
}
