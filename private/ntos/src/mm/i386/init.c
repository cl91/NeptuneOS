#include "../mi.h"

NTSTATUS MiPrepareInitialUntyped(IN PMM_INIT_INFO InitInfo)
{
    MWORD RootCap = InitInfo->RootCNodeCap;
    MWORD DestCap = InitInfo->RootCNodeFreeCapStart;
    MWORD UntypedCap = InitInfo->InitUntypedCap;
    LONG Log2Size = InitInfo->InitUntypedLog2Size;
    LONG NumSplits = Log2Size - MM_PAGE_BITS;
    for (int i = 0; i < NumSplits; i++) {
	RET_IF_ERR(MiSplitInitialUntyped(RootCap, UntypedCap, Log2Size, DestCap));
	UntypedCap = DestCap;
	DestCap += 2;
	Log2Size--;
    }
    MWORD SrcCap = InitInfo->RootCNodeFreeCapStart + 2*NumSplits - 3;
    return MiSplitInitialUntyped(RootCap, SrcCap, Log2Size+1, DestCap);
}

NTSTATUS MiInitMapInitialHeap(IN PMM_INIT_INFO InitInfo,
			      OUT LONG *PoolPages,
			      OUT MWORD *FreeCapStart)
{
    /* We require at least three pages to initialize ExPool */
    if (InitInfo->InitUntypedLog2Size < seL4_PageBits + 2) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }

    /* Map initial pages for ExPool */
    RET_IF_ERR(MiPrepareInitialUntyped(InitInfo));
    LONG NumSplits = InitInfo->InitUntypedLog2Size - MM_PAGE_BITS;
    MWORD Page0Untyped = InitInfo->RootCNodeFreeCapStart + 2*NumSplits - 2;
    MWORD Page1Untyped = Page0Untyped + 1;
    MWORD Page2Untyped = Page0Untyped + 2;
    MWORD PageTableUntyped = Page0Untyped + 3;
    MWORD Page0Cap = Page0Untyped + 4;
    MWORD Page1Cap = Page0Untyped + 5;
    MWORD Page2Cap = Page0Untyped + 6;
    MWORD PageTableCap = Page0Untyped + 7;
    RET_IF_ERR(MiInitMapPage(InitInfo, PageTableUntyped, PageTableCap,
			     EX_POOL_START, seL4_X86_PageTableObject));
    RET_IF_ERR(MiInitMapPage(InitInfo, Page0Untyped, Page0Cap,
			     EX_POOL_START, seL4_X86_4K));
    RET_IF_ERR(MiInitMapPage(InitInfo, Page1Untyped, Page1Cap,
			     EX_POOL_START + MM_PAGE_SIZE, seL4_X86_4K));
    RET_IF_ERR(MiInitMapPage(InitInfo, Page2Untyped, Page2Cap,
			     EX_POOL_START + 2*MM_PAGE_SIZE, seL4_X86_4K));

    *PoolPages = 3;
    *FreeCapStart = PageTableCap + 1;
    return STATUS_SUCCESS;
}

NTSTATUS MiInitRecordUntypedAndPages(IN PMM_INIT_INFO InitInfo,
				     IN PMM_VAD ExPoolVad)
{
    MiAllocatePool(RootUntyped, MM_UNTYPED);
    MiInitializeUntyped(RootUntyped, NULL, TRUE, InitInfo->InitUntypedCap,
			InitInfo->InitUntypedPhyAddr,
			InitInfo->InitUntypedLog2Size, FALSE);

    PMM_UNTYPED ParentUntyped = RootUntyped;
    LONG NumSplits = InitInfo->InitUntypedLog2Size - MM_PAGE_BITS;
    PMM_PAGE_TABLE PageTable = NULL;
    for (int i = 0; i < NumSplits; i++) {
	MiAllocatePool(LeftChildUntyped, MM_UNTYPED);
	MiAllocatePool(RightChildUntyped, MM_UNTYPED);

	LONG ChildLog2Size = InitInfo->InitUntypedLog2Size - 1 - i;
	MWORD LeftChildCap = InitInfo->RootCNodeFreeCapStart + 2*i;
	MWORD RigthChildCap = LeftChildCap + 1;
	MiInitializeUntyped(LeftChildUntyped, ParentUntyped, TRUE,
			    LeftChildCap, InitInfo->InitUntypedPhyAddr,
			    ChildLog2Size, FALSE);
	MiInitializeUntyped(RightChildUntyped, ParentUntyped, FALSE, RigthChildCap,
			    InitInfo->InitUntypedPhyAddr + (1 << ChildLog2Size),
			    ChildLog2Size, FALSE);

	if (i < NumSplits-2) {
	    MiInsertFreeUntyped(&MiPhyMemDescriptor, RightChildUntyped);
	} else if (i == NumSplits-2) {
	    /*
	     * The capability derivation tree at this level is:
	     *
	     *                 (ParentUntyped)                         ----    (i == NumSplits-2)
	     *                  /           \
	     *    (LeftChildUntyped)     (RightChilduntyped)           ----    (i == NumSplits-1)
	     *       /         \            /             \
	     * (Page0Un)   (Page1Un)    (Page2Un)    (PageTableUn)     ----    (i == NumSplits)
	     *     |           |            |              |
	     *  (Page0)     (Page1)      (Page2)      (PageTable)
	     *
	     * Capabilities are
	     *
	     *            (FS+2NS-5 or InitUntypedCap)                   ----    (i == NumSplits-2)
	     *             /                        \
	     *        (FS+2NS-4)                (FS+2NS-3)               ----    (i == NumSplits-1)
	     *       /         \               /          \
	     * (FS+2NS-2)   (FS+2NS-1)    (FS+2NS)    (FS+2NS+1)         ----    (i == NumSplits)
	     *     |            |             |            |
	     * (FS+2NS+2)   (FS+2NS+3)    (FS+2NS+4)  (FS+2NS+5)
	     *
	     * Here FS = InitInfo->RootCNodeFreeCapStart, NS = NumSplits
	     */
	    MiAllocatePool(Page2Untyped, MM_UNTYPED);
	    MiAllocatePool(PageTableUntyped, MM_UNTYPED);
	    assert(InitInfo->InitUntypedLog2Size - NumSplits == MM_PAGE_BITS);
	    MWORD Page2UntypedCap = InitInfo->RootCNodeFreeCapStart + 2*NumSplits;
	    MWORD PageTableUntypedCap = Page2UntypedCap + 1;
	    MiInitializeUntyped(Page2Untyped, RightChildUntyped, TRUE, Page2UntypedCap,
				InitInfo->InitUntypedPhyAddr + 2 * MM_PAGE_SIZE,
				MM_PAGE_BITS, FALSE);
	    MiInitializeUntyped(PageTableUntyped, RightChildUntyped, FALSE, PageTableUntypedCap,
				InitInfo->InitUntypedPhyAddr + 3 * MM_PAGE_SIZE,
				MM_PAGE_BITS, FALSE);
	    MiAllocatePool(Page2, MM_PAGE);
	    MiAllocatePool(pPageTable, MM_PAGE_TABLE);
	    PageTable = pPageTable;
	    MiInitializePageTable(PageTable, PageTableUntyped, &MiNtosVaddrSpace,
				  InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 5,
				  EX_POOL_START >> MM_LARGE_PAGE_BITS, TRUE);
	    MiInitializePage(Page2, Page2Untyped, &MiNtosVaddrSpace,
			     InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 4,
			     (EX_POOL_START >> MM_PAGE_BITS) + 2, TRUE, MM_RIGHTS_RW);
	    RET_IF_ERR(MiVspaceInsertPageTable(&MiNtosVaddrSpace, ExPoolVad, PageTable));
	    assert(ExPoolVad->FirstPageTable == &PageTable->AvlNode);
	    assert(ExPoolVad->LastPageTable == &PageTable->AvlNode);
	    RET_IF_ERR(MiPageTableInsertPage(PageTable, Page2));
	} else {		/* i == NumSplits-1 */
	    MiAllocatePool(Page0, MM_PAGE);
	    MiAllocatePool(Page1, MM_PAGE);
	    MiInitializePage(Page0, LeftChildUntyped, &MiNtosVaddrSpace,
			     InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 2,
			     EX_POOL_START >> MM_PAGE_BITS, TRUE, MM_RIGHTS_RW);
	    MiInitializePage(Page1, RightChildUntyped, &MiNtosVaddrSpace,
			     InitInfo->RootCNodeFreeCapStart + 2*NumSplits + 3,
			     (EX_POOL_START >> MM_PAGE_BITS) + 1, TRUE, MM_RIGHTS_RW);
	    RET_IF_ERR(MiPageTableInsertPage(PageTable, Page0));
	    RET_IF_ERR(MiPageTableInsertPage(PageTable, Page1));
	}
	ParentUntyped = LeftChildUntyped;
    }

    return STATUS_SUCCESS;
}

NTSTATUS MiInitRecordUserImagePaging(IN PMM_INIT_INFO InitInfo,
				     IN PMM_VAD UserImageVad)
{
    MWORD StartPageNum = InitInfo->UserStartPageNum;
    MWORD EndPageNum = StartPageNum + InitInfo->NumUserPages;
    MWORD StartPTNum = StartPageNum >> MM_LARGE_PN_SHIFT;
    MWORD EndPTNum = StartPTNum + InitInfo->NumUserPagingStructureCaps;
    MWORD PageNum = StartPageNum;
    for (MWORD PTNum = StartPTNum; PTNum < EndPTNum; PTNum++) {
	MiAllocatePool(PageTable, MM_PAGE_TABLE);
	MiInitializePageTable(PageTable, NULL, &MiNtosVaddrSpace,
			      InitInfo->UserPagingStructureCapStart + PTNum - StartPTNum,
			      PTNum, TRUE);
	RET_IF_ERR(MiVspaceInsertPageTable(&MiNtosVaddrSpace, UserImageVad, PageTable));
	while (PageNum < EndPageNum && PageNum < ((PTNum+1) << MM_LARGE_PN_SHIFT)) {
	    MiAllocatePool(Page, MM_PAGE);
	    MiInitializePage(Page, NULL, &MiNtosVaddrSpace,
			     InitInfo->UserPageCapStart + PageNum - StartPageNum,
			     PageNum, TRUE, MM_RIGHTS_RW);
	    RET_IF_ERR(MiPageTableInsertPage(PageTable, Page));
	    PageNum++;
	}
    }

    return STATUS_SUCCESS;
}
