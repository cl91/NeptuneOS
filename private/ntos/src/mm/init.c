/* TODO: Add amd64 code path. */

#include "mi.h"
#include <ctype.h>

MM_VADDR_SPACE MiNtosVaddrSpace;
MM_PHY_MEM MiPhyMemDescriptor;
MM_CNODE MiNtosCNode;
static MWORD MiNtosCNodeUsedMap[(1 << ROOT_CNODE_LOG2SIZE) / MWORD_BITS] PAGE_ALIGNED_DATA;

NTSTATUS MiSplitInitialUntyped(IN MWORD SrcCap,
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

NTSTATUS MiInitRetypeIntoPage(IN MWORD Untyped,
			      IN MWORD PageCap,
			      IN MWORD Type)
{
    int Error = seL4_Untyped_Retype(Untyped,
				    Type,
				    PAGE_LOG2SIZE,
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

NTSTATUS MiInitMapPage(IN PMM_INIT_INFO InitInfo,
		       IN MWORD Untyped,
		       IN MWORD PageCap,
		       IN MWORD Vaddr,
		       IN MWORD Type)
{
    RET_ERR(MiInitRetypeIntoPage(Untyped, PageCap, Type));

    int Error;
    if (Type == seL4_X86_4K) {
	Error = seL4_X86_Page_Map(PageCap,
				  ROOT_VSPACE_CAP,
				  Vaddr,
				  MM_RIGHTS_RW,
				  seL4_X86_Default_VMAttributes);
    } else if (Type == seL4_X86_PageTableObject) {
	Error = seL4_X86_PageTable_Map(PageCap,
				       ROOT_VSPACE_CAP,
				       Vaddr,
				       seL4_X86_Default_VMAttributes);
    } else {
	/* This is a programming error. */
	return STATUS_NTOS_BUG;
    }

    if (Error) {
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS MiInitializeRootTask(IN PMM_INIT_INFO InitInfo)
{
    /* Map initial pages for ExPool */
    LONG PoolPages;
    MWORD FreeCapStart;
    RET_ERR(MiInitMapInitialHeap(InitInfo, &PoolPages, &FreeCapStart));

    /* Initialize ExPool */
    RET_ERR(ExInitializePool(EX_POOL_START, PoolPages));

    /* Initialize root CNode. Record used cap slots at this point. */
    MiInitializeCNode(&MiNtosCNode, ROOT_CNODE_CAP, ROOT_CNODE_LOG2SIZE,
		      NULL, MiNtosCNodeUsedMap);
    for (ULONG i = 0; i < FreeCapStart; i++) {
	SetBit(MiNtosCNode.UsedMap, i);
    }
    MiNtosCNode.TotalUsed = FreeCapStart;
    MiNtosCNode.RecentFree = FreeCapStart;

    /* Build the Vad tree of the ntos virtual address space */
    MmInitializeVaddrSpace(&MiNtosVaddrSpace, ROOT_VSPACE_CAP);
    RET_ERR(MmReserveVirtualMemory(EX_POOL_START_PN, EX_POOL_RESERVED_PAGES));
    PMM_VAD ExPoolVad = MiVspaceFindVadNode(&MiNtosVaddrSpace, EX_POOL_START_PN, 1);
    if (ExPoolVad == NULL) {
	return STATUS_NTOS_BUG;
    }

    /* Add untyped and paging structure built during mapping of initial heap */
    MiAvlInitializeTree(&MiPhyMemDescriptor.RootUntypedForest);
    MiPhyMemDescriptor.CachedRootUntyped = NULL;
    InitializeListHead(&MiPhyMemDescriptor.SmallUntypedList);
    InitializeListHead(&MiPhyMemDescriptor.MediumUntypedList);
    InitializeListHead(&MiPhyMemDescriptor.LargeUntypedList);
    RET_ERR(MiInitRecordUntypedAndPages(InitInfo, ExPoolVad));

    /* Build Vad for ntos image */
    RET_ERR(MmReserveVirtualMemory(InitInfo->UserStartPageNum, InitInfo->NumUserPages));
    PMM_VAD UserImageVad = MiVspaceFindVadNode(&MiNtosVaddrSpace, InitInfo->UserStartPageNum, InitInfo->NumUserPages);
    if (UserImageVad == NULL) {
	return STATUS_NTOS_BUG;
    }
    RET_ERR(MiInitRecordUserImagePaging(InitInfo, UserImageVad));

    return STATUS_SUCCESS;
}

static NTSTATUS MiRegisterRootUntyped(IN PMM_PHY_MEM PhyMem,
				      IN MWORD Cap,
				      IN MWORD PhyAddr,
				      IN LONG Log2Size,
				      IN BOOLEAN IsDevice)
{
    MiAllocatePool(Untyped, MM_UNTYPED);
    MiInitializeUntyped(Untyped, NULL, Cap, PhyAddr, Log2Size, IsDevice);
    RET_ERR_EX(MiInsertRootUntyped(PhyMem, Untyped), ExFreePool(Untyped));
    if (!IsDevice) {
	MiInsertFreeUntyped(PhyMem, Untyped);
    }
    return STATUS_SUCCESS;
}

NTSTATUS MmInitSystem(seL4_BootInfo *bootinfo)
{
    extern char _text_start[];
    seL4_SlotRegion UntypedCaps = bootinfo->untyped;
    MWORD InitUntyped = 0;
    MWORD InitUntypedPhyAddr = 0;
    LONG Log2Size = 128;

    /* Find at least 7 Pages + 1 PageDirectory */
    LoopOverUntyped(cap, desc, bootinfo) {
	if (!desc->isDevice && desc->sizeBits >= (seL4_PageBits + 3)
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
	 .UserStartPageNum = (MWORD) (&_text_start[0]) >> PAGE_LOG2SIZE,
	 .UserPageCapStart = bootinfo->userImageFrames.start,
	 .NumUserPages = bootinfo->userImageFrames.end - bootinfo->userImageFrames.start,
	 .UserPagingStructureCapStart = bootinfo->userImagePaging.start,
	 .NumUserPagingStructureCaps = bootinfo->userImagePaging.end - bootinfo->userImagePaging.start
	};
    RET_ERR(MiInitializeRootTask(&InitInfo));

    LoopOverUntyped(cap, desc, bootinfo) {
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
