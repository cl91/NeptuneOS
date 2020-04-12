#include "mi.h"

LONG MiPageGetLog2Size(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Type == MM_PAGE_TYPE_PAGE) {
	return seL4_PageBits;
    } else if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	return seL4_LargePageBits;
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	return seL4_LargePageBits;
    } else {
	return 0;
    }
}

MWORD MiPageGetSel4Type(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Type == MM_PAGE_TYPE_PAGE) {
	return seL4_X86_4K;
    } else if (Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	return seL4_X86_LargePageObject;
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	return seL4_X86_PageTableObject;
    } else {
	return 0;
    }
}

NTSTATUS MiMapPagingStructure(PMM_PAGING_STRUCTURE Page)
{
    if (Page->Mapped) {
	return STATUS_SUCCESS;
    }

    Page->VirtualAddr &= (~0) << MiPageGetLog2Size(Page);

    int Error = 0;
    if (Page->Cap == 0) {
	PMM_UNTYPED Untyped = (PMM_UNTYPED) Page->TreeNode.Parent;
	if (Untyped == NULL) {
	    return STATUS_NTOS_INVALID_ARGUMENT;
	}
	MWORD Cap;
	RET_IF_ERR(MiCapSpaceAllocCap(Page->TreeNode.CapSpace, &Cap));
	Page->Cap = Cap;
	Error = seL4_Untyped_Retype(Untyped->Cap,
				    MiPageGetSel4Type(Page),
				    MiPageGetLog2Size(Page),
				    Page->TreeNode.CapSpace->RootCap,
				    0, // node_index
				    0, // node_depth
				    Page->Cap,
				    1 // num_caps
				    );
	if (Error) {
	    goto CleanUpCap;
	}
    }

    if (Page->Type == MM_PAGE_TYPE_PAGE || Page->Type == MM_PAGE_TYPE_LARGE_PAGE) {
	Error = seL4_X86_Page_Map(Page->Cap,
				  Page->VSpaceCap,
				  Page->VirtualAddr,
				  Page->Rights,
				  Page->Attributes);
    } else if (Page->Type == MM_PAGE_TYPE_PAGE_TABLE) {
	Error = seL4_X86_PageTable_Map(Page->Cap,
				       Page->VSpaceCap,
				       Page->VirtualAddr,
				       Page->Attributes);
    }

    if (Error == 0) {
	Page->Mapped = TRUE;
	return STATUS_SUCCESS;
    }

    int RevokeError = 0;
    MWORD Cap = 0;
 CleanUpRevoke:
    RevokeError = seL4_CNode_Revoke(Page->TreeNode.CapSpace->RootCap,
				    Page->Cap,
				    0); /* FIXME: depth */
    if (RevokeError) {
	return SEL4_ERROR(RevokeError);
    }

 CleanUpCap:
    Cap = Page->Cap;
    Page->Cap = 0;
    MiCapSpaceDeallocCap(Page->TreeNode.CapSpace, Cap);
    return SEL4_ERROR(Error);
}
