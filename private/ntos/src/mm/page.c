#include "mi.h"

LONG MiPageGetLog2Size(PPAGING_STRUCTURE_DESCRIPTOR Page)
{
    if (Page.Type == MM_PAGE) {
	return seL4_PageBits;
    } else if (Page.Type == MM_LARGE_PAGE) {
	return seL4_LargePageBits;
    } else if (Page.Type == MM_PAGE_TABLE) {
	return seL4_LargePageBits;
    } else {
	return 0;
    }
}

MWORD MiPageGetSel4Type(PPAGING_STRUCTURE_DESCRIPTOR Page)
{
    if (Page.Type == MM_PAGE) {
	return seL4_X86_4K;
    } else if (Page.Type == MM_LARGE_PAGE) {
	return seL4_X86_LargePageObject;
    } else if (Page.Type == MM_PAGE_TABLE) {
	return seL4_X86_PageTableObject;
    } else {
	return 0;
    }
}

NTSTATUS MiMapPagingStructure(PPAGING_STRUCTURE_DESCRIPTOR Page)
{
    if (Page.Mapped) {
	return STATUS_SUCCESS;
    }

    Page.VirtualAddr &= (~0) << MiPageGetLog2Size(Page);

    BOOLEAN NeedDeallocCap = FALSE;
    if (Page.Cap == 0) {
	MWORD Cap;
	RET_IF_ERR(MiCapSpaceAllocCap(Page.CapSpace, &Cap));
	Page.Cap = Cap;
	NeedDeallocCap = TRUE;
	int Error = seL4_Untyped_Retype(Page.Untyped->Cap,
					MiPageGetSel4Type(Page),
					MiPageGetLog2Size(Page),
					Page.CapSpace->Root,
					0, // node_index
					0, // node_depth
					Page.Cap,
					1 // num_caps
					);
	if (Error) {
	    return SEL4_ERROR(Error);
	}
    }

    int Error = 0;
    if (Page.Type == MM_PAGE || Page.Type == MM_LARGE_PAGE) {
	Error = seL4_X86_Page_Map(Page.Cap,
				  Page.VSpaceCap,
				  Page.VirtualAddr,
				  Page.Rights,
				  Page.Attributes);
    } else if (Page.Type == MM_PAGE_TABLE) {
	Error = seL4_X86_PageTable_Map(Page.Cap,
				       Page.VSpaceCap,
				       Page.VirtualAddr,
				       Page.Attributes);
    }

    if (Error) {
	if (NeedDeallocCap) {
	    int RevokeError = seL4_CNode_Revoke(Page.CapSpace->Root,
						Page.Cap,
						0); /* FIXME: depth */
	    if (RevokeError) {
		return SEL4_ERROR(RevokeError);
	    }
	    MWORD Cap = Page.Cap;
	    Page.Cap = 0;
	    MiCapSpaceDeallocCap(Page.CapSpace, Cap);
	}
	return SEL4_ERROR(Error);
    }

    Page.Mapped = TRUE;
    return STATUS_SUCCESS;
}
