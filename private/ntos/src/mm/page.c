#include <nt.h>
#include <ntos.h>

NTSTATUS MmMapTopLevelPage(PPAGE_DESCRIPTOR Page)
{
    Page.VirtualAddr &= (~0) << Page.Log2Size;

    BOOLEAN NeedDeallocIfError = FALSE;
    if (Page.Cap == 0) {
	MWORD Cap;
	RET_IF_ERR(MmCapSpaceAllocCap(Page.CapSpace, &Cap));
	Page.Cap = Cap;
	NeedDeallocIfError = TRUE;
    }

    int Error = seL4_X86_Page_Map(Page.Cap,
				  Page.VSpaceCap,
				  Page.VirtualAddr,
				  Page.Rights,
				  Page.Attributes);
    DbgPrint("cap = %zd vspace = %zd vaddr = %p rights = 0x%x attr = 0x%x",
	     Page.Cap, Page.VSpaceCap, Page.VirtualAddr, Page.Rights, Page.Attributes);

    if (Error) {
	if (NeedDeallocIfError) {
	    MWORD Cap = Page.Cap;
	    Page.Cap = 0;
	    MmCapSpaceDeallocCap(Page.CapSpace, Cap);
	}
	/* TODO: Encode error code into NTSTATUS */
	return STATUS_NTOS_EXEC_INVALID_ARGUMENT;
    }

    Page.Mapped = TRUE;
    return STATUS_SUCCESS;
}
