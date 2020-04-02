#include <ntos.h>

NTSTATUS MmSplitUntyped(IN PUNTYPED_DESCRIPTOR Src,
			OUT PUNTYPED_DESCRIPTOR Dest1,
			OUT PUNTYPED_DESCRIPTOR Dest2)
{
    if (Src->Split == TRUE) {
	return STATUS_NTOS_EXEC_INVALID_ARGUMENT;
    }

    PCAPSPACE_DESCRIPTOR CapSpace = Src->CapSpace;
    Dest1->CapSpace = CapSpace;
    Dest2->CapSpace = CapSpace;

    Dest1->Log2Size = Src->Log2Size - 1;
    Dest2->Log2Size = Src->Log2Size - 1;

    MWORD NewCap = 0;
    RET_IF_ERR(MmCapSpaceAllocCaps(CapSpace, &NewCap, 2));

    MWORD error = seL4_Untyped_Retype(Src->Cap,
				      seL4_UntypedObject,
				      Dest1->Log2Size,
				      CapSpace->Root,
				      0, // node_index
				      0, // node_depth
				      NewCap, // node_offset
				      2);
    if (error != seL4_NoError) {
	RET_IF_ERR(MmCapSpaceDeallocCap(CapSpace, NewCap+1));
	RET_IF_ERR(MmCapSpaceDeallocCap(CapSpace, NewCap));
	return SEL4_ERROR(error);
    }

    Src->Split = TRUE;
    Dest1->Split = FALSE;
    Dest2->Split = FALSE;
    Dest1->Cap = NewCap;
    Dest2->Cap = NewCap+1;
    return STATUS_SUCCESS;
}
