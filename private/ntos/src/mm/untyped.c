#include "mi.h"

NTSTATUS MiSplitUntyped(IN PMM_UNTYPED Src,
			OUT PMM_UNTYPED Dest1,
			OUT PMM_UNTYPED Dest2)
{
    if (Src->Split == TRUE) {
	return STATUS_NTOS_EXEC_INVALID_ARGUMENT;
    }

    PMM_CAPSPACE CapSpace = Src->TreeNode.CapSpace;
    Dest1->TreeNode.CapSpace = CapSpace;
    Dest2->TreeNode.CapSpace = CapSpace;

    Dest1->Log2Size = Src->Log2Size - 1;
    Dest2->Log2Size = Src->Log2Size - 1;

    MWORD NewCap = 0;
    RET_IF_ERR(MiCapSpaceAllocCaps(CapSpace, &NewCap, 2));

    MWORD error = seL4_Untyped_Retype(Src->Cap,
				      seL4_UntypedObject,
				      Dest1->Log2Size,
				      CapSpace->RootCap,
				      0, // node_index
				      0, // node_depth
				      NewCap, // node_offset
				      2);
    if (error != seL4_NoError) {
	RET_IF_ERR(MiCapSpaceDeallocCap(CapSpace, NewCap+1));
	RET_IF_ERR(MiCapSpaceDeallocCap(CapSpace, NewCap));
	return SEL4_ERROR(error);
    }

    Src->Split = TRUE;
    Dest1->Split = FALSE;
    Dest2->Split = FALSE;
    Dest1->Cap = NewCap;
    Dest2->Cap = NewCap+1;

    Src->TreeNode.LeftChild = &Dest1->TreeNode;
    Src->TreeNode.RightChild = &Dest2->TreeNode;
    Dest1->TreeNode.Parent = &Src->TreeNode;
    Dest2->TreeNode.Parent = &Src->TreeNode;

    return STATUS_SUCCESS;
}
