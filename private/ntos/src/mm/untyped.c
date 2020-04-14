#include "mi.h"

NTSTATUS MiSplitUntyped(IN PMM_UNTYPED Src,
			OUT PMM_UNTYPED Dest1,
			OUT PMM_UNTYPED Dest2)
{
    if ((Src->TreeNode.LeftChild != NULL) || (Src->TreeNode.RightChild != NULL)) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    PMM_CAPSPACE CapSpace = Src->TreeNode.CapSpace;
    Dest1->TreeNode.CapSpace = CapSpace;
    Dest2->TreeNode.CapSpace = CapSpace;

    Dest1->Log2Size = Src->Log2Size - 1;
    Dest2->Log2Size = Src->Log2Size - 1;

    MWORD NewCap = 0;
    RET_IF_ERR(MiCapSpaceAllocCaps(CapSpace, &NewCap, 2));

    MWORD Error = seL4_Untyped_Retype(Src->TreeNode.Cap,
				      seL4_UntypedObject,
				      Dest1->Log2Size,
				      CapSpace->RootCap,
				      0, // node_index
				      0, // node_depth
				      NewCap, // node_offset
				      2);
    if (Error != seL4_NoError) {
	RET_IF_ERR(MiCapSpaceDeallocCap(CapSpace, NewCap+1));
	RET_IF_ERR(MiCapSpaceDeallocCap(CapSpace, NewCap));
	return SEL4_ERROR(Error);
    }

    Dest1->TreeNode.Cap = NewCap;
    Dest2->TreeNode.Cap = NewCap+1;

    Src->TreeNode.LeftChild = &Dest1->TreeNode;
    Src->TreeNode.RightChild = &Dest2->TreeNode;
    Dest1->TreeNode.Parent = &Src->TreeNode;
    Dest2->TreeNode.Parent = &Src->TreeNode;
    Dest1->TreeNode.LeftChild = NULL;
    Dest1->TreeNode.RightChild = NULL;
    Dest2->TreeNode.LeftChild = NULL;
    Dest2->TreeNode.RightChild = NULL;

    return STATUS_SUCCESS;
}

VOID MiInsertFreeUntyped(IN PMM_VADDR_SPACE VaddrSpace,
			 IN PMM_UNTYPED Untyped)
{
    PLIST_ENTRY List;
    if (Untyped->Log2Size >= MM_LARGE_PAGE_BITS) {
	List = &VaddrSpace->LargeUntypedList;
    } else if (Untyped->Log2Size >= MM_PAGE_BITS) {
	List = &VaddrSpace->MediumUntypedList;
    } else {
	List = &VaddrSpace->SmallUntypedList;
    }
    InsertHeadList(List, &Untyped->FreeListEntry);
}

NTSTATUS MiRequestUntyped(IN PMM_VADDR_SPACE VaddrSpace,
			  IN ULONG Log2Size,
			  OUT PMM_UNTYPED *Untyped)
{
    PLIST_ENTRY List = NULL;
    if (Log2Size >= MM_LARGE_PAGE_BITS && !IsListEmpty(&VaddrSpace->LargeUntypedList)) {
	List = &VaddrSpace->LargeUntypedList;
    } else if (Log2Size >= MM_PAGE_BITS && !IsListEmpty(&VaddrSpace->MediumUntypedList)) {
	List = &VaddrSpace->MediumUntypedList;
    } else if (Log2Size >= MM_PAGE_BITS && !IsListEmpty(&VaddrSpace->LargeUntypedList)) {
	List = &VaddrSpace->LargeUntypedList;
    } else if (!IsListEmpty(&VaddrSpace->SmallUntypedList)) {
	List = &VaddrSpace->SmallUntypedList;
    } else if (!IsListEmpty(&VaddrSpace->MediumUntypedList)) {
	List = &VaddrSpace->MediumUntypedList;
    } else if (!IsListEmpty(&VaddrSpace->LargeUntypedList)) {
	List = &VaddrSpace->LargeUntypedList;
    }
    if (List == NULL) {
	return STATUS_NTOS_OUT_OF_MEMORY;
    }
    PMM_UNTYPED RootUntyped = CONTAINING_RECORD(List->Flink, MM_UNTYPED, FreeListEntry);
    LONG NumSplits = RootUntyped->Log2Size - Log2Size;
    assert(NumSplits >= 0);
    RemoveEntryList(List->Flink);
    for (LONG i = 0; i < NumSplits; i++) {
	MWORD LeftCap, RightCap;
	MiAllocatePool(LeftChild, MM_UNTYPED);
	MiAllocatePool(RightChild, MM_UNTYPED);
	RET_IF_ERR(MiSplitUntyped(RootUntyped, LeftChild, RightChild));
	MiInsertFreeUntyped(VaddrSpace, RightChild);
	RootUntyped = LeftChild;
    }

    *Untyped = RootUntyped;

    return STATUS_SUCCESS;
}
