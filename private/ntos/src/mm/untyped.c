#include "mi.h"

NTSTATUS MiSplitUntyped(IN PMM_UNTYPED Src,
			OUT PMM_UNTYPED Dest1,
			OUT PMM_UNTYPED Dest2)
{
    if ((Src->TreeNode.LeftChild != NULL) || (Src->TreeNode.RightChild != NULL)) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }

    Dest1->Log2Size = Src->Log2Size - 1;
    Dest2->Log2Size = Src->Log2Size - 1;

    MWORD NewCap = 0;
    RET_IF_ERR(MmAllocateCaps(&NewCap, 2));

    MWORD Error = seL4_Untyped_Retype(Src->TreeNode.Cap,
				      seL4_UntypedObject,
				      Dest1->Log2Size,
				      MmRootCspaceCap(),
				      0, // node_index
				      0, // node_depth
				      NewCap, // node_offset
				      2);
    if (Error != seL4_NoError) {
	RET_IF_ERR(MmDeallocateCap(NewCap+1));
	RET_IF_ERR(MmDeallocateCap(NewCap));
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

VOID MiInsertFreeUntyped(IN PMM_PHY_MEM PhyMem,
			 IN PMM_UNTYPED Untyped)
{
    PLIST_ENTRY List;
    if (Untyped->Log2Size >= MM_LARGE_PAGE_BITS) {
	List = &PhyMem->LargeUntypedList;
    } else if (Untyped->Log2Size >= MM_PAGE_BITS) {
	List = &PhyMem->MediumUntypedList;
    } else {
	List = &PhyMem->SmallUntypedList;
    }
    InsertHeadList(List, &Untyped->FreeListEntry);
}

NTSTATUS MmRequestUntyped(IN LONG Log2Size,
			  OUT PMM_UNTYPED *Untyped)
{
    PLIST_ENTRY List = NULL;
    if (Log2Size >= MM_LARGE_PAGE_BITS && !IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    } else if (Log2Size >= MM_PAGE_BITS && !IsListEmpty(&MiPhyMemDescriptor.MediumUntypedList)) {
	List = &MiPhyMemDescriptor.MediumUntypedList;
    } else if (Log2Size >= MM_PAGE_BITS && !IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.SmallUntypedList)) {
	List = &MiPhyMemDescriptor.SmallUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.MediumUntypedList)) {
	List = &MiPhyMemDescriptor.MediumUntypedList;
    } else if (!IsListEmpty(&MiPhyMemDescriptor.LargeUntypedList)) {
	List = &MiPhyMemDescriptor.LargeUntypedList;
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
	MiInsertFreeUntyped(&MiPhyMemDescriptor, RightChild);
	RootUntyped = LeftChild;
    }

    *Untyped = RootUntyped;

    return STATUS_SUCCESS;
}

NTSTATUS MiRequestIoUntyped(IN PMM_IO_UNTYPED RootIoUntyped,
			    IN MWORD PhyPageNum,
			    OUT PMM_IO_UNTYPED *IoUntyped)
{
    *IoUntyped = RootIoUntyped;
    LONG NumSplits = RootIoUntyped->Untyped.Log2Size - MM_PAGE_BITS;
    for (LONG i = NumSplits-1; i >= 0; i--) {
	if ((*IoUntyped)->Untyped.TreeNode.LeftChild == NULL) {
	    MiAllocatePool(LeftChild, MM_IO_UNTYPED);
	    MiAllocatePool(RightChild, MM_IO_UNTYPED);
	    RET_IF_ERR(MiSplitUntyped(&(*IoUntyped)->Untyped,
				      &LeftChild->Untyped,
				      &RightChild->Untyped));
	    LeftChild->AvlNode.Key = (*IoUntyped)->AvlNode.Key;
	    RightChild->AvlNode.Key = (*IoUntyped)->AvlNode.Key +
		(1 << (LeftChild->Untyped.Log2Size - MM_PAGE_BITS));
	}
	MWORD Bit = PhyPageNum & (1 << i);
	PMM_UNTYPED Child;
	if (Bit) {
	    Child = (PMM_UNTYPED) (*IoUntyped)->Untyped.TreeNode.RightChild;
	} else {
	    Child = (PMM_UNTYPED) (*IoUntyped)->Untyped.TreeNode.LeftChild;
	}
	*IoUntyped = CONTAINING_RECORD(Child, MM_IO_UNTYPED, Untyped);
    }

    return STATUS_SUCCESS;
}
