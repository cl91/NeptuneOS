#include "psp.h"

static NTSTATUS PspRetypeIntoObject(IN PMM_VADDR_SPACE LocalVspace,
				    IN PMM_UNTYPED Untyped,
				    IN MWORD ObjType,
				    IN MWORD ObjBits,
				    OUT MWORD *ObjCap)
{
    if (Untyped->Log2Size != ObjBits) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    RET_IF_ERR(MmAllocateCap(LocalVspace, ObjCap));
    MWORD Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				      ObjType,
				      ObjBits,
				      LocalVspace->CapSpace.RootCap,
				      0, // node_index
				      0, // node_depth
				      *ObjCap, // node_offset
				      1);
    if (Error != seL4_NoError) {
	RET_IF_ERR(MmDeallocateCap(LocalVspace, *ObjCap));
	*ObjCap = 0;
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS PspCreateThread(PMM_VADDR_SPACE LocalVspace)
{
    PMM_UNTYPED TcbUntyped;
    PMM_UNTYPED IpcBufferUntyped;
    PMM_UNTYPED NtBufferUntyped;
    RET_IF_ERR(MmRequestUntyped(LocalVspace, seL4_TCBBits, &TcbUntyped));
    RET_IF_ERR(MmRequestUntyped(LocalVspace, seL4_PageBits, &IpcBufferUntyped));
    RET_IF_ERR(MmRequestUntyped(LocalVspace, seL4_PageBits, &NtBufferUntyped));
    MWORD TcbCap;
    RET_IF_ERR(PspRetypeIntoObject(LocalVspace, TcbUntyped, seL4_TCBObject,
				   seL4_TCBBits, &TcbCap));
    return STATUS_SUCCESS;
}

static NTSTATUS PspCreateProcess(PMM_VADDR_SPACE LocalVspace)
{
    PMM_UNTYPED VspaceUntyped;
    RET_IF_ERR(MmRequestUntyped(LocalVspace, seL4_VSpaceBits, &VspaceUntyped));
    MWORD VspaceCap;
    RET_IF_ERR(PspRetypeIntoObject(LocalVspace, VspaceUntyped, seL4_VSpaceObject,
				   seL4_VSpaceBits, &VspaceCap));
    return STATUS_SUCCESS;
}
