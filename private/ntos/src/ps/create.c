
#include "psp.h"

static NTSTATUS PspRetypeIntoObject(IN PMM_UNTYPED Untyped,
				    IN MWORD ObjType,
				    IN MWORD ObjBits,
				    OUT MWORD *ObjCap)
{
    if (Untyped->Log2Size != ObjBits) {
	return STATUS_NTOS_INVALID_ARGUMENT;
    }
    RET_IF_ERR(MmAllocateCap(ObjCap));
    MWORD Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				      ObjType,
				      ObjBits,
				      MmRootCspaceCap(),
				      0, // node_index
				      0, // node_depth
				      *ObjCap, // node_offset
				      1);
    if (Error != seL4_NoError) {
	RET_IF_ERR(MmDeallocateCap(*ObjCap));
	*ObjCap = 0;
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS PspCreateThread(IN PPROCESS pProcess,
				OUT PTHREAD *pThread)
{
    PMM_UNTYPED TcbUntyped;
    PMM_UNTYPED IpcBufferUntyped;
    RET_IF_ERR(MmRequestFreeUntyped(seL4_TCBBits, &TcbUntyped));
    RET_IF_ERR(MmRequestFreeUntyped(seL4_PageBits, &IpcBufferUntyped));
    MWORD TcbCap;
    RET_IF_ERR(PspRetypeIntoObject(TcbUntyped, seL4_TCBObject,
				   seL4_TCBBits, &TcbCap));
    /* Retype into ipc buffer page */

    PspAllocatePool(Thread, THREAD);
    Thread->TcbUntyped = TcbUntyped;
    Thread->IpcBufferUntyped = IpcBufferUntyped;
    Thread->TcbCap = TcbCap;
    /* Record ipc buffer page */

    *pThread = Thread;
    return STATUS_SUCCESS;
}

static NTSTATUS PspCreateProcess(OUT PPROCESS *pProcess)
{
    PMM_UNTYPED VspaceUntyped;
    RET_IF_ERR(MmRequestFreeUntyped(seL4_VSpaceBits, &VspaceUntyped));
    MWORD VspaceCap;
    RET_IF_ERR(PspRetypeIntoObject(VspaceUntyped, seL4_VSpaceObject,
				   seL4_VSpaceBits, &VspaceCap));

    PspAllocatePool(Process, PROCESS);
    Process->InitThread = NULL;
    InitializeListHead(&Process->ThreadList);
    MmInitializeVaddrSpace(&Process->VaddrSpace, VspaceCap);

    *pProcess = Process;
    return STATUS_SUCCESS;
}
