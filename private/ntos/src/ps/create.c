#include "psp.h"

extern UCHAR _ntdll_start[];
extern UCHAR _ntdll_end[];

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

NTSTATUS PspThreadObjectCreateProc(PVOID Object)
{
    PTHREAD Thread = (PTHREAD) Object;

    PMM_UNTYPED TcbUntyped;
    RET_IF_ERR(MmRequestUntyped(seL4_TCBBits, &TcbUntyped));

    MWORD TcbCap;
    NTSTATUS Status = PspRetypeIntoObject(TcbUntyped, seL4_TCBObject,
					  seL4_TCBBits, &TcbCap);
    if (!NT_SUCCESS(Status)) {
	RET_IF_ERR(MmReleaseUntyped(TcbUntyped));
	return Status;
    }

    Thread->TcbUntyped = TcbUntyped;
    Thread->TcbCap = TcbCap;
    Thread->IpcBuffer = NULL;

    return STATUS_SUCCESS;
}

NTSTATUS PspProcessObjectCreateProc(PVOID Object)
{
    PPROCESS Process = (PPROCESS) Object;

    PMM_UNTYPED VspaceUntyped;
    RET_IF_ERR(MmRequestUntyped(seL4_VSpaceBits, &VspaceUntyped));
    MWORD VspaceCap;
    NTSTATUS Status = PspRetypeIntoObject(VspaceUntyped, seL4_VSpaceObject,
					  seL4_VSpaceBits, &VspaceCap);
    if (!NT_SUCCESS(Status)) {
	RET_IF_ERR(MmReleaseUntyped(VspaceUntyped));
	return Status;
    }

    Process->InitThread = NULL;
    InitializeListHead(&Process->ThreadList);
    MmInitializeVaddrSpace(&Process->VaddrSpace, VspaceCap);

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *Thread)
{
    RET_IF_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (PPVOID) Thread));

    PMM_PAGE IpcBuffer;
    RET_IF_ERR(MmCommitPageEx(&Process->VaddrSpace, IPC_BUFFER_VADDR, &IpcBuffer));
    (*Thread)->IpcBuffer = IpcBuffer;

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(OUT PPROCESS *Process)
{
    RET_IF_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (PPVOID) Process));

    RET_IF_ERR(MmReserveVirtualMemoryEx(&(*Process)->VaddrSpace,
					IPC_BUFFER_VADDR, 1));

    return STATUS_SUCCESS;
}
