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
    RET_ERR(MmAllocateCap(ObjCap));
    MWORD Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				      ObjType,
				      ObjBits,
				      MmRootCspaceCap(),
				      0, // node_index
				      0, // node_depth
				      *ObjCap, // node_offset
				      1);
    if (Error != seL4_NoError) {
	MmDeallocateCap(*ObjCap);
	*ObjCap = 0;
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

NTSTATUS PspThreadObjectCreateProc(PVOID Object)
{
    PTHREAD Thread = (PTHREAD) Object;

    PMM_UNTYPED TcbUntyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_TCBBits, &TcbUntyped));

    MWORD TcbCap = 0;
    NTSTATUS Status = PspRetypeIntoObject(TcbUntyped, seL4_TCBObject,
					  seL4_TCBBits, &TcbCap);
    if (!NT_SUCCESS(Status)) {
	MmReleaseUntyped(TcbUntyped);
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

    PMM_UNTYPED VspaceUntyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_VSpaceBits, &VspaceUntyped));
    MWORD VspaceCap = 0;
    RET_ERR_EX(PspRetypeIntoObject(VspaceUntyped, seL4_VSpaceObject,
				   seL4_VSpaceBits, &VspaceCap),
	       MmReleaseUntyped(VspaceUntyped));

    Process->InitThread = NULL;
    InitializeListHead(&Process->ThreadList);
    MmInitializeVaddrSpace(&Process->VaddrSpace, VspaceCap);

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *Thread)
{
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (PPVOID) Thread));

    PMM_PAGE IpcBuffer;
    RET_ERR_EX(MmCommitPageEx(&Process->VaddrSpace,
			      IPC_BUFFER_PAGENUM, &IpcBuffer),
	       ObDereferenceObject(*Thread))
    (*Thread)->IpcBuffer = IpcBuffer;

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(OUT PPROCESS *Process)
{
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (PPVOID) Process));

    RET_ERR_EX(MmReserveVirtualMemoryEx(&(*Process)->VaddrSpace,
					IPC_BUFFER_PAGENUM, 1),
	       ObDereferenceObject(*Process));

    return STATUS_SUCCESS;
}
