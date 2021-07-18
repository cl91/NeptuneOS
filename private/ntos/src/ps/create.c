#include "psp.h"

extern UCHAR _ntdll_start[];
extern UCHAR _ntdll_end[];

static NTSTATUS PspRetypeIntoObject(IN PMM_UNTYPED Untyped,
				    IN MWORD ObjType,
				    IN MWORD ObjBits,
				    OUT MWORD *ObjCap)
{
    if (Untyped->Log2Size != ObjBits) {
	/* This is a programming error. */
	assert(FALSE);
	return STATUS_NTOS_BUG;
    }
    RET_ERR(MmAllocateCap(ObjCap));
    MWORD Error = seL4_Untyped_Retype(Untyped->TreeNode.Cap,
				      ObjType,
				      ObjBits,
				      ROOT_CNODE_CAP, /* TODO: Fix CspaceRoot */
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

static NTSTATUS PspSetThreadCapVaddrSpace(IN MWORD Tcb,
					  IN MWORD FaultHandler,
					  IN PMM_CNODE CNode,
					  IN PMM_VADDR_SPACE VaddrSpace)
{
    assert(CapSpace != NULL);
    assert(VaddrSpace != NULL);
    seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool, VaddrSpace->VSpaceCap);
    int Error = seL4_TCB_SetSpace(Tcb, FaultHandler, CNode->TreeNode.Cap,
				  0, /* TODO: Fix capspace guard */
				  VaddrSpace->VSpaceCap, 0);

    if (Error != seL4_NoError) {
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS PspThreadObjectCreateProc(IN PVOID Object)
{
    PTHREAD Thread = (PTHREAD) Object;

    PMM_UNTYPED TcbUntyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_TCBBits, &TcbUntyped));

    MWORD TcbCap = 0;
    RET_ERR_EX(PspRetypeIntoObject(TcbUntyped, seL4_TCBObject,
				   seL4_TCBBits, &TcbCap),
	       MmReleaseUntyped(TcbUntyped));

    Thread->TcbUntyped = TcbUntyped;
    Thread->TcbCap = TcbCap;
    Thread->IpcBuffer = NULL;

    return STATUS_SUCCESS;
}

NTSTATUS PspProcessObjectCreateProc(IN PVOID Object)
{
    PPROCESS Process = (PPROCESS) Object;

    /* TODO: Create new cap space */
    extern MM_CNODE MiNtosCNode;
    Process->CNode = MiNtosCNode;

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
			OUT PTHREAD *pThread)
{
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (PPVOID) pThread));

    RET_ERR_EX(PspSetThreadCapVaddrSpace((*pThread)->TcbCap,
					 0, /* TODO: Fault handler */
					 &Process->CNode,
					 &Process->VaddrSpace),
	       ObDereferenceObject(*pThread));

    PMM_PAGE IpcBuffer;
    RET_ERR_EX(MmCommitPageEx(&Process->VaddrSpace,
			      IPC_BUFFER_PAGENUM, &IpcBuffer),
	       ObDereferenceObject(*pThread));
    (*pThread)->IpcBuffer = IpcBuffer;

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(OUT PPROCESS *pProcess)
{
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (PPVOID) pProcess));

    RET_ERR_EX(MmReserveVirtualMemoryEx(&(*pProcess)->VaddrSpace,
					IPC_BUFFER_PAGENUM, 1),
	       ObDereferenceObject(*pProcess));

    return STATUS_SUCCESS;
}
