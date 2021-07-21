#include "psp.h"

extern UCHAR _ntdll_start[];
extern UCHAR _ntdll_end[];

static NTSTATUS PspConfigureThread(IN MWORD Tcb,
				   IN MWORD FaultHandler,
				   IN PMM_CNODE CNode,
				   IN PMM_VADDR_SPACE VaddrSpace,
				   IN PMM_PAGING_STRUCTURE IpcPage)
{
    assert(CNode != NULL);
    assert(VaddrSpace != NULL);
    assert(IpcPage != NULL);
    int Error = seL4_TCB_Configure(Tcb, FaultHandler, CNode->TreeNode.Cap, 0,
				   VaddrSpace->VSpaceCap, 0, IPC_BUFFER_VADDR,
				   IpcPage->TreeNode.Cap);

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
    RET_ERR_EX(MmRetypeIntoObject(TcbUntyped, seL4_TCBObject,
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

    PMM_CNODE CNode = NULL;
    RET_ERR(MmCreateCNode(PROCESS_INIT_CNODE_LOG2SIZE, &CNode));
    assert(CNode != NULL);
    Process->CNode = CNode;

    PMM_UNTYPED VspaceUntyped = NULL;
    RET_ERR_EX(MmRequestUntyped(seL4_VSpaceBits, &VspaceUntyped), MmDeleteCNode(CNode));
    MWORD VspaceCap = 0;
    RET_ERR_EX(MmRetypeIntoObject(VspaceUntyped, seL4_VSpaceObject,
				  seL4_VSpaceBits, &VspaceCap),
	       {
		   MmReleaseUntyped(VspaceUntyped);
		   MmDeleteCNode(CNode);
	       });

    Process->InitThread = NULL;
    InitializeListHead(&Process->ThreadList);
    MmInitializeVaddrSpace(&Process->VaddrSpace, VspaceCap);

    /* Assign an ASID for the virtual address space just created */
    seL4_X86_ASIDPool_Assign(seL4_CapInitThreadASIDPool,
			     Process->VaddrSpace.VSpaceCap);

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread)
{
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (PPVOID) pThread));

    PMM_PAGING_STRUCTURE IpcBuffer = NULL;
    RET_ERR_EX(MmCommitAddrWindowEx(&Process->VaddrSpace, IPC_BUFFER_VADDR,
				    PAGE_SIZE, MM_RIGHTS_RW, TRUE, NULL,
				    &IpcBuffer, 1, NULL),
	       ObDereferenceObject(*pThread));
    assert(IpcBuffer != NULL);
    (*pThread)->IpcBuffer = IpcBuffer;

    RET_ERR_EX(PspConfigureThread((*pThread)->TcbCap,
				  0, /* TODO: Fault handler */
				  Process->CNode,
				  &Process->VaddrSpace,
				  IpcBuffer),
	       ObDereferenceObject(*pThread));

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(OUT PPROCESS *pProcess)
{
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (PPVOID) pProcess));

    RET_ERR_EX(MmReserveVirtualMemoryEx(&(*pProcess)->VaddrSpace,
					IPC_BUFFER_VADDR, PAGE_SIZE),
	       ObDereferenceObject(*pProcess));

    return STATUS_SUCCESS;
}
