#include "psp.h"

static NTSTATUS PspConfigureThread(IN MWORD Tcb,
				   IN MWORD FaultHandler,
				   IN PCNODE CNode,
				   IN PVIRT_ADDR_SPACE VaddrSpace,
				   IN PPAGING_STRUCTURE IpcPage)
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

NTSTATUS PspThreadObjectCreateProc(IN POBJECT Object)
{
    PTHREAD Thread = (PTHREAD) Object;

    PUNTYPED TcbUntyped = NULL;
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

NTSTATUS PspProcessObjectCreateProc(IN POBJECT Object)
{
    PPROCESS Process = (PPROCESS) Object;

    PCNODE CNode = NULL;
    RET_ERR(MmCreateCNode(PROCESS_INIT_CNODE_LOG2SIZE, &CNode));
    assert(CNode != NULL);
    Process->CNode = CNode;

    PUNTYPED VspaceUntyped = NULL;
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
    RET_ERR_EX(MmAssignASID(&Process->VaddrSpace),
	       {
		   MmReleaseUntyped(VspaceUntyped);
		   MmDeleteCNode(CNode);
	       });

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread)
{
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (POBJECT *) pThread));

    PPAGING_STRUCTURE IpcBuffer = NULL;
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
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (POBJECT *) pProcess));

    RET_ERR_EX(MmReserveVirtualMemoryEx(&(*pProcess)->VaddrSpace,
					IPC_BUFFER_VADDR, PAGE_SIZE),
	       ObDereferenceObject(*pProcess));

    return STATUS_SUCCESS;
}
