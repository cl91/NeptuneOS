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
    memset(Thread, 0, sizeof(THREAD));

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
    Process->ImageSection = NULL;
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

static NTSTATUS PspLoadThreadContext(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_ReadRegisters(Thread->TcbCap, 0, 0,
				       sizeof(THREAD_CONTEXT) / sizeof(MWORD),
				       &Thread->Context);

    if (Error != 0) {
	DbgTrace("seL4_TCB_ReadRegisters failed for thread cap 0x%zx with error %zd\n",
		 Thread->TcbCap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PspSetThreadContext(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_WriteRegisters(Thread->TcbCap, 0, 0,
					sizeof(THREAD_CONTEXT) / sizeof(MWORD),
					&Thread->Context);

    if (Error != 0) {
	DbgTrace("seL4_TCB_WriteRegisters failed for thread cap 0x%zx with error %zd\n",
		 Thread->TcbCap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PspSetThreadPriority(IN PTHREAD Thread,
				     IN THREAD_PRIORITY Priority)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_SetPriority(Thread->TcbCap, ROOT_TCB_CAP, Priority);

    if (Error != 0) {
	DbgTrace("seL4_TCB_SetPriority failed for thread cap 0x%zx with error %zd\n",
		 Thread->TcbCap, Error);
	return SEL4_ERROR(Error);
    }

    Thread->CurrentPriority = Priority;
    return STATUS_SUCCESS;
}

static NTSTATUS PspResumeThread(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_Resume(Thread->TcbCap);

    if (Error != 0) {
	DbgTrace("seL4_TCB_Resume failed for thread cap 0x%zx with error %zd\n",
		 Thread->TcbCap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread)
{
    assert(Process);

    if (Process->ImageSection == NULL) {
	return STATUS_NTOS_UNIMPLEMENTED;
    }

    if (!Process->ImageSection->Flags.Image) {
	return STATUS_NTOS_BUG;
    }

    if (Process->ImageSection->ImageSectionObject == NULL) {
	return STATUS_NTOS_BUG;
    }

    PTHREAD Thread = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (POBJECT *) &Thread));

    RET_ERR_EX(MmAllocatePrivateMemoryEx(&Process->VaddrSpace, IPC_BUFFER_VADDR,
					 PAGE_SIZE, MEM_COMMIT | MEM_RESERVE,
					 PAGE_READWRITE),
	       ObDereferenceObject(Thread));
    PPAGING_STRUCTURE IpcBuffer = NULL;
    RET_ERR_EX(MmQueryVirtualAddress(&Process->VaddrSpace, IPC_BUFFER_VADDR, &IpcBuffer),
	       return STATUS_NTOS_BUG); /* Should never fail. */
    assert(IpcBuffer != NULL);
    Thread->IpcBuffer = IpcBuffer;

    RET_ERR_EX(PspConfigureThread(Thread->TcbCap,
				  0, /* TODO: Fault handler */
				  Process->CNode,
				  &Process->VaddrSpace,
				  IpcBuffer),
	       ObDereferenceObject(Thread));

    RET_ERR_EX(MmMapViewOfSection(&Process->VaddrSpace, Process->ImageSection, 
				  NULL, NULL, NULL),
	       ObDereferenceObject(Thread));

    ULONG StackCommitSize = Process->ImageSection->ImageSectionObject->ImageInformation.CommittedStackSize;
    if (StackCommitSize > (THREAD_STACK_END - THREAD_STACK_START)) {
	StackCommitSize = THREAD_STACK_END - THREAD_STACK_START;
    }
    RET_ERR_EX(MmAllocatePrivateMemoryEx(&Process->VaddrSpace, THREAD_STACK_END - StackCommitSize,
					 StackCommitSize,
					 MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE),
	       ObDereferenceObject(Thread));

    RET_ERR_EX(PspLoadThreadContext(Thread), ObDereferenceObject(Thread));
    Thread->Context.eip = (MWORD) Process->ImageSection->ImageSectionObject->ImageInformation.TransferAddress;
    Thread->Context.esp = THREAD_STACK_END;
    Thread->Context.ebp = THREAD_STACK_END;

    RET_ERR_EX(PspSetThreadContext(Thread), ObDereferenceObject(Thread));
    RET_ERR_EX(PspSetThreadPriority(Thread, seL4_MaxPrio), ObDereferenceObject(Thread));
    RET_ERR_EX(PspResumeThread(Thread), ObDereferenceObject(Thread));

    *pThread = Thread;
    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(IN PFILE_OBJECT ImageFile,
			 OUT PPROCESS *pProcess)
{
    assert(ImageFile != NULL);
    assert(pProcess != NULL);

    PPROCESS Process = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (POBJECT *) &Process));

    PSECTION Section = NULL;
    RET_ERR(MmCreateSection(ImageFile, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			    &Section));
    assert(Section != NULL);
    Process->ImageSection = Section;
    MmDbgDumpSection(Process->ImageSection);

    *pProcess = Process;
    return STATUS_SUCCESS;
}
