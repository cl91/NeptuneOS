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
				   VaddrSpace->VSpaceCap, 0, IPC_BUFFER_START,
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

    assert(TcbUntyped->TreeNode.CSpace != NULL);
    Thread->TreeNode.CSpace = TcbUntyped->TreeNode.CSpace;
    RET_ERR_EX(MmRetypeIntoObject(TcbUntyped, seL4_TCBObject,
				  seL4_TCBBits, &Thread->TreeNode),
	       MmReleaseUntyped(TcbUntyped));

    InitializeListHead(&Thread->ThreadListEntry);

    return STATUS_SUCCESS;
}

NTSTATUS PspProcessObjectCreateProc(IN POBJECT Object)
{
    PPROCESS Process = (PPROCESS) Object;
    memset(Process, 0, sizeof(PROCESS));

    RET_ERR(MmCreateCNode(PROCESS_INIT_CNODE_LOG2SIZE, &Process->CSpace));
    RET_ERR_EX(MmCreateVSpace(&Process->VSpace), MmDeleteCNode(Process->CSpace));

    InitializeListHead(&Process->ThreadList);
    InitializeListHead(&Process->ProcessListEntry);

    /* Assign an ASID for the virtual address space just created */
    RET_ERR_EX(MmAssignASID(&Process->VSpace),
	       {
		   MmDestroyVSpace(&Process->VSpace);
		   MmDeleteCNode(Process->CSpace);
	       });

    return STATUS_SUCCESS;
}

static NTSTATUS PspLoadThreadContext(IN PTHREAD Thread,
				     IN PTHREAD_CONTEXT Context)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_ReadRegisters(Thread->TreeNode.Cap, 0, 0,
				       sizeof(THREAD_CONTEXT) / sizeof(MWORD),
				       Context);

    if (Error != 0) {
	DbgTrace("seL4_TCB_ReadRegisters failed for thread cap 0x%zx with error %d\n",
		 Thread->TreeNode.Cap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PspSetThreadContext(IN PTHREAD Thread,
				    IN PTHREAD_CONTEXT Context)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_WriteRegisters(Thread->TreeNode.Cap, 0, 0,
					sizeof(THREAD_CONTEXT) / sizeof(MWORD),
					Context);

    if (Error != 0) {
	DbgTrace("seL4_TCB_WriteRegisters failed for thread cap 0x%zx with error %d\n",
		 Thread->TreeNode.Cap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PspSetThreadPriority(IN PTHREAD Thread,
				     IN THREAD_PRIORITY Priority)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_SetPriority(Thread->TreeNode.Cap, ROOT_TCB_CAP, Priority);

    if (Error != 0) {
	DbgTrace("seL4_TCB_SetPriority failed for thread cap 0x%zx with error %d\n",
		 Thread->TreeNode.Cap, Error);
	return SEL4_ERROR(Error);
    }

    Thread->CurrentPriority = Priority;
    return STATUS_SUCCESS;
}

static NTSTATUS PspResumeThread(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    int Error = seL4_TCB_Resume(Thread->TreeNode.Cap);

    if (Error != 0) {
	DbgTrace("seL4_TCB_Resume failed for thread cap 0x%zx with error %d\n",
		 Thread->TreeNode.Cap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread)
{
    assert(Process);

    if (Process->ImageSection == NULL) {
	return STATUS_NTOS_BUG;
    }

    if (!Process->ImageSection->Flags.Image) {
	return STATUS_NTOS_BUG;
    }

    if (Process->ImageSection->ImageSectionObject == NULL) {
	return STATUS_NTOS_BUG;
    }

    PTHREAD Thread = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (POBJECT *) &Thread));
    Thread->Process = Process;

    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, IPC_BUFFER_START, 0,
					PAGE_SIZE, MEM_RESERVE_OWNED_MEMORY,
					NULL),
	       ObDereferenceObject(Thread));
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, IPC_BUFFER_START,
				       PAGE_SIZE, 0),
	       ObDereferenceObject(Thread));
    Thread->IpcBufferClientPage = MmQueryPage(&Process->VSpace, IPC_BUFFER_START);
    assert(Thread->IpcBufferClientPage != NULL);

    RET_ERR_EX(PspConfigureThread(Thread->TreeNode.Cap,
				  0, /* TODO: Fault handler */
				  Process->CSpace,
				  &Process->VSpace,
				  Thread->IpcBufferClientPage),
	       ObDereferenceObject(Thread));

    ULONG StackReserve = Process->ImageSection->ImageSectionObject->ImageInformation.MaximumStackSize;
    ULONG StackCommit = Process->ImageSection->ImageSectionObject->ImageInformation.CommittedStackSize;
    if (StackCommit > StackReserve) {
	StackCommit = StackReserve;
    }
    PMMVAD StackVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, THREAD_STACK_REGION_START,
					THREAD_STACK_REGION_END, StackReserve,
					MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES, &StackVad),
	       ObDereferenceObject(Thread));
    assert(StackVad != NULL);
    Thread->StackTop = StackVad->AvlNode.Key + StackVad->WindowSize;
    Thread->StackReserve = StackReserve;
    Thread->StackCommit = StackCommit;
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, Thread->StackTop - StackCommit,
				       StackCommit, 0),
	       ObDereferenceObject(Thread));

    if (Process->PEBClientAddr == 0) {
	/* TODO: Map PEB client and server area */
    }
    /* assert(Process->PEBClientAddr); */
    /* assert(Process->PEBServerAddr); */

    PMMVAD TebVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, WIN32_TEB_START, WIN32_TEB_END, sizeof(TEB),
					MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_TOP_DOWN,
					&TebVad),
	       ObDereferenceObject(Thread));
    assert(TebVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, TebVad->AvlNode.Key, TebVad->WindowSize, 0),
	       ObDereferenceObject(Thread));
    Thread->TEBClientAddr = TebVad->AvlNode.Key;
    /* TODO: Map TEB server area */

    THREAD_CONTEXT Context;
    memset(&Context, 0, sizeof(THREAD_CONTEXT));
    PspInitializeThreadContext(Thread, &Context);
    RET_ERR_EX(PspSetThreadContext(Thread, &Context), ObDereferenceObject(Thread));
    RET_ERR_EX(PspSetThreadPriority(Thread, seL4_MaxPrio), ObDereferenceObject(Thread));

    RET_ERR_EX(KeEnableSystemServices(Process, Thread), ObDereferenceObject(Thread));
    RET_ERR_EX(PspResumeThread(Thread), ObDereferenceObject(Thread));

    InsertTailList(&Process->ThreadList, &Thread->ThreadListEntry);
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

    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, Process->ImageSection, 
				  NULL, NULL, NULL),
	       {
		   ObDereferenceObject(Section);
		   ObDereferenceObject(Process);
	       });

    InsertTailList(&PspProcessList, &Process->ProcessListEntry);
    *pProcess = Process;
    return STATUS_SUCCESS;
}
