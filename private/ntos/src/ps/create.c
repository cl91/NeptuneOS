#include "psp.h"

static MWORD PspServerPebTebFreeStart = EX_PEB_TEB_REGION_START;
static MWORD PspServerIpcBufferFreeStart = EX_IPC_BUFFER_REGION_START;

static NTSTATUS PspReservePebOrTebServerRegion(IN MWORD RegionSize,
					       OUT PMMVAD *pVad)
{
    assert(pVad != NULL);
    PMMVAD ServerVad = NULL;
    if (!NT_SUCCESS(MmReserveVirtualMemory(PspServerPebTebFreeStart,
					   0, RegionSize,
					   MEM_RESERVE_MIRRORED_MEMORY,
					   &ServerVad))) {
	RET_ERR(MmReserveVirtualMemory(EX_PEB_TEB_REGION_START,
				       EX_PEB_TEB_REGION_END,
				       RegionSize,
				       MEM_RESERVE_MIRRORED_MEMORY,
				       &ServerVad));
    }
    PspServerPebTebFreeStart = ServerVad->AvlNode.Key + ServerVad->WindowSize;
    if (PspServerPebTebFreeStart >= EX_PEB_TEB_REGION_END) {
	PspServerPebTebFreeStart = EX_PEB_TEB_REGION_START;
    }
    *pVad = ServerVad;
    return STATUS_SUCCESS;
}

static NTSTATUS PspReserveIpcBufferServerRegion(OUT PMMVAD *pVad)
{
    assert(pVad != NULL);
    PMMVAD ServerVad = NULL;
    if (!NT_SUCCESS(MmReserveVirtualMemory(PspServerIpcBufferFreeStart,
					   0, IPC_BUFFER_RESERVE,
					   MEM_RESERVE_MIRRORED_MEMORY,
					   &ServerVad))) {
	RET_ERR(MmReserveVirtualMemory(EX_IPC_BUFFER_REGION_START,
				       EX_IPC_BUFFER_REGION_END,
				       IPC_BUFFER_RESERVE,
				       MEM_RESERVE_MIRRORED_MEMORY,
				       &ServerVad));
    }
    PspServerIpcBufferFreeStart = ServerVad->AvlNode.Key + ServerVad->WindowSize;
    if (PspServerIpcBufferFreeStart >= EX_IPC_BUFFER_REGION_END) {
	PspServerIpcBufferFreeStart = EX_IPC_BUFFER_REGION_START;
    }
    *pVad = ServerVad;
    return STATUS_SUCCESS;
}

static NTSTATUS PspConfigureThread(IN MWORD Tcb,
				   IN MWORD FaultHandler,
				   IN PCNODE CNode,
				   IN PVIRT_ADDR_SPACE VaddrSpace,
				   IN PPAGING_STRUCTURE IpcPage)
{
    assert(CNode != NULL);
    assert(VaddrSpace != NULL);
    assert(IpcPage != NULL);
    int Error = seL4_TCB_Configure(Tcb, FaultHandler, CNode->TreeNode.Cap,
				   seL4_CNode_CapData_new(0, MWORD_BITS - CNode->Log2Size).words[0],
				   VaddrSpace->VSpaceCap, 0, IpcPage->AvlNode.Key,
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

    PMMVAD ClientIpcBufferVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, IPC_BUFFER_START, 0,
					IPC_BUFFER_RESERVE, MEM_RESERVE_OWNED_MEMORY,
					&ClientIpcBufferVad),
	       ObDereferenceObject(Thread));
    assert(ClientIpcBufferVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, IPC_BUFFER_START,
				       IPC_BUFFER_COMMIT, 0),
	       ObDereferenceObject(Thread));
    Thread->IpcBufferClientPage = MmQueryPage(&Process->VSpace, IPC_BUFFER_START);
    assert(Thread->IpcBufferClientPage != NULL);
    PMMVAD ServerIpcBufferVad = NULL;
    RET_ERR_EX(PspReserveIpcBufferServerRegion(&ServerIpcBufferVad),
	       ObDereferenceObject(Thread));
    MmRegisterMirroredMemory(ServerIpcBufferVad, ClientIpcBufferVad, 0);
    RET_ERR_EX(MmCommitVirtualMemory(ServerIpcBufferVad->AvlNode.Key,
				     ClientIpcBufferVad->OwnedMemory.CommitmentSize),
	       ObDereferenceObject(Thread));
    Thread->IpcBufferServerAddr = ServerIpcBufferVad->AvlNode.Key;

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
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, THREAD_STACK_START,
					HIGHEST_USER_ADDRESS, StackReserve,
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
	/* Thread is the initial thread in the process */
	PMMVAD ClientPebVad = NULL;
	RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, WIN32_PEB_START, 0, sizeof(PEB),
					    MEM_RESERVE_OWNED_MEMORY, &ClientPebVad),
		   ObDereferenceObject(Thread));
	assert(ClientPebVad != NULL);
	RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, ClientPebVad->AvlNode.Key,
					   ClientPebVad->WindowSize, 0),
		   ObDereferenceObject(Thread));
	Process->PEBClientAddr = ClientPebVad->AvlNode.Key;
	PMMVAD ServerPebVad = NULL;
	RET_ERR_EX(PspReservePebOrTebServerRegion(sizeof(PEB), &ServerPebVad),
		   ObDereferenceObject(Thread));
	MmRegisterMirroredMemory(ServerPebVad, ClientPebVad, 0);
	RET_ERR_EX(MmCommitVirtualMemory(ServerPebVad->AvlNode.Key, ServerPebVad->WindowSize),
		   ObDereferenceObject(Thread));
	Process->PEBServerAddr = ServerPebVad->AvlNode.Key;
	/* Use the .tls subsection of the PE image map for SystemDll TLS region */
	assert(PspSystemDllTlsSubsection != NULL);
	assert(PspSystemDllTlsSubsection->ImageSection != NULL);
	Thread->SystemDllTlsBase = PspSystemDllTlsSubsection->ImageSection->ImageBase +
	    PspSystemDllTlsSubsection->SubSectionBase;
    } else {
	/* Allocate SystemDll TLS region */
	assert(PspSystemDllTlsSubsection != NULL);
	PMMVAD SystemDllTlsVad = NULL;
	RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, SYSTEM_DLL_TLS_REGION_START,
					    SYSTEM_DLL_TLS_REGION_END,
					    PspSystemDllTlsSubsection->SubSectionSize,
					    MEM_RESERVE_OWNED_MEMORY, &SystemDllTlsVad),
		   ObDereferenceObject(Thread));
	assert(SystemDllTlsVad != NULL);
	RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, SystemDllTlsVad->AvlNode.Key,
					   SystemDllTlsVad->WindowSize, 0),
		   ObDereferenceObject(Thread));
	Thread->SystemDllTlsBase = SystemDllTlsVad->AvlNode.Key;
    }
    assert(Process->PEBClientAddr);
    assert(Process->PEBServerAddr);

    PMMVAD ClientTebVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, WIN32_TEB_START, WIN32_TEB_END, sizeof(TEB),
					MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_TOP_DOWN,
					&ClientTebVad),
	       ObDereferenceObject(Thread));
    assert(ClientTebVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, ClientTebVad->AvlNode.Key,
				       ClientTebVad->WindowSize, 0),
	       ObDereferenceObject(Thread));
    Thread->TEBClientAddr = ClientTebVad->AvlNode.Key;
    PMMVAD ServerTebVad = NULL;
    RET_ERR_EX(PspReservePebOrTebServerRegion(sizeof(TEB), &ServerTebVad),
	       ObDereferenceObject(Thread));
    MmRegisterMirroredMemory(ServerTebVad, ClientTebVad, 0);
    RET_ERR_EX(MmCommitVirtualMemory(ServerTebVad->AvlNode.Key, ServerTebVad->WindowSize),
	       ObDereferenceObject(Thread));
    Thread->TEBServerAddr = ServerTebVad->AvlNode.Key;
    PTEB Teb = (PTEB) Thread->TEBServerAddr;
    Teb->ThreadLocalStoragePointer = (PVOID) Thread->SystemDllTlsBase;

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
    MmDbgDumpSection(Section);

    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, Section, 
				  NULL, NULL, NULL),
	       ObDereferenceObject(Section));
    Process->ImageSection = Section;
    Process->ImageFile = ImageFile;
    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, PspSystemDllSection,
				  NULL, NULL, NULL),
	       ObDereferenceObject(Process));

    InsertTailList(&PspProcessList, &Process->ProcessListEntry);
    *pProcess = Process;
    return STATUS_SUCCESS;
}
