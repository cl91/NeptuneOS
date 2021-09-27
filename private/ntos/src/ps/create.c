#include "psp.h"

static inline NTSTATUS PspReservePebOrTebServerRegion(IN MWORD RegionSize,
						      OUT PMMVAD *pVad)
{
    return MmReserveVirtualMemory(EX_PEB_TEB_REGION_START,
				  EX_PEB_TEB_REGION_END,
				  RegionSize,
				  MEM_RESERVE_MIRRORED_MEMORY,
				  pVad);
}

static inline NTSTATUS PspReserveIpcBufferServerRegion(OUT PMMVAD *pVad)
{
    return MmReserveVirtualMemory(EX_IPC_BUFFER_REGION_START,
				  EX_IPC_BUFFER_REGION_END,
				  IPC_BUFFER_RESERVE,
				  MEM_RESERVE_MIRRORED_MEMORY,
				  pVad);
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
	       ObDeleteObject(Thread));
    assert(ClientIpcBufferVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, IPC_BUFFER_START,
				       IPC_BUFFER_COMMIT, 0),
	       ObDeleteObject(Thread));
    Thread->IpcBufferClientPage = MmQueryPage(&Process->VSpace, IPC_BUFFER_START);
    assert(Thread->IpcBufferClientPage != NULL);
    PMMVAD ServerIpcBufferVad = NULL;
    RET_ERR_EX(PspReserveIpcBufferServerRegion(&ServerIpcBufferVad),
	       ObDeleteObject(Thread));
    MmRegisterMirroredMemory(ServerIpcBufferVad, ClientIpcBufferVad, 0);
    RET_ERR_EX(MmCommitVirtualMemory(ServerIpcBufferVad->AvlNode.Key,
				     ClientIpcBufferVad->OwnedMemory.CommitmentSize),
	       ObDeleteObject(Thread));
    Thread->IpcBufferServerAddr = ServerIpcBufferVad->AvlNode.Key;

    RET_ERR_EX(PspConfigureThread(Thread->TreeNode.Cap,
				  0, /* TODO: Fault handler */
				  Process->CSpace,
				  &Process->VSpace,
				  Thread->IpcBufferClientPage),
	       ObDeleteObject(Thread));

    ULONG StackReserve = Process->ImageSection->ImageSectionObject->ImageInformation.MaximumStackSize;
    ULONG StackCommit = Process->ImageSection->ImageSectionObject->ImageInformation.CommittedStackSize;
    if (StackCommit > StackReserve) {
	StackCommit = StackReserve;
    }
    PMMVAD StackVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, THREAD_STACK_START,
					HIGHEST_USER_ADDRESS, StackReserve,
					MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES, &StackVad),
	       ObDeleteObject(Thread));
    assert(StackVad != NULL);
    Thread->StackTop = StackVad->AvlNode.Key + StackVad->WindowSize;
    Thread->StackReserve = StackReserve;
    Thread->StackCommit = StackCommit;
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, Thread->StackTop - StackCommit,
				       StackCommit, 0),
	       ObDeleteObject(Thread));

    if (Process->PEBClientAddr == 0) {
	/* Thread is the initial thread in the process. Use the .tls subsection
	 * of the mapped NTDLL PE image for SystemDll TLS region */
	assert(PspSystemDllTlsSubsection != NULL);
	assert(PspSystemDllTlsSubsection->ImageSection != NULL);
	Thread->SystemDllTlsBase = PspSystemDllTlsSubsection->ImageSection->ImageBase +
	    PspSystemDllTlsSubsection->SubSectionBase;
	/* Populate the process init info used by ntdll on process startup */
	*((PNTDLL_PROCESS_INIT_INFO) Thread->IpcBufferServerAddr) = Process->InitInfo;
    } else {
	/* Allocate SystemDll TLS region */
	assert(PspSystemDllTlsSubsection != NULL);
	PMMVAD SystemDllTlsVad = NULL;
	RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, SYSTEM_DLL_TLS_REGION_START,
					    SYSTEM_DLL_TLS_REGION_END,
					    PspSystemDllTlsSubsection->SubSectionSize,
					    MEM_RESERVE_OWNED_MEMORY, &SystemDllTlsVad),
		   ObDeleteObject(Thread));
	assert(SystemDllTlsVad != NULL);
	RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, SystemDllTlsVad->AvlNode.Key,
					   SystemDllTlsVad->WindowSize, 0),
		   ObDeleteObject(Thread));
	Thread->SystemDllTlsBase = SystemDllTlsVad->AvlNode.Key;
    }
    assert(Process->PEBClientAddr);
    assert(Process->PEBServerAddr);

    PMMVAD ClientTebVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, WIN32_TEB_START, WIN32_TEB_END, sizeof(TEB),
					MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_TOP_DOWN,
					&ClientTebVad),
	       ObDeleteObject(Thread));
    assert(ClientTebVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, ClientTebVad->AvlNode.Key,
				       ClientTebVad->WindowSize, 0),
	       ObDeleteObject(Thread));
    Thread->TEBClientAddr = ClientTebVad->AvlNode.Key;
    PMMVAD ServerTebVad = NULL;
    RET_ERR_EX(PspReservePebOrTebServerRegion(sizeof(TEB), &ServerTebVad),
	       ObDeleteObject(Thread));
    MmRegisterMirroredMemory(ServerTebVad, ClientTebVad, 0);
    RET_ERR_EX(MmCommitVirtualMemory(ServerTebVad->AvlNode.Key, ServerTebVad->WindowSize),
	       ObDeleteObject(Thread));
    Thread->TEBServerAddr = ServerTebVad->AvlNode.Key;
    PTEB Teb = (PTEB) Thread->TEBServerAddr;
    Teb->ThreadLocalStoragePointer = (PVOID) Thread->SystemDllTlsBase;

    THREAD_CONTEXT Context;
    memset(&Context, 0, sizeof(THREAD_CONTEXT));
    PspInitializeThreadContext(Thread, &Context);
    RET_ERR_EX(PspSetThreadContext(Thread, &Context), ObDeleteObject(Thread));
    RET_ERR_EX(PspSetThreadPriority(Thread, seL4_MaxPrio), ObDeleteObject(Thread));
    RET_ERR_EX(KeEnableSystemServices(Process, Thread), ObDeleteObject(Thread));
    RET_ERR_EX(PspResumeThread(Thread), ObDeleteObject(Thread));

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

    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, PspSystemDllSection,
				  NULL, NULL, NULL),
	       ObDeleteObject(Process));

    PSECTION Section = NULL;
    RET_ERR(MmCreateSection(ImageFile, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			    &Section));
    assert(Section != NULL);
    MmDbgDumpSection(Section);

    MWORD ImageBaseAddress = 0;
    MWORD ImageVirtualSize = 0;
    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, Section, 
				  &ImageBaseAddress, NULL, &ImageVirtualSize),
	       {
		   ObDeleteObject(Section);
		   ObDeleteObject(Process);
	       });
    assert(ImageBaseAddress != 0);
    assert(ImageVirtualSize != 0);
    Process->ImageSection = Section;
    Process->ImageFile = ImageFile;

    /* Reserve and commit the loader private heap */
    MWORD LoaderHeapStart = ImageBaseAddress + ImageVirtualSize;
    RET_ERR_EX(MmReserveVirtualMemory(LoaderHeapStart, 0, NTDLL_LOADER_HEAP_RESERVE,
				      MEM_RESERVE_OWNED_MEMORY, NULL),
	       ObDeleteObject(Process));
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, LoaderHeapStart,
				       NTDLL_LOADER_HEAP_COMMIT, 0),
	       ObDeleteObject(Process));
    Process->InitInfo.LoaderHeapStart = LoaderHeapStart;

    /* Reserve and commit the process heap */
    PIMAGE_NT_HEADERS NtHeader = PspImageNtHeader(ImageFile->BufferPtr);
    MWORD ProcessHeapStart = LoaderHeapStart + NTDLL_LOADER_HEAP_RESERVE;
    MWORD ProcessHeapReserve = PAGE_ALIGN_UP(NtHeader->OptionalHeader.SizeOfHeapReserve);
    MWORD ProcessHeapCommit = PAGE_ALIGN_UP(NtHeader->OptionalHeader.SizeOfHeapCommit);
    if (ProcessHeapReserve == 0) {
	ProcessHeapReserve = PROCESS_HEAP_DEFAULT_RESERVE;
    }
    if (ProcessHeapCommit == 0) {
	ProcessHeapCommit = PROCESS_HEAP_DEFAULT_COMMIT;
    }
    if (ProcessHeapReserve < ProcessHeapCommit) {
	ProcessHeapReserve = ProcessHeapCommit;
    }
    RET_ERR_EX(MmReserveVirtualMemory(ProcessHeapStart, 0, ProcessHeapReserve,
				      MEM_RESERVE_OWNED_MEMORY, NULL),
	       ObDeleteObject(Process));
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, ProcessHeapStart,
				       ProcessHeapCommit, 0),
	       ObDeleteObject(Process));
    Process->InitInfo.ProcessHeapStart = ProcessHeapStart;
    Process->InitInfo.ProcessHeapReserve = ProcessHeapReserve;
    Process->InitInfo.ProcessHeapCommit = ProcessHeapCommit;

    /* Map and initialize the Process Environment Block */
    PMMVAD ClientPebVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, WIN32_PEB_START, 0, sizeof(PEB),
					MEM_RESERVE_OWNED_MEMORY, &ClientPebVad),
	       ObDeleteObject(Process));
    assert(ClientPebVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, ClientPebVad->AvlNode.Key,
				       ClientPebVad->WindowSize, 0),
	       ObDeleteObject(Process));
    Process->PEBClientAddr = ClientPebVad->AvlNode.Key;
    PMMVAD ServerPebVad = NULL;
    RET_ERR_EX(PspReservePebOrTebServerRegion(sizeof(PEB), &ServerPebVad),
	       ObDeleteObject(Process));
    MmRegisterMirroredMemory(ServerPebVad, ClientPebVad, 0);
    RET_ERR_EX(MmCommitVirtualMemory(ServerPebVad->AvlNode.Key, ServerPebVad->WindowSize),
	       ObDeleteObject(Process));
    Process->PEBServerAddr = ServerPebVad->AvlNode.Key;
    PPEB Peb = (PPEB) Process->PEBServerAddr;
    Peb->ImageBaseAddress = (HMODULE) ImageBaseAddress;

    InsertTailList(&PspProcessList, &Process->ProcessListEntry);
    *pProcess = Process;
    return STATUS_SUCCESS;
}

NTSTATUS NtCreateThread(IN PTHREAD Thread,
                        OUT HANDLE *ThreadHandle,
                        IN ACCESS_MASK DesiredAccess,
                        IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                        IN HANDLE ProcessHandle,
                        OUT CLIENT_ID *ClientId,
                        IN PCONTEXT ThreadContext,
                        IN PINITIAL_TEB InitialTeb,
                        IN BOOLEAN CreateSuspended)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtCreateProcess(IN PTHREAD Thread,
                         OUT HANDLE *ProcessHandle,
                         IN ACCESS_MASK DesiredAccess,
                         IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                         IN HANDLE ParentProcess,
                         IN BOOLEAN InheritObjectTable,
                         IN HANDLE SectionHandle,
                         IN HANDLE DebugPort,
                         IN HANDLE ExceptionPort)
{
    return STATUS_NOT_IMPLEMENTED;
}
