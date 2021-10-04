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

VOID PspPopulateTeb(IN PTHREAD Thread)
{
    PTEB Teb = (PTEB) Thread->TebServerAddr;
    Teb->ThreadLocalStoragePointer = (PVOID) Thread->SystemDllTlsBase;
    Teb->NtTib.Self = (PNT_TIB) Thread->TebClientAddr;
    Teb->ProcessEnvironmentBlock = (PPEB) Thread->Process->PebClientAddr;
}

VOID PspPopulatePeb(IN PPROCESS Process)
{
    PPEB Peb = (PPEB) Process->PebServerAddr;
    Peb->ImageBaseAddress = (HMODULE) Process->ImageBaseAddress;
    Peb->MaximumNumberOfHeaps = (PAGE_SIZE - sizeof(PEB)) / sizeof(PVOID);
    /* Place the process heap book keeping structures immediately after the PEB */
    Peb->ProcessHeaps = (PPVOID)(Process->PebClientAddr + sizeof(PEB));
}

static inline NTSTATUS PspMapSharedRegion(IN PPROCESS Process,
					  IN MWORD ServerStart,
					  IN MWORD ServerEnd,
					  IN MWORD ReserveSize,
					  IN MWORD CommitSize,
					  IN MWORD ClientStart,
					  IN MWORD ClientEnd,
					  IN MWORD ClientReserveFlag,
					  OUT PMMVAD *ServerVad,
					  OUT PMMVAD *ClientVad)
{
    RET_ERR(MmReserveVirtualMemory(ServerStart, ServerEnd, ReserveSize,
				   MEM_RESERVE_OWNED_MEMORY, ServerVad));
    assert(*ServerVad != NULL);
    assert((*ServerVad)->AvlNode.Key != 0);
    RET_ERR(MmCommitVirtualMemory((*ServerVad)->AvlNode.Key, ReserveSize));

    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, ClientStart, ClientEnd,
				     ReserveSize, MEM_RESERVE_MIRRORED_MEMORY | ClientReserveFlag,
				     ClientVad));
    assert(*ClientVad != NULL);
    assert((*ClientVad)->AvlNode.Key != 0);
    MmRegisterMirroredMemory(*ClientVad, *ServerVad, 0);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, (*ClientVad)->AvlNode.Key, CommitSize, 0));

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

    PMMVAD ServerIpcBufferVad = NULL;
    PMMVAD ClientIpcBufferVad = NULL;
    RET_ERR_EX(PspMapSharedRegion(Process,
				  EX_IPC_BUFFER_REGION_START,
				  EX_IPC_BUFFER_REGION_END,
				  IPC_BUFFER_RESERVE,
				  IPC_BUFFER_COMMIT,
				  IPC_BUFFER_START,
				  IPC_BUFFER_END,
				  0,
				  &ServerIpcBufferVad,
				  &ClientIpcBufferVad),
	       ObDeleteObject(Thread));
    Thread->IpcBufferServerAddr = ServerIpcBufferVad->AvlNode.Key;
    Thread->IpcBufferClientAddr = ClientIpcBufferVad->AvlNode.Key;

    PPAGING_STRUCTURE IpcBufferClientPage = MmQueryPage(&Process->VSpace,
							Thread->IpcBufferClientAddr);
    assert(IpcBufferClientPage != NULL);
    RET_ERR_EX(PspConfigureThread(Thread->TreeNode.Cap,
				  0, /* TODO: Fault handler */
				  Process->CSpace,
				  &Process->VSpace,
				  IpcBufferClientPage),
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

    if (Process->InitThread == NULL) {
	/* Thread is the initial thread in the process. Use the .tls subsection
	 * of the mapped NTDLL PE image for SystemDll TLS region */
	assert(PspSystemDllTlsSubsection != NULL);
	assert(PspSystemDllTlsSubsection->ImageSection != NULL);
	Thread->SystemDllTlsBase = PspSystemDllTlsSubsection->ImageSection->ImageBase +
	    PspSystemDllTlsSubsection->SubSectionBase;
	/* Populate the process init info used by ntdll on process startup */
	*((PNTDLL_PROCESS_INIT_INFO) Thread->IpcBufferServerAddr) = Process->InitInfo;
	Thread->EntryPoint = Process->ImageEntryPoint;
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

    /* Allocate and populate the Thread Environment Block */
    PMMVAD ServerTebVad = NULL;
    PMMVAD ClientTebVad = NULL;
    RET_ERR_EX(PspMapSharedRegion(Process,
				  EX_PEB_TEB_REGION_START,
				  EX_PEB_TEB_REGION_END,
				  sizeof(TEB),
				  sizeof(TEB),
				  WIN32_TEB_START,
				  WIN32_TEB_END,
				  MEM_RESERVE_TOP_DOWN,
				  &ServerTebVad,
				  &ClientTebVad),
	       ObDeleteObject(Thread));
    Thread->TebServerAddr = ServerTebVad->AvlNode.Key;
    Thread->TebClientAddr = ClientTebVad->AvlNode.Key;
    /* Populate the Thread Environment Block */
    PspPopulateTeb(Thread);

    THREAD_CONTEXT Context;
    memset(&Context, 0, sizeof(THREAD_CONTEXT));
    PspInitializeThreadContext(Thread, &Context);
    RET_ERR_EX(PspSetThreadContext(Thread, &Context), ObDeleteObject(Thread));
    RET_ERR_EX(PspSetThreadPriority(Thread, seL4_MaxPrio), ObDeleteObject(Thread));
    RET_ERR_EX(KeEnableSystemServices(Process, Thread), ObDeleteObject(Thread));
    RET_ERR_EX(PspResumeThread(Thread), ObDeleteObject(Thread));

    if (Process->InitThread == NULL) {
	Process->InitThread = Thread;
    }
    InsertTailList(&Process->ThreadList, &Thread->ThreadListEntry);
    *pThread = Thread;
    return STATUS_SUCCESS;
}

static inline NTSTATUS PspPopulateLoaderSharedData(IN PPROCESS Process,
						   IN OUT MWORD *LoaderDataOffset,
						   IN PCSTR DllPath,
						   IN MWORD ImageBase)
{
    SIZE_T DllPathLength = strlen(DllPath);
    if (*LoaderDataOffset + sizeof(LDRP_LOADED_MODULE) + DllPathLength >= LOADER_SHARED_DATA_COMMIT) {
	return STATUS_NO_MEMORY;
    }
    PLDRP_LOADED_MODULE LoadedModule = (PLDRP_LOADED_MODULE)(Process->LoaderSharedDataServerAddr + *LoaderDataOffset);
    LoadedModule->DllPath = *LoaderDataOffset + sizeof(LDRP_LOADED_MODULE);
    LoadedModule->ImageBase = ImageBase;
    PUCHAR DllPathCopy = (PUCHAR)(Process->LoaderSharedDataServerAddr + LoadedModule->DllPath);
    memcpy(DllPathCopy, DllPath, DllPathLength + 1); /* trailing '\0' */
    *LoaderDataOffset += sizeof(LDRP_LOADED_MODULE) + DllPathLength + 1; /* trailing '\0' */
    return STATUS_SUCCESS;
}

/*
 * Search the given dll name in the process's PATH and map the dll if found.
 * Write the loader shared data and return the dll file object.
 *
 * If the dll is already mapped, nothing will be done, and DllFile will be
 * set to NULL.
 */
static NTSTATUS PspMapDll(IN PPROCESS Process,
			  IN OUT MWORD *LoaderDataOffset,
			  IN PCSTR DllName,
			  OUT PFILE_OBJECT *DllFile)
{
    DbgTrace("DllName = %s\n", DllName);
    if (!strcmp("ntdll.dll", DllName) || !strcmp("ntdll", DllName)) {
	*DllFile = NULL;
	return STATUS_SUCCESS;
    }
    /* TODO: Actually read and map the dll file */
    /* TODO: Call PspPopulateLoaderSharedData once done */
    return STATUS_SUCCESS;
}

static NTSTATUS PspMapDependencies(IN PPROCESS Process,
				   IN OUT MWORD *LoaderDataOffset,
				   IN PVOID DllFileBuffer)
{
    SIZE_T ImportTableSize = 0;
    PIMAGE_IMPORT_DESCRIPTOR ImportTable =
	RtlImageDirectoryEntryToData(DllFileBuffer, FALSE,
				     IMAGE_DIRECTORY_ENTRY_IMPORT,
				     &ImportTableSize);
    DbgTrace("ImportTableSize = 0x%zx\n", ImportTableSize);
    SIZE_T ImportDescriptorCount = ImportTableSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (ULONG i = 0; i < ImportDescriptorCount; i++) {
	if (ImportTable[i].Name != 0) {
	    PCSTR DllName = RtlImageRvaToPtr(DllFileBuffer, ImportTable[i].Name);
	    PFILE_OBJECT DllFile = NULL;
	    RET_ERR(PspMapDll(Process, LoaderDataOffset, DllName, &DllFile));
	    if (DllFile != NULL) {
		RET_ERR(PspMapDependencies(Process, LoaderDataOffset, DllFile->BufferPtr));
	    }
	}
    }
    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(IN PFILE_OBJECT ImageFile,
			 OUT PPROCESS *pProcess)
{
    assert(ImageFile != NULL);
    assert(pProcess != NULL);

    PPROCESS Process = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (POBJECT *) &Process));

    MWORD NtdllBase = 0;
    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, PspSystemDllSection,
				  &NtdllBase, NULL, NULL),
	       ObDeleteObject(Process));
    assert(NtdllBase != 0);

    PSECTION Section = NULL;
    RET_ERR(MmCreateSection(ImageFile, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			    &Section));
    assert(Section != NULL);

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
    Process->ImageBaseAddress = ImageBaseAddress;
    Process->ImageVirtualSize = ImageVirtualSize;
    Process->ImageEntryPoint = (MWORD) Section->ImageSectionObject->ImageInformation.TransferAddress;
    Process->ImageSection = Section;
    Process->ImageFile = ImageFile;

    /* Reserve and commit the loader private heap */
    MWORD LoaderHeapStart = ImageBaseAddress + ImageVirtualSize;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, LoaderHeapStart, 0, NTDLL_LOADER_HEAP_RESERVE,
				      MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES, NULL),
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
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, ProcessHeapStart, 0, ProcessHeapReserve,
				      MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES, NULL),
	       ObDeleteObject(Process));
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, ProcessHeapStart,
				       ProcessHeapCommit, 0),
	       ObDeleteObject(Process));
    Process->InitInfo.ProcessHeapStart = ProcessHeapStart;
    Process->InitInfo.ProcessHeapReserve = ProcessHeapReserve;
    Process->InitInfo.ProcessHeapCommit = ProcessHeapCommit;

    /* Map and initialize the Process Environment Block */
    PMMVAD ServerPebVad = NULL;
    PMMVAD ClientPebVad = NULL;
    RET_ERR_EX(PspMapSharedRegion(Process,
				  EX_PEB_TEB_REGION_START,
				  EX_PEB_TEB_REGION_END,
				  sizeof(PEB),
				  sizeof(PEB),
				  WIN32_PEB_START,
				  0, 0,
				  &ServerPebVad,
				  &ClientPebVad),
	       ObDeleteObject(Process));
    Process->PebServerAddr = ServerPebVad->AvlNode.Key;
    Process->PebClientAddr = ClientPebVad->AvlNode.Key;
    /* Populate the Process Environment Block */
    PspPopulatePeb(Process);

    /* Map the KUSER_SHARED_DATA into the client address space */
    PMMVAD ClientSharedDataVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, KUSER_SHARED_DATA_CLIENT_ADDR,
					0, sizeof(KUSER_SHARED_DATA),
					MEM_RESERVE_MIRRORED_MEMORY,
					&ClientSharedDataVad),
	       ObDeleteObject(Process));
    assert(ClientSharedDataVad != NULL);
    assert(ClientSharedDataVad->AvlNode.Key == KUSER_SHARED_DATA_CLIENT_ADDR);
    MmRegisterMirroredMemory(ClientSharedDataVad, PspUserSharedDataVad, 0);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, KUSER_SHARED_DATA_CLIENT_ADDR,
				       sizeof(KUSER_SHARED_DATA), 0),
	       ObDeleteObject(Process));

    /* Map the loader shared data */
    PMMVAD ServerLoaderSharedDataVad = NULL;
    PMMVAD ClientLoaderSharedDataVad = NULL;
    RET_ERR_EX(PspMapSharedRegion(Process,
				  EX_LOADER_SHARED_REGION_START,
				  EX_LOADER_SHARED_REGION_END,
				  LOADER_SHARED_DATA_RESERVE,
				  LOADER_SHARED_DATA_COMMIT,
				  LOADER_SHARED_DATA_CLIENT_ADDR,
				  0, 0,
				  &ServerLoaderSharedDataVad,
				  &ClientLoaderSharedDataVad),
	       ObDeleteObject(Process));
    Process->LoaderSharedDataServerAddr = ServerLoaderSharedDataVad->AvlNode.Key;
    Process->LoaderSharedDataClientAddr = ClientLoaderSharedDataVad->AvlNode.Key;

    /* Walk the import table and map the dependencies recursively */
    PLOADER_SHARED_DATA LoaderSharedData = (PLOADER_SHARED_DATA) Process->LoaderSharedDataServerAddr;
    MWORD LoaderDataOffset = sizeof(LOADER_SHARED_DATA);
    RET_ERR_EX(PspPopulateLoaderSharedData(Process, &LoaderDataOffset,
					   "ntdll.dll", NtdllBase),
	       ObDeleteObject(Process));
    RET_ERR_EX(PspMapDependencies(Process, &LoaderDataOffset, ImageFile->BufferPtr),
	       ObDeleteObject(Process));

    /* Create the Event objects used by the NTDLL ldr component */
    /* FIXME: TODO */
    Process->InitInfo.ProcessHeapLockSemaphore = (HANDLE) 3;
    Process->InitInfo.LoaderHeapLockSemaphore = (HANDLE) 3;

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
