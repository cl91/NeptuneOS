#include "psp.h"
#include <halsvc.h>

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

NTSTATUS PspThreadObjectInitProc(IN POBJECT Object)
{
    PTHREAD Thread = (PTHREAD) Object;

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

NTSTATUS PspProcessObjectInitProc(IN POBJECT Object)
{
    PPROCESS Process = (PPROCESS) Object;

    RET_ERR(MmCreateCNode(PROCESS_INIT_CNODE_LOG2SIZE, &Process->CSpace));
    RET_ERR_EX(MmCreateVSpace(&Process->VSpace), MmDeleteCNode(Process->CSpace));

    InitializeListHead(&Process->ThreadList);
    InitializeListHead(&Process->ProcessListEntry);
    ObInitializeHandleTable(&Process->HandleTable);

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
    int Error = seL4_TCB_SetPriority(Thread->TreeNode.Cap, NTEX_TCB_CAP, Priority);

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
    RET_ERR_EX(MmCommitVirtualMemory((*ServerVad)->AvlNode.Key, CommitSize),
	       {});		/* TODO: Unreserve */

    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, ClientStart, ClientEnd,
					ReserveSize, MEM_RESERVE_MIRRORED_MEMORY | ClientReserveFlag,
					ClientVad),
	       {});		/* TODO: Error path */
    assert(*ClientVad != NULL);
    assert((*ClientVad)->AvlNode.Key != 0);
    MmRegisterMirroredVad(*ClientVad, *ServerVad);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, (*ClientVad)->AvlNode.Key, CommitSize),
	       {});		/* TODO: ERROR PATH */

    return STATUS_SUCCESS;
}

static inline VOID PspSetThreadDebugName(IN PTHREAD Thread)
{
#ifdef CONFIG_DEBUG_BUILD
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->Process->ImageFile != NULL);
    assert(Thread->Process->ImageFile->FileName != NULL);
    char NameBuf[seL4_MsgMaxLength * sizeof(MWORD)];
    /* We use the thread object addr to distinguish threads. */
    snprintf(NameBuf, sizeof(NameBuf), "%s!%p", Thread->Process->ImageFile->FileName, Thread);
    seL4_DebugNameThread(Thread->TreeNode.Cap, NameBuf);
#endif
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
			OUT PTHREAD *pThread)
{
    assert(Process != NULL);

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
	       ObDereferenceObject(Thread));
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
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, Thread->StackTop - StackCommit, StackCommit),
	       ObDereferenceObject(Thread));

    if (Process->InitThread == NULL) {
	/* Thread is the initial thread in the process. Use the .tls subsection
	 * of the mapped NTDLL PE image for SystemDll TLS region */
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
					   SystemDllTlsVad->WindowSize),
		   ObDereferenceObject(Thread));
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
	       ObDereferenceObject(Thread));
    Thread->TebServerAddr = ServerTebVad->AvlNode.Key;
    Thread->TebClientAddr = ClientTebVad->AvlNode.Key;
    /* Populate the Thread Environment Block */
    PspPopulateTeb(Thread);

    THREAD_CONTEXT Context;
    memset(&Context, 0, sizeof(THREAD_CONTEXT));
    PspInitializeThreadContext(Thread, &Context);
    RET_ERR_EX(PspSetThreadContext(Thread, &Context), ObDereferenceObject(Thread));
    RET_ERR_EX(PspSetThreadPriority(Thread, seL4_MaxPrio), ObDereferenceObject(Thread));
    RET_ERR_EX(KeEnableSystemServices(Thread), ObDereferenceObject(Thread));
    if (Process->InitInfo.DriverProcess) {
	RET_ERR_EX(KeEnableHalServices(Thread), ObDereferenceObject(Thread));
    }
    PspSetThreadDebugName(Thread);

    if (Process->InitThread == NULL) {
	/* Populate the process init info used by ntdll on process startup */
	Process->InitInfo.ThreadInitInfo = Thread->InitInfo;
	*((PNTDLL_PROCESS_INIT_INFO) Thread->IpcBufferServerAddr) = Process->InitInfo;
    } else {
	/* Populate the thread init info used by ntdll on process startup */
	*((PNTDLL_THREAD_INIT_INFO) Thread->IpcBufferServerAddr) = Thread->InitInfo;
    }

    RET_ERR_EX(PspResumeThread(Thread), ObDereferenceObject(Thread));

    if (Process->InitThread == NULL) {
	Process->InitThread = Thread;
    }
    InsertTailList(&Process->ThreadList, &Thread->ThreadListEntry);
    *pThread = Thread;
    return STATUS_SUCCESS;
}

static inline NTSTATUS PspMarshalString(IN PPROCESS Process,
					IN OUT MWORD *LoaderDataOffset,
					IN PCSTR String,
					OUT MWORD *OutArg)
{
    assert(LoaderDataOffset != NULL);
    assert(IS_ALIGNED(*LoaderDataOffset, MWORD));
    assert(String != NULL);
    SIZE_T Length = strlen(String);
    if (Length == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    if (*LoaderDataOffset + ALIGN_UP(Length+1, MWORD) > LOADER_SHARED_DATA_COMMIT) {
	return STATUS_NO_MEMORY;
    }
    *OutArg = *LoaderDataOffset;
    PUCHAR StrCopy = (PUCHAR)(Process->LoaderSharedDataServerAddr + *LoaderDataOffset);
    memcpy(StrCopy, String, Length + 1); /* trailing '\0' */
    if (!IS_ALIGNED(Length + 1, MWORD)) {
	memset(StrCopy+Length+1, 0, ALIGN_UP(Length+1, MWORD) - (Length+1));
    }
    *LoaderDataOffset += ALIGN_UP(Length + 1, MWORD);
    return STATUS_SUCCESS;
}

/*
 * Serialized format:
 * [LDRP_LOADED_MODULE] [DllPath] [DllName]
 */
static inline NTSTATUS PspPopulateLoaderSharedData(IN PPROCESS Process,
						   IN OUT MWORD *LoaderDataOffset,
						   IN PCSTR DllPath,
						   IN PCSTR DllName,
						   IN MWORD ViewBase,
						   IN MWORD ViewSize)
{
    assert(LoaderDataOffset != NULL);
    assert(IS_ALIGNED(*LoaderDataOffset, MWORD));
    assert(DllPath != NULL);
    assert(DllName != NULL);
    if (*LoaderDataOffset + sizeof(LDRP_LOADED_MODULE) > LOADER_SHARED_DATA_COMMIT) {
	return STATUS_NO_MEMORY;
    }
    PLDRP_LOADED_MODULE LoadedModule = (PLDRP_LOADED_MODULE)(Process->LoaderSharedDataServerAddr + *LoaderDataOffset);
    MWORD OrigLoaderDataOffset = *LoaderDataOffset;
    *LoaderDataOffset += sizeof(LDRP_LOADED_MODULE);
    RET_ERR(PspMarshalString(Process, LoaderDataOffset, DllPath, &LoadedModule->DllPath));
    RET_ERR(PspMarshalString(Process, LoaderDataOffset, DllName, &LoadedModule->DllName));
    LoadedModule->ViewBase = ViewBase;
    LoadedModule->ViewSize = ViewSize;
    LoadedModule->EntrySize = *LoaderDataOffset - OrigLoaderDataOffset;
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
			  IN PLOADER_SHARED_DATA LoaderSharedData,
			  IN OUT MWORD *LoaderDataOffset,
			  IN PCSTR DllName,
			  OUT PIO_FILE_OBJECT *DllFile)
{
    DbgTrace("DllName = %s\n", DllName);
    assert(LoaderDataOffset != NULL);
    assert(DllFile != NULL);
    MWORD OrigLoaderDataOffset = *LoaderDataOffset;

    /* Check the loader shared data to see if the dll has already been mapped */
    PLDRP_LOADED_MODULE LoadedModule = (PLDRP_LOADED_MODULE)((MWORD)LoaderSharedData + LoaderSharedData->LoadedModules);
    for (ULONG i = 0; i < LoaderSharedData->LoadedModuleCount; i++) {
	PCSTR LoadedDllName = (PCSTR)((MWORD)LoaderSharedData + LoadedModule->DllName);
	if (!strcasecmp(LoadedDllName, DllName)) {
	    *DllFile = NULL;
	    return STATUS_SUCCESS;
	}
	LoadedModule = (PLDRP_LOADED_MODULE)((MWORD)LoadedModule + LoadedModule->EntrySize);
    }

    /* Search under \BootModules first. */
    /* TODO: Eventually we need to implement the NT process search path semantics. */
    ULONG DllNameLength = strlen(DllName);
    PspAllocateArray(DllPath, CHAR, DllNameLength + sizeof(BOOTMODULE_OBJECT_DIRECTORY) + 1);
    memcpy(DllPath, BOOTMODULE_OBJECT_DIRECTORY, sizeof(BOOTMODULE_OBJECT_DIRECTORY) - 1);
    DllPath[sizeof(BOOTMODULE_OBJECT_DIRECTORY) - 1] = '\\';
    memcpy(DllPath + sizeof(BOOTMODULE_OBJECT_DIRECTORY), DllName, DllNameLength+1);

    NTSTATUS Status = ObReferenceObjectByName(DllPath, OBJECT_TYPE_FILE, (POBJECT *)DllFile);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(*DllFile != NULL);

    PSECTION DllSection = NULL;
    Status = MmCreateSection(*DllFile, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			     &DllSection);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(DllSection != NULL);

    MWORD DllBase = 0;
    MWORD DllViewSize = 0;
    Status = MmMapViewOfSection(&Process->VSpace, DllSection,
				&DllBase, NULL, &DllViewSize, TRUE);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(DllBase != 0);
    assert(DllViewSize != 0);

    LoaderSharedData->LoadedModuleCount++;
    Status = PspPopulateLoaderSharedData(Process, LoaderDataOffset, DllPath,
					 DllName, DllBase, DllViewSize);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    return STATUS_SUCCESS;

 fail:
    ExFreePool(DllPath);
    if (DllSection != NULL) {
	ObDereferenceObject(DllSection);
    }
    *LoaderDataOffset = OrigLoaderDataOffset;
    *DllFile = NULL;
    return Status;
}

static NTSTATUS PspMapDependencies(IN PPROCESS Process,
				   IN PLOADER_SHARED_DATA LoaderSharedData,
				   IN OUT MWORD *LoaderDataOffset,
				   IN PVOID DllFileBuffer)
{
    ULONG ImportTableSize = 0;
    PIMAGE_IMPORT_DESCRIPTOR ImportTable =
	RtlImageDirectoryEntryToData(DllFileBuffer, FALSE,
				     IMAGE_DIRECTORY_ENTRY_IMPORT,
				     &ImportTableSize);
    DbgTrace("ImportTableSize = 0x%x\n", ImportTableSize);
    SIZE_T ImportDescriptorCount = ImportTableSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    for (ULONG i = 0; i < ImportDescriptorCount; i++) {
	if (ImportTable[i].Name != 0) {
	    PCSTR DllName = RtlImageRvaToPtr(DllFileBuffer, ImportTable[i].Name);
	    PIO_FILE_OBJECT DllFile = NULL;
	    RET_ERR(PspMapDll(Process, LoaderSharedData, LoaderDataOffset, DllName, &DllFile));
	    if (DllFile != NULL) {
		RET_ERR(PspMapDependencies(Process, LoaderSharedData, LoaderDataOffset, DllFile->BufferPtr));
	    }
	}
    }
    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(IN PIO_FILE_OBJECT ImageFile,
			 IN PIO_DRIVER_OBJECT DriverObject,
			 OUT PPROCESS *pProcess)
{
    assert(ImageFile != NULL);
    assert(pProcess != NULL);

    PPROCESS Process = NULL;
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (POBJECT *) &Process));

    MWORD NtdllBase = 0;
    MWORD NtdllViewSize = 0;
    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, PspSystemDllSection,
				  &NtdllBase, NULL, &NtdllViewSize, TRUE),
	       ObDereferenceObject(Process));
    assert(NtdllBase != 0);
    assert(NtdllViewSize != 0);

    PSECTION Section = NULL;
    RET_ERR(MmCreateSection(ImageFile, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			    &Section));
    assert(Section != NULL);

    MWORD ImageBaseAddress = 0;
    MWORD ImageVirtualSize = 0;
    RET_ERR_EX(MmMapViewOfSection(&Process->VSpace, Section, 
				  &ImageBaseAddress, NULL, &ImageVirtualSize, TRUE),
	       {
		   ObDereferenceObject(Section);
		   ObDereferenceObject(Process);
	       });
    assert(ImageBaseAddress != 0);
    assert(ImageVirtualSize != 0);
    Process->ImageBaseAddress = ImageBaseAddress;
    Process->ImageVirtualSize = ImageVirtualSize;
    Process->ImageSection = Section;
    Process->ImageFile = ImageFile;

    if (DriverObject != NULL) {
	Process->InitInfo.DriverProcess = TRUE;
	Process->DriverObject = DriverObject;
    }

    /* Reserve and commit the loader private heap */
    PMMVAD LoaderHeapVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
					USER_IMAGE_REGION_END, NTDLL_LOADER_HEAP_RESERVE,
					MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES,
					&LoaderHeapVad),
	       ObDereferenceObject(Process));
    assert(LoaderHeapVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, LoaderHeapVad->AvlNode.Key,
				       NTDLL_LOADER_HEAP_COMMIT),
	       ObDereferenceObject(Process));
    Process->InitInfo.LoaderHeapStart = LoaderHeapVad->AvlNode.Key;

    /* Reserve and commit the process heap */
    PIMAGE_NT_HEADERS NtHeader = PspImageNtHeader(ImageFile->BufferPtr);
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
    PMMVAD ProcessHeapVad = NULL;
    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
					USER_IMAGE_REGION_END, ProcessHeapReserve,
					MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES,
					&ProcessHeapVad),
	       ObDereferenceObject(Process));
    assert(ProcessHeapVad != NULL);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, ProcessHeapVad->AvlNode.Key,
				       ProcessHeapCommit),
	       ObDereferenceObject(Process));
    Process->InitInfo.ProcessHeapStart = ProcessHeapVad->AvlNode.Key;
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
	       ObDereferenceObject(Process));
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
	       ObDereferenceObject(Process));
    assert(ClientSharedDataVad != NULL);
    assert(ClientSharedDataVad->AvlNode.Key == KUSER_SHARED_DATA_CLIENT_ADDR);
    MmRegisterMirroredVad(ClientSharedDataVad, PspUserSharedDataVad);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, KUSER_SHARED_DATA_CLIENT_ADDR,
				       sizeof(KUSER_SHARED_DATA)),
	       ObDereferenceObject(Process));

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
	       ObDereferenceObject(Process));
    Process->LoaderSharedDataServerAddr = ServerLoaderSharedDataVad->AvlNode.Key;
    Process->LoaderSharedDataClientAddr = ClientLoaderSharedDataVad->AvlNode.Key;

    /* Walk the import table and map the dependencies recursively */
    PLOADER_SHARED_DATA LoaderSharedData = (PLOADER_SHARED_DATA) Process->LoaderSharedDataServerAddr;
    MWORD LoaderDataOffset = sizeof(LOADER_SHARED_DATA);
    /* TODO: Fix image path and command line */
    RET_ERR_EX(PspMarshalString(Process, &LoaderDataOffset, ImageFile->FileName, &LoaderSharedData->ImagePath),
	       ObDereferenceObject(Process));
    RET_ERR_EX(PspMarshalString(Process, &LoaderDataOffset, ImageFile->FileName, &LoaderSharedData->ImageName),
	       ObDereferenceObject(Process));
    RET_ERR_EX(PspMarshalString(Process, &LoaderDataOffset, ImageFile->FileName, &LoaderSharedData->CommandLine),
	       ObDereferenceObject(Process));
    LoaderSharedData->LoadedModuleCount = 1;
    LoaderSharedData->LoadedModules = LoaderDataOffset;
    RET_ERR_EX(PspPopulateLoaderSharedData(Process, &LoaderDataOffset,
					   NTDLL_PATH, NTDLL_NAME, NtdllBase, NtdllViewSize),
	       ObDereferenceObject(Process));
    RET_ERR_EX(PspMapDependencies(Process, LoaderSharedData, &LoaderDataOffset, ImageFile->BufferPtr),
	       ObDereferenceObject(Process));

    if (DriverObject != NULL) {
	PMMVAD ServerIncomingIrpVad = NULL;
	PMMVAD ClientIncomingIrpVad = NULL;
	RET_ERR_EX(PspMapSharedRegion(Process,
				      EX_DRIVER_IRP_REGION_START,
				      EX_DRIVER_IRP_REGION_END,
				      DRIVER_IRP_BUFFER_RESERVE,
				      DRIVER_IRP_BUFFER_COMMIT,
				      USER_IMAGE_REGION_START,
				      USER_IMAGE_REGION_END,
				      0,
				      &ServerIncomingIrpVad,
				      &ClientIncomingIrpVad),
		   ObDereferenceObject(Process));
	DriverObject->IncomingIrpServerAddr = ServerIncomingIrpVad->AvlNode.Key;
	DriverObject->IncomingIrpClientAddr = ClientIncomingIrpVad->AvlNode.Key;
	PMMVAD ServerOutgoingIrpVad = NULL;
	PMMVAD ClientOutgoingIrpVad = NULL;
	RET_ERR_EX(PspMapSharedRegion(Process,
				      EX_DRIVER_IRP_REGION_START,
				      EX_DRIVER_IRP_REGION_END,
				      DRIVER_IRP_BUFFER_RESERVE,
				      DRIVER_IRP_BUFFER_COMMIT,
				      USER_IMAGE_REGION_START,
				      USER_IMAGE_REGION_END,
				      0,
				      &ServerOutgoingIrpVad,
				      &ClientOutgoingIrpVad),
		   ObDereferenceObject(Process));
	DriverObject->OutgoingIrpServerAddr = ServerOutgoingIrpVad->AvlNode.Key;
	DriverObject->OutgoingIrpClientAddr = ClientOutgoingIrpVad->AvlNode.Key;
	Process->InitInfo.DriverInitInfo.IncomingIrpBuffer = DriverObject->IncomingIrpClientAddr;
	Process->InitInfo.DriverInitInfo.OutgoingIrpBuffer = DriverObject->OutgoingIrpClientAddr;
    }

    /* Create the Event objects used by the NTDLL ldr component */
    /* FIXME: TODO */
    Process->InitInfo.ProcessHeapLockSemaphore = (HANDLE) 3;
    Process->InitInfo.LoaderHeapLockSemaphore = (HANDLE) 3;

    InsertTailList(&PspProcessList, &Process->ProcessListEntry);
    *pProcess = Process;
    return STATUS_SUCCESS;
}

NTSTATUS PsLoadDll(IN PPROCESS Process,
		   IN PCSTR DllName)
{
    /* Locate the end of the loader shared data */
    PLOADER_SHARED_DATA LoaderSharedData = (PLOADER_SHARED_DATA)Process->LoaderSharedDataServerAddr;
    PLDRP_LOADED_MODULE LoadedModule = (PLDRP_LOADED_MODULE)(Process->LoaderSharedDataServerAddr
							     + LoaderSharedData->LoadedModules);
    for (ULONG i = 0; i < LoaderSharedData->LoadedModuleCount; i++) {
	LoadedModule = (PLDRP_LOADED_MODULE)((MWORD)LoadedModule + LoadedModule->EntrySize);
    }
    MWORD LoaderDataOffset = (MWORD)LoadedModule - Process->LoaderSharedDataServerAddr;

    PIO_FILE_OBJECT DllFile = NULL;
    RET_ERR(PspMapDll(Process, LoaderSharedData, &LoaderDataOffset, DllName, &DllFile));
    if (DllFile != NULL) {
	RET_ERR(PspMapDependencies(Process, LoaderSharedData, &LoaderDataOffset, DllFile->BufferPtr));
    }
    return STATUS_SUCCESS;
}

NTSTATUS NtCreateThread(IN ASYNC_STATE State,
			IN PTHREAD Thread,
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

NTSTATUS NtCreateProcess(IN ASYNC_STATE State,
			 IN PTHREAD Thread,
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
