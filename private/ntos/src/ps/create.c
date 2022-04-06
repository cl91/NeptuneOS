#include "psp.h"
#include <wdmsvc.h>

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

static NTSTATUS PspSetThreadPriority(IN MWORD ThreadCap,
				     IN THREAD_PRIORITY Priority)
{
    assert(ThreadCap != 0);
    int Error = seL4_TCB_SetPriority(ThreadCap, NTOS_TCB_CAP, Priority);

    if (Error != 0) {
	DbgTrace("seL4_TCB_SetPriority failed for thread cap 0x%zx with error %d\n",
		 ThreadCap, Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

NTSTATUS PsSetThreadPriority(IN PTHREAD Thread,
			     IN THREAD_PRIORITY Priority)
{
    RET_ERR(PspSetThreadPriority(Thread->TreeNode.Cap, Priority));
    Thread->CurrentPriority = Priority;
    return STATUS_SUCCESS;
}

NTSTATUS PsSetSystemThreadPriority(IN PSYSTEM_THREAD Thread,
				   IN THREAD_PRIORITY Priority)
{
    RET_ERR(PspSetThreadPriority(Thread->TreeNode.Cap, Priority));
    Thread->CurrentPriority = Priority;
    return STATUS_SUCCESS;
}

static NTSTATUS PspResumeThread(IN MWORD ThreadCap)
{
    assert(ThreadCap != 0);
    int Error = seL4_TCB_Resume(ThreadCap);

    if (Error != 0) {
	DbgTrace("seL4_TCB_Resume failed for thread cap 0x%zx with error %d\n",
		 ThreadCap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS PsResumeThread(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    return PspResumeThread(Thread->TreeNode.Cap);
}

NTSTATUS PsResumeSystemThread(IN PSYSTEM_THREAD Thread)
{
    assert(Thread != NULL);
    return PspResumeThread(Thread->TreeNode.Cap);
}

/*
 * Startup function for system threads. This is the common entry point for
 * all system threads. We simply set the seL4 IPC buffer and branch to the
 * supplied thread entry point.
 *
 * The thread entrypoint should never return. On debug build we assert if
 * it did.
 */
VOID PspSystemThreadStartup(IN seL4_IPCBuffer *IpcBuffer,
			    IN PSYSTEM_THREAD_ENTRY EntryPoint)
{
    __sel4_ipc_buffer = IpcBuffer;
    EntryPoint();
    DbgTrace("ERROR: System thread entry point %p returned. Current stack pointer is %p\n",
	     EntryPoint, __builtin_frame_address(0));
    assert(FALSE);
    while (TRUE) ;
}

NTSTATUS PsCreateSystemThread(IN PSYSTEM_THREAD Thread,
			      IN PCSTR DebugName,
			      IN PSYSTEM_THREAD_ENTRY EntryPoint,
			      IN BOOLEAN Suspended)
{
    extern VIRT_ADDR_SPACE MiNtosVaddrSpace;
    extern CNODE MiNtosCNode;
    assert(Thread != NULL);

    PUNTYPED TcbUntyped = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    IF_ERR_GOTO(Fail, Status, MmRequestUntyped(seL4_TCBBits, &TcbUntyped));
    Thread->TreeNode.CSpace = &MiNtosCNode;
    assert(TcbUntyped->TreeNode.CSpace == &MiNtosCNode);
    MmInitializeCapTreeNode(&Thread->TreeNode, CAP_TREE_NODE_TCB,
			    0, &MiNtosCNode, NULL);
    IF_ERR_GOTO(Fail, Status, MmRetypeIntoObject(TcbUntyped, seL4_TCBObject,
						 seL4_TCBBits, &Thread->TreeNode));

    assert(DebugName != NULL);
    assert(DebugName[0] != '\0');
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugNameThread(Thread->TreeNode.Cap, DebugName);
#endif
    Thread->DebugName = DebugName;
    Thread->EntryPoint = EntryPoint;

    PMMVAD IpcBufferVad = NULL;
    IF_ERR_GOTO(Fail, Status,
		MmReserveVirtualMemory(SYSTEM_THREAD_REGION_START, SYSTEM_THREAD_REGION_END,
				       SYSTEM_THREAD_IPC_RESERVE, MEM_RESERVE_OWNED_MEMORY,
				       &IpcBufferVad));
    assert(IpcBufferVad != NULL);
    IF_ERR_GOTO(Fail, Status,
		MmCommitVirtualMemory(IpcBufferVad->AvlNode.Key, SYSTEM_THREAD_IPC_COMMIT));
    PPAGING_STRUCTURE IpcBufferPage = MmQueryPage(&MiNtosVaddrSpace,
						  IpcBufferVad->AvlNode.Key);
    assert(IpcBufferPage != NULL);
    IF_ERR_GOTO(Fail, Status, KeEnableSystemThreadFaultHandler(Thread));
    IF_ERR_GOTO(Fail, Status, PspConfigureThread(Thread->TreeNode.Cap,
						 Thread->FaultEndpoint->TreeNode.Cap,
						 &MiNtosCNode,
						 &MiNtosVaddrSpace,
						 IpcBufferPage));
    Thread->IpcBuffer = (PVOID)IpcBufferVad->AvlNode.Key;

    PMMVAD StackVad = NULL;
    IF_ERR_GOTO(Fail, Status,
		MmReserveVirtualMemory(SYSTEM_THREAD_REGION_START, SYSTEM_THREAD_REGION_END,
				       SYSTEM_THREAD_STACK_RESERVE, MEM_RESERVE_OWNED_MEMORY,
				       &StackVad));
    assert(StackVad != NULL);
    assert(SYSTEM_THREAD_STACK_RESERVE >= (2 * PAGE_SIZE + SYSTEM_THREAD_STACK_COMMIT));
    /* There is one uncommitted page above and one uncommitted page below every system thread stack */
    IF_ERR_GOTO(Fail, Status,
		MmCommitVirtualMemory(StackVad->AvlNode.Key + PAGE_SIZE, SYSTEM_THREAD_STACK_COMMIT));
    Thread->StackTop = (PVOID)(StackVad->AvlNode.Key + PAGE_SIZE + SYSTEM_THREAD_STACK_COMMIT);

    PspAllocateArrayEx(TlsBase, CHAR, NTOS_TLS_AREA_SIZE,
		       {
			   Status = STATUS_NO_MEMORY;
			   goto Fail;
		       });
    Thread->TlsBase = TlsBase + NTOS_TLS_AREA_SIZE - sizeof(ULONGLONG);
    *((PPVOID)(Thread->TlsBase)) = Thread->TlsBase;

    THREAD_CONTEXT Context;
    memset(&Context, 0, sizeof(THREAD_CONTEXT));
    PspInitializeSystemThreadContext(Thread, &Context, EntryPoint);
    IF_ERR_GOTO(Fail, Status, KeSetThreadContext(Thread->TreeNode.Cap, &Context));
    IF_ERR_GOTO(Fail, Status, PspSetThreadPriority(Thread->TreeNode.Cap, PASSIVE_LEVEL));
    Thread->CurrentPriority = PASSIVE_LEVEL;
    if (!Suspended) {
	IF_ERR_GOTO(Fail, Status, PspResumeThread(Thread->TreeNode.Cap));
    }

    return STATUS_SUCCESS;

Fail:
    if (StackVad != NULL) {
	MmDeleteVad(StackVad);
    }
    if (IpcBufferVad != NULL) {
	MmDeleteVad(IpcBufferVad);
    }
    if (TcbUntyped != NULL) {
	MmReleaseUntyped(TcbUntyped);
    }
    return Status;
}

VOID PspPopulateTeb(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    assert(Thread->InitialStackTop > Thread->InitialStackCommit);
    assert(Thread->InitialStackTop > Thread->InitialStackReserve);
    assert(Thread->InitialStackReserve >= Thread->InitialStackCommit);
    PTEB Teb = (PTEB) Thread->TebServerAddr;
    Teb->ThreadLocalStoragePointer = (PVOID) Thread->SystemDllTlsBase;
    Teb->NtTib.Self = (PNT_TIB) Thread->TebClientAddr;
    Teb->ProcessEnvironmentBlock = (PPEB) Thread->Process->PebClientAddr;
    Teb->NtTib.StackBase = (PVOID)Thread->InitialStackTop;
    Teb->NtTib.StackLimit = (PVOID)(Thread->InitialStackTop - Thread->InitialStackCommit);
    Teb->DeallocationStack = (PVOID)(Thread->InitialStackTop - Thread->InitialStackReserve);
}

VOID PspPopulatePeb(IN PPROCESS Process)
{
    PPEB Peb = (PPEB)Process->PebServerAddr;
    Peb->ImageBaseAddress = (HMODULE)Process->ImageBaseAddress;
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
	       MmDeleteVad(*ServerVad));

    RET_ERR_EX(MmReserveVirtualMemoryEx(&Process->VSpace, ClientStart, ClientEnd,
					ReserveSize, MEM_RESERVE_MIRRORED_MEMORY | ClientReserveFlag,
					ClientVad),
	       MmDeleteVad(*ServerVad));
    assert(*ClientVad != NULL);
    assert((*ClientVad)->AvlNode.Key != 0);
    MmRegisterMirroredVad(*ClientVad, *ServerVad);
    RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, (*ClientVad)->AvlNode.Key, CommitSize),
	       {
		   MmDeleteVad(*ServerVad);
		   MmDeleteVad(*ClientVad);
	       });

    return STATUS_SUCCESS;
}

static inline VOID PspSetThreadDebugName(IN PTHREAD Thread)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->Process->ImageFile != NULL);
    assert(Thread->Process->ImageFile->FileName != NULL);
    char NameBuf[seL4_MsgMaxLength * sizeof(MWORD)];
    /* We use the thread object addr to distinguish threads. */
    snprintf(NameBuf, sizeof(NameBuf), "%s|%p", Thread->Process->ImageFile->FileName, Thread);
    Thread->DebugName = RtlDuplicateString(NameBuf, NTOS_PS_TAG);
    if (Thread->DebugName == NULL) {
	Thread->DebugName = "UNKNOWN THREAD";
    }
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugNameThread(Thread->TreeNode.Cap, Thread->DebugName);
#endif
}

NTSTATUS PspThreadObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx)
{
    PTHREAD Thread = (PTHREAD) Object;
    PTHREAD_CREATION_CONTEXT Ctx = (PTHREAD_CREATION_CONTEXT)CreaCtx;
    PPROCESS Process = Ctx->Process;
    assert(Ctx != NULL);

    /* Unless you are creating the initial thread of a process, you must specify
     * the thread context */
    assert(Process->InitThread == NULL || Ctx->Context != NULL);

    if (Ctx->InitialTeb != NULL &&
	(Ctx->InitialTeb->StackBase == NULL || Ctx->InitialTeb->StackLimit == NULL ||
	 Ctx->InitialTeb->AllocatedStackBase == NULL ||
	 /* Stack reserve must be at least stack commit */
	 Ctx->InitialTeb->AllocatedStackBase > Ctx->InitialTeb->StackLimit ||
	 /* Stack commit cannot be zero */
	 Ctx->InitialTeb->StackLimit >= Ctx->InitialTeb->StackBase)) {
	return STATUS_INVALID_PARAMETER;
    }

    PUNTYPED TcbUntyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_TCBBits, &TcbUntyped));

    assert(TcbUntyped->TreeNode.CSpace != NULL);
    MmInitializeCapTreeNode(&Thread->TreeNode, CAP_TREE_NODE_TCB,
			    0, TcbUntyped->TreeNode.CSpace, NULL);
    RET_ERR_EX(MmRetypeIntoObject(TcbUntyped, seL4_TCBObject,
				  seL4_TCBBits, &Thread->TreeNode),
	       MmReleaseUntyped(TcbUntyped));

    Thread->Process = Process;
    InitializeListHead(&Thread->ThreadListEntry);
    InitializeListHead(&Thread->PendingIrpList);
    InitializeListHead(&Thread->ApcList);

    PMMVAD ServerIpcBufferVad = NULL;
    PMMVAD ClientIpcBufferVad = NULL;
    RET_ERR(PspMapSharedRegion(Process,
			       EX_IPC_BUFFER_REGION_START,
			       EX_IPC_BUFFER_REGION_END,
			       IPC_BUFFER_RESERVE,
			       IPC_BUFFER_COMMIT,
			       IPC_BUFFER_START,
			       IPC_BUFFER_END,
			       0,
			       &ServerIpcBufferVad,
			       &ClientIpcBufferVad));
    Thread->IpcBufferServerAddr = ServerIpcBufferVad->AvlNode.Key;
    Thread->IpcBufferClientAddr = ClientIpcBufferVad->AvlNode.Key;

    PPAGING_STRUCTURE IpcBufferClientPage = MmQueryPage(&Process->VSpace,
							Thread->IpcBufferClientAddr);
    assert(IpcBufferClientPage != NULL);
    RET_ERR(KeEnableThreadFaultHandler(Thread));
    RET_ERR(PspConfigureThread(Thread->TreeNode.Cap,
			       Thread->FaultEndpoint->TreeNode.Cap,
			       Process->CSpace,
			       &Process->VSpace,
			       IpcBufferClientPage));

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
	RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, SYSTEM_DLL_TLS_REGION_START,
					 SYSTEM_DLL_TLS_REGION_END,
					 PspSystemDllTlsSubsection->SubSectionSize,
					 MEM_RESERVE_OWNED_MEMORY, &SystemDllTlsVad));
	assert(SystemDllTlsVad != NULL);
	RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace, SystemDllTlsVad->AvlNode.Key,
					   SystemDllTlsVad->WindowSize),
		   MmDeleteVad(SystemDllTlsVad));
	Thread->SystemDllTlsBase = SystemDllTlsVad->AvlNode.Key;
    }

    if (Ctx->InitialTeb == NULL) {
	ULONG StackReserve = Process->ImageSection->ImageSectionObject->ImageInformation.MaximumStackSize;
	ULONG StackCommit = Process->ImageSection->ImageSectionObject->ImageInformation.CommittedStackSize;
	if (StackCommit > StackReserve) {
	    StackCommit = StackReserve;
	}
	PMMVAD StackVad = NULL;
	RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, THREAD_STACK_START,
					 HIGHEST_USER_ADDRESS, StackReserve,
					 MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES | MEM_COMMIT_ON_DEMAND,
					 &StackVad));
	assert(StackVad != NULL);
	Thread->InitialStackTop = StackVad->AvlNode.Key + StackVad->WindowSize;
	Thread->InitialStackReserve = StackReserve;
	Thread->InitialStackCommit = StackCommit;
	RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace,
					   Thread->InitialStackTop - StackCommit,
					   StackCommit),
		   MmDeleteVad(StackVad));
    } else {
	Thread->InitialStackTop = (MWORD)Ctx->InitialTeb->StackBase;
	Thread->InitialStackReserve = Ctx->InitialTeb->StackBase - Ctx->InitialTeb->AllocatedStackBase;
	Thread->InitialStackCommit = Ctx->InitialTeb->StackBase - Ctx->InitialTeb->StackLimit;
    }

    /* Allocate and populate the Thread Environment Block */
    PMMVAD ServerTebVad = NULL;
    PMMVAD ClientTebVad = NULL;
    RET_ERR(PspMapSharedRegion(Process,
			       EX_PEB_TEB_REGION_START,
			       EX_PEB_TEB_REGION_END,
			       sizeof(TEB),
			       sizeof(TEB),
			       WIN32_TEB_START,
			       WIN32_TEB_END,
			       MEM_RESERVE_TOP_DOWN,
			       &ServerTebVad,
			       &ClientTebVad));
    Thread->TebServerAddr = ServerTebVad->AvlNode.Key;
    Thread->TebClientAddr = ClientTebVad->AvlNode.Key;
    /* Populate the Thread Environment Block */
    PspPopulateTeb(Thread);

    /* Note that this is the initial thread context immediately after a new thread
     * starts running (ie. immediately after LdrInitializeThunk is jumped into),
     * not to be confused with the initial context specified in Ctx->Context.
     * The latter is the thread context that ntdll will load once it has finished
     * thread initialization. */
    THREAD_CONTEXT Context;
    memset(&Context, 0, sizeof(THREAD_CONTEXT));
    PspInitializeThreadContext(Thread, &Context);
    RET_ERR(KeSetThreadContext(Thread->TreeNode.Cap, &Context));
    RET_ERR(PspSetThreadPriority(Thread->TreeNode.Cap, PASSIVE_LEVEL));
    /* Thread->InitInfo.InitialContext is initialized as zero so if the caller
     * did not supply Ctx->Context we simply leave InitialContext as zero. */
    if (Ctx->Context != NULL) {
	Thread->InitInfo.InitialContext = *(Ctx->Context);
    }
    Thread->CurrentPriority = PASSIVE_LEVEL;
    RET_ERR(KeEnableSystemServices(Thread));
    if (Process->InitInfo.DriverProcess) {
	RET_ERR(KeEnableWdmServices(Thread));
    }
    PspSetThreadDebugName(Thread);

    if (Process->InitThread == NULL) {
	/* Populate the process init info used by ntdll on process startup */
	Process->InitInfo.ThreadInitInfo = Thread->InitInfo;
	*((PNTDLL_PROCESS_INIT_INFO)Thread->IpcBufferServerAddr) = Process->InitInfo;
    } else {
	/* Populate the thread init info used by ntdll on process startup */
	*((PNTDLL_THREAD_INIT_INFO)Thread->IpcBufferServerAddr) = Thread->InitInfo;
    }

    if (!Ctx->CreateSuspended) {
	RET_ERR(PspResumeThread(Thread->TreeNode.Cap));
    }

    if (Process->InitThread == NULL) {
	Process->InitThread = Thread;
    }
    InsertTailList(&Process->ThreadList, &Thread->ThreadListEntry);

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
    DbgTrace("Mapping DllName %s for Process %p (%s)\n", DllName, Process,
	     (Process->ImageFile && Process->ImageFile->FileName) ? Process->ImageFile->FileName : "???");
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

    NTSTATUS Status = ObReferenceObjectByName(DllPath, OBJECT_TYPE_FILE,
					      NULL, (POBJECT *)DllFile);
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Unable to find dll %s\n", DllPath);
	goto fail;
    }
    assert(*DllFile != NULL);

    PSECTION DllSection = NULL;
    Status = MmCreateSection(*DllFile, 0, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
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
    PspFreePool(DllPath);
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
    PIMAGE_IMPORT_DESCRIPTOR ImportTable = RtlImageDirectoryEntryToData(DllFileBuffer, FALSE,
									IMAGE_DIRECTORY_ENTRY_IMPORT,
									&ImportTableSize);
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

/*
 * Reserve and commit a coroutine stack for the driver process. Drivers can have
 * many coroutine stacks, each of which has 4 pages of reserved space, and the
 * middle two pages are committed. The first and last page are left as uncommitted
 * such that a stack overflow or underflow will trigger an exception.
 */
#define DRIVER_COROUTINE_STACK_RESERVE	(4 * PAGE_SIZE)
#define DRIVER_COROUTINE_STACK_COMMIT	(2 * PAGE_SIZE)
NTSTATUS PsMapDriverCoroutineStack(IN PPROCESS Process,
				   OUT MWORD *pStackTop)
{
    assert(Process != NULL);
    assert(Process->DriverObject != NULL);
    assert(pStackTop != NULL);

    PMMVAD Vad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
				     USER_IMAGE_REGION_END, DRIVER_COROUTINE_STACK_RESERVE,
				     MEM_RESERVE_OWNED_MEMORY, &Vad));
    assert(Vad != NULL);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, Vad->AvlNode.Key + PAGE_SIZE,
				    DRIVER_COROUTINE_STACK_COMMIT));
    *pStackTop = Vad->AvlNode.Key + PAGE_SIZE + DRIVER_COROUTINE_STACK_COMMIT;
    return STATUS_SUCCESS;
}

NTSTATUS PspProcessObjectCreateProc(IN POBJECT Object,
				    IN PVOID CreaCtx)
{
    PPROCESS Process = (PPROCESS) Object;
    PPROCESS_CREATION_CONTEXT Ctx = (PPROCESS_CREATION_CONTEXT)CreaCtx;
    PIO_FILE_OBJECT ImageFile = Ctx->ImageFile;
    PSECTION Section = Ctx->ImageSection;
    PIO_DRIVER_OBJECT DriverObject = Ctx->DriverObject;

    /* You cannot specify both ImageSection and ImageFile */
    if ((Section != NULL) && (ImageFile != NULL)) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Section must be an image section */
    if ((Section != NULL) && !Section->Flags.Image) {
	return STATUS_INVALID_PARAMETER;
    }

    /* We haven't implemented process inheritance yet */
    if ((Section == NULL) && (ImageFile == NULL)) {
	UNIMPLEMENTED;
    }

    RET_ERR(MmCreateCNode(PROCESS_INIT_CNODE_LOG2SIZE, &Process->CSpace));
    RET_ERR(MmCreateVSpace(&Process->VSpace));

    InitializeListHead(&Process->ThreadList);
    InitializeListHead(&Process->ProcessListEntry);
    ObInitializeHandleTable(&Process->HandleTable);

    /* Assign an ASID for the virtual address space just created */
    RET_ERR(MmAssignASID(&Process->VSpace));

    MWORD NtdllBase = 0;
    MWORD NtdllViewSize = 0;
    RET_ERR(MmMapViewOfSection(&Process->VSpace, PspSystemDllSection,
			       &NtdllBase, NULL, &NtdllViewSize, TRUE));
    assert(NtdllBase != 0);
    assert(NtdllViewSize != 0);

    if (Section == NULL) {
	RET_ERR(MmCreateSection(ImageFile, 0, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
				&Section));
    } else {
	ImageFile = Section->ImageSectionObject->FileObject;
    }
    assert(Section != NULL);
    assert(ImageFile != NULL);
    Process->ImageSection = Section;
    Process->ImageFile = ImageFile;

    MWORD ImageBaseAddress = 0;
    MWORD ImageVirtualSize = 0;
    RET_ERR(MmMapViewOfSection(&Process->VSpace, Section,
			       &ImageBaseAddress, NULL, &ImageVirtualSize, TRUE));
    assert(ImageBaseAddress != 0);
    assert(ImageVirtualSize != 0);
    Process->ImageBaseAddress = ImageBaseAddress;
    Process->ImageVirtualSize = ImageVirtualSize;

    if (DriverObject != NULL) {
	Process->InitInfo.DriverProcess = TRUE;
	Process->InitInfo.DriverInitInfo.X86TscFreq = KeX86TscFreq;
	Process->DriverObject = DriverObject;
    }

    /* Reserve and commit the loader private heap */
    PMMVAD LoaderHeapVad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
				     USER_IMAGE_REGION_END, NTDLL_LOADER_HEAP_RESERVE,
				     MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES,
				     &LoaderHeapVad));
    assert(LoaderHeapVad != NULL);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, LoaderHeapVad->AvlNode.Key,
				    NTDLL_LOADER_HEAP_COMMIT));
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
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
				     USER_IMAGE_REGION_END, ProcessHeapReserve,
				     MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES,
				     &ProcessHeapVad));
    assert(ProcessHeapVad != NULL);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, ProcessHeapVad->AvlNode.Key,
				    ProcessHeapCommit));
    Process->InitInfo.ProcessHeapStart = ProcessHeapVad->AvlNode.Key;
    Process->InitInfo.ProcessHeapReserve = ProcessHeapReserve;
    Process->InitInfo.ProcessHeapCommit = ProcessHeapCommit;

    /* Map and initialize the Process Environment Block */
    PMMVAD ServerPebVad = NULL;
    PMMVAD ClientPebVad = NULL;
    RET_ERR(PspMapSharedRegion(Process,
			       EX_PEB_TEB_REGION_START,
			       EX_PEB_TEB_REGION_END,
			       sizeof(PEB),
			       sizeof(PEB),
			       WIN32_PEB_START,
			       0, 0,
			       &ServerPebVad,
			       &ClientPebVad));
    Process->PebServerAddr = ServerPebVad->AvlNode.Key;
    Process->PebClientAddr = ClientPebVad->AvlNode.Key;
    /* Populate the Process Environment Block */
    PspPopulatePeb(Process);

    /* Map the KUSER_SHARED_DATA into the client address space */
    PMMVAD ClientSharedDataVad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, KUSER_SHARED_DATA_CLIENT_ADDR,
				     0, sizeof(KUSER_SHARED_DATA),
				     MEM_RESERVE_MIRRORED_MEMORY,
				     &ClientSharedDataVad));
    assert(ClientSharedDataVad != NULL);
    assert(ClientSharedDataVad->AvlNode.Key == KUSER_SHARED_DATA_CLIENT_ADDR);
    MmRegisterMirroredVad(ClientSharedDataVad, PspUserSharedDataVad);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, KUSER_SHARED_DATA_CLIENT_ADDR,
				    sizeof(KUSER_SHARED_DATA)));

    /* Map the loader shared data */
    PMMVAD ServerLoaderSharedDataVad = NULL;
    PMMVAD ClientLoaderSharedDataVad = NULL;
    RET_ERR(PspMapSharedRegion(Process,
			       EX_LOADER_SHARED_REGION_START,
			       EX_LOADER_SHARED_REGION_END,
			       LOADER_SHARED_DATA_RESERVE,
			       LOADER_SHARED_DATA_COMMIT,
			       LOADER_SHARED_DATA_CLIENT_ADDR,
			       0, 0,
			       &ServerLoaderSharedDataVad,
			       &ClientLoaderSharedDataVad));
    Process->LoaderSharedDataServerAddr = ServerLoaderSharedDataVad->AvlNode.Key;
    Process->LoaderSharedDataClientAddr = ClientLoaderSharedDataVad->AvlNode.Key;

    /* Walk the import table and map the dependencies recursively */
    PLOADER_SHARED_DATA LoaderSharedData = (PLOADER_SHARED_DATA)Process->LoaderSharedDataServerAddr;
    MWORD LoaderDataOffset = sizeof(LOADER_SHARED_DATA);
    RET_ERR(PspMarshalString(Process, &LoaderDataOffset, ImageFile->FileName,
			     &LoaderSharedData->ImageName));
    if (DriverObject != NULL) {
	RET_ERR(PspMarshalString(Process, &LoaderDataOffset, DriverObject->DriverImagePath,
				 &LoaderSharedData->ImagePath));
	RET_ERR(PspMarshalString(Process, &LoaderDataOffset, DriverObject->DriverRegistryPath,
				 &LoaderSharedData->CommandLine));
    } else {
	/* TODO: Fix image path and command line */
	RET_ERR(PspMarshalString(Process, &LoaderDataOffset, ImageFile->FileName,
				 &LoaderSharedData->ImagePath));
	RET_ERR(PspMarshalString(Process, &LoaderDataOffset, ImageFile->FileName,
				 &LoaderSharedData->CommandLine));
    }
    LoaderSharedData->LoadedModuleCount = 1;
    LoaderSharedData->LoadedModules = LoaderDataOffset;
    RET_ERR(PspPopulateLoaderSharedData(Process, &LoaderDataOffset,
					NTDLL_PATH, NTDLL_NAME, NtdllBase, NtdllViewSize));
    RET_ERR(PspMapDependencies(Process, LoaderSharedData, &LoaderDataOffset, ImageFile->BufferPtr));

    if (DriverObject != NULL) {
	PMMVAD ServerIncomingIoPacketsVad = NULL;
	PMMVAD ClientIncomingIoPacketsVad = NULL;
	RET_ERR(PspMapSharedRegion(Process,
				   EX_DRIVER_IO_PACKET_REGION_START,
				   EX_DRIVER_IO_PACKET_REGION_END,
				   DRIVER_IO_PACKET_BUFFER_RESERVE,
				   DRIVER_IO_PACKET_BUFFER_COMMIT,
				   USER_IMAGE_REGION_START,
				   USER_IMAGE_REGION_END,
				   MEM_RESERVE_READ_ONLY,
				   &ServerIncomingIoPacketsVad,
				   &ClientIncomingIoPacketsVad));
	DriverObject->IncomingIoPacketsServerAddr = ServerIncomingIoPacketsVad->AvlNode.Key;
	DriverObject->IncomingIoPacketsClientAddr = ClientIncomingIoPacketsVad->AvlNode.Key;
	PMMVAD ServerOutgoingIoPacketsVad = NULL;
	PMMVAD ClientOutgoingIoPacketsVad = NULL;
	RET_ERR(PspMapSharedRegion(Process,
				   EX_DRIVER_IO_PACKET_REGION_START,
				   EX_DRIVER_IO_PACKET_REGION_END,
				   DRIVER_IO_PACKET_BUFFER_RESERVE,
				   DRIVER_IO_PACKET_BUFFER_COMMIT,
				   USER_IMAGE_REGION_START,
				   USER_IMAGE_REGION_END,
				   0,
				   &ServerOutgoingIoPacketsVad,
				   &ClientOutgoingIoPacketsVad));
	DriverObject->OutgoingIoPacketsServerAddr = ServerOutgoingIoPacketsVad->AvlNode.Key;
	DriverObject->OutgoingIoPacketsClientAddr = ClientOutgoingIoPacketsVad->AvlNode.Key;
	Process->InitInfo.DriverInitInfo.IncomingIoPacketBuffer = DriverObject->IncomingIoPacketsClientAddr;
	Process->InitInfo.DriverInitInfo.OutgoingIoPacketBuffer = DriverObject->OutgoingIoPacketsClientAddr;
	MWORD InitialCoroutineStackTop = 0;
	RET_ERR(PsMapDriverCoroutineStack(Process, &InitialCoroutineStackTop));
	Process->InitInfo.DriverInitInfo.InitialCoroutineStackTop = InitialCoroutineStackTop;
	RET_ERR(KeCreateNotificationEx(&Process->DpcMutex, Process->CSpace));
	Process->InitInfo.DriverInitInfo.DpcMutexCap = Process->DpcMutex.TreeNode.Cap;
    }

    /* Create the Event objects used by the NTDLL ldr component */
    /* FIXME: TODO */
    Process->InitInfo.ProcessHeapLockSemaphore = (HANDLE) 3;
    Process->InitInfo.LoaderHeapLockSemaphore = (HANDLE) 3;

    /* Generate a per-process security cookie */
    LARGE_INTEGER SystemTime = { .QuadPart = KeQuerySystemTime() };
    Process->Cookie = KeQueryInterruptTime() ^ SystemTime.LowPart ^ SystemTime.HighPart;

    InsertTailList(&PspProcessList, &Process->ProcessListEntry);

    return STATUS_SUCCESS;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
                        IN PCONTEXT ThreadContext,
                        IN PINITIAL_TEB InitialTeb,
                        IN BOOLEAN CreateSuspended,
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
    THREAD_CREATION_CONTEXT CreaCtx = {
	.Process = Process,
	.Context = ThreadContext,
	.InitialTeb = InitialTeb,
	.CreateSuspended = CreateSuspended
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (POBJECT *) &Thread, &CreaCtx));
    *pThread = Thread;
    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(IN PIO_FILE_OBJECT ImageFile,
			 IN PIO_DRIVER_OBJECT DriverObject,
			 IN PSECTION ImageSection,
			 OUT PPROCESS *pProcess)
{
    assert(pProcess != NULL);

    PPROCESS Process = NULL;
    PROCESS_CREATION_CONTEXT CreaCtx = {
	.ImageFile = ImageFile,
	.DriverObject = DriverObject,
	.ImageSection = ImageSection
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (POBJECT *) &Process, &CreaCtx));
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
    assert(Thread != NULL);
    assert(Thread->Process != NULL);

    PPROCESS Process = NULL;
    if (ProcessHandle == NtCurrentProcess()) {
	Process = Thread->Process;
    } else {
	RET_ERR(ObReferenceObjectByHandle(Thread->Process, ProcessHandle,
					  OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    }
    assert(Process != NULL);

    PTHREAD CreatedThread = NULL;
    RET_ERR_EX(PsCreateThread(Process, ThreadContext, InitialTeb,
			      CreateSuspended, &CreatedThread),
	       if (ProcessHandle != NtCurrentProcess()) {
		   ObDereferenceObject(Process);
	       });
    RET_ERR_EX(ObCreateHandle(Thread->Process, CreatedThread, ThreadHandle),
	       {
		   ObDereferenceObject(CreatedThread);
		   if (ProcessHandle != NtCurrentProcess()) {
		       ObDereferenceObject(Process);
		   }
	       });
    return STATUS_SUCCESS;
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
    assert(Thread != NULL);
    assert(Thread->Process != NULL);

    /* Inheriting address space from parent process is not yet implemented */
    if (SectionHandle == NULL) {
	UNIMPLEMENTED;
    }

    PSECTION Section = NULL;
    /* When the process exits or is terminated the image section object is
     * dereferenced. */
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, SectionHandle,
				      OBJECT_TYPE_SECTION, (POBJECT *) &Section));
    assert(Section != NULL);
    if (!Section->Flags.Image) {
	ObDereferenceObject(Section);
	return STATUS_INVALID_PARAMETER_6;
    }

    PPROCESS Process = NULL;
    RET_ERR_EX(PsCreateProcess(NULL, NULL, Section, &Process),
	       ObDereferenceObject(Section));
    RET_ERR_EX(ObCreateHandle(Thread->Process, Process, ProcessHandle),
	       /* This will dereference the section object */
	       ObDereferenceObject(Process));

    return STATUS_SUCCESS;
}
