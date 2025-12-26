#include "ke.h"
#include "ntexapi.h"
#include "psp.h"
#include <wdmsvc.h>

extern VIRT_ADDR_SPACE MiNtosVaddrSpace;

/* For the client address space we reserve four pages and map the first page for the
 * IPC buffer and the third page as the thread information block. The second and
 * fourth pages are unmapped. */
#define CLIENT_IPC_REGION_LOW_ZERO_BITS (PAGE_LOG2SIZE + 2)

#define PEB_RESERVE	(16 * PAGE_SIZE)
#define PEB_COMMIT	(PAGE_SIZE)

#ifndef _WIN64
AVL_TREE PspCidMap;

/* splitmix32 algorithm that hashes the global handle to a 18-bit value */
FORCEINLINE ULONG PspCidHashFunction(ULONG x)
{
    x += 0x9e3779b9UL;
    x = (x ^ (x >> 16)) * 0x85ebca6bUL;
    x = (x ^ (x >> 13)) * 0xc2b2ae35UL;
    x ^= (x >> 16);
    return x & ((1UL << seL4_GuardBits) - 1);
}

static GLOBAL_HANDLE PspGenerateCid(IN POBJECT Object,
				    OUT PAVL_NODE *Parent)
{
    ULONG Offset = OBJECT_TO_GLOBAL_HANDLE(Object) >> EX_POOL_BLOCK_SHIFT;
    ULONG Cid = PspCidHashFunction(Offset);
    /* Make sure Cid is not zero */
    while (!Cid) {
	Cid = PspCidHashFunction(++Offset);
    }
    /* Retry if collision is detected */
    while ((*Parent = AvlTreeFindNodeOrParent(&PspCidMap, Cid)) &&
	   ((*Parent)->Key == Cid)) {
        Offset += 0x9E3779B9UL;  // perturb and rehash
        Cid = PspCidHashFunction(Offset);
    }
    return Cid;
}

#define PSP_GET_CID(Obj)					\
    if (Obj->CidMapNode.Key) {					\
	assert(Obj->CidMapNode.Key < (1UL << seL4_GuardBits));	\
	return Obj->CidMapNode.Key << EX_POOL_BLOCK_SHIFT;	\
    }								\
    PAVL_NODE Parent = NULL;					\
    GLOBAL_HANDLE Cid = PspGenerateCid(Obj, &Parent);		\
    Obj->CidMapNode.Key = Cid;					\
    assert(Cid);						\
    assert(!Parent || Parent->Key != Cid);			\
    AvlTreeInsertNode(&PspCidMap, Parent, &Obj->CidMapNode);	\
    return Cid << EX_POOL_BLOCK_SHIFT

GLOBAL_HANDLE PsGetProcessId(IN PPROCESS Process)
{
    PSP_GET_CID(Process);
}

GLOBAL_HANDLE PsGetThreadId(IN PTHREAD Thread)
{
    PSP_GET_CID(Thread);
}
#endif

static NTSTATUS PspConfigureThread(IN MWORD Tcb,
				   IN MWORD FaultHandler,
				   IN PCNODE CNode,
				   IN PVIRT_ADDR_SPACE VaddrSpace,
				   IN PPAGING_STRUCTURE IpcPage,
				   IN MWORD GuardValue)
{
    assert(CNode != NULL);
    assert(VaddrSpace != NULL);
    assert(IpcPage != NULL);
    ULONG Radix = GuardValue ? THREAD_PRIVATE_CNODE_LOG2SIZE + PROCESS_SHARED_CNODE_LOG2SIZE :
	CNode->Log2Size;
    seL4_CNode_CapData_t CapData = seL4_CNode_CapData_new(GuardValue, MWORD_BITS - Radix);
    int Error = seL4_TCB_Configure(Tcb, FaultHandler, CNode->TreeNode.Cap, CapData.words[0],
				   VaddrSpace->VSpaceCap, 0, IpcPage->AvlNode.Key,
				   IpcPage->TreeNode.Cap);

    if (Error != seL4_NoError) {
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PspSetThreadFpu(IN MWORD ThreadCap,
				IN BOOLEAN Enabled)
{
    assert(ThreadCap != 0);
    MWORD Clear = Enabled ? 1 : 0;
    MWORD Set = Enabled ? 0 : 1;
    int Error = seL4_TCB_SetFlags(ThreadCap, Clear, Set).error;

    if (Error != 0) {
	DbgTrace("seL4_TCB_SetFlags failed for thread cap 0x%zx with error %d\n",
		 ThreadCap, Error);
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
    extern CNODE MiNtosCNode;
    assert(Thread != NULL);

    PUNTYPED TcbUntyped = NULL;
    MWORD StackStart = 0;

    NTSTATUS Status;
    IF_ERR_GOTO(Fail, Status, MmRequestUntyped(seL4_TCBBits, &TcbUntyped));
    Thread->TreeNode.CNode = &MiNtosCNode;
    assert(TcbUntyped->TreeNode.CNode == &MiNtosCNode);
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

    /* See comments in mm.h for the organization of the system thread subregions. */
    StackStart = MmFindAndMarkUncommittedSubregion(PspSystemThreadRegionVad);
    if (!StackStart) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto Fail;
    }
    IF_ERR_GOTO(Fail, Status, MmCommitOwnedMemory(StackStart,
						  SYSTEM_THREAD_STACK_COMMIT,
						  MM_RIGHTS_RW, FALSE));
    Thread->StackTop = (PVOID)(StackStart + SYSTEM_THREAD_STACK_COMMIT);

    MWORD IpcBuffer = StackStart + SYSTEM_THREAD_IPC_OFFSET;
    IF_ERR_GOTO(Fail, Status, MmCommitOwnedMemory(IpcBuffer, PAGE_SIZE,
						  MM_RIGHTS_RW, FALSE));
    PPAGING_STRUCTURE IpcBufferPage = MmQueryPage(IpcBuffer);
    assert(IpcBufferPage != NULL);
    assert(IpcBufferPage->AvlNode.Key == IpcBuffer);
    IF_ERR_GOTO(Fail, Status, KeEnableSystemThreadFaultHandler(Thread));
    IF_ERR_GOTO(Fail, Status, PspConfigureThread(Thread->TreeNode.Cap,
						 Thread->FaultEndpoint->TreeNode.Cap,
						 &MiNtosCNode,
						 &MiNtosVaddrSpace,
						 IpcBufferPage,
						 0));
    Thread->IpcBuffer = (PVOID)IpcBuffer;

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
    if (StackStart) {
	MmUnmapServerRegion(StackStart);
    }
    if (TcbUntyped != NULL) {
	MmReleaseUntyped(TcbUntyped);
    }
    return Status;
}

static inline NTSTATUS PspSetThreadDebugName(IN PTHREAD Thread)
{
    assert(Thread);
    char NameBuf[seL4_MsgMaxLength * sizeof(MWORD)];
    /* We use the thread object addr to distinguish threads. */
    snprintf(NameBuf, sizeof(NameBuf), "%s|%p",
	     KEDBG_THREAD_TO_FILENAME(Thread), Thread);
    PCSTR DebugName = RtlDuplicateString(NameBuf, NTOS_PS_TAG);
    if (DebugName == NULL) {
	return STATUS_NO_MEMORY;
    }
    Thread->DebugName = DebugName;
#ifdef CONFIG_DEBUG_BUILD
    seL4_DebugNameThread(Thread->TreeNode.Cap, Thread->DebugName);
#endif
    return STATUS_SUCCESS;
}


static NTSTATUS PspMapSharedRegion(IN PPROCESS ClientProcess,
				   IN PMMVAD ServerVad,
				   IN OPTIONAL PMMVAD ClientVad,
				   IN MWORD InitialCommitSize,
				   IN BOOLEAN ClientReadOnly,
				   OUT MWORD *pServerAddr,
				   OUT MWORD *pClientAddr)
{
    assert(ServerVad);
    assert(ServerVad->Flags.BitmapManaged);
    MWORD ServerAddr = MmFindAndMarkUncommittedSubregion(ServerVad);
    if (!ServerAddr) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    MWORD ReserveSize = 1ULL << ServerVad->CommitmentStatus.LowZeroBits;
    BOOLEAN DeleteClientVad = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;
    MWORD ClientAddr = 0;
    if (ClientVad) {
	ClientAddr = MmFindAndMarkUncommittedSubregion(ClientVad);
	if (!ClientAddr) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto Fail;
	}
    } else {
	MWORD Flags = MEM_RESERVE_MIRRORED_MEMORY;
	if (ClientReadOnly) {
	    Flags |= MEM_RESERVE_READ_ONLY;
	}
	IF_ERR_GOTO(Fail, Status, MmReserveVirtualMemoryEx(&ClientProcess->VSpace,
							   USER_IMAGE_REGION_START,
							   USER_ADDRESS_END, ReserveSize,
							   0, 0, Flags, &ClientVad));
	DeleteClientVad = TRUE;
	MmRegisterMirroredMemory(ClientVad, &MiNtosVaddrSpace, ReserveSize);
	ClientAddr = ClientVad->AvlNode.Key;
    }
    assert(ClientVad != NULL);
    assert(ClientAddr != 0);

    IF_ERR_GOTO(Fail, Status, MmCommitOwnedMemory(ServerAddr, InitialCommitSize,
						  MM_RIGHTS_RW, FALSE));
    IF_ERR_GOTO(Fail, Status, MmMapMirroredMemory(&MiNtosVaddrSpace, ServerAddr,
						  &ClientProcess->VSpace, ClientAddr,
						  InitialCommitSize,
						  ClientReadOnly ? MM_RIGHTS_RO : MM_RIGHTS_RW,
						  MM_ATTRIBUTES_DEFAULT));

    *pServerAddr = ServerAddr;
    *pClientAddr = ClientAddr;
    return STATUS_SUCCESS;
Fail:
    if (DeleteClientVad) {
	MmDeleteVad(ClientVad);
    }
    MmUnmapServerRegion(ServerAddr);
    return Status;
}

static NTSTATUS PspCopyString(IN PCHAR Dest,
			      IN ULONG BufferSize,
			      IN PCSTR String)
{
    assert(Dest);
    assert(BufferSize);
    assert(String);
    SIZE_T Length = strlen(String);
    if (Length == 0) {
	return STATUS_INVALID_PARAMETER;
    }
    if (BufferSize < (Length + 1)) {
	return STATUS_BUFFER_TOO_SMALL;
    }
    memcpy(Dest, String, Length+1); /* trailing '\0' */
    return STATUS_SUCCESS;
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
    assert(!Process->Initialized || Ctx->Context != NULL);

    if (Ctx->InitialTeb &&
	(!Ctx->InitialTeb->StackBase || !Ctx->InitialTeb->StackLimit ||
	 !Ctx->InitialTeb->AllocatedStackBase ||
	 /* Stack reserve must be at least stack commit */
	 Ctx->InitialTeb->AllocatedStackBase > Ctx->InitialTeb->StackLimit ||
	 /* Stack commitment cannot be zero */
	 Ctx->InitialTeb->StackLimit >= Ctx->InitialTeb->StackBase)) {
	return STATUS_INVALID_PARAMETER;
    }

    PUNTYPED TcbUntyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_TCBBits, &TcbUntyped));

    assert(TcbUntyped->TreeNode.CNode != NULL);
    MmInitializeCapTreeNode(&Thread->TreeNode, CAP_TREE_NODE_TCB,
			    0, TcbUntyped->TreeNode.CNode, NULL);
    RET_ERR_EX(MmRetypeIntoObject(TcbUntyped, seL4_TCBObject,
				  seL4_TCBBits, &Thread->TreeNode),
	       MmReleaseUntyped(TcbUntyped));

    RET_ERR(MmCreateCNode(THREAD_PRIVATE_CNODE_LOG2SIZE, &Thread->CSpace));
    /* Copy the process shared CNode into the zeroth slot of the thread private CNode.
     * Note we don't track the cap tree derivation of this cap in a CAP_TREE_NODE, since
     * it is only used as a pointer into the process-wide shared CNode. Deleting the
     * thread-private CNode itself will automatically revoke this cap (and every other cap
     * in the thread-private CNode). */
    RET_ERR(MmCopyCap(Thread->CSpace, 0, Process->SharedCNode->TreeNode.CNode,
		      Process->SharedCNode->TreeNode.Cap, seL4_AllRights));

    Thread->Process = Process;
    ObpReferenceObject(Process);
    InitializeListHead(&Thread->ThreadListEntry);
    InitializeListHead(&Thread->PendingIrpList);
    InitializeListHead(&Thread->QueuedApcList);
    InitializeListHead(&Thread->TimerApcList);
    InitializeListHead(&Thread->LpcConnectionList);
    KeInitializeTimer(&Thread->WaitTimer, SynchronizationTimer);

    Thread->InitialThread = !Process->Initialized;
    InsertTailList(&Process->ThreadList, &Thread->ThreadListEntry);

    RET_ERR(PspSetThreadDebugName(Thread));

    /* Allocate and map the IPC buffer page */
    assert(Process->IpcRegionVad);
    RET_ERR(PspMapSharedRegion(Process, PspClientRegionServerVad, Process->IpcRegionVad,
			       PAGE_SIZE, FALSE, &Thread->IpcBufferServerAddr,
			       &Thread->IpcBufferClientAddr));
    assert(Thread->IpcBufferServerAddr);
    assert(Thread->IpcBufferClientAddr);

    PPAGING_STRUCTURE IpcBufferClientPage = MmQueryPageEx(&Process->VSpace,
							  Thread->IpcBufferClientAddr,
							  FALSE);
    assert(IpcBufferClientPage != NULL);
    assert(IpcBufferClientPage->AvlNode.Key == Thread->IpcBufferClientAddr);
    RET_ERR(KeEnableThreadFaultHandler(Thread));
    /* Note the TCB cap is in the NT Executive CSpace while the fault handler cap is
     * in the client thread's CSpace. */
    MWORD FaultHandlerCap = PsThreadCNodeIndexToGuardedCap(Thread->FaultEndpoint->TreeNode.Cap,
							   Thread);
    RET_ERR(PspConfigureThread(Thread->TreeNode.Cap, FaultHandlerCap,
			       Thread->CSpace, &Process->VSpace, IpcBufferClientPage,
			       PsGetThreadId(Thread) >> EX_POOL_BLOCK_SHIFT));
    RET_ERR(PspSetThreadFpu(Thread->TreeNode.Cap, FALSE));

    /* Allocate the subsystem-independent Thread Information Block for the client */
    RET_ERR(MmCommitOwnedMemoryEx(&Process->VSpace,
				  Thread->IpcBufferClientAddr + NT_TIB_OFFSET,
				  PAGE_SIZE, MM_RIGHTS_RW, MM_ATTRIBUTES_DEFAULT,
				  FALSE, NULL, 0));

    if (Ctx->InitialTeb == NULL) {
	PIMAGE_SECTION_OBJECT ImageSectionObject = Process->ImageSection->ImageSectionObject;
	ULONG StackReserve = ImageSectionObject->ImageInformation.MaximumStackSize;
	ULONG StackCommit = ImageSectionObject->ImageInformation.CommittedStackSize;
	if (StackCommit > StackReserve) {
	    StackCommit = StackReserve;
	}
	PMMVAD StackVad = NULL;
	RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, THREAD_STACK_START,
					 HIGHEST_USER_ADDRESS, StackReserve, 0, 0,
					 MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES
					 | MEM_COMMIT_ON_DEMAND, &StackVad));
	assert(StackVad != NULL);
	Thread->InitInfo.StackTop = StackVad->AvlNode.Key + StackVad->WindowSize;
	Thread->InitInfo.StackReserve = StackReserve;
	RET_ERR_EX(MmCommitVirtualMemoryEx(&Process->VSpace,
					   Thread->InitInfo.StackTop - StackCommit,
					   StackCommit),
		   MmDeleteVad(StackVad));
    } else {
	Thread->InitInfo.StackTop = (MWORD)Ctx->InitialTeb->StackBase;
	Thread->InitInfo.StackReserve =
	    Ctx->InitialTeb->StackBase - Ctx->InitialTeb->AllocatedStackBase;
    }

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
    /* Thread->InitInfo.Context is initialized as zero so if the caller
     * did not supply Ctx->Context we simply leave Context as zero. */
    if (Ctx->Context != NULL) {
	Thread->InitInfo.Context = *(Ctx->Context);
    }
    Thread->CurrentPriority = PASSIVE_LEVEL;
    RET_ERR(KeEnableSystemServices(Thread));
    if (Process->InitInfo.DriverProcess && !Thread->IsrThread) {
	RET_ERR(KeEnableWdmServices(Thread));
    }

    Thread->InitInfo.ClientId = PsGetClientId(Thread);
    if (Thread->InitialThread) {
	/* Populate the process init info used by ntdll on process startup */
	Process->InitInfo.ThreadInitInfo = Thread->InitInfo;
	PNTDLL_PROCESS_INIT_INFO InitInfo = (PVOID)Thread->IpcBufferServerAddr;
	*InitInfo = Process->InitInfo;

	PSECTION ImageSection = Process->ImageSection;
	assert(ImageSection);
	assert(ImageSection->ImageSectionObject);
	PIO_FILE_CONTROL_BLOCK Fcb = ImageSection->ImageSectionObject->Fcb;
	assert(Fcb);
	assert(Fcb->FileName);
	RET_ERR(PspCopyString(InitInfo->ImageName,
			      INIT_INFO_IMAGE_NAME_SIZE, Fcb->FileName));
	RET_ERR(PspCopyString(InitInfo->NtdllPath,
			      INIT_INFO_NTDLL_PATH_SIZE, NTDLL_PATH));
	if (Process->DriverObject) {
	    RET_ERR(PspCopyString(InitInfo->DriverInitInfo.ServicePath,
				  INIT_INFO_SERVICE_PATH_SIZE,
				  Process->DriverObject->DriverRegistryPath));
	}
    } else {
	/* Populate the thread init info used by ntdll on process startup */
	*((PNTDLL_THREAD_INIT_INFO)Thread->IpcBufferServerAddr) = Thread->InitInfo;
    }

    if (!Ctx->CreateSuspended) {
	RET_ERR(PspResumeThread(Thread->TreeNode.Cap));
    }

    if (Thread->InitialThread) {
	assert(!Process->Initialized);
	Process->Initialized = TRUE;
    }

    return STATUS_SUCCESS;
}

/*
 * Reserve and commit a coroutine stack for the driver process. Drivers can have
 * many coroutine stacks, each of which has 4 pages of reserved space, and the
 * middle two pages are committed. The first and last page are left as uncommitted
 * such that a stack overflow or underflow will trigger an exception.
 */
NTSTATUS PsMapDriverCoroutineStack(IN PPROCESS Process,
				   OUT MWORD *pStackTop)
{
    assert(Process != NULL);
    assert(Process->DriverObject != NULL);
    assert(pStackTop != NULL);

    PMMVAD Vad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
				     USER_ADDRESS_END, DRIVER_COROUTINE_STACK_RESERVE,
				     0, 0, MEM_RESERVE_OWNED_MEMORY, &Vad));
    assert(Vad != NULL);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, Vad->AvlNode.Key + PAGE_SIZE,
				    DRIVER_COROUTINE_STACK_COMMIT));
    *pStackTop = Vad->AvlNode.Key + PAGE_SIZE + DRIVER_COROUTINE_STACK_COMMIT;
    return STATUS_SUCCESS;
}

NTSTATUS PspProcessObjectCreateProc(IN POBJECT Object,
				    IN PVOID CreaCtx)
{
    PPROCESS Process = (PPROCESS)Object;
    assert(Process);
    PPROCESS_CREATION_CONTEXT Ctx = (PPROCESS_CREATION_CONTEXT)CreaCtx;
    assert(Ctx);
    PSECTION Section = Ctx->ImageSection;
    assert(Section);
    PIO_DRIVER_OBJECT DriverObject = Ctx->DriverObject;

    /* Section must be an image section */
    if (!Section->Flags.Image) {
	return STATUS_INVALID_PARAMETER;
    }
    BOOLEAN PeImage = Section->ImageSectionObject->Type == PeImageSection;

    ObpReferenceObject(Section);
    Process->ImageSection = Section;
    KeInitializeDispatcherHeader(&Process->Header, NotificationEvent);

    RET_ERR(MmCreateCNode(PROCESS_SHARED_CNODE_LOG2SIZE, &Process->SharedCNode));
    RET_ERR(MmCreateVSpace(&Process->VSpace));
    /* Reserve the memory before THREAD_STACK_START so we can catch stack underflow. */
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, 0, THREAD_STACK_START,
				     THREAD_STACK_START, 0, 0,
				     MEM_RESERVE_NO_ACCESS, NULL));

    InitializeListHead(&Process->ThreadList);
    InitializeListHead(&Process->ProcessListEntry);
    ObInitializeHandleTable(&Process->HandleTable);

    /* Assign an ASID for the virtual address space just created */
    RET_ERR(MmAssignASID(&Process->VSpace));

    if (PeImage) {
	MWORD NtdllBase = 0;
	MWORD NtdllViewSize = 0;
	RET_ERR(MmMapViewOfSection(&Process->VSpace, PspSystemDllSection,
				   &NtdllBase, NULL, &NtdllViewSize, 0,
				   ViewShare, 0, TRUE));
	assert(NtdllBase != 0);
	assert(NtdllViewSize != 0);
	Process->InitInfo.NtdllViewBase = NtdllBase;
	Process->InitInfo.NtdllViewSize = NtdllViewSize;
    }

    MWORD ImageBaseAddress = 0;
    MWORD ImageVirtualSize = 0;
    RET_ERR(MmMapViewOfSection(&Process->VSpace, Section,
			       &ImageBaseAddress, NULL, &ImageVirtualSize,
			       0, ViewUnmap, 0, TRUE));
    assert(ImageBaseAddress != 0);
    assert(ImageVirtualSize != 0);
    Process->InitInfo.ImageBase = ImageBaseAddress;
    Process->ImageVirtualSize = ImageVirtualSize;
    PSECTION TransferTarget = PeImage ? PspSystemDllSection : Section;
    Process->UserExceptionDispatcher =
	(MWORD)TransferTarget->ImageSectionObject->ImageInformation.TransferAddress;
    assert(Process->UserExceptionDispatcher);

    if (DriverObject != NULL) {
	Process->InitInfo.DriverProcess = TRUE;
	Process->InitInfo.DriverInitInfo.X86TscFreq = KeX86TscFreq;
	Process->DriverObject = DriverObject;
    }

    /* Reserve and commit the loader private heap */
    PMMVAD LoaderHeapVad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
				     USER_ADDRESS_END, NTDLL_LOADER_HEAP_RESERVE, 0, 0,
				     MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES,
				     &LoaderHeapVad));
    assert(LoaderHeapVad != NULL);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, LoaderHeapVad->AvlNode.Key,
				    NTDLL_LOADER_HEAP_COMMIT));
    Process->InitInfo.LoaderHeapStart = LoaderHeapVad->AvlNode.Key;

    /* Reserve and commit the process heap if target is a PE image */
    if (PeImage) {
	PIO_FILE_CONTROL_BLOCK Fcb = Section->ImageSectionObject->Fcb;
	PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(Fcb);
	if (!NtHeader) {
	    /* This shouldn't happen since we have already verified the image above. */
	    assert(FALSE);
	    return STATUS_INVALID_IMAGE_FORMAT;
	}
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
					 USER_ADDRESS_END, ProcessHeapReserve, 0, 0,
					 MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_LARGE_PAGES,
					 &ProcessHeapVad));
	assert(ProcessHeapVad != NULL);
	RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, ProcessHeapVad->AvlNode.Key,
					ProcessHeapCommit));
	Process->InitInfo.ProcessHeapStart = ProcessHeapVad->AvlNode.Key;
	Process->InitInfo.ProcessHeapReserve = ProcessHeapReserve;
	Process->InitInfo.ProcessHeapCommit = ProcessHeapCommit;
    }

    /* Reserve and commit the process environment block. */
    PMMVAD PebVad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, USER_IMAGE_REGION_START,
				     USER_ADDRESS_END, PEB_RESERVE, 0, 0,
				     MEM_RESERVE_OWNED_MEMORY | MEM_RESERVE_TOP_DOWN,
				     &PebVad));
    assert(PebVad != NULL);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, PebVad->AvlNode.Key,
				    PEB_COMMIT));
    Process->InitInfo.PebAddress = PebVad->AvlNode.Key;

    /* Reserve the client address space dedicated for IPC buffers and TEBs. */
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, IPC_BUFFER_START,
				     IPC_BUFFER_END, IPC_BUFFER_END - IPC_BUFFER_START,
				     CLIENT_IPC_REGION_LOW_ZERO_BITS, 0,
				     MEM_RESERVE_BITMAP_MANAGED, &Process->IpcRegionVad));

    /* Map the KUSER_SHARED_DATA into the client address space (read-only). */
    PMMVAD ClientSharedDataVad = NULL;
    RET_ERR(MmReserveVirtualMemoryEx(&Process->VSpace, KUSER_SHARED_DATA_CLIENT_ADDR,
				     0, sizeof(KUSER_SHARED_DATA), 0, 0,
				     MEM_RESERVE_MIRRORED_MEMORY | MEM_RESERVE_READ_ONLY,
				     &ClientSharedDataVad));
    assert(ClientSharedDataVad != NULL);
    assert(ClientSharedDataVad->AvlNode.Key == KUSER_SHARED_DATA_CLIENT_ADDR);
    MmRegisterMirroredVad(ClientSharedDataVad, PspUserSharedDataVad);
    RET_ERR(MmCommitVirtualMemoryEx(&Process->VSpace, KUSER_SHARED_DATA_CLIENT_ADDR,
				    sizeof(KUSER_SHARED_DATA)));

    if (DriverObject) {
	RET_ERR(PspMapSharedRegion(Process, PspDriverRegionServerVad, NULL,
				   DRIVER_IO_PACKET_BUFFER_COMMIT, TRUE,
				   &DriverObject->IncomingIoPacketsServerAddr,
				   &DriverObject->IncomingIoPacketsClientAddr));
	RET_ERR(PspMapSharedRegion(Process, PspDriverRegionServerVad, NULL,
				   DRIVER_IO_PACKET_BUFFER_COMMIT, FALSE,
				   &DriverObject->OutgoingIoPacketsServerAddr,
				   &DriverObject->OutgoingIoPacketsClientAddr));
	PNTDLL_DRIVER_INIT_INFO DriverInitInfo = &Process->InitInfo.DriverInitInfo;
	DriverInitInfo->IncomingIoPacketBuffer = DriverObject->IncomingIoPacketsClientAddr;
	DriverInitInfo->OutgoingIoPacketBuffer = DriverObject->OutgoingIoPacketsClientAddr;
	MWORD InitialCoroutineStackTop = 0;
	RET_ERR(PsMapDriverCoroutineStack(Process, &InitialCoroutineStackTop));
	Process->InitInfo.DriverInitInfo.InitialCoroutineStackTop = InitialCoroutineStackTop;
	RET_ERR(KeCreateNotificationEx(&Process->DpcMutex, Process->SharedCNode));
	Process->InitInfo.DriverInitInfo.DpcMutexCap = Process->DpcMutex.TreeNode.Cap;
	RET_ERR(KeCreateNotificationEx(&Process->WorkItemMutex, Process->SharedCNode));
	Process->InitInfo.DriverInitInfo.WorkItemMutexCap = Process->WorkItemMutex.TreeNode.Cap;
#if defined(_M_IX86) || defined(_M_AMD64)
	RET_ERR(KeCreateNotificationEx(&Process->X86PortMutex, Process->SharedCNode));
	Process->InitInfo.DriverInitInfo.X86PortMutexCap = Process->X86PortMutex.TreeNode.Cap;
#endif
    }

    /* Create the Event objects used by the NTDLL ldr component. Note if creation of
     * these events failed, we need to cleanup the handle entries here because in the
     * delete routine of the PROCESS object, we require that the handle table of the
     * process be empty (PsTerminateProcess is required to cleanup the handle table). */
#define DECLARE_EVENT_HANDLE(ObjName)				\
    PHANDLE_TABLE_ENTRY ObjName ## HandleTableEntry = NULL
    DECLARE_EVENT_HANDLE(CriticalSectionLockSemaphore);
    DECLARE_EVENT_HANDLE(LoaderLockSemaphore);
    DECLARE_EVENT_HANDLE(FastPebLockSemaphore);
    DECLARE_EVENT_HANDLE(ProcessHeapListLockSemaphore);
    DECLARE_EVENT_HANDLE(VectoredHandlerLockSemaphore);
    DECLARE_EVENT_HANDLE(ProcessHeapLockSemaphore);
    DECLARE_EVENT_HANDLE(LoaderHeapLockSemaphore);
#undef DECLARE_EVENT_HANDLE
    NTSTATUS Status;
#define CREATE_EVENT(ObjName)						\
    IF_ERR_GOTO(fail, Status, ExCreateEvent(Process,			\
					    SynchronizationEvent,	\
					    &Process->ObjName,		\
					    &Process->InitInfo.ObjName,	\
					    &ObjName##HandleTableEntry))
    CREATE_EVENT(CriticalSectionLockSemaphore);
    CREATE_EVENT(LoaderLockSemaphore);
    CREATE_EVENT(FastPebLockSemaphore);
    CREATE_EVENT(ProcessHeapListLockSemaphore);
    CREATE_EVENT(VectoredHandlerLockSemaphore);
    CREATE_EVENT(ProcessHeapLockSemaphore);
    CREATE_EVENT(LoaderHeapLockSemaphore);
#undef CREATE_EVENT

    /* Generate a per-process security cookie */
    LARGE_INTEGER SystemTime = { .QuadPart = KeQuerySystemTime() };
    Process->Cookie = KeQueryInterruptTime() ^ SystemTime.LowPart ^ SystemTime.HighPart;

    InsertTailList(&PspProcessList, &Process->ProcessListEntry);

    return STATUS_SUCCESS;

fail:
#define CLEANUP_HANDLE_ENTRY(ObjName)			\
    if (ObjName##HandleTableEntry) {			\
	ObRemoveHandle(ObjName##HandleTableEntry);	\
    }
    CLEANUP_HANDLE_ENTRY(CriticalSectionLockSemaphore);
    CLEANUP_HANDLE_ENTRY(LoaderLockSemaphore);
    CLEANUP_HANDLE_ENTRY(FastPebLockSemaphore);
    CLEANUP_HANDLE_ENTRY(ProcessHeapListLockSemaphore);
    CLEANUP_HANDLE_ENTRY(VectoredHandlerLockSemaphore);
    CLEANUP_HANDLE_ENTRY(ProcessHeapLockSemaphore);
    CLEANUP_HANDLE_ENTRY(LoaderHeapLockSemaphore);
#undef CLEANUP_HANDLE_ENTRY
    return Status;
}

NTSTATUS PsCreateThread(IN PPROCESS Process,
                        IN PCONTEXT ThreadContext,
                        IN PINITIAL_TEB InitialTeb,
                        IN ULONG Flags,
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
	.CreateSuspended = !!(Flags & PS_CREATE_THREAD_SUSPENDED),
	.IsrThread = !!(Flags & PS_CREATE_ISR_THREAD)
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_THREAD, (POBJECT *)&Thread, &CreaCtx));
    *pThread = Thread;
    return STATUS_SUCCESS;
}

NTSTATUS PsCreateProcess(IN OPTIONAL PSECTION ImageSection,
			 IN OPTIONAL PIO_DRIVER_OBJECT DriverObject,
			 OUT PPROCESS *pProcess)
{
    assert(pProcess != NULL);

    PPROCESS Process = NULL;
    PROCESS_CREATION_CONTEXT CreaCtx = {
	.DriverObject = DriverObject,
	.ImageSection = ImageSection
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_PROCESS, (POBJECT *)&Process, &CreaCtx));
    *pProcess = Process;
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
    RET_ERR(ObReferenceObjectByHandle(Thread, ProcessHandle,
				      OBJECT_TYPE_PROCESS, (POBJECT *)&Process));
    assert(Process != NULL);
    ObDereferenceObject(Process);

    PTHREAD CreatedThread = NULL;
    /* The newly created thread will increase the reference count of the process
     * object and decrease it when the thread exits or is terminated. */
    RET_ERR(PsCreateThread(Process, ThreadContext, InitialTeb,
			   CreateSuspended ? PS_CREATE_THREAD_SUSPENDED : 0,
			   &CreatedThread));
    /* The newly created thread object will have refcount 2. Although NT API semantics
     * states that thread object is always created as a temporary object, we don't make
     * it temporary at this point. The refcount decrement is done in PsTerminateThread,
     * when the thread exits. */
    RET_ERR_EX(ObCreateHandle(Thread->Process, CreatedThread, FALSE, ThreadHandle, NULL),
	       ObDereferenceObject(CreatedThread));
    *ClientId = PsGetClientId(CreatedThread);
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
    RET_ERR(ObReferenceObjectByHandle(Thread, SectionHandle,
				      OBJECT_TYPE_SECTION, (POBJECT *)&Section));
    assert(Section != NULL);
    ObDereferenceObject(Section);
    if (!Section->Flags.Image) {
	return STATUS_INVALID_PARAMETER_6;
    }

    PPROCESS Process = NULL;
    /* The newly created process will increase the reference count of the image section
     * object and decrease it when the process exits or is terminated. */
    RET_ERR(PsCreateProcess(Section, NULL, &Process));
    /* Like the case of thread objects, the newly created thread object will have
     * refcount 2, but we don't make decrement its refcount at this point. That is
     * done in PsTerminateProcess, when the process exits. */
    RET_ERR_EX(ObCreateHandle(Thread->Process, Process, FALSE, ProcessHandle, NULL),
	       ObDereferenceObject(Process));

    return STATUS_SUCCESS;
}
