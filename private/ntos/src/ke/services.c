#include "ki.h"

/* GCC assumes that stack is always 16-byte aligned before calling a function
 * (before the return address is pushed onto the stack). Do not change this. */
#define GCC_STACK_ALIGNMENT		(16)

/* ps/init.c */
extern MWORD PspUserExceptionDispatcherAddress;

IPC_ENDPOINT KiExecutiveServiceEndpoint;
LIST_ENTRY KiReadyThreadList;

NTSTATUS KiCreateEndpoint(IN PIPC_ENDPOINT Endpoint)
{
    PUNTYPED Untyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_EndpointBits, &Untyped));
    assert(Untyped != NULL);
    KeInitializeIpcEndpoint(Endpoint, Untyped->TreeNode.CSpace, 0, 0);
    RET_ERR_EX(MmRetypeIntoObject(Untyped, seL4_EndpointObject, seL4_EndpointBits,
				  &Endpoint->TreeNode),
	       MmReleaseUntyped(Untyped));
    assert(Endpoint->TreeNode.Cap != 0);
    return STATUS_SUCCESS;
}

/*
 * This destroys the endpoint object but does not free the pool memory.
 *
 * IMPORTANT: The endpoint being destroyed cannot have any derived cap.
 */
static VOID KiDestroyEndpoint(IN PIPC_ENDPOINT Endpoint)
{
    assert(Endpoint != NULL);
    assert(!MmCapTreeNodeHasChildren(&Endpoint->TreeNode));
    /* Detach the cap node from the cap derivation tree and release its
     * parent untyped (if any) */
    MmCapTreeDeleteNode(&Endpoint->TreeNode);
}

/*
 * Create the IPC endpoint for the system services. This IPC endpoint
 * is then badged via seL4_CNode_Mint. Also initialize the ready thread list.
 */
NTSTATUS KiInitExecutiveServices()
{
    RET_ERR(KiCreateEndpoint(&KiExecutiveServiceEndpoint));
    InitializeListHead(&KiReadyThreadList);
    return STATUS_SUCCESS;
}

/*
 * If the reply endpoint cap has not been reserved, reserves the reply cap
 * in the NTOS Executive CSpace and creates an IPC endpoint derived from
 * the Executive service endpoint with the given IPC badge. Otherwise, just
 * create the service endpoint.
 *
 * Note that since all service types share the same reply type (and are
 * derived from the same master endpoint in the NTOS Executive CSpace), we
 * only need to reserve one reply endpoint for each thread.
 *
 * The IPC endpoint cap is created in the specified CSpace.
 */
static NTSTATUS KiEnableClientServiceEndpoint(IN PIPC_ENDPOINT ReplyEndpoint,
					      OUT PIPC_ENDPOINT *pServiceEndpoint,
					      IN PCNODE CSpace,
					      IN MWORD IPCBadge)
{
    assert(ReplyEndpoint != NULL);
    assert(pServiceEndpoint != NULL);
    assert(CSpace != NULL);

    MWORD ReplyCap = 0;
    extern CNODE MiNtosCNode;
    if (ReplyEndpoint->TreeNode.Cap == 0) {
	RET_ERR(MmAllocateCapRange(&MiNtosCNode, &ReplyCap, 1));
	assert(ReplyCap != 0);
	KeInitializeIpcEndpoint(ReplyEndpoint, &MiNtosCNode, ReplyCap, 0);
    }

    KiAllocatePool(ServiceEndpoint, IPC_ENDPOINT);
    KeInitializeIpcEndpoint(ServiceEndpoint, CSpace, 0, IPCBadge);
    RET_ERR_EX(MmCapTreeDeriveBadgedNode(&ServiceEndpoint->TreeNode,
					 &KiExecutiveServiceEndpoint.TreeNode,
					 ENDPOINT_RIGHTS_WRITE_GRANTREPLY,
					 IPCBadge),
	       KiFreePool(ServiceEndpoint));

    *pServiceEndpoint = ServiceEndpoint;
    return STATUS_SUCCESS;
}

static NTSTATUS KiEnableThreadServiceEndpoint(IN PTHREAD Thread,
					      IN SERVICE_TYPE ServiceType)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->Process->CSpace != NULL);
    assert(ServiceType < MAX_NUM_SERVICE_TYPES);
    assert(ServiceType != SERVICE_TYPE_NOTIFICATION);
    assert(ServiceType != SERVICE_TYPE_SYSTEM_THREAD_FAULT_HANDLER);

    MWORD IPCBadge = OBJECT_TO_GLOBAL_HANDLE(Thread) | ServiceType;
    PIPC_ENDPOINT ServiceEndpoint = NULL;
    RET_ERR(KiEnableClientServiceEndpoint(&Thread->ReplyEndpoint,
					  &ServiceEndpoint,
					  Thread->Process->CSpace,
					  IPCBadge));
    assert(ServiceEndpoint != NULL);

    if (ServiceType == SERVICE_TYPE_SYSTEM_SERVICE) {
	Thread->SystemServiceEndpoint = ServiceEndpoint;
	Thread->InitInfo.SystemServiceCap = ServiceEndpoint->TreeNode.Cap;
    } else if (ServiceType == SERVICE_TYPE_WDM_SERVICE) {
	Thread->WdmServiceEndpoint = ServiceEndpoint;
	Thread->InitInfo.WdmServiceCap = ServiceEndpoint->TreeNode.Cap;
    } else {
	assert(ServiceType == SERVICE_TYPE_FAULT_HANDLER);
	Thread->FaultEndpoint = ServiceEndpoint;
    }
    return STATUS_SUCCESS;
}

NTSTATUS KeEnableSystemServices(IN PTHREAD Thread)
{
    return KiEnableThreadServiceEndpoint(Thread, SERVICE_TYPE_SYSTEM_SERVICE);
}

VOID KiDeleteThreadEndpoint(IN OPTIONAL PIPC_ENDPOINT Endpoint)
{
    if (Endpoint != NULL) {
	KiDestroyEndpoint(Endpoint);
	KiFreePool(Endpoint);
    }
}

/*
 * This will delete all the client-side service endpoints and release the
 * reply cap (in the NTOS CSpace) previously reserved for the thread.
 *
 * Note this is called by the delete routine of the THREAD object so it should
 * not assert when the endpoint is NULL.
 */
VOID KeDisableThreadServices(IN PTHREAD Thread)
{
    extern CNODE MiNtosCNode;
    if (Thread->ReplyEndpoint.TreeNode.Cap != 0) {
	MmDeallocateCap(&MiNtosCNode, Thread->ReplyEndpoint.TreeNode.Cap);
    }
    KiDeleteThreadEndpoint(Thread->SystemServiceEndpoint);
    KiDeleteThreadEndpoint(Thread->WdmServiceEndpoint);
    KiDeleteThreadEndpoint(Thread->FaultEndpoint);
}

/*
 * Enable the WDM service endpoint.
 */
NTSTATUS KeEnableWdmServices(IN PTHREAD Thread)
{
    return KiEnableThreadServiceEndpoint(Thread, SERVICE_TYPE_WDM_SERVICE);
}

/*
 * Enable the thread fault handler endpoint.
 */
NTSTATUS KeEnableThreadFaultHandler(IN PTHREAD Thread)
{
    return KiEnableThreadServiceEndpoint(Thread, SERVICE_TYPE_FAULT_HANDLER);
}

NTSTATUS KeEnableSystemThreadFaultHandler(IN PSYSTEM_THREAD Thread)
{
    assert(Thread != NULL);
    extern CNODE MiNtosCNode;

    MWORD IPCBadge = POINTER_TO_GLOBAL_HANDLE(Thread) | SERVICE_TYPE_SYSTEM_THREAD_FAULT_HANDLER;
    PIPC_ENDPOINT ServiceEndpoint = NULL;
    RET_ERR(KiEnableClientServiceEndpoint(&Thread->ReplyEndpoint,
					  &Thread->FaultEndpoint,
					  &MiNtosCNode,
					  IPCBadge));
    assert(Thread->FaultEndpoint != NULL);

    return STATUS_SUCCESS;
}

NTSTATUS KeLoadThreadContext(IN MWORD ThreadCap,
			     IN PTHREAD_CONTEXT Context)
{
    assert(ThreadCap != 0);
    int Error = seL4_TCB_ReadRegisters(ThreadCap, 0, 0,
				       sizeof(THREAD_CONTEXT) / sizeof(MWORD),
				       Context);

    if (Error != 0) {
	DbgTrace("seL4_TCB_ReadRegisters failed for thread cap 0x%zx with error %d\n",
		 ThreadCap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

NTSTATUS KeSetThreadContext(IN MWORD ThreadCap,
			    IN PTHREAD_CONTEXT Context)
{
    assert(ThreadCap != 0);
    int Error = seL4_TCB_WriteRegisters(ThreadCap, 0, 0,
					sizeof(THREAD_CONTEXT) / sizeof(MWORD),
					Context);

    if (Error != 0) {
	DbgTrace("seL4_TCB_WriteRegisters failed for thread cap 0x%zx with error %d\n",
		 ThreadCap, Error);
	return SEL4_ERROR(Error);
    }

    return STATUS_SUCCESS;
}

static inline BOOLEAN KiValidateUnicodeString(IN MWORD IpcBufferServerAddr,
					      IN MWORD MsgWord,
					      IN BOOLEAN Optional)
{
    /* Allow NULL pointer if parameter is marked optional */
    if (MsgWord == 0) {
	return Optional;
    }

    SERVICE_ARGUMENT Arg = { .Word = MsgWord };
    if (!KiServiceValidateArgument(MsgWord)) {
	return FALSE;
    }
    PCSTR String = (PCSTR) KiServiceGetArgument(IpcBufferServerAddr, MsgWord);
    if (String[Arg.BufferSize-1] != '\0') {
	return FALSE;
    }
    return TRUE;
}

static inline BOOLEAN KiValidateObjectAttributes(IN MWORD IpcBufferServerAddr,
						 IN MWORD MsgWord,
						 IN BOOLEAN Optional)
{
    /* Allow NULL pointer if parameter is marked optional */
    if (MsgWord == 0) {
	return Optional;
    }

    SERVICE_ARGUMENT Arg = { .Word = MsgWord };
    if (!KiServiceValidateArgument(MsgWord)) {
	return FALSE;
    }
    if (Arg.BufferSize < (sizeof(HANDLE) + sizeof(ULONG))) {
	return FALSE;
    }
    /* Object name can be NULL. */
    if (Arg.BufferSize == (sizeof(HANDLE) + sizeof(ULONG))) {
	return TRUE;
    }
    PCSTR String = (PCSTR) KiServiceGetArgument(IpcBufferServerAddr, MsgWord);
    if (String[Arg.BufferSize-1] != '\0') {
	return FALSE;
    }
    return TRUE;
}

/*
 * When unmarshaling an OBJECT_ATTRIBUTES argument we allocate the OB_OBJECT_ATTRIBUTES
 * struct on the stack and pass it around by value. This way we don't need to invoke
 * ExAllocatePoolWithTag which might fail.
 */
static inline OB_OBJECT_ATTRIBUTES KiUnmarshalObjectAttributes(IN MWORD IpcBufferAddr,
							       IN MWORD MsgWord)
{
    SERVICE_ARGUMENT Arg = { .Word = MsgWord };
    ULONG MsgOffset = Arg.BufferStart;
    ULONG MsgSize = Arg.BufferSize;
    OB_OBJECT_ATTRIBUTES ObjAttr;
    if (MsgWord == 0) {
	memset(&ObjAttr, 0, sizeof(OB_OBJECT_ATTRIBUTES));
    } else {
	ObjAttr.RootDirectory = SVC_MSGBUF_OFFSET_TO_ARG(IpcBufferAddr, MsgOffset, HANDLE);
	MsgOffset += sizeof(HANDLE);
	ObjAttr.Attributes = SVC_MSGBUF_OFFSET_TO_ARG(IpcBufferAddr, MsgOffset, ULONG);
	MsgOffset += sizeof(ULONG);
	if (MsgSize == (sizeof(HANDLE) + sizeof(ULONG))) {
	    ObjAttr.ObjectNameBuffer = NULL;
	} else {
	    ObjAttr.ObjectNameBuffer = &SVC_MSGBUF_OFFSET_TO_ARG(IpcBufferAddr, MsgOffset, CHAR);
	}
	ObjAttr.ObjectNameBufferLength = MsgSize - sizeof(HANDLE) - sizeof(ULONG);
    }
    return ObjAttr;
}

static NTSTATUS KiServiceSaveReplyCap(IN PTHREAD Thread)
{
    assert(Thread->ReplyEndpoint.TreeNode.CSpace != NULL);
    int Error = seL4_CNode_SaveCaller(Thread->ReplyEndpoint.TreeNode.CSpace->TreeNode.Cap,
				      Thread->ReplyEndpoint.TreeNode.Cap,
				      Thread->ReplyEndpoint.TreeNode.CSpace->Depth);
    if (Error != 0) {
	KeDbgDumpIPCError(Error);
	return SEL4_ERROR(Error);
    }
    return STATUS_SUCCESS;
}

static inline VOID KiCheckAsyncStackEmpty(IN PTHREAD Thread)
{
    for (ULONG i = 0; i < ARRAYSIZE(Thread->AsyncStack.Stack); i++) {
	assert(Thread->AsyncStack.Stack[i] == 0);
    }
}

/* The actual handling of system services is in the generated file below. */
#include <ntos_syssvc_gen.c>
#include <ntos_wdmsvc_gen.c>

static inline NTSTATUS KiResumeService(IN PTHREAD ReadyThread,
				       OUT ULONG *pReplyMsgLength,
				       OUT ULONG *pMsgBufferEnd)
{
    if (ReadyThread->WdmSvc) {
	return KiResumeWdmService(ReadyThread, pReplyMsgLength, pMsgBufferEnd);
    } else {
	return KiResumeSystemService(ReadyThread, pReplyMsgLength, pMsgBufferEnd);
    }
}

static VOID KiDumpThreadFault(IN seL4_Fault_t Fault,
			      IN PTHREAD Thread,
			      IN BOOLEAN Unhandled,
			      IN KI_DBG_PRINTER DbgPrinter)
{
    PPROCESS Process = Thread->Process;
    assert(Process != NULL);
    assert(Process->ImageFile != NULL);
    assert(Process->ImageFile->FileName != NULL);
    DbgPrinter("\n==============================================================================\n"
		"%s %s in thread %s|%p\n",
	       Unhandled ? "Unhandled" : "Caught",
	       KiDbgGetFaultName(Fault),
	       Process->ImageFile->FileName, Thread);
    KiDbgDumpFault(Fault, DbgPrinter);
    THREAD_CONTEXT Context;
    NTSTATUS Status = KeLoadThreadContext(Thread->TreeNode.Cap, &Context);
    if (!NT_SUCCESS(Status)) {
	DbgPrinter("Unable to dump thread context. Error 0x%08x\n", Status);
    }
    KiDumpThreadContext(&Context, DbgPrinter);
    DbgPrinter("MODULE %s  MAPPED [%p, %p)\n", Process->ImageFile->FileName,
	       Process->ImageBaseAddress, Process->ImageBaseAddress + Process->ImageVirtualSize);
    /* Dump the loaded modules of the process as well. */
    PLOADER_SHARED_DATA LdrData = (PLOADER_SHARED_DATA)Process->LoaderSharedDataServerAddr;
    if (LdrData != NULL) {
	PLDRP_LOADED_MODULE ModuleData = (PLDRP_LOADED_MODULE)((MWORD)LdrData + LdrData->LoadedModules);
	for (ULONG i = 0; i < LdrData->LoadedModuleCount; i++) {
	    DbgPrinter("MODULE %s  MAPPED [%p, %p)\n", (PCSTR)((MWORD)LdrData + ModuleData->DllName),
		       (PVOID)ModuleData->ViewBase,
		       (PVOID)(ModuleData->ViewBase + ModuleData->ViewSize));
	    ModuleData = (PLDRP_LOADED_MODULE)((MWORD)ModuleData + ModuleData->EntrySize);
	}
    }
    DbgPrinter("==============================================================================\n");
}

static VOID KiDumpSystemThreadFault(IN seL4_Fault_t Fault,
				    IN PSYSTEM_THREAD Thread,
				    IN KI_DBG_PRINTER DbgPrinter)
{
    DbgPrinter("\n==============================================================================\n"
	       "Unhandled %s in system thread %s (thread obj %p thread entry %p)\n",
	       KiDbgGetFaultName(Fault), Thread->DebugName, Thread, Thread->EntryPoint);
    KiDbgDumpFault(Fault, DbgPrinter);
    THREAD_CONTEXT Context;
    NTSTATUS Status = KeLoadThreadContext(Thread->TreeNode.Cap, &Context);
    if (!NT_SUCCESS(Status)) {
	DbgPrinter("Unable to dump thread context. Error 0x%08x\n", Status);
    }
    KiDumpThreadContext(&Context, DbgPrinter);
    DbgPrinter("==============================================================================\n");
}

#define MIN_USER_EXCEPTION_STACK    (256)

/*
 * Attempt to handle the thread fault. Return STATUS_SUCCESS if the
 * fault is handled and thread should be resumed. Return error if the
 * fault cannot be handled and the thread should be terminated.
 */
static NTSTATUS KiHandleThreadFault(IN PTHREAD Thread,
				    IN seL4_Fault_t Fault)
{
    assert(Thread != NULL);

    ULONG ExceptionCode = KI_VM_FAULT_CODE;
    MWORD ExceptionAddress = 0;
    MWORD ExceptionParameter = 0;
    switch (seL4_Fault_get_seL4_FaultType(Fault)) {
    case seL4_Fault_VMFault:
	/* For VM fault the first exception parameter is the vm address that
	 * the client was trying to access. */
	ExceptionParameter = seL4_Fault_VMFault_get_Addr(Fault);
	/* Check if the VM fault should be handled transparently, without
	 * ever involving the client side. */
	if (MmHandleThreadVmFault(Thread, ExceptionParameter)) {
	    DbgTrace("VM fault handled transparently. Restarting thread.\n");
	    /* VM fault is handled transparently. Restart the thread. */
	    return STATUS_SUCCESS;
	}
	ExceptionAddress = seL4_Fault_VMFault_get_IP(Fault);
	break;
    case seL4_Fault_UserException:
	ExceptionCode = seL4_Fault_UserException_get_Number(Fault);
	ExceptionAddress = seL4_Fault_UserException_get_FaultIP(Fault);
	ExceptionParameter = seL4_Fault_UserException_get_Code(Fault);
	break;
    /* Anything other than user exception or vm fault will simply
     * terminate the thread. */
    case seL4_Fault_CapFault:
	return STATUS_INVALID_HANDLE;
    case seL4_Fault_UnknownSyscall:
	return STATUS_INVALID_SYSTEM_SERVICE;
    case seL4_Fault_NullFault:
    default:
	return STATUS_UNSUCCESSFUL;
    }

    /* Note this code path corresponds to the FirstChance == TRUE logic
     * in the KiDispatchException function of the Windows/ReactOS code
     * (ntoskrnl/ke/i386/exp.c in ReactOS). The second chance exception
     * handling is done in NtRaiseException. */
    THREAD_CONTEXT Context;
    RET_ERR(KeLoadThreadContext(Thread->TreeNode.Cap, &Context));
    MWORD StackPointer = Context._STACK_POINTER;
    MWORD AlignedStackPointer = ALIGN_DOWN_BY(StackPointer, GCC_STACK_ALIGNMENT);
    MWORD ContextSize = ALIGN_UP_BY(sizeof(CONTEXT), GCC_STACK_ALIGNMENT);
    MWORD ExceptionRecordSize = ALIGN_UP_BY(sizeof(EXCEPTION_RECORD), GCC_STACK_ALIGNMENT);
    /* In addition to the CONTEXT and EXCEPTION_RECORD we also include
     * the minimal stack space needed to handle an exception. */
    MWORD MinFreeUserStack = ContextSize + ExceptionRecordSize + MIN_USER_EXCEPTION_STACK;

    /* Check if the user stack is valid and has enough space. If ok,
     * map the user stack into server address space so we can copy the
     * exception context onto the user stack. If not, try committing more
     * space. If that fails, then we have no choice but to terminate the process. */
    if (AlignedStackPointer < MinFreeUserStack) {
	return STATUS_NO_MEMORY;
    }
    MWORD WindowSize = MinFreeUserStack + StackPointer - AlignedStackPointer;
    PCHAR MappedUserStack = 0;
    NTSTATUS Status = MmMapUserBuffer(&Thread->Process->VSpace,
				      AlignedStackPointer - MinFreeUserStack,
				      WindowSize,
				      (PPVOID)&MappedUserStack);
    if (!NT_SUCCESS(Status) && (Status != STATUS_NOT_COMMITTED)) {
	return Status;
    } else if (Status == STATUS_NOT_COMMITTED) {
	/* If the user stack is reserved but not committed, try committing more
	 * space, and then attempt to map the user buffer for a second time. */
	RET_ERR(MmTryCommitWindowRW(&Thread->Process->VSpace,
				    AlignedStackPointer - MinFreeUserStack,
				    WindowSize));
	RET_ERR(MmMapUserBuffer(&Thread->Process->VSpace,
				AlignedStackPointer - MinFreeUserStack,
				WindowSize,
				(PPVOID)&MappedUserStack));
    }

    /* If we got here, the user stack must have been mapped successfully. */
    assert(MappedUserStack != NULL);
    /*
     * The stack organization is as follows (left is lower address):
     *
     * |------------------------|------------------------|
     * |MIN_USER_EXCEPTION_STACK|CONTEXT|EXCEPTION_RECORD|
     * |------------------------|------------------------|
     * ^                        ^                        ^
     * ^                        NewStackPointer          AlignedStackPointer
     * ^
     * MappedUserStack (in server address space)
     *
     * Pointer to ExceptionRecord is passed via FASTCALL_FIRST_PARAM (ecx/rcx).
     * Pointer to Context is passed via FASTCALL_SECOND_PARAM (edx/rdx).
     *
     * Note: The Windows AMD64 ABI does NOT have the 128-byte red zone that
     * the SystemV AMD64 ABI has. Therefore we are free to clobber the stack
     * space below %rsp.
     */
    PCONTEXT UserContext = (PCONTEXT)(MappedUserStack + MIN_USER_EXCEPTION_STACK);
    memset(UserContext, 0, ContextSize + ExceptionRecordSize);
    KiPopulateUserExceptionContext(UserContext, &Context);
    PEXCEPTION_RECORD ExceptionRecord = (PEXCEPTION_RECORD)
	(MappedUserStack + MIN_USER_EXCEPTION_STACK + ContextSize);
    ExceptionRecord->ExceptionCode = ExceptionCode;
    ExceptionRecord->ExceptionAddress = (PVOID)ExceptionAddress;
    ExceptionRecord->NumberParameters = 1;
    ExceptionRecord->ExceptionInformation[0] = ExceptionParameter;

    /* Set the thread context to dispatch to KiUserExceptionDispatcher */
    MWORD NewStackPointer = AlignedStackPointer - ExceptionRecordSize - ContextSize;
    Context._FASTCALL_FIRST_PARAM = AlignedStackPointer - ExceptionRecordSize;
    Context._FASTCALL_SECOND_PARAM = NewStackPointer;
    Context._STACK_POINTER = NewStackPointer;
    Context._INSTRUCTION_POINTER = PspUserExceptionDispatcherAddress;
    RET_ERR_EX(KeSetThreadContext(Thread->TreeNode.Cap, &Context),
	       MmUnmapUserBuffer(MappedUserStack));
    MmUnmapUserBuffer(MappedUserStack);
    DbgTrace("Dispatched thread %s to ntdll!" USER_EXCEPTION_DISPATCHER_NAME "\n",
	     Thread->DebugName);
    return STATUS_SUCCESS;
}

VOID KiDispatchExecutiveServices()
{
    MWORD Badge = 0;
    while (TRUE) {
	seL4_MessageInfo_t Request = seL4_Recv(KiExecutiveServiceEndpoint.TreeNode.Cap, &Badge);
	ULONG SvcNum = seL4_MessageInfo_get_label(Request);
	ULONG ReqMsgLength = seL4_MessageInfo_get_length(Request);
	ULONG NumUnwrappedCaps = seL4_MessageInfo_get_capsUnwrapped(Request);
	ULONG NumExtraCaps = seL4_MessageInfo_get_extraCaps(Request);
	DbgTrace("Got message label 0x%x length %d unwrapped caps %d extra caps %d badge 0x%zx\n",
		 SvcNum, ReqMsgLength, NumUnwrappedCaps, NumExtraCaps, Badge);
	if (GLOBAL_HANDLE_GET_FLAG(Badge) == SERVICE_TYPE_FAULT_HANDLER) {
	    /* The thread has faulted. */
	    PTHREAD Thread = GLOBAL_HANDLE_TO_OBJECT(Badge);
	    seL4_Fault_t Fault = seL4_getFault(Request);
#ifdef CONFIG_DEBUG_BUILD
	    KiDumpThreadFault(Fault, Thread, FALSE, DbgPrint);
#endif
	    NTSTATUS Status = KiHandleThreadFault(Thread, Fault);
	    if (!NT_SUCCESS(Status)) {
		/* The fault cannot be handled. Printe a message and terminate the thread. */
		KiDumpThreadFault(Fault, Thread, TRUE, HalVgaPrint);
		PsTerminateThread(Thread, Status);
	    } else {
		/* The fault has been either handled or we are dispatching user SEH.
		 * Restart the thread. */
		seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
	    }
	} else if (GLOBAL_HANDLE_GET_FLAG(Badge) == SERVICE_TYPE_SYSTEM_THREAD_FAULT_HANDLER) {
	    /* The thread has faulted. For system services we always terminate the thread. */
	    PSYSTEM_THREAD Thread = (PSYSTEM_THREAD)GLOBAL_HANDLE_TO_POINTER(Badge);
	    seL4_Fault_t Fault = seL4_getFault(Request);
#ifdef CONFIG_DEBUG_BUILD
	    KiDumpSystemThreadFault(Fault, Thread, DbgPrint);
#endif
	    KiDumpSystemThreadFault(Fault, Thread, HalVgaPrint);
	    PsTerminateSystemThread(Thread);
	} else if (GLOBAL_HANDLE_GET_FLAG(Badge) != SERVICE_TYPE_NOTIFICATION) {
	    /* The timer irq thread generates service notifications with seL4_NBWait, to inform
	     * us that the expired timer list should be checked even though there is no service
	     * message from a client thread. In the case of a service notification, we skip the
	     * following message processing, as is indicated by the if-condition above. */
	    ULONG ReplyMsgLength = 1;
	    ULONG MsgBufferEnd = 0;
	    SHORT NumApc = 0;
	    /* Reject the system service call since the service message is invalid. */
	    NTSTATUS Status = STATUS_INVALID_PARAMETER;
	    if ((NumUnwrappedCaps != 0) || (NumExtraCaps != 0)) {
		DbgTrace("Invalid system service message (%d unwrapped caps, %d extra caps)\n",
			 NumUnwrappedCaps, NumExtraCaps);
	    } else {
		/* Thread is always a valid pointer since the client cannot modify the badge */
		assert(Badge != 0);
		PTHREAD Thread = GLOBAL_HANDLE_TO_OBJECT(Badge);
		/* On debug build we check that the async function has correctly poped the
		 * async stack (by using ASYNC_RETURN rather than return). This should have
		 * been caught by the KiCheckAsyncStackEmpty when we reply to the client but
		 * we want to make sure (async calls are hard to debug!). */
		KiCheckAsyncStackEmpty(Thread);
		if (GLOBAL_HANDLE_GET_FLAG(Badge) == SERVICE_TYPE_WDM_SERVICE) {
		    DbgTrace("Got driver call from thread %p\n", Thread);
		    Status = KiHandleWdmService(SvcNum, Thread, ReqMsgLength,
						&ReplyMsgLength, &MsgBufferEnd);
		} else {
		    assert(GLOBAL_HANDLE_GET_FLAG(Badge) == SERVICE_TYPE_SYSTEM_SERVICE);
		    DbgTrace("Got call from thread %p\n", Thread);
		    Status = KiHandleSystemService(SvcNum, Thread, ReqMsgLength,
						   &ReplyMsgLength, &MsgBufferEnd);
		}
		/* If the service handler returned USER APC status, we should deliver APCs */
		if (Status == STATUS_USER_APC) {
		    NumApc = KiDeliverApc(Thread, MsgBufferEnd);
		}
		if ((Status != STATUS_ASYNC_PENDING) && (Status != STATUS_NTOS_NO_REPLY)) {
		    /* Before we reply to the client, on debug build we check that the async function has
		     * correctly poped the async stack (by using ASYNC_RETURN rather than return). */
		    KiCheckAsyncStackEmpty(Thread);
		}
	    }
	    if ((Status != STATUS_ASYNC_PENDING) && (Status != STATUS_NTOS_NO_REPLY)) {
		seL4_SetMR(0, (MWORD) Status);
		seL4_Reply(seL4_MessageInfo_new((USHORT)NumApc, 0, 0, ReplyMsgLength));
	    }
	}
	/* Check the expired timer list and wake up any thread that is waiting on them */
	KiSignalExpiredTimerList();
	/* Check if any other thread is awaken and attempt to continue the execution of
	 * its service handler from the saved context. */
	while (!IsListEmpty(&KiReadyThreadList)) {
	    PTHREAD ReadyThread = CONTAINING_RECORD(KiReadyThreadList.Flink,
						    THREAD, ReadyListLink);
	    ULONG ReplyMsgLength = 0;
	    ULONG MsgBufferEnd = 0;
	    SHORT NumApc = 0;
	    NTSTATUS Status = KiResumeService(ReadyThread, &ReplyMsgLength, &MsgBufferEnd);
	    /* Regardless of whether the handler function has completed, we should
	     * remove the thread from the ready list. In the case that the async status
	     * is still pending (because the handler function has blocked on a different
	     * async wait), it is important that we do not wake up the thread too soon. */
	    RemoveEntryList(&ReadyThread->ReadyListLink);
	    /* Reply to the thread if the handler function has completed */
	    if ((Status != STATUS_ASYNC_PENDING) && (Status != STATUS_NTOS_NO_REPLY)) {
		/* If the service handler returned USER APC status, we should deliver APCs */
		if (Status == STATUS_USER_APC) {
		    NumApc = KiDeliverApc(ReadyThread, MsgBufferEnd);
		}
		/* Before we reply to the client, on debug build we check that the async function has
		 * correctly poped the async stack (by using ASYNC_RETURN rather than return). */
		KiCheckAsyncStackEmpty(ReadyThread);
		/* We return the service status via the zeroth message register and
		 * the number of APCs via the label of the message */
		seL4_SetMR(0, (MWORD) Status);
		seL4_Send(ReadyThread->ReplyEndpoint.TreeNode.Cap,
			  seL4_MessageInfo_new((USHORT)NumApc, 0, 0, ReplyMsgLength));
	    }
	}
    }
}
