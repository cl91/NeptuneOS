#include "ki.h"

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
 * Reserves the reply cap in the NTOS Executive CSpace and creates
 * an IPC endpoint derived from the Executive service endpoint with
 * the given IPC badge. The IPC endpoint cap is in the given CSpace.
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
    RET_ERR(MmAllocateCapRange(&MiNtosCNode, &ReplyCap, 1));
    assert(ReplyCap != 0);
    KeInitializeIpcEndpoint(ReplyEndpoint, &MiNtosCNode, ReplyCap, 0);

    KiAllocatePoolEx(ServiceEndpoint, IPC_ENDPOINT,
		     {
			 MmDeallocateCap(&MiNtosCNode, ReplyCap);
			 ReplyEndpoint->TreeNode.Cap = 0;
		     });
    KeInitializeIpcEndpoint(ServiceEndpoint, CSpace, 0, IPCBadge);
    RET_ERR_EX(MmCapTreeDeriveBadgedNode(&ServiceEndpoint->TreeNode,
					 &KiExecutiveServiceEndpoint.TreeNode,
					 ENDPOINT_RIGHTS_WRITE_GRANTREPLY,
					 IPCBadge),
	       {
		   KiFreePool(ServiceEndpoint);
		   MmDeallocateCap(&MiNtosCNode, ReplyCap);
		   ReplyEndpoint->TreeNode.Cap = 0;
	       });

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

NTSTATUS KeEnableWdmServices(IN PTHREAD Thread)
{
    return KiEnableThreadServiceEndpoint(Thread, SERVICE_TYPE_WDM_SERVICE);
}

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
			      IN KI_DBG_PRINTER DbgPrinter)
{
    PPROCESS Process = Thread->Process;
    assert(Process != NULL);
    assert(Process->ImageFile != NULL);
    assert(Process->ImageFile->FileName != NULL);
    DbgPrinter("\n==============================================================================\n"
		"Unhandled %s in thread %s|%p\n",
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
	       "Unhandled %s in thread %s (thread obj %p thread entry %p)\n",
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

/*
 * Attempt to handle the thread fault. Return TRUE if the fault is
 * handled and thread should be resumed. Return FALSE if the fault
 * cannot be handled and the thread should be terminated.
 */
static BOOLEAN KiHandleThreadFault(IN PTHREAD Thread,
				   IN seL4_Fault_t Fault)
{
    assert(Thread != NULL);
    if (seL4_Fault_get_seL4_FaultType(Fault) == seL4_Fault_VMFault) {
	MWORD Addr = seL4_Fault_VMFault_get_Addr(Fault);
	return MmHandleThreadVmFault(Thread, Addr);
    }
    return FALSE;
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
	    /* The thread has faulted. For now we simply print a message and terminate the thread. */
	    PTHREAD Thread = GLOBAL_HANDLE_TO_OBJECT(Badge);
	    seL4_Fault_t Fault = seL4_getFault(Request);
	    BOOLEAN Handled = KiHandleThreadFault(Thread, Fault);
	    if (!Handled) {
#ifdef CONFIG_DEBUG_BUILD
		KiDumpThreadFault(Fault, Thread, DbgPrint);
#endif
		KiDumpThreadFault(Fault, Thread, HalVgaPrint);
		PsTerminateThread(Thread, STATUS_UNSUCCESSFUL);
	    } else {
		seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
	    }
	} else if (GLOBAL_HANDLE_GET_FLAG(Badge) == SERVICE_TYPE_SYSTEM_THREAD_FAULT_HANDLER) {
	    /* The thread has faulted. For now we simply print a message and terminate the thread. */
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
