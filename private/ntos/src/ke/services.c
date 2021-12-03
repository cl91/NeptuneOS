#include "ki.h"

IPC_ENDPOINT KiExecutiveServiceEndpoint;
LIST_ENTRY KiReadyThreadList;

/*
 * Create the IPC endpoint for the system services. This IPC endpoint
 * is then badged via seL4_CNode_Mint. Also initialize the ready thread list.
 */
NTSTATUS KiInitExecutiveServices()
{
    PUNTYPED Untyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_EndpointBits, &Untyped));
    assert(Untyped != NULL);
    KeInitializeIpcEndpoint(&KiExecutiveServiceEndpoint, Untyped->TreeNode.CSpace, 0, 0);
    RET_ERR_EX(MmRetypeIntoObject(Untyped, seL4_EndpointObject, seL4_EndpointBits,
				  &KiExecutiveServiceEndpoint.TreeNode),
	       MmReleaseUntyped(Untyped));
    assert(KiExecutiveServiceEndpoint.TreeNode.Cap != 0);
    InitializeListHead(&KiReadyThreadList);
    return STATUS_SUCCESS;
}

static NTSTATUS KiEnableClientServiceEndpoint(IN PTHREAD Thread,
					      IN BOOLEAN HalService)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Thread->Process->CSpace != NULL);

    MWORD ReplyCap = 0;
    extern CNODE MiNtosCNode;
    RET_ERR(MmAllocateCapRange(&MiNtosCNode, &ReplyCap, 1));
    assert(ReplyCap != 0);
    KeInitializeIpcEndpoint(&Thread->ReplyEndpoint, &MiNtosCNode, ReplyCap, 0);

    KiAllocatePoolEx(ServiceEndpoint, IPC_ENDPOINT,
		     {
			 MmDeallocateCap(&MiNtosCNode, ReplyCap);
			 Thread->ReplyEndpoint.TreeNode.Cap = 0;
		     });
    MWORD IPCBadge = OBJECT_TO_GLOBAL_HANDLE(Thread);
    if (HalService) {
	IPCBadge |= HAL_SERVICE_IPC_BADGE;
    } else {
	IPCBadge |= SYSTEM_SERVICE_IPC_BADGE;
    }
    KeInitializeIpcEndpoint(ServiceEndpoint, Thread->Process->CSpace, 0, IPCBadge);
    RET_ERR_EX(MmCapTreeDeriveBadgedNode(&ServiceEndpoint->TreeNode,
					 &KiExecutiveServiceEndpoint.TreeNode,
					 ENDPOINT_RIGHTS_WRITE_GRANTREPLY,
					 IPCBadge),
	       {
		   ExFreePool(ServiceEndpoint);
		   MmDeallocateCap(&MiNtosCNode, ReplyCap);
		   Thread->ReplyEndpoint.TreeNode.Cap = 0;
	       });
    if (HalService) {
	Thread->HalServiceEndpoint = ServiceEndpoint;
	Thread->InitInfo.HalServiceCap = ServiceEndpoint->TreeNode.Cap;
    } else {
	Thread->SystemServiceEndpoint = ServiceEndpoint;
	Thread->InitInfo.SystemServiceCap = ServiceEndpoint->TreeNode.Cap;
    }
    return STATUS_SUCCESS;
}

NTSTATUS KeEnableSystemServices(IN PTHREAD Thread)
{
    return KiEnableClientServiceEndpoint(Thread, FALSE);
}

NTSTATUS KeEnableHalServices(IN PTHREAD Thread)
{
    return KiEnableClientServiceEndpoint(Thread, TRUE);
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
    if (Arg.BufferSize <= (sizeof(HANDLE) + sizeof(ULONG))) {
	return FALSE;
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
	ObjAttr.ObjectNameBuffer = &SVC_MSGBUF_OFFSET_TO_ARG(IpcBufferAddr, MsgOffset, CHAR);
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

static inline VOID KiClearAsyncStack(IN PTHREAD Thread)
{
    memset(&Thread->AsyncStack, 0, sizeof(ASYNC_STACK));
}

/* The actual handling of system services is in the generated file below. */
#include <ntos_syssvc_gen.c>
#include <ntos_halsvc_gen.c>

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
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	/* Check if this is a service notification. The timer irq thread generates such a
	 * notification with seL4_NBWait, to inform us that the expired timer list should
	 * be checked */
	if (GLOBAL_HANDLE_GET_FLAG(Badge) != SERVICE_NOTIFICATION) {
	    /* Reject the system service call since the service message is invalid. */
	    ULONG ReplyMsgLength = 1;
	    ULONG MsgBufferEnd = 0;
	    SHORT NumApc = 0;
	    if ((NumUnwrappedCaps != 0) || (NumExtraCaps != 0)) {
		DbgTrace("Invalid system service message (%d unwrapped caps, %d extra caps)\n",
			 NumUnwrappedCaps, NumExtraCaps);
	    } else {
		/* Thread is always a valid pointer since the client cannot modify the badge */
		assert(Badge != 0);
		PTHREAD Thread = GLOBAL_HANDLE_TO_OBJECT(Badge);
		KiClearAsyncStack(Thread);
		if (GLOBAL_HANDLE_GET_FLAG(Badge) == HAL_SERVICE_IPC_BADGE) {
		    DbgTrace("Got driver call from thread %p\n", Thread);
		    Status = KiHandleHalService(SvcNum, Thread, ReqMsgLength,
						&ReplyMsgLength, &MsgBufferEnd);
		} else {
		    assert(GLOBAL_HANDLE_GET_FLAG(Badge) == SYSTEM_SERVICE_IPC_BADGE);
		    DbgTrace("Got call from thread %p\n", Thread);
		    Status = KiHandleSystemService(SvcNum, Thread, ReqMsgLength,
						   &ReplyMsgLength, &MsgBufferEnd);
		}
		/* If the service handler returned USER APC status, we should deliver APCs */
		if (Status == STATUS_USER_APC) {
		    NumApc = KiDeliverApc(Thread, MsgBufferEnd);
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
	LoopOverList(ReadyThread, &KiReadyThreadList, THREAD, ReadyListLink) {
	    ULONG ReplyMsgLength = 0;
	    ULONG MsgBufferEnd = 0;
	    SHORT NumApc = 0;
	    if (ReadyThread->HalSvc) {
		Status = KiResumeHalService(ReadyThread, &ReplyMsgLength, &MsgBufferEnd);
	    } else {
		Status = KiResumeSystemService(ReadyThread, &ReplyMsgLength, &MsgBufferEnd);
	    }
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
		/* We return the service status via the zeroth message register and
		 * the number of APCs via the label of the message */
		seL4_SetMR(0, (MWORD) Status);
		seL4_Send(ReadyThread->ReplyEndpoint.TreeNode.Cap,
			  seL4_MessageInfo_new((USHORT)NumApc, 0, 0, ReplyMsgLength));
	    }
	}
    }
}

#ifdef CONFIG_DEBUG_BUILD
PCSTR KiDbgErrorCodeToStr(IN int Error)
{
    switch (Error) {
    case seL4_InvalidArgument:
	return "Invalid argument";
    case seL4_InvalidCapability:
	return "Invalid capability";
    case seL4_IllegalOperation:
	return "Illegal operation";
    case seL4_RangeError:
	return "Range error";
    case seL4_AlignmentError:
	return "Alignment error";
    case seL4_FailedLookup:
	return "Failed lookup";
    case seL4_TruncatedMessage:
	return "Truncated Message";
    case seL4_DeleteFirst:
	return "Delete first";
    case seL4_RevokeFirst:
	return "Revoke first";
    case seL4_NotEnoughMemory:
	return "Not enough memory";
    }

    return "Unknown error";
}

VOID KiDbgDumpFailedLookupError()
{
    DbgPrint("    Lookup failed for a %s capability.\n", seL4_GetMR(0) ? "source" : "destination");
    DbgPrint("    Failure type is ");
    switch (seL4_GetMR(1)) {
    case seL4_InvalidRoot:
	DbgPrint("invalid root\n");
	break;
    case seL4_MissingCapability:
	DbgPrint("missing capability (%zd bits left)\n", seL4_GetMR(2));
	break;
    case seL4_DepthMismatch:
	DbgPrint("depth mismatch (%zd bits of CPTR remaining to be decoded,"
		 " %zd bits that the current CNode being traversed resolved)\n",
		 seL4_GetMR(2), seL4_GetMR(3));
	break;
    case seL4_GuardMismatch:
	DbgPrint("guard mismatch (%zd bits of CPTR remaining to be decoded,"
		 " CNode guard is 0x%zx, CNode guard size is %zd)\n",
		 seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4));
	break;
    }
}

VOID KeDbgDumpIPCError(IN int Error)
{
    DbgPrint("IPC Error code %d (%s):\n", Error, KiDbgErrorCodeToStr(Error));

    switch (Error) {
    case seL4_InvalidArgument:
	DbgPrint("    Invalid argument number is %zd\n", seL4_GetMR(0));
	break;
    case seL4_InvalidCapability:
	DbgPrint("    Invalid capability is 0x%zx\n", seL4_GetMR(0));
	break;
    case seL4_IllegalOperation:
	break;
    case seL4_RangeError:
	DbgPrint("    Allowed range: [0x%zx, 0x%zx]\n", seL4_GetMR(0), seL4_GetMR(1));
	break;
    case seL4_AlignmentError:
	break;
    case seL4_FailedLookup:
	KiDbgDumpFailedLookupError();
	break;
    case seL4_TruncatedMessage:
	break;
    case seL4_DeleteFirst:
	break;
    case seL4_RevokeFirst:
	break;
    case seL4_NotEnoughMemory:
	DbgPrint("    Amount of memory available: 0x%zx bytes\n", seL4_GetMR(0));
	break;
    }
}
#endif
