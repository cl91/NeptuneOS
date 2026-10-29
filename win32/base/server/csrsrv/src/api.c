/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/api.c
 * PURPOSE:         CSR Server DLL API LPC Implementation
 *                  "\Windows\ApiPort" port process management functions
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES *******************************************************************/

#include "srv.h"
#include <stdio.h>

/* PRIVATE FUNCTIONS ***********************************************************/

static NTSTATUS CsrpMapPortView(IN PCSR_PROCESS CsrProcess, OUT PVOID *ServerViewBase,
				OUT PVOID *ClientViewBase)
{
    NTSTATUS Status;
    HANDLE SectionHandle;
    LARGE_INTEGER SectionSize;
    SIZE_T ViewSize;
    ULONG_PTR ZeroBits = (CsrProcess->Flags & CsrProcessIsWow64) ? MAXULONG : 0;

    SectionSize.QuadPart = CSR_CSRSS_SECTION_SIZE;
    Status = NtCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, &SectionSize,
			     PAGE_READWRITE, SEC_RESERVE, NULL);
    if (!NT_SUCCESS(Status))
	return Status;

    *ServerViewBase = NULL;
    ViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle, NtCurrentProcess(), ServerViewBase,
				ZeroBits, 0, NULL, &ViewSize, ViewUnmap, 0,
				PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	*ClientViewBase = NULL;
	ViewSize = 0;
	Status = NtMapViewOfSection(SectionHandle, CsrProcess->ProcessHandle,
				    ClientViewBase, ZeroBits, 0, NULL, &ViewSize,
				    ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	    NtUnmapViewOfSection(NtCurrentProcess(), *ServerViewBase);
    }

    NtClose(SectionHandle);
    return Status;
}

static NTSTATUS CsrpRegisterSessionClient(IN PCLIENT_ID ClientId)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    PROCESS_SESSION_INFORMATION SessionInfo;
    KERNEL_USER_TIMES KernelTimes;
    CLIENT_ID ProcessCid;
    HANDLE hProcess = NULL, hThread = NULL;
    PCSR_PROCESS CsrProcess;
    PCSR_THREAD CsrThread;
    NTSTATUS Status;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ProcessCid.UniqueProcess = ClientId->UniqueProcess;
    ProcessCid.UniqueThread = NULL;
    Status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ProcessCid);
    if (!NT_SUCCESS(Status))
	return Status;
    Status = NtQueryInformationProcess(hProcess, ProcessSessionInformation, &SessionInfo,
				       sizeof(SessionInfo), NULL);
    if (!NT_SUCCESS(Status) || SessionInfo.SessionId != NtCurrentPeb()->SessionId)
	goto Cleanup;
    Status = NtOpenThread(&hThread, THREAD_ALL_ACCESS, &ObjectAttributes, ClientId);
    if (!NT_SUCCESS(Status))
	goto Cleanup;
    Status = NtQueryInformationThread(hThread, ThreadTimes, &KernelTimes,
				      sizeof(KernelTimes), NULL);
    if (!NT_SUCCESS(Status))
	goto Cleanup;
    PROCESS_EXCEPTION_PORT ExceptionPort = {
	.ExceptionPortHandle = CsrSrv->CsrApiCommPort
    };
    Status = NtSetInformationProcess(hProcess, ProcessExceptionPort, &ExceptionPort,
				     sizeof(ExceptionPort));
    if (!NT_SUCCESS(Status))
	goto Cleanup;

    CsrpAcquireProcessLock();
    if (CsrpLocateClientThreadByThreadId(NULL, ClientId)) {
	CsrpReleaseProcessLock();
	goto Cleanup;
    }

    CsrProcess = CsrpAllocateClientProcess();
    if (!CsrProcess) {
	CsrpReleaseProcessLock();
	goto Cleanup;
    }
    CsrThread = CsrpAllocateClientThread(CsrProcess);
    if (!CsrThread) {
	CsrpDeallocateClientProcess(CsrProcess);
	CsrpReleaseProcessLock();
	goto Cleanup;
    }

    CsrThread->CreateTime = KernelTimes.CreateTime;
    CsrThread->ClientId = *ClientId;
    CsrThread->ThreadHandle = hThread;
    CsrpProtectHandle(hThread);
    CsrThread->Flags = 0;
    Status = CsrpInsertClientThread(CsrProcess, CsrThread);
    if (!NT_SUCCESS(Status)) {
	CsrpUnProtectHandle(hThread);
	CsrpDeallocateClientProcess(CsrProcess);
	CsrpDeallocateClientThread(CsrThread);
	CsrpReleaseProcessLock();
	goto Cleanup;
    }

    CsrProcess->ClientId = *ClientId;
    CsrProcess->ProcessGroupId = HandleToUlong(ClientId->UniqueProcess);
    CsrProcess->ProcessHandle = hProcess;
    CsrSetBackgroundPriority(CsrProcess);

    CsrpInsertProcess(CsrProcess);
    CsrpReleaseProcessLock();
    return STATUS_SUCCESS;

Cleanup:
    if (hThread)
	NtClose(hThread);
    if (hProcess)
	NtClose(hProcess);
    return Status;
}

/*++
 * @name CsrpApiHandleConnectionRequest
 *
 * The CsrpApiHandleConnectionRequest routine handles and accepts a new
 * connection request to the CSR API LPC Port.
 *
 * @param ApiMessage
 *        Pointer to the incoming CSR API Message which contains the
 *        connection request.
 *
 * @return STATUS_SUCCESS in case of success, or status code which caused
 *         the routine to error.
 *
 * @remarks This routine is responsible for attaching the Shared Section to
 *          new clients connecting to CSR.
 *
 *--*/
static NTSTATUS CsrpApiHandleConnectionRequest(IN PCLIENT_ID ClientId,
					       IN PCSR_API_CONNECTINFO ConnectInfo)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCSR_PROCESS CsrProcess = NULL;
    BOOLEAN AllowConnection = FALSE;
    PVOID ServerViewBase = NULL, ClientViewBase = NULL;

    /* Acquire the Process Lock */
    CsrpAcquireProcessLock();

    /* Lookup the CSR Thread object. If not found, register one. */
    PCSR_THREAD CsrThread = CsrpLocateClientThreadByThreadId(NULL, ClientId);
    if (!CsrThread) {
	CsrpReleaseProcessLock();
	Status = CsrpRegisterSessionClient(ClientId);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
	CsrpAcquireProcessLock();
	CsrThread = CsrpLocateClientThreadByThreadId(NULL, ClientId);
	assert(CsrThread);
    }

    /* In the unlikely event that CsrThread is NULL (meaning we have a bug),
     * in the debug build we will assert. In the release build we will simply
     * deny the connection request. */
    if (CsrThread) {
	/* Get the CSR Process object. The process object cannot be NULL. */
	PCSR_PROCESS CsrProcess = CsrThread->Process;
	assert(CsrProcess);

	/* However if it did, we will likewise deny connection request. */
	if (CsrProcess) {
	    /* Reference the Process */
	    CsrpLockedReferenceClientProcess(CsrProcess);

	    /* Attach the Shared Section. If any of the following failed, we will
	     * deny the connection request. */
	    Status = CsrpAttachSharedSection(CsrProcess, ConnectInfo);
	    if (NT_SUCCESS(Status)) {
		Status = CsrpMapPortView(CsrProcess, &ServerViewBase, &ClientViewBase);
		if (NT_SUCCESS(Status)) {
		    /* Allow the connection and return debugging flag */
		    ConnectInfo->DebugFlags = CsrSrv->DebugFlags;
		    ConnectInfo->PortViewBase = ClientViewBase;
		    ConnectInfo->PortViewRemoteBase = ServerViewBase;
		    AllowConnection = TRUE;
		}
	    }
	}
    }

    /* Save the Process ID */
    ConnectInfo->ServerProcessId = NtCurrentTeb()->NtTib.ClientId.UniqueProcess;

    /* Accept the Connection */
    ASSERT(!AllowConnection || CsrProcess);
    Status = NtAcceptPort(NULL, CsrSrv->CsrApiPort,
			  AllowConnection ? (ULONG_PTR)ClientId->UniqueThread : 0,
			  ClientId, AllowConnection, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: NtAlpcAcceptConnectPort - failed.  Status == %X\n", Status);
	if (AllowConnection) {
	    NtUnmapViewOfSection(CsrProcess->ProcessHandle, ClientViewBase);
	    NtUnmapViewOfSection(NtCurrentProcess(), ServerViewBase);
	}
    } else if (AllowConnection) {
	if (CsrSrv->DebugFlags & 2) {
	    DPRINT1("CSRSS: ClientId: %p.%p has ClientView: Base=%p, Size=%x\n",
		    ClientId->UniqueProcess, ClientId->UniqueThread, ServerViewBase,
		    CSR_CSRSS_SECTION_SIZE);
	}

	/* Set some Port Data in the Process */
	CsrProcess->ServerViewBase = ServerViewBase;
	CsrProcess->ClientViewBase = (ULONG_PTR)ClientViewBase;
	CsrProcess->ClientViewBounds = (ULONG_PTR)ClientViewBase + CSR_CSRSS_SECTION_SIZE;
    } else {
	DPRINT1("CSRSS: Rejecting Connection Request from ClientId: %p.%p\n",
		ClientId->UniqueProcess, ClientId->UniqueThread);
    }

    /* Dereference the Process */
    if (CsrProcess)
	CsrpLockedDereferenceClientProcess(CsrProcess);

    /* Release the Process Lock */
    CsrpReleaseProcessLock();

    /* Return status to caller */
    return Status;
}

/*++
 * @name CsrpCaptureArguments
 * @implemented NT5.1
 *
 * The CsrpCaptureArguments routine validates a CSR Capture Buffer and
 * re-captures it into a server CSR Capture Buffer.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread performing the validation.
 *
 * @param ApiMessage
 *        Pointer to the CSR API Message containing the Capture Buffer
 *        that needs to be validated.
 *
 * @return TRUE if validation succeeded, FALSE otherwise.
 *
 * @remarks None.
 *
 *--*/
static BOOLEAN CsrpCaptureArguments(IN PCSR_THREAD CsrThread,
				    IN PCSR_API_MESSAGE ApiMessage)
{
    PCSR_PROCESS CsrProcess = CsrThread->Process;
    PCSR_CAPTURE_BUFFER ClientCaptureBuffer, ServerCaptureBuffer = NULL;
    ULONG_PTR EndOfClientBuffer = 0;
    SIZE_T SizeOfBufferThroughOffsetsArray = 0;
    SIZE_T BufferDistance;
    ULONG Length = 0;
    ULONG PointerCount = 0;
    PULONG_PTR OffsetPointer;
    ULONG_PTR CurrentOffset;

    /* Get the buffer we got from whoever called csrdll */
    ClientCaptureBuffer = ApiMessage->CsrCaptureData;

    /* Use SEH to validate and capture the client buffer */
    __try {
	/* Check whether at least the buffer's header is inside our mapped section */
	if (((ULONG_PTR)ClientCaptureBuffer < CsrProcess->ClientViewBase) ||
	    (((ULONG_PTR)ClientCaptureBuffer +
	      FIELD_OFFSET(CSR_CAPTURE_BUFFER, PointerOffsetsArray)) >=
	     CsrProcess->ClientViewBounds)) {
#ifdef CSR_DBG
	    DPRINT1("*** CSRSS: CaptureBuffer outside of ClientView 1\n");
	    if (NtCurrentPeb()->BeingDebugged)
		DbgBreakPoint();
#endif
	    /* Return failure */
	    ApiMessage->Status = STATUS_INVALID_PARAMETER;
	    return FALSE;
	}

	/* Capture the buffer length */
	Length = ((volatile CSR_CAPTURE_BUFFER *)ClientCaptureBuffer)->Size;

	/*
	 * Now check if the remaining of the buffer is inside our mapped section.
	 * Take also care for any possible wrap-around of the buffer end-address.
	 */
	EndOfClientBuffer = (ULONG_PTR)ClientCaptureBuffer + Length;
	if ((EndOfClientBuffer < (ULONG_PTR)ClientCaptureBuffer) ||
	    (EndOfClientBuffer >= CsrProcess->ClientViewBounds)) {
#ifdef CSR_DBG
	    DPRINT1("*** CSRSS: CaptureBuffer outside of ClientView 2\n");
	    if (NtCurrentPeb()->BeingDebugged)
		DbgBreakPoint();
#endif
	    /* Return failure */
	    ApiMessage->Status = STATUS_INVALID_PARAMETER;
	    return FALSE;
	}

	/* Capture the pointer count */
	PointerCount = ((volatile CSR_CAPTURE_BUFFER *)ClientCaptureBuffer)->PointerCount;

	/*
	 * Check whether the total buffer size and the pointer count are consistent
	 * -- the array of offsets must be contained inside the buffer.
	 */
	SizeOfBufferThroughOffsetsArray = FIELD_OFFSET(CSR_CAPTURE_BUFFER,
						       PointerOffsetsArray) +
					  (PointerCount * sizeof(PVOID));
	if ((PointerCount > MAXUSHORT) || (SizeOfBufferThroughOffsetsArray > Length)) {
#ifdef CSR_DBG
	    DPRINT1("*** CSRSS: CaptureBuffer %p has bad length\n", ClientCaptureBuffer);
	    if (NtCurrentPeb()->BeingDebugged)
		DbgBreakPoint();
#endif
	    /* Return failure */
	    ApiMessage->Status = STATUS_INVALID_PARAMETER;
	    return FALSE;
	}
    } __except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef CSR_DBG
	DPRINT1("*** CSRSS: Took exception during capture %lx\n",
		GetExceptionCode());
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	/* Return failure */
	ApiMessage->Status = STATUS_INVALID_PARAMETER;
	return FALSE;
    }

    /* We validated the client buffer, now allocate the server buffer */
    ServerCaptureBuffer = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    if (!ServerCaptureBuffer) {
	/* We're out of memory */
	ApiMessage->Status = STATUS_NO_MEMORY;
	return FALSE;
    }

    /*
     * Copy the client's buffer and ensure we use the correct buffer length
     * and pointer count we captured and used for validation earlier on.
     */
    __try {
	RtlMoveMemory(ServerCaptureBuffer, ClientCaptureBuffer, Length);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef CSR_DBG
	DPRINT1("*** CSRSS: Took exception during capture %lx\n",
		GetExceptionCode());
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	/* Failure, free the buffer and return */
	RtlFreeHeap(RtlGetProcessHeap(), 0, ServerCaptureBuffer);
	ApiMessage->Status = STATUS_INVALID_PARAMETER;
	return FALSE;
    }

    ServerCaptureBuffer->Size = Length;
    ServerCaptureBuffer->PointerCount = PointerCount;

    /* Calculate the difference between our buffer and the client's */
    BufferDistance = (ULONG_PTR)ServerCaptureBuffer - (ULONG_PTR)ClientCaptureBuffer;

    /*
     * All the pointer offsets correspond to pointers that point
     * to the server data buffer instead of the client one.
     */
    // PointerCount  = ServerCaptureBuffer->PointerCount;
    OffsetPointer = ServerCaptureBuffer->PointerOffsetsArray;
    while (PointerCount--) {
	CurrentOffset = *OffsetPointer;

	if (CurrentOffset != 0) {
	    /*
	     * Check whether the offset is pointer-aligned and whether
	     * it points inside CSR_API_MESSAGE::Data.ApiMessageData.
	     */
	    if (((CurrentOffset & (sizeof(PVOID) - 1)) != 0) ||
		(CurrentOffset < FIELD_OFFSET(CSR_API_MESSAGE, Data.ApiMessageData)) ||
		(CurrentOffset >= sizeof(CSR_API_MESSAGE))) {
#ifdef CSR_DBG
		DPRINT1("*** CSRSS: CaptureBuffer MessagePointer outside of message\n");
		if (NtCurrentPeb()->BeingDebugged)
		    DbgBreakPoint();
#endif
		/* Invalid pointer, fail */
		ApiMessage->Status = STATUS_INVALID_PARAMETER;
		break;
	    }

	    /* Get the pointer corresponding to the offset */
	    CurrentOffset += (ULONG_PTR)ApiMessage;

	    /* Validate the bounds of the current pointed pointer */
	    if ((*(PULONG_PTR)CurrentOffset >=
		 ((ULONG_PTR)ClientCaptureBuffer + SizeOfBufferThroughOffsetsArray)) &&
		(*(PULONG_PTR)CurrentOffset <= (EndOfClientBuffer - sizeof(PVOID)))) {
		/* Modify the pointed pointer to take into account its new position */
		*(PULONG_PTR)CurrentOffset += BufferDistance;
	    } else {
#ifdef CSR_DBG
		DPRINT1("*** CSRSS: CaptureBuffer MessagePointer outside of ClientView\n");
		if (NtCurrentPeb()->BeingDebugged)
		    DbgBreakPoint();
#endif
		/* Invalid pointer, fail */
		ApiMessage->Status = STATUS_INVALID_PARAMETER;
		break;
	    }
	}

	++OffsetPointer;
    }

    /* Check if we got success */
    if (ApiMessage->Status != STATUS_SUCCESS) {
	/* Failure, free the buffer and return */
	if (ServerCaptureBuffer) {
	    RtlFreeHeap(RtlGetProcessHeap(), 0, ServerCaptureBuffer);
	}
	return FALSE;
    } else {
	/* Success, save the previous buffer and use the server capture buffer */
	ServerCaptureBuffer->PreviousCaptureBuffer = ClientCaptureBuffer;
	ApiMessage->CsrCaptureData = ServerCaptureBuffer;
    }

    /* Success */
    return TRUE;
}

/*++
 * @name CsrpReleaseCapturedArguments
 * @implemented NT5.1
 *
 * The CsrpReleaseCapturedArguments routine releases a Capture Buffer
 * that was previously captured with CsrCaptureArguments.
 *
 * @param ApiMessage
 *        Pointer to the CSR API Message containing the Capture Buffer
 *        that needs to be released.
 *
 * @return None.
 *
 * @remarks None.
 *
 *--*/
VOID CsrpReleaseCapturedArguments(IN PCSR_API_MESSAGE ApiMessage)
{
    PCSR_CAPTURE_BUFFER ServerCaptureBuffer, ClientCaptureBuffer;
    SIZE_T BufferDistance;
    ULONG PointerCount;
    PULONG_PTR OffsetPointer;
    ULONG_PTR CurrentOffset;

    /* Get the server capture buffer */
    ServerCaptureBuffer = ApiMessage->CsrCaptureData;

    /* Do not continue if there is no captured buffer */
    if (!ServerCaptureBuffer)
	return;

    /* If there is one, get the corresponding client capture buffer */
    ClientCaptureBuffer = ServerCaptureBuffer->PreviousCaptureBuffer;

    /* Free the previous one and use again the client capture buffer */
    ServerCaptureBuffer->PreviousCaptureBuffer = NULL;
    ApiMessage->CsrCaptureData = ClientCaptureBuffer;

    /* Calculate the difference between our buffer and the client's */
    BufferDistance = (ULONG_PTR)ServerCaptureBuffer - (ULONG_PTR)ClientCaptureBuffer;

    /*
     * All the pointer offsets correspond to pointers that point
     * to the client data buffer instead of the server one (reverse
     * the logic of CsrCaptureArguments()).
     */
    PointerCount = ServerCaptureBuffer->PointerCount;
    OffsetPointer = ServerCaptureBuffer->PointerOffsetsArray;
    while (PointerCount--) {
	CurrentOffset = *OffsetPointer;

	if (CurrentOffset != 0) {
	    /* Get the pointer corresponding to the offset */
	    CurrentOffset += (ULONG_PTR)ApiMessage;

	    /* Modify the pointed pointer to take into account its new position */
	    *(PULONG_PTR)CurrentOffset -= BufferDistance;
	}

	++OffsetPointer;
    }

    /* Copy the data back into the client buffer */
    __try {
	RtlMoveMemory(ClientCaptureBuffer, ServerCaptureBuffer,
		      ServerCaptureBuffer->Size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
#ifdef CSR_DBG
	DPRINT1("*** CSRSS: Took exception during release %lx\n",
		GetExceptionCode());
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	/* Return failure */
	ApiMessage->Status = GetExceptionCode();
    }

    /* Free our allocated buffer */
    RtlFreeHeap(RtlGetProcessHeap(), 0, ServerCaptureBuffer);
}

/*++
 * @name CsrApiRequestThread
 *
 * The CsrApiRequestThread routine handles incoming messages or connection
 * requests on the CSR API LPC Port.
 *
 * @param Parameter
 *        System-default user-defined parameter. Unused.
 *
 * @return The thread exit code, if the thread is terminated.
 *
 * @remarks Before listening on the port, the routine will first attempt
 *          to connect to the user subsystem.
 *
 *--*/
static NTAPI ULONG CsrpApiRequestThread(IN PVOID Parameter)
{
    ULONG_PTR PortContext = 0;
    union {
	PORT_MESSAGE Header;
	CSR_API_MESSAGE Csr;
	HARDERROR_MSG Error;
	DBGKM_MSG Dbg;
    } Msg = {};
    NTSTATUS Status = NtReceivePort(CsrSrv->CsrApiCommPort, &PortContext,
				    &Msg.Header, sizeof(Msg), NULL);
    while (TRUE) {
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}

	BOOLEAN Reply = TRUE;

	/* Get the Message Type */
	ULONG MessageType = Msg.Header.Type &
	    ~(LPC_CONTINUATION_REQUIRED | LPC_NO_IMPERSONATE | LPC_LONG_MESSAGE);

	/* Get the lock for the lookup */
	CsrpAcquireProcessLock();

	/* Now do the lookup to get the CSR_THREAD */
	PCSR_PROCESS CsrProcess = NULL;
	PCSR_THREAD CsrThread = CsrpLocateClientThreadByThreadId(&CsrProcess,
								 (HANDLE)PortContext);

	/* We should always find the CSR thread object. */
	assert(CsrThread);
	if (!CsrThread) {
	    Reply = FALSE;
	    goto Reply;
	}

	/* Reference the thread and release the lock */
	CsrpLockedReferenceClientThread(CsrThread);
	CsrpReleaseProcessLock();

	if (MessageType == LPC_REQUEST) {
	    /* This is an API call, get the Server ID */
	    ULONG ServerId = CSR_API_NUMBER_TO_SERVER_ID(Msg.Csr.ApiNumber);

	    /* Make sure that the ID is within limits, and the Server DLL loaded */
	    PCSR_SERVER_DLL ServerDll = NULL;
	    if ((ServerId >= CSR_SERVER_DLL_MAX) ||
		(!(ServerDll = CsrSrv->LoadedServerDll[ServerId]))) {
		/* We are beyond the Maximum Server ID */
#ifdef CSR_DBG
		DPRINT1("CSRSS: %x is invalid ServerDllIndex (%p)\n", ServerId, ServerDll);
		if (NtCurrentPeb()->BeingDebugged)
		    DbgBreakPoint();
#endif
		RtlZeroMemory(&Msg, sizeof(Msg));
		Msg.Header.Type = LPC_REPLY;
		Msg.Header.TotalLength = sizeof(CSR_API_MESSAGE);
		Msg.Csr.Status = STATUS_ILLEGAL_FUNCTION;
		goto Done;
	    }

	    /* Get the API ID, normalized with our Base ID */
	    ULONG ApiId = CSR_API_NUMBER_TO_API_ID(Msg.Csr.ApiNumber) - ServerDll->ApiBase;

	    /* Make sure that the ID is within limits, and the entry exists */
	    if (ApiId >= ServerDll->HighestApiSupported) {
#ifdef CSR_DBG
		/* We are beyond the Maximum API ID, or it doesn't exist */
		DPRINT1("CSRSS: %x is invalid ApiTableIndex for %Z\n",
			CSR_API_NUMBER_TO_API_ID(Msg.Csr.ApiNumber),
			&ServerDll->Name);
#endif
		RtlZeroMemory(&Msg, sizeof(Msg));
		Msg.Header.Type = LPC_REPLY;
		Msg.Header.TotalLength = sizeof(CSR_API_MESSAGE);
		Msg.Csr.Status = STATUS_ILLEGAL_FUNCTION;
		goto Done;
	    }

#ifdef CSR_DBG
	    if (CsrSrv->DebugFlags & 2) {
		DPRINT1("CSRSS: %s Api called from thread id %p, process id %p\n",
			ServerDll->NameTable[ApiId], CsrThread->ClientId.UniqueThread,
			CsrThread->ClientId.UniqueProcess);
	    }
#endif

	    /* Check if there's a capture buffer */
	    if (Msg.Csr.CsrCaptureData) {
		/* Capture the arguments */
		if (!CsrpCaptureArguments(CsrThread, &Msg.Csr)) {
		    /* CsrpCaptureArguments sets the return status in the message */
		    Msg.Header.Type = LPC_REPLY;
		    Msg.Header.TotalLength = sizeof(CSR_API_MESSAGE);
		    Msg.Csr.CsrCaptureData = NULL;
		    goto Done;
		}
	    }

	    /* Validation complete, start SEH */
	    __try {
		/* Call the API, get the reply code and return the result */
		CSR_REPLY_CODE ReplyCode = CsrReplyImmediately;
		Msg.Csr.Status = ServerDll->DispatchTable[ApiId](CsrThread, &Msg.Csr,
								 &ReplyCode);

		if (ReplyCode == CsrReplyAlreadySent || ReplyCode == CsrReplyDeadClient ||
		    ReplyCode == CsrReplyPending) {
		    Reply = FALSE;
		}
	    } __except (CsrUnhandledExceptionFilter(GetExceptionInformation())) {
		Reply = FALSE;
	    }
	    if (Msg.Csr.CsrCaptureData) {
		CsrpReleaseCapturedArguments(&Msg.Csr);
	    }
	    Msg.Csr.CsrCaptureData = NULL;
	    if (Reply) {
		Msg.Header.Type = LPC_REPLY;
		Msg.Header.TotalLength = sizeof(CSR_API_MESSAGE);
	    }
	} else if (MessageType == LPC_EXCEPTION) {
	    PDBGKM_MSG DebugMessage = (PDBGKM_MSG)&Msg;
	    NTSTATUS ExceptionStatus = DebugMessage->Exception.ExceptionRecord.ExceptionCode;

	    /* Kill the process */
	    NtTerminateProcess(CsrProcess->ProcessHandle, ExceptionStatus);

	    /* Destroy it from CSR */
	    CsrpDestroyProcess(CsrThread, ExceptionStatus);

	    /* Return a Debug Message */
	    Msg.Header.Type = LPC_REPLY;
	    Msg.Header.TotalLength = sizeof(DBGKM_MSG);
	    DebugMessage->ReturnedStatus = DBG_CONTINUE;
	} else if (MessageType == LPC_ERROR_EVENT) {
	    /* If it's a hard error message, handle it by calling the server dlls. */
	    Msg.Error.Response = ResponseNotHandled;

	    /* Loop every Server DLL */
	    for (ULONG i = 0; i < CSR_SERVER_DLL_MAX; i++) {
		/* Get the Server DLL */
		PCSR_SERVER_DLL ServerDll = CsrSrv->LoadedServerDll[i];

		/* Check if it's valid and if it has a Hard Error Callback */
		if ((ServerDll) && (ServerDll->HardErrorCallback)) {
		    /* Call it */
		    ServerDll->HardErrorCallback(CsrThread, &Msg.Error);

		    /* If it's handled, get out of here */
		    if (Msg.Error.Response != ResponseNotHandled)
			break;
		}
	    }

	    /* If the response was 0xFFFFFFFF, we'll ignore it */
	    if (Msg.Error.Response == 0xFFFFFFFF) {
		Reply = FALSE;
	    }
	} else {
	    /* Ignore unknown message types */
	    Reply = FALSE;
	}

    Done:
	/* Remove our extra reference */
	CsrDereferenceThread(CsrThread);

    Reply:
	if (Reply) {
	    Status = NtReplyWaitReceivePort(CsrSrv->CsrApiCommPort, &Msg.Header,
					    &PortContext, &Msg.Header, sizeof(Msg), NULL);
	} else {
	    Status = NtReceivePort(CsrSrv->CsrApiCommPort, &PortContext, &Msg.Header,
				   sizeof(Msg), NULL);
	}
    }

    /* We're out of the loop for some reason, terminate! */
    NtTerminateThread(NtCurrentThread(), Status);
    return Status;
}

/*++
 * @name CsrpApiPortInitialize
 *
 * The CsrpApiPortInitialize routine initializes the LPC Port used for
 * communications with the Client/Server Runtime (CSR) and initializes the
 * static thread that will handle API requests.
 *
 * @param None
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS CsrpApiPortInitialize(VOID)
{
    SECURITY_DESCRIPTOR CsrApiPortSd = {};
    PACL CsrApiPortSacl = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE hThread;
    CLIENT_ID ClientId;

    /* Calculate how much space we'll need for the Port Name */
    ULONG Size = wcslen(CsrSrv->ObjectDirectoryName) * sizeof(WCHAR) +
	sizeof(CSR_PORT_NAME) + sizeof(WCHAR);

    /* Create the buffer for it */
    UNICODE_STRING CsrApiPortName;
    CsrApiPortName.Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
    if (!CsrApiPortName.Buffer)
	return STATUS_NO_MEMORY;

    /* Setup the rest of the empty string */
    CsrApiPortName.Length = Size - sizeof(WCHAR);
    CsrApiPortName.MaximumLength = (USHORT)Size;
    _snwprintf(CsrApiPortName.Buffer,
	       CsrApiPortName.MaximumLength / sizeof(WCHAR), L"%ws\\%ws",
	       CsrSrv->ObjectDirectoryName, CSR_PORT_NAME);
    if (CsrSrv->DebugFlags & 1) {
	DPRINT1("CSRSS: Creating %wZ port and associated threads\n", &CsrApiPortName);
	DPRINT1("CSRSS: sizeof( CONNECTINFO ) == %zd  sizeof( API_MSG ) == %zd\n",
		sizeof(CSR_API_CONNECTINFO), sizeof(CSR_API_MESSAGE));
    }

    SID_IDENTIFIER_AUTHORITY LabelAuthority = { SECURITY_MANDATORY_LABEL_AUTHORITY };
    PSID UntrustedSid = NULL;
    Status = RtlAllocateAndInitializeSid(&LabelAuthority, 1,
					 SECURITY_MANDATORY_UNTRUSTED_RID, 0, 0, 0, 0, 0,
					 0, 0, &UntrustedSid);
    if (!NT_SUCCESS(Status)) {
	goto Out;
    }
    ULONG SaclSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) +
	RtlLengthSid(UntrustedSid);
    CsrApiPortSacl = RtlAllocateHeap(RtlGetProcessHeap(), 0, SaclSize);
    if (!CsrApiPortSacl) {
	Status = STATUS_NO_MEMORY;
	goto Out;
    }
    RtlCreateAcl(CsrApiPortSacl, SaclSize, ACL_REVISION);
    RtlAddMandatoryAce(CsrApiPortSacl, ACL_REVISION, 0,
		       SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
		       SYSTEM_MANDATORY_LABEL_ACE_TYPE, UntrustedSid);
    RtlCreateSecurityDescriptor(&CsrApiPortSd, SECURITY_DESCRIPTOR_REVISION);
    RtlSetDaclSecurityDescriptor(&CsrApiPortSd, TRUE, NULL, FALSE);
    RtlSetSaclSecurityDescriptor(&CsrApiPortSd, TRUE, CsrApiPortSacl, FALSE);

    /* Initialize the Attributes */
    InitializeObjectAttributes(&ObjectAttributes, &CsrApiPortName, 0, NULL,
			       &CsrApiPortSd);

    /* Create the Port Object */
    SECURITY_QUALITY_OF_SERVICE SecurityQos = {
	.Length = sizeof(SecurityQos),
	.ImpersonationLevel = SecurityImpersonation,
	.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING
    };
    Status = NtCreatePort(&CsrSrv->CsrApiPort, &CsrSrv->CsrApiCommPort,
			  &ObjectAttributes, sizeof(CSR_API_MESSAGE), &SecurityQos);
    if (!NT_SUCCESS(Status)) {
	goto Out;
    }

    /* Create the Request Thread */
    Status = RtlCreateUserThread(NtCurrentProcess(), NULL, TRUE, 0, 0, 0,
				 CsrpApiRequestThread, NULL,
				 &hThread, &ClientId);
    if (!NT_SUCCESS(Status)) {
	goto Out;
    }

    /* Return */
Out:
    if (CsrApiPortName.Buffer) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, CsrApiPortName.Buffer);
    }
    if (CsrApiPortSacl) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, CsrApiPortSacl);
    }
    if (UntrustedSid) {
	RtlFreeSid(UntrustedSid);
    }
    return Status;
}

/* PUBLIC FUNCTIONS ************************************************************/

/*++
 * @name CsrStartServer
 * @implemented NT4
 *
 * The CsrStartServer routine starts the event loop to listen for incoming
 * client connection requests. It does not return unless a fatal error has
 * occured.
 *
 * @return Error status in case of fatal errors.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrStartServer()
{
    NTSTATUS Status;
    while (TRUE) {
	CLIENT_ID ClientId = {};
	CSR_API_CONNECTINFO ConnectionInfo = {};
	ULONG InfoLength = 0;
	Status = NtListenPort(CsrSrv->CsrApiPort, &ClientId, &ConnectionInfo,
			      sizeof(ConnectionInfo), &InfoLength);
	if (NT_SUCCESS(Status)) {
	    if (InfoLength == sizeof(ConnectionInfo)) {
		Status = CsrpApiHandleConnectionRequest(&ClientId, &ConnectionInfo);
	    } else {
		Status = NtAcceptPort(NULL, CsrSrv->CsrApiPort, 0, &ClientId, FALSE,
				      NULL, NULL);
	    }
	    /* The calls above should always return sucess unless in a fatal error. */
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	} else if (Status == STATUS_PORT_CLOSED) {
	    /* TODO: Handle client death */
	} else {
	    /* This is a fatal error. */
	    return Status;
	}
    }
}

/*++
 * @name CsrCallServerFromServer
 * @implemented NT4
 *
 * The CsrCallServerFromServer routine calls a CSR API from within a server.
 * It avoids using LPC messages since the request isn't coming from a client.
 *
 * @param ReceiveMsg
 *        Pointer to the CSR API Message to send to the server.
 *
 * @param ReplyMsg
 *        Pointer to the CSR API Message to receive from the server.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_ILLEGAL_FUNCTION
 *         if the ApiNumber is invalid, or STATUS_ACCESS_VIOLATION if there
 *         was a problem executing the API.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrCallServerFromServer(IN PCSR_API_MESSAGE ReceiveMsg,
				       IN OUT PCSR_API_MESSAGE ReplyMsg)
{
    ULONG ServerId;
    PCSR_SERVER_DLL ServerDll = NULL;
    ULONG ApiId;
    CSR_REPLY_CODE ReplyCode = CsrReplyImmediately;

    /* Get the Server ID */
    ServerId = CSR_API_NUMBER_TO_SERVER_ID(ReceiveMsg->ApiNumber);

    /* Make sure that the ID is within limits, and the Server DLL loaded */
    if ((ServerId >= CSR_SERVER_DLL_MAX) ||
	(!(ServerDll = CsrSrv->LoadedServerDll[ServerId]))) {
	/* We are beyond the Maximum Server ID */
#ifdef CSR_DBG
	DPRINT1("CSRSS: %x is invalid ServerDllIndex\n", ServerId);
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	ReplyMsg->Status = STATUS_ILLEGAL_FUNCTION;
	return STATUS_ILLEGAL_FUNCTION;
    } else {
	/* Get the API ID, normalized with our Base ID */
	ApiId = CSR_API_NUMBER_TO_API_ID(ReceiveMsg->ApiNumber) - ServerDll->ApiBase;

	/* Make sure that the ID is within limits */
	if (ApiId >= ServerDll->HighestApiSupported) {
	    /* We are beyond the Maximum API ID */
#ifdef CSR_DBG
	    DPRINT1("API: %d\n", ApiId);
	    DPRINT1("CSRSS: %x (%s) is invalid ApiTableIndex for %Z or is an "
		    "invalid API to call from the server.\n",
		    ApiId,
		    ((ServerDll->NameTable) && (ServerDll->NameTable[ApiId])) ?
			ServerDll->NameTable[ApiId] :
			"*** UNKNOWN ***",
		    &ServerDll->Name);
	    if (NtCurrentPeb()->BeingDebugged)
		DbgBreakPoint();
#endif
	    ReplyMsg->Status = STATUS_ILLEGAL_FUNCTION;
	    return STATUS_ILLEGAL_FUNCTION;
	}
    }

#ifdef CSR_DBG
    if (CsrSrv->DebugFlags & 2) {
	DPRINT1("CSRSS: %s Api Request received from server process\n",
		ServerDll->NameTable[ApiId]);
    }
#endif

    /* Validation complete, start SEH */
    __try {
	/* Call the API, get the reply code and return the result */
	ReplyMsg->Status = ServerDll->DispatchTable[ApiId](NULL, ReceiveMsg, &ReplyCode);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	/* If we got an exception, return access violation */
	ReplyMsg->Status = STATUS_ACCESS_VIOLATION;
    }

    /* Return success */
    return STATUS_SUCCESS;
}

/*++
 * @name CsrQueryApiPort
 * @implemented NT4
 *
 * The CsrQueryApiPort routine returns a handle to the CSR API LPC port.
 *
 * @param None.
 *
 * @return A handle to the port.
 *
 * @remarks None.
 *
 *--*/
NTAPI LOCAL_HANDLE CsrQueryApiPort(VOID)
{
    return CsrSrv->CsrApiCommPort;
}

/*++
 * @name CsrValidateMessageBuffer
 * @implemented NT5.1
 *
 * The CsrValidateMessageBuffer routine validates a captured message buffer
 * present in the CSR Api Message
 *
 * @param ApiMessage
 *        Pointer to the CSR API Message containing the CSR Capture Buffer.
 *
 * @param Buffer
 *        Pointer to the message buffer to validate.
 *
 * @param ElementCount
 *        Number of elements contained in the message buffer.
 *
 * @param ElementSize
 *        Size of each element.
 *
 * @return TRUE if validation succeeded, FALSE otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI BOOLEAN CsrValidateMessageBuffer(IN PCSR_API_MESSAGE ApiMessage, IN PVOID *Buffer,
				       IN ULONG ElementCount, IN ULONG ElementSize)
{
    PCSR_CAPTURE_BUFFER CaptureBuffer = ApiMessage->CsrCaptureData;
    SIZE_T BufferDistance = (ULONG_PTR)Buffer - (ULONG_PTR)ApiMessage;
    ULONG PointerCount;
    PULONG_PTR OffsetPointer;

    /*
     * Check whether we have a valid buffer pointer, elements
     * of non-trivial size and that we don't overflow.
     */
    if (!Buffer || ElementSize == 0 ||
	(ULONGLONG)ElementCount * ElementSize > (ULONGLONG)MAXULONG) {
	return FALSE;
    }

    /* Check if didn't get a buffer and there aren't any arguments to check */
    // if (!*Buffer && (ElementCount * ElementSize == 0))
    if (!*Buffer && ElementCount == 0) // Here ElementSize != 0 therefore only
				       // ElementCount can be == 0
	return TRUE;

    /* Check if we have no capture buffer */
    if (!CaptureBuffer) {
	return FALSE;
    }

    /* Make sure that there is still space left in the capture buffer */
    if ((CaptureBuffer->Size - (ULONG_PTR)*Buffer + (ULONG_PTR)CaptureBuffer) >=
	(ElementCount * ElementSize)) {
	/* Perform the validation test */
	PointerCount = CaptureBuffer->PointerCount;
	OffsetPointer = CaptureBuffer->PointerOffsetsArray;
	while (PointerCount--) {
	    /*
	     * Find in the array, the pointer offset (from the
	     * API message) that corresponds to the buffer.
	     */
	    if (*OffsetPointer == BufferDistance) {
		return TRUE;
	    }
	    ++OffsetPointer;
	}
    }

    /* Failure */
#ifdef CSR_DBG
    DPRINT1("CSRSRV: Bad message buffer %p\n", ApiMessage);
    if (NtCurrentPeb()->BeingDebugged)
	DbgBreakPoint();
#endif
    return FALSE;
}

/*++
 * @name CsrValidateMessageString
 * @implemented NT5.1
 *
 * The CsrValidateMessageString validates a captured Wide-Character String
 * present in a CSR API Message.
 *
 * @param ApiMessage
 *        Pointer to the CSR API Message containing the CSR Capture Buffer.
 *
 * @param MessageString
 *        Pointer to the buffer containing the string to validate.
 *
 * @return TRUE if validation succeeded, FALSE otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI BOOLEAN CsrValidateMessageString(IN PCSR_API_MESSAGE ApiMessage,
				       IN PWSTR *MessageString)
{
    if (MessageString) {
	return CsrValidateMessageBuffer(ApiMessage, (PVOID *)MessageString,
					wcslen(*MessageString) + 1, sizeof(WCHAR));
    } else {
	return FALSE;
    }
}

/* EOF */
