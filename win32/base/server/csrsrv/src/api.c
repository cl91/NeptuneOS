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

#include <wingdi.h>
#include <wincon.h>
#include <winconp.h>

/* GLOBALS ********************************************************************/

BOOLEAN (*CsrClientThreadSetup)(VOID) = NULL;
UNICODE_STRING CsrApiPortName;
volatile ULONG CsrpStaticThreadCount;
volatile ULONG CsrpDynamicThreadTotal;
extern ULONG CsrMaxApiRequestThreads;

/* FUNCTIONS ******************************************************************/

static NTSTATUS CsrpRegisterClientThread(PCLIENT_ID ClientId)
{
    NTSTATUS Status;
    PCSR_PROCESS Process;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ThreadHandle;

    /* The LPC header supplies the sender's kernel-authenticated identity.
     * Only threads of an already connected, live CSR process may join it. */
    Status = CsrLockProcessByClientId(ClientId->UniqueProcess, &Process);
    if (!NT_SUCCESS(Status))
	return STATUS_ILLEGAL_FUNCTION;

    if (!Process->ClientPort ||
	(Process->Flags & (CsrProcessTerminating | CsrProcessTerminated |
			   CsrProcessLastThreadTerminated))) {
	CsrUnlockProcess(Process);
	return STATUS_PROCESS_IS_TERMINATING;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtOpenThread(&ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, ClientId);
    if (NT_SUCCESS(Status)) {
	Status = CsrCreateThread(Process, ThreadHandle, ClientId, FALSE);
	if (NT_SUCCESS(Status)) {
	    Status = NtSetThreadHardErrorPort(ThreadHandle, CsrApiCommPort);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("CSRSRV:%s: NtSetThreadHardErrorPort failed (Status=0x%08x)\n",
			__FUNCTION__, Status);
	    }
	} else {
	    NtClose(ThreadHandle);
	}
    }

    CsrUnlockProcess(Process);
    return Status;
}

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
	(!(ServerDll = CsrLoadedServerDll[ServerId]))) {
	/* We are beyond the Maximum Server ID */
#ifdef CSR_DBG
	DPRINT1("CSRSS: %lx is invalid ServerDllIndex (%08x)\n", ServerId, ServerDll);
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	ReplyMsg->Status = STATUS_ILLEGAL_FUNCTION;
	return STATUS_ILLEGAL_FUNCTION;
    } else {
	/* Get the API ID, normalized with our Base ID */
	ApiId = CSR_API_NUMBER_TO_API_ID(ReceiveMsg->ApiNumber) - ServerDll->ApiBase;

	/* Make sure that the ID is within limits, and the entry exists */
	if ((ApiId >= ServerDll->HighestApiSupported) ||
	    ((ServerDll->ValidTable) && !(ServerDll->ValidTable[ApiId]))) {
	    /* We are beyond the Maximum API ID, or it doesn't exist */
#ifdef CSR_DBG
	    DPRINT1("API: %d\n", ApiId);
	    DPRINT1("CSRSS: %lx (%s) is invalid ApiTableIndex for %Z or is an "
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
    if (CsrDebug & 2) {
	DPRINT1("CSRSS: %s Api Request received from server process\n",
		ServerDll->NameTable[ApiId]);
    }
#endif

    /* Validation complete, start SEH */
    __try
    {
	/* Call the API, get the reply code and return the result */
	ReplyMsg->Status = ServerDll->DispatchTable[ApiId](ReceiveMsg, &ReplyCode);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
	/* If we got an exception, return access violation */
	ReplyMsg->Status = STATUS_ACCESS_VIOLATION;
    }

    /* Return success */
    return STATUS_SUCCESS;
}

/*++
 * @name CsrApiHandleConnectionRequest
 *
 * The CsrApiHandleConnectionRequest routine handles and accepts a new
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
static VOID CsrpRegisterSessionClient(IN PCLIENT_ID ClientId)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    PROCESS_SESSION_INFORMATION SessionInfo;
    KERNEL_USER_TIMES KernelTimes;
    CLIENT_ID ProcessCid;
    HANDLE hProcess = NULL, hThread = NULL;
    PCSR_PROCESS CsrProcess;
    PCSR_THREAD CsrThread;
    PCSR_SERVER_DLL ServerDll;
    PVOID ProcessData;
    NTSTATUS Status;
    ULONG i;

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    ProcessCid.UniqueProcess = ClientId->UniqueProcess;
    ProcessCid.UniqueThread = NULL;
    Status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ProcessCid);
    if (!NT_SUCCESS(Status))
	return;
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
    Status = NtSetInformationProcess(hProcess, ProcessExceptionPort, &CsrApiCommPort,
				     sizeof(CsrApiCommPort));
    if (!NT_SUCCESS(Status))
	goto Cleanup;

    CsrAcquireProcessLock();
    if (CsrLocateThreadByClientId(NULL, ClientId)) {
	CsrReleaseProcessLock();
	goto Cleanup;
    }

    CsrProcess = CsrAllocateProcess();
    if (!CsrProcess) {
	CsrReleaseProcessLock();
	goto Cleanup;
    }
    CsrThread = CsrAllocateThread(CsrProcess);
    if (!CsrThread) {
	CsrDeallocateProcess(CsrProcess);
	CsrReleaseProcessLock();
	goto Cleanup;
    }

    CsrThread->CreateTime = KernelTimes.CreateTime;
    CsrThread->ClientId = *ClientId;
    CsrThread->ThreadHandle = hThread;
    ProtectHandle(hThread);
    CsrThread->Flags = 0;
    Status = CsrInsertThread(CsrProcess, CsrThread);
    if (!NT_SUCCESS(Status)) {
	UnProtectHandle(hThread);
	CsrDeallocateProcess(CsrProcess);
	CsrDeallocateThread(CsrThread);
	CsrReleaseProcessLock();
	goto Cleanup;
    }

    CsrProcess->ClientId = *ClientId;
    CsrProcess->ProcessGroupId = HandleToUlong(ClientId->UniqueProcess);
    CsrProcess->ProcessHandle = hProcess;
    CsrSetBackgroundPriority(CsrProcess);

    ProcessData = (PVOID)((ULONG_PTR)CsrProcess + FIELD_OFFSET(CSR_PROCESS, ServerData) +
			  CSR_SERVER_DLL_MAX * sizeof(PVOID));
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++) {
	ServerDll = CsrLoadedServerDll[i];
	if (ServerDll && ServerDll->SizeOfProcessData) {
	    CsrProcess->ServerData[i] = ProcessData;
	    ProcessData = (PVOID)((ULONG_PTR)ProcessData + ServerDll->SizeOfProcessData);
	} else {
	    CsrProcess->ServerData[i] = NULL;
	}
    }

    CsrInsertProcess(NULL, CsrProcess);
    CsrReleaseProcessLock();
    return;

Cleanup:
    if (hThread)
	NtClose(hThread);
    if (hProcess)
	NtClose(hProcess);
}

NTAPI NTSTATUS CsrApiHandleConnectionRequest(IN PCSR_API_MESSAGE ApiMessage)
{
    PCSR_THREAD CsrThread = NULL;
    PCSR_PROCESS CsrProcess = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    PCSR_API_CONNECTINFO ConnectInfo = &ApiMessage->ConnectionInfo;
    BOOLEAN AllowConnection = FALSE;
    PVOID ServerViewBase = NULL, ClientViewBase = NULL;
    HANDLE ServerPort;

    /* Acquire the Process Lock */
    CsrAcquireProcessLock();

    /* Lookup the CSR Thread */
    CsrThread = CsrLocateThreadByClientId(NULL, &ApiMessage->Header.ClientId);
    if (!CsrThread) {
	CsrReleaseProcessLock();
	CsrpRegisterSessionClient(&ApiMessage->Header.ClientId);
	CsrAcquireProcessLock();
	CsrThread = CsrLocateThreadByClientId(NULL, &ApiMessage->Header.ClientId);
    }

    /* Check if we have a thread */
    if (CsrThread) {
	/* Get the Process and make sure we have it as well */
	CsrProcess = CsrThread->Process;
	if (CsrProcess) {
	    /* Reference the Process */
	    CsrLockedReferenceProcess(CsrProcess);

	    /* Attach the Shared Section */
	    Status = CsrSrvAttachSharedSection(CsrProcess, ConnectInfo);
	    if (NT_SUCCESS(Status) && !CsrProcess->ClientPort) {
		Status = CsrpMapPortView(CsrProcess, &ServerViewBase, &ClientViewBase);
		if (NT_SUCCESS(Status)) {
		    /* Allow the connection and return debugging flag */
		    ConnectInfo->DebugFlags = CsrDebug;
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
    Status = NtAlpcAcceptConnectPort(&ServerPort, CsrApiCommPort, 0, NULL, NULL,
				     AllowConnection ?
					 UlongToPtr(CsrProcess->SequenceNumber) :
					 0,
				     &ApiMessage->Header, NULL, AllowConnection);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: NtAlpcAcceptConnectPort - failed.  Status == %X\n", Status);
	if (AllowConnection) {
	    NtUnmapViewOfSection(CsrProcess->ProcessHandle, ClientViewBase);
	    NtUnmapViewOfSection(NtCurrentProcess(), ServerViewBase);
	}
    } else if (AllowConnection) {
	if (CsrDebug & 2) {
	    DPRINT1("CSRSS: ClientId: %lx.%lx has ClientView: Base=%p, Size=%lx\n",
		    ApiMessage->Header.ClientId.UniqueProcess,
		    ApiMessage->Header.ClientId.UniqueThread, ServerViewBase,
		    CSR_CSRSS_SECTION_SIZE);
	}

	/* Set some Port Data in the Process */
	CsrProcess->ClientPort = ServerPort;
	CsrProcess->ClientViewBase = (ULONG_PTR)ServerViewBase;
	CsrProcess->ClientViewBounds = (ULONG_PTR)ServerViewBase + CSR_CSRSS_SECTION_SIZE;
    } else {
	DPRINT1("CSRSS: Rejecting Connection Request from ClientId: %lx.%lx\n",
		ApiMessage->Header.ClientId.UniqueProcess,
		ApiMessage->Header.ClientId.UniqueThread);
    }

    /* Dereference the Process */
    if (CsrProcess)
	CsrLockedDereferenceProcess(CsrProcess);

    /* Release the Process Lock */
    CsrReleaseProcessLock();

    /* Return status to caller */
    return Status;
}

/*++
 * @name CsrpCheckRequestThreads
 *
 * The CsrpCheckRequestThreads routine checks if there are no more threads
 * to handle CSR API Requests, and creates a new thread if possible, to
 * avoid starvation.
 *
 * @param None.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL
 *         if a new thread couldn't be created.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrpCheckRequestThreads(VOID)
{
    HANDLE hThread;
    CLIENT_ID ClientId;
    NTSTATUS Status;

    /* Decrease the count, and see if we're out */
    if (InterlockedDecrementUL(&CsrpStaticThreadCount) == 0) {
	/* Check if we've still got space for a Dynamic Thread */
	if (CsrpDynamicThreadTotal < CsrMaxApiRequestThreads) {
	    /* Create a new dynamic thread */
	    Status = RtlCreateUserThread(NtCurrentProcess(), NULL, TRUE, 0, 0, 0,
					 (PVOID)CsrApiRequestThread, NULL, &hThread,
					 &ClientId);
	    /* Check success */
	    if (NT_SUCCESS(Status)) {
		/* Increase the thread counts */
		InterlockedIncrementUL(&CsrpStaticThreadCount);
		InterlockedIncrementUL(&CsrpDynamicThreadTotal);

		/* Add a new server thread */
		if (CsrAddStaticServerThread(hThread, &ClientId,
					     CsrThreadIsServerThread)) {
		    /* Activate it */
		    NtResumeThread(hThread, NULL);
		} else {
		    /* Failed to create a new static thread */
		    InterlockedDecrementUL(&CsrpStaticThreadCount);
		    InterlockedDecrementUL(&CsrpDynamicThreadTotal);

		    /* Terminate it */
		    DPRINT1("Failing\n");
		    NtTerminateThread(hThread, 0);
		    NtClose(hThread);

		    /* Return */
		    return STATUS_UNSUCCESSFUL;
		}
	    }
	}
    }

    /* Success */
    return STATUS_SUCCESS;
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
NTAPI NTSTATUS CsrApiRequestThread(IN PVOID Parameter)
{
    PTEB Teb = NtCurrentTeb();
    LARGE_INTEGER TimeOut;
    PCSR_THREAD CurrentThread, CsrThread;
    NTSTATUS Status;
    CSR_REPLY_CODE ReplyCode;
    PCSR_API_MESSAGE ReplyMsg;
    CSR_API_MESSAGE ReceiveMsg;
    PCSR_PROCESS CsrProcess;
    PHARDERROR_MSG HardErrorMsg;
    SIZE_T BufferLength;
    PCSR_SERVER_DLL ServerDll;
    PCLIENT_DIED_MSG ClientDiedMsg;
    PDBGKM_MSG DebugMessage;
    ULONG ServerId, ApiId, MessageType, i;
    LOCAL_HANDLE ReplyPort;

    /* Setup LPC loop port and message */
    ReplyMsg = NULL;
    ReplyPort = CsrApiCommPort;

    /* Connect to user32 */
    while (!CsrConnectToUser()) {
	/* Set up the timeout for the connect (30 seconds) */
	TimeOut.QuadPart = -30 * 1000 * 1000 * 10;

	/* Keep trying until we get a response */
	Teb->Win32.Win32ClientInfo[0] = 0;
	NtDelayExecution(FALSE, &TimeOut);
    }

    /* Get our thread */
    CurrentThread = Teb->CsrClientThread;

    /* If we got an event... */
    if (Parameter) {
	/* Set it, to let stuff waiting on us load */
	Status = NtSetEvent((HANDLE)Parameter, NULL);
	ASSERT(NT_SUCCESS(Status));

	/* Increase the Thread Counts */
	InterlockedIncrementUL(&CsrpStaticThreadCount);
	InterlockedIncrementUL(&CsrpDynamicThreadTotal);
    }

    /* Now start the loop */
    while (TRUE) {
	/* Make sure the real CID is set */
	Teb->Win32.RealClientId = Teb->NtTib.ClientId;

#ifdef CSR_DBG
	/* Debug check */
	if (Teb->CountOfOwnedCriticalSections) {
	    DPRINT1("CSRSRV: FATAL ERROR. CsrThread is Idle while holding %lu critical "
		    "sections\n",
		    Teb->CountOfOwnedCriticalSections);
	    DPRINT1("CSRSRV: Last Receive Message %lx ReplyMessage %lx\n", &ReceiveMsg,
		    ReplyMsg);
	    DbgBreakPoint();
	}
#endif

	/* Wait for a message to come through */
	BufferLength = sizeof(ReceiveMsg);
	Status = NtAlpcSendWaitReceivePort(ReplyPort,
					   ReplyMsg ? ALPC_MSGFLG_REPLY_MESSAGE : 0,
					   ReplyMsg ? &ReplyMsg->Header : NULL, NULL,
					   &ReceiveMsg.Header, &BufferLength, NULL, NULL);

	/* Check if we didn't get success */
	if (Status != STATUS_SUCCESS) {
	    /* Was it a failure or another success code? */
	    if (!NT_SUCCESS(Status)) {
#ifdef CSR_DBG
		/* Check for specific status cases */
		if ((Status != STATUS_INVALID_CID) && (Status != STATUS_UNSUCCESSFUL) &&
		    ((Status != STATUS_INVALID_HANDLE) || (ReplyPort == CsrApiPort))) {
		    /* Notify the debugger */
		    DPRINT1("CSRSS: ReceivePort failed - Status == %X\n", Status);
		    DPRINT1("CSRSS: ReplyPortHandle %lx CsrApiPort %lx\n", ReplyPort,
			    CsrApiPort);
		}
#endif

		/* We failed big time, so start out fresh */
		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
		continue;
	    } else {
		/* A strange "success" code, just try again */
		DPRINT1("NtAlpcSendWaitReceivePort returned \"success\" status 0x%x\n",
			Status);
		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
		continue;
	    }
	}

	// ASSERT(ReceiveMsg.Header.u1.s1.TotalLength >= sizeof(PORT_MESSAGE));
	// ASSERT(ReceiveMsg.Header.u1.s1.TotalLength <  sizeof(ReceiveMsg));

	/* Use whatever Client ID we got */
	Teb->Win32.RealClientId = ReceiveMsg.Header.ClientId;

	/* Get the Message Type */
	MessageType = ReceiveMsg.Header.Type &
		      ~(LPC_CONTINUATION_REQUIRED | LPC_NO_IMPERSONATE |
			LPC_KERNELMODE_MESSAGE);

	/* Handle connection requests */
	if (MessageType == LPC_CONNECTION_REQUEST) {
	    /* Handle the Connection Request */
	    CsrApiHandleConnectionRequest(&ReceiveMsg);

	    ReplyMsg = NULL;
	    ReplyPort = CsrApiCommPort;
	    continue;
	}

	/* It's some other kind of request. Get the lock for the lookup */
	CsrAcquireProcessLock();

	/* Now do the lookup to get the CSR_THREAD */
	CsrThread = CsrLocateThreadByClientId(&CsrProcess, &ReceiveMsg.Header.ClientId);

	/* NtCreateThread/RtlCreateUserThread callers do not send the Win32
	 * create notification. Capture the actual sender on its first API. */
	if (!CsrThread && MessageType == LPC_REQUEST) {
	    Status = CsrpRegisterClientThread(&ReceiveMsg.Header.ClientId);
	    if (NT_SUCCESS(Status))
		CsrThread = CsrLocateThreadByClientId(&CsrProcess,
						      &ReceiveMsg.Header.ClientId);
	}

	/* Did we find a thread? */
	if (!CsrThread) {
	    /* This wasn't a CSR Thread, release lock */
	    CsrReleaseProcessLock();

	    /* If this was an exception, handle it */
	    if (MessageType == LPC_EXCEPTION) {
		ReplyMsg = &ReceiveMsg;
		ReplyPort = CsrApiCommPort;
		ReplyMsg->Status = DBG_CONTINUE;
	    } else if (MessageType == LPC_PORT_CLOSED || MessageType == LPC_CLIENT_DIED) {
		/* The Client or Port are gone, loop again */
		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
	    } else if (MessageType == LPC_ERROR_EVENT) {
		/* If it's a hard error, handle this too */
		HardErrorMsg = (PHARDERROR_MSG)&ReceiveMsg;

		/* Default it to unhandled */
		HardErrorMsg->Response = ResponseNotHandled;

		/* Check if there are free api threads */
		CsrpCheckRequestThreads();
		if (CsrpStaticThreadCount) {
		    /* Loop every Server DLL */
		    for (i = 0; i < CSR_SERVER_DLL_MAX; i++) {
			/* Get the Server DLL */
			ServerDll = CsrLoadedServerDll[i];

			/* Check if it's valid and if it has a Hard Error Callback */
			if ((ServerDll) && (ServerDll->HardErrorCallback)) {
			    /* Call it */
			    ServerDll->HardErrorCallback(NULL /* == CsrThread */,
							 HardErrorMsg);

			    /* If it's handled, get out of here */
			    if (HardErrorMsg->Response != ResponseNotHandled)
				break;
			}
		    }
		}

		/* Increase the thread count */
		InterlockedIncrementUL(&CsrpStaticThreadCount);

		/* If the response was 0xFFFFFFFF, we'll ignore it */
		if (HardErrorMsg->Response == 0xFFFFFFFF) {
		    ReplyMsg = NULL;
		    ReplyPort = CsrApiCommPort;
		} else {
		    ReplyMsg = &ReceiveMsg;
		    ReplyPort = CsrApiCommPort;
		}
	    } else if (MessageType == LPC_REQUEST) {
		/* This is an API Message coming from a non-CSR Thread */
		ReplyMsg = &ReceiveMsg;
		ReplyPort = CsrApiCommPort;
		ReplyMsg->Status = Status;
	    } else if (MessageType == LPC_DATAGRAM) {
		/* This is an API call, get the Server ID */
		ServerId = CSR_API_NUMBER_TO_SERVER_ID(ReceiveMsg.ApiNumber);

		/* Make sure that the ID is within limits, and the Server DLL loaded */
		ServerDll = NULL;
		if ((ServerId >= CSR_SERVER_DLL_MAX) ||
		    (!(ServerDll = CsrLoadedServerDll[ServerId]))) {
		    /* We are beyond the Maximum Server ID */
#ifdef CSR_DBG
		    DPRINT1("CSRSS: %lx is invalid ServerDllIndex (%08x)\n", ServerId,
			    ServerDll);
		    if (NtCurrentPeb()->BeingDebugged)
			DbgBreakPoint();
#endif
		    ReplyMsg = NULL;
		    ReplyPort = CsrApiCommPort;
		    continue;
		}

		/* Get the API ID, normalized with our Base ID */
		ApiId = CSR_API_NUMBER_TO_API_ID(ReceiveMsg.ApiNumber) -
			ServerDll->ApiBase;

		/* Make sure that the ID is within limits, and the entry exists */
		if (ApiId >= ServerDll->HighestApiSupported) {
		    /* We are beyond the Maximum API ID, or it doesn't exist */
#ifdef CSR_DBG
		    DPRINT1("CSRSS: %lx is invalid ApiTableIndex for %Z\n",
			    CSR_API_NUMBER_TO_API_ID(ReceiveMsg.ApiNumber),
			    &ServerDll->Name);
#endif
		    ReplyPort = CsrApiCommPort;
		    ReplyMsg = NULL;
		    continue;
		}

#ifdef CSR_DBG
		if (CsrDebug & 2) {
		    DPRINT1("[%02x] CSRSS: [%02x,%02x] - %s Api called from %08x\n",
			    Teb->ClientId.UniqueThread,
			    ReceiveMsg.Header.ClientId.UniqueProcess,
			    ReceiveMsg.Header.ClientId.UniqueThread,
			    ServerDll->NameTable[ApiId], NULL);
		}
#endif

		/* Assume success */
		ReceiveMsg.Status = STATUS_SUCCESS;

		/* Validation complete, start SEH */
		__try
		{
		    /* Make sure we have enough threads */
		    CsrpCheckRequestThreads();

		    /* Call the API and get the reply code */
		    ReplyMsg = NULL;
		    ReplyPort = CsrApiCommPort;
		    ServerDll->DispatchTable[ApiId](&ReceiveMsg, &ReplyCode);

		    /* Increase the static thread count */
		    InterlockedIncrementUL(&CsrpStaticThreadCount);
		}
		__except (CsrUnhandledExceptionFilter(GetExceptionInformation()))
		{
		    ReplyMsg = NULL;
		    ReplyPort = CsrApiCommPort;
		}
	    } else {
		/* Some other ignored message type */
		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
	    }

	    /* Keep going */
	    continue;
	}

	/* We have a valid thread, was this an LPC Request? */
	if (MessageType != LPC_REQUEST) {
	    /* It's not an API, check if the client died */
	    if (MessageType == LPC_CLIENT_DIED) {
		/* Get the information and check if it matches our thread */
		ClientDiedMsg = (PCLIENT_DIED_MSG)&ReceiveMsg;
		if (ClientDiedMsg->CreateTime.QuadPart ==
		    CsrThread->CreateTime.QuadPart) {
		    /* Now we reply to the dying client */
		    ReplyPort = CsrThread->Process->ClientPort;

		    /* Reference the thread */
		    CsrLockedReferenceThread(CsrThread);

		    /* Destroy the thread in the API Message */
		    CsrDestroyThread(&ReceiveMsg.Header.ClientId);

		    /* Check if the thread was actually ourselves */
		    if (CsrProcess->ThreadCount == 1) {
			/* Kill the process manually here */
			CsrDestroyProcess(&CsrThread->ClientId, 0);
		    }

		    /* Remove our extra reference */
		    CsrLockedDereferenceThread(CsrThread);
		}

		/* Release the lock and keep looping */
		CsrReleaseProcessLock();

		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
		continue;
	    }

	    /* Reference the thread and release the lock */
	    CsrLockedReferenceThread(CsrThread);
	    CsrReleaseProcessLock();

	    /* Check if this was an exception */
	    if (MessageType == LPC_EXCEPTION) {
		NTSTATUS ExceptionStatus;

		DebugMessage = (PDBGKM_MSG)&ReceiveMsg;
		ExceptionStatus = DebugMessage->Exception.ExceptionRecord.ExceptionCode;

		/* Kill the process */
		NtTerminateProcess(CsrProcess->ProcessHandle, ExceptionStatus);

		/* Destroy it from CSR */
		CsrDestroyProcess(&ReceiveMsg.Header.ClientId, ExceptionStatus);

		/* Return a Debug Message */
		DebugMessage->ReturnedStatus = DBG_CONTINUE;
		ReplyMsg = &ReceiveMsg;
		ReplyPort = CsrApiCommPort;

		/* Remove our extra reference */
		CsrDereferenceThread(CsrThread);
	    } else if (MessageType == LPC_ERROR_EVENT) {
		/* If it's a hard error, handle this too */
		HardErrorMsg = (PHARDERROR_MSG)&ReceiveMsg;

		/* Default it to unhandled */
		HardErrorMsg->Response = ResponseNotHandled;

		/* Check if there are free api threads */
		CsrpCheckRequestThreads();
		if (CsrpStaticThreadCount) {
		    /* Loop every Server DLL */
		    for (i = 0; i < CSR_SERVER_DLL_MAX; i++) {
			/* Get the Server DLL */
			ServerDll = CsrLoadedServerDll[i];

			/* Check if it's valid and if it has a Hard Error Callback */
			if ((ServerDll) && (ServerDll->HardErrorCallback)) {
			    /* Call it */
			    ServerDll->HardErrorCallback(CsrThread, HardErrorMsg);

			    /* If it's handled, get out of here */
			    if (HardErrorMsg->Response != ResponseNotHandled)
				break;
			}
		    }
		}

		/* Increase the thread count */
		InterlockedIncrementUL(&CsrpStaticThreadCount);

		/* If the response was 0xFFFFFFFF, we'll ignore it */
		if (HardErrorMsg->Response == 0xFFFFFFFF) {
		    ReplyMsg = NULL;
		    ReplyPort = CsrApiCommPort;
		} else {
		    CsrDereferenceThread(CsrThread);
		    ReplyMsg = &ReceiveMsg;
		    ReplyPort = CsrApiCommPort;
		}
	    } else {
		/* Something else */
		CsrDereferenceThread(CsrThread);
		ReplyMsg = NULL;
	    }

	    /* Keep looping */
	    continue;
	}

	/* We got an API Request */
	CsrLockedReferenceThread(CsrThread);
	CsrReleaseProcessLock();

	/* This is an API call, get the Server ID */
	ServerId = CSR_API_NUMBER_TO_SERVER_ID(ReceiveMsg.ApiNumber);

	/* Make sure that the ID is within limits, and the Server DLL loaded */
	ServerDll = NULL;
	if ((ServerId >= CSR_SERVER_DLL_MAX) ||
	    (!(ServerDll = CsrLoadedServerDll[ServerId]))) {
	    /* We are beyond the Maximum Server ID */
#ifdef CSR_DBG
	    DPRINT1("CSRSS: %lx is invalid ServerDllIndex (%08x)\n", ServerId, ServerDll);
	    if (NtCurrentPeb()->BeingDebugged)
		DbgBreakPoint();
#endif
	    ReplyPort = CsrApiCommPort;
	    ReplyMsg = &ReceiveMsg;
	    ReplyMsg->Status = STATUS_ILLEGAL_FUNCTION;
	    CsrDereferenceThread(CsrThread);
	    continue;
	}

	/* Get the API ID, normalized with our Base ID */
	ApiId = CSR_API_NUMBER_TO_API_ID(ReceiveMsg.ApiNumber) - ServerDll->ApiBase;

	/* Make sure that the ID is within limits, and the entry exists */
	if (ApiId >= ServerDll->HighestApiSupported) {
#ifdef CSR_DBG
	    /* We are beyond the Maximum API ID, or it doesn't exist */
	    DPRINT1("CSRSS: %lx is invalid ApiTableIndex for %Z\n",
		    CSR_API_NUMBER_TO_API_ID(ReceiveMsg.ApiNumber), &ServerDll->Name);
#endif
	    ReplyPort = CsrApiCommPort;
	    ReplyMsg = &ReceiveMsg;
	    ReplyMsg->Status = STATUS_ILLEGAL_FUNCTION;
	    CsrDereferenceThread(CsrThread);
	    continue;
	}

#ifdef CSR_DBG
	if (CsrDebug & 2) {
	    DPRINT1("[%02x] CSRSS: [%02x,%02x] - %s Api called from %08x, Process %08x - "
		    "%08x\n",
		    Teb->ClientId.UniqueThread, ReceiveMsg.Header.ClientId.UniqueProcess,
		    ReceiveMsg.Header.ClientId.UniqueThread, ServerDll->NameTable[ApiId],
		    CsrThread, CsrThread->Process, CsrProcess);
	}
#endif

	/* Assume success */
	ReplyMsg = &ReceiveMsg;
	ReceiveMsg.Status = STATUS_SUCCESS;

	/* Now we reply to a particular client */
	ReplyPort = CsrThread->Process->ClientPort;

	/* Check if there's a capture buffer */
	if (ReceiveMsg.CsrCaptureData) {
	    /* Capture the arguments */
	    if (!CsrCaptureArguments(CsrThread, &ReceiveMsg)) {
		/* Ignore this message if we failed to get the arguments */
		CsrDereferenceThread(CsrThread);
		continue;
	    }
	}

	/* Validation complete, start SEH */
	__try {
	    /* Make sure we have enough threads */
	    CsrpCheckRequestThreads();

	    Teb->CsrClientThread = CsrThread;

	    /* Call the API, get the reply code and return the result */
	    ReplyCode = CsrReplyImmediately;
	    ReplyMsg->Status = ServerDll->DispatchTable[ApiId](&ReceiveMsg, &ReplyCode);

	    /* Increase the static thread count */
	    InterlockedIncrementUL(&CsrpStaticThreadCount);

	    Teb->CsrClientThread = CurrentThread;

	    if (ReplyCode == CsrReplyAlreadySent) {
		if (ReceiveMsg.CsrCaptureData) {
		    CsrReleaseCapturedArguments(&ReceiveMsg);
		}
		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
		CsrDereferenceThread(CsrThread);
	    } else if (ReplyCode == CsrReplyDeadClient) {
		/* Reply to the death message */
		NTSTATUS Status2;
		Status2 = NtAlpcSendWaitReceivePort(ReplyPort, ALPC_MSGFLG_REPLY_MESSAGE,
						    &ReplyMsg->Header, NULL, NULL, NULL,
						    NULL, NULL);
		if (!NT_SUCCESS(Status2))
		    DPRINT1("CSRSS: Error while replying to the death message, Status 0x%x\n",
			    Status2);

		/* Reply back to the API port now */
		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
		CsrDereferenceThread(CsrThread);
	    } else if (ReplyCode == CsrReplyPending) {
		ReplyMsg = NULL;
		ReplyPort = CsrApiCommPort;
	    } else {
		if (ReceiveMsg.CsrCaptureData) {
		    CsrReleaseCapturedArguments(&ReceiveMsg);
		}
		CsrDereferenceThread(CsrThread);
	    }
	} __except (CsrUnhandledExceptionFilter(GetExceptionInformation())) {
	    ReplyMsg = NULL;
	    ReplyPort = CsrApiCommPort;
	}
    }

    /* We're out of the loop for some reason, terminate! */
    NtTerminateThread(NtCurrentThread(), Status);
    return Status;
}

/*++
 * @name CsrApiPortInitialize
 *
 * The CsrApiPortInitialize routine initializes the LPC Port used for
 * communications with the Client/Server Runtime (CSR) and initializes the
 * static thread that will handle connection requests and APIs.
 *
 * @param None
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrApiPortInitialize(VOID)
{
    static SECURITY_DESCRIPTOR CsrApiPortSd;
    static PACL CsrApiPortSacl;
    ULONG Size;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ALPC_PORT_ATTRIBUTES PortAttributes;
    NTSTATUS Status;
    HANDLE hRequestEvent, hThread;
    CLIENT_ID ClientId;
    PLIST_ENTRY ListHead, NextEntry;
    PCSR_THREAD ServerThread;

    /* Calculate how much space we'll need for the Port Name */
    Size = CsrDirectoryName.Length + sizeof(CSR_PORT_NAME) + sizeof(WCHAR);

    /* Create the buffer for it */
    CsrApiPortName.Buffer = RtlAllocateHeap(CsrHeap, 0, Size);
    if (!CsrApiPortName.Buffer)
	return STATUS_NO_MEMORY;

    /* Setup the rest of the empty string */
    CsrApiPortName.Length = 0;
    CsrApiPortName.MaximumLength = (USHORT)Size;
    RtlAppendUnicodeStringToString(&CsrApiPortName, &CsrDirectoryName);
    RtlAppendUnicodeToString(&CsrApiPortName, UNICODE_PATH_SEP);
    RtlAppendUnicodeToString(&CsrApiPortName, CSR_PORT_NAME);
    if (CsrDebug & 1) {
	DPRINT1("CSRSS: Creating %wZ port and associated threads\n", &CsrApiPortName);
	DPRINT1("CSRSS: sizeof( CONNECTINFO ) == %zd  sizeof( API_MSG ) == %zd\n",
		sizeof(CSR_API_CONNECTINFO), sizeof(CSR_API_MESSAGE));
    }

    {
	SID_IDENTIFIER_AUTHORITY LabelAuthority = { SECURITY_MANDATORY_LABEL_AUTHORITY };
	PSID UntrustedSid = NULL;
	ULONG SaclSize;

	Status = RtlAllocateAndInitializeSid(&LabelAuthority, 1,
					     SECURITY_MANDATORY_UNTRUSTED_RID, 0, 0, 0, 0,
					     0, 0, 0, &UntrustedSid);
	if (!NT_SUCCESS(Status))
	    return Status;
	SaclSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) +
		   RtlLengthSid(UntrustedSid);
	CsrApiPortSacl = RtlAllocateHeap(CsrHeap, 0, SaclSize);
	if (!CsrApiPortSacl)
	    return STATUS_NO_MEMORY;
	RtlCreateAcl(CsrApiPortSacl, SaclSize, ACL_REVISION);
	RtlAddMandatoryAce(CsrApiPortSacl, ACL_REVISION, 0,
			   SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
			   SYSTEM_MANDATORY_LABEL_ACE_TYPE, UntrustedSid);
	RtlCreateSecurityDescriptor(&CsrApiPortSd, SECURITY_DESCRIPTOR_REVISION);
	RtlSetDaclSecurityDescriptor(&CsrApiPortSd, TRUE, NULL, FALSE);
	RtlSetSaclSecurityDescriptor(&CsrApiPortSd, TRUE, CsrApiPortSacl, FALSE);
    }

    /* Initialize the Attributes */
    InitializeObjectAttributes(&ObjectAttributes, &CsrApiPortName, 0, NULL,
			       &CsrApiPortSd);

    /* Create the Port Object */
    RtlZeroMemory(&PortAttributes, sizeof(PortAttributes));
    PortAttributes.Flags = ALPC_PORFLG_ALLOW_LPC_REQUESTS |
			   ALPC_PORFLG_ALLOW_IMPERSONATION;
    PortAttributes.MaxMessageLength = sizeof(CSR_API_MESSAGE);
    PortAttributes.MaxPoolUsage = 16 * PAGE_SIZE;
    PortAttributes.SecurityQos.Length = sizeof(PortAttributes.SecurityQos);
    PortAttributes.SecurityQos.ImpersonationLevel = SecurityImpersonation;
    PortAttributes.SecurityQos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    Status = NtAlpcCreatePort(&CsrApiCommPort, &ObjectAttributes, &PortAttributes);
    if (NT_SUCCESS(Status)) {
	/* Create the event the Port Thread will use */
	Status = NtCreateEvent(&hRequestEvent, EVENT_ALL_ACCESS, NULL,
			       SynchronizationEvent, FALSE);
	if (NT_SUCCESS(Status)) {
	    /* Create the Request Thread */
	    Status = RtlCreateUserThread(NtCurrentProcess(), NULL, TRUE, 0, 0, 0,
					 (PVOID)CsrApiRequestThread, (PVOID)hRequestEvent,
					 &hThread, &ClientId);
	    if (NT_SUCCESS(Status)) {
		/* Add this as a static thread to CSRSRV */
		CsrAddStaticServerThread(hThread, &ClientId, CsrThreadIsServerThread);

		/* Get the Thread List Pointers */
		ListHead = &CsrRootProcess->ThreadList;
		NextEntry = ListHead->Flink;

		/* Start looping the list */
		while (NextEntry != ListHead) {
		    /* Get the Thread */
		    ServerThread = CONTAINING_RECORD(NextEntry, CSR_THREAD, Link);

		    /* Start it up */
		    Status = NtResumeThread(ServerThread->ThreadHandle, NULL);

		    /* Is this a Server Thread? */
		    if (ServerThread->Flags & CsrThreadIsServerThread) {
			/* If so, then wait for it to initialize */
			Status = NtWaitForSingleObject(hRequestEvent, FALSE, NULL);
			ASSERT(NT_SUCCESS(Status));
		    }

		    /* Next thread */
		    NextEntry = NextEntry->Flink;
		}

		/* We don't need this anymore */
		NtClose(hRequestEvent);
	    }
	}
    }

    /* Return */
    return Status;
}

/*++
 * @name CsrConnectToUser
 * @implemented NT4
 *
 * The CsrConnectToUser connects to the User subsystem.
 *
 * @param None
 *
 * @return A pointer to the CSR Thread
 *
 * @remarks None.
 *
 *--*/
NTAPI PCSR_THREAD CsrConnectToUser(VOID)
{
    NTSTATUS Status;
    ANSI_STRING DllName;
    UNICODE_STRING TempName;
    HANDLE hUser32;
    STRING StartupName;
    PTEB Teb = NtCurrentTeb();
    PCSR_THREAD CsrThread;
    BOOLEAN Connected = FALSE;

    /* Check if we didn't already find it */
    if (!CsrClientThreadSetup) {
	/* Get the DLL Handle for user32.dll */
	RtlInitAnsiString(&DllName, "user32");
	RtlAnsiStringToUnicodeString(&TempName, &DllName, TRUE);
	Status = LdrGetDllHandle(NULL, NULL, &TempName, &hUser32);
	RtlFreeUnicodeString(&TempName);

	/* If we got the handle, get the Client Thread Startup Entrypoint */
	if (NT_SUCCESS(Status)) {
	    RtlInitAnsiString(&StartupName, "ClientThreadSetup");
	    Status = LdrGetProcedureAddress(hUser32, &StartupName, 0,
					    (PVOID)&CsrClientThreadSetup);
	}
    }

    /* Connect to user32 */
    __try {
	Connected = CsrClientThreadSetup();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
	Connected = FALSE;
    }

    if (!Connected) {
	DPRINT1("CSRSS: CsrConnectToUser failed\n");
	return NULL;
    }

    /* Save pointer to this thread in TEB */
    CsrAcquireProcessLock();
    CsrThread = CsrLocateThreadInProcess(NULL, &Teb->NtTib.ClientId);
    CsrReleaseProcessLock();
    if (CsrThread)
	Teb->CsrClientThread = CsrThread;

    /* Return it */
    return CsrThread;
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
    return CsrApiCommPort;
}

/*++
 * @name CsrCaptureArguments
 * @implemented NT5.1
 *
 * The CsrCaptureArguments routine validates a CSR Capture Buffer and
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
NTAPI BOOLEAN CsrCaptureArguments(IN PCSR_THREAD CsrThread,
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

    /* Get the buffer we got from whoever called NTDLL */
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
	DPRINT1("*** CSRSS: Took exception during capture %x\n",
		GetExceptionCode());
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	/* Return failure */
	ApiMessage->Status = STATUS_INVALID_PARAMETER;
	return FALSE;
    }

    /* We validated the client buffer, now allocate the server buffer */
    ServerCaptureBuffer = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, Length);
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
	DPRINT1("*** CSRSS: Took exception during capture %x\n",
		GetExceptionCode());
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	/* Failure, free the buffer and return */
	RtlFreeHeap(CsrHeap, 0, ServerCaptureBuffer);
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
		DPRINT1("*** CSRSS: CaptureBuffer MessagePointer outside of "
			"ClientView\n");
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
	RtlFreeHeap(CsrHeap, 0, ServerCaptureBuffer);
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
 * @name CsrReleaseCapturedArguments
 * @implemented NT5.1
 *
 * The CsrReleaseCapturedArguments routine releases a Capture Buffer
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
NTAPI VOID CsrReleaseCapturedArguments(IN PCSR_API_MESSAGE ApiMessage)
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
	DPRINT1("*** CSRSS: Took exception during release %x\n",
		GetExceptionCode());
	if (NtCurrentPeb()->BeingDebugged)
	    DbgBreakPoint();
#endif
	/* Return failure */
	ApiMessage->Status = GetExceptionCode();
    }

    /* Free our allocated buffer */
    RtlFreeHeap(CsrHeap, 0, ServerCaptureBuffer);
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
	/* In this case, succeed only if the caller is CSRSS */
	if (NtCurrentTeb()->NtTib.ClientId.UniqueProcess ==
	    ApiMessage->Header.ClientId.UniqueProcess) {
	    return TRUE;
	}
    } else {
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
