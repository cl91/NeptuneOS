/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/server.c
 * PURPOSE:         CSR Server DLL Server Functions
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES *******************************************************************/

#include "srv.h"

/* DATA ***********************************************************************/

#ifdef _WIN64
#define CSR_WOW64_ADDRESS_LIMIT 0x80000000ULL
#define CSR_WOW64_RESERVED_TAIL 0x00100000ULL
#define MM_ALLOCATION_GRANULARITY 0x10000
#endif

/* PRIVATE FUNCTIONS **********************************************************/

/*++
 * @name CsrpLoadServerDll
 * @implemented NT4
 *
 * The CsrpLoadServerDll routine loads a CSR Server DLL and calls its entrypoint.
 *
 * @param DllName
 *        Unicode name of the CSR Server DLL to load and call.
 *
 * @param EntryPoint
 *        Name of the server's initialization function.
 *        If this parameter is NULL, the default ServerDllInitialize
 *        will be assumed.
 *
 * @return STATUS_SUCCESS in case of success, error status otherwise.
 *
 * @remarks This is only called during csrss initialization.
 *
 *--*/
static NTSTATUS CsrpLoadServerDll(IN PCUNICODE_STRING DllName,
				  IN OPTIONAL PCSTR EntryPoint,
				  IN ULONG ServerId)
{
    NTSTATUS Status;
    HANDLE hServerDll = NULL;
    PCSR_SERVER_DLL_INIT_CALLBACK ServerDllInitProcedure;

    /* Check if it's beyond the maximum we support */
    if (ServerId >= CSR_SERVER_DLL_MAX)
	return STATUS_TOO_MANY_NAMES;

    /* Check if it's already been loaded */
    if (CsrSrv->LoadedServerDll[ServerId])
	return STATUS_INVALID_PARAMETER;

    /* Validate the Unicode names */
    if (!DllName || !DllName->Length || !DllName->Buffer ||
	(DllName->Length & (sizeof(WCHAR) - 1)))
	return STATUS_INVALID_PARAMETER;

    /* If we are loading ourselves (csrsrv.dll), don't actually load it */
    if (ServerId != CSRSRV_SERVERDLL_INDEX) {
	/* Load the DLL */
	Status = LdrLoadDll(NULL, 0, DllName, &hServerDll);
	if (!NT_SUCCESS(Status)) {
	    /* Setup error parameters */
	    UNICODE_STRING ErrorString;
	    RtlInitUnicodeString(&ErrorString, L"Default Load Path");
	    ULONG_PTR Parameters[2];
	    Parameters[0] = (ULONG_PTR)&DllName;
	    Parameters[1] = (ULONG_PTR)&ErrorString;

	    /* Send a hard error */
	    ULONG Response;
	    NtRaiseHardError(Status, 2, 3, Parameters, OptionOk, (PVOID)&Response);
	    goto Cleanup;
	}
    }

    /* Allocate a CSR DLL Object */
    ULONG Size = sizeof(CSR_SERVER_DLL) + DllName->MaximumLength;
    PCSR_SERVER_DLL ServerDll = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
    if (!ServerDll) {
	Status = STATUS_NO_MEMORY;
	goto Cleanup;
    }

    /* Set up the Object */
    ServerDll->Length = Size;
    /* Send our shared heap pointer to the server dll. */
    ServerDll->SharedSection = CsrSrv->SharedSectionHeap;
    ServerDll->SharedSection32 = CsrSrv->SharedSectionHeap;
    ServerDll->Name.Length = DllName->Length;
    ServerDll->Name.MaximumLength = DllName->MaximumLength;
    ServerDll->Name.Buffer = (PWCHAR)(ServerDll + 1);
    if (DllName->Length) {
	memcpy(ServerDll->Name.Buffer, DllName->Buffer, DllName->Length);
    }
    ServerDll->ServerId = ServerId;
    ServerDll->ServerHandle = hServerDll;

    /* Now get the entrypoint */
    ANSI_STRING EntryPointString = { 0 };
    if (hServerDll) {
	RtlInitAnsiString(&EntryPointString,
			  EntryPoint ? EntryPoint : "ServerDllInitialization");
	Status = LdrGetProcedureAddress(hServerDll, &EntryPointString, 0,
					(PVOID)&ServerDllInitProcedure);
    } else {
	/* No handle, so we are loading ourselves */
#ifdef CSR_DBG
	RtlInitAnsiString(&EntryPointString, "CsrServerDllInitialization");
#endif
	ServerDllInitProcedure = CsrServerDllInitialization;
	Status = STATUS_SUCCESS;
    }

    /* Check if we got the pointer, and call it */
    if (NT_SUCCESS(Status)) {
	/* Call the Server DLL entrypoint */
	__try {
	    Status = ServerDllInitProcedure(ServerDll);
	} __except (CsrUnhandledExceptionFilter(GetExceptionInformation())) {
	    Status = GetExceptionCode();
#ifdef CSR_DBG
	    DPRINT1("CSRSS: Exception 0x%x while calling Server DLL entrypoint %Z!%Z()\n",
		    Status, &DllName, &EntryPointString);
#endif
	}

	if (NT_SUCCESS(Status)) {
	    /* Save the pointer in our list */
	    CsrSrv->LoadedServerDll[ServerDll->ServerId] = ServerDll;

	    /* Does it use our generic heap? */
	    if (ServerDll->SharedSection != CsrSrv->SharedSectionHeap) {
		/* No, save the pointer to its shared section in our list */
		CsrSrv->SharedStaticServerData[ServerDll->ServerId] =
		    ServerDll->SharedSection;
	    }
	    if (ServerDll->SharedSection32 != CsrSrv->SharedSectionHeap)
		CsrSrv->SharedStaticServerData32[ServerDll->ServerId] =
		    PtrToUlong(ServerDll->SharedSection32);
	}
    }

Cleanup:
    if (!NT_SUCCESS(Status) && ServerDll) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, ServerDll);
    }
    if (!NT_SUCCESS(Status) && hServerDll)
	LdrUnloadDll(hServerDll);

    /* Return to caller */
    return Status;
}

/*++
 * @name CsrpLoadServerDlls
 *
 * The CsrpLoadServerDlls routine loads all CSR Server DLLs and performs their initializations.
 *
 * @return STATUS_SUCCESS in case of success, error status otherwise.
 *
 * @remarks This is only called during csrss initialization.
 *
 *--*/
NTSTATUS CsrpLoadServerDlls(VOID)
{
    /* Load us first */
    UNICODE_STRING CsrSrvName = RTL_CONSTANT_STRING(L"CSRSRV");
    NTSTATUS Status = CsrpLoadServerDll(&CsrSrvName, NULL, CSRSRV_SERVERDLL_INDEX);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Load all other server dlls */
    for (ULONG i = CSRSRV_SERVERDLL_INDEX + 1; i < CSR_SERVER_DLL_MAX; i++) {
	if (CsrSrv->DebugFlags & 1)
	    DPRINT1("CSRSS: Loading ServerDll=%ws:%s\n",
		    CsrSrv->ServerDllNames[i], CsrSrv->ServerDllEntryPoints[i]);
	UNICODE_STRING DllNameString;
	RtlInitUnicodeString(&DllNameString, CsrSrv->ServerDllNames[i]);
	Status = CsrpLoadServerDll(&DllNameString, CsrSrv->ServerDllEntryPoints[i], i);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("CSRSS: *** Failed loading ServerDll=%ws (Status == 0x%x)\n",
		    CsrSrv->ServerDllNames[i], Status);
	    return Status;
	}
    }
    return STATUS_SUCCESS;
}

/*++
 * @name CsrpSrvCreateSharedSection
 *
 * The CsrpSrvCreateSharedSection creates the Shared Section that all
 * CSR Server DLLs and Clients can use to share data.
 *
 * @param ParameterValue
 *        Specially formatted Unicode string from our registry command-line which
 *        specifies various arguments for the shared section.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks This is only called during csrss initialization.
 *
 *--*/
NTSTATUS CsrpCreateSharedSection(VOID)
{
    NTSTATUS Status;
    LARGE_INTEGER SectionSize;
    SIZE_T ViewSize = 0;
    PPEB Peb = NtCurrentPeb();
#ifdef _WIN64
    ULONG AllocationAttributes = SEC_RESERVE;
    ULONG_PTR ZeroBits = 0x7fffffff;
#else
    ULONG AllocationAttributes = SEC_BASED | SEC_RESERVE;
    ULONG_PTR ZeroBits = 0;
#endif

    /* Create the Secion */
    SectionSize.LowPart = CsrSrv->SharedSectionSize;
    SectionSize.HighPart = 0;
    Status = NtCreateSection(&CsrSrv->SharedSection, SECTION_ALL_ACCESS, NULL,
			     &SectionSize, PAGE_EXECUTE_READWRITE, AllocationAttributes,
			     NULL);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Map the section */
    Status = NtMapViewOfSection(CsrSrv->SharedSection, NtCurrentProcess(),
				&CsrSrv->SharedSectionBase, ZeroBits, 0, NULL,
				&ViewSize, ViewUnmap, MEM_TOP_DOWN,
				PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(Status)) {
	/* Fail */
	NtClose(CsrSrv->SharedSection);
	CsrSrv->SharedSection = NULL;
	return Status;
    }

#ifdef _WIN64
    if ((ULONG_PTR)CsrSrv->SharedSectionBase + CsrSrv->SharedSectionSize >
	CSR_WOW64_ADDRESS_LIMIT - CSR_WOW64_RESERVED_TAIL) {
	NtUnmapViewOfSection(NtCurrentProcess(), CsrSrv->SharedSectionBase);

	CsrSrv->SharedSectionBase = (PVOID)
	    ALIGN_DOWN_BY(CSR_WOW64_ADDRESS_LIMIT - CSR_WOW64_RESERVED_TAIL -
			      CsrSrv->SharedSectionSize,
			  MM_ALLOCATION_GRANULARITY);
	ViewSize = 0;
	Status = NtMapViewOfSection(CsrSrv->SharedSection, NtCurrentProcess(),
				    &CsrSrv->SharedSectionBase, 0, 0, NULL,
				    &ViewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(Status)) {
	    NtClose(CsrSrv->SharedSection);
	    CsrSrv->SharedSection = NULL;
	    return Status;
	}
    }
#endif

    /* FIXME: Write the value to registry */

    /* The Heap is the same place as the Base */
    CsrSrv->SharedSectionHeap = CsrSrv->SharedSectionBase;

    /* Create the heap */
    if (!(RtlCreateHeap(HEAP_ZERO_MEMORY | HEAP_CLASS_7,
			CsrSrv->SharedSectionHeap,
			CsrSrv->SharedSectionSize, PAGE_SIZE, 0, 0))) {
	/* Failure, unmap section and return */
	NtUnmapViewOfSection(NtCurrentProcess(), CsrSrv->SharedSectionBase);
	NtClose(CsrSrv->SharedSection);
	CsrSrv->SharedSection = NULL;
	return STATUS_NO_MEMORY;
    }

    /* Now allocate space from the heap for the Shared Data */
    CsrSrv->SharedStaticServerData =
	RtlAllocateHeap(CsrSrv->SharedSectionHeap, HEAP_ZERO_MEMORY,
			CSR_SERVER_DLL_MAX * sizeof(PVOID));
    if (!CsrSrv->SharedStaticServerData)
	return STATUS_NO_MEMORY;

    CsrSrv->SharedStaticServerData32 =
	RtlAllocateHeap(CsrSrv->SharedSectionHeap, HEAP_ZERO_MEMORY,
			CSR_SERVER_DLL_MAX * sizeof(ULONG));
    if (!CsrSrv->SharedStaticServerData32)
	return STATUS_NO_MEMORY;

    /* Write the values to the PEB */
    Peb->ReadOnlySharedMemoryBase = CsrSrv->SharedSectionBase;
    Peb->ReadOnlySharedMemoryHeap = CsrSrv->SharedSectionHeap;
    Peb->ReadOnlyStaticServerData = CsrSrv->SharedStaticServerData;

    /* Return */
    return STATUS_SUCCESS;
}

/*++
 * @name CsrpSrvAttachSharedSection
 *
 * The CsrpSrvAttachSharedSection maps the CSR Shared Section into a new
 * CSR Process' address space, and returns the pointers to the section
 * through the Connection Info structure.
 *
 * @param CsrProcess
 *        Pointer to the CSR Process that is attempting a connection.
 *
 * @param ConnectInfo
 *        Pointer to the CSR Connection Info structure for the incoming
 *        connection.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS CsrpAttachSharedSection(IN PCSR_PROCESS CsrProcess OPTIONAL,
				 OUT PCSR_API_CONNECTINFO ConnectInfo)
{
    NTSTATUS Status;
    SIZE_T ViewSize = 0;

    /* Check if we have a process */
    if (CsrProcess && !(CsrProcess->Flags & CsrProcessSharedSectionMapped)) {
	/* Map the section into this process */
	Status = NtMapViewOfSection(CsrSrv->SharedSection,
				    CsrProcess->ProcessHandle,
				    &CsrSrv->SharedSectionBase, 0, 0, NULL,
				    &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);
	if (!NT_SUCCESS(Status))
	    return Status;
	CsrProcess->Flags |= CsrProcessSharedSectionMapped;
    }

    /* Write the values in the Connection Info structure */
    ConnectInfo->SharedSectionBase = CsrSrv->SharedSectionBase;
    ConnectInfo->SharedSectionHeap = CsrSrv->SharedSectionHeap;
    ConnectInfo->SharedStaticServerData = (CsrProcess &&
					   (CsrProcess->Flags & CsrProcessIsWow64)) ?
					      (PVOID)CsrSrv->SharedStaticServerData32 :
					      (PVOID)CsrSrv->SharedStaticServerData;

    /* Return success */
    return STATUS_SUCCESS;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*++
 * @name CsrSrvClientConnect
 *
 * The CsrSrvClientConnect CSR API handles a new connection to a server DLL.
 *
 * @param ApiMessage
 *        Pointer to the CSR API Message for this request.
 *
 * @param ReplyCode
 *        Optional reply to this request.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_INVALID_PARAMETER
 *         or STATUS_TOO_MANY_NAMES in case of failure.
 *
 * @remarks None.
 *
 *--*/
static CSR_API(CsrSrvClientConnect)
{
    /* You cannot call this service from the CSRSS server. */
    if (!Thread) {
	return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status;
    PCSR_CLIENT_CONNECT Request = &ApiMessage->Data.CsrClientConnect;
    PCSR_PROCESS ClientProcess = Thread->Process;

    /* Set default reply */
    *ReplyCode = CsrReplyImmediately;

    /* Validate the ServerID */
    if (Request->ServerId >= CSR_SERVER_DLL_MAX) {
	return STATUS_TOO_MANY_NAMES;
    } else if (!CsrSrv->LoadedServerDll[Request->ServerId]) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Validate the Message Buffer */
    if (!(CsrValidateMessageBuffer(ApiMessage, &Request->ConnectionInfo,
				   Request->ConnectionInfoSize, sizeof(BYTE)))) {
	/* Fail due to buffer overflow or other invalid buffer */
	return STATUS_INVALID_PARAMETER;
    }

    /* Find the loaded Server DLL */
    PCSR_SERVER_DLL ServerDll = CsrSrv->LoadedServerDll[Request->ServerId];

    /* Check if it has a Connect Callback */
    if (ServerDll->ConnectCallback) {
	/* Call the callback */
	Status = ServerDll->ConnectCallback(ClientProcess, Request->ConnectionInfo,
					    &Request->ConnectionInfoSize);
    } else {
	/* Assume success */
	Status = STATUS_SUCCESS;
    }

    /* Return status */
    return Status;
}

static PCSR_API_ROUTINE CsrpServerApiDispatchTable[CsrpMaxApiNumber] = {
    CsrSrvClientConnect
};

/*
 * On Windows Server 2003, CSR Servers contain
 * the API Names Table only in Debug Builds.
 */
#ifdef CSR_DBG
static PCHAR CsrpServerApiNameTable[CsrpMaxApiNumber] = { "ClientConnect" };
#endif

/*++
 * @name CsrServerDllInitialization
 * @implemented NT4
 *
 * The CsrServerDllInitialization is the initialization routine
 * for this Server DLL.
 *
 * @param LoadedServerDll
 *        Pointer to the CSR Server DLL structure representing this Server DLL.
 *
 * @return STATUS_SUCCESS.
 *
 * @remarks None.
 *
 *--*/
CSR_SERVER_DLL_INIT(CsrServerDllInitialization)
{
    /* Setup the DLL Object */
    LoadedServerDll->ApiBase = CSRSRV_FIRST_API_NUMBER;
    LoadedServerDll->HighestApiSupported = CsrpMaxApiNumber;
    LoadedServerDll->DispatchTable = CsrpServerApiDispatchTable;
#ifdef CSR_DBG
    LoadedServerDll->NameTable = CsrpServerApiNameTable;
#endif
    LoadedServerDll->ConnectCallback = NULL;
    LoadedServerDll->DisconnectCallback = NULL;

    /* All done */
    return STATUS_SUCCESS;
}

/*++
 * @name CsrUnhandledExceptionFilter
 * @implemented NT5
 *
 * The CsrUnhandledExceptionFilter routine handles all exceptions
 * within SEH-protected blocks.
 *
 * @param ExceptionPointers
 *        System-defined Argument.
 *
 * @return EXCEPTION_EXECUTE_HANDLER.
 *
 * @remarks None.
 *
 *--*/
NTAPI EXCEPTION_DISPOSITION CsrUnhandledExceptionFilter(IN PEXCEPTION_POINTERS ExceptionInfo)
{
    SYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo;
    EXCEPTION_DISPOSITION Result = EXCEPTION_EXECUTE_HANDLER;
    BOOLEAN OldValue;
    NTSTATUS Status;
    UNICODE_STRING ErrorSource;
    ULONG_PTR ErrorParameters[4];
    ULONG Response;

    DPRINT1("CsrUnhandledExceptionFilter called\n");

    /* Check if a debugger is installed */
    Status = NtQuerySystemInformation(SystemKernelDebuggerInformation, &DebuggerInfo,
				      sizeof(DebuggerInfo), NULL);

    /* Check if this is Session 0, and the Debugger is Enabled */
    if ((NtCurrentPeb()->SessionId != 0) && (NT_SUCCESS(Status)) &&
	(DebuggerInfo.KernelDebuggerEnabled)) {
	/* Call the Unhandled Exception Filter */
	Result = RtlUnhandledExceptionFilter(ExceptionInfo);
	if (Result != EXCEPTION_CONTINUE_EXECUTION) {
	    /* We're going to raise an error. Get Shutdown Privilege first */
	    Status = RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, TRUE, &OldValue);

	    /* Use the Process token if that failed */
	    if (Status == STATUS_NO_TOKEN) {
		Status = RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE,
					    &OldValue);
	    }
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("CsrUnhandledExceptionFilter(): "
			"RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE) failed, Status = 0x%08x\n",
			Status);
		goto NoPrivilege;
	    }

	    /* Initialize our Name String */
	    RtlInitUnicodeString(&ErrorSource, L"Windows SubSystem");

	    /* Set the parameters */
	    ErrorParameters[0] = (ULONG_PTR)&ErrorSource;
	    ErrorParameters[1] = ExceptionInfo->ExceptionRecord->ExceptionCode;
	    ErrorParameters[2] = (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
	    ErrorParameters[3] = (ULONG_PTR)ExceptionInfo->ContextRecord;

	    /* Bugcheck */
	    NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED, 4, 1, ErrorParameters,
			     OptionShutdownSystem, (PVOID)&Response);
	}

    NoPrivilege:
	/* Just terminate us */
	NtTerminateProcess(NtCurrentProcess(),
			   ExceptionInfo->ExceptionRecord->ExceptionCode);
    }

    return Result;
}

/* EOF */
