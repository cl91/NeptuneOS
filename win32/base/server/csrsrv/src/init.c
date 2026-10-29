/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/init.c
 * PURPOSE:         CSR Server DLL Initialization
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 *                  ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "srv.h"
#include <stdio.h>

/* DATA ***********************************************************************/

PCSR_SERVER CsrSrv;

/* PRIVATE FUNCTIONS **********************************************************/

/* === INIT ROUTINES === */

/*++
 * @name CsrpSetProcessSecurity
 *
 * The CsrpSetProcessSecurity routine protects access to the CSRSS process
 * from unauthorized tampering.
 *
 * @param None.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS CsrpSetProcessSecurity(VOID)
{
    NTSTATUS Status;
    HANDLE hToken, hProcess = NtCurrentProcess();
    ULONG Length;
    PTOKEN_USER TokenInfo = NULL;
    PSECURITY_DESCRIPTOR ProcSd = NULL;
    PACL Dacl;
    PSID UserSid;

    /* Open our token */
    Status = NtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    if (!NT_SUCCESS(Status))
	goto Quickie;

    /* Get the Token User Length */
    Status = NtQueryInformationToken(hToken, TokenUser, NULL, 0, &Length);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
	NtClose(hToken);
	goto Quickie;
    }

    /* Allocate space for it */
    TokenInfo = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Length);
    if (!TokenInfo) {
	NtClose(hToken);
	Status = STATUS_NO_MEMORY;
	goto Quickie;
    }

    /* Now query the data */
    Status = NtQueryInformationToken(hToken, TokenUser, TokenInfo, Length, &Length);
    NtClose(hToken);
    if (!NT_SUCCESS(Status))
	goto Quickie;

    /* Now check the SID Length */
    UserSid = TokenInfo->User.Sid;
    Length = RtlLengthSid(UserSid) + sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE);

    /* Allocate a buffer for the Security Descriptor, with SID and DACL */
    ProcSd = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
			     SECURITY_DESCRIPTOR_MIN_LENGTH + Length);
    if (!ProcSd) {
	Status = STATUS_NO_MEMORY;
	goto Quickie;
    }

    /* Set the pointer to the DACL */
    Dacl = (PACL)((ULONG_PTR)ProcSd + SECURITY_DESCRIPTOR_MIN_LENGTH);

    /* Now create the SD itself */
    Status = RtlCreateSecurityDescriptor(ProcSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: SD creation failed - status = %x\n", Status);
	goto Quickie;
    }

    /* Create the DACL for it*/
    Status = RtlCreateAcl(Dacl, Length, ACL_REVISION2);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: DACL creation failed - status = %x\n", Status);
	goto Quickie;
    }

    /* Create the ACE */
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION,
				    PROCESS_VM_READ | PROCESS_VM_WRITE |
					PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE |
					PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME |
					PROCESS_QUERY_INFORMATION | READ_CONTROL,
				    UserSid);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: ACE creation failed - status = %x\n", Status);
	goto Quickie;
    }

    /* Clear the DACL in the SD */
    Status = RtlSetDaclSecurityDescriptor(ProcSd, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: set DACL failed - status = %x\n", Status);
	goto Quickie;
    }

    /* Write the SD into the Process */
    Status = NtSetSecurityObject(hProcess, DACL_SECURITY_INFORMATION, ProcSd);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: set process DACL failed - status = %x\n", Status);
	goto Quickie;
    }

    /* Free the memory and return */
Quickie:
    if (ProcSd)
	RtlFreeHeap(RtlGetProcessHeap(), 0, ProcSd);
    if (TokenInfo)
	RtlFreeHeap(RtlGetProcessHeap(), 0, TokenInfo);
    return Status;
}

/*++
 * @name CsrpParseServerCommandLine
 *
 * The CsrpParseServerCommandLine routine parses the CSRSS command-line and
 * saves the parsed information in the CSR_SERVER struct.
 *
 * @param Arguments
 *        Unicode command-line arguments.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
static NTSTATUS CsrpParseServerCommandLine(IN PCUNICODE_STRING Arguments)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWSTR CommandLine = NULL, Cursor, Argument, ParameterName, ParameterValue;
    UNICODE_STRING ParameterNameString, ParameterValueString;
    UNICODE_STRING SessionIdName = RTL_CONSTANT_STRING(L"SessionId");
    UNICODE_STRING SharedSectionName = RTL_CONSTANT_STRING(L"SharedSection");
    UNICODE_STRING ObjectDirectoryName = RTL_CONSTANT_STRING(L"ObjectDirectory");
    UNICODE_STRING ServerDllName = RTL_CONSTANT_STRING(L"ServerDll");
    BOOLEAN InQuotes;
    WCHAR Character;

    if (!Arguments || (Arguments->Length && !Arguments->Buffer) ||
	(Arguments->Length & (sizeof(WCHAR) - 1))) {
	Status = STATUS_INVALID_PARAMETER;
	goto Cleanup;
    }

    /* Make a writable copy so that quotes can be removed and tokens split in place */
    CommandLine = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				  Arguments->Length + sizeof(UNICODE_NULL));
    if (!CommandLine) {
	Status = STATUS_NO_MEMORY;
	goto Cleanup;
    }
    RtlCopyMemory(CommandLine, Arguments->Buffer, Arguments->Length);

    /* Loop through every argument in the Unicode command line */
    for (Cursor = CommandLine; *Cursor;) {
	PWSTR Write;

	/* Skip whitespace between arguments */
	while (*Cursor && *Cursor <= L' ')
	    Cursor++;
	if (!*Cursor)
	    break;

	/* Find the end of the argument, honoring double-quoted strings */
	Argument = Cursor;
	InQuotes = FALSE;
	Write = Argument;
	while (*Cursor) {
	    Character = *Cursor;
	    if (Character == L'"') {
		InQuotes = !InQuotes;
		Cursor++;
		continue;
	    }
	    if (!InQuotes && Character <= L' ') {
		break;
	    }
	    *Write++ = Character;
	    Cursor++;
	}
	if (*Cursor)
	    Cursor++;
	*Write = UNICODE_NULL;

	/* Split Name and Value */
	ParameterName = Argument;
	ParameterValue = ParameterName;
	while (*ParameterValue && *ParameterValue != L'=')
	    ParameterValue++;
	if (*ParameterValue == L'=') {
	    *ParameterValue++ = UNICODE_NULL;
	} else {
	    ParameterValue = NULL;
	}
	DPRINT("Name=%ls, Value=%ls\n", ParameterName,
	       ParameterValue ? ParameterValue : L"(null)");

	if (!ParameterValue) {
	    Status = STATUS_INVALID_PARAMETER;
	    goto Cleanup;
	}
	RtlInitUnicodeString(&ParameterNameString, ParameterName);
	RtlInitUnicodeString(&ParameterValueString, ParameterValue);

	/* Check for Object Directory */
	if (RtlEqualUnicodeString(&ParameterNameString, &SessionIdName, TRUE)) {
	    Status = RtlUnicodeStringToInteger(&ParameterValueString, 0, &CsrSrv->SessionId);
	    if (!NT_SUCCESS(Status)) {
		goto Cleanup;
	    }
	} else if (RtlEqualUnicodeString(&ParameterNameString, &ObjectDirectoryName, TRUE)) {
	    ULONG NumChars = ParameterValueString.Length / sizeof(WCHAR);
	    if (NumChars >= sizeof(CsrSrv->ObjectDirectoryName)) {
		Status = STATUS_NAME_TOO_LONG;
		goto Cleanup;
	    }
	    memcpy(CsrSrv->ObjectDirectoryName, ParameterValue,
		   ParameterValueString.Length);
	    CsrSrv->ObjectDirectoryName[NumChars] = UNICODE_NULL;
	} else if (RtlEqualUnicodeString(&ParameterNameString, &SharedSectionName, TRUE)) {
	    /* If there's no parameter, fail */
	    if (!ParameterValueString.Buffer ||
		(ParameterValueString.Length & (sizeof(WCHAR) - 1))) {
		Status = STATUS_INVALID_PARAMETER;
		goto Cleanup;
	    }

	    /* The number before the first comma specifies the size of the shared heap
	     * for this session */
	    ULONG ValueChars = 0;
	    ULONG CharsRemaining = ParameterValueString.Length / sizeof(WCHAR);
	    while (CharsRemaining && ParameterValue[ValueChars] != L',') {
		ValueChars++;
		CharsRemaining--;
	    }

	    /* Convert the size string to an integer */
	    UNICODE_STRING SizeString;
	    SizeString.Buffer = ParameterValue;
	    SizeString.MaximumLength = SizeString.Length = ValueChars * sizeof(WCHAR);
	    ULONG Size = 0;
	    Status = RtlUnicodeStringToInteger(&SizeString, 0, &Size);
	    if (!NT_SUCCESS(Status)) {
		goto Cleanup;
	    }

	    /* Find out about the system page size */
	    SYSTEM_BASIC_INFORMATION NtSysInfo;
	    Status = NtQuerySystemInformation(SystemBasicInformation, &NtSysInfo,
					      sizeof(SYSTEM_BASIC_INFORMATION), NULL);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("CSRSRV:%s: NtQuerySystemInformation failed (Status=0x%08x)\n",
			__FUNCTION__, Status);
		goto Cleanup;
	    }

	    /* Multiply by 1024 entries and round to page size */
	    CsrSrv->SharedSectionSize = ROUND_UP(Size * 1024, NtSysInfo.PageSize);
	} else if (RtlEqualUnicodeString(&ParameterNameString, &ServerDllName, TRUE)) {
	    /* Loop the command line */
	    PWSTR EntryPoint = NULL;
	    Status = STATUS_INVALID_PARAMETER;
	    PWSTR ServerString = ParameterValue;
	    while (*ServerString) {
		/* Check for the Entry Point */
		if ((*ServerString == L':') && (!EntryPoint)) {
		    /* Found it. NULL-terminate and save it. */
		    *ServerString++ = UNICODE_NULL;
		    EntryPoint = ServerString;
		}

		/* Check for the Dll Index */
		if (*ServerString++ == L',')
		    break;
	    }

	    /* Did we find something to load? */
	    if (!*ServerString) {
		DPRINT1("CSRSS: *** Invalid syntax for ServerDll=%ls (Status == %X)\n",
			ParameterValue, Status);
		goto Cleanup;
	    }

	    /* Convert it to a ULONG */
	    UNICODE_STRING DllIndexString;
	    RtlInitUnicodeString(&DllIndexString, ServerString);
	    ULONG DllIndex;
	    Status = RtlUnicodeStringToInteger(&DllIndexString, 10, &DllIndex);

	    /* Add a null char if it was valid */
	    if (NT_SUCCESS(Status))
		ServerString[-1] = UNICODE_NULL;

	    if (!NT_SUCCESS(Status))
		goto Cleanup;

	    UNICODE_STRING DllNameString, DllEntryPointString = {};
	    RtlInitUnicodeString(&DllNameString, ParameterValue);
	    if (EntryPoint) {
		RtlInitUnicodeString(&DllEntryPointString, EntryPoint);
	    }

	    if (DllIndex >= CSR_SERVER_DLL_MAX) {
		Status = STATUS_INVALID_PARAMETER;
		goto Cleanup;
	    }
	    if (DllNameString.Length >= sizeof(CsrSrv->ServerDllNames[DllIndex])) {
		Status = STATUS_NAME_TOO_LONG;
		goto Cleanup;
	    }
	    memcpy(CsrSrv->ServerDllNames[DllIndex],
		   DllNameString.Buffer, DllNameString.Length + sizeof(WCHAR));
	    if (DllEntryPointString.Length / sizeof(WCHAR) >=
		sizeof(CsrSrv->ServerDllEntryPoints[DllIndex])) {
		Status = STATUS_NAME_TOO_LONG;
		goto Cleanup;
	    }
	    snprintf(CsrSrv->ServerDllEntryPoints[DllIndex],
		     sizeof(CsrSrv->ServerDllEntryPoints[DllIndex]),
		     "%wZ", &DllEntryPointString);
	} else {
	    /* Invalid parameter on the command line */
	    Status = STATUS_INVALID_PARAMETER;
	    goto Cleanup;
	}
    }

Cleanup:
    if (CommandLine)
	RtlFreeHeap(RtlGetProcessHeap(), 0, CommandLine);
    return Status;
}

/*++
 * @name CsrpSetDirectorySecurity
 *
 * The CsrpSetDirectorySecurity routine sets the security descriptor for the
 * specified Object Directory.
 *
 * @param ObjectDirectory
 *        Handle fo the Object Directory to protect.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
static NTSTATUS CsrpSetDirectorySecurity(IN HANDLE ObjectDirectory)
{
    /* FIXME: Implement */
    return STATUS_SUCCESS;
}

/*++
 * @name CsrCreateSessionObjectDirectory
 *
 * The CsrCreateSessionObjectDirectory routine creates the BaseNamedObjects,
 * Session and Dos Devices directories for the specified session.
 *
 * @param Session
 *        Session ID for which to create the directories.
 *
 * @return STATUS_SUCCESS in case of success, error status otherwise.
 *
 * @remarks The \Sessions\<id> object directory is created by the SMSS before
 *          this routine is called.
 *
 *--*/
static NTSTATUS CsrpCreateSessionObjectDirectory(VOID)
{
    /* Construct the session object directory path */
    WCHAR SessionDirectory[MAX_PATH] = {};
    PWSTR FormatString = CsrSrv->ObjectDirectoryName[0] == L'\\'
	? L"\\Sessions\\%lu%ls" : L"\\Sessions\\%lu\\%ls";
    _snwprintf(SessionDirectory, ARRAYSIZE(SessionDirectory),
	       FormatString, CsrSrv->SessionId, CsrSrv->ObjectDirectoryName);
    UNICODE_STRING SessionDirectoryString;
    RtlInitUnicodeString(&SessionDirectoryString, SessionDirectory);

    /* Create the session object directory */
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &SessionDirectoryString,
			       OBJ_OPENIF | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL,
			       NULL);
    NTSTATUS Status = NtCreateDirectoryObject(&CsrSrv->SessionObjectDirectory,
					      DIRECTORY_ALL_ACCESS,
					      &ObjectAttributes);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Secure it */
    return CsrpSetDirectorySecurity(CsrSrv->SessionObjectDirectory);
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*++
 * @name CsrServerInitialization
 * @implemented NT4
 *
 * The CsrServerInitialization routine is called by the entrypoint of CSRSS.
 * It initializes the CSR API port and establishes the connection to the
 * Session Manager API port.
 *
 * @param Arguments
 *        Unicode command-line arguments.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrServerInitialization(IN PCUNICODE_STRING Arguments)
{
    /* Set our Security Descriptor to protect the process */
    NTSTATUS Status = CsrpSetProcessSecurity();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrSetProcessSecurity failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Allocate and set up the CSR_SERVER object */
    CsrSrv = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CSR_SERVER));
    if (!CsrSrv)
	return STATUS_NO_MEMORY;
    InitializeListHead(&CsrSrv->ServerThreadList);
    InitializeListHead(&CsrSrv->ClientProcessList);
    for (ULONG i = 0; i < NUMBER_THREAD_HASH_BUCKETS; i++)
	InitializeListHead(&CsrSrv->ClientThreadHashTable[i]);
    CsrSrv->ProcessSequenceCount = 5;

    /* Initialize the Client Process Lock */
    Status = RtlInitializeCriticalSection(&CsrSrv->ClientProcessLock);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Parse the command line. This will load the requested server dll. */
    Status = CsrpParseServerCommandLine(Arguments);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrParseServerCommandLine failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Create the object directories for this session */
    Status = CsrpCreateSessionObjectDirectory();
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Create the section object that is shared between the server and the clients */
    Status = CsrpCreateSharedSection();
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Load all server dlls */
    Status = CsrpLoadServerDlls();
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Now initialize our API Port */
    Status = CsrpApiPortInitialize();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrApiPortInitialize failed (Status=0x%08x)\n", __FUNCTION__,
		Status);
	return Status;
    }

    /* We're all set! Connect to SM! */
    Status = SmConnectToSm(&CsrSrv->SmApiCommPort);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: SmConnectToSm failed (Status=0x%08x)\n", __FUNCTION__,
		Status);
    }

    /* Return status */
    return Status;
}

NTAPI BOOL DllMain(IN HINSTANCE hInstanceDll, IN DWORD dwReason, IN LPVOID lpReserved)
{
    /* We don't do much */
    UNREFERENCED_PARAMETER(hInstanceDll);
    UNREFERENCED_PARAMETER(dwReason);
    UNREFERENCED_PARAMETER(lpReserved);

    return TRUE;
}

/* EOF */
