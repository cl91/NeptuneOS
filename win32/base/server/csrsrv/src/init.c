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

#include <winreg.h>

/* DATA ***********************************************************************/

// Debug Flag
ULONG CsrDebug = 0; // 0xFFFFFFFF;

HANDLE CsrHeap;
HANDLE CsrObjectDirectory;
UNICODE_STRING CsrDirectoryName;
UNICODE_STRING CsrSbApiPortName;
LOCAL_HANDLE CsrApiCommPort;
LOCAL_HANDLE CsrSbApiCommPort;
LOCAL_HANDLE CsrSmApiCommPort;
static HANDLE CsrApiPort;
static HANDLE CsrSbApiPort;
PCSR_THREAD CsrSbApiRequestThreadPtr;
BOOLEAN CsrWindowsControl;
ULONG CsrSubSystemType; // Known as SessionFirstProcessImageType in Windows 7+
ULONG CsrMaxApiRequestThreads;
ULONG CsrTotalPerProcessDataLength;
ULONG SessionId;
HANDLE BNOLinksDirectory;
HANDLE SessionObjectDirectory;
HANDLE DosDevicesDirectory;
SYSTEM_BASIC_INFORMATION CsrNtSysInfo;

/* PRIVATE FUNCTIONS **********************************************************/

/* === INIT ROUTINES === */

/*++
 * @name CsrSetProcessSecurity
 *
 * The CsrSetProcessSecurity routine protects access to the CSRSS process
 * from unauthorized tampering.
 *
 * @param None.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrSetProcessSecurity(VOID)
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
    TokenInfo = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, Length);
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
    ProcSd = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY,
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
	RtlFreeHeap(CsrHeap, 0, ProcSd);
    if (TokenInfo)
	RtlFreeHeap(CsrHeap, 0, TokenInfo);
    return Status;
}

/*++
 * @name CsrSetDirectorySecurity
 *
 * The CsrSetDirectorySecurity routine sets the security descriptor for the
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
NTAPI NTSTATUS CsrSetDirectorySecurity(IN HANDLE ObjectDirectory)
{
    /* FIXME: Implement */
    return STATUS_SUCCESS;
}

/*++
 * @name GetDosDevicesProtection
 *
 * The GetDosDevicesProtection creates a security descriptor for the DOS Devices
 * Object Directory.
 *
 * @param DosDevicesSd
 *        Pointer to the Security Descriptor to return.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks Depending on the DOS Devices Protection Mode (set in the registry),
 *          regular users may or may not have full access to the directory.
 *
 *--*/
NTAPI NTSTATUS GetDosDevicesProtection(OUT PSECURITY_DESCRIPTOR DosDevicesSd)
{
    SID_IDENTIFIER_AUTHORITY WorldAuthority = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY CreatorAuthority = { SECURITY_CREATOR_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY NtSidAuthority = { SECURITY_NT_AUTHORITY };
    PSID WorldSid, CreatorSid, AdminSid, SystemSid;
    UCHAR KeyValueBuffer[0x40];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo;
    UNICODE_STRING KeyName;
    ULONG ProtectionMode = 0;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PACL Dacl;
    PACCESS_ALLOWED_ACE Ace;
    HANDLE hKey;
    NTSTATUS Status;
    ULONG ResultLength, SidLength, AclLength;

    /* Create the SD */
    Status = RtlCreateSecurityDescriptor(DosDevicesSd, SECURITY_DESCRIPTOR_REVISION);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the System SID */
    Status = RtlAllocateAndInitializeSid(&NtSidAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0,
					 0, 0, 0, 0, 0, 0, &SystemSid);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the World SID */
    Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0,
					 0, 0, 0, 0, &WorldSid);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the Admin SID */
    Status = RtlAllocateAndInitializeSid(&NtSidAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
					 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
					 &AdminSid);
    ASSERT(NT_SUCCESS(Status));

    /* Initialize the Creator SID */
    Status = RtlAllocateAndInitializeSid(&CreatorAuthority, 1, SECURITY_CREATOR_OWNER_RID,
					 0, 0, 0, 0, 0, 0, 0, &CreatorSid);
    ASSERT(NT_SUCCESS(Status));

    /* Open the Session Manager Key */
    RtlInitUnicodeString(&KeyName, SM_REG_KEY);
    InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL,
			       NULL);
    Status = NtOpenKey(&hKey, KEY_READ, &ObjectAttributes);
    if (NT_SUCCESS(Status)) {
	/* Read the key value */
	RtlInitUnicodeString(&KeyName, L"ProtectionMode");
	Status = NtQueryValueKey(hKey, &KeyName, KeyValuePartialInformation,
				 KeyValueBuffer, sizeof(KeyValueBuffer), &ResultLength);

	/* Make sure it's what we expect it to be */
	KeyValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueBuffer;
	if ((NT_SUCCESS(Status)) && (KeyValuePartialInfo->Type == REG_DWORD) &&
	    (*(PULONG)KeyValuePartialInfo->Data)) {
	    /* Save the Protection Mode */
	    ProtectionMode = *(PULONG)KeyValuePartialInfo->Data;
	}

	/* Close the handle */
	NtClose(hKey);
    }

    /* Check the Protection Mode */
    if (ProtectionMode & 3) {
	/* Calculate SID Lengths */
	SidLength = RtlLengthSid(CreatorSid) + RtlLengthSid(SystemSid) +
		    RtlLengthSid(AdminSid);
	AclLength = sizeof(ACL) + 3 * sizeof(ACCESS_ALLOWED_ACE) + SidLength;

	/* Allocate memory for the DACL */
	Dacl = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, AclLength);
	ASSERT(Dacl != NULL);

	/* Build the ACL and add 3 ACEs */
	Status = RtlCreateAcl(Dacl, AclLength, ACL_REVISION2);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, SystemSid);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, AdminSid);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, CreatorSid);
	ASSERT(NT_SUCCESS(Status));

	/* Edit the ACEs to make them inheritable */
	Status = RtlGetAce(Dacl, 0, (PVOID *)&Ace);
	ASSERT(NT_SUCCESS(Status));
	Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	Status = RtlGetAce(Dacl, 1, (PVOID *)&Ace);
	ASSERT(NT_SUCCESS(Status));
	Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	Status = RtlGetAce(Dacl, 2, (PVOID *)&Ace);
	ASSERT(NT_SUCCESS(Status));
	Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
				INHERIT_ONLY_ACE;

	/* Set this DACL with the SD */
	Status = RtlSetDaclSecurityDescriptor(DosDevicesSd, TRUE, Dacl, FALSE);
	ASSERT(NT_SUCCESS(Status));
	goto Quickie;
    } else {
	/* Calculate SID Lengths */
	SidLength = RtlLengthSid(WorldSid) + RtlLengthSid(SystemSid);
	AclLength = sizeof(ACL) + 3 * sizeof(ACCESS_ALLOWED_ACE) + SidLength;

	/* Allocate memory for the DACL */
	Dacl = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY, AclLength);
	ASSERT(Dacl != NULL);

	/* Build the ACL and add 3 ACEs */
	Status = RtlCreateAcl(Dacl, AclLength, ACL_REVISION2);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION,
					GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
					WorldSid);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, SystemSid);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, GENERIC_ALL, WorldSid);
	ASSERT(NT_SUCCESS(Status));

	/* Edit the last ACE to make it inheritable */
	Status = RtlGetAce(Dacl, 2, (PVOID *)&Ace);
	ASSERT(NT_SUCCESS(Status));
	Ace->Header.AceFlags |= OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
				INHERIT_ONLY_ACE;

	/* Set this DACL with the SD */
	Status = RtlSetDaclSecurityDescriptor(DosDevicesSd, TRUE, Dacl, FALSE);
	ASSERT(NT_SUCCESS(Status));
	goto Quickie;
    }

    /* FIXME: failure cases! Fail: */
    /* Free the memory */
    RtlFreeHeap(CsrHeap, 0, Dacl);

/* FIXME: semi-failure cases! Quickie: */
Quickie:
    /* Free the SIDs */
    RtlFreeSid(CreatorSid);
    RtlFreeSid(AdminSid);
    RtlFreeSid(WorldSid);
    RtlFreeSid(SystemSid);

    /* Return */
    return Status;
}

/*++
 * @name FreeDosDevicesProtection
 *
 * The FreeDosDevicesProtection frees the security descriptor that was created
 * by GetDosDevicesProtection
 *
 * @param DosDevicesSd
 *        Pointer to the security descriptor to free.

 * @return None.
 *
 * @remarks None.
 *
 *--*/
NTAPI VOID FreeDosDevicesProtection(IN PSECURITY_DESCRIPTOR DosDevicesSd)
{
    PACL Dacl;
    BOOLEAN Present, Default;
    NTSTATUS Status;

    /* Get the DACL corresponding to this SD */
    Status = RtlGetDaclSecurityDescriptor(DosDevicesSd, &Present, &Dacl, &Default);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Present);
    ASSERT(Dacl != NULL);

    /* Free it */
    if ((NT_SUCCESS(Status)) && (Dacl))
	RtlFreeHeap(CsrHeap, 0, Dacl);
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
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrCreateSessionObjectDirectory(IN ULONG Session)
{
    WCHAR SessionBuffer[512], BnoBuffer[512];
    UNICODE_STRING SessionString, BnoString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE BnoHandle;
    SECURITY_DESCRIPTOR DosDevicesSd;
    NTSTATUS Status;

    /* Generate the Session BNOLINKS Directory name */
    _swprintf(SessionBuffer, L"%ws\\BNOLINKS", SESSION_ROOT);
    RtlInitUnicodeString(&SessionString, SessionBuffer);

    /* Create it */
    InitializeObjectAttributes(&ObjectAttributes, &SessionString,
			       OBJ_OPENIF | OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtCreateDirectoryObject(&BNOLinksDirectory, DIRECTORY_ALL_ACCESS,
				     &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: NtCreateDirectoryObject failed in "
		"CsrCreateSessionObjectDirectory - status = %x\n",
		Status);
	return Status;
    }

    /* Now add the Session ID */
    _swprintf(SessionBuffer, L"%ld", Session);
    RtlInitUnicodeString(&SessionString, SessionBuffer);

    /* Check if this is the first Session */
    if (Session) {
	/* Not the first, so the name will be slighly more complex */
	_swprintf(BnoBuffer, L"%ws\\%ld\\BaseNamedObjects", SESSION_ROOT, Session);
	RtlInitUnicodeString(&BnoString, BnoBuffer);
    } else {
	/* Use the direct name */
	RtlInitUnicodeString(&BnoString, L"\\BaseNamedObjects");
    }

    /* Create the symlink */
    InitializeObjectAttributes(&ObjectAttributes, &SessionString,
			       OBJ_OPENIF | OBJ_CASE_INSENSITIVE, BNOLinksDirectory,
			       NULL);
    Status = NtCreateSymbolicLinkObject(&BnoHandle, SYMBOLIC_LINK_ALL_ACCESS,
					&ObjectAttributes, &BnoString);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: NtCreateSymbolicLinkObject failed in "
		"CsrCreateSessionObjectDirectory - status = %x\n",
		Status);
	return Status;
    }

    /* Create the \DosDevices Security Descriptor */
    Status = GetDosDevicesProtection(&DosDevicesSd);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Now create a directory for this session */
    _swprintf(SessionBuffer, L"%ws\\%ld", SESSION_ROOT, Session);
    RtlInitUnicodeString(&SessionString, SessionBuffer);

    /* Create the directory */
    InitializeObjectAttributes(&ObjectAttributes, &SessionString,
			       OBJ_OPENIF | OBJ_CASE_INSENSITIVE, 0, &DosDevicesSd);
    Status = NtCreateDirectoryObject(&SessionObjectDirectory, DIRECTORY_ALL_ACCESS,
				     &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: NtCreateDirectoryObject failed in "
		"CsrCreateSessionObjectDirectory - status = %x\n",
		Status);
	FreeDosDevicesProtection(&DosDevicesSd);
	return Status;
    }

    if (Session == 0) {
	UNICODE_STRING WindowsString = RTL_CONSTANT_STRING(L"\\Windows");

	RtlInitUnicodeString(&SessionString, L"Windows");
	InitializeObjectAttributes(&ObjectAttributes, &SessionString,
				   OBJ_OPENIF | OBJ_CASE_INSENSITIVE,
				   SessionObjectDirectory, NULL);
	Status = NtCreateSymbolicLinkObject(&BnoHandle, SYMBOLIC_LINK_ALL_ACCESS,
					    &ObjectAttributes, &WindowsString);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("CSRSS: NtCreateSymbolicLinkObject failed in "
		    "CsrCreateSessionObjectDirectory - status = %x\n",
		    Status);
	    FreeDosDevicesProtection(&DosDevicesSd);
	    return Status;
	}
    }

    /* Next, create a directory for this session's DOS Devices */
    RtlInitUnicodeString(&SessionString, L"DosDevices");
    InitializeObjectAttributes(&ObjectAttributes, &SessionString,
			       OBJ_OPENIF | OBJ_CASE_INSENSITIVE, SessionObjectDirectory,
			       &DosDevicesSd);
    Status = NtCreateDirectoryObject(&DosDevicesDirectory, DIRECTORY_ALL_ACCESS,
				     &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: NtCreateDirectoryObject failed in "
		"CsrCreateSessionObjectDirectory - status = %x\n",
		Status);
    }

    /* Release the Security Descriptor */
    FreeDosDevicesProtection(&DosDevicesSd);

    /* Return */
    return Status;
}

/*++
 * @name CsrParseServerCommandLine
 *
 * The CsrParseServerCommandLine routine parses the CSRSS command-line in the
 * registry and performs operations for each entry found.
 *
 * @param Arguments
 *        Unicode command-line arguments.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
static NTSTATUS CsrParseServerCommandLine(IN PCUNICODE_STRING Arguments)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWSTR CommandLine = NULL, Cursor, Argument, ParameterName, ParameterValue, EntryPoint,
	  ServerString;
    ULONG DllIndex;
    UNICODE_STRING ParameterNameString, ParameterValueString, DllIndexString;
    UNICODE_STRING DllNameString, DllEntryPointString;
    UNICODE_STRING CsrssName = RTL_CONSTANT_STRING(L"CSRSS");
    UNICODE_STRING ObjectDirectoryName = RTL_CONSTANT_STRING(L"ObjectDirectory");
    UNICODE_STRING SubSystemTypeName = RTL_CONSTANT_STRING(L"SubSystemType");
    UNICODE_STRING MaxRequestThreadsName = RTL_CONSTANT_STRING(L"MaxRequestThreads");
    UNICODE_STRING RequestThreadsName = RTL_CONSTANT_STRING(L"RequestThreads");
    UNICODE_STRING ProfileControlName = RTL_CONSTANT_STRING(L"ProfileControl");
    UNICODE_STRING SharedSectionName = RTL_CONSTANT_STRING(L"SharedSection");
    UNICODE_STRING ServerDllName = RTL_CONSTANT_STRING(L"ServerDll");
    UNICODE_STRING WindowsName = RTL_CONSTANT_STRING(L"Windows");
    UNICODE_STRING WindowsValue = RTL_CONSTANT_STRING(L"windows");
    UNICODE_STRING PosixValue = RTL_CONSTANT_STRING(L"posix");
    UNICODE_STRING Os2Value = RTL_CONSTANT_STRING(L"os2");
    UNICODE_STRING NativeValue = RTL_CONSTANT_STRING(L"native");
    UNICODE_STRING OnValue = RTL_CONSTANT_STRING(L"On");
    OBJECT_ATTRIBUTES ObjectAttributes;
    WCHAR SessionDirectory[MAX_PATH];
    INT Length;
    BOOLEAN InQuotes;
    WCHAR Character;

    /* Set the Defaults */
    CsrTotalPerProcessDataLength = 0;
    CsrObjectDirectory = NULL;
    CsrWindowsControl = FALSE;
    CsrSubSystemType = IMAGE_SUBSYSTEM_UNKNOWN;
    CsrMaxApiRequestThreads = 16;

    /* Save our Session ID, and create a Directory for it */
    SessionId = NtCurrentPeb()->SessionId;
    Status = CsrCreateSessionObjectDirectory(SessionId);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSS: CsrCreateSessionObjectDirectory failed (%x)\n", Status);

	/* It's not fatal if the session ID isn't zero */
	if (SessionId != 0)
	    return Status;
	ASSERT(NT_SUCCESS(Status));
    }

    if (!Arguments || (Arguments->Length && !Arguments->Buffer) ||
	(Arguments->Length & (sizeof(WCHAR) - 1))) {
	Status = STATUS_INVALID_PARAMETER;
	goto Cleanup;
    }

    /* Make a writable copy so that quotes can be removed and tokens split in place */
    CommandLine = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY,
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
	if (RtlEqualUnicodeString(&ParameterNameString, &ObjectDirectoryName, TRUE)) {
	    /* Check if a session ID is specified */
	    if (SessionId != 0) {
		Length = _snwprintf(SessionDirectory, ARRAYSIZE(SessionDirectory),
				    L"\\Sessions\\%lu%ls", SessionId, ParameterValue);
		if (Length < 0 || Length >= (INT)ARRAYSIZE(SessionDirectory)) {
		    Status = STATUS_NAME_TOO_LONG;
		    goto Cleanup;
		}
		if (!RtlCreateUnicodeString(&CsrDirectoryName, SessionDirectory)) {
		    Status = STATUS_NO_MEMORY;
		    goto Cleanup;
		}
	    } else if (!RtlCreateUnicodeString(&CsrDirectoryName, ParameterValue)) {
		Status = STATUS_NO_MEMORY;
		goto Cleanup;
	    }

	    /* Create it */
	    InitializeObjectAttributes(&ObjectAttributes, &CsrDirectoryName,
				       OBJ_OPENIF | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
				       NULL, NULL);
	    Status = NtCreateDirectoryObject(&CsrObjectDirectory, DIRECTORY_ALL_ACCESS,
					     &ObjectAttributes);
	    if (!NT_SUCCESS(Status))
		goto Cleanup;

	    /* Secure it */
	    Status = CsrSetDirectorySecurity(CsrObjectDirectory);
	    if (!NT_SUCCESS(Status))
		goto Cleanup;
	} else if (RtlEqualUnicodeString(&ParameterNameString, &SubSystemTypeName,
					 TRUE)) {
	    /* Well-known subsystems, specified by names */
	    if (RtlEqualUnicodeString(&ParameterValueString, &WindowsValue, TRUE)) {
		/* Behaviour compatible with Windows 7+ */
		if (CsrWindowsControl)
		    CsrSubSystemType = IMAGE_SUBSYSTEM_WINDOWS_GUI;
		else
		    CsrSubSystemType = IMAGE_SUBSYSTEM_WINDOWS_CUI;
	    } else if (RtlEqualUnicodeString(&ParameterValueString, &PosixValue, TRUE)) {
		CsrSubSystemType = IMAGE_SUBSYSTEM_POSIX_CUI;
	    } else if (RtlEqualUnicodeString(&ParameterValueString, &Os2Value, TRUE)) {
		CsrSubSystemType = IMAGE_SUBSYSTEM_OS2_CUI;
	    } else if (RtlEqualUnicodeString(&ParameterValueString, &NativeValue, TRUE)) {
		CsrSubSystemType = IMAGE_SUBSYSTEM_NATIVE;
	    } else {
		/* Another subsystem type, specified by a numerical value */
		Status = RtlUnicodeStringToInteger(&ParameterValueString, 0,
						   &CsrSubSystemType);
		if (!NT_SUCCESS(Status))
		    goto Cleanup;
	    }
	} else if (RtlEqualUnicodeString(&ParameterNameString, &MaxRequestThreadsName,
					 TRUE)) {
	    Status = RtlUnicodeStringToInteger(&ParameterValueString, 0,
					       &CsrMaxApiRequestThreads);
	    if (!NT_SUCCESS(Status))
		goto Cleanup;
	} else if (RtlEqualUnicodeString(&ParameterNameString, &RequestThreadsName,
					 TRUE)) {
	    /* Ignored */
	    Status = STATUS_SUCCESS;
	} else if (RtlEqualUnicodeString(&ParameterNameString, &ProfileControlName,
					 TRUE)) {
	    /* Related functionality ignored since NT 3.5 */
	} else if (RtlEqualUnicodeString(&ParameterNameString, &SharedSectionName,
					 TRUE)) {
	    /* Create the Section */
	    Status = CsrSrvCreateSharedSection(&ParameterValueString);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("CSRSS: *** Invalid syntax for %ls=%ls (Status == %X)\n",
			ParameterName, ParameterValue, Status);
		goto Cleanup;
	    }

	    /* Load us */
	    Status = CsrLoadServerDll(&CsrssName, NULL, CSRSRV_SERVERDLL_INDEX);
	    if (!NT_SUCCESS(Status))
		goto Cleanup;
	} else if (RtlEqualUnicodeString(&ParameterNameString, &ServerDllName, TRUE)) {
	    /* Loop the command line */
	    EntryPoint = NULL;
	    Status = STATUS_INVALID_PARAMETER;
	    ServerString = ParameterValue;
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
	    RtlInitUnicodeString(&DllIndexString, ServerString);
	    Status = RtlUnicodeStringToInteger(&DllIndexString, 10, &DllIndex);

	    /* Add a null char if it was valid */
	    if (NT_SUCCESS(Status))
		ServerString[-1] = UNICODE_NULL;

	    if (!NT_SUCCESS(Status))
		goto Cleanup;

	    RtlInitUnicodeString(&DllNameString, ParameterValue);
	    if (EntryPoint) {
		RtlInitUnicodeString(&DllEntryPointString, EntryPoint);
	    }

	    /* Load it */
	    if (CsrDebug & 1)
		DPRINT1("CSRSS: Loading ServerDll=%ls:%ls\n", ParameterValue,
			EntryPoint ? EntryPoint : L"");
	    Status = CsrLoadServerDll(&DllNameString,
				      EntryPoint ? &DllEntryPointString : NULL, DllIndex);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("CSRSS: *** Failed loading ServerDll=%ls (Status == 0x%x)\n",
			ParameterValue, Status);
		goto Cleanup;
	    }
	} else if (RtlEqualUnicodeString(&ParameterNameString, &WindowsName, TRUE)) {
	    CsrWindowsControl = RtlEqualUnicodeString(&ParameterValueString, &OnValue,
						      TRUE);
	} else {
	    /* Invalid parameter on the command line */
	    Status = STATUS_INVALID_PARAMETER;
	    goto Cleanup;
	}
    }

Cleanup:
    if (CommandLine)
	RtlFreeHeap(CsrHeap, 0, CommandLine);
    return Status;
}

/*++
 * @name CsrInitCsrRootProcess
 *
 * The CsrInitCsrRootProcess routine further initializes the CSR Root Process
 * created by CsrInitializeProcessStructure, by allocating and initializing
 * per-process data for each Server DLL.
 *
 * @param None.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrInitCsrRootProcess(VOID)
{
    PVOID ProcessData;
    PCSR_SERVER_DLL ServerDll;
    ULONG i = 0;

    /* All Server DLLs are now loaded, allocate a heap for the Root Process */
    ProcessData = RtlAllocateHeap(CsrHeap, HEAP_ZERO_MEMORY,
				  CsrTotalPerProcessDataLength);
    if (!ProcessData) {
	DPRINT1("CSRSRV:%s: RtlAllocateHeap failed (Status=%08x)\n", __FUNCTION__,
		STATUS_NO_MEMORY);
	return STATUS_NO_MEMORY;
    }

    /*
     * Our Root Process was never officially initialized,
     * so write the data for each Server DLL manually.
     */

    /* Loop every DLL */
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++) {
	/* Get the current Server */
	ServerDll = CsrLoadedServerDll[i];

	/* Is it loaded, and does it have per process data? */
	if (ServerDll && ServerDll->SizeOfProcessData) {
	    /* It does, give it part of our allocated heap */
	    CsrRootProcess->ServerData[i] = ProcessData;

	    /* Move to the next heap position */
	    ProcessData = (PVOID)((ULONG_PTR)ProcessData + ServerDll->SizeOfProcessData);
	} else {
	    /* Nothing for this Server DLL */
	    CsrRootProcess->ServerData[i] = NULL;
	}
    }

    /* Now initialize the Root Process manually as well */
    for (i = 0; i < CSR_SERVER_DLL_MAX; i++) {
	/* Get the current Server */
	ServerDll = CsrLoadedServerDll[i];

	/* Is it loaded, and does it a callback for new processes? */
	if (ServerDll && ServerDll->NewProcessCallback) {
	    /* Call the callback */
	    ServerDll->NewProcessCallback(NULL, CsrRootProcess);
	}
    }

    return STATUS_SUCCESS;
}

/*++
 * @name CsrCreateLocalSystemSD
 *
 * The CsrCreateLocalSystemSD routine creates a Security Descriptor for
 * the local account with PORT_ALL_ACCESS.
 *
 * @param LocalSystemSd
 *        Pointer to a pointer to the security descriptor to create.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrCreateLocalSystemSD(OUT PSECURITY_DESCRIPTOR *LocalSystemSd)
{
    SID_IDENTIFIER_AUTHORITY NtSidAuthority = { SECURITY_NT_AUTHORITY };
    PSID SystemSid;
    ULONG Length;
    PSECURITY_DESCRIPTOR SystemSd;
    PACL Dacl;
    NTSTATUS Status;

    /* Initialize the System SID */
    RtlAllocateAndInitializeSid(&NtSidAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0,
				0, 0, 0, &SystemSid);

    /* Get the length of the SID */
    Length = RtlLengthSid(SystemSid) + sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE);

    /* Allocate a buffer for the Security Descriptor, with SID and DACL */
    SystemSd = RtlAllocateHeap(CsrHeap, 0, SECURITY_DESCRIPTOR_MIN_LENGTH + Length);

    /* Set the pointer to the DACL */
    Dacl = (PACL)((ULONG_PTR)SystemSd + SECURITY_DESCRIPTOR_MIN_LENGTH);

    /* Now create the SD itself */
    Status = RtlCreateSecurityDescriptor(SystemSd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(Status))
	goto Quit;

    /* Create the DACL for it */
    RtlCreateAcl(Dacl, Length, ACL_REVISION2);

    /* Create the ACE */
    Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, PORT_ALL_ACCESS, SystemSid);
    if (!NT_SUCCESS(Status))
	goto Quit;

    /* Clear the DACL in the SD */
    Status = RtlSetDaclSecurityDescriptor(SystemSd, TRUE, Dacl, FALSE);
    if (!NT_SUCCESS(Status))
	goto Quit;

Quit:
    if (!NT_SUCCESS(Status)) {
	RtlFreeHeap(CsrHeap, 0, SystemSd);
	SystemSd = NULL;
    }

    /* Free the SID and return*/
    RtlFreeSid(SystemSid);
    *LocalSystemSd = SystemSd;
    return Status;
}

/*++
 * @name CsrSbApiPortInitialize
 *
 * The CsrSbApiPortInitialize routine initializes the LPC Port used for
 * communications with the Session Manager (SM) and initializes the static
 * thread that will handle connection requests and APIs.
 *
 * @param None
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrSbApiPortInitialize(VOID)
{
    ULONG Size;
    PSECURITY_DESCRIPTOR PortSd;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;
    HANDLE hRequestThread;
    CLIENT_ID ClientId;

    /* Calculate how much space we'll need for the Port Name */
    Size = CsrDirectoryName.Length + sizeof(SB_PORT_NAME) + sizeof(WCHAR);

    /* Create the buffer for it */
    CsrSbApiPortName.Buffer = RtlAllocateHeap(CsrHeap, 0, Size);
    if (!CsrSbApiPortName.Buffer)
	return STATUS_NO_MEMORY;

    /* Setup the rest of the empty string */
    CsrSbApiPortName.Length = 0;
    CsrSbApiPortName.MaximumLength = (USHORT)Size;

    /* Now append the full port name */
    RtlAppendUnicodeStringToString(&CsrSbApiPortName, &CsrDirectoryName);
    RtlAppendUnicodeToString(&CsrSbApiPortName, UNICODE_PATH_SEP);
    RtlAppendUnicodeToString(&CsrSbApiPortName, SB_PORT_NAME);
    if (CsrDebug & 2)
	DPRINT1("CSRSS: Creating %wZ port and associated thread\n", &CsrSbApiPortName);

    /* Create Security Descriptor for this Port */
    Status = CsrCreateLocalSystemSD(&PortSd);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Initialize the Attributes */
    InitializeObjectAttributes(&ObjectAttributes, &CsrSbApiPortName, 0, NULL, PortSd);

    /* Create the Port Object */
    Status = NtCreatePort(&CsrSbApiPort, &CsrSbApiCommPort,
			  &ObjectAttributes, sizeof(SB_API_MSG));
    if (PortSd)
	RtlFreeHeap(CsrHeap, 0, PortSd);

    if (NT_SUCCESS(Status)) {
	/* Create the Thread to handle the API Requests */
	Status = RtlCreateUserThread(NtCurrentProcess(), NULL, TRUE, 0, 0, 0,
				     (PVOID)CsrSbApiRequestThread, NULL, &hRequestThread,
				     &ClientId);
	if (NT_SUCCESS(Status)) {
	    /* Add it as a Static Server Thread */
	    CsrSbApiRequestThreadPtr = CsrAddStaticServerThread(hRequestThread, &ClientId,
								0);

	    /* Activate it */
	    Status = NtResumeThread(hRequestThread, NULL);
	}
    }

    return Status;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*++
 * @name CsrServerInitialization
 * @implemented NT4
 *
 * The CsrServerInitialization routine is the native (not Server) entrypoint
 * of this Server DLL. It serves as the entrypoint for CSRSS.
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
    NTSTATUS Status = STATUS_SUCCESS;

    /* Cache System Basic Information so we don't always request it */
    Status = NtQuerySystemInformation(SystemBasicInformation, &CsrNtSysInfo,
				      sizeof(SYSTEM_BASIC_INFORMATION), NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: NtQuerySystemInformation failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Save our Heap */
    CsrHeap = RtlGetProcessHeap();

    /* Set our Security Descriptor to protect the process */
    Status = CsrSetProcessSecurity();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrSetProcessSecurity failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Set up Session Support */
    Status = CsrInitializeNtSessionList();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrInitializeSessions failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Set up Process Support and allocate the CSR Root Process */
    Status = CsrInitializeProcessStructure();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrInitializeProcessStructure failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Parse the command line */
    Status = CsrParseServerCommandLine(Arguments);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrParseServerCommandLine failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Finish to initialize the CSR Root Process */
    Status = CsrInitCsrRootProcess();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrInitCsrRootProcess failed (Status=0x%08x)\n",
		__FUNCTION__, Status);
	return Status;
    }

    /* Now initialize our API Port */
    Status = CsrApiPortInitialize();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("CSRSRV:%s: CsrApiPortInitialize failed (Status=0x%08x)\n", __FUNCTION__,
		Status);
	return Status;
    }

    if (CsrSubSystemType != IMAGE_SUBSYSTEM_UNKNOWN) {
	/* Initialize the API Port for SM communication */
	Status = CsrSbApiPortInitialize();
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("CSRSRV:%s: CsrSbApiPortInitialize failed (Status=0x%08x)\n",
		    __FUNCTION__, Status);
	    return Status;
	}

	/* We're all set! Connect to SM! */
	Status = SmConnectToSm(&CsrSbApiPortName, CsrSbApiCommPort, CsrSubSystemType,
			       &CsrSmApiCommPort);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("CSRSRV:%s: SmConnectToSm failed (Status=0x%08x)\n", __FUNCTION__,
		    Status);
	    return Status;
	}
    }

    /* Return status */
    return Status;
}

/*++
 * @name CsrPopulateDosDevices
 * @unimplemented NT5.1
 *
 * The CsrPopulateDosDevices routine uses the DOS Device Map from the Kernel
 * to populate the Dos Devices Object Directory for the session.
 *
 * @param None.
 *
 * @return None.
 *
 * @remarks None.
 *
 *--*/
NTAPI VOID CsrPopulateDosDevices(VOID)
{
    DPRINT1("Deprecated API in r55585.\n");
    return;
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
