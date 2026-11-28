/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Base API Server DLL
 * FILE:            subsystems/win/basesrv/init.c
 * PURPOSE:         Initialization
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 *                  Pierre Schweitzer (pierre@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "basesrv.h"
#include <winreg.h>
#include "api.h"

/* GLOBALS ********************************************************************/

HANDLE BaseSrvDllInstance = NULL;
extern UNICODE_STRING BaseSrvKernel32DllPath;

/* Memory */
HANDLE BaseSrvHeap = NULL; // Our own heap.
HANDLE BaseSrvSharedHeap = NULL; // Shared heap with CSR. (CsrSrvSharedSectionHeap)
PBASE_STATIC_SERVER_DATA BaseStaticServerData = NULL; // Data that we can share amongst
						      // processes. Initialized inside
						      // BaseSrvSharedHeap.

ULONG SessionId = 0;
ULONG ProtectionMode = 0;

// Windows Server 2003 table from
// http://j00ru.vexillium.org/csrss_list/api_list.html#Windows_2k3
PCSR_API_ROUTINE BaseServerApiDispatchTable[] = {
    BaseSrvCreateProcess,
    BaseSrvCreateThread,
    BaseSrvGetTempFile,
    BaseSrvExitProcess,
    BaseSrvDebugProcess,
    BaseSrvSetProcessShutdownParam,
    BaseSrvGetProcessShutdownParam,
    BaseSrvNlsSetUserInfo,
    BaseSrvNlsSetMultipleUserInfo,
    BaseSrvNlsCreateSection,
    BaseSrvSoundSentryNotification,
    BaseSrvDefineDosDevice,
    BaseSrvSetTermsrvAppInstallMode,
    BaseSrvNlsUpdateCacheCount,
    BaseSrvSetTermsrvClientTimeZone,
    BaseSrvSxsCreateActivationContext,
    BaseSrvDebugProcess,
    BaseSrvRegisterThread,
    BaseSrvNlsGetUserInfo,
};
C_ASSERT(ARRAYSIZE(BaseServerApiDispatchTable) == BasepMaxApiNumber - BASESRV_FIRST_API_NUMBER);

/*
 * On Windows Server 2003, CSR Servers contain
 * the API Names Table only in Debug Builds.
 */
#ifdef CSR_DBG
PCHAR BaseServerApiNameTable[] = {
    "BaseCreateProcess",
    "BaseCreateThread",
    "BaseGetTempFile",
    "BaseExitProcess",
    "BaseDebugProcess",
    "BaseSetProcessShutdownParam",
    "BaseGetProcessShutdownParam",
    "BaseNlsSetUserInfo",
    "BaseNlsSetMultipleUserInfo",
    "BaseNlsCreateSection",
    "BaseSoundSentryNotification",
    "BaseDefineDosDevice",
    "BaseSetTermsrvAppInstallMode",
    "BaseNlsUpdateCacheCount",
    "BaseSetTermsrvClientTimeZone",
    "BaseSxsCreateActivationContext",
    "BaseSrvDebugProcessStop",
    "BaseRegisterThread",
    "BaseNlsGetUserInfo",
};
C_ASSERT(ARRAYSIZE(BaseServerApiNameTable) == BasepMaxApiNumber - BASESRV_FIRST_API_NUMBER);
#endif

/* FUNCTIONS ******************************************************************/

static HANDLE BaseSrvAppContainerObjectDirectory;

static VOID BaseSrvCreateAppContainerDirectory(IN ULONG SessionId,
					       IN PSECURITY_DESCRIPTOR LabeledSd)
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY WorldAuthority = { SECURITY_WORLD_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY PackageAuthority = { SECURITY_APP_PACKAGE_AUTHORITY };
    PSID SystemSid = NULL, WorldSid = NULL, AllPackagesSid = NULL,
	 AllRestrictedSid = NULL;
    PACL Dacl = NULL, Sacl = NULL;
    BOOLEAN SaclPresent = FALSE, SaclDefaulted = FALSE;
    SECURITY_DESCRIPTOR Sd;
    UNICODE_STRING Name;
    WCHAR Buffer[64];
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG AclLength;
    ACCESS_MASK PackageAccess = DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
				DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;
    NTSTATUS Status;

    Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0,
					 0, 0, 0, 0, 0, &SystemSid);
    if (!NT_SUCCESS(Status))
	goto Quit;
    Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0,
					 0, 0, 0, 0, &WorldSid);
    if (!NT_SUCCESS(Status))
	goto Quit;
    Status = RtlAllocateAndInitializeSid(&PackageAuthority, 2,
					 SECURITY_APP_PACKAGE_BASE_RID,
					 SECURITY_BUILTIN_PACKAGE_ANY_PACKAGE, 0, 0, 0, 0,
					 0, 0, &AllPackagesSid);
    if (!NT_SUCCESS(Status))
	goto Quit;
    Status = RtlAllocateAndInitializeSid(&PackageAuthority, 2,
					 SECURITY_APP_PACKAGE_BASE_RID,
					 SECURITY_BUILTIN_PACKAGE_ANY_RESTRICTED_PACKAGE,
					 0, 0, 0, 0, 0, 0, &AllRestrictedSid);
    if (!NT_SUCCESS(Status))
	goto Quit;

    AclLength = sizeof(ACL) + 4 * FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
		RtlLengthSid(SystemSid) + RtlLengthSid(WorldSid) +
		RtlLengthSid(AllPackagesSid) + RtlLengthSid(AllRestrictedSid);
    Dacl = RtlAllocateHeap(BaseSrvHeap, 0, AclLength);
    if (!Dacl)
	goto Quit;
    Status = RtlCreateAcl(Dacl, AclLength, ACL_REVISION);
    if (NT_SUCCESS(Status))
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, DIRECTORY_ALL_ACCESS,
					SystemSid);
    if (NT_SUCCESS(Status))
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, PackageAccess, WorldSid);
    if (NT_SUCCESS(Status))
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, PackageAccess,
					AllPackagesSid);
    if (NT_SUCCESS(Status))
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, PackageAccess,
					AllRestrictedSid);
    if (NT_SUCCESS(Status))
	Status = RtlCreateSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
	Status = RtlSetDaclSecurityDescriptor(&Sd, TRUE, Dacl, FALSE);
    if (NT_SUCCESS(Status))
	Status = RtlGetSaclSecurityDescriptor(LabeledSd, &SaclPresent, &Sacl,
					      &SaclDefaulted);
    if (NT_SUCCESS(Status) && SaclPresent)
	Status = RtlSetSaclSecurityDescriptor(&Sd, TRUE, Sacl, FALSE);
    if (!NT_SUCCESS(Status))
	goto Quit;

    _swprintf(Buffer, L"\\Sessions\\%lu\\AppContainerNamedObjects", SessionId);
    RtlInitUnicodeString(&Name, Buffer);
    InitializeObjectAttributes(&ObjectAttributes, &Name,
			       OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE, NULL,
			       &Sd);
    Status = NtCreateDirectoryObject(&BaseSrvAppContainerObjectDirectory,
				     DIRECTORY_ALL_ACCESS, &ObjectAttributes);
    if (!NT_SUCCESS(Status))
	DPRINT1("BASESRV: AppContainerNamedObjects creation failed 0x%x\n", Status);

Quit:
    if (Dacl)
	RtlFreeHeap(BaseSrvHeap, 0, Dacl);
    if (AllRestrictedSid)
	RtlFreeSid(AllRestrictedSid);
    if (AllPackagesSid)
	RtlFreeSid(AllPackagesSid);
    if (WorldSid)
	RtlFreeSid(WorldSid);
    if (SystemSid)
	RtlFreeSid(SystemSid);
}

NTSTATUS
NTAPI
CreateBaseAcls(OUT PACL *Dacl, OUT PACL *RestrictedDacl)
{
    PSID SystemSid, WorldSid, RestrictedSid, AdminsSid, CreatorOwnerSid;
    SID_IDENTIFIER_AUTHORITY CreatorAuthority = { SECURITY_CREATOR_SID_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
    SID_IDENTIFIER_AUTHORITY WorldAuthority = { SECURITY_WORLD_SID_AUTHORITY };
    NTSTATUS Status;
    UCHAR KeyValueBuffer[0x40];
    PKEY_VALUE_PARTIAL_INFORMATION KeyValuePartialInfo;
    UNICODE_STRING KeyName;
    ULONG AclLength;
    ULONG ResultLength;
    HANDLE hKey;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ULONG ObjectSecurityMode;
    ACCESS_MASK WorldAccess, RestrictedAccess;

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

    /* Get object security mode */
    if (SessionId == 0 ||
	!NT_SUCCESS(NtQuerySystemInformation(SystemObjectSecurityMode,
					     &ObjectSecurityMode, sizeof(ULONG), NULL))) {
	ObjectSecurityMode = 0;
    }

    /* Allocate the System SID */
    Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0,
					 0, 0, 0, 0, 0, &SystemSid);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Allocate the World SID */
    Status = RtlAllocateAndInitializeSid(&WorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0,
					 0, 0, 0, 0, &WorldSid);
    if (!NT_SUCCESS(Status)) {
	RtlFreeSid(SystemSid);
	goto Return;
    }

    /* Allocate the restricted SID */
    Status = RtlAllocateAndInitializeSid(&NtAuthority, 1, SECURITY_RESTRICTED_CODE_RID, 0,
					 0, 0, 0, 0, 0, 0, &RestrictedSid);
    if (!NT_SUCCESS(Status)) {
	RtlFreeSid(WorldSid);
	RtlFreeSid(SystemSid);
	goto Return;
    }

    Status = RtlAllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
					 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
					 &AdminsSid);
    if (!NT_SUCCESS(Status)) {
	RtlFreeSid(RestrictedSid);
	RtlFreeSid(WorldSid);
	RtlFreeSid(SystemSid);
	goto Return;
    }

    Status = RtlAllocateAndInitializeSid(&CreatorAuthority, 1, SECURITY_CREATOR_OWNER_RID,
					 0, 0, 0, 0, 0, 0, 0, &CreatorOwnerSid);
    if (!NT_SUCCESS(Status)) {
	RtlFreeSid(AdminsSid);
	RtlFreeSid(RestrictedSid);
	RtlFreeSid(WorldSid);
	RtlFreeSid(SystemSid);
	goto Return;
    }

    AclLength = sizeof(ACL) + 6 * sizeof(ACCESS_ALLOWED_ACE) +
		2 * RtlLengthSid(SystemSid) + RtlLengthSid(WorldSid) +
		RtlLengthSid(RestrictedSid) + RtlLengthSid(AdminsSid) +
		RtlLengthSid(CreatorOwnerSid);
    *Dacl = RtlAllocateHeap(BaseSrvHeap, 0, AclLength);
    if (*Dacl == NULL) {
	Status = STATUS_NO_MEMORY;
	goto FreeAndReturn;
    }

    /* Set the correct header fields */
    Status = RtlCreateAcl(*Dacl, AclLength, ACL_REVISION2);
    if (!NT_SUCCESS(Status)) {
	RtlFreeHeap(BaseSrvHeap, 0, *Dacl);
	goto FreeAndReturn;
    }

    /* Setup access for anyone depending on object security mode */
    if (ObjectSecurityMode != 0) {
	/*
	 * If we have restrictions on security mode, make it read only
	 * it also means session ID is not 0
	 */
	WorldAccess = DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    } else {
	/* Otherwise, open wide */
	WorldAccess = READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
		      DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;
    }

    /* Give the appropriate rights to each SID */
    if (ObjectSecurityMode != 0) {
	Status = RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2, DIRECTORY_ALL_ACCESS,
					SystemSid);
	if (NT_SUCCESS(Status))
	    Status = RtlAddAccessAllowedAceEx(*Dacl, ACL_REVISION2,
					      OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
						  INHERIT_ONLY_ACE,
					      GENERIC_ALL, SystemSid);
	if (NT_SUCCESS(Status))
	    Status = RtlAddAccessAllowedAceEx(*Dacl, ACL_REVISION2,
					      OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
						  INHERIT_ONLY_ACE,
					      GENERIC_ALL, CreatorOwnerSid);
	if (NT_SUCCESS(Status))
	    Status = RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2,
					    READ_CONTROL | DIRECTORY_QUERY |
						DIRECTORY_TRAVERSE |
						DIRECTORY_CREATE_OBJECT |
						DIRECTORY_CREATE_SUBDIRECTORY,
					    AdminsSid);
	if (NT_SUCCESS(Status))
	    Status = RtlAddAccessAllowedAceEx(*Dacl, ACL_REVISION2, CONTAINER_INHERIT_ACE,
					      WorldAccess, WorldSid);
	if (NT_SUCCESS(Status))
	    RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2, DIRECTORY_TRAVERSE,
				   RestrictedSid);
    } else if (NT_SUCCESS(
		   RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2, WorldAccess, WorldSid)) &&
	       NT_SUCCESS(RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2,
						 DIRECTORY_ALL_ACCESS, SystemSid))) {
	RtlAddAccessAllowedAce(*Dacl, ACL_REVISION2, DIRECTORY_TRAVERSE, RestrictedSid);
    }

    /* Now allocate the restricted DACL */
    *RestrictedDacl = RtlAllocateHeap(BaseSrvHeap, 0, AclLength);
    if (*RestrictedDacl == NULL) {
	Status = STATUS_NO_MEMORY;
	RtlFreeHeap(BaseSrvHeap, 0, *Dacl);
	goto FreeAndReturn;
    }

    /* Initialize it */
    Status = RtlCreateAcl(*RestrictedDacl, AclLength, ACL_REVISION2);
    if (!NT_SUCCESS(Status)) {
	RtlFreeHeap(BaseSrvHeap, 0, *RestrictedDacl);
	RtlFreeHeap(BaseSrvHeap, 0, *Dacl);
	goto FreeAndReturn;
    }

    /* Setup access for restricted sid depending on session id and protection mode */
    if (SessionId == 0 || (ProtectionMode & 3) == 0) {
	/* If we have no session ID or if protection mode is not set, then open wide */
	RestrictedAccess = READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
			   DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;
    } else {
	/* Otherwise, make read only */
	RestrictedAccess = READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE;
    }

    /* And add the same ACEs as before */
    Status = RtlAddAccessAllowedAce(*RestrictedDacl, ACL_REVISION2, WorldAccess,
				    WorldSid);
    if (NT_SUCCESS(Status)) {
	Status = RtlAddAccessAllowedAce(*RestrictedDacl, ACL_REVISION2,
					DIRECTORY_ALL_ACCESS, SystemSid);
	if (NT_SUCCESS(Status)) {
	    Status = RtlAddAccessAllowedAce(*RestrictedDacl, ACL_REVISION2,
					    RestrictedAccess, RestrictedSid);
	}
    }

    /* The SIDs are captured, can free them now */
FreeAndReturn:
    RtlFreeSid(CreatorOwnerSid);
    RtlFreeSid(AdminsSid);
    RtlFreeSid(RestrictedSid);
    RtlFreeSid(WorldSid);
    RtlFreeSid(SystemSid);

Return:
    return Status;
}

VOID NTAPI BaseInitializeStaticServerData(IN PCSR_SERVER_DLL LoadedServerDll)
{
    NTSTATUS Status;
    BOOLEAN Success;
    WCHAR BnoBuffer[100];
    WCHAR Buffer[MAX_PATH];
    PWCHAR HeapBuffer;
    UNICODE_STRING SystemRootString;
    UNICODE_STRING UnexpandedSystemRootString = RTL_CONSTANT_STRING(L"%SystemRoot%");
    UNICODE_STRING BaseSrvCSDString;
    UNICODE_STRING BaseSrvWindowsDirectory;
    UNICODE_STRING BaseSrvWindowsSystemDirectory;
    UNICODE_STRING BnoString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE BaseSrvNamedObjectDirectory;
    HANDLE BaseSrvRestrictedObjectDirectory;
    PACL BnoDacl, BnoRestrictedDacl;
    PSECURITY_DESCRIPTOR BnoSd;
    HANDLE SymHandle;
    UNICODE_STRING DirectoryName, SymlinkName;
    ULONG LuidEnabled;
    RTL_QUERY_REGISTRY_TABLE BaseServerRegistryConfigurationTable[2] = {
	{ NULL, RTL_QUERY_REGISTRY_DIRECT, L"CSDVersion", &BaseSrvCSDString, REG_NONE,
	  NULL, 0 },

	{ 0 }
    };

    /* Initialize the memory */
    BaseSrvHeap = RtlGetProcessHeap(); // Initialize our own heap.
    BaseSrvSharedHeap = LoadedServerDll->SharedSection; // Get the CSR shared heap.

    /* Get the session ID */
    SessionId = NtCurrentPeb()->SessionId;

    /* Get the Windows directory */
    RtlInitEmptyUnicodeString(&SystemRootString, Buffer, sizeof(Buffer));
    Status = RtlExpandEnvironmentStrings_U(NULL, &UnexpandedSystemRootString,
					   &SystemRootString, NULL);
    ASSERT(NT_SUCCESS(Status));

    /* Create the base directory */
    Buffer[SystemRootString.Length / sizeof(WCHAR)] = UNICODE_NULL;
    Success = RtlCreateUnicodeString(&BaseSrvWindowsDirectory, SystemRootString.Buffer);
    ASSERT(Success);

    /* Create the system directory */
    wcscat(SystemRootString.Buffer, L"\\system32");
    Success = RtlCreateUnicodeString(&BaseSrvWindowsSystemDirectory,
				     SystemRootString.Buffer);
    ASSERT(Success);

    /* Create the kernel32 path */
    wcscat(SystemRootString.Buffer, L"\\kernel32.dll");
    Success = RtlCreateUnicodeString(&BaseSrvKernel32DllPath, SystemRootString.Buffer);
    ASSERT(Success);

    if (SessionId != 0) {
	_swprintf(BnoBuffer, L"\\Sessions\\%ld\\BaseNamedObjects", SessionId);
    } else {
	wcscpy(BnoBuffer, L"\\BaseNamedObjects");
    }
    RtlInitUnicodeString(&BnoString, BnoBuffer);

    /* Allocate the server data */
    BaseStaticServerData = RtlAllocateHeap(BaseSrvSharedHeap, HEAP_ZERO_MEMORY,
					   sizeof(BASE_STATIC_SERVER_DATA));
    ASSERT(BaseStaticServerData != NULL);

    /* Process timezone information */
    BaseStaticServerData->TermsrvClientTimeZoneId = TIME_ZONE_ID_INVALID;
    BaseStaticServerData->TermsrvClientTimeZoneChangeNum = 0;
    Status = NtQuerySystemInformation(SystemTimeOfDayInformation,
				      &BaseStaticServerData->TimeOfDay,
				      sizeof(BaseStaticServerData->TimeOfDay), NULL);
    ASSERT(NT_SUCCESS(Status));

    /* Make a shared heap copy of the Windows directory */
    BaseStaticServerData->WindowsDirectory = BaseSrvWindowsDirectory;
    HeapBuffer = RtlAllocateHeap(BaseSrvSharedHeap, 0,
				 BaseSrvWindowsDirectory.MaximumLength);
    ASSERT(HeapBuffer);
    RtlCopyMemory(HeapBuffer, BaseStaticServerData->WindowsDirectory.Buffer,
		  BaseSrvWindowsDirectory.MaximumLength);
    BaseStaticServerData->WindowsDirectory.Buffer = HeapBuffer;

    /* Make a shared heap copy of the System directory */
    BaseStaticServerData->WindowsSystemDirectory = BaseSrvWindowsSystemDirectory;
    HeapBuffer = RtlAllocateHeap(BaseSrvSharedHeap, 0,
				 BaseSrvWindowsSystemDirectory.MaximumLength);
    ASSERT(HeapBuffer);
    RtlCopyMemory(HeapBuffer, BaseStaticServerData->WindowsSystemDirectory.Buffer,
		  BaseSrvWindowsSystemDirectory.MaximumLength);
    BaseStaticServerData->WindowsSystemDirectory.Buffer = HeapBuffer;

    /* This string is not used */
    RtlInitEmptyUnicodeString(&BaseStaticServerData->WindowsSys32x86Directory, NULL, 0);

    /* Make a shared heap copy of the BNO directory */
    BaseStaticServerData->NamedObjectDirectory = BnoString;
    BaseStaticServerData->NamedObjectDirectory.MaximumLength = BnoString.Length +
							       sizeof(UNICODE_NULL);
    HeapBuffer = RtlAllocateHeap(
	BaseSrvSharedHeap, 0, BaseStaticServerData->NamedObjectDirectory.MaximumLength);
    ASSERT(HeapBuffer);
    RtlCopyMemory(HeapBuffer, BaseStaticServerData->NamedObjectDirectory.Buffer,
		  BaseStaticServerData->NamedObjectDirectory.MaximumLength);
    BaseStaticServerData->NamedObjectDirectory.Buffer = HeapBuffer;

    /*
     * Confirmed that in Windows, CSDNumber and RCNumber are actually Length
     * and MaximumLength of the CSD String, since the same UNICODE_STRING is
     * being queried twice, the first time as a ULONG!
     *
     * Somehow, in Windows this doesn't cause a buffer overflow, but it might
     * in ReactOS, so this code is disabled until someone figures out WTF.
     */
    BaseStaticServerData->CSDNumber = 0;
    BaseStaticServerData->RCNumber = 0;

    /* Initialize the CSD string and query its value from the registry */
    RtlInitEmptyUnicodeString(&BaseSrvCSDString, Buffer, sizeof(Buffer));
    Status = RtlQueryRegistryValues(RTL_REGISTRY_WINDOWS_NT, L"",
				    BaseServerRegistryConfigurationTable, NULL, NULL);
    if (NT_SUCCESS(Status)) {
	/* Copy into the shared buffer */
	wcsncpy(BaseStaticServerData->CSDVersion, BaseSrvCSDString.Buffer,
		BaseSrvCSDString.Length / sizeof(WCHAR));
    } else {
	/* Indicate nothing is there */
	BaseSrvCSDString.Length = 0;
    }
    /* NULL-terminate */
    BaseStaticServerData->CSDVersion[BaseSrvCSDString.Length / sizeof(WCHAR)] =
	UNICODE_NULL;

    /* Cache the system information */
    Status = NtQuerySystemInformation(SystemBasicInformation,
				      &BaseStaticServerData->SysInfo,
				      sizeof(BaseStaticServerData->SysInfo), NULL);
    ASSERT(NT_SUCCESS(Status));

    /* Allocate a security descriptor and create it */
    BnoSd = RtlAllocateHeap(BaseSrvHeap, 0, 1024);
    ASSERT(BnoSd);
    Status = RtlCreateSecurityDescriptor(BnoSd, SECURITY_DESCRIPTOR_REVISION);
    ASSERT(NT_SUCCESS(Status));

    /* Create the BNO and \Restricted DACLs */
    Status = CreateBaseAcls(&BnoDacl, &BnoRestrictedDacl);
    ASSERT(NT_SUCCESS(Status));

    /* Set the BNO DACL as active for now */
    Status = RtlSetDaclSecurityDescriptor(BnoSd, TRUE, BnoDacl, FALSE);
    ASSERT(NT_SUCCESS(Status));

    {
	SID_IDENTIFIER_AUTHORITY LabelAuthority = { SECURITY_MANDATORY_LABEL_AUTHORITY };
	PSID LowSid = NULL;
	PACL LabelSacl;
	ULONG SaclSize;

	Status = RtlAllocateAndInitializeSid(&LabelAuthority, 1,
					     SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0,
					     0, &LowSid);
	ASSERT(NT_SUCCESS(Status));
	SaclSize = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) +
		   RtlLengthSid(LowSid);
	LabelSacl = RtlAllocateHeap(BaseSrvHeap, 0, SaclSize);
	ASSERT(LabelSacl);
	Status = RtlCreateAcl(LabelSacl, SaclSize, ACL_REVISION);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlAddMandatoryAce(LabelSacl, ACL_REVISION, 0,
				    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
				    SYSTEM_MANDATORY_LABEL_ACE_TYPE, LowSid);
	ASSERT(NT_SUCCESS(Status));
	Status = RtlSetSaclSecurityDescriptor(BnoSd, TRUE, LabelSacl, FALSE);
	ASSERT(NT_SUCCESS(Status));
    }

    /* Create the BNO directory */
    InitializeObjectAttributes(&ObjectAttributes, &BnoString,
			       OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE, NULL,
			       BnoSd);
    Status = NtCreateDirectoryObject(&BaseSrvNamedObjectDirectory, DIRECTORY_ALL_ACCESS,
				     &ObjectAttributes);
    ASSERT(NT_SUCCESS(Status));
    if (Status == STATUS_OBJECT_NAME_EXISTS) {
	Status = NtSetSecurityObject(BaseSrvNamedObjectDirectory,
				     DACL_SECURITY_INFORMATION |
					 LABEL_SECURITY_INFORMATION,
				     BnoSd);
	ASSERT(NT_SUCCESS(Status));
    }

    BaseSrvCreateAppContainerDirectory(SessionId, BnoSd);

    /* Check if we are session 0 */
    if (SessionId == 0) {
	/* Mark this as a session 0 directory */
	Status = NtSetInformationObject(BaseSrvNamedObjectDirectory,
					ObjectSessionInformation, NULL, 0);
	ASSERT(NT_SUCCESS(Status));
    }

    /* Check if LUID device maps are enabled */
    Status = NtQueryInformationProcess(NtCurrentProcess(), ProcessLUIDDeviceMapsEnabled,
				       &LuidEnabled, sizeof(LuidEnabled), NULL);
    ASSERT(NT_SUCCESS(Status));
    BaseStaticServerData->LUIDDeviceMapsEnabled = (BOOLEAN)LuidEnabled;

    /* Initialize Global */
    if (!BaseStaticServerData->LUIDDeviceMapsEnabled ||
	NT_SUCCESS(RtlInitializeCriticalSectionAndSpinCount(&BaseSrvDDDBSMCritSec,
							    0x80000000))) {
	/* Make Global point back to BNO */
	RtlInitUnicodeString(&DirectoryName, L"Global");
	RtlInitUnicodeString(&SymlinkName, L"\\BaseNamedObjects");
	InitializeObjectAttributes(&ObjectAttributes, &DirectoryName,
				   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
				   BaseSrvNamedObjectDirectory, BnoSd);
	Status = NtCreateSymbolicLinkObject(&SymHandle, SYMBOLIC_LINK_ALL_ACCESS,
					    &ObjectAttributes, &SymlinkName);
	if ((NT_SUCCESS(Status)) && SessionId == 0)
	    NtClose(SymHandle);

	/* Make local point back to \Sessions\x\BNO */
	RtlInitUnicodeString(&DirectoryName, L"Local");
	InitializeObjectAttributes(&ObjectAttributes, &DirectoryName,
				   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
				   BaseSrvNamedObjectDirectory, BnoSd);
	Status = NtCreateSymbolicLinkObject(&SymHandle, SYMBOLIC_LINK_ALL_ACCESS,
					    &ObjectAttributes, &BnoString);
	if ((NT_SUCCESS(Status)) && SessionId == 0)
	    NtClose(SymHandle);

	/* Make Session point back to BNOLINKS */
	RtlInitUnicodeString(&DirectoryName, L"Session");
	RtlInitUnicodeString(&SymlinkName, L"\\Sessions\\BNOLINKS");
	InitializeObjectAttributes(&ObjectAttributes, &DirectoryName,
				   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
				   BaseSrvNamedObjectDirectory, BnoSd);
	Status = NtCreateSymbolicLinkObject(&SymHandle, SYMBOLIC_LINK_ALL_ACCESS,
					    &ObjectAttributes, &SymlinkName);
	if ((NT_SUCCESS(Status)) && SessionId == 0)
	    NtClose(SymHandle);

	/* Create the BNO\Restricted directory and set the restricted DACL */
	RtlInitUnicodeString(&DirectoryName, L"Restricted");
	Status = RtlSetDaclSecurityDescriptor(BnoSd, TRUE, BnoRestrictedDacl, FALSE);
	ASSERT(NT_SUCCESS(Status));
	InitializeObjectAttributes(&ObjectAttributes, &DirectoryName,
				   OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
				   BaseSrvNamedObjectDirectory, BnoSd);
	Status = NtCreateDirectoryObject(&BaseSrvRestrictedObjectDirectory,
					 DIRECTORY_ALL_ACCESS, &ObjectAttributes);
	ASSERT(NT_SUCCESS(Status));
    } else {
	/* That should never happen */
	ASSERT(FALSE);
    }

    /* Initialize NLS */
    BaseSrvNLSInit(BaseStaticServerData);

    /* Finally, set the pointer */
    LoadedServerDll->SharedSection = BaseStaticServerData;
}

NTSTATUS
NTAPI
BaseClientConnectRoutine(IN PCSR_PROCESS CsrProcess, IN OUT PVOID ConnectionInfo,
			 IN OUT PULONG ConnectionInfoLength)
{
    PBASESRV_API_CONNECTINFO ConnectInfo = (PBASESRV_API_CONNECTINFO)ConnectionInfo;

    if (ConnectionInfo == NULL || ConnectionInfoLength == NULL ||
	*ConnectionInfoLength != sizeof(*ConnectInfo)) {
	DPRINT1("BASESRV: Connection failed - ConnectionInfo = 0x%p ; "
		"ConnectionInfoLength = 0x%p (%u), expected %zu\n",
		ConnectionInfo, ConnectionInfoLength,
		ConnectionInfoLength ? *ConnectionInfoLength : (ULONG)-1,
		sizeof(*ConnectInfo));

	return STATUS_INVALID_PARAMETER;
    }

    /* Do the NLS connection */
    return BaseSrvNlsConnect(CsrProcess, ConnectionInfo, ConnectionInfoLength);
}

VOID NTAPI BaseClientDisconnectRoutine(IN PCSR_PROCESS CsrProcess)
{
    /* Do nothing */
}

CSR_SERVER_DLL_INIT(ServerDllInitialization)
{
    /* Setup the DLL Object */
    LoadedServerDll->ApiBase = BASESRV_FIRST_API_NUMBER;
    LoadedServerDll->HighestApiSupported = BasepMaxApiNumber;
    LoadedServerDll->DispatchTable = BaseServerApiDispatchTable;
#ifdef CSR_DBG
    LoadedServerDll->NameTable = BaseServerApiNameTable;
#endif
    LoadedServerDll->ConnectCallback = BaseClientConnectRoutine;
    LoadedServerDll->DisconnectCallback = BaseClientDisconnectRoutine;
    LoadedServerDll->ShutdownProcessCallback = NULL;

    BaseSrvDllInstance = LoadedServerDll->ServerHandle;

    BaseInitializeStaticServerData(LoadedServerDll);

    /* Initialize DOS devices management */
    BaseInitDefineDosDevice();

    /* All done */
    return STATUS_SUCCESS;
}

BOOL NTAPI DllMain(IN HINSTANCE hInstanceDll, IN DWORD dwReason, IN LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hInstanceDll);
    UNREFERENCED_PARAMETER(dwReason);
    UNREFERENCED_PARAMETER(lpReserved);

    if (DLL_PROCESS_DETACH == dwReason) {
	BaseCleanupDefineDosDevice();
    }

    return TRUE;
}

/* EOF */
