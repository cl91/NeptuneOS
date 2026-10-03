/*
 * PROJECT:         ReactOS Win32 Base API
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            dll/win32/kernel32/client/appcache.c
 * PURPOSE:         Application Compatibility Cache
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include <k32.h>

/* GLOBALS ********************************************************************/

ULONG g_ShimsDisabled = -1;
static BOOL g_ApphelpInitialized = FALSE;
static PVOID g_pApphelpCheckRunAppEx;
static PVOID g_pSdbPackAppCompatData;

typedef BOOL(WINAPI *tApphelpCheckRunAppEx)(
    HANDLE FileHandle, PVOID Unk1, PVOID Unk2, PWCHAR ApplicationName, PVOID Environment,
    USHORT ExeType, PULONG Reason, PVOID *SdbQueryAppCompatData,
    PULONG SdbQueryAppCompatDataSize, PVOID *SxsData, PULONG SxsDataSize,
    PULONG FusionFlags, PULONG64 SomeFlag1, PULONG SomeFlag2);
typedef BOOL(WINAPI *tSdbPackAppCompatData)(PVOID hSdb, PVOID pQueryResult, PVOID *ppData,
					    DWORD *dwSize);

#define APPHELP_VALID_RESULT 0x10000
#define APPHELP_RESULT_NOTFOUND 0x20000
#define APPHELP_RESULT_FOUND 0x40000

/*
 * Apphelp SHIM Cache
 */
typedef enum _APPHELPCACHESERVICECLASS {
    ApphelpCacheServiceLookup = 0,
    ApphelpCacheServiceRemove = 1,
    ApphelpCacheServiceUpdate = 2,
    ApphelpCacheServiceFlush = 3,
    ApphelpCacheServiceDump = 4,

    ApphelpDBGReadRegistry = 0x100,
    ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS;

typedef struct _APPHELP_CACHE_SERVICE_LOOKUP {
    UNICODE_STRING ImageName;
    HANDLE ImageHandle;
} APPHELP_CACHE_SERVICE_LOOKUP, *PAPPHELP_CACHE_SERVICE_LOOKUP;

/* FUNCTIONS ******************************************************************/

/*
 * This is the equivalent of NtApphelpCacheControl, except we implement it
 * on the client side.
 */
static NTSTATUS BasepApphelpCacheControl(IN APPHELPCACHESERVICECLASS Service,
					 IN OPTIONAL PAPPHELP_CACHE_SERVICE_LOOKUP ServiceData)
{
    return STATUS_NOT_IMPLEMENTED;
}

WINAPI BOOLEAN IsShimInfrastructureDisabled(VOID)
{
    HANDLE KeyHandle;
    NTSTATUS Status;
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    ULONG ResultLength;
    UNICODE_STRING OptionKey = RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\System\\Current"
						   L"ControlSet\\Control\\SafeBoot\\Optio"
						   L"n");
    UNICODE_STRING AppCompatKey = RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\System\\Curr"
						      L"entControlSet\\Control\\Session "
						      L"Manager\\AppCompatibility");
    UNICODE_STRING PolicyKey = RTL_CONSTANT_STRING(L"\\Registry\\MACHINE\\Software\\Polic"
						   L"ies\\Microsoft\\Windows\\AppCompat");
    UNICODE_STRING OptionValue = RTL_CONSTANT_STRING(L"OptionValue");
    UNICODE_STRING DisableAppCompat = RTL_CONSTANT_STRING(L"DisableAppCompat");
    UNICODE_STRING DisableEngine = RTL_CONSTANT_STRING(L"DisableEngine");
    OBJECT_ATTRIBUTES OptionKeyAttributes =
	RTL_CONSTANT_OBJECT_ATTRIBUTES(&OptionKey, OBJ_CASE_INSENSITIVE);
    OBJECT_ATTRIBUTES AppCompatKeyAttributes =
	RTL_CONSTANT_OBJECT_ATTRIBUTES(&AppCompatKey, OBJ_CASE_INSENSITIVE);
    OBJECT_ATTRIBUTES PolicyKeyAttributes =
	RTL_CONSTANT_OBJECT_ATTRIBUTES(&PolicyKey, OBJ_CASE_INSENSITIVE);

    /*
     * This is a TROOLEAN, -1 means we haven't yet figured it out.
     * 0 means shims are enabled, and 1 means shims are disabled!
     */
    if (g_ShimsDisabled == -1) {
	ULONG DisableShims = FALSE;

	/* Open the safe mode key */
	Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &OptionKeyAttributes);
	if (NT_SUCCESS(Status)) {
	    /* Check if this is safemode */
	    Status = NtQueryValueKey(KeyHandle, &OptionValue, KeyValuePartialInformation,
				     &KeyInfo, sizeof(KeyInfo), &ResultLength);
	    NtClose(KeyHandle);
	    if ((NT_SUCCESS(Status)) && (KeyInfo.Type == REG_DWORD) &&
		(KeyInfo.DataLength == sizeof(ULONG)) && (KeyInfo.Data[0] != FALSE)) {
		/* It is, so disable shims! */
		DisableShims = TRUE;
	    }
	}

	if (!DisableShims) {
	    /* Open the app compatibility engine settings key */
	    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &AppCompatKeyAttributes);
	    if (NT_SUCCESS(Status)) {
		/* Check if the app compat engine is turned off */
		Status = NtQueryValueKey(KeyHandle, &DisableAppCompat,
					 KeyValuePartialInformation, &KeyInfo,
					 sizeof(KeyInfo), &ResultLength);
		NtClose(KeyHandle);
		if ((NT_SUCCESS(Status)) && (KeyInfo.Type == REG_DWORD) &&
		    (KeyInfo.DataLength == sizeof(ULONG)) && (KeyInfo.Data[0] == TRUE)) {
		    /* It is, so disable shims! */
		    DisableShims = TRUE;
		}
	    }
	}
	if (!DisableShims) {
	    /* Finally, open the app compatibility policy key */
	    Status = NtOpenKey(&KeyHandle, KEY_QUERY_VALUE, &PolicyKeyAttributes);
	    if (NT_SUCCESS(Status)) {
		/* Check if the system policy disables app compat */
		Status = NtQueryValueKey(KeyHandle, &DisableEngine,
					 KeyValuePartialInformation, &KeyInfo,
					 sizeof(KeyInfo), &ResultLength);
		NtClose(KeyHandle);
		if ((NT_SUCCESS(Status)) && (KeyInfo.Type == REG_DWORD) &&
		    (KeyInfo.DataLength == sizeof(ULONG)) && (KeyInfo.Data[0] == TRUE)) {
		    /* It does, so disable shims! */
		    DisableShims = TRUE;
		}
	    }
	}
	g_ShimsDisabled = DisableShims;
    }

    /* Return if shims are disabled or not ("Enabled == 1" means disabled!) */
    return g_ShimsDisabled ? TRUE : FALSE;
}

/*
 * @unimplemented
 */
BOOL BasepShimCacheCheckBypass(_In_ PCWSTR ApplicationName, _In_ HANDLE FileHandle,
			       _In_opt_ PCWSTR Environment, _In_ BOOL bUnknown,
			       _Out_opt_ PULONG pdwReason)
{
    DPRINT("fixme:(%S, %p, %S, %d, %p)\n", ApplicationName, FileHandle, Environment,
	   bUnknown, pdwReason);
    return FALSE;
}

/*
 * @implemented
 */
BOOL BasepShimCacheSearch(_In_ PCWSTR ApplicationName, _In_ HANDLE FileHandle)
{
    APPHELP_CACHE_SERVICE_LOOKUP Lookup;
    RtlInitUnicodeString(&Lookup.ImageName, ApplicationName);
    Lookup.ImageHandle = FileHandle;
    return NT_SUCCESS(BasepApphelpCacheControl(ApphelpCacheServiceLookup, &Lookup));
}

/*
 * @unimplemented
 */
BOOL BasepCheckCacheExcludeList(_In_ PCWSTR ApplicationName)
{
    return FALSE;
}

/*
 * @unimplemented
 */
BOOL BasepCheckCacheExcludeCustom(_In_ PCWSTR ApplicationName)
{
    return FALSE;
}

/*
 * @implemented
 */
VOID BasepShimCacheRemoveEntry(_In_ PCWSTR ApplicationName)
{
    APPHELP_CACHE_SERVICE_LOOKUP Lookup;
    RtlInitUnicodeString(&Lookup.ImageName, ApplicationName);
    Lookup.ImageHandle = INVALID_HANDLE_VALUE;
    BasepApphelpCacheControl(ApphelpCacheServiceRemove, &Lookup);
}

/*
 * @unimplemented
 */
BOOL BasepShimCacheLookup(_In_ PCWSTR ApplicationName, _In_ HANDLE FileHandle)
{
    DPRINT("fixme:(%S, %p)\n", ApplicationName, FileHandle);

    if (!BasepShimCacheSearch(ApplicationName, FileHandle))
	return FALSE;

    if (!BasepCheckCacheExcludeList(ApplicationName) ||
	!BasepCheckCacheExcludeCustom(ApplicationName)) {
	BasepShimCacheRemoveEntry(ApplicationName);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL BaseCheckAppcompatCache(_In_ PCWSTR ApplicationName, _In_ HANDLE FileHandle,
				    _In_opt_ PCWSTR Environment,
				    _Out_opt_ PULONG pdwReason)
{
    BOOL Ret = FALSE;
    ULONG dwReason;

    DPRINT("(%S, %p, %S, %p)\n", ApplicationName, FileHandle, Environment, pdwReason);

    dwReason = 0;
    if (BasepShimCacheCheckBypass(ApplicationName, FileHandle, Environment, TRUE,
				  &dwReason)) {
	dwReason |= 2;
    } else {
	Ret = BasepShimCacheLookup(ApplicationName, FileHandle);
	if (!Ret)
	    dwReason |= 1;
    }

    if (pdwReason)
	*pdwReason = dwReason;

    return Ret;
}

static VOID BaseInitApphelp(VOID)
{
    WCHAR Buffer[MAX_PATH * 2];
    UNICODE_STRING DllPath = { 0 };
    PVOID ApphelpAddress;
    PVOID pApphelpCheckRunAppEx = NULL, pSdbPackAppCompatData = NULL;

    RtlInitEmptyUnicodeString(&DllPath, Buffer, sizeof(Buffer));
    RtlCopyUnicodeString(&DllPath, &BaseWindowsDirectory);
    RtlAppendUnicodeToString(&DllPath, L"\\system32\\apphelp.dll");

    if (NT_SUCCESS(LdrLoadDll(NULL, NULL, &DllPath, &ApphelpAddress))) {
	ANSI_STRING ProcName;

	RtlInitAnsiString(&ProcName, "ApphelpCheckRunAppEx");
	if (!NT_SUCCESS(LdrGetProcedureAddress(ApphelpAddress, &ProcName, 0,
					       &pApphelpCheckRunAppEx)))
	    pApphelpCheckRunAppEx = NULL;

	RtlInitAnsiString(&ProcName, "SdbPackAppCompatData");
	if (!NT_SUCCESS(LdrGetProcedureAddress(ApphelpAddress, &ProcName, 0,
					       &pSdbPackAppCompatData)))
	    pSdbPackAppCompatData = NULL;
    }

    if (InterlockedCompareExchangePointer(&g_pApphelpCheckRunAppEx,
					  RtlEncodeSystemPointer(pApphelpCheckRunAppEx),
					  NULL) == NULL) {
	g_pSdbPackAppCompatData = RtlEncodeSystemPointer(pSdbPackAppCompatData);
    }
}

/*
 *
 */
WINAPI BOOL BaseCheckRunApp(IN HANDLE FileHandle, IN PWCHAR ApplicationName,
			    IN PWCHAR Environment, IN USHORT ExeType, IN PULONG pReason,
			    IN PVOID *SdbQueryAppCompatData,
			    IN PULONG SdbQueryAppCompatDataSize, IN PVOID *SxsData,
			    IN PULONG SxsDataSize, OUT PULONG FusionFlags)
{
    ULONG Reason = 0;
    ULONG64 Flags1 = 0;
    ULONG Flags2 = 0;
    BOOL Continue, NeedCleanup = FALSE;
    tApphelpCheckRunAppEx pApphelpCheckRunAppEx;
    tSdbPackAppCompatData pSdbPackAppCompatData;
    PVOID QueryResult = NULL;
    ULONG QueryResultSize = 0;

    if (!g_ApphelpInitialized) {
	BaseInitApphelp();
	g_ApphelpInitialized = TRUE;
    }

    pApphelpCheckRunAppEx = RtlDecodeSystemPointer(g_pApphelpCheckRunAppEx);
    pSdbPackAppCompatData = RtlDecodeSystemPointer(g_pSdbPackAppCompatData);

    if (!pApphelpCheckRunAppEx || !pSdbPackAppCompatData)
	return TRUE;

    if (pReason)
	Reason = *pReason;

    Continue = pApphelpCheckRunAppEx(FileHandle, NULL, NULL, ApplicationName, Environment,
				     ExeType, &Reason, &QueryResult, &QueryResultSize,
				     SxsData, SxsDataSize, FusionFlags, &Flags1, &Flags2);

    if (pReason)
	*pReason = Reason;

    if (Continue) {
	if ((Reason & (APPHELP_VALID_RESULT | APPHELP_RESULT_FOUND)) ==
	    (APPHELP_VALID_RESULT | APPHELP_RESULT_FOUND)) {
	    if (!pSdbPackAppCompatData(NULL, QueryResult, SdbQueryAppCompatData,
				       SdbQueryAppCompatDataSize)) {
		DPRINT1("SdbPackAppCompatData returned a failure!\n");
		NeedCleanup = TRUE;
	    }
	} else {
	    NeedCleanup = TRUE;
	}
    }

    if (QueryResult)
	RtlFreeHeap(RtlGetProcessHeap(), 0, QueryResult);

    if (NeedCleanup) {
	BasepFreeAppCompatData(*SdbQueryAppCompatData, *SxsData);
	*SdbQueryAppCompatData = NULL;
	if (SdbQueryAppCompatDataSize)
	    *SdbQueryAppCompatDataSize = 0;
	*SxsData = NULL;
	if (SxsDataSize)
	    *SxsDataSize = 0;
    }

    return Continue;
}

/*
 * @implemented
 */
WINAPI NTSTATUS BasepCheckBadapp(IN HANDLE FileHandle, IN PWCHAR ApplicationName,
				 IN PWCHAR Environment, IN USHORT ExeType,
				 IN PVOID *SdbQueryAppCompatData,
				 IN PULONG SdbQueryAppCompatDataSize, IN PVOID *SxsData,
				 IN PULONG SxsDataSize, OUT PULONG FusionFlags)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Reason = 0;

    /* Is shimming enabled by group policy? */
    if (IsShimInfrastructureDisabled()) {
	/* Nothing to worry about */
	Status = STATUS_SUCCESS;
    } else {
	/* It is, check if we know about this app */
	if (!BaseCheckAppcompatCache(ApplicationName, FileHandle, Environment, &Reason)) {
	    if (!BaseCheckRunApp(FileHandle, ApplicationName, Environment, ExeType,
				 &Reason, SdbQueryAppCompatData,
				 SdbQueryAppCompatDataSize, SxsData, SxsDataSize,
				 FusionFlags)) {
		Status = STATUS_ACCESS_DENIED;
	    }
	}
    }

    /* Return caller the status */
    return Status;
}

/*
 * @implemented
 */
WINAPI BOOL BaseDumpAppcompatCache(VOID)
{
    NTSTATUS Status;

    Status = BasepApphelpCacheControl(ApphelpCacheServiceDump, NULL);
    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
WINAPI BOOL BaseFlushAppcompatCache(VOID)
{
    NTSTATUS Status;

    Status = BasepApphelpCacheControl(ApphelpCacheServiceFlush, NULL);
    return NT_SUCCESS(Status);
}

/*
 * @implemented
 */
WINAPI VOID BasepFreeAppCompatData(IN PVOID AppCompatData, IN PVOID AppCompatSxsData)
{
    /* Free the input pointers if present */
    if (AppCompatData)
	RtlFreeHeap(RtlGetProcessHeap(), 0, AppCompatData);
    if (AppCompatSxsData)
	RtlFreeHeap(RtlGetProcessHeap(), 0, AppCompatSxsData);
}

/*
 * @unimplemented
 */
WINAPI VOID BaseUpdateAppcompatCache(ULONG Unknown1, ULONG Unknown2, ULONG Unknown3)
{
    STUB;
}

/*
 * @unimplemented
 */
WINAPI NTSTATUS BaseCleanupAppcompatCache(VOID)
{
    STUB;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
WINAPI NTSTATUS BaseCleanupAppcompatCacheSupport(PVOID pUnknown)
{
    STUB;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
WINAPI BOOL BaseInitAppcompatCache(VOID)
{
    STUB;
    return FALSE;
}

/*
 * @unimplemented
 */
WINAPI BOOL BaseInitAppcompatCacheSupport(VOID)
{
    STUB;
    return FALSE;
}

/*
 * @unimplemented
 */
WINAPI PVOID GetComPlusPackageInstallStatus(VOID)
{
    STUB;
    return NULL;
}

/*
 * @implemented
 */
WINAPI BOOL SetComPlusPackageInstallStatus(IN ULONG ComPlusPackage)
{
    NTSTATUS Status;

    DPRINT("(0x%X)\n", ComPlusPackage);

    if (ComPlusPackage & ~1) {
	DPRINT1("0x%X\n", ComPlusPackage);
	BaseSetLastNTError(STATUS_INVALID_PARAMETER);
	return FALSE;
    }

    Status = NtSetSystemInformation(SystemComPlusPackage, &ComPlusPackage,
				    sizeof(ComPlusPackage));
    if (!NT_SUCCESS(Status)) {
	DPRINT1("0x%X\n", Status);
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @unimplemented
 */
WINAPI VOID SetTermsrvAppInstallMode(IN BOOL bInstallMode)
{
    STUB;
}

/*
 * @unimplemented
 */
WINAPI BOOL TermsrvAppInstallMode(VOID)
{
    STUB;
    return FALSE;
}
