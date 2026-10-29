/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/wine/actctx.c
 * PURPOSE:         Activation contexts
 * PROGRAMMERS:     Jacek Caban for CodeWeavers
 *                  Eric Pouech
 *                  Jon Griffiths
 *                  Dmitry Chapyshev (dmitry@reactos.org)
 *                  Samuel Serapión
 */

/* Synched with Wine 1.7.55 */

#include <k32.h>
DEBUG_CHANNEL(actctx);

/***********************************************************************
 * CreateActCtxA (KERNEL32.@)
 *
 * Create an activation context.
 */
WINAPI HANDLE CreateActCtxA(PCACTCTXA pActCtx)
{
    ACTCTXW ActCtx;
    SIZE_T Len;
    HANDLE Ret = INVALID_HANDLE_VALUE;
    LPWSTR Src = NULL, AssDir = NULL, ResName = NULL, AppName = NULL;

    TRACE("%p %08x\n", pActCtx, pActCtx ? pActCtx->dwFlags : 0);

    if (!pActCtx || pActCtx->cbSize != sizeof(*pActCtx)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return INVALID_HANDLE_VALUE;
    }

    ActCtx.cbSize = sizeof(ActCtx);
    ActCtx.dwFlags = pActCtx->dwFlags;
    if (pActCtx->lpSource) {
	Len = MultiByteToWideChar(CP_ACP, 0, pActCtx->lpSource, -1, NULL, 0);
	Src = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	if (!Src)
	    return INVALID_HANDLE_VALUE;
	MultiByteToWideChar(CP_ACP, 0, pActCtx->lpSource, -1, Src, Len);
    }
    ActCtx.lpSource = Src;

    if (ActCtx.dwFlags & ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID)
	ActCtx.wProcessorArchitecture = pActCtx->wProcessorArchitecture;
    if (ActCtx.dwFlags & ACTCTX_FLAG_LANGID_VALID)
	ActCtx.wLangId = pActCtx->wLangId;
    if (ActCtx.dwFlags & ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID) {
	Len = MultiByteToWideChar(CP_ACP, 0, pActCtx->lpAssemblyDirectory, -1, NULL, 0);
	AssDir = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	if (!AssDir)
	    goto done;
	MultiByteToWideChar(CP_ACP, 0, pActCtx->lpAssemblyDirectory, -1, AssDir, Len);
	ActCtx.lpAssemblyDirectory = AssDir;
    }
    if (ActCtx.dwFlags & ACTCTX_FLAG_RESOURCE_NAME_VALID) {
	if ((ULONG_PTR)pActCtx->lpResourceName >> 16) {
	    Len = MultiByteToWideChar(CP_ACP, 0, pActCtx->lpResourceName, -1, NULL, 0);
	    ResName = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	    if (!ResName)
		goto done;
	    MultiByteToWideChar(CP_ACP, 0, pActCtx->lpResourceName, -1, ResName, Len);
	    ActCtx.lpResourceName = ResName;
	} else
	    ActCtx.lpResourceName = (LPCWSTR)pActCtx->lpResourceName;
    }
    if (ActCtx.dwFlags & ACTCTX_FLAG_APPLICATION_NAME_VALID) {
	Len = MultiByteToWideChar(CP_ACP, 0, pActCtx->lpApplicationName, -1, NULL, 0);
	AppName = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
	if (!AppName)
	    goto done;
	MultiByteToWideChar(CP_ACP, 0, pActCtx->lpApplicationName, -1, AppName, Len);
	ActCtx.lpApplicationName = AppName;
    }
    if (ActCtx.dwFlags & ACTCTX_FLAG_HMODULE_VALID)
	ActCtx.hModule = pActCtx->hModule;

    Ret = CreateActCtxW(&ActCtx);

done:
    HeapFree(GetProcessHeap(), 0, Src);
    HeapFree(GetProcessHeap(), 0, AssDir);
    HeapFree(GetProcessHeap(), 0, ResName);
    HeapFree(GetProcessHeap(), 0, AppName);
    return Ret;
}

/***********************************************************************
 * CreateActCtxW (KERNEL32.@)
 *
 * Create an activation context.
 */
WINAPI HANDLE CreateActCtxW(PCACTCTXW pActCtx)
{
    NTSTATUS Status;
    HANDLE hActCtx;

    TRACE("%p %08x\n", pActCtx, pActCtx ? pActCtx->dwFlags : 0);

    if ((Status = RtlCreateActivationContext(0, (PVOID)pActCtx, 0, NULL, NULL,
					     &hActCtx))) {
	SetLastError(RtlNtStatusToDosError(Status));
	return INVALID_HANDLE_VALUE;
    }
    return hActCtx;
}

/***********************************************************************
 * FindActCtxSectionStringA (KERNEL32.@)
 *
 * Find information about a string in an activation context.
 */
WINAPI BOOL FindActCtxSectionStringA(DWORD dwFlags, const GUID *lpExtGuid, ULONG ulId,
				     LPCSTR lpSearchStr, PACTCTX_SECTION_KEYED_DATA pInfo)
{
    LPWSTR SearchStr;
    DWORD Len;
    BOOL Ret;

    TRACE("%08x %p %u %s %p\n", dwFlags, debugstr_guid(lpExtGuid), ulId,
	  debugstr_a(lpSearchStr), pInfo);

    if (!lpSearchStr || !pInfo) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    Len = MultiByteToWideChar(CP_ACP, 0, lpSearchStr, -1, NULL, 0);
    SearchStr = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, lpSearchStr, -1, SearchStr, Len);

    Ret = FindActCtxSectionStringW(dwFlags, lpExtGuid, ulId, SearchStr, pInfo);

    HeapFree(GetProcessHeap(), 0, SearchStr);
    return Ret;
}

/***********************************************************************
 * FindActCtxSectionStringW (KERNEL32.@)
 *
 * Find information about a string in an activation context.
 */
WINAPI BOOL FindActCtxSectionStringW(DWORD dwFlags, const GUID *lpExtGuid, ULONG ulId,
				     LPCWSTR lpSearchStr,
				     PACTCTX_SECTION_KEYED_DATA pInfo)
{
    UNICODE_STRING Str;
    NTSTATUS Status;

    if (!pInfo) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    RtlInitUnicodeString(&Str, lpSearchStr);
    if ((Status = RtlFindActivationContextSectionString(dwFlags, lpExtGuid, ulId, &Str,
							pInfo))) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }
    return TRUE;
}

/***********************************************************************
 * FindActCtxSectionGuid (KERNEL32.@)
 *
 * Find information about a GUID in an activation context.
 */
WINAPI BOOL FindActCtxSectionGuid(DWORD dwFlags, const GUID *lpExtGuid, ULONG ulId,
				  const GUID *lpSearchGuid,
				  PACTCTX_SECTION_KEYED_DATA pInfo)
{
    NTSTATUS Status;

    if ((Status = RtlFindActivationContextSectionGuid(dwFlags, lpExtGuid, ulId,
						      lpSearchGuid, pInfo))) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }

    return TRUE;
}
