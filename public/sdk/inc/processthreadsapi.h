/*
 * PROJECT:     ReactOS SDK
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     API definitions for api-ms-win-core-processthreads-l1
 * COPYRIGHT:   Copyright 2024 Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    PBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    PBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

#ifdef UNICODE
typedef STARTUPINFOW STARTUPINFO, *LPSTARTUPINFO;
#else
typedef STARTUPINFOA STARTUPINFO, *LPSTARTUPINFO;
#endif // UNICODE

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST *PPROC_THREAD_ATTRIBUTE_LIST,
    *LPPROC_THREAD_ATTRIBUTE_LIST;

WINBASEAPI
HRESULT
WINAPI
GetThreadDescription(_In_ HANDLE hThread, _Outptr_result_z_ PWSTR *ppszThreadDescription);

WINBASEAPI
HRESULT
WINAPI
SetThreadDescription(_In_ HANDLE hThread, _In_ PCWSTR lpThreadDescription);

WINBASEAPI
BOOL WINAPI SetThreadStackGuarantee(_Inout_ PULONG StackSizeInBytes);

WINBASEAPI
VOID WINAPI FlushProcessWriteBuffers(VOID);

WINBASEAPI
_Success_(return != FALSE) BOOL WINAPI
    InitializeProcThreadAttributeList(_Out_writes_bytes_to_opt_(*lpSize, *lpSize)
					  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
				      _In_ DWORD dwAttributeCount,
				      _Reserved_ DWORD dwFlags,
				      _When_(lpAttributeList == nullptr, _Out_)
					  _When_(lpAttributeList != nullptr, _Inout_)
					      PSIZE_T lpSize);

WINBASEAPI
BOOL WINAPI UpdateProcThreadAttribute(
    _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, _In_ DWORD dwFlags,
    _In_ DWORD_PTR Attribute, _In_reads_bytes_opt_(cbSize) PVOID lpValue,
    _In_ SIZE_T cbSize, _Out_writes_bytes_opt_(cbSize) PVOID lpPreviousValue,
    _In_opt_ PSIZE_T lpReturnSize);

WINBASEAPI
VOID WINAPI
DeleteProcThreadAttributeList(_Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);

FORCEINLINE HANDLE GetCurrentProcessToken(VOID)
{
    return (HANDLE)(LONG_PTR)-4;
}

FORCEINLINE HANDLE GetCurrentThreadToken(VOID)
{
    return (HANDLE)(LONG_PTR)-5;
}

FORCEINLINE HANDLE GetCurrentThreadEffectiveToken(VOID)
{
    return (HANDLE)(LONG_PTR)-6;
}

/*
 * Note in Windows 10 API this is called PROCESS_INFORMATION_CLASS. We change the
 * enum name to be consistent with NT and Win32 naming convention (ie. NT uses
 * INFORMATION_CLASS and Win32 uses INFOCLASS, see USERTHREADINFOCLASS in winuser.h).
 */
typedef enum _PROCESSINFOCLASS {
    ProcessMemoryPriority,
    ProcessMemoryExhaustionInfo,
    ProcessAppMemoryInfo,
    ProcessInPrivateInfo,
    ProcessPowerThrottling,
    ProcessReservedValue1, // Formerly ProcessActivityThrottlePolicyInfo
    ProcessTelemetryCoverageInfo,
    ProcessProtectionLevelInfo,
    ProcessLeapSecondInfo,
    ProcessMachineTypeInfo,
    ProcessOverrideSubsequentPrefetchParameter,
    ProcessMaxOverridePrefetchParameter,
    ProcessInformationClassMax
} PROCESSINFOCLASS;

#define PROCESS_MACHINE_ATTRIBUTE_KERNEL_ENABLED 0x00000001
#define PROCESS_MACHINE_ATTRIBUTE_USER_ENABLED 0x00000002
#define PROCESS_MACHINE_ATTRIBUTE_NATIVE_OS 0x00000004
#define PROCESS_MACHINE_ATTRIBUTE_WOW64_CONTAINER 0x00000008

/*
 * In Win10 this is called THREAD_INFORMATION_CLASS. See the comment above for
 * reason of the name change.
 */
typedef enum _THREADINFOCLASS {
    ThreadMemoryPriority,
    ThreadAbsoluteCpuPriority,
    ThreadDynamicCodePolicy,
    ThreadPowerThrottling,
    ThreadInformationClassMax
} THREADINFOCLASS;

#ifdef __cplusplus
} // extern "C"
#endif
