/* This file is stolen shamelessly from reactos/sdk/lib/crt/wine/winternl.h */

#pragma once

#include <ldrtypes.h>
#include <ntstatus.h>
#include <ntrtl.h>
#include <ntkeapi.h>

/* This is placed at the same address for both i386 and amd64 */
#define USER_SHARED_DATA                        0x7FFE0000

/*
 * Global Flags
 */
#define FLG_STOP_ON_EXCEPTION                   0x00000001
#define FLG_SHOW_LDR_SNAPS                      0x00000002
#define FLG_DEBUG_INITIAL_COMMAND               0x00000004
#define FLG_STOP_ON_HUNG_GUI                    0x00000008
#define FLG_HEAP_ENABLE_TAIL_CHECK              0x00000010
#define FLG_HEAP_ENABLE_FREE_CHECK              0x00000020
#define FLG_HEAP_VALIDATE_PARAMETERS            0x00000040
#define FLG_HEAP_VALIDATE_ALL                   0x00000080
#define FLG_APPLICATION_VERIFIER                0x00000100
#define FLG_POOL_ENABLE_TAGGING                 0x00000400
#define FLG_HEAP_ENABLE_TAGGING                 0x00000800
#define FLG_USER_STACK_TRACE_DB                 0x00001000
#define FLG_KERNEL_STACK_TRACE_DB               0x00002000
#define FLG_MAINTAIN_OBJECT_TYPELIST            0x00004000
#define FLG_HEAP_ENABLE_TAG_BY_DLL              0x00008000
#define FLG_DISABLE_STACK_EXTENSION             0x00010000
#define FLG_ENABLE_CSRDEBUG                     0x00020000
#define FLG_ENABLE_KDEBUG_SYMBOL_LOAD           0x00040000
#define FLG_DISABLE_PAGE_KERNEL_STACKS          0x00080000
#define FLG_ENABLE_SYSTEM_CRIT_BREAKS           0x00100000
#define FLG_HEAP_DISABLE_COALESCING             0x00200000
#define FLG_ENABLE_CLOSE_EXCEPTIONS             0x00400000
#define FLG_ENABLE_EXCEPTION_LOGGING            0x00800000
#define FLG_ENABLE_HANDLE_TYPE_TAGGING          0x01000000
#define FLG_HEAP_PAGE_ALLOCS                    0x02000000
#define FLG_DEBUG_INITIAL_COMMAND_EX            0x04000000
#define FLG_VALID_BITS                          0x07FFFFFF

/*
 * Thread Access Rights
 */
#define THREAD_TERMINATE                 0x0001
#define THREAD_SUSPEND_RESUME            0x0002
#define THREAD_ALERT                     0x0004
#define THREAD_GET_CONTEXT               0x0008
#define THREAD_SET_CONTEXT               0x0010
#define THREAD_SET_INFORMATION           0x0020
#define THREAD_SET_LIMITED_INFORMATION   0x0400
#define THREAD_QUERY_LIMITED_INFORMATION 0x0800
#define PROCESS_DUP_HANDLE               0x0040

#define PROCESS_ALL_ACCESS  (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#define THREAD_ALL_ACCESS   (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

/*
 * Thread priority
 */
#define LOW_PRIORITY                      0
#define LOW_REALTIME_PRIORITY             16
#define HIGH_PRIORITY                     31
#define MAXIMUM_PRIORITY                  32

/*
 * Quota limits
 */
#define QUOTA_LIMITS_HARDWS_MIN_ENABLE  0x00000001
#define QUOTA_LIMITS_HARDWS_MIN_DISABLE 0x00000002
#define QUOTA_LIMITS_HARDWS_MAX_ENABLE  0x00000004
#define QUOTA_LIMITS_HARDWS_MAX_DISABLE 0x00000008
#define QUOTA_LIMITS_USE_DEFAULT_LIMITS 0x00000010

/*
 * Process Handle Tracing Values
 */
#define PROCESS_HANDLE_TRACE_TYPE_OPEN          1
#define PROCESS_HANDLE_TRACE_TYPE_CLOSE         2
#define PROCESS_HANDLE_TRACE_TYPE_BADREF        3
#define PROCESS_HANDLE_TRACING_MAX_STACKS       16

typedef struct _QUOTA_LIMITS {
    SIZE_T PagedPoolLimit;
    SIZE_T NonPagedPoolLimit;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    SIZE_T PagefileLimit;
    LARGE_INTEGER TimeLimit;
} QUOTA_LIMITS, *PQUOTA_LIMITS;

typedef union _RATE_QUOTA_LIMIT {
    ULONG RateData;
    struct {
	ULONG RatePercent : 7;
	ULONG Reserved0 : 25;
    };
} RATE_QUOTA_LIMIT, *PRATE_QUOTA_LIMIT;

typedef struct _QUOTA_LIMITS_EX {
    SIZE_T PagedPoolLimit;
    SIZE_T NonPagedPoolLimit;
    SIZE_T MinimumWorkingSetSize;
    SIZE_T MaximumWorkingSetSize;
    SIZE_T PagefileLimit;
    LARGE_INTEGER TimeLimit;
    SIZE_T WorkingSetLimit;
    SIZE_T Reserved2;
    SIZE_T Reserved3;
    SIZE_T Reserved4;
    ULONG Flags;
    RATE_QUOTA_LIMIT CpuRateLimit;
} QUOTA_LIMITS_EX, *PQUOTA_LIMITS_EX;

typedef struct _IO_COUNTERS {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _VM_COUNTERS_EX {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivateUsage;
} VM_COUNTERS_EX, *PVM_COUNTERS_EX;

#define MAX_HW_COUNTERS 16
#define THREAD_PROFILING_FLAG_DISPATCH  0x00000001

typedef enum _HARDWARE_COUNTER_TYPE {
    PMCCounter,
    MaxHardwareCounterType
} HARDWARE_COUNTER_TYPE, *PHARDWARE_COUNTER_TYPE;

typedef struct _HARDWARE_COUNTER {
    HARDWARE_COUNTER_TYPE Type;
    ULONG Reserved;
    ULONG64 Index;
} HARDWARE_COUNTER, *PHARDWARE_COUNTER;

#define PROCESS_EXCEPTION_PORT_ALL_STATE_BITS     0x00000003UL
#define PROCESS_EXCEPTION_PORT_ALL_STATE_FLAGS    ((ULONG_PTR)((1UL << PROCESS_EXCEPTION_PORT_ALL_STATE_BITS) - 1))

typedef struct _PROCESS_EXCEPTION_PORT {
    HANDLE ExceptionPortHandle;
    ULONG StateFlags;
} PROCESS_EXCEPTION_PORT, *PPROCESS_EXCEPTION_PORT;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    ProcessIoPriority,
    ProcessExecuteFlags,
    ProcessTlsInformation,
    ProcessCookie,
    ProcessImageInformation,
    ProcessCycleTime,
    ProcessPagePriority,
    ProcessInstrumentationCallback,
    ProcessThreadStackAllocation,
    ProcessWorkingSetWatchEx,
    ProcessImageFileNameWin32,
    ProcessImageFileMapping,
    ProcessAffinityUpdateMode,
    ProcessMemoryAllocationMode,
    ProcessGroupInformation,
    ProcessTokenVirtualizationEnabled,
    ProcessConsoleHostProcess,
    ProcessWindowInformation,
    MaxProcessInfoClass
} PROCESSINFOCLASS, PROCESS_INFORMATION_CLASS;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    MaxThreadInfoClass
} THREADINFOCLASS, THREAD_INFORMATION_CLASS;

/*
 * Initial TEB
 */
typedef struct _INITIAL_TEB {
    PVOID PreviousStackBase;
    PVOID PreviousStackLimit;
    PVOID StackBase;		/* Top of the initial stack */
    PVOID StackLimit;		/* Bottom of the initial committed stack */
    PVOID AllocatedStackBase;	/* Bottom of the initial stack reserve */
} INITIAL_TEB, *PINITIAL_TEB;

/*
 * Thread information block common to all NT subsystems, including Win32 and Posix
 */
typedef struct _NT_TIB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    PVOID FiberData;
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
    ULONG_PTR SystemServiceCap;
    CLIENT_ID ClientId;
} NT_TIB, *PNT_TIB;

/*
 * Process Information Structures for NtQueryProcessInformation
 */
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _PROCESS_ACCESS_TOKEN {
    HANDLE Token;
    HANDLE Thread;
} PROCESS_ACCESS_TOKEN, *PPROCESS_ACCESS_TOKEN;

typedef struct _PROCESS_DEVICEMAP_INFORMATION {
    union {
	struct {
	    HANDLE DirectoryHandle;
	} Set;
	struct {
	    ULONG DriveMap;
	    UCHAR DriveType[32];
	} Query;
    };
} PROCESS_DEVICEMAP_INFORMATION, *PPROCESS_DEVICEMAP_INFORMATION;

typedef struct _KERNEL_USER_TIMES {
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _POOLED_USAGE_AND_LIMITS {
    SIZE_T PeakPagedPoolUsage;
    SIZE_T PagedPoolUsage;
    SIZE_T PagedPoolLimit;
    SIZE_T PeakNonPagedPoolUsage;
    SIZE_T NonPagedPoolUsage;
    SIZE_T NonPagedPoolLimit;
    SIZE_T PeakPagefileUsage;
    SIZE_T PagefileUsage;
    SIZE_T PagefileLimit;
} POOLED_USAGE_AND_LIMITS, *PPOOLED_USAGE_AND_LIMITS;

typedef struct _PROCESS_WS_WATCH_INFORMATION {
    PVOID FaultingPc;
    PVOID FaultingVa;
} PROCESS_WS_WATCH_INFORMATION, *PPROCESS_WS_WATCH_INFORMATION;

typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

typedef struct _PROCESS_HANDLE_TRACING_ENTRY {
    HANDLE Handle;
    CLIENT_ID ClientId;
    ULONG Type;
    PVOID Stacks[PROCESS_HANDLE_TRACING_MAX_STACKS];
} PROCESS_HANDLE_TRACING_ENTRY, *PPROCESS_HANDLE_TRACING_ENTRY;

typedef struct _PROCESS_HANDLE_TRACING_QUERY {
    HANDLE Handle;
    ULONG TotalTraces;
    PROCESS_HANDLE_TRACING_ENTRY HandleTrace[ANYSIZE_ARRAY];
} PROCESS_HANDLE_TRACING_QUERY, *PPROCESS_HANDLE_TRACING_QUERY;

typedef struct _PROCESS_LDT_INFORMATION {
    ULONG Start;
    ULONG Length;
    PVOID LdtEntries;
} PROCESS_LDT_INFORMATION, *PPROCESS_LDT_INFORMATION;

typedef struct _PROCESS_LDT_SIZE {
    ULONG Length;
} PROCESS_LDT_SIZE, *PPROCESS_LDT_SIZE;

typedef struct _PROCESS_PRIORITY_CLASS {
    BOOLEAN Foreground;
    UCHAR PriorityClass;
} PROCESS_PRIORITY_CLASS, *PPROCESS_PRIORITY_CLASS;

// Compatibility with windows, see ReactOS CORE-16757, CORE-17106, CORE-17247
C_ASSERT(sizeof(PROCESS_PRIORITY_CLASS) == 2);

typedef struct _PROCESS_FOREGROUND_BACKGROUND {
    BOOLEAN Foreground;
} PROCESS_FOREGROUND_BACKGROUND, *PPROCESS_FOREGROUND_BACKGROUND;

/*
 * Thread Information Structures for NtQueryProcessInformation
 */
typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

/*
 * Native Calls. These are only available for client threads.
 * The NTOS root task has different function signatures for these.
 */
#ifndef _NTOSKRNL_

NTAPI NTSYSAPI NTSTATUS NtTerminateProcess(IN HANDLE ProcessHandle,
					   IN NTSTATUS ExitStatus);

NTAPI NTSYSAPI NTSTATUS NtTerminateThread(IN HANDLE ThreadHandle,
					  IN NTSTATUS ExitStatus);

NTAPI NTSYSAPI NTSTATUS NtResumeThread(IN HANDLE ThreadHandle,
				       OUT OPTIONAL PULONG SuspendCount);

FORCEINLINE DECLSPEC_NOFPU NTAPI PNT_TIB NtCurrentTib(VOID)
{
#ifdef _M_IX86
    return (PNT_TIB)__readfsdword(FIELD_OFFSET(NT_TIB, Self));
#elif defined(_M_AMD64)
    ULONG_PTR Tib;
    __asm__ __volatile__("rdgsbase %0" : "=r"(Tib));
    return (PNT_TIB)Tib;
#elif defined(_M_ARM64)
#ifdef _MSC_VER
    return (PNT_TIB)__getReg(18);
#else
    /* For ELT targets the X18 register is a scratch register so we use
     * tpidrro_el0 for the pointer to the TIB. */
    ULONG_PTR Tib;
    __asm__ __volatile__("mrs %0,tpidrro_el0" : "=r"(Tib));
    return (PNT_TIB)Tib;
#endif
#else
#error "Unsupported architecture"
#endif
}

#endif
