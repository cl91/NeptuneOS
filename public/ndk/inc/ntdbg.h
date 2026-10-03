#pragma once

#include <ntdef.h>
#include <ntioapi.h>
#include <ntlpc.h>
#include <ntrtl.h>

/*
 * Debug Object Access Masks
 */
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)

/*
 * Debug Event Flags
 */
#define DEBUG_EVENT_READ                  (0x01)
#define DEBUG_EVENT_NOWAIT                (0x02)
#define DEBUG_EVENT_INACTIVE              (0x04)
#define DEBUG_EVENT_RELEASE               (0x08)
#define DEBUG_EVENT_PROTECT_FAILED        (0x10)
#define DEBUG_EVENT_SUSPEND               (0x20)

/*
 * NtCreateDebugObject Flags
 */
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)

/*
 * Debug Object Information Classes for NtQueryDebugObject
 */
typedef enum _DEBUGOBJECTINFOCLASS {
    DebugObjectUnusedInformation,
    DebugObjectKillProcessOnExitInformation
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

/*
 * Debug Message API Number
 */
typedef enum _DBGKM_APINUMBER {
    DbgKmExceptionApi = 0,
    DbgKmCreateThreadApi = 1,
    DbgKmCreateProcessApi = 2,
    DbgKmExitThreadApi = 3,
    DbgKmExitProcessApi = 4,
    DbgKmLoadDllApi = 5,
    DbgKmUnloadDllApi = 6,
    DbgKmErrorReportApi = 7,
    DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

/*
 * Debug Object Information Structures
 */
typedef struct _DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION {
    ULONG KillProcessOnExit;
} DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION, *PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION;

/*
 * Debug States
 */
typedef enum _DBG_STATE {
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

/*
 * Debug Message Structures
 */
typedef struct _DBGKM_EXCEPTION {
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD {
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS {
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS {
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL {
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL {
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

/*
 * User-Mode Debug State Change Structure
 */
typedef struct _DBGUI_WAIT_STATE_CHANGE {
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union {
	struct {
	    HANDLE HandleToThread;
	    DBGKM_CREATE_THREAD NewThread;
	} CreateThread;
	struct {
	    HANDLE HandleToProcess;
	    HANDLE HandleToThread;
	    DBGKM_CREATE_PROCESS NewProcess;
	} CreateProcessInfo;
	DBGKM_EXIT_THREAD ExitThread;
	DBGKM_EXIT_PROCESS ExitProcess;
	DBGKM_EXCEPTION Exception;
	DBGKM_LOAD_DLL LoadDll;
	DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

/*
 * LPC Debug Message
 */
typedef struct _DBGKM_MSG {
    PORT_MESSAGE h;
    DBGKM_APINUMBER ApiNumber;
    NTSTATUS ReturnedStatus;
    union {
	DBGKM_EXCEPTION Exception;
	DBGKM_CREATE_THREAD CreateThread;
	DBGKM_CREATE_PROCESS CreateProcess;
	DBGKM_EXIT_THREAD ExitThread;
	DBGKM_EXIT_PROCESS ExitProcess;
	DBGKM_LOAD_DLL LoadDll;
	DBGKM_UNLOAD_DLL UnloadDll;
    };
} DBGKM_MSG, *PDBGKM_MSG;

#ifndef _NTOSKRNL_

/*
 * Debug UI Routines
 */
NTAPI NTSYSAPI NTSTATUS DbgUiConnectToDbg(VOID);

NTAPI NTSYSAPI NTSTATUS DbgUiContinue(IN PCLIENT_ID ClientId, IN NTSTATUS ContinueStatus);

NTAPI NTSYSAPI NTSTATUS DbgUiDebugActiveProcess(IN HANDLE Process);

NTAPI NTSYSAPI NTSTATUS DbgUiStopDebugging(IN HANDLE Process);

NTAPI NTSYSAPI NTSTATUS DbgUiWaitStateChange(IN PDBGUI_WAIT_STATE_CHANGE Change,
					     IN PLARGE_INTEGER TimeOut);

NTAPI NTSYSAPI VOID DbgUiRemoteBreakin(VOID);

NTAPI NTSYSAPI NTSTATUS DbgUiIssueRemoteBreakin(IN HANDLE Process);

NTAPI NTSYSAPI HANDLE DbgUiGetThreadDebugObject(VOID);

#endif	/* !_NTOSKRNL_ */
