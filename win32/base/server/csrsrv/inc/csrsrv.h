/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            include/reactos/subsys/csr/csrsrv.h
 * PURPOSE:         Public definitions for CSR Servers
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Hermes Belusca-Maito (hermes.belusca@sfr.fr)
 */

#ifndef _CSRSRV_H
#define _CSRSRV_H

/*
 * The CSR_DBG macro is defined for building CSR Servers
 * with extended debugging information.
 */
#if DBG
#define CSR_DBG
#endif

#include <csrmsg.h>

/* TYPES **********************************************************************/

/*
 * Represents a client process tracked by the server
 */
typedef struct _CSR_PROCESS {
    CLIENT_ID ClientId;
    LIST_ENTRY ListLink;
    LIST_ENTRY ThreadList;
    PVOID ServerViewBase;
    ULONG_PTR ClientViewBase;
    ULONG_PTR ClientViewBounds;
    HANDLE ProcessHandle;
    ULONG ExpectedVersion;
    ULONG SequenceNumber;
    ULONG Flags;
    ULONG DebugFlags;
    CLIENT_ID DebugCid;
    ULONG ReferenceCount;
    ULONG ProcessGroupId;
    ULONG ProcessGroupSequence;
    ULONG ThreadCount;
    ULONG ShutdownLevel;
    ULONG ShutdownFlags;
} CSR_PROCESS, *PCSR_PROCESS;

/*
 * Represents a client thread tracked by the server
 */
typedef struct _CSR_THREAD {
    LARGE_INTEGER CreateTime;
    LIST_ENTRY Link;
    LIST_ENTRY HashLinks;
    CLIENT_ID ClientId;
    PCSR_PROCESS Process;
    HANDLE ThreadHandle;
    ULONG Flags;
    ULONG ReferenceCount;
    ULONG ImpersonationCount;
} CSR_THREAD, *PCSR_THREAD;

/* ENUMERATIONS ***************************************************************/

typedef enum _CSR_PROCESS_FLAGS {
    CsrProcessTerminating = 0x1,
    CsrProcessSkipShutdown = 0x2,
    CsrProcessNormalPriority = 0x10,
    CsrProcessIdlePriority = 0x20,
    CsrProcessHighPriority = 0x40,
    CsrProcessRealtimePriority = 0x80,
    CsrProcessCreateNewGroup = 0x100,
    CsrProcessTerminated = 0x200,
    CsrProcessLastThreadTerminated = 0x400,
    CsrProcessIsConsoleApp = 0x800,
    CsrProcessIsWow64 = 0x1000,
    CsrProcessSharedSectionMapped = 0x2000
} CSR_PROCESS_FLAGS, *PCSR_PROCESS_FLAGS;

#define CsrProcessPriorityFlags                                                   \
    (CsrProcessNormalPriority | CsrProcessIdlePriority | CsrProcessHighPriority | \
     CsrProcessRealtimePriority)

typedef enum _CSR_THREAD_FLAGS {
    CsrThreadAlertable = 0x1,
    CsrThreadInTermination = 0x2,
    CsrThreadTerminated = 0x4
} CSR_THREAD_FLAGS, *PCSR_THREAD_FLAGS;

typedef enum _SHUTDOWN_RESULT {
    CsrShutdownCsrProcess = 1,
    CsrShutdownNonCsrProcess,
    CsrShutdownCancelled
} SHUTDOWN_RESULT, *PSHUTDOWN_RESULT;

typedef enum _CSR_SHUTDOWN_FLAGS {
    CsrShutdownSystem = 4,
    CsrShutdownOther = 8
} CSR_SHUTDOWN_FLAGS, *PCSR_SHUTDOWN_FLAGS;

typedef enum _CSR_DEBUG_FLAGS {
    CsrDebugOnlyThisProcess = 1,
    CsrDebugProcessChildren = 2
} CSR_PROCESS_DEBUG_FLAGS, *PCSR_PROCESS_DEBUG_FLAGS;

typedef enum _CSR_REPLY_CODE {
    CsrReplyImmediately = 0,
    CsrReplyPending = 1,
    CsrReplyDeadClient = 2,
    CsrReplyAlreadySent = 3
} CSR_REPLY_CODE, *PCSR_REPLY_CODE;

/* FUNCTION TYPES AND STRUCTURES **********************************************/

/*
 * Server DLL structure
 */
typedef NTSTATUS (NTAPI *PCSR_API_ROUTINE)(IN OPTIONAL PCSR_THREAD Thread,
					   IN OUT PCSR_API_MESSAGE ApiMessage,
					   IN OUT PCSR_REPLY_CODE ReplyCode OPTIONAL);

#define CSR_API(n)							\
    NTAPI NTSTATUS n(IN OPTIONAL PCSR_THREAD Thread,			\
		     IN OUT PCSR_API_MESSAGE ApiMessage,		\
		     IN OUT OPTIONAL PCSR_REPLY_CODE ReplyCode)

typedef NTSTATUS (NTAPI *PCSR_CONNECT_CALLBACK)(IN PCSR_PROCESS CsrProcess,
						IN OUT PVOID ConnectionInfo,
						IN OUT PULONG ConnectionInfoLength);

typedef VOID (NTAPI *PCSR_DISCONNECT_CALLBACK)(IN PCSR_PROCESS CsrProcess);

typedef VOID (NTAPI *PCSR_HARDERROR_CALLBACK)(IN PCSR_THREAD CsrThread,
					      IN PHARDERROR_MSG HardErrorMessage);

typedef ULONG (NTAPI *PCSR_SHUTDOWNPROCESS_CALLBACK)(IN PCSR_PROCESS CsrProcess,
						     IN ULONG Flags,
						     IN BOOLEAN FirstPhase);

// See http://redplait.blogspot.fr/2011/07/csrserverdll.html
typedef struct _CSR_SERVER_DLL {
    ULONG Length;
    ULONG ServerId;
    UNICODE_STRING Name;
    HANDLE ServerHandle;
    ULONG ApiBase;
    ULONG HighestApiSupported;
    PCSR_API_ROUTINE *DispatchTable;
    /*
     * On Windows Server 2003, CSR Servers contain
     * the API Names Table only in Debug Builds.
     */
#ifdef CSR_DBG
    PCHAR *NameTable;
#endif
    PCSR_CONNECT_CALLBACK ConnectCallback;
    PCSR_DISCONNECT_CALLBACK DisconnectCallback;
    PCSR_HARDERROR_CALLBACK HardErrorCallback;
    PVOID SharedSection;
    PVOID SharedSection32;
    PCSR_SHUTDOWNPROCESS_CALLBACK ShutdownProcessCallback;
} CSR_SERVER_DLL, *PCSR_SERVER_DLL;

typedef NTSTATUS(NTAPI *PCSR_SERVER_DLL_INIT_CALLBACK)(IN PCSR_SERVER_DLL LoadedServerDll);

#define CSR_SERVER_DLL_INIT(n) NTAPI NTSTATUS n(IN PCSR_SERVER_DLL LoadedServerDll)

/* PROTOTYPES ****************************************************************/

CSR_SERVER_DLL_INIT(CsrServerDllInitialization);

NTAPI NTSYSAPI NTSTATUS CsrServerInitialization(IN PCUNICODE_STRING Arguments);

NTAPI NTSYSAPI NTSTATUS CsrStartServer(VOID);

NTAPI NTSYSAPI NTSTATUS CsrCallServerFromServer(IN PCSR_API_MESSAGE ReceiveMsg,
						IN OUT PCSR_API_MESSAGE ReplyMsg);

NTAPI NTSYSAPI NTSTATUS CsrCreateProcess(IN HANDLE hProcess, IN HANDLE hThread,
					 IN PCLIENT_ID ClientId, IN ULONG Flags,
					 IN PCLIENT_ID DebugCid);

NTAPI NTSYSAPI NTSTATUS CsrCreateRemoteThread(IN HANDLE hThread, IN PCLIENT_ID ClientId);

NTAPI NTSYSAPI NTSTATUS CsrCreateThread(IN PCSR_PROCESS CsrProcess, IN HANDLE hThread,
					IN PCLIENT_ID ClientId, IN BOOLEAN HaveClient);

NTAPI NTSYSAPI NTSTATUS CsrDebugProcess(IN PCSR_PROCESS CsrProcess);

NTAPI NTSYSAPI NTSTATUS CsrDebugProcessStop(IN PCSR_PROCESS CsrProcess);

NTAPI NTSYSAPI VOID CsrDereferenceProcess(IN PCSR_PROCESS CsrProcess);

NTAPI NTSYSAPI VOID CsrDereferenceThread(IN PCSR_THREAD CsrThread);

NTAPI NTSYSAPI NTSTATUS CsrDestroyProcess(IN PCLIENT_ID Cid, IN NTSTATUS ExitStatus);

NTAPI NTSYSAPI NTSTATUS CsrDestroyThread(IN PCLIENT_ID Cid);

NTAPI NTSYSAPI NTSTATUS CsrGetProcessLuid(IN HANDLE hProcess OPTIONAL, OUT PLUID Luid);

NTAPI NTSYSAPI BOOLEAN CsrImpersonateClient(IN PCSR_THREAD CsrThread);

NTAPI NTSYSAPI NTSTATUS CsrLockProcessByClientId(IN HANDLE Pid,
						 OUT PCSR_PROCESS *CsrProcess OPTIONAL);

NTAPI NTSYSAPI NTSTATUS CsrLockThreadByClientId(IN HANDLE Tid,
						OUT PCSR_THREAD *CsrThread);

NTAPI NTSYSAPI LOCAL_HANDLE CsrQueryApiPort(VOID);

NTAPI NTSYSAPI VOID CsrReferenceThread(IN PCSR_THREAD CsrThread);

NTAPI NTSYSAPI BOOLEAN CsrRevertToSelf(VOID);

NTAPI NTSYSAPI VOID CsrSetBackgroundPriority(IN PCSR_PROCESS CsrProcess);

NTAPI NTSYSAPI VOID CsrSetForegroundPriority(IN PCSR_PROCESS CsrProcess);

NTAPI NTSYSAPI NTSTATUS CsrShutdownProcesses(IN PLUID CallerLuid, IN ULONG Flags);

NTAPI NTSYSAPI EXCEPTION_DISPOSITION
CsrUnhandledExceptionFilter(IN PEXCEPTION_POINTERS ExceptionInfo);

NTAPI NTSYSAPI NTSTATUS CsrUnlockProcess(IN PCSR_PROCESS CsrProcess);

NTAPI NTSYSAPI NTSTATUS CsrUnlockThread(IN PCSR_THREAD CsrThread);

NTAPI NTSYSAPI BOOLEAN CsrValidateMessageBuffer(IN PCSR_API_MESSAGE ApiMessage,
						IN PVOID *Buffer, IN ULONG ElementCount,
						IN ULONG ElementSize);

NTAPI NTSYSAPI BOOLEAN CsrValidateMessageString(IN PCSR_API_MESSAGE ApiMessage,
						IN PWSTR *MessageString);

#endif // _CSRSRV_H

/* EOF */
