/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/srv.h
 * PURPOSE:         Main header - Definitions
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 *                  ReactOS Portable Systems Group
 */

#ifndef _SRV_H
#define _SRV_H

#include <nt.h>
#include <csrsrv.h>
#include <smlib.h>

/* Defines */
#define SM_REG_KEY \
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager"

#define SESSION_ROOT L"\\Sessions"
#define GLOBAL_ROOT L"\\GLOBAL??"
#define SYMLINK_NAME L"SymbolicLink"
#define SB_PORT_NAME L"SbApiPort"
#define CSR_PORT_NAME L"ApiPort"
#define UNICODE_PATH_SEP L"\\"

#define ROUND_UP(n, align) ROUND_DOWN(((ULONG)(n)) + (align) - 1, (align))
#define ROUND_DOWN(n, align) (((ULONG)(n)) & ~((align) - 1l))
#define InterlockedIncrementUL(Value) (ULONG) _InterlockedIncrement((volatile long *)(Value))
#define InterlockedDecrementUL(Value) (ULONG) _InterlockedDecrement((volatile long *)(Value))

#define CSR_SERVER_DLL_MAX 8
#define NUMBER_THREAD_HASH_BUCKETS 257

/*
 * Represents a server process. There is exactly one such struct per csrss process.
 * Note different csrss processes do not share any memory. Each NT session belongs
 * to one csrss process.
 */
typedef struct _CSR_SERVER {
    ULONG SessionId;
    ULONG DebugFlags;
    WCHAR ObjectDirectoryName[64];
    LOCAL_HANDLE SmApiCommPort;
    HANDLE SbEventHandle; /* Event that the SMSS will signal to send us messages */
    HANDLE CsrApiPort;
    LOCAL_HANDLE CsrApiCommPort;
    struct _CSR_SERVER_THREAD *CsrSbApiRequestThreadPtr;
    LIST_ENTRY ServerThreadList;
    LIST_ENTRY ClientProcessList;
    LIST_ENTRY ClientThreadHashTable[NUMBER_THREAD_HASH_BUCKETS];
    RTL_CRITICAL_SECTION ClientProcessLock;
    HANDLE SessionObjectDirectory;
    ULONG ProcessSequenceCount;
    ULONG SharedSectionSize;
    PVOID SharedSectionHeap;
    HANDLE SharedSection;
    PVOID SharedSectionBase;
    PPVOID SharedStaticServerData; /* Allocated from the shared section above */
    PULONG SharedStaticServerData32; /* Allocated from the shared section above */
    HANDLE InitializationEvent;
    PCSR_SERVER_DLL LoadedServerDll[CSR_SERVER_DLL_MAX];
    WCHAR ServerDllNames[CSR_SERVER_DLL_MAX][32];
    CHAR ServerDllEntryPoints[CSR_SERVER_DLL_MAX][128];
} CSR_SERVER, *PCSR_SERVER;

/*
 * Represents a server thread in the server process
 */
typedef struct _CSR_SERVER_THREAD {
    PCSR_SERVER Process;
    CLIENT_ID Id;
    LIST_ENTRY Link; /* List link for CSR_SERVER_PROCESS::ServerThreadList */
    HANDLE ThreadHandle;
} CSR_SERVER_THREAD, *PCSR_SERVER_THREAD;

extern PCSR_SERVER CsrSrv;

FORCEINLINE VOID CsrpAcquireProcessLock(VOID)
{
    RtlEnterCriticalSection(&CsrSrv->ClientProcessLock);
}

FORCEINLINE VOID CsrpReleaseProcessLock(VOID)
{
    RtlLeaveCriticalSection(&CsrSrv->ClientProcessLock);
}

FORCEINLINE BOOLEAN CsrpProcessStructureListLocked()
{
    return CsrSrv->ClientProcessLock.OwningThread ==
	NtCurrentTeb()->NtTib.ClientId.UniqueThread;
}

FORCEINLINE PCSR_THREAD CsrpGetClientThread(VOID)
{
    /* TODO: Get the CSR_THREAD pointer from the fiber data */
    return ((PCSR_THREAD)(NtCurrentTeb()->NtTib.FiberData));
}

/* api.c */
NTSTATUS CsrpApiPortInitialize(VOID);

VOID CsrpReleaseCapturedArguments(IN PCSR_API_MESSAGE ApiMessage);

/* procsup.c */
PCSR_PROCESS CsrpAllocateClientProcess(VOID);

VOID CsrpDeallocateClientProcess(IN PCSR_PROCESS CsrProcess);

VOID CsrpInsertProcess(IN PCSR_PROCESS CsrProcess);

NTSTATUS CsrpDestroyProcess(IN PCSR_THREAD CsrThread, IN NTSTATUS ExitStatus);

VOID CsrpLockedReferenceClientProcess(IN PCSR_PROCESS CsrProcess);

VOID CsrpLockedDereferenceClientProcess(PCSR_PROCESS CsrProcess);

/* thredsup.c */

BOOLEAN CsrpProtectHandle(IN HANDLE ObjectHandle);

BOOLEAN CsrpUnProtectHandle(IN HANDLE ObjectHandle);

PCSR_THREAD CsrpAllocateClientThread(IN PCSR_PROCESS CsrProcess);

NTSTATUS CsrpInsertClientThread(IN PCSR_PROCESS Process, IN PCSR_THREAD Thread);

VOID CsrpDeallocateClientThread(IN PCSR_THREAD CsrThread);

VOID CsrpLockedReferenceClientThread(IN PCSR_THREAD CsrThread);

VOID CsrpLockedDereferenceClientThread(IN PCSR_THREAD CsrThread);

PCSR_THREAD CsrpLocateClientThreadByThreadId(OUT OPTIONAL PCSR_PROCESS *Process,
					     IN HANDLE ThreadId);

/* server.c */
NTSTATUS CsrpLoadServerDlls(VOID);

NTSTATUS CsrpAttachSharedSection(IN PCSR_PROCESS CsrProcess OPTIONAL,
				 OUT PCSR_API_CONNECTINFO ConnectInfo);

NTSTATUS CsrpCreateSharedSection(VOID);

#endif /* _SRV_H */
