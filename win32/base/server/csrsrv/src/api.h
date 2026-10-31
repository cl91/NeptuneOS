/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            subsystems/win32/csrsrv/api.h
 * PURPOSE:         CSRSS Internal API
 */

#pragma once

#include <nt.h>
#include <csrsrv.h>

extern RTL_CRITICAL_SECTION CsrProcessLock, CsrWaitListsLock;

#define CsrAcquireProcessLock() RtlEnterCriticalSection(&CsrProcessLock);

#define CsrReleaseProcessLock() RtlLeaveCriticalSection(&CsrProcessLock);

#define ProcessStructureListLocked() \
    (CsrProcessLock.OwningThread == NtCurrentTeb()->NtTib.ClientId.UniqueThread)

#define CsrAcquireWaitLock() RtlEnterCriticalSection(&CsrWaitListsLock);

#define CsrReleaseWaitLock() RtlLeaveCriticalSection(&CsrWaitListsLock);

#define CsrAcquireNtSessionLock() RtlEnterCriticalSection(&CsrNtSessionLock);

#define CsrReleaseNtSessionLock() RtlLeaveCriticalSection(&CsrNtSessionLock);

#define CSR_SERVER_DLL_MAX 4

// Debug Flag
extern ULONG CsrDebug;

extern HANDLE hBootstrapOk;
extern LOCAL_HANDLE CsrApiCommPort;
extern LOCAL_HANDLE CsrSmApiCommPort;
extern LOCAL_HANDLE CsrSbApiCommPort;
#define NUMBER_THREAD_HASH_BUCKETS 257
extern LIST_ENTRY CsrThreadHashTable[NUMBER_THREAD_HASH_BUCKETS];
extern PCSR_PROCESS CsrRootProcess;
extern UNICODE_STRING CsrDirectoryName;
extern ULONG CsrTotalPerProcessDataLength;
extern SYSTEM_BASIC_INFORMATION CsrNtSysInfo;
extern HANDLE CsrHeap;
extern PVOID CsrSrvSharedSectionHeap;
extern PVOID *CsrSrvSharedStaticServerData;
extern PULONG CsrSrvSharedStaticServerData32;
extern HANDLE CsrInitializationEvent;
extern PCSR_SERVER_DLL CsrLoadedServerDll[CSR_SERVER_DLL_MAX];
extern ULONG CsrMaxApiRequestThreads;

/****************************************************/
extern UNICODE_STRING CsrSbApiPortName;
extern UNICODE_STRING CsrApiPortName;
extern RTL_CRITICAL_SECTION CsrProcessLock;
extern RTL_CRITICAL_SECTION CsrWaitListsLock;
extern HANDLE CsrObjectDirectory;
/****************************************************/

CSR_API(CsrSrvClientConnect);
CSR_API(CsrSrvUnusedFunction);

NTAPI NTSTATUS CsrServerDllInitialization(IN PCSR_SERVER_DLL LoadedServerDll);

NTAPI BOOLEAN CsrCaptureArguments(IN PCSR_THREAD CsrThread,
				  IN PCSR_API_MESSAGE ApiMessage);

NTAPI VOID CsrReleaseCapturedArguments(IN PCSR_API_MESSAGE ApiMessage);

NTAPI NTSTATUS CsrLoadServerDll(IN PCUNICODE_STRING DllString,
				IN PCUNICODE_STRING EntryPoint OPTIONAL,
				IN ULONG ServerId);

NTAPI PCSR_THREAD CsrAllocateThread(IN PCSR_PROCESS CsrProcess);

NTAPI PCSR_PROCESS CsrAllocateProcess(VOID);

NTAPI VOID CsrDeallocateProcess(IN PCSR_PROCESS CsrProcess);

NTAPI VOID CsrInsertProcess(IN PCSR_PROCESS ParentProcess OPTIONAL,
			    IN PCSR_PROCESS CsrProcess);

NTAPI VOID CsrRemoveProcess(IN PCSR_PROCESS CsrProcess);

NTAPI NTSTATUS CsrApiRequestThread(IN PVOID Parameter);

NTAPI VOID CsrSbApiRequestThread(IN PVOID Parameter);

NTAPI NTSTATUS CsrApiPortInitialize(VOID);

NTAPI BOOLEAN ProtectHandle(IN HANDLE ObjectHandle);

NTAPI BOOLEAN UnProtectHandle(IN HANDLE ObjectHandle);

NTAPI NTSTATUS CsrInsertThread(IN PCSR_PROCESS Process, IN PCSR_THREAD Thread);

NTAPI VOID CsrDeallocateThread(IN PCSR_THREAD CsrThread);

NTAPI VOID CsrLockedReferenceProcess(IN PCSR_PROCESS CsrProcess);

NTAPI VOID CsrLockedReferenceThread(IN PCSR_THREAD CsrThread);

NTAPI NTSTATUS CsrInitializeProcessStructure(VOID);

NTAPI PCSR_THREAD CsrLocateThreadInProcess(IN PCSR_PROCESS CsrProcess OPTIONAL,
					   IN PCLIENT_ID Cid);
NTAPI PCSR_THREAD CsrLocateThreadByClientId(OUT PCSR_PROCESS *Process OPTIONAL,
					    IN PCLIENT_ID ClientId);

NTAPI NTSTATUS CsrInitializeNtSessionList(VOID);

NTAPI NTSTATUS CsrSrvAttachSharedSection(IN PCSR_PROCESS CsrProcess OPTIONAL,
					 OUT PCSR_API_CONNECTINFO ConnectInfo);

NTAPI NTSTATUS CsrSrvCreateSharedSection(IN PCUNICODE_STRING ParameterValue);

NTAPI VOID CsrLockedDereferenceProcess(PCSR_PROCESS CsrProcess);

NTAPI VOID CsrLockedDereferenceThread(IN PCSR_THREAD CsrThread);

NTAPI BOOLEAN CsrNotifyWaitBlock(IN PCSR_WAIT_BLOCK WaitBlock, IN PLIST_ENTRY WaitList,
				 IN PVOID WaitArgument1, IN PVOID WaitArgument2,
				 IN ULONG WaitFlags, IN BOOLEAN DereferenceThread);

NTAPI VOID CsrReferenceNtSession(IN PCSR_NT_SESSION Session);

NTAPI VOID CsrDereferenceNtSession(IN PCSR_NT_SESSION Session, IN NTSTATUS ExitStatus);

/******************************************************************************
 ******************************************************************************/

NTAPI NTSTATUS CsrCreateSessionObjectDirectory(IN ULONG SessionId);

NTAPI NTSTATUS CsrCreateObjectDirectory(IN PCHAR ObjectDirectory);

NTAPI NTSTATUS CsrSbApiPortInitialize(VOID);

NTAPI BOOLEAN CsrSbCreateSession(IN PSB_API_MSG ApiMessage);

NTAPI BOOLEAN CsrSbTerminateSession(IN PSB_API_MSG ApiMessage);

NTAPI BOOLEAN CsrSbForeignSessionComplete(IN PSB_API_MSG ApiMessage);

NTAPI BOOLEAN CsrSbCreateProcess(IN PSB_API_MSG ApiMessage);

NTAPI NTSTATUS CsrSbApiHandleConnectionRequest(IN PSB_API_MSG Message);

NTAPI NTSTATUS CsrApiHandleConnectionRequest(IN PCSR_API_MESSAGE ApiMessage);

/** this API is used with CsrPopulateDosDevices, deprecated in r55585.
NTAPI NTSTATUS CsrPopulateDosDevicesDirectory(IN HANDLE DosDevicesDirectory,
			       IN PPROCESS_DEVICEMAP_INFORMATION DeviceMap);
**/

NTAPI NTSTATUS CsrCreateLocalSystemSD(OUT PSECURITY_DESCRIPTOR *LocalSystemSd);

NTAPI NTSTATUS CsrSetDirectorySecurity(IN HANDLE ObjectDirectory);

/* EOF */
