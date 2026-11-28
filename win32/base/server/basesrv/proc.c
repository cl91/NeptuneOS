/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Base API Server DLL
 * FILE:            subsystems/win/basesrv/proc.c
 * PURPOSE:         Process and Thread Management
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "basesrv.h"

/* GLOBALS ********************************************************************/

/* User notification procedure to be called when a process is created */
static BASE_PROCESS_CREATE_NOTIFY_ROUTINE UserNotifyProcessCreate = NULL;

/* PUBLIC SERVER APIS *********************************************************/

CSR_API(BaseSrvDebugProcess)
{
    /* Deprecated */
    return STATUS_UNSUCCESSFUL;
}

CSR_API(BaseSrvRegisterThread)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvSxsCreateActivationContext)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvSetTermsrvAppInstallMode)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvSetTermsrvClientTimeZone)
{
    DPRINT1("%s not yet implemented\n", __FUNCTION__);
    return STATUS_NOT_IMPLEMENTED;
}

CSR_API(BaseSrvGetTempFile)
{
    static UINT BaseGetTempFileUnique = 0;
    PBASE_GET_TEMP_FILE GetTempFile =
	&((PBASE_API_MESSAGE)ApiMessage)->Data.GetTempFileRequest;

    /* Return 16-bits ID */
    GetTempFile->UniqueID = (++BaseGetTempFileUnique & 0xFFFF);

    DPRINT("Returning: %u\n", GetTempFile->UniqueID);

    return GetTempFile->UniqueID;
}

CSR_API(BaseSrvCreateProcess)
{
    NTSTATUS Status;
    PBASE_CREATE_PROCESS CreateProcessRequest =
	&((PBASE_API_MESSAGE)ApiMessage)->Data.CreateProcessRequest;
    HANDLE ProcessHandle, ThreadHandle;
    PCSR_PROCESS Process;
    ULONG Flags = 0, DebugFlags = 0;

    /* Get the current client thread */
    ASSERT(Thread != NULL);

    Process = Thread->Process;

    /* Extract the flags out of the process handle */
    Flags = (ULONG_PTR)CreateProcessRequest->ProcessHandle & 3;
    CreateProcessRequest->ProcessHandle =
	(HANDLE)((ULONG_PTR)CreateProcessRequest->ProcessHandle & ~3);

    /* Duplicate the process handle */
    Status = NtDuplicateObject(Process->ProcessHandle,
			       CreateProcessRequest->ProcessHandle, NtCurrentProcess(),
			       &ProcessHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to duplicate process handle: %x\n", Status);
	return Status;
    }

    /* Duplicate the thread handle */
    Status = NtDuplicateObject(Process->ProcessHandle, CreateProcessRequest->ThreadHandle,
			       NtCurrentProcess(), &ThreadHandle, 0, 0,
			       DUPLICATE_SAME_ACCESS);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to duplicate thread handle: %x\n", Status);
	NtClose(ProcessHandle);
	return Status;
    }

    /* Flags conversion. FIXME: More need conversion */
    if (CreateProcessRequest->CreationFlags & CREATE_NEW_PROCESS_GROUP) {
	DebugFlags |= CsrProcessCreateNewGroup;
    }
    if ((Flags & 2) == 0) {
	/* We are launching a console process */
	DebugFlags |= CsrProcessIsConsoleApp;
    }

    /* FIXME: SxS Stuff */

    /* Call CSRSRV to create the CSR_PROCESS structure and the first CSR_THREAD */
    Status = CsrCreateProcess(ProcessHandle, ThreadHandle,
			      &CreateProcessRequest->ClientId,
			      DebugFlags, NULL);
    if (Status == STATUS_THREAD_IS_TERMINATING) {
	DPRINT1("Thread already dead\n");
	NtClose(ProcessHandle);
	NtClose(ThreadHandle);

	/* Set the special reply value so we don't reply this message back */
	*ReplyCode = CsrReplyDeadClient;

	return Status;
    }

    /* Check for other failures */
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to create process/thread structures: %x\n", Status);
	NtClose(ProcessHandle);
	NtClose(ThreadHandle);
	return Status;
    }

    /* Call the user notification procedure */
    if (UserNotifyProcessCreate) {
	UserNotifyProcessCreate(CreateProcessRequest->ClientId.UniqueProcess,
				Thread->ClientId.UniqueThread, 0, Flags);
    }

    /* Return the result of this operation */
    return Status;
}

CSR_API(BaseSrvCreateThread)
{
    NTSTATUS Status;
    PBASE_CREATE_THREAD CreateThreadRequest =
	&((PBASE_API_MESSAGE)ApiMessage)->Data.CreateThreadRequest;
    HANDLE ThreadHandle;
    PCSR_PROCESS CsrProcess;

    /* Get the current CSR thread */
    if (!Thread) {
	DPRINT1("Server Thread TID: [%p.%p]\n",
		CreateThreadRequest->ClientId.UniqueProcess,
		CreateThreadRequest->ClientId.UniqueThread);
	return STATUS_SUCCESS; // server-to-server
    }

    /* Get the CSR Process for this request */
    CsrProcess = Thread->Process;
    if (CsrProcess->ClientId.UniqueProcess !=
	CreateThreadRequest->ClientId.UniqueProcess) {
	/* This is a remote thread request -- is it within the server itself? */
	if (CreateThreadRequest->ClientId.UniqueProcess ==
	    NtCurrentTeb()->NtTib.ClientId.UniqueProcess) {
	    /* Accept this without any further work */
	    return STATUS_SUCCESS;
	}

	/* Get the real CSR Process for the remote thread's process */
	Status = CsrLockProcessByClientId(CreateThreadRequest->ClientId.UniqueProcess,
					  &CsrProcess);
	if (!NT_SUCCESS(Status))
	    return Status;
    }

    /* Duplicate the thread handle so we can own it */
    Status = NtDuplicateObject(Thread->Process->ProcessHandle,
			       CreateThreadRequest->ThreadHandle, NtCurrentProcess(),
			       &ThreadHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    if (NT_SUCCESS(Status)) {
	/* Call CSRSRV to tell it about the new thread */
	Status = CsrCreateThread(CsrProcess, ThreadHandle, &CreateThreadRequest->ClientId,
				 TRUE);
	if (!NT_SUCCESS(Status)) {
	    NtClose(ThreadHandle);
	}
    }

    /* Unlock the process and return */
    if (CsrProcess != Thread->Process)
	CsrUnlockProcess(CsrProcess);
    return Status;
}

CSR_API(BaseSrvExitProcess)
{
    ASSERT(Thread != NULL);

    /* Set the special reply value so we don't reply this message back */
    *ReplyCode = CsrReplyDeadClient;

    /* Remove the CSR_THREADs and CSR_PROCESS */
    PBASE_API_MESSAGE BaseMsg = (PVOID)ApiMessage;
    return CsrDestroyProcess(&Thread->ClientId,
			     (NTSTATUS)BaseMsg->Data.ExitProcessRequest.uExitCode);
}

CSR_API(BaseSrvGetProcessShutdownParam)
{
    PBASE_GETSET_PROCESS_SHUTDOWN_PARAMS ShutdownParametersRequest =
	&((PBASE_API_MESSAGE)ApiMessage)->Data.ShutdownParametersRequest;
    ASSERT(Thread);

    ShutdownParametersRequest->ShutdownLevel = Thread->Process->ShutdownLevel;
    /* Only SHUTDOWN_NORETRY flag is valid for this API. The other private flags are for
     * CSRSRV/WINSRV only. */
    ShutdownParametersRequest->ShutdownFlags = Thread->Process->ShutdownFlags &
					       SHUTDOWN_NORETRY;

    return STATUS_SUCCESS;
}

CSR_API(BaseSrvSetProcessShutdownParam)
{
    PBASE_GETSET_PROCESS_SHUTDOWN_PARAMS ShutdownParametersRequest =
	&((PBASE_API_MESSAGE)ApiMessage)->Data.ShutdownParametersRequest;
    ASSERT(Thread);

    /* Only SHUTDOWN_NORETRY flag is valid for this API. The other private flags are for
     * CSRSRV/WINSRV only. */
    if (ShutdownParametersRequest->ShutdownFlags & ~SHUTDOWN_NORETRY) {
	/* If there were other flags specified, fail the call */
	return STATUS_INVALID_PARAMETER;
    }

    Thread->Process->ShutdownLevel = ShutdownParametersRequest->ShutdownLevel;
    /* Notice that all the possible other private flags are reinitialized here */
    Thread->Process->ShutdownFlags = ShutdownParametersRequest->ShutdownFlags;

    return STATUS_SUCCESS;
}

/* PUBLIC API *****************************************************************/

NTAPI VOID BaseSetProcessCreateNotify(IN BASE_PROCESS_CREATE_NOTIFY_ROUTINE Proc)
{
    /* Set the user notification procedure to be called when a process is created */
    UserNotifyProcessCreate = Proc;
}

/* EOF */
