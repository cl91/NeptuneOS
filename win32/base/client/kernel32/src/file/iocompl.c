/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/iocompl.c
 * PURPOSE:         Io Completion functions
 * PROGRAMMERS:     Ariadne (ariadne@xs4all.nl)
 *                  Oleg Dubinskiy (oleg.dubinskij30@gmail.com)
 * UPDATE HISTORY:
 *                  Created 01/11/98
 */

#include <k32.h>

/*
 * SetFileCompletionNotificationModes is not entirely Vista-exclusive,
 * it was actually added to Windows 2003 in SP2. Headers restrict it from
 * pre-Vista though so define the flags we need for it.
 */
#if (_WIN32_WINNT < 0x0600)
#define FILE_SKIP_COMPLETION_PORT_ON_SUCCESS 0x1
#define FILE_SKIP_SET_EVENT_ON_HANDLE 0x2
#endif

static struct {
    HANDLE CompletionPort;
    RTL_CRITICAL_SECTION ThreadPoolLock;
} OldThreadPool;

VOID BasepInitializeOldThreadPool(VOID)
{
    NTSTATUS Status = RtlInitializeCriticalSection(&OldThreadPool.ThreadPoolLock);
    if (!NT_SUCCESS(Status)) {
	RtlRaiseStatus(Status);
    }
}

/***********************************************************************
 * iocp_poller - get completion events and run callbacks
 */
static NTAPI VOID IocpPoller(HANDLE IoCp)
{
    while (TRUE) {
        LPOVERLAPPED_COMPLETION_ROUTINE Callback;
	LPVOID ApcContext;
	IO_STATUS_BLOCK Iosb;
	NTSTATUS Status = NtRemoveIoCompletion(IoCp, (PVOID)&Callback, &ApcContext,
					       &Iosb, NULL);
	if (!NT_SUCCESS(Status)) {
	    ERR("NtRemoveIoCompletion failed: 0x%x\n", Status);
	} else {
            DWORD Transferred = 0;
            DWORD Err = 0;

            if (Iosb.Status == STATUS_SUCCESS)
                Transferred = Iosb.Information;
            else
                Err = RtlNtStatusToDosError(Iosb.Status);

            Callback(Err, Transferred, ApcContext);
	}
    }
}

/***********************************************************************
 *              RtlSetIoCompletionCallback  (NTDLL.@)
 *
 * Binds a handle to a thread pool's completion port, and possibly
 * starts a non-I/O thread to monitor this port and call functions back.
 *
 * PARAMS
 *  FileHandle [I] Handle to bind to a completion port.
 *  Function   [I] Callback function to call on I/O completions.
 *  Flags      [I] Not used.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 *
 */
NTAPI NTSTATUS RtlSetIoCompletionCallback(HANDLE FileHandle,
					  LPOVERLAPPED_COMPLETION_ROUTINE Function,
					  ULONG Flags)
{
    IO_STATUS_BLOCK Iosb;
    FILE_COMPLETION_INFORMATION Info;

    if (Flags)
	FIXME("Unknown value Flags=0x%x\n", Flags);

    /* If the IO completion port does not exist yet, create it. */
    if (!OldThreadPool.CompletionPort) {
	NTSTATUS Status = STATUS_SUCCESS;

	RtlEnterCriticalSection(&OldThreadPool.ThreadPoolLock);
	if (!OldThreadPool.CompletionPort) {
	    HANDLE IoCp;

	    Status = NtCreateIoCompletion(&IoCp, IO_COMPLETION_ALL_ACCESS, NULL, 0);
	    if (NT_SUCCESS(Status)) {
		/* FIXME native can start additional threads in case of e.g. hung callback
		 * function. */
		Status = RtlQueueWorkItem(IocpPoller, IoCp, WT_EXECUTEDEFAULT);
		if (NT_SUCCESS(Status))
		    OldThreadPool.CompletionPort = IoCp;
		else
		    NtClose(IoCp);
	    }
	}
	RtlLeaveCriticalSection(&OldThreadPool.ThreadPoolLock);
	if (!NT_SUCCESS(Status))
	    return Status;
    }

    Info.Port = OldThreadPool.CompletionPort;
    Info.Key = Function;

    return NtSetInformationFile(FileHandle, &Iosb, &Info, sizeof(Info),
				FileCompletionInformation);
}

/*
 * @implemented
 */
WINAPI BOOL SetFileCompletionNotificationModes(IN HANDLE FileHandle, IN UCHAR Flags)
{
    NTSTATUS Status;
    FILE_IO_COMPLETION_NOTIFICATION_INFORMATION FileInformation;
    IO_STATUS_BLOCK IoStatusBlock;

    if (Flags & ~(FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    FileInformation.Flags = Flags;

    Status = NtSetInformationFile(FileHandle, &IoStatusBlock, &FileInformation,
				  sizeof(FileInformation),
				  FileIoCompletionNotificationInformation);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI HANDLE CreateIoCompletionPort(IN HANDLE FileHandle,
				     IN HANDLE ExistingCompletionPort,
				     IN ULONG_PTR CompletionKey,
				     IN DWORD NumberOfConcurrentThreads)
{
    NTSTATUS Status;
    HANDLE NewPort;
    FILE_COMPLETION_INFORMATION CompletionInformation;
    IO_STATUS_BLOCK IoStatusBlock;

    /* Check if this is a new port */
    NewPort = ExistingCompletionPort;
    if (!ExistingCompletionPort) {
	/* Create it */
	Status = NtCreateIoCompletion(&NewPort, IO_COMPLETION_ALL_ACCESS, NULL,
				      NumberOfConcurrentThreads);
	if (!NT_SUCCESS(Status)) {
	    /* Convert error and fail */
	    BaseSetLastNTError(Status);
	    return FALSE;
	}
    }

    /* Check if no actual file is being associated with the completion port */
    if (FileHandle == INVALID_HANDLE_VALUE) {
	/* Was there a port already associated? */
	if (ExistingCompletionPort) {
	    /* You are not allowed using an old port and dropping the handle */
	    NewPort = NULL;
	    BaseSetLastNTError(STATUS_INVALID_PARAMETER);
	}
    } else {
	/* We have a file handle, so associated it with this completion port */
	CompletionInformation.Port = NewPort;
	CompletionInformation.Key = (PVOID)CompletionKey;
	Status = NtSetInformationFile(FileHandle, &IoStatusBlock, &CompletionInformation,
				      sizeof(FILE_COMPLETION_INFORMATION),
				      FileCompletionInformation);
	if (!NT_SUCCESS(Status)) {
	    /* Convert the error code and close the newly created port, if any */
	    BaseSetLastNTError(Status);
	    if (!ExistingCompletionPort)
		NtClose(NewPort);
	    return FALSE;
	}
    }

    /* Return the newly created port, if any */
    return NewPort;
}

/*
 * @implemented
 */
WINAPI BOOL GetQueuedCompletionStatus(IN HANDLE CompletionHandle,
				      IN LPDWORD lpNumberOfBytesTransferred,
				      OUT PULONG_PTR lpCompletionKey,
				      OUT LPOVERLAPPED *lpOverlapped,
				      IN DWORD dwMilliseconds)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;
    ULONG_PTR CompletionKey;
    LARGE_INTEGER Time;
    PLARGE_INTEGER TimePtr;

    /* Convert the timeout and then call the native API */
    TimePtr = BaseFormatTimeOut(&Time, dwMilliseconds);
    Status = NtRemoveIoCompletion(CompletionHandle, (PVOID *)&CompletionKey,
				  (PVOID *)lpOverlapped, &IoStatus, TimePtr);
    if (!(NT_SUCCESS(Status)) || (Status == STATUS_TIMEOUT)) {
	/* Clear out the overlapped output */
	*lpOverlapped = NULL;

	/* Check what kind of error we got */
	if (Status == STATUS_TIMEOUT) {
	    /* Timeout error is set directly since there's no conversion */
	    SetLastError(WAIT_TIMEOUT);
	} else {
	    /* Any other error gets converted */
	    BaseSetLastNTError(Status);
	}

	/* This is a failure case */
	return FALSE;
    }

    /* Write back the output parameters */
    *lpCompletionKey = CompletionKey;
    *lpNumberOfBytesTransferred = IoStatus.Information;

    /* Check for error */
    if (!NT_SUCCESS(IoStatus.Status)) {
	/* Convert and fail */
	BaseSetLastNTError(IoStatus.Status);
	return FALSE;
    }

    /* Return success */
    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL PostQueuedCompletionStatus(IN HANDLE CompletionHandle,
				       IN DWORD dwNumberOfBytesTransferred,
				       IN ULONG_PTR dwCompletionKey,
				       IN LPOVERLAPPED lpOverlapped)
{
    NTSTATUS Status;

    /* Call the native API */
    Status = NtSetIoCompletion(CompletionHandle, (PVOID)dwCompletionKey,
			       (PVOID)lpOverlapped, STATUS_SUCCESS,
			       dwNumberOfBytesTransferred);
    if (!NT_SUCCESS(Status)) {
	/* Convert the error and fail */
	BaseSetLastNTError(Status);
	return FALSE;
    }

    /* Success path */
    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL GetOverlappedResult(IN HANDLE hFile, IN LPOVERLAPPED lpOverlapped,
				OUT LPDWORD lpNumberOfBytesTransferred, IN BOOL bWait)
{
    DWORD WaitStatus;
    HANDLE hObject;

    /* Check for pending operation */
    if (lpOverlapped->Internal == STATUS_PENDING) {
	/* Check if the caller is okay with waiting */
	if (!bWait) {
	    /* Set timeout */
	    WaitStatus = WAIT_TIMEOUT;
	} else {
	    /* Wait for the result */
	    hObject = lpOverlapped->hEvent ? lpOverlapped->hEvent : hFile;
	    WaitStatus = WaitForSingleObject(hObject, INFINITE);
	}

	/* Check for timeout */
	if (WaitStatus == WAIT_TIMEOUT) {
	    /* We have to override the last error with INCOMPLETE instead */
	    SetLastError(ERROR_IO_INCOMPLETE);
	    return FALSE;
	}

	/* Fail if we had an error -- the last error is already set */
	if (WaitStatus)
	    return FALSE;
    }

    /* Return bytes transferred */
    *lpNumberOfBytesTransferred = lpOverlapped->InternalHigh;

    /* Check for failure during I/O */
    if (!NT_SUCCESS(lpOverlapped->Internal)) {
	/* Set the error and fail */
	BaseSetLastNTError(lpOverlapped->Internal);
	return FALSE;
    }

    /* All done */
    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL BindIoCompletionCallback(IN HANDLE FileHandle,
				     IN LPOVERLAPPED_COMPLETION_ROUTINE Function,
				     IN ULONG Flags)
{
    NTSTATUS Status;

    /* Call RTL */
    Status = RtlSetIoCompletionCallback(FileHandle, Function, Flags);
    if (!NT_SUCCESS(Status)) {
	/* Set error and fail */
	BaseSetLastNTError(Status);
	return FALSE;
    }

    /* Return success */
    return TRUE;
}

/* EOF */
