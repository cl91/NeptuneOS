/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/copy.c
 * PURPOSE:         Copying files
 * PROGRAMMER:      Ariadne (ariadne@xs4all.nl)
 * UPDATE HISTORY:
 *                  01/11/98 Created
 *                  07/02/99 Moved to separate file
 */

/* INCLUDES ****************************************************************/

#include <k32.h>

#if DBG
DEBUG_CHANNEL(kernel32file);
#endif

/* FUNCTIONS ****************************************************************/

static NTSTATUS CopyLoop(HANDLE FileHandleSource, HANDLE FileHandleDest,
			 LARGE_INTEGER SourceFileSize,
			 LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData,
			 BOOL *pbCancel, BOOL *KeepDest)
{
    NTSTATUS ErrCode;
    IO_STATUS_BLOCK IoStatusBlock;
    UCHAR *lpBuffer = NULL;
    SIZE_T RegionSize = 0x10000;
    LARGE_INTEGER BytesCopied;
    DWORD CallbackReason;
    DWORD ProgressResult;
    BOOL EndOfFileFound;

    *KeepDest = FALSE;
    ErrCode = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID *)&lpBuffer, 0,
				      &RegionSize, MEM_RESERVE | MEM_COMMIT,
				      PAGE_READWRITE);

    if (NT_SUCCESS(ErrCode)) {
	BytesCopied.QuadPart = 0;
	EndOfFileFound = FALSE;
	CallbackReason = CALLBACK_STREAM_SWITCH;
	while (!EndOfFileFound && NT_SUCCESS(ErrCode) &&
	       (NULL == pbCancel || !*pbCancel)) {
	    if (NULL != lpProgressRoutine) {
		ProgressResult = (*lpProgressRoutine)(SourceFileSize, BytesCopied,
						      SourceFileSize, BytesCopied, 0,
						      CallbackReason, FileHandleSource,
						      FileHandleDest, lpData);
		switch (ProgressResult) {
		case PROGRESS_CANCEL:
		    TRACE("Progress callback requested cancel\n");
		    ErrCode = STATUS_REQUEST_ABORTED;
		    break;
		case PROGRESS_STOP:
		    TRACE("Progress callback requested stop\n");
		    ErrCode = STATUS_REQUEST_ABORTED;
		    *KeepDest = TRUE;
		    break;
		case PROGRESS_QUIET:
		    lpProgressRoutine = NULL;
		    break;
		case PROGRESS_CONTINUE:
		default:
		    break;
		}
		CallbackReason = CALLBACK_CHUNK_FINISHED;
	    }
	    if (NT_SUCCESS(ErrCode)) {
		ErrCode = NtReadFile(FileHandleSource, NULL, NULL, NULL,
				     (PIO_STATUS_BLOCK)&IoStatusBlock, lpBuffer,
				     RegionSize, NULL, NULL);
		/* With sync read, 0 length + status success mean EOF:
		 * https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
		 */
		if (NT_SUCCESS(ErrCode) && IoStatusBlock.Information == 0) {
		    ErrCode = STATUS_END_OF_FILE;
		}
		if (NT_SUCCESS(ErrCode) && (NULL == pbCancel || !*pbCancel)) {
		    ErrCode = NtWriteFile(FileHandleDest, NULL, NULL, NULL,
					  (PIO_STATUS_BLOCK)&IoStatusBlock, lpBuffer,
					  IoStatusBlock.Information, NULL, NULL);
		    if (NT_SUCCESS(ErrCode)) {
			BytesCopied.QuadPart += IoStatusBlock.Information;
		    } else {
			WARN("Error 0x%08x reading writing to dest\n", ErrCode);
		    }
		} else if (!NT_SUCCESS(ErrCode)) {
		    if (STATUS_END_OF_FILE == ErrCode) {
			EndOfFileFound = TRUE;
			ErrCode = STATUS_SUCCESS;
		    } else {
			WARN("Error 0x%08x reading from source\n", ErrCode);
		    }
		}
	    }
	}

	if (!EndOfFileFound && (NULL != pbCancel && *pbCancel)) {
	    TRACE("User requested cancel\n");
	    ErrCode = STATUS_REQUEST_ABORTED;
	}

	NtFreeVirtualMemory(NtCurrentProcess(), (PVOID *)&lpBuffer, &RegionSize,
			    MEM_RELEASE);
    } else {
	TRACE("Error 0x%08x allocating buffer of %zu bytes\n", ErrCode, RegionSize);
    }

    return ErrCode;
}

static NTSTATUS SetLastWriteTime(HANDLE FileHandle, LARGE_INTEGER LastWriteTime)
{
    NTSTATUS ErrCode = STATUS_SUCCESS;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_BASIC_INFORMATION FileBasic;

    ErrCode = NtQueryInformationFile(FileHandle, &IoStatusBlock, &FileBasic,
				     sizeof(FILE_BASIC_INFORMATION),
				     FileBasicInformation);
    if (!NT_SUCCESS(ErrCode)) {
	WARN("Error 0x%08x obtaining FileBasicInformation\n", ErrCode);
    } else {
	FileBasic.LastWriteTime.QuadPart = LastWriteTime.QuadPart;
	ErrCode = NtSetInformationFile(FileHandle, &IoStatusBlock, &FileBasic,
				       sizeof(FILE_BASIC_INFORMATION),
				       FileBasicInformation);
	if (!NT_SUCCESS(ErrCode)) {
	    WARN("Error 0x%0x setting LastWriteTime\n", ErrCode);
	}
    }

    return ErrCode;
}

BOOL BasepCopyFileExW(IN LPCWSTR lpExistingFileName, IN LPCWSTR lpNewFileName,
		      IN LPPROGRESS_ROUTINE lpProgressRoutine OPTIONAL,
		      IN LPVOID lpData OPTIONAL, IN LPBOOL pbCancel OPTIONAL,
		      IN DWORD dwCopyFlags, IN DWORD dwBasepFlags,
		      OUT LPHANDLE lpExistingHandle, OUT LPHANDLE lpNewHandle)
{
    NTSTATUS ErrCode;
    HANDLE FileHandleSource, FileHandleDest;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION FileStandard;
    FILE_BASIC_INFORMATION FileBasic;
    BOOL RC = FALSE;
    BOOL KeepDestOnError = FALSE;
    DWORD SystemError;

    FileHandleSource = CreateFileW(lpExistingFileName, GENERIC_READ,
				   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				   OPEN_EXISTING,
				   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, NULL);
    if (INVALID_HANDLE_VALUE != FileHandleSource) {
	ErrCode = NtQueryInformationFile(FileHandleSource, &IoStatusBlock, &FileStandard,
					 sizeof(FILE_STANDARD_INFORMATION),
					 FileStandardInformation);
	if (!NT_SUCCESS(ErrCode)) {
	    TRACE("Status 0x%08x obtaining FileStandardInformation for source\n",
		  ErrCode);
	    BaseSetLastNTError(ErrCode);
	} else {
	    ErrCode = NtQueryInformationFile(FileHandleSource, &IoStatusBlock, &FileBasic,
					     sizeof(FILE_BASIC_INFORMATION),
					     FileBasicInformation);
	    if (!NT_SUCCESS(ErrCode)) {
		TRACE("Status 0x%08x obtaining FileBasicInformation for source\n",
		      ErrCode);
		BaseSetLastNTError(ErrCode);
	    } else {
		FileHandleDest = CreateFileW(lpNewFileName, GENERIC_WRITE,
					     FILE_SHARE_WRITE, NULL,
					     (dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) ?
						 CREATE_NEW :
						 CREATE_ALWAYS,
					     FileBasic.FileAttributes, NULL);
		if (INVALID_HANDLE_VALUE != FileHandleDest) {
		    if (!(dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS) &&
			GetLastError() == ERROR_ALREADY_EXISTS)
			SetLastError(ERROR_SUCCESS);
		    ErrCode = CopyLoop(FileHandleSource, FileHandleDest,
				       FileStandard.EndOfFile, lpProgressRoutine, lpData,
				       pbCancel, &KeepDestOnError);
		    if (!NT_SUCCESS(ErrCode)) {
			BaseSetLastNTError(ErrCode);
		    } else {
			LARGE_INTEGER t;

			t.QuadPart = FileBasic.LastWriteTime.QuadPart;
			ErrCode = SetLastWriteTime(FileHandleDest, t);
			if (!NT_SUCCESS(ErrCode)) {
			    BaseSetLastNTError(ErrCode);
			} else {
			    RC = TRUE;
			}
		    }
		    NtClose(FileHandleDest);
		    if (!RC && !KeepDestOnError) {
			SystemError = GetLastError();
			SetFileAttributesW(lpNewFileName, FILE_ATTRIBUTE_NORMAL);
			DeleteFileW(lpNewFileName);
			SetLastError(SystemError);
		    }
		} else {
		    WARN("Error %u during opening of dest file\n", GetLastError());
		}
	    }
	}
	NtClose(FileHandleSource);
    } else {
	WARN("Error %u during opening of source file\n", GetLastError());
    }

    return RC;
}

/*
 * @implemented
 */
WINAPI BOOL CopyFileExW(IN LPCWSTR lpExistingFileName, IN LPCWSTR lpNewFileName,
			IN LPPROGRESS_ROUTINE lpProgressRoutine OPTIONAL,
			IN LPVOID lpData OPTIONAL, IN LPBOOL pbCancel OPTIONAL,
			IN DWORD dwCopyFlags)
{
    BOOL Ret;
    HANDLE ExistingHandle, NewHandle;

    ExistingHandle = INVALID_HANDLE_VALUE;
    NewHandle = INVALID_HANDLE_VALUE;

    __try {
	Ret = BasepCopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine,
			       lpData, pbCancel, dwCopyFlags, 0, &ExistingHandle,
			       &NewHandle);
    } __finally {
	if (ExistingHandle != INVALID_HANDLE_VALUE) {
	    CloseHandle(ExistingHandle);
	}

	if (NewHandle != INVALID_HANDLE_VALUE) {
	    CloseHandle(NewHandle);
	}
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI BOOL CopyFileW(IN LPCWSTR lpExistingFileName, IN LPCWSTR lpNewFileName,
		      IN BOOL bFailIfExists)
{
    return CopyFileExW(lpExistingFileName, lpNewFileName, NULL, NULL, NULL,
		       (bFailIfExists ? COPY_FILE_FAIL_IF_EXISTS : 0));
}

/*
 * @implemented
 */
WINAPI BOOL PrivCopyFileExW(IN LPCWSTR lpExistingFileName, IN LPCWSTR lpNewFileName,
			    IN LPPROGRESS_ROUTINE lpProgressRoutine, IN LPVOID lpData,
			    IN LPBOOL pbCancel, IN DWORD dwCopyFlags)
{
    BOOL Ret;
    HANDLE ExistingHandle, NewHandle;

    ExistingHandle = INVALID_HANDLE_VALUE;
    NewHandle = INVALID_HANDLE_VALUE;

    /* Check for incompatible flags */
    if (dwCopyFlags & COPY_FILE_FAIL_IF_EXISTS && dwCopyFlags & BASEP_COPY_REPLACE) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    __try {
	Ret = BasepCopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine,
			       lpData, pbCancel, dwCopyFlags & BASEP_COPY_PUBLIC_MASK,
			       dwCopyFlags & BASEP_COPY_BASEP_MASK, &ExistingHandle,
			       &NewHandle);
    } __finally {
	if (ExistingHandle != INVALID_HANDLE_VALUE) {
	    CloseHandle(ExistingHandle);
	}

	if (NewHandle != INVALID_HANDLE_VALUE) {
	    CloseHandle(NewHandle);
	}
    }

    return Ret;
}

/* EOF */
