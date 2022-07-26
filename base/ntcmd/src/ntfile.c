
//#define DEBUGMODE

#include "precomp.h"
#include "ntfile.h"

BOOLEAN NtFileOpenDirectory(HANDLE * phRetFile, WCHAR * pwszFileName,
			    BOOLEAN bWrite, BOOLEAN bOverwrite)
{
    HANDLE hFile;
    UNICODE_STRING ustrFileName;
    IO_STATUS_BLOCK IoStatusBlock;
    WCHAR wszFileName[1024] = L"\\??\\";
    OBJECT_ATTRIBUTES ObjectAttributes;

    wcscat_s(wszFileName, sizeof(wszFileName)/sizeof(WCHAR), pwszFileName);

    RtlInitUnicodeString(&ustrFileName, wszFileName);

    InitializeObjectAttributes(&ObjectAttributes,
			       &ustrFileName,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    ULONG CreateDisposition = 0;
    if (bWrite) {
	if (bOverwrite) {
	    CreateDisposition = FILE_OVERWRITE_IF;
	} else {
	    CreateDisposition = FILE_OPEN_IF;
	}
    } else {
	CreateDisposition = FILE_OPEN;
    }

    NtCreateFile(&hFile,
		 FILE_LIST_DIRECTORY | SYNCHRONIZE |
		 FILE_OPEN_FOR_BACKUP_INTENT, &ObjectAttributes,
		 &IoStatusBlock, 0, FILE_ATTRIBUTE_NORMAL,
		 FILE_SHARE_READ | FILE_SHARE_WRITE, CreateDisposition,
		 FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL,
		 0);

    *phRetFile = hFile;

    return TRUE;
}

BOOLEAN NtFileOpenFile(HANDLE * phRetFile, WCHAR * pwszFileName,
		       BOOLEAN bWrite, BOOLEAN bOverwrite)
{
    HANDLE hFile;
    UNICODE_STRING ustrFileName;
    IO_STATUS_BLOCK IoStatusBlock;
    ULONG CreateDisposition = 0;
    WCHAR wszFileName[1024] = L"\\??\\";
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS ntStatus;

    wcscat_s(wszFileName, sizeof(wszFileName)/sizeof(WCHAR), pwszFileName);

    RtlInitUnicodeString(&ustrFileName, wszFileName);

    InitializeObjectAttributes(&ObjectAttributes,
			       &ustrFileName,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (bWrite) {
	if (bOverwrite) {
	    CreateDisposition = FILE_OVERWRITE_IF;
	} else {
	    CreateDisposition = FILE_OPEN_IF;
	}
    } else {
	CreateDisposition = FILE_OPEN;
    }

    ntStatus =
	NtCreateFile(&hFile, GENERIC_WRITE | SYNCHRONIZE | GENERIC_READ,
		     &ObjectAttributes, &IoStatusBlock, 0,
		     FILE_ATTRIBUTE_NORMAL, 0, CreateDisposition,
		     FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(ntStatus)) {
	RtlCliDisplayString("NtCreateFile() failed 0x%.8X\n", ntStatus);
	return FALSE;
    }

    *phRetFile = hFile;

    return TRUE;
}

BOOLEAN NtFileWriteFile(HANDLE hFile, LPVOID lpData, DWORD dwBufferSize,
			DWORD * pRetWrittenSize)
{
    IO_STATUS_BLOCK sIoStatus;
    NTSTATUS ntStatus = 0;

    memset(&sIoStatus, 0, sizeof(IO_STATUS_BLOCK));

    ntStatus = NtWriteFile(hFile, NULL, NULL, NULL, &sIoStatus, lpData,
			   dwBufferSize, NULL, NULL);

    if (ntStatus == STATUS_SUCCESS) {
	if (pRetWrittenSize) {
	    *pRetWrittenSize = sIoStatus.Information;
	}
	return TRUE;
    }

    return FALSE;
}

BOOLEAN NtFileCopyFile(WCHAR * pszSrc, WCHAR * pszDst)
{
    HANDLE hSrc = NULL;
    HANDLE hDst = NULL;
    BYTE byData[8192];
    LONGLONG lFileSize = 0;
    LONGLONG lWrittenSizeTotal = 0;
    DWORD dwReadedSize = 0;
    DWORD dwWrittenSize = 0;
    BOOLEAN bResult = 0;

    bResult = NtFileOpenFile(&hSrc, pszSrc, FALSE, FALSE);
    if (bResult == FALSE) {
	return FALSE;
    }

    bResult = NtFileOpenFile(&hDst, pszDst, TRUE, TRUE);

    if (bResult == FALSE) {
	NtFileCloseFile(hSrc);
	return FALSE;
    }

    if (NtFileGetFileSize(hSrc, &lFileSize) == FALSE) {
	NtFileCloseFile(hSrc);
	NtFileCloseFile(hDst);
	return FALSE;
    }

    lWrittenSizeTotal = 0;
    while (1) {
	dwReadedSize = 0;

	if (NtFileReadFile(hSrc, byData, 8192, &dwReadedSize) == FALSE) {
	    NtFileCloseFile(hSrc);
	    NtFileCloseFile(hDst);
	    return FALSE;
	}

	if (NtFileWriteFile(hDst, byData, dwReadedSize, &dwWrittenSize) ==
	    FALSE) {
	    NtFileCloseFile(hSrc);
	    NtFileCloseFile(hDst);
	    return FALSE;
	}

	if (dwReadedSize != dwWrittenSize) {
	    NtFileCloseFile(hSrc);
	    NtFileCloseFile(hDst);
	    return FALSE;
	}

	lWrittenSizeTotal += dwWrittenSize;
	if (lWrittenSizeTotal == lFileSize) {
	    // End of File...
	    break;
	}
    }

    NtFileCloseFile(hSrc);
    NtFileCloseFile(hDst);

    return TRUE;
}

BOOLEAN NtFileReadFile(HANDLE hFile, LPVOID pOutBuffer,
		       DWORD dwOutBufferSize, DWORD * pRetReadedSize)
{
    IO_STATUS_BLOCK sIoStatus;
    NTSTATUS ntStatus = 0;

    memset(&sIoStatus, 0, sizeof(IO_STATUS_BLOCK));

    ntStatus =
	NtReadFile(hFile, NULL, NULL, NULL, &sIoStatus, pOutBuffer,
		   dwOutBufferSize, NULL, NULL);
    if (ntStatus == STATUS_SUCCESS) {
	if (pRetReadedSize) {
	    *pRetReadedSize = sIoStatus.Information;
	}

	return TRUE;
    }
    return FALSE;
}

BOOLEAN NtFileGetFilePosition(HANDLE hFile, LONGLONG * pRetCurrentPosition)
{
    IO_STATUS_BLOCK sIoStatus;
    FILE_POSITION_INFORMATION sFilePosition;
    NTSTATUS ntStatus = 0;

    memset(&sIoStatus, 0, sizeof(IO_STATUS_BLOCK));
    memset(&sFilePosition, 0, sizeof(FILE_POSITION_INFORMATION));

    ntStatus = NtQueryInformationFile(hFile, &sIoStatus, &sFilePosition,
				      sizeof(FILE_POSITION_INFORMATION),
				      FilePositionInformation);
    if (ntStatus == STATUS_SUCCESS) {
	if (pRetCurrentPosition) {
	    *pRetCurrentPosition =
		(sFilePosition.CurrentByteOffset.QuadPart);
	}
	return TRUE;
    }

    return FALSE;
}

BOOLEAN NtFileGetFileSize(HANDLE hFile, LONGLONG * pRetFileSize)
{
    IO_STATUS_BLOCK sIoStatus;
    FILE_STANDARD_INFORMATION sFileInfo;
    NTSTATUS ntStatus = 0;

    memset(&sIoStatus, 0, sizeof(IO_STATUS_BLOCK));
    memset(&sFileInfo, 0, sizeof(FILE_STANDARD_INFORMATION));

    ntStatus = NtQueryInformationFile(hFile, &sIoStatus, &sFileInfo,
				      sizeof(FILE_STANDARD_INFORMATION),
				      FileStandardInformation);
    if (ntStatus == STATUS_SUCCESS) {
	if (pRetFileSize) {
	    *pRetFileSize = (sFileInfo.EndOfFile.QuadPart);
	}
	return TRUE;
    }

    return FALSE;
}

BOOLEAN NtFileSeekFile(HANDLE hFile, LONGLONG lAmount)
{
    IO_STATUS_BLOCK sIoStatus;
    FILE_POSITION_INFORMATION sFilePosition;
    NTSTATUS ntStatus = 0;

    memset(&sIoStatus, 0, sizeof(IO_STATUS_BLOCK));

    sFilePosition.CurrentByteOffset.QuadPart = lAmount;
    ntStatus = NtSetInformationFile(hFile, &sIoStatus, &sFilePosition,
				    sizeof(FILE_POSITION_INFORMATION),
				    FilePositionInformation);
    if (ntStatus == STATUS_SUCCESS) {
	return TRUE;
    }

    return FALSE;
}

BOOLEAN NtFileCloseFile(HANDLE hFile)
{
    NTSTATUS ntStatus = 0;

    ntStatus = NtClose(hFile);

    if (ntStatus == STATUS_SUCCESS) {
	return TRUE;
    }

    return FALSE;
}

// filename - full path in DOS format
BOOLEAN NtFileDeleteFile(PCWSTR filename)
{
    UNICODE_STRING us;
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;

    RtlInitUnicodeString(&us, filename);

    if (!RtlDosPathNameToNtPathName_U(filename, &us, NULL, NULL)) {
	return FALSE;
    }

    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtDeleteFile(&oa);

    if (!NT_SUCCESS(status)) {
	RtlFreeUnicodeString(&us);
	return FALSE;
    }

    RtlFreeUnicodeString(&us);
    return TRUE;
}

BOOLEAN NtFileCreateDirectory(PCWSTR dirname)
{
    UNICODE_STRING us;
    NTSTATUS status;
    HANDLE hFile;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;

    if (!RtlDosPathNameToNtPathName_U(dirname, &us, NULL, NULL)) {
	return FALSE;
    }

    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFile,
			  FILE_LIST_DIRECTORY | SYNCHRONIZE |
			  FILE_OPEN_FOR_BACKUP_INTENT, &oa, &iosb, NULL,
			  FILE_ATTRIBUTE_NORMAL,
			  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
			  FILE_SYNCHRONOUS_IO_NONALERT |
			  FILE_DIRECTORY_FILE, NULL, 0);

    if (NT_SUCCESS(status)) {
	NtClose(hFile);
	RtlFreeUnicodeString(&us);
	return TRUE;
    }

    /* if it already exists then return success */
    if (status == STATUS_OBJECT_NAME_COLLISION) {
	RtlFreeUnicodeString(&us);
	return TRUE;
    }

    RtlFreeUnicodeString(&us);
    return FALSE;
}

/*
lpExistingFileName - full path in DOS format
lpNewFileName - full path in DOS format, or filename
*/

BOOLEAN NtFileMoveFile(IN LPCWSTR lpExistingFileName,
		       IN LPCWSTR lpNewFileName, BOOLEAN ReplaceIfExists)
{
    PFILE_RENAME_INFORMATION FileRenameInfo;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING ExistingFileNameU;
    WCHAR NewFileName[MAX_PATH] = L"\\??\\";
    HANDLE FileHandle;
    DWORD FileNameSize;

    NTSTATUS Status;

    if (!lpExistingFileName || !lpNewFileName) {
	return FALSE;
    }

    RtlDosPathNameToNtPathName_U(lpExistingFileName, &ExistingFileNameU,
				 NULL, NULL);

    if ((wcslen(lpNewFileName) > 2) && L':' == lpNewFileName[1]) {
	wcsncat_s(NewFileName, sizeof(NewFileName)/sizeof(WCHAR), lpNewFileName, MAX_PATH);
    } else {
	wcsncpy_s(NewFileName, sizeof(NewFileName)/sizeof(WCHAR), lpNewFileName, MAX_PATH);
    }

    RtlCliDisplayString("NtFileMoveFile (%S, %S)\n",
			ExistingFileNameU.Buffer, NewFileName);

    InitializeObjectAttributes(&ObjectAttributes,
			       &ExistingFileNameU,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtCreateFile(&FileHandle,
			  FILE_ALL_ACCESS,
			  &ObjectAttributes,
			  &IoStatusBlock,
			  NULL,
			  FILE_ATTRIBUTE_NORMAL,
			  FILE_SHARE_READ | FILE_SHARE_WRITE,
			  FILE_OPEN,
			  FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(Status)) {
	RtlCliDisplayString("NtCreateFile() failed (Status %lx)\n",
			    Status);
	return FALSE;
    }

    FileNameSize = wcslen(NewFileName) * sizeof(*NewFileName);

    FileRenameInfo = RtlAllocateHeap(RtlGetProcessHeap(),
				     HEAP_ZERO_MEMORY,
				     sizeof(FILE_RENAME_INFORMATION) +
				     FileNameSize);

    if (!FileRenameInfo) {
	RtlCliDisplayString("RtlAllocateHeap failed\n");
	NtClose(FileHandle);
	return FALSE;
    }

    FileRenameInfo->RootDirectory = NULL;
    FileRenameInfo->ReplaceIfExists = ReplaceIfExists;
    FileRenameInfo->FileNameLength = FileNameSize;
    RtlCopyMemory(FileRenameInfo->FileName, NewFileName, FileNameSize);

    Status = NtSetInformationFile(FileHandle,
				  &IoStatusBlock,
				  FileRenameInfo,
				  sizeof(FILE_RENAME_INFORMATION) +
				  FileNameSize, FileRenameInformation);

    RtlFreeHeap(RtlGetProcessHeap(), 0, FileRenameInfo);

    NtClose(FileHandle);

    return TRUE;
}
