#pragma once

#include <nt.h>

BOOLEAN NtFileOpenFile(HANDLE *phRetFile, WCHAR *pwszFileName,
		       BOOLEAN bWrite, BOOLEAN bOverwrite);
BOOLEAN NtFileOpenDirectory(HANDLE *phRetFile, WCHAR *pwszFileName,
			    BOOLEAN bWrite, BOOLEAN bOverwrite);

BOOLEAN NtFileReadFile(HANDLE hFile, PVOID pOutBuffer,
		       ULONG dwOutBufferSize, ULONG *pRetReadedSize);
BOOLEAN NtFileWriteFile(HANDLE hFile, PVOID lpData, ULONG dwBufferSize,
			ULONG *pRetWrittenSize);

BOOLEAN NtFileSeekFile(HANDLE hFile, LONGLONG lAmount);
BOOLEAN NtFileGetFilePosition(HANDLE hFile,
			      LONGLONG *pRetCurrentPosition);
BOOLEAN NtFileGetFileSize(HANDLE hFile, LONGLONG *pRetFileSize);

BOOLEAN NtFileCloseFile(HANDLE hFile);

BOOLEAN NtFileCopyFile(WCHAR *pszSrc, WCHAR *pszDst);

BOOLEAN NtFileDeleteFile(PCWSTR filename);
BOOLEAN NtFileCreateDirectory(PCWSTR dirname);

BOOLEAN NtFileMoveFile(IN PCWSTR lpExistingFileName,
		       IN PCWSTR lpNewFileName, BOOLEAN ReplaceIfExists);
