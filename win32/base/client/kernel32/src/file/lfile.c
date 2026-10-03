/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/file/lfile.c
 * PURPOSE:         Find functions
 * PROGRAMMER:      Ariadne ( ariadne@xs4all.nl)
 * UPDATE HISTORY:
 *                  Created 01/11/98
 */

#include <k32.h>
#define NDEBUG
#include <debug.h>

/*
 * @implemented
 */
WINAPI long _hread(HFILE hFile, LPVOID lpBuffer, long lBytes)
{
    DWORD NumberOfBytesRead;

    if (!ReadFile(LongToHandle(hFile), lpBuffer, (DWORD)lBytes, &NumberOfBytesRead,
		  NULL)) {
	return HFILE_ERROR;
    }
    return NumberOfBytesRead;
}

/*
 * @implemented
 */
WINAPI long _hwrite(HFILE hFile, LPCSTR lpBuffer, long lBytes)
{
    DWORD NumberOfBytesWritten;

    if (lBytes == 0) {
	if (!SetEndOfFile((HANDLE)(ULONG_PTR)hFile)) {
	    return HFILE_ERROR;
	}
	return 0;
    }
    if (!WriteFile(LongToHandle(hFile), (LPVOID)lpBuffer, (DWORD)lBytes,
		   &NumberOfBytesWritten, NULL)) {
	return HFILE_ERROR;
    }
    return NumberOfBytesWritten;
}

/*
 * @implemented
 */
WINAPI HFILE _lopen(LPCSTR lpPathName, int iReadWrite)
{
    DWORD dwAccess, dwSharing, dwCreation;

    if (iReadWrite & OF_CREATE) {
	dwCreation = CREATE_ALWAYS;
	dwAccess = GENERIC_READ | GENERIC_WRITE;
    } else {
	dwCreation = OPEN_EXISTING;
	switch (iReadWrite & 0x03) {
	case OF_READ:
	    dwAccess = GENERIC_READ;
	    break;
	case OF_WRITE:
	    dwAccess = GENERIC_WRITE;
	    break;
	case OF_READWRITE:
	    dwAccess = GENERIC_READ | GENERIC_WRITE;
	    break;
	default:
	    dwAccess = 0;
	    break;
	}
    }

    switch (iReadWrite & 0x70) {
    case OF_SHARE_EXCLUSIVE:
	dwSharing = 0;
	break;
    case OF_SHARE_DENY_WRITE:
	dwSharing = FILE_SHARE_READ;
	break;
    case OF_SHARE_DENY_READ:
	dwSharing = FILE_SHARE_WRITE;
	break;
    case OF_SHARE_DENY_NONE:
    case OF_SHARE_COMPAT:
    default:
	dwSharing = FILE_SHARE_READ | FILE_SHARE_WRITE;
	break;
    }

    return (HFILE)(ULONG_PTR)CreateFileA(lpPathName, dwAccess, dwSharing, NULL,
					 dwCreation, FILE_ATTRIBUTE_NORMAL, NULL);
}

/*
 * @implemented
 */
WINAPI HFILE _lcreat(LPCSTR lpPathName, int iAttribute)
{
    HANDLE hFile;

    iAttribute &= FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    hFile = CreateFileA(lpPathName, GENERIC_READ | GENERIC_WRITE,
			(FILE_SHARE_READ | FILE_SHARE_WRITE), NULL, CREATE_ALWAYS,
			iAttribute, NULL);

    return HandleToLong(hFile);
}

/*
 * @implemented
 */
WINAPI int _lclose(HFILE hFile)
{
    return CloseHandle(LongToHandle(hFile)) ? 0 : HFILE_ERROR;
}

/*
 * @implemented
 */
WINAPI LONG _llseek(HFILE hFile, LONG lOffset, int iOrigin)
{
    return SetFilePointer(LongToHandle(hFile), lOffset, NULL, (DWORD)iOrigin);
}

/* EOF */
