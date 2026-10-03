/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/winnls/string/lstring.c
 * PURPOSE:         Local string functions
 * PROGRAMMER:      Ariadne ( ariadne@xs4all.nl)
 * UPDATE HISTORY:
 *                  Created 01/11/98
 */

#include <k32.h>

/*
 * @implemented
 */
WINAPI int lstrcmpA(LPCSTR lpString1, LPCSTR lpString2)
{
    int Result;

    if (lpString1 == lpString2)
	return 0;
    if (lpString1 == NULL)
	return -1;
    if (lpString2 == NULL)
	return 1;

    Result = CompareStringA(GetThreadLocale(), 0, lpString1, -1, lpString2, -1);
    if (Result)
	Result -= 2;

    return Result;
}

/*
 * @implemented
 */
WINAPI int lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2)
{
    int Result;

    if (lpString1 == lpString2)
	return 0;
    if (lpString1 == NULL)
	return -1;
    if (lpString2 == NULL)
	return 1;

    Result = CompareStringA(GetThreadLocale(), NORM_IGNORECASE, lpString1, -1, lpString2,
			    -1);
    if (Result)
	Result -= 2;

    return Result;
}

/*
 * @implemented
 */
WINAPI LPSTR lstrcpynA(LPSTR lpString1, LPCSTR lpString2, int iMaxLength)
{
    LPSTR d = lpString1;
    LPCSTR s = lpString2;
    UINT Count = iMaxLength;
    LPSTR Ret = NULL;

    __try {
	while ((Count > 1) && *s) {
	    Count--;
	    *d++ = *s++;
	}

	if (Count)
	    *d = 0;

	Ret = lpString1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI LPSTR lstrcpyA(LPSTR lpString1, LPCSTR lpString2)
{
    LPSTR Ret = NULL;

    __try {
	memmove(lpString1, lpString2, strlen(lpString2) + 1);
	Ret = lpString1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI LPSTR lstrcatA(LPSTR lpString1, LPCSTR lpString2)
{
    LPSTR Ret = NULL;

    __try {
	Ret = strcat(lpString1, lpString2);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI int lstrlenA(LPCSTR lpString)
{
    INT Ret = 0;

    if (lpString == NULL)
	return 0;

    __try {
	Ret = strlen(lpString);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI int lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2)
{
    int Result;

    if (lpString1 == lpString2)
	return 0;
    if (lpString1 == NULL)
	return -1;
    if (lpString2 == NULL)
	return 1;

    Result = CompareStringW(GetThreadLocale(), 0, lpString1, -1, lpString2, -1);
    if (Result)
	Result -= 2;

    return Result;
}

/*
 * @implemented
 */
WINAPI int lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2)
{
    int Result;

    if (lpString1 == lpString2)
	return 0;
    if (lpString1 == NULL)
	return -1;
    if (lpString2 == NULL)
	return 1;

    Result = CompareStringW(GetThreadLocale(), NORM_IGNORECASE, lpString1, -1, lpString2, -1);
    if (Result)
	Result -= 2;

    return Result;
}

/*
 * @implemented
 */
WINAPI LPWSTR lstrcpynW(LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength)
{
    LPWSTR d = lpString1;
    LPCWSTR s = lpString2;
    UINT Count = iMaxLength;
    LPWSTR Ret = NULL;

    __try {
	while ((Count > 1) && *s) {
	    Count--;
	    *d++ = *s++;
	}

	if (Count)
	    *d = 0;

	Ret = lpString1;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI LPWSTR lstrcpyW(LPWSTR lpString1, LPCWSTR lpString2)
{
    LPWSTR Ret = NULL;

    __try {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	Ret = wcscpy(lpString1, lpString2);
#pragma GCC diagnostic pop
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI LPWSTR lstrcatW(LPWSTR lpString1, LPCWSTR lpString2)
{
    LPWSTR Ret = NULL;

    __try {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	Ret = wcscat(lpString1, lpString2);
#pragma GCC diagnostic pop
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI int lstrlenW(LPCWSTR lpString)
{
    INT Ret = 0;

    if (lpString == NULL)
	return 0;

    __try {
	Ret = wcslen(lpString);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    return Ret;
}
