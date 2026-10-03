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
int WINAPI lstrcmpA(LPCSTR lpString1, LPCSTR lpString2)
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
int WINAPI lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2)
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
LPSTR
WINAPI
lstrcpynA(LPSTR lpString1, LPCSTR lpString2, int iMaxLength)
{
    LPSTR d = lpString1;
    LPCSTR s = lpString2;
    UINT count = iMaxLength;
    LPSTR Ret = NULL;

    __try
    {
	while ((count > 1) && *s) {
	    count--;
	    *d++ = *s++;
	}

	if (count)
	    *d = 0;

	Ret = lpString1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}

/*
 * @implemented
 */
LPSTR
WINAPI
lstrcpyA(LPSTR lpString1, LPCSTR lpString2)
{
    LPSTR Ret = NULL;

    __try
    {
	memmove(lpString1, lpString2, strlen(lpString2) + 1);
	Ret = lpString1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}

/*
 * @implemented
 */
LPSTR
WINAPI
lstrcatA(LPSTR lpString1, LPCSTR lpString2)
{
    LPSTR Ret = NULL;

    __try
    {
	Ret = strcat(lpString1, lpString2);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}

/*
 * @implemented
 */
int WINAPI lstrlenA(LPCSTR lpString)
{
    INT Ret = 0;

    if (lpString == NULL)
	return 0;

    __try
    {
	Ret = strlen(lpString);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}

/*
 * @implemented
 */
int WINAPI lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2)
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
int WINAPI lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2)
{
    int Result;

    if (lpString1 == lpString2)
	return 0;
    if (lpString1 == NULL)
	return -1;
    if (lpString2 == NULL)
	return 1;

    Result = CompareStringW(GetThreadLocale(), NORM_IGNORECASE, lpString1, -1, lpString2,
			    -1);
    if (Result)
	Result -= 2;

    return Result;
}

/*
 * @implemented
 */
LPWSTR
WINAPI
lstrcpynW(LPWSTR lpString1, LPCWSTR lpString2, int iMaxLength)
{
    LPWSTR d = lpString1;
    LPCWSTR s = lpString2;
    UINT count = iMaxLength;
    LPWSTR Ret = NULL;

    __try
    {
	while ((count > 1) && *s) {
	    count--;
	    *d++ = *s++;
	}

	if (count)
	    *d = 0;

	Ret = lpString1;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}

/*
 * @implemented
 */
LPWSTR
WINAPI
lstrcpyW(LPWSTR lpString1, LPCWSTR lpString2)
{
    LPWSTR Ret = NULL;

    __try
    {
	Ret = wcscpy(lpString1, lpString2);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}

/*
 * @implemented
 */
LPWSTR
WINAPI
lstrcatW(LPWSTR lpString1, LPCWSTR lpString2)
{
    LPWSTR Ret = NULL;

    __try
    {
	Ret = wcscat(lpString1, lpString2);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}

/*
 * @implemented
 */
int WINAPI lstrlenW(LPCWSTR lpString)
{
    INT Ret = 0;

    if (lpString == NULL)
	return 0;

    __try
    {
	Ret = wcslen(lpString);
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
    }

    return Ret;
}
