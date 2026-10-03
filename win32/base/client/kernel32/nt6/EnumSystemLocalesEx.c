/*
 * PROJECT:     ReactOS Win32 Base API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Implementation of GetLocaleInfoEx (taken from wine-locale.c)
 * COPYRIGHT:   Copyright 1995 Martin von Loewis
 *              Copyright 1998 David Lee Lambert
 *              Copyright 2000 Julio César Gázquez
 *              Copyright 2002 Alexandre Julliard for CodeWeavers
 */

#include "k32.h"
#include <winuser.h>

struct ENUM_LOCALE_EX_DATA {
    LOCALE_ENUMPROCEX Proc;
    DWORD Flags;
    LPARAM Lparam;
};

static BOOL CALLBACK enum_locale_ex_proc(HMODULE module, LPCWSTR type, LPCWSTR name,
					 WORD lang, LONG_PTR lparam)
{
    struct ENUM_LOCALE_EX_DATA *data = (struct ENUM_LOCALE_EX_DATA *)lparam;
    WCHAR buffer[256];
    DWORD neutral;
    unsigned int flags;

    GetLocaleInfoW(MAKELCID(lang, SORT_DEFAULT), LOCALE_SNAME | LOCALE_NOUSEROVERRIDE,
		   buffer, sizeof(buffer) / sizeof(WCHAR));
    if (!GetLocaleInfoW(MAKELCID(lang, SORT_DEFAULT),
			LOCALE_INEUTRAL | LOCALE_NOUSEROVERRIDE | LOCALE_RETURN_NUMBER,
			(LPWSTR)&neutral, sizeof(neutral) / sizeof(WCHAR)))
	neutral = 0;
    flags = LOCALE_WINDOWS;
    flags |= neutral ? LOCALE_NEUTRALDATA : LOCALE_SPECIFICDATA;
    if (data->Flags && !(data->Flags & flags))
	return TRUE;
    return data->Proc(buffer, flags, data->Lparam);
}

/******************************************************************************
 *           EnumSystemLocalesEx  (KERNEL32.@)
 */
WINAPI BOOL EnumSystemLocalesEx(LOCALE_ENUMPROCEX proc, DWORD flags, LPARAM lparam,
				LPVOID reserved)
{
    struct ENUM_LOCALE_EX_DATA data;
    HMODULE kernel32_handle = GetModuleHandleW(L"kernel32.dll");

    if (reserved) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    data.Proc = proc;
    data.Flags = flags;
    data.Lparam = lparam;
    EnumResourceLanguagesW(kernel32_handle, (LPCWSTR)RT_STRING,
			   (LPCWSTR)MAKEINTRESOURCE((LOCALE_SNAME >> 4) + 1),
			   enum_locale_ex_proc, (LONG_PTR)&data);
    return TRUE;
}
