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
#include <winnls.h>

/******************************************************************************
 *           GetLocaleInfoEx (KERNEL32.@)
 */
WINAPI INT GetLocaleInfoEx(LPCWSTR Locale, LCTYPE Info, LPWSTR Buffer, INT Len)
{
    LCID Lcid = LocaleNameToLCID(Locale, 0);

    DPRINT("%ws, lcid=0x%x, 0x%x\n", Locale, Lcid, Info);

    if (!Lcid)
	return 0;

    /* special handling for neutral locale names */
    if (Locale && strlenW(Locale) == 2) {
	switch (Info) {
	case LOCALE_SNAME:
	    if (Len && Len < 3) {
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	    }
	    if (Len)
		wcscpy_s(Buffer, Len, Locale);
	    return 3;
	case LOCALE_SPARENT:
	    if (Len)
		Buffer[0] = 0;
	    return 1;
	}
    }

    return GetLocaleInfoW(Lcid, Info, Buffer, Len);
}
