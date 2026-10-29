/*
 * Locale-dependent format handling
 *
 * Copyright 1995 Martin von Loewis
 * Copyright 1998 David Lee Lambert
 * Copyright 2000 Julio Cesar Gazquez
 * Copyright 2003 Jon Griffiths
 * Copyright 2005 Dmitry Timoshkov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <k32.h>

DEBUG_CHANNEL(nls);

#include "lcformat_private.h"

#ifndef CAL_SABBREVERASTRING
#define CAL_SABBREVERASTRING 0x00000039
#endif

/**************************************************************************
 *              GetNumberFormatA	(KERNEL32.@)
 *
 * Format a number string for a given locale.
 *
 * PARAMS
 *  lcid        [I] Locale to format for
 *  dwFlags     [I] LOCALE_ flags from "winnls.h"
 *  lpszValue   [I] String to format
 *  lpFormat    [I] Formatting overrides
 *  lpNumberStr [O] Destination for formatted string
 *  cchOut      [I] Size of lpNumberStr, or 0 to calculate the resulting size
 *
 * NOTES
 *  - lpszValue can contain only '0' - '9', '-' and '.'.
 *  - If lpFormat is non-NULL, dwFlags must be 0. In this case lpszValue will
 *    be formatted according to the format details returned by GetLocaleInfoA().
 *  - This function rounds the number string if the number of decimals exceeds the
 *    locales normal number of decimal places.
 *  - If cchOut is 0, this function does not write to lpNumberStr.
 *  - The Ascii version of this function fails if lcid is Unicode only.
 *
 * RETURNS
 *  Success: The number of character written to lpNumberStr, or that would
 *           have been written, if cchOut is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */

/**************************************************************************
 *              GetNumberFormatA	(KERNEL32.@)
 */
WINAPI INT GetNumberFormatA(LCID Lcid, DWORD dwFlags, LPCSTR lpszValue,
			    const NUMBERFMTA *lpFormat, LPSTR lpNumberStr, int cchOut)
{
    DWORD Cp = CP_ACP;
    WCHAR szDec[8], szGrp[8], szIn[128], szOut[128];
    NUMBERFMTW Fmt;
    const NUMBERFMTW *Pfmt = NULL;
    INT iRet;

    TRACE("(0x%04x,0x%08x,%s,%p,%p,%d)\n", Lcid, dwFlags, debugstr_a(lpszValue), lpFormat,
	  lpNumberStr, cchOut);

    if (NLS_IsUnicodeOnlyLcid(Lcid)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (!(dwFlags & LOCALE_USE_CP_ACP)) {
	Cp = NLS_GetAnsiCodePage(Lcid, dwFlags);
	if (!Cp) {
	    SetLastError(ERROR_INVALID_PARAMETER);
	    return 0;
	}
    }

    if (lpFormat) {
	memcpy(&Fmt, lpFormat, sizeof(Fmt));
	Pfmt = &Fmt;
	if (lpFormat->lpDecimalSep) {
	    MultiByteToWideChar(Cp, 0, lpFormat->lpDecimalSep, -1, szDec,
				ARRAY_SIZE(szDec));
	    Fmt.lpDecimalSep = szDec;
	}
	if (lpFormat->lpThousandSep) {
	    MultiByteToWideChar(Cp, 0, lpFormat->lpThousandSep, -1, szGrp,
				ARRAY_SIZE(szGrp));
	    Fmt.lpThousandSep = szGrp;
	}
    }

    if (lpszValue)
	MultiByteToWideChar(Cp, 0, lpszValue, -1, szIn, ARRAY_SIZE(szIn));

    if (cchOut > (int)ARRAY_SIZE(szOut))
	cchOut = ARRAY_SIZE(szOut);

    szOut[0] = '\0';

    iRet = GetNumberFormatW(Lcid, dwFlags, lpszValue ? szIn : NULL, Pfmt,
			    lpNumberStr ? szOut : NULL, cchOut);

    if (szOut[0] && lpNumberStr)
	WideCharToMultiByte(Cp, 0, szOut, -1, lpNumberStr, cchOut, 0, 0);
    return iRet;
}

/**************************************************************************
 *              GetCurrencyFormatA	(KERNEL32.@)
 *
 * Format a currency string for a given locale.
 *
 * PARAMS
 *  lcid          [I] Locale to format for
 *  dwFlags       [I] LOCALE_ flags from "winnls.h"
 *  lpszValue     [I] String to format
 *  lpFormat      [I] Formatting overrides
 *  lpCurrencyStr [O] Destination for formatted string
 *  cchOut        [I] Size of lpCurrencyStr, or 0 to calculate the resulting size
 *
 * NOTES
 *  - lpszValue can contain only '0' - '9', '-' and '.'.
 *  - If lpFormat is non-NULL, dwFlags must be 0. In this case lpszValue will
 *    be formatted according to the format details returned by GetLocaleInfoA().
 *  - This function rounds the currency if the number of decimals exceeds the
 *    locales number of currency decimal places.
 *  - If cchOut is 0, this function does not write to lpCurrencyStr.
 *  - The Ascii version of this function fails if lcid is Unicode only.
 *
 * RETURNS
 *  Success: The number of character written to lpNumberStr, or that would
 *           have been written, if cchOut is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */

/**************************************************************************
 *              GetCurrencyFormatA	(KERNEL32.@)
 */
WINAPI INT GetCurrencyFormatA(LCID Lcid, DWORD dwFlags, LPCSTR lpszValue,
			      const CURRENCYFMTA *lpFormat, LPSTR lpCurrencyStr,
			      int cchOut)
{
    DWORD Cp = CP_ACP;
    WCHAR szDec[8], szGrp[8], szCy[8], szIn[128], szOut[128];
    CURRENCYFMTW Fmt;
    const CURRENCYFMTW *Pfmt = NULL;
    INT iRet;

    TRACE("(0x%04x,0x%08x,%s,%p,%p,%d)\n", Lcid, dwFlags, debugstr_a(lpszValue), lpFormat,
	  lpCurrencyStr, cchOut);

    if (NLS_IsUnicodeOnlyLcid(Lcid)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (!(dwFlags & LOCALE_USE_CP_ACP)) {
	Cp = NLS_GetAnsiCodePage(Lcid, dwFlags);
	if (!Cp) {
	    SetLastError(ERROR_INVALID_PARAMETER);
	    return 0;
	}
    }

    if (lpFormat) {
	memcpy(&Fmt, lpFormat, sizeof(Fmt));
	Pfmt = &Fmt;
	if (lpFormat->lpDecimalSep) {
	    MultiByteToWideChar(Cp, 0, lpFormat->lpDecimalSep, -1, szDec,
				ARRAY_SIZE(szDec));
	    Fmt.lpDecimalSep = szDec;
	}
	if (lpFormat->lpThousandSep) {
	    MultiByteToWideChar(Cp, 0, lpFormat->lpThousandSep, -1, szGrp,
				ARRAY_SIZE(szGrp));
	    Fmt.lpThousandSep = szGrp;
	}
	if (lpFormat->lpCurrencySymbol) {
	    MultiByteToWideChar(Cp, 0, lpFormat->lpCurrencySymbol, -1, szCy,
				ARRAY_SIZE(szCy));
	    Fmt.lpCurrencySymbol = szCy;
	}
    }

    if (lpszValue)
	MultiByteToWideChar(Cp, 0, lpszValue, -1, szIn, ARRAY_SIZE(szIn));

    if (cchOut > (int)ARRAY_SIZE(szOut))
	cchOut = ARRAY_SIZE(szOut);

    szOut[0] = '\0';

    iRet = GetCurrencyFormatW(Lcid, dwFlags, lpszValue ? szIn : NULL, Pfmt,
			      lpCurrencyStr ? szOut : NULL, cchOut);

    if (szOut[0] && lpCurrencyStr)
	WideCharToMultiByte(Cp, 0, szOut, -1, lpCurrencyStr, cchOut, 0, 0);
    return iRet;
}

/**************************************************************************
 *              EnumDateFormatsA	(KERNEL32.@)
 *
 * FIXME: MSDN mentions only LOCALE_USE_CP_ACP, should we handle
 * LOCALE_NOUSEROVERRIDE here as well?
 */
WINAPI BOOL EnumDateFormatsA(DATEFMT_ENUMPROCA Proc, LCID Lcid, DWORD Flags)
{
    struct ENUM_DATE_FORMATS_CONTEXT Ctxt;

    Ctxt.Type = CALLBACK_ENUMPROC;
    Ctxt.u.Callback = (DATEFMT_ENUMPROCW)Proc;
    Ctxt.Lcid = Lcid;
    Ctxt.Flags = Flags;
    Ctxt.Unicode = FALSE;

    return NLS_EnumDateFormats(&Ctxt);
}

/**************************************************************************
 *              EnumTimeFormatsA	(KERNEL32.@)
 *
 * FIXME: MSDN mentions only LOCALE_USE_CP_ACP, should we handle
 * LOCALE_NOUSEROVERRIDE here as well?
 */
WINAPI BOOL EnumTimeFormatsA(TIMEFMT_ENUMPROCA Proc, LCID Lcid, DWORD Flags)
{
    struct ENUM_TIME_FORMATS_CONTEXT Ctxt;

    /* EnumTimeFormatsA doesn't support flags, EnumTimeFormatsW does. */
    if (Flags & ~LOCALE_USE_CP_ACP) {
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    Ctxt.Type = CALLBACK_ENUMPROC;
    Ctxt.u.Callback = (TIMEFMT_ENUMPROCW)Proc;
    Ctxt.Lcid = Lcid;
    Ctxt.Flags = Flags;
    Ctxt.Unicode = FALSE;

    return NLS_EnumTimeFormats(&Ctxt);
}

/******************************************************************************
 *		EnumCalendarInfoA	[KERNEL32.@]
 */

WINAPI BOOL EnumCalendarInfoA(CALINFO_ENUMPROCA Calinfoproc, LCID Locale, CALID Calendar,
			      CALTYPE Caltype)
{
    struct ENUM_CALENDAR_CONTEXT Ctx;

    TRACE("(%p,0x%08x,0x%08x,0x%08x)\n", Calinfoproc, Locale, Calendar, Caltype);

    Ctx.type = CALLBACK_ENUMPROC;
    Ctx.u.Callback = (CALINFO_ENUMPROCW)Calinfoproc;
    Ctx.Lcid = Locale;
    Ctx.Calendar = Calendar;
    Ctx.CalType = Caltype;
    Ctx.lParam = 0;
    Ctx.Unicode = FALSE;
    return NLS_EnumCalendarInfo(&Ctx);
}

/**************************************************************************
 *		EnumCalendarInfoExA	[KERNEL32.@]
 */
WINAPI BOOL EnumCalendarInfoExA(CALINFO_ENUMPROCEXA CalInfoProc, LCID Locale,
				CALID Calendar, CALTYPE CalType)
{
    struct ENUM_CALENDAR_CONTEXT Ctx;

    TRACE("(%p,0x%08x,0x%08x,0x%08x)\n", CalInfoProc, Locale, Calendar, CalType);

    Ctx.type = CALLBACK_ENUMPROCEX;
    Ctx.u.CallbackEx = (CALINFO_ENUMPROCEXW)CalInfoProc;
    Ctx.Lcid = Locale;
    Ctx.Calendar = Calendar;
    Ctx.CalType = CalType;
    Ctx.lParam = 0;
    Ctx.Unicode = FALSE;
    return NLS_EnumCalendarInfo(&Ctx);
}

/*********************************************************************
 *	GetCalendarInfoA			(KERNEL32.@)
 */
WINAPI int GetCalendarInfoA(LCID Lcid, CALID Calendar, CALTYPE CalType, LPSTR lpCalData,
			    int cchData, LPDWORD lpValue)
{
    int Ret, cchDataW = cchData;
    LPWSTR lpCalDataW = NULL;
    DWORD Cp = CP_ACP;
    if (!(CalType & CAL_USE_CP_ACP)) {
	DWORD dwFlags = ((CalType & CAL_NOUSEROVERRIDE) ? LOCALE_NOUSEROVERRIDE : 0);
	Cp = NLS_GetAnsiCodePage(Lcid, dwFlags);
	if (!Cp) {
	    SetLastError(ERROR_INVALID_PARAMETER);
	    return 0;
	}
    }
    if ((CalType & 0xFFFF) == CAL_SABBREVERASTRING) {
	/* NOTE: CAL_SABBREVERASTRING is not supported in GetCalendarInfoA */
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (NLS_IsUnicodeOnlyLcid(Lcid)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (!cchData && !(CalType & CAL_RETURN_NUMBER))
	cchDataW = GetCalendarInfoW(Lcid, Calendar, CalType, NULL, 0, NULL);
    if (!(lpCalDataW = HeapAlloc(GetProcessHeap(), 0, cchDataW * sizeof(WCHAR))))
	return 0;

    Ret = GetCalendarInfoW(Lcid, Calendar, CalType, lpCalDataW, cchDataW, lpValue);
    if (Ret && lpCalDataW && lpCalData)
	Ret = WideCharToMultiByte(Cp, 0, lpCalDataW, -1, lpCalData, cchData, NULL, NULL);
    else if (CalType & CAL_RETURN_NUMBER)
	Ret *= sizeof(WCHAR);
    HeapFree(GetProcessHeap(), 0, lpCalDataW);

    return Ret;
}

/*********************************************************************
 *	SetCalendarInfoA			(KERNEL32.@)
 */
WINAPI int SetCalendarInfoA(LCID Locale, CALID Calendar, CALTYPE CalType,
			    LPCSTR lpCalData)
{
    FIXME("(%08x,%08x,%08x,%s): stub\n", Locale, Calendar, CalType,
	  debugstr_a(lpCalData));
    return 0;
}

/* EOF */
