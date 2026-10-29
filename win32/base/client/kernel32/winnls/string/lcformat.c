/*
 * Locale-dependent format handling
 *
 * Copyright 1995 Martin von Loewis
 * Copyright 1998 David Lee Lambert
 * Copyright 2000 Julio César Gázquez
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
#include "japanese.h" /* Japanese eras */

#include "lcformat_private.h"

DEBUG_CHANNEL(nls);

WINAPI LCID LocaleNameToLCID(_In_ LPCWSTR, _In_ DWORD);
#define LOCALE_SSHORTESTDAYNAME1 96
#define LOCALE_SSHORTESTDAYNAME2 97
#define LOCALE_SSHORTESTDAYNAME3 98
#define LOCALE_SSHORTESTDAYNAME4 99
#define LOCALE_SSHORTESTDAYNAME5 100
#define LOCALE_SSHORTESTDAYNAME6 101
#define LOCALE_SSHORTESTDAYNAME7 102

#define CRITICAL_SECTION RTL_CRITICAL_SECTION
#define CRITICAL_SECTION_DEBUG RTL_CRITICAL_SECTION_DEBUG
#define CALINFO_MAX_YEAR 2029

#define IS_LCID_JAPANESE(lcid) PRIMARYLANGID(LANGIDFROMLCID(lcid)) == LANG_JAPANESE

#ifndef CAL_SABBREVERASTRING
#define CAL_SABBREVERASTRING 0x00000039
#endif

#define DATE_DATEVARSONLY 0x0100 /* only date stuff: yMdg */
#define TIME_TIMEVARSONLY 0x0200 /* only time stuff: hHmst */

/* Since calculating the formatting data for each locale is time-consuming,
 * we get the format data for each locale only once and cache it in memory.
 * We cache both the system default and user overridden data, after converting
 * them into the formats that the functions here expect. Since these functions
 * will typically be called with only a small number of the total locales
 * installed, the memory overhead is minimal while the speedup is significant.
 *
 * Our cache takes the form of a singly linked list, whose node is below:
 */
#define NLS_NUM_CACHED_STRINGS 57

typedef struct _NLS_FORMAT_NODE {
    LCID Lcid; /* Locale Id */
    DWORD dwFlags; /* 0 or LOCALE_NOUSEROVERRIDE */
    DWORD dwCodePage; /* Default code page (if LOCALE_USE_ANSI_CP not given) */
    NUMBERFMTW Fmt; /* Default format for numbers */
    CURRENCYFMTW Cyfmt; /* Default format for currencies */
    LPWSTR lppszStrings[NLS_NUM_CACHED_STRINGS]; /* Default formats,day/month names */
    WCHAR szShortAM[2]; /* Short 'AM' marker */
    WCHAR szShortPM[2]; /* Short 'PM' marker */
    struct _NLS_FORMAT_NODE *Next;
} NLS_FORMAT_NODE;

/* Macros to get particular data strings from a format node */
#define GetNegative(fmt) fmt->lppszStrings[0]
#define GetLongDate(fmt) fmt->lppszStrings[1]
#define GetShortDate(fmt) fmt->lppszStrings[2]
#define GetTime(fmt) fmt->lppszStrings[3]
#define GetAM(fmt) fmt->lppszStrings[54]
#define GetPM(fmt) fmt->lppszStrings[55]
#define GetYearMonth(fmt) fmt->lppszStrings[56]

#define GetLongDay(fmt, day) fmt->lppszStrings[4 + day]
#define GetShortDay(fmt, day) fmt->lppszStrings[11 + day]
#define GetLongMonth(fmt, mth) fmt->lppszStrings[18 + mth]
#define GetGenitiveMonth(fmt, mth) fmt->lppszStrings[30 + mth]
#define GetShortMonth(fmt, mth) fmt->lppszStrings[42 + mth]

/* Write access to the cache is protected by this critical section */
static CRITICAL_SECTION NLS_FormatsCS;
static CRITICAL_SECTION_DEBUG NLS_FormatsCS_debug = {
    0,
    0,
    &NLS_FormatsCS,
    { &NLS_FormatsCS_debug.ProcessLocksList, &NLS_FormatsCS_debug.ProcessLocksList },
    0,
    0,
};
static CRITICAL_SECTION NLS_FormatsCS = { &NLS_FormatsCS_debug, -1, 0, 0, 0, 0 };

/**************************************************************************
 * NLS_GetLocaleNumber <internal>
 *
 * Get a numeric locale format value.
 */
static DWORD NLS_GetLocaleNumber(LCID Lcid, DWORD dwFlags)
{
    WCHAR szBuff[80];
    DWORD dwVal = 0;

    szBuff[0] = '\0';
    GetLocaleInfoW(Lcid, dwFlags, szBuff, ARRAY_SIZE(szBuff));

    if (szBuff[0] && szBuff[1] == ';' && szBuff[2] != '0')
	dwVal = (szBuff[0] - '0') * 10 + (szBuff[2] - '0');
    else {
	const WCHAR *Iter = szBuff;
	dwVal = 0;
	while (*Iter >= '0' && *Iter <= '9')
	    dwVal = dwVal * 10 + (*Iter++ - '0');
    }
    return dwVal;
}

/**************************************************************************
 * NLS_GetLocaleString <internal>
 *
 * Get a string locale format value.
 */
static WCHAR *NLS_GetLocaleString(LCID Lcid, DWORD dwFlags)
{
    WCHAR szBuff[80], *Str;
    DWORD dwLen;

    szBuff[0] = '\0';
    GetLocaleInfoW(Lcid, dwFlags, szBuff, ARRAY_SIZE(szBuff));
    dwLen = strlenW(szBuff) + 1;
    Str = HeapAlloc(GetProcessHeap(), 0, dwLen * sizeof(WCHAR));
    if (Str)
	memcpy(Str, szBuff, dwLen * sizeof(WCHAR));
    return Str;
}

#define GET_LOCALE_NUMBER(num, type)                 \
    num = NLS_GetLocaleNumber(lcid, type | dwFlags); \
    TRACE(#type ": %d (%08x)\n", (DWORD)num, (DWORD)num)

#define GET_LOCALE_STRING(str, type)                 \
    str = NLS_GetLocaleString(lcid, type | dwFlags); \
    TRACE(#type ": %ws\n", str)

/**************************************************************************
 * NLS_GetFormats <internal>
 *
 * Calculate (and cache) the number formats for a locale.
 */
static const NLS_FORMAT_NODE *NLS_GetFormats(LCID lcid, DWORD dwFlags)
{
    /* GetLocaleInfo() identifiers for cached formatting strings */
    static const LCTYPE NlsLocaleIndices[] = {
	LOCALE_SNEGATIVESIGN,
	LOCALE_SLONGDATE,
	LOCALE_SSHORTDATE,
	LOCALE_STIMEFORMAT,
	LOCALE_SDAYNAME1,
	LOCALE_SDAYNAME2,
	LOCALE_SDAYNAME3,
	LOCALE_SDAYNAME4,
	LOCALE_SDAYNAME5,
	LOCALE_SDAYNAME6,
	LOCALE_SDAYNAME7,
	LOCALE_SABBREVDAYNAME1,
	LOCALE_SABBREVDAYNAME2,
	LOCALE_SABBREVDAYNAME3,
	LOCALE_SABBREVDAYNAME4,
	LOCALE_SABBREVDAYNAME5,
	LOCALE_SABBREVDAYNAME6,
	LOCALE_SABBREVDAYNAME7,
	LOCALE_SMONTHNAME1,
	LOCALE_SMONTHNAME2,
	LOCALE_SMONTHNAME3,
	LOCALE_SMONTHNAME4,
	LOCALE_SMONTHNAME5,
	LOCALE_SMONTHNAME6,
	LOCALE_SMONTHNAME7,
	LOCALE_SMONTHNAME8,
	LOCALE_SMONTHNAME9,
	LOCALE_SMONTHNAME10,
	LOCALE_SMONTHNAME11,
	LOCALE_SMONTHNAME12,
	LOCALE_SMONTHNAME1 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME2 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME3 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME4 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME5 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME6 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME7 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME8 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME9 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME10 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME11 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SMONTHNAME12 | LOCALE_RETURN_GENITIVE_NAMES,
	LOCALE_SABBREVMONTHNAME1,
	LOCALE_SABBREVMONTHNAME2,
	LOCALE_SABBREVMONTHNAME3,
	LOCALE_SABBREVMONTHNAME4,
	LOCALE_SABBREVMONTHNAME5,
	LOCALE_SABBREVMONTHNAME6,
	LOCALE_SABBREVMONTHNAME7,
	LOCALE_SABBREVMONTHNAME8,
	LOCALE_SABBREVMONTHNAME9,
	LOCALE_SABBREVMONTHNAME10,
	LOCALE_SABBREVMONTHNAME11,
	LOCALE_SABBREVMONTHNAME12,
	LOCALE_S1159,
	LOCALE_S2359,
	LOCALE_SYEARMONTH
    };
    static NLS_FORMAT_NODE *NlsCachedFormats = NULL;
    NLS_FORMAT_NODE *Node = NlsCachedFormats;

    dwFlags &= LOCALE_NOUSEROVERRIDE;

    TRACE("(0x%04x,0x%08x)\n", lcid, dwFlags);

    /* See if we have already cached the locales number format */
    while (Node && (Node->Lcid != lcid || Node->dwFlags != dwFlags) && Node->Next)
	Node = Node->Next;

    if (!Node || Node->Lcid != lcid || Node->dwFlags != dwFlags) {
	NLS_FORMAT_NODE *NewNode;
	DWORD i;

	TRACE("Creating new cache entry\n");

	if (!(NewNode = HeapAlloc(GetProcessHeap(), 0, sizeof(NLS_FORMAT_NODE))))
	    return NULL;

	GET_LOCALE_NUMBER(NewNode->dwCodePage, LOCALE_IDEFAULTANSICODEPAGE);

	/* Number Format */
	NewNode->Lcid = lcid;
	NewNode->dwFlags = dwFlags;
	NewNode->Next = NULL;

	GET_LOCALE_NUMBER(NewNode->Fmt.NumDigits, LOCALE_IDIGITS);
	GET_LOCALE_NUMBER(NewNode->Fmt.LeadingZero, LOCALE_ILZERO);
	GET_LOCALE_NUMBER(NewNode->Fmt.NegativeOrder, LOCALE_INEGNUMBER);

	GET_LOCALE_NUMBER(NewNode->Fmt.Grouping, LOCALE_SGROUPING);
	if (NewNode->Fmt.Grouping > 9 && NewNode->Fmt.Grouping != 32) {
	    WARN("LOCALE_SGROUPING (%d) unhandled, please report!\n",
		 NewNode->Fmt.Grouping);
	    NewNode->Fmt.Grouping = 0;
	}

	LPWSTR Placeholder = NewNode->Fmt.lpDecimalSep;
	GET_LOCALE_STRING(Placeholder, LOCALE_SDECIMAL);
	GET_LOCALE_STRING(NewNode->Fmt.lpThousandSep, LOCALE_STHOUSAND);

	/* Currency Format */
	NewNode->Cyfmt.NumDigits = NewNode->Fmt.NumDigits;
	NewNode->Cyfmt.LeadingZero = NewNode->Fmt.LeadingZero;

	GET_LOCALE_NUMBER(NewNode->Cyfmt.Grouping, LOCALE_SGROUPING);

	if (NewNode->Cyfmt.Grouping > 9) {
	    WARN("LOCALE_SMONGROUPING (%d) unhandled, please report!\n",
		 NewNode->Cyfmt.Grouping);
	    NewNode->Cyfmt.Grouping = 0;
	}

	GET_LOCALE_NUMBER(NewNode->Cyfmt.NegativeOrder, LOCALE_INEGCURR);
	if (NewNode->Cyfmt.NegativeOrder > 15) {
	    WARN("LOCALE_INEGCURR (%d) unhandled, please report!\n",
		 NewNode->Cyfmt.NegativeOrder);
	    NewNode->Cyfmt.NegativeOrder = 0;
	}
	GET_LOCALE_NUMBER(NewNode->Cyfmt.PositiveOrder, LOCALE_ICURRENCY);
	if (NewNode->Cyfmt.PositiveOrder > 3) {
	    WARN("LOCALE_IPOSCURR (%d) unhandled,please report!\n",
		 NewNode->Cyfmt.PositiveOrder);
	    NewNode->Cyfmt.PositiveOrder = 0;
	}
	GET_LOCALE_STRING(NewNode->Cyfmt.lpDecimalSep, LOCALE_SMONDECIMALSEP);
	GET_LOCALE_STRING(NewNode->Cyfmt.lpThousandSep, LOCALE_SMONTHOUSANDSEP);
	GET_LOCALE_STRING(NewNode->Cyfmt.lpCurrencySymbol, LOCALE_SCURRENCY);

	/* Date/Time Format info, negative character, etc */
	for (i = 0; i < ARRAY_SIZE(NlsLocaleIndices); i++) {
	    GET_LOCALE_STRING(NewNode->lppszStrings[i], NlsLocaleIndices[i]);
	}
	/* Save some memory if month genitive name is the same or not present */
	for (i = 0; i < 12; i++) {
	    if (strcmpW(GetLongMonth(NewNode, i), GetGenitiveMonth(NewNode, i)) == 0) {
		HeapFree(GetProcessHeap(), 0, GetGenitiveMonth(NewNode, i));
		GetGenitiveMonth(NewNode, i) = NULL;
	    }
	}

	NewNode->szShortAM[0] = GetAM(NewNode)[0];
	NewNode->szShortAM[1] = '\0';
	NewNode->szShortPM[0] = GetPM(NewNode)[0];
	NewNode->szShortPM[1] = '\0';

	/* Now add the computed format to the cache */
	RtlEnterCriticalSection(&NLS_FormatsCS);

	/* Search again: We may have raced to add the node */
	Node = NlsCachedFormats;
	while (Node && (Node->Lcid != lcid || Node->dwFlags != dwFlags) && Node->Next)
	    Node = Node->Next;

	if (!Node) {
	    Node = NlsCachedFormats = NewNode; /* Empty list */
	    NewNode = NULL;
	} else if (Node->Lcid != lcid || Node->dwFlags != dwFlags) {
	    Node->Next = NewNode; /* Not in the list, add to end */
	    Node = NewNode;
	    NewNode = NULL;
	}

	RtlLeaveCriticalSection(&NLS_FormatsCS);

	if (NewNode) {
	    /* We raced and lost: The node was already added by another thread.
	     * node points to the currently cached node, so free new_node.
	     */
	    for (i = 0; i < ARRAY_SIZE(NlsLocaleIndices); i++)
		HeapFree(GetProcessHeap(), 0, NewNode->lppszStrings[i]);
	    HeapFree(GetProcessHeap(), 0, NewNode->Fmt.lpDecimalSep);
	    HeapFree(GetProcessHeap(), 0, NewNode->Fmt.lpThousandSep);
	    HeapFree(GetProcessHeap(), 0, NewNode->Cyfmt.lpDecimalSep);
	    HeapFree(GetProcessHeap(), 0, NewNode->Cyfmt.lpThousandSep);
	    HeapFree(GetProcessHeap(), 0, NewNode->Cyfmt.lpCurrencySymbol);
	    HeapFree(GetProcessHeap(), 0, NewNode);
	}
    }
    return Node;
}

/*
 * NLS_GetAnsiCodePage <internal>
 * Helper used by ANSI entrypoints to determine the locale codepage.
 */
DWORD NLS_GetAnsiCodePage(LCID Lcid, DWORD dwFlags)
{
    const NLS_FORMAT_NODE *Node = NLS_GetFormats(Lcid, dwFlags);
    return Node ? Node->dwCodePage : 0;
}

/**************************************************************************
 * NLS_IsUnicodeOnlyLcid <internal>
 *
 * Determine if a locale is Unicode only, and thus invalid in ASCII calls.
 */
BOOL NLS_IsUnicodeOnlyLcid(LCID Lcid)
{
    Lcid = ConvertDefaultLocale(Lcid);

    switch (PRIMARYLANGID(Lcid)) {
    case LANG_ARMENIAN:
    case LANG_DIVEHI:
    case LANG_GEORGIAN:
    case LANG_GUJARATI:
    case LANG_HINDI:
    case LANG_KANNADA:
    case LANG_KONKANI:
    case LANG_MARATHI:
    case LANG_PUNJABI:
    case LANG_SANSKRIT:
	TRACE("lcid 0x%08x: langid 0x%4x is Unicode Only\n", Lcid, PRIMARYLANGID(Lcid));
	return TRUE;
    default:
	return FALSE;
    }
}

/*
 * Formatting of dates, times, numbers and currencies.
 */

#define IsLiteralMarker(p) (p == '\'')
#define IsDateFmtChar(p) (p == 'd' || p == 'M' || p == 'y' || p == 'g')
#define IsTimeFmtChar(p) (p == 'H' || p == 'h' || p == 'm' || p == 's' || p == 't')

/* Only the following flags can be given if a date/time format is specified */
#define DATE_FORMAT_FLAGS (DATE_DATEVARSONLY | DATE_USE_ALT_CALENDAR)
#define TIME_FORMAT_FLAGS                                                   \
    (TIME_TIMEVARSONLY | TIME_FORCE24HOURFORMAT | TIME_NOMINUTESORSECONDS | \
     TIME_NOSECONDS | TIME_NOTIMEMARKER)

/******************************************************************************
 * NLS_GetDateTimeFormatW <internal>
 *
 * Performs the formatting for GetDateFormatW/GetTimeFormatW.
 *
 * FIXME
 * DATE_USE_ALT_CALENDAR           - Requires GetCalendarInfo to work first.
 * DATE_LTRREADING/DATE_RTLREADING - Not yet implemented.
 */
static INT NLS_GetDateTimeFormatW(LCID Lcid, DWORD dwFlags, const SYSTEMTIME *lpTime,
				  LPCWSTR lpFormat, LPWSTR lpStr, INT cchOut)
{
    const NLS_FORMAT_NODE *Node;
    SYSTEMTIME St;
    INT cchWritten = 0;
    INT LastFormatPos = 0;
    BOOL bSkipping = FALSE; /* Skipping text around marker? */
    BOOL DDdFormatted = FALSE; /* previous formatted part was for d or dd */

    /* Verify our arguments */
    if ((cchOut && !lpStr) || !(Node = NLS_GetFormats(Lcid, dwFlags)))
	goto invalid_parameter;

    if (dwFlags & ~(DATE_DATEVARSONLY | TIME_TIMEVARSONLY)) {
	if (lpFormat && ((dwFlags & DATE_DATEVARSONLY && dwFlags & ~DATE_FORMAT_FLAGS) ||
			 (dwFlags & TIME_TIMEVARSONLY && dwFlags & ~TIME_FORMAT_FLAGS))) {
	    goto invalid_flags;
	}

	if (dwFlags & DATE_DATEVARSONLY) {
	    if ((dwFlags & (DATE_LTRREADING | DATE_RTLREADING)) ==
		(DATE_LTRREADING | DATE_RTLREADING))
		goto invalid_flags;
	    else if (dwFlags & (DATE_LTRREADING | DATE_RTLREADING))
		FIXME("Unsupported flags: DATE_LTRREADING/DATE_RTLREADING\n");

	    switch (dwFlags & (DATE_SHORTDATE | DATE_LONGDATE | DATE_YEARMONTH)) {
	    case 0:
		break;
	    case DATE_SHORTDATE:
	    case DATE_LONGDATE:
	    case DATE_YEARMONTH:
		if (lpFormat)
		    goto invalid_flags;
		break;
	    default:
		goto invalid_flags;
	    }
	}
    }

    if (!lpFormat) {
	/* Use the appropriate default format */
	if (dwFlags & DATE_DATEVARSONLY) {
	    if (dwFlags & DATE_YEARMONTH)
		lpFormat = GetYearMonth(Node);
	    else if (dwFlags & DATE_LONGDATE)
		lpFormat = GetLongDate(Node);
	    else
		lpFormat = GetShortDate(Node);
	} else
	    lpFormat = GetTime(Node);
    }

    if (!lpTime) {
	GetLocalTime(&St); /* Default to current time */
	lpTime = &St;
    } else {
	if (dwFlags & DATE_DATEVARSONLY) {
	    FILETIME FtTmp;

	    /* Verify the date and correct the D.O.W. if needed */
	    memset(&St, 0, sizeof(St));
	    St.wYear = lpTime->wYear;
	    St.wMonth = lpTime->wMonth;
	    St.wDay = lpTime->wDay;

	    if (St.wDay > 31 || St.wMonth > 12 || !SystemTimeToFileTime(&St, &FtTmp))
		goto invalid_parameter;

	    FileTimeToSystemTime(&FtTmp, &St);
	    lpTime = &St;
	}

	if (dwFlags & TIME_TIMEVARSONLY) {
	    /* Verify the time */
	    if (lpTime->wHour > 24 || lpTime->wMinute > 59 || lpTime->wSecond > 59)
		goto invalid_parameter;
	}
    }

    /* Format the output */
    while (*lpFormat) {
	if (IsLiteralMarker(*lpFormat)) {
	    /* Start of a literal string */
	    lpFormat++;

	    /* Loop until the end of the literal marker or end of the string */
	    while (*lpFormat) {
		if (IsLiteralMarker(*lpFormat)) {
		    lpFormat++;
		    if (!IsLiteralMarker(*lpFormat))
			break; /* Terminating literal marker */
		}

		if (!cchOut)
		    cchWritten++; /* Count size only */
		else if (cchWritten >= cchOut)
		    goto overrun;
		else if (!bSkipping) {
		    lpStr[cchWritten] = *lpFormat;
		    cchWritten++;
		}
		lpFormat++;
	    }
	} else if ((dwFlags & DATE_DATEVARSONLY && IsDateFmtChar(*lpFormat)) ||
		   (dwFlags & TIME_TIMEVARSONLY && IsTimeFmtChar(*lpFormat))) {
	    WCHAR Buff[32], FmtChar;
	    LPCWSTR szAdd = NULL;
	    DWORD dwVal = 0;
	    int Count = 0, dwLen;

	    bSkipping = FALSE;

	    FmtChar = *lpFormat;
	    while (*lpFormat == FmtChar) {
		Count++;
		lpFormat++;
	    }
	    Buff[0] = '\0';

	    if (FmtChar != 'M')
		DDdFormatted = FALSE;
	    switch (FmtChar) {
	    case 'd':
		if (Count >= 4)
		    szAdd = GetLongDay(Node, (lpTime->wDayOfWeek + 6) % 7);
		else if (Count == 3)
		    szAdd = GetShortDay(Node, (lpTime->wDayOfWeek + 6) % 7);
		else {
		    dwVal = lpTime->wDay;
		    szAdd = Buff;
		    DDdFormatted = TRUE;
		}
		break;

	    case 'M':
		if (Count >= 4) {
		    LPCWSTR Genitive = GetGenitiveMonth(Node, lpTime->wMonth - 1);
		    if (Genitive) {
			if (DDdFormatted) {
			    szAdd = Genitive;
			    break;
			} else {
			    LPCWSTR Format = lpFormat;
			    /* Look forward now, if next format pattern is for day
			       genitive name should be used */
			    while (*Format) {
				/* Skip parts within markers */
				if (IsLiteralMarker(*Format)) {
				    ++Format;
				    while (*Format) {
					if (IsLiteralMarker(*Format)) {
					    ++Format;
					    if (!IsLiteralMarker(*Format))
						break;
					}
				    }
				}
				if (*Format != ' ')
				    break;
				++Format;
			    }
			    /* Only numeric day form matters */
			    if (*Format == 'd') {
				INT Dcount = 1;
				while (*++Format == 'd')
				    Dcount++;
				if (Dcount < 3) {
				    szAdd = Genitive;
				    break;
				}
			    }
			}
		    }
		    szAdd = GetLongMonth(Node, lpTime->wMonth - 1);
		} else if (Count == 3)
		    szAdd = GetShortMonth(Node, lpTime->wMonth - 1);
		else {
		    dwVal = lpTime->wMonth;
		    szAdd = Buff;
		}
		break;

	    case 'y':
		if (IS_LCID_JAPANESE(Lcid) && (dwFlags & DATE_USE_ALT_CALENDAR)) {
		    PCJAPANESE_ERA pEra = JapaneseEra_Find(lpTime);
		    if (pEra) {
			if (Count >= 2) {
			    Count = 2;
			}

			dwVal = lpTime->wYear - pEra->wYear + 1;

			if (dwVal == 1 && JapaneseEra_IsFirstYearGannen()) {
			    // Gan of 'Gannen'
			    Buff[0] = 0x5143;
			    Buff[1] = 0;
			}
			szAdd = Buff;
			break;
		    }
		    SetLastError(ERROR_INVALID_PARAMETER);
		    return 0;
		}
		if (Count >= 4) {
		    Count = 4;
		    dwVal = lpTime->wYear;
		} else {
		    Count = Count > 2 ? 2 : Count;
		    dwVal = lpTime->wYear % 100;
		}
		szAdd = Buff;
		break;

	    case 'g':
		if (IS_LCID_JAPANESE(Lcid)) {
		    if (dwFlags & DATE_USE_ALT_CALENDAR) {
			PCJAPANESE_ERA pEra = JapaneseEra_Find(lpTime);
			if (pEra) {
			    RtlStringCbCopyW(Buff, sizeof(Buff), pEra->szEraName);
			    szAdd = Buff;
			    break;
			}
			SetLastError(ERROR_INVALID_PARAMETER);
			return 0;
		    } else {
			/* Seireki */
			Buff[0] = 0x897F;
			Buff[1] = 0x66A6;
			Buff[2] = 0;
			szAdd = Buff;
			break;
		    }
		}
		if (Count == 2) {
		    /* FIXME: Our GetCalendarInfo() does not yet support CAL_SERASTRING.
		     *        When it is fixed, this string should be cached in 'node'.
		     */
		    FIXME("Should be using GetCalendarInfo(CAL_SERASTRING), defaulting "
			  "to 'AD'\n");
		    Buff[0] = 'A';
		    Buff[1] = 'D';
		    Buff[2] = '\0';
		} else {
		    Buff[0] = 'g';
		    Buff[1] = '\0'; /* Add a literal 'g' */
		}
		szAdd = Buff;
		break;

	    case 'h':
		if (!(dwFlags & TIME_FORCE24HOURFORMAT)) {
		    Count = Count > 2 ? 2 : Count;
		    dwVal = lpTime->wHour == 0 ? 12 : (lpTime->wHour - 1) % 12 + 1;
		    szAdd = Buff;
		    break;
		}
		/* .. fall through if we are forced to output in 24 hour format */

	    case 'H':
		Count = Count > 2 ? 2 : Count;
		dwVal = lpTime->wHour;
		szAdd = Buff;
		break;

	    case 'm':
		if (dwFlags & TIME_NOMINUTESORSECONDS) {
		    cchWritten = LastFormatPos; /* Skip */
		    bSkipping = TRUE;
		} else {
		    Count = Count > 2 ? 2 : Count;
		    dwVal = lpTime->wMinute;
		    szAdd = Buff;
		}
		break;

	    case 's':
		if (dwFlags & (TIME_NOSECONDS | TIME_NOMINUTESORSECONDS)) {
		    cchWritten = LastFormatPos; /* Skip */
		    bSkipping = TRUE;
		} else {
		    Count = Count > 2 ? 2 : Count;
		    dwVal = lpTime->wSecond;
		    szAdd = Buff;
		}
		break;

	    case 't':
		if (dwFlags & TIME_NOTIMEMARKER) {
		    cchWritten = LastFormatPos; /* Skip */
		    bSkipping = TRUE;
		} else {
		    if (Count == 1)
			szAdd = lpTime->wHour < 12 ? Node->szShortAM : Node->szShortPM;
		    else
			szAdd = lpTime->wHour < 12 ? GetAM(Node) : GetPM(Node);
		}
		break;
	    }

	    if (szAdd == Buff && Buff[0] == '\0') {
		static const WCHAR FmtW[] = { '%', '.', '*', 'd', 0 };
		/* We have a numeric value to add */
		snprintfW(Buff, ARRAY_SIZE(Buff), FmtW, Count, dwVal);
	    }

	    dwLen = szAdd ? strlenW(szAdd) : 0;

	    if (cchOut && dwLen) {
		if (cchWritten + dwLen < cchOut)
		    memcpy(lpStr + cchWritten, szAdd, dwLen * sizeof(WCHAR));
		else {
		    memcpy(lpStr + cchWritten, szAdd,
			   (cchOut - cchWritten) * sizeof(WCHAR));
		    goto overrun;
		}
	    }
	    cchWritten += dwLen;
	    LastFormatPos = cchWritten; /* Save position of last output format text */
	} else {
	    /* Literal character */
	    if (!cchOut)
		cchWritten++; /* Count size only */
	    else if (cchWritten >= cchOut)
		goto overrun;
	    else if (!bSkipping || *lpFormat == ' ') {
		lpStr[cchWritten] = *lpFormat;
		cchWritten++;
	    }
	    lpFormat++;
	}
    }

    /* Final string terminator and sanity check */
    if (cchOut) {
	if (cchWritten >= cchOut)
	    goto overrun;
	else
	    lpStr[cchWritten] = '\0';
    }
    cchWritten++; /* Include terminating NUL */

    TRACE("returning length=%d, output=%ws\n", cchWritten, lpStr);
    return cchWritten;

overrun:
    TRACE("returning 0, (ERROR_INSUFFICIENT_BUFFER)\n");
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return 0;

invalid_parameter:
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;

invalid_flags:
    SetLastError(ERROR_INVALID_FLAGS);
    return 0;
}

/******************************************************************************
 * NLS_GetDateTimeFormatA <internal>
 *
 * ASCII wrapper for GetDateFormatA/GetTimeFormatA.
 */
static INT NLS_GetDateTimeFormatA(LCID Lcid, DWORD dwFlags, const SYSTEMTIME *lpTime,
				  LPCSTR lpFormat, LPSTR lpStr, INT cchOut)
{
    DWORD Cp = CP_ACP;
    WCHAR szFormat[128], szOut[128];
    INT iRet;

    TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n", Lcid, dwFlags, lpTime, lpFormat,
	  lpStr, cchOut);

    if (NLS_IsUnicodeOnlyLcid(Lcid)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (!(dwFlags & LOCALE_USE_CP_ACP)) {
	const NLS_FORMAT_NODE *Node = NLS_GetFormats(Lcid, dwFlags);
	if (!Node) {
	    SetLastError(ERROR_INVALID_PARAMETER);
	    return 0;
	}

	Cp = Node->dwCodePage;
    }

    if (lpFormat)
	MultiByteToWideChar(Cp, 0, lpFormat, -1, szFormat, ARRAY_SIZE(szFormat));

    if (cchOut > (int)ARRAY_SIZE(szOut))
	cchOut = ARRAY_SIZE(szOut);

    szOut[0] = '\0';

    iRet = NLS_GetDateTimeFormatW(Lcid, dwFlags, lpTime, lpFormat ? szFormat : NULL,
				  lpStr ? szOut : NULL, cchOut);

    if (lpStr) {
	if (szOut[0])
	    WideCharToMultiByte(Cp, 0, szOut, iRet ? -1 : cchOut, lpStr, cchOut, 0, 0);
	else if (cchOut && iRet)
	    *lpStr = '\0';
    }
    return iRet;
}

/******************************************************************************
 * GetDateFormatA [KERNEL32.@]
 *
 * Format a date for a given locale.
 *
 * PARAMS
 *  lcid      [I] Locale to format for
 *  dwFlags   [I] LOCALE_ and DATE_ flags from "winnls.h"
 *  lpTime    [I] Date to format
 *  lpFormat  [I] Format string, or NULL to use the system defaults
 *  lpDateStr [O] Destination for formatted string
 *  cchOut    [I] Size of lpDateStr, or 0 to calculate the resulting size
 *
 * NOTES
 *  - If lpFormat is NULL, lpDateStr will be formatted according to the format
 *    details returned by GetLocaleInfoA() and modified by dwFlags.
 *  - lpFormat is a string of characters and formatting tokens. Any characters
 *    in the string are copied verbatim to lpDateStr, with tokens being replaced
 *    by the date values they represent.
 *  - The following tokens have special meanings in a date format string:
 *|  Token  Meaning
 *|  -----  -------
 *|  d      Single digit day of the month (no leading 0)
 *|  dd     Double digit day of the month
 *|  ddd    Short name for the day of the week
 *|  dddd   Long name for the day of the week
 *|  M      Single digit month of the year (no leading 0)
 *|  MM     Double digit month of the year
 *|  MMM    Short name for the month of the year
 *|  MMMM   Long name for the month of the year
 *|  y      Double digit year number (no leading 0)
 *|  yy     Double digit year number
 *|  yyyy   Four digit year number
 *|  gg     Era string, for example 'AD'.
 *  - To output any literal character that could be misidentified as a token,
 *    enclose it in single quotes.
 *  - The Ascii version of this function fails if lcid is Unicode only.
 *
 * RETURNS
 *  Success: The number of character written to lpDateStr, or that would
 *           have been written, if cchOut is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
WINAPI INT GetDateFormatA(LCID Lcid, DWORD dwFlags, const SYSTEMTIME *lpTime,
			  LPCSTR lpFormat, LPSTR lpDateStr, INT cchOut)
{
    TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n", Lcid, dwFlags, lpTime, lpFormat,
	  lpDateStr, cchOut);

    return NLS_GetDateTimeFormatA(Lcid, dwFlags | DATE_DATEVARSONLY, lpTime, lpFormat,
				  lpDateStr, cchOut);
}

/******************************************************************************
 * GetDateFormatEx [KERNEL32.@]
 *
 * Format a date for a given locale.
 *
 * PARAMS
 *  localename [I] Locale to format for
 *  flags      [I] LOCALE_ and DATE_ flags from "winnls.h"
 *  date       [I] Date to format
 *  format     [I] Format string, or NULL to use the locale defaults
 *  outbuf     [O] Destination for formatted string
 *  bufsize    [I] Size of outbuf, or 0 to calculate the resulting size
 *  calendar   [I] Reserved, must be NULL
 *
 * See GetDateFormatA for notes.
 *
 * RETURNS
 *  Success: The number of characters written to outbuf, or that would have
 *           been written if bufsize is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
WINAPI INT GetDateFormatEx(LPCWSTR Localename, DWORD Flags, const SYSTEMTIME *Date,
			   LPCWSTR Format, LPWSTR Outbuf, INT Bufsize, LPCWSTR Calendar)
{
    TRACE("(%ws,0x%08x,%p,%ws,%p,%d,%ws)\n", Localename, Flags, Date,
	  Format, Outbuf, Bufsize, Calendar);

    /* Parameter is currently reserved and Windows errors if set */
    if (Calendar != NULL) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    return NLS_GetDateTimeFormatW(LocaleNameToLCID(Localename, 0),
				  Flags | DATE_DATEVARSONLY, Date, Format, Outbuf,
				  Bufsize);
}

/******************************************************************************
 * GetDateFormatW	[KERNEL32.@]
 *
 * See GetDateFormatA.
 */
WINAPI INT GetDateFormatW(LCID Lcid, DWORD dwFlags, const SYSTEMTIME *lpTime,
			  LPCWSTR lpFormat, LPWSTR lpDateStr, INT cchOut)
{
    TRACE("(0x%04x,0x%08x,%p,%ws,%p,%d)\n", Lcid, dwFlags, lpTime, lpFormat,
	  lpDateStr, cchOut);

    return NLS_GetDateTimeFormatW(Lcid, dwFlags | DATE_DATEVARSONLY, lpTime, lpFormat,
				  lpDateStr, cchOut);
}

/******************************************************************************
 *		GetTimeFormatA	[KERNEL32.@]
 *
 * Format a time for a given locale.
 *
 * PARAMS
 *  lcid      [I] Locale to format for
 *  dwFlags   [I] LOCALE_ and TIME_ flags from "winnls.h"
 *  lpTime    [I] Time to format
 *  lpFormat  [I] Formatting overrides
 *  lpTimeStr [O] Destination for formatted string
 *  cchOut    [I] Size of lpTimeStr, or 0 to calculate the resulting size
 *
 * NOTES
 *  - If lpFormat is NULL, lpszValue will be formatted according to the format
 *    details returned by GetLocaleInfoA() and modified by dwFlags.
 *  - lpFormat is a string of characters and formatting tokens. Any characters
 *    in the string are copied verbatim to lpTimeStr, with tokens being replaced
 *    by the time values they represent.
 *  - The following tokens have special meanings in a time format string:
 *|  Token  Meaning
 *|  -----  -------
 *|  h      Hours with no leading zero (12-hour clock)
 *|  hh     Hours with full two digits (12-hour clock)
 *|  H      Hours with no leading zero (24-hour clock)
 *|  HH     Hours with full two digits (24-hour clock)
 *|  m      Minutes with no leading zero
 *|  mm     Minutes with full two digits
 *|  s      Seconds with no leading zero
 *|  ss     Seconds with full two digits
 *|  t      Short time marker (e.g. "A" or "P")
 *|  tt     Long time marker (e.g. "AM", "PM")
 *  - To output any literal character that could be misidentified as a token,
 *    enclose it in single quotes.
 *  - The Ascii version of this function fails if lcid is Unicode only.
 *
 * RETURNS
 *  Success: The number of character written to lpTimeStr, or that would
 *           have been written, if cchOut is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
WINAPI INT GetTimeFormatA(LCID Lcid, DWORD dwFlags, const SYSTEMTIME *lpTime,
			  LPCSTR lpFormat, LPSTR lpTimeStr, INT cchOut)
{
    TRACE("(0x%04x,0x%08x,%p,%s,%p,%d)\n", Lcid, dwFlags, lpTime, lpFormat,
	  lpTimeStr, cchOut);

    return NLS_GetDateTimeFormatA(Lcid, dwFlags | TIME_TIMEVARSONLY, lpTime, lpFormat,
				  lpTimeStr, cchOut);
}

/******************************************************************************
 * GetTimeFormatEx [KERNEL32.@]
 *
 * Format a date for a given locale.
 *
 * PARAMS
 *  localename [I] Locale to format for
 *  flags      [I] LOCALE_ and TIME_ flags from "winnls.h"
 *  time       [I] Time to format
 *  format     [I] Formatting overrides
 *  outbuf     [O] Destination for formatted string
 *  bufsize    [I] Size of outbuf, or 0 to calculate the resulting size
 *
 * See GetTimeFormatA for notes.
 *
 * RETURNS
 *  Success: The number of characters written to outbuf, or that would have
 *           have been written if bufsize is 0.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
WINAPI INT GetTimeFormatEx(LPCWSTR LocaleName, DWORD Flags, const SYSTEMTIME *Time,
			   LPCWSTR Format, LPWSTR Outbuf, INT Bufsize)
{
    TRACE("(%ws,0x%08x,%p,%ws,%p,%d)\n", LocaleName, Flags, Time,
	  Format, Outbuf, Bufsize);

    return NLS_GetDateTimeFormatW(LocaleNameToLCID(LocaleName, 0),
				  Flags | TIME_TIMEVARSONLY, Time, Format, Outbuf,
				  Bufsize);
}

/******************************************************************************
 *		GetTimeFormatW	[KERNEL32.@]
 *
 * See GetTimeFormatA.
 */
WINAPI INT GetTimeFormatW(LCID Lcid, DWORD dwFlags, const SYSTEMTIME *lpTime,
			  LPCWSTR lpFormat, LPWSTR lpTimeStr, INT cchOut)
{
    TRACE("(0x%04x,0x%08x,%p,%ws,%p,%d)\n", Lcid, dwFlags, lpTime, lpFormat,
	  lpTimeStr, cchOut);

    return NLS_GetDateTimeFormatW(Lcid, dwFlags | TIME_TIMEVARSONLY, lpTime, lpFormat,
				  lpTimeStr, cchOut);
}

/* Number parsing state flags */
#define NF_ISNEGATIVE 0x1 /* '-' found */
#define NF_ISREAL 0x2 /* '.' found */
#define NF_DIGITS 0x4 /* '0'-'9' found */
#define NF_DIGITS_OUT 0x8 /* Digits before the '.' found */
#define NF_ROUND 0x10 /* Number needs to be rounded */

/* Formatting options for Numbers */
#define NLS_NEG_PARENS 0 /* "(1.1)" */
#define NLS_NEG_LEFT 1 /* "-1.1"  */
#define NLS_NEG_LEFT_SPACE 2 /* "- 1.1" */
#define NLS_NEG_RIGHT 3 /* "1.1-"  */
#define NLS_NEG_RIGHT_SPACE 4 /* "1.1 -" */

/**************************************************************************
 *              GetNumberFormatW	(KERNEL32.@)
 *
 * See GetNumberFormatA.
 */
WINAPI INT GetNumberFormatW(LCID Lcid, DWORD dwFlags, LPCWSTR lpszValue,
			    const NUMBERFMTW *lpFormat, LPWSTR lpNumberStr, int cchOut)
{
    WCHAR szBuff[128], *szOut = szBuff + ARRAY_SIZE(szBuff) - 1;
    WCHAR szNegBuff[8];
    const WCHAR *lpszNeg = NULL, *lpszNegStart, *szSrc;
    DWORD dwState = 0, dwDecimals = 0, dwGroupCount = 0, dwCurrentGroupCount = 0;
    INT iRet;

    TRACE("(0x%04x,0x%08x,%ws,%p,%p,%d)\n", Lcid, dwFlags, lpszValue, lpFormat,
	  lpNumberStr, cchOut);

    if (!lpszValue || cchOut < 0 || (cchOut > 0 && !lpNumberStr) ||
	!IsValidLocale(Lcid, 0) ||
	(lpFormat && (dwFlags || !lpFormat->lpDecimalSep || !lpFormat->lpThousandSep))) {
	goto error;
    }

    if (!lpFormat) {
	const NLS_FORMAT_NODE *Node = NLS_GetFormats(Lcid, dwFlags);

	if (!Node)
	    goto error;
	lpFormat = &Node->Fmt;
	lpszNegStart = lpszNeg = GetNegative(Node);
    } else {
	GetLocaleInfoW(Lcid, LOCALE_SNEGATIVESIGN | (dwFlags & LOCALE_NOUSEROVERRIDE),
		       szNegBuff, ARRAY_SIZE(szNegBuff));
	lpszNegStart = lpszNeg = szNegBuff;
    }
    lpszNeg = lpszNeg + strlenW(lpszNeg) - 1;

    dwFlags &= (LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP);

    /* Format the number backwards into a temporary buffer */

    szSrc = lpszValue;
    *szOut-- = '\0';

    /* Check the number for validity */
    while (*szSrc) {
	if (*szSrc >= '0' && *szSrc <= '9') {
	    dwState |= NF_DIGITS;
	    if (dwState & NF_ISREAL)
		dwDecimals++;
	} else if (*szSrc == '-') {
	    if (dwState)
		goto error; /* '-' not first character */
	    dwState |= NF_ISNEGATIVE;
	} else if (*szSrc == '.') {
	    if (dwState & NF_ISREAL)
		goto error; /* More than one '.' */
	    dwState |= NF_ISREAL;
	} else
	    goto error; /* Invalid char */
	szSrc++;
    }
    szSrc--; /* Point to last character */

    if (!(dwState & NF_DIGITS))
	goto error; /* No digits */

    /* Add any trailing negative sign */
    if (dwState & NF_ISNEGATIVE) {
	switch (lpFormat->NegativeOrder) {
	case NLS_NEG_PARENS:
	    *szOut-- = ')';
	    break;
	case NLS_NEG_RIGHT:
	case NLS_NEG_RIGHT_SPACE:
	    while (lpszNeg >= lpszNegStart)
		*szOut-- = *lpszNeg--;
	    if (lpFormat->NegativeOrder == NLS_NEG_RIGHT_SPACE)
		*szOut-- = ' ';
	    break;
	}
    }

    /* Copy all digits up to the decimal point */
    if (!lpFormat->NumDigits) {
	if (dwState & NF_ISREAL) {
	    while (*szSrc != '.') /* Don't write any decimals or a separator */
	    {
		if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
		    dwState |= NF_ROUND;
		else
		    dwState &= ~NF_ROUND;
		szSrc--;
	    }
	    szSrc--;
	}
    } else {
	LPWSTR lpszDec = lpFormat->lpDecimalSep + strlenW(lpFormat->lpDecimalSep) - 1;

	if (dwDecimals <= lpFormat->NumDigits) {
	    dwDecimals = lpFormat->NumDigits - dwDecimals;
	    while (dwDecimals--)
		*szOut-- = '0'; /* Pad to correct number of dp */
	} else {
	    dwDecimals -= lpFormat->NumDigits;
	    /* Skip excess decimals, and determine if we have to round the number */
	    while (dwDecimals--) {
		if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
		    dwState |= NF_ROUND;
		else
		    dwState &= ~NF_ROUND;
		szSrc--;
	    }
	}

	if (dwState & NF_ISREAL) {
	    while (*szSrc != '.') {
		if (dwState & NF_ROUND) {
		    if (*szSrc == '9')
			*szOut-- = '0'; /* continue rounding */
		    else {
			dwState &= ~NF_ROUND;
			*szOut-- = (*szSrc) + 1;
		    }
		    szSrc--;
		} else
		    *szOut-- = *szSrc--; /* Write existing decimals */
	    }
	    szSrc--; /* Skip '.' */
	}

	while (lpszDec >= lpFormat->lpDecimalSep)
	    *szOut-- = *lpszDec--; /* Write decimal separator */
    }

    dwGroupCount = lpFormat->Grouping == 32 ? 3 : lpFormat->Grouping;

    /* Write the remaining whole number digits, including grouping chars */
    while (szSrc >= lpszValue && *szSrc >= '0' && *szSrc <= '9') {
	if (dwState & NF_ROUND) {
	    if (*szSrc == '9')
		*szOut-- = '0'; /* continue rounding */
	    else {
		dwState &= ~NF_ROUND;
		*szOut-- = (*szSrc) + 1;
	    }
	    szSrc--;
	} else
	    *szOut-- = *szSrc--;

	dwState |= NF_DIGITS_OUT;
	dwCurrentGroupCount++;
	if (szSrc >= lpszValue && dwCurrentGroupCount == dwGroupCount && *szSrc != '-') {
	    LPWSTR lpszGrp = lpFormat->lpThousandSep + strlenW(lpFormat->lpThousandSep) -
			     1;

	    while (lpszGrp >= lpFormat->lpThousandSep)
		*szOut-- = *lpszGrp--; /* Write grouping char */

	    dwCurrentGroupCount = 0;
	    if (lpFormat->Grouping == 32)
		dwGroupCount = 2; /* Indic grouping: 3 then 2 */
	}
    }
    if (dwState & NF_ROUND) {
	*szOut-- = '1'; /* e.g. .6 > 1.0 */
    } else if (!(dwState & NF_DIGITS_OUT) && lpFormat->LeadingZero)
	*szOut-- = '0'; /* Add leading 0 if we have no digits before the decimal point */

    /* Add any leading negative sign */
    if (dwState & NF_ISNEGATIVE) {
	switch (lpFormat->NegativeOrder) {
	case NLS_NEG_PARENS:
	    *szOut-- = '(';
	    break;
	case NLS_NEG_LEFT_SPACE:
	    *szOut-- = ' ';
	    /* Fall through */
	case NLS_NEG_LEFT:
	    while (lpszNeg >= lpszNegStart)
		*szOut-- = *lpszNeg--;
	    break;
	}
    }
    szOut++;

    iRet = strlenW(szOut) + 1;
    if (cchOut) {
	if (iRet <= cchOut)
	    memcpy(lpNumberStr, szOut, iRet * sizeof(WCHAR));
	else {
	    memcpy(lpNumberStr, szOut, cchOut * sizeof(WCHAR));
	    lpNumberStr[cchOut - 1] = '\0';
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	    iRet = 0;
	}
    }
    return iRet;

error:
    SetLastError(lpFormat && dwFlags ? ERROR_INVALID_FLAGS : ERROR_INVALID_PARAMETER);
    return 0;
}

/**************************************************************************
 *              GetNumberFormatEx	(KERNEL32.@)
 */
WINAPI INT GetNumberFormatEx(LPCWSTR Name, DWORD Flags, LPCWSTR Value,
			     const NUMBERFMTW *Format, LPWSTR Number, int Numout)
{
    LCID Lcid;

    TRACE("(%ws,0x%08x,%ws,%p,%p,%d)\n", Name, Flags, Value, Format,
	  Number, Numout);

    Lcid = LocaleNameToLCID(Name, 0);
    if (!Lcid)
	return 0;

    return GetNumberFormatW(Lcid, Flags, Value, Format, Number, Numout);
}

/* Formatting states for Currencies. We use flags to avoid code duplication. */
#define CF_PARENS 0x1 /* Parentheses      */
#define CF_MINUS_LEFT 0x2 /* '-' to the left  */
#define CF_MINUS_RIGHT 0x4 /* '-' to the right */
#define CF_MINUS_BEFORE 0x8 /* '-' before '$'   */
#define CF_CY_LEFT 0x10 /* '$' to the left  */
#define CF_CY_RIGHT 0x20 /* '$' to the right */
#define CF_CY_SPACE 0x40 /* ' ' by '$'       */

/**************************************************************************
 *              GetCurrencyFormatW	(KERNEL32.@)
 *
 * See GetCurrencyFormatA.
 */
WINAPI INT GetCurrencyFormatW(LCID Lcid, DWORD dwFlags, LPCWSTR lpszValue,
			      const CURRENCYFMTW *lpFormat, LPWSTR lpCurrencyStr,
			      int cchOut)
{
    static const BYTE NLS_NegCyFormats[16] = {
	CF_PARENS | CF_CY_LEFT, /* ($1.1) */
	CF_MINUS_LEFT | CF_MINUS_BEFORE | CF_CY_LEFT, /* -$1.1  */
	CF_MINUS_LEFT | CF_CY_LEFT, /* $-1.1  */
	CF_MINUS_RIGHT | CF_CY_LEFT, /* $1.1-  */
	CF_PARENS | CF_CY_RIGHT, /* (1.1$) */
	CF_MINUS_LEFT | CF_CY_RIGHT, /* -1.1$  */
	CF_MINUS_RIGHT | CF_MINUS_BEFORE | CF_CY_RIGHT, /* 1.1-$  */
	CF_MINUS_RIGHT | CF_CY_RIGHT, /* 1.1$-  */
	CF_MINUS_LEFT | CF_CY_RIGHT | CF_CY_SPACE, /* -1.1 $ */
	CF_MINUS_LEFT | CF_MINUS_BEFORE | CF_CY_LEFT | CF_CY_SPACE, /* -$ 1.1 */
	CF_MINUS_RIGHT | CF_CY_RIGHT | CF_CY_SPACE, /* 1.1 $-  */
	CF_MINUS_RIGHT | CF_CY_LEFT | CF_CY_SPACE, /* $ 1.1-  */
	CF_MINUS_LEFT | CF_CY_LEFT | CF_CY_SPACE, /* $ -1.1  */
	CF_MINUS_RIGHT | CF_MINUS_BEFORE | CF_CY_RIGHT | CF_CY_SPACE, /* 1.1- $ */
	CF_PARENS | CF_CY_LEFT | CF_CY_SPACE, /* ($ 1.1) */
	CF_PARENS | CF_CY_RIGHT | CF_CY_SPACE, /* (1.1 $) */
    };
    static const BYTE NLS_PosCyFormats[4] = {
	CF_CY_LEFT, /* $1.1  */
	CF_CY_RIGHT, /* 1.1$  */
	CF_CY_LEFT | CF_CY_SPACE, /* $ 1.1 */
	CF_CY_RIGHT | CF_CY_SPACE, /* 1.1 $ */
    };
    WCHAR szBuff[128], *szOut = szBuff + ARRAY_SIZE(szBuff) - 1;
    WCHAR szNegBuff[8];
    const WCHAR *lpszNeg = NULL, *lpszNegStart, *szSrc, *lpszCy, *lpszCyStart;
    DWORD dwState = 0, dwDecimals = 0, dwGroupCount = 0, dwCurrentGroupCount = 0, dwFmt;
    INT iRet;

    TRACE("(0x%04x,0x%08x,%ws,%p,%p,%d)\n", Lcid, dwFlags, lpszValue, lpFormat,
	  lpCurrencyStr, cchOut);

    if (!lpszValue || cchOut < 0 || (cchOut > 0 && !lpCurrencyStr) ||
	!IsValidLocale(Lcid, 0) ||
	(lpFormat && (dwFlags || !lpFormat->lpDecimalSep || !lpFormat->lpThousandSep ||
		      !lpFormat->lpCurrencySymbol || lpFormat->NegativeOrder > 15 ||
		      lpFormat->PositiveOrder > 3))) {
	goto error;
    }

    if (!lpFormat) {
	const NLS_FORMAT_NODE *Node = NLS_GetFormats(Lcid, dwFlags);

	if (!Node)
	    goto error;

	lpFormat = &Node->Cyfmt;
	lpszNegStart = lpszNeg = GetNegative(Node);
    } else {
	GetLocaleInfoW(Lcid, LOCALE_SNEGATIVESIGN | (dwFlags & LOCALE_NOUSEROVERRIDE),
		       szNegBuff, ARRAY_SIZE(szNegBuff));
	lpszNegStart = lpszNeg = szNegBuff;
    }
    dwFlags &= (LOCALE_NOUSEROVERRIDE | LOCALE_USE_CP_ACP);

    lpszNeg = lpszNeg + strlenW(lpszNeg) - 1;
    lpszCyStart = lpFormat->lpCurrencySymbol;
    lpszCy = lpszCyStart + strlenW(lpszCyStart) - 1;

    /* Format the currency backwards into a temporary buffer */

    szSrc = lpszValue;
    *szOut-- = '\0';

    /* Check the number for validity */
    while (*szSrc) {
	if (*szSrc >= '0' && *szSrc <= '9') {
	    dwState |= NF_DIGITS;
	    if (dwState & NF_ISREAL)
		dwDecimals++;
	} else if (*szSrc == '-') {
	    if (dwState)
		goto error; /* '-' not first character */
	    dwState |= NF_ISNEGATIVE;
	} else if (*szSrc == '.') {
	    if (dwState & NF_ISREAL)
		goto error; /* More than one '.' */
	    dwState |= NF_ISREAL;
	} else
	    goto error; /* Invalid char */
	szSrc++;
    }
    szSrc--; /* Point to last character */

    if (!(dwState & NF_DIGITS))
	goto error; /* No digits */

    if (dwState & NF_ISNEGATIVE)
	dwFmt = NLS_NegCyFormats[lpFormat->NegativeOrder];
    else
	dwFmt = NLS_PosCyFormats[lpFormat->PositiveOrder];

    /* Add any trailing negative or currency signs */
    if (dwFmt & CF_PARENS)
	*szOut-- = ')';

    while (dwFmt & (CF_MINUS_RIGHT | CF_CY_RIGHT)) {
	switch (dwFmt & (CF_MINUS_RIGHT | CF_MINUS_BEFORE | CF_CY_RIGHT)) {
	case CF_MINUS_RIGHT:
	case CF_MINUS_RIGHT | CF_CY_RIGHT:
	    while (lpszNeg >= lpszNegStart)
		*szOut-- = *lpszNeg--;
	    dwFmt &= ~CF_MINUS_RIGHT;
	    break;

	case CF_CY_RIGHT:
	case CF_MINUS_BEFORE | CF_CY_RIGHT:
	case CF_MINUS_RIGHT | CF_MINUS_BEFORE | CF_CY_RIGHT:
	    while (lpszCy >= lpszCyStart)
		*szOut-- = *lpszCy--;
	    if (dwFmt & CF_CY_SPACE)
		*szOut-- = ' ';
	    dwFmt &= ~(CF_CY_RIGHT | CF_MINUS_BEFORE);
	    break;
	}
    }

    /* Copy all digits up to the decimal point */
    if (!lpFormat->NumDigits) {
	if (dwState & NF_ISREAL) {
	    while (*szSrc != '.') /* Don't write any decimals or a separator */
	    {
		if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
		    dwState |= NF_ROUND;
		else
		    dwState &= ~NF_ROUND;
		szSrc--;
	    }
	    szSrc--;
	}
    } else {
	LPWSTR lpszDec = lpFormat->lpDecimalSep + strlenW(lpFormat->lpDecimalSep) - 1;

	if (dwDecimals <= lpFormat->NumDigits) {
	    dwDecimals = lpFormat->NumDigits - dwDecimals;
	    while (dwDecimals--)
		*szOut-- = '0'; /* Pad to correct number of dp */
	} else {
	    dwDecimals -= lpFormat->NumDigits;
	    /* Skip excess decimals, and determine if we have to round the number */
	    while (dwDecimals--) {
		if (*szSrc >= '5' || (*szSrc == '4' && (dwState & NF_ROUND)))
		    dwState |= NF_ROUND;
		else
		    dwState &= ~NF_ROUND;
		szSrc--;
	    }
	}

	if (dwState & NF_ISREAL) {
	    while (*szSrc != '.') {
		if (dwState & NF_ROUND) {
		    if (*szSrc == '9')
			*szOut-- = '0'; /* continue rounding */
		    else {
			dwState &= ~NF_ROUND;
			*szOut-- = (*szSrc) + 1;
		    }
		    szSrc--;
		} else
		    *szOut-- = *szSrc--; /* Write existing decimals */
	    }
	    szSrc--; /* Skip '.' */
	}
	while (lpszDec >= lpFormat->lpDecimalSep)
	    *szOut-- = *lpszDec--; /* Write decimal separator */
    }

    dwGroupCount = lpFormat->Grouping == 32 ? 3 : lpFormat->Grouping;

    /* Write the remaining whole number digits, including grouping chars */
    while (szSrc >= lpszValue && *szSrc >= '0' && *szSrc <= '9') {
	if (dwState & NF_ROUND) {
	    if (*szSrc == '9')
		*szOut-- = '0'; /* continue rounding */
	    else {
		dwState &= ~NF_ROUND;
		*szOut-- = (*szSrc) + 1;
	    }
	    szSrc--;
	} else
	    *szOut-- = *szSrc--;

	dwState |= NF_DIGITS_OUT;
	dwCurrentGroupCount++;
	if (szSrc >= lpszValue && dwCurrentGroupCount == dwGroupCount && *szSrc != '-') {
	    LPWSTR lpszGrp = lpFormat->lpThousandSep + strlenW(lpFormat->lpThousandSep) -
			     1;

	    while (lpszGrp >= lpFormat->lpThousandSep)
		*szOut-- = *lpszGrp--; /* Write grouping char */

	    dwCurrentGroupCount = 0;
	    if (lpFormat->Grouping == 32)
		dwGroupCount = 2; /* Indic grouping: 3 then 2 */
	}
    }
    if (dwState & NF_ROUND)
	*szOut-- = '1'; /* e.g. .6 > 1.0 */
    else if (!(dwState & NF_DIGITS_OUT) && lpFormat->LeadingZero)
	*szOut-- = '0'; /* Add leading 0 if we have no digits before the decimal point */

    /* Add any leading negative or currency sign */
    while (dwFmt & (CF_MINUS_LEFT | CF_CY_LEFT)) {
	switch (dwFmt & (CF_MINUS_LEFT | CF_MINUS_BEFORE | CF_CY_LEFT)) {
	case CF_MINUS_LEFT:
	case CF_MINUS_LEFT | CF_CY_LEFT:
	    while (lpszNeg >= lpszNegStart)
		*szOut-- = *lpszNeg--;
	    dwFmt &= ~CF_MINUS_LEFT;
	    break;

	case CF_CY_LEFT:
	case CF_CY_LEFT | CF_MINUS_BEFORE:
	case CF_MINUS_LEFT | CF_MINUS_BEFORE | CF_CY_LEFT:
	    if (dwFmt & CF_CY_SPACE)
		*szOut-- = ' ';
	    while (lpszCy >= lpszCyStart)
		*szOut-- = *lpszCy--;
	    dwFmt &= ~(CF_CY_LEFT | CF_MINUS_BEFORE);
	    break;
	}
    }
    if (dwFmt & CF_PARENS)
	*szOut-- = '(';
    szOut++;

    iRet = strlenW(szOut) + 1;
    if (cchOut) {
	if (iRet <= cchOut)
	    memcpy(lpCurrencyStr, szOut, iRet * sizeof(WCHAR));
	else {
	    memcpy(lpCurrencyStr, szOut, cchOut * sizeof(WCHAR));
	    lpCurrencyStr[cchOut - 1] = '\0';
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	    iRet = 0;
	}
    }
    return iRet;

error:
    SetLastError(lpFormat && dwFlags ? ERROR_INVALID_FLAGS : ERROR_INVALID_PARAMETER);
    return 0;
}

/***********************************************************************
 *            GetCurrencyFormatEx (KERNEL32.@)
 */
WINAPI int GetCurrencyFormatEx(LPCWSTR LocaleName, DWORD Flags, LPCWSTR Value,
			       const CURRENCYFMTW *Format, LPWSTR Str, int Len)
{
    TRACE("(%ws,0x%08x,%ws,%p,%p,%d)\n", LocaleName, Flags, Value,
	  Format, Str, Len);

    return GetCurrencyFormatW(LocaleNameToLCID(LocaleName, 0), Flags, Value, Format, Str,
			      Len);
}

/* FIXME: Everything below here needs to move somewhere else along with the
 *        other EnumXXX functions, when a method for storing resources for
 *        alternate calendars is determined.
 */

/* Types for Enum* internals are declared in lcformat_private.h */

/******************************************************************************
 * NLS_EnumDateFormats <internal>
 * Enumerates date formats for a specified locale.
 *
 * PARAMS
 *    ctxt [I] enumeration context, see 'struct enumdateformats_context'
 *
 * RETURNS
 *    Success: TRUE.
 *    Failure: FALSE. Use GetLastError() to determine the cause.
 */
BOOL NLS_EnumDateFormats(const struct ENUM_DATE_FORMATS_CONTEXT *Ctxt)
{
    WCHAR BufW[256];
    char BufA[256];
    LCTYPE Lctype;
    CALID CalId;
    INT Ret;

    if (!Ctxt->u.Callback) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if (!GetLocaleInfoW(Ctxt->Lcid, LOCALE_ICALENDARTYPE | LOCALE_RETURN_NUMBER,
			(LPWSTR)&CalId, sizeof(CalId) / sizeof(WCHAR)))
	return FALSE;

    switch (Ctxt->Flags & ~LOCALE_USE_CP_ACP) {
    case 0:
    case DATE_SHORTDATE:
	Lctype = LOCALE_SSHORTDATE;
	break;
    case DATE_LONGDATE:
	Lctype = LOCALE_SLONGDATE;
	break;
    case DATE_YEARMONTH:
	Lctype = LOCALE_SYEARMONTH;
	break;
    default:
	FIXME("Unknown date format (0x%08x)\n", Ctxt->Flags);
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    Lctype |= Ctxt->Flags & LOCALE_USE_CP_ACP;
    if (Ctxt->Unicode)
	Ret = GetLocaleInfoW(Ctxt->Lcid, Lctype, BufW, ARRAY_SIZE(BufW));
    else
	Ret = GetLocaleInfoA(Ctxt->Lcid, Lctype, BufA, ARRAY_SIZE(BufA));

    if (Ret) {
	switch (Ctxt->Type) {
	case CALLBACK_ENUMPROC:
	    Ctxt->u.Callback(Ctxt->Unicode ? BufW : (WCHAR *)BufA);
	    break;
	case CALLBACK_ENUMPROCEX:
	    Ctxt->u.CallbackEx(Ctxt->Unicode ? BufW : (WCHAR *)BufA, CalId);
	    break;
	case CALLBACK_ENUMPROCEXEX:
	    Ctxt->u.CallbackExEx(BufW, CalId, Ctxt->lParam);
	    break;
	default:;
	}
    }

    return TRUE;
}

/**************************************************************************
 *              EnumDateFormatsExA    (KERNEL32.@)
 *
 * FIXME: MSDN mentions only LOCALE_USE_CP_ACP, should we handle
 * LOCALE_NOUSEROVERRIDE here as well?
 */
WINAPI BOOL EnumDateFormatsExA(DATEFMT_ENUMPROCEXA Proc, LCID Lcid, DWORD Flags)
{
    struct ENUM_DATE_FORMATS_CONTEXT Ctxt;

    Ctxt.Type = CALLBACK_ENUMPROCEX;
    Ctxt.u.CallbackEx = (DATEFMT_ENUMPROCEXW)Proc;
    Ctxt.Lcid = Lcid;
    Ctxt.Flags = Flags;
    Ctxt.Unicode = FALSE;

    return NLS_EnumDateFormats(&Ctxt);
}

/**************************************************************************
 *              EnumDateFormatsExW    (KERNEL32.@)
 */
WINAPI BOOL EnumDateFormatsExW(DATEFMT_ENUMPROCEXW Proc, LCID Lcid, DWORD Flags)
{
    struct ENUM_DATE_FORMATS_CONTEXT Ctxt;

    Ctxt.Type = CALLBACK_ENUMPROCEX;
    Ctxt.u.CallbackEx = Proc;
    Ctxt.Lcid = Lcid;
    Ctxt.Flags = Flags;
    Ctxt.Unicode = TRUE;

    return NLS_EnumDateFormats(&Ctxt);
}

/**************************************************************************
 *              EnumDateFormatsW	(KERNEL32.@)
 */
WINAPI BOOL EnumDateFormatsW(DATEFMT_ENUMPROCW Proc, LCID Lcid, DWORD Flags)
{
    struct ENUM_DATE_FORMATS_CONTEXT Ctxt;

    Ctxt.Type = CALLBACK_ENUMPROC;
    Ctxt.u.Callback = Proc;
    Ctxt.Lcid = Lcid;
    Ctxt.Flags = Flags;
    Ctxt.Unicode = TRUE;

    return NLS_EnumDateFormats(&Ctxt);
}

/**************************************************************************
 *              EnumDateFormatsExEx	(KERNEL32.@)
 */
WINAPI BOOL EnumDateFormatsExEx(DATEFMT_ENUMPROCEXEX Proc, const WCHAR *Locale,
				DWORD Flags, LPARAM lParam)
{
    struct ENUM_DATE_FORMATS_CONTEXT Ctxt;

    Ctxt.Type = CALLBACK_ENUMPROCEXEX;
    Ctxt.u.CallbackExEx = Proc;
    Ctxt.Lcid = LocaleNameToLCID(Locale, 0);
    Ctxt.Flags = Flags;
    Ctxt.lParam = lParam;
    Ctxt.Unicode = TRUE;

    return NLS_EnumDateFormats(&Ctxt);
}

BOOL NLS_EnumTimeFormats(struct ENUM_TIME_FORMATS_CONTEXT *Ctxt)
{
    WCHAR BufW[256];
    char BufA[256];
    LCTYPE Lctype;
    INT Ret;

    if (!Ctxt->u.Callback) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    switch (Ctxt->Flags & ~LOCALE_USE_CP_ACP) {
    case 0:
	Lctype = LOCALE_STIMEFORMAT;
	break;
    case TIME_NOSECONDS:
	Lctype = LOCALE_SSHORTTIME;
	break;
    default:
	FIXME("Unknown time format (%d)\n", Ctxt->Flags);
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    Lctype |= Ctxt->Flags & LOCALE_USE_CP_ACP;
    if (Ctxt->Unicode)
	Ret = GetLocaleInfoW(Ctxt->Lcid, Lctype, BufW, ARRAY_SIZE(BufW));
    else
	Ret = GetLocaleInfoA(Ctxt->Lcid, Lctype, BufA, ARRAY_SIZE(BufA));

    if (Ret) {
	switch (Ctxt->Type) {
	case CALLBACK_ENUMPROC:
	    Ctxt->u.Callback(Ctxt->Unicode ? BufW : (WCHAR *)BufA);
	    break;
	case CALLBACK_ENUMPROCEX:
	    Ctxt->u.CallbackEx(BufW, Ctxt->lParam);
	    break;
	default:;
	}
    }

    return TRUE;
}

/**************************************************************************
 *              EnumTimeFormatsW	(KERNEL32.@)
 */
WINAPI BOOL EnumTimeFormatsW(TIMEFMT_ENUMPROCW Proc, LCID Lcid, DWORD Flags)
{
    struct ENUM_TIME_FORMATS_CONTEXT Ctxt;

    Ctxt.Type = CALLBACK_ENUMPROC;
    Ctxt.u.Callback = Proc;
    Ctxt.Lcid = Lcid;
    Ctxt.Flags = Flags;
    Ctxt.Unicode = TRUE;

    return NLS_EnumTimeFormats(&Ctxt);
}

/**************************************************************************
 *              EnumTimeFormatsEx	(KERNEL32.@)
 */
WINAPI BOOL EnumTimeFormatsEx(TIMEFMT_ENUMPROCEX Proc, const WCHAR *Locale, DWORD Flags,
			      LPARAM lParam)
{
    struct ENUM_TIME_FORMATS_CONTEXT Ctxt;

    Ctxt.Type = CALLBACK_ENUMPROCEX;
    Ctxt.u.CallbackEx = Proc;
    Ctxt.Lcid = LocaleNameToLCID(Locale, 0);
    Ctxt.Flags = Flags;
    Ctxt.lParam = lParam;
    Ctxt.Unicode = TRUE;

    return NLS_EnumTimeFormats(&Ctxt);
}

/******************************************************************************
 * NLS_EnumCalendarInfo <internal>
 * Enumerates calendar information for a specified locale.
 *
 * PARAMS
 *    ctxt [I] enumeration context, see 'struct enumcalendar_context'
 *
 * RETURNS
 *    Success: TRUE.
 *    Failure: FALSE. Use GetLastError() to determine the cause.
 *
 * NOTES
 *    When the ANSI version of this function is used with a Unicode-only LCID,
 *    the call can succeed because the system uses the system code page.
 *    However, characters that are undefined in the system code page appear
 *    in the string as a question mark (?).
 *
 * TODO
 *    The above note should be respected by GetCalendarInfoA.
 */
BOOL NLS_EnumCalendarInfo(const struct ENUM_CALENDAR_CONTEXT *Ctx)
{
    WCHAR *Buf, *Opt = NULL, *Iter = NULL;
    CALID Calendar = Ctx->Calendar;
    BOOL Ret = FALSE;
    int BufSz = 200; /* the size of the buffer */

    if (Ctx->u.Callback == NULL) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    Buf = HeapAlloc(GetProcessHeap(), 0, BufSz);
    if (Buf == NULL) {
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return FALSE;
    }

    if (Calendar == ENUM_ALL_CALENDARS) {
	int OptSz = GetLocaleInfoW(Ctx->Lcid, LOCALE_IOPTIONALCALENDAR, NULL, 0);
	if (OptSz > 1) {
	    Opt = HeapAlloc(GetProcessHeap(), 0, OptSz * sizeof(WCHAR));
	    if (Opt == NULL) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		goto cleanup;
	    }
	    if (GetLocaleInfoW(Ctx->Lcid, LOCALE_IOPTIONALCALENDAR, Opt, OptSz))
		Iter = Opt;
	}
	Calendar = NLS_GetLocaleNumber(Ctx->Lcid, LOCALE_ICALENDARTYPE);
    }

    while (TRUE) /* loop through calendars */
    {
	do /* loop until there's no error */
	{
	    if (Ctx->CalType & CAL_RETURN_NUMBER)
		Ret = GetCalendarInfoW(Ctx->Lcid, Calendar, Ctx->CalType, NULL,
				       BufSz / sizeof(WCHAR), (LPDWORD)Buf);
	    else if (Ctx->Unicode)
		Ret = GetCalendarInfoW(Ctx->Lcid, Calendar, Ctx->CalType, Buf,
				       BufSz / sizeof(WCHAR), NULL);
	    else
		Ret = GetCalendarInfoA(Ctx->Lcid, Calendar, Ctx->CalType, (CHAR *)Buf,
				       BufSz / sizeof(CHAR), NULL);

	    if (!Ret) {
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) { /* so resize it */
		    int NewSz;
		    if (Ctx->Unicode)
			NewSz = GetCalendarInfoW(Ctx->Lcid, Calendar, Ctx->CalType,
						 NULL, 0, NULL) *
				sizeof(WCHAR);
		    else
			NewSz = GetCalendarInfoA(Ctx->Lcid, Calendar, Ctx->CalType,
						 NULL, 0, NULL) *
				sizeof(CHAR);
		    if (BufSz >= NewSz) {
			ERR("Buffer resizing disorder: was %d, requested %d.\n", BufSz,
			    NewSz);
			goto cleanup;
		    }
		    BufSz = NewSz;
		    WARN("Buffer too small; resizing to %d bytes.\n", BufSz);
		    Buf = HeapReAlloc(GetProcessHeap(), 0, Buf, BufSz);
		    if (Buf == NULL)
			goto cleanup;
		} else
		    goto cleanup;
	    }
	} while (!Ret);

	/* Here we are. We pass the buffer to the correct version of
	 * the callback. Because it's not the same number of params,
	 * we must check for Ex, but we don't care about Unicode
	 * because the buffer is already in the correct format.
	 */
	switch (Ctx->type) {
	case CALLBACK_ENUMPROC:
	    Ret = Ctx->u.Callback(Buf);
	    break;
	case CALLBACK_ENUMPROCEX:
	    Ret = Ctx->u.CallbackEx(Buf, Calendar);
	    break;
	case CALLBACK_ENUMPROCEXEX:
	    Ret = Ctx->u.CallbackExEx(Buf, Calendar, NULL, Ctx->lParam);
	    break;
	default:;
	}

	if (!Ret) { /* the callback told to stop */
	    Ret = TRUE;
	    break;
	}

	if ((Iter == NULL) || (*Iter == 0)) /* no more calendars */
	    break;

	Calendar = 0;
	while ((*Iter >= '0') && (*Iter <= '9'))
	    Calendar = Calendar * 10 + *Iter++ - '0';

	if (*Iter++ != 0) {
	    SetLastError(ERROR_BADDB);
	    Ret = FALSE;
	    break;
	}
    }

cleanup:
    HeapFree(GetProcessHeap(), 0, Opt);
    HeapFree(GetProcessHeap(), 0, Buf);
    return Ret;
}

/******************************************************************************
 *		EnumCalendarInfoW	[KERNEL32.@]
 */
WINAPI BOOL EnumCalendarInfoW(CALINFO_ENUMPROCW Calinfoproc, LCID Locale, CALID Calendar,
			      CALTYPE Caltype)
{
    struct ENUM_CALENDAR_CONTEXT Ctxt;

    TRACE("(%p,0x%08x,0x%08x,0x%08x)\n", Calinfoproc, Locale, Calendar, Caltype);

    Ctxt.type = CALLBACK_ENUMPROC;
    Ctxt.u.Callback = Calinfoproc;
    Ctxt.Lcid = Locale;
    Ctxt.Calendar = Calendar;
    Ctxt.CalType = Caltype;
    Ctxt.lParam = 0;
    Ctxt.Unicode = TRUE;
    return NLS_EnumCalendarInfo(&Ctxt);
}

/******************************************************************************
 *		EnumCalendarInfoExA	[KERNEL32.@]
 */

/******************************************************************************
 *		EnumCalendarInfoExW	[KERNEL32.@]
 */
WINAPI BOOL EnumCalendarInfoExW(CALINFO_ENUMPROCEXW Calinfoproc, LCID Locale,
				CALID Calendar, CALTYPE Caltype)
{
    struct ENUM_CALENDAR_CONTEXT Ctxt;

    TRACE("(%p,0x%08x,0x%08x,0x%08x)\n", Calinfoproc, Locale, Calendar, Caltype);

    Ctxt.type = CALLBACK_ENUMPROCEX;
    Ctxt.u.CallbackEx = Calinfoproc;
    Ctxt.Lcid = Locale;
    Ctxt.Calendar = Calendar;
    Ctxt.CalType = Caltype;
    Ctxt.lParam = 0;
    Ctxt.Unicode = TRUE;
    return NLS_EnumCalendarInfo(&Ctxt);
}

/******************************************************************************
 *		EnumCalendarInfoExEx	[KERNEL32.@]
 */
WINAPI BOOL EnumCalendarInfoExEx(CALINFO_ENUMPROCEXEX Calinfoproc, LPCWSTR Locale,
				 CALID Calendar, LPCWSTR Reserved, CALTYPE Caltype,
				 LPARAM lParam)
{
    struct ENUM_CALENDAR_CONTEXT Ctxt;

    TRACE("(%p,%ws,0x%08x,%p,0x%08x,0x%zd)\n", Calinfoproc, Locale, Calendar,
	  Reserved, Caltype, lParam);

    Ctxt.type = CALLBACK_ENUMPROCEXEX;
    Ctxt.u.CallbackExEx = Calinfoproc;
    Ctxt.Lcid = LocaleNameToLCID(Locale, 0);
    Ctxt.Calendar = Calendar;
    Ctxt.CalType = Caltype;
    Ctxt.lParam = lParam;
    Ctxt.Unicode = TRUE;
    return NLS_EnumCalendarInfo(&Ctxt);
}

/*********************************************************************
 *	GetCalendarInfoW				(KERNEL32.@)
 *
 */
WINAPI int GetCalendarInfoW(LCID Locale, CALID Calendar, CALTYPE CalType,
			    LPWSTR lpCalData, int cchData, LPDWORD lpValue)
{
    static const LCTYPE CaltypeLctypeMap[] = {
	0, /* not used */
	0, /* CAL_ICALINTVALUE */
	0, /* CAL_SCALNAME */
	0, /* CAL_IYEAROFFSETRANGE */
	0, /* CAL_SERASTRING */
	LOCALE_SSHORTDATE,
	LOCALE_SLONGDATE,
	LOCALE_SDAYNAME1,
	LOCALE_SDAYNAME2,
	LOCALE_SDAYNAME3,
	LOCALE_SDAYNAME4,
	LOCALE_SDAYNAME5,
	LOCALE_SDAYNAME6,
	LOCALE_SDAYNAME7,
	LOCALE_SABBREVDAYNAME1,
	LOCALE_SABBREVDAYNAME2,
	LOCALE_SABBREVDAYNAME3,
	LOCALE_SABBREVDAYNAME4,
	LOCALE_SABBREVDAYNAME5,
	LOCALE_SABBREVDAYNAME6,
	LOCALE_SABBREVDAYNAME7,
	LOCALE_SMONTHNAME1,
	LOCALE_SMONTHNAME2,
	LOCALE_SMONTHNAME3,
	LOCALE_SMONTHNAME4,
	LOCALE_SMONTHNAME5,
	LOCALE_SMONTHNAME6,
	LOCALE_SMONTHNAME7,
	LOCALE_SMONTHNAME8,
	LOCALE_SMONTHNAME9,
	LOCALE_SMONTHNAME10,
	LOCALE_SMONTHNAME11,
	LOCALE_SMONTHNAME12,
	LOCALE_SMONTHNAME13,
	LOCALE_SABBREVMONTHNAME1,
	LOCALE_SABBREVMONTHNAME2,
	LOCALE_SABBREVMONTHNAME3,
	LOCALE_SABBREVMONTHNAME4,
	LOCALE_SABBREVMONTHNAME5,
	LOCALE_SABBREVMONTHNAME6,
	LOCALE_SABBREVMONTHNAME7,
	LOCALE_SABBREVMONTHNAME8,
	LOCALE_SABBREVMONTHNAME9,
	LOCALE_SABBREVMONTHNAME10,
	LOCALE_SABBREVMONTHNAME11,
	LOCALE_SABBREVMONTHNAME12,
	LOCALE_SABBREVMONTHNAME13,
	LOCALE_SYEARMONTH,
	0, /* CAL_ITWODIGITYEARMAX */
	LOCALE_SSHORTESTDAYNAME1,
	LOCALE_SSHORTESTDAYNAME2,
	LOCALE_SSHORTESTDAYNAME3,
	LOCALE_SSHORTESTDAYNAME4,
	LOCALE_SSHORTESTDAYNAME5,
	LOCALE_SSHORTESTDAYNAME6,
	LOCALE_SSHORTESTDAYNAME7,
	LOCALE_SMONTHDAY,
	0, /* CAL_SABBREVERASTRING */
    };
    DWORD Localeflags = 0;
    CALTYPE Calinfo;

    if (CalType & CAL_NOUSEROVERRIDE)
	FIXME("flag CAL_NOUSEROVERRIDE used, not fully implemented\n");
    if (CalType & CAL_USE_CP_ACP)
	FIXME("flag CAL_USE_CP_ACP used, not fully implemented\n");

    if (CalType & CAL_RETURN_NUMBER) {
	if (!lpValue) {
	    SetLastError(ERROR_INVALID_PARAMETER);
	    return 0;
	}
	if (lpCalData != NULL)
	    WARN("lpCalData not NULL (%p) when it should!\n", lpCalData);
	if (cchData != 0)
	    WARN("cchData not 0 (%d) when it should!\n", cchData);
    } else {
	if (lpValue != NULL)
	    WARN("lpValue not NULL (%p) when it should!\n", lpValue);
    }

    /* FIXME: No verification is made yet wrt Locale
     * for the CALTYPES not requiring GetLocaleInfoA */

    Calinfo = CalType & 0xffff;

    if (CalType & LOCALE_RETURN_GENITIVE_NAMES)
	Localeflags |= LOCALE_RETURN_GENITIVE_NAMES;

    switch (Calinfo) {
    case CAL_ICALINTVALUE:
	if (IS_LCID_JAPANESE(Locale)) {
	    if (CalType & CAL_RETURN_NUMBER) {
		*lpValue = CAL_JAPAN;
		return sizeof(DWORD) / sizeof(WCHAR);
	    } else {
		static const WCHAR FmtW[] = { '%', 'u', 0 };
		WCHAR Buffer[10];
		int Ret = snprintfW(Buffer, 10, FmtW, CAL_JAPAN) + 1;
		if (!lpCalData)
		    return Ret;
		if (Ret <= cchData) {
		    wcscpy_s(lpCalData, cchData, Buffer);
		    return Ret;
		}
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	    }
	}
	if (CalType & CAL_RETURN_NUMBER)
	    return GetLocaleInfoW(Locale, LOCALE_RETURN_NUMBER | LOCALE_ICALENDARTYPE,
				  (LPWSTR)lpValue, 2);
	return GetLocaleInfoW(Locale, LOCALE_ICALENDARTYPE, lpCalData, cchData);
    case CAL_SCALNAME:
	if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN) {
	    // Wareki
	    lpCalData[0] = 0x548C;
	    lpCalData[1] = 0x66A6;
	    lpCalData[2] = 0;
	    return 3;
	}
	FIXME("Unimplemented caltype %d\n", Calinfo);
	if (lpCalData)
	    *lpCalData = 0;
	return 1;
    case CAL_IYEAROFFSETRANGE:
	if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN) {
	    PCJAPANESE_ERA pEra = JapaneseEra_Find(NULL);
	    if (pEra) {
		if (CalType & CAL_RETURN_NUMBER) {
		    *lpValue = pEra->wYear;
		    return sizeof(DWORD) / sizeof(WCHAR);
		} else {
		    static const WCHAR FmtW[] = { '%', 'u', 0 };
		    WCHAR Buffer[10];
		    int Ret = snprintfW(Buffer, 10, FmtW, pEra->wYear) + 1;
		    if (!lpCalData)
			return Ret;
		    if (Ret <= cchData) {
			wcscpy_s(lpCalData, cchData, Buffer);
			return Ret;
		    }
		    SetLastError(ERROR_INSUFFICIENT_BUFFER);
		    return 0;
		}
	    } else {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	    }
	}
	FIXME("Unimplemented caltype %d\n", Calinfo);
	return 0;
    case CAL_SERASTRING:
	if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN) {
	    PCJAPANESE_ERA pEra = JapaneseEra_Find(NULL);
	    if (pEra) {
		RtlStringCchCopyW(lpCalData, cchData, pEra->szEraName);
		return strlenW(lpCalData) + 1;
	    } else {
		SetLastError(ERROR_INVALID_PARAMETER);
		return 0;
	    }
	}
	FIXME("Unimplemented caltype %d\n", Calinfo);
	return 0;
    case CAL_SSHORTDATE:
    case CAL_SLONGDATE:
    case CAL_SDAYNAME1:
    case CAL_SDAYNAME2:
    case CAL_SDAYNAME3:
    case CAL_SDAYNAME4:
    case CAL_SDAYNAME5:
    case CAL_SDAYNAME6:
    case CAL_SDAYNAME7:
    case CAL_SABBREVDAYNAME1:
    case CAL_SABBREVDAYNAME2:
    case CAL_SABBREVDAYNAME3:
    case CAL_SABBREVDAYNAME4:
    case CAL_SABBREVDAYNAME5:
    case CAL_SABBREVDAYNAME6:
    case CAL_SABBREVDAYNAME7:
    case CAL_SMONTHNAME1:
    case CAL_SMONTHNAME2:
    case CAL_SMONTHNAME3:
    case CAL_SMONTHNAME4:
    case CAL_SMONTHNAME5:
    case CAL_SMONTHNAME6:
    case CAL_SMONTHNAME7:
    case CAL_SMONTHNAME8:
    case CAL_SMONTHNAME9:
    case CAL_SMONTHNAME10:
    case CAL_SMONTHNAME11:
    case CAL_SMONTHNAME12:
    case CAL_SMONTHNAME13:
    case CAL_SABBREVMONTHNAME1:
    case CAL_SABBREVMONTHNAME2:
    case CAL_SABBREVMONTHNAME3:
    case CAL_SABBREVMONTHNAME4:
    case CAL_SABBREVMONTHNAME5:
    case CAL_SABBREVMONTHNAME6:
    case CAL_SABBREVMONTHNAME7:
    case CAL_SABBREVMONTHNAME8:
    case CAL_SABBREVMONTHNAME9:
    case CAL_SABBREVMONTHNAME10:
    case CAL_SABBREVMONTHNAME11:
    case CAL_SABBREVMONTHNAME12:
    case CAL_SABBREVMONTHNAME13:
    case CAL_SYEARMONTH:
	return GetLocaleInfoW(Locale, CaltypeLctypeMap[Calinfo] | Localeflags,
			      lpCalData, cchData);
    case CAL_ITWODIGITYEARMAX:
	if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN) {
	    if (CalType & CAL_RETURN_NUMBER) {
		*lpValue = JAPANESE_MAX_TWODIGITYEAR;
		return sizeof(DWORD) / sizeof(WCHAR);
	    } else {
		static const WCHAR FmtW[] = { '%', 'u', 0 };
		WCHAR Buffer[10];
		int Ret = snprintfW(Buffer, 10, FmtW, JAPANESE_MAX_TWODIGITYEAR) + 1;
		if (!lpCalData)
		    return Ret;
		if (Ret <= cchData) {
		    wcscpy_s(lpCalData, cchData, Buffer);
		    return Ret;
		}
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	    }
	}
	if (CalType & CAL_RETURN_NUMBER) {
	    *lpValue = CALINFO_MAX_YEAR;
	    return sizeof(DWORD) / sizeof(WCHAR);
	} else {
	    static const WCHAR FmtW[] = { '%', 'u', 0 };
	    WCHAR Buffer[10];
	    int Ret = snprintfW(Buffer, 10, FmtW, CALINFO_MAX_YEAR) + 1;
	    if (!lpCalData)
		return Ret;
	    if (Ret <= cchData) {
		wcscpy_s(lpCalData, cchData, Buffer);
		return Ret;
	    }
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	    return 0;
	}
	break;
    case CAL_SABBREVERASTRING:
	if (IS_LCID_JAPANESE(Locale) && Calendar == CAL_JAPAN) {
	    PCJAPANESE_ERA pEra = JapaneseEra_Find(NULL);
	    if (pEra) {
		RtlStringCchCopyW(lpCalData, cchData, pEra->szEraAbbrev);
		return strlenW(lpCalData) + 1;
	    }
	}
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    default:
	FIXME("Unknown caltype %d\n", Calinfo);
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }
    return 0;
}

/*********************************************************************
 *	GetCalendarInfoEx				(KERNEL32.@)
 */
WINAPI int GetCalendarInfoEx(LPCWSTR Locale, CALID Calendar, LPCWSTR lpReserved,
			     CALTYPE Caltype, LPWSTR Data, int Len, DWORD *Value)
{
    static int Once;

    LCID Lcid = LocaleNameToLCID(Locale, 0);
    if (!Once++)
	FIXME("(%ws, %d, %p, 0x%08x, %p, %d, %p): semi-stub\n", Locale,
	      Calendar, lpReserved, Caltype, Data, Len, Value);
    return GetCalendarInfoW(Lcid, Calendar, Caltype, Data, Len, Value);
}

/*********************************************************************
 *	SetCalendarInfoW				(KERNEL32.@)
 *
 *
 */
WINAPI int SetCalendarInfoW(LCID Locale, CALID Calendar, CALTYPE CalType,
			    LPCWSTR lpCalData)
{
    FIXME("(%08x,%08x,%08x,%ws): stub\n", Locale, Calendar, CalType,
	  lpCalData);
    return 0;
}
