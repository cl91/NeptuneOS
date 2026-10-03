/*
 * Locale support
 *
 * Copyright 1995 Martin von Loewis
 * Copyright 1998 David Lee Lambert
 * Copyright 2000 Julio César Gázquez
 * Copyright 2002 Alexandre Julliard for CodeWeavers
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
#include "wine_cptable.h"
DEBUG_CHANNEL(nls);

#include "lcformat_private.h"
#include "japanese.h"

WINAPI INT CompareStringEx(LPCWSTR Locale, DWORD Flags, LPCWSTR Str1, INT Len1,
			   LPCWSTR Str2, INT Len2, LPNLSVERSIONINFO Version,
			   LPVOID Reserved, LPARAM lParam);

extern int wine_fold_string(int Flags, const WCHAR *Src, int Srclen, WCHAR *Dst,
			    int Dstlen);
extern int wine_get_sortkey(int Flags, const WCHAR *Src, int Srclen, char *Dst,
			    int Dstlen);
extern int wine_compare_string(int Flags, const WCHAR *Str1, int Len1, const WCHAR *Str2,
			       int Len2);
extern UINT GetLocalisedText(IN UINT uID, IN LPWSTR LpszDest, IN UINT cchDest,
			     IN LANGID Lang);
#define NLSRC_OFFSET 5000 /* FIXME */

extern HMODULE Kernel32Handle;

#define LOCALE_LOCALEINFOFLAGSMASK (LOCALE_NOUSEROVERRIDE|LOCALE_USE_CP_ACP|\
                                    LOCALE_RETURN_NUMBER|LOCALE_RETURN_GENITIVE_NAMES)
#define MB_FLAGSMASK (MB_PRECOMPOSED|MB_COMPOSITE|MB_USEGLYPHCHARS|MB_ERR_INVALID_CHARS)
#define WC_FLAGSMASK (WC_DISCARDNS|WC_SEPCHARS|WC_DEFAULTCHAR|WC_ERR_INVALID_CHARS|\
                      WC_COMPOSITECHECK|WC_NO_BEST_FIT_CHARS)

static const WCHAR szLocaleKeyName[] = {
    '\\','R','e','g','i','s','t','r','y','\\','M','a','c','h','i','n','e','\\','S','y','s','t','e','m','\\',
    'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
    'C','o','n','t','r','o','l','\\','N','l','s','\\','L','o','c','a','l','e',0
};

static const WCHAR szLangGroupsKeyName[] = {
    '\\','R','e','g','i','s','t','r','y','\\','M','a','c','h','i','n','e','\\','S','y','s','t','e','m','\\',
    'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
    'C','o','n','t','r','o','l','\\','N','l','s','\\',
    'L','a','n','g','u','a','g','e',' ','G','r','o','u','p','s',0
};

struct LOCALE_NAME {
    WCHAR  WinName[128];   /* Windows name ("en-US") */
    WCHAR  Lang[128];       /* language ("en") (note: buffer contains the other strings too) */
    WCHAR *Country;         /* country ("US") */
    WCHAR *Charset;         /* charset ("UTF-8") for Unix format only */
    WCHAR *Script;          /* script ("Latn") for Windows format only */
    WCHAR *Modifier;        /* modifier or sort order */
    LCID   Lcid;            /* corresponding LCID */
    int    Matches;         /* number of elements matching LCID (0..4) */
    UINT   Codepage;        /* codepage corresponding to charset */
};

/* locale ids corresponding to the various Unix locale parameters */
static LCID lcid_LC_COLLATE;
static LCID lcid_LC_CTYPE;
static LCID lcid_LC_MONETARY;
static LCID lcid_LC_NUMERIC;
static LCID lcid_LC_TIME;
static LCID lcid_LC_PAPER;
static LCID lcid_LC_MEASUREMENT;
static LCID lcid_LC_TELEPHONE;

static const WCHAR iCalendarTypeW[] = {'i','C','a','l','e','n','d','a','r','T','y','p','e',0};
static const WCHAR iCountryW[] = {'i','C','o','u','n','t','r','y',0};
static const WCHAR iCurrDigitsW[] = {'i','C','u','r','r','D','i','g','i','t','s',0};
static const WCHAR iCurrencyW[] = {'i','C','u','r','r','e','n','c','y',0};
static const WCHAR iDateW[] = {'i','D','a','t','e',0};
static const WCHAR iDigitsW[] = {'i','D','i','g','i','t','s',0};
static const WCHAR iFirstDayOfWeekW[] = {'i','F','i','r','s','t','D','a','y','O','f','W','e','e','k',0};
static const WCHAR iFirstWeekOfYearW[] = {'i','F','i','r','s','t','W','e','e','k','O','f','Y','e','a','r',0};
static const WCHAR iLDateW[] = {'i','L','D','a','t','e',0};
static const WCHAR iLZeroW[] = {'i','L','Z','e','r','o',0};
static const WCHAR iMeasureW[] = {'i','M','e','a','s','u','r','e',0};
static const WCHAR iNegCurrW[] = {'i','N','e','g','C','u','r','r',0};
static const WCHAR iNegNumberW[] = {'i','N','e','g','N','u','m','b','e','r',0};
static const WCHAR iPaperSizeW[] = {'i','P','a','p','e','r','S','i','z','e',0};
static const WCHAR iTLZeroW[] = {'i','T','L','Z','e','r','o',0};
static const WCHAR iTimePrefixW[] = {'i','T','i','m','e','P','r','e','f','i','x',0};
static const WCHAR iTimeW[] = {'i','T','i','m','e',0};
static const WCHAR s1159W[] = {'s','1','1','5','9',0};
static const WCHAR s2359W[] = {'s','2','3','5','9',0};
static const WCHAR sCountryW[] = {'s','C','o','u','n','t','r','y',0};
static const WCHAR sCurrencyW[] = {'s','C','u','r','r','e','n','c','y',0};
static const WCHAR sDateW[] = {'s','D','a','t','e',0};
static const WCHAR sDecimalW[] = {'s','D','e','c','i','m','a','l',0};
static const WCHAR sGroupingW[] = {'s','G','r','o','u','p','i','n','g',0};
static const WCHAR sLanguageW[] = {'s','L','a','n','g','u','a','g','e',0};
static const WCHAR sListW[] = {'s','L','i','s','t',0};
static const WCHAR sLongDateW[] = {'s','L','o','n','g','D','a','t','e',0};
static const WCHAR sMonDecimalSepW[] = {'s','M','o','n','D','e','c','i','m','a','l','S','e','p',0};
static const WCHAR sMonGroupingW[] = {'s','M','o','n','G','r','o','u','p','i','n','g',0};
static const WCHAR sMonThousandSepW[] = {'s','M','o','n','T','h','o','u','s','a','n','d','S','e','p',0};
static const WCHAR sNativeDigitsW[] = {'s','N','a','t','i','v','e','D','i','g','i','t','s',0};
static const WCHAR sNegativeSignW[] = {'s','N','e','g','a','t','i','v','e','S','i','g','n',0};
static const WCHAR sPositiveSignW[] = {'s','P','o','s','i','t','i','v','e','S','i','g','n',0};
static const WCHAR sShortDateW[] = {'s','S','h','o','r','t','D','a','t','e',0};
static const WCHAR sThousandW[] = {'s','T','h','o','u','s','a','n','d',0};
static const WCHAR sTimeFormatW[] = {'s','T','i','m','e','F','o','r','m','a','t',0};
static const WCHAR sTimeW[] = {'s','T','i','m','e',0};
static const WCHAR sYearMonthW[] = {'s','Y','e','a','r','M','o','n','t','h',0};
static const WCHAR NumShapeW[] = {'N','u','m','s','h','a','p','e',0};

static struct REGISTRY_VALUE {
    DWORD           LcType;
    const WCHAR    *Name;
    WCHAR          *CachedValue;
} RegistryValues[] = {
    { LOCALE_ICALENDARTYPE, iCalendarTypeW },
    { LOCALE_ICURRDIGITS, iCurrDigitsW },
    { LOCALE_ICURRENCY, iCurrencyW },
    { LOCALE_IDIGITS, iDigitsW },
    { LOCALE_IFIRSTDAYOFWEEK, iFirstDayOfWeekW },
    { LOCALE_IFIRSTWEEKOFYEAR, iFirstWeekOfYearW },
    { LOCALE_ILZERO, iLZeroW },
    { LOCALE_IMEASURE, iMeasureW },
    { LOCALE_INEGCURR, iNegCurrW },
    { LOCALE_INEGNUMBER, iNegNumberW },
    { LOCALE_IPAPERSIZE, iPaperSizeW },
    { LOCALE_ITIME, iTimeW },
    { LOCALE_S1159, s1159W },
    { LOCALE_S2359, s2359W },
    { LOCALE_SCURRENCY, sCurrencyW },
    { LOCALE_SDATE, sDateW },
    { LOCALE_SDECIMAL, sDecimalW },
    { LOCALE_SGROUPING, sGroupingW },
    { LOCALE_SLIST, sListW },
    { LOCALE_SLONGDATE, sLongDateW },
    { LOCALE_SMONDECIMALSEP, sMonDecimalSepW },
    { LOCALE_SMONGROUPING, sMonGroupingW },
    { LOCALE_SMONTHOUSANDSEP, sMonThousandSepW },
    { LOCALE_SNEGATIVESIGN, sNegativeSignW },
    { LOCALE_SPOSITIVESIGN, sPositiveSignW },
    { LOCALE_SSHORTDATE, sShortDateW },
    { LOCALE_STHOUSAND, sThousandW },
    { LOCALE_STIME, sTimeW },
    { LOCALE_STIMEFORMAT, sTimeFormatW },
    { LOCALE_SYEARMONTH, sYearMonthW },
    /* The following are not listed under MSDN as supported,
     * but seem to be used and also stored in the registry.
     */
    { LOCALE_ICOUNTRY, iCountryW },
    { LOCALE_IDATE, iDateW },
    { LOCALE_ILDATE, iLDateW },
    { LOCALE_ITLZERO, iTLZeroW },
    { LOCALE_SCOUNTRY, sCountryW },
    { LOCALE_SABBREVLANGNAME, sLanguageW },
    /* The following are used in XP and later */
    { LOCALE_IDIGITSUBSTITUTION, NumShapeW },
    { LOCALE_SNATIVEDIGITS, sNativeDigitsW },
    { LOCALE_ITIMEMARKPOSN, iTimePrefixW }
};

static RTL_CRITICAL_SECTION CacheSection = { NULL, -1, 0, 0, 0, 0 };

/***********************************************************************
 *		GetLcidCodepage
 *
 * Retrieve the ANSI codepage for a given locale.
 */
static inline UINT GetLcidCodepage(LCID Lcid)
{
    UINT Ret;
    if (!GetLocaleInfoW(Lcid, LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
			(WCHAR *)&Ret, sizeof(Ret) / sizeof(WCHAR)))
	Ret = 0;
    return Ret;
}

static LANGID GetDefaultSublang(LANGID Lang)
{
    switch (Lang) {
    case MAKELANGID(LANG_SPANISH, SUBLANG_NEUTRAL):
	return MAKELANGID(LANG_SPANISH, SUBLANG_SPANISH_MODERN);
    case MAKELANGID(LANG_CHINESE, SUBLANG_NEUTRAL):
	return MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED);
    case MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SINGAPORE):
	return MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED);
    case MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_TRADITIONAL):
    case MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_MACAU):
	return MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_HONGKONG);
    }
    if (SUBLANGID(Lang) == SUBLANG_NEUTRAL)
	Lang = MAKELANGID(PRIMARYLANGID(Lang), SUBLANG_DEFAULT);
    return Lang;
}

/***********************************************************************
 *           ConvertDefaultLcid
 *
 * Get the default LCID to use for a given lctype in GetLocaleInfo.
 */
static LCID ConvertDefaultLcid(LCID Lcid, LCTYPE Lctype)
{
    if (Lcid == LOCALE_SYSTEM_DEFAULT || Lcid == LOCALE_USER_DEFAULT ||
	Lcid == LOCALE_NEUTRAL) {
	LCID DefaultId = 0;

	switch (Lctype & 0xffff) {
	case LOCALE_SSORTNAME:
	    DefaultId = lcid_LC_COLLATE;
	    break;

	case LOCALE_FONTSIGNATURE:
	case LOCALE_IDEFAULTANSICODEPAGE:
	case LOCALE_IDEFAULTCODEPAGE:
	case LOCALE_IDEFAULTEBCDICCODEPAGE:
	case LOCALE_IDEFAULTMACCODEPAGE:
	case LOCALE_IDEFAULTUNIXCODEPAGE:
	    DefaultId = lcid_LC_CTYPE;
	    break;

	case LOCALE_ICURRDIGITS:
	case LOCALE_ICURRENCY:
	case LOCALE_IINTLCURRDIGITS:
	case LOCALE_INEGCURR:
	case LOCALE_INEGSEPBYSPACE:
	case LOCALE_INEGSIGNPOSN:
	case LOCALE_INEGSYMPRECEDES:
	case LOCALE_IPOSSEPBYSPACE:
	case LOCALE_IPOSSIGNPOSN:
	case LOCALE_IPOSSYMPRECEDES:
	case LOCALE_SCURRENCY:
	case LOCALE_SINTLSYMBOL:
	case LOCALE_SMONDECIMALSEP:
	case LOCALE_SMONGROUPING:
	case LOCALE_SMONTHOUSANDSEP:
	case LOCALE_SNATIVECURRNAME:
	    DefaultId = lcid_LC_MONETARY;
	    break;

	case LOCALE_IDIGITS:
	case LOCALE_IDIGITSUBSTITUTION:
	case LOCALE_ILZERO:
	case LOCALE_INEGNUMBER:
	case LOCALE_SDECIMAL:
	case LOCALE_SGROUPING:
	// case LOCALE_SNAN:
	case LOCALE_SNATIVEDIGITS:
	case LOCALE_SNEGATIVESIGN:
	// case LOCALE_SNEGINFINITY:
	// case LOCALE_SPOSINFINITY:
	case LOCALE_SPOSITIVESIGN:
	case LOCALE_STHOUSAND:
	    DefaultId = lcid_LC_NUMERIC;
	    break;

	case LOCALE_ICALENDARTYPE:
	case LOCALE_ICENTURY:
	case LOCALE_IDATE:
	case LOCALE_IDAYLZERO:
	case LOCALE_IFIRSTDAYOFWEEK:
	case LOCALE_IFIRSTWEEKOFYEAR:
	case LOCALE_ILDATE:
	case LOCALE_IMONLZERO:
	case LOCALE_IOPTIONALCALENDAR:
	case LOCALE_ITIME:
	case LOCALE_ITIMEMARKPOSN:
	case LOCALE_ITLZERO:
	case LOCALE_S1159:
	case LOCALE_S2359:
	case LOCALE_SABBREVDAYNAME1:
	case LOCALE_SABBREVDAYNAME2:
	case LOCALE_SABBREVDAYNAME3:
	case LOCALE_SABBREVDAYNAME4:
	case LOCALE_SABBREVDAYNAME5:
	case LOCALE_SABBREVDAYNAME6:
	case LOCALE_SABBREVDAYNAME7:
	case LOCALE_SABBREVMONTHNAME1:
	case LOCALE_SABBREVMONTHNAME2:
	case LOCALE_SABBREVMONTHNAME3:
	case LOCALE_SABBREVMONTHNAME4:
	case LOCALE_SABBREVMONTHNAME5:
	case LOCALE_SABBREVMONTHNAME6:
	case LOCALE_SABBREVMONTHNAME7:
	case LOCALE_SABBREVMONTHNAME8:
	case LOCALE_SABBREVMONTHNAME9:
	case LOCALE_SABBREVMONTHNAME10:
	case LOCALE_SABBREVMONTHNAME11:
	case LOCALE_SABBREVMONTHNAME12:
	case LOCALE_SABBREVMONTHNAME13:
	case LOCALE_SDATE:
	case LOCALE_SDAYNAME1:
	case LOCALE_SDAYNAME2:
	case LOCALE_SDAYNAME3:
	case LOCALE_SDAYNAME4:
	case LOCALE_SDAYNAME5:
	case LOCALE_SDAYNAME6:
	case LOCALE_SDAYNAME7:
	// case LOCALE_SDURATION:
	case LOCALE_SLONGDATE:
	case LOCALE_SMONTHNAME1:
	case LOCALE_SMONTHNAME2:
	case LOCALE_SMONTHNAME3:
	case LOCALE_SMONTHNAME4:
	case LOCALE_SMONTHNAME5:
	case LOCALE_SMONTHNAME6:
	case LOCALE_SMONTHNAME7:
	case LOCALE_SMONTHNAME8:
	case LOCALE_SMONTHNAME9:
	case LOCALE_SMONTHNAME10:
	case LOCALE_SMONTHNAME11:
	case LOCALE_SMONTHNAME12:
	case LOCALE_SMONTHNAME13:
	case LOCALE_SSHORTDATE:
	// case LOCALE_SSHORTESTDAYNAME1:
	// case LOCALE_SSHORTESTDAYNAME2:
	// case LOCALE_SSHORTESTDAYNAME3:
	// case LOCALE_SSHORTESTDAYNAME4:
	// case LOCALE_SSHORTESTDAYNAME5:
	// case LOCALE_SSHORTESTDAYNAME6:
	// case LOCALE_SSHORTESTDAYNAME7:
	case LOCALE_STIME:
	case LOCALE_STIMEFORMAT:
	case LOCALE_SYEARMONTH:
	    DefaultId = lcid_LC_TIME;
	    break;

	case LOCALE_IPAPERSIZE:
	    DefaultId = lcid_LC_PAPER;
	    break;

	case LOCALE_IMEASURE:
	    DefaultId = lcid_LC_MEASUREMENT;
	    break;

	case LOCALE_ICOUNTRY:
	    DefaultId = lcid_LC_TELEPHONE;
	    break;
	}
	if (DefaultId)
	    Lcid = DefaultId;
    }
    return ConvertDefaultLocale(Lcid);
}

/***********************************************************************
 *           IsGenitiveNameSupported
 *
 * Determine could LCTYPE basically support genitive name form or not.
 */
static BOOL IsGenitiveNameSupported(LCTYPE Lctype)
{
    switch (Lctype & 0xffff) {
    case LOCALE_SMONTHNAME1:
    case LOCALE_SMONTHNAME2:
    case LOCALE_SMONTHNAME3:
    case LOCALE_SMONTHNAME4:
    case LOCALE_SMONTHNAME5:
    case LOCALE_SMONTHNAME6:
    case LOCALE_SMONTHNAME7:
    case LOCALE_SMONTHNAME8:
    case LOCALE_SMONTHNAME9:
    case LOCALE_SMONTHNAME10:
    case LOCALE_SMONTHNAME11:
    case LOCALE_SMONTHNAME12:
    case LOCALE_SMONTHNAME13:
	return TRUE;
    default:
	return FALSE;
    }
}

/***********************************************************************
 *		CreateRegistryKey
 *
 * Create the Control Panel\\International registry key.
 */
static inline HANDLE CreateRegistryKey(void)
{
    static const WCHAR CplW[] = {'C','o','n','t','r','o','l',' ','P','a','n','e','l',0};
    static const WCHAR IntlW[] = {'I','n','t','e','r','n','a','t','i','o','n','a','l',0};
    OBJECT_ATTRIBUTES Attr;
    UNICODE_STRING NameW;
    HANDLE CplKey, hKey = 0;

    if (RtlOpenCurrentUser(KEY_ALL_ACCESS, &hKey) != STATUS_SUCCESS)
	return 0;

    Attr.Length = sizeof(Attr);
    Attr.RootDirectory = hKey;
    Attr.ObjectName = &NameW;
    Attr.Attributes = 0;
    Attr.SecurityDescriptor = NULL;
    Attr.SecurityQualityOfService = NULL;
    RtlInitUnicodeString(&NameW, CplW);

    if (!NtCreateKey(&CplKey, KEY_ALL_ACCESS, &Attr, 0, NULL, 0, NULL)) {
	NtClose(Attr.RootDirectory);
	Attr.RootDirectory = CplKey;
	RtlInitUnicodeString(&NameW, IntlW);
	if (NtCreateKey(&hKey, KEY_ALL_ACCESS, &Attr, 0, NULL, 0, NULL))
	    hKey = 0;
    }
    NtClose(Attr.RootDirectory);
    return hKey;
}

/***********************************************************************
 *		GetUserDefaultLangID (KERNEL32.@)
 *
 * Get the default language Id for the current user.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  The current LANGID of the default language for the current user.
 */
WINAPI LANGID GetUserDefaultLangID(void)
{
    return LANGIDFROMLCID(GetUserDefaultLCID());
}

/***********************************************************************
 *		GetSystemDefaultLangID (KERNEL32.@)
 *
 * Get the default language Id for the system.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  The current LANGID of the default language for the system.
 */
WINAPI LANGID GetSystemDefaultLangID(void)
{
    return LANGIDFROMLCID(GetSystemDefaultLCID());
}

/***********************************************************************
 *		GetUserDefaultLCID (KERNEL32.@)
 *
 * Get the default locale Id for the current user.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  The current LCID of the default locale for the current user.
 */
WINAPI LCID GetUserDefaultLCID(void)
{
    LCID Lcid;
    NtQueryDefaultLocale(TRUE, &Lcid);
    return Lcid;
}

/***********************************************************************
 *		GetSystemDefaultLCID (KERNEL32.@)
 *
 * Get the default locale Id for the system.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  The current LCID of the default locale for the system.
 */
WINAPI LCID GetSystemDefaultLCID(void)
{
    LCID Lcid;
    NtQueryDefaultLocale(FALSE, &Lcid);
    return Lcid;
}

/***********************************************************************
 *		GetUserDefaultUILanguage (KERNEL32.@)
 *
 * Get the default user interface language Id for the current user.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  The current LANGID of the default UI language for the current user.
 */
WINAPI LANGID GetUserDefaultUILanguage(void)
{
    LANGID Lang;
    NtQueryDefaultUILanguage(&Lang);
    return Lang;
}

/***********************************************************************
 *		GetSystemDefaultUILanguage (KERNEL32.@)
 *
 * Get the default user interface language Id for the system.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  The current LANGID of the default UI language for the system. This is
 *  typically the same language used during the installation process.
 */
WINAPI LANGID GetSystemDefaultUILanguage(void)
{
    LANGID Lang;
    NtQueryInstallUILanguage(&Lang);
    return Lang;
}

/******************************************************************************
 *		get_locale_registry_value
 *
 * Gets the registry value name and cache for a given lctype.
 */
static struct REGISTRY_VALUE *GetLocaleRegistryValue(DWORD Lctype)
{
    int i;
    for (i = 0; i < sizeof(RegistryValues) / sizeof(RegistryValues[0]); i++)
	if (RegistryValues[i].LcType == Lctype)
	    return &RegistryValues[i];
    return NULL;
}

/******************************************************************************
 *		get_registry_locale_info
 *
 * Retrieve user-modified locale info from the registry.
 * Return length, 0 on error, -1 if not found.
 */
static INT GetRegistryLocaleInfo(struct REGISTRY_VALUE *RegistryValue, LPWSTR Buffer,
				    INT Len)
{
    DWORD Size;
    INT Ret;
    HANDLE hKey;
    NTSTATUS Status;
    UNICODE_STRING NameW;
    KEY_VALUE_PARTIAL_INFORMATION *Info;
    static const int InfoSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);

    RtlEnterCriticalSection(&CacheSection);

    if (!RegistryValue->CachedValue) {
	if (!(hKey = CreateRegistryKey())) {
	    RtlLeaveCriticalSection(&CacheSection);
	    return -1;
	}

	RtlInitUnicodeString(&NameW, RegistryValue->Name);
	Size = InfoSize + Len * sizeof(WCHAR);

	if (!(Info = HeapAlloc(GetProcessHeap(), 0, Size))) {
	    NtClose(hKey);
	    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	    RtlLeaveCriticalSection(&CacheSection);
	    return 0;
	}

	Status = NtQueryValueKey(hKey, &NameW, KeyValuePartialInformation, Info, Size,
				 &Size);

	/* try again with a bigger buffer when we have to return the correct size */
	if (Status == STATUS_BUFFER_OVERFLOW && !Buffer && Size > InfoSize) {
	    KEY_VALUE_PARTIAL_INFORMATION *NewInfo;
	    if ((NewInfo = HeapReAlloc(GetProcessHeap(), 0, Info, Size))) {
		Info = NewInfo;
		Status = NtQueryValueKey(hKey, &NameW, KeyValuePartialInformation, Info,
					 Size, &Size);
	    }
	}

	NtClose(hKey);

	if (!Status) {
	    INT Length = (Size - InfoSize) / sizeof(WCHAR);
	    LPWSTR CachedValue;

	    if (!Length || ((WCHAR *)&Info->Data)[Length - 1])
		Length++;

	    CachedValue = HeapAlloc(GetProcessHeap(), 0, Length * sizeof(WCHAR));

	    if (!CachedValue) {
		HeapFree(GetProcessHeap(), 0, Info);
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		RtlLeaveCriticalSection(&CacheSection);
		return 0;
	    }

	    memcpy(CachedValue, Info->Data, (Length - 1) * sizeof(WCHAR));
	    CachedValue[Length - 1] = 0;
	    HeapFree(GetProcessHeap(), 0, Info);
	    RegistryValue->CachedValue = CachedValue;
	} else {
	    if (Status == STATUS_BUFFER_OVERFLOW && !Buffer) {
		Ret = (Size - InfoSize) / sizeof(WCHAR);
	    } else if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
		Ret = -1;
	    } else {
		SetLastError(RtlNtStatusToDosError(Status));
		Ret = 0;
	    }
	    HeapFree(GetProcessHeap(), 0, Info);
	    RtlLeaveCriticalSection(&CacheSection);
	    return Ret;
	}
    }

    Ret = lstrlenW(RegistryValue->CachedValue) + 1;

    if (Buffer) {
	if (Ret > Len) {
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	    Ret = 0;
	} else {
	    lstrcpyW(Buffer, RegistryValue->CachedValue);
	}
    }

    RtlLeaveCriticalSection(&CacheSection);

    return Ret;
}

/******************************************************************************
 *		GetLocaleInfoA (KERNEL32.@)
 *
 * Get information about an aspect of a locale.
 *
 * PARAMS
 *  lcid   [I] LCID of the locale
 *  lctype [I] LCTYPE_ flags from "winnls.h"
 *  buffer [O] Destination for the information
 *  len    [I] Length of buffer in characters
 *
 * RETURNS
 *  Success: The size of the data requested. If buffer is non-NULL, it is filled
 *           with the information.
 *  Failure: 0. Use GetLastError() to determine the cause.
 *
 * NOTES
 *  - LOCALE_NEUTRAL is equal to LOCALE_SYSTEM_DEFAULT
 *  - The string returned is NUL terminated, except for LOCALE_FONTSIGNATURE,
 *    which is a bit string.
 */
WINAPI INT GetLocaleInfoA(LCID Lcid, LCTYPE Lctype, LPSTR Buffer, INT Len)
{
    WCHAR *BufferW;
    INT LenW, Ret;

    TRACE("(lcid=0x%x,lctype=0x%x,%p,%d)\n", lcid, lctype, buffer, len);

    if (Len < 0 || (Len && !Buffer)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }
    if (((Lctype & ~LOCALE_LOCALEINFOFLAGSMASK) == LOCALE_SSHORTTIME) ||
	(Lctype & LOCALE_RETURN_GENITIVE_NAMES)) {
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    if (!Len)
	Buffer = NULL;

    if (!(LenW = GetLocaleInfoW(Lcid, Lctype, NULL, 0)))
	return 0;

    if (!(BufferW = HeapAlloc(GetProcessHeap(), 0, LenW * sizeof(WCHAR)))) {
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return 0;
    }
    if ((Ret = GetLocaleInfoW(Lcid, Lctype, BufferW, LenW))) {
	if ((Lctype & LOCALE_RETURN_NUMBER) ||
	    ((Lctype & ~LOCALE_LOCALEINFOFLAGSMASK) == LOCALE_FONTSIGNATURE)) {
	    /* it's not an ASCII string, just bytes */
	    Ret *= sizeof(WCHAR);
	    if (Buffer) {
		if (Ret <= Len)
		    memcpy(Buffer, BufferW, Ret);
		else {
		    SetLastError(ERROR_INSUFFICIENT_BUFFER);
		    Ret = 0;
		}
	    }
	} else {
	    UINT Codepage = CP_ACP;
	    if (!(Lctype & LOCALE_USE_CP_ACP))
		Codepage = GetLcidCodepage(Lcid);
	    Ret = WideCharToMultiByte(Codepage, 0, BufferW, Ret, Buffer, Len, NULL, NULL);
	}
    }
    HeapFree(GetProcessHeap(), 0, BufferW);
    return Ret;
}

static int GetValueBaseByLctype(LCTYPE Lctype)
{
    return Lctype == LOCALE_ILANGUAGE || Lctype == LOCALE_IDEFAULTLANGUAGE ? 16 : 10;
}

/******************************************************************************
 *		GetLocaleInfoW (KERNEL32.@)
 *
 * See GetLocaleInfoA.
 */
WINAPI INT GetLocaleInfoW(LCID Lcid, LCTYPE Lctype, LPWSTR Buffer, INT Len)
{
    LANGID LangId;
    HRSRC Hrsrc;
    HGLOBAL Hmem;
    INT Ret;
    UINT Lcflags;
    const WCHAR *p;
    unsigned int i;

    if (Len < 0 || (Len && !Buffer)) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }
    if (Lctype & LOCALE_RETURN_GENITIVE_NAMES && !IsGenitiveNameSupported(Lctype)) {
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    if (!Len)
	Buffer = NULL;

    Lcid = ConvertDefaultLcid(Lcid, Lctype);

    Lcflags = Lctype & LOCALE_LOCALEINFOFLAGSMASK;
    Lctype &= 0xffff;

    TRACE("(lcid=0x%x,lctype=0x%x,%p,%d)\n", lcid, lctype, buffer, len);

    /* first check for overrides in the registry */

    if (!(Lcflags & LOCALE_NOUSEROVERRIDE) &&
	Lcid == ConvertDefaultLcid(LOCALE_USER_DEFAULT, Lctype)) {
	struct REGISTRY_VALUE *Value = GetLocaleRegistryValue(Lctype);

	if (Value) {
	    if (Lcflags & LOCALE_RETURN_NUMBER) {
		WCHAR Tmp[16];
		Ret = GetRegistryLocaleInfo(Value, Tmp, sizeof(Tmp) / sizeof(WCHAR));
		if (Ret > 0) {
		    WCHAR *End;
		    UINT Number = strtolW(Tmp, &End, GetValueBaseByLctype(Lctype));
		    if (*End) /* invalid number */
		    {
			SetLastError(ERROR_INVALID_FLAGS);
			return 0;
		    }
		    Ret = sizeof(UINT) / sizeof(WCHAR);
		    if (!Buffer)
			return Ret;
		    if (Ret > Len) {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return 0;
		    }
		    memcpy(Buffer, &Number, sizeof(Number));
		}
	    } else
		Ret = GetRegistryLocaleInfo(Value, Buffer, Len);

	    if (Ret != -1)
		return Ret;
	}
    }

    /* now load it from kernel resources */

    LangId = LANGIDFROMLCID(Lcid);

    /* replace SUBLANG_NEUTRAL by SUBLANG_DEFAULT */
    if (SUBLANGID(LangId) == SUBLANG_NEUTRAL)
	LangId = GetDefaultSublang(LangId);

    if (!(Hrsrc = FindResourceExW(Kernel32Handle, (LPWSTR)RT_STRING,
				  ULongToPtr((Lctype >> 4) + 1), LangId))) {
	SetLastError(ERROR_INVALID_FLAGS); /* no such lctype */
	return 0;
    }
    if (!(Hmem = LoadResource(Kernel32Handle, Hrsrc)))
	return 0;

    p = LockResource(Hmem);
    for (i = 0; i < (Lctype & 0x0f); i++)
	p += *p + 1;

    if (Lcflags & LOCALE_RETURN_NUMBER)
	Ret = sizeof(UINT) / sizeof(WCHAR);
    else if (IsGenitiveNameSupported(Lctype) && *p) {
	/* genitive form's stored after a null separator from a nominative */
	for (i = 1; i <= *p; i++)
	    if (!p[i])
		break;

	if (i <= *p && (Lcflags & LOCALE_RETURN_GENITIVE_NAMES)) {
	    Ret = *p - i + 1;
	    p += i;
	} else
	    Ret = i;
    } else
	Ret = (Lctype == LOCALE_FONTSIGNATURE) ? *p : *p + 1;

    if (!Buffer)
	return Ret;

    if (Ret > Len) {
	SetLastError(ERROR_INSUFFICIENT_BUFFER);
	return 0;
    }

    if (Lcflags & LOCALE_RETURN_NUMBER) {
	UINT Number;
	WCHAR *End, *Tmp = HeapAlloc(GetProcessHeap(), 0, (*p + 1) * sizeof(WCHAR));
	if (!Tmp)
	    return 0;
	memcpy(Tmp, p + 1, *p * sizeof(WCHAR));
	Tmp[*p] = 0;
	Number = strtolW(Tmp, &End, GetValueBaseByLctype(Lctype));
	if (!*End)
	    memcpy(Buffer, &Number, sizeof(Number));
	else /* invalid number */
	{
	    SetLastError(ERROR_INVALID_FLAGS);
	    Ret = 0;
	}
	HeapFree(GetProcessHeap(), 0, Tmp);

	TRACE("(lcid=0x%x,lctype=0x%x,%p,%d) returning number %d\n", lcid, lctype, buffer,
	      len, number);
    } else {
	memcpy(Buffer, p + 1, Ret * sizeof(WCHAR));
	if (Lctype != LOCALE_FONTSIGNATURE)
	    Buffer[Ret - 1] = 0;

	TRACE("(lcid=0x%x,lctype=0x%x,%p,%d) returning %d %s\n", lcid, lctype, buffer,
	      len, ret, debugstr_w(buffer));
    }
    return Ret;
}

/******************************************************************************
 *		SetLocaleInfoA	[KERNEL32.@]
 *
 * Set information about an aspect of a locale.
 *
 * PARAMS
 *  lcid   [I] LCID of the locale
 *  lctype [I] LCTYPE_ flags from "winnls.h"
 *  data   [I] Information to set
 *
 * RETURNS
 *  Success: TRUE. The information given will be returned by GetLocaleInfoA()
 *           whenever it is called without LOCALE_NOUSEROVERRIDE.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 *
 * NOTES
 *  - Values are only be set for the current user locale; the system locale
 *  settings cannot be changed.
 *  - Any settings changed by this call are lost when the locale is changed by
 *  the control panel (in Wine, this happens every time you change LANG).
 *  - The native implementation of this function does not check that lcid matches
 *  the current user locale, and simply sets the new values. Wine warns you in
 *  this case, but behaves the same.
 */
WINAPI BOOL SetLocaleInfoA(LCID Lcid, LCTYPE Lctype, LPCSTR Data)
{
    UINT Codepage = CP_ACP;
    WCHAR *StrW;
    DWORD Len;
    BOOL Ret;

    if (!(Lctype & LOCALE_USE_CP_ACP))
	Codepage = GetLcidCodepage(Lcid);

    if (!Data) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    Len = MultiByteToWideChar(Codepage, 0, Data, -1, NULL, 0);
    if (!(StrW = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR)))) {
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return FALSE;
    }
    MultiByteToWideChar(Codepage, 0, Data, -1, StrW, Len);
    Ret = SetLocaleInfoW(Lcid, Lctype, StrW);
    HeapFree(GetProcessHeap(), 0, StrW);
    return Ret;
}

/******************************************************************************
 *		SetLocaleInfoW	(KERNEL32.@)
 *
 * See SetLocaleInfoA.
 */
WINAPI BOOL SetLocaleInfoW(LCID Lcid, LCTYPE Lctype, LPCWSTR Data)
{
    struct REGISTRY_VALUE *Value;
    static const WCHAR IntlW[] = { 'i', 'n', 't', 'l', 0 };
    UNICODE_STRING ValueW;
    NTSTATUS Status;
    HANDLE hKey;

    Lctype &= 0xffff;
    Value = GetLocaleRegistryValue(Lctype);

    if (!Data || !Value) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if (Lctype == LOCALE_IDATE || Lctype == LOCALE_ILDATE) {
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    TRACE("setting %x (%s) to %s\n", lctype, debugstr_w(value->name), debugstr_w(data));

    /* FIXME: should check that data to set is sane */

    /* FIXME: profile functions should map to registry */
    WriteProfileStringW(IntlW, Value->Name, Data);

    if (!(hKey = CreateRegistryKey()))
	return FALSE;
    RtlInitUnicodeString(&ValueW, Value->Name);
    Status = NtSetValueKey(hKey, &ValueW, 0, REG_SZ, (PVOID)Data,
			   (strlenW(Data) + 1) * sizeof(WCHAR));

    RtlEnterCriticalSection(&CacheSection);
    HeapFree(GetProcessHeap(), 0, Value->CachedValue);
    Value->CachedValue = NULL;
    RtlLeaveCriticalSection(&CacheSection);

    if (Lctype == LOCALE_SSHORTDATE || Lctype == LOCALE_SLONGDATE) {
	/* Set I-value from S value */
	WCHAR *lpD, *lpM, *lpY;
	WCHAR szBuff[2];

	lpD = strrchrW(Data, 'd');
	lpM = strrchrW(Data, 'M');
	lpY = strrchrW(Data, 'y');

	if (lpD <= lpM) {
	    szBuff[0] = '1'; /* D-M-Y */
	} else {
	    if (lpY <= lpM)
		szBuff[0] = '2'; /* Y-M-D */
	    else
		szBuff[0] = '0'; /* M-D-Y */
	}

	szBuff[1] = '\0';

	if (Lctype == LOCALE_SSHORTDATE)
	    Lctype = LOCALE_IDATE;
	else
	    Lctype = LOCALE_ILDATE;

	Value = GetLocaleRegistryValue(Lctype);

	WriteProfileStringW(IntlW, Value->Name, szBuff);

	RtlInitUnicodeString(&ValueW, Value->Name);
	Status = NtSetValueKey(hKey, &ValueW, 0, REG_SZ, szBuff, sizeof(szBuff));

	RtlEnterCriticalSection(&CacheSection);
	HeapFree(GetProcessHeap(), 0, Value->CachedValue);
	Value->CachedValue = NULL;
	RtlLeaveCriticalSection(&CacheSection);
    }

    NtClose(hKey);

    if (Status)
	SetLastError(RtlNtStatusToDosError(Status));
    return !Status;
}

/***********************************************************************
 *           GetThreadLocale    (KERNEL32.@)
 *
 * Get the current threads locale.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  The LCID currently associated with the calling thread.
 */
WINAPI LCID GetThreadLocale(void)
{
    LCID Ret = NtCurrentTeb()->CurrentLocale;
    if (!Ret)
	NtCurrentTeb()->CurrentLocale = Ret = GetUserDefaultLCID();
    return Ret;
}

/**********************************************************************
 *           SetThreadLocale    (KERNEL32.@)
 *
 * Set the current threads locale.
 *
 * PARAMS
 *  lcid [I] LCID of the locale to set
 *
 * RETURNS
 *  Success: TRUE. The threads locale is set to lcid.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI BOOL SetThreadLocale(LCID Lcid)
{
    TRACE("(0x%04X)\n", lcid);

    Lcid = ConvertDefaultLocale(Lcid);

    if (Lcid != GetThreadLocale()) {
	if (!IsValidLocale(Lcid, LCID_SUPPORTED)) {
	    SetLastError(ERROR_INVALID_PARAMETER);
	    return FALSE;
	}

	NtCurrentTeb()->CurrentLocale = Lcid;
    }
    return TRUE;
}

/******************************************************************************
 *		ConvertDefaultLocale (KERNEL32.@)
 *
 * Convert a default locale identifier into a real identifier.
 *
 * PARAMS
 *  lcid [I] LCID identifier of the locale to convert
 *
 * RETURNS
 *  lcid unchanged, if not a default locale or its sublanguage is
 *   not SUBLANG_NEUTRAL.
 *  GetSystemDefaultLCID(), if lcid == LOCALE_SYSTEM_DEFAULT.
 *  GetUserDefaultLCID(), if lcid == LOCALE_USER_DEFAULT or LOCALE_NEUTRAL.
 *  Otherwise, lcid with sublanguage changed to SUBLANG_DEFAULT.
 */
WINAPI LCID ConvertDefaultLocale(LCID Lcid)
{
    LANGID Langid;

    switch (Lcid) {
    case LOCALE_INVARIANT:
	/* keep as-is */
	break;
    case LOCALE_SYSTEM_DEFAULT:
	Lcid = GetSystemDefaultLCID();
	break;
    case LOCALE_USER_DEFAULT:
    case LOCALE_NEUTRAL:
	Lcid = GetUserDefaultLCID();
	break;
    default:
	/* Replace SUBLANG_NEUTRAL with SUBLANG_DEFAULT */
	Langid = LANGIDFROMLCID(Lcid);
	if (SUBLANGID(Langid) == SUBLANG_NEUTRAL) {
	    Langid = GetDefaultSublang(Langid);
	    Lcid = MAKELCID(Langid, SORTIDFROMLCID(Lcid));
	}
    }
    return Lcid;
}

/******************************************************************************
 *           IsValidLocale   (KERNEL32.@)
 *
 * Determine if a locale is valid.
 *
 * PARAMS
 *  lcid  [I] LCID of the locale to check
 *  flags [I] LCID_SUPPORTED = Valid, LCID_INSTALLED = Valid and installed on the system
 *
 * RETURNS
 *  TRUE,  if lcid is valid,
 *  FALSE, otherwise.
 *
 * NOTES
 *  Wine does not currently make the distinction between supported and installed. All
 *  languages supported are installed by default.
 */
WINAPI BOOL IsValidLocale(LCID Lcid, DWORD Flags)
{
    /* check if language is registered in the kernel32 resources */
    return FindResourceExW(Kernel32Handle, (LPWSTR)RT_STRING, (LPCWSTR)LOCALE_ILANGUAGE,
			   LANGIDFROMLCID(Lcid)) != 0;
}

static BOOL CALLBACK EnumLangProcA(HMODULE hModule, LPCSTR Type, LPCSTR Name,
				      WORD LangID, LONG_PTR lParam)
{
    LOCALE_ENUMPROCA LpfnLocaleEnum = (LOCALE_ENUMPROCA)lParam;
    char Buf[20];

    sprintf(Buf, "%08x", (UINT)LangID);
    return LpfnLocaleEnum(Buf);
}

static BOOL CALLBACK EnumLangProcW(HMODULE hModule, LPCWSTR Type, LPCWSTR Name,
				      WORD LangID, LONG_PTR lParam)
{
    static const WCHAR FormatW[] = { '%', '0', '8', 'x', 0 };
    LOCALE_ENUMPROCW LpfnLocaleEnum = (LOCALE_ENUMPROCW)lParam;
    WCHAR Buf[20];
    sprintfW(Buf, FormatW, (UINT)LangID);
    return LpfnLocaleEnum(Buf);
}

/******************************************************************************
 *           EnumSystemLocalesA  (KERNEL32.@)
 *
 * Call a users function for each locale available on the system.
 *
 * PARAMS
 *  lpfnLocaleEnum [I] Callback function to call for each locale
 *  dwFlags        [I] LOCALE_SUPPORTED=All supported, LOCALE_INSTALLED=Installed only
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI BOOL EnumSystemLocalesA(LOCALE_ENUMPROCA LpfnLocaleEnum, DWORD dwFlags)
{
    TRACE("(%p,%08x)\n", lpfnLocaleEnum, dwFlags);
    EnumResourceLanguagesA(Kernel32Handle, (LPSTR)RT_STRING, (LPCSTR)LOCALE_ILANGUAGE,
			   EnumLangProcA, (LONG_PTR)LpfnLocaleEnum);
    return TRUE;
}

/******************************************************************************
 *           EnumSystemLocalesW  (KERNEL32.@)
 *
 * See EnumSystemLocalesA.
 */
WINAPI BOOL EnumSystemLocalesW(LOCALE_ENUMPROCW LpfnLocaleEnum, DWORD dwFlags)
{
    TRACE("(%p,%08x)\n", lpfnLocaleEnum, dwFlags);
    EnumResourceLanguagesW(Kernel32Handle, (LPWSTR)RT_STRING, (LPCWSTR)LOCALE_ILANGUAGE,
			   EnumLangProcW, (LONG_PTR)LpfnLocaleEnum);
    return TRUE;
}

struct ENUM_LOCALE_EX_DATA {
    LOCALE_ENUMPROCEX Proc;
    DWORD Flags;
    LPARAM Lparam;
};

/***********************************************************************
 *           VerLanguageNameA  (KERNEL32.@)
 *
 * Get the name of a language.
 *
 * PARAMS
 *  wLang  [I] LANGID of the language
 *  szLang [O] Destination for the language name
 *
 * RETURNS
 *  Success: The size of the language name. If szLang is non-NULL, it is filled
 *           with the name.
 *  Failure: 0. Use GetLastError() to determine the cause.
 *
 */
WINAPI DWORD VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD nSize)
{
    return GetLocaleInfoA(MAKELCID(wLang, SORT_DEFAULT), LOCALE_SENGLANGUAGE, szLang,
			  nSize);
}

/***********************************************************************
 *           VerLanguageNameW  (KERNEL32.@)
 *
 * See VerLanguageNameA.
 */
WINAPI DWORD VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD nSize)
{
    return GetLocaleInfoW(MAKELCID(wLang, SORT_DEFAULT), LOCALE_SENGLANGUAGE, szLang,
			  nSize);
}

/******************************************************************************
 *           GetStringTypeW    (KERNEL32.@)
 *
 * See GetStringTypeA.
 */
WINAPI BOOL GetStringTypeW(DWORD Type, LPCWSTR Src, INT Count, LPWORD Chartype)
{
    static const unsigned char Type2Map[16] = {
	C2_NOTAPPLICABLE, /* unassigned */
	C2_LEFTTORIGHT, /* L */
	C2_RIGHTTOLEFT, /* R */
	C2_EUROPENUMBER, /* EN */
	C2_EUROPESEPARATOR, /* ES */
	C2_EUROPETERMINATOR, /* ET */
	C2_ARABICNUMBER, /* AN */
	C2_COMMONSEPARATOR, /* CS */
	C2_BLOCKSEPARATOR, /* B */
	C2_SEGMENTSEPARATOR, /* S */
	C2_WHITESPACE, /* WS */
	C2_OTHERNEUTRAL, /* ON */
	C2_RIGHTTOLEFT, /* AL */
	C2_NOTAPPLICABLE, /* NSM */
	C2_NOTAPPLICABLE, /* BN */
	C2_OTHERNEUTRAL /* LRE, LRO, RLE, RLO, PDF */
    };

    if (!Src) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if (Count == -1)
	Count = strlenW(Src) + 1;
    switch (Type) {
    case CT_CTYPE1:
	while (Count--)
	    *Chartype++ = get_char_typeW(*Src++) & 0xfff;
	break;
    case CT_CTYPE2:
	while (Count--)
	    *Chartype++ = Type2Map[get_char_typeW(*Src++) >> 12];
	break;
    case CT_CTYPE3: {
	WARN("CT_CTYPE3: semi-stub.\n");
	while (Count--) {
	    int c = *Src;
	    WORD Type1, Type3 = 0; /* C3_NOTAPPLICABLE */

	    Type1 = get_char_typeW(*Src++) & 0xfff;
	    /* try to construct type3 from type1 */
	    if (Type1 & C1_SPACE)
		Type3 |= C3_SYMBOL;
	    if (Type1 & C1_ALPHA)
		Type3 |= C3_ALPHA;
	    if ((c >= 0x30A0) && (c <= 0x30FF))
		Type3 |= C3_KATAKANA;
	    if ((c >= 0x3040) && (c <= 0x309F))
		Type3 |= C3_HIRAGANA;
	    if ((c >= 0x4E00) && (c <= 0x9FAF))
		Type3 |= C3_IDEOGRAPH;
	    if (c == 0x0640)
		Type3 |= C3_KASHIDA;
	    if ((c >= 0x3000) && (c <= 0x303F))
		Type3 |= C3_SYMBOL;

	    if ((c >= 0xD800) && (c <= 0xDBFF))
		Type3 |= C3_HIGHSURROGATE;
	    if ((c >= 0xDC00) && (c <= 0xDFFF))
		Type3 |= C3_LOWSURROGATE;

	    if ((c >= 0xFF00) && (c <= 0xFF60))
		Type3 |= C3_FULLWIDTH;
	    if ((c >= 0xFF00) && (c <= 0xFF20))
		Type3 |= C3_SYMBOL;
	    if ((c >= 0xFF3B) && (c <= 0xFF40))
		Type3 |= C3_SYMBOL;
	    if ((c >= 0xFF5B) && (c <= 0xFF60))
		Type3 |= C3_SYMBOL;
	    if ((c >= 0xFF21) && (c <= 0xFF3A))
		Type3 |= C3_ALPHA;
	    if ((c >= 0xFF41) && (c <= 0xFF5A))
		Type3 |= C3_ALPHA;
	    if ((c >= 0xFFE0) && (c <= 0xFFE6))
		Type3 |= C3_FULLWIDTH;
	    if ((c >= 0xFFE0) && (c <= 0xFFE6))
		Type3 |= C3_SYMBOL;

	    if ((c >= 0xFF61) && (c <= 0xFFDC))
		Type3 |= C3_HALFWIDTH;
	    if ((c >= 0xFF61) && (c <= 0xFF64))
		Type3 |= C3_SYMBOL;
	    if ((c >= 0xFF65) && (c <= 0xFF9F))
		Type3 |= C3_KATAKANA;
	    if ((c >= 0xFF65) && (c <= 0xFF9F))
		Type3 |= C3_ALPHA;
	    if ((c >= 0xFFE8) && (c <= 0xFFEE))
		Type3 |= C3_HALFWIDTH;
	    if ((c >= 0xFFE8) && (c <= 0xFFEE))
		Type3 |= C3_SYMBOL;
	    *Chartype++ = Type3;
	}
	break;
    }
    default:
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    return TRUE;
}

/******************************************************************************
 *           GetStringTypeExW    (KERNEL32.@)
 *
 * See GetStringTypeExA.
 */
WINAPI BOOL GetStringTypeExW(LCID Locale, DWORD Type, LPCWSTR Src, INT Count,
			     LPWORD Chartype)
{
    /* locale is ignored for Unicode */
    return GetStringTypeW(Type, Src, Count, Chartype);
}

/******************************************************************************
 *           GetStringTypeA    (KERNEL32.@)
 *
 * Get characteristics of the characters making up a string.
 *
 * PARAMS
 *  locale   [I] Locale Id for the string
 *  type     [I] CT_CTYPE1 = classification, CT_CTYPE2 = directionality, CT_CTYPE3 =
 * typographic info src      [I] String to analyse count    [I] Length of src in chars, or
 * -1 if src is NUL terminated chartype [O] Destination for the calculated characteristics
 *
 * RETURNS
 *  Success: TRUE. chartype is filled with the requested characteristics of each char
 *           in src.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI BOOL GetStringTypeA(LCID Locale, DWORD Type, LPCSTR Src, INT Count,
			   LPWORD Chartype)
{
    UINT Cp;
    INT CountW;
    LPWSTR SrcW;
    BOOL Ret = FALSE;

    if (Count == -1)
	Count = strlen(Src) + 1;

    if (!(Cp = GetLcidCodepage(Locale))) {
	FIXME("For locale %04x using current ANSI code page\n", locale);
	Cp = GetACP();
    }

    CountW = MultiByteToWideChar(Cp, 0, Src, Count, NULL, 0);
    if ((SrcW = HeapAlloc(GetProcessHeap(), 0, CountW * sizeof(WCHAR)))) {
	MultiByteToWideChar(Cp, 0, Src, Count, SrcW, CountW);
	/*
	 * NOTE: the target buffer has 1 word for each CHARACTER in the source
	 * string, with multibyte characters there maybe be more bytes in count
	 * than character space in the buffer!
	 */
	Ret = GetStringTypeW(Type, SrcW, CountW, Chartype);
	HeapFree(GetProcessHeap(), 0, SrcW);
    }
    return Ret;
}

/******************************************************************************
 *           GetStringTypeExA    (KERNEL32.@)
 *
 * Get characteristics of the characters making up a string.
 *
 * PARAMS
 *  locale   [I] Locale Id for the string
 *  type     [I] CT_CTYPE1 = classification, CT_CTYPE2 = directionality, CT_CTYPE3 = typographic info
 *  src      [I] String to analyse
 *  count    [I] Length of src in chars, or -1 if src is NUL terminated
 *  chartype [O] Destination for the calculated characteristics
 *
 * RETURNS
 *  Success: TRUE. chartype is filled with the requested characteristics of each char
 *           in src.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI BOOL GetStringTypeExA(LCID Locale, DWORD Type, LPCSTR Src, INT Count,
			     LPWORD Chartype)
{
    return GetStringTypeA(Locale, Type, Src, Count, Chartype);
}

static inline void MapByterev(const WCHAR *Src, int Len, WCHAR *Dst)
{
    while (Len--)
	*Dst++ = RtlUshortByteSwap(*Src++);
}

static int MapToHiragana(const WCHAR *Src, int Srclen, WCHAR *Dst, int Dstlen)
{
    int Pos;
    for (Pos = 0; Srclen; Src++, Srclen--, Pos++) {
	/*
	 * U+30A1 ... U+30F3: Katakana
	 * U+30F4: Katakana Letter VU
	 * U+30F5: Katakana Letter Small KA
	 * U+30FD: Katakana Iteration Mark
	 * U+30FE: Katakana Voiced Iteration Mark
	 */
	WCHAR Wch = *Src;
	if ((0x30A1 <= Wch && Wch <= 0x30F3) || Wch == 0x30F4 || Wch == 0x30F5 ||
	    Wch == 0x30FD || Wch == 0x30FE) {
	    Wch -= 0x60; /* Katakana to Hiragana */
	}
	if (Pos < Dstlen)
	    Dst[Pos] = Wch;
    }
    return Pos;
}

static int MapToKatakana(const WCHAR *Src, int Srclen, WCHAR *Dst, int Dstlen)
{
    int Pos;
    for (Pos = 0; Srclen; Src++, Srclen--, Pos++) {
	/*
	 * U+3041 ... U+3093: Hiragana
	 * U+3094: Hiragana Letter VU
	 * U+3095: Hiragana Letter Small KA
	 * U+309D: Hiragana Iteration Mark
	 * U+309E: Hiragana Voiced Iteration Mark
	 */
	WCHAR Wch = *Src;
	if ((0x3041 <= Wch && Wch <= 0x3093) || Wch == 3094 || Wch == 0x3095 ||
	    Wch == 0x309D || Wch == 0x309E) {
	    Wch += 0x60; /* Hiragana to Katakana */
	}
	if (Pos < Dstlen)
	    Dst[Pos] = Wch;
    }
    return Pos;
}

/* The table that contains fullwidth characters and halfwidth characters */
typedef WCHAR FULL2HALF_ENTRY[3];
static const FULL2HALF_ENTRY Full2halfTable[] = {
#define DEFINE_FULL2HALF(full, half1, half2) { full, half1, half2 },
#include "full2half.h"
#undef DEFINE_FULL2HALF
};
#define GET_FULL(table, index) ((table)[index][0])
#define GET_HALF1(table, index) ((table)[index][1])
#define GET_HALF2(table, index) ((table)[index][2])

/* The table that contains dakuten entries */
typedef WCHAR DAKUTEN_ENTRY[3];
static const DAKUTEN_ENTRY DakutenTable[] = {
#define DEFINE_DAKUTEN(voiced, single1, single2, half1, half2) \
    { voiced, single1, single2 },
#include "dakuten.h"
#undef DEFINE_DAKUTEN
};
#define GET_VOICED(table, index) ((table)[index][0])
#define GET_SINGLE1(table, index) ((table)[index][1])
#define GET_SINGLE2(table, index) ((table)[index][2])

static int MapToHalfwidth(DWORD Flags, const WCHAR *Src, int Srclen, WCHAR *Dst,
			  int Dstlen)
{
    int Pos, i;
    const int Count1 = (int)ARRAY_SIZE(Full2halfTable);
    const FULL2HALF_ENTRY *Table1 = Full2halfTable;

    for (Pos = 0; Srclen; Src++, Srclen--, Pos++) {
	WCHAR Ch = *Src;

	if (Flags & LCMAP_KATAKANA)
	    MapToKatakana(&Ch, 1, &Ch, 1);
	else if (Flags & LCMAP_HIRAGANA)
	    MapToHiragana(&Ch, 1, &Ch, 1);

	if (Ch < 0x3000) /* Quick judgment */
	{
	    if (Pos < Dstlen)
		Dst[Pos] = Ch;
	    continue;
	}

	if (0xFF01 <= Ch && Ch <= 0xFF5E) /* U+FF01 ... U+FF5E */
	{
	    if (Pos < Dstlen)
		Dst[Pos] = Ch - 0xFEE0; /* Fullwidth ASCII to halfwidth ASCII */
	    continue;
	}

	/* Search in table1 (full/half) */
	for (i = Count1 - 1; i >= 0; --i) /* In reverse order */
	{
	    if (GET_FULL(Table1, i) != Ch)
		continue;

	    if (GET_HALF2(Table1, i) == 0) {
		if (Pos < Dstlen)
		    Dst[Pos] = GET_HALF1(Table1, i);
	    } else if (!Dstlen) {
		Pos++;
	    } else if (Pos + 1 < Dstlen) {
		Dst[Pos++] = GET_HALF1(Table1, i);
		Dst[Pos] = GET_HALF2(Table1, i);
	    } else {
		Dst[Pos] = Ch;
	    }
	    break;
	}

	if (i >= 0)
	    continue;

	if (Pos < Dstlen)
	    Dst[Pos] = Ch;
    }

    return Pos;
}

static int MapToFullwidth(const WCHAR *Src, int Srclen, WCHAR *Dst, int Dstlen)
{
    int Pos, i;
    const FULL2HALF_ENTRY *Table1 = Full2halfTable;
    const DAKUTEN_ENTRY *Table2 = DakutenTable;
    const int Count1 = (int)ARRAY_SIZE(Full2halfTable);
    const int Count2 = (int)ARRAY_SIZE(DakutenTable);

    for (Pos = 0; Srclen; Src++, Srclen--, Pos++) {
	WCHAR Ch = *Src;

	if (Ch == 0x20) /* U+0020: Space */
	{
	    if (Pos < Dstlen)
		Dst[Pos] = 0x3000; /* U+3000: Ideographic Space */
	    continue;
	}

	if (0x21 <= Ch && Ch <= 0x7E) /* Mappable halfwidth ASCII */
	{
	    if (Pos < Dstlen)
		Dst[Pos] = Ch + 0xFEE0; /* U+FF01 ... U+FF5E */
	    continue;
	}

	if (Ch < 0xFF00) /* Quick judgment */
	{
	    if (Pos < Dstlen)
		Dst[Pos] = Ch;
	    continue;
	}

	/* Search in table1 (full/half) */
	for (i = Count1 - 1; i >= 0; --i) /* In reverse order */
	{
	    if (GET_HALF1(Table1, i) != Ch)
		continue; /* Mismatched */

	    if (GET_HALF2(Table1, i) == 0) {
		if (Pos < Dstlen)
		    Dst[Pos] = GET_FULL(Table1, i);
		break;
	    }

	    if (Srclen <= 1 || GET_HALF2(Table1, i) != Src[1])
		continue; /* Mismatched */

	    --Srclen;
	    ++Src;

	    if (Pos < Dstlen)
		Dst[Pos] = GET_FULL(Table1, i);
	    break;
	}

	if (i >= 0)
	    continue;

	/* Search in table2 (dakuten) */
	for (i = Count2 - 1; i >= 0; --i) /* In reverse order */
	{
	    if (GET_SINGLE1(Table2, i) != Ch)
		continue; /* Mismatched */

	    if (Srclen <= 1 || GET_SINGLE2(Table2, i) != Src[1])
		continue; /* Mismatched */

	    --Srclen;
	    ++Src;

	    if (Pos < Dstlen)
		Dst[Pos] = GET_VOICED(Table2, i);
	    break;
	}

	if (i >= 0)
	    continue;

	if (Pos < Dstlen)
	    Dst[Pos] = Ch;
    }

    return Pos;
}

static int MapToLowercase(DWORD Flags, const WCHAR *Src, int Srclen, WCHAR *Dst,
			    int Dstlen)
{
    int Pos;
    for (Pos = 0; Srclen; Src++, Srclen--) {
	WCHAR Wch = *Src;
	if ((Flags & NORM_IGNORESYMBOLS) && (get_char_typeW(Wch) & (C1_PUNCT | C1_SPACE)))
	    continue;
	if (Pos < Dstlen)
	    Dst[Pos] = tolowerW(Wch);
	Pos++;
    }
    return Pos;
}

static int MapToUppercase(DWORD Flags, const WCHAR *Src, int Srclen, WCHAR *Dst,
			    int Dstlen)
{
    int Pos;
    for (Pos = 0; Srclen; Src++, Srclen--) {
	WCHAR Wch = *Src;
	if ((Flags & NORM_IGNORESYMBOLS) && (get_char_typeW(Wch) & (C1_PUNCT | C1_SPACE)))
	    continue;
	if (Pos < Dstlen)
	    Dst[Pos] = toupperW(Wch);
	Pos++;
    }
    return Pos;
}

typedef struct _WCHAR_PAIR {
    WCHAR From, To;
} WCHAR_PAIR, *PWCHAR_PAIR;

/* The table to convert Simplified Chinese to Traditional Chinese */
static const WCHAR_PAIR SSim2tra[] = {
#define DEFINE_SIM2TRA(from, to) { from, to },
#include "sim2tra.h"
#undef DEFINE_SIM2TRA
};

/* The table to convert Traditional Chinese to Simplified Chinese */
static const WCHAR_PAIR STra2sim[] = {
#define DEFINE_TRA2SIM(from, to) { from, to },
#include "tra2sim.h"
#undef DEFINE_TRA2SIM
};

/* The comparison function to do bsearch */
static int CompareWcharPair(const void *x, const void *y)
{
    const WCHAR_PAIR *a = x;
    const WCHAR_PAIR *b = y;
    if (a->From < b->From)
	return -1;
    if (a->From > b->From)
	return +1;
    return 0;
}

static WCHAR FindWcharPair(const WCHAR_PAIR *Pairs, size_t Count, WCHAR Ch)
{
    PWCHAR_PAIR Found = bsearch(&Ch, Pairs, Count, sizeof(WCHAR_PAIR),
				CompareWcharPair);
    if (Found)
	return Found->To;
    return Ch;
}

static int MapToSimplifiedChinese(DWORD Flags, const WCHAR *Src, int Srclen,
				     WCHAR *Dst, int Dstlen)
{
    int Pos;
    for (Pos = 0; Srclen; Src++, Srclen--) {
	WCHAR Wch = *Src;
	if (Pos < Dstlen)
	    Dst[Pos] = FindWcharPair(STra2sim, ARRAY_SIZE(STra2sim), Wch);
	Pos++;
    }
    return Pos;
}

static int MapToTraditionalChinese(DWORD Flags, const WCHAR *Src, int Srclen,
				      WCHAR *Dst, int Dstlen)
{
    int Pos;
    for (Pos = 0; Srclen; Src++, Srclen--) {
	WCHAR Wch = *Src;
	if (Pos < Dstlen)
	    Dst[Pos] = FindWcharPair(SSim2tra, ARRAY_SIZE(SSim2tra), Wch);
	Pos++;
    }
    return Pos;
}

static int MapRemoveIgnored(DWORD Flags, const WCHAR *Src, int Srclen, WCHAR *Dst,
			      int Dstlen)
{
    int Pos;
    WORD wC1, wC2, wC3;
    for (Pos = 0; Srclen; Src++, Srclen--) {
	WCHAR Wch = *Src;
	GetStringTypeW(CT_CTYPE1, &Wch, 1, &wC1);
	GetStringTypeW(CT_CTYPE2, &Wch, 1, &wC2);
	GetStringTypeW(CT_CTYPE3, &Wch, 1, &wC3);
	if (Flags & NORM_IGNORESYMBOLS) {
	    if ((wC1 & C1_PUNCT) || (wC3 & C3_SYMBOL))
		continue;
	}
	if (Flags & NORM_IGNORENONSPACE) {
	    if ((wC2 & C2_OTHERNEUTRAL) && (wC3 & (C3_NONSPACING | C3_DIACRITIC)))
		continue;
	}
	if (Pos < Dstlen)
	    Dst[Pos] = Wch;
	Pos++;
    }
    return Pos;
}

static int LcmapString(DWORD Flags, const WCHAR *Src, int Srclen, WCHAR *Dst, int Dstlen)
{
    int Ret = 0;

    if ((Flags & (LCMAP_LOWERCASE | LCMAP_UPPERCASE)) ==
	(LCMAP_LOWERCASE | LCMAP_UPPERCASE)) {
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    switch (Flags & ~(LCMAP_BYTEREV | LCMAP_LOWERCASE | LCMAP_UPPERCASE |
		      LCMAP_LINGUISTIC_CASING)) {
    case LCMAP_HIRAGANA:
	Ret = MapToHiragana(Src, Srclen, Dst, Dstlen);
	break;
    case LCMAP_KATAKANA:
	Ret = MapToKatakana(Src, Srclen, Dst, Dstlen);
	break;
    case LCMAP_HALFWIDTH:
	Ret = MapToHalfwidth(Flags, Src, Srclen, Dst, Dstlen);
	break;
    case LCMAP_HIRAGANA | LCMAP_HALFWIDTH:
	Ret = MapToHalfwidth(Flags, Src, Srclen, Dst, Dstlen);
	break;
    case LCMAP_KATAKANA | LCMAP_HALFWIDTH:
	Ret = MapToHalfwidth(Flags, Src, Srclen, Dst, Dstlen);
	break;
    case LCMAP_FULLWIDTH:
	Ret = MapToFullwidth(Src, Srclen, Dst, Dstlen);
	break;
    case LCMAP_HIRAGANA | LCMAP_FULLWIDTH:
	Ret = MapToFullwidth(Src, Srclen, Dst, Dstlen);
	if (Dstlen && Ret)
	    MapToHiragana(Dst, Ret, Dst, Dstlen);
	break;
    case LCMAP_KATAKANA | LCMAP_FULLWIDTH:
	Ret = MapToFullwidth(Src, Srclen, Dst, Dstlen);
	if (Dstlen && Ret)
	    MapToKatakana(Dst, Ret, Dst, Dstlen);
	break;
    case LCMAP_SIMPLIFIED_CHINESE:
	Ret = MapToSimplifiedChinese(Flags, Src, Srclen, Dst, Dstlen);
	break;
    case LCMAP_TRADITIONAL_CHINESE:
	Ret = MapToTraditionalChinese(Flags, Src, Srclen, Dst, Dstlen);
	break;
    case NORM_IGNORENONSPACE:
    case NORM_IGNORESYMBOLS:
    case NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS:
	if (Flags & ~(NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS | LCMAP_BYTEREV)) {
	    SetLastError(ERROR_INVALID_FLAGS);
	    return 0;
	}
	Ret = MapRemoveIgnored(Flags, Src, Srclen, Dst, Dstlen);
	break;
    case 0:
	if (Flags & LCMAP_LOWERCASE) {
	    Ret = MapToLowercase(Flags, Src, Srclen, Dst, Dstlen);
	    Flags &= ~LCMAP_LOWERCASE;
	    break;
	}
	if (Flags & LCMAP_UPPERCASE) {
	    Ret = MapToUppercase(Flags, Src, Srclen, Dst, Dstlen);
	    Flags &= ~LCMAP_UPPERCASE;
	    break;
	}
	if (Flags & LCMAP_BYTEREV) {
	    if (Dstlen == 0) {
		Ret = Srclen;
		break;
	    }
	    Ret = min(Srclen, Dstlen);
	    RtlCopyMemory(Dst, Src, Ret * sizeof(WCHAR));
	    break;
	}
	/* fall through */
    default:
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    if (Dstlen) {
	if (Flags & LCMAP_LOWERCASE)
	    MapToLowercase(Flags, Dst, Ret, Dst, Dstlen);
	if (Flags & LCMAP_UPPERCASE)
	    MapToUppercase(Flags, Dst, Ret, Dst, Dstlen);
	if (Flags & LCMAP_BYTEREV)
	    MapByterev(Dst, min(Ret, Dstlen), Dst);

	if (Dstlen < Ret) {
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	    return 0;
	}
    }

    return Ret;
}

/*************************************************************************
 *           LCMapStringEx   (KERNEL32.@)
 *
 * Map characters in a locale sensitive string.
 *
 * PARAMS
 *  locale   [I] Locale name for the conversion.
 *  flags    [I] Flags controlling the mapping (LCMAP_ constants from "winnls.h")
 *  src      [I] String to map
 *  srclen   [I] Length of src in chars, or -1 if src is NUL terminated
 *  dst      [O] Destination for mapped string
 *  dstlen   [I] Length of dst in characters
 *  version  [I] reserved, must be NULL
 *  reserved [I] reserved, must be NULL
 *  lparam   [I] reserved, must be 0
 *
 * RETURNS
 *  Success: The length of the mapped string in dst, including the NUL terminator.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
WINAPI INT LCMapStringEx(LPCWSTR Locale, DWORD Flags, LPCWSTR Src, INT Srclen, LPWSTR Dst,
			 INT Dstlen, LPNLSVERSIONINFO Version, LPVOID Reserved,
			 LPARAM Handle)
{
    if (Version)
	FIXME("unsupported version structure %p\n", version);
    if (Reserved)
	FIXME("unsupported reserved pointer %p\n", reserved);
    if (Handle) {
	static int Once;
	if (!Once++)
	    FIXME("unsupported lparam %Ix\n", handle);
    }

    if (!Src || !Srclen || Dstlen < 0) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (Srclen < 0)
	Srclen = lstrlenW(Src) + 1;

    TRACE("(%s,0x%08lx,%s,%d,%p,%d)\n", debugstr_w(locale), flags,
	  debugstr_wn(src, srclen), srclen, dst, dstlen);

    Flags &= ~LOCALE_USE_CP_ACP;

    if (Src == Dst && (Flags & ~(LCMAP_LOWERCASE | LCMAP_UPPERCASE))) {
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    if (!Dstlen)
	Dst = NULL;

    if (Flags & LCMAP_SORTKEY) {
	INT Ret;

	if (Srclen < 0)
	    Srclen = strlenW(Src);

	Ret = wine_get_sortkey(Flags, Src, Srclen, (char *)Dst, Dstlen);
	if (Ret == 0)
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	else
	    Ret++;
	return Ret;
    }

    /* SORT_STRINGSORT must be used exclusively with LCMAP_SORTKEY */
    if (Flags & SORT_STRINGSORT) {
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    return LcmapString(Flags, Src, Srclen, Dst, Dstlen);
}

/*************************************************************************
 *           LCMapStringW    (KERNEL32.@)
 *
 * See LCMapStringA.
 */
WINAPI INT LCMapStringW(LCID Lcid, DWORD Flags, LPCWSTR Src, INT Srclen, LPWSTR Dst,
			INT Dstlen)
{
    TRACE("(0x%04x,0x%08x,%s,%d,%p,%d)\n", lcid, flags, debugstr_wn(src, srclen), srclen,
	  dst, dstlen);

    return LCMapStringEx(NULL, Flags, Src, Srclen, Dst, Dstlen, NULL, NULL, 0);
}

/*************************************************************************
 *           LCMapStringA    (KERNEL32.@)
 *
 * Map characters in a locale sensitive string.
 *
 * PARAMS
 *  lcid   [I] LCID for the conversion.
 *  flags  [I] Flags controlling the mapping (LCMAP_ constants from "winnls.h").
 *  src    [I] String to map
 *  srclen [I] Length of src in chars, or -1 if src is NUL terminated
 *  dst    [O] Destination for mapped string
 *  dstlen [I] Length of dst in characters
 *
 * RETURNS
 *  Success: The length of the mapped string in dst, including the NUL terminator.
 *  Failure: 0. Use GetLastError() to determine the cause.
 */
WINAPI INT LCMapStringA(LCID Lcid, DWORD Flags, LPCSTR Src, INT Srclen, LPSTR Dst,
			INT Dstlen)
{
    WCHAR *BufW = NtCurrentTeb()->Win32.StaticUnicodeBuffer;
    LPWSTR SrcW, DstW;
    INT Ret = 0, SrclenW, DstlenW;
    UINT LocaleCp = CP_ACP;

    if (!Src || !Srclen || Dstlen < 0) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (!(Flags & LOCALE_USE_CP_ACP))
	LocaleCp = GetLcidCodepage(Lcid);

    SrclenW = MultiByteToWideChar(LocaleCp, 0, Src, Srclen, BufW, 260);
    if (SrclenW)
	SrcW = BufW;
    else {
	SrclenW = MultiByteToWideChar(LocaleCp, 0, Src, Srclen, NULL, 0);
	SrcW = HeapAlloc(GetProcessHeap(), 0, SrclenW * sizeof(WCHAR));
	if (!SrcW) {
	    SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	    return 0;
	}
	MultiByteToWideChar(LocaleCp, 0, Src, Srclen, SrcW, SrclenW);
    }

    if (Flags & LCMAP_SORTKEY) {
	if (Src == Dst) {
	    SetLastError(ERROR_INVALID_FLAGS);
	    goto map_string_exit;
	}
	Ret = wine_get_sortkey(Flags, SrcW, SrclenW, Dst, Dstlen);
	if (Ret == 0)
	    SetLastError(ERROR_INSUFFICIENT_BUFFER);
	else
	    Ret++;
	goto map_string_exit;
    }

    if (Flags & SORT_STRINGSORT) {
	SetLastError(ERROR_INVALID_FLAGS);
	goto map_string_exit;
    }

    DstlenW = LCMapStringEx(NULL, Flags, SrcW, SrclenW, NULL, 0, NULL, NULL, 0);
    if (!DstlenW)
	goto map_string_exit;

    DstW = HeapAlloc(GetProcessHeap(), 0, DstlenW * sizeof(WCHAR));
    if (!DstW) {
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	goto map_string_exit;
    }

    LCMapStringEx(NULL, Flags, SrcW, SrclenW, DstW, DstlenW, NULL, NULL, 0);
    Ret = WideCharToMultiByte(LocaleCp, 0, DstW, DstlenW, Dst, Dstlen, NULL, NULL);
    HeapFree(GetProcessHeap(), 0, DstW);

map_string_exit:
    if (SrcW != BufW)
	HeapFree(GetProcessHeap(), 0, SrcW);
    return Ret;
}

/*************************************************************************
 *           FoldStringW    (KERNEL32.@)
 *
 * See FoldStringA.
 */
WINAPI INT FoldStringW(DWORD dwFlags, LPCWSTR Src, INT Srclen, LPWSTR Dst, INT Dstlen)
{
    int Ret;

    switch (dwFlags & (MAP_COMPOSITE | MAP_PRECOMPOSED | MAP_EXPAND_LIGATURES)) {
    case 0:
	if (dwFlags)
	    break;
	/* Fall through for dwFlags == 0 */
    case MAP_PRECOMPOSED | MAP_COMPOSITE:
    case MAP_PRECOMPOSED | MAP_EXPAND_LIGATURES:
    case MAP_COMPOSITE | MAP_EXPAND_LIGATURES:
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    if (!Src || !Srclen || Dstlen < 0 || (Dstlen && !Dst) || Src == Dst) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    Ret = wine_fold_string(dwFlags, Src, Srclen, Dst, Dstlen);
    if (!Ret)
	SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return Ret;
}

/******************************************************************************
 *           CompareStringW    (KERNEL32.@)
 *
 * See CompareStringA.
 */
WINAPI INT CompareStringW(LCID Lcid, DWORD Flags, LPCWSTR Str1, INT Len1, LPCWSTR Str2,
			  INT Len2)
{
    return CompareStringEx(NULL, Flags, Str1, Len1, Str2, Len2, NULL, NULL, 0);
}

/******************************************************************************
 *           CompareStringEx    (KERNEL32.@)
 */
WINAPI INT CompareStringEx(LPCWSTR Locale, DWORD Flags, LPCWSTR Str1, INT Len1,
			   LPCWSTR Str2, INT Len2, LPNLSVERSIONINFO Version,
			   LPVOID Reserved, LPARAM lParam)
{
    DWORD SupportedFlags = NORM_IGNORECASE | NORM_IGNORENONSPACE | NORM_IGNORESYMBOLS |
			    SORT_STRINGSORT | NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH |
			    LOCALE_USE_CP_ACP;
    DWORD SemistubFlags = NORM_LINGUISTIC_CASING | LINGUISTIC_IGNORECASE | 0x10000000;
    /* 0x10000000 is related to diacritics in Arabic, Japanese, and Hebrew */
    INT Ret;
    static int Once;

    if (Version)
	FIXME("unexpected version parameter\n");
    if (Reserved)
	FIXME("unexpected reserved value\n");
    if (lParam)
	FIXME("unexpected lParam\n");

    if (!Str1 || !Str2) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    if (Flags & ~(SupportedFlags | SemistubFlags)) {
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    if (Flags & SemistubFlags) {
	if (!Once++)
	    FIXME("semi-stub behavior for flag(s) 0x%x\n", flags & semistub_flags);
    }

    if (Len1 < 0)
	Len1 = strlenW(Str1);
    if (Len2 < 0)
	Len2 = strlenW(Str2);

    Ret = wine_compare_string(Flags, Str1, Len1, Str2, Len2);

    if (Ret) /* need to translate result */
	return (Ret < 0) ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
    return CSTR_EQUAL;
}

/******************************************************************************
 *           CompareStringA    (KERNEL32.@)
 *
 * Compare two locale sensitive strings.
 *
 * PARAMS
 *  lcid  [I] LCID for the comparison
 *  flags [I] Flags for the comparison (NORM_ constants from "winnls.h").
 *  str1  [I] First string to compare
 *  len1  [I] Length of str1, or -1 if str1 is NUL terminated
 *  str2  [I] Second string to compare
 *  len2  [I] Length of str2, or -1 if str2 is NUL terminated
 *
 * RETURNS
 *  Success: CSTR_LESS_THAN, CSTR_EQUAL or CSTR_GREATER_THAN depending on whether
 *           str1 is less than, equal to or greater than str2 respectively.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI INT CompareStringA(LCID Lcid, DWORD Flags, LPCSTR Str1, INT Len1, LPCSTR Str2,
			  INT Len2)
{
    WCHAR *Buf1W = NtCurrentTeb()->Win32.StaticUnicodeBuffer;
    WCHAR *Buf2W = Buf1W + 130;
    LPWSTR Str1W, Str2W;
    INT Len1W = 0, Len2W = 0, Ret;
    UINT LocaleCp = CP_ACP;

    if (!Str1 || !Str2) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }
    if (Len1 < 0)
	Len1 = strlen(Str1);
    if (Len2 < 0)
	Len2 = strlen(Str2);

    if (!(Flags & LOCALE_USE_CP_ACP))
	LocaleCp = GetLcidCodepage(Lcid);

    if (Len1) {
	if (Len1 <= 130)
	    Len1W = MultiByteToWideChar(LocaleCp, 0, Str1, Len1, Buf1W, 130);
	if (Len1W)
	    Str1W = Buf1W;
	else {
	    Len1W = MultiByteToWideChar(LocaleCp, 0, Str1, Len1, NULL, 0);
	    Str1W = HeapAlloc(GetProcessHeap(), 0, Len1W * sizeof(WCHAR));
	    if (!Str1W) {
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return 0;
	    }
	    MultiByteToWideChar(LocaleCp, 0, Str1, Len1, Str1W, Len1W);
	}
    } else {
	Len1W = 0;
	Str1W = Buf1W;
    }

    if (Len2) {
	if (Len2 <= 130)
	    Len2W = MultiByteToWideChar(LocaleCp, 0, Str2, Len2, Buf2W, 130);
	if (Len2W)
	    Str2W = Buf2W;
	else {
	    Len2W = MultiByteToWideChar(LocaleCp, 0, Str2, Len2, NULL, 0);
	    Str2W = HeapAlloc(GetProcessHeap(), 0, Len2W * sizeof(WCHAR));
	    if (!Str2W) {
		if (Str1W != Buf1W)
		    HeapFree(GetProcessHeap(), 0, Str1W);
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return 0;
	    }
	    MultiByteToWideChar(LocaleCp, 0, Str2, Len2, Str2W, Len2W);
	}
    } else {
	Len2W = 0;
	Str2W = Buf2W;
    }

    Ret = CompareStringEx(NULL, Flags, Str1W, Len1W, Str2W, Len2W, NULL, NULL, 0);

    if (Str1W != Buf1W)
	HeapFree(GetProcessHeap(), 0, Str1W);
    if (Str2W != Buf2W)
	HeapFree(GetProcessHeap(), 0, Str2W);
    return Ret;
}

HANDLE NLS_RegOpenKey(HANDLE hRootKey, LPCWSTR szKeyName)
{
    UNICODE_STRING KeyName;
    OBJECT_ATTRIBUTES Attr;
    HANDLE hKey;

    RtlInitUnicodeString(&KeyName, szKeyName);
    InitializeObjectAttributes(&Attr, &KeyName, OBJ_CASE_INSENSITIVE, hRootKey, NULL);

    if (NtOpenKey(&hKey, KEY_READ, &Attr) != STATUS_SUCCESS)
	hKey = 0;

    return hKey;
}

BOOL NLS_RegEnumValue(HANDLE hKey, UINT ulIndex, LPWSTR szValueName, ULONG ValueNameSize,
		      LPWSTR szValueData, ULONG ValueDataSize)
{
    BYTE Buffer[80];
    KEY_VALUE_FULL_INFORMATION *Info = (KEY_VALUE_FULL_INFORMATION *)Buffer;
    DWORD dwLen;

    if (NtEnumerateValueKey(hKey, ulIndex, KeyValueFullInformation, Buffer,
			    sizeof(Buffer), &dwLen) != STATUS_SUCCESS ||
	Info->NameLength > ValueNameSize || Info->DataLength > ValueDataSize) {
	return FALSE;
    }

    TRACE("info->Name %s info->DataLength %d\n", debugstr_w(info->Name),
	  info->DataLength);

    memcpy(szValueName, Info->Name, Info->NameLength);
    szValueName[Info->NameLength / sizeof(WCHAR)] = '\0';
    memcpy(szValueData, Buffer + Info->DataOffset, Info->DataLength);
    szValueData[Info->DataLength / sizeof(WCHAR)] = '\0';

    TRACE("returning %s %s\n", debugstr_w(szValueName), debugstr_w(szValueData));
    return TRUE;
}

static BOOL NLS_RegGetDword(HANDLE hKey, LPCWSTR szValueName, DWORD *lpVal)
{
    BYTE Buffer[128];
    const KEY_VALUE_PARTIAL_INFORMATION *Info = (KEY_VALUE_PARTIAL_INFORMATION *)Buffer;
    DWORD dwSize = sizeof(Buffer);
    UNICODE_STRING ValueName;

    RtlInitUnicodeString(&ValueName, szValueName);

    TRACE("%p, %s\n", hKey, debugstr_w(szValueName));
    if (NtQueryValueKey(hKey, &ValueName, KeyValuePartialInformation, Buffer, dwSize,
			&dwSize) == STATUS_SUCCESS &&
	Info->DataLength == sizeof(DWORD)) {
	memcpy(lpVal, Info->Data, sizeof(DWORD));
	return TRUE;
    }

    return FALSE;
}

static BOOL NLS_GetLanguageGroupName(LGRPID Lgrpid, LPWSTR szName, ULONG NameSize)
{
    LANGID LangId;
    LPCWSTR szResourceName = MAKEINTRESOURCEW(((Lgrpid + 0x2000) >> 4) + 1);
    HRSRC hResource;
    BOOL bRet = FALSE;

    /* FIXME: Is it correct to use the system default langid? */
    LangId = GetSystemDefaultLangID();

    if (SUBLANGID(LangId) == SUBLANG_NEUTRAL)
	LangId = GetDefaultSublang(LangId);

    hResource = FindResourceExW(Kernel32Handle, (LPWSTR)RT_STRING, szResourceName,
				LangId);

    if (hResource) {
	HGLOBAL hResDir = LoadResource(Kernel32Handle, hResource);

	if (hResDir) {
	    ULONG iResourceIndex = Lgrpid & 0xf;
	    LPCWSTR lpResEntry = LockResource(hResDir);
	    ULONG i;

	    for (i = 0; i < iResourceIndex; i++)
		lpResEntry += *lpResEntry + 1;

	    if (*lpResEntry < NameSize) {
		memcpy(szName, lpResEntry + 1, *lpResEntry * sizeof(WCHAR));
		szName[*lpResEntry] = '\0';
		bRet = TRUE;
	    }
	}
	FreeResource(hResource);
    }
    return bRet;
}

/* Callback function ptrs for EnumSystemLanguageGroupsA/W */
typedef struct {
    LANGUAGEGROUP_ENUMPROCA ProcA;
    LANGUAGEGROUP_ENUMPROCW ProcW;
    DWORD dwFlags;
    LONG_PTR lParam;
} ENUMLANGUAGEGROUP_CALLBACKS;

/* Internal implementation of EnumSystemLanguageGroupsA/W */
static BOOL NLS_EnumSystemLanguageGroups(ENUMLANGUAGEGROUP_CALLBACKS *lpProcs)
{
    WCHAR szNumber[10], szValue[4];
    HANDLE hKey;
    BOOL bContinue = TRUE;
    ULONG ulIndex = 0;

    if (!lpProcs) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    switch (lpProcs->dwFlags) {
    case 0:
	/* Default to LGRPID_INSTALLED */
	lpProcs->dwFlags = LGRPID_INSTALLED;
	/* Fall through... */
    case LGRPID_INSTALLED:
    case LGRPID_SUPPORTED:
	break;
    default:
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    hKey = NLS_RegOpenKey(0, szLangGroupsKeyName);

    if (!hKey)
	FIXME("NLS registry key not found. Please apply the default registry file "
	      "'wine.inf'\n");

    while (bContinue) {
	if (NLS_RegEnumValue(hKey, ulIndex, szNumber, sizeof(szNumber), szValue,
			     sizeof(szValue))) {
	    BOOL bInstalled = szValue[0] == '1';
	    LGRPID Lgrpid = strtoulW(szNumber, NULL, 16);

	    TRACE("grpid %s (%sinstalled)\n", debugstr_w(szNumber),
		  bInstalled ? "" : "not ");

	    if (lpProcs->dwFlags == LGRPID_SUPPORTED || bInstalled) {
		WCHAR szGrpName[48];

		if (!NLS_GetLanguageGroupName(Lgrpid, szGrpName,
					      sizeof(szGrpName) / sizeof(WCHAR)))
		    szGrpName[0] = '\0';

		if (lpProcs->ProcW)
		    bContinue = lpProcs->ProcW(Lgrpid, szNumber, szGrpName,
					       lpProcs->dwFlags, lpProcs->lParam);
		else {
		    char szNumberA[sizeof(szNumber) / sizeof(WCHAR)];
		    char szGrpNameA[48];

		    /* FIXME: MSDN doesn't say which code page the W->A translation uses,
		     *        or whether the language names are ever localised. Assume
		     * CP_ACP.
		     */

		    WideCharToMultiByte(CP_ACP, 0, szNumber, -1, szNumberA,
					sizeof(szNumberA), 0, 0);
		    WideCharToMultiByte(CP_ACP, 0, szGrpName, -1, szGrpNameA,
					sizeof(szGrpNameA), 0, 0);

		    bContinue = lpProcs->ProcA(Lgrpid, szNumberA, szGrpNameA,
					       lpProcs->dwFlags, lpProcs->lParam);
		}
	    }

	    ulIndex++;
	} else
	    bContinue = FALSE;

	if (!bContinue)
	    break;
    }

    if (hKey)
	NtClose(hKey);

    return TRUE;
}

/******************************************************************************
 *           EnumSystemLanguageGroupsA    (KERNEL32.@)
 *
 * Call a users function for each language group available on the system.
 *
 * PARAMS
 *  pLangGrpEnumProc [I] Callback function to call for each language group
 *  dwFlags          [I] LGRPID_SUPPORTED=All Supported, LGRPID_INSTALLED=Installed only
 *  lParam           [I] User parameter to pass to pLangGrpEnumProc
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI BOOL EnumSystemLanguageGroupsA(LANGUAGEGROUP_ENUMPROCA pLangGrpEnumProc,
				      DWORD dwFlags, LONG_PTR lParam)
{
    ENUMLANGUAGEGROUP_CALLBACKS Procs;

    TRACE("(%p,0x%08X,0x%08lX)\n", pLangGrpEnumProc, dwFlags, lParam);

    Procs.ProcA = pLangGrpEnumProc;
    Procs.ProcW = NULL;
    Procs.dwFlags = dwFlags;
    Procs.lParam = lParam;

    return NLS_EnumSystemLanguageGroups(pLangGrpEnumProc ? &Procs : NULL);
}

/******************************************************************************
 *           EnumSystemLanguageGroupsW    (KERNEL32.@)
 *
 * See EnumSystemLanguageGroupsA.
 */
WINAPI BOOL EnumSystemLanguageGroupsW(LANGUAGEGROUP_ENUMPROCW pLangGrpEnumProc,
				      DWORD dwFlags, LONG_PTR lParam)
{
    ENUMLANGUAGEGROUP_CALLBACKS Procs;

    TRACE("(%p,0x%08X,0x%08lX)\n", pLangGrpEnumProc, dwFlags, lParam);

    Procs.ProcA = NULL;
    Procs.ProcW = pLangGrpEnumProc;
    Procs.dwFlags = dwFlags;
    Procs.lParam = lParam;

    return NLS_EnumSystemLanguageGroups(pLangGrpEnumProc ? &Procs : NULL);
}

/******************************************************************************
 *           IsValidLanguageGroup    (KERNEL32.@)
 *
 * Determine if a language group is supported and/or installed.
 *
 * PARAMS
 *  lgrpid  [I] Language Group Id (LGRPID_ values from "winnls.h")
 *  dwFlags [I] LGRPID_SUPPORTED=Supported, LGRPID_INSTALLED=Installed
 *
 * RETURNS
 *  TRUE, if lgrpid is supported and/or installed, according to dwFlags.
 *  FALSE otherwise.
 */
WINAPI BOOL IsValidLanguageGroup(LGRPID Lgrpid, DWORD dwFlags)
{
    static const WCHAR szFormat[] = { '%', 'x', '\0' };
    WCHAR szValueName[16], szValue[2];
    BOOL bSupported = FALSE, bInstalled = FALSE;
    HANDLE hKey;

    switch (dwFlags) {
    case LGRPID_INSTALLED:
    case LGRPID_SUPPORTED:

	hKey = NLS_RegOpenKey(0, szLangGroupsKeyName);

	sprintfW(szValueName, szFormat, Lgrpid);

	if (NLS_RegGetDword(hKey, szValueName, (LPDWORD)szValue)) {
	    bSupported = TRUE;

	    if (szValue[0] == '1')
		bInstalled = TRUE;
	}

	if (hKey)
	    NtClose(hKey);

	break;
    }

    if ((dwFlags == LGRPID_SUPPORTED && bSupported) ||
	(dwFlags == LGRPID_INSTALLED && bInstalled))
	return TRUE;

    return FALSE;
}

/* Callback function ptrs for EnumLanguageGrouplocalesA/W */
typedef struct {
    LANGGROUPLOCALE_ENUMPROCA ProcA;
    LANGGROUPLOCALE_ENUMPROCW ProcW;
    DWORD dwFlags;
    LGRPID Lgrpid;
    LONG_PTR lParam;
} ENUMLANGUAGEGROUPLOCALE_CALLBACKS;

/* Internal implementation of EnumLanguageGrouplocalesA/W */
static BOOL NLS_EnumLanguageGroupLocales(ENUMLANGUAGEGROUPLOCALE_CALLBACKS *lpProcs)
{
    static const WCHAR szAlternateSortsKeyName[] = { 'A', 'l', 't', 'e', 'r', 'n',
						     'a', 't', 'e', ' ', 'S', 'o',
						     'r', 't', 's', '\0' };
    WCHAR szNumber[10], szValue[4];
    HANDLE hKey;
    BOOL bContinue = TRUE, bAlternate = FALSE;
    LGRPID Lgrpid;
    ULONG ulIndex = 1; /* Ignore default entry of 1st key */

    if (!lpProcs || !lpProcs->Lgrpid || lpProcs->Lgrpid > LGRPID_ARMENIAN) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if (lpProcs->dwFlags) {
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    hKey = NLS_RegOpenKey(0, szLocaleKeyName);

    if (!hKey)
	WARN("NLS registry key not found. Please apply the default registry file "
	     "'wine.inf'\n");

    while (bContinue) {
	if (NLS_RegEnumValue(hKey, ulIndex, szNumber, sizeof(szNumber), szValue,
			     sizeof(szValue))) {
	    Lgrpid = strtoulW(szValue, NULL, 16);

	    TRACE("lcid %s, grpid %d (%smatched)\n", debugstr_w(szNumber), lgrpid,
		  lgrpid == lpProcs->lgrpid ? "" : "not ");

	    if (Lgrpid == lpProcs->Lgrpid) {
		LCID Lcid;

		Lcid = strtoulW(szNumber, NULL, 16);

		/* FIXME: native returns extra text for a few (17/150) locales, e.g:
		 * '00000437          ;Georgian'
		 * At present we only pass the LCID string.
		 */

		if (lpProcs->ProcW)
		    bContinue = lpProcs->ProcW(Lgrpid, Lcid, szNumber, lpProcs->lParam);
		else {
		    char szNumberA[sizeof(szNumber) / sizeof(WCHAR)];

		    WideCharToMultiByte(CP_ACP, 0, szNumber, -1, szNumberA,
					sizeof(szNumberA), 0, 0);

		    bContinue = lpProcs->ProcA(Lgrpid, Lcid, szNumberA, lpProcs->lParam);
		}
	    }

	    ulIndex++;
	} else {
	    /* Finished enumerating this key */
	    if (!bAlternate) {
		/* Enumerate alternate sorts also */
		hKey = NLS_RegOpenKey(hKey, szAlternateSortsKeyName);
		bAlternate = TRUE;
		ulIndex = 0;
	    } else
		bContinue = FALSE; /* Finished both keys */
	}

	if (!bContinue)
	    break;
    }

    if (hKey)
	NtClose(hKey);

    return TRUE;
}

/******************************************************************************
 *           EnumLanguageGroupLocalesA    (KERNEL32.@)
 *
 * Call a users function for every locale in a language group available on the system.
 *
 * PARAMS
 *  pLangGrpLcEnumProc [I] Callback function to call for each locale
 *  lgrpid             [I] Language group (LGRPID_ values from "winnls.h")
 *  dwFlags            [I] Reserved, set to 0
 *  lParam             [I] User parameter to pass to pLangGrpLcEnumProc
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI BOOL EnumLanguageGroupLocalesA(LANGGROUPLOCALE_ENUMPROCA pLangGrpLcEnumProc,
				      LGRPID Lgrpid, DWORD dwFlags, LONG_PTR lParam)
{
    ENUMLANGUAGEGROUPLOCALE_CALLBACKS Callbacks;

    TRACE("(%p,0x%08X,0x%08X,0x%08lX)\n", pLangGrpLcEnumProc, lgrpid, dwFlags, lParam);

    Callbacks.ProcA = pLangGrpLcEnumProc;
    Callbacks.ProcW = NULL;
    Callbacks.dwFlags = dwFlags;
    Callbacks.Lgrpid = Lgrpid;
    Callbacks.lParam = lParam;

    return NLS_EnumLanguageGroupLocales(pLangGrpLcEnumProc ? &Callbacks : NULL);
}

/******************************************************************************
 *           EnumLanguageGroupLocalesW    (KERNEL32.@)
 *
 * See EnumLanguageGroupLocalesA.
 */
WINAPI BOOL EnumLanguageGroupLocalesW(LANGGROUPLOCALE_ENUMPROCW pLangGrpLcEnumProc,
				      LGRPID Lgrpid, DWORD dwFlags, LONG_PTR lParam)
{
    ENUMLANGUAGEGROUPLOCALE_CALLBACKS Callbacks;

    TRACE("(%p,0x%08X,0x%08X,0x%08lX)\n", pLangGrpLcEnumProc, lgrpid, dwFlags, lParam);

    Callbacks.ProcA = NULL;
    Callbacks.ProcW = pLangGrpLcEnumProc;
    Callbacks.dwFlags = dwFlags;
    Callbacks.Lgrpid = Lgrpid;
    Callbacks.lParam = lParam;

    return NLS_EnumLanguageGroupLocales(pLangGrpLcEnumProc ? &Callbacks : NULL);
}

/******************************************************************************
 *           InvalidateNLSCache           (KERNEL32.@)
 *
 * Invalidate the cache of NLS values.
 *
 * PARAMS
 *  None.
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE.
 */
WINAPI BOOL InvalidateNLSCache(void)
{
    JapaneseEra_ClearCache();
    return TRUE;
}

/******************************************************************************
 *           GetUserGeoID (KERNEL32.@)
 */
WINAPI GEOID GetUserGeoID(GEOCLASS GeoClass)
{
    GEOID Ret = GEOID_NOT_AVAILABLE;
    static const WCHAR GeoW[] = { 'G', 'e', 'o', 0 };
    static const WCHAR NationW[] = { 'N', 'a', 't', 'i', 'o', 'n', 0 };
    WCHAR BufferW[40], *End;
    DWORD Count;
    HANDLE hKey, hSubkey = 0;
    UNICODE_STRING KeyW;
    const KEY_VALUE_PARTIAL_INFORMATION *Info = (KEY_VALUE_PARTIAL_INFORMATION *)BufferW;
    RtlInitUnicodeString(&KeyW, NationW);
    Count = sizeof(BufferW);

    if (!(hKey = CreateRegistryKey()))
	return Ret;

    switch (GeoClass) {
    case GEOCLASS_NATION:
	if ((hSubkey = NLS_RegOpenKey(hKey, GeoW))) {
	    if ((NtQueryValueKey(hSubkey, &KeyW, KeyValuePartialInformation, BufferW,
				 Count, &Count) == STATUS_SUCCESS) &&
		Info->DataLength)
		Ret = strtolW((LPCWSTR)Info->Data, &End, 10);
	}
	break;
    case GEOCLASS_REGION:
	FIXME("GEOCLASS_REGION not handled yet\n");
	break;
    }

    NtClose(hKey);
    if (hSubkey)
	NtClose(hSubkey);
    return Ret;
}

/******************************************************************************
 *           SetUserGeoID (KERNEL32.@)
 */
WINAPI BOOL SetUserGeoID(GEOID GeoID)
{
    static const WCHAR GeoW[] = { 'G', 'e', 'o', 0 };
    static const WCHAR NationW[] = { 'N', 'a', 't', 'i', 'o', 'n', 0 };
    static const WCHAR FormatW[] = { '%', 'i', 0 };
    UNICODE_STRING NameW, KeyW;
    WCHAR BufferW[10];
    OBJECT_ATTRIBUTES Attr;
    HANDLE hKey;

    if (!(hKey = CreateRegistryKey()))
	return FALSE;

    Attr.Length = sizeof(Attr);
    Attr.RootDirectory = hKey;
    Attr.ObjectName = &NameW;
    Attr.Attributes = 0;
    Attr.SecurityDescriptor = NULL;
    Attr.SecurityQualityOfService = NULL;
    RtlInitUnicodeString(&NameW, GeoW);
    RtlInitUnicodeString(&KeyW, NationW);

    if (NtCreateKey(&hKey, KEY_ALL_ACCESS, &Attr, 0, NULL, 0, NULL) != STATUS_SUCCESS)

    {
	NtClose(Attr.RootDirectory);
	return FALSE;
    }

    sprintfW(BufferW, FormatW, GeoID);
    NtSetValueKey(hKey, &KeyW, 0, REG_SZ, BufferW,
		  (strlenW(BufferW) + 1) * sizeof(WCHAR));
    NtClose(Attr.RootDirectory);
    NtClose(hKey);
    return TRUE;
}

typedef struct {
    union {
	UILANGUAGE_ENUMPROCA ProcA;
	UILANGUAGE_ENUMPROCW ProcW;
    } u;
    DWORD Flags;
    LONG_PTR Param;
} ENUM_UILANG_CALLBACK;

static BOOL CALLBACK EnumUilangProcA(HMODULE hModule, LPCSTR Type, LPCSTR Name,
					WORD LangID, LONG_PTR lParam)
{
    ENUM_UILANG_CALLBACK *EnumUilang = (ENUM_UILANG_CALLBACK *)lParam;
    char Buf[20];

    sprintf(Buf, "%08x", (UINT)LangID);
    return EnumUilang->u.ProcA(Buf, EnumUilang->Param);
}

static BOOL CALLBACK EnumUilangProcW(HMODULE hModule, LPCWSTR Type, LPCWSTR Name,
					WORD LangID, LONG_PTR lParam)
{
    static const WCHAR FormatW[] = { '%', '0', '8', 'x', 0 };
    ENUM_UILANG_CALLBACK *EnumUilang = (ENUM_UILANG_CALLBACK *)lParam;
    WCHAR Buf[20];

    sprintfW(Buf, FormatW, (UINT)LangID);
    return EnumUilang->u.ProcW(Buf, EnumUilang->Param);
}

/******************************************************************************
 *           EnumUILanguagesA (KERNEL32.@)
 */
WINAPI BOOL EnumUILanguagesA(UILANGUAGE_ENUMPROCA pUILangEnumProc, DWORD dwFlags,
			     LONG_PTR lParam)
{
    ENUM_UILANG_CALLBACK EnumUilang;

    TRACE("%p, %x, %lx\n", pUILangEnumProc, dwFlags, lParam);

    if (!pUILangEnumProc) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    if (dwFlags) {
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    EnumUilang.u.ProcA = pUILangEnumProc;
    EnumUilang.Flags = dwFlags;
    EnumUilang.Param = lParam;

    EnumResourceLanguagesA(Kernel32Handle, (LPCSTR)RT_STRING, (LPCSTR)LOCALE_ILANGUAGE,
			   EnumUilangProcA, (LONG_PTR)&EnumUilang);
    return TRUE;
}

/******************************************************************************
 *           EnumUILanguagesW (KERNEL32.@)
 */
WINAPI BOOL EnumUILanguagesW(UILANGUAGE_ENUMPROCW pUILangEnumProc, DWORD dwFlags,
			     LONG_PTR lParam)
{
    ENUM_UILANG_CALLBACK EnumUilang;

    TRACE("%p, %x, %lx\n", pUILangEnumProc, dwFlags, lParam);

    if (!pUILangEnumProc) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }
    if (dwFlags) {
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    EnumUilang.u.ProcW = pUILangEnumProc;
    EnumUilang.Flags = dwFlags;
    EnumUilang.Param = lParam;

    EnumResourceLanguagesW(Kernel32Handle, (LPCWSTR)RT_STRING, (LPCWSTR)LOCALE_ILANGUAGE,
			   EnumUilangProcW, (LONG_PTR)&EnumUilang);
    return TRUE;
}

enum locationkind { LOCATION_NATION = 0, LOCATION_REGION, LOCATION_BOTH };

struct GEOINFO {
    GEOID Id;
    WCHAR Iso2W[3];
    WCHAR Iso3W[4];
    GEOID Parent;
    INT Uncode;
    enum locationkind Kind;
};

static const struct GEOINFO Geoinfodata[] = {
    { 2, {'A','G',0}, {'A','T','G',0}, 10039880,  28 }, /* Antigua and Barbuda */
    { 3, {'A','F',0}, {'A','F','G',0}, 47614,   4 }, /* Afghanistan */
    { 4, {'D','Z',0}, {'D','Z','A',0}, 42487,  12 }, /* Algeria */
    { 5, {'A','Z',0}, {'A','Z','E',0}, 47611,  31 }, /* Azerbaijan */
    { 6, {'A','L',0}, {'A','L','B',0}, 47610,   8 }, /* Albania */
    { 7, {'A','M',0}, {'A','R','M',0}, 47611,  51 }, /* Armenia */
    { 8, {'A','D',0}, {'A','N','D',0}, 47610,  20 }, /* Andorra */
    { 9, {'A','O',0}, {'A','G','O',0}, 42484,  24 }, /* Angola */
    { 10, {'A','S',0}, {'A','S','M',0}, 26286,  16 }, /* American Samoa */
    { 11, {'A','R',0}, {'A','R','G',0}, 31396,  32 }, /* Argentina */
    { 12, {'A','U',0}, {'A','U','S',0}, 10210825,  36 }, /* Australia */
    { 14, {'A','T',0}, {'A','U','T',0}, 10210824,  40 }, /* Austria */
    { 17, {'B','H',0}, {'B','H','R',0}, 47611,  48 }, /* Bahrain */
    { 18, {'B','B',0}, {'B','R','B',0}, 10039880,  52 }, /* Barbados */
    { 19, {'B','W',0}, {'B','W','A',0}, 10039883,  72 }, /* Botswana */
    { 20, {'B','M',0}, {'B','M','U',0}, 23581,  60 }, /* Bermuda */
    { 21, {'B','E',0}, {'B','E','L',0}, 10210824,  56 }, /* Belgium */
    { 22, {'B','S',0}, {'B','H','S',0}, 10039880,  44 }, /* Bahamas, The */
    { 23, {'B','D',0}, {'B','G','D',0}, 47614,  50 }, /* Bangladesh */
    { 24, {'B','Z',0}, {'B','L','Z',0}, 27082,  84 }, /* Belize */
    { 25, {'B','A',0}, {'B','I','H',0}, 47610,  70 }, /* Bosnia and Herzegovina */
    { 26, {'B','O',0}, {'B','O','L',0}, 31396,  68 }, /* Bolivia */
    { 27, {'M','M',0}, {'M','M','R',0}, 47599, 104 }, /* Myanmar */
    { 28, {'B','J',0}, {'B','E','N',0}, 42483, 204 }, /* Benin */
    { 29, {'B','Y',0}, {'B','L','R',0}, 47609, 112 }, /* Belarus */
    { 30, {'S','B',0}, {'S','L','B',0}, 20900,  90 }, /* Solomon Islands */
    { 32, {'B','R',0}, {'B','R','A',0}, 31396,  76 }, /* Brazil */
    { 34, {'B','T',0}, {'B','T','N',0}, 47614,  64 }, /* Bhutan */
    { 35, {'B','G',0}, {'B','G','R',0}, 47609, 100 }, /* Bulgaria */
    { 37, {'B','N',0}, {'B','R','N',0}, 47599,  96 }, /* Brunei */
    { 38, {'B','I',0}, {'B','D','I',0}, 47603, 108 }, /* Burundi */
    { 39, {'C','A',0}, {'C','A','N',0}, 23581, 124 }, /* Canada */
    { 40, {'K','H',0}, {'K','H','M',0}, 47599, 116 }, /* Cambodia */
    { 41, {'T','D',0}, {'T','C','D',0}, 42484, 148 }, /* Chad */
    { 42, {'L','K',0}, {'L','K','A',0}, 47614, 144 }, /* Sri Lanka */
    { 43, {'C','G',0}, {'C','O','G',0}, 42484, 178 }, /* Congo */
    { 44, {'C','D',0}, {'C','O','D',0}, 42484, 180 }, /* Congo (DRC) */
    { 45, {'C','N',0}, {'C','H','N',0}, 47600, 156 }, /* China */
    { 46, {'C','L',0}, {'C','H','L',0}, 31396, 152 }, /* Chile */
    { 49, {'C','M',0}, {'C','M','R',0}, 42484, 120 }, /* Cameroon */
    { 50, {'K','M',0}, {'C','O','M',0}, 47603, 174 }, /* Comoros */
    { 51, {'C','O',0}, {'C','O','L',0}, 31396, 170 }, /* Colombia */
    { 54, {'C','R',0}, {'C','R','I',0}, 27082, 188 }, /* Costa Rica */
    { 55, {'C','F',0}, {'C','A','F',0}, 42484, 140 }, /* Central African Republic */
    { 56, {'C','U',0}, {'C','U','B',0}, 10039880, 192 }, /* Cuba */
    { 57, {'C','V',0}, {'C','P','V',0}, 42483, 132 }, /* Cape Verde */
    { 59, {'C','Y',0}, {'C','Y','P',0}, 47611, 196 }, /* Cyprus */
    { 61, {'D','K',0}, {'D','N','K',0}, 10039882, 208 }, /* Denmark */
    { 62, {'D','J',0}, {'D','J','I',0}, 47603, 262 }, /* Djibouti */
    { 63, {'D','M',0}, {'D','M','A',0}, 10039880, 212 }, /* Dominica */
    { 65, {'D','O',0}, {'D','O','M',0}, 10039880, 214 }, /* Dominican Republic */
    { 66, {'E','C',0}, {'E','C','U',0}, 31396, 218 }, /* Ecuador */
    { 67, {'E','G',0}, {'E','G','Y',0}, 42487, 818 }, /* Egypt */
    { 68, {'I','E',0}, {'I','R','L',0}, 10039882, 372 }, /* Ireland */
    { 69, {'G','Q',0}, {'G','N','Q',0}, 42484, 226 }, /* Equatorial Guinea */
    { 70, {'E','E',0}, {'E','S','T',0}, 10039882, 233 }, /* Estonia */
    { 71, {'E','R',0}, {'E','R','I',0}, 47603, 232 }, /* Eritrea */
    { 72, {'S','V',0}, {'S','L','V',0}, 27082, 222 }, /* El Salvador */
    { 73, {'E','T',0}, {'E','T','H',0}, 47603, 231 }, /* Ethiopia */
    { 75, {'C','Z',0}, {'C','Z','E',0}, 47609, 203 }, /* Czech Republic */
    { 77, {'F','I',0}, {'F','I','N',0}, 10039882, 246 }, /* Finland */
    { 78, {'F','J',0}, {'F','J','I',0}, 20900, 242 }, /* Fiji Islands */
    { 80, {'F','M',0}, {'F','S','M',0}, 21206, 583 }, /* Micronesia */
    { 81, {'F','O',0}, {'F','R','O',0}, 10039882, 234 }, /* Faroe Islands */
    { 84, {'F','R',0}, {'F','R','A',0}, 10210824, 250 }, /* France */
    { 86, {'G','M',0}, {'G','M','B',0}, 42483, 270 }, /* Gambia, The */
    { 87, {'G','A',0}, {'G','A','B',0}, 42484, 266 }, /* Gabon */
    { 88, {'G','E',0}, {'G','E','O',0}, 47611, 268 }, /* Georgia */
    { 89, {'G','H',0}, {'G','H','A',0}, 42483, 288 }, /* Ghana */
    { 90, {'G','I',0}, {'G','I','B',0}, 47610, 292 }, /* Gibraltar */
    { 91, {'G','D',0}, {'G','R','D',0}, 10039880, 308 }, /* Grenada */
    { 93, {'G','L',0}, {'G','R','L',0}, 23581, 304 }, /* Greenland */
    { 94, {'D','E',0}, {'D','E','U',0}, 10210824, 276 }, /* Germany */
    { 98, {'G','R',0}, {'G','R','C',0}, 47610, 300 }, /* Greece */
    { 99, {'G','T',0}, {'G','T','M',0}, 27082, 320 }, /* Guatemala */
    { 100, {'G','N',0}, {'G','I','N',0}, 42483, 324 }, /* Guinea */
    { 101, {'G','Y',0}, {'G','U','Y',0}, 31396, 328 }, /* Guyana */
    { 103, {'H','T',0}, {'H','T','I',0}, 10039880, 332 }, /* Haiti */
    { 104, {'H','K',0}, {'H','K','G',0}, 47600, 344 }, /* Hong Kong S.A.R. */
    { 106, {'H','N',0}, {'H','N','D',0}, 27082, 340 }, /* Honduras */
    { 108, {'H','R',0}, {'H','R','V',0}, 47610, 191 }, /* Croatia */
    { 109, {'H','U',0}, {'H','U','N',0}, 47609, 348 }, /* Hungary */
    { 110, {'I','S',0}, {'I','S','L',0}, 10039882, 352 }, /* Iceland */
    { 111, {'I','D',0}, {'I','D','N',0}, 47599, 360 }, /* Indonesia */
    { 113, {'I','N',0}, {'I','N','D',0}, 47614, 356 }, /* India */
    { 114, {'I','O',0}, {'I','O','T',0}, 39070,  86 }, /* British Indian Ocean Territory */
    { 116, {'I','R',0}, {'I','R','N',0}, 47614, 364 }, /* Iran */
    { 117, {'I','L',0}, {'I','S','R',0}, 47611, 376 }, /* Israel */
    { 118, {'I','T',0}, {'I','T','A',0}, 47610, 380 }, /* Italy */
    { 119, {'C','I',0}, {'C','I','V',0}, 42483, 384 }, /* Côte d'Ivoire */
    { 121, {'I','Q',0}, {'I','R','Q',0}, 47611, 368 }, /* Iraq */
    { 122, {'J','P',0}, {'J','P','N',0}, 47600, 392 }, /* Japan */
    { 124, {'J','M',0}, {'J','A','M',0}, 10039880, 388 }, /* Jamaica */
    { 125, {'S','J',0}, {'S','J','M',0}, 10039882, 744 }, /* Jan Mayen */
    { 126, {'J','O',0}, {'J','O','R',0}, 47611, 400 }, /* Jordan */
    { 127, {'X','X',0}, {'X','X',0}, 161832256 }, /* Johnston Atoll */
    { 129, {'K','E',0}, {'K','E','N',0}, 47603, 404 }, /* Kenya */
    { 130, {'K','G',0}, {'K','G','Z',0}, 47590, 417 }, /* Kyrgyzstan */
    { 131, {'K','P',0}, {'P','R','K',0}, 47600, 408 }, /* North Korea */
    { 133, {'K','I',0}, {'K','I','R',0}, 21206, 296 }, /* Kiribati */
    { 134, {'K','R',0}, {'K','O','R',0}, 47600, 410 }, /* Korea */
    { 136, {'K','W',0}, {'K','W','T',0}, 47611, 414 }, /* Kuwait */
    { 137, {'K','Z',0}, {'K','A','Z',0}, 47590, 398 }, /* Kazakhstan */
    { 138, {'L','A',0}, {'L','A','O',0}, 47599, 418 }, /* Laos */
    { 139, {'L','B',0}, {'L','B','N',0}, 47611, 422 }, /* Lebanon */
    { 140, {'L','V',0}, {'L','V','A',0}, 10039882, 428 }, /* Latvia */
    { 141, {'L','T',0}, {'L','T','U',0}, 10039882, 440 }, /* Lithuania */
    { 142, {'L','R',0}, {'L','B','R',0}, 42483, 430 }, /* Liberia */
    { 143, {'S','K',0}, {'S','V','K',0}, 47609, 703 }, /* Slovakia */
    { 145, {'L','I',0}, {'L','I','E',0}, 10210824, 438 }, /* Liechtenstein */
    { 146, {'L','S',0}, {'L','S','O',0}, 10039883, 426 }, /* Lesotho */
    { 147, {'L','U',0}, {'L','U','X',0}, 10210824, 442 }, /* Luxembourg */
    { 148, {'L','Y',0}, {'L','B','Y',0}, 42487, 434 }, /* Libya */
    { 149, {'M','G',0}, {'M','D','G',0}, 47603, 450 }, /* Madagascar */
    { 151, {'M','O',0}, {'M','A','C',0}, 47600, 446 }, /* Macao S.A.R. */
    { 152, {'M','D',0}, {'M','D','A',0}, 47609, 498 }, /* Moldova */
    { 154, {'M','N',0}, {'M','N','G',0}, 47600, 496 }, /* Mongolia */
    { 156, {'M','W',0}, {'M','W','I',0}, 47603, 454 }, /* Malawi */
    { 157, {'M','L',0}, {'M','L','I',0}, 42483, 466 }, /* Mali */
    { 158, {'M','C',0}, {'M','C','O',0}, 10210824, 492 }, /* Monaco */
    { 159, {'M','A',0}, {'M','A','R',0}, 42487, 504 }, /* Morocco */
    { 160, {'M','U',0}, {'M','U','S',0}, 47603, 480 }, /* Mauritius */
    { 162, {'M','R',0}, {'M','R','T',0}, 42483, 478 }, /* Mauritania */
    { 163, {'M','T',0}, {'M','L','T',0}, 47610, 470 }, /* Malta */
    { 164, {'O','M',0}, {'O','M','N',0}, 47611, 512 }, /* Oman */
    { 165, {'M','V',0}, {'M','D','V',0}, 47614, 462 }, /* Maldives */
    { 166, {'M','X',0}, {'M','E','X',0}, 27082, 484 }, /* Mexico */
    { 167, {'M','Y',0}, {'M','Y','S',0}, 47599, 458 }, /* Malaysia */
    { 168, {'M','Z',0}, {'M','O','Z',0}, 47603, 508 }, /* Mozambique */
    { 173, {'N','E',0}, {'N','E','R',0}, 42483, 562 }, /* Niger */
    { 174, {'V','U',0}, {'V','U','T',0}, 20900, 548 }, /* Vanuatu */
    { 175, {'N','G',0}, {'N','G','A',0}, 42483, 566 }, /* Nigeria */
    { 176, {'N','L',0}, {'N','L','D',0}, 10210824, 528 }, /* Netherlands */
    { 177, {'N','O',0}, {'N','O','R',0}, 10039882, 578 }, /* Norway */
    { 178, {'N','P',0}, {'N','P','L',0}, 47614, 524 }, /* Nepal */
    { 180, {'N','R',0}, {'N','R','U',0}, 21206, 520 }, /* Nauru */
    { 181, {'S','R',0}, {'S','U','R',0}, 31396, 740 }, /* Suriname */
    { 182, {'N','I',0}, {'N','I','C',0}, 27082, 558 }, /* Nicaragua */
    { 183, {'N','Z',0}, {'N','Z','L',0}, 10210825, 554 }, /* New Zealand */
    { 184, {'P','S',0}, {'P','S','E',0}, 47611, 275 }, /* Palestinian Authority */
    { 185, {'P','Y',0}, {'P','R','Y',0}, 31396, 600 }, /* Paraguay */
    { 187, {'P','E',0}, {'P','E','R',0}, 31396, 604 }, /* Peru */
    { 190, {'P','K',0}, {'P','A','K',0}, 47614, 586 }, /* Pakistan */
    { 191, {'P','L',0}, {'P','O','L',0}, 47609, 616 }, /* Poland */
    { 192, {'P','A',0}, {'P','A','N',0}, 27082, 591 }, /* Panama */
    { 193, {'P','T',0}, {'P','R','T',0}, 47610, 620 }, /* Portugal */
    { 194, {'P','G',0}, {'P','N','G',0}, 20900, 598 }, /* Papua New Guinea */
    { 195, {'P','W',0}, {'P','L','W',0}, 21206, 585 }, /* Palau */
    { 196, {'G','W',0}, {'G','N','B',0}, 42483, 624 }, /* Guinea-Bissau */
    { 197, {'Q','A',0}, {'Q','A','T',0}, 47611, 634 }, /* Qatar */
    { 198, {'R','E',0}, {'R','E','U',0}, 47603, 638 }, /* Reunion */
    { 199, {'M','H',0}, {'M','H','L',0}, 21206, 584 }, /* Marshall Islands */
    { 200, {'R','O',0}, {'R','O','U',0}, 47609, 642 }, /* Romania */
    { 201, {'P','H',0}, {'P','H','L',0}, 47599, 608 }, /* Philippines */
    { 202, {'P','R',0}, {'P','R','I',0}, 10039880, 630 }, /* Puerto Rico */
    { 203, {'R','U',0}, {'R','U','S',0}, 47609, 643 }, /* Russia */
    { 204, {'R','W',0}, {'R','W','A',0}, 47603, 646 }, /* Rwanda */
    { 205, {'S','A',0}, {'S','A','U',0}, 47611, 682 }, /* Saudi Arabia */
    { 206, {'P','M',0}, {'S','P','M',0}, 23581, 666 }, /* St. Pierre and Miquelon */
    { 207, {'K','N',0}, {'K','N','A',0}, 10039880, 659 }, /* St. Kitts and Nevis */
    { 208, {'S','C',0}, {'S','Y','C',0}, 47603, 690 }, /* Seychelles */
    { 209, {'Z','A',0}, {'Z','A','F',0}, 10039883, 710 }, /* South Africa */
    { 210, {'S','N',0}, {'S','E','N',0}, 42483, 686 }, /* Senegal */
    { 212, {'S','I',0}, {'S','V','N',0}, 47610, 705 }, /* Slovenia */
    { 213, {'S','L',0}, {'S','L','E',0}, 42483, 694 }, /* Sierra Leone */
    { 214, {'S','M',0}, {'S','M','R',0}, 47610, 674 }, /* San Marino */
    { 215, {'S','G',0}, {'S','G','P',0}, 47599, 702 }, /* Singapore */
    { 216, {'S','O',0}, {'S','O','M',0}, 47603, 706 }, /* Somalia */
    { 217, {'E','S',0}, {'E','S','P',0}, 47610, 724 }, /* Spain */
    { 218, {'L','C',0}, {'L','C','A',0}, 10039880, 662 }, /* St. Lucia */
    { 219, {'S','D',0}, {'S','D','N',0}, 42487, 736 }, /* Sudan */
    { 220, {'S','J',0}, {'S','J','M',0}, 10039882, 744 }, /* Svalbard */
    { 221, {'S','E',0}, {'S','W','E',0}, 10039882, 752 }, /* Sweden */
    { 222, {'S','Y',0}, {'S','Y','R',0}, 47611, 760 }, /* Syria */
    { 223, {'C','H',0}, {'C','H','E',0}, 10210824, 756 }, /* Switzerland */
    { 224, {'A','E',0}, {'A','R','E',0}, 47611, 784 }, /* United Arab Emirates */
    { 225, {'T','T',0}, {'T','T','O',0}, 10039880, 780 }, /* Trinidad and Tobago */
    { 227, {'T','H',0}, {'T','H','A',0}, 47599, 764 }, /* Thailand */
    { 228, {'T','J',0}, {'T','J','K',0}, 47590, 762 }, /* Tajikistan */
    { 231, {'T','O',0}, {'T','O','N',0}, 26286, 776 }, /* Tonga */
    { 232, {'T','G',0}, {'T','G','O',0}, 42483, 768 }, /* Togo */
    { 233, {'S','T',0}, {'S','T','P',0}, 42484, 678 }, /* São Tomé and Príncipe */
    { 234, {'T','N',0}, {'T','U','N',0}, 42487, 788 }, /* Tunisia */
    { 235, {'T','R',0}, {'T','U','R',0}, 47611, 792 }, /* Turkey */
    { 236, {'T','V',0}, {'T','U','V',0}, 26286, 798 }, /* Tuvalu */
    { 237, {'T','W',0}, {'T','W','N',0}, 47600, 158 }, /* Taiwan */
    { 238, {'T','M',0}, {'T','K','M',0}, 47590, 795 }, /* Turkmenistan */
    { 239, {'T','Z',0}, {'T','Z','A',0}, 47603, 834 }, /* Tanzania */
    { 240, {'U','G',0}, {'U','G','A',0}, 47603, 800 }, /* Uganda */
    { 241, {'U','A',0}, {'U','K','R',0}, 47609, 804 }, /* Ukraine */
    { 242, {'G','B',0}, {'G','B','R',0}, 10039882, 826 }, /* United Kingdom */
    { 244, {'U','S',0}, {'U','S','A',0}, 23581, 840 }, /* United States */
    { 245, {'B','F',0}, {'B','F','A',0}, 42483, 854 }, /* Burkina Faso */
    { 246, {'U','Y',0}, {'U','R','Y',0}, 31396, 858 }, /* Uruguay */
    { 247, {'U','Z',0}, {'U','Z','B',0}, 47590, 860 }, /* Uzbekistan */
    { 248, {'V','C',0}, {'V','C','T',0}, 10039880, 670 }, /* St. Vincent and the Grenadines */
    { 249, {'V','E',0}, {'V','E','N',0}, 31396, 862 }, /* Bolivarian Republic of Venezuela */
    { 251, {'V','N',0}, {'V','N','M',0}, 47599, 704 }, /* Vietnam */
    { 252, {'V','I',0}, {'V','I','R',0}, 10039880, 850 }, /* Virgin Islands */
    { 253, {'V','A',0}, {'V','A','T',0}, 47610, 336 }, /* Vatican City */
    { 254, {'N','A',0}, {'N','A','M',0}, 10039883, 516 }, /* Namibia */
    { 257, {'E','H',0}, {'E','S','H',0}, 42487, 732 }, /* Western Sahara (disputed) */
    { 258, {'X','X',0}, {'X','X',0}, 161832256 }, /* Wake Island */
    { 259, {'W','S',0}, {'W','S','M',0}, 26286, 882 }, /* Samoa */
    { 260, {'S','Z',0}, {'S','W','Z',0}, 10039883, 748 }, /* Swaziland */
    { 261, {'Y','E',0}, {'Y','E','M',0}, 47611, 887 }, /* Yemen */
    { 263, {'Z','M',0}, {'Z','M','B',0}, 47603, 894 }, /* Zambia */
    { 264, {'Z','W',0}, {'Z','W','E',0}, 47603, 716 }, /* Zimbabwe */
    { 269, {'C','S',0}, {'S','C','G',0}, 47610, 891 }, /* Serbia and Montenegro (Former) */
    { 270, {'M','E',0}, {'M','N','E',0}, 47610, 499 }, /* Montenegro */
    { 271, {'R','S',0}, {'S','R','B',0}, 47610, 688 }, /* Serbia */
    { 273, {'C','W',0}, {'C','U','W',0}, 10039880, 531 }, /* Curaçao */
    { 276, {'S','S',0}, {'S','S','D',0}, 42487, 728 }, /* South Sudan */
    { 300, {'A','I',0}, {'A','I','A',0}, 10039880, 660 }, /* Anguilla */
    { 301, {'A','Q',0}, {'A','T','A',0}, 39070,  10 }, /* Antarctica */
    { 302, {'A','W',0}, {'A','B','W',0}, 10039880, 533 }, /* Aruba */
    { 303, {'X','X',0}, {'X','X',0}, 39070 }, /* Ascension Island */
    { 304, {'X','X',0}, {'X','X',0}, 10210825 }, /* Ashmore and Cartier Islands */
    { 305, {'X','X',0}, {'X','X',0}, 161832256 }, /* Baker Island */
    { 306, {'B','V',0}, {'B','V','T',0}, 39070,  74 }, /* Bouvet Island */
    { 307, {'K','Y',0}, {'C','Y','M',0}, 10039880, 136 }, /* Cayman Islands */
    { 308, {'X','X',0}, {'X','X',0}, 10210824, 0, LOCATION_BOTH }, /* Channel Islands */
    { 309, {'C','X',0}, {'C','X','R',0}, 12, 162 }, /* Christmas Island */
    { 310, {'X','X',0}, {'X','X',0}, 27114 }, /* Clipperton Island */
    { 311, {'C','C',0}, {'C','C','K',0}, 10210825, 166 }, /* Cocos (Keeling) Islands */
    { 312, {'C','K',0}, {'C','O','K',0}, 26286, 184 }, /* Cook Islands */
    { 313, {'X','X',0}, {'X','X',0}, 10210825 }, /* Coral Sea Islands */
    { 314, {'X','X',0}, {'X','X',0}, 114 }, /* Diego Garcia */
    { 315, {'F','K',0}, {'F','L','K',0}, 31396, 238 }, /* Falkland Islands (Islas Malvinas) */
    { 317, {'G','F',0}, {'G','U','F',0}, 31396, 254 }, /* French Guiana */
    { 318, {'P','F',0}, {'P','Y','F',0}, 26286, 258 }, /* French Polynesia */
    { 319, {'T','F',0}, {'A','T','F',0}, 39070, 260 }, /* French Southern and Antarctic Lands */
    { 321, {'G','P',0}, {'G','L','P',0}, 10039880, 312 }, /* Guadeloupe */
    { 322, {'G','U',0}, {'G','U','M',0}, 21206, 316 }, /* Guam */
    { 323, {'X','X',0}, {'X','X',0}, 39070 }, /* Guantanamo Bay */
    { 324, {'G','G',0}, {'G','G','Y',0}, 308, 831 }, /* Guernsey */
    { 325, {'H','M',0}, {'H','M','D',0}, 39070, 334 }, /* Heard Island and McDonald Islands */
    { 326, {'X','X',0}, {'X','X',0}, 161832256 }, /* Howland Island */
    { 327, {'X','X',0}, {'X','X',0}, 161832256 }, /* Jarvis Island */
    { 328, {'J','E',0}, {'J','E','Y',0}, 308, 832 }, /* Jersey */
    { 329, {'X','X',0}, {'X','X',0}, 161832256 }, /* Kingman Reef */
    { 330, {'M','Q',0}, {'M','T','Q',0}, 10039880, 474 }, /* Martinique */
    { 331, {'Y','T',0}, {'M','Y','T',0}, 47603, 175 }, /* Mayotte */
    { 332, {'M','S',0}, {'M','S','R',0}, 10039880, 500 }, /* Montserrat */
    { 333, {'A','N',0}, {'A','N','T',0}, 10039880, 530, LOCATION_BOTH }, /* Netherlands Antilles (Former) */
    { 334, {'N','C',0}, {'N','C','L',0}, 20900, 540 }, /* New Caledonia */
    { 335, {'N','U',0}, {'N','I','U',0}, 26286, 570 }, /* Niue */
    { 336, {'N','F',0}, {'N','F','K',0}, 10210825, 574 }, /* Norfolk Island */
    { 337, {'M','P',0}, {'M','N','P',0}, 21206, 580 }, /* Northern Mariana Islands */
    { 338, {'X','X',0}, {'X','X',0}, 161832256 }, /* Palmyra Atoll */
    { 339, {'P','N',0}, {'P','C','N',0}, 26286, 612 }, /* Pitcairn Islands */
    { 340, {'X','X',0}, {'X','X',0}, 337 }, /* Rota Island */
    { 341, {'X','X',0}, {'X','X',0}, 337 }, /* Saipan */
    { 342, {'G','S',0}, {'S','G','S',0}, 39070, 239 }, /* South Georgia and the South Sandwich Islands */
    { 343, {'S','H',0}, {'S','H','N',0}, 42483, 654 }, /* St. Helena */
    { 346, {'X','X',0}, {'X','X',0}, 337 }, /* Tinian Island */
    { 347, {'T','K',0}, {'T','K','L',0}, 26286, 772 }, /* Tokelau */
    { 348, {'X','X',0}, {'X','X',0}, 39070 }, /* Tristan da Cunha */
    { 349, {'T','C',0}, {'T','C','A',0}, 10039880, 796 }, /* Turks and Caicos Islands */
    { 351, {'V','G',0}, {'V','G','B',0}, 10039880,  92 }, /* Virgin Islands, British */
    { 352, {'W','F',0}, {'W','L','F',0}, 26286, 876 }, /* Wallis and Futuna */
    { 742, {'X','X',0}, {'X','X',0}, 39070, 0, LOCATION_REGION }, /* Africa */
    { 2129, {'X','X',0}, {'X','X',0}, 39070, 0, LOCATION_REGION }, /* Asia */
    { 10541, {'X','X',0}, {'X','X',0}, 39070, 0, LOCATION_REGION }, /* Europe */
    { 15126, {'I','M',0}, {'I','M','N',0}, 10039882, 833 }, /* Man, Isle of */
    { 19618, {'M','K',0}, {'M','K','D',0}, 47610, 807 }, /* Macedonia, Former Yugoslav Republic of */
    { 20900, {'X','X',0}, {'X','X',0}, 27114, 0, LOCATION_REGION }, /* Melanesia */
    { 21206, {'X','X',0}, {'X','X',0}, 27114, 0, LOCATION_REGION }, /* Micronesia */
    { 21242, {'X','X',0}, {'X','X',0}, 161832256 }, /* Midway Islands */
    { 23581, {'X','X',0}, {'X','X',0}, 10026358, 0, LOCATION_REGION }, /* Northern America */
    { 26286, {'X','X',0}, {'X','X',0}, 27114, 0, LOCATION_REGION }, /* Polynesia */
    { 27082, {'X','X',0}, {'X','X',0}, 161832257, 0, LOCATION_REGION }, /* Central America */
    { 27114, {'X','X',0}, {'X','X',0}, 39070, 0, LOCATION_REGION }, /* Oceania */
    { 30967, {'S','X',0}, {'S','X','M',0}, 10039880, 534 }, /* Sint Maarten (Dutch part) */
    { 31396, {'X','X',0}, {'X','X',0}, 161832257, 0, LOCATION_REGION }, /* South America */
    { 31706, {'M','F',0}, {'M','A','F',0}, 10039880, 663 }, /* Saint Martin (French part) */
    { 39070, {'X','X',0}, {'X','X',0}, 39070, 0, LOCATION_REGION }, /* World */
    { 42483, {'X','X',0}, {'X','X',0}, 742, 0, LOCATION_REGION }, /* Western Africa */
    { 42484, {'X','X',0}, {'X','X',0}, 742, 0, LOCATION_REGION }, /* Middle Africa */
    { 42487, {'X','X',0}, {'X','X',0}, 742, 0, LOCATION_REGION }, /* Northern Africa */
    { 47590, {'X','X',0}, {'X','X',0}, 2129, 0, LOCATION_REGION }, /* Central Asia */
    { 47599, {'X','X',0}, {'X','X',0}, 2129, 0, LOCATION_REGION }, /* South-Eastern Asia */
    { 47600, {'X','X',0}, {'X','X',0}, 2129, 0, LOCATION_REGION }, /* Eastern Asia */
    { 47603, {'X','X',0}, {'X','X',0}, 742, 0, LOCATION_REGION }, /* Eastern Africa */
    { 47609, {'X','X',0}, {'X','X',0}, 10541, 0, LOCATION_REGION }, /* Eastern Europe */
    { 47610, {'X','X',0}, {'X','X',0}, 10541, 0, LOCATION_REGION }, /* Southern Europe */
    { 47611, {'X','X',0}, {'X','X',0}, 2129, 0, LOCATION_REGION }, /* Middle East */
    { 47614, {'X','X',0}, {'X','X',0}, 2129, 0, LOCATION_REGION }, /* Southern Asia */
    { 7299303, {'T','L',0}, {'T','L','S',0}, 47599, 626 }, /* Democratic Republic of Timor-Leste */
    { 10026358, {'X','X',0}, {'X','X',0}, 39070, 0, LOCATION_REGION }, /* Americas */
    { 10028789, {'A','X',0}, {'A','L','A',0}, 10039882, 248 }, /* Åland Islands */
    { 10039880, {'X','X',0}, {'X','X',0}, 161832257, 0, LOCATION_REGION }, /* Caribbean */
    { 10039882, {'X','X',0}, {'X','X',0}, 10541, 0, LOCATION_REGION }, /* Northern Europe */
    { 10039883, {'X','X',0}, {'X','X',0}, 742, 0, LOCATION_REGION }, /* Southern Africa */
    { 10210824, {'X','X',0}, {'X','X',0}, 10541, 0, LOCATION_REGION }, /* Western Europe */
    { 10210825, {'X','X',0}, {'X','X',0}, 27114, 0, LOCATION_REGION }, /* Australia and New Zealand */
    { 161832015, {'B','L',0}, {'B','L','M',0}, 10039880, 652 }, /* Saint Barthélemy */
    { 161832256, {'U','M',0}, {'U','M','I',0}, 27114, 581 }, /* U.S. Minor Outlying Islands */
    { 161832257, {'X','X',0}, {'X','X',0}, 10026358, 0, LOCATION_REGION }, /* Latin America and the Caribbean */
};

/* Callback function ptrs for EnumSystemCodePagesA/W */
typedef struct {
    CODEPAGE_ENUMPROCA ProcA;
    CODEPAGE_ENUMPROCW ProcW;
    DWORD dwFlags;
} ENUMSYSTEMCODEPAGES_CALLBACKS;

/* Internal implementation of EnumSystemCodePagesA/W */
static BOOL NLS_EnumSystemCodePages(ENUMSYSTEMCODEPAGES_CALLBACKS *lpProcs)
{
    WCHAR szNumber[5 + 1], szValue[MAX_PATH];
    HANDLE hKey;
    BOOL bContinue = TRUE;
    ULONG ulIndex = 0;

    if (!lpProcs) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    switch (lpProcs->dwFlags) {
    case CP_INSTALLED:
    case CP_SUPPORTED:
	break;
    default:
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    hKey = NLS_RegOpenKey(0, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\N"
			     L"LS\\CodePage");
    if (!hKey) {
	WARN("NLS_RegOpenKey() failed\n");
	return FALSE;
    }

    while (bContinue) {
	if (NLS_RegEnumValue(hKey, ulIndex, szNumber, sizeof(szNumber), szValue,
			     sizeof(szValue))) {
	    if ((lpProcs->dwFlags == CP_SUPPORTED) ||
		((lpProcs->dwFlags == CP_INSTALLED) && (wcslen(szValue) > 2))) {
		if (lpProcs->ProcW) {
		    bContinue = lpProcs->ProcW(szNumber);
		} else {
		    char szNumberA[sizeof(szNumber) / sizeof(WCHAR)];

		    WideCharToMultiByte(CP_ACP, 0, szNumber, -1, szNumberA,
					sizeof(szNumberA), 0, 0);
		    bContinue = lpProcs->ProcA(szNumberA);
		}
	    }

	    ulIndex++;

	} else
	    bContinue = FALSE;

	if (!bContinue)
	    break;
    }

    if (hKey)
	NtClose(hKey);

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL EnumSystemCodePagesW(CODEPAGE_ENUMPROCW lpCodePageEnumProc, DWORD dwFlags)
{
    ENUMSYSTEMCODEPAGES_CALLBACKS Procs;

    TRACE("(%p,0x%08X)\n", lpCodePageEnumProc, dwFlags);

    Procs.ProcA = NULL;
    Procs.ProcW = lpCodePageEnumProc;
    Procs.dwFlags = dwFlags;

    return NLS_EnumSystemCodePages(lpCodePageEnumProc ? &Procs : NULL);
}

/*
 * @implemented
 */
WINAPI BOOL EnumSystemCodePagesA(CODEPAGE_ENUMPROCA lpCodePageEnumProc, DWORD dwFlags)
{
    ENUMSYSTEMCODEPAGES_CALLBACKS Procs;

    TRACE("(%p,0x%08X)\n", lpCodePageEnumProc, dwFlags);

    Procs.ProcA = lpCodePageEnumProc;
    Procs.ProcW = NULL;
    Procs.dwFlags = dwFlags;

    return NLS_EnumSystemCodePages(lpCodePageEnumProc ? &Procs : NULL);
}

static int NLS_GetGeoFriendlyName(GEOID Location, LPWSTR szFriendlyName, int cchData,
				  LANGID Lang)
{
    /* FIXME: move *.nls resources out of kernel32 into locale.nls */
    Location += NLSRC_OFFSET;
    Location &= 0xFFFF;

    if (cchData == 0)
	return GetLocalisedText(Location, NULL, 0, Lang);

    if (GetLocalisedText(Location, szFriendlyName, (UINT)cchData, Lang))
	return strlenW(szFriendlyName) + 1;

    return 0;
}

static const struct GEOINFO *GetGeoinfoDataptr(GEOID Geoid)
{
    int Min, Max;

    Min = 0;
    Max = sizeof(Geoinfodata) / sizeof(struct GEOINFO) - 1;

    while (Min <= Max) {
	const struct GEOINFO *Ptr;
	int n = (Min + Max) / 2;

	Ptr = &Geoinfodata[n];
	if (Geoid == Ptr->Id)
	    /* we don't need empty entries */
	    return *Ptr->Iso2W ? Ptr : NULL;

	if (Ptr->Id > Geoid)
	    Max = n - 1;
	else
	    Min = n + 1;
    }

    return NULL;
}

/******************************************************************************
 *           GetGeoInfoW (KERNEL32.@)
 */
WINAPI INT GetGeoInfoW(GEOID Geoid, GEOTYPE Geotype, LPWSTR Data, int DataLen,
		       LANGID Lang)
{
    const struct GEOINFO *Ptr;
    const WCHAR *Str = NULL;
    WCHAR BuffW[12];
    LONG Val = 0;
    INT Len;

    TRACE("%d %d %p %d %d\n", geoid, geotype, data, data_len, lang);

    if (!(Ptr = GetGeoinfoDataptr(Geoid))) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return 0;
    }

    switch (Geotype) {
    case GEO_FRIENDLYNAME: {
	return NLS_GetGeoFriendlyName(Geoid, Data, DataLen, Lang);
    }
    case GEO_NATION:
	Val = Geoid;
	break;
    case GEO_ISO_UN_NUMBER:
	Val = Ptr->Uncode;
	break;
    case GEO_PARENT:
	Val = Ptr->Parent;
	break;
    case GEO_ISO2:
    case GEO_ISO3: {
	Str = Geotype == GEO_ISO2 ? Ptr->Iso2W : Ptr->Iso3W;
	break;
    }
    case GEO_RFC1766:
    case GEO_LCID:
    case GEO_OFFICIALNAME:
    case GEO_TIMEZONES:
    case GEO_OFFICIALLANGUAGES:
    case GEO_LATITUDE:
    case GEO_LONGITUDE:
	FIXME("type %d is not supported\n", geotype);
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return 0;
    default:
	WARN("unrecognized type %d\n", geotype);
	SetLastError(ERROR_INVALID_FLAGS);
	return 0;
    }

    if (Val) {
	static const WCHAR FmtW[] = { '%', 'd', 0 };
	sprintfW(BuffW, FmtW, Val);
	Str = BuffW;
    }

    Len = strlenW(Str) + 1;
    if (!Data || !DataLen)
	return Len;

    memcpy(Data, Str, min(Len, DataLen) * sizeof(WCHAR));
    if (DataLen < Len)
	SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return DataLen < Len ? 0 : Len;
}

/******************************************************************************
 *           GetGeoInfoA (KERNEL32.@)
 */
WINAPI INT GetGeoInfoA(GEOID Geoid, GEOTYPE Geotype, LPSTR Data, int DataLen,
		       LANGID Lang)
{
    WCHAR *BuffW;
    INT Len;

    TRACE("%d %d %p %d %d\n", geoid, geotype, data, data_len, lang);

    Len = GetGeoInfoW(Geoid, Geotype, NULL, 0, Lang);
    if (!Len)
	return 0;

    BuffW = HeapAlloc(GetProcessHeap(), 0, Len * sizeof(WCHAR));
    if (!BuffW)
	return 0;

    GetGeoInfoW(Geoid, Geotype, BuffW, Len, Lang);
    Len = WideCharToMultiByte(CP_ACP, 0, BuffW, -1, NULL, 0, NULL, NULL);
    if (!Data || !DataLen) {
	HeapFree(GetProcessHeap(), 0, BuffW);
	return Len;
    }

    Len = WideCharToMultiByte(CP_ACP, 0, BuffW, -1, Data, DataLen, NULL, NULL);
    HeapFree(GetProcessHeap(), 0, BuffW);

    if (DataLen < Len)
	SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return DataLen < Len ? 0 : Len;
}

/******************************************************************************
 *           EnumSystemGeoID    (KERNEL32.@)
 *
 * Call a users function for every location available on the system.
 *
 * PARAMS
 *  geoclass   [I] Type of information desired (SYSGEOTYPE enum from "winnls.h")
 *  parent     [I] GEOID for the parent
 *  enumproc   [I] Callback function to call for each location
 *
 * RETURNS
 *  Success: TRUE.
 *  Failure: FALSE. Use GetLastError() to determine the cause.
 */
WINAPI BOOL EnumSystemGeoID(GEOCLASS Geoclass, GEOID Parent, GEO_ENUMPROC Enumproc)
{
    INT i;

    TRACE("(%d, %d, %p)\n", geoclass, parent, enumproc);

    if (!Enumproc) {
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if (Geoclass != GEOCLASS_NATION && Geoclass != GEOCLASS_REGION) {
	SetLastError(ERROR_INVALID_FLAGS);
	return FALSE;
    }

    for (i = 0; i < sizeof(Geoinfodata) / sizeof(struct GEOINFO); i++) {
	const struct GEOINFO *Ptr = &Geoinfodata[i];

	if (Geoclass == GEOCLASS_NATION && (Ptr->Kind == LOCATION_REGION))
	    continue;

	if (Geoclass == GEOCLASS_REGION && (Ptr->Kind == LOCATION_NATION))
	    continue;

	if (Parent && Ptr->Parent != Parent)
	    continue;

	if (!Enumproc(Ptr->Id))
	    return TRUE;
    }

    return TRUE;
}
