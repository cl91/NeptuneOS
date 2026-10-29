/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS System Libraries
 * FILE:            dll/win32/kernel32/winnls/string/lcformat_private.h
 * PURPOSE:         Win32 Kernel Library Header
 * PROGRAMMER:      Dmitry Chapyshev (dmitry@reactos.org)
 */

#pragma once

/*lcformat.c */
extern BOOL NLS_IsUnicodeOnlyLcid(LCID);

/* Returns the ANSI codepage used by locale formatting when LOCALE_USE_CP_ACP is not set.
 * dwFlags should contain the LOCALE_ flags relevant to formatting (typically
 * LOCALE_NOUSEROVERRIDE).
 */
extern DWORD NLS_GetAnsiCodePage(LCID lcid, DWORD dwFlags);

enum ENUM_CALLBACK_TYPE { CALLBACK_ENUMPROC, CALLBACK_ENUMPROCEX, CALLBACK_ENUMPROCEXEX };

struct ENUM_DATE_FORMATS_CONTEXT {
    enum ENUM_CALLBACK_TYPE Type; /* callback kind */
    union {
	DATEFMT_ENUMPROCW Callback; /* user callback pointer */
	DATEFMT_ENUMPROCEXW CallbackEx;
	DATEFMT_ENUMPROCEXEX CallbackExEx;
    } u;
    LCID Lcid; /* locale of interest */
    DWORD Flags;
    LPARAM lParam;
    BOOL Unicode; /* A vs W callback type, only for regular and Ex callbacks */
};

struct ENUM_TIME_FORMATS_CONTEXT {
    enum ENUM_CALLBACK_TYPE Type; /* callback kind */
    union {
	TIMEFMT_ENUMPROCW Callback; /* user callback pointer */
	TIMEFMT_ENUMPROCEX CallbackEx;
    } u;
    LCID Lcid; /* locale of interest */
    DWORD Flags;
    LPARAM lParam;
    BOOL Unicode; /* A vs W callback type, only for regular and Ex callbacks */
};

struct ENUM_CALENDAR_CONTEXT {
    enum ENUM_CALLBACK_TYPE type; /* callback kind */
    union {
	CALINFO_ENUMPROCW Callback; /* user callback pointer */
	CALINFO_ENUMPROCEXW CallbackEx;
	CALINFO_ENUMPROCEXEX CallbackExEx;
    } u;
    LCID Lcid; /* locale of interest */
    CALID Calendar; /* specific calendar or ENUM_ALL_CALENDARS */
    CALTYPE CalType; /* calendar information type */
    LPARAM lParam; /* user input parameter passed to callback, for ExEx case only */
    BOOL Unicode; /* A vs W callback type, only for regular and Ex callbacks */
};

extern BOOL NLS_EnumDateFormats(const struct ENUM_DATE_FORMATS_CONTEXT *ctxt);
extern BOOL NLS_EnumTimeFormats(struct ENUM_TIME_FORMATS_CONTEXT *ctxt);
extern BOOL NLS_EnumCalendarInfo(const struct ENUM_CALENDAR_CONTEXT *ctxt);
