/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/wine/timezone.c
 * PURPOSE:         Time conversion functions
 * PROGRAMMER:      Ariadne
 *                  DOSDATE and DOSTIME structures from Onno Hovers
 * UPDATE HISTORY:
 *                  Created 19/01/99
 */

/* INCLUDES ******************************************************************/

#include <k32.h>

/* TYPES *********************************************************************/

#define TICKSPERMIN 600000000

#define LL2FILETIME(ll, pft)           \
    (pft)->dwLowDateTime = (UINT)(ll); \
    (pft)->dwHighDateTime = (UINT)((ll) >> 32);
#define FILETIME2LL(pft, ll) \
    ll = (((LONGLONG)((pft)->dwHighDateTime)) << 32) + (pft)->dwLowDateTime;

static const int MonthLengths[2][12] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

/* STATIC FUNCTIONS **********************************************************/

static inline int IsLeapYear(int Year)
{
    return Year % 4 == 0 && (Year % 100 != 0 || Year % 400 == 0) ? 1 : 0;
}

/***********************************************************************
 *  TIME_DayLightCompareDate
 *
 * Compares two dates without looking at the year.
 *
 * PARAMS
 *   date        [in] The local time to compare.
 *   compareDate [in] The daylight savings begin or end date.
 *
 * RETURNS
 *
 *  -1 if date < compareDate
 *   0 if date == compareDate
 *   1 if date > compareDate
 *  -2 if an error occurs
 */
static int TIME_DayLightCompareDate(const SYSTEMTIME *Date, const SYSTEMTIME *CompareDate)
{
    int LimitDay, Dayinsecs;

    if (Date->wMonth < CompareDate->wMonth)
	return -1; /* We are in a month before the date limit. */

    if (Date->wMonth > CompareDate->wMonth)
	return 1; /* We are in a month after the date limit. */

    /* if year is 0 then date is in day-of-week format, otherwise
     * it's absolute date.
     */
    if (CompareDate->wYear == 0) {
	WORD First;
	/* compareDate->wDay is interpreted as number of the week in the month
	 * 5 means: the last week in the month */
	int Weekofmonth = CompareDate->wDay;
	/* calculate the day of the first DayOfWeek in the month */
	First = (6 + CompareDate->wDayOfWeek - Date->wDayOfWeek + Date->wDay) % 7 + 1;
	LimitDay = First + 7 * (Weekofmonth - 1);
	/* check needed for the 5th weekday of the month */
	if (LimitDay >
	    MonthLengths[Date->wMonth == 2 && IsLeapYear(Date->wYear)][Date->wMonth - 1])
	    LimitDay -= 7;
    } else {
	LimitDay = CompareDate->wDay;
    }

    /* convert to seconds */
    LimitDay = ((LimitDay * 24 + CompareDate->wHour) * 60 + CompareDate->wMinute) * 60;
    Dayinsecs = ((Date->wDay * 24 + Date->wHour) * 60 + Date->wMinute) * 60 +
		Date->wSecond;
    /* and compare */
    return Dayinsecs < LimitDay ? -1 :
	   Dayinsecs > LimitDay ? 1 :
				   0; /* date is equal to the date limit. */
}

/***********************************************************************
 *  TIME_CompTimeZoneID
 *
 *  Computes the local time bias for a given time and time zone.
 *
 *  PARAMS
 *      pTZinfo     [in] The time zone data.
 *      lpFileTime  [in] The system or local time.
 *      islocal     [in] it is local time.
 *
 *  RETURNS
 *      TIME_ZONE_ID_INVALID    An error occurred
 *      TIME_ZONE_ID_UNKNOWN    There are no transition time known
 *      TIME_ZONE_ID_STANDARD   Current time is standard time
 *      TIME_ZONE_ID_DAYLIGHT   Current time is daylight savings time
 */
static DWORD TIME_CompTimeZoneID(const TIME_ZONE_INFORMATION *pTZinfo,
				 FILETIME *lpFileTime, BOOL Islocal)
{
    int Ret, Year;
    BOOL BeforeStandardDate, AfterDaylightDate;
    DWORD Retval = TIME_ZONE_ID_INVALID;
    LONGLONG LlTime = 0; /* initialized to prevent gcc complaining */
    SYSTEMTIME SysTime;
    FILETIME FtTemp;

    if (pTZinfo->DaylightDate.wMonth != 0) {
	/* if year is 0 then date is in day-of-week format, otherwise
	 * it's absolute date.
	 */
	if (pTZinfo->StandardDate.wMonth == 0 ||
	    (pTZinfo->StandardDate.wYear == 0 &&
	     (pTZinfo->StandardDate.wDay < 1 || pTZinfo->StandardDate.wDay > 5 ||
	      pTZinfo->DaylightDate.wDay < 1 || pTZinfo->DaylightDate.wDay > 5))) {
	    SetLastError(ERROR_INVALID_PARAMETER);
	    return TIME_ZONE_ID_INVALID;
	}

	if (!Islocal) {
	    FILETIME2LL(lpFileTime, LlTime);
	    LlTime -= pTZinfo->Bias * (LONGLONG)TICKSPERMIN;
	    LL2FILETIME(LlTime, &FtTemp)
	    lpFileTime = &FtTemp;
	}

	FileTimeToSystemTime(lpFileTime, &SysTime);
	Year = SysTime.wYear;

	if (!Islocal) {
	    LlTime -= pTZinfo->DaylightBias * (LONGLONG)TICKSPERMIN;
	    LL2FILETIME(LlTime, &FtTemp)
	    FileTimeToSystemTime(lpFileTime, &SysTime);
	}

	/* check for daylight savings */
	if (Year == SysTime.wYear) {
	    Ret = TIME_DayLightCompareDate(&SysTime, &pTZinfo->StandardDate);
	    if (Ret == -2)
		return TIME_ZONE_ID_INVALID;

	    BeforeStandardDate = Ret < 0;
	} else
	    BeforeStandardDate = SysTime.wYear < Year;

	if (!Islocal) {
	    LlTime -= (pTZinfo->StandardBias - pTZinfo->DaylightBias) *
		      (LONGLONG)TICKSPERMIN;
	    LL2FILETIME(LlTime, &FtTemp)
	    FileTimeToSystemTime(lpFileTime, &SysTime);
	}

	if (Year == SysTime.wYear) {
	    Ret = TIME_DayLightCompareDate(&SysTime, &pTZinfo->DaylightDate);
	    if (Ret == -2)
		return TIME_ZONE_ID_INVALID;

	    AfterDaylightDate = Ret >= 0;
	} else
	    AfterDaylightDate = SysTime.wYear > Year;

	Retval = TIME_ZONE_ID_STANDARD;
	if (pTZinfo->DaylightDate.wMonth < pTZinfo->StandardDate.wMonth) {
	    /* Northern hemisphere */
	    if (BeforeStandardDate && AfterDaylightDate)
		Retval = TIME_ZONE_ID_DAYLIGHT;
	} else /* Down south */
	    if (BeforeStandardDate || AfterDaylightDate)
		Retval = TIME_ZONE_ID_DAYLIGHT;
    } else
	/* No transition date */
	Retval = TIME_ZONE_ID_UNKNOWN;

    return Retval;
}

/***********************************************************************
 *  TIME_TimeZoneID
 *
 *  Calculates whether daylight savings is on now.
 *
 *  PARAMS
 *      pTzi [in] Timezone info.
 *
 *  RETURNS
 *      TIME_ZONE_ID_INVALID    An error occurred
 *      TIME_ZONE_ID_UNKNOWN    There are no transition time known
 *      TIME_ZONE_ID_STANDARD   Current time is standard time
 *      TIME_ZONE_ID_DAYLIGHT   Current time is daylight savings time
 */
static DWORD TIME_ZoneID(const TIME_ZONE_INFORMATION *pTzi)
{
    FILETIME FtTime;
    GetSystemTimeAsFileTime(&FtTime);
    return TIME_CompTimeZoneID(pTzi, &FtTime, FALSE);
}

/***********************************************************************
 *  TIME_GetTimezoneBias
 *
 *  Calculates the local time bias for a given time zone.
 *
 * PARAMS
 *  pTZinfo    [in]  The time zone data.
 *  lpFileTime [in]  The system or local time.
 *  islocal    [in]  It is local time.
 *  pBias      [out] The calculated bias in minutes.
 *
 * RETURNS
 *  TRUE when the time zone bias was calculated.
 */
static BOOL TIME_GetTimezoneBias(const TIME_ZONE_INFORMATION *pTZinfo,
				 FILETIME *lpFileTime, BOOL Islocal, LONG *pBias)
{
    LONG Bias = pTZinfo->Bias;
    DWORD Tzid = TIME_CompTimeZoneID(pTZinfo, lpFileTime, Islocal);

    if (Tzid == TIME_ZONE_ID_INVALID)
	return FALSE;
    if (Tzid == TIME_ZONE_ID_DAYLIGHT)
	Bias += pTZinfo->DaylightBias;
    else if (Tzid == TIME_ZONE_ID_STANDARD)
	Bias += pTZinfo->StandardBias;
    *pBias = Bias;
    return TRUE;
}

/* FUNCTIONS ****************************************************************/

/*
 * @implemented
 */
WINAPI DWORD GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTimeZoneInformation)
{
    RTL_TIME_ZONE_INFORMATION TimeZoneInformation;
    NTSTATUS Status;

    DPRINT("GetTimeZoneInformation()\n");

    Status = NtQuerySystemInformation(SystemCurrentTimeZoneInformation,
				      &TimeZoneInformation,
				      sizeof(RTL_TIME_ZONE_INFORMATION), NULL);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return TIME_ZONE_ID_INVALID;
    }

    lpTimeZoneInformation->Bias = TimeZoneInformation.Bias;

    wcsncpy_s(lpTimeZoneInformation->StandardName,
	      ARRAYSIZE(lpTimeZoneInformation->StandardName),
	      TimeZoneInformation.StandardName,
	      ARRAYSIZE(lpTimeZoneInformation->StandardName));
    lpTimeZoneInformation->StandardDate.wYear = TimeZoneInformation.StandardDate.Year;
    lpTimeZoneInformation->StandardDate.wMonth = TimeZoneInformation.StandardDate.Month;
    lpTimeZoneInformation->StandardDate.wDay = TimeZoneInformation.StandardDate.Day;
    lpTimeZoneInformation->StandardDate.wHour = TimeZoneInformation.StandardDate.Hour;
    lpTimeZoneInformation->StandardDate.wMinute = TimeZoneInformation.StandardDate.Minute;
    lpTimeZoneInformation->StandardDate.wSecond = TimeZoneInformation.StandardDate.Second;
    lpTimeZoneInformation->StandardDate.wMilliseconds =
	TimeZoneInformation.StandardDate.Milliseconds;
    lpTimeZoneInformation->StandardDate.wDayOfWeek =
	TimeZoneInformation.StandardDate.Weekday;
    lpTimeZoneInformation->StandardBias = TimeZoneInformation.StandardBias;

    wcsncpy_s(lpTimeZoneInformation->DaylightName,
	      ARRAYSIZE(lpTimeZoneInformation->DaylightName),
	      TimeZoneInformation.DaylightName,
	      ARRAYSIZE(lpTimeZoneInformation->DaylightName));
    lpTimeZoneInformation->DaylightDate.wYear = TimeZoneInformation.DaylightDate.Year;
    lpTimeZoneInformation->DaylightDate.wMonth = TimeZoneInformation.DaylightDate.Month;
    lpTimeZoneInformation->DaylightDate.wDay = TimeZoneInformation.DaylightDate.Day;
    lpTimeZoneInformation->DaylightDate.wHour = TimeZoneInformation.DaylightDate.Hour;
    lpTimeZoneInformation->DaylightDate.wMinute = TimeZoneInformation.DaylightDate.Minute;
    lpTimeZoneInformation->DaylightDate.wSecond = TimeZoneInformation.DaylightDate.Second;
    lpTimeZoneInformation->DaylightDate.wMilliseconds =
	TimeZoneInformation.DaylightDate.Milliseconds;
    lpTimeZoneInformation->DaylightDate.wDayOfWeek =
	TimeZoneInformation.DaylightDate.Weekday;
    lpTimeZoneInformation->DaylightBias = TimeZoneInformation.DaylightBias;

    return TIME_ZoneID(lpTimeZoneInformation);
}

/*
 * @implemented
 */
WINAPI BOOL SetTimeZoneInformation(CONST TIME_ZONE_INFORMATION *lpTimeZoneInformation)
{
    RTL_TIME_ZONE_INFORMATION TimeZoneInformation;
    NTSTATUS Status;

    DPRINT("SetTimeZoneInformation()\n");

    TimeZoneInformation.Bias = lpTimeZoneInformation->Bias;

    wcsncpy_s(TimeZoneInformation.StandardName,
	      ARRAYSIZE(TimeZoneInformation.StandardName),
	      lpTimeZoneInformation->StandardName,
	      ARRAYSIZE(TimeZoneInformation.StandardName));
    TimeZoneInformation.StandardDate.Year = lpTimeZoneInformation->StandardDate.wYear;
    TimeZoneInformation.StandardDate.Month = lpTimeZoneInformation->StandardDate.wMonth;
    TimeZoneInformation.StandardDate.Day = lpTimeZoneInformation->StandardDate.wDay;
    TimeZoneInformation.StandardDate.Hour = lpTimeZoneInformation->StandardDate.wHour;
    TimeZoneInformation.StandardDate.Minute = lpTimeZoneInformation->StandardDate.wMinute;
    TimeZoneInformation.StandardDate.Second = lpTimeZoneInformation->StandardDate.wSecond;
    TimeZoneInformation.StandardDate.Milliseconds =
	lpTimeZoneInformation->StandardDate.wMilliseconds;
    TimeZoneInformation.StandardDate.Weekday =
	lpTimeZoneInformation->StandardDate.wDayOfWeek;
    TimeZoneInformation.StandardBias = lpTimeZoneInformation->StandardBias;

    wcsncpy_s(TimeZoneInformation.DaylightName,
	      ARRAYSIZE(TimeZoneInformation.DaylightName),
	      lpTimeZoneInformation->DaylightName,
	      ARRAYSIZE(TimeZoneInformation.DaylightName));
    TimeZoneInformation.DaylightDate.Year = lpTimeZoneInformation->DaylightDate.wYear;
    TimeZoneInformation.DaylightDate.Month = lpTimeZoneInformation->DaylightDate.wMonth;
    TimeZoneInformation.DaylightDate.Day = lpTimeZoneInformation->DaylightDate.wDay;
    TimeZoneInformation.DaylightDate.Hour = lpTimeZoneInformation->DaylightDate.wHour;
    TimeZoneInformation.DaylightDate.Minute = lpTimeZoneInformation->DaylightDate.wMinute;
    TimeZoneInformation.DaylightDate.Second = lpTimeZoneInformation->DaylightDate.wSecond;
    TimeZoneInformation.DaylightDate.Milliseconds =
	lpTimeZoneInformation->DaylightDate.wMilliseconds;
    TimeZoneInformation.DaylightDate.Weekday =
	lpTimeZoneInformation->DaylightDate.wDayOfWeek;
    TimeZoneInformation.DaylightBias = lpTimeZoneInformation->DaylightBias;

    Status = RtlSetTimeZoneInformation(&TimeZoneInformation);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("RtlSetTimeZoneInformation() failed (Status %x)\n", Status);
	BaseSetLastNTError(Status);
	return FALSE;
    }

    Status = NtSetSystemInformation(SystemCurrentTimeZoneInformation,
				    (PVOID)&TimeZoneInformation,
				    sizeof(RTL_TIME_ZONE_INFORMATION));
    if (!NT_SUCCESS(Status)) {
	DPRINT1("NtSetSystemInformation() failed (Status %x)\n", Status);
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL SystemTimeToTzSpecificLocalTime(
    CONST TIME_ZONE_INFORMATION *lpTimeZoneInformation, CONST SYSTEMTIME *lpUniversalTime,
    LPSYSTEMTIME lpLocalTime)
{
    TIME_ZONE_INFORMATION TzInfo;
    FILETIME FileTime;
    LONGLONG llTime;
    LONG lBias;

    if (lpTimeZoneInformation != NULL) {
	TzInfo = *lpTimeZoneInformation;
    } else {
	if (GetTimeZoneInformation(&TzInfo) == TIME_ZONE_ID_INVALID)
	    return FALSE;
    }

    if (!lpUniversalTime || !lpLocalTime)
	return FALSE;

    if (!SystemTimeToFileTime(lpUniversalTime, &FileTime))
	return FALSE;

    FILETIME2LL(&FileTime, llTime)

    if (!TIME_GetTimezoneBias(&TzInfo, &FileTime, FALSE, &lBias))
	return FALSE;

    /* convert minutes to 100-nanoseconds-ticks */
    llTime -= (LONGLONG)lBias * TICKSPERMIN;

    LL2FILETIME(llTime, &FileTime)

    return FileTimeToSystemTime(&FileTime, lpLocalTime);
}

/*
 * @implemented (Wine 13 sep 2008)
 */
WINAPI BOOL TzSpecificLocalTimeToSystemTime(
    CONST TIME_ZONE_INFORMATION *lpTimeZoneInformation, CONST SYSTEMTIME *lpLocalTime,
    LPSYSTEMTIME lpUniversalTime)
{
    FILETIME Ft;
    LONG lBias;
    LONGLONG t;
    TIME_ZONE_INFORMATION TzInfo;

    if (lpTimeZoneInformation != NULL) {
	TzInfo = *lpTimeZoneInformation;
    } else {
	if (GetTimeZoneInformation(&TzInfo) == TIME_ZONE_ID_INVALID)
	    return FALSE;
    }

    if (!SystemTimeToFileTime(lpLocalTime, &Ft))
	return FALSE;
    FILETIME2LL(&Ft, t)
    if (!TIME_GetTimezoneBias(&TzInfo, &Ft, TRUE, &lBias))
	return FALSE;
    /* convert minutes to 100-nanoseconds-ticks */
    t += (LONGLONG)lBias * TICKSPERMIN;
    LL2FILETIME(t, &Ft)
    return FileTimeToSystemTime(&Ft, lpUniversalTime);
}

/* EOF */
