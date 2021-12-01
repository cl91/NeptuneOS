/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * FILE:              lib/rtl/time.c
 * PURPOSE:           Conversion between Time and TimeFields
 * PROGRAMMER:        Rex Jolliff (rex@lvcablemodem.com)
 */

/* INCLUDES *****************************************************************/

#include <nt.h>
#include <string.h>

#define TICKSPERMIN        600000000
#define TICKSPERSEC        10000000
#define TICKSPERMSEC       10000
#define SECSPERDAY         86400
#define SECSPERHOUR        3600
#define SECSPERMIN         60
#define MINSPERHOUR        60
#define HOURSPERDAY        24
#define EPOCHWEEKDAY       1
#define DAYSPERWEEK        7
#define EPOCHYEAR          1601
#define DAYSPERNORMALYEAR  365
#define DAYSPERLEAPYEAR    366
#define MONSPERYEAR        12

#define TICKSTO1970         0x019db1ded53e8000LL
#define TICKSTO1980         0x01a8e79fe1d58000LL

static const unsigned int YearLengths[2] = {
    DAYSPERNORMALYEAR, DAYSPERLEAPYEAR
};

static const UCHAR MonthLengths[2][MONSPERYEAR] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static inline int IsLeapYear(int Year)
{
    return Year % 4 == 0 && (Year % 100 != 0 || Year % 400 == 0) ? 1 : 0;
}

static int DaysSinceEpoch(int Year)
{
    int Days;
    Year--;	  /* Don't include a leap day from the current year */
    Days = Year * DAYSPERNORMALYEAR + Year / 4 - Year / 100 + Year / 400;
    Days -= (EPOCHYEAR - 1) * DAYSPERNORMALYEAR + (EPOCHYEAR - 1) / 4 -
	(EPOCHYEAR - 1) / 100 + (EPOCHYEAR - 1) / 400;
    return Days;
}

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
NTAPI BOOLEAN RtlCutoverTimeToSystemTime(IN PTIME_FIELDS CutoverTimeFields,
					 OUT PLARGE_INTEGER SystemTime,
					 IN PLARGE_INTEGER CurrentTime,
					 IN BOOLEAN ThisYearsCutoverOnly)
{
    TIME_FIELDS AdjustedTimeFields;
    TIME_FIELDS CurrentTimeFields;
    TIME_FIELDS CutoverSystemTimeFields;
    LARGE_INTEGER CutoverSystemTime;
    UCHAR MonthLength;
    CSHORT Days;
    BOOLEAN NextYearsCutover = FALSE;

    /* Check fixed cutover time */
    if (CutoverTimeFields->Year != 0) {
	if (!RtlTimeFieldsToTime(CutoverTimeFields, SystemTime))
	    return FALSE;

	if (SystemTime->QuadPart < CurrentTime->QuadPart)
	    return FALSE;

	return TRUE;
    }

    /*
     * Compute recurring cutover time
     */

    /* Day must be between 1(first) and 5(last) */
    if (CutoverTimeFields->Day == 0 || CutoverTimeFields->Day > 5)
	return FALSE;

    RtlTimeToTimeFields(CurrentTime, &CurrentTimeFields);

    while (TRUE) {
	/* Compute the cutover time of the first day of the current month */
	AdjustedTimeFields.Year = CurrentTimeFields.Year;
	if (NextYearsCutover)
	    AdjustedTimeFields.Year++;

	AdjustedTimeFields.Month = CutoverTimeFields->Month;
	AdjustedTimeFields.Day = 1;
	AdjustedTimeFields.Hour = CutoverTimeFields->Hour;
	AdjustedTimeFields.Minute = CutoverTimeFields->Minute;
	AdjustedTimeFields.Second = CutoverTimeFields->Second;
	AdjustedTimeFields.Milliseconds = CutoverTimeFields->Milliseconds;

	if (!RtlTimeFieldsToTime(&AdjustedTimeFields, &CutoverSystemTime))
	    return FALSE;

	RtlTimeToTimeFields(&CutoverSystemTime, &CutoverSystemTimeFields);

	/* Adjust day to first matching weekday */
	if (CutoverSystemTimeFields.Weekday != CutoverTimeFields->Weekday) {
	    if (CutoverSystemTimeFields.Weekday < CutoverTimeFields->Weekday) {
		Days = CutoverTimeFields->Weekday - CutoverSystemTimeFields.Weekday;
	    } else {
		Days = DAYSPERWEEK - (CutoverSystemTimeFields.Weekday -
				      CutoverTimeFields->Weekday);
	    }

	    AdjustedTimeFields.Day += Days;
	}

	/* Adjust the number of weeks */
	if (CutoverTimeFields->Day > 1) {
	    Days = DAYSPERWEEK * (CutoverTimeFields->Day - 1);
	    MonthLength = MonthLengths[IsLeapYear(AdjustedTimeFields.Year)][AdjustedTimeFields.Month - 1];
	    if ((AdjustedTimeFields.Day + Days) > MonthLength) {
		Days -= DAYSPERWEEK;
	    }

	    AdjustedTimeFields.Day += Days;
	}

	if (!RtlTimeFieldsToTime(&AdjustedTimeFields, &CutoverSystemTime))
	    return FALSE;

	if (ThisYearsCutoverOnly || NextYearsCutover ||
	    CutoverSystemTime.QuadPart >= CurrentTime->QuadPart) {
	    break;
	}

	NextYearsCutover = TRUE;
    }

    SystemTime->QuadPart = CutoverSystemTime.QuadPart;

    return TRUE;
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlTimeFieldsToTime(IN PTIME_FIELDS TimeFields,
				  OUT PLARGE_INTEGER Time)
{
    ULONG CurMonth;
    TIME_FIELDS IntTimeFields;

    RtlCopyMemory(&IntTimeFields, TimeFields, sizeof(TIME_FIELDS));

    if (TimeFields->Milliseconds < 0 || TimeFields->Milliseconds > 999 ||
	TimeFields->Second < 0 || TimeFields->Second > 59 ||
	TimeFields->Minute < 0 || TimeFields->Minute > 59 ||
	TimeFields->Hour < 0 || TimeFields->Hour > 23 ||
	TimeFields->Month < 1 || TimeFields->Month > 12 ||
	TimeFields->Day < 1 ||
	TimeFields->Day > MonthLengths[IsLeapYear(TimeFields->Year)][TimeFields->Month - 1] ||
	TimeFields->Year < 1601) {
	return FALSE;
    }

    /* Compute the time */
    Time->QuadPart = DaysSinceEpoch(IntTimeFields.Year);
    for (CurMonth = 1; CurMonth < IntTimeFields.Month; CurMonth++) {
	Time->QuadPart += MonthLengths[IsLeapYear(IntTimeFields.Year)][CurMonth - 1];
    }
    Time->QuadPart += IntTimeFields.Day - 1;
    Time->QuadPart *= SECSPERDAY;
    Time->QuadPart += IntTimeFields.Hour * SECSPERHOUR +
	IntTimeFields.Minute * SECSPERMIN + IntTimeFields.Second;
    Time->QuadPart *= TICKSPERSEC;
    Time->QuadPart += IntTimeFields.Milliseconds * TICKSPERMSEC;

    return TRUE;
}

/*
 * @implemented
 */
NTAPI VOID RtlTimeToElapsedTimeFields(IN PLARGE_INTEGER Time,
				      OUT PTIME_FIELDS TimeFields)
{
    ULONGLONG ElapsedSeconds;
    ULONG SecondsInDay;
    ULONG SecondsInMinute;

    /* Extract millisecond from time */
    TimeFields->Milliseconds = (CSHORT)((Time->QuadPart % TICKSPERSEC) / TICKSPERMSEC);

    /* Compute elapsed seconds */
    ElapsedSeconds = (ULONGLONG) Time->QuadPart / TICKSPERSEC;

    /* Compute seconds within the day */
    SecondsInDay = ElapsedSeconds % SECSPERDAY;

    /* Compute elapsed minutes within the day */
    SecondsInMinute = SecondsInDay % SECSPERHOUR;

    /* Compute elapsed time of day */
    TimeFields->Hour = (CSHORT) (SecondsInDay / SECSPERHOUR);
    TimeFields->Minute = (CSHORT) (SecondsInMinute / SECSPERMIN);
    TimeFields->Second = (CSHORT) (SecondsInMinute % SECSPERMIN);

    /* Compute elapsed days */
    TimeFields->Day = (CSHORT) (ElapsedSeconds / SECSPERDAY);

    /* The elapsed number of months and days cannot be calculated */
    TimeFields->Month = 0;
    TimeFields->Year = 0;
}

/*
 * @implemented
 */
NTAPI VOID RtlTimeToTimeFields(IN PLARGE_INTEGER Time,
			       OUT PTIME_FIELDS TimeFields)
{
    const UCHAR *Months;
    ULONG SecondsInDay, CurYear;
    ULONG LeapYear, CurMonth;
    ULONG Days;
    ULONGLONG IntTime = Time->QuadPart;

    /* Extract millisecond from time and convert time into seconds */
    TimeFields->Milliseconds = (CSHORT) ((IntTime % TICKSPERSEC) / TICKSPERMSEC);
    IntTime = IntTime / TICKSPERSEC;

    /* Split the time into days and seconds within the day */
    Days = (ULONG) (IntTime / SECSPERDAY);
    SecondsInDay = IntTime % SECSPERDAY;

    /* Compute time of day */
    TimeFields->Hour = (CSHORT) (SecondsInDay / SECSPERHOUR);
    SecondsInDay = SecondsInDay % SECSPERHOUR;
    TimeFields->Minute = (CSHORT) (SecondsInDay / SECSPERMIN);
    TimeFields->Second = (CSHORT) (SecondsInDay % SECSPERMIN);

    /* Compute day of week */
    TimeFields->Weekday = (CSHORT) ((EPOCHWEEKDAY + Days) % DAYSPERWEEK);

    /* Compute year */
    CurYear = EPOCHYEAR;
    CurYear += Days / DAYSPERLEAPYEAR;
    Days -= DaysSinceEpoch(CurYear);
    while (TRUE) {
	LeapYear = IsLeapYear(CurYear);
	if (Days < YearLengths[LeapYear]) {
	    break;
	}
	CurYear++;
	Days = Days - YearLengths[LeapYear];
    }
    TimeFields->Year = (CSHORT) CurYear;

    /* Compute month of year */
    LeapYear = IsLeapYear(CurYear);
    Months = MonthLengths[LeapYear];
    for (CurMonth = 0; Days >= Months[CurMonth]; CurMonth++) {
	Days = Days - Months[CurMonth];
    }
    TimeFields->Month = (CSHORT) (CurMonth + 1);
    TimeFields->Day = (CSHORT) (Days + 1);
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlTimeToSecondsSince1970(IN PLARGE_INTEGER Time,
					OUT PULONG SecondsSince1970)
{
    LARGE_INTEGER IntTime;

    IntTime.QuadPart = Time->QuadPart - TICKSTO1970;
    IntTime.QuadPart = IntTime.QuadPart / TICKSPERSEC;

    if (IntTime.u.HighPart != 0)
	return FALSE;

    *SecondsSince1970 = IntTime.u.LowPart;

    return TRUE;
}

/*
 * @implemented
 */
NTAPI BOOLEAN RtlTimeToSecondsSince1980(IN PLARGE_INTEGER Time,
					OUT PULONG SecondsSince1980)
{
    LARGE_INTEGER IntTime;

    IntTime.QuadPart = Time->QuadPart - TICKSTO1980;
    IntTime.QuadPart = IntTime.QuadPart / TICKSPERSEC;

    if (IntTime.u.HighPart != 0)
	return FALSE;

    *SecondsSince1980 = IntTime.u.LowPart;

    return TRUE;
}

/*
 * @implemented
 */
NTAPI VOID RtlSecondsSince1970ToTime(IN ULONG SecondsSince1970,
				     OUT PLARGE_INTEGER Time)
{
    Time->QuadPart = ((LONGLONG) SecondsSince1970 * TICKSPERSEC) + TICKSTO1970;
}

/*
 * @implemented
 */
NTAPI VOID RtlSecondsSince1980ToTime(IN ULONG SecondsSince1980,
				     OUT PLARGE_INTEGER Time)
{
    Time->QuadPart = ((LONGLONG) SecondsSince1980 * TICKSPERSEC) + TICKSTO1980;
}
