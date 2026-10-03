/* This file is imported by both the NT NDK and the Win32 SDK */

#pragma once

#include "ntbasedef.h"

#define INVALID_HANDLE_VALUE ((HANDLE)(-1))

/*
 * Event Object Access Masks
 */
#define EVENT_QUERY_STATE                   (0x0001)
#define EVENT_MODIFY_STATE                  (0x0002)
#define EVENT_ALL_ACCESS                    (STANDARD_RIGHTS_REQUIRED | \
					     SYNCHRONIZE | 0x3)

/*
 * Mutant Object Access Masks
 */
#define MUTANT_QUERY_STATE                  (0x0001)
#define MUTANT_ALL_ACCESS                   (STANDARD_RIGHTS_REQUIRED | \
                                             SYNCHRONIZE | \
                                             MUTANT_QUERY_STATE)

/*
 * Timer Object Access Masks
 */
#define TIMER_QUERY_STATE                   (0x0001)
#define TIMER_MODIFY_STATE                  (0x0002)
#define TIMER_ALL_ACCESS                    (STANDARD_RIGHTS_REQUIRED | \
                                             SYNCHRONIZE | \
                                             TIMER_QUERY_STATE | \
                                             TIMER_MODIFY_STATE)

#define _SYSTEMTIME_
typedef struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef enum _FIRMWARE_TYPE {
    FirmwareTypeUnknown,
    FirmwareTypeBios,
    FirmwareTypeUefi,
    FirmwareTypeMax
} FIRMWARE_TYPE, *PFIRMWARE_TYPE;
