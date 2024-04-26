/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * FILE:              lib/rtl/time.c
 * PURPOSE:           Conversion between Time and TimeFields
 * PROGRAMMER:        Rex Jolliff (rex@lvcablemodem.com)
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS RtlLocalTimeToSystemTime(IN PLARGE_INTEGER LocalTime,
					OUT PLARGE_INTEGER SystemTime)
{
    /* TODO: This should be cached. Maybe look at UserSharedData? */
    SYSTEM_TIMEOFDAY_INFORMATION TimeInformation;
    NTSTATUS Status = NtQuerySystemInformation(SystemTimeOfDayInformation, &TimeInformation,
					       sizeof(TimeInformation), NULL);
    if (!NT_SUCCESS(Status))
        return Status;

    SystemTime->QuadPart = LocalTime->QuadPart + TimeInformation.TimeZoneBias.QuadPart;

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSystemTimeToLocalTime(IN PLARGE_INTEGER SystemTime,
					OUT PLARGE_INTEGER LocalTime)
{
    /* TODO: This should be cached. Maybe look at UserSharedData? */
    SYSTEM_TIMEOFDAY_INFORMATION TimeInformation;
    NTSTATUS Status = NtQuerySystemInformation(SystemTimeOfDayInformation, &TimeInformation,
					       sizeof(TimeInformation), NULL);
    if (!NT_SUCCESS(Status))
	return Status;

    LocalTime->QuadPart = SystemTime->QuadPart - TimeInformation.TimeZoneBias.QuadPart;

    return STATUS_SUCCESS;
}
