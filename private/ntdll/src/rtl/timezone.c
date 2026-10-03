/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Timezone functions
 * FILE:              lib/rtl/timezone.c
 * PROGRAMER:         Eric Kohl
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"

/* FUNCTIONS ***************************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS RtlQueryTimeZoneInformation(PRTL_TIME_ZONE_INFORMATION TimeZoneInformation)
{
    return NtQuerySystemInformation(SystemCurrentTimeZoneInformation,
				    TimeZoneInformation, sizeof(*TimeZoneInformation),
				    NULL);
}

NTAPI NTSTATUS RtlQueryDynamicTimeZoneInformation(PRTL_DYNAMIC_TIME_ZONE_INFORMATION Info)
{
    return NtQuerySystemInformation(SystemDynamicTimeZoneInformation, Info,
				    sizeof(*Info), NULL);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlSetTimeZoneInformation(PRTL_TIME_ZONE_INFORMATION TimeZoneInformation)
{
    SIZE_T Length;
    NTSTATUS Status;

    DPRINT("RtlSetTimeZoneInformation()\n");

    Status = RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, L"TimeZoneInformation", L"Bias",
				   REG_DWORD, &TimeZoneInformation->Bias, sizeof(LONG));
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Length = (wcslen(TimeZoneInformation->StandardName) + 1) * sizeof(WCHAR);
    Status = RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, L"TimeZoneInformation",
				   L"StandardName", REG_SZ,
				   TimeZoneInformation->StandardName, (ULONG)Length);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Status = RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, L"TimeZoneInformation",
				   L"StandardBias", REG_DWORD,
				   &TimeZoneInformation->StandardBias, sizeof(LONG));
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Status = RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, L"TimeZoneInformation",
				   L"StandardStart", REG_BINARY,
				   &TimeZoneInformation->StandardDate,
				   sizeof(SYSTEMTIME));
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Length = (wcslen(TimeZoneInformation->DaylightName) + 1) * sizeof(WCHAR);
    Status = RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, L"TimeZoneInformation",
				   L"DaylightName", REG_SZ,
				   TimeZoneInformation->DaylightName, (ULONG)Length);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Status = RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, L"TimeZoneInformation",
				   L"DaylightBias", REG_DWORD,
				   &TimeZoneInformation->DaylightBias, sizeof(LONG));
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Status = RtlWriteRegistryValue(RTL_REGISTRY_CONTROL, L"TimeZoneInformation",
				   L"DaylightStart", REG_BINARY,
				   &TimeZoneInformation->DaylightDate,
				   sizeof(SYSTEMTIME));

    return Status;
}

/* EOF */
