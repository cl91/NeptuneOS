/*
 *
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/power.c
 * PURPOSE:         Power Management Functions
 * PROGRAMMER:      Dmitry Chapyshev <dmitry@reactos.org>
 *
 * UPDATE HISTORY:
 *                  01/15/2009 Created
 */

#include <k32.h>

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
WINAPI BOOL GetSystemPowerStatus(IN LPSYSTEM_POWER_STATUS PowerStatus)
{
    NTSTATUS Status;
    SYSTEM_BATTERY_STATE BattState;
    ULONG Max, Current;

    Status = NtPowerInformation(SystemBatteryState, NULL, 0, &BattState,
				sizeof(SYSTEM_BATTERY_STATE));
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    RtlZeroMemory(PowerStatus, sizeof(SYSTEM_POWER_STATUS));

    PowerStatus->BatteryLifeTime = BATTERY_LIFE_UNKNOWN;
    PowerStatus->BatteryFullLifeTime = BATTERY_LIFE_UNKNOWN;
    PowerStatus->BatteryLifePercent = BATTERY_PERCENTAGE_UNKNOWN;
    PowerStatus->ACLineStatus = AC_LINE_ONLINE;

    Max = BattState.MaxCapacity;
    Current = BattState.RemainingCapacity;
    if (Max) {
	if (Current <= Max) {
	    PowerStatus->BatteryLifePercent = (UCHAR)((100 * Current + Max / 2) / Max);
	} else {
	    PowerStatus->BatteryLifePercent = 100;
	}

	if (PowerStatus->BatteryLifePercent <= 4)
	    PowerStatus->BatteryFlag |= BATTERY_FLAG_CRITICAL;

	if (PowerStatus->BatteryLifePercent <= 32)
	    PowerStatus->BatteryFlag |= BATTERY_FLAG_LOW;

	if (PowerStatus->BatteryLifePercent >= 67)
	    PowerStatus->BatteryFlag |= BATTERY_FLAG_HIGH;
    }

    if (!BattState.BatteryPresent)
	PowerStatus->BatteryFlag |= BATTERY_FLAG_NO_BATTERY;

    if (BattState.Charging)
	PowerStatus->BatteryFlag |= BATTERY_FLAG_CHARGING;

    if (!(BattState.AcOnLine) && (BattState.BatteryPresent))
	PowerStatus->ACLineStatus = AC_LINE_OFFLINE;

    if (BattState.EstimatedTime)
	PowerStatus->BatteryLifeTime = BattState.EstimatedTime;

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL SetSystemPowerState(IN BOOL fSuspend, IN BOOL fForce)
{
    NTSTATUS Status;

    Status = NtInitiatePowerAction((fSuspend != FALSE) ? PowerActionSleep :
							 PowerActionHibernate,
				   (fSuspend != FALSE) ? PowerSystemSleeping1 :
							 PowerSystemHibernate,
				   (fForce == FALSE), FALSE);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL GetDevicePowerState(IN HANDLE hDevice, OUT BOOL *pOn)
{
    DEVICE_POWER_STATE DevicePowerState;
    NTSTATUS Status;

    Status = NtGetDevicePowerState(hDevice, &DevicePowerState);
    if (NT_SUCCESS(Status)) {
	*pOn = (DevicePowerState == PowerDeviceUnspecified) ||
		(DevicePowerState == PowerDeviceD0);
	return TRUE;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL RequestDeviceWakeup(IN HANDLE hDevice)
{
    NTSTATUS Status;

    Status = NtRequestDeviceWakeup(hDevice);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL RequestWakeupLatency(IN LATENCY_TIME Latency)
{
    NTSTATUS Status;

    Status = NtRequestWakeupLatency(Latency);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL CancelDeviceWakeupRequest(IN HANDLE hDevice)
{
    NTSTATUS Status;

    Status = NtCancelDeviceWakeupRequest(hDevice);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL IsSystemResumeAutomatic(VOID)
{
    BOOLEAN Automatic;
    NTSTATUS Status;

    Status = NtIsSystemResumeAutomatic(&Automatic);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return Automatic;
}

/*
 * @implemented
 */
WINAPI BOOL SetMessageWaitingIndicator(IN HANDLE hMsgIndicator, IN ULONG ulMsgCount)
{
    /* This is the correct Windows implementation */
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/*
 * @implemented
 */
WINAPI EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE EsFlags)
{
    NTSTATUS Status;

    Status = NtSetThreadExecutionState(EsFlags, &EsFlags);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return 0;
    }

    return EsFlags;
}
