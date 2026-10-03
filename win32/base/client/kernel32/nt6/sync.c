#include "k32.h"

WINAPI VOID AcquireSRWLockExclusive(PSRWLOCK Lock)
{
    RtlAcquireSRWLockExclusive((PRTL_SRWLOCK)Lock);
}

WINAPI VOID AcquireSRWLockShared(PSRWLOCK Lock)
{
    RtlAcquireSRWLockShared((PRTL_SRWLOCK)Lock);
}

WINAPI VOID InitializeConditionVariable(PCONDITION_VARIABLE ConditionVariable)
{
    RtlInitializeConditionVariable((PRTL_CONDITION_VARIABLE)ConditionVariable);
}

WINAPI VOID InitializeSRWLock(PSRWLOCK Lock)
{
    RtlInitializeSRWLock((PRTL_SRWLOCK)Lock);
}

WINAPI VOID ReleaseSRWLockExclusive(PSRWLOCK Lock)
{
    RtlReleaseSRWLockExclusive((PRTL_SRWLOCK)Lock);
}

WINAPI VOID ReleaseSRWLockShared(PSRWLOCK Lock)
{
    RtlReleaseSRWLockShared((PRTL_SRWLOCK)Lock);
}

FORCEINLINE
PLARGE_INTEGER
GetNtTimeout(PLARGE_INTEGER Time, DWORD Timeout)
{
    if (Timeout == INFINITE)
	return NULL;
    Time->QuadPart = (ULONGLONG)Timeout * -10000;
    return Time;
}

WINAPI BOOL SleepConditionVariableCS(PCONDITION_VARIABLE ConditionVariable,
				     PCRITICAL_SECTION CriticalSection, DWORD Timeout)
{
    NTSTATUS Status;
    LARGE_INTEGER Time;

    Status = RtlSleepConditionVariableCS(ConditionVariable,
					 (PRTL_CRITICAL_SECTION)CriticalSection,
					 GetNtTimeout(&Time, Timeout));
    if (!NT_SUCCESS(Status) || Status == STATUS_TIMEOUT) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }
    return TRUE;
}

WINAPI BOOL SleepConditionVariableSRW(PCONDITION_VARIABLE ConditionVariable,
				      PSRWLOCK Lock, DWORD Timeout, ULONG Flags)
{
    NTSTATUS Status;
    LARGE_INTEGER Time;

    Status = RtlSleepConditionVariableSRW(ConditionVariable, Lock,
					  GetNtTimeout(&Time, Timeout), Flags);
    if (!NT_SUCCESS(Status) || Status == STATUS_TIMEOUT) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }
    return TRUE;
}

WINAPI VOID WakeAllConditionVariable(PCONDITION_VARIABLE ConditionVariable)
{
    RtlWakeAllConditionVariable((PRTL_CONDITION_VARIABLE)ConditionVariable);
}

WINAPI VOID WakeConditionVariable(PCONDITION_VARIABLE ConditionVariable)
{
    RtlWakeConditionVariable((PRTL_CONDITION_VARIABLE)ConditionVariable);
}

/*
 * @implemented
 */
WINAPI BOOL InitializeCriticalSectionEx(OUT LPCRITICAL_SECTION lpCriticalSection,
					IN DWORD dwSpinCount, IN DWORD flags)
{
    NTSTATUS Status;

    /* FIXME: Flags ignored */

    /* Initialize the critical section */
    Status = RtlInitializeCriticalSectionAndSpinCount(
	(PRTL_CRITICAL_SECTION)lpCriticalSection, dwSpinCount);
    if (!NT_SUCCESS(Status)) {
	/* Set failure code */
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }

    /* Success */
    return TRUE;
}
