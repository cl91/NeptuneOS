#include <ntdll.h>

SYSTEM_TIME KiInitialSystemTime;
ABSOLUTE_COUNTER_TIME KiInitialCounterTime;

ULONG64 KiCounterTimeMultiplier;
ULONG64 KiInterruptTimeMultiplier;

VOID KiInitTime(VOID)
{
    ULONG TscFreqInMHz = SharedUserData->TscFrequencyInMHz;
    KiCounterTimeMultiplier = (10ULL << TIME_MULTIPLIER_SHIFT) / TscFreqInMHz;
    KiInterruptTimeMultiplier = ((ULONG64)TscFreqInMHz << TIME_MULTIPLIER_SHIFT) / 10;
    KiInitialSystemTime.SystemTime = SharedUserData->InitialSystemTime;
    KiInitialCounterTime.CounterTime = SharedUserData->InitialTsc;
}

NTAPI NTSTATUS NtQuerySystemTime(OUT PLARGE_INTEGER CurrentTime)
{
    CurrentTime->QuadPart =
	KiAbsoluteCounterTimeToSystemTime(KiQueryAbsoluteCounterTime()).SystemTime;
    return STATUS_SUCCESS;
}
