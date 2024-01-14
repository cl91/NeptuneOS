#include <ntdll.h>

NTAPI NTSTATUS NtQuerySystemTime(OUT PLARGE_INTEGER CurrentTime)
{
    /* Loop until we get a perfect match */
    while (TRUE) {
        /* Read the time value */
        CurrentTime->HighPart = SharedUserData->SystemTime.High1Time;
        CurrentTime->LowPart = SharedUserData->SystemTime.LowPart;
        if (CurrentTime->HighPart == SharedUserData->SystemTime.High2Time) {
	    break;
	}
    }
    return STATUS_SUCCESS;
}
