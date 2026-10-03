#include "k32.h"

/*
 * @implemented
 */
WINAPI ULONGLONG GetTickCount64(VOID)
{
    LARGE_INTEGER TickCount;

    TickCount = KiReadSystemTime(&SharedUserData->TickCount);

    /* Convert to milliseconds */
    return KiTickCountToMs(TickCount);
}
