#include <nt.h>

#ifdef _M_IX86
#define _BITCOUNT 32
#endif

CCHAR NTAPI RtlFindMostSignificantBit(ULONGLONG Value)
{
#ifdef _WIN64
    ULONGLONG Position;
    if (BitScanReverse64(&Position, Value)) {
	return (CCHAR) Position;
    }
#else
    ULONG Position;
    if (BitScanReverse(&Position, Value >> _BITCOUNT)) {
	return (CCHAR) (Position + _BITCOUNT);
    } else if (BitScanReverse(&Position, (ULONG) Value)) {
	return (CCHAR) Position;
    }
#endif
    return -1;
}

CCHAR NTAPI RtlFindLeastSignificantBit(ULONGLONG Value)
{
#ifdef _WIN64
    ULONGLONG Position;
    if (BitScanForward64(&Position, Value)) {
	return (CCHAR) Position;
    }
#else
    ULONG Position;
    if (BitScanForward(&Position, (ULONG) Value)) {
	return (CCHAR) Position;
    } else if (BitScanForward(&Position, Value >> _BITCOUNT)) {
	return (CCHAR) (Position + _BITCOUNT);
    }
#endif
    return -1;
}
