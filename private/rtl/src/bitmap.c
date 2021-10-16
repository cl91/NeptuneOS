#include <nt.h>

#ifdef _M_IX86
#define _BITCOUNT 32
#endif

CCHAR NTAPI RtlFindMostSignificantBit(ULONGLONG Value)
{
    ULONG Position;

#ifdef _M_AMD64
    if (BitScanReverse64(&Position, Value)) {
	return (CCHAR) Position;
    }
#else
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
    ULONG Position;

#ifdef _M_AMD64
    if (BitScanForward64(&Position, Value)) {
	return (CCHAR) Position;
    }
#else
    if (BitScanForward(&Position, (ULONG) Value)) {
	return (CCHAR) Position;
    } else if (BitScanForward(&Position, Value >> _BITCOUNT)) {
	return (CCHAR) (Position + _BITCOUNT);
    }
#endif
    return -1;
}
