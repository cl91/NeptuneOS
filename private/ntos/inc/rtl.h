#include <nt.h>
#include "ex.h"

static inline PCSTR RtlDuplicateString(IN PCSTR String,
				       IN ULONG Tag)
{
    if (String == NULL) {
	return String;
    }

    SIZE_T BufLen = strlen(String) + 1;
    PCHAR Buf = ExAllocatePoolWithTag(BufLen, Tag);
    if (Buf == NULL) {
	return NULL;
    }
    memcpy(Buf, String, BufLen);
    return Buf;
}

static inline ULONG RtlNumberOfSetBits(ULONG Integer)
{
    return __builtin_popcount(Integer);
}

static inline ULONG RtlFirstSetBit(ULONG Integer)
{
    return __builtin_ffs(Integer);
}
