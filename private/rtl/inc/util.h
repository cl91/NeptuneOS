#pragma once

static inline ULONG RtlpHashString(PCSTR Str)
{
    ULONG Hash = 5381;
    ULONG Chr;

    while ((Chr = (UCHAR) *Str++) != '\0') {
        Hash = ((Hash << 5) + Hash) + Chr; /* Hash * 33 + Chr */
    }
    return Hash;
}
