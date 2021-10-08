#pragma once

#include <nt.h>
#include <wdm.h>

static inline VOID IopDisplayString(PCWSTR String)
{
    UNICODE_STRING UnicodeString;
    RtlInitUnicodeString(&UnicodeString, String);
    NtDisplayString(&UnicodeString);
}
