#include <nt.h>
#include <string.h>

static WCHAR LdrpUninitializedArray[512];

static WCHAR LdrpInitializedArray[512] = L"From initialized array.\n";

static inline VOID LdrpDisplayString(PCWSTR String)
{
    UNICODE_STRING UnicodeString;
    RtlInitUnicodeString(&UnicodeString, String);
    NtDisplayString(&UnicodeString);
}

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    LdrpDisplayString(L"Hello, world from NT client!\n");
    LdrpDisplayString(LdrpInitializedArray);
    memcpy(LdrpUninitializedArray, L"From .bss array\n", sizeof(L"From .bss array\n"));
    LdrpDisplayString(LdrpUninitializedArray);

    while (1);
}
