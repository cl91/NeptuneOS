#include "umtests.h"

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    TestNullDriver();
    TestBeepDriver(440, 1000);
    TestFloppyDriver();
}
