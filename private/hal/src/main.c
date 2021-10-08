#include <hal.h>

NTAPI VOID NtProcessStartup(PPEB Peb)
{
    IopDisplayString(L"Hello, world from hal.dll!\n");

    while (1);
}
