#include <psxdll.h>

VOID PsxProcessStartup()
{
    NtDisplayStringA("Hello from POSIX process\n");
    NtTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);
}
