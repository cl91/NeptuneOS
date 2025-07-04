#include <psxdllp.h>

VOID PsxExitProcess(INT Status)
{
    NtTerminateProcess(NtCurrentProcess(), Status);
}

VOID PsxProcessStartup()
{
    NtDisplayStringA("Hello from POSIX process\n");
    PPEB Peb = NtCurrentPeb();
    Peb->SyscallTable.ExitProcess = PsxExitProcess;
    NtTerminateProcess(NtCurrentProcess(), STATUS_UNSUCCESSFUL);
}
