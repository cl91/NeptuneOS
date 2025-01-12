#include <ntdll.h>

VOID LnxProcessStartup(PNTDLL_PROCESS_INIT_INFO InitInfo)
{
    assert(InitInfo->DriverProcess);
    NtDisplayStringA("Hello from ELF driver target\n");
    while (1) ;
}
