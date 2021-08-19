#include "ki.h"

NTSTATUS KeCallSystemService(SYSTEM_SERVICE_NUMBER SvcNum)
{
    seL4_MessageInfo_t Request = seL4_MessageInfo_new(SvcNum, 0, 0, 0);
    seL4_MessageInfo_t Reply = seL4_Call(SYSSVC_IPC_CAP, Request);
    return STATUS_SUCCESS;
}

NTSTATUS NtDisplayString(PCSTR String)
{
    return KeCallSystemService(NT_DISPLAY_STRING);
}
