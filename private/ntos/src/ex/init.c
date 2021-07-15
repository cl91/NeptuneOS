#include <ntos.h>
#include <sel4/sel4.h>

NTSTATUS ExInitSystem(seL4_BootInfo *bootinfo)
{
    RET_ERR(MmInitSystem(bootinfo));
    RET_ERR(ObInitSystem());
    RET_ERR(PsInitSystem());
    return STATUS_SUCCESS;
}
