#include <ntos.h>
#include <sel4/sel4.h>

NTSTATUS ExInitSystem(seL4_BootInfo *bootinfo)
{
    RET_IF_ERR(MmInitSystem(bootinfo));
    RET_IF_ERR(PsInitSystem());
    return STATUS_SUCCESS;
}
