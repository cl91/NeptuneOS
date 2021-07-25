#include <ntos.h>
#include <sel4/sel4.h>

NTSTATUS ExInitSystemPhase0(seL4_BootInfo *bootinfo)
{
    RET_ERR(MmInitSystem(bootinfo));
    RET_ERR(ObInitSystem());
    RET_ERR(PsInitSystem());
    RET_ERR(IoInitSystem());

    return STATUS_SUCCESS;
}

static NTSTATUS EiStartSessionManager()
{
    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(&Process));
    assert(Process != NULL);
    PTHREAD Thread = NULL;
    RET_ERR(PsCreateThread(Process, &Thread));

    PFILE_OBJECT NtdllFile = NULL;
    RET_ERR(ObReferenceObjectByName("\\BootModules\\ntdll",
				    (POBJECT *) &NtdllFile));
    assert(NtdllFile != NULL);
    DbgTrace("Ntdll file name = %s, size = 0x%zx, buffer = %p\n",
	     NtdllFile->FileName, NtdllFile->Size, (PVOID) NtdllFile->BufferPtr);

    return STATUS_SUCCESS;
}

NTSTATUS ExInitSystemPhase1()
{
    RET_ERR(LdrLoadBootModules());
    RET_ERR(EiStartSessionManager());

    return STATUS_SUCCESS;
}
