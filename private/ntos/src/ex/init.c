#include <ntos.h>
#include <sel4/sel4.h>

NTSTATUS ExInitSystemPhase0(seL4_BootInfo *bootinfo)
{
    RET_ERR(MmInitSystemPhase0(bootinfo));
    RET_ERR(ObInitSystemPhase0());
    RET_ERR(MmSectionInitialization());
    RET_ERR(PsInitSystemPhase0());
    RET_ERR(IoInitSystemPhase0());

    return STATUS_SUCCESS;
}

static NTSTATUS EiStartSessionManager()
{
    PFILE_OBJECT NtdllFile = NULL;
    RET_ERR(ObReferenceObjectByName("\\BootModules\\ntdll",
				    (POBJECT *) &NtdllFile));
    assert(NtdllFile != NULL);
    DbgTrace("Ntdll file name = %s, size = 0x%zx, buffer = %p\n",
	     NtdllFile->FileName, NtdllFile->Size, (PVOID) NtdllFile->BufferPtr);

    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(NtdllFile, &Process));
    assert(Process != NULL);
    PTHREAD Thread = NULL;
    RET_ERR(PsCreateThread(Process, &Thread));

    return STATUS_SUCCESS;
}

NTSTATUS ExInitSystemPhase1()
{
    RET_ERR(LdrLoadBootModules());
    RET_ERR(EiStartSessionManager());

    return STATUS_SUCCESS;
}
