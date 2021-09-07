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
    PFILE_OBJECT SmssExe = NULL;
    RET_ERR(ObReferenceObjectByName("\\BootModules\\smss.exe",
				    (POBJECT *) &SmssExe));
    assert(SmssExe != NULL);

    PPROCESS Process = NULL;
    RET_ERR(PsCreateProcess(SmssExe, &Process));
    assert(Process != NULL);
    PTHREAD Thread = NULL;
    RET_ERR(PsCreateThread(Process, &Thread));

    return STATUS_SUCCESS;
}

NTSTATUS ExInitSystemPhase1()
{
    RET_ERR(LdrLoadBootModules());
    RET_ERR(PsInitSystemPhase1());
    RET_ERR(EiStartSessionManager());

    return STATUS_SUCCESS;
}
