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

static PPROCESS EiSessionManagerProcess;
static PTHREAD EiSessionManagerThread;

static NTSTATUS EiStartSessionManager()
{
    PIO_FILE_OBJECT SmssExe = NULL;
    NTSTATUS Status = ObReferenceObjectByName(SMSS_PATH, (POBJECT *) &SmssExe);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(SmssExe != NULL);

    Status = PsCreateProcess(SmssExe, 0, &EiSessionManagerProcess);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(EiSessionManagerProcess != NULL);

    Status = PsCreateThread(EiSessionManagerProcess,
			    &EiSessionManagerThread);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(EiSessionManagerThread != NULL);

    return STATUS_SUCCESS;

 fail:
    KeVgaPrint("\nFailed to start Session Manager: ");
    if (SmssExe == NULL) {
	KeVgaPrint("%s not found", SMSS_PATH);
    } else if (EiSessionManagerProcess == NULL) {
	KeVgaPrint("process creation returned error 0x%x", Status);
    } else {
	KeVgaPrint("thread creation returned error 0x%x", Status);
    }
    KeVgaPrint("\n\n");
    return Status;
}

NTSTATUS ExInitSystemPhase1()
{
    RET_ERR(LdrLoadBootModules());
    RET_ERR(PsInitSystemPhase1());
    RET_ERR(IoInitSystemPhase1());
    RET_ERR(EiStartSessionManager());

    return STATUS_SUCCESS;
}
