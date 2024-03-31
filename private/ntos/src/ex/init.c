#include "ei.h"

NTSTATUS ExInitSystemPhase0(seL4_BootInfo *bootinfo)
{
    RET_ERR(MmInitSystemPhase0(bootinfo));
    RET_ERR(ObInitSystemPhase0());
    RET_ERR(MmSectionInitialization());
    RET_ERR(PsInitSystemPhase0());
    RET_ERR(IoInitSystemPhase0());
    RET_ERR(HalInitSystemPhase0());

    return STATUS_SUCCESS;
}

static PPROCESS EiSessionManagerProcess;
static PTHREAD EiSessionManagerThread;

static NTSTATUS EiStartSessionManager()
{
    PIO_FILE_OBJECT SmssExe = NULL;
    PSECTION SmssSection = NULL;
    NTSTATUS Status = ObReferenceObjectByName(SMSS_EXE_PATH, OBJECT_TYPE_FILE,
					      NULL, FALSE, (POBJECT *)&SmssExe);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(SmssExe != NULL);

    Status = MmCreateSection(SmssExe, 0, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			     &SmssSection);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }

    Status = PsCreateProcess(SmssSection, NULL, &EiSessionManagerProcess);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(EiSessionManagerProcess != NULL);

    Status = PsCreateThread(EiSessionManagerProcess, NULL, NULL, FALSE,
			    &EiSessionManagerThread);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(EiSessionManagerThread != NULL);

    return STATUS_SUCCESS;

fail:
    HalVgaPrint("\nFailed to start Session Manager: ");
    if (!SmssExe) {
	HalVgaPrint("%s not found", SMSS_EXE_PATH);
    } else if (!SmssSection) {
	HalVgaPrint("failed to create image section for %s, error 0x%x",
		    SMSS_EXE_PATH, Status);
    } else if (EiSessionManagerProcess == NULL) {
	HalVgaPrint("process creation returned error 0x%x", Status);
    } else {
	HalVgaPrint("thread creation returned error 0x%x", Status);
    }
    HalVgaPrint("\n\n");
    return Status;
}

static NTSTATUS EiTimerObjectCreateProc(IN POBJECT Object,
					IN PVOID CreaCtx)
{
    PTIMER Timer = (PTIMER)Object;
    PTIMER_OBJ_CREATE_CONTEXT Ctx = (PTIMER_OBJ_CREATE_CONTEXT)CreaCtx;
    KeInitializeTimer(Timer, Ctx->Type);
    return STATUS_SUCCESS;
}

static VOID EiTimerObjectDeleteProc(IN POBJECT Self)
{
    assert(ObObjectIsType(Self, OBJECT_TYPE_TIMER));
    PTIMER Timer = (PTIMER)Self;
    KeUninitializeTimer(Timer);
}

static NTSTATUS EiCreateTimerType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = EiTimerObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = EiTimerObjectDeleteProc
    };
    return ObCreateObjectType(OBJECT_TYPE_TIMER,
			      "Timer",
			      sizeof(TIMER),
			      TypeInfo);
}

static NTSTATUS EiCreateObjectTypes()
{
    RET_ERR(EiCreateTimerType());
    RET_ERR(EiInitEventObject());
    return STATUS_SUCCESS;
}

NTSTATUS ExInitSystemPhase1()
{
    RET_ERR(EiCreateObjectTypes());
    RET_ERR(LdrLoadBootModules());
    RET_ERR(CmInitSystemPhase1());
    RET_ERR(PsInitSystemPhase1());
    RET_ERR(IoInitSystemPhase1());
    RET_ERR(HalInitSystemPhase1());
    RET_ERR(EiStartSessionManager());

    return STATUS_SUCCESS;
}
