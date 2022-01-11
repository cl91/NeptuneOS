#include <ntos.h>
#include <sel4/sel4.h>

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
    OB_PARSE_CONTEXT ParseContext = { .RequestedTypeMask = OBJECT_TYPE_MASK_FILE };
    NTSTATUS Status = ObReferenceObjectByName(SMSS_EXE_PATH, &ParseContext, (POBJECT *)&SmssExe);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(SmssExe != NULL);

    Status = PsCreateProcess(SmssExe, NULL, NULL, &EiSessionManagerProcess);
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
    HalVgaPrint("\nFailed to start Session Manager: ");
    if (SmssExe == NULL) {
	HalVgaPrint("%s not found", SMSS_EXE_PATH);
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

static NTSTATUS EiCreateTimerType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = EiTimerObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_TIMER,
			      "Timer",
			      sizeof(TIMER),
			      TypeInfo);
}

static NTSTATUS EiCreateObjectTypes()
{
    RET_ERR(EiCreateTimerType());
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
