#include "iop.h"

static NTSTATUS IopCreateFileType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = IopFileObjectCreateProc,
	.OpenProc = IopFileObjectOpenProc,
	.ParseProc = NULL,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_FILE,
			      "File",
			      sizeof(FILE_OBJECT),
			      TypeInfo);
}

NTSTATUS IoInitSystemPhase0()
{
    RET_ERR(IopCreateFileType());

    return STATUS_SUCCESS;
}

static NTSTATUS IopLoadHalDll()
{
    PFILE_OBJECT HalDll = NULL;
    NTSTATUS Status = ObReferenceObjectByName(HAL_PATH, (POBJECT *) &HalDll);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(HalDll != NULL);

    PSECTION HalDllSection = NULL;
    Status = MmCreateSection(HalDll, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			     &HalDllSection);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(HalDllSection != NULL);
    assert(HalDllSection->ImageSectionObject != NULL);
    ObDeleteObject(HalDllSection);

    return STATUS_SUCCESS;

 fail:
    KeVgaPrint("\nFatal error: ");
    if (HalDll == NULL) {
	KeVgaPrint("%s not found", HAL_PATH);
    } else if (HalDllSection == NULL) {
	KeVgaPrint("create section failed for hal.dll with error 0x%x", Status);
    }
    KeVgaPrint("\n\n");
    return Status;
}

NTSTATUS IoInitSystemPhase1()
{
    RET_ERR(IopLoadHalDll());

    return STATUS_SUCCESS;
}
