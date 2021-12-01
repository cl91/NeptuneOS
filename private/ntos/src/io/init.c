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
			      sizeof(IO_FILE_OBJECT),
			      TypeInfo);
}

static NTSTATUS IopCreateDeviceType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = IopDeviceObjectCreateProc,
	.OpenProc = IopDeviceObjectOpenProc,
	.ParseProc = NULL,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_DEVICE,
			      "Device",
			      sizeof(IO_DEVICE_OBJECT),
			      TypeInfo);
}

static NTSTATUS IopCreateDriverType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = IopDriverObjectCreateProc,
	.OpenProc = NULL,
	.ParseProc = NULL,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_DRIVER,
			      "Driver",
			      sizeof(IO_DRIVER_OBJECT),
			      TypeInfo);
}

NTSTATUS IoInitSystemPhase0()
{
    RET_ERR(IopCreateFileType());
    RET_ERR(IopCreateDeviceType());
    RET_ERR(IopCreateDriverType());
    RET_ERR(ObCreateDirectory(DRIVER_OBJECT_DIRECTORY));
    RET_ERR(ObCreateDirectory(DEVICE_OBJECT_DIRECTORY));

    return STATUS_SUCCESS;
}

static NTSTATUS IopLoadHalDll()
{
    PIO_FILE_OBJECT HalDll = NULL;
    NTSTATUS Status = ObReferenceObjectByName(HAL_PATH, OBJECT_TYPE_FILE, (POBJECT *) &HalDll);
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
    ObDereferenceObject(HalDllSection);

    return STATUS_SUCCESS;

 fail:
    HalVgaPrint("\nFatal error: ");
    if (HalDll == NULL) {
	HalVgaPrint("%s not found", HAL_PATH);
    } else if (HalDllSection == NULL) {
	HalVgaPrint("create section failed for hal.dll with error 0x%x", Status);
    }
    HalVgaPrint("\n\n");
    return Status;
}

NTSTATUS IoInitSystemPhase1()
{
    RET_ERR(IopLoadHalDll());

    return STATUS_SUCCESS;
}
