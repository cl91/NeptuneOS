#include "iop.h"

LIST_ENTRY IopDriverList;

static NTSTATUS IopCreateFileType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = IopFileObjectCreateProc,
	.ParseProc = NULL,
	.OpenProc = IopFileObjectOpenProc,
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
	.ParseProc = NULL,
	.OpenProc = IopDeviceObjectOpenProc,
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
	.ParseProc = NULL,
	.OpenProc = NULL,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_DRIVER,
			      "Driver",
			      sizeof(IO_DRIVER_OBJECT),
			      TypeInfo);
}

NTSTATUS IoInitSystemPhase0()
{
    InitializeListHead(&IopDriverList);
    RET_ERR(IopCreateFileType());
    RET_ERR(IopCreateDeviceType());
    RET_ERR(IopCreateDriverType());
    RET_ERR(ObCreateDirectory(DRIVER_OBJECT_DIRECTORY));
    RET_ERR(ObCreateDirectory(DEVICE_OBJECT_DIRECTORY));

    return STATUS_SUCCESS;
}

static NTSTATUS IopLoadWdmDll()
{
    PIO_FILE_OBJECT WdmDll = NULL;
    NTSTATUS Status = ObReferenceObjectByName(WDM_DLL_PATH, OBJECT_TYPE_FILE,
					      NULL, (POBJECT *) &WdmDll);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(WdmDll != NULL);

    PSECTION WdmDllSection = NULL;
    Status = MmCreateSection(WdmDll, 0, SEC_IMAGE | SEC_RESERVE | SEC_COMMIT,
			     &WdmDllSection);
    if (!NT_SUCCESS(Status)) {
	goto fail;
    }
    assert(WdmDllSection != NULL);
    assert(WdmDllSection->ImageSectionObject != NULL);
    ObDereferenceObject(WdmDllSection);

    return STATUS_SUCCESS;

 fail:
    HalVgaPrint("\nFatal error: ");
    if (WdmDll == NULL) {
	HalVgaPrint("%s not found", WDM_DLL_PATH);
    } else if (WdmDllSection == NULL) {
	HalVgaPrint("create section failed for wdm.dll with error 0x%x", Status);
    }
    HalVgaPrint("\n\n");
    return Status;
}

NTSTATUS IoInitSystemPhase1()
{
    RET_ERR(IopLoadWdmDll());

    return STATUS_SUCCESS;
}
