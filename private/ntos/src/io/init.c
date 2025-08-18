#include "iop.h"

LIST_ENTRY IopDriverList;

static NTSTATUS IopCreateFileType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = IopFileObjectCreateProc,
	.ParseProc = IopFileObjectParseProc,
	.OpenProc = IopFileObjectOpenProc,
	.CloseProc = IopFileObjectCloseProc,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = IopFileObjectDeleteProc
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
	.ParseProc = IopDeviceObjectParseProc,
	.OpenProc = IopDeviceObjectOpenProc,
	.CloseProc = IopDeviceObjectCloseProc,
	.InsertProc = IopDeviceObjectInsertProc,
	.RemoveProc = IopDeviceObjectRemoveProc,
	.DeleteProc = IopDeviceObjectDeleteProc
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
	.CloseProc = NULL,
	.InsertProc = NULL,
	.RemoveProc = NULL,
	.DeleteProc = IopDriverObjectDeleteProc
    };
    return ObCreateObjectType(OBJECT_TYPE_DRIVER,
			      "Driver",
			      sizeof(IO_DRIVER_OBJECT),
			      TypeInfo);
}

NTSTATUS IoInitSystemPhase0()
{
    InitializeListHead(&IopDriverList);
    InitializeListHead(&IopNtosPendingIrpList);
    RET_ERR(IopCreateFileType());
    RET_ERR(IopCreateDeviceType());
    RET_ERR(IopCreateDriverType());
    RET_ERR(ObCreateDirectory(DRIVER_OBJECT_DIRECTORY));
    RET_ERR(ObCreateDirectory(DEVICE_OBJECT_DIRECTORY));
    RET_ERR(ObCreateDirectory(FILE_SYSTEM_OBJECT_DIRECTORY));
    RET_ERR(CcInitializeCacheManager());

    return STATUS_SUCCESS;
}

NTSTATUS IoInitSystemPhase1()
{
    RET_ERR(IopInitFileSystem());
    RET_ERR(IopInitPnpManager());

    return STATUS_SUCCESS;
}
