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

NTSTATUS IoInitSystem()
{
    RET_ERR(IopCreateFileType());

    return STATUS_SUCCESS;
}
