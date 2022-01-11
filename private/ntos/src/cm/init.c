#include "cmp.h"

static NTSTATUS CmpCreateKeyType()
{
    OBJECT_TYPE_INITIALIZER TypeInfo = {
	.CreateProc = CmpKeyObjectCreateProc,
	.ParseProc = CmpKeyObjectParseProc,
	.OpenProc = CmpKeyObjectOpenProc,
	.InsertProc = NULL,
    };
    return ObCreateObjectType(OBJECT_TYPE_KEY,
			      "Key",
			      sizeof(CM_KEY_OBJECT),
			      TypeInfo);
}

NTSTATUS CmInitSystemPhase1()
{
    RET_ERR(CmpCreateKeyType());
    RET_ERR(ObCreateDirectory(REGISTRY_OBJECT_DIRECTORY));
    return STATUS_SUCCESS;
}
