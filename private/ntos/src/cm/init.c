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
    PCM_KEY_OBJECT Key = NULL;
    KEY_OBJECT_CREATE_CONTEXT Ctx = {
	.Volatile = FALSE,
	.Name = "Machine",
	.NameLength = sizeof("Machine")-1,
	.Parent = NULL
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_KEY, (POBJECT *)&Key, &Ctx));
    RET_ERR(ObInsertObjectByPath(REGISTRY_OBJECT_DIRECTORY "\\Machine", Key));
    Ctx.Name = "User";
    Ctx.NameLength = sizeof("User")-1;
    RET_ERR(ObCreateObject(OBJECT_TYPE_KEY, (POBJECT *)&Key, &Ctx));
    RET_ERR(ObInsertObjectByPath(REGISTRY_OBJECT_DIRECTORY "\\User", Key));
    return STATUS_SUCCESS;
}
