#include "obp.h"

NTSTATUS ObInitSystemPhase0()
{
    InitializeListHead(&ObpObjectList);
    RET_ERR(ObpInitDirectoryObjectType());
    RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY,
			   (POBJECT *) &ObpRootObjectDirectory,
			   NULL, NULL, 0, NULL));

    return STATUS_SUCCESS;
}
