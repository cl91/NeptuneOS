#include "obp.h"

NTSTATUS ObInitSystem()
{
    InitializeListHead(&ObpObjectList);
    RET_ERR(ObpInitDirectoryObjectType());
    RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY,
			   (POBJECT *) &ObpRootObjectDirectory));

    return STATUS_SUCCESS;
}
