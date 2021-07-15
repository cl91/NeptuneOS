#include "obp.h"

NTSTATUS ObInitSystem()
{
    InitializeListHead(&ObpObjectList);
    RET_ERR(ObpInitDirectoryObjectType());
    RET_ERR(ObCreateObject(OBJECT_TYPE_DIRECTORY,
			   (PVOID *) &ObpRootObjectDirectory));

    return STATUS_SUCCESS;
}
