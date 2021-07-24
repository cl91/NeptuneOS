#include "obp.h"

NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 OUT POBJECT *Object)
{
    if (Object == NULL) {
	return STATUS_NTOS_BUG;
    }
    RET_ERR(ObpLookupObjectName(Path, Object));
    ObpReferenceObject(*Object);
    return STATUS_SUCCESS;
}

NTSTATUS ObDereferenceObject(IN POBJECT Object)
{
    assert(Object != NULL);
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader != NULL);

    ObjectHeader->RefCount--;
    if (ObjectHeader->RefCount < 0) {
	/* This is a programming error since refcount should never
	 * go zero or below.
	 */
	assert(FALSE);
	ObjectHeader->RefCount = 0;
    }

    if (ObjectHeader->RefCount == 0) {
	/* TODO: Invoke the delete routine */
	RemoveEntryList(&ObjectHeader->ObjectLink);
	ExFreePool(ObjectHeader);
    }

    return STATUS_SUCCESS;
}
