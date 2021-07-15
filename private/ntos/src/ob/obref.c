#include "obp.h"

NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 OUT PVOID *Object)
{
    POBJECT_HEADER ObjectHeader = NULL;
    RET_ERR(ObpLookupObjectName(Path, &ObjectHeader));
    assert(ObjectHeader != NULL);
    ObpReferenceObject(ObjectHeader);
    *Object = OBJECT_HEADER_TO_OBJECT(ObjectHeader);
    return STATUS_SUCCESS;
}

NTSTATUS ObDereferenceObject(IN PVOID Object)
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
