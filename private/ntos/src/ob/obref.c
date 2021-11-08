#include "obp.h"

NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 IN OBJECT_TYPE_ENUM Type,
				 OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    POBJECT Object = NULL;
    RET_ERR(ObpLookupObjectName(Path, &Object));
    assert(Object != NULL);
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader->Type != NULL);
    if (ObjectHeader->Type->Index == Type) {
	ObpReferenceObject(Object);
	*pObject = Object;
	return STATUS_SUCCESS;
    }
    return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS ObDeleteObject(IN POBJECT Object)
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

NTSTATUS NtClose(IN ASYNC_STATE State,
		 IN PTHREAD Thread,
		 IN HANDLE Handle)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS NtDuplicateObject(IN ASYNC_STATE State,
			   IN PTHREAD Thread,
                           IN HANDLE SourceProcessHandle,
                           IN HANDLE SourceHandle,
                           IN HANDLE TargetProcessHandle,
                           OUT HANDLE *TargetHandle,
                           IN ACCESS_MASK DesiredAccess,
                           IN BOOLEAN InheritHandle,
                           IN ULONG Options)
{
    return STATUS_NOT_IMPLEMENTED;
}
