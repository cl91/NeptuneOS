#include "obp.h"

static NTSTATUS ObpLookupObjectNameEx(IN PCSTR Path,
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
	*pObject = Object;
	return STATUS_SUCCESS;
    }
    return STATUS_OBJECT_TYPE_MISMATCH;
}

static NTSTATUS ObpCreateHandle(IN PTHREAD Thread,
				IN POBJECT Object,
				OUT HANDLE *pHandle)
{
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(Object != NULL);
    assert(pHandle != NULL);
    ObpAllocatePool(Entry, HANDLE_TABLE_ENTRY);
    Entry->Object = Object;
    MmAvlTreeAppendNode(&Thread->Process->HandleTable.Tree,
			&Entry->AvlNode, HANDLE_VALUE_INC);
    *pHandle = (HANDLE) Entry->AvlNode.Key;
    return STATUS_SUCCESS;
}

NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 IN OBJECT_TYPE_ENUM Type,
				 OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    RET_ERR(ObpLookupObjectNameEx(Path, Type, pObject));
    ObpReferenceObject(*pObject);
    return STATUS_SUCCESS;
}

static NTSTATUS ObpOpenObjectByPointer(IN ASYNC_STATE State,
				       IN PTHREAD Thread,
				       IN POBJECT Object,
				       OUT HANDLE *pHandle)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(pHandle != NULL);
    ASYNC_BEGIN(State);

    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    POBJECT OpenedInstance = NULL;
    assert(ObjectHeader->Type != NULL);
    if (ObjectHeader->Type->TypeInfo.OpenProc != NULL) {
	AWAIT(ObjectHeader->Type->TypeInfo.OpenProc, State, Thread, Object, &OpenedInstance);
    }
    if (OpenedInstance == NULL) {
	OpenedInstance = Object;
    }
    RET_ERR_EX(ObpCreateHandle(Thread, OpenedInstance, pHandle),
	       if (Object != OpenedInstance) {
		   /* TODO: Close the opened instance */
	       });

    ASYNC_END(STATUS_SUCCESS);
}

NTSTATUS ObOpenObjectByName(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
			    IN PCSTR Path,
			    IN OBJECT_TYPE_ENUM Type,
			    OUT HANDLE *pHandle)
{
    assert(Thread != NULL);
    assert(Path != NULL);
    assert(Path[0] != '\0');
    assert(Type < NUM_OBJECT_TYPES);
    assert(pHandle != NULL);
    ASYNC_BEGIN(State);

    POBJECT Object = NULL;
    RET_ERR(ObpLookupObjectNameEx(Path, Type, &Object));
    assert(Object != NULL);

    AWAIT(ObpOpenObjectByPointer, State, Thread, Object, pHandle);

    ASYNC_END(STATUS_SUCCESS);
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
