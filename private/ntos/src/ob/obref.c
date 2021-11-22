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

static NTSTATUS ObpLookupObjectHandle(IN PPROCESS Process,
				      IN HANDLE Handle,
				      OUT POBJECT *pObject)
{
    assert(Process != NULL);
    assert(Handle != NULL);
    assert(pObject != NULL);
    PMM_AVL_NODE Node = MmAvlTreeFindNode(&Process->HandleTable.Tree, (MWORD) Handle);
    if (Node == NULL) {
	return STATUS_INVALID_HANDLE;
    }
    *pObject = CONTAINING_RECORD(Node, HANDLE_TABLE_ENTRY, AvlNode)->Object;
    return STATUS_SUCCESS;
}

static NTSTATUS ObpLookupObjectHandleEx(IN PPROCESS Process,
					IN HANDLE Handle,
					IN OBJECT_TYPE_ENUM Type,
					OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    POBJECT Object = NULL;
    RET_ERR(ObpLookupObjectHandle(Process, Handle, &Object));
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
    POBJECT_HEADER Header = OBJECT_TO_OBJECT_HEADER(Object);
    ObpAllocatePool(Entry, HANDLE_TABLE_ENTRY);
    Entry->Object = Object;
    InsertTailList(&Header->HandleEntryList, &Entry->HandleEntryLink);
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

NTSTATUS ObReferenceObjectByHandle(IN PPROCESS Process,
				   IN HANDLE Handle,
				   IN OBJECT_TYPE_ENUM Type,
				   OUT POBJECT *pObject)
{
    assert(Process != NULL);
    assert(Handle != NULL);
    assert(pObject != NULL);
    RET_ERR(ObpLookupObjectHandleEx(Process, Handle, Type, pObject));
    ObpReferenceObject(*pObject);
    return STATUS_SUCCESS;
}

static NTSTATUS ObpOpenObjectByPointer(IN ASYNC_STATE State,
				       IN PTHREAD Thread,
				       IN POBJECT Object,
				       IN PVOID Context,
				       OUT PVOID OpenResponse,
				       OUT HANDLE *pHandle)
{
    assert(Thread != NULL);
    assert(Object != NULL);
    assert(pHandle != NULL);

    /* These must come before ASYNC_BEGIN since local variables
     * are not preserved across async suspension and resumption. */
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    POBJECT OpenedInstance = NULL;
    NTSTATUS Status;

    ASYNC_BEGIN(State);
    assert(ObjectHeader->Type != NULL);

    AWAIT_EX_IF(ObjectHeader->Type->TypeInfo.OpenProc != NULL,
		ObjectHeader->Type->TypeInfo.OpenProc,
		Status, State, Thread, Object, Context,
		OpenResponse, &OpenedInstance);
    if (OpenedInstance == NULL) {
	OpenedInstance = Object;
    }
    if (NT_SUCCESS(Status)) {
	RET_ERR_EX(ObpCreateHandle(Thread, OpenedInstance, pHandle),
		   if (Object != OpenedInstance) {
		       /* TODO: Close opened instance */
		   });
    }

    ASYNC_END(Status);
}

NTSTATUS ObOpenObjectByName(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
			    IN PCSTR Path,
			    IN OBJECT_TYPE_ENUM Type,
			    IN PVOID Context,
			    OUT PVOID OpenResponse,
			    OUT HANDLE *pHandle)
{
    assert(Thread != NULL);
    assert(Path != NULL);
    assert(Path[0] != '\0');
    assert(Type < NUM_OBJECT_TYPES);
    assert(pHandle != NULL);

    /* When the async function is resumed the object may have been deleted.
     * Rerun the parse routines to make sure it's still there. */
    POBJECT Object = NULL;
    NTSTATUS Status = ObpLookupObjectNameEx(Path, Type, &Object);
    NTSTATUS OpenStatus;

    ASYNC_BEGIN(State);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    AWAIT_EX_IF(NT_SUCCESS(Status),
		ObpOpenObjectByPointer, OpenStatus, State, Thread,
		Object, Context, OpenResponse, pHandle);

    if (!NT_SUCCESS(Status)) {
	/* We should never delete the object when there is still pending
	 * open request on it. Assert in debug build. */
	assert(FALSE);
	return Status;
    }

    ASYNC_END(OpenStatus);
}

static VOID ObpDeleteObject(IN POBJECT_HEADER ObjectHeader)
{
    assert(ObjectHeader != NULL);

    /* TODO: Invoke the delete routine */
    RemoveEntryList(&ObjectHeader->ObjectLink);
    ExFreePool(ObjectHeader);
}

VOID ObDereferenceObject(IN POBJECT Object)
{
    assert(Object != NULL);
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader != NULL);

    ObjectHeader->RefCount--;
    if (ObjectHeader->RefCount < 0) {
       /* This is a programming error since refcount should never
        * be zero at the time of calling ObDereferenceObject.
        */
       assert(FALSE);
       ObjectHeader->RefCount = 0;
    }
    if (ObjectHeader->RefCount == 0) {
	ObpDeleteObject(ObjectHeader);
    }
}

/*
 * We should always do lazy close and just flag the object
 * for closing and inform driver of object closure whenever
 * the driver asks for more IRPs.
 */
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
