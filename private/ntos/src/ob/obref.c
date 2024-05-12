#include "obp.h"

static NTSTATUS ObpLookupObjectHandle(IN PPROCESS Process,
				      IN HANDLE Handle,
				      OUT POBJECT *pObject,
				      OUT OPTIONAL PHANDLE_TABLE_ENTRY *pEntry)
{
    assert(Process != NULL);
    assert(Handle != NULL);
    assert(pObject != NULL);
    PAVL_NODE Node = AvlTreeFindNode(&Process->HandleTable.Tree, (MWORD) Handle);
    if (Node == NULL) {
	return STATUS_INVALID_HANDLE;
    }
    PHANDLE_TABLE_ENTRY Entry = CONTAINING_RECORD(Node, HANDLE_TABLE_ENTRY, AvlNode);
    *pObject = Entry->Object;
    if (pEntry) {
	*pEntry = Entry;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS ObpLookupObjectHandleWithType(IN PPROCESS Process,
					      IN HANDLE Handle,
					      IN OBJECT_TYPE_ENUM Type,
					      OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    POBJECT Object = NULL;
    RET_ERR(ObpLookupObjectHandle(Process, Handle, &Object, NULL));
    assert(Object != NULL);
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader->Type != NULL);
    if (Type == OBJECT_TYPE_ANY || Type == ObjectHeader->Type->Index) {
	*pObject = Object;
	return STATUS_SUCCESS;
    }
    ObDbg("Object handle %p (process %s) lookup type mismatch: "
	  "expected mask 0x%x found type %d\n",
	  Handle, KEDBG_PROCESS_TO_FILENAME(Process),
	  Type, ObjectHeader->Type->Index);
    return STATUS_OBJECT_TYPE_MISMATCH;
}

/*
 * Create a client handle for the given object.
 */
NTSTATUS ObCreateHandle(IN PPROCESS Process,
			IN POBJECT Object,
			IN BOOLEAN ObjectOpened,
			OUT HANDLE *pHandle)
{
    assert(Object != NULL);
    assert(pHandle != NULL);
    POBJECT_HEADER Header = OBJECT_TO_OBJECT_HEADER(Object);
    ObpAllocatePool(Entry, HANDLE_TABLE_ENTRY);
    Entry->Object = Object;
    Entry->Process = Process;
    Entry->InvokeClose = ObjectOpened;
    InsertTailList(&Header->HandleEntryList, &Entry->HandleEntryLink);
    AvlTreeAppendNode(&Process->HandleTable.Tree,
		      &Entry->AvlNode, HANDLE_VALUE_INC);
    /* Increase the reference count since we now exposing it to client space */
    ObpReferenceObject(Object);
    *pHandle = (HANDLE)Entry->AvlNode.Key;
    return STATUS_SUCCESS;
}

/*
 * Search the object manager namespace for the specified Path with the
 * given type (or OBJECT_TYPE_ANY), returning the pointer to the object body.
 */
NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 IN OBJECT_TYPE_ENUM Type,
				 IN POBJECT RootDirectory,
				 IN BOOLEAN CaseInsensitive,
				 OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    POBJECT Object = NULL;
    NTSTATUS Status = ObParseObjectByName(RootDirectory, Path,
					  CaseInsensitive, &Object);
    if (!NT_SUCCESS(Status)) {
	ObDbg("Object look up failed for %s. Status = 0x%x\n", Path, Status);
	return Status;
    }
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader->Type != NULL);
    if (Type == OBJECT_TYPE_ANY || Type == ObjectHeader->Type->Index) {
	ObpReferenceObject(Object);
	*pObject = Object;
	return STATUS_SUCCESS;
    }
    ObDbg("Object path %s lookup type mismatch: expected type 0x%x found type %d\n",
	  Path, Type, ObjectHeader->Type->Index);
    return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS ObReferenceObjectByHandle(IN PTHREAD Thread,
				   IN HANDLE Handle,
				   IN OBJECT_TYPE_ENUM Type,
				   OUT POBJECT *pObject)
{
    assert(Thread != NULL);
    assert(pObject != NULL);
    if (Handle == NULL) {
	return STATUS_INVALID_HANDLE;
    }
    if (Handle == NtCurrentProcess() && (Type == OBJECT_TYPE_ANY || Type == OBJECT_TYPE_PROCESS)) {
	*pObject = Thread->Process;
    } else if (Handle == NtCurrentThread() && (Type == OBJECT_TYPE_ANY || Type == OBJECT_TYPE_THREAD)) {
	*pObject = Thread;
    } else {
	RET_ERR(ObpLookupObjectHandleWithType(Thread->Process, Handle, Type, pObject));
    }
    ObpReferenceObject(*pObject);
    return STATUS_SUCCESS;
}

/* Remove the object from its parent object (if it exists). */
VOID ObRemoveObject(IN POBJECT Object)
{
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    if (ObjectHeader->ParentObject) {
	ObDbg("Removing object %p (parent %p)\n", Object, ObjectHeader->ParentObject);
	POBJECT_HEADER ParentHeader = OBJECT_TO_OBJECT_HEADER(ObjectHeader->ParentObject);
	assert(ParentHeader);
	assert(ParentHeader->Type);
	OBJECT_REMOVE_METHOD RemoveProc = ParentHeader->Type->TypeInfo.RemoveProc;
	assert(RemoveProc);
	if (RemoveProc) {
	    RemoveProc(Object);
	}
	/* The remove procedure should clear the ParentLink member of the object header. */
	assert(!ObjectHeader->ParentLink);
	/* Dereference the parent object whose refcount we increased in ObInsertObject. */
	ObDereferenceObject(ObjectHeader->ParentObject);
	ObjectHeader->ParentObject = NULL;
    }
}

static VOID ObpDeleteObject(IN POBJECT_HEADER ObjectHeader)
{
    assert(ObjectHeader != NULL);
    assert(ObjectHeader->Type != NULL);
    assert(IsListEmpty(&ObjectHeader->HandleEntryList));

    POBJECT Object = OBJECT_HEADER_TO_OBJECT(ObjectHeader);
    ObDbg("Deleting object %p (type %s)\n", Object,
	  Object ? ObjectHeader->Type->Name : "UNKNOWN-TYPE");
    ObRemoveObject(Object);
    if (ObjectHeader->Type->TypeInfo.DeleteProc != NULL) {
	ObjectHeader->Type->TypeInfo.DeleteProc(Object);
    }
    RemoveEntryList(&ObjectHeader->ObjectLink);
    ObpFreePool(ObjectHeader);
}

VOID ObDereferenceObject(IN POBJECT Object)
{
    assert(Object != NULL);
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader != NULL);
    /* Refcount should never be zero at the time of calling ObDereferenceObject. */
    assert(ObjectHeader->RefCount > 0);

    ObjectHeader->RefCount--;
    /* Handle count should never be larger than refcount, even after dereferencing. */
    assert(ObGetObjectHandleCount(Object) <= ObjectHeader->RefCount);

    if (ObjectHeader->RefCount <= 0) {
	ObpDeleteObject(ObjectHeader);
    }
}

static NTSTATUS ObpCloseHandle(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN PPROCESS Process,
			       IN HANDLE Handle)
{

    NTSTATUS Status = STATUS_NTOS_BUG;

    ASYNC_BEGIN(State, Locals, {
	    POBJECT Object;
	    PHANDLE_TABLE_ENTRY Entry;
	});

    ObDbg("Closing handle %p for process %s\n", Handle, KEDBG_PROCESS_TO_FILENAME(Process));
    if (!Handle) {
	ASYNC_RETURN(State, STATUS_SUCCESS);
    }
    IF_ERR_GOTO(out, Status, ObpLookupObjectHandle(Process, Handle,
						   &Locals.Object, &Locals.Entry));
    assert(Locals.Object);
    assert(Locals.Entry);
    /* Handle count should always be smaller than or equal to refcount. */
    assert(ObGetObjectHandleCount(Locals.Object)
           <= OBJECT_TO_OBJECT_HEADER(Locals.Object)->RefCount);
    /* Invoke the close procedure if we are closing a handle that was
     * created as a result of an open). */
    AWAIT_IF(Locals.Entry->InvokeClose &&
	     OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->TypeInfo.CloseProc,
	     OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->TypeInfo.CloseProc,
	     State, Locals, Thread, Locals.Object);
    AvlTreeRemoveNode(&Process->HandleTable.Tree, &Locals.Entry->AvlNode);
    RemoveEntryList(&Locals.Entry->HandleEntryLink);
    /* If the handle was created during an open, decrease the object refcount
     * because the open routine increased it. */
    if (Locals.Entry->InvokeClose) {
	ObDereferenceObject(Locals.Object);
    }
    ObpFreePool(Locals.Entry);
    /* Decrease the object refcount because ObCreateHandle increased it. */
    ObDereferenceObject(Locals.Object);
    Status = STATUS_SUCCESS;
out:
    ASYNC_END(State, Status);
}

NTSTATUS NtClose(IN ASYNC_STATE State,
		 IN PTHREAD Thread,
		 IN HANDLE Handle)
{
    return ObpCloseHandle(State, Thread, Thread->Process, Handle);
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
    UNIMPLEMENTED;
}

VOID ObDbgDumpObjectHandles(IN POBJECT Object,
			    IN ULONG Indentation)
{
    if (!Object) {
	return;
    }
    POBJECT_HEADER Header = OBJECT_TO_OBJECT_HEADER(Object);
    if (IsListEmpty(&Header->HandleEntryList)) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("No open handle for object %p\n", Object);
	return;
    }
    RtlDbgPrintIndentation(Indentation);
    DbgPrint("Open handles of object %p\n", Object);
    LoopOverList(Entry, &Header->HandleEntryList, HANDLE_TABLE_ENTRY, HandleEntryLink) {
	RtlDbgPrintIndentation(Indentation);
	DbgPrint("  Process %p (%s) Handle 0x%llx InvokeClose %d\n", Entry->Process,
		 KEDBG_PROCESS_TO_FILENAME(Entry->Process), Entry->AvlNode.Key,
		 Entry->InvokeClose);
    }
}
