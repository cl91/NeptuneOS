#include "obp.h"

static inline BOOLEAN NeedReparse(IN NTSTATUS Status)
{
    return (Status == STATUS_REPARSE) || (Status == STATUS_REPARSE_OBJECT);
}

/*
 * Parse the object path by recursively invoke the parse procedures
 * and return the final object to which the path points, in which
 * case the remaining path is empty, or until either the object does
 * not have a parse procedure or if the parse procedure returns
 * STATUS_NTOS_PARSE_DONE. In this case the remaining path points to
 * the sub-path that is yet to be parsed.
 *
 * If the parse procedure returns error, the resulting object of the
 * last successful parse is returned, as well as the remaining path
 * that is yet to be parsed.
 *
 * If at any point the parse procedure returned STATUS_REPARSE or
 * STATUS_REPARSE_OBJECT, the remaining path is set to the full path
 * of the new path to be parsed, and the object manager restarts the
 * new parse from the very beginning.
 */
NTSTATUS ObpLookupObjectName(IN PCSTR Path,
			     IN PVOID ParseContext,
			     OUT PCSTR *pRemainingPath,
			     OUT POBJECT *FoundObject)
{
    assert(ObpRootObjectDirectory != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);

    /* We always start the lookup from the root directory.
     * It is an error to specify a relative path. */
    if (Path[0] != OBJ_NAME_PATH_SEPARATOR) {
	return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    /* Points to the terminating '\0' charactor of Path */
    PCSTR LastByte = Path + strlen(Path);

    /* Skip the leading OBJ_NAME_PATH_SEPARATOR. */
    Path++;

    /* Recursively invoke the parse procedure of the object, until
     * one of the following is true:
     *   1. The remaining path is empty
     *   2. The parse procedure returns a failure status
     *   3. The parse procedure is NULL
     *   4. The parse procedure returns STATUS_NTOS_PARSE_DONE
     *   5. The parse procedure returns STATUS_REPARSE or STATUS_REPARSE_OBJECT
     */
    POBJECT Object = ObpRootObjectDirectory;
    NTSTATUS Status = STATUS_SUCCESS;

    while (*Path != '\0') {
	POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
	OBJECT_PARSE_METHOD ParseProc = ObjectHeader->Type->TypeInfo.ParseProc;
	if (ParseProc == NULL) {
	    break;
	}
	POBJECT Subobject = NULL;
	PCSTR RemainingPath = NULL;
	Status = ParseProc(Object, Path, ParseContext, &Subobject, &RemainingPath);
	if (!NT_SUCCESS(Status) || NeedReparse(Status) || Status == STATUS_NTOS_PARSE_DONE) {
	    break;
	}
	/* Parse procedure should not return a NULL Subobject (unless reparsing) */
	assert(Subobject != NULL);
	/* Remaining path should not have leading OBJ_NAME_PATH_SEPARATOR (unless reparsing) */
	assert(*RemainingPath != OBJ_NAME_PATH_SEPARATOR);
	/* Remaining path should also be within the original Path (unless reparsing) */
	assert(RemainingPath > Path);
	assert(RemainingPath <= LastByte);
	/* If all is good, keep going. */
	Object = Subobject;
	Path = RemainingPath;
    }

    *pRemainingPath = Path;
    *FoundObject = Object;
    return Status;
}

/*
 * Just like ObpLookupObjectName, but we also check if the object type
 * matches the specified type mask (unless STATUS_REPARSE or STATUS_REPARSE_OBJECT
 * is returned).
 */
static NTSTATUS ObpLookupObjectNameEx(IN PCSTR Path,
				      IN OBJECT_TYPE_MASK Type,
				      IN PVOID ParseContext,
				      OUT PCSTR *pRemainingPath,
				      OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    POBJECT Object = NULL;
    PCSTR RemainingPath = NULL;
    NTSTATUS Status = ObpLookupObjectName(Path, ParseContext, &RemainingPath, &Object);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(Object != NULL);
    assert(RemainingPath != NULL);
    if (NeedReparse(Status)) {
	*pRemainingPath = RemainingPath;
	return STATUS_REPARSE_OBJECT;
    }
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader->Type != NULL);
    if ((1UL << ObjectHeader->Type->Index) & Type) {
	*pObject = Object;
	*pRemainingPath = RemainingPath;
	return STATUS_SUCCESS;
    }
    DbgTrace("Object path %s lookup type mismatch: expected mask 0x%x found type %d\n",
	     Path, Type, ObjectHeader->Type->Index);
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
					IN OBJECT_TYPE_MASK Type,
					OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    POBJECT Object = NULL;
    RET_ERR(ObpLookupObjectHandle(Process, Handle, &Object));
    assert(Object != NULL);
    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    assert(ObjectHeader->Type != NULL);
    if ((1UL << ObjectHeader->Type->Index) == Type) {
	*pObject = Object;
	return STATUS_SUCCESS;
    }
    assert(Process->ImageFile != NULL);
    DbgTrace("Object handle %p (process %s) lookup type mismatch: expected mask 0x%x found type %d\n",
	     Handle, Process->ImageFile->FileName ? Process->ImageFile->FileName : "UNKNOWN",
	     Type, ObjectHeader->Type->Index);
    return STATUS_OBJECT_TYPE_MISMATCH;
}

NTSTATUS ObCreateHandle(IN PPROCESS Process,
			IN POBJECT Object,
			OUT HANDLE *pHandle)
{
    assert(Object != NULL);
    assert(pHandle != NULL);
    POBJECT_HEADER Header = OBJECT_TO_OBJECT_HEADER(Object);
    ObpAllocatePool(Entry, HANDLE_TABLE_ENTRY);
    Entry->Object = Object;
    InsertTailList(&Header->HandleEntryList, &Entry->HandleEntryLink);
    MmAvlTreeAppendNode(&Process->HandleTable.Tree,
			&Entry->AvlNode, HANDLE_VALUE_INC);
    *pHandle = (HANDLE) Entry->AvlNode.Key;
    return STATUS_SUCCESS;
}

NTSTATUS ObReferenceObjectByName(IN PCSTR Path,
				 IN OBJECT_TYPE_MASK Type,
				 IN PVOID ParseContext,
				 OUT POBJECT *pObject)
{
    assert(pObject != NULL);
    PCSTR RemainingPath = NULL;
    RET_ERR(ObpLookupObjectNameEx(Path, Type, ParseContext, &RemainingPath, pObject));
    assert(RemainingPath != NULL);
    /* Return error if the path cannot be fully parsed */
    if (*RemainingPath != '\0') {
	DbgTrace("Unable to parse remaining path %s\n", RemainingPath);
	return STATUS_OBJECT_NAME_INVALID;
    }
    ObpReferenceObject(*pObject);
    return STATUS_SUCCESS;
}

NTSTATUS ObReferenceObjectByHandle(IN PPROCESS Process,
				   IN HANDLE Handle,
				   IN OBJECT_TYPE_MASK Type,
				   OUT POBJECT *pObject)
{
    assert(Process != NULL);
    assert(Handle != NULL);
    assert(pObject != NULL);
    RET_ERR(ObpLookupObjectHandleEx(Process, Handle, Type, pObject));
    ObpReferenceObject(*pObject);
    return STATUS_SUCCESS;
}

/*
 * Open the given path by first invoking the parse procedures and then
 * invoking the open procedures, the latter of which can sleep. Assign
 * handle to the process if the open procedure has consumed all of Path
 * (ie. RemainingPath is empty).
 *
 * Note: OpenResponse must be large enough to accommodate the open responses
 * of all intermediate open procedure invocations.
 */
NTSTATUS ObOpenObjectByName(IN ASYNC_STATE AsyncState,
			    IN PTHREAD Thread,
			    IN PCSTR Path,
			    IN OBJECT_TYPE_MASK Type,
			    IN PVOID ParseContext,
			    OUT PVOID OpenResponse,
			    OUT HANDLE *pHandle)
{
    assert(Thread != NULL);
    assert(Path != NULL);
    assert(Path[0] != '\0');
    assert(pHandle != NULL);

    NTSTATUS Status = STATUS_NTOS_BUG;
    BOOLEAN PathIsModified = FALSE;
    POBJECT OpenedInstance = NULL;
    POBJECT Object = NULL;
    PCSTR RemainingPath = NULL;

    ASYNC_BEGIN(AsyncState);

    /* Invoke the parse procedure first */
reparse:
    Status = ObpLookupObjectNameEx(Path, Type, ParseContext, &RemainingPath, &Object);
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Parsing path %s failed\n", Path);
	goto out;
    }
    /* If the parse routine indicates reparse, rerun the parse routine with the
     * new path utill it finds the actual object */
    if (NeedReparse(Status)) {
	if (PathIsModified) {
	    ExFreePool(Path);
	}
	Path = RemainingPath;
	PathIsModified = TRUE;
	DbgTrace("Reparsing with new path %s\n", Path);
	goto reparse;
    }

    /* If we got here, we have found an object that needs to be opened. */
open:
    assert(Object != NULL);
    assert(OBJECT_TO_OBJECT_HEADER(Object)->Type != NULL);
    /* If the object type does not define an open procedure, return error */
    if (OBJECT_TO_OBJECT_HEADER(Object)->Type->TypeInfo.OpenProc == NULL) {
	DbgTrace("Type %s does not have an open procedure\n",
		 OBJECT_TO_OBJECT_HEADER(Object)->Type->Name);
	Status = STATUS_OBJECT_NAME_INVALID;
	goto out;
    }
    /* Save the object to THREAD because we may need to suspend it below. */
    Thread->ObOpenObjectSavedState.Object = Object;
    /* Also save the path to be parsed, since it might have changed due to reparse */
    Thread->ObOpenObjectSavedState.Path = RemainingPath;
    Thread->ObOpenObjectSavedState.PathIsModified = PathIsModified;

    AWAIT_EX(OBJECT_TO_OBJECT_HEADER(Thread->ObOpenObjectSavedState.Object)->Type->TypeInfo.OpenProc,
	     Status, AsyncState, Thread, Thread->ObOpenObjectSavedState.Object,
	     Thread->ObOpenObjectSavedState.Path,
	     ParseContext, &OpenedInstance, &RemainingPath, OpenResponse);

    if (!NT_SUCCESS(Status)) {
	DbgTrace("Opening subpath %s failed\n", Thread->ObOpenObjectSavedState.Path);
	goto out;
    }
    /* If the open procedure returned REPARSE, start from the very beginning */
    if (NeedReparse(Status)) {
	/* If reparsing, the open procedure should never touch OpenedInstance */
	assert(OpenedInstance == NULL);
	if (Thread->ObOpenObjectSavedState.PathIsModified) {
	    ExFreePool(Thread->ObOpenObjectSavedState.Path);
	}
	Path = RemainingPath;
	PathIsModified = TRUE;
	DbgTrace("Reparsing with new path %s\n", Path);
	goto reparse;
    }
    /* Otherwise, the OpenedInstance should not be NULL */
    assert(OpenedInstance != NULL);
    /* RemainingPath should not be NULL either. The open procedure should always
     * set OpenedInstance and RemainingPath on successful open (unless reparsing). */
    assert(RemainingPath != NULL);
    /* If RemainingPath is not empty, invoke the open procedure of the opened instance
     * with the remaining path. This is recursive, until the remaining path is empty */
    if (*RemainingPath != '\0') {
	/* However, if the opened instance does not support being opened, we should
	 * return error */
	if (OBJECT_TO_OBJECT_HEADER(Object)->Type->TypeInfo.OpenProc == NULL) {
	    DbgTrace("Type %s does not have an open procedure\n",
		     OBJECT_TO_OBJECT_HEADER(Object)->Type->Name);
	    /* TODO: Close the opened instance */
	    if (Thread->ObOpenObjectSavedState.PathIsModified) {
		ExFreePool(Thread->ObOpenObjectSavedState.Path);
	    }
	    Status = STATUS_OBJECT_NAME_INVALID;
	    goto out_no_free;
	}
	Object = OpenedInstance;
	/* We don't need to set Path here since it is not needed by the code path above */
	goto open;
    }

    /* RemainingPath is empty. Open is successful. Assign the handle */
    RET_ERR_EX(ObCreateHandle(Thread->Process, OpenedInstance, pHandle),
	       {
		   /* TODO: Close opened instance */
	       });
    Status = STATUS_SUCCESS;

out:
    if (PathIsModified) {
	ExFreePool(Path);
    }
out_no_free:
    /* Clear the saved states in THREAD. */
    Thread->ObOpenObjectSavedState.Object = NULL;
    Thread->ObOpenObjectSavedState.Path = NULL;
    Thread->ObOpenObjectSavedState.PathIsModified = FALSE;
    ASYNC_END(Status);
}

VOID ObpDeleteObject(IN POBJECT_HEADER ObjectHeader)
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
