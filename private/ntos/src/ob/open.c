#include "obp.h"

static inline BOOLEAN NeedReparse(IN NTSTATUS Status)
{
    return (Status == STATUS_REPARSE) || (Status == STATUS_REPARSE_OBJECT);
}

/*
 * Parse the object path by recursively invoking the parse procedures,
 * starting from the given directory object, and parse as much path as
 * is possible. If the entire path can be parsed, the object returned
 * is the final object that corresponds to the full path. In this case
 * the RemainingPath pointer points to an empty string. If there is
 * remaining path leftover, the object returned is the final object at
 * which the parse failed. The remaining path points to the sub-path
 * that is yet to be parsed. The remaining path does NOT include the
 * leading OBJ_NAME_PATH_SEPARATOR. The remaining path returned is never
 * NULL, likewise for FoundObject.
 *
 * Directory object can be NULL, in which case the root object directory
 * is assumed. In this case you must specify an absolute path (one
 * that starts with the OBJ_NAME_PATH_SEPARATOR).
 *
 * If at any point the parse procedure returned STATUS_REPARSE or
 * STATUS_REPARSE_OBJECT, the object manager restarts a new parse from
 * the very beginning, using the path string returned by the parse
 * routine. The parse routine must always allocate the new string on the
 * ExPool with OB_PARSE_TAG. We generate an assertion if this has not
 * been maintained.
 *
 * On return, *StringToFree contains the pointer to the string that the
 * caller needs to free. The caller must free it using the OB_PARSE_TAG.
 */
NTSTATUS ObpParseObjectByName(IN POBJECT DirectoryObject,
			      IN PCSTR Path,
			      IN BOOLEAN CaseInsensitive,
			      OUT POBJECT *FoundObject,
			      OUT PCSTR *pRemainingPath,
			      OUT PCSTR *StringToFree)
{
    assert(ObpRootObjectDirectory != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    /* If the directory object is NULL, the path must be an absolute path. */
    assert(DirectoryObject != NULL || Path[0] == OBJ_NAME_PATH_SEPARATOR);
    *StringToFree = NULL;

    /* Skip the leading OBJ_NAME_PATH_SEPARATOR. */
    if (Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	Path++;
    }

    /* Points to the terminating NUL of Path */
    UNUSED PCSTR LastByte = Path + strlen(Path);

    /* Recursively invoke the parse procedure of the object, until
     * one of the following is true:
     *   1. The parse procedure is NULL
     *   2. The parse procedure returns STATUS_NTOS_STOP_PARSING
     *   3. The parse procedure returns a failure status
     */
    POBJECT Object = DirectoryObject ? DirectoryObject : ObpRootObjectDirectory;
    NTSTATUS Status = STATUS_SUCCESS;

    while (TRUE) {
	POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
	OBJECT_PARSE_METHOD ParseProc = ObjectHeader->Type->TypeInfo.ParseProc;
	if (!ParseProc) {
	    break;
	}
	POBJECT Subobject = NULL;
	PCSTR RemainingPath = NULL;
	Status = ParseProc(Object, Path, CaseInsensitive, &Subobject, &RemainingPath);
	if (!NT_SUCCESS(Status) || Status == STATUS_NTOS_STOP_PARSING) {
	    break;
	}
	assert(RemainingPath != NULL);
	/* If the parse procedure returned REPARSE, it will set Subobject to the new
	 * root object and RemainingPath to the new path to be parsed. The new path
	 * string must be allocated from the pool with OB_PARSE_TAG. */
	if (NeedReparse(Status)) {
	    assert(RemainingPath);
	    assert(ExCheckPoolObjectTag(RemainingPath, OB_PARSE_TAG));
	    if (*StringToFree) {
		ExFreePoolWithTag(*StringToFree, OB_PARSE_TAG);
	    }
	    *StringToFree = RemainingPath;
	} else {
	    /* Parse procedure should not return a NULL Subobject (unless reparsing) */
	    assert(Subobject != NULL);
	    /* Remaining path should also be within the original Path (unless reparsing) */
	    assert(RemainingPath > Path);
	    assert(RemainingPath <= LastByte);
	}
	/* Skip the leading OBJ_NAME_PATH_SEPARATOR if there is one */
	if (*RemainingPath == OBJ_NAME_PATH_SEPARATOR) {
	    RemainingPath++;
	}
	/* If the parse routine returned REPARSE, it can set the subobject to NULL
	 * to indicate parsing from the root object directory */
	Object = Subobject ? Subobject : ObpRootObjectDirectory;
	Path = RemainingPath;
    }

    *pRemainingPath = Path;
    *FoundObject = Object;
    assert(Path);
    assert(Object);
    if (Path && *Path) {
	/* The object type does not support subobject or namespace. */
	return STATUS_OBJECT_PATH_NOT_FOUND;
    } else {
	/* Path is empty. Parse succeeded. */
	return STATUS_SUCCESS;
    }
}

NTSTATUS ObParseObjectByName(IN POBJECT DirectoryObject,
			     IN PCSTR Path,
                             IN BOOLEAN CaseInsensitive,
                             OUT POBJECT *FoundObject)
{
    PCSTR RemainingPath = NULL, StringToFree = NULL;
    NTSTATUS Status = ObpParseObjectByName(DirectoryObject, Path, CaseInsensitive,
					   FoundObject, &RemainingPath, &StringToFree);
    if (StringToFree) {
	ExFreePoolWithTag(StringToFree, OB_PARSE_TAG);
    }
    if (!NT_SUCCESS(Status)) {
	*FoundObject = NULL;
    }
    return Status;
}

/*
 * Open the given object by first invoking the parse procedures and then
 * invoking the open procedures, the latter of which can sleep. Assign
 * handle to the process if the open procedure has consumed all of specified
 * object path (ie. RemainingPath is empty).
 *
 * Type specifies the object type of the handle (ie. specify OBJECT_TYPE_FILE
 * if you are opening a DEVICE object).
 */
NTSTATUS ObOpenObjectByNameEx(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread,
			      IN OB_OBJECT_ATTRIBUTES ObjectAttributes,
			      IN OBJECT_TYPE_ENUM Type,
			      IN POB_OPEN_CONTEXT OpenContext,
			      IN BOOLEAN AssignHandle,
			      OUT PVOID *pHandle)
{
    assert(ObpRootObjectDirectory != NULL);
    assert(Thread != NULL);
    assert(Thread->Process != NULL);
    assert(pHandle != NULL);

    NTSTATUS Status = STATUS_NTOS_BUG;
    PCSTR RemainingPath = NULL;
    POBJECT OpenedInstance = NULL;

    ASYNC_BEGIN(AsyncState, Locals, {
	    POBJECT Object;
	    POBJECT OpenedInstance;
	    PCSTR Path;
	    PCSTR StringToFree;
	});

    if (ObjectAttributes.ObjectNameBuffer == NULL && ObjectAttributes.RootDirectory == NULL) {
	ASYNC_RETURN(AsyncState, STATUS_OBJECT_NAME_INVALID);
    }

    Locals.Object = ObpRootObjectDirectory;
    Locals.OpenedInstance = NULL;
    Locals.Path = ObjectAttributes.ObjectNameBuffer ? ObjectAttributes.ObjectNameBuffer : "";

    /* If caller has specified a root directory, the object path must be relative */
    if (ObjectAttributes.RootDirectory != NULL && Locals.Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	ASYNC_RETURN(AsyncState, STATUS_OBJECT_PATH_INVALID);
    }
    /* Get the root directory if user has specified one. Otherwise, default to the
     * global root object directory. */
    if (ObjectAttributes.RootDirectory != NULL) {
	POBJECT UserRootDirectory = NULL;
	ASYNC_RET_ERR(AsyncState, ObReferenceObjectByHandle(Thread,
							    ObjectAttributes.RootDirectory,
							    OBJECT_TYPE_ANY,
							    &UserRootDirectory));
	assert(UserRootDirectory != NULL);
	/* ObReferenceObjectByHandle increased reference count, so we need to dereference it. */
	ObDereferenceObject(UserRootDirectory);
	Locals.Object = UserRootDirectory;
    }
    /* Skip the leading OBJ_NAME_PATH_SEPARATOR. */
    if (Locals.Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	Locals.Path++;
    }

parse:
    /* Invoke the parse procedure first. If there isn't a parse procedure,
     * invoke the open procedure instead. */
    if (OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->TypeInfo.ParseProc == NULL) {
	goto open;
    }
    POBJECT Subobject = NULL;
    RemainingPath = Locals.Path;
    Status = OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->TypeInfo.ParseProc(
	Locals.Object, Locals.Path,
	!!(ObjectAttributes.Attributes & OBJ_CASE_INSENSITIVE),
	&Subobject, &RemainingPath);
    if (!NT_SUCCESS(Status) || Status == STATUS_NTOS_STOP_PARSING) {
	ObDbg("Parsing path %s returned error status 0x%x\n", Locals.Path, Status);
	/* In this case the parse routine should not modify the remaining path. */
	assert(RemainingPath == Locals.Path);
	/* If the remaining path is empty, or if the parse routine returned NTOS_STOP_PARSING,
	 * OBJECT_NAME_NOT_FOUND or OBJECT_PATH_NOT_FOUND, we should invoke the open routine.
	 * Otherwise we simply fail. */
	if (!Locals.Path[0] || Status == STATUS_NTOS_STOP_PARSING ||
	    Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND) {
	    goto open;
	} else {
	    goto out;
	}
    }
    if (NeedReparse(Status)) {
	/* If the parse routine indicates reparse, RemainingPath will be the
	 * new path with which we should restart the parse from. */
	ObDbg("Reparsing with new path %s\n", RemainingPath);
	assert(ExCheckPoolObjectTag(RemainingPath, OB_PARSE_TAG));
	if (Locals.StringToFree) {
	    ExFreePoolWithTag(Locals.StringToFree, OB_PARSE_TAG);
	}
	Locals.StringToFree = RemainingPath;
	/* If the parse routine returned a subobject, use that as the new object to
	 * start the reparse from. Otherwise, assume the root object directory. */
        Locals.Object = Subobject ? Subobject : ObpRootObjectDirectory;
    } else {
	/* If we get here, the parse routine has successfully parsed (part
	 * of) the sub-path and returned a sub-object. We continue the parse by
	 * invoking the sub-object's parse routine. This is recursive, until
	 * either the remaining path is empty, or the process errors out. */
	Locals.Object = Subobject;
	ObDbg("Invoking parse routine on sub-object %p sub-path %s\n",
	      Subobject, RemainingPath);
    }
    /* Skip the leading path separator. */
    if (*RemainingPath == OBJ_NAME_PATH_SEPARATOR) {
	RemainingPath++;
    }
    Locals.Path = RemainingPath;
    /* Continue parsing until the object does not define a parse routine. */
    goto parse;

open:
    /* If we have ready opened an object, we are done. */
    if (Locals.OpenedInstance) {
	goto done;
    }

    assert(Locals.Object != NULL);
    assert(OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type != NULL);
    /* If the object type does not define an open procedure, return error */
    if (OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->TypeInfo.OpenProc == NULL) {
	ObDbg("Type %s does not have an open procedure\n",
	      OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->Name);
	goto done;
    }

    /* Increase the reference count of the object so it doesn't get deleted by another
     * client thread during the wait. */
    ObpReferenceObject(Locals.Object);

    /* Call the open procedure, and wait asynchronously. */
    ObDbg("Invoking open routine for object %p with path %s\n",
	  Locals.Object, Locals.Path);
    AWAIT_EX(Status,
	     OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->TypeInfo.OpenProc,
	     AsyncState, Locals, Thread, Locals.Object, Locals.Path,
	     ObjectAttributes.Attributes, OpenContext, &OpenedInstance, &RemainingPath);

    /* Now that the open is done, dereference the object. */
    ObDereferenceObject(Locals.Object);

    /* The open routine should always set the remaining path. */
    assert(RemainingPath != NULL);
    if (!NT_SUCCESS(Status)) {
	ObDbg("Opening path %s on object %p failed, remaining path = %s\n",
	      Locals.Path, Locals.Object, RemainingPath);
	goto out;
    }
    Locals.Path = RemainingPath;

    if (NeedReparse(Status)) {
	/* If the open procedure returned REPARSE, restart the whole process from the
	 * very beginning. In this case the RemainingPath will be the new path with
	 * which we should restart the parse from. */
	ObDbg("Reparsing with new path %s\n", RemainingPath);
	assert(ExCheckPoolObjectTag(RemainingPath, OB_PARSE_TAG));
	if (Locals.StringToFree) {
	    ExFreePoolWithTag(Locals.StringToFree, OB_PARSE_TAG);
	}
	Locals.StringToFree = RemainingPath;
	/* If the open routine returned a subobject, use that as the new object to
	 * start the reparse from. Otherwise, assume the root object directory. */
        Locals.Object = OpenedInstance ? OpenedInstance : ObpRootObjectDirectory;
	assert(!Locals.OpenedInstance);
    } else {
	/* If the open succeeded, OpenedInstance should not be NULL. Note in this
	 * case the open procedure must increase the reference count of the opened
	 * instance before returning. */
	assert(OpenedInstance != NULL);
	/* Record the newly opened instance. */
	Locals.Object = OpenedInstance;
	Locals.OpenedInstance = OpenedInstance;
    }
    /* Skip the leading path separator. */
    if (*Locals.Path == OBJ_NAME_PATH_SEPARATOR) {
	Locals.Path++;
    }
    /* If the remaining path is not empty, invoke the parse routine of the newly
     * opened instance with the remaining path, until the remaining path is empty.
     * This also applies if the open routine returned REPARSE, in which case we
     * restart the whole process from the beginning with the new path. Note we will
     * not invoke any open routines from this point on in the case where the open
     * succeeded without reparsing. */
    if (*Locals.Path != '\0') {
	goto parse;
    } else if (NeedReparse(Status)) {
	/* The new path cannot be empty. It is an error if the parse routine
	 * returned REPARSE with an empty path string (in other words, we don't
	 * allow the root object directory to have any alias). */
	assert(FALSE);
	Status = STATUS_OBJECT_NAME_INVALID;
	goto out;
    }

done:
    if (*Locals.Path != '\0') {
	Status = STATUS_OBJECT_NAME_INVALID;
	goto out;
    }
    /* Remaining path is empty. Open is successful. Check the object type. */
    if (Type == OBJECT_TYPE_ANY || Type == OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->Index) {
	/* Type is valid. Assign the handle. */
	if (AssignHandle) {
	    Status = ObCreateHandle(Thread->Process, Locals.Object, pHandle);
	} else {
	    ObpReferenceObject(Locals.Object);
	    *pHandle = Locals.Object;
	}
    } else {
	Status = STATUS_OBJECT_TYPE_MISMATCH;
    }

out:
    if (Locals.StringToFree) {
	ExFreePoolWithTag(Locals.StringToFree, OB_PARSE_TAG);
    }
    /* Note even in the case of a successful open, we should decrease the refcount
     * of the OpenedInstance, because the open procedure increased its refcount.
     * In the case of a successful open, the final opened object will have its
     * refcount increased, so in the end the refcounting is correctly maintained. */
    if (Locals.OpenedInstance) {
	ObDereferenceObject(Locals.OpenedInstance);
    }
    ASYNC_END(AsyncState, Status);
}
