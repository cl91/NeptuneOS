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
 * the pRemainingPath pointer points to the last \NUL byte of the path
 * string. If there is remaining path leftover, the object returned is
 * the final object at which the parse failed. The remaining path points
 * to the sub-path that is yet to be parsed.
 *
 * Directory object can be NULL, in which case the root object directory
 * is assumed. In this case you must specify an absolute path (one
 * that starts with the OBJ_NAME_PATH_SEPARATOR).
 *
 * If the parse procedure returns error, the resulting object of the
 * last successful parse is returned, as well as the remaining path
 * that is yet to be parsed. The remaining path does NOT include the
 * leading OBJ_NAME_PATH_SEPARATOR. The remaining path returned is
 * never NULL, likewise for FoundObject.
 *
 * If at any point the parse procedure returned STATUS_REPARSE or
 * STATUS_REPARSE_OBJECT, the object manager restarts a new parse from
 * the very beginning, using the path string returned by the parse
 * routine.
 *
 * Note that you should not free the remaining path returned by this
 * routine. If you need to store the string returned by the remaining
 * path, you should make a copy.
 */
NTSTATUS ObParseObjectByName(IN POBJECT DirectoryObject,
			     IN PCSTR Path,
			     IN BOOLEAN CaseInsensitive,
			     OUT POBJECT *FoundObject,
			     OUT PCSTR *pRemainingPath)
{
    assert(ObpRootObjectDirectory != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    /* If the directory object is NULL, the path must be an absolute path. */
    assert(DirectoryObject != NULL || Path[0] == OBJ_NAME_PATH_SEPARATOR);

    /* Skip the leading OBJ_NAME_PATH_SEPARATOR. */
    if (Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	Path++;
    }

    /* Points to the terminating '\0' charactor of Path */
    UNUSED PCSTR LastByte = Path + strlen(Path);

    /* Recursively invoke the parse procedure of the object, until
     * one of the following is true:
     *   1. The remaining path is empty
     *   2. The parse procedure returns a failure status
     *   3. The parse procedure is NULL
     */
    POBJECT Object = DirectoryObject ? DirectoryObject : ObpRootObjectDirectory;
    NTSTATUS Status = STATUS_SUCCESS;

    while (*Path != '\0') {
	POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
	OBJECT_PARSE_METHOD ParseProc = ObjectHeader->Type->TypeInfo.ParseProc;
	if (ParseProc == NULL) {
	    /* The object type does not support subobject or namespace */
	    Status = STATUS_OBJECT_TYPE_MISMATCH;
	    break;
	}
	POBJECT Subobject = NULL;
	PCSTR RemainingPath = NULL;
	Status = ParseProc(Object, Path, CaseInsensitive, &Subobject, &RemainingPath);
	if (!NT_SUCCESS(Status)) {
	    break;
	}
	assert(RemainingPath != NULL);
	/* If the parse procedure returned REPARSE, it will set Subobject to the new
	 * root object and remaining path to the new path to be parsed */
	if (!NeedReparse(Status)) {
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
	    POBJECT UserRootDirectory;
	    PCSTR Path;
	});

    if (ObjectAttributes.ObjectNameBuffer == NULL && ObjectAttributes.RootDirectory == NULL) {
	ASYNC_RETURN(AsyncState, STATUS_OBJECT_NAME_INVALID);
    }

    Locals.Object = ObpRootObjectDirectory;
    Locals.OpenedInstance = NULL;
    Locals.UserRootDirectory = NULL;
    Locals.Path = ObjectAttributes.ObjectNameBuffer ? ObjectAttributes.ObjectNameBuffer : "";

    /* If caller has specified a root directory, the object path must be relative */
    if (ObjectAttributes.RootDirectory != NULL && Locals.Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	ASYNC_RETURN(AsyncState, STATUS_OBJECT_PATH_INVALID);
    }
    /* Get the root directory if user has specified one. Otherwise, default to the
     * global root object directory. */
    if (ObjectAttributes.RootDirectory != NULL) {
	ASYNC_RET_ERR(AsyncState, ObReferenceObjectByHandle(Thread,
							    ObjectAttributes.RootDirectory,
							    OBJECT_TYPE_ANY,
							    &Locals.UserRootDirectory));
	assert(Locals.UserRootDirectory != NULL);
	Locals.Object = Locals.UserRootDirectory;
	/* ObReferenceObjectByHandle increased reference count, so we need to dereference it. */
	ObDereferenceObject(Locals.Object);
    }
    /* Skip the leading OBJ_NAME_PATH_SEPARATOR. */
    if (Locals.Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	Locals.Path++;
    }

parse:
    /* If the path to be parsed is now empty, we are done parsing. Open the object. */
    if (*Locals.Path == '\0') {
	goto open;
    }
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
    if (!NT_SUCCESS(Status)) {
	ObDbg("Parsing path %s returned error status 0x%x\n", Locals.Path, Status);
	/* In this case the parse routine should not modify the remaining path. */
	assert(RemainingPath == Locals.Path);
	/* If the parse routine returned OBJECT_NAME_NOT_FOUND or OBJECT_PATH_NOT_FOUND,
	 * we should invoke the open routine. Otherwise we simply fail. */
	if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND) {
	    goto open;
	} else {
	    goto out;
	}
    }
    /* If the parse routine indicates reparse, rerun the parse routine with the
     * new path utill it finds the actual object. */
    if (NeedReparse(Status)) {
	/* Note although the parse routine returned a new string in the RemainingPath,
	 * we do not need to worry about freeing this string, as the parse routine shall
	 * take care of recording this string and freeing it later when the object closes. */
	ObDbg("Reparsing with new path %s\n", RemainingPath);
	/* If we have an absolute path, reparse should start from the global root directory */
	if (RemainingPath[0] == OBJ_NAME_PATH_SEPARATOR) {
	    Locals.Object = ObpRootObjectDirectory;
	}
	/* Otherwise, for a relative path reparse should start from the current object.
	 * In this case we do not need to do anything. */
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
    /* Continue parsing until the remaining path is empty. */
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
	Status = STATUS_OBJECT_NAME_INVALID;
	goto out;
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

    /* The open routine should always set the remaining path */
    assert(RemainingPath != NULL);
    if (!NT_SUCCESS(Status)) {
	ObDbg("Opening path %s on object %p failed, remaining path = %s\n",
	      Locals.Path, Locals.Object, RemainingPath);
	goto out;
    }
    Locals.Path = RemainingPath;

    /* If the open procedure returned REPARSE, restart the process from the
     * very beginning. Note that just like the similar situation above, we do
     * not need to worry about freeing the string returned by the open routine
     * in the RemainingPath variable, because the open routine will take care of
     * recording the allocation and freeing it later, when the object is closed. */
    if (NeedReparse(Status)) {
	/* If reparsing, the open procedure should never touch OpenedInstance */
	assert(OpenedInstance == NULL);
	/* If we have an absolute path, reparse should start from the global root directory */
	if (*Locals.Path == OBJ_NAME_PATH_SEPARATOR) {
	    Locals.Object = ObpRootObjectDirectory;
	}
	/* Otherwise, for a relative path reparse should start from the current object.
	 * In this case we do not need to do anything. */
	ObDbg("Reparsing with new path %s\n", Locals.Path);
    } else {
	/* If the open succeeded, OpenedInstance should not be NULL. */
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
     * This also applies to the reparse case aboove, in which case we invoke the
     * parse routine on the original object with the new path. Note we will not
     * invoke any open routines from this point on in the case where the open
     * succeeded without reparsing.  */
    if (*Locals.Path != '\0') {
	goto parse;
    } else if (NeedReparse(Status)) {
	/* The new path cannot be empty. It is an error if the parse routine
	 * returned REPARSE with an empty path string. */
	assert(FALSE);
	Status = STATUS_OBJECT_NAME_INVALID;
    }

done:
    if (*Locals.Path != '\0') {
	assert(!NT_SUCCESS(Status));
	goto out;
    }
    /* Remaining path is empty. Open is successful. Check the object type. */
    if (Type == OBJECT_TYPE_ANY || Type == OBJECT_TO_OBJECT_HEADER(Locals.Object)->Type->Index) {
	/* Type is valid. Assign the handle. */
	if (AssignHandle) {
	    Status = ObCreateHandle(Thread->Process, Locals.Object, pHandle);
	} else {
	    *pHandle = Locals.Object;
	}
    } else {
	Status = STATUS_OBJECT_TYPE_MISMATCH;
    }

out:
    if (!NT_SUCCESS(Status) && Locals.OpenedInstance) {
	/* FIXME: TODO: Invoke the delete procedure of the opened instance */
    }
    ASYNC_END(AsyncState, Status);
}
