#include "obp.h"

/*
 * Insert the given object as a subobject of the parent object,
 * with a name identifier. The subobject can later be retrieved
 * by calling the parse routine of the parent object with the
 * supplied name identifier.
 */
NTSTATUS ObInsertObject(IN POBJECT Parent,
			IN POBJECT Subobject,
			IN PCSTR Name)
{
    assert(Parent != NULL);
    assert(Subobject != NULL);
    assert(Name != NULL);
    POBJECT_HEADER ParentHeader = OBJECT_TO_OBJECT_HEADER(Parent);
    assert(ParentHeader != NULL);

    OBJECT_INSERT_METHOD InsertProc = ParentHeader->Type->TypeInfo.InsertProc;
    if (InsertProc == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    return InsertProc(Parent, Subobject, Name);
}

NTSTATUS ObInsertObjectByName(IN PCSTR ParentPath,
			      IN POBJECT Subobject,
			      IN PCSTR Name)
{
    POBJECT Parent = NULL;
    RET_ERR(ObpLookupObjectName(ParentPath, &Parent));
    assert(Parent != NULL);
    RET_ERR(ObInsertObject(Parent, Subobject, Name));
    return STATUS_SUCCESS;
}

/*
 * After insertion, AbsolutePath will point to the given Object
 * in the global object namespace
 */
NTSTATUS ObInsertObjectByPath(IN PCSTR AbsolutePath,
			      IN POBJECT Object)
{
    assert(AbsolutePath != NULL);
    assert(Object != NULL);

    /* Path must be absolute */
    if (AbsolutePath[0] != OBJ_NAME_PATH_SEPARATOR) {
	return STATUS_INVALID_PARAMETER;
    }

    SIZE_T PathLen = strlen(AbsolutePath);
    /* Start from the last non-nul byte, look for the path separator '\\' */
    SIZE_T SepIndex = 0;
    for (SIZE_T i = PathLen-1; i > 0; i--) {
	if (AbsolutePath[i] == OBJ_NAME_PATH_SEPARATOR) {
	    SepIndex = i;
	    break;
	}
    }
    /* Object path must specify an object name */
    if (AbsolutePath[SepIndex+1] == '\0') {
	return STATUS_INVALID_PARAMETER;
    }

    ObpAllocatePoolEx(ParentPath, CHAR, SepIndex+2, {});
    memcpy(ParentPath, AbsolutePath, SepIndex+1);
    ParentPath[SepIndex+1] = '\0';
    PCSTR ObjectName = &AbsolutePath[SepIndex+1];
    RET_ERR_EX(ObInsertObjectByName(ParentPath, Object, ObjectName),
	       ExFreePool(ParentPath));
    ExFreePool(ParentPath);

    return STATUS_SUCCESS;
}
