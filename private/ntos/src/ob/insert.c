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
