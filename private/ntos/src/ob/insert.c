#include "obp.h"

/*
 * Insert the given object as a subobject of the parent object,
 * with a name identifier. The subobject can later be retrieved
 * by calling the parse routine of the parent object with the
 * supplied name identifier.
 */
NTSTATUS ObInsertObject(IN POBJECT_HEADER Parent,
			IN POBJECT_HEADER Subobject,
			IN PCSTR Name)
{
    assert(Parent != NULL);
    assert(Subobject != NULL);
    assert(Name != NULL);

    return Parent->Type->TypeInfo.InsertProc(OBJECT_HEADER_TO_OBJECT(Parent),
					     Subobject, Name);
}
