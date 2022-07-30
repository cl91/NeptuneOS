#include "obp.h"

static OBJECT_TYPE ObpObjectTypes[MAX_NUM_OBJECT_TYPES];
LIST_ENTRY ObpObjectList;

static inline POBJECT_TYPE ObpGetObjectType(IN OBJECT_TYPE_ENUM Type)
{
    assert(Type < MAX_NUM_OBJECT_TYPES);
    return &ObpObjectTypes[Type];
}

NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_ENUM Type,
			    IN PCSTR TypeName,
			    IN ULONG ObjectBodySize,
			    IN OBJECT_TYPE_INITIALIZER Init)
{
    assert(TypeName != NULL);
    assert(ObjectBodySize != 0);
    assert(Init.CreateProc != NULL);
    assert(Init.DeleteProc != NULL);
    /* The remove procedure cannot be NULL if the insert procedure
     * is supplied. */
    if (Init.InsertProc != NULL) {
	assert(Init.RemoveProc != NULL);
    }

    POBJECT_TYPE ObjectType = ObpGetObjectType(Type);
    ObjectType->Name = TypeName;
    ObjectType->Index = Type;
    ObjectType->ObjectBodySize = ObjectBodySize;
    ObjectType->TypeInfo = Init;

    return STATUS_SUCCESS;
}

/*
 * Insert the given object as a subobject of the parent object,
 * with a name identifier. The subobject can later be retrieved
 * by calling the parse routine of the parent object with the
 * supplied name identifier.
 *
 * Unless the OBJ_NO_PARSE flag is specified, the parse procedure
 * is invoked first on the directory object and will parse the
 * subpath until it cannot be parsed. If the remaining path is now
 * empty, object insertion fails and we return STATUS_OBJECT_NAME_
 * COLLISION. Otherwise, the insert procedure is invoked on the
 * final parse result and its result is returned.
 *
 * The directory object can be NULL, in which case the root object
 * directory is assumed. In this case you must specify an absolute
 * path.
 */
static NTSTATUS ObpInsertObject(IN POBJECT DirectoryObject,
				IN POBJECT Subobject,
				IN PCSTR Name,
				IN ULONG Flags,
				OUT POBJECT *pParentObject,
				OUT PCSTR *pRemainingPath)
{
    assert(Subobject != NULL);
    assert(Name != NULL);
    assert(pParentObject != NULL);
    assert(pRemainingPath != NULL);

    POBJECT Parent = DirectoryObject ? DirectoryObject : ObpRootObjectDirectory;
    PCSTR RemainingPath = Name;
    if (!(Flags & OBJ_NO_PARSE)) {
	/* Note that we don't check the return value of the lookup here,
	 * because we rely on the remaining path to determine whether the
	 * path has been fully parsed. */
	ObpLookupObjectName(DirectoryObject, Name, &RemainingPath, &Parent);
	assert(Parent != NULL);
	assert(RemainingPath != NULL);
	/* If the remaining path is empty, it means that there is already an
	 * object with the given path. In this case we reject the insertion. */
	if (*RemainingPath == '\0') {
	    return STATUS_OBJECT_NAME_COLLISION;
	}
    }
    assert(*RemainingPath != OBJ_NAME_PATH_SEPARATOR);

    POBJECT_HEADER ParentHeader = OBJECT_TO_OBJECT_HEADER(Parent);
    assert(ParentHeader != NULL);

    OBJECT_INSERT_METHOD InsertProc = ParentHeader->Type->TypeInfo.InsertProc;
    if (InsertProc == NULL) {
	return STATUS_INVALID_PARAMETER;
    }

    RET_ERR(InsertProc(Parent, Subobject, RemainingPath));
    *pParentObject = Parent;
    *pRemainingPath = RemainingPath;
    return STATUS_SUCCESS;
}

/*
 * Request the correct amount of memory (object header + body)
 * from the Executive Pool (allocated memory is zeroed by ExPool), invoke the
 * initialization procedure of the object type, and insert the object
 * into the global object list. If specified, will also insert the object
 * under the given sub-path of the directory object.
 */
NTSTATUS ObCreateObject(IN OBJECT_TYPE_ENUM Type,
			OUT POBJECT *pObject,
			IN OPTIONAL POBJECT DirectoryObject,
			IN OPTIONAL PCSTR Subpath,
			IN ULONG Flags,
			IN PVOID CreationContext)
{
    assert(pObject != NULL);
    /* If a sub-path is given, it cannot be empty. */
    assert(Subpath == NULL || Subpath[0] != '\0');
    /* If a directory object is specified, a valid sub-path is needed. */
    assert(DirectoryObject == NULL || Subpath != NULL);
    POBJECT_TYPE ObjectType = ObpGetObjectType(Type);
    assert(ObjectType->TypeInfo.CreateProc != NULL);
    assert(ObjectType->TypeInfo.DeleteProc != NULL);

    /* If we are given a sub-path to insert into, make sure there isn't
     * already an object there. */
    if (Subpath != NULL) {
	POBJECT Object = NULL;
	NTSTATUS Status = ObReferenceObjectByName(Subpath,
						  OBJECT_TYPE_ANY,
						  DirectoryObject,
						  &Object);
	if (Object != NULL) {
	    ObDereferenceObject(Object);
	}
	if (NT_SUCCESS(Status)) {
	    return STATUS_OBJECT_NAME_COLLISION;
	}
    }

    MWORD TotalSize = sizeof(OBJECT_HEADER) + ObjectType->ObjectBodySize;
    ObpAllocatePoolEx(ObjectHeader, OBJECT_HEADER, TotalSize, {});
    ObjectHeader->Type = ObjectType;
    InitializeListHead(&ObjectHeader->ObjectLink);
    InitializeListHead(&ObjectHeader->HandleEntryList);
    POBJECT Object = OBJECT_HEADER_TO_OBJECT(ObjectHeader);

    RET_ERR_EX(ObjectType->TypeInfo.CreateProc(Object, CreationContext),
	       {
		   ObjectType->TypeInfo.DeleteProc(Object);
		   ObpFreePool(ObjectHeader);
	       });
    InsertHeadList(&ObpObjectList, &ObjectHeader->ObjectLink);
    ObpReferenceObjectHeader(ObjectHeader);

    if (Subpath != NULL) {
	POBJECT Parent = NULL;
	PCSTR Name = NULL;
	assert(*Subpath != '\0');
	RET_ERR_EX(ObpInsertObject(DirectoryObject, Object,
				   Subpath, Flags, &Parent, &Name),
		   ObDereferenceObject(Object));
	assert(Parent != NULL);
	assert(Name != NULL);
	/* The ObjectName of the object header is owned by the object
	 * so we need to allocate storage for it. When the object is
	 * deleted, the ObjectName is freed by the object manager. */
	PCSTR ObjectName = RtlDuplicateString(Name, NTOS_OB_TAG);
	if (ObjectName == NULL) {
	    /* We failed to allocate the object name. In this case
	     * we will need to invoke the remove routine to remove
	     * it from the parent object that we just inserted into. */
	    assert(ObjectType->TypeInfo.RemoveProc != NULL);
	    ObjectType->TypeInfo.RemoveProc(Parent, Object, Name);
	    ObDereferenceObject(Object);
	    return STATUS_NO_MEMORY;
	}
	ObjectHeader->ParentObject = Parent;
	ObjectHeader->ObjectName = ObjectName;
    }
    *pObject = Object;
    return STATUS_SUCCESS;
}
