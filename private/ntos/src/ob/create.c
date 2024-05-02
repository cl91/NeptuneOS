#include "obp.h"
#include "ex.h"
#include "ntdef.h"
#include "ntstatus.h"
#include "ob.h"

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

    POBJECT_TYPE ObjectType = ObpGetObjectType(Type);
    ObjectType->Name = TypeName;
    ObjectType->Index = Type;
    ObjectType->ObjectBodySize = ObjectBodySize;
    ObjectType->TypeInfo = Init;

    return STATUS_SUCCESS;
}

/*
 * Insert the given object as a subobject under the directory
 * object with the given path. The subobject can later be retrieved
 * by calling the parse routine on the directory object with the
 * supplied path.
 *
 * Unless the OBJ_NO_PARSE flag is specified, the parse procedure
 * is invoked first on the directory object and will parse the
 * subpath until it cannot be parsed. If the remaining path is now
 * empty, object insertion fails and we return STATUS_OBJECT_NAME_COLLISION.
 * Otherwise, the insert procedure is invoked on the final parse
 * result and its result is returned.
 *
 * Supplying the OBJ_NO_PARSE flag circumvents the parse procedure
 * above. In this case the insertion routine is called directly.
 *
 * If the OBJ_CASE_INSENSITIVE flag is supplied, the object name
 * collision checks are done case-insensitively.
 *
 * The directory object can be NULL, in which case the root object
 * directory is assumed. In this case you must specify an absolute
 * path.
 *
 * If OBJ_CREATE_DIR_IF flag is specified, intermediate directory objects
 * will be created if they don't yet exist. You cannot specify OBJ_NO_PARSE
 * if you have specified OBJ_CREATE_DIR_IF.
 */
NTSTATUS ObInsertObject(IN OPTIONAL POBJECT DirectoryObject,
			IN POBJECT Object,
			IN PCSTR Path,
			IN ULONG Flags)
{
    assert(Object != NULL);
    assert(Path != NULL);
    ObRemoveObject(Object);

    POBJECT Parent = DirectoryObject ? DirectoryObject : ObpRootObjectDirectory;
    PCSTR RemainingPath = Path;
    PCSTR StringToFree = NULL;
    if (!(Flags & OBJ_NO_PARSE)) {
	/* Note that we don't check the return value of the lookup here,
	 * because we rely on the remaining path to determine whether the
	 * path has been fully parsed. */
	ObpParseObjectByName(DirectoryObject, Path,
			     !!(Flags & OBJ_CASE_INSENSITIVE),
			     &Parent, &RemainingPath, &StringToFree);
	assert(Parent != NULL);
	assert(RemainingPath != NULL);
	/* Skip the leading path separator in the remaining path. */
	if (RemainingPath[0] == OBJ_NAME_PATH_SEPARATOR) {
	    RemainingPath++;
	}
    }
    /* If the remaining path is empty, it means that there is already an
     * object with the given path. In this case we reject the insertion.
     * This check is skipped if OBJ_NO_PARSE is specified. */
    NTSTATUS Status;
    if (*RemainingPath == '\0' && !(Flags & OBJ_NO_PARSE)) {
	Status = STATUS_OBJECT_NAME_COLLISION;
	goto out;
    }

    /* The ObjectName of the object header is owned by the object
     * so we need to allocate storage for it. When the object is
     * deleted, the ObjectName is freed by the object manager. */
    PCHAR ObjectName = RtlDuplicateString(RemainingPath, NTOS_OB_TAG);
    if (!ObjectName) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    POBJECT_HEADER ParentHeader = OBJECT_TO_OBJECT_HEADER(Parent);
    assert(ParentHeader != NULL);
    assert(ParentHeader->Type != NULL);

    ObDbg("Inserting subobject %p under object %p with name %s\n",
	  Object, Parent, ObjectName);
    OBJECT_INSERT_METHOD InsertProc = ParentHeader->Type->TypeInfo.InsertProc;
    if (InsertProc == NULL) {
	Status = STATUS_OBJECT_TYPE_MISMATCH;
	goto out;
    }

    Status = InsertProc(Parent, Object, ObjectName);
    if (!NT_SUCCESS(Status)) {
	ObpFreePool(ObjectName);
	goto out;
    }

    POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(Object);
    ObjectHeader->ParentObject = Parent;
    ObjectHeader->ObjectName = ObjectName;
    /* We need to increase the refcount of the parent object so it cannot be
     * deleted before all its children are deleted. */
    ObpReferenceObject(Parent);
    Status = STATUS_SUCCESS;

out:
    if (StringToFree) {
	ExFreePoolWithTag(StringToFree, OB_PARSE_TAG);
    }
    return Status;
}

/*
 * Request the correct amount of memory (object header + body)
 * from the Executive Pool (allocated memory is zeroed by ExPool), invoke the
 * initialization procedure of the object type, and insert the object
 * into the global object list.
 */
NTSTATUS ObCreateObject(IN OBJECT_TYPE_ENUM Type,
			OUT POBJECT *pObject,
			IN PVOID CreationContext)
{
    assert(pObject != NULL);
    POBJECT_TYPE ObjectType = ObpGetObjectType(Type);
    assert(ObjectType->TypeInfo.CreateProc != NULL);

    MWORD TotalSize = sizeof(OBJECT_HEADER) + ObjectType->ObjectBodySize;
    ObpAllocatePoolEx(ObjectHeader, OBJECT_HEADER, TotalSize, {});
    ObjectHeader->Type = ObjectType;
    InitializeListHead(&ObjectHeader->ObjectLink);
    InitializeListHead(&ObjectHeader->HandleEntryList);
    POBJECT Object = OBJECT_HEADER_TO_OBJECT(ObjectHeader);

    RET_ERR_EX(ObjectType->TypeInfo.CreateProc(Object, CreationContext),
	       {
		   /* Due to the sometimes complicated process of cleaning up
		    * a partially created object, we allow the create proc to
		    * fail without fully cleaning up. We will invoke the delete
		    * routine in this case, so the delete routine must be able
		    * to clean up a partially created object. */
		   if (ObjectType->TypeInfo.DeleteProc != NULL) {
		       ObjectType->TypeInfo.DeleteProc(Object);
		   }
		   ObpFreePool(ObjectHeader);
	       });
    InsertHeadList(&ObpObjectList, &ObjectHeader->ObjectLink);
    ObpReferenceObjectHeader(ObjectHeader);

    *pObject = Object;
    return STATUS_SUCCESS;
}
