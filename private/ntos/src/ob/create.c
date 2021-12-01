#include "obp.h"

OBJECT_TYPE ObpObjectTypes[NUM_OBJECT_TYPES];
LIST_ENTRY ObpObjectList;

NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_ENUM Type,
			    IN PCSTR TypeName,
			    IN ULONG ObjectBodySize,
			    IN OBJECT_TYPE_INITIALIZER Init)
{
    assert(TypeName != NULL);
    assert(ObjectBodySize != 0);
    assert(Init.CreateProc != NULL);

    POBJECT_TYPE ObjectType = &ObpObjectTypes[Type];
    ObjectType->Name = TypeName;
    ObjectType->Index = Type;
    ObjectType->ObjectBodySize = ObjectBodySize;
    ObjectType->TypeInfo = Init;

    return STATUS_SUCCESS;
}

/*
 * Request the correct amount of memory (object header + body)
 * from the Executive Pool (allocated memory is zeroed by ExPool), invoke the
 * initialization procedure of the object type, and insert the object
 * into the global object list.
 */
NTSTATUS ObCreateObject(IN OBJECT_TYPE_ENUM Type,
			OUT POBJECT *Object,
			IN PVOID CreationContext)
{
    assert(Type < NUM_OBJECT_TYPES);
    POBJECT_TYPE ObjectType = &ObpObjectTypes[Type];
    assert(ObjectType->TypeInfo.CreateProc != NULL);

    MWORD TotalSize = sizeof(OBJECT_HEADER) + ObjectType->ObjectBodySize;
    ObpAllocatePoolEx(ObjectHeader, OBJECT_HEADER, TotalSize, {});
    ObjectHeader->Type = ObjectType;
    InitializeListHead(&ObjectHeader->ObjectLink);
    InitializeListHead(&ObjectHeader->HandleEntryList);
    *Object = OBJECT_HEADER_TO_OBJECT(ObjectHeader);

    RET_ERR_EX(ObjectType->TypeInfo.CreateProc(*Object, CreationContext),
	       {
		   ObpDeleteObject(*Object);
		   ExFreePool(ObjectHeader);
		   *Object = NULL;
	       });
    InsertHeadList(&ObpObjectList, &ObjectHeader->ObjectLink);
    ObpReferenceObjectHeader(ObjectHeader);
    return STATUS_SUCCESS;
}
