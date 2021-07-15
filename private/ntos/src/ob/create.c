#include "obp.h"

OBJECT_TYPE ObpObjectTypes[NUM_OBJECT_TYPES];
LIST_ENTRY ObpObjectList;

NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_ENUM Type,
			    IN PCSTR TypeName,
			    IN ULONG ObjectBodySize,
			    IN OBJECT_TYPE_INITIALIZER Init)
{
    POBJECT_TYPE ObjectType = &ObpObjectTypes[Type];
    ObjectType->Name = TypeName;
    ObjectType->Index = Type;
    ObjectType->ObjectBodySize = ObjectBodySize;
    ObjectType->TypeInfo = Init;
    return STATUS_SUCCESS;
}

/* Request the correct amount of memory (object header + body)
 * from the Executive Pool, invoke the creation procedure of the
 * object type, and insert the object into the global object list.
 */
NTSTATUS ObCreateObject(IN OBJECT_TYPE_ENUM Type,
			OUT PVOID *Object)
{
    POBJECT_TYPE ObjectType = &ObpObjectTypes[Type];
    ObpAllocatePoolEx(ObjectHeader, OBJECT_HEADER,
		      sizeof(OBJECT_HEADER) + ObjectType->ObjectBodySize,
		      {});
    ObjectHeader->Type = ObjectType;
    ObjectHeader->RefCount = 0;
    InitializeListHead(&ObjectHeader->ObjectLink);
    *Object = OBJECT_HEADER_TO_OBJECT(ObjectHeader);
    NTSTATUS Status = ObjectType->TypeInfo.CreateProc(*Object);
    if (!NT_SUCCESS(Status)) {
	*Object = NULL;
	ExFreePool(ObjectHeader);
    }
    InsertHeadList(&ObpObjectList, &ObjectHeader->ObjectLink);
    ObpReferenceObject(ObjectHeader);
    return Status;
}
