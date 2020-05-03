#include "obp.h"

OBJECT_TYPE ObpObjectTypes[NUM_OBJECT_TYPES];

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

NTSTATUS ObCreateObject(IN OBJECT_TYPE_ENUM Type,
			OUT PVOID *Object)
{
    POBJECT_TYPE ObjectType = &ObpObjectTypes[Type];
    ObpAllocatePool(ObjectHeader, OBJECT_HEADER,
		    sizeof(OBJECT_HEADER) + ObjectType->ObjectBodySize);
    *Object = (PVOID) ((MWORD) ObjectHeader + sizeof(OBJECT_HEADER));
    NTSTATUS Status = ObjectType->TypeInfo.CreateProc(*Object);
    if (!NT_SUCCESS(Status)) {
	*Object = NULL;
	ExFreePool(ObjectHeader);
    }
    return Status;
}
