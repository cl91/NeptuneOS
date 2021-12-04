#include "obp.h"

static OBJECT_TYPE ObpObjectTypes[MAX_NUM_OBJECT_TYPES];
LIST_ENTRY ObpObjectList;

static inline POBJECT_TYPE ObpGetObjectType(IN OBJECT_TYPE_MASK Type)
{
    assert(RtlNumberOfSetBits(Type) == 1);
    assert(RtlFirstSetBit(Type) != 0);
    assert(RtlFirstSetBit(Type) <= MAX_NUM_OBJECT_TYPES);
    return &ObpObjectTypes[RtlFirstSetBit(Type)-1];
}

NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_MASK Type,
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
 * Request the correct amount of memory (object header + body)
 * from the Executive Pool (allocated memory is zeroed by ExPool), invoke the
 * initialization procedure of the object type, and insert the object
 * into the global object list.
 */
NTSTATUS ObCreateObject(IN OBJECT_TYPE_MASK Type,
			OUT POBJECT *Object,
			IN PVOID CreationContext)
{
    POBJECT_TYPE ObjectType = ObpGetObjectType(Type);
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
