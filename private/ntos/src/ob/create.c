#include "obp.h"

OBJECT_TYPE ObpObjectTypes[NUM_OBJECT_TYPES];

NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_ENUM Type,
			    IN PCWSTR TypeName,
			    IN POBJECT_TYPE_INITIALIZER Init)
{
    POBJECT_TYPE ObjectType = &ObpObjectTypes[Type];
    RtlInitUnicodeString(&ObjectType->Name, TypeName);
    ObjectType->TypeEnum = Type;
    ObjectType->Init = Init;
    return ObjectType->Init->TypeCreateProc(ObjectType);
}
