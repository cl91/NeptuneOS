#include "obp.h"

OBJECT_TYPE ObpObjectTypes[NUM_OBJECT_TYPES];

NTSTATUS ObCreateObjectType(IN OBJECT_TYPE_ENUM Type,
			    IN PCSTR TypeName,
			    IN POBJECT_TYPE_INITIALIZER Init)
{
    POBJECT_TYPE ObjectType = &ObpObjectTypes[Type];
    ObjectType->Name = TypeName;
    ObjectType->TypeEnum = Type;
    ObjectType->Init = Init;
    return ObjectType->Init->TypeCreateProc(ObjectType);
}
