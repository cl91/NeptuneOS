#include "obp.h"

NTSTATUS ObQueryNameString(IN POBJECT Object,
			   OUT PCHAR Name,
			   IN ULONG BufferLength,
			   OUT OPTIONAL ULONG *ResultLength)
{
    ObDbg("Querying name for object %p buffer length 0x%x\n", Object, BufferLength);
    if (ResultLength) {
	*ResultLength = 0;
    }
    if (BufferLength < 1) {
	return STATUS_BUFFER_TOO_SMALL;
    }
    ULONG RemainingLength = BufferLength - 1;
    Name[RemainingLength] = '\0';
    POBJECT Subobject = Object;
    POBJECT Parent = OBJECT_TO_OBJECT_HEADER(Object)->ParentObject;
    while (Parent) {
	POBJECT_HEADER ParentHeader = OBJECT_TO_OBJECT_HEADER(Parent);
	assert(ParentHeader->Type);
	if (!ParentHeader->Type->TypeInfo.QueryNameProc) {
	    return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	assert(RemainingLength <= BufferLength);
	ULONG SubpathLength = RemainingLength;
	ObDbg("Calling query-name method for object %p subobject %p subpath length 0x%x\n",
	      Parent, Subobject, SubpathLength);
	NTSTATUS Status = ParentHeader->Type->TypeInfo.QueryNameProc(Parent,
								     Subobject,
								     Name,
								     &SubpathLength);
	assert(SubpathLength <= RemainingLength);
	/* Subpath cannot be empty */
	if (SubpathLength < 1) {
	    assert(FALSE);
	    return STATUS_OBJECT_NAME_INVALID;
	}
	if (!NT_SUCCESS(Status)) {
	    if (ResultLength) {
		*ResultLength = BufferLength - RemainingLength + SubpathLength;
	    }
	    return Status;
	}
	ObDbg("Query-name method returned subpath %s\n", Name);
	/* Move the returned subpath to the end of the buffer */
	for (ULONG i = 1; i < SubpathLength; i++) {
	    Name[RemainingLength - i] = Name[SubpathLength - i - 1];
	}
	RemainingLength -= SubpathLength;
	Name[RemainingLength] = OBJ_NAME_PATH_SEPARATOR;
	Subobject = Parent;
	Parent = OBJECT_TO_OBJECT_HEADER(Subobject)->ParentObject;
    }
    /* Move the final full path to the beginning of the buffer. If
     * the root object is the root object directory, the final path
     * will begin with a '\' to indicate it is an absolute path.
     * Otherwise, the returned path will be a relative path. */
    if (Subobject != ObpRootObjectDirectory) {
	RemainingLength++;
    }
    BufferLength -= RemainingLength;
    if (RemainingLength) {
	RtlMoveMemory(Name, Name + RemainingLength, BufferLength);
    }
    if (ResultLength) {
	*ResultLength = BufferLength;
    }
    ObDbg("Final object path %s\n", Name);
    return STATUS_SUCCESS;
}

NTSTATUS NtQueryObject(IN ASYNC_STATE AsyncState,
                       IN PTHREAD Thread,
                       IN HANDLE ObjectHandle,
                       IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
                       OUT PVOID ObjectInformationBuffer,
                       IN ULONG ObjectInformationLength,
                       OUT OPTIONAL ULONG *ReturnLength)
{
    POBJECT Object = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, ObjectHandle,
				      OBJECT_TYPE_ANY, &Object));
    NTSTATUS Status;
    switch (ObjectInformationClass) {
    case ObjectNameInformation:
	Status = ObQueryNameString(Object, ObjectInformationBuffer,
				   ObjectInformationLength, ReturnLength);
	if (Status == STATUS_BUFFER_TOO_SMALL) {
	    if (ReturnLength) {
		/* The client expects the object information to be in UTF16. */
		*ReturnLength *= sizeof(WCHAR);
		*ReturnLength += sizeof(OBJECT_NAME_INFORMATION);
	    }
	}
	break;
    default:
	assert(FALSE);
	Status = STATUS_NOT_IMPLEMENTED;
    }
    ObDereferenceObject(Object);
    return Status;
}
