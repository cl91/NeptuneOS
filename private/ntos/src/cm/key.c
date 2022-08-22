#include "cmp.h"

NTSTATUS CmpKeyObjectCreateProc(IN POBJECT Object,
				IN PVOID CreaCtx)
{
    assert(Object != NULL);
    assert(CreaCtx != NULL);
    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Object;
    PKEY_OBJECT_CREATE_CONTEXT Ctx = (PKEY_OBJECT_CREATE_CONTEXT)CreaCtx;
    Key->Node.Type = CM_NODE_KEY;
    Key->Volatile = Ctx->Volatile;
    for (ULONG i = 0; i < CM_KEY_HASH_BUCKETS; i++) {
	InitializeListHead(&Key->HashBuckets[i]);
    }
    return STATUS_SUCCESS;
}

NTSTATUS CmpKeyObjectInsertProc(IN POBJECT Parent,
				IN POBJECT Subobject,
				IN PCSTR Subpath)
{
    assert(ObObjectIsType(Parent, OBJECT_TYPE_KEY));
    assert(ObObjectIsType(Subobject, OBJECT_TYPE_KEY));
    assert(!ObpPathHasSeparator(Subpath));
    PCM_KEY_OBJECT SubKey = (PCM_KEY_OBJECT)Subobject;
    CmpInsertNamedNode(Parent, &SubKey->Node, Subpath);
    return STATUS_SUCCESS;
}

VOID CmpKeyObjectRemoveProc(IN POBJECT Parent,
			    IN POBJECT Subobject,
			    IN PCSTR Subpath)
{
}

/*
 * Parse routine for the KEY object. This is invoked when the
 * object manager looks for a KEY object that is already loaded
 * into memory. Note that since the Windows registry is always
 * case-insensitive, the CaseInsensitive parameter is ignored
 * and all name lookups are case insensitive.
 */
NTSTATUS CmpKeyObjectParseProc(IN POBJECT Self,
			       IN PCSTR Path,
			       IN BOOLEAN CaseInsensitive,
			       OUT POBJECT *FoundObject,
			       OUT PCSTR *RemainingPath)
{
    assert(Self != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    assert(RemainingPath != NULL);
    assert(ObObjectIsType(Self, OBJECT_TYPE_KEY));

    DbgTrace("Parsing path %s\n", Path);

    if (*Path == '\0') {
	return STATUS_OBJECT_NAME_INVALID;
    }

    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Self;
    ULONG NameLength = ObpLocateFirstPathSeparator(Path);
    PCM_NODE NodeFound = CmpGetNamedNode(Key, Path, NameLength);

    /* If we did not find the named key object, we pass on to the
     * open routine for further processing. If we found a value node,
     * return error so parsing/opening is stopped. */
    if (NodeFound == NULL || NodeFound->Type != CM_NODE_KEY) {
	*FoundObject = NULL;
	*RemainingPath = Path;
	DbgTrace("Unable to parse %s. Should invoke open routine.\n", Path);
	return NodeFound == NULL ? STATUS_NTOS_INVOKE_OPEN_ROUTINE : STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Else, we return the key object that we have found */
    *FoundObject = NodeFound;
    *RemainingPath = Path + NameLength;
    DbgTrace("Found key %s\n", ObGetObjectName(NodeFound));
    /* Note that in the case where we are called in an open operation, we don't
     * need to return INVOKE_OPEN_ROUTINE here since the object manager will call
     * the open procedure once the path is fully parsed. */
    return STATUS_SUCCESS;
}

NTSTATUS CmpKeyObjectOpenProc(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
			      IN POBJECT Self,
			      IN PCSTR Path,
			      IN ULONG Attributes,
			      IN POB_OPEN_CONTEXT OpenContext,
			      OUT POBJECT *OpenedInstance,
			      OUT PCSTR *RemainingPath)
{
    assert(Self != NULL);
    assert(Path != NULL);
    assert(OpenContext != NULL);
    assert(OpenedInstance != NULL);
    assert(RemainingPath != NULL);

    DbgTrace("Opening path %s\n", Path);

    /* Reject the open if the open context is not CM_OPEN_CONTEXT */
    if (OpenContext == NULL || OpenContext->Type != OPEN_CONTEXT_KEY_OPEN) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }
    PCM_OPEN_CONTEXT Context = (PCM_OPEN_CONTEXT)OpenContext;

    /* Parse routine has successfully located the in-memory key object.
     * Simply return it. */
    if (*Path == '\0') {
	*OpenedInstance = Self;
	*RemainingPath = Path;
	if (Context->Disposition != NULL) {
	    *Context->Disposition = REG_OPENED_EXISTING_KEY;
	}
	return STATUS_SUCCESS;
    }

    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Self;

    /* TODO: Eventually we will implement the on-disk format of registry.
     * This in the future will be replaced by a database query. */
    if (!Context->Create) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* If we get here, it means that we are creating a new sub-key.
     * Check that the path does not contain a path separator. */
    if (ObpPathHasSeparator(Path)) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* Create the sub-key object and insert into the parent key */
    BOOLEAN Volatile = Context->CreateOptions & REG_OPTION_VOLATILE;
    PCM_KEY_OBJECT SubKey = NULL;
    KEY_OBJECT_CREATE_CONTEXT CreaCtx = {
	.Volatile = Volatile,
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_KEY, (POBJECT *)&SubKey,
			   Key, Path, OBJ_NO_PARSE, &CreaCtx))

    *OpenedInstance = SubKey;
    *RemainingPath = Path + strlen(Path);
    if (Context->Disposition != NULL) {
	*Context->Disposition = REG_CREATED_NEW_KEY;
    }
    DbgTrace("Created sub-key %s\n", ObGetObjectName(SubKey));
    return STATUS_SUCCESS;
}

/*
 * TODO: We will need to figure out how to distinguish closing a
 * handle vs deleting a key from the registry. This is done via
 * the object manager's OBJ_PERMANENT attribute.
 */
VOID CmpKeyObjectDeleteProc(IN POBJECT Self)
{
}

static NTSTATUS CmpQueryKeyData(IN PCM_KEY_OBJECT Node,
				IN KEY_INFORMATION_CLASS KeyInformationClass,
				OUT PVOID KeyInformation,
				IN ULONG Length,
				OUT ULONG *ResultLength,
				IN BOOLEAN Utf16)
{
    ULONG NameLength = strlen(ObGetObjectName(Node));
    if (Utf16) {
	RET_ERR(RtlUTF8ToUnicodeN(NULL, 0, &NameLength,
				  ObGetObjectName(Node), NameLength));
    }

    /* Check what kind of information is being requested */
    NTSTATUS Status = STATUS_SUCCESS;
    switch (KeyInformationClass) {
    case KeyBasicInformation:
    {
	/* This is the size we need */
	ULONG Size = FIELD_OFFSET(KEY_BASIC_INFORMATION, Name) + NameLength;

	/* And this is the minimum we can work with */
	ULONG MinimumSize = FIELD_OFFSET(KEY_BASIC_INFORMATION, Name);

	/* Let the caller know and assume success */
	*ResultLength = Size;

	/* Check if the bufer we got is too small */
	if (Length < MinimumSize) {
	    /* Let the caller know and fail */
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	/* Copy the basic information */
	PKEY_BASIC_INFORMATION Info = KeyInformation;
	Info->LastWriteTime = Node->LastWriteTime;
	Info->TitleIndex = 0;
	Info->NameLength = NameLength;

	/* Only the name is left */
	ULONG SizeLeft = Length - MinimumSize;
	Size = NameLength;

	/* Check if we don't have enough space for the name */
	if (SizeLeft < Size) {
	    /* Truncate the name we'll return, and tell the caller */
	    Size = SizeLeft;
	    Status = STATUS_BUFFER_OVERFLOW;
	}

	/* Copy the key name */
	if (Utf16) {
	    Status = RtlUTF8ToUnicodeN(Info->Name, Size, &NameLength,
				       ObGetObjectName(Node), Size);
	} else {
	    RtlCopyMemory(Info->Name, ObGetObjectName(Node), Size);
	}
    }
    break;

    case KeyNodeInformation:
    {
	/* Calculate the size we need */
	ULONG Size = FIELD_OFFSET(KEY_NODE_INFORMATION, Name) +
	    NameLength + Node->ClassLength;

	/* And the minimum size we can support */
	ULONG MinimumSize = FIELD_OFFSET(KEY_NODE_INFORMATION, Name);

	/* Return the size to the caller and assume succes */
	*ResultLength = Size;

	/* Check if the caller's buffer is too small */
	if (Length < MinimumSize) {
	    /* Let them know, and fail */
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	/* Copy the node information */
	PKEY_NODE_INFORMATION Info = KeyInformation;
	Info->LastWriteTime = Node->LastWriteTime;
	Info->TitleIndex = 0;
	Info->ClassLength = Node->ClassLength;
	Info->NameLength = NameLength;

	/* Now the name is left */
	ULONG SizeLeft = Length - MinimumSize;
	Size = NameLength;

	/* Check if the name can fit entirely */
	if (SizeLeft < Size) {
	    /* It can't, we'll have to truncate. Tell the caller */
	    Size = SizeLeft;
	    Status = STATUS_BUFFER_OVERFLOW;
	}

	/* Copy the key object name */
	if (Utf16) {
	    Status = RtlUTF8ToUnicodeN(Info->Name, Size, &NameLength,
				       ObGetObjectName(Node), Size);
	} else {
	    RtlCopyMemory(Info->Name, ObGetObjectName(Node), Size);
	}

	/* Check if the node has a class */
	if (Node->ClassLength > 0) {
	    /* Set the class offset */
	    ULONG Offset = FIELD_OFFSET(KEY_NODE_INFORMATION, Name) + NameLength;
	    Offset = ALIGN_UP_BY(Offset, sizeof(ULONG));
	    Info->ClassOffset = Offset;

	    /* Check if we can copy anything */
	    if (Length > Offset) {
		/* Copy the class data */
		RtlCopyMemory((PUCHAR)Info + Offset,
			      Node->ClassData,
			      min(Node->ClassLength, Length - Offset));
	    }

	    /* Check if the buffer was large enough */
	    if (Length < Offset + Node->ClassLength) {
		Status = STATUS_BUFFER_OVERFLOW;
	    }
	} else {
	    /* It doesn't, so set offset to -1, not 0! */
	    Info->ClassOffset = 0xFFFFFFFF;
	}
    }
    break;

    case KeyFullInformation:
    {
	/* This is the size we need */
	ULONG Size = FIELD_OFFSET(KEY_FULL_INFORMATION, Class) +
	    Node->ClassLength;

	/* This is what we can work with */
	ULONG MinimumSize = FIELD_OFFSET(KEY_FULL_INFORMATION, Class);

	/* Return it to caller and assume success */
	*ResultLength = Size;

	/* Check if the caller's buffer is to small */
	if (Length < MinimumSize) {
	    /* Let them know and fail */
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	/* Now copy the full information */
	PKEY_FULL_INFORMATION Info = KeyInformation;
	Info->LastWriteTime = Node->LastWriteTime;
	Info->TitleIndex = 0;
	Info->ClassLength = Node->ClassLength;
	Info->SubKeys = Node->StableSubKeyCount + Node->VolatileSubKeyCount;
	Info->Values = Node->ValueCount;
	Info->MaxNameLen = Node->MaxNameLength;
	Info->MaxClassLen = Node->MaxClassLength;
	Info->MaxValueNameLen = Node->MaxValueNameLength;
	Info->MaxValueDataLen = Node->MaxValueDataLength;

	/* Check if we have a class */
	if (Node->ClassLength > 0) {
	    /* Set the class offset */
	    ULONG Offset = FIELD_OFFSET(KEY_FULL_INFORMATION, Class);
	    Info->ClassOffset = Offset;

	    /* Copy the class data */
	    ASSERT(Length >= Offset);
	    RtlCopyMemory(Info->Class, Node->ClassData,
			  min(Node->ClassLength, Length - Offset));

	    /* Check if the buffer was large enough */
	    if (Length < Offset + Node->ClassLength) {
		Status = STATUS_BUFFER_OVERFLOW;
	    }
	} else {
	    /* We don't have a class, so set offset to -1, not 0! */
	    Info->ClassOffset = 0xFFFFFFFF;
	}
    }
    break;

    case KeyNameInformation:
    {
	/* This is the size we need */
	ULONG Size = FIELD_OFFSET(KEY_NAME_INFORMATION, Name) + NameLength;

	/* And this is the minimum we can work with */
	ULONG MinimumSize = FIELD_OFFSET(KEY_NAME_INFORMATION, Name);

	/* Let the caller know and assume success */
	*ResultLength = Size;

	/* Check if the bufer we got is too small */
	if (Length < MinimumSize) {
	    /* Let the caller know and fail */
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	/* Copy the name information */
	PKEY_NAME_INFORMATION Info = KeyInformation;
	Info->NameLength = NameLength;

	/* Check if we don't have enough space for the name */
	ULONG SizeLeft = Length - MinimumSize;
	Size = NameLength;
	if (SizeLeft < Size) {
	    /* Truncate the name we'll return, and tell the caller */
	    Size = SizeLeft;
	    Status = STATUS_BUFFER_OVERFLOW;
	}

	/* Copy the key name */
	if (Utf16) {
	    Status = RtlUTF8ToUnicodeN(Info->Name, Size, &NameLength,
				       ObGetObjectName(Node), Size);
	} else {
	    RtlCopyMemory(Info->Name, ObGetObjectName(Node), Size);
	}
    }

    default:
	/* Any other class that got sent here is invalid! */
	Status = STATUS_INVALID_PARAMETER;
	break;
    }

    return Status;
}

static NTSTATUS CmpQueryFlagsInformation(IN PCM_KEY_OBJECT Key,
					 OUT PVOID Info,
					 IN ULONG Length,
					 OUT ULONG *ResultLength)
{
    PKEY_USER_FLAGS_INFORMATION KeyFlagsInfo = Info;

    /* Validate the buffer size */
    *ResultLength = sizeof(*KeyFlagsInfo);
    if (Length < *ResultLength) {
	return STATUS_BUFFER_TOO_SMALL;
    }

    /* Copy the user flags. */
    KeyFlagsInfo->UserFlags = Key->UserFlags;

    return STATUS_SUCCESS;
}

static NTSTATUS CmpQueryKey(IN PCM_KEY_OBJECT Key,
			    IN KEY_INFORMATION_CLASS KeyInformationClass,
			    OUT OPTIONAL PVOID KeyInformation,
			    IN ULONG Length,
			    OUT PULONG ResultLength,
			    IN BOOLEAN Utf16)
{
    NTSTATUS Status;

    switch (KeyInformationClass) {
    case KeyFullInformation:
    case KeyBasicInformation:
    case KeyNodeInformation:
	Status = CmpQueryKeyData(Key,
				 KeyInformationClass,
				 KeyInformation,
				 Length,
				 ResultLength, Utf16);
	break;

    case KeyCachedInformation:
	/* TODO! */
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    case KeyFlagsInformation:
	Status = CmpQueryFlagsInformation(Key,
					  KeyInformation,
					  Length,
					  ResultLength);
	break;

    default:
	/* Illegal class. Print message and fail */
	DPRINT1("Unsupported class: %d!\n", KeyInformationClass);
	Status = STATUS_INVALID_INFO_CLASS;
	break;
    }

    return Status;
}

VOID CmpDbgDumpKey(IN PCM_KEY_OBJECT Key)
{
    DbgTrace("Dumping key %s\n", ObGetObjectName(Key));
    for (ULONG i = 0; i < CM_KEY_HASH_BUCKETS; i++) {
        LoopOverList(Node, &Key->HashBuckets[i], CM_NODE, HashLink) {
	    if (Node->Type == CM_NODE_KEY) {
		DbgPrint("    KEY %s\n", ObGetObjectName(Node));
	    } else if (Node->Type == CM_NODE_VALUE) {
		CmpDbgDumpValue((PCM_REG_VALUE)Node);
	    }
	}
    }
}

NTSTATUS NtOpenKey(IN ASYNC_STATE AsyncState,
                   IN PTHREAD Thread,
                   OUT HANDLE *KeyHandle,
                   IN ACCESS_MASK DesiredAccess,
                   IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    NTSTATUS Status;

    ASYNC_BEGIN(AsyncState, Locals, {
	    OB_OBJECT_ATTRIBUTES ObjectAttributes;
	    CM_OPEN_CONTEXT OpenContext;
	});
    DbgTrace("Trying to open key %s root directory %p\n",
	     ObjectAttributes.ObjectNameBuffer, ObjectAttributes.RootDirectory);
    /* Windows registry is always case insensitive so we set the
     * OBJ_CASE_INSENSITIVE even if the client did not. */
    Locals.ObjectAttributes = ObjectAttributes;
    Locals.ObjectAttributes.Attributes |= OBJ_CASE_INSENSITIVE;
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_KEY_OPEN;
    Locals.OpenContext.Create = FALSE;

    AWAIT_EX(Status, ObOpenObjectByName, AsyncState, Locals, Thread,
	     Locals.ObjectAttributes, OBJECT_TYPE_KEY,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, KeyHandle);
    ASYNC_END(AsyncState, Status);
}

NTSTATUS NtCreateKey(IN ASYNC_STATE AsyncState,
                     IN PTHREAD Thread,
                     OUT HANDLE *KeyHandle,
                     IN ACCESS_MASK DesiredAccess,
                     IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
                     IN ULONG TitleIndex,
                     IN OPTIONAL PCSTR Class,
                     IN ULONG CreateOptions,
                     OUT OPTIONAL PULONG Disposition)
{
    NTSTATUS Status;

    ASYNC_BEGIN(AsyncState, Locals, {
	    OB_OBJECT_ATTRIBUTES ObjectAttributes;
	    CM_OPEN_CONTEXT OpenContext;
	});
    DbgTrace("Trying to create key %s root directory %p\n",
	     ObjectAttributes.ObjectNameBuffer, ObjectAttributes.RootDirectory);
    /* Windows registry is always case insensitive so we set the
     * OBJ_CASE_INSENSITIVE even if the client did not. */
    Locals.ObjectAttributes = ObjectAttributes;
    Locals.ObjectAttributes.Attributes |= OBJ_CASE_INSENSITIVE;
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_KEY_OPEN;
    Locals.OpenContext.Create = TRUE;
    Locals.OpenContext.TitleIndex = TitleIndex;
    Locals.OpenContext.Class = Class;
    Locals.OpenContext.CreateOptions = CreateOptions;
    Locals.OpenContext.Disposition = Disposition;

    AWAIT_EX(Status, ObOpenObjectByName, AsyncState, Locals,
	     Thread, Locals.ObjectAttributes, OBJECT_TYPE_KEY,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, KeyHandle);
    ASYNC_END(AsyncState, Status);
}

NTSTATUS NtEnumerateKey(IN ASYNC_STATE AsyncState,
                        IN PTHREAD Thread,
                        IN HANDLE KeyHandle,
                        IN ULONG Index,
                        IN KEY_INFORMATION_CLASS KeyInformationClass,
                        OUT OPTIONAL PVOID InformationBuffer,
                        IN ULONG BufferSize,
                        OUT ULONG *ResultLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryKeyW(IN ASYNC_STATE AsyncState,
		     IN PTHREAD Thread,
		     IN HANDLE KeyHandle,
		     IN KEY_INFORMATION_CLASS KeyInformationClass,
		     OUT OPTIONAL PVOID OutputBuffer,
		     IN ULONG BufferSize,
		     OUT ULONG *ResultLength)
{
    DbgTrace("Querying key information for key handle %p\n", KeyHandle);
    assert(Thread->Process != NULL);

    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    NTSTATUS Status = CmpQueryKey(Key, KeyInformationClass, OutputBuffer,
				  BufferSize, ResultLength, TRUE);
    ObDereferenceObject(Key);
    return Status;
}

NTSTATUS NtQueryKeyA(IN ASYNC_STATE AsyncState,
		     IN PTHREAD Thread,
		     IN HANDLE KeyHandle,
		     IN KEY_INFORMATION_CLASS KeyInformationClass,
		     OUT OPTIONAL PVOID OutputBuffer,
		     IN ULONG BufferSize,
		     OUT ULONG *ResultLength)
{
    DbgTrace("Querying key information for key handle %p\n", KeyHandle);
    assert(Thread->Process != NULL);

    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread->Process, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    NTSTATUS Status = CmpQueryKey(Key, KeyInformationClass, OutputBuffer,
				  BufferSize, ResultLength, FALSE);
    ObDereferenceObject(Key);
    return Status;
}

NTSTATUS NtDeleteKey(IN ASYNC_STATE AsyncState,
                     IN PTHREAD Thread,
                     IN HANDLE KeyHandle)
{
    UNIMPLEMENTED;
}
