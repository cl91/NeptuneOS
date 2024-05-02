#include "cmp.h"
#include "ntstatus.h"
#include "util.h"

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
    InitializeListHead(&Key->SubKeyList);
    return STATUS_SUCCESS;
}

/*
 * Link the node to parent.
 */
NTSTATUS CmpInsertNamedNode(IN PCM_KEY_OBJECT Parent,
			    IN PCM_NODE Node,
			    IN PCSTR NodeName)
{
    assert(Parent != NULL);
    assert(ObObjectIsType(Parent, OBJECT_TYPE_KEY));
    assert(Parent->Node.Type == CM_NODE_KEY);
    Node->Name = RtlDuplicateString(NodeName, NTOS_CM_TAG);
    if (!Node->Name) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RET_ERR_EX(RtlUTF8ToUnicodeN(NULL, 0, &Node->Utf16NameLength,
				 NodeName, Node->NameLength),
	       {
		   CmpFreePool(Node->Name);
		   Node->Name = NULL;
	       });
    Node->NameLength = strlen(NodeName);
    Node->Parent = Parent;
    ULONG HashIndex = CmpKeyHashIndex(NodeName);
    InsertTailList(&Parent->HashBuckets[HashIndex], &Node->HashLink);
    if (Node->Utf16NameLength < Node->NameLength * sizeof(WCHAR)) {
	Node->Utf16NameLength = Node->NameLength * sizeof(WCHAR);
    }
    if (Node->NameLength > Parent->MaxNameLength) {
	Parent->MaxNameLength = Node->NameLength;
    }
    if (Node->Utf16NameLength > Parent->MaxUtf16NameLength) {
	Parent->MaxUtf16NameLength = Node->Utf16NameLength;
    }
    if (Node->Type == CM_NODE_KEY) {
	PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Node;
	if (Key->Volatile) {
	    Parent->VolatileSubKeyCount++;
	} else {
	    Parent->StableSubKeyCount++;
	}
	if (Key->ClassLength > Parent->MaxClassLength) {
	    Parent->MaxClassLength = Key->ClassLength;
	}
    } else {
	assert(Node->Type == CM_NODE_VALUE);
	Parent->ValueCount++;
	PCM_REG_VALUE Value = (PCM_REG_VALUE)Node;
	ULONG ValueDataLen = CmpGetValueDataLength(Value, FALSE);
	ULONG Utf16ValueDataLen = CmpGetValueDataLength(Value, TRUE);
	if (Node->NameLength > Parent->MaxValueNameLength) {
	    Parent->MaxValueNameLength = Node->NameLength;
	}
	if (Node->Utf16NameLength > Parent->MaxUtf16ValueNameLength) {
	    Parent->MaxUtf16ValueNameLength = Node->Utf16NameLength;
	}
	if (ValueDataLen > Parent->MaxValueDataLength) {
	    Parent->MaxValueDataLength = ValueDataLen;
	}
	if (Utf16ValueDataLen > Parent->MaxUtf16ValueDataLength) {
	    Parent->MaxUtf16ValueDataLength = Utf16ValueDataLen;
	}
    }
    return STATUS_SUCCESS;
}

NTSTATUS CmpKeyObjectInsertProc(IN POBJECT Parent,
				IN POBJECT Subobject,
				IN PCSTR Subpath)
{
    assert(ObObjectIsType(Parent, OBJECT_TYPE_KEY));
    assert(ObObjectIsType(Subobject, OBJECT_TYPE_KEY));
    assert(!ObPathHasSeparator(Subpath));
    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Parent;
    PCM_KEY_OBJECT SubKey = (PCM_KEY_OBJECT)Subobject;
    CmpInsertNamedNode(Parent, &SubKey->Node, Subpath);
    InsertTailList(&Key->SubKeyList, &SubKey->SubKeyListEntry);
    return STATUS_SUCCESS;
}

VOID CmpKeyObjectRemoveProc(IN POBJECT Subobject)
{
    /* TODO! */
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
    *FoundObject = NULL;
    *RemainingPath = Path;

    if (*Path == '\0') {
	return STATUS_NTOS_STOP_PARSING;
    }

    /* Skip the leading path separator. */
    if (Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	Path++;
    }

    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Self;
    ULONG NameLength = ObLocateFirstPathSeparator(Path);
    if (NameLength == 0) {
	return STATUS_OBJECT_NAME_INVALID;
    }
    PCM_NODE NodeFound = CmpGetNamedNode(Key, Path, NameLength);

    /* If we did not find the named key object, we pass on to the
     * open routine for further processing. If we found a value node,
     * return error so parsing/opening is stopped. */
    if (!NodeFound || NodeFound->Type != CM_NODE_KEY) {
	DbgTrace("Unable to parse %s. Should invoke open routine.\n", Path);
	return NodeFound ? STATUS_OBJECT_TYPE_MISMATCH : STATUS_OBJECT_PATH_NOT_FOUND;
    }

    /* Else, we return the key object that we have found */
    *FoundObject = NodeFound;
    *RemainingPath = Path + NameLength;
    DbgTrace("Found key %s\n", NodeFound->Name);
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
    *RemainingPath = Path;

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
     * Skip the leading path separator. */
    if (Path[0] == OBJ_NAME_PATH_SEPARATOR) {
	Path++;
    }

    /* The remaining path must not be empty. */
    if (!Path[0]) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* Create the sub-key object and insert into the parent key */
    BOOLEAN Volatile = Context->CreateOptions & REG_OPTION_VOLATILE;
    PCM_KEY_OBJECT SubKey = NULL;
    KEY_OBJECT_CREATE_CONTEXT CreaCtx = {
	.Volatile = Volatile,
    };
    DbgTrace("Creating subkey under path %s\n", Path);
    RET_ERR(ObCreateObject(OBJECT_TYPE_KEY, (POBJECT *)&SubKey, &CreaCtx));
    RET_ERR_EX(ObInsertObject(Key, SubKey, Path, OBJ_NO_PARSE),
	       {
		   ObDereferenceObject(SubKey);
		   *RemainingPath = Path;
	       });

    *OpenedInstance = SubKey;
    *RemainingPath = Path + strlen(Path);
    if (Context->Disposition != NULL) {
	*Context->Disposition = REG_CREATED_NEW_KEY;
    }
    DbgTrace("Created sub-key %s\n", SubKey->Node.Name);
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
    ULONG NameLength = Utf16 ? Node->Node.Utf16NameLength : Node->Node.NameLength;

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
	    DbgTrace("Need buffer size 0x%x got 0x%x\n", MinimumSize, Length);
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
	    DbgTrace("Need buffer size 0x%x got sizeleft 0x%x\n",
		     Size, SizeLeft);
	    Size = SizeLeft;
	    Status = STATUS_BUFFER_OVERFLOW;
	}

	/* Copy the key name */
	if (Utf16) {
	    RtlUTF8ToUnicodeN(Info->Name, Size, &Size,
			      Node->Node.Name, Node->Node.NameLength);
	} else {
	    RtlCopyMemory(Info->Name, Node->Node.Name, Size);
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
	    DbgTrace("Need buffer size 0x%x got 0x%x\n", MinimumSize, Length);
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
	    DbgTrace("Need buffer size 0x%x got sizeleft 0x%x\n",
		     Size, SizeLeft);
	    Size = SizeLeft;
	    Status = STATUS_BUFFER_OVERFLOW;
	}

	/* Copy the key object name */
	if (Utf16) {
	    RtlUTF8ToUnicodeN(Info->Name, Size, &Size,
			      Node->Node.Name, Node->Node.NameLength);
	} else {
	    RtlCopyMemory(Info->Name, Node->Node.Name, Size);
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
	    DbgTrace("Need buffer size 0x%x got 0x%x\n", MinimumSize, Length);
	    Status = STATUS_BUFFER_TOO_SMALL;
	    break;
	}

	/* Now copy the full information */
	PKEY_FULL_INFORMATION Info = KeyInformation;
	Info->LastWriteTime = Node->LastWriteTime;
	Info->TitleIndex = 0;
	Info->ClassLength = Node->ClassLength;
	Info->SubKeys = Node->StableSubKeyCount + Node->VolatileSubKeyCount;
	assert(Info->SubKeys == GetListLength(&Node->SubKeyList));
	Info->Values = Node->ValueCount;
	if (Utf16) {
	    Info->MaxNameLen = Node->MaxUtf16NameLength;
	    Info->MaxValueNameLen = Node->MaxUtf16ValueNameLength;
	    Info->MaxValueDataLen = Node->MaxUtf16ValueDataLength;
	} else {
	    Info->MaxNameLen = Node->MaxNameLength;
	    Info->MaxValueNameLen = Node->MaxValueNameLength;
	    Info->MaxValueDataLen = Node->MaxValueDataLength;
	}
	Info->MaxClassLen = Node->MaxClassLength;

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
	    DbgTrace("Need buffer size 0x%x got 0x%x\n", MinimumSize, Length);
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
	    DbgTrace("Need buffer size 0x%x got sizeleft 0x%x\n",
		     Size, SizeLeft);
	    Size = SizeLeft;
	    Status = STATUS_BUFFER_OVERFLOW;
	}

	/* Copy the key name */
	if (Utf16) {
	    RtlUTF8ToUnicodeN(Info->Name, Size, &Size,
			      Node->Node.Name, Node->Node.NameLength);
	} else {
	    RtlCopyMemory(Info->Name, Node->Node.Name, Size);
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
	DbgTrace("Need buffer size 0x%x got 0x%x\n", Length, *ResultLength);
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
    DbgTrace("Querying key %s infoclass %d bufsize 0x%x\n",
	     Key->Node.Name, KeyInformationClass, Length);
    NTSTATUS Status;

    switch (KeyInformationClass) {
    case KeyFullInformation:
    case KeyBasicInformation:
    case KeyNodeInformation:
    case KeyNameInformation:
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

static NTSTATUS CmpEnumerateKey(IN PCM_KEY_OBJECT Key,
				IN ULONG Index,
				IN KEY_INFORMATION_CLASS KeyInformationClass,
				OUT OPTIONAL PVOID InformationBuffer,
				IN ULONG BufferSize,
				OUT ULONG *ResultLength,
				IN BOOLEAN Utf16)
{
    /* Reject classes we don't know about */
    if ((KeyInformationClass != KeyBasicInformation) &&
        (KeyInformationClass != KeyNodeInformation)  &&
        (KeyInformationClass != KeyFullInformation)) {
        return STATUS_INVALID_PARAMETER_3;
    }
    CmpDbgDumpKey(Key);

    /* Find the Index-th (zero-based) sub-key */
    PCM_KEY_OBJECT SubKey = GetIndexedElementOfList(&Key->SubKeyList, Index,
						    CM_KEY_OBJECT, SubKeyListEntry);
    if (SubKey == NULL) {
	return STATUS_NO_MORE_ENTRIES;
    }
    CmpDbgDumpKey(SubKey);

    /* Returned the key information for the sub-key */
    return CmpQueryKey(SubKey, KeyInformationClass, InformationBuffer,
		       BufferSize, ResultLength, Utf16);
}

VOID CmpDbgDumpKey(IN PCM_KEY_OBJECT Key)
{
    DbgTrace("Dumping key %s\n", Key->Node.Name);
    for (ULONG i = 0; i < CM_KEY_HASH_BUCKETS; i++) {
        LoopOverList(Node, &Key->HashBuckets[i], CM_NODE, HashLink) {
	    if (Node->Type == CM_NODE_KEY) {
		CmDbgPrint("    KEY %s\n", Node->Name);
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
    CmDbg("Trying to open key %s root directory %p\n",
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
    CmDbg("Trying to create key %s root directory %p\n",
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

NTSTATUS NtEnumerateKeyW(IN ASYNC_STATE AsyncState,
			 IN PTHREAD Thread,
			 IN HANDLE KeyHandle,
			 IN ULONG Index,
			 IN KEY_INFORMATION_CLASS KeyInformationClass,
			 OUT OPTIONAL PVOID InformationBuffer,
			 IN ULONG BufferSize,
			 OUT ULONG *ResultLength)
{
    CmDbg("KeyHandle 0x%p, Index 0x%x, KIC %d, Length 0x%x\n",
	  KeyHandle, Index, KeyInformationClass, BufferSize);
    assert(Thread->Process != NULL);

    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    NTSTATUS Status = CmpEnumerateKey(Key, Index, KeyInformationClass,
				      InformationBuffer, BufferSize,
				      ResultLength, TRUE);
    ObDereferenceObject(Key);
    return Status;
}


NTSTATUS NtEnumerateKeyA(IN ASYNC_STATE AsyncState,
			 IN PTHREAD Thread,
			 IN HANDLE KeyHandle,
			 IN ULONG Index,
			 IN KEY_INFORMATION_CLASS KeyInformationClass,
			 OUT OPTIONAL PVOID InformationBuffer,
			 IN ULONG BufferSize,
			 OUT ULONG *ResultLength)
{
    CmDbg("NtEnumerateKey() KY 0x%p, Index 0x%x, KIC %d, Length 0x%x\n",
	  KeyHandle, Index, KeyInformationClass, BufferSize);
    assert(Thread->Process != NULL);

    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, KeyHandle,
				      OBJECT_TYPE_KEY, (POBJECT *)&Key));
    assert(Key != NULL);
    NTSTATUS Status = CmpEnumerateKey(Key, Index, KeyInformationClass,
				      InformationBuffer, BufferSize,
				      ResultLength, FALSE);
    ObDereferenceObject(Key);
    return Status;
}

NTSTATUS NtQueryKeyW(IN ASYNC_STATE AsyncState,
		     IN PTHREAD Thread,
		     IN HANDLE KeyHandle,
		     IN KEY_INFORMATION_CLASS KeyInformationClass,
		     OUT OPTIONAL PVOID OutputBuffer,
		     IN ULONG BufferSize,
		     OUT ULONG *ResultLength)
{
    CmDbg("Querying key information class %d for key handle %p bufsize 0x%x\n",
	  KeyInformationClass, KeyHandle, BufferSize);
    assert(Thread->Process != NULL);

    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, KeyHandle,
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
    CmDbg("Querying key information for key handle %p\n", KeyHandle);
    assert(Thread->Process != NULL);

    PCM_KEY_OBJECT Key = NULL;
    RET_ERR(ObReferenceObjectByHandle(Thread, KeyHandle,
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
