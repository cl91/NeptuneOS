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
    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Parent;
    PCM_KEY_OBJECT SubKey = (PCM_KEY_OBJECT)Subobject;
    CmpInsertNamedNode(Parent, &SubKey->Node, Subpath);
    return STATUS_SUCCESS;
}

VOID CmpKeyObjectRemoveProc(IN POBJECT Parent,
			    IN POBJECT Subobject,
			    IN PCSTR Subpath)
{
}

NTSTATUS CmpKeyObjectParseProc(IN POBJECT Self,
			       IN PCSTR Path,
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
 * handle vs deleting a key from the registry.
 */
VOID CmpKeyObjectDeleteProc(IN POBJECT Self)
{
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
	    CM_OPEN_CONTEXT OpenContext;
	});
    DbgTrace("Trying to open key %s root directory %p\n",
	     ObjectAttributes.ObjectNameBuffer, ObjectAttributes.RootDirectory);
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_KEY_OPEN;
    Locals.OpenContext.Create = FALSE;

    AWAIT_EX(Status, ObOpenObjectByName, AsyncState, Locals, Thread,
	     ObjectAttributes, OBJECT_TYPE_KEY,
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
	    CM_OPEN_CONTEXT OpenContext;
	});
    DbgTrace("Trying to create key %s root directory %p\n",
	     ObjectAttributes.ObjectNameBuffer, ObjectAttributes.RootDirectory);
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_KEY_OPEN;
    Locals.OpenContext.Create = TRUE;
    Locals.OpenContext.TitleIndex = TitleIndex;
    Locals.OpenContext.Class = Class;
    Locals.OpenContext.CreateOptions = CreateOptions;
    Locals.OpenContext.Disposition = Disposition;

    AWAIT_EX(Status, ObOpenObjectByName, AsyncState, Locals,
	     Thread, ObjectAttributes, OBJECT_TYPE_KEY,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, KeyHandle);
    ASYNC_END(AsyncState, Status);
}

NTSTATUS NtEnumerateKey(IN ASYNC_STATE AsyncState,
                        IN PTHREAD Thread,
                        IN HANDLE KeyHandle,
                        IN ULONG Index,
                        IN KEY_INFORMATION_CLASS KeyInformationClass,
                        IN PVOID InformationBuffer,
                        IN ULONG BufferSize,
                        OUT ULONG *ResultLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDeleteKey(IN ASYNC_STATE AsyncState,
                     IN PTHREAD Thread,
                     IN HANDLE KeyHandle)
{
    UNIMPLEMENTED;
}
