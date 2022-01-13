#include "cmp.h"

NTSTATUS CmpKeyObjectCreateProc(IN POBJECT Object,
				IN PVOID CreaCtx)
{
    assert(Object != NULL);
    assert(CreaCtx != NULL);
    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Object;
    PKEY_OBJECT_CREATE_CONTEXT Ctx = (PKEY_OBJECT_CREATE_CONTEXT)CreaCtx;
    for (ULONG i = 0; i < Ctx->NameLength; i++) {
	assert(Ctx->Name[i] != OBJ_NAME_PATH_SEPARATOR);
	assert(Ctx->Name[i] != '\0');
    }
    Key->Node.Type = CM_NODE_KEY;
    Key->Volatile = Ctx->Volatile;
    RET_ERR(CmpInsertNamedNode(Ctx->Parent, &Key->Node,
			       Ctx->Name, Ctx->NameLength));
    for (ULONG i = 0; i < CM_KEY_HASH_BUCKETS; i++) {
	InitializeListHead(&Key->HashBuckets[i]);
    }
    return STATUS_SUCCESS;
}

NTSTATUS CmpKeyObjectParseProc(IN POBJECT Self,
			       IN PCSTR Path,
			       IN POB_PARSE_CONTEXT ParseContext,
			       OUT POBJECT *FoundObject,
			       OUT PCSTR *RemainingPath)
{
    assert(Self != NULL);
    assert(Path != NULL);
    assert(FoundObject != NULL);
    assert(RemainingPath != NULL);

    DbgTrace("Parsing path %s\n", Path);

    /* Reject the open if the parse context is not CM_OPEN_CONTEXT */
    if (ParseContext != NULL && ParseContext->Type != PARSE_CONTEXT_KEY_OPEN) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }

    if (*Path == '\0') {
	return STATUS_OBJECT_NAME_INVALID;
    }

    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Self;
    PCM_OPEN_CONTEXT Context = (PCM_OPEN_CONTEXT)ParseContext;
    ULONG NameLength = ObpLocateFirstPathSeparator(Path);
    PCM_NODE NodeFound = CmpGetNamedNode(Key, Path, NameLength);

    /* If we did not find the named key object (which includes the
     * case where the node found is a value node), we pass on to the
     * open routine for further processing */
    if (NodeFound == NULL || NodeFound->Type != CM_NODE_KEY) {
	*FoundObject = NULL;
	*RemainingPath = Path;
	DbgTrace("Unable to parse %s. Should invoke open routine.\n", Path);
	return STATUS_NTOS_INVOKE_OPEN_ROUTINE;
    }

    /* Else, we return the key object that we have found */
    *FoundObject = NodeFound;
    *RemainingPath = Path + NameLength;
    if (Context != NULL && Context->Disposition != NULL) {
	/* Eventually this will be overwritten by the open proc if a sub-key
	 * is later created. */
	*Context->Disposition = REG_OPENED_EXISTING_KEY;
    }
    DbgTrace("Found key %s\n", NodeFound->Name);
    return STATUS_SUCCESS;
}

NTSTATUS CmpKeyObjectOpenProc(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
			      IN POBJECT Self,
			      IN PCSTR Path,
			      IN POB_PARSE_CONTEXT ParseContext,
			      OUT POBJECT *OpenedInstance,
			      OUT PCSTR *RemainingPath)
{
    assert(Self != NULL);
    assert(Path != NULL);
    assert(ParseContext != NULL);
    assert(OpenedInstance != NULL);
    assert(RemainingPath != NULL);

    DbgTrace("Opening path %s\n", Path);

    /* Reject the open if the parse context is not CM_OPEN_CONTEXT */
    if (ParseContext->Type != PARSE_CONTEXT_KEY_OPEN) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }

    /* Parse routine has successfully located the in-memory key object.
     * Simply return it. */
    if (*Path == '\0') {
	*OpenedInstance = Self;
	*RemainingPath = Path;
	return STATUS_SUCCESS;
    }

    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Self;
    PCM_OPEN_CONTEXT Context = (PCM_OPEN_CONTEXT)ParseContext;

    /* TODO: Eventually we will implement the on-disk format of registry.
     * This in the future will be replaced by a database query. */
    if (!Context->Create) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* Create the sub-key object and insert into the parent key */
    ULONG NameLength = ObpLocateFirstPathSeparator(Path);
    BOOLEAN Volatile = Context->CreateOptions & REG_OPTION_VOLATILE;
    PCM_KEY_OBJECT SubKey = NULL;
    KEY_OBJECT_CREATE_CONTEXT CreaCtx = {
	.Volatile = Volatile,
	.Name = Path,
	.NameLength = NameLength,
	.Parent = Key
    };
    RET_ERR(ObCreateObject(OBJECT_TYPE_KEY, (POBJECT *)&SubKey, &CreaCtx));

    *OpenedInstance = SubKey;
    *RemainingPath = Path + NameLength;
    if (Context->Disposition != NULL) {
	*Context->Disposition = REG_CREATED_NEW_KEY;
    }
    DbgTrace("Created sub-key %s\n", SubKey->Node.Name);
    return STATUS_SUCCESS;
}

VOID CmpDbgDumpKey(IN PCM_KEY_OBJECT Key)
{
    DbgTrace("Dumping key %s\n", Key->Node.Name);
    for (ULONG i = 0; i < CM_KEY_HASH_BUCKETS; i++) {
        LoopOverList(Node, &Key->HashBuckets[i], CM_NODE, HashLink) {
	    assert(Node->Name != NULL);
	    if (Node->Type == CM_NODE_KEY) {
		DbgPrint(    "KEY %s\n", Node->Name);
	    } else if (Node->Type == CM_NODE_VALUE) {
		DbgPrint(    "VALUE %s ", Node->Name);
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

    ASYNC_BEGIN(AsyncState);
    DbgTrace("Trying to open key %s root directory %p\n",
	     ObjectAttributes.ObjectNameBuffer, ObjectAttributes.RootDirectory);
    Thread->NtOpenKeySavedState.OpenContext.Header.Type = PARSE_CONTEXT_KEY_OPEN;
    Thread->NtOpenKeySavedState.OpenContext.Create = FALSE;

    AWAIT_EX(ObOpenObjectByName, Status, AsyncState, Thread, ObjectAttributes, OBJECT_TYPE_KEY,
	     (POB_PARSE_CONTEXT)&Thread->NtOpenKeySavedState.OpenContext, KeyHandle);
    ASYNC_END(Status);
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

    ASYNC_BEGIN(AsyncState);
    DbgTrace("Trying to create key %s root directory %p\n",
	     ObjectAttributes.ObjectNameBuffer, ObjectAttributes.RootDirectory);
    Thread->NtCreateKeySavedState.OpenContext.Header.Type = PARSE_CONTEXT_KEY_OPEN;
    Thread->NtCreateKeySavedState.OpenContext.Create = TRUE;
    Thread->NtCreateKeySavedState.OpenContext.TitleIndex = TitleIndex;
    Thread->NtCreateKeySavedState.OpenContext.Class = Class;
    Thread->NtCreateKeySavedState.OpenContext.CreateOptions = CreateOptions;
    Thread->NtCreateKeySavedState.OpenContext.Disposition = Disposition;

    AWAIT_EX(ObOpenObjectByName, Status, AsyncState, Thread, ObjectAttributes, OBJECT_TYPE_KEY,
	     (POB_PARSE_CONTEXT)&Thread->NtCreateKeySavedState.OpenContext, KeyHandle);
    ASYNC_END(Status);
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
