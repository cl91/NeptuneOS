#include "cmp.h"

NTSTATUS CmpKeyObjectCreateProc(IN POBJECT Object,
				IN PVOID CreaCtx)
{
    assert(Object != NULL);
    assert(CreaCtx != NULL);
    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Object;
    PKEY_OBJECT_CREATE_CONTEXT Ctx = (PKEY_OBJECT_CREATE_CONTEXT)CreaCtx;
    Key->Node.Name = RtlDuplicateStringEx(Ctx->Name, Ctx->NameLength,
					  NTOS_CM_TAG);
    if (Key->Node.Name == NULL) {
	return STATUS_NO_MEMORY;
    }
    Key->Node.Parent = &Ctx->Parent->Node;
    Key->Node.Type = CM_NODE_KEY;
    Key->Volatile = Ctx->Volatile;
    for (ULONG i = 0; i < CM_KEY_HASH_BUCKETS; i++) {
	InitializeListHead(&Key->HashBuckets[i]);
    }
    return STATUS_SUCCESS;
}

/* Compute the hash index of the given string. */
static inline ULONG CmpKeyHashIndex(IN PCSTR Str,
				    IN ULONG Length) /* Excluding trailing '\0' */
{
    ULONG Hash = RtlpHashStringEx(Str, Length);
    return Hash % CM_KEY_HASH_BUCKETS;
}

NTSTATUS CmpKeyObjectParseProc(IN POBJECT Self,
			       IN PCSTR Path,
			       IN POB_PARSE_CONTEXT ParseContext,
			       OUT POBJECT *FoundObject,
			       OUT PCSTR *RemainingPath)
{
    assert(Self != NULL);
    assert(Path != NULL);
    assert(ParseContext != NULL);
    assert(FoundObject != NULL);
    assert(RemainingPath != NULL);

    DbgTrace("Parsing path %s\n", Path);

    if (!ObpParseTypeIsValid(ParseContext, OBJECT_TYPE_KEY)) {
	return STATUS_OBJECT_TYPE_MISMATCH;
    }

    if (*Path == '\0') {
	return STATUS_OBJECT_NAME_INVALID;
    }

    PCM_KEY_OBJECT Key = (PCM_KEY_OBJECT)Self;
    PCM_OPEN_CONTEXT Context = (PCM_OPEN_CONTEXT)ParseContext;
    ULONG NameLength = ObpLocateFirstPathSeparator(Path);
    ULONG HashIndex = CmpKeyHashIndex(Path, NameLength);
    assert(HashIndex < CM_KEY_HASH_BUCKETS);

    PCM_NODE NodeFound = NULL;
    LoopOverList(Node, &Key->HashBuckets[HashIndex], CM_NODE, HashLink) {
	assert(Node->Name != NULL);
	if (!strncmp(Path, Node->Name, NameLength)) {
	    NodeFound = Node;
	}
    }

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
    DbgTrace("Found key %s\n", NodeFound->Name);
    return STATUS_SUCCESS;
}

NTSTATUS CmpKeyObjectOpenProc(IN ASYNC_STATE State,
			      IN PTHREAD Thread,
			      IN POBJECT Object,
			      IN PCSTR SubPath,
			      IN POB_PARSE_CONTEXT ParseContext,
			      OUT POBJECT *pOpenedInstance,
			      OUT PCSTR *pRemainingPath)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenKey(IN ASYNC_STATE AsyncState,
                   IN PTHREAD Thread,
                   OUT HANDLE *KeyHandle,
                   IN ACCESS_MASK DesiredAccess,
                   IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    PCSTR KeyPath = ObjectAttributes.ObjectNameBuffer;
    NTSTATUS Status;

    ASYNC_BEGIN(AsyncState);
    Thread->NtOpenKeySavedState.OpenContext.Header.RequestedTypeMask = OBJECT_TYPE_MASK_KEY;
    Thread->NtOpenKeySavedState.OpenContext.Create = FALSE;

    AWAIT_EX(ObOpenObjectByName, Status, AsyncState, Thread, KeyPath,
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
                     IN OPTIONAL PULONG Disposition)
{
    PCSTR KeyPath = ObjectAttributes.ObjectNameBuffer;
    NTSTATUS Status;

    ASYNC_BEGIN(AsyncState);
    Thread->NtCreateKeySavedState.OpenContext.Header.RequestedTypeMask = OBJECT_TYPE_MASK_KEY;
    Thread->NtCreateKeySavedState.OpenContext.Create = TRUE;
    Thread->NtCreateKeySavedState.OpenContext.TitleIndex = TitleIndex;
    Thread->NtCreateKeySavedState.OpenContext.Class = Class;
    Thread->NtCreateKeySavedState.OpenContext.CreateOptions = CreateOptions;
    Thread->NtCreateKeySavedState.OpenContext.Disposition = Disposition;

    AWAIT_EX(ObOpenObjectByName, Status, AsyncState, Thread, KeyPath,
	     (POB_PARSE_CONTEXT)&Thread->NtCreateKeySavedState.OpenContext, KeyHandle);
    ASYNC_END(Status);
}

NTSTATUS NtQueryValueKey(IN ASYNC_STATE AsyncState,
                         IN PTHREAD Thread,
                         IN HANDLE KeyHandle,
                         IN PCSTR ValueName,
                         IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                         IN PVOID InformationBuffer,
                         IN ULONG BufferSize,
                         OUT ULONG *ResultLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetValueKey(IN ASYNC_STATE AsyncState,
                       IN PTHREAD Thread,
                       IN HANDLE KeyHandle,
                       IN PCSTR ValueName,
                       IN ULONG TitleIndex,
                       IN ULONG Type,
                       IN PVOID Data,
                       IN ULONG DataSize)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDeleteKey(IN ASYNC_STATE AsyncState,
                     IN PTHREAD Thread,
                     IN HANDLE KeyHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDeleteValueKey(IN ASYNC_STATE AsyncState,
                          IN PTHREAD Thread,
                          IN HANDLE KeyHandle,
                          IN PCSTR ValueName)
{
    UNIMPLEMENTED;
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

NTSTATUS NtEnumerateValueKey(IN ASYNC_STATE AsyncState,
                             IN PTHREAD Thread,
                             IN HANDLE KeyHandle,
                             IN ULONG Index,
                             IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
                             IN PVOID InformationBuffer,
                             IN ULONG BufferSize,
                             OUT ULONG *ResultLength)
{
    UNIMPLEMENTED;
}
