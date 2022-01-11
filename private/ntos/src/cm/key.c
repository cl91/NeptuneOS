#include "cmp.h"

NTSTATUS CmpKeyObjectCreateProc(IN POBJECT Object,
				IN PVOID CreaCtx)
{
    UNIMPLEMENTED;
}

NTSTATUS CmpKeyObjectParseProc(IN POBJECT Self,
			       IN PCSTR Path,
			       IN POB_PARSE_CONTEXT ParseContext,
			       OUT POBJECT *FoundObject,
			       OUT PCSTR *RemainingPath)
{
    UNIMPLEMENTED;
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
