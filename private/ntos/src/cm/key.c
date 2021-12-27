#include "cmp.h"

NTSTATUS NtOpenKey(IN ASYNC_STATE AsyncState,
                   IN PTHREAD Thread,
                   OUT HANDLE *KeyHandle,
                   IN ACCESS_MASK DesiredAccess,
                   IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes)
{
    UNIMPLEMENTED;
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
    UNIMPLEMENTED;
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
