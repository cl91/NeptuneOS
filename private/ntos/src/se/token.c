#include "sepriv.h"

NTSTATUS NtOpenProcessToken(IN ASYNC_STATE AsyncState,
                            IN struct _THREAD *Thread,
                            IN HANDLE ProcessHandle,
                            IN ACCESS_MASK DesiredAccess,
                            OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenProcessTokenEx(IN ASYNC_STATE AsyncState,
                              IN struct _THREAD *Thread,
                              IN HANDLE ProcessHandle,
                              IN ACCESS_MASK DesiredAccess,
                              IN ULONG HandleAttributes,
                              OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenThreadToken(IN ASYNC_STATE AsyncState,
                           IN struct _THREAD *Thread,
                           IN HANDLE ThreadHandle,
                           IN ACCESS_MASK DesiredAccess,
                           IN BOOLEAN OpenAsSelf,
                           OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenThreadTokenEx(IN ASYNC_STATE AsyncState,
                             IN struct _THREAD *Thread,
                             IN HANDLE ThreadHandle,
                             IN ACCESS_MASK DesiredAccess,
                             IN BOOLEAN OpenAsSelf,
                             IN ULONG HandleAttributes,
                             OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryInformationToken(IN ASYNC_STATE AsyncState,
                                 IN struct _THREAD *Thread,
                                 IN HANDLE TokenHandle,
                                 IN TOKEN_INFORMATION_CLASS TokenInformationClass,
                                 IN PVOID TokenInformationBuffer,
                                 IN ULONG TokenInformationLength,
                                 OUT OPTIONAL ULONG *ReturnLength)
{
    UNIMPLEMENTED;
}
