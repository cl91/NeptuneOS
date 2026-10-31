#include "sepriv.h"

NTSTATUS NtOpenProcessToken(IN ASYNC_STATE AsyncState,
                            IN PTHREAD Thread,
                            IN HANDLE ProcessHandle,
                            IN ACCESS_MASK DesiredAccess,
                            OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenProcessTokenEx(IN ASYNC_STATE AsyncState,
                              IN PTHREAD Thread,
                              IN HANDLE ProcessHandle,
                              IN ACCESS_MASK DesiredAccess,
                              IN ULONG HandleAttributes,
                              OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenThreadToken(IN ASYNC_STATE AsyncState,
                           IN PTHREAD Thread,
                           IN HANDLE ThreadHandle,
                           IN ACCESS_MASK DesiredAccess,
                           IN BOOLEAN OpenAsSelf,
                           OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtOpenThreadTokenEx(IN ASYNC_STATE AsyncState,
                             IN PTHREAD Thread,
                             IN HANDLE ThreadHandle,
                             IN ACCESS_MASK DesiredAccess,
                             IN BOOLEAN OpenAsSelf,
                             IN ULONG HandleAttributes,
                             OUT HANDLE *TokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtQueryInformationToken(IN ASYNC_STATE AsyncState,
                                 IN PTHREAD Thread,
                                 IN HANDLE TokenHandle,
                                 IN TOKEN_INFORMATION_CLASS TokenInformationClass,
                                 IN PVOID TokenInformationBuffer,
                                 IN ULONG TokenInformationLength,
                                 OUT OPTIONAL ULONG *ReturnLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtAdjustPrivilegesToken(IN ASYNC_STATE AsyncState,
                                 IN PTHREAD Thread,
                                 IN HANDLE TokenHandle,
                                 IN BOOLEAN DisableAllPrivileges,
                                 IN PVOID NewState,
                                 IN ULONG BufferLength,
                                 OUT OPTIONAL PVOID PreviousState,
                                 OUT OPTIONAL ULONG *ReturnLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtDuplicateToken(IN ASYNC_STATE AsyncState,
			  IN PTHREAD Thread,
			  IN HANDLE ExistingTokenHandle,
			  IN ACCESS_MASK DesiredAccess,
			  IN OPTIONAL OB_OBJECT_ATTRIBUTES ObjectAttributes,
			  IN BOOLEAN EffectiveOnly,
			  IN TOKEN_TYPE TokenType,
			  OUT HANDLE *NewTokenHandle)
{
    UNIMPLEMENTED;
}

NTSTATUS NtImpersonateThread(IN ASYNC_STATE AsyncState,
			     IN PTHREAD Thread,
			     IN HANDLE ThreadHandle,
			     IN HANDLE ThreadToImpersonate,
			     IN PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService)
{
    UNIMPLEMENTED;
}
