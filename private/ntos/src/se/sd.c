#include "sepriv.h"

NTSTATUS NtQuerySecurityObject(IN ASYNC_STATE AsyncState,
                               IN PTHREAD Thread,
                               IN HANDLE ObjectHandle,
                               IN SECURITY_INFORMATION SecurityInformationClass,
                               OUT PVOID DescriptorBuffer,
                               IN ULONG DescriptorBufferLength,
                               OUT ULONG *RequiredLength)
{
    UNIMPLEMENTED;
}

NTSTATUS NtSetSecurityObject(IN ASYNC_STATE AsyncState,
                             IN PTHREAD Thread,
                             IN HANDLE ObjectHandle,
                             IN SECURITY_INFORMATION SecurityInformationClass,
                             IN PVOID DescriptorBuffer)
{
    UNIMPLEMENTED;
}
