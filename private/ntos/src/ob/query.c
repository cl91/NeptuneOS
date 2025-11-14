#include "obp.h"

NTSTATUS NtQueryObject(IN ASYNC_STATE AsyncState,
                       IN PTHREAD Thread,
                       IN HANDLE ObjectHandle,
                       IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
                       OUT PVOID ObjectInformationBuffer,
                       IN ULONG ObjectInformationLength,
                       OUT OPTIONAL ULONG *ReturnLength)
{
    UNIMPLEMENTED;
}
