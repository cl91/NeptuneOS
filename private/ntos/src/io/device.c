#include "iop.h"

NTSTATUS IopCreateDevice(IN PTHREAD Thread,
                         IN OPTIONAL PCSTR DeviceName,
                         IN DEVICE_TYPE DeviceType,
                         IN ULONG DeviceCharacteristics,
                         IN BOOLEAN Exclusive,
                         OUT HANDLE *DeviceHandle)
{
    return STATUS_SUCCESS;
}
