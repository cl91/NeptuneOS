#include <lnxdrv.h>

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    return LnxInitializeDriver(DriverObject, RegistryPath);
}
