#include <videoprt.h>

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    return VideoPortInitialize(DriverObject, RegistryPath, NULL, NULL);
}
