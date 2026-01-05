#include <lnxdrv.h>
#include <videoprt.h>

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTAPI VIDEOPRT_API NTSTATUS VideoPortInitialize(IN PDRIVER_OBJECT DriverObject,
						IN PUNICODE_STRING RegistryPath,
						IN PVIDEO_HW_INITIALIZATION_DATA HwInitData,
						IN PVOID HwContext)
{
    return LnxInitializeDriver(DriverObject, RegistryPath);
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    return STATUS_SUCCESS;
}
