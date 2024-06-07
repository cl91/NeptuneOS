#include <wdmp.h>

/*
 * @unimplemented
 */
NTAPI NTSTATUS IoWMIRegistrationControl(IN PDEVICE_OBJECT DeviceObject,
					IN ULONG Action)
{
    DPRINT("IoWMIRegistrationControl() called for DO %p, "
	   "requesting %u action, returning success\n",
	   DeviceObject, Action);
    return STATUS_SUCCESS;
}
