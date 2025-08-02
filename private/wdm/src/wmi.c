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

NTAPI ULONG IoWMIDeviceObjectToProviderId(IN PDEVICE_OBJECT DeviceObject)
{
    return DeviceObject->Header.GlobalHandle >> EX_POOL_BLOCK_SHIFT;
}

NTAPI NTSTATUS IoWMIWriteEvent(IN OUT PVOID WnodeEventItem)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI NTSTATUS EtwRegister(IN LPCGUID ProviderId,
			   IN OPTIONAL PETWENABLECALLBACK EnableCallback,
			   IN OPTIONAL PVOID CallbackContext,
			   OUT PREGHANDLE RegHandle)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI NTSTATUS EtwUnregister(IN REGHANDLE RegHandle)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI NTSTATUS EtwWrite(IN REGHANDLE RegHandle,
			IN PCEVENT_DESCRIPTOR EventDescriptor,
			IN OPTIONAL LPCGUID ActivityId,
			IN ULONG UserDataCount,
			IN PEVENT_DATA_DESCRIPTOR UserData)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI PVOID IoAllocateErrorLogEntry(IN PVOID IoObject,
				    IN UCHAR EntrySize)
{
    UNIMPLEMENTED;
    return NULL;
}

NTAPI VOID IoWriteErrorLogEntry(IN PVOID ElEntry)
{
    UNIMPLEMENTED;
}
