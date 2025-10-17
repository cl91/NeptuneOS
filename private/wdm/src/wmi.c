#include <initguid.h>
#include <wmidata.h>
#include <wmistr.h>
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

/*
 * @unimplemented
 */
NTAPI NTSTATUS IoWMIOpenBlock(IN LPCGUID DataBlockGuid,
			      IN ULONG DesiredAccess,
			      OUT HANDLE *DataBlockObject)
{
    if (IsEqualGUID(DataBlockGuid, &MSSmBios_RawSMBiosTables_GUID)) {
	*DataBlockObject = (PVOID)&MSSmBios_RawSMBiosTables_GUID;
	return STATUS_SUCCESS;
    }
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @unimplemented
 */
NTAPI NTSTATUS IoWMIQueryAllData(IN HANDLE DataBlockObject,
				 IN OUT ULONG *InOutBufferSize,
				 OUT PVOID OutBuffer)
{
    if (!InOutBufferSize) {
	return STATUS_INVALID_PARAMETER_2;
    }
    if (DataBlockObject == (PVOID)&MSSmBios_RawSMBiosTables_GUID) {
	if (*InOutBufferSize <= sizeof(WNODE_ALL_DATA) + sizeof(MSSmBios_RawSMBiosTables) ||
	    !OutBuffer) {
	    WdmWmiQueryRawSmbiosTables(InOutBufferSize, NULL);
	    *InOutBufferSize += sizeof(WNODE_ALL_DATA);
	    return STATUS_BUFFER_TOO_SMALL;
	}
	ULONG FixedInstanceSize = *InOutBufferSize - sizeof(WNODE_ALL_DATA);
	NTSTATUS Status = WdmWmiQueryRawSmbiosTables(&FixedInstanceSize,
						     (PCHAR)OutBuffer + sizeof(WNODE_ALL_DATA));
	*InOutBufferSize = sizeof(WNODE_ALL_DATA) + FixedInstanceSize;
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
	PWNODE_ALL_DATA AllData = OutBuffer;
	AllData->WnodeHeader.BufferSize = *InOutBufferSize;
        AllData->WnodeHeader.ProviderId = 0;
        AllData->WnodeHeader.Version = 0;
        AllData->WnodeHeader.Linkage = 0; // last entry
	AllData->WnodeHeader.TimeStamp.QuadPart = 0;
        AllData->WnodeHeader.Guid = MSSmBios_RawSMBiosTables_GUID;
        AllData->WnodeHeader.ClientContext = 0;
        AllData->WnodeHeader.Flags = WNODE_FLAG_FIXED_INSTANCE_SIZE;
        AllData->DataBlockOffset = sizeof(WNODE_ALL_DATA);
        AllData->InstanceCount = 1;
        AllData->FixedInstanceSize = FixedInstanceSize;
	return STATUS_SUCCESS;
    }
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
