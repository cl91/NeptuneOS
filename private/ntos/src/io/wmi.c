#include "iop.h"

NTSTATUS WdmWmiQueryRawSmbiosTables(IN ASYNC_STATE AsyncState,
				    IN PTHREAD Thread,
				    IN OUT PULONG InOutBufferSize,
				    IN OPTIONAL PVOID OutBuffer)
{
    PMSSmBios_RawSMBiosTables RawTables = HalGetRawSmbiosTables();
    if (!RawTables || !RawTables->Size) {
	return STATUS_NOT_FOUND;
    }
    ULONG HeaderSize = FIELD_OFFSET(MSSmBios_RawSMBiosTables, SMBiosData);
    ULONG BufferSize = HeaderSize + RawTables->Size;
    if (*InOutBufferSize < BufferSize) {
	*InOutBufferSize = BufferSize;
	return STATUS_BUFFER_TOO_SMALL;
    }
    *InOutBufferSize = BufferSize;
    if (!OutBuffer) {
	return STATUS_SUCCESS;
    }
    PVOID MappedBuffer = NULL;
    RET_ERR(MmMapUserBuffer(&Thread->Process->VSpace, (MWORD)OutBuffer, BufferSize,
			    &MappedBuffer));
    assert(MappedBuffer);
    RtlCopyMemory(MappedBuffer, RawTables, BufferSize);
    MmUnmapUserBuffer(MappedBuffer);
    return STATUS_SUCCESS;
}
