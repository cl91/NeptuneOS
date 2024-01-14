#include <wdmp.h>

NTAPI NTSTATUS CcInitializeCacheMap(IN PFILE_OBJECT FileObject,
				    IN PCC_FILE_SIZES FileSizes,
				    IN BOOLEAN PinAccess,
				    IN PVOID LazyWriteContext)
{
    return STATUS_SUCCESS;
}

NTAPI BOOLEAN CcUninitializeCacheMap(IN PFILE_OBJECT FileObject,
				     IN OPTIONAL PLARGE_INTEGER TruncateSize)
{
    return TRUE;
}

NTAPI NTSTATUS CcPinRead(IN PFILE_OBJECT FileObject,
			 IN PLARGE_INTEGER FileOffset,
			 IN ULONG Length,
			 IN ULONG Flags,
			 OUT PVOID *Bcb,
			 OUT PVOID *pBuffer)
{
    /* For now we simply call the lower driver synchronously. */
    assert(FileObject);
    PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    assert(DeviceObject);
    PVOID Buffer = ExAllocatePool(Length);
    if (!Buffer) {
	return STATUS_NO_MEMORY;
    }

    DPRINT("CcPinRead(FileObj %p DeviceObj %p, Offset %I64x, Length %u, Buffer %p)\n",
	   FileObject, DeviceObject, FileOffset->QuadPart, Length, Buffer);

    IO_STATUS_BLOCK IoStatus;
    PIRP Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer,
					    Length, FileOffset, &IoStatus);
    if (!Irp) {
	ExFreePool(Buffer);
	DPRINT("IoBuildSynchronousFsdRequest failed\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    DPRINT("Calling IO Driver... with irp %p\n", Irp);
    NTSTATUS Status = IoCallDriver(DeviceObject, Irp);

    if (!NT_SUCCESS(Status)) {
	DPRINT("IO failed!!! CcPinRead : Error code: %x\n", Status);
	DPRINT("(FileObj %p DeviceObj %p, Offset %I64x, Size %u, Buffer %p\n",
	       FileObject, DeviceObject, FileOffset->QuadPart, Length, Buffer);
	ExFreePool(Buffer);
	return Status;
    }
    DPRINT("Block request succeeded for %p\n", Irp);
    *pBuffer = Buffer;
    *Bcb = Buffer;
    return STATUS_SUCCESS;
}

NTAPI VOID CcSetDirtyPinnedData(IN PVOID BcbVoid,
				IN OPTIONAL PLARGE_INTEGER Lsn)
{
}

NTAPI VOID CcUnpinData(IN PVOID Bcb)
{
    ExFreePool(Bcb);
}

NTAPI NTSTATUS CcZeroData(IN PFILE_OBJECT FileObject,
			  IN PLARGE_INTEGER StartOffset,
			  IN PLARGE_INTEGER EndOffset,
			  IN BOOLEAN Wait)
{
    return STATUS_SUCCESS;
}

NTAPI VOID CcSetFileSizes(IN PFILE_OBJECT FileObject,
			  IN PCC_FILE_SIZES FileSizes)
{
}
