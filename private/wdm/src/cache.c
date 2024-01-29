#include <wdmp.h>

NTAPI NTSTATUS CcInitializeCacheMap(IN PFILE_OBJECT FileObject,
				    IN PCC_FILE_SIZES FileSizes,
				    IN BOOLEAN PinAccess,
				    IN PVOID LazyWriteContext)
{
    assert(FileObject);
    PDEVICE_OBJECT DeviceObject = FileObject->DeviceObject;
    assert(DeviceObject);
    if (!DeviceObject->SectorSize) {
	DeviceObject->SectorSize = IopDeviceTypeToSectorSize(DeviceObject->DeviceType);
    }
    if (!DeviceObject->SectorSize && DeviceObject->Vpb && DeviceObject->Vpb->RealDevice) {
	DeviceObject->SectorSize = IopDeviceTypeToSectorSize(DeviceObject->Vpb->RealDevice->DeviceType);
    }
    if (!DeviceObject->SectorSize) {
	/* Most likely the file object is created from a non-storage device. */
	return STATUS_INVALID_DEVICE_REQUEST;
    }
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
    /* Align the read to sector size. */
    ULONG SectorSize = DeviceObject->SectorSize;
    if (!SectorSize) {
	/* Most likely caching has not been initialized for the file object. */
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    LARGE_INTEGER ReadOffset = {
	.QuadPart = ALIGN_DOWN_64(FileOffset->QuadPart, SectorSize)
    };
    ULONG ReadLength = ALIGN_UP_BY(Length, SectorSize);
    PVOID Buffer = ExAllocatePool(ReadLength);
    if (!Buffer) {
	return STATUS_NO_MEMORY;
    }

    DPRINT("CcPinRead(FileObj %p DeviceObj %p, Offset 0x%llx, Length %u, Buffer %p, "
	   "SectorSize %d, ReadOffset 0x%llx, ReadLength 0x%x)\n",
	   FileObject, DeviceObject, FileOffset->QuadPart, Length, Buffer,
	   SectorSize, ReadOffset.QuadPart, ReadLength);

    IO_STATUS_BLOCK IoStatus;
    PIRP Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer,
					    ReadLength, &ReadOffset, &IoStatus);
    if (!Irp) {
	ExFreePool(Buffer);
	DPRINT("IoBuildSynchronousFsdRequest failed\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    DPRINT("Calling storage device driver with irp %p\n", Irp);
    NTSTATUS Status = IoCallDriver(DeviceObject, Irp);

    if (!NT_SUCCESS(Status)) {
	DPRINT("IO failed!!! CcPinRead : Error code: %x\n", Status);
	DPRINT("(FileObj %p DeviceObj %p, ReadOffset %I64x, ReadLength %u, Buffer %p\n",
	       FileObject, DeviceObject, ReadOffset.QuadPart, ReadLength, Buffer);
	ExFreePool(Buffer);
	return Status;
    }
    DPRINT("Block request succeeded for %p\n", Irp);
    *pBuffer = (PUCHAR)Buffer + (FileOffset->QuadPart - ReadOffset.QuadPart);
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
