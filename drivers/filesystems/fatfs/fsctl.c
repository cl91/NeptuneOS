/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Filesystem routines
 * COPYRIGHT:   Copyright 2002-2013 Eric Kohl <eric.kohl@reactos.org>
 *              Copyright 2008-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"
#include <ctype.h>

extern FAT_DISPATCH FatXDispatch;
extern FAT_DISPATCH FatDispatch;

/* FUNCTIONS ****************************************************************/

/* Read the disk by sending an IRP to the volume device object and wait for
 * the results. This is used by the mount logic before caching is setup. */
static NTSTATUS FatReadDisk(IN PDEVICE_OBJECT DeviceObject,
			    IN PLARGE_INTEGER ReadOffset,
			    IN ULONG ReadLength,
			    OUT PUCHAR Buffer,
			    IN BOOLEAN OverrideVerify)
{
    DPRINT("FatReadDisk(DeviceObject %p, Offset 0x%llx, Length 0x%x, Buffer %p)\n",
	   DeviceObject, ReadOffset ? ReadOffset->QuadPart : 0ULL, ReadLength, Buffer);

    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer,
					    ReadLength, ReadOffset, &Event, &IoStatus);
    if (Irp == NULL) {
	DPRINT("IoBuildSynchronousFsdRequest failed\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (OverrideVerify) {
	IoGetNextIrpStackLocation(Irp)->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    }

    DPRINT("Calling storage device driver with irp %p\n", Irp);
    NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    if (!NT_SUCCESS(Status)) {
	DPRINT("IO failed!!! FatReadDisk : Error code: %x\n", Status);
	DPRINT("(DeviceObject %p, Offset %llx, Size %u, Buffer %p\n",
	       DeviceObject, ReadOffset->QuadPart, ReadLength, Buffer);
	return Status;
    }
    DPRINT("Block request succeeded for %p\n", Irp);
    return STATUS_SUCCESS;
}

NTSTATUS FatBlockDeviceIoControl(IN PDEVICE_OBJECT DeviceObject,
				 IN ULONG CtlCode,
				 IN OPTIONAL PVOID InputBuffer,
				 IN ULONG InputBufferSize,
				 OUT OPTIONAL PVOID OutputBuffer,
				 OUT PULONG OutputBufferSize,
				 IN BOOLEAN OverrideVerify)
{
    DPRINT("FatBlockDeviceIoControl(DeviceObject %p, CtlCode %x, "
	   "InputBuffer %p, InputBufferSize %x, OutputBuffer %p, "
	   "OutputBufferSize %p (%x)\n", DeviceObject, CtlCode,
	   InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize,
	   OutputBufferSize ? *OutputBufferSize : 0);

    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp = IoBuildDeviceIoControlRequest(CtlCode, DeviceObject, InputBuffer,
					     InputBufferSize, OutputBuffer,
					     OutputBufferSize ? *OutputBufferSize : 0,
					     FALSE, &Event, &IoStatus);
    if (Irp == NULL) {
	DPRINT("IoBuildDeviceIoControlRequest failed\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (OverrideVerify) {
	IoGetNextIrpStackLocation(Irp)->Flags |= SL_OVERRIDE_VERIFY_VOLUME;
    }

    DPRINT("Calling storage device driver with irp %p\n", Irp);
    NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject (&Event, Suspended, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    if (OutputBufferSize) {
	*OutputBufferSize = IoStatus.Information;
    }

    DPRINT("Returning Status %x\n", Status);
    return Status;
}

/* Returns TRUE if Val matches one of the values in Set. */
FORCEINLINE BOOLEAN ValidateValue(IN ULONG Val,
				  IN ULONG *Set,
				  IN ULONG Size)
{
    for (ULONG i = 0; i < Size; i++) {
	if (Val == Set[i]) {
	    return TRUE;
	}
    }
    return FALSE;
}

static NTSTATUS FatHasFileSystem(PDEVICE_OBJECT DeviceToMount,
				 PBOOLEAN RecognizedFS,
				 PFATINFO pFatInfo,
				 BOOLEAN OverrideVerify)
{
    DPRINT("FatHasFileSystem\n");

    *RecognizedFS = FALSE;

    ULONG Size = sizeof(DISK_GEOMETRY);
    DISK_GEOMETRY DiskGeometry;
    NTSTATUS Status = FatBlockDeviceIoControl(DeviceToMount,
					      IOCTL_DISK_GET_DRIVE_GEOMETRY,
					      NULL, 0, &DiskGeometry,
					      &Size, OverrideVerify);
    if (!NT_SUCCESS(Status)) {
	DPRINT("FatBlockDeviceIoControl failed (%x)\n", Status);
	return Status;
    }
    DPRINT("Disk Geometry:\n");
    DPRINT("Cylinders         0x%llx\n", DiskGeometry.Cylinders.QuadPart);
    DPRINT("MediaType           %d\n", DiskGeometry.MediaType);
    DPRINT("TracksPerCylinder   %d\n", DiskGeometry.TracksPerCylinder);
    DPRINT("SectorsPerTrack     %d\n", DiskGeometry.SectorsPerTrack);
    DPRINT("BytesPerSector      %d\n", DiskGeometry.BytesPerSector);

    FATINFO FatInfo = { .FixedMedia = (DiskGeometry.MediaType == FixedMedia) };
    BOOLEAN PartitionInfoIsValid = FALSE;
    PARTITION_INFORMATION PartitionInfo;
    if (FatInfo.FixedMedia || DiskGeometry.MediaType == RemovableMedia) {
	/* We have found a hard disk. Now ask partmgr for the partition info.
	 * Note this call will only succeed for MBR partitions. */
	Size = sizeof(PARTITION_INFORMATION);
	Status = FatBlockDeviceIoControl(DeviceToMount,
					 IOCTL_DISK_GET_PARTITION_INFO,
					 NULL, 0, &PartitionInfo,
					 &Size, OverrideVerify);
	if (!NT_SUCCESS(Status)) {
	    DPRINT("FatBlockDeviceIoControl failed (%x)\n", Status);
	    goto check;
	}

	DPRINT("Partition Information:\n");
	DPRINT("StartingOffset      0x%llx\n",
	       PartitionInfo.StartingOffset.QuadPart / 512);
	DPRINT("PartitionLength     0x%llx\n",
	       PartitionInfo.PartitionLength.QuadPart / 512);
	DPRINT("HiddenSectors       %u\n", PartitionInfo.HiddenSectors);
	DPRINT("PartitionNumber     %u\n", PartitionInfo.PartitionNumber);
	DPRINT("PartitionType       %u\n", PartitionInfo.PartitionType);
	DPRINT("BootIndicator       %u\n", PartitionInfo.BootIndicator);
	DPRINT("RecognizedPartition %u\n", PartitionInfo.RecognizedPartition);
	DPRINT("RewritePartition    %u\n", PartitionInfo.RewritePartition);
	if (PartitionInfo.PartitionType) {
	    ULONG ValidPartitionTypes[] = {
		PARTITION_FAT_12, PARTITION_FAT_16, PARTITION_HUGE,
		PARTITION_FAT32, PARTITION_FAT32_XINT13, PARTITION_XINT13
	    };
	    PartitionInfoIsValid = ValidateValue(PartitionInfo.PartitionType,
						 ValidPartitionTypes,
						 ARRAYSIZE(ValidPartitionTypes));
	} else if (DiskGeometry.MediaType == RemovableMedia &&
		   PartitionInfo.PartitionNumber > 0 &&
		   PartitionInfo.StartingOffset.QuadPart == 0 &&
		   PartitionInfo.PartitionLength.QuadPart > 0) {
	    /* This is possible (a removable media formated as super floppy) */
	    PartitionInfoIsValid = TRUE;
	}
    }

    /* Even if PartitionInfoIsValid is FALSE, we will still check if
     * the boot sector is a FAT boot sector. This mostly applies to floppy
     * and ZIP disks formatted using the FAT file system, and GPT disks. */
check:
    PBOOT_SECTOR Boot = ExAllocatePoolWithTag(NonPagedPool,
					      DiskGeometry.BytesPerSector,
					      TAG_BUFFER);
    if (Boot == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Try to recognize FAT12/FAT16/FAT32 partitions */
    LARGE_INTEGER Offset = { .QuadPart = 0 };
    Status = FatReadDisk(DeviceToMount, &Offset, DiskGeometry.BytesPerSector,
			 (PUCHAR)Boot, OverrideVerify);
    ULONG ValidBytesPerSector[] = { 512, 1024, 2048, 4096 };
    ULONG ValidMedia[] = { 0xf0, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
    ULONG ValidSectorsPerCluster[] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    if (!NT_SUCCESS(Status) || Boot->Signature1 != 0xaa55 ||
	!ValidateValue(Boot->BytesPerSector, ValidBytesPerSector,
		       ARRAYSIZE(ValidBytesPerSector)) ||
	!(Boot->FATCount == 1 || Boot->FATCount == 2) ||
	!ValidateValue(Boot->Media, ValidMedia, ARRAYSIZE(ValidMedia)) ||
	!ValidateValue(Boot->SectorsPerCluster, ValidSectorsPerCluster,
		       ARRAYSIZE(ValidSectorsPerCluster)) ||
	!(Boot->BytesPerSector * Boot->SectorsPerCluster <= 64 * 1024)) {
	goto CheckFatX;
    }

    FatInfo.VolumeID = Boot->VolumeID;
    FatInfo.FatStart = Boot->ReservedSectors;
    FatInfo.FATCount = Boot->FATCount;
    FatInfo.BytesPerSector = Boot->BytesPerSector;
    FatInfo.SectorsPerCluster = Boot->SectorsPerCluster;
    FatInfo.FatSectors = Boot->FatSectors ? Boot-> FatSectors :
	((PBOOT_SECTOR_FAT32)Boot)->FatSectors32;
    FatInfo.BytesPerCluster = FatInfo.BytesPerSector * FatInfo.SectorsPerCluster;
    FatInfo.RootDirectorySectors = (Boot->RootEntries * 32 + Boot->BytesPerSector - 1)
	/ Boot->BytesPerSector;
    FatInfo.RootStart = FatInfo.FatStart + FatInfo.FATCount * FatInfo.FatSectors;
    FatInfo.DataStart = FatInfo.RootStart + FatInfo.RootDirectorySectors;
    ULONG Sectors = Boot->Sectors ? Boot->Sectors : Boot->SectorsHuge;
    FatInfo.Sectors = Sectors;
    Sectors -= Boot->ReservedSectors + FatInfo.FATCount * FatInfo.FatSectors
	+ FatInfo.RootDirectorySectors;
    FatInfo.NumberOfClusters = Sectors / Boot->SectorsPerCluster;
    if (FatInfo.NumberOfClusters < 4085) {
	DPRINT("FAT12\n");
	FatInfo.FatType = FAT12;
	FatInfo.RootCluster = (FatInfo.RootStart - 1) / FatInfo.SectorsPerCluster;
	RtlCopyMemory(&FatInfo.VolumeLabel, &Boot->VolumeLabel,
		      sizeof(FatInfo.VolumeLabel));
    } else if (FatInfo.NumberOfClusters >= 65525) {
	DPRINT("FAT32\n");
	FatInfo.FatType = FAT32;
	FatInfo.RootCluster = ((PBOOT_SECTOR_FAT32)Boot)->RootCluster;
	FatInfo.RootStart = FatInfo.DataStart +
	    ((FatInfo.RootCluster - 2) * FatInfo.SectorsPerCluster);
	FatInfo.VolumeID = ((PBOOT_SECTOR_FAT32)Boot)->VolumeID;
	FatInfo.FSInfoSector = ((PBOOT_SECTOR_FAT32)Boot)->FSInfoSector;
	RtlCopyMemory(&FatInfo.VolumeLabel,
		      &((PBOOT_SECTOR_FAT32)Boot)->VolumeLabel,
		      sizeof(FatInfo.VolumeLabel));
    } else {
	DPRINT("FAT16\n");
	FatInfo.FatType = FAT16;
	FatInfo.RootCluster = FatInfo.RootStart / FatInfo.SectorsPerCluster;
	RtlCopyMemory(&FatInfo.VolumeLabel, &Boot->VolumeLabel,
		      sizeof(FatInfo.VolumeLabel));
    }

    if (PartitionInfoIsValid && FatInfo.Sectors >
	PartitionInfo.PartitionLength.QuadPart / FatInfo.BytesPerSector) {
	goto CheckFatX;
    }

    /* We have a valid FAT12/16/32 file system! */
    *RecognizedFS = TRUE;
    if (pFatInfo) {
	*pFatInfo = FatInfo;
    }
    ExFreePoolWithTag(Boot, TAG_BUFFER);
    return *RecognizedFS ? STATUS_SUCCESS : STATUS_UNRECOGNIZED_VOLUME;

CheckFatX:
    ExFreePoolWithTag(Boot, TAG_BUFFER);

    /* XBox hard drives must have an MBR partition table, so return error
     * if partition info is invalid. */
    if (!PartitionInfoIsValid) {
	return STATUS_UNRECOGNIZED_VOLUME;
    }

    PBOOT_SECTOR_FATX BootFatX = ExAllocatePoolWithTag(NonPagedPool,
						       sizeof(BOOT_SECTOR_FATX),
						       TAG_BUFFER);
    if (BootFatX == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Try to recognize FATX16/FATX32 partitions (Xbox) */
    Offset.QuadPart = 0;
    Status = FatReadDisk(DeviceToMount, &Offset, sizeof(BOOT_SECTOR_FATX),
			 (PUCHAR)BootFatX, OverrideVerify);
    if (!NT_SUCCESS(Status)) {
	goto Exit;
    }

    if (BootFatX->SysType[0] != 'F' || BootFatX->SysType[1] != 'A' ||
	BootFatX->SysType[2] != 'T' || BootFatX->SysType[3] != 'X') {
	DPRINT1("SysType %02X%02X%02X%02X (%c%c%c%c)\n",
		BootFatX->SysType[0], BootFatX->SysType[1],
		BootFatX->SysType[2], BootFatX->SysType[3],
		isprint(BootFatX->SysType[0]) ? BootFatX->SysType[0] : '.',
		isprint(BootFatX->SysType[1]) ? BootFatX->SysType[1] : '.',
		isprint(BootFatX->SysType[2]) ? BootFatX->SysType[2] : '.',
		isprint(BootFatX->SysType[3]) ? BootFatX->SysType[3] : '.');
	goto Exit;
    }

    if (!ValidateValue(BootFatX->SectorsPerCluster, ValidSectorsPerCluster,
		       ARRAYSIZE(ValidSectorsPerCluster))) {
	DPRINT1("Invalid SectorsPerCluster %u\n", BootFatX->SectorsPerCluster);
	goto Exit;
    }

    FatInfo.BytesPerSector = DiskGeometry.BytesPerSector;
    FatInfo.SectorsPerCluster = BootFatX->SectorsPerCluster;
    FatInfo.RootDirectorySectors = BootFatX->SectorsPerCluster;
    FatInfo.BytesPerCluster = BootFatX->SectorsPerCluster * DiskGeometry.BytesPerSector;
    FatInfo.Sectors = (ULONG)(PartitionInfo.PartitionLength.QuadPart /
			      DiskGeometry.BytesPerSector);
    if (FatInfo.Sectors / FatInfo.SectorsPerCluster < 65525) {
	DPRINT("FATX16\n");
	FatInfo.FatType = FATX16;
    } else {
	DPRINT("FATX32\n");
	FatInfo.FatType = FATX32;
    }
    FatInfo.VolumeID = BootFatX->VolumeID;
    FatInfo.FatStart = sizeof(BOOT_SECTOR_FATX) / DiskGeometry.BytesPerSector;
    FatInfo.FATCount = BootFatX->FATCount;
    FatInfo.FatSectors = ROUND_UP_32(FatInfo.Sectors / FatInfo.SectorsPerCluster *
				     (FatInfo.FatType == FATX16 ? 2 : 4), 4096) /
	FatInfo.BytesPerSector;
    FatInfo.RootStart = FatInfo.FatStart + FatInfo.FATCount * FatInfo.FatSectors;
    FatInfo.RootCluster = (FatInfo.RootStart - 1) / FatInfo.SectorsPerCluster;
    FatInfo.DataStart = FatInfo.RootStart + FatInfo.RootDirectorySectors;
    FatInfo.NumberOfClusters = (FatInfo.Sectors - FatInfo.DataStart) /
	FatInfo.SectorsPerCluster;

    /* We have a valid FATX file system! */
    *RecognizedFS = TRUE;
    if (pFatInfo) {
	*pFatInfo = FatInfo;
    }

Exit:
    ExFreePoolWithTag(BootFatX, TAG_BUFFER);
    DPRINT("FatHasFileSystem done\n");
    return Status;
}

/*
 * FUNCTION: Read the volume label
 * WARNING: Read this comment carefully before using this function.
 *
 * If Start is zero, we access the underlying disk through the cache manager.
 * In this case the Device pointer must point to a Volume Control Block.
 *
 * If Start is not zero, we access the underlying disk by calling the storage
 * device driver directly. In this case, the Device pointer must point to
 * the storage device object, and Start is the file offset (in bytes) within
 * the volume of the root directory entry.
 *
 * VolumeLabel parameter is expected to be a preallocated UNICODE_STRING (ie,
 * with a valid buffer pointer). The buffer must be able to contain at least
 * MAXIMUM_VOLUME_LABEL_LENGTH bytes.
 */
static NTSTATUS ReadVolumeLabel(IN PVOID Device,
				IN ULONG Start,
				IN BOOLEAN IsFatX,
				IN ULONG ClusterSize,
				OUT PUNICODE_STRING VolumeLabel)
{
    ULONG SizeDirEntry = IsFatX ? sizeof(FATX_DIR_ENTRY) : sizeof(FAT_DIR_ENTRY);
    ULONG EntriesPerCluster = ClusterSize / SizeDirEntry;

    PFATFCB pFcb = NULL;
    PVOID Buffer = NULL;
    if (!Start) {
	/* FIXME: Check we really have a VCB */
	pFcb = FatOpenRootFcb((PDEVICE_EXTENSION)Device);
    } else {
	Buffer = ExAllocatePoolWithTag(NonPagedPool, ClusterSize, TAG_DIRENT);
	if (Buffer == NULL) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
    }

    LARGE_INTEGER FileOffset = { .QuadPart = Start };
    PVOID Context = NULL;
    ULONG DirIndex = 0;
    PDIR_ENTRY Entry;
    NTSTATUS Status = STATUS_SUCCESS;
    while (TRUE) {
	/* When we cross a cluster boundary (including at the very start),
	 * read one cluster off the disk, either via the cache manager or
	 * by calling the underlying storage driver. */
	if ((DirIndex % EntriesPerCluster) == 0) {
	    if (!Start) {
		if (Context) {
		    CcUnpinData(Context);
		    Context = NULL;
		}
		ULONG MappedLength;
		Status = CcMapData(pFcb->FileObject, &FileOffset, SizeDirEntry,
				   MAP_WAIT, &MappedLength, &Context, (PVOID *)&Entry);
		if (MappedLength != SizeDirEntry) {
		    Status = STATUS_NONE_MAPPED;
		}
	    } else {
		Status = FatReadDisk((PDEVICE_OBJECT)Device, &FileOffset,
				     ClusterSize, (PUCHAR)Buffer, TRUE);
		Entry = Buffer;
	    }
	    if (!NT_SUCCESS(Status)) {
		break;
	    }
	}

	/* Check if the directory entry contains the volume label */
	if (ENTRY_VOLUME(IsFatX, Entry)) {
	    /* Copy volume label */
	    if (IsFatX) {
		OEM_STRING StringO;
		StringO.Buffer = (PCHAR)Entry->FatX.Filename;
		StringO.Length = Entry->FatX.FilenameLength;
		StringO.MaximumLength = StringO.Length;
		RtlOemStringToUnicodeString(VolumeLabel, &StringO, FALSE);
	    } else {
		Fat8Dot3ToString(&Entry->Fat, VolumeLabel);
	    }
	    Status = STATUS_SUCCESS;
	    break;
	}
	if (ENTRY_END(IsFatX, Entry)) {
	    VolumeLabel->Length = 0;
	    Status = STATUS_SUCCESS;
	    break;
	}
	DirIndex++;
	Entry = (PDIR_ENTRY)((ULONG_PTR)Entry + SizeDirEntry);
	if ((DirIndex % EntriesPerCluster) == 0) {
	    FileOffset.QuadPart += ClusterSize;
	}
    }

    if (pFcb) {
	FatReleaseFcb((PDEVICE_EXTENSION)Device, pFcb);
    }
    if (Context) {
	CcUnpinData(Context);
    }
    if (Buffer) {
	ExFreePoolWithTag(Buffer, TAG_DIRENT);
    }

    return Status;
}


/*
 * FUNCTION: Mount the filesystem
 */
static NTSTATUS FatMount(PFAT_IRP_CONTEXT IrpContext)
{
    DPRINT("FatMount(IrpContext %p)\n", IrpContext);

    ASSERT(IrpContext);

    /* This IRP must be sent to the device object representing the file
     * system itself (ie. the \FatX device created in DriverEntry). */
    if (IrpContext->DeviceObject != FatGlobalData->DeviceObject) {
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* DeviceToMount is the underlying storage device object. */
    PDEVICE_OBJECT DeviceToMount = IrpContext->Stack->Parameters.MountVolume.DeviceObject;
    PVPB Vpb = IrpContext->Stack->Parameters.MountVolume.Vpb;

    BOOLEAN RecognizedFS;
    FATINFO FatInfo;
    NTSTATUS Status = FatHasFileSystem(DeviceToMount, &RecognizedFS, &FatInfo, FALSE);

    /* Call the storage device driver to clear the VERIFY_REQUIRED flag and try again. */
    if (Status == STATUS_MEDIA_CHANGED || Status == STATUS_VERIFY_REQUIRED) {
	ULONG ChangeCount, BufSize = sizeof(ChangeCount);
	Status = FatBlockDeviceIoControl(DeviceToMount, IOCTL_DISK_CHECK_VERIFY, NULL,
					 0, &ChangeCount, &BufSize, TRUE);
	if (!NT_SUCCESS(Status) && Status != STATUS_VERIFY_REQUIRED) {
	    DPRINT("FatBlockDeviceIoControl() failed (Status %x)\n", Status);
	    return Status;
	}
	Status = FatHasFileSystem(DeviceToMount, &RecognizedFS, &FatInfo, FALSE);
    }

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (RecognizedFS == FALSE) {
	DPRINT("FAT: Unrecognized Volume\n");
	return STATUS_UNRECOGNIZED_VOLUME;
    }

    /* Use prime numbers for the table size */
    ULONG HashTableSize;
    if (FatInfo.FatType == FAT12) {
	HashTableSize = 4099;	// 4096 = 4 * 1024
    } else if (FatInfo.FatType == FAT16 || FatInfo.FatType == FATX16) {
	HashTableSize = 16411;	// 16384 = 16 * 1024
    } else {
	HashTableSize = 65537;	// 65536 = 64 * 1024;
    }
    DPRINT("FAT: Recognized volume!\n");

    /* Create the FS volume device object. Read/write IRPs are sent to this device. */
    PDEVICE_OBJECT DeviceObject;
    ULONG DevExtStructSize = ROUND_UP_32(sizeof(DEVICE_EXTENSION), sizeof(ULONG));
    ULONG DevExtFullSize = DevExtStructSize + sizeof(PHASHENTRY) * HashTableSize;
    ULONG Flags = DeviceToMount->Flags & (FILE_REMOVABLE_MEDIA | FILE_READ_ONLY_DEVICE
					  | FILE_FLOPPY_DISKETTE | FILE_DEVICE_SECURE_OPEN);
    /* For write-once media, we can only mount the volume read-only. */
    if (DeviceToMount->Flags & FILE_WRITE_ONCE_MEDIA) {
	Flags |= FILE_READ_ONLY_DEVICE;
    }
    Status = IoCreateDevice(FatGlobalData->DriverObject, DevExtFullSize, NULL,
			    FILE_DEVICE_DISK_FILE_SYSTEM, Flags, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    PDEVICE_EXTENSION DeviceExt = DeviceObject->DeviceExtension;
    RtlZeroMemory(DeviceExt, DevExtFullSize);
    DeviceExt->FcbHashTable = (PHASHENTRY *)((ULONG_PTR)DeviceExt + DevExtStructSize);
    DeviceExt->HashTableSize = HashTableSize;
    DeviceExt->VolumeDevice = DeviceObject;

    /* Use the same vpb as the underlying storage device object */
    DeviceObject->Vpb = Vpb;
    DeviceToMount->Vpb = Vpb;

    RtlCopyMemory(&DeviceExt->FatInfo, &FatInfo, sizeof(FATINFO));

    DPRINT("BytesPerSector:     %u\n", DeviceExt->FatInfo.BytesPerSector);
    DPRINT("SectorsPerCluster:  %u\n", DeviceExt->FatInfo.SectorsPerCluster);
    DPRINT("FATCount:           %u\n", DeviceExt->FatInfo.FATCount);
    DPRINT("FatSectors:         %u\n", DeviceExt->FatInfo.FatSectors);
    DPRINT("RootStart:          %u\n", DeviceExt->FatInfo.RootStart);
    DPRINT("DataStart:          %u\n", DeviceExt->FatInfo.DataStart);
    if (DeviceExt->FatInfo.FatType == FAT32) {
	DPRINT("RootCluster:        %u\n", DeviceExt->FatInfo.RootCluster);
    }

    if (DeviceExt->FatInfo.FatType == FATX16 ||
	DeviceExt->FatInfo.FatType == FATX32) {
	DeviceExt->Flags |= VCB_IS_FATX;
	DeviceExt->BaseDateYear = 2000;
	RtlCopyMemory(&DeviceExt->Dispatch, &FatXDispatch,
		      sizeof(FAT_DISPATCH));
    } else {
	DeviceExt->BaseDateYear = 1980;
	RtlCopyMemory(&DeviceExt->Dispatch, &FatDispatch,
		      sizeof(FAT_DISPATCH));
    }

    DeviceExt->StorageDevice = DeviceToMount;
    DeviceExt->StorageDevice->Vpb->DeviceObject = DeviceObject;
    DeviceExt->StorageDevice->Vpb->RealDevice = DeviceExt->StorageDevice;
    DeviceExt->StorageDevice->Vpb->VolumeSize = (ULONG64)FatInfo.Sectors *
	FatInfo.BytesPerSector;
    DeviceExt->StorageDevice->Vpb->Flags |= VPB_MOUNTED;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT("FsDeviceObject %p\n", DeviceObject);

    /* Record the VPB in the device object, and create a spare VPB.
     * Both are used by the dismount logic. */
    DeviceExt->IoVPB = DeviceObject->Vpb;
    DeviceExt->SpareVPB = ExAllocatePoolWithTag(NonPagedPool, sizeof(VPB), TAG_VPB);
    PFATFCB FatFcb = NULL, VolumeFcb = NULL;
    PFILE_OBJECT VolumeFileObject = NULL;
    if (DeviceExt->SpareVPB == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto ByeBye;
    }

    ULONG StatisticsSize = sizeof(STATISTICS) * FatGlobalData->NumberProcessors;
    DeviceExt->Statistics = ExAllocatePoolWithTag(NonPagedPool,
						  StatisticsSize, TAG_STATS);
    if (DeviceExt->Statistics == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto ByeBye;
    }

    RtlZeroMemory(DeviceExt->Statistics, StatisticsSize);
    for (ULONG i = 0; i < FatGlobalData->NumberProcessors; ++i) {
	DeviceExt->Statistics[i].Base.FileSystemType = FILESYSTEM_STATISTICS_TYPE_FAT;
	DeviceExt->Statistics[i].Base.Version = 1;
	DeviceExt->Statistics[i].Base.SizeOfCompleteStructure = sizeof(STATISTICS);
    }

    /* Create the volume stream file object and initialize caching for it. */
    UNICODE_STRING VolumeNameU = RTL_CONSTANT_STRING(L"\\$$Volume$$");
    VolumeFcb = FatNewFcb(DeviceExt, &VolumeNameU);
    if (VolumeFcb == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto ByeBye;
    }

    VolumeFileObject = IoCreateStreamFileObject(DeviceExt->StorageDevice);
    if (!VolumeFileObject) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto ByeBye;
    }

    Status = FatAttachFcbToFileObject(DeviceExt, VolumeFcb, VolumeFileObject);
    if (!NT_SUCCESS(Status))
	goto ByeBye;

    VolumeFcb->Flags = FCB_IS_VOLUME;
    VolumeFcb->Base.FileSizes.FileSize.QuadPart = (LONGLONG)FatInfo.Sectors *
	FatInfo.BytesPerSector;
    VolumeFcb->Base.FileSizes.ValidDataLength = VolumeFcb->Base.FileSizes.FileSize;
    VolumeFcb->Base.FileSizes.AllocationSize = VolumeFcb->Base.FileSizes.FileSize;
    VolumeFcb->FileObject = VolumeFileObject;
    DeviceExt->VolumeFcb = VolumeFcb;

    Status = CcInitializeCacheMap(VolumeFileObject);
    if (!NT_SUCCESS(Status)) {
	goto ByeBye;
    }

    /* Create the FAT table stream file object and initialize caching for it. */
    DeviceExt->FatFileObject = IoCreateStreamFileObject(DeviceExt->StorageDevice);
    if (!DeviceExt->FatFileObject) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto ByeBye;
    }
    UNICODE_STRING NameU = RTL_CONSTANT_STRING(L"\\$$Fat$$");
    FatFcb = FatNewFcb(DeviceExt, &NameU);
    if (!FatFcb) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto ByeBye;
    }

    Status = FatAttachFcbToFileObject(DeviceExt, FatFcb, DeviceExt->FatFileObject);
    if (!NT_SUCCESS(Status))
	goto ByeBye;

    FatFcb->FileObject = DeviceExt->FatFileObject;

    FatFcb->Flags = FCB_IS_FAT;
    FatFcb->Base.FileSizes.FileSize.QuadPart = (LONGLONG)FatInfo.FatSectors *
	FatInfo.BytesPerSector;
    FatFcb->Base.FileSizes.AllocationSize = FatFcb->Base.FileSizes.FileSize;
    FatFcb->Base.FileSizes.ValidDataLength = FatFcb->Base.FileSizes.FileSize;

    Status = CcInitializeCacheMap(DeviceExt->FatFileObject);
    if (!NT_SUCCESS(Status)) {
	goto ByeBye;
    }

    DeviceExt->LastAvailableCluster = 2;
    Status = CountAvailableClusters(DeviceExt, NULL);
    if (!NT_SUCCESS(Status)) {
	goto ByeBye;
    }

    InitializeListHead(&DeviceExt->FcbListHead);
    InsertHeadList(&FatGlobalData->VolumeListHead, &DeviceExt->VolumeListEntry);

    /* Read serial number */
    DeviceObject->Vpb->SerialNumber = DeviceExt->FatInfo.VolumeID;

    /* Read volume label */
    UNICODE_STRING VolumeLabelU = {
	.Buffer = DeviceObject->Vpb->VolumeLabel,
	.Length = 0,
	.MaximumLength = sizeof(DeviceObject->Vpb->VolumeLabel)
    };
    Status = ReadVolumeLabel(DeviceExt, 0, FatVolumeIsFatX(DeviceExt),
			     DeviceExt->FatInfo.BytesPerCluster, &VolumeLabelU);
    if (!NT_SUCCESS(Status)) {
	goto ByeBye;
    }
    Vpb->VolumeLabelLength = VolumeLabelU.Length;

    /* Read dirty bit status */
    BOOLEAN Dirty;
    Status = GetDirtyStatus(DeviceExt, &Dirty);
    if (!NT_SUCCESS(Status)) {
	goto ByeBye;
    }

    /* The volume wasn't dirty, it was properly dismounted */
    if (!Dirty) {
	/* Mark it dirty now! */
	Status = SetDirtyStatus(DeviceExt, TRUE);
	if (!NT_SUCCESS(Status)) {
	    goto ByeBye;
	}
	VolumeFcb->Flags |= VCB_CLEAR_DIRTY;
    } else {
	DPRINT1("Mounting a dirty volume\n");
    }

    VolumeFcb->Flags |= VCB_IS_DIRTY;
    if (BooleanFlagOn(Vpb->RealDevice->Flags, DO_SYSTEM_BOOT_PARTITION)) {
	SetFlag(DeviceExt->Flags, VCB_IS_SYS_OR_HAS_PAGE);
    }

    /* The VCB is OK for usage */
    SetFlag(DeviceExt->Flags, VCB_GOOD);

    /* Send the mount notification */
    FsRtlNotifyVolumeEvent(DeviceExt->FatFileObject, FSRTL_VOLUME_MOUNT);

    DPRINT("Mount success\n");
    return STATUS_SUCCESS;

ByeBye:
    /* Cleanup */
    assert(DeviceObject);
    assert(DeviceExt);
    if (DeviceExt->FatFileObject) {
	LARGE_INTEGER Zero = {{0, 0}};
	PFATCCB Ccb = (PFATCCB)DeviceExt->FatFileObject->FsContext2;
	CcUninitializeCacheMap(DeviceExt->FatFileObject, &Zero);
	ObDereferenceObject(DeviceExt->FatFileObject);
	if (Ccb)
	    FatDestroyCcb(Ccb);
	DeviceExt->FatFileObject = NULL;
    }
    if (FatFcb) {
	FatDestroyFcb(FatFcb);
    }
    if (VolumeFileObject) {
	LARGE_INTEGER Zero = {{0, 0}};
	PFATCCB Ccb = (PFATCCB)VolumeFileObject->FsContext2;
	CcUninitializeCacheMap(VolumeFileObject, &Zero);
	ObDereferenceObject(VolumeFileObject);
	if (Ccb)
	    FatDestroyCcb(Ccb);
    }
    if (VolumeFcb) {
	FatDestroyFcb(VolumeFcb);
	DeviceExt->VolumeFcb = NULL;
    }
    if (DeviceExt->SpareVPB)
	ExFreePoolWithTag(DeviceExt->SpareVPB, TAG_VPB);
    if (DeviceExt->Statistics)
	ExFreePoolWithTag(DeviceExt->Statistics, TAG_STATS);
    IoDeleteDevice(DeviceObject);

    return Status;
}


/*
 * FUNCTION: Verify the filesystem
 */
static NTSTATUS FatVerify(PFAT_IRP_CONTEXT IrpContext)
{
    DPRINT("FatVerify(IrpContext %p)\n", IrpContext);

    PDEVICE_OBJECT DeviceToVerify = IrpContext->Stack->Parameters.VerifyVolume.DeviceObject;
    PDEVICE_EXTENSION DeviceExt = DeviceToVerify->DeviceExtension;
    PVPB Vpb = IrpContext->Stack->Parameters.VerifyVolume.Vpb;
    BOOLEAN AllowRaw = BooleanFlagOn(IrpContext->Stack->Flags, SL_ALLOW_RAW_MOUNT);

    ULONG ChangeCount, BufSize = sizeof(ChangeCount);
    NTSTATUS Status = FatBlockDeviceIoControl(DeviceExt->StorageDevice,
					      IOCTL_DISK_CHECK_VERIFY, NULL,
					      0, &ChangeCount, &BufSize, TRUE);
    if (!NT_SUCCESS(Status) && Status != STATUS_VERIFY_REQUIRED) {
	DPRINT("FatBlockDeviceIoControl() failed (Status %x)\n", Status);
	return AllowRaw ? STATUS_WRONG_VOLUME : Status;
    }

    /* At this point the underlying disk driver should have DO_VERIFY_VOLUME
     * cleared, but just to make sure we set SL_OVERRIDE_VERIFY_VOLUME. */
    FATINFO FatInfo;
    BOOLEAN RecognizedFS;
    Status = FatHasFileSystem(DeviceExt->StorageDevice, &RecognizedFS,
			      &FatInfo, TRUE);
    if (!NT_SUCCESS(Status)) {
	goto err;
    }

    if (!RecognizedFS || RtlCompareMemory(&FatInfo, &DeviceExt->FatInfo,
					  sizeof(FATINFO)) != sizeof(FATINFO)) {
	return STATUS_WRONG_VOLUME;
    }

    WCHAR BufferU[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
    UNICODE_STRING VolumeLabelU;
    UNICODE_STRING VpbLabelU;
    VolumeLabelU.Buffer = BufferU;
    VolumeLabelU.Length = 0;
    VolumeLabelU.MaximumLength = sizeof(BufferU);
    Status = ReadVolumeLabel(DeviceExt->StorageDevice,
			     FatInfo.RootStart * FatInfo.BytesPerSector,
			     FatInfo.FatType >= FATX16,
			     FatInfo.BytesPerCluster, &VolumeLabelU);
    if (!NT_SUCCESS(Status)) {
	goto err;
    }

    VpbLabelU.Buffer = Vpb->VolumeLabel;
    VpbLabelU.Length = Vpb->VolumeLabelLength;
    VpbLabelU.MaximumLength = sizeof(Vpb->VolumeLabel);
    if (RtlCompareUnicodeString(&VpbLabelU, &VolumeLabelU, FALSE) != 0) {
	return STATUS_WRONG_VOLUME;
    }
    DPRINT1("Same volume\n");
    return STATUS_SUCCESS;

err:
    if (AllowRaw) {
	Status = STATUS_WRONG_VOLUME;
    }
    return Status;
}


static NTSTATUS FatGetVolumeBitmap(PFAT_IRP_CONTEXT IrpContext)
{
    DPRINT("FatGetVolumeBitmap (IrpContext %p)\n", IrpContext);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS FatGetRetrievalPointers(PFAT_IRP_CONTEXT IrpContext)
{
    DPRINT("FatGetRetrievalPointers(IrpContext %p)\n", IrpContext);

    PDEVICE_EXTENSION DeviceExt = IrpContext->DeviceExt;
    PFILE_OBJECT FileObject = IrpContext->FileObject;
    PIO_STACK_LOCATION Stack = IrpContext->Stack;
    ULONG InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    PSTARTING_VCN_INPUT_BUFFER VcnBuffer = Stack->Parameters.DeviceIoControl.Type3InputBuffer;
    ULONG OutputBufferLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PRETRIEVAL_POINTERS_BUFFER RetrPtrs = IrpContext->Irp->UserBuffer;

    if (!VcnBuffer || InputBufferLength < sizeof(STARTING_VCN_INPUT_BUFFER)) {
	return STATUS_INVALID_PARAMETER;
    }
    if (!RetrPtrs || OutputBufferLength < sizeof(RETRIEVAL_POINTERS_BUFFER)) {
	return STATUS_BUFFER_TOO_SMALL;
    }

    PFATFCB Fcb = FileObject->FsContext;
    LARGE_INTEGER Vcn = VcnBuffer->StartingVcn;

    ULONG MaxExtentCount = (OutputBufferLength - sizeof(RETRIEVAL_POINTERS_BUFFER)) /
			    sizeof(RetrPtrs->Extents[0]);

    ULONG ClusterSize = DeviceExt->FatInfo.BytesPerCluster;
    if (Vcn.QuadPart >= Fcb->Base.FileSizes.AllocationSize.QuadPart / ClusterSize) {
	return STATUS_INVALID_PARAMETER;
    }

    ULONG FirstCluster = FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry);
    ULONG CurrentCluster = FirstCluster;
    NTSTATUS Status = OffsetToCluster(DeviceExt, FirstCluster, Vcn.LowPart * ClusterSize,
				      &CurrentCluster, FALSE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    RetrPtrs->StartingVcn = Vcn;
    RetrPtrs->ExtentCount = 0;
    RetrPtrs->Extents[0].Lcn.HighPart = 0;
    RetrPtrs->Extents[0].Lcn.LowPart = CurrentCluster-2;

    ULONG LastCluster = 0;
    while (CurrentCluster != 0xffffffff && RetrPtrs->ExtentCount < MaxExtentCount) {
	LastCluster = CurrentCluster;
	Status = NextCluster(DeviceExt, CurrentCluster, &CurrentCluster, FALSE);
	Vcn.QuadPart++;
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}

	if (LastCluster + 1 != CurrentCluster) {
	    RetrPtrs->Extents[RetrPtrs->ExtentCount].NextVcn = Vcn;
	    RetrPtrs->ExtentCount++;
	    if (RetrPtrs->ExtentCount < MaxExtentCount) {
		RetrPtrs->Extents[RetrPtrs->ExtentCount].Lcn.HighPart = 0;
		RetrPtrs->Extents[RetrPtrs->ExtentCount].Lcn.LowPart = CurrentCluster-2;
	    }
	}
    }

    IrpContext->Irp->IoStatus.Information = sizeof(RETRIEVAL_POINTERS_BUFFER) +
	sizeof(RetrPtrs->Extents[0]) * RetrPtrs->ExtentCount;
    return STATUS_SUCCESS;
}

static NTSTATUS FatMoveFile(PFAT_IRP_CONTEXT IrpContext)
{
    DPRINT("FatMoveFile(IrpContext %p)\n", IrpContext);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS FatIsVolumeDirty(PFAT_IRP_CONTEXT IrpContext)
{
    PULONG Flags;

    DPRINT("FatIsVolumeDirty(IrpContext %p)\n", IrpContext);

    if (IrpContext->Stack->Parameters.FileSystemControl.OutputBufferLength != sizeof(ULONG))
	return STATUS_INVALID_BUFFER_SIZE;
    else if (!IrpContext->Irp->SystemBuffer)
	return STATUS_INVALID_USER_BUFFER;

    Flags = (PULONG)IrpContext->Irp->SystemBuffer;
    *Flags = 0;

    if (BooleanFlagOn(IrpContext->DeviceExt->VolumeFcb->Flags, VCB_IS_DIRTY)
	&& !BooleanFlagOn(IrpContext->DeviceExt->VolumeFcb->Flags, VCB_CLEAR_DIRTY)) {
	*Flags |= VOLUME_IS_DIRTY;
    }

    IrpContext->Irp->IoStatus.Information = sizeof(ULONG);

    return STATUS_SUCCESS;
}

static NTSTATUS FatMarkVolumeDirty(PFAT_IRP_CONTEXT IrpContext)
{
    PDEVICE_EXTENSION DeviceExt;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("FatMarkVolumeDirty(IrpContext %p)\n", IrpContext);
    DeviceExt = IrpContext->DeviceExt;

    if (!BooleanFlagOn(DeviceExt->VolumeFcb->Flags, VCB_IS_DIRTY)) {
	Status = SetDirtyStatus(DeviceExt, TRUE);
    }

    DeviceExt->VolumeFcb->Flags &= ~VCB_CLEAR_DIRTY;

    return Status;
}

static NTSTATUS FatLockOrUnlockVolume(PFAT_IRP_CONTEXT IrpContext,
				      BOOLEAN Lock)
{
    PFILE_OBJECT FileObject;
    PDEVICE_EXTENSION DeviceExt;
    PFATFCB Fcb;
    PVPB Vpb;

    DPRINT("FatLockOrUnlockVolume(%p, %d)\n", IrpContext, Lock);

    DeviceExt = IrpContext->DeviceExt;
    FileObject = IrpContext->FileObject;
    Fcb = FileObject->FsContext;
    Vpb = DeviceExt->FatFileObject->Vpb;

    /* Only allow locking with the volume open */
    if (!BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME)) {
	return STATUS_ACCESS_DENIED;
    }

    /* Bail out if it's already in the demanded state */
    if ((BooleanFlagOn(DeviceExt->Flags, VCB_VOLUME_LOCKED) && Lock) ||
	(!BooleanFlagOn(DeviceExt->Flags, VCB_VOLUME_LOCKED) && !Lock)) {
	return STATUS_ACCESS_DENIED;
    }

    /* Bail out if it's already in the demanded state */
    if ((BooleanFlagOn(Vpb->Flags, VPB_LOCKED) && Lock) ||
	(!BooleanFlagOn(Vpb->Flags, VPB_LOCKED) && !Lock)) {
	return STATUS_ACCESS_DENIED;
    }

    if (Lock) {
	FsRtlNotifyVolumeEvent(IrpContext->Stack->FileObject, FSRTL_VOLUME_LOCK);
    }

    /* Deny locking if we're not alone */
    if (Lock && DeviceExt->OpenHandleCount != 1) {
	PLIST_ENTRY ListEntry;

#if 1
	/* FIXME: Hack that allows locking the system volume on
	 * boot so that autochk can run properly
	 * That hack is, on purpose, really restrictive
	 * it will only allow locking with two directories
	 * open: current directory of smss and autochk.
	 */
	BOOLEAN ForceLock = TRUE;
	ULONG HandleCount = 0;

	/* Only allow boot volume */
	if (BooleanFlagOn(DeviceExt->Flags, VCB_IS_SYS_OR_HAS_PAGE)) {
	    /* We'll browse all the FCB */
	    ListEntry = DeviceExt->FcbListHead.Flink;
	    while (ListEntry != &DeviceExt->FcbListHead) {
		Fcb = CONTAINING_RECORD(ListEntry, FATFCB, FcbListEntry);
		ListEntry = ListEntry->Flink;

		/* If no handle: that FCB is no problem for locking
		 * so ignore it
		 */
		if (Fcb->OpenHandleCount == 0) {
		    continue;
		}

		/* Not a dir? We're no longer at boot */
		if (!FatFcbIsDirectory(Fcb)) {
		    ForceLock = FALSE;
		    break;
		}

		/* If we have cached initialized and several handles, we're
		   not in the boot case
		*/
		if (Fcb->FileObject != NULL && Fcb->OpenHandleCount > 1) {
		    ForceLock = FALSE;
		    break;
		}

		/* Count the handles */
		HandleCount += Fcb->OpenHandleCount;
		/* More than two handles? Then, we're not booting anymore */
		if (HandleCount > 2) {
		    ForceLock = FALSE;
		    break;
		}
	    }
	} else {
	    ForceLock = FALSE;
	}

	/* Here comes the hack, ignore the failure! */
	if (!ForceLock) {
#endif

	    DPRINT1("Can't lock: %u opened\n", DeviceExt->OpenHandleCount);

	    ListEntry = DeviceExt->FcbListHead.Flink;
	    while (ListEntry != &DeviceExt->FcbListHead) {
		Fcb = CONTAINING_RECORD(ListEntry, FATFCB, FcbListEntry);
		ListEntry = ListEntry->Flink;

		if (Fcb->OpenHandleCount > 0) {
		    DPRINT1("Opened (%u - %u): %wZ\n",
			    Fcb->OpenHandleCount, Fcb->RefCount,
			    &Fcb->PathNameU);
		}
	    }

	    FsRtlNotifyVolumeEvent(IrpContext->Stack->FileObject,
				   FSRTL_VOLUME_LOCK_FAILED);

	    return STATUS_ACCESS_DENIED;

#if 1
	    /* End of the hack: be verbose about its usage,
	     * just in case we would mess up everything!
	     */
	} else {
	    DPRINT1("HACK: Using lock-hack!\n");
	}
#endif
    }

    /* Finally, proceed */
    if (Lock) {
	/* Flush volume & files */
	FatFlushVolume(DeviceExt, DeviceExt->VolumeFcb);

	/* The volume is now clean */
	if (BooleanFlagOn(DeviceExt->VolumeFcb->Flags, VCB_CLEAR_DIRTY) &&
	    BooleanFlagOn(DeviceExt->VolumeFcb->Flags, VCB_IS_DIRTY)) {
	    /* Drop the dirty bit */
	    if (NT_SUCCESS(SetDirtyStatus(DeviceExt, FALSE)))
		ClearFlag(DeviceExt->VolumeFcb->Flags, VCB_IS_DIRTY);
	}

	DeviceExt->Flags |= VCB_VOLUME_LOCKED;
	Vpb->Flags |= VPB_LOCKED;
    } else {
	DeviceExt->Flags &= ~VCB_VOLUME_LOCKED;
	Vpb->Flags &= ~VPB_LOCKED;

	FsRtlNotifyVolumeEvent(IrpContext->Stack->FileObject,
			       FSRTL_VOLUME_UNLOCK);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS FatDismountVolume(PFAT_IRP_CONTEXT IrpContext)
{
    PDEVICE_EXTENSION DeviceExt;
    PLIST_ENTRY NextEntry;
    PFATFCB Fcb;
    PFILE_OBJECT FileObject;

    DPRINT("FatDismountVolume(%p)\n", IrpContext);

    DeviceExt = IrpContext->DeviceExt;
    FileObject = IrpContext->FileObject;

    /* We HAVE to be locked. Windows also allows dismount with no lock
     * but we're here mainly for 1st stage, so KISS. */
    if (!BooleanFlagOn(DeviceExt->Flags, VCB_VOLUME_LOCKED)) {
	return STATUS_ACCESS_DENIED;
    }

    /* Deny dismount of boot volume */
    if (BooleanFlagOn(DeviceExt->Flags, VCB_IS_SYS_OR_HAS_PAGE)) {
	return STATUS_ACCESS_DENIED;
    }

    /* Race condition? */
    if (BooleanFlagOn(DeviceExt->Flags, VCB_DISMOUNT_PENDING)) {
	return STATUS_VOLUME_DISMOUNTED;
    }

    /* Notify we'll dismount. Pass that point there's no reason we fail */
    FsRtlNotifyVolumeEvent(IrpContext->Stack->FileObject,
			   FSRTL_VOLUME_DISMOUNT);

    /* Flush volume & files */
    FatFlushVolume(DeviceExt, (PFATFCB)FileObject->FsContext);
    IO_STATUS_BLOCK IoStatus;
    /* If cache flushing failed, there isn't a lot we can do. */
    CcFlushCache(FileObject, NULL, 0, &IoStatus);
    if (!NT_SUCCESS(IoStatus.Status)) {
	DPRINT("CcFlushCache failed with error 0x%08x\n", IoStatus.Status);
    }

    /* The volume is now clean */
    if (BooleanFlagOn(DeviceExt->VolumeFcb->Flags, VCB_CLEAR_DIRTY) &&
	BooleanFlagOn(DeviceExt->VolumeFcb->Flags, VCB_IS_DIRTY)) {
	/* Drop the dirty bit */
	if (NT_SUCCESS(SetDirtyStatus(DeviceExt, FALSE)))
	    DeviceExt->VolumeFcb->Flags &= ~VCB_IS_DIRTY;
    }

    /* Rebrowse the FCB in order to free them now */
    while (!IsListEmpty(&DeviceExt->FcbListHead)) {
	NextEntry = RemoveTailList(&DeviceExt->FcbListHead);
	Fcb = CONTAINING_RECORD(NextEntry, FATFCB, FcbListEntry);

	if (Fcb == DeviceExt->RootFcb)
	    DeviceExt->RootFcb = NULL;
	else if (Fcb == DeviceExt->VolumeFcb)
	    DeviceExt->VolumeFcb = NULL;

	FatDestroyFcb(Fcb);
    }

    /* We are uninitializing, the VCB cannot be used anymore */
    ClearFlag(DeviceExt->Flags, VCB_GOOD);

    /* Mark we're being dismounted */
    DeviceExt->Flags |= VCB_DISMOUNT_PENDING;
    IrpContext->DeviceObject->Vpb->Flags &= ~VPB_MOUNTED;

    return STATUS_SUCCESS;
}

static NTSTATUS FatGetStatistics(PFAT_IRP_CONTEXT IrpContext)
{
    PVOID Buffer;
    ULONG Length;
    NTSTATUS Status;
    PDEVICE_EXTENSION DeviceExt;

    DeviceExt = IrpContext->DeviceExt;
    Length = IrpContext->Stack->Parameters.FileSystemControl.OutputBufferLength;
    Buffer = IrpContext->Irp->SystemBuffer;

    if (Length < sizeof(FILESYSTEM_STATISTICS)) {
	return STATUS_BUFFER_TOO_SMALL;
    }

    if (Buffer == NULL) {
	return STATUS_INVALID_USER_BUFFER;
    }

    if (Length >= sizeof(STATISTICS) * FatGlobalData->NumberProcessors) {
	Length = sizeof(STATISTICS) * FatGlobalData->NumberProcessors;
	Status = STATUS_SUCCESS;
    } else {
	Status = STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(Buffer, DeviceExt->Statistics, Length);
    IrpContext->Irp->IoStatus.Information = Length;

    return Status;
}

/*
 * FUNCTION: File system control
 */
NTSTATUS FatFileSystemControl(PFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status;

    DPRINT("FatFileSystemControl(IrpContext %p)\n", IrpContext);

    ASSERT(IrpContext);
    ASSERT(IrpContext->Irp);
    ASSERT(IrpContext->Stack);

    IrpContext->Irp->IoStatus.Information = 0;

    switch (IrpContext->MinorFunction) {
    case IRP_MN_KERNEL_CALL:
    case IRP_MN_USER_FS_REQUEST:
	switch (IrpContext->Stack->Parameters.DeviceIoControl.IoControlCode) {
	case FSCTL_GET_VOLUME_BITMAP:
	    Status = FatGetVolumeBitmap(IrpContext);
	    break;

	case FSCTL_GET_RETRIEVAL_POINTERS:
	    Status = FatGetRetrievalPointers(IrpContext);
	    break;

	case FSCTL_MOVE_FILE:
	    Status = FatMoveFile(IrpContext);
	    break;

	case FSCTL_IS_VOLUME_DIRTY:
	    Status = FatIsVolumeDirty(IrpContext);
	    break;

	case FSCTL_MARK_VOLUME_DIRTY:
	    Status = FatMarkVolumeDirty(IrpContext);
	    break;

	case FSCTL_LOCK_VOLUME:
	    Status = FatLockOrUnlockVolume(IrpContext, TRUE);
	    break;

	case FSCTL_UNLOCK_VOLUME:
	    Status = FatLockOrUnlockVolume(IrpContext, FALSE);
	    break;

	case FSCTL_DISMOUNT_VOLUME:
	    Status = FatDismountVolume(IrpContext);
	    break;

	case FSCTL_FILESYSTEM_GET_STATISTICS:
	    Status = FatGetStatistics(IrpContext);
	    break;

	default:
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	}
	break;

    case IRP_MN_MOUNT_VOLUME:
	Status = FatMount(IrpContext);
	break;

    case IRP_MN_VERIFY_VOLUME:
	DPRINT("FATFS: IRP_MN_VERIFY_VOLUME\n");
	Status = FatVerify(IrpContext);
	break;

    default:
	DPRINT("FAT FSC: MinorFunction %u\n", IrpContext->MinorFunction);
	Status = STATUS_INVALID_DEVICE_REQUEST;
	break;
    }

    return Status;
}
