/*
* PROJECT:         ReactOS Kernel
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            ntoskrnl/fstub/disksup.c
* PURPOSE:         I/O HAL Routines for Disk Access
* PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
*                  Eric Kohl
*                  Casper S. Hornstrup (chorns@users.sourceforge.net)
*                  Pierre Schweitzer
*/

#include <wchar.h>
#include <halp.h>
#include <ntdddisk.h>
#include <ntddstor.h>
#include <mountmgr.h>

const WCHAR DiskMountString[] = L"\\DosDevices\\%C:";

#define AUTO_DRIVE MAXULONG

#define PARTITION_MAGIC 0xaa55

#define EFI_PMBR_OSTYPE_EFI 0xEE

#include <pshpack1.h>
typedef struct _REG_DISK_MOUNT_INFO {
    ULONG Signature;
    LARGE_INTEGER StartingOffset;
} REG_DISK_MOUNT_INFO, *PREG_DISK_MOUNT_INFO;
#include <poppack.h>

typedef enum _DISK_MANAGER { NoDiskManager, OntrackDiskManager, EZ_Drive } DISK_MANAGER;

typedef enum _PARTITION_TYPE {
    BootablePartition,
    PrimaryPartition,
    LogicalPartition,
    FtPartition,
    UnknownPartition,
    DataPartition
} PARTITION_TYPE, *PPARTITION_TYPE;

/* PRIVATE FUNCTIONS *********************************************************/

static NTSTATUS HalpGetFullGeometry(IN PDEVICE_OBJECT DeviceObject,
				    OUT PDISK_GEOMETRY_EX Geometry)
{
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;
    PKEVENT Event;
    NTSTATUS Status;

    PAGED_CODE();

    /* Allocate a non-paged event */
    Event = ExAllocatePoolWithTag(sizeof(KEVENT), TAG_FILE_SYSTEM);
    if (!Event)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Initialize it */
    KeInitializeEvent(Event, SynchronizationEvent, FALSE);

    /* Build the IRP */
    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, DeviceObject,
					NULL, 0UL, Geometry, sizeof(DISK_GEOMETRY_EX),
					FALSE, Event, &IoStatusBlock);
    if (!Irp) {
	/* Fail, free the event */
	ExFreePoolWithTag(Event, TAG_FILE_SYSTEM);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Call the driver and check if it's pending */
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
	/* Wait on the driver */
	KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
	Status = IoStatusBlock.Status;
    }

    /* Free the event and return the Status */
    ExFreePoolWithTag(Event, TAG_FILE_SYSTEM);
    return Status;
}

static BOOLEAN HalpIsValidPartitionEntry(IN PPARTITION_DESCRIPTOR Entry,
					 IN ULONGLONG MaxOffset,
					 IN ULONGLONG MaxSector)
{
    ULONGLONG EndingSector;
    PAGED_CODE();

    /* Unused partitions are considered valid */
    if (Entry->PartitionType == PARTITION_ENTRY_UNUSED)
	return TRUE;

    /* Get the last sector of the partition */
    EndingSector = GET_STARTING_SECTOR(Entry) + GET_PARTITION_LENGTH(Entry);

    /* Check if it's more then the maximum sector */
    if (EndingSector > MaxSector) {
	/* Invalid partition */
	DPRINT1("FSTUB: entry is invalid\n");
	DPRINT1("FSTUB: offset %#08x\n", GET_STARTING_SECTOR(Entry));
	DPRINT1("FSTUB: length %#08x\n", GET_PARTITION_LENGTH(Entry));
	DPRINT1("FSTUB: end %#I64x\n", EndingSector);
	DPRINT1("FSTUB: max %#I64x\n", MaxSector);
	return FALSE;
    } else if (GET_STARTING_SECTOR(Entry) > MaxOffset) {
	/* Invalid partition */
	DPRINT1("FSTUB: entry is invalid\n");
	DPRINT1("FSTUB: offset %#08x\n", GET_STARTING_SECTOR(Entry));
	DPRINT1("FSTUB: length %#08x\n", GET_PARTITION_LENGTH(Entry));
	DPRINT1("FSTUB: end %#I64x\n", EndingSector);
	DPRINT1("FSTUB: maxOffset %#I64x\n", MaxOffset);
	return FALSE;
    }

    /* It's fine, return success */
    return TRUE;
}

static VOID HalpCalculateChsValues(IN PLARGE_INTEGER PartitionOffset,
				   IN PLARGE_INTEGER PartitionLength,
				   IN CCHAR ShiftCount,
				   IN ULONG SectorsPerTrack,
				   IN ULONG NumberOfTracks,
				   IN ULONG ConventionalCylinders,
				   OUT PPARTITION_DESCRIPTOR PartitionDescriptor)
{
    LARGE_INTEGER FirstSector, SectorCount;
    ULONG LastSector, Remainder, SectorsPerCylinder;
    ULONG StartingCylinder, EndingCylinder;
    ULONG StartingTrack, EndingTrack;
    ULONG StartingSector, EndingSector;
    PAGED_CODE();

    /* Calculate the number of sectors for each cylinder */
    SectorsPerCylinder = SectorsPerTrack * NumberOfTracks;

    /* Calculate the first sector, and the sector count */
    FirstSector.QuadPart = PartitionOffset->QuadPart >> ShiftCount;
    SectorCount.QuadPart = PartitionLength->QuadPart >> ShiftCount;

    /* Now calculate the last sector */
    LastSector = FirstSector.LowPart + SectorCount.LowPart - 1;

    /* Calculate the first and last cylinders */
    StartingCylinder = FirstSector.LowPart / SectorsPerCylinder;
    EndingCylinder = LastSector / SectorsPerCylinder;

    /* Set the default number of cylinders */
    if (!ConventionalCylinders)
	ConventionalCylinders = 1024;

    /* Normalize the values */
    if (StartingCylinder >= ConventionalCylinders) {
	/* Set the maximum to 1023 */
	StartingCylinder = ConventionalCylinders - 1;
    }
    if (EndingCylinder >= ConventionalCylinders) {
	/* Set the maximum to 1023 */
	EndingCylinder = ConventionalCylinders - 1;
    }

    /* Calculate the starting head and sector that still remain */
    Remainder = FirstSector.LowPart % SectorsPerCylinder;
    StartingTrack = Remainder / SectorsPerTrack;
    StartingSector = Remainder % SectorsPerTrack;

    /* Calculate the ending head and sector that still remain */
    Remainder = LastSector % SectorsPerCylinder;
    EndingTrack = Remainder / SectorsPerTrack;
    EndingSector = Remainder % SectorsPerTrack;

    /* Set cylinder data for the MSB */
    PartitionDescriptor->StartingCylinderMsb = (UCHAR)StartingCylinder;
    PartitionDescriptor->EndingCylinderMsb = (UCHAR)EndingCylinder;

    /* Set the track data */
    PartitionDescriptor->StartingTrack = (UCHAR)StartingTrack;
    PartitionDescriptor->EndingTrack = (UCHAR)EndingTrack;

    /* Update cylinder data for the LSB */
    StartingCylinder = ((StartingSector + 1) & 0x3F) | ((StartingCylinder >> 2) & 0xC0);
    EndingCylinder = ((EndingSector + 1) & 0x3F) | ((EndingCylinder >> 2) & 0xC0);

    /* Set the cylinder data for the LSB */
    PartitionDescriptor->StartingCylinderLsb = (UCHAR)StartingCylinder;
    PartitionDescriptor->EndingCylinderLsb = (UCHAR)EndingCylinder;
}

static VOID HalpGetPartialGeometry(IN PDEVICE_OBJECT DeviceObject,
				   IN PULONG ConventionalCylinders,
				   IN PLONGLONG DiskSize)
{
    PDISK_GEOMETRY DiskGeometry = NULL;
    PIO_STATUS_BLOCK IoStatusBlock = NULL;
    PKEVENT Event = NULL;
    PIRP Irp;
    NTSTATUS Status;

    /* Set defaults */
    *ConventionalCylinders = 0;
    *DiskSize = 0;

    /* Allocate the structure in nonpaged pool */
    DiskGeometry = ExAllocatePoolWithTag(sizeof(DISK_GEOMETRY),
					 TAG_FILE_SYSTEM);
    if (!DiskGeometry)
	goto Cleanup;

    /* Allocate the status block in nonpaged pool */
    IoStatusBlock = ExAllocatePoolWithTag(sizeof(IO_STATUS_BLOCK),
					  TAG_FILE_SYSTEM);
    if (!IoStatusBlock)
	goto Cleanup;

    /* Allocate the event in nonpaged pool too */
    Event = ExAllocatePoolWithTag(sizeof(KEVENT), TAG_FILE_SYSTEM);
    if (!Event)
	goto Cleanup;

    /* Initialize the event */
    KeInitializeEvent(Event, SynchronizationEvent, FALSE);

    /* Build the IRP */
    Irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_GET_DRIVE_GEOMETRY, DeviceObject, NULL,
					0, DiskGeometry, sizeof(DISK_GEOMETRY), FALSE,
					Event, IoStatusBlock);
    if (!Irp)
	goto Cleanup;

    /* Now call the driver */
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
	/* Wait for it to complete */
	KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, NULL);
	Status = IoStatusBlock->Status;
    }

    /* Check driver status */
    if (NT_SUCCESS(Status)) {
	/* Return the cylinder count */
	*ConventionalCylinders = DiskGeometry->Cylinders.LowPart;

	/* Make sure it's not larger then 1024 */
	if (DiskGeometry->Cylinders.LowPart >= 1024) {
	    /* Otherwise, normalize the value */
	    *ConventionalCylinders = 1024;
	}

	/* Calculate the disk size */
	*DiskSize = DiskGeometry->Cylinders.QuadPart * DiskGeometry->TracksPerCylinder *
		    DiskGeometry->SectorsPerTrack * DiskGeometry->BytesPerSector;
    }

Cleanup:
    /* Free all the pointers */
    if (Event)
	ExFreePoolWithTag(Event, TAG_FILE_SYSTEM);
    if (IoStatusBlock)
	ExFreePoolWithTag(IoStatusBlock, TAG_FILE_SYSTEM);
    if (DiskGeometry)
	ExFreePoolWithTag(DiskGeometry, TAG_FILE_SYSTEM);
    return;
}

NTAPI VOID HalExamineMBR(IN PDEVICE_OBJECT DeviceObject,
			 IN ULONG SectorSize,
			 IN ULONG MbrTypeIdentifier,
			 OUT PVOID *MbrBuffer)
{
    LARGE_INTEGER Offset;
    PUCHAR Buffer;
    ULONG BufferSize;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatusBlock;
    PIRP Irp;
    PPARTITION_DESCRIPTOR PartitionDescriptor;
    NTSTATUS Status;
    PIO_STACK_LOCATION IoStackLocation;

    Offset.QuadPart = 0;

    /* Assume failure */
    *MbrBuffer = NULL;

    /* Normalize the buffer size */
    BufferSize = max(512, SectorSize);

    /* Allocate the buffer */
    Buffer = ExAllocatePoolWithTag(max(PAGE_SIZE, BufferSize),
				   TAG_FILE_SYSTEM);
    if (!Buffer)
	return;

    /* Initialize the Event */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* Build the IRP */
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer, BufferSize,
				       &Offset, &Event, &IoStatusBlock);
    if (!Irp) {
	/* Failed */
	ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
	return;
    }

    /* Make sure to override volume verification */
    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

    /* Call the driver */
    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
	/* Wait for completion */
	KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	Status = IoStatusBlock.Status;
    }

    /* Check driver Status */
    if (NT_SUCCESS(Status)) {
	/* Validate the MBR Signature */
	if (*(PUSHORT)&Buffer[BOOT_SIGNATURE_OFFSET] != BOOT_RECORD_SIGNATURE) {
	    /* Failed */
	    ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
	    return;
	}

	/* Get the partition entry */
	PartitionDescriptor = (PPARTITION_DESCRIPTOR)&Buffer[PARTITION_TABLE_OFFSET];

	/* Make sure it's what the caller wanted */
	if (PartitionDescriptor->PartitionType != MbrTypeIdentifier) {
	    /* It's not, free our buffer */
	    ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
	} else {
	    /* Check for OnTrack Disk Manager 6.0 / EZ-Drive partitions */

	    if (PartitionDescriptor->PartitionType == PARTITION_DM) {
		/* Return our buffer, but at sector 63 */
		*(PULONG)Buffer = 63;
		*MbrBuffer = Buffer;
	    } else if (PartitionDescriptor->PartitionType == PARTITION_EZDRIVE) {
		/* EZ-Drive, return the buffer directly */
		*MbrBuffer = Buffer;
	    } else {
		/* Otherwise crash on debug builds */
		ASSERT(PartitionDescriptor->PartitionType == PARTITION_EZDRIVE);
	    }
	}
    }
}

static VOID FstubFixupEfiPartition(IN PPARTITION_DESCRIPTOR PartitionDescriptor,
				   IN ULONGLONG MaxOffset)
{
    ULONG PartitionMaxOffset, PartitionLength;
    PAGED_CODE();

    /* Compute partition length (according to MBR entry) */
    PartitionMaxOffset = GET_STARTING_SECTOR(PartitionDescriptor) +
			 GET_PARTITION_LENGTH(PartitionDescriptor);
    /* In case the partition length goes beyond disk size... */
    if (PartitionMaxOffset > MaxOffset) {
	/* Resize partition to its maximum real length */
	PartitionLength = (ULONG)(PartitionMaxOffset -
				  GET_STARTING_SECTOR(PartitionDescriptor));
	SET_PARTITION_LENGTH(PartitionDescriptor, PartitionLength);
    }
}

NTAPI NTSTATUS IoReadPartitionTable(IN PDEVICE_OBJECT DeviceObject,
				    IN ULONG SectorSize,
				    IN BOOLEAN ReturnRecognizedPartitions,
				    IN OUT PDRIVE_LAYOUT_INFORMATION *PartitionBuffer)
{
    KEVENT Event;
    IO_STATUS_BLOCK IoStatusBlock;
    PIRP Irp;
    PPARTITION_DESCRIPTOR PartitionDescriptor;
    CCHAR Entry;
    NTSTATUS Status;
    PPARTITION_INFORMATION PartitionInfo;
    PUCHAR Buffer = NULL;
    ULONG BufferSize = 2048, InputSize;
    PDRIVE_LAYOUT_INFORMATION DriveLayoutInfo = NULL;
    LONG j = -1, i = -1, k;
    DISK_GEOMETRY_EX DiskGeometryEx;
    LONGLONG EndSector, MaxSector, StartOffset;
    LARGE_INTEGER Offset, VolumeOffset;
    BOOLEAN IsPrimary = TRUE, IsEzDrive = FALSE, MbrFound = FALSE;
    BOOLEAN IsValid, IsEmpty = TRUE;
    PVOID MbrBuffer;
    PIO_STACK_LOCATION IoStackLocation;
    UCHAR PartitionType;
    LARGE_INTEGER HiddenSectors64;

    PAGED_CODE();

    VolumeOffset.QuadPart = Offset.QuadPart = 0;

    /* Allocate the buffer */
    *PartitionBuffer = ExAllocatePoolWithTag(BufferSize, TAG_FILE_SYSTEM);
    if (!(*PartitionBuffer))
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Normalize the buffer size */
    InputSize = max(512, SectorSize);

    /* Check for EZ-Drive */
    HalExamineMBR(DeviceObject, InputSize, PARTITION_EZDRIVE, &MbrBuffer);
    if (MbrBuffer) {
	/* EZ-Drive found, bias the offset */
	IsEzDrive = TRUE;
	ExFreePoolWithTag(MbrBuffer, TAG_FILE_SYSTEM);
	Offset.QuadPart = 512;
    }

    /* Get drive geometry */
    Status = HalpGetFullGeometry(DeviceObject, &DiskGeometryEx);
    if (!NT_SUCCESS(Status)) {
	ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
	*PartitionBuffer = NULL;
	return Status;
    }

    /* Get the end and maximum sector */
    EndSector = DiskGeometryEx.DiskSize.QuadPart / DiskGeometryEx.Geometry.BytesPerSector;
    MaxSector = EndSector << 1;
    DPRINT("FSTUB: DiskSize = %#I64x, MaxSector = %#I64x\n",
	   DiskGeometryEx.DiskSize.QuadPart, MaxSector);

    /* Allocate our buffer */
    Buffer = ExAllocatePoolWithTag(InputSize, TAG_FILE_SYSTEM);
    if (!Buffer) {
	/* Fail, free the input buffer */
	ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
	*PartitionBuffer = NULL;
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Start partition loop */
    do {
	/* Assume the partition is valid */
	IsValid = TRUE;

	/* Initialize the event */
	KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	/* Clear the buffer and build the IRP */
	RtlZeroMemory(Buffer, InputSize);
	Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer, InputSize,
					   &Offset, &Event, &IoStatusBlock);
	if (!Irp) {
	    /* Failed */
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	/* Make sure to disable volume verification */
	IoStackLocation = IoGetNextIrpStackLocation(Irp);
	IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

	/* Call the driver */
	Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING) {
	    /* Wait for completion */
	    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	    Status = IoStatusBlock.Status;
	}

	/* Normalize status code and check for failure */
	if (Status == STATUS_NO_DATA_DETECTED)
	    Status = STATUS_SUCCESS;
	if (!NT_SUCCESS(Status))
	    break;

	/* If we biased for EZ-Drive, unbias now */
	if (IsEzDrive && (Offset.QuadPart == 512))
	    Offset.QuadPart = 0;

	/* Make sure this is a valid MBR */
	if (*(PUSHORT)&Buffer[BOOT_SIGNATURE_OFFSET] != BOOT_RECORD_SIGNATURE) {
	    /* It's not, fail */
	    DPRINT1("FSTUB: (IoReadPartitionTable) No 0xaa55 found in "
		    "partition table %d\n",
		    j + 1);
	    break;
	}

	/* At this point we have a valid MBR */
	MbrFound = TRUE;

	/* Check if we weren't given an offset */
	if (!Offset.QuadPart) {
	    /* Then read the signature off the disk */
	    (*PartitionBuffer)->Signature = *(PULONG)&Buffer[DISK_SIGNATURE_OFFSET];
	}

	/* Get the partition descriptor array */
	PartitionDescriptor = (PPARTITION_DESCRIPTOR)&Buffer[PARTITION_TABLE_OFFSET];

	/* Start looping partitions */
	j++;
	DPRINT("FSTUB: Partition Table %d:\n", j);
	for (Entry = 1, k = 0; Entry <= NUM_PARTITION_TABLE_ENTRIES;
	     Entry++, PartitionDescriptor++) {
	    /* Get the partition type */
	    PartitionType = PartitionDescriptor->PartitionType;

	    /* Print debug messages */
	    DPRINT("Partition Entry %d,%d: type %#x %s\n", j, Entry, PartitionType,
		   (PartitionDescriptor->ActiveFlag) ? "Active" : "");
	    DPRINT("\tOffset %#08x for %#08x Sectors\n",
		   GET_STARTING_SECTOR(PartitionDescriptor),
		   GET_PARTITION_LENGTH(PartitionDescriptor));

	    /* Check whether we're facing a protective MBR */
	    if (PartitionType == EFI_PMBR_OSTYPE_EFI) {
		/* Partition length might be bigger than disk size */
		FstubFixupEfiPartition(PartitionDescriptor,
				       DiskGeometryEx.DiskSize.QuadPart);
	    }

	    /* Make sure that the partition is valid, unless it's the first */
	    if (!(HalpIsValidPartitionEntry(PartitionDescriptor,
					    DiskGeometryEx.DiskSize.QuadPart,
					    MaxSector)) &&
		(j == 0)) {
		/* It's invalid, so fail */
		IsValid = FALSE;
		break;
	    }

	    /* Check if it's a container */
	    if (IsContainerPartition(PartitionType)) {
		/* Increase the count of containers */
		if (++k != 1) {
		    /* More then one table is invalid */
		    DPRINT1("FSTUB: Multiple container partitions found in "
			    "partition table %d\n - table is invalid\n",
			    j);
		    IsValid = FALSE;
		    break;
		}
	    }

	    /* Check if the partition is supposedly empty */
	    if (IsEmpty) {
		/* But check if it actually has a start and/or length */
		if ((GET_STARTING_SECTOR(PartitionDescriptor)) ||
		    (GET_PARTITION_LENGTH(PartitionDescriptor))) {
		    /* So then it's not really empty */
		    IsEmpty = FALSE;
		}
	    }

	    /* Check if the caller wanted only recognized partitions */
	    if (ReturnRecognizedPartitions) {
		/* Then check if this one is unused, or a container */
		if ((PartitionType == PARTITION_ENTRY_UNUSED) ||
		    IsContainerPartition(PartitionType)) {
		    /* Skip it, since the caller doesn't want it */
		    continue;
		}
	    }

	    /* Increase the structure count and check if they can fit */
	    if ((sizeof(DRIVE_LAYOUT_INFORMATION) +
		 (++i * sizeof(PARTITION_INFORMATION))) > BufferSize) {
		/* Allocate a new buffer that's twice as big */
		DriveLayoutInfo = ExAllocatePoolWithTag(BufferSize << 1,
							TAG_FILE_SYSTEM);
		if (!DriveLayoutInfo) {
		    /* Out of memory, undo this extra structure */
		    --i;
		    Status = STATUS_INSUFFICIENT_RESOURCES;
		    break;
		}

		/* Copy the contents of the old buffer */
		RtlMoveMemory(DriveLayoutInfo, *PartitionBuffer, BufferSize);

		/* Free the old buffer and set this one as the new one */
		ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
		*PartitionBuffer = DriveLayoutInfo;

		/* Double the size */
		BufferSize <<= 1;
	    }

	    /* Now get the current structure being filled and initialize it */
	    PartitionInfo = &(*PartitionBuffer)->PartitionEntry[i];
	    PartitionInfo->PartitionType = PartitionType;
	    PartitionInfo->RewritePartition = FALSE;

	    /* Check if we're dealing with a partition that's in use */
	    if (PartitionType != PARTITION_ENTRY_UNUSED) {
		/* Check if it's bootable */
		PartitionInfo->BootIndicator = PartitionDescriptor->ActiveFlag & 0x80 ?
						   TRUE :
						   FALSE;

		/* Check if its' a container */
		if (IsContainerPartition(PartitionType)) {
		    /* Then don't recognize it and use the volume offset */
		    PartitionInfo->RecognizedPartition = FALSE;
		    StartOffset = VolumeOffset.QuadPart;
		} else {
		    /* Then recognize it and use the partition offset */
		    PartitionInfo->RecognizedPartition = TRUE;
		    StartOffset = Offset.QuadPart;
		}

		/* Get the starting offset */
		PartitionInfo->StartingOffset.QuadPart =
		    StartOffset +
		    UInt32x32To64(GET_STARTING_SECTOR(PartitionDescriptor), SectorSize);

		/* Calculate the number of hidden sectors */
		HiddenSectors64.QuadPart = (PartitionInfo->StartingOffset.QuadPart -
					    StartOffset) /
					   SectorSize;
		PartitionInfo->HiddenSectors = HiddenSectors64.LowPart;

		/* Get the partition length */
		PartitionInfo->PartitionLength.QuadPart =
		    UInt32x32To64(GET_PARTITION_LENGTH(PartitionDescriptor), SectorSize);

		/* Get the partition number */
		/* FIXME: REACTOS HACK -- Needed for xHalIoAssignDriveLetters() */
		PartitionInfo->PartitionNumber = (!IsContainerPartition(PartitionType)) ?
						     i + 1 :
						     0;
	    } else {
		/* Otherwise, clear all the relevant fields */
		PartitionInfo->BootIndicator = FALSE;
		PartitionInfo->RecognizedPartition = FALSE;
		PartitionInfo->StartingOffset.QuadPart = 0;
		PartitionInfo->PartitionLength.QuadPart = 0;
		PartitionInfo->HiddenSectors = 0;

		/* FIXME: REACTOS HACK -- Needed for xHalIoAssignDriveLetters() */
		PartitionInfo->PartitionNumber = 0;
	    }
	}

	/* Finish debug log, and check for failure */
	DPRINT("\n");
	if (!NT_SUCCESS(Status))
	    break;

	/* Also check if we hit an invalid entry here */
	if (!IsValid) {
	    /* We did, so break out of the loop minus one entry */
	    j--;
	    break;
	}

	/* Reset the offset */
	Offset.QuadPart = 0;

	/* Go back to the descriptor array and loop it */
	PartitionDescriptor = (PPARTITION_DESCRIPTOR)&Buffer[PARTITION_TABLE_OFFSET];
	for (Entry = 1; Entry <= NUM_PARTITION_TABLE_ENTRIES;
	     Entry++, PartitionDescriptor++) {
	    /* Check if this is a container partition, since we skipped them */
	    if (IsContainerPartition(PartitionDescriptor->PartitionType)) {
		/* Get its offset */
		Offset.QuadPart = VolumeOffset.QuadPart +
				  UInt32x32To64(GET_STARTING_SECTOR(PartitionDescriptor),
						SectorSize);

		/* If this is a primary partition, this is the volume offset */
		if (IsPrimary)
		    VolumeOffset = Offset;

		/* Also update the maximum sector */
		MaxSector = GET_PARTITION_LENGTH(PartitionDescriptor);
		DPRINT1("FSTUB: MaxSector now = %lld\n", MaxSector);
		break;
	    }
	}

	/* Loop the next partitions, which are not primary anymore */
	IsPrimary = FALSE;
    } while (Offset.HighPart | Offset.LowPart);

    /* Check if this is a removable device that's probably a super-floppy */
    if ((DiskGeometryEx.Geometry.MediaType == RemovableMedia) && (j == 0) && (MbrFound) &&
	(IsEmpty)) {
	PBOOT_SECTOR_INFO BootSectorInfo = (PBOOT_SECTOR_INFO)Buffer;

	/* Read the jump bytes to detect super-floppy */
	if ((BootSectorInfo->JumpByte[0] == 0xeb) ||
	    (BootSectorInfo->JumpByte[0] == 0xe9)) {
	    /* Super floppes don't have typical MBRs, so skip them */
	    DPRINT1("FSTUB: Jump byte %x found along with empty partition "
		    "table - disk is a super floppy and has no valid MBR\n",
		    *BootSectorInfo->JumpByte);
	    j = -1;
	}
    }

    /* Check if we're still at partition -1 */
    if (j == -1) {
	/* The likely cause is the super floppy detection above */
	if ((MbrFound) || (DiskGeometryEx.Geometry.MediaType == RemovableMedia)) {
	    /* Print out debugging information */
	    DPRINT1("FSTUB: Drive %p has no valid MBR. Make it into a "
		    "super-floppy\n",
		    DeviceObject);
	    DPRINT1("FSTUB: Drive has %lld sectors and is %#016I64x "
		    "bytes large\n",
		    EndSector, DiskGeometryEx.DiskSize.QuadPart);

	    /* We should at least have some sectors */
	    if (EndSector > 0) {
		/* Get the entry we'll use */
		PartitionInfo = &(*PartitionBuffer)->PartitionEntry[0];

		/* Fill it out with data for a super-floppy */
		PartitionInfo->RewritePartition = FALSE;
		PartitionInfo->RecognizedPartition = TRUE;
		PartitionInfo->PartitionType = PARTITION_FAT_16;
		PartitionInfo->BootIndicator = FALSE;
		PartitionInfo->HiddenSectors = 0;
		PartitionInfo->StartingOffset.QuadPart = 0;
		PartitionInfo->PartitionLength = DiskGeometryEx.DiskSize;

		/* FIXME: REACTOS HACK -- Needed for xHalIoAssignDriveLetters() */
		PartitionInfo->PartitionNumber = 0;

		/* Set the signature and set the count back to 0 */
		(*PartitionBuffer)->Signature = 1;
		i = 0;
	    }
	} else {
	    /* Otherwise, this isn't a super floppy, so set an invalid count */
	    i = -1;
	}
    }

    /* Set the partition count */
    (*PartitionBuffer)->PartitionCount = ++i;

    /* If we have no count, delete the signature */
    if (!i)
	(*PartitionBuffer)->Signature = 0;

    /* Free the buffer and check for success */
    if (Buffer)
	ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
    if (!NT_SUCCESS(Status)) {
	ExFreePoolWithTag(*PartitionBuffer, TAG_FILE_SYSTEM);
	*PartitionBuffer = NULL;
    }

    /* Return status */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS IoSetPartitionInformation(IN PDEVICE_OBJECT DeviceObject,
					 IN ULONG SectorSize,
					 IN ULONG PartitionNumber,
					 IN ULONG PartitionType)
{
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;
    LARGE_INTEGER Offset, VolumeOffset;
    PUCHAR Buffer = NULL;
    ULONG BufferSize;
    ULONG i = 0;
    ULONG Entry;
    PPARTITION_DESCRIPTOR PartitionDescriptor;
    BOOLEAN IsPrimary = TRUE, IsEzDrive = FALSE;
    PVOID MbrBuffer;
    PIO_STACK_LOCATION IoStackLocation;

    PAGED_CODE();

    VolumeOffset.QuadPart = Offset.QuadPart = 0;

    /* Normalize the buffer size */
    BufferSize = max(512, SectorSize);

    /* Check for EZ-Drive */
    HalExamineMBR(DeviceObject, BufferSize, PARTITION_EZDRIVE, &MbrBuffer);
    if (MbrBuffer) {
	/* EZ-Drive found, bias the offset */
	IsEzDrive = TRUE;
	ExFreePoolWithTag(MbrBuffer, TAG_FILE_SYSTEM);
	Offset.QuadPart = 512;
    }

    /* Allocate our partition buffer */
    Buffer = ExAllocatePoolWithTag(PAGE_SIZE, TAG_FILE_SYSTEM);
    if (!Buffer)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Initialize the event we'll use and loop partitions */
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    do {
	/* Reset the event since we reuse it */
	KeClearEvent(&Event);

	/* Build the read IRP */
	Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer, BufferSize,
					   &Offset, &Event, &IoStatusBlock);
	if (!Irp) {
	    /* Fail */
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	/* Make sure to disable volume verification */
	IoStackLocation = IoGetNextIrpStackLocation(Irp);
	IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

	/* Call the driver */
	Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING) {
	    /* Wait for completion */
	    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	    Status = IoStatusBlock.Status;
	}

	/* Check for failure */
	if (!NT_SUCCESS(Status))
	    break;

	/* If we biased for EZ-Drive, unbias now */
	if (IsEzDrive && (Offset.QuadPart == 512))
	    Offset.QuadPart = 0;

	/* Make sure this is a valid MBR */
	if (*(PUSHORT)&Buffer[BOOT_SIGNATURE_OFFSET] != BOOT_RECORD_SIGNATURE) {
	    /* It's not, fail */
	    Status = STATUS_BAD_MASTER_BOOT_RECORD;
	    break;
	}

	/* Get the partition descriptors and loop them */
	PartitionDescriptor = (PPARTITION_DESCRIPTOR)&Buffer[PARTITION_TABLE_OFFSET];
	for (Entry = 1; Entry <= NUM_PARTITION_TABLE_ENTRIES;
	     Entry++, PartitionDescriptor++) {
	    /* Check if it's unused or a container partition */
	    if ((PartitionDescriptor->PartitionType == PARTITION_ENTRY_UNUSED) ||
		(IsContainerPartition(PartitionDescriptor->PartitionType))) {
		/* Go to the next one */
		continue;
	    }

	    /* It's a valid partition, so increase the partition count */
	    if (++i == PartitionNumber) {
		/* We found a match, set the type */
		PartitionDescriptor->PartitionType = (UCHAR)PartitionType;

		/* Reset the reusable event */
		KeClearEvent(&Event);

		/* Build the write IRP */
		Irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, DeviceObject, Buffer,
						   BufferSize, &Offset, &Event,
						   &IoStatusBlock);
		if (!Irp) {
		    /* Fail */
		    Status = STATUS_INSUFFICIENT_RESOURCES;
		    break;
		}

		/* Disable volume verification */
		IoStackLocation = IoGetNextIrpStackLocation(Irp);
		IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

		/* Call the driver */
		Status = IoCallDriver(DeviceObject, Irp);
		if (Status == STATUS_PENDING) {
		    /* Wait for completion */
		    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		    Status = IoStatusBlock.Status;
		}

		/* We're done, break out of the loop */
		break;
	    }
	}

	/* If we looped all the partitions, break out */
	if (Entry <= NUM_PARTITION_TABLE_ENTRIES)
	    break;

	/* Nothing found yet, get the partition array again */
	PartitionDescriptor = (PPARTITION_DESCRIPTOR)&Buffer[PARTITION_TABLE_OFFSET];
	for (Entry = 1; Entry <= NUM_PARTITION_TABLE_ENTRIES;
	     Entry++, PartitionDescriptor++) {
	    /* Check if this was a container partition (we skipped these) */
	    if (IsContainerPartition(PartitionDescriptor->PartitionType)) {
		/* Update the partition offset */
		Offset.QuadPart = VolumeOffset.QuadPart +
				  GET_STARTING_SECTOR(PartitionDescriptor) * SectorSize;

		/* If this was the primary partition, update the volume too */
		if (IsPrimary)
		    VolumeOffset = Offset;
		break;
	    }
	}

	/* Check if we already searched all the partitions */
	if (Entry > NUM_PARTITION_TABLE_ENTRIES) {
	    /* Then we failed to find a good MBR */
	    Status = STATUS_BAD_MASTER_BOOT_RECORD;
	    break;
	}

	/* Loop the next partitions, which are not primary anymore */
	IsPrimary = FALSE;
    } while (i < PartitionNumber);

    /* Everything done, cleanup */
    if (Buffer)
	ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
    return Status;
}


/*
 * @implemented
 */
NTAPI NTSTATUS IoWritePartitionTable(IN PDEVICE_OBJECT DeviceObject,
				     IN ULONG SectorSize,
				     IN ULONG SectorsPerTrack,
				     IN ULONG NumberOfHeads,
				     IN PDRIVE_LAYOUT_INFORMATION PartitionBuffer)
{
    KEVENT Event;
    IO_STATUS_BLOCK IoStatusBlock;
    PIRP Irp;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BufferSize;
    PUCHAR Buffer;
    PPTE Entry;
    PPARTITION_TABLE PartitionTable;
    LARGE_INTEGER Offset, NextOffset, ExtendedOffset, SectorOffset;
    LARGE_INTEGER StartOffset, PartitionLength;
    ULONG i, j;
    CCHAR k;
    BOOLEAN IsEzDrive = FALSE, IsSuperFloppy = FALSE, DoRewrite = FALSE, IsMbr;
    ULONG ConventionalCylinders;
    LONGLONG DiskSize;
    PDISK_LAYOUT DiskLayout = (PDISK_LAYOUT)PartitionBuffer;
    PVOID MbrBuffer;
    UCHAR PartitionType;
    PIO_STACK_LOCATION IoStackLocation;
    PPARTITION_INFORMATION PartitionInfo = PartitionBuffer->PartitionEntry;
    PPARTITION_INFORMATION TableEntry;

    PAGED_CODE();

    ExtendedOffset.QuadPart = NextOffset.QuadPart = Offset.QuadPart = 0;

    /* Normalize the buffer size */
    BufferSize = max(512, SectorSize);

    /* Get the partial drive geometry */
    HalpGetPartialGeometry(DeviceObject, &ConventionalCylinders, &DiskSize);

    /* Check for EZ-Drive */
    HalExamineMBR(DeviceObject, BufferSize, PARTITION_EZDRIVE, &MbrBuffer);
    if (MbrBuffer) {
	/* EZ-Drive found, bias the offset */
	IsEzDrive = TRUE;
	ExFreePoolWithTag(MbrBuffer, TAG_FILE_SYSTEM);
	Offset.QuadPart = 512;
    }

    /* Get the number of bits to shift to multiply by the sector size */
    for (k = 0; k < 32; k++)
	if ((SectorSize >> k) == 1)
	    break;

    /* Check if there's only one partition */
    if (PartitionBuffer->PartitionCount == 1) {
	/* Check if it has no starting offset or hidden sectors */
	if (!(PartitionInfo->StartingOffset.QuadPart) &&
	    !(PartitionInfo->HiddenSectors)) {
	    /* Then it's a super floppy */
	    IsSuperFloppy = TRUE;

	    /* Which also means it must be non-bootable FAT-16 */
	    if ((PartitionInfo->PartitionNumber) ||
		(PartitionInfo->PartitionType != PARTITION_FAT_16) ||
		(PartitionInfo->BootIndicator)) {
		/* It's not, so we fail */
		return STATUS_INVALID_PARAMETER;
	    }

	    /* Check if it needs a rewrite, and disable EZ-Drive for sure */
	    if (PartitionInfo->RewritePartition)
		DoRewrite = TRUE;
	    IsEzDrive = FALSE;
	}
    }

    /* Count the number of partition tables */
    DiskLayout->TableCount = (PartitionBuffer->PartitionCount +
			      NUM_PARTITION_TABLE_ENTRIES - 1) /
			     NUM_PARTITION_TABLE_ENTRIES;

    /* Allocate our partition buffer */
    Buffer = ExAllocatePoolWithTag(PAGE_SIZE, TAG_FILE_SYSTEM);
    if (!Buffer)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Loop the entries */
    Entry = (PPTE)&Buffer[PARTITION_TABLE_OFFSET];
    for (i = 0; i < DiskLayout->TableCount; i++) {
	/* Set if this is the MBR partition */
	IsMbr = (BOOLEAN)!i;

	/* Initialize th event */
	KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	/* Build the read IRP */
	Irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, DeviceObject, Buffer, BufferSize,
					   &Offset, &Event, &IoStatusBlock);
	if (!Irp) {
	    /* Fail */
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	/* Make sure to disable volume verification */
	IoStackLocation = IoGetNextIrpStackLocation(Irp);
	IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

	/* Call the driver */
	Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING) {
	    /* Wait for completion */
	    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	    Status = IoStatusBlock.Status;
	}

	/* Check for failure */
	if (!NT_SUCCESS(Status))
	    break;

	/* If we biased for EZ-Drive, unbias now */
	if (IsEzDrive && (Offset.QuadPart == 512))
	    Offset.QuadPart = 0;

	/* Check if this is a normal disk */
	if (!IsSuperFloppy) {
	    /* Set the boot record signature */
	    *(PUSHORT)&Buffer[BOOT_SIGNATURE_OFFSET] = BOOT_RECORD_SIGNATURE;

	    /* By default, don't require a rewrite */
	    DoRewrite = FALSE;

	    /* Check if we don't have an offset */
	    if (!Offset.QuadPart) {
		/* Check if the signature doesn't match */
		if (*(PULONG)&Buffer[DISK_SIGNATURE_OFFSET] !=
		    PartitionBuffer->Signature) {
		    /* Then write the signature and now we need a rewrite */
		    *(PULONG)&Buffer[DISK_SIGNATURE_OFFSET] = PartitionBuffer->Signature;
		    DoRewrite = TRUE;
		}
	    }

	    /* Loop the partition table entries */
	    PartitionTable = &DiskLayout->PartitionTable[i];
	    for (j = 0; j < NUM_PARTITION_TABLE_ENTRIES; j++) {
		/* Get the current entry and type */
		TableEntry = &PartitionTable->PartitionEntry[j];
		PartitionType = TableEntry->PartitionType;

		/* Check if the entry needs a rewrite */
		if (TableEntry->RewritePartition) {
		    /* Then we need one too */
		    DoRewrite = TRUE;

		    /* Save the type and if it's a bootable partition */
		    Entry[j].PartitionType = TableEntry->PartitionType;
		    Entry[j].ActiveFlag = TableEntry->BootIndicator ? 0x80 : 0;

		    /* Make sure it's used */
		    if (PartitionType != PARTITION_ENTRY_UNUSED) {
			/* Make sure it's not a container (unless primary) */
			if ((IsMbr) || !(IsContainerPartition(PartitionType))) {
			    /* Use the partition offset */
			    StartOffset.QuadPart = Offset.QuadPart;
			} else {
			    /* Use the extended logical partition offset */
			    StartOffset.QuadPart = ExtendedOffset.QuadPart;
			}

			/* Set the sector offset */
			SectorOffset.QuadPart = TableEntry->StartingOffset.QuadPart -
						StartOffset.QuadPart;

			/* Now calculate the starting sector */
			StartOffset.QuadPart = SectorOffset.QuadPart >> k;
			Entry[j].StartingSector = StartOffset.LowPart;

			/* As well as the length */
			PartitionLength.QuadPart = TableEntry->PartitionLength.QuadPart >>
						   k;
			Entry[j].PartitionLength = PartitionLength.LowPart;

			/* Calculate the CHS values */
			HalpCalculateChsValues(&TableEntry->StartingOffset,
					       &TableEntry->PartitionLength, k,
					       SectorsPerTrack, NumberOfHeads,
					       ConventionalCylinders,
					       (PPARTITION_DESCRIPTOR)&Entry[j]);
		    } else {
			/* Otherwise set up an empty entry */
			Entry[j].StartingSector = 0;
			Entry[j].PartitionLength = 0;
			Entry[j].StartingTrack = 0;
			Entry[j].EndingTrack = 0;
			Entry[j].StartingCylinder = 0;
			Entry[j].EndingCylinder = 0;
		    }
		}

		/* Check if this is a container partition */
		if (IsContainerPartition(PartitionType)) {
		    /* Then update the offset to use */
		    NextOffset = TableEntry->StartingOffset;
		}
	    }
	}

	/* Check if we need to write back the buffer */
	if (DoRewrite) {
	    /* We don't need to do this again */
	    DoRewrite = FALSE;

	    /* Initialize the event */
	    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	    /* If we unbiased for EZ-Drive, rebias now */
	    if (IsEzDrive && !Offset.QuadPart)
		Offset.QuadPart = 512;

	    /* Build the write IRP */
	    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_WRITE, DeviceObject, Buffer,
					       BufferSize, &Offset, &Event,
					       &IoStatusBlock);
	    if (!Irp) {
		/* Fail */
		Status = STATUS_INSUFFICIENT_RESOURCES;
		break;
	    }

	    /* Make sure to disable volume verification */
	    IoStackLocation = IoGetNextIrpStackLocation(Irp);
	    IoStackLocation->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

	    /* Call the driver */
	    Status = IoCallDriver(DeviceObject, Irp);
	    if (Status == STATUS_PENDING) {
		/* Wait for completion */
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
		Status = IoStatusBlock.Status;
	    }

	    /* Check for failure */
	    if (!NT_SUCCESS(Status))
		break;

	    /* If we biased for EZ-Drive, unbias now */
	    if (IsEzDrive && (Offset.QuadPart == 512))
		Offset.QuadPart = 0;
	}

	/* Update the partition offset and set the extended offset if needed */
	Offset = NextOffset;
	if (IsMbr)
	    ExtendedOffset = NextOffset;
    }

    /* If we had a buffer, free it, then return status */
    if (Buffer)
	ExFreePoolWithTag(Buffer, TAG_FILE_SYSTEM);
    return Status;
}
