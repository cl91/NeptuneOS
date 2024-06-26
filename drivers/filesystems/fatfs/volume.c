/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Volume routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2004-2022 Hervé Poussineau <hpoussin@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS ****************************************************************/

static NTSTATUS FsdGetFsVolumeInformation(PDEVICE_OBJECT DeviceObject,
					  PFILE_FS_VOLUME_INFORMATION FsVolumeInfo,
					  PULONG BufferLength)
{
    NTSTATUS Status;
    PDEVICE_EXTENSION DeviceExt;

    DPRINT("FsdGetFsVolumeInformation()\n");
    DPRINT("FsVolumeInfo = %p\n", FsVolumeInfo);
    DPRINT("BufferLength %u\n", *BufferLength);

    DPRINT("Required length %u\n",
	   FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel) +
	   DeviceObject->Vpb->VolumeLabelLength);
    DPRINT("LabelLength %hu\nLabel ", DeviceObject->Vpb->VolumeLabelLength);
    for (int i = 0; i < DeviceObject->Vpb->VolumeLabelLength; i++) {
	DPRINT("%wc", DeviceObject->Vpb->VolumeLabel[i]);
    }
    DPRINT("\n");

    ASSERT(*BufferLength >= sizeof(FILE_FS_VOLUME_INFORMATION));
    *BufferLength -= FIELD_OFFSET(FILE_FS_VOLUME_INFORMATION, VolumeLabel);

    DeviceExt = DeviceObject->DeviceExtension;

    /* valid entries */
    FsVolumeInfo->VolumeSerialNumber = DeviceObject->Vpb->SerialNumber;
    FsVolumeInfo->VolumeLabelLength = DeviceObject->Vpb->VolumeLabelLength;
    if (*BufferLength < DeviceObject->Vpb->VolumeLabelLength) {
	Status = STATUS_BUFFER_OVERFLOW;
	RtlCopyMemory(FsVolumeInfo->VolumeLabel,
		      DeviceObject->Vpb->VolumeLabel, *BufferLength);
    } else {
	Status = STATUS_SUCCESS;
	RtlCopyMemory(FsVolumeInfo->VolumeLabel,
		      DeviceObject->Vpb->VolumeLabel,
		      FsVolumeInfo->VolumeLabelLength);
	*BufferLength -= DeviceObject->Vpb->VolumeLabelLength;
    }

    if (FatVolumeIsFatX(DeviceExt)) {
	FsdDosDateTimeToSystemTime(DeviceExt,
				   DeviceExt->VolumeFcb->Entry.FatX.CreationDate,
				   DeviceExt->VolumeFcb->Entry.FatX.CreationTime,
				   &FsVolumeInfo->VolumeCreationTime);
    } else {
	FsdDosDateTimeToSystemTime(DeviceExt,
				   DeviceExt->VolumeFcb->Entry.Fat.CreationDate,
				   DeviceExt->VolumeFcb->Entry.Fat.CreationTime,
				   &FsVolumeInfo->VolumeCreationTime);
    }

    FsVolumeInfo->SupportsObjects = FALSE;

    DPRINT("Finished FsdGetFsVolumeInformation()\n");
    DPRINT("BufferLength %u\n", *BufferLength);

    return Status;
}

static NTSTATUS FsdGetFsAttributeInformation(PDEVICE_EXTENSION DeviceExt,
					     PFILE_FS_ATTRIBUTE_INFORMATION AttrInfo,
					     PULONG BufferLength)
{
    NTSTATUS Status;
    PCWSTR pName;
    ULONG Length;

    DPRINT("FsdGetFsAttributeInformation()\n");
    DPRINT("FsAttributeInfo = %p\n", AttrInfo);
    DPRINT("BufferLength %u\n", *BufferLength);

    ASSERT(*BufferLength >= sizeof(FILE_FS_ATTRIBUTE_INFORMATION));
    *BufferLength -= FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName);

    switch (DeviceExt->FatInfo.FatType) {
    case FAT12:
	pName = L"FAT";
	break;
    case FAT16:
	pName = L"FAT";
	break;
    case FAT32:
	pName = L"FAT32";
	break;
    case FATX16:
	pName = L"FATX";
	break;
    case FATX32:
	pName = L"FATX";
	break;
    default:
	return STATUS_NOT_SUPPORTED;
    }

    Length = wcslen(pName) * sizeof(WCHAR);
    DPRINT("Required length %u\n",
	   FIELD_OFFSET(FILE_FS_ATTRIBUTE_INFORMATION, FileSystemName) + Length);

    if (*BufferLength < Length) {
	Status = STATUS_BUFFER_OVERFLOW;
	Length = *BufferLength;
    } else {
	Status = STATUS_SUCCESS;
    }

    AttrInfo->FileSystemAttributes = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;
    AttrInfo->MaximumComponentNameLength = 255;
    AttrInfo->FileSystemNameLength = Length;

    RtlCopyMemory(AttrInfo->FileSystemName, pName, Length);

    DPRINT("Finished FsdGetFsAttributeInformation()\n");

    *BufferLength -= Length;
    DPRINT("BufferLength %u\n", *BufferLength);

    return Status;
}


static NTSTATUS FsdGetFsSizeInformation(PDEVICE_OBJECT DeviceObject,
					PFILE_FS_SIZE_INFORMATION FsSizeInfo,
					PULONG BufferLength)
{
    PDEVICE_EXTENSION DeviceExt;
    NTSTATUS Status;

    DPRINT("FsdGetFsSizeInformation()\n");
    DPRINT("FsSizeInfo = %p\n", FsSizeInfo);

    ASSERT(*BufferLength >= sizeof(FILE_FS_SIZE_INFORMATION));

    DeviceExt = DeviceObject->DeviceExtension;
    Status = CountAvailableClusters(DeviceExt,
				    &FsSizeInfo->AvailableAllocationUnits);

    FsSizeInfo->TotalAllocationUnits.QuadPart = DeviceExt->FatInfo.NumberOfClusters;
    FsSizeInfo->SectorsPerAllocationUnit = DeviceExt->FatInfo.SectorsPerCluster;
    FsSizeInfo->BytesPerSector = DeviceExt->FatInfo.BytesPerSector;

    DPRINT("Finished FsdGetFsSizeInformation()\n");
    if (NT_SUCCESS(Status))
	*BufferLength -= sizeof(FILE_FS_SIZE_INFORMATION);

    return Status;
}


static NTSTATUS FsdGetFsDeviceInformation(PDEVICE_OBJECT DeviceObject,
					  PFILE_FS_DEVICE_INFORMATION FsDeviceInfo,
					  PULONG BufferLength)
{
    DPRINT("FsdGetFsDeviceInformation()\n");
    DPRINT("FsDeviceInfo = %p\n", FsDeviceInfo);
    DPRINT("BufferLength %u\n", *BufferLength);
    DPRINT("Required length 0x%zx\n", sizeof(FILE_FS_DEVICE_INFORMATION));

    ASSERT(*BufferLength >= sizeof(FILE_FS_DEVICE_INFORMATION));

    FsDeviceInfo->DeviceType = FILE_DEVICE_DISK;
    FsDeviceInfo->Characteristics = DeviceObject->Flags;

    DPRINT("FsdGetFsDeviceInformation() finished.\n");

    *BufferLength -= sizeof(FILE_FS_DEVICE_INFORMATION);
    DPRINT("BufferLength %u\n", *BufferLength);

    return STATUS_SUCCESS;
}


static NTSTATUS FsdGetFsFullSizeInformation(PDEVICE_OBJECT DeviceObject,
					    PFILE_FS_FULL_SIZE_INFORMATION FsSizeInfo,
					    PULONG BufferLength)
{
    PDEVICE_EXTENSION DeviceExt;
    NTSTATUS Status;

    DPRINT("FsdGetFsFullSizeInformation()\n");
    DPRINT("FsSizeInfo = %p\n", FsSizeInfo);

    ASSERT(*BufferLength >= sizeof(FILE_FS_FULL_SIZE_INFORMATION));

    DeviceExt = DeviceObject->DeviceExtension;
    Status = CountAvailableClusters(DeviceExt,
				    &FsSizeInfo->CallerAvailableAllocationUnits);

    FsSizeInfo->TotalAllocationUnits.QuadPart = DeviceExt->FatInfo.NumberOfClusters;
    FsSizeInfo->ActualAvailableAllocationUnits.QuadPart =
	FsSizeInfo->CallerAvailableAllocationUnits.QuadPart;
    FsSizeInfo->SectorsPerAllocationUnit = DeviceExt->FatInfo.SectorsPerCluster;
    FsSizeInfo->BytesPerSector = DeviceExt->FatInfo.BytesPerSector;

    DPRINT("Finished FsdGetFsFullSizeInformation()\n");
    if (NT_SUCCESS(Status))
	*BufferLength -= sizeof(FILE_FS_FULL_SIZE_INFORMATION);

    return Status;
}

/* TODO: This needs cleaning up. */
static NTSTATUS FsdSetFsLabelInformation(PDEVICE_OBJECT DeviceObject,
					 PFILE_FS_LABEL_INFORMATION FsLabelInfo)
{
    PDEVICE_EXTENSION DeviceExt;
    PVOID Context = NULL;
    ULONG DirIndex = 0;
    PDIR_ENTRY Entry;
    PFATFCB pRootFcb;
    LARGE_INTEGER FileOffset;
    BOOLEAN LabelFound = FALSE;
    DIR_ENTRY VolumeLabelDirEntry;
    ULONG VolumeLabelDirIndex;
    ULONG LabelLen;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OEM_STRING StringO;
    UNICODE_STRING StringW;
    CHAR cString[43];
    BOOLEAN IsFatX;

    DPRINT("FsdSetFsLabelInformation()\n");

    DeviceExt = (PDEVICE_EXTENSION) DeviceObject->DeviceExtension;
    IsFatX = FatVolumeIsFatX(DeviceExt);

    if (sizeof(DeviceObject->Vpb->VolumeLabel) < FsLabelInfo->VolumeLabelLength) {
	return STATUS_NAME_TOO_LONG;
    }

    ULONG ClusterSize = DeviceExt->FatInfo.BytesPerCluster;
    ULONG SizeDirEntry;
    if (IsFatX) {
	if (FsLabelInfo->VolumeLabelLength / sizeof(WCHAR) > 42)
	    return STATUS_NAME_TOO_LONG;

	SizeDirEntry = sizeof(FATX_DIR_ENTRY);
    } else {
	if (FsLabelInfo->VolumeLabelLength / sizeof(WCHAR) > 11)
	    return STATUS_NAME_TOO_LONG;

	SizeDirEntry = sizeof(FAT_DIR_ENTRY);
    }
    ULONG EntriesPerCluster = ClusterSize / SizeDirEntry;

    /* Create Volume label dir entry */
    LabelLen = FsLabelInfo->VolumeLabelLength / sizeof(WCHAR);
    RtlZeroMemory(&VolumeLabelDirEntry, SizeDirEntry);
    StringW.Buffer = FsLabelInfo->VolumeLabel;
    StringW.Length = StringW.MaximumLength = (USHORT)FsLabelInfo->VolumeLabelLength;
    StringO.Buffer = cString;
    StringO.Length = 0;
    StringO.MaximumLength = 42;
    Status = RtlUnicodeStringToOemString(&StringO, &StringW, FALSE);
    if (!NT_SUCCESS(Status))
	return Status;

    if (IsFatX) {
	RtlCopyMemory(VolumeLabelDirEntry.FatX.Filename, cString, LabelLen);
	memset(&VolumeLabelDirEntry.FatX.Filename[LabelLen], ' ', 42 - LabelLen);
	VolumeLabelDirEntry.FatX.Attrib = _A_VOLID;
    } else {
	RtlCopyMemory(VolumeLabelDirEntry.Fat.Filename, cString,
		      max(sizeof(VolumeLabelDirEntry.Fat.Filename), LabelLen));
	if (LabelLen > sizeof(VolumeLabelDirEntry.Fat.Filename)) {
	    memset(VolumeLabelDirEntry.Fat.Ext, ' ',
		   sizeof(VolumeLabelDirEntry.Fat.Ext));
	    RtlCopyMemory(VolumeLabelDirEntry.Fat.Ext,
			  cString + sizeof(VolumeLabelDirEntry.Fat.Filename),
			  LabelLen - sizeof(VolumeLabelDirEntry.Fat.Filename));
	} else {
	    memset(&VolumeLabelDirEntry.Fat.Filename[LabelLen], ' ',
		   sizeof(VolumeLabelDirEntry.Fat.Filename) - LabelLen);
	}
	VolumeLabelDirEntry.Fat.Attrib = _A_VOLID;
    }

    pRootFcb = FatOpenRootFcb(DeviceExt);
    Status = FatFcbInitializeCacheFromVolume(DeviceExt, pRootFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Search existing volume entry on disk */
    FileOffset.QuadPart = 0;
    ULONG MappedLength;
    Status = CcMapData(pRootFcb->FileObject, &FileOffset, SizeDirEntry,
		       MAP_WAIT, &MappedLength, &Context, (PVOID *)&Entry);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(MappedLength == SizeDirEntry);

    if (NT_SUCCESS(Status)) {
	while (TRUE) {
	    if (ENTRY_VOLUME(IsFatX, Entry)) {
		/* Update entry */
		LabelFound = TRUE;
		RtlCopyMemory(Entry, &VolumeLabelDirEntry, SizeDirEntry);
		CcSetDirtyData(Context);
		Status = STATUS_SUCCESS;
		break;
	    }

	    if (ENTRY_END(IsFatX, Entry)) {
		break;
	    }

	    DirIndex++;
	    Entry = (PDIR_ENTRY) ((ULONG_PTR) Entry + SizeDirEntry);
	    if ((DirIndex % EntriesPerCluster) == 0) {
		CcUnpinData(Context);
		FileOffset.LowPart += ClusterSize;
		Status = CcMapData(pRootFcb->FileObject, &FileOffset,
				   SizeDirEntry, MAP_WAIT, &MappedLength,
				   &Context, (PVOID *)&Entry);
		if (!NT_SUCCESS(Status)) {
		    Context = NULL;
		    break;
		}
		assert(MappedLength == SizeDirEntry);
	    }
	}

	if (Context) {
	    CcUnpinData(Context);
	}
    }

    if (!LabelFound) {
	/* Add new entry for label */
	if (!FatFindDirSpace(DeviceExt, pRootFcb, 1, &VolumeLabelDirIndex))
	    Status = STATUS_DISK_FULL;
	else {
	    FileOffset.HighPart = 0;
	    FileOffset.LowPart = VolumeLabelDirIndex * SizeDirEntry;

	    Status = CcMapData(pRootFcb->FileObject, &FileOffset, SizeDirEntry,
			       MAP_WAIT, &MappedLength, &Context, (PVOID *)&Entry);

	    if (NT_SUCCESS(Status)) {
		assert(MappedLength == SizeDirEntry);
		RtlCopyMemory(Entry, &VolumeLabelDirEntry, SizeDirEntry);
		CcSetDirtyData(Context);
		CcUnpinData(Context);
		Status = STATUS_SUCCESS;
	    }
	}
    }

    FatReleaseFcb(DeviceExt, pRootFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Update volume label in memory */
    DeviceObject->Vpb->VolumeLabelLength = (USHORT)FsLabelInfo->VolumeLabelLength;
    RtlCopyMemory(DeviceObject->Vpb->VolumeLabel, FsLabelInfo->VolumeLabel,
		  DeviceObject->Vpb->VolumeLabelLength);

    return Status;
}


/*
 * FUNCTION: Retrieve the specified volume information
 */
NTSTATUS FatQueryVolumeInformation(PFAT_IRP_CONTEXT IrpContext)
{
    FS_INFORMATION_CLASS FsInformationClass;
    NTSTATUS RC = STATUS_SUCCESS;
    PVOID SystemBuffer;
    ULONG BufferLength;

    /* PRECONDITION */
    ASSERT(IrpContext);

    DPRINT("FatQueryVolumeInformation(IrpContext %p)\n", IrpContext);

    /* INITIALIZATION */
    FsInformationClass = IrpContext->Stack->Parameters.QueryVolume.FsInformationClass;
    BufferLength = IrpContext->Stack->Parameters.QueryVolume.Length;
    SystemBuffer = IrpContext->Irp->SystemBuffer;

    DPRINT("FsInformationClass %d\n", FsInformationClass);
    DPRINT("SystemBuffer %p\n", SystemBuffer);

    RtlZeroMemory(SystemBuffer, BufferLength);

    switch (FsInformationClass) {
    case FileFsVolumeInformation:
	RC = FsdGetFsVolumeInformation(IrpContext->DeviceObject,
				       SystemBuffer, &BufferLength);
	break;

    case FileFsAttributeInformation:
	RC = FsdGetFsAttributeInformation(IrpContext->DeviceObject->DeviceExtension,
					  SystemBuffer, &BufferLength);
	break;

    case FileFsSizeInformation:
	RC = FsdGetFsSizeInformation(IrpContext->DeviceObject,
				     SystemBuffer, &BufferLength);
	break;

    case FileFsDeviceInformation:
	RC = FsdGetFsDeviceInformation(IrpContext->DeviceObject,
				       SystemBuffer, &BufferLength);
	break;

    case FileFsFullSizeInformation:
	RC = FsdGetFsFullSizeInformation(IrpContext->DeviceObject,
					 SystemBuffer, &BufferLength);
	break;

    default:
	RC = STATUS_NOT_SUPPORTED;
    }

    IrpContext->Irp->IoStatus.Information =
	IrpContext->Stack->Parameters.QueryVolume.Length - BufferLength;

    return RC;
}


/*
 * FUNCTION: Set the specified volume information
 */
NTSTATUS FatSetVolumeInformation(PFAT_IRP_CONTEXT IrpContext)
{
    FS_INFORMATION_CLASS FsInformationClass;
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID SystemBuffer;
    ULONG BufferLength;
    PIO_STACK_LOCATION Stack = IrpContext->Stack;

    /* PRECONDITION */
    ASSERT(IrpContext);

    DPRINT("FatSetVolumeInformation(IrpContext %p)\n", IrpContext);

    FsInformationClass = Stack->Parameters.SetVolume.FsInformationClass;
    BufferLength = Stack->Parameters.SetVolume.Length;
    SystemBuffer = IrpContext->Irp->SystemBuffer;

    DPRINT("FsInformationClass %d\n", FsInformationClass);
    DPRINT("BufferLength %u\n", BufferLength);
    DPRINT("SystemBuffer %p\n", SystemBuffer);

    switch (FsInformationClass) {
    case FileFsLabelInformation:
	Status = FsdSetFsLabelInformation(IrpContext->DeviceObject,
					  SystemBuffer);
	break;

    default:
	Status = STATUS_NOT_SUPPORTED;
    }

    IrpContext->Irp->IoStatus.Information = 0;

    return Status;
}
