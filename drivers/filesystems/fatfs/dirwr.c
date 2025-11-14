/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Write in directory
 * COPYRIGHT:   Copyright 1999-2001 Rex Jolliff <rex@lvcablemodem.com>
 *              Copyright 2004-2008 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2010-2018 Pierre Schweitzer <pierre@reactos.org>
 */

#include "fatfs.h"

NTSTATUS FatFcbInitializeCacheFromVolume(IN PVCB Vcb, IN PFATFCB Fcb)
{
    /* Don't re-initialize if already done */
    if (BooleanFlagOn(Fcb->Flags, FCB_CACHE_INITIALIZED)) {
	return STATUS_SUCCESS;
    }

    ASSERT(FatFcbIsDirectory(Fcb));
    ASSERT(Fcb->FileObject == NULL);

    PFILE_OBJECT FileObject = IoCreateStreamFileObject(Vcb->StorageDevice);
    if (!FileObject) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS Status;
    PFATCCB NewCcb = ExAllocateFromLookasideList(&FatGlobalData->CcbLookasideList);
    if (!NewCcb) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto Quit;
    }
    RtlZeroMemory(NewCcb, sizeof(FATCCB));

    FileObject->FsContext = Fcb;
    FileObject->FsContext2 = NewCcb;
    FileObject->Vpb = Vcb->IoVPB;
    Fcb->FileObject = FileObject;

    Status = CcInitializeCacheMap(FileObject);
    if (!NT_SUCCESS(Status)) {
	Fcb->FileObject = NULL;
	ExFreeToLookasideList(&FatGlobalData->CcbLookasideList, NewCcb);
	goto Quit;
    }

    FatGrabFcb(Vcb, Fcb);
    SetFlag(Fcb->Flags, FCB_CACHE_INITIALIZED);
    Status = STATUS_SUCCESS;

Quit:
    if (!NT_SUCCESS(Status) && FileObject) {
	ObDereferenceObject(FileObject);
    }
    return Status;
}

/*
 * Update an existing FAT entry
 */
NTSTATUS FatUpdateEntry(IN PDEVICE_EXTENSION DeviceExt, IN PFATFCB Fcb)
{
    ULONG SizeDirEntry;
    ULONG DirIndex;

    ASSERT(Fcb);

    if (FatVolumeIsFatX(DeviceExt)) {
	SizeDirEntry = sizeof(FATX_DIR_ENTRY);
	DirIndex = Fcb->StartIndex;
    } else {
	SizeDirEntry = sizeof(FAT_DIR_ENTRY);
	DirIndex = Fcb->DirIndex;
    }

    DPRINT("UpdateEntry DirIndex %u, PathName \'%wZ\'\n", DirIndex, &Fcb->PathNameU);

    if (FatFcbIsRoot(Fcb) || BooleanFlagOn(Fcb->Flags, FCB_IS_FAT | FCB_IS_VOLUME)) {
	return STATUS_SUCCESS;
    }

    ASSERT(Fcb->ParentFcb);

    NTSTATUS Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb->ParentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    LARGE_INTEGER Offset = {
	.HighPart = 0,
	.LowPart = DirIndex * SizeDirEntry
    };
    ULONG BytesWritten;
    Status = CcCopyWrite(Fcb->ParentFcb->FileObject, &Offset, SizeDirEntry,
			 TRUE, &Fcb->Entry, &BytesWritten);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed write to \'%wZ\'.\n", &Fcb->ParentFcb->PathNameU);
	return Status;
    }
    assert(BytesWritten == SizeDirEntry);

    Fcb->Flags &= ~FCB_IS_DIRTY;
    return STATUS_SUCCESS;
}

/*
 * Rename an existing FAT entry
 */
NTSTATUS FatRenameEntry(IN PDEVICE_EXTENSION DeviceExt,
			IN PFATFCB Fcb,
			IN PUNICODE_STRING FileName,
			IN BOOLEAN CaseChangeOnly)
{
    OEM_STRING NameA;
    ULONG StartIndex;
    PVOID Context = NULL;
    LARGE_INTEGER Offset;
    PFATX_DIR_ENTRY DirEntry;
    ULONG ClusterSize = DeviceExt->FatInfo.BytesPerCluster;
    NTSTATUS Status;

    DPRINT("FatRenameEntry(%p, %p, %wZ, %d)\n", DeviceExt, Fcb, FileName,
	   CaseChangeOnly);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb->ParentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (FatVolumeIsFatX(DeviceExt)) {
	FAT_DIRENTRY_CONTEXT DirContext;

	/* Open associated dir entry */
	StartIndex = Fcb->StartIndex;
	Offset.HighPart = 0;
	Offset.LowPart = (StartIndex * sizeof(FATX_DIR_ENTRY) / ClusterSize) * ClusterSize;
	ULONG MappedLength;
	Status = CcMapData(Fcb->ParentFcb->FileObject, &Offset, ClusterSize,
			   MAP_WAIT, &MappedLength, &Context, (PVOID *)&DirEntry);
	if (!NT_SUCCESS(Status) || MappedLength != ClusterSize) {
	    DPRINT1("CcMapData(Offset 0x%llx, Length 0x%x) failed, "
		    "status 0x%x, mapped length 0x%x\n",
		    Offset.QuadPart, ClusterSize, Status, MappedLength);
	    assert(FALSE);
	    return Status;
	}
	assert(MappedLength == ClusterSize);

	DirEntry = &DirEntry[StartIndex % (ClusterSize / sizeof(FATX_DIR_ENTRY))];

	/* Set file name */
	NameA.Buffer = (PCHAR) DirEntry->Filename;
	NameA.Length = 0;
	NameA.MaximumLength = 42;
	RtlUnicodeStringToOemString(&NameA, FileName, FALSE);
	DirEntry->FilenameLength = (UCHAR)NameA.Length;

	/* Update FCB */
	DirContext.DeviceExt = DeviceExt;
	DirContext.ShortNameU.Length = 0;
	DirContext.ShortNameU.MaximumLength = 0;
	DirContext.ShortNameU.Buffer = NULL;
	DirContext.LongNameU = *FileName;
	DirContext.DirEntry.FatX = *DirEntry;

	CcSetDirtyData(Context);
	CcUnpinData(Context);

	Status = FatUpdateFcb(DeviceExt, Fcb, &DirContext, Fcb->ParentFcb);

	return Status;
    } else {
	/* This we cannot handle properly, move file - would likely need love */
	return FatMoveEntry(DeviceExt, Fcb, FileName, Fcb->ParentFcb);
    }
}

/*
 * Try to find contiguous entries frees in the directory. Extend a directory if necessary.
 */
BOOLEAN FatFindDirSpace(IN PDEVICE_EXTENSION DeviceExt,
			IN PFATFCB DirFcb,
			IN ULONG NumSlots,
			OUT PULONG pStart)
{
    LARGE_INTEGER FileOffset = { .QuadPart = 0 };
    ULONG i, NumFree = 0;
    PDIR_ENTRY FatEntry = NULL;
    PVOID Context = NULL;
    NTSTATUS Status;
    ULONG SizeDirEntry;
    BOOLEAN IsFatX = FatVolumeIsFatX(DeviceExt);
    ULONG ClusterSize = DeviceExt->FatInfo.BytesPerCluster;

    if (IsFatX)
	SizeDirEntry = sizeof(FATX_DIR_ENTRY);
    else
	SizeDirEntry = sizeof(FAT_DIR_ENTRY);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, DirFcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    ULONG Count = DirFcb->Base.FileSizes.FileSize.LowPart / SizeDirEntry;
    ULONG Size = ClusterSize / SizeDirEntry;
    ULONG MappedLength;
    for (i = 0; i < Count; i++, FatEntry = (PDIR_ENTRY)((ULONG_PTR)FatEntry + SizeDirEntry)) {
	if (Context == NULL || (i % Size) == 0) {
	    if (Context) {
		CcUnpinData(Context);
	    }
	    Status = CcMapData(DirFcb->FileObject, &FileOffset, ClusterSize, MAP_WAIT,
			       &MappedLength, &Context, (PVOID *)&FatEntry);
	    if (!NT_SUCCESS(Status) || MappedLength != ClusterSize) {
		assert(FALSE);
		return FALSE;
	    }
	    assert(MappedLength == ClusterSize);
	    FileOffset.LowPart += ClusterSize;
	}

	if (ENTRY_END(IsFatX, FatEntry)) {
	    break;
	}
	if (ENTRY_DELETED(IsFatX, FatEntry)) {
	    NumFree++;
	} else {
	    NumFree = 0;
	}
	if (NumFree == NumSlots) {
	    break;
	}
    }

    if (Context) {
	CcUnpinData(Context);
	Context = NULL;
    }

    if (NumFree == NumSlots) {
	/* Found enough contiguous free slots */
	*pStart = i - NumSlots + 1;
    } else {
	*pStart = i - NumFree;
	if (*pStart + NumSlots > Count) {
	    LARGE_INTEGER AllocationSize;

	    /* Extend the directory */
	    if (FatFcbIsRoot(DirFcb) && DeviceExt->FatInfo.FatType != FAT32) {
		/* We can't extend a root directory on a FAT12/FAT16/FATX partition */
		return FALSE;
	    }
	    AllocationSize.QuadPart = DirFcb->Base.FileSizes.FileSize.LowPart + ClusterSize;
	    Status = FatSetFileSizeInformation(DirFcb->FileObject, DirFcb, DeviceExt,
					       &AllocationSize);
	    if (!NT_SUCCESS(Status)) {
		return FALSE;
	    }

	    /* Clear the new dir cluster */
	    FileOffset.LowPart = DirFcb->Base.FileSizes.FileSize.QuadPart - ClusterSize;
	    Status = CcMapData(DirFcb->FileObject, &FileOffset, ClusterSize, MAP_WAIT,
			       &MappedLength, &Context, (PVOID *)&FatEntry);
	    if (!NT_SUCCESS(Status) || MappedLength != ClusterSize) {
		assert(FALSE);
		return FALSE;
	    }
	    assert(MappedLength == ClusterSize);

	    if (IsFatX)
		memset(FatEntry, 0xff, ClusterSize);
	    else
		RtlZeroMemory(FatEntry, ClusterSize);
	} else if (*pStart + NumSlots < Count) {
	    /* Clear the entry after the last new entry */
	    FileOffset.LowPart = (*pStart + NumSlots) * SizeDirEntry;
	    Status = CcMapData(DirFcb->FileObject, &FileOffset, SizeDirEntry,
			       MAP_WAIT, &MappedLength, &Context, (PVOID *)&FatEntry);
	    if (!NT_SUCCESS(Status) || MappedLength != SizeDirEntry) {
		assert(FALSE);
		return FALSE;
	    }
	    assert(MappedLength == SizeDirEntry);

	    if (IsFatX)
		memset(FatEntry, 0xff, SizeDirEntry);
	    else
		RtlZeroMemory(FatEntry, SizeDirEntry);
	}

	if (Context) {
	    CcSetDirtyData(Context);
	    CcUnpinData(Context);
	}
    }
    DPRINT("NumSlots %u NumFree %u, entry number %u\n",
	   NumSlots, NumFree, *pStart);
    return TRUE;
}

/*
 * Move an existing FAT entry
 */
NTSTATUS FatMoveEntry(IN PDEVICE_EXTENSION DeviceExt,
		      IN PFATFCB Fcb,
		      IN PUNICODE_STRING FileName,
		      IN PFATFCB ParentFcb)
{
    NTSTATUS Status;
    PFATFCB OldParent;
    FAT_MOVE_CONTEXT MoveContext;

    DPRINT("FatMoveEntry(%p, %p, %wZ, %p)\n", DeviceExt, Fcb, FileName, ParentFcb);

    /* Delete old entry while keeping data */
    Status = FatDelEntry(DeviceExt, Fcb, &MoveContext);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    OldParent = Fcb->ParentFcb;
    MoveContext.InPlace = (OldParent == ParentFcb);

    /* Add our new entry with our cluster */
    Status = FatAddEntry(DeviceExt, FileName, &Fcb, ParentFcb,
			 (FatFcbIsDirectory(Fcb) ? FILE_DIRECTORY_FILE : 0),
			 *Fcb->Attributes, &MoveContext);

    return Status;
}
