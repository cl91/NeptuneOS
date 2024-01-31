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
    PFILE_OBJECT FileObject;
    PFATCCB NewCCB;

    /* Don't re-initialize if already done */
    if (BooleanFlagOn(Fcb->Flags, FCB_CACHE_INITIALIZED)) {
	return STATUS_SUCCESS;
    }

    ASSERT(FatFcbIsDirectory(Fcb));
    ASSERT(Fcb->FileObject == NULL);

    FileObject = IoCreateStreamFileObject(Vcb->StorageDevice);
    if (FileObject == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS Status;
    NewCCB = ExAllocateFromLookasideList(&FatGlobalData->CcbLookasideList);
    if (NewCCB == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto Quit;
    }
    RtlZeroMemory(NewCCB, sizeof(FATCCB));

    FileObject->FsContext = Fcb;
    FileObject->FsContext2 = NewCCB;
    FileObject->Vpb = Vcb->IoVPB;
    Fcb->FileObject = FileObject;

    Status = CcInitializeCacheMap(FileObject,
				  (PCC_FILE_SIZES)(&Fcb->Base.AllocationSize),
				  TRUE, Fcb);
    if (!NT_SUCCESS(Status)) {
	Fcb->FileObject = NULL;
	ExFreeToLookasideList(&FatGlobalData->CcbLookasideList, NewCCB);
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
    PVOID Context;
    PDIR_ENTRY PinEntry;
    LARGE_INTEGER Offset;
    ULONG SizeDirEntry;
    ULONG DirIndex;
    NTSTATUS Status;

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

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb->ParentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Offset.HighPart = 0;
    Offset.LowPart = DirIndex * SizeDirEntry;
    Status = CcPinRead(Fcb->ParentFcb->FileObject, &Offset, SizeDirEntry,
		       PIN_WAIT, &Context, (PVOID *)&PinEntry);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed write to \'%wZ\'.\n", &Fcb->ParentFcb->PathNameU);
	return Status;
    }

    Fcb->Flags &= ~FCB_IS_DIRTY;
    RtlCopyMemory(PinEntry, &Fcb->Entry, SizeDirEntry);
    CcSetDirtyPinnedData(Context, NULL);
    CcUnpinData(Context);
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
    PFATX_DIR_ENTRY pDirEntry;
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
	Offset.LowPart = (StartIndex * sizeof(FATX_DIR_ENTRY) / PAGE_SIZE) * PAGE_SIZE;
	Status = CcPinRead(Fcb->ParentFcb->FileObject, &Offset, PAGE_SIZE,
			   PIN_WAIT, &Context, (PVOID *)&pDirEntry);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("CcPinRead(Offset %x:%x, Length %d) failed\n",
		    Offset.HighPart, Offset.LowPart, PAGE_SIZE);
	    return Status;
	}

	pDirEntry = &pDirEntry[StartIndex % (PAGE_SIZE / sizeof(FATX_DIR_ENTRY))];

	/* Set file name */
	NameA.Buffer = (PCHAR) pDirEntry->Filename;
	NameA.Length = 0;
	NameA.MaximumLength = 42;
	RtlUnicodeStringToOemString(&NameA, FileName, FALSE);
	pDirEntry->FilenameLength = (UCHAR)NameA.Length;

	/* Update FCB */
	DirContext.DeviceExt = DeviceExt;
	DirContext.ShortNameU.Length = 0;
	DirContext.ShortNameU.MaximumLength = 0;
	DirContext.ShortNameU.Buffer = NULL;
	DirContext.LongNameU = *FileName;
	DirContext.DirEntry.FatX = *pDirEntry;

	CcSetDirtyPinnedData(Context, NULL);
	CcUnpinData(Context);

	Status = FatUpdateFcb(DeviceExt, Fcb, &DirContext, Fcb->ParentFcb);
	if (NT_SUCCESS(Status)) {
	    CcFlushCache(&Fcb->ParentFcb->Base, NULL, 0, NULL);
	}

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
    LARGE_INTEGER FileOffset;
    ULONG i, Count, Size, NumFree = 0;
    PDIR_ENTRY pFatEntry = NULL;
    PVOID Context = NULL;
    NTSTATUS Status;
    ULONG SizeDirEntry;
    BOOLEAN IsFatX = FatVolumeIsFatX(DeviceExt);
    FileOffset.QuadPart = 0;

    if (IsFatX)
	SizeDirEntry = sizeof(FATX_DIR_ENTRY);
    else
	SizeDirEntry = sizeof(FAT_DIR_ENTRY);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, DirFcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    Count = DirFcb->Base.FileSize.LowPart / SizeDirEntry;
    Size = DeviceExt->FatInfo.BytesPerCluster / SizeDirEntry;
    for (i = 0; i < Count; i++, pFatEntry = (PDIR_ENTRY)((ULONG_PTR)pFatEntry + SizeDirEntry)) {
	if (Context == NULL || (i % Size) == 0) {
	    if (Context) {
		CcUnpinData(Context);
	    }
	    Status = CcPinRead(DirFcb->FileObject, &FileOffset,
			       DeviceExt->FatInfo.BytesPerCluster, PIN_WAIT,
			       &Context, (PVOID *)&pFatEntry);
	    if (!NT_SUCCESS(Status)) {
		return FALSE;
	    }
	    FileOffset.LowPart += DeviceExt->FatInfo.BytesPerCluster;
	}

	if (ENTRY_END(IsFatX, pFatEntry)) {
	    break;
	}
	if (ENTRY_DELETED(IsFatX, pFatEntry)) {
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
	    AllocationSize.QuadPart = DirFcb->Base.FileSize.LowPart +
		DeviceExt->FatInfo.BytesPerCluster;
	    Status = FatSetFileSizeInformation(DirFcb->FileObject,
					       DirFcb, DeviceExt,
					       &AllocationSize);
	    if (!NT_SUCCESS(Status)) {
		return FALSE;
	    }

	    /* Clear the new dir cluster */
	    FileOffset.LowPart = (ULONG)(DirFcb->Base.FileSize.QuadPart -
					 DeviceExt->FatInfo.BytesPerCluster);
	    Status = CcPinRead(DirFcb->FileObject, &FileOffset,
			       DeviceExt->FatInfo.BytesPerCluster, PIN_WAIT,
			       &Context, (PVOID *)&pFatEntry);
	    if (!NT_SUCCESS(Status)) {
		return FALSE;
	    }

	    if (IsFatX)
		memset(pFatEntry, 0xff, DeviceExt->FatInfo.BytesPerCluster);
	    else
		RtlZeroMemory(pFatEntry, DeviceExt->FatInfo.BytesPerCluster);
	} else if (*pStart + NumSlots < Count) {
	    /* Clear the entry after the last new entry */
	    FileOffset.LowPart = (*pStart + NumSlots) * SizeDirEntry;
	    Status = CcPinRead(DirFcb->FileObject, &FileOffset, SizeDirEntry,
			       PIN_WAIT, &Context, (PVOID *)&pFatEntry);
	    if (!NT_SUCCESS(Status)) {
		return FALSE;
	    }

	    if (IsFatX)
		memset(pFatEntry, 0xff, SizeDirEntry);
	    else
		RtlZeroMemory(pFatEntry, SizeDirEntry);
	}

	if (Context) {
	    CcSetDirtyPinnedData(Context, NULL);
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
    CcFlushCache(&OldParent->Base, NULL, 0, NULL);
    MoveContext.InPlace = (OldParent == ParentFcb);

    /* Add our new entry with our cluster */
    Status = FatAddEntry(DeviceExt, FileName, &Fcb, ParentFcb,
			 (FatFcbIsDirectory(Fcb) ? FILE_DIRECTORY_FILE : 0),
			 *Fcb->Attributes, &MoveContext);

    CcFlushCache(&Fcb->ParentFcb->Base, NULL, 0, NULL);

    return Status;
}
