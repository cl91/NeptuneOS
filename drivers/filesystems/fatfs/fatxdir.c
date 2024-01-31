/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Routines to manipulate FatX directory entries
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2001 Rex Jolliff <rex@lvcablemodem.com>
 *              Copyright 2004-2022 Hervé Poussineau <hpoussin@reactos.org>
 */

#include "fatfs.h"

/*
 * Create a new FAT entry
 */
static NTSTATUS AddEntry(IN PDEVICE_EXTENSION DeviceExt,
			 IN PUNICODE_STRING NameU,
			 IN PFATFCB *Fcb,
			 IN PFATFCB ParentFcb,
			 IN ULONG RequestedOptions,
			 IN UCHAR ReqAttr,
			 IN PFAT_MOVE_CONTEXT MoveContext)
{
    PVOID Context = NULL;
    LARGE_INTEGER SystemTime, FileOffset;
    OEM_STRING NameA;
    FAT_DIRENTRY_CONTEXT DirContext;
    PFATX_DIR_ENTRY pFatXDirEntry;
    ULONG Index;

    DPRINT("addEntry: Name='%wZ', Dir='%wZ'\n", NameU, &ParentFcb->PathNameU);

    DirContext.LongNameU = *NameU;

    if (DirContext.LongNameU.Length / sizeof(WCHAR) > 42) {
	/* name too long */
	return STATUS_NAME_TOO_LONG;
    }

    /* try to find 1 entry free in directory */
    if (!FatFindDirSpace(DeviceExt, ParentFcb, 1, &DirContext.StartIndex)) {
	return STATUS_DISK_FULL;
    }
    Index = DirContext.DirIndex = DirContext.StartIndex;
    if (!FatFcbIsRoot(ParentFcb)) {
	DirContext.DirIndex += 2;
	DirContext.StartIndex += 2;
    }

    DirContext.ShortNameU.Buffer = 0;
    DirContext.ShortNameU.Length = 0;
    DirContext.ShortNameU.MaximumLength = 0;
    DirContext.DeviceExt = DeviceExt;
    RtlZeroMemory(&DirContext.DirEntry.FatX, sizeof(FATX_DIR_ENTRY));
    memset(DirContext.DirEntry.FatX.Filename, 0xff, 42);
    /* Use cluster, if moving */
    if (MoveContext != NULL) {
	DirContext.DirEntry.FatX.FirstCluster = MoveContext->FirstCluster;
    } else {
	DirContext.DirEntry.FatX.FirstCluster = 0;
    }
    DirContext.DirEntry.FatX.FileSize = 0;

    /* Set file name */
    NameA.Buffer = (PCHAR)DirContext.DirEntry.FatX.Filename;
    NameA.Length = 0;
    NameA.MaximumLength = 42;
    RtlUnicodeStringToOemString(&NameA, &DirContext.LongNameU, FALSE);
    DirContext.DirEntry.FatX.FilenameLength = (UCHAR)NameA.Length;

    /* Set attributes */
    DirContext.DirEntry.FatX.Attrib = ReqAttr;
    if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE)) {
	DirContext.DirEntry.FatX.Attrib |= FILE_ATTRIBUTE_DIRECTORY;
    }

    /* Set dates and times */
    NtQuerySystemTime(&SystemTime);
    FsdSystemTimeToDosDateTime(DeviceExt, &SystemTime,
			       &DirContext.DirEntry.FatX.CreationDate,
			       &DirContext.DirEntry.FatX.CreationTime);
    DirContext.DirEntry.FatX.UpdateDate = DirContext.DirEntry.FatX.CreationDate;
    DirContext.DirEntry.FatX.UpdateTime = DirContext.DirEntry.FatX.CreationTime;
    DirContext.DirEntry.FatX.AccessDate = DirContext.DirEntry.FatX.CreationDate;
    DirContext.DirEntry.FatX.AccessTime = DirContext.DirEntry.FatX.CreationTime;
    /* If it's moving, preserve creation time and file size */
    if (MoveContext != NULL) {
	DirContext.DirEntry.FatX.CreationDate = MoveContext->CreationDate;
	DirContext.DirEntry.FatX.CreationTime = MoveContext->CreationTime;
	DirContext.DirEntry.FatX.FileSize = MoveContext->FileSize;
    }

    /* No need to init cache here, FatFindDirSpace() will have done it for us */
    ASSERT(BooleanFlagOn(ParentFcb->Flags, FCB_CACHE_INITIALIZED));

    /* add entry into parent directory */
    FileOffset.HighPart = 0;
    FileOffset.LowPart = Index * sizeof(FATX_DIR_ENTRY);
    NTSTATUS Status = CcPinRead(ParentFcb->FileObject, &FileOffset,
				sizeof(FATX_DIR_ENTRY), PIN_WAIT, &Context,
				(PVOID *)&pFatXDirEntry);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    RtlCopyMemory(pFatXDirEntry, &DirContext.DirEntry.FatX, sizeof(FATX_DIR_ENTRY));
    CcSetDirtyPinnedData(Context, NULL);
    CcUnpinData(Context);

    if (MoveContext != NULL) {
	/* We're modifying an existing FCB - likely rename/move */
	/* FIXME: check status */
	FatUpdateFcb(DeviceExt, *Fcb, &DirContext, ParentFcb);
    } else {
	/* FIXME: check status */
	FatMakeFcbFromDirEntry(DeviceExt, ParentFcb, &DirContext, Fcb);
    }

    DPRINT("addentry ok\n");
    return STATUS_SUCCESS;
}

/*
 * Deleting an existing FAT entry
 */
static NTSTATUS DelEntry(IN PDEVICE_EXTENSION DeviceExt,
			 IN PFATFCB Fcb,
			 OUT PFAT_MOVE_CONTEXT MoveContext)
{
    ULONG CurrentCluster = 0, NextCluster;
    PVOID Context = NULL;
    LARGE_INTEGER Offset;
    PFATX_DIR_ENTRY pDirEntry;
    ULONG StartIndex;
    NTSTATUS Status;

    ASSERT(Fcb);
    ASSERT(Fcb->ParentFcb);
    ASSERT(FatVolumeIsFatX(DeviceExt));

    StartIndex = Fcb->StartIndex;

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb->ParentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("delEntry PathName \'%wZ\'\n", &Fcb->PathNameU);
    DPRINT("delete entry: %u\n", StartIndex);
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
    pDirEntry->FilenameLength = 0xe5;
    CurrentCluster = FatDirEntryGetFirstCluster(DeviceExt, (PDIR_ENTRY)pDirEntry);

    /* In case of moving, save properties */
    if (MoveContext != NULL) {
	MoveContext->FirstCluster = CurrentCluster;
	MoveContext->FileSize = pDirEntry->FileSize;
	MoveContext->CreationTime = pDirEntry->CreationTime;
	MoveContext->CreationDate = pDirEntry->CreationDate;
    }

    CcSetDirtyPinnedData(Context, NULL);
    CcUnpinData(Context);

    /* In case of moving, don't delete data */
    if (MoveContext == NULL) {
	while (CurrentCluster && CurrentCluster != 0xffffffff) {
	    GetNextCluster(DeviceExt, CurrentCluster, &NextCluster);
	    /* FIXME: check status */
	    WriteCluster(DeviceExt, CurrentCluster, 0);
	    CurrentCluster = NextCluster;
	}
    }

    return STATUS_SUCCESS;
}

static BOOLEAN IsDirectoryEmpty(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb)
{
    LARGE_INTEGER FileOffset;
    PVOID Context = NULL;
    PFATX_DIR_ENTRY FatXDirEntry;
    ULONG Index = 0, MaxIndex;
    NTSTATUS Status;

    FileOffset.QuadPart = 0;
    MaxIndex = Fcb->Base.FileSize.LowPart / sizeof(FATX_DIR_ENTRY);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    while (Index < MaxIndex) {
	if (Context == NULL || (Index % FATX_ENTRIES_PER_PAGE) == 0) {
	    if (Context != NULL) {
		CcUnpinData(Context);
	    }

	    Status = CcMapData(Fcb->FileObject, &FileOffset,
			       sizeof(FATX_DIR_ENTRY), MAP_WAIT, &Context,
			       (PVOID *)&FatXDirEntry);
	    if (!NT_SUCCESS(Status)) {
		return TRUE;
	    }

	    FatXDirEntry += Index % FATX_ENTRIES_PER_PAGE;
	    FileOffset.QuadPart += PAGE_SIZE;
	}

	if (FATX_ENTRY_END(FatXDirEntry)) {
	    CcUnpinData(Context);
	    return TRUE;
	}

	if (!FATX_ENTRY_DELETED(FatXDirEntry)) {
	    CcUnpinData(Context);
	    return FALSE;
	}

	Index++;
	FatXDirEntry++;
    }

    if (Context) {
	CcUnpinData(Context);
    }

    return TRUE;
}

static NTSTATUS GetNextDirEntry(PVOID *pContext, PVOID *pPage, IN PFATFCB DirFcb,
				PFAT_DIRENTRY_CONTEXT DirContext, BOOLEAN First)
{
    LARGE_INTEGER FileOffset;
    PFATX_DIR_ENTRY FatXDirEntry;
    OEM_STRING StringO;
    ULONG DirIndex = DirContext->DirIndex;
    NTSTATUS Status;

    FileOffset.HighPart = 0;

    UNREFERENCED_PARAMETER(First);

    if (!FatFcbIsRoot(DirFcb)) {
	/* need to add . and .. entries */
	switch (DirContext->DirIndex) {
	case 0:		/* entry . */
	    wcscpy_s(DirContext->LongNameU.Buffer, sizeof(WCHAR), L".");
	    DirContext->LongNameU.Length = sizeof(WCHAR);
	    DirContext->ShortNameU = DirContext->LongNameU;
	    RtlCopyMemory(&DirContext->DirEntry.FatX, &DirFcb->Entry.FatX,
			  sizeof(FATX_DIR_ENTRY));
	    DirContext->DirEntry.FatX.Filename[0] = '.';
	    DirContext->DirEntry.FatX.FilenameLength = 1;
	    DirContext->StartIndex = 0;
	    return STATUS_SUCCESS;

	case 1:		/* entry .. */
	    wcscpy_s(DirContext->LongNameU.Buffer, 2 * sizeof(WCHAR), L"..");
	    DirContext->LongNameU.Length = 2 * sizeof(WCHAR);
	    DirContext->ShortNameU = DirContext->LongNameU;
	    RtlCopyMemory(&DirContext->DirEntry.FatX, &DirFcb->Entry.FatX,
			  sizeof(FATX_DIR_ENTRY));
	    DirContext->DirEntry.FatX.Filename[0] =
		DirContext->DirEntry.FatX.Filename[1] = '.';
	    DirContext->DirEntry.FatX.FilenameLength = 2;
	    DirContext->StartIndex = 1;
	    return STATUS_SUCCESS;

	default:
	    DirIndex -= 2;
	}
    }

    Status = FatFcbInitializeCacheFromVolume(DirContext->DeviceExt, DirFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (*pContext == NULL || (DirIndex % FATX_ENTRIES_PER_PAGE) == 0) {
	if (*pContext != NULL) {
	    CcUnpinData(*pContext);
	}
	FileOffset.LowPart = ROUND_DOWN(DirIndex * sizeof(FATX_DIR_ENTRY), PAGE_SIZE);
	if (FileOffset.LowPart >= DirFcb->Base.FileSize.LowPart) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}

	Status = CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
			   MAP_WAIT, pContext, pPage);
	if (!NT_SUCCESS(Status)) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}
    }

    FatXDirEntry = (PFATX_DIR_ENTRY)(*pPage) + DirIndex % FATX_ENTRIES_PER_PAGE;

    DirContext->StartIndex = DirContext->DirIndex;

    while (TRUE) {
	if (FATX_ENTRY_END(FatXDirEntry)) {
	    CcUnpinData(*pContext);
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}

	if (!FATX_ENTRY_DELETED(FatXDirEntry)) {
	    RtlCopyMemory(&DirContext->DirEntry.FatX, FatXDirEntry,
			  sizeof(FATX_DIR_ENTRY));
	    break;
	}
	DirContext->DirIndex++;
	DirContext->StartIndex++;
	DirIndex++;
	if ((DirIndex % FATX_ENTRIES_PER_PAGE) == 0) {
	    CcUnpinData(*pContext);
	    FileOffset.LowPart += PAGE_SIZE;
	    if (FileOffset.LowPart >= DirFcb->Base.FileSize.LowPart) {
		*pContext = NULL;
		return STATUS_NO_MORE_ENTRIES;
	    }

	    Status = CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
			       MAP_WAIT, pContext, pPage);
	    if (!NT_SUCCESS(Status)) {
		*pContext = NULL;
		return STATUS_NO_MORE_ENTRIES;
	    }

	    FatXDirEntry = (PFATX_DIR_ENTRY)*pPage;
	} else {
	    FatXDirEntry++;
	}
    }
    StringO.Buffer = (PCHAR)FatXDirEntry->Filename;
    StringO.Length = StringO.MaximumLength = FatXDirEntry->FilenameLength;
    RtlOemStringToUnicodeString(&DirContext->LongNameU, &StringO, FALSE);
    DirContext->ShortNameU = DirContext->LongNameU;
    return STATUS_SUCCESS;
}

FAT_DISPATCH FatXDispatch = {
    .IsDirectoryEmpty = IsDirectoryEmpty,
    .AddEntry = AddEntry,
    .DelEntry = DelEntry,
    .GetNextDirEntry = GetNextDirEntry
};
