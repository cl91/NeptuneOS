/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Routines to manipulate Fat12/16/32 (non-FatX) directory entries
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
    PFAT_DIR_ENTRY pFatEntry;
    PSLOT pSlots;
    USHORT NumSlots = 0, j;
    PUCHAR Buffer;
    BOOLEAN needTilde = FALSE, NeedLong = FALSE;
    BOOLEAN BaseAllLower, BaseAllUpper;
    BOOLEAN ExtensionAllLower, ExtensionAllUpper;
    BOOLEAN InExtension;
    BOOLEAN IsDirectory;
    WCHAR c;
    ULONG CurrentCluster;
    LARGE_INTEGER SystemTime, FileOffset;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Size;
    long i;

    OEM_STRING NameA;
    CHAR aName[13];
    BOOLEAN IsNameLegal;
    BOOLEAN SpacesFound;

    FAT_DIRENTRY_CONTEXT DirContext;
    WCHAR LongNameBuffer[LONGNAME_MAX_LENGTH + 1];
    WCHAR ShortNameBuffer[13];

    DPRINT("AddEntry: Name='%wZ', Dir='%wZ'\n", NameU,
	   &ParentFcb->PathNameU);

    DirContext.LongNameU = *NameU;
    IsDirectory = BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE);

    /* nb of entry needed for long name+normal entry */
    NumSlots = (DirContext.LongNameU.Length / sizeof(WCHAR) + 12) / 13 + 1;
    DPRINT("NameLen= 0x%zx, NumSlots =%u\n",
	   DirContext.LongNameU.Length / sizeof(WCHAR), NumSlots);
    Buffer = ExAllocatePoolWithTag((NumSlots - 1) * sizeof(FAT_DIR_ENTRY),
				   TAG_DIRENT);
    if (Buffer == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Buffer, (NumSlots - 1) * sizeof(FAT_DIR_ENTRY));
    pSlots = (PSLOT)Buffer;

    NameA.Buffer = aName;
    NameA.Length = 0;
    NameA.MaximumLength = sizeof(aName);

    DirContext.DeviceExt = DeviceExt;
    DirContext.ShortNameU.Buffer = ShortNameBuffer;
    DirContext.ShortNameU.Length = 0;
    DirContext.ShortNameU.MaximumLength = sizeof(ShortNameBuffer);

    RtlZeroMemory(&DirContext.DirEntry.Fat, sizeof(FAT_DIR_ENTRY));

    IsNameLegal = RtlIsNameLegalDOS8Dot3(&DirContext.LongNameU, &NameA,
					 &SpacesFound);

    if (!IsNameLegal || SpacesFound) {
	GENERATE_NAME_CONTEXT NameContext;
	FAT_DIRENTRY_CONTEXT SearchContext;
	WCHAR ShortSearchName[13];
	needTilde = TRUE;
	NeedLong = TRUE;
	RtlZeroMemory(&NameContext, sizeof(GENERATE_NAME_CONTEXT));
	SearchContext.DeviceExt = DeviceExt;
	SearchContext.LongNameU.Buffer = LongNameBuffer;
	SearchContext.LongNameU.MaximumLength = sizeof(LongNameBuffer);
	SearchContext.ShortNameU.Buffer = ShortSearchName;
	SearchContext.ShortNameU.MaximumLength = sizeof(ShortSearchName);

	for (i = 0; i < 100; i++) {
	    RtlGenerate8dot3Name(&DirContext.LongNameU, FALSE,
				 &NameContext, &DirContext.ShortNameU);
	    DirContext.ShortNameU.Buffer[DirContext.ShortNameU.Length /
					 sizeof(WCHAR)] = 0;
	    SearchContext.DirIndex = 0;
	    Status = FindFile(DeviceExt, ParentFcb, &DirContext.ShortNameU,
			      &SearchContext, TRUE);
	    if (!NT_SUCCESS(Status)) {
		break;
	    } else if (MoveContext) {
		ASSERT(*Fcb);
		if (strncmp((char *)SearchContext.DirEntry.Fat.ShortName,
			    (char *)(*Fcb)->Entry.Fat.ShortName, 11) == 0) {
		    if (MoveContext->InPlace) {
			ASSERT(SearchContext.DirEntry.Fat.FileSize ==
			       MoveContext->FileSize);
			break;
		    }
		}
	    }
	}
	if (i == 100) {		/* FIXME : what to do after this ? */
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return STATUS_UNSUCCESSFUL;
	}
	IsNameLegal = RtlIsNameLegalDOS8Dot3(&DirContext.ShortNameU, &NameA,
					     &SpacesFound);
    } else {
	BaseAllLower = BaseAllUpper = TRUE;
	ExtensionAllLower = ExtensionAllUpper = TRUE;
	InExtension = FALSE;
	for (i = 0; i < DirContext.LongNameU.Length / sizeof(WCHAR); i++) {
	    c = DirContext.LongNameU.Buffer[i];
	    if (c >= L'A' && c <= L'Z') {
		if (InExtension)
		    ExtensionAllLower = FALSE;
		else
		    BaseAllLower = FALSE;
	    } else if (c >= L'a' && c <= L'z') {
		if (InExtension)
		    ExtensionAllUpper = FALSE;
		else
		    BaseAllUpper = FALSE;
	    } else if (c > 0x7f) {
		NeedLong = TRUE;
		break;
	    }

	    if (c == L'.') {
		InExtension = TRUE;
	    }
	}

	if ((!BaseAllLower && !BaseAllUpper) ||
	    (!ExtensionAllLower && !ExtensionAllUpper)) {
	    NeedLong = TRUE;
	}

	RtlUpcaseUnicodeString(&DirContext.ShortNameU,
			       &DirContext.LongNameU, FALSE);
	DirContext.ShortNameU.Buffer[DirContext.ShortNameU.Length / sizeof(WCHAR)] = 0;
    }
    aName[NameA.Length] = 0;
    DPRINT("'%s', '%wZ', needTilde=%u, NeedLong=%u\n",
	   aName, &DirContext.LongNameU, needTilde, NeedLong);
    memset(DirContext.DirEntry.Fat.ShortName, ' ', 11);
    for (i = 0; i < 8 && aName[i] && aName[i] != '.'; i++) {
	DirContext.DirEntry.Fat.Filename[i] = aName[i];
    }
    if (aName[i] == '.') {
	i++;
	for (j = 0; j < 3 && aName[i]; j++, i++) {
	    DirContext.DirEntry.Fat.Ext[j] = aName[i];
	}
    }
    if (DirContext.DirEntry.Fat.Filename[0] == 0xe5) {
	DirContext.DirEntry.Fat.Filename[0] = 0x05;
    }

    if (NeedLong) {
	RtlCopyMemory(LongNameBuffer, DirContext.LongNameU.Buffer,
		      DirContext.LongNameU.Length);
	DirContext.LongNameU.Buffer = LongNameBuffer;
	DirContext.LongNameU.MaximumLength = sizeof(LongNameBuffer);
	DirContext.LongNameU.Buffer[DirContext.LongNameU.Length / sizeof(WCHAR)] = 0;
	memset(DirContext.LongNameU.Buffer +
	       DirContext.LongNameU.Length / sizeof(WCHAR) + 1, 0xff,
	       DirContext.LongNameU.MaximumLength -
	       DirContext.LongNameU.Length - sizeof(WCHAR));
    } else {
	NumSlots = 1;
	if (BaseAllLower && !BaseAllUpper) {
	    DirContext.DirEntry.Fat.Case |= FAT_CASE_LOWER_BASE;
	}
	if (ExtensionAllLower && !ExtensionAllUpper) {
	    DirContext.DirEntry.Fat.Case |= FAT_CASE_LOWER_EXT;
	}
    }

    DPRINT("dos name=%11.11s\n", DirContext.DirEntry.Fat.Filename);

    /* Set attributes */
    DirContext.DirEntry.Fat.Attrib = ReqAttr;
    if (IsDirectory) {
	DirContext.DirEntry.Fat.Attrib |= FILE_ATTRIBUTE_DIRECTORY;
    }

    /* Set dates and times */
    NtQuerySystemTime(&SystemTime);
    FsdSystemTimeToDosDateTime(DeviceExt, &SystemTime,
			       &DirContext.DirEntry.Fat.CreationDate,
			       &DirContext.DirEntry.Fat.CreationTime);
    DirContext.DirEntry.Fat.UpdateDate = DirContext.DirEntry.Fat.CreationDate;
    DirContext.DirEntry.Fat.UpdateTime = DirContext.DirEntry.Fat.CreationTime;
    DirContext.DirEntry.Fat.AccessDate = DirContext.DirEntry.Fat.CreationDate;

    /* If it's moving, preserve creation time and file size */
    if (MoveContext != NULL) {
	DirContext.DirEntry.Fat.CreationDate = MoveContext->CreationDate;
	DirContext.DirEntry.Fat.CreationTime = MoveContext->CreationTime;
	DirContext.DirEntry.Fat.FileSize = MoveContext->FileSize;
    }

    if (NeedLong) {
	/* Calculate checksum for 8.3 name */
	for (pSlots[0].AliasChecksum = 0, i = 0; i < 11; i++) {
	    pSlots[0].AliasChecksum =
		((pSlots[0].AliasChecksum & 1) << 7 | ((pSlots[0].AliasChecksum & 0xfe) >> 1))
		+ DirContext.DirEntry.Fat.ShortName[i];
	}
	/* construct slots and entry */
	for (i = NumSlots - 2; i >= 0; i--) {
	    DPRINT("construct slot %ld\n", i);
	    pSlots[i].Attr = 0xf;
	    if (i) {
		pSlots[i].Id = (UCHAR)(NumSlots - i - 1);
	    } else {
		pSlots[i].Id = (UCHAR)(NumSlots - i - 1 + 0x40);
	    }
	    pSlots[i].AliasChecksum = pSlots[0].AliasChecksum;
	    RtlCopyMemory(pSlots[i].Name0_4,
			  DirContext.LongNameU.Buffer + (NumSlots-i-2)*13, 10);
	    RtlCopyMemory(pSlots[i].Name5_10,
			  DirContext.LongNameU.Buffer + (NumSlots-i-2)*13 + 5, 12);
	    RtlCopyMemory(pSlots[i].Name11_12,
			  DirContext.LongNameU.Buffer + (NumSlots-i-2)*13 + 11, 4);
	}
    }
    /* try to find NumSlots contiguous entries frees in directory */
    if (!FatFindDirSpace(DeviceExt, ParentFcb, NumSlots, &DirContext.StartIndex)) {
	ExFreePoolWithTag(Buffer, TAG_DIRENT);
	return STATUS_DISK_FULL;
    }
    DirContext.DirIndex = DirContext.StartIndex + NumSlots - 1;
    if (IsDirectory) {
	/* If we aren't moving, use next */
	if (MoveContext == NULL) {
	    CurrentCluster = 0;
	    Status = NextCluster(DeviceExt, 0, &CurrentCluster, TRUE);
	    if (CurrentCluster == 0xffffffff || !NT_SUCCESS(Status)) {
		ExFreePoolWithTag(Buffer, TAG_DIRENT);
		if (!NT_SUCCESS(Status)) {
		    return Status;
		}
		return STATUS_DISK_FULL;
	    }

	    if (DeviceExt->FatInfo.FatType == FAT32) {
		Fat32UpdateFreeClustersCount(DeviceExt);
	    }
	} else {
	    CurrentCluster = MoveContext->FirstCluster;
	}

	if (DeviceExt->FatInfo.FatType == FAT32) {
	    DirContext.DirEntry.Fat.FirstClusterHigh = (USHORT)(CurrentCluster >> 16);
	}
	DirContext.DirEntry.Fat.FirstCluster = (USHORT)CurrentCluster;
    } else if (MoveContext != NULL) {
	CurrentCluster = MoveContext->FirstCluster;

	if (DeviceExt->FatInfo.FatType == FAT32) {
	    DirContext.DirEntry.Fat.FirstClusterHigh = (USHORT)(CurrentCluster >> 16);
	}
	DirContext.DirEntry.Fat.FirstCluster = (USHORT)CurrentCluster;
    }

    /* No need to init cache here, FatFindDirSpace() will have done it for us */
    ASSERT(BooleanFlagOn(ParentFcb->Flags, FCB_CACHE_INITIALIZED));

    i = DeviceExt->FatInfo.BytesPerCluster / sizeof(FAT_DIR_ENTRY);
    FileOffset.u.HighPart = 0;
    FileOffset.u.LowPart = DirContext.StartIndex * sizeof(FAT_DIR_ENTRY);
    if (DirContext.StartIndex / i == DirContext.DirIndex / i) {
	/* one cluster */
	Status = CcPinRead(ParentFcb->FileObject, &FileOffset,
			   NumSlots * sizeof(FAT_DIR_ENTRY), PIN_WAIT, &Context,
			   (PVOID *)&pFatEntry);
	if (!NT_SUCCESS(Status)) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return Status;
	}


	if (NumSlots > 1) {
	    RtlCopyMemory(pFatEntry, Buffer,
			  (NumSlots - 1) * sizeof(FAT_DIR_ENTRY));
	}
	RtlCopyMemory(pFatEntry + (NumSlots - 1), &DirContext.DirEntry.Fat,
		      sizeof(FAT_DIR_ENTRY));
    } else {
	/* two clusters */
	Size = DeviceExt->FatInfo.BytesPerCluster -
	    (DirContext.StartIndex * sizeof(FAT_DIR_ENTRY)) %
	    DeviceExt->FatInfo.BytesPerCluster;
	i = Size / sizeof(FAT_DIR_ENTRY);
	Status = CcPinRead(ParentFcb->FileObject, &FileOffset, Size, PIN_WAIT,
			   &Context, (PVOID *)&pFatEntry);
	if (!NT_SUCCESS(Status)) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return Status;
	}

	RtlCopyMemory(pFatEntry, Buffer, Size);
	CcSetDirtyPinnedData(Context, NULL);
	CcUnpinData(Context);
	FileOffset.LowPart += Size;
	Status = CcPinRead(ParentFcb->FileObject, &FileOffset,
			   NumSlots * sizeof(FAT_DIR_ENTRY) - Size, PIN_WAIT,
			   &Context, (PVOID *)&pFatEntry);
	if (!NT_SUCCESS(Status)) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return Status;
	}

	if (NumSlots - 1 > i) {
	    RtlCopyMemory(pFatEntry, (PVOID) (Buffer + Size),
			  (NumSlots - 1 - i) * sizeof(FAT_DIR_ENTRY));
	}
	RtlCopyMemory(pFatEntry + NumSlots - 1 - i,
		      &DirContext.DirEntry.Fat, sizeof(FAT_DIR_ENTRY));
    }
    CcSetDirtyPinnedData(Context, NULL);
    CcUnpinData(Context);

    if (MoveContext != NULL) {
	/* We're modifying an existing FCB - likely rename/move */
	Status = FatUpdateFcb(DeviceExt, *Fcb, &DirContext, ParentFcb);
    } else {
	Status =
	    FatMakeFcbFromDirEntry(DeviceExt, ParentFcb, &DirContext, Fcb);
    }
    if (!NT_SUCCESS(Status)) {
	ExFreePoolWithTag(Buffer, TAG_DIRENT);
	return Status;
    }

    DPRINT("new : entry=%11.11s\n", (*Fcb)->Entry.Fat.Filename);
    DPRINT("new : entry=%11.11s\n", DirContext.DirEntry.Fat.Filename);

    if (IsDirectory) {
	Status = FatFcbInitializeCacheFromVolume(DeviceExt, (*Fcb));
	if (!NT_SUCCESS(Status)) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return Status;
	}

	FileOffset.QuadPart = 0;
	Status = CcPinRead((*Fcb)->FileObject, &FileOffset,
			   DeviceExt->FatInfo.BytesPerCluster, PIN_WAIT,
			   &Context, (PVOID *)&pFatEntry);
	if (!NT_SUCCESS(Status)) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return Status;
	}

	/* clear the new directory cluster if not moving */
	if (MoveContext == NULL) {
	    RtlZeroMemory(pFatEntry, DeviceExt->FatInfo.BytesPerCluster);
	    /* create '.' and '..' */
	    pFatEntry[0] = DirContext.DirEntry.Fat;
	    RtlCopyMemory(pFatEntry[0].ShortName, ".          ", 11);
	    pFatEntry[1] = DirContext.DirEntry.Fat;
	    RtlCopyMemory(pFatEntry[1].ShortName, "..         ", 11);
	}

	pFatEntry[1].FirstCluster = ParentFcb->Entry.Fat.FirstCluster;
	pFatEntry[1].FirstClusterHigh =
	    ParentFcb->Entry.Fat.FirstClusterHigh;
	if (FatFcbIsRoot(ParentFcb)) {
	    pFatEntry[1].FirstCluster = 0;
	    pFatEntry[1].FirstClusterHigh = 0;
	}
	CcSetDirtyPinnedData(Context, NULL);
	CcUnpinData(Context);
    }
    ExFreePoolWithTag(Buffer, TAG_DIRENT);
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
    PFAT_DIR_ENTRY pDirEntry = NULL;
    NTSTATUS Status;

    ASSERT(Fcb);
    ASSERT(Fcb->ParentFcb);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb->ParentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("delEntry PathName \'%wZ\'\n", &Fcb->PathNameU);
    DPRINT("delete entry: %u to %u\n", Fcb->StartIndex, Fcb->DirIndex);
    Offset.u.HighPart = 0;
    for (ULONG i = Fcb->StartIndex; i <= Fcb->DirIndex; i++) {
	if (Context == NULL || ((i * sizeof(FAT_DIR_ENTRY)) % PAGE_SIZE) == 0) {
	    if (Context) {
		CcSetDirtyPinnedData(Context, NULL);
		CcUnpinData(Context);
	    }
	    Offset.LowPart = (i * sizeof(FAT_DIR_ENTRY) / PAGE_SIZE) * PAGE_SIZE;
	    Status = CcPinRead(Fcb->ParentFcb->FileObject, &Offset, PAGE_SIZE,
			       PIN_WAIT, &Context, (PVOID *)&pDirEntry);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	}
	pDirEntry[i % (PAGE_SIZE / sizeof(FAT_DIR_ENTRY))].Filename[0] = 0xe5;
	if (i == Fcb->DirIndex) {
	    ULONG Idx = i % (PAGE_SIZE / sizeof(FAT_DIR_ENTRY));
	    CurrentCluster = FatDirEntryGetFirstCluster(DeviceExt,
							(PDIR_ENTRY)&pDirEntry[Idx]);
	}
    }

    /* In case of moving, save properties */
    if (MoveContext != NULL) {
	pDirEntry = &pDirEntry[Fcb->DirIndex % (PAGE_SIZE / sizeof(FAT_DIR_ENTRY))];
	MoveContext->FirstCluster = CurrentCluster;
	MoveContext->FileSize = pDirEntry->FileSize;
	MoveContext->CreationTime = pDirEntry->CreationTime;
	MoveContext->CreationDate = pDirEntry->CreationDate;
    }

    if (Context) {
	CcSetDirtyPinnedData(Context, NULL);
	CcUnpinData(Context);
    }

    /* In case of moving, don't delete data */
    if (MoveContext == NULL) {
	while (CurrentCluster && CurrentCluster != 0xffffffff) {
	    GetNextCluster(DeviceExt, CurrentCluster, &NextCluster);
	    /* FIXME: check status */
	    WriteCluster(DeviceExt, CurrentCluster, 0);
	    CurrentCluster = NextCluster;
	}

	if (DeviceExt->FatInfo.FatType == FAT32) {
	    Fat32UpdateFreeClustersCount(DeviceExt);
	}
    }

    return STATUS_SUCCESS;
}

static BOOLEAN IsDirectoryEmpty(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb)
{
    LARGE_INTEGER FileOffset;
    PVOID Context = NULL;
    PFAT_DIR_ENTRY FatDirEntry;
    ULONG Index, MaxIndex;
    NTSTATUS Status;

    if (FatFcbIsRoot(Fcb)) {
	Index = 0;
    } else {
	Index = 2;
    }

    FileOffset.QuadPart = 0;
    MaxIndex = Fcb->Base.FileSize.LowPart / sizeof(FAT_DIR_ENTRY);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    while (Index < MaxIndex) {
	if (Context == NULL || (Index % FAT_ENTRIES_PER_PAGE) == 0) {
	    if (Context != NULL) {
		CcUnpinData(Context);
	    }

	    Status = CcMapData(Fcb->FileObject, &FileOffset, sizeof(FAT_DIR_ENTRY),
			       MAP_WAIT, &Context, (PVOID *)&FatDirEntry);
	    if (!NT_SUCCESS(Status)) {
		return TRUE;
	    }

	    FatDirEntry += Index % FAT_ENTRIES_PER_PAGE;
	    FileOffset.QuadPart += PAGE_SIZE;
	}

	if (FAT_ENTRY_END(FatDirEntry)) {
	    CcUnpinData(Context);
	    return TRUE;
	}

	if (!FAT_ENTRY_DELETED(FatDirEntry)) {
	    CcUnpinData(Context);
	    return FALSE;
	}

	Index++;
	FatDirEntry++;
    }

    if (Context) {
	CcUnpinData(Context);
    }

    return TRUE;
}

static NTSTATUS GetNextDirEntry(OUT PVOID *pContext,
				OUT PVOID *pPage,
				IN PFATFCB DirFcb,
				IN PFAT_DIRENTRY_CONTEXT DirContext,
				IN BOOLEAN First)
{
    ULONG DirMap;
    PWCHAR Name;
    LARGE_INTEGER FileOffset;
    PFAT_DIR_ENTRY FatDirEntry;
    PSLOT LongNameEntry;
    ULONG Index;

    UCHAR CheckSum, ShortCheckSum;
    USHORT i;
    BOOLEAN Valid = TRUE;
    BOOLEAN Back = FALSE;

    DirContext->LongNameU.Length = 0;
    DirContext->LongNameU.Buffer[0] = UNICODE_NULL;

    FileOffset.HighPart = 0;
    FileOffset.LowPart = ROUND_DOWN(DirContext->DirIndex * sizeof(FAT_DIR_ENTRY),
				    PAGE_SIZE);

    NTSTATUS Status = FatFcbInitializeCacheFromVolume(DirContext->DeviceExt, DirFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (!(*pContext) || !(DirContext->DirIndex % FAT_ENTRIES_PER_PAGE)) {
	if (*pContext) {
	    CcUnpinData(*pContext);
	}

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

    FatDirEntry = (PFAT_DIR_ENTRY)(*pPage) + DirContext->DirIndex % FAT_ENTRIES_PER_PAGE;
    LongNameEntry = (PSLOT)FatDirEntry;
    DirMap = 0;

    if (First) {
	/* This is the first call to FatGetNextDirEntry. Possibly the start Index points
	 * into a long name or points to a short name with an assigned long name.
	 * We must go back to the real start of the entry */
	while (DirContext->DirIndex > 0 && !FAT_ENTRY_END(FatDirEntry) &&
	       !FAT_ENTRY_DELETED(FatDirEntry) && ((!FAT_ENTRY_LONG(FatDirEntry) && !Back) ||
						   (FAT_ENTRY_LONG(FatDirEntry)
						    && !(LongNameEntry->Id & 0x40)))) {
	    DirContext->DirIndex--;
	    Back = TRUE;

	    if ((DirContext->DirIndex % FAT_ENTRIES_PER_PAGE) == FAT_ENTRIES_PER_PAGE - 1) {
		CcUnpinData(*pContext);
		FileOffset.LowPart -= PAGE_SIZE;

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

		FatDirEntry = (PFAT_DIR_ENTRY)(*pPage) + DirContext->DirIndex % FAT_ENTRIES_PER_PAGE;
		LongNameEntry = (PSLOT)FatDirEntry;
	    } else {
		FatDirEntry--;
		LongNameEntry--;
	    }
	}

	if (Back && !FAT_ENTRY_END(FatDirEntry) &&
	    (FAT_ENTRY_DELETED(FatDirEntry) || !FAT_ENTRY_LONG(FatDirEntry))) {
	    DirContext->DirIndex++;

	    if ((DirContext->DirIndex % FAT_ENTRIES_PER_PAGE) == 0) {
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

		FatDirEntry = (PFAT_DIR_ENTRY)(*pPage);
		LongNameEntry = (PSLOT)(*pPage);
	    } else {
		FatDirEntry++;
		LongNameEntry++;
	    }
	}
    }

    DirContext->StartIndex = DirContext->DirIndex;
    CheckSum = 0;

    while (TRUE) {
	if (FAT_ENTRY_END(FatDirEntry)) {
	    CcUnpinData(*pContext);
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}

	if (FAT_ENTRY_DELETED(FatDirEntry)) {
	    DirMap = 0;
	    DirContext->LongNameU.Buffer[0] = 0;
	    DirContext->StartIndex = DirContext->DirIndex + 1;
	} else {
	    if (FAT_ENTRY_LONG(FatDirEntry)) {
		if (DirMap == 0) {
		    DPRINT("  long name entry found at %u\n",
			   DirContext->DirIndex);
		    RtlZeroMemory(DirContext->LongNameU.Buffer,
				  DirContext->LongNameU.MaximumLength);
		    CheckSum = LongNameEntry->AliasChecksum;
		    Valid = TRUE;
		}

		DPRINT("  name chunk1:[%c%c%c%c%c] chunk2:[%c%c%c%c%c%c] chunk3:[%c%c]\n",
		       LongNameEntry->Name0_4[0], LongNameEntry->Name0_4[1],
		       LongNameEntry->Name0_4[2], LongNameEntry->Name0_4[3],
		       LongNameEntry->Name0_4[4], LongNameEntry->Name5_10[0],
		       LongNameEntry->Name5_10[1], LongNameEntry->Name5_10[2],
		       LongNameEntry->Name5_10[3], LongNameEntry->Name5_10[4],
		       LongNameEntry->Name5_10[5], LongNameEntry->Name11_12[0],
		       LongNameEntry->Name11_12[1]);

		Index = LongNameEntry->Id & 0x3f;	// Note: it can be 0 for corrupted FS

		/* Make sure Index is valid and we have enough space in buffer
		   (we count one char for \0) */
		if (Index > 0 &&
		    Index * 13 <
		    DirContext->LongNameU.MaximumLength / sizeof(WCHAR)) {
		    Index--;	// make Index 0 based
		    DirMap |= 1 << Index;

		    Name = DirContext->LongNameU.Buffer + Index * 13;
		    RtlCopyMemory(Name, LongNameEntry->Name0_4, 5 * sizeof(WCHAR));
		    RtlCopyMemory(Name + 5, LongNameEntry->Name5_10, 6 * sizeof(WCHAR));
		    RtlCopyMemory(Name + 11, LongNameEntry->Name11_12, 2 * sizeof(WCHAR));

		    if (LongNameEntry->Id & 0x40) {
			/* It's last LFN entry. Terminate filename with \0 */
			Name[13] = UNICODE_NULL;
		    }
		} else
		    DPRINT1("Long name entry has invalid Index: %x!\n",
			    LongNameEntry->Id);

		DPRINT("  LongName: [%S]\n", DirContext->LongNameU.Buffer);

		if (CheckSum != LongNameEntry->AliasChecksum) {
		    DPRINT1("Found wrong alias checksum in long name entry (first %x, current %x, %S)\n",
			    CheckSum, LongNameEntry->AliasChecksum,
			    DirContext->LongNameU.Buffer);
		    Valid = FALSE;
		}
	    } else {
		ShortCheckSum = 0;
		for (i = 0; i < 11; i++) {
		    ShortCheckSum = (((ShortCheckSum & 1) << 7)
				     | ((ShortCheckSum & 0xfe) >> 1))
			+ FatDirEntry->ShortName[i];
		}

		if (ShortCheckSum != CheckSum && DirContext->LongNameU.Buffer[0]) {
		    DPRINT1("Checksum from long and short name is not equal (short: %x, long: %x, %S)\n",
			    ShortCheckSum, CheckSum,
			    DirContext->LongNameU.Buffer);
		    DirContext->LongNameU.Buffer[0] = 0;
		}

		if (Valid == FALSE) {
		    DirContext->LongNameU.Buffer[0] = 0;
		}

		RtlCopyMemory(&DirContext->DirEntry.Fat, FatDirEntry,
			      sizeof(FAT_DIR_ENTRY));
		break;
	    }
	}

	DirContext->DirIndex++;

	if ((DirContext->DirIndex % FAT_ENTRIES_PER_PAGE) == 0) {
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

	    FatDirEntry = (PFAT_DIR_ENTRY)(*pPage);
	    LongNameEntry = (PSLOT)(*pPage);
	} else {
	    FatDirEntry++;
	    LongNameEntry++;
	}
    }

    /* Make sure filename is NULL terminate and calculate length */
    DirContext->LongNameU.Buffer[DirContext->LongNameU.MaximumLength/sizeof(WCHAR) - 1]
	= UNICODE_NULL;
    DirContext->LongNameU.Length =
	wcslen(DirContext->LongNameU.Buffer) * sizeof(WCHAR);

    /* Init short name */
    Fat8Dot3ToString(&DirContext->DirEntry.Fat, &DirContext->ShortNameU);

    /* If we found no LFN, use short name as long */
    if (DirContext->LongNameU.Length == 0)
	RtlCopyUnicodeString(&DirContext->LongNameU, &DirContext->ShortNameU);

    return STATUS_SUCCESS;
}

FAT_DISPATCH FatDispatch = {
    .IsDirectoryEmpty = IsDirectoryEmpty,
    .AddEntry = AddEntry,
    .DelEntry = DelEntry,
    .GetNextDirEntry = GetNextDirEntry
};
