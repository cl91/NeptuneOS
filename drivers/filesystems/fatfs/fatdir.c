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
    PSLOT Slots;
    USHORT NumSlots = 0;
    BOOLEAN needTilde = FALSE, NeedLong = FALSE;
    BOOLEAN BaseAllLower, BaseAllUpper;
    BOOLEAN ExtensionAllLower, ExtensionAllUpper;
    BOOLEAN InExtension;
    BOOLEAN IsDirectory;
    WCHAR c;
    ULONG CurrentCluster;
    NTSTATUS Status = STATUS_SUCCESS;

    OEM_STRING NameA;
    CHAR Name[13];
    BOOLEAN IsNameLegal;
    BOOLEAN SpacesFound;

    FAT_DIRENTRY_CONTEXT DirContext;
    WCHAR LongNameBuffer[LONGNAME_MAX_LENGTH + 1];
    WCHAR ShortNameBuffer[13];

    DPRINT("AddEntry: Name='%wZ', Dir='%wZ'\n", NameU,
	   &ParentFcb->PathNameU);

    DirContext.LongNameU = *NameU;
    IsDirectory = BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE);

    /* Number of entry needed for long name+normal entry */
    NumSlots = (DirContext.LongNameU.Length / sizeof(WCHAR) + 12) / 13 + 1;
    DPRINT("NameLen = 0x%zx, NumSlots = %u\n",
	   DirContext.LongNameU.Length / sizeof(WCHAR), NumSlots);
    PFAT_DIR_ENTRY Buffer = ExAllocatePoolWithTag(NonPagedPool,
						  NumSlots * sizeof(FAT_DIR_ENTRY),
						  TAG_DIRENT);
    if (!Buffer) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    Slots = (PSLOT)Buffer;

    NameA.Buffer = Name;
    NameA.Length = 0;
    NameA.MaximumLength = sizeof(Name);

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

	ULONG i;
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
	for (ULONG i = 0; i < DirContext.LongNameU.Length / sizeof(WCHAR); i++) {
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
    Name[NameA.Length] = 0;
    DPRINT("'%s', '%wZ', needTilde=%u, NeedLong=%u\n",
	   Name, &DirContext.LongNameU, needTilde, NeedLong);
    memset(DirContext.DirEntry.Fat.ShortName, ' ', 11);

    ULONG i;
    for (i = 0; i < 8 && Name[i] && Name[i] != '.'; i++) {
	DirContext.DirEntry.Fat.Filename[i] = Name[i];
    }
    if (Name[i] == '.') {
	i++;
	for (ULONG j = 0; j < 3 && Name[i]; j++, i++) {
	    DirContext.DirEntry.Fat.Ext[j] = Name[i];
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

    DPRINT("DOS Name = %11.11s\n", DirContext.DirEntry.Fat.Filename);

    /* Set attributes */
    DirContext.DirEntry.Fat.Attrib = ReqAttr;
    if (IsDirectory) {
	DirContext.DirEntry.Fat.Attrib |= FILE_ATTRIBUTE_DIRECTORY;
    }

    /* Set dates and times */
    LARGE_INTEGER SystemTime;
    NtQuerySystemTime(&SystemTime);
    FsdSystemTimeToDosDateTime(DeviceExt, &SystemTime,
			       &DirContext.DirEntry.Fat.CreationDate,
			       &DirContext.DirEntry.Fat.CreationTime);
    DirContext.DirEntry.Fat.UpdateDate = DirContext.DirEntry.Fat.CreationDate;
    DirContext.DirEntry.Fat.UpdateTime = DirContext.DirEntry.Fat.CreationTime;
    DirContext.DirEntry.Fat.AccessDate = DirContext.DirEntry.Fat.CreationDate;

    /* If it's moving, preserve creation time and file size */
    if (MoveContext) {
	DirContext.DirEntry.Fat.CreationDate = MoveContext->CreationDate;
	DirContext.DirEntry.Fat.CreationTime = MoveContext->CreationTime;
	DirContext.DirEntry.Fat.FileSize = MoveContext->FileSize;
    }

    if (NeedLong) {
	/* Calculate checksum for 8.3 name */
	Slots[0].AliasChecksum = 0;
	for (ULONG i = 0; i < 11; i++) {
	    Slots[0].AliasChecksum =
		((Slots[0].AliasChecksum & 1) << 7 | ((Slots[0].AliasChecksum & 0xfe) >> 1))
		+ DirContext.DirEntry.Fat.ShortName[i];
	}
	/* Construct slots and entry */
	for (LONG i = NumSlots - 2; i >= 0; i--) {
	    DPRINT("construct slot %d\n", i);
	    Slots[i].Attr = 0xf;
	    if (i) {
		Slots[i].Id = (UCHAR)(NumSlots - i - 1);
	    } else {
		Slots[i].Id = (UCHAR)(NumSlots - i - 1 + 0x40);
	    }
	    Slots[i].AliasChecksum = Slots[0].AliasChecksum;
	    RtlCopyMemory(Slots[i].Name0_4,
			  DirContext.LongNameU.Buffer + (NumSlots-i-2)*13, 10);
	    RtlCopyMemory(Slots[i].Name5_10,
			  DirContext.LongNameU.Buffer + (NumSlots-i-2)*13 + 5, 12);
	    RtlCopyMemory(Slots[i].Name11_12,
			  DirContext.LongNameU.Buffer + (NumSlots-i-2)*13 + 11, 4);
	}
    }
    /* Try to find NumSlots contiguous entries frees in directory */
    if (!FatFindDirSpace(DeviceExt, ParentFcb, NumSlots, &DirContext.StartIndex)) {
	ExFreePoolWithTag(Buffer, TAG_DIRENT);
	return STATUS_DISK_FULL;
    }
    DirContext.DirIndex = DirContext.StartIndex + NumSlots - 1;
    if (IsDirectory) {
	/* If we aren't moving, use next cluster */
	if (!MoveContext) {
	    CurrentCluster = 0;
	    Status = NextCluster(DeviceExt, 0, &CurrentCluster, TRUE);
	    DPRINT("CurrentCluster is 0x%x\n", CurrentCluster);
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
    } else if (MoveContext) {
	CurrentCluster = MoveContext->FirstCluster;

	if (DeviceExt->FatInfo.FatType == FAT32) {
	    DirContext.DirEntry.Fat.FirstClusterHigh = (USHORT)(CurrentCluster >> 16);
	}
	DirContext.DirEntry.Fat.FirstCluster = (USHORT)CurrentCluster;
    }

    /* No need to init cache here, FatFindDirSpace() will have done it for us */
    ASSERT(BooleanFlagOn(ParentFcb->Flags, FCB_CACHE_INITIALIZED));

    RtlCopyMemory(Buffer + (NumSlots - 1), &DirContext.DirEntry.Fat,
		  sizeof(FAT_DIR_ENTRY));
    LARGE_INTEGER FileOffset = {
	.HighPart = 0,
	.LowPart = DirContext.StartIndex * sizeof(FAT_DIR_ENTRY)
    };
    ULONG BytesWritten = 0;
    Status = CcCopyWrite(ParentFcb->FileObject, &FileOffset,
			 NumSlots * sizeof(FAT_DIR_ENTRY), TRUE, Buffer, &BytesWritten);
    ExFreePoolWithTag(Buffer, TAG_DIRENT);
    Buffer = NULL;
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(BytesWritten == NumSlots * sizeof(FAT_DIR_ENTRY));

    if (MoveContext) {
	/* We're modifying an existing FCB - likely rename/move */
	Status = FatUpdateFcb(DeviceExt, *Fcb, &DirContext, ParentFcb);
    } else {
	Status = FatMakeFcbFromDirEntry(DeviceExt, ParentFcb, &DirContext, Fcb);
    }
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("New : entry=%11.11s\n", (*Fcb)->Entry.Fat.Filename);
    DPRINT("New : entry=%11.11s\n", DirContext.DirEntry.Fat.Filename);

    if (IsDirectory) {
	Status = FatFcbInitializeCacheFromVolume(DeviceExt, (*Fcb));
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}

	FileOffset.QuadPart = 0;
	ULONG SizeToMap = sizeof(FAT_DIR_ENTRY) * 2;
	PVOID Context;
	ULONG MappedLength;
	PFAT_DIR_ENTRY FatEntry;
	Status = CcMapData((*Fcb)->FileObject, &FileOffset, SizeToMap, MAP_WAIT,
			   &MappedLength, &Context, (PVOID *)&FatEntry);
	if (!NT_SUCCESS(Status) || SizeToMap != MappedLength) {
	    return Status;
	}

	/* Clear the new directory cluster if not moving */
	if (!MoveContext) {
	    RtlZeroMemory(FatEntry, DeviceExt->FatInfo.BytesPerCluster);
	    /* Create '.' and '..' */
	    FatEntry[0] = DirContext.DirEntry.Fat;
	    RtlCopyMemory(FatEntry[0].ShortName, ".          ", 11);
	    FatEntry[1] = DirContext.DirEntry.Fat;
	    RtlCopyMemory(FatEntry[1].ShortName, "..         ", 11);
	}

	FatEntry[1].FirstCluster = ParentFcb->Entry.Fat.FirstCluster;
	FatEntry[1].FirstClusterHigh = ParentFcb->Entry.Fat.FirstClusterHigh;
	if (FatFcbIsRoot(ParentFcb)) {
	    FatEntry[1].FirstCluster = 0;
	    FatEntry[1].FirstClusterHigh = 0;
	}
	CcSetDirtyData(Context);
	CcUnpinData(Context);
    }
    DPRINT("AddEntry OK!\n");
    return STATUS_SUCCESS;
}

/*
 * Deleting an existing FAT entry
 */
static NTSTATUS DelEntry(IN PDEVICE_EXTENSION DeviceExt,
			 IN PFATFCB Fcb,
			 OUT PFAT_MOVE_CONTEXT MoveContext)
{
    NTSTATUS Status;

    ASSERT(Fcb);
    ASSERT(Fcb->ParentFcb);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb->ParentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("delEntry PathName \'%wZ\'\n", &Fcb->PathNameU);
    DPRINT("delete entry: %u to %u\n", Fcb->StartIndex, Fcb->DirIndex);
    assert(Fcb->DirIndex >= Fcb->StartIndex);
    ULONG NumSlots = Fcb->DirIndex - Fcb->StartIndex + 1;
    ULONG SizeToMap = NumSlots * sizeof(FAT_DIR_ENTRY);
    PFAT_DIR_ENTRY Buffer = ExAllocatePoolWithTag(NonPagedPool, SizeToMap, TAG_DIRENT);
    if (!Buffer) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    LARGE_INTEGER Offset = { .QuadPart = Fcb->StartIndex * sizeof(FAT_DIR_ENTRY) };
    ULONG SizeCompleted = 0;
    Status = CcCopyRead(Fcb->ParentFcb->FileObject, &Offset, SizeToMap, TRUE,
			Buffer, &SizeCompleted);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(SizeCompleted == SizeToMap);

    /* Update the first byte of file name and write it back to disk */
    for (ULONG i = 0; i < NumSlots; i++) {
	Buffer[i].Filename[0] = 0xe5;
    }
    Status = CcCopyWrite(Fcb->ParentFcb->FileObject, &Offset, SizeToMap, TRUE,
			 Buffer, &SizeCompleted);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(SizeCompleted == SizeToMap);

    PFAT_DIR_ENTRY LastEntry = &Buffer[NumSlots-1];
    ULONG CurrentCluster = FatDirEntryGetFirstCluster(DeviceExt,
						      (PDIR_ENTRY)LastEntry);

    /* In case of moving, save properties */
    if (MoveContext != NULL) {
	MoveContext->FirstCluster = CurrentCluster;
	MoveContext->FileSize = LastEntry->FileSize;
	MoveContext->CreationTime = LastEntry->CreationTime;
	MoveContext->CreationDate = LastEntry->CreationDate;
    }

    /* In case of moving, don't delete data */
    if (!MoveContext) {
	while (CurrentCluster && CurrentCluster != 0xffffffff) {
	    ULONG NextCluster;
	    Status = GetNextCluster(DeviceExt, CurrentCluster, &NextCluster);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
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
    MaxIndex = Fcb->Base.FileSizes.FileSize.LowPart / sizeof(FAT_DIR_ENTRY);

    Status = FatFcbInitializeCacheFromVolume(DeviceExt, Fcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    ULONG EntriesPerCluster = DeviceExt->FatInfo.BytesPerCluster / sizeof(FAT_DIR_ENTRY);
    while (Index < MaxIndex) {
	if (Context == NULL || (Index % EntriesPerCluster) == 0) {
	    if (Context != NULL) {
		CcUnpinData(Context);
	    }

	    ULONG MappedLength;
	    Status = CcMapData(Fcb->FileObject, &FileOffset, sizeof(FAT_DIR_ENTRY),
			       MAP_WAIT, &MappedLength, &Context, (PVOID *)&FatDirEntry);
	    if (!NT_SUCCESS(Status) || MappedLength != sizeof(FAT_DIR_ENTRY)) {
		return TRUE;
	    }
	    assert(MappedLength == sizeof(FAT_DIR_ENTRY));

	    FatDirEntry += Index % EntriesPerCluster;
	    FileOffset.QuadPart += DeviceExt->FatInfo.BytesPerCluster;
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
				OUT PVOID *pSector,
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

    ULONG SectorSize = DirContext->DeviceExt->FatInfo.BytesPerSector;
    FileOffset.HighPart = 0;
    FileOffset.LowPart = ROUND_DOWN(DirContext->DirIndex * sizeof(FAT_DIR_ENTRY),
				    SectorSize);

    NTSTATUS Status = FatFcbInitializeCacheFromVolume(DirContext->DeviceExt, DirFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    ULONG MappedLength;
    ULONG EntriesPerSector = SectorSize / sizeof(FAT_DIR_ENTRY);
    if (!(*pContext) || !(DirContext->DirIndex % EntriesPerSector)) {
	if (*pContext) {
	    CcUnpinData(*pContext);
	}

	if (FileOffset.LowPart >= DirFcb->Base.FileSizes.FileSize.LowPart) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}

	Status = CcMapData(DirFcb->FileObject, &FileOffset, SectorSize,
			   MAP_WAIT, &MappedLength, pContext, pSector);
	if (!NT_SUCCESS(Status) || MappedLength != SectorSize) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}
	assert(MappedLength == SectorSize);
    }

    FatDirEntry = (PFAT_DIR_ENTRY)(*pSector) + DirContext->DirIndex % EntriesPerSector;
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

	    if ((DirContext->DirIndex % EntriesPerSector) == EntriesPerSector - 1) {
		CcUnpinData(*pContext);
		FileOffset.LowPart -= SectorSize;

		if (FileOffset.LowPart >= DirFcb->Base.FileSizes.FileSize.LowPart) {
		    *pContext = NULL;
		    return STATUS_NO_MORE_ENTRIES;
		}

		Status = CcMapData(DirFcb->FileObject, &FileOffset, SectorSize,
				   MAP_WAIT, &MappedLength, pContext, pSector);
		if (!NT_SUCCESS(Status) || MappedLength != SectorSize) {
		    *pContext = NULL;
		    return STATUS_NO_MORE_ENTRIES;
		}
		assert(MappedLength == SectorSize);

		FatDirEntry = (PFAT_DIR_ENTRY)(*pSector) + DirContext->DirIndex % EntriesPerSector;
		LongNameEntry = (PSLOT)FatDirEntry;
	    } else {
		FatDirEntry--;
		LongNameEntry--;
	    }
	}

	if (Back && !FAT_ENTRY_END(FatDirEntry) &&
	    (FAT_ENTRY_DELETED(FatDirEntry) || !FAT_ENTRY_LONG(FatDirEntry))) {
	    DirContext->DirIndex++;

	    if ((DirContext->DirIndex % EntriesPerSector) == 0) {
		CcUnpinData(*pContext);
		FileOffset.LowPart += SectorSize;

		if (FileOffset.LowPart >= DirFcb->Base.FileSizes.FileSize.LowPart) {
		    *pContext = NULL;
		    return STATUS_NO_MORE_ENTRIES;
		}

		Status = CcMapData(DirFcb->FileObject, &FileOffset, SectorSize,
				   MAP_WAIT, &MappedLength, pContext, pSector);
		if (!NT_SUCCESS(Status) || MappedLength != SectorSize) {
		    *pContext = NULL;
		    return STATUS_NO_MORE_ENTRIES;
		}
		assert(MappedLength == SectorSize);

		FatDirEntry = (PFAT_DIR_ENTRY)(*pSector);
		LongNameEntry = (PSLOT)(*pSector);
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
		    Index * 13 < DirContext->LongNameU.MaximumLength / sizeof(WCHAR)) {
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

		DPRINT("  LongName: [%ws]\n", DirContext->LongNameU.Buffer);

		if (CheckSum != LongNameEntry->AliasChecksum) {
		    DPRINT1("Found wrong alias checksum in long name entry (first %x, current %x, %ws)\n",
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
		    DPRINT1("Checksum from long and short name is not equal (short: %x, long: %x, %ws)\n",
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

	if ((DirContext->DirIndex % EntriesPerSector) == 0) {
	    CcUnpinData(*pContext);
	    FileOffset.LowPart += SectorSize;

	    if (FileOffset.LowPart >= DirFcb->Base.FileSizes.FileSize.LowPart) {
		*pContext = NULL;
		return STATUS_NO_MORE_ENTRIES;
	    }

	    Status = CcMapData(DirFcb->FileObject, &FileOffset, SectorSize,
			       MAP_WAIT, &MappedLength, pContext, pSector);
	    if (!NT_SUCCESS(Status) || MappedLength != SectorSize) {
		*pContext = NULL;
		return STATUS_NO_MORE_ENTRIES;
	    }

	    FatDirEntry = (PFAT_DIR_ENTRY)(*pSector);
	    LongNameEntry = (PSLOT)(*pSector);
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
