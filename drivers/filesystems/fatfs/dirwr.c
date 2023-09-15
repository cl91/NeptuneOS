/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Write in directory
 * COPYRIGHT:   Copyright 1999-2001 Rex Jolliff <rex@lvcablemodem.com>
 *              Copyright 2004-2008 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2010-2018 Pierre Schweitzer <pierre@reactos.org>
 */

#include "fatfs.h"

NTSTATUS FatFCBInitializeCacheFromVolume(PVCB Vcb, PFATFCB Fcb)
{
    PFILE_OBJECT FileObject;
    PFATCCB NewCCB;
    NTSTATUS Status;

    /* Don't re-initialize if already done */
    if (BooleanFlagOn(Fcb->Flags, FCB_CACHE_INITIALIZED)) {
	return STATUS_SUCCESS;
    }

    ASSERT(FatFCBIsDirectory(Fcb));
    ASSERT(Fcb->FileObject == NULL);

    FileObject = IoCreateStreamFileObject(NULL, Vcb->StorageDevice);
    if (FileObject == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto Quit;
    }
#ifdef KDBG
    if (DebugFile.Buffer != NULL
	&& FsRtlIsNameInExpression(&DebugFile, &Fcb->LongNameU, FALSE,
				   NULL)) {
	DPRINT1("Attaching %p to %p (%d)\n", Fcb, FileObject,
		Fcb->RefCount);
    }
#endif

    NewCCB = ExAllocateFromNPagedLookasideList(&FatGlobalData->CcbLookasideList);
    if (NewCCB == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	ObDereferenceObject(FileObject);
	goto Quit;
    }
    RtlZeroMemory(NewCCB, sizeof(FATCCB));

    FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
    FileObject->FsContext = Fcb;
    FileObject->FsContext2 = NewCCB;
    FileObject->Vpb = Vcb->IoVPB;
    Fcb->FileObject = FileObject;

    __try {
	CcInitializeCacheMap(FileObject, (PCC_FILE_SIZES)(&Fcb->RFCB.AllocationSize),
			     TRUE, &FatGlobalData->CacheMgrCallbacks, Fcb);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	Status = GetExceptionCode();
	Fcb->FileObject = NULL;
	ExFreeToNPagedLookasideList(&FatGlobalData->CcbLookasideList, NewCCB);
	ObDereferenceObject(FileObject);
	return Status;
    }

    FatGrabFCB(Vcb, Fcb);
    SetFlag(Fcb->Flags, FCB_CACHE_INITIALIZED);
    Status = STATUS_SUCCESS;

Quit:

    return Status;
}

/*
 * Update an existing FAT entry
 */
NTSTATUS FatUpdateEntry(IN PDEVICE_EXTENSION DeviceExt, IN PFATFCB pFcb)
{
    PVOID Context;
    PDIR_ENTRY PinEntry;
    LARGE_INTEGER Offset;
    ULONG SizeDirEntry;
    ULONG DirIndex;
    NTSTATUS Status;

    ASSERT(pFcb);

    if (FatVolumeIsFatX(DeviceExt)) {
	SizeDirEntry = sizeof(FATX_DIR_ENTRY);
	DirIndex = pFcb->startIndex;
    } else {
	SizeDirEntry = sizeof(FAT_DIR_ENTRY);
	DirIndex = pFcb->DirIndex;
    }

    DPRINT("updEntry DirIndex %u, PathName \'%wZ\'\n", DirIndex, &pFcb->PathNameU);

    if (FatFCBIsRoot(pFcb) || BooleanFlagOn(pFcb->Flags, FCB_IS_FAT | FCB_IS_VOLUME)) {
	return STATUS_SUCCESS;
    }

    ASSERT(pFcb->parentFcb);

    Status = FatFCBInitializeCacheFromVolume(DeviceExt, pFcb->parentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Offset.u.HighPart = 0;
    Offset.u.LowPart = DirIndex * SizeDirEntry;
    __try {
	CcPinRead(pFcb->parentFcb->FileObject, &Offset, SizeDirEntry,
		  PIN_WAIT, &Context, (PVOID *) & PinEntry);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	DPRINT1("Failed write to \'%wZ\'.\n", &pFcb->parentFcb->PathNameU);
	return GetExceptionCode();
    }

    pFcb->Flags &= ~FCB_IS_DIRTY;
    RtlCopyMemory(PinEntry, &pFcb->entry, SizeDirEntry);
    CcSetDirtyPinnedData(Context, NULL);
    CcUnpinData(Context);
    return STATUS_SUCCESS;
}

/*
 * Rename an existing FAT entry
 */
NTSTATUS FatRenameEntry(IN PDEVICE_EXTENSION DeviceExt,
			IN PFATFCB pFcb,
			IN PUNICODE_STRING FileName,
			IN BOOLEAN CaseChangeOnly)
{
    OEM_STRING NameA;
    ULONG StartIndex;
    PVOID Context = NULL;
    LARGE_INTEGER Offset;
    PFATX_DIR_ENTRY pDirEntry;
    NTSTATUS Status;

    DPRINT("FatRenameEntry(%p, %p, %wZ, %d)\n", DeviceExt, pFcb, FileName,
	   CaseChangeOnly);

    Status = FatFCBInitializeCacheFromVolume(DeviceExt, pFcb->parentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (FatVolumeIsFatX(DeviceExt)) {
	FAT_DIRENTRY_CONTEXT DirContext;

	/* Open associated dir entry */
	StartIndex = pFcb->startIndex;
	Offset.u.HighPart = 0;
	Offset.u.LowPart = (StartIndex * sizeof(FATX_DIR_ENTRY) / PAGE_SIZE) * PAGE_SIZE;
	__try {
	    CcPinRead(pFcb->parentFcb->FileObject, &Offset, PAGE_SIZE,
		      PIN_WAIT, &Context, (PVOID *) & pDirEntry);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    DPRINT1("CcPinRead(Offset %x:%x, Length %d) failed\n",
		    Offset.u.HighPart, Offset.u.LowPart, PAGE_SIZE);
	    return GetExceptionCode();
	}

	pDirEntry = &pDirEntry[StartIndex % (PAGE_SIZE / sizeof(FATX_DIR_ENTRY))];

	/* Set file name */
	NameA.Buffer = (PCHAR) pDirEntry->Filename;
	NameA.Length = 0;
	NameA.MaximumLength = 42;
	RtlUnicodeStringToOemString(&NameA, FileName, FALSE);
	pDirEntry->FilenameLength = (unsigned char) NameA.Length;

	/* Update FCB */
	DirContext.DeviceExt = DeviceExt;
	DirContext.ShortNameU.Length = 0;
	DirContext.ShortNameU.MaximumLength = 0;
	DirContext.ShortNameU.Buffer = NULL;
	DirContext.LongNameU = *FileName;
	DirContext.DirEntry.FatX = *pDirEntry;

	CcSetDirtyPinnedData(Context, NULL);
	CcUnpinData(Context);

	Status = FatUpdateFCB(DeviceExt, pFcb, &DirContext, pFcb->parentFcb);
	if (NT_SUCCESS(Status)) {
	    CcFlushCache(&pFcb->parentFcb->SectionObjectPointers, NULL, 0, NULL);
	}

	return Status;
    } else {
	/* This we cannot handle properly, move file - would likely need love */
	return FatMoveEntry(DeviceExt, pFcb, FileName, pFcb->parentFcb);
    }
}

/*
 * Try to find contiguous entries frees in the directory. Extend a directory if necessary.
 */
BOOLEAN FatFindDirSpace(IN PDEVICE_EXTENSION DeviceExt,
			IN PFATFCB pDirFcb, IN ULONG nbSlots, OUT PULONG start)
{
    LARGE_INTEGER FileOffset;
    ULONG count, size, nbFree = 0;
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

    Status = FatFCBInitializeCacheFromVolume(DeviceExt, pDirFcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    count = pDirFcb->RFCB.FileSize.u.LowPart / SizeDirEntry;
    size = DeviceExt->FatInfo.BytesPerCluster / SizeDirEntry;
    for (ULONG i = 0; i < count;
	 i++, pFatEntry = (PDIR_ENTRY)((ULONG_PTR) pFatEntry + SizeDirEntry)) {
	if (Context == NULL || (i % size) == 0) {
	    if (Context) {
		CcUnpinData(Context);
	    }
	    __try {
		CcPinRead(pDirFcb->FileObject, &FileOffset,
			  DeviceExt->FatInfo.BytesPerCluster, PIN_WAIT,
			  &Context, (PVOID *) & pFatEntry);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	    }


	    FileOffset.u.LowPart += DeviceExt->FatInfo.BytesPerCluster;
	}
	if (ENTRY_END(IsFatX, pFatEntry)) {
	    break;
	}
	if (ENTRY_DELETED(IsFatX, pFatEntry)) {
	    nbFree++;
	} else {
	    nbFree = 0;
	}
	if (nbFree == nbSlots) {
	    break;
	}
    }
    if (Context) {
	CcUnpinData(Context);
	Context = NULL;
    }
    if (nbFree == nbSlots) {
	/* Found enough contiguous free slots */
	*start = i - nbSlots + 1;
    } else {
	*start = i - nbFree;
	if (*start + nbSlots > count) {
	    LARGE_INTEGER AllocationSize;
	    /* Extend the directory */
	    if (FatFCBIsRoot(pDirFcb) && DeviceExt->FatInfo.FatType != FAT32) {
		/* We can't extend a root directory on a FAT12/FAT16/FATX partition */
		return FALSE;
	    }
	    AllocationSize.QuadPart = pDirFcb->RFCB.FileSize.u.LowPart +
		DeviceExt->FatInfo.BytesPerCluster;
	    Status = FatSetAllocationSizeInformation(pDirFcb->FileObject,
						     pDirFcb, DeviceExt,
						     &AllocationSize);
	    if (!NT_SUCCESS(Status)) {
		return FALSE;
	    }
	    /* clear the new dir cluster */
	    FileOffset.u.LowPart = (ULONG)(pDirFcb->RFCB.FileSize.QuadPart -
					   DeviceExt->FatInfo.BytesPerCluster);
	    __try {
		CcPinRead(pDirFcb->FileObject, &FileOffset,
			  DeviceExt->FatInfo.BytesPerCluster, PIN_WAIT,
			  &Context, (PVOID *)&pFatEntry);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	    }


	    if (IsFatX)
		memset(pFatEntry, 0xff,
		       DeviceExt->FatInfo.BytesPerCluster);
	    else
		RtlZeroMemory(pFatEntry,
			      DeviceExt->FatInfo.BytesPerCluster);
	} else if (*start + nbSlots < count) {
	    /* clear the entry after the last new entry */
	    FileOffset.u.LowPart = (*start + nbSlots) * SizeDirEntry;
	    __try {
		CcPinRead(pDirFcb->FileObject, &FileOffset, SizeDirEntry,
			  PIN_WAIT, &Context, (PVOID *) & pFatEntry);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
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
    DPRINT("nbSlots %u nbFree %u, entry number %u\n", nbSlots, nbFree,
	   *start);
    return TRUE;
}

/*
 * Create a new FAT entry
 */
static NTSTATUS FATAddEntry(IN PDEVICE_EXTENSION DeviceExt,
			    IN PUNICODE_STRING NameU,
			    IN PFATFCB *Fcb,
			    IN PFATFCB ParentFcb,
			    IN ULONG RequestedOptions,
			    IN UCHAR ReqAttr,
			    IN PFAT_MOVE_CONTEXT MoveContext)
{
    PVOID Context = NULL;
    PFAT_DIR_ENTRY pFatEntry;
    slot *pSlots;
    USHORT nbSlots = 0, j;
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
    ULONG size;
    long i;

    OEM_STRING NameA;
    CHAR aName[13];
    BOOLEAN IsNameLegal;
    BOOLEAN SpacesFound;

    FAT_DIRENTRY_CONTEXT DirContext;
    WCHAR LongNameBuffer[LONGNAME_MAX_LENGTH + 1];
    WCHAR ShortNameBuffer[13];

    DPRINT("addEntry: Name='%wZ', Dir='%wZ'\n", NameU,
	   &ParentFcb->PathNameU);

    DirContext.LongNameU = *NameU;
    IsDirectory = BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE);

    /* nb of entry needed for long name+normal entry */
    nbSlots = (DirContext.LongNameU.Length / sizeof(WCHAR) + 12) / 13 + 1;
    DPRINT("NameLen= %u, nbSlots =%u\n",
	   DirContext.LongNameU.Length / sizeof(WCHAR), nbSlots);
    Buffer = ExAllocatePoolWithTag(NonPagedPool,
				   (nbSlots - 1) * sizeof(FAT_DIR_ENTRY),
				   TAG_DIRENT);
    if (Buffer == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Buffer, (nbSlots - 1) * sizeof(FAT_DIR_ENTRY));
    pSlots = (slot *) Buffer;

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
			    (char *)(*Fcb)->entry.Fat.ShortName, 11) == 0) {
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
	nbSlots = 1;
	if (BaseAllLower && !BaseAllUpper) {
	    DirContext.DirEntry.Fat.lCase |= FAT_CASE_LOWER_BASE;
	}
	if (ExtensionAllLower && !ExtensionAllUpper) {
	    DirContext.DirEntry.Fat.lCase |= FAT_CASE_LOWER_EXT;
	}
    }

    DPRINT("dos name=%11.11s\n", DirContext.DirEntry.Fat.Filename);

    /* Set attributes */
    DirContext.DirEntry.Fat.Attrib = ReqAttr;
    if (IsDirectory) {
	DirContext.DirEntry.Fat.Attrib |= FILE_ATTRIBUTE_DIRECTORY;
    }

    /* Set dates and times */
    KeQuerySystemTime(&SystemTime);
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
	for (pSlots[0].alias_checksum = 0, i = 0; i < 11; i++) {
	    pSlots[0].alias_checksum =
		(((pSlots[0].
		   alias_checksum & 1) << 7 | ((pSlots[0].
						alias_checksum & 0xfe) >>
					       1))
		 + DirContext.DirEntry.Fat.ShortName[i]);
	}
	/* construct slots and entry */
	for (i = nbSlots - 2; i >= 0; i--) {
	    DPRINT("construct slot %d\n", i);
	    pSlots[i].attr = 0xf;
	    if (i) {
		pSlots[i].id = (unsigned char) (nbSlots - i - 1);
	    } else {
		pSlots[i].id = (unsigned char) (nbSlots - i - 1 + 0x40);
	    }
	    pSlots[i].alias_checksum = pSlots[0].alias_checksum;
	    RtlCopyMemory(pSlots[i].name0_4,
			  DirContext.LongNameU.Buffer + (nbSlots - i -
							 2) * 13, 10);
	    RtlCopyMemory(pSlots[i].name5_10,
			  DirContext.LongNameU.Buffer + (nbSlots - i -
							 2) * 13 + 5, 12);
	    RtlCopyMemory(pSlots[i].name11_12,
			  DirContext.LongNameU.Buffer + (nbSlots - i -
							 2) * 13 + 11, 4);
	}
    }
    /* try to find nbSlots contiguous entries frees in directory */
    if (!FatFindDirSpace(DeviceExt, ParentFcb, nbSlots, &DirContext.StartIndex)) {
	ExFreePoolWithTag(Buffer, TAG_DIRENT);
	return STATUS_DISK_FULL;
    }
    DirContext.DirIndex = DirContext.StartIndex + nbSlots - 1;
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
	DirContext.DirEntry.Fat.FirstCluster = (unsigned short) CurrentCluster;
    } else if (MoveContext != NULL) {
	CurrentCluster = MoveContext->FirstCluster;

	if (DeviceExt->FatInfo.FatType == FAT32) {
	    DirContext.DirEntry.Fat.FirstClusterHigh =
		(unsigned short) (CurrentCluster >> 16);
	}
	DirContext.DirEntry.Fat.FirstCluster =
	    (unsigned short) CurrentCluster;
    }

    /* No need to init cache here, FatFindDirSpace() will have done it for us */
    ASSERT(BooleanFlagOn(ParentFcb->Flags, FCB_CACHE_INITIALIZED));

    i = DeviceExt->FatInfo.BytesPerCluster / sizeof(FAT_DIR_ENTRY);
    FileOffset.u.HighPart = 0;
    FileOffset.u.LowPart = DirContext.StartIndex * sizeof(FAT_DIR_ENTRY);
    if (DirContext.StartIndex / i == DirContext.DirIndex / i) {
	/* one cluster */
	__try {
	    CcPinRead(ParentFcb->FileObject, &FileOffset,
		      nbSlots * sizeof(FAT_DIR_ENTRY), PIN_WAIT, &Context,
		      (PVOID *) & pFatEntry);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return GetExceptionCode();
	}


	if (nbSlots > 1) {
	    RtlCopyMemory(pFatEntry, Buffer,
			  (nbSlots - 1) * sizeof(FAT_DIR_ENTRY));
	}
	RtlCopyMemory(pFatEntry + (nbSlots - 1), &DirContext.DirEntry.Fat,
		      sizeof(FAT_DIR_ENTRY));
    } else {
	/* two clusters */
	size = DeviceExt->FatInfo.BytesPerCluster -
	    (DirContext.StartIndex * sizeof(FAT_DIR_ENTRY)) %
	    DeviceExt->FatInfo.BytesPerCluster;
	i = size / sizeof(FAT_DIR_ENTRY);
	__try {
	    CcPinRead(ParentFcb->FileObject, &FileOffset, size, PIN_WAIT,
		      &Context, (PVOID *) & pFatEntry);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return GetExceptionCode();
	}

	RtlCopyMemory(pFatEntry, Buffer, size);
	CcSetDirtyPinnedData(Context, NULL);
	CcUnpinData(Context);
	FileOffset.u.LowPart += size;
	__try {
	    CcPinRead(ParentFcb->FileObject, &FileOffset,
		      nbSlots * sizeof(FAT_DIR_ENTRY) - size, PIN_WAIT,
		      &Context, (PVOID *) & pFatEntry);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return GetExceptionCode();
	}

	if (nbSlots - 1 > i) {
	    RtlCopyMemory(pFatEntry, (PVOID) (Buffer + size),
			  (nbSlots - 1 - i) * sizeof(FAT_DIR_ENTRY));
	}
	RtlCopyMemory(pFatEntry + nbSlots - 1 - i,
		      &DirContext.DirEntry.Fat, sizeof(FAT_DIR_ENTRY));
    }
    CcSetDirtyPinnedData(Context, NULL);
    CcUnpinData(Context);

    if (MoveContext != NULL) {
	/* We're modifying an existing FCB - likely rename/move */
	Status = FatUpdateFCB(DeviceExt, *Fcb, &DirContext, ParentFcb);
    } else {
	Status =
	    FatMakeFCBFromDirEntry(DeviceExt, ParentFcb, &DirContext, Fcb);
    }
    if (!NT_SUCCESS(Status)) {
	ExFreePoolWithTag(Buffer, TAG_DIRENT);
	return Status;
    }

    DPRINT("new : entry=%11.11s\n", (*Fcb)->entry.Fat.Filename);
    DPRINT("new : entry=%11.11s\n", DirContext.DirEntry.Fat.Filename);

    if (IsDirectory) {
	Status = FatFCBInitializeCacheFromVolume(DeviceExt, (*Fcb));
	if (!NT_SUCCESS(Status)) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return Status;
	}

	FileOffset.QuadPart = 0;
	__try {
	    CcPinRead((*Fcb)->FileObject, &FileOffset,
		      DeviceExt->FatInfo.BytesPerCluster, PIN_WAIT,
		      &Context, (PVOID *) & pFatEntry);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    ExFreePoolWithTag(Buffer, TAG_DIRENT);
	    return GetExceptionCode();
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

	pFatEntry[1].FirstCluster = ParentFcb->entry.Fat.FirstCluster;
	pFatEntry[1].FirstClusterHigh =
	    ParentFcb->entry.Fat.FirstClusterHigh;
	if (FatFCBIsRoot(ParentFcb)) {
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
 * Create a new FAT entry
 */
static NTSTATUS FATXAddEntry(IN PDEVICE_EXTENSION DeviceExt,
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
    if (!FatFCBIsRoot(ParentFcb)) {
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
    DirContext.DirEntry.FatX.FilenameLength = (unsigned char) NameA.Length;

    /* Set attributes */
    DirContext.DirEntry.FatX.Attrib = ReqAttr;
    if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE)) {
	DirContext.DirEntry.FatX.Attrib |= FILE_ATTRIBUTE_DIRECTORY;
    }

    /* Set dates and times */
    KeQuerySystemTime(&SystemTime);
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
    FileOffset.u.HighPart = 0;
    FileOffset.u.LowPart = Index * sizeof(FATX_DIR_ENTRY);
    __try {
	CcPinRead(ParentFcb->FileObject, &FileOffset,
		  sizeof(FATX_DIR_ENTRY), PIN_WAIT, &Context,
		  (PVOID *)&pFatXDirEntry);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	return GetExceptionCode();
    }

    RtlCopyMemory(pFatXDirEntry, &DirContext.DirEntry.FatX, sizeof(FATX_DIR_ENTRY));
    CcSetDirtyPinnedData(Context, NULL);
    CcUnpinData(Context);

    if (MoveContext != NULL) {
	/* We're modifying an existing FCB - likely rename/move */
	/* FIXME: check status */
	FatUpdateFCB(DeviceExt, *Fcb, &DirContext, ParentFcb);
    } else {
	/* FIXME: check status */
	FatMakeFCBFromDirEntry(DeviceExt, ParentFcb, &DirContext, Fcb);
    }

    DPRINT("addentry ok\n");
    return STATUS_SUCCESS;
}

/*
 * Deleting an existing FAT entry
 */
static NTSTATUS FATDelEntry(IN PDEVICE_EXTENSION DeviceExt,
			    IN PFATFCB pFcb,
			    OUT PFAT_MOVE_CONTEXT MoveContext)
{
    ULONG CurrentCluster = 0, NextCluster;
    PVOID Context = NULL;
    LARGE_INTEGER Offset;
    PFAT_DIR_ENTRY pDirEntry = NULL;
    NTSTATUS Status;

    ASSERT(pFcb);
    ASSERT(pFcb->parentFcb);

    Status = FatFCBInitializeCacheFromVolume(DeviceExt, pFcb->parentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("delEntry PathName \'%wZ\'\n", &pFcb->PathNameU);
    DPRINT("delete entry: %u to %u\n", pFcb->startIndex, pFcb->DirIndex);
    Offset.u.HighPart = 0;
    for (ULONG i = pFcb->startIndex; i <= pFcb->DirIndex; i++) {
	if (Context == NULL || ((i * sizeof(FAT_DIR_ENTRY)) % PAGE_SIZE) == 0) {
	    if (Context) {
		CcSetDirtyPinnedData(Context, NULL);
		CcUnpinData(Context);
	    }
	    Offset.u.LowPart = (i * sizeof(FAT_DIR_ENTRY) / PAGE_SIZE) * PAGE_SIZE;
	    __try {
		CcPinRead(pFcb->parentFcb->FileObject, &Offset, PAGE_SIZE,
			  PIN_WAIT, &Context, (PVOID *) & pDirEntry);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
		return GetExceptionCode();
	    }
	}
	pDirEntry[i % (PAGE_SIZE / sizeof(FAT_DIR_ENTRY))].Filename[0] = 0xe5;
	if (i == pFcb->DirIndex) {
	    ULONG Idx = i % (PAGE_SIZE / sizeof(FAT_DIR_ENTRY));
	    CurrentCluster = FatDirEntryGetFirstCluster(DeviceExt,
							(PDIR_ENTRY)&pDirEntry[Idx]);
	}
    }

    /* In case of moving, save properties */
    if (MoveContext != NULL) {
	pDirEntry = &pDirEntry[pFcb->DirIndex % (PAGE_SIZE / sizeof(FAT_DIR_ENTRY))];
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

/*
 * Deleting an existing FAT entry
 */
static NTSTATUS FATXDelEntry(IN PDEVICE_EXTENSION DeviceExt,
			     IN PFATFCB pFcb,
			     OUT PFAT_MOVE_CONTEXT MoveContext)
{
    ULONG CurrentCluster = 0, NextCluster;
    PVOID Context = NULL;
    LARGE_INTEGER Offset;
    PFATX_DIR_ENTRY pDirEntry;
    ULONG StartIndex;
    NTSTATUS Status;

    ASSERT(pFcb);
    ASSERT(pFcb->parentFcb);
    ASSERT(FatVolumeIsFatX(DeviceExt));

    StartIndex = pFcb->startIndex;

    Status = FatFCBInitializeCacheFromVolume(DeviceExt, pFcb->parentFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("delEntry PathName \'%wZ\'\n", &pFcb->PathNameU);
    DPRINT("delete entry: %u\n", StartIndex);
    Offset.u.HighPart = 0;
    Offset.u.LowPart = (StartIndex * sizeof(FATX_DIR_ENTRY) / PAGE_SIZE) * PAGE_SIZE;
    __try {
	CcPinRead(pFcb->parentFcb->FileObject, &Offset, PAGE_SIZE,
		  PIN_WAIT, &Context, (PVOID *)&pDirEntry);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	DPRINT1("CcPinRead(Offset %x:%x, Length %d) failed\n",
		Offset.u.HighPart, Offset.u.LowPart, PAGE_SIZE);
	return GetExceptionCode();
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

/*
 * Move an existing FAT entry
 */
NTSTATUS FatMoveEntry(IN PDEVICE_EXTENSION DeviceExt,
		      IN PFATFCB pFcb,
		      IN PUNICODE_STRING FileName,
		      IN PFATFCB ParentFcb)
{
    NTSTATUS Status;
    PFATFCB OldParent;
    FAT_MOVE_CONTEXT MoveContext;

    DPRINT("FatMoveEntry(%p, %p, %wZ, %p)\n", DeviceExt, pFcb, FileName, ParentFcb);

    /* Delete old entry while keeping data */
    Status = FatDelEntry(DeviceExt, pFcb, &MoveContext);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    OldParent = pFcb->parentFcb;
    CcFlushCache(&OldParent->SectionObjectPointers, NULL, 0, NULL);
    MoveContext.InPlace = (OldParent == ParentFcb);

    /* Add our new entry with our cluster */
    Status = FatAddEntry(DeviceExt, FileName, &pFcb, ParentFcb,
			 (FatFCBIsDirectory(pFcb) ? FILE_DIRECTORY_FILE : 0),
			 *pFcb->Attributes, &MoveContext);

    CcFlushCache(&pFcb->parentFcb->SectionObjectPointers, NULL, 0, NULL);

    return Status;
}

extern BOOLEAN FATXIsDirectoryEmpty(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb);
extern BOOLEAN FATIsDirectoryEmpty(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb);
extern NTSTATUS FATGetNextDirEntry(PVOID *pContext, PVOID *pPage, PFATFCB pDirFcb,
				   PFAT_DIRENTRY_CONTEXT DirContext, BOOLEAN First);
extern NTSTATUS FATXGetNextDirEntry(PVOID *pContext, PVOID *pPage, PFATFCB pDirFcb,
				    PFAT_DIRENTRY_CONTEXT DirContext, BOOLEAN First);

FAT_DISPATCH FatXDispatch = {
    FATXIsDirectoryEmpty,	// .IsDirectoryEmpty
    FATXAddEntry,		// .AddEntry
    FATXDelEntry,		// .DelEntry
    FATXGetNextDirEntry,	// .GetNextDirEntry
};

FAT_DISPATCH FatDispatch = {
    FATIsDirectoryEmpty,	// .IsDirectoryEmpty
    FATAddEntry,		// .AddEntry
    FATDelEntry,		// .DelEntry
    FATGetNextDirEntry,		// .GetNextDirEntry
};
