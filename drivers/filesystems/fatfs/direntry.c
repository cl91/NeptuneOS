/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Routines to manipulate directory entries
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2001 Rex Jolliff <rex@lvcablemodem.com>
 *              Copyright 2004-2022 Hervé Poussineau <hpoussin@reactos.org>
 */

#include "fatfs.h"

ULONG FatDirEntryGetFirstCluster(PDEVICE_EXTENSION DevExt,
				 PDIR_ENTRY DirEnt)
{
    if (DevExt->FatInfo.FatType == FAT32) {
	return DirEnt->Fat.FirstCluster | ((ULONG)DirEnt->Fat.FirstClusterHigh << 16);
    } else if (FatVolumeIsFatX(DevExt)) {
	return DirEnt->FatX.FirstCluster;
    } else {
	return DirEnt->Fat.FirstCluster;
    }
}

BOOLEAN FATIsDirectoryEmpty(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb)
{
    LARGE_INTEGER FileOffset;
    PVOID Context = NULL;
    PFAT_DIR_ENTRY FatDirEntry;
    ULONG Index, MaxIndex;
    NTSTATUS Status;

    if (FatFCBIsRoot(Fcb)) {
	Index = 0;
    } else {
	Index = 2;
    }

    FileOffset.QuadPart = 0;
    MaxIndex = Fcb->Base.FileSize.u.LowPart / sizeof(FAT_DIR_ENTRY);

    Status = FatFCBInitializeCacheFromVolume(DeviceExt, Fcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    while (Index < MaxIndex) {
	if (Context == NULL || (Index % FAT_ENTRIES_PER_PAGE) == 0) {
	    if (Context != NULL) {
		CcUnpinData(Context);
	    }

	    __try {
		CcMapData(Fcb->FileObject, &FileOffset, sizeof(FAT_DIR_ENTRY),
			  MAP_WAIT, &Context, (PVOID *)&FatDirEntry);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
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

BOOLEAN FATXIsDirectoryEmpty(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb)
{
    LARGE_INTEGER FileOffset;
    PVOID Context = NULL;
    PFATX_DIR_ENTRY FatXDirEntry;
    ULONG Index = 0, MaxIndex;
    NTSTATUS Status;

    FileOffset.QuadPart = 0;
    MaxIndex = Fcb->Base.FileSize.u.LowPart / sizeof(FATX_DIR_ENTRY);

    Status = FatFCBInitializeCacheFromVolume(DeviceExt, Fcb);
    if (!NT_SUCCESS(Status)) {
	return FALSE;
    }

    while (Index < MaxIndex) {
	if (Context == NULL || (Index % FATX_ENTRIES_PER_PAGE) == 0) {
	    if (Context != NULL) {
		CcUnpinData(Context);
	    }

	    __try {
		CcMapData(Fcb->FileObject, &FileOffset,
			  sizeof(FATX_DIR_ENTRY), MAP_WAIT, &Context,
			  (PVOID *)&FatXDirEntry);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
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

NTSTATUS FATGetNextDirEntry(PVOID *pContext,
			    PVOID *pPage,
			    IN PFATFCB DirFcb,
			    PFAT_DIRENTRY_CONTEXT DirContext,
			    BOOLEAN First)
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

    FileOffset.u.HighPart = 0;
    FileOffset.u.LowPart = ROUND_DOWN(DirContext->DirIndex * sizeof(FAT_DIR_ENTRY),
				      PAGE_SIZE);

    NTSTATUS Status = FatFCBInitializeCacheFromVolume(DirContext->DeviceExt, DirFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (*pContext == NULL
	|| (DirContext->DirIndex % FAT_ENTRIES_PER_PAGE) == 0) {
	if (*pContext != NULL) {
	    CcUnpinData(*pContext);
	}

	if (FileOffset.u.LowPart >= DirFcb->Base.FileSize.u.LowPart) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}

	__try {
	    CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
		      MAP_WAIT, pContext, pPage);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}
    }

    FatDirEntry = (PFAT_DIR_ENTRY)(*pPage) + DirContext->DirIndex % FAT_ENTRIES_PER_PAGE;
    LongNameEntry = (PSLOT)FatDirEntry;
    DirMap = 0;

    if (First) {
	/* This is the first call to FatGetNextDirEntry. Possible the start Index points
	 * into a long name or points to a short name with an assigned long name.
	 * We must go back to the real start of the entry */
	while (DirContext->DirIndex > 0 &&
	       !FAT_ENTRY_END(FatDirEntry) &&
	       !FAT_ENTRY_DELETED(FatDirEntry) &&
	       ((!FAT_ENTRY_LONG(FatDirEntry) && !Back) ||
		(FAT_ENTRY_LONG(FatDirEntry)
		 && !(LongNameEntry->Id & 0x40)))) {
	    DirContext->DirIndex--;
	    Back = TRUE;

	    if ((DirContext->DirIndex % FAT_ENTRIES_PER_PAGE) ==
		FAT_ENTRIES_PER_PAGE - 1) {
		CcUnpinData(*pContext);
		FileOffset.u.LowPart -= PAGE_SIZE;

		if (FileOffset.u.LowPart >=
		    DirFcb->Base.FileSize.u.LowPart) {
		    *pContext = NULL;
		    return STATUS_NO_MORE_ENTRIES;
		}

		__try {
		    CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
			      MAP_WAIT, pContext, pPage);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
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
	    (FAT_ENTRY_DELETED(FatDirEntry)
	     || !FAT_ENTRY_LONG(FatDirEntry))) {
	    DirContext->DirIndex++;

	    if ((DirContext->DirIndex % FAT_ENTRIES_PER_PAGE) == 0) {
		CcUnpinData(*pContext);
		FileOffset.u.LowPart += PAGE_SIZE;

		if (FileOffset.u.LowPart >=
		    DirFcb->Base.FileSize.u.LowPart) {
		    *pContext = NULL;
		    return STATUS_NO_MORE_ENTRIES;
		}

		__try {
		    CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
			      MAP_WAIT, pContext, pPage);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
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
		    RtlCopyMemory(Name, LongNameEntry->Name0_4,
				  5 * sizeof(WCHAR));
		    RtlCopyMemory(Name + 5, LongNameEntry->Name5_10,
				  6 * sizeof(WCHAR));
		    RtlCopyMemory(Name + 11, LongNameEntry->Name11_12,
				  2 * sizeof(WCHAR));

		    if (LongNameEntry->Id & 0x40) {
			/* It's last LFN entry. Terminate filename with \0 */
			Name[13] = UNICODE_NULL;
		    }
		} else
		    DPRINT1("Long name entry has invalid Index: %x!\n",
			    LongNameEntry->Id);

		DPRINT("  longName: [%S]\n", DirContext->LongNameU.Buffer);

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

		if (ShortCheckSum != CheckSum
		    && DirContext->LongNameU.Buffer[0]) {
		    DPRINT1
			("Checksum from long and short name is not equal (short: %x, long: %x, %S)\n",
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
	    FileOffset.u.LowPart += PAGE_SIZE;

	    if (FileOffset.u.LowPart >= DirFcb->Base.FileSize.u.LowPart) {
		*pContext = NULL;
		return STATUS_NO_MORE_ENTRIES;
	    }

	    __try {
		CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
			  MAP_WAIT, pContext, pPage);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
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
    DirContext->LongNameU.Buffer[DirContext->LongNameU.MaximumLength /
				 sizeof(WCHAR) - 1]
	= UNICODE_NULL;
    DirContext->LongNameU.Length =
	wcslen(DirContext->LongNameU.Buffer) * sizeof(WCHAR);

    /* Init short name */
    Fat8Dot3ToString(&DirContext->DirEntry.Fat, &DirContext->ShortNameU);

    /* If we found no LFN, use short name as long */
    if (DirContext->LongNameU.Length == 0)
	RtlCopyUnicodeString(&DirContext->LongNameU,
			     &DirContext->ShortNameU);

    return STATUS_SUCCESS;
}

NTSTATUS FATXGetNextDirEntry(PVOID *pContext, PVOID *pPage, IN PFATFCB DirFcb,
			     PFAT_DIRENTRY_CONTEXT DirContext, BOOLEAN First)
{
    LARGE_INTEGER FileOffset;
    PFATX_DIR_ENTRY fatxDirEntry;
    OEM_STRING StringO;
    ULONG DirIndex = DirContext->DirIndex;
    NTSTATUS Status;

    FileOffset.u.HighPart = 0;

    UNREFERENCED_PARAMETER(First);

    if (!FatFCBIsRoot(DirFcb)) {
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

    Status =
	FatFCBInitializeCacheFromVolume(DirContext->DeviceExt, DirFcb);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if (*pContext == NULL || (DirIndex % FATX_ENTRIES_PER_PAGE) == 0) {
	if (*pContext != NULL) {
	    CcUnpinData(*pContext);
	}
	FileOffset.u.LowPart =
	    ROUND_DOWN(DirIndex * sizeof(FATX_DIR_ENTRY), PAGE_SIZE);
	if (FileOffset.u.LowPart >= DirFcb->Base.FileSize.u.LowPart) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}

	__try {
	    CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
		      MAP_WAIT, pContext, pPage);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}
    }

    fatxDirEntry = (PFATX_DIR_ENTRY)(*pPage) + DirIndex % FATX_ENTRIES_PER_PAGE;

    DirContext->StartIndex = DirContext->DirIndex;

    while (TRUE) {
	if (FATX_ENTRY_END(fatxDirEntry)) {
	    CcUnpinData(*pContext);
	    *pContext = NULL;
	    return STATUS_NO_MORE_ENTRIES;
	}

	if (!FATX_ENTRY_DELETED(fatxDirEntry)) {
	    RtlCopyMemory(&DirContext->DirEntry.FatX, fatxDirEntry,
			  sizeof(FATX_DIR_ENTRY));
	    break;
	}
	DirContext->DirIndex++;
	DirContext->StartIndex++;
	DirIndex++;
	if ((DirIndex % FATX_ENTRIES_PER_PAGE) == 0) {
	    CcUnpinData(*pContext);
	    FileOffset.u.LowPart += PAGE_SIZE;
	    if (FileOffset.u.LowPart >= DirFcb->Base.FileSize.u.LowPart) {
		*pContext = NULL;
		return STATUS_NO_MORE_ENTRIES;
	    }

	    __try {
		CcMapData(DirFcb->FileObject, &FileOffset, PAGE_SIZE,
			  MAP_WAIT, pContext, pPage);
	    } __except(EXCEPTION_EXECUTE_HANDLER) {
		*pContext = NULL;
		return STATUS_NO_MORE_ENTRIES;
	    }

	    fatxDirEntry = (PFATX_DIR_ENTRY) * pPage;
	} else {
	    fatxDirEntry++;
	}
    }
    StringO.Buffer = (PCHAR) fatxDirEntry->Filename;
    StringO.Length = StringO.MaximumLength = fatxDirEntry->FilenameLength;
    RtlOemStringToUnicodeString(&DirContext->LongNameU, &StringO, FALSE);
    DirContext->ShortNameU = DirContext->LongNameU;
    return STATUS_SUCCESS;
}
