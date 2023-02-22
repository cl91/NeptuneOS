/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Routines to manipulate FCBs
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2001 Rex Jolliff <rex@lvcablemodem.com>
 *              Copyright 2005-2022 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2008-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/*  -------------------------------------------------------  INCLUDES  */

#include "fatfs.h"

/*  --------------------------------------------------------  PUBLICS  */

static ULONG FatNameHash(ULONG hash, PUNICODE_STRING NameU)
{
    PWCHAR last;
    PWCHAR curr;
    register WCHAR c;

    // LFN could start from "."
    //ASSERT(NameU->Buffer[0] != L'.');
    curr = NameU->Buffer;
    last = NameU->Buffer + NameU->Length / sizeof(WCHAR);

    while (curr < last) {
	c = towlower(*curr++);
	hash = (hash + (c << 4) + (c >> 4)) * 11;
    }
    return hash;
}

VOID FatSplitPathName(PUNICODE_STRING PathNameU,
		      PUNICODE_STRING DirNameU,
		      PUNICODE_STRING FileNameU)
{
    PWCHAR pName;
    USHORT Length = 0;
    pName = PathNameU->Buffer + PathNameU->Length / sizeof(WCHAR) - 1;
    while (*pName != L'\\' && pName >= PathNameU->Buffer) {
	pName--;
	Length++;
    }
    ASSERT(*pName == L'\\' || pName < PathNameU->Buffer);
    if (FileNameU) {
	FileNameU->Buffer = pName + 1;
	FileNameU->Length = FileNameU->MaximumLength = Length * sizeof(WCHAR);
    }
    if (DirNameU) {
	DirNameU->Buffer = PathNameU->Buffer;
	DirNameU->Length = (pName + 1 - PathNameU->Buffer) * sizeof(WCHAR);
	DirNameU->MaximumLength = DirNameU->Length;
    }
}

static VOID FatInitFcb(PFATFCB Fcb, PUNICODE_STRING NameU)
{
    USHORT PathNameBufferLength;

    if (NameU)
	PathNameBufferLength = NameU->Length + sizeof(WCHAR);
    else
	PathNameBufferLength = 0;

    Fcb->PathNameBuffer = ExAllocatePoolWithTag(PathNameBufferLength, TAG_FCB);
    if (!Fcb->PathNameBuffer) {
	/* FIXME: what to do if no more memory? */
	DPRINT1("Unable to initialize FCB for filename '%wZ'\n", NameU);
	KeBugCheckEx(FAT_FILE_SYSTEM, (ULONG_PTR) Fcb, (ULONG_PTR) NameU,
		     0, 0);
    }

    Fcb->RFCB.NodeTypeCode = NODE_TYPE_FCB;
    Fcb->RFCB.NodeByteSize = sizeof(FATFCB);

    Fcb->PathNameU.Length = 0;
    Fcb->PathNameU.Buffer = Fcb->PathNameBuffer;
    Fcb->PathNameU.MaximumLength = PathNameBufferLength;
    Fcb->ShortNameU.Length = 0;
    Fcb->ShortNameU.Buffer = Fcb->ShortNameBuffer;
    Fcb->ShortNameU.MaximumLength = sizeof(Fcb->ShortNameBuffer);
    Fcb->DirNameU.Buffer = Fcb->PathNameU.Buffer;
    if (NameU && NameU->Length) {
	RtlCopyUnicodeString(&Fcb->PathNameU, NameU);
	FatSplitPathName(&Fcb->PathNameU, &Fcb->DirNameU, &Fcb->LongNameU);
    } else {
	Fcb->DirNameU.Buffer = Fcb->LongNameU.Buffer = NULL;
	Fcb->DirNameU.MaximumLength = Fcb->DirNameU.Length = 0;
	Fcb->LongNameU.MaximumLength = Fcb->LongNameU.Length = 0;
    }
    RtlZeroMemory(&Fcb->FCBShareAccess, sizeof(SHARE_ACCESS));
    Fcb->OpenHandleCount = 0;
}

PFATFCB FatNewFCB(PDEVICE_EXTENSION pVCB, PUNICODE_STRING pFileNameU)
{
    PFATFCB rcFCB;

    DPRINT("'%wZ'\n", pFileNameU);

    rcFCB = ExAllocateFromNPagedLookasideList(&FatGlobalData->FcbLookasideList);
    if (rcFCB == NULL) {
	return NULL;
    }
    RtlZeroMemory(rcFCB, sizeof(FATFCB));
    FatInitFcb(rcFCB, pFileNameU);
    if (FatVolumeIsFatX(pVCB))
	rcFCB->Attributes = &rcFCB->entry.FatX.Attrib;
    else
	rcFCB->Attributes = &rcFCB->entry.Fat.Attrib;
    rcFCB->Hash.Hash = FatNameHash(0, &rcFCB->PathNameU);
    rcFCB->Hash.self = rcFCB;
    rcFCB->ShortHash.self = rcFCB;
    ExInitializeResourceLite(&rcFCB->PagingIoResource);
    ExInitializeResourceLite(&rcFCB->MainResource);
    FsRtlInitializeFileLock(&rcFCB->FileLock, NULL, NULL);
    ExInitializeFastMutex(&rcFCB->LastMutex);
    rcFCB->RFCB.PagingIoResource = &rcFCB->PagingIoResource;
    rcFCB->RFCB.Resource = &rcFCB->MainResource;
    rcFCB->RFCB.IsFastIoPossible = FastIoIsNotPossible;
    InitializeListHead(&rcFCB->ParentListHead);

    return rcFCB;
}

static VOID FatDelFCBFromTable(PDEVICE_EXTENSION pVCB, PFATFCB pFCB)
{
    ULONG Index;
    ULONG ShortIndex;
    HASHENTRY *entry;

    Index = pFCB->Hash.Hash % pVCB->HashTableSize;
    ShortIndex = pFCB->ShortHash.Hash % pVCB->HashTableSize;

    if (pFCB->Hash.Hash != pFCB->ShortHash.Hash) {
	entry = pVCB->FcbHashTable[ShortIndex];
	if (entry->self == pFCB) {
	    pVCB->FcbHashTable[ShortIndex] = entry->next;
	} else {
	    while (entry->next->self != pFCB) {
		entry = entry->next;
	    }
	    entry->next = pFCB->ShortHash.next;
	}
    }
    entry = pVCB->FcbHashTable[Index];
    if (entry->self == pFCB) {
	pVCB->FcbHashTable[Index] = entry->next;
    } else {
	while (entry->next->self != pFCB) {
	    entry = entry->next;
	}
	entry->next = pFCB->Hash.next;
    }

    RemoveEntryList(&pFCB->FcbListEntry);
}

static NTSTATUS FatMakeFullName(PFATFCB directoryFCB,
				PUNICODE_STRING LongNameU,
				PUNICODE_STRING ShortNameU,
				PUNICODE_STRING NameU)
{
    PWCHAR PathNameBuffer;
    USHORT PathNameLength;

    PathNameLength = directoryFCB->PathNameU.Length + max(LongNameU->Length,
							  ShortNameU->Length);
    if (!FatFCBIsRoot(directoryFCB)) {
	PathNameLength += sizeof(WCHAR);
    }

    if (PathNameLength > LONGNAME_MAX_LENGTH * sizeof(WCHAR)) {
	return STATUS_OBJECT_NAME_INVALID;
    }
    PathNameBuffer = ExAllocatePoolWithTag(NonPagedPool, PathNameLength + sizeof(WCHAR),
					   TAG_FCB);
    if (!PathNameBuffer) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    NameU->Buffer = PathNameBuffer;
    NameU->Length = 0;
    NameU->MaximumLength = PathNameLength;

    RtlCopyUnicodeString(NameU, &directoryFCB->PathNameU);
    if (!FatFCBIsRoot(directoryFCB)) {
	RtlAppendUnicodeToString(NameU, L"\\");
    }
    if (LongNameU->Length > 0) {
	RtlAppendUnicodeStringToString(NameU, LongNameU);
    } else {
	RtlAppendUnicodeStringToString(NameU, ShortNameU);
    }
    NameU->Buffer[NameU->Length / sizeof(WCHAR)] = 0;

    return STATUS_SUCCESS;
}

VOID FatDestroyCCB(PFATCCB pCcb)
{
    if (pCcb->SearchPattern.Buffer) {
	ExFreePoolWithTag(pCcb->SearchPattern.Buffer, TAG_SEARCH);
    }
    ExFreeToNPagedLookasideList(&FatGlobalData->CcbLookasideList, pCcb);
}

VOID FatDestroyFCB(PFATFCB pFCB)
{
#ifdef KDBG
    if (DebugFile.Buffer != NULL
	&& FsRtlIsNameInExpression(&DebugFile, &pFCB->LongNameU, FALSE,
				   NULL)) {
	DPRINT1("Destroying: %p (%wZ) %d\n", pFCB, &pFCB->PathNameU,
		pFCB->RefCount);
    }
#endif

    FsRtlUninitializeFileLock(&pFCB->FileLock);

    if (!FatFCBIsRoot(pFCB) &&
	!BooleanFlagOn(pFCB->Flags, FCB_IS_FAT)
	&& !BooleanFlagOn(pFCB->Flags, FCB_IS_VOLUME)) {
	RemoveEntryList(&pFCB->ParentListEntry);
    }
    ExFreePool(pFCB->PathNameBuffer);
    ExDeleteResourceLite(&pFCB->PagingIoResource);
    ExDeleteResourceLite(&pFCB->MainResource);
    ASSERT(IsListEmpty(&pFCB->ParentListHead));
    ExFreeToNPagedLookasideList(&FatGlobalData->FcbLookasideList, pFCB);
}

BOOLEAN FatFCBIsRoot(PFATFCB FCB)
{
    return FCB->PathNameU.Length == sizeof(WCHAR)
	&& FCB->PathNameU.Buffer[0] == L'\\' ? TRUE : FALSE;
}

VOID FatGrabFCB(PDEVICE_EXTENSION pVCB, PFATFCB pFCB)
{
    DPRINT("Grabbing FCB at %p: %wZ, refCount:%d\n",
	   pFCB, &pFCB->PathNameU, pFCB->RefCount);

    ASSERT(ExIsResourceAcquiredExclusive(&pVCB->DirResource));

    ASSERT(!BooleanFlagOn(pFCB->Flags, FCB_IS_FAT));
    ASSERT(pFCB != pVCB->VolumeFcb
	   && !BooleanFlagOn(pFCB->Flags, FCB_IS_VOLUME));
    ASSERT(pFCB->RefCount > 0);
    ++pFCB->RefCount;
}

VOID FatReleaseFCB(PDEVICE_EXTENSION pVCB, PFATFCB pFCB)
{
    PFATFCB tmpFcb;

    DPRINT("Releasing FCB at %p: %wZ, refCount:%d\n",
	   pFCB, &pFCB->PathNameU, pFCB->RefCount);

    ASSERT(ExIsResourceAcquiredExclusive(&pVCB->DirResource));

    while (pFCB) {
	ULONG RefCount;

	ASSERT(!BooleanFlagOn(pFCB->Flags, FCB_IS_FAT));
	ASSERT(pFCB != pVCB->VolumeFcb
	       && !BooleanFlagOn(pFCB->Flags, FCB_IS_VOLUME));
	ASSERT(pFCB->RefCount > 0);
	RefCount = --pFCB->RefCount;

	if (RefCount == 1
	    && BooleanFlagOn(pFCB->Flags, FCB_CACHE_INITIALIZED)) {
	    PFILE_OBJECT tmpFileObject;
	    tmpFileObject = pFCB->FileObject;

	    pFCB->FileObject = NULL;
	    CcUninitializeCacheMap(tmpFileObject, NULL, NULL);
	    ClearFlag(pFCB->Flags, FCB_CACHE_INITIALIZED);
	    ObDereferenceObject(tmpFileObject);
	}

	if (RefCount == 0) {
	    ASSERT(pFCB->OpenHandleCount == 0);
	    tmpFcb = pFCB->parentFcb;
	    FatDelFCBFromTable(pVCB, pFCB);
	    FatDestroyFCB(pFCB);
	} else {
	    tmpFcb = NULL;
	}
	pFCB = tmpFcb;
    }
}

static VOID FatAddFCBToTable(PDEVICE_EXTENSION pVCB, PFATFCB pFCB)
{
    ULONG Index;
    ULONG ShortIndex;

    ASSERT(pFCB->Hash.Hash == FatNameHash(0, &pFCB->PathNameU));
    Index = pFCB->Hash.Hash % pVCB->HashTableSize;
    ShortIndex = pFCB->ShortHash.Hash % pVCB->HashTableSize;

    InsertTailList(&pVCB->FcbListHead, &pFCB->FcbListEntry);

    pFCB->Hash.next = pVCB->FcbHashTable[Index];
    pVCB->FcbHashTable[Index] = &pFCB->Hash;
    if (pFCB->Hash.Hash != pFCB->ShortHash.Hash) {
	pFCB->ShortHash.next = pVCB->FcbHashTable[ShortIndex];
	pVCB->FcbHashTable[ShortIndex] = &pFCB->ShortHash;
    }
    if (pFCB->parentFcb) {
	FatGrabFCB(pVCB, pFCB->parentFcb);
    }
}

static VOID FatInitFCBFromDirEntry(PDEVICE_EXTENSION Vcb,
				   PFATFCB ParentFcb,
				   PFATFCB Fcb,
				   PFAT_DIRENTRY_CONTEXT DirContext)
{
    ULONG Size;

    RtlCopyMemory(&Fcb->entry, &DirContext->DirEntry, sizeof(DIR_ENTRY));
    RtlCopyUnicodeString(&Fcb->ShortNameU, &DirContext->ShortNameU);
    Fcb->Hash.Hash = FatNameHash(0, &Fcb->PathNameU);
    if (FatVolumeIsFatX(Vcb)) {
	Fcb->ShortHash.Hash = Fcb->Hash.Hash;
    } else {
	Fcb->ShortHash.Hash = FatNameHash(0, &Fcb->DirNameU);
	Fcb->ShortHash.Hash = FatNameHash(Fcb->ShortHash.Hash, &Fcb->ShortNameU);
    }

    if (FatFCBIsDirectory(Fcb)) {
	ULONG FirstCluster, CurrentCluster;
	NTSTATUS Status = STATUS_SUCCESS;
	Size = 0;
	FirstCluster = FatDirEntryGetFirstCluster(Vcb, &Fcb->entry);
	if (FirstCluster == 1) {
	    Size = Vcb->FatInfo.rootDirectorySectors *
		Vcb->FatInfo.BytesPerSector;
	} else if (FirstCluster != 0) {
	    CurrentCluster = FirstCluster;
	    while (CurrentCluster != 0xffffffff && NT_SUCCESS(Status)) {
		Size += Vcb->FatInfo.BytesPerCluster;
		Status = NextCluster(Vcb, FirstCluster, &CurrentCluster, FALSE);
	    }
	}
    } else if (FatVolumeIsFatX(Vcb)) {
	Size = Fcb->entry.FatX.FileSize;
    } else {
	Size = Fcb->entry.Fat.FileSize;
    }
    Fcb->dirIndex = DirContext->DirIndex;
    Fcb->startIndex = DirContext->StartIndex;
    Fcb->parentFcb = ParentFcb;
    if (FatVolumeIsFatX(Vcb) && !FatFCBIsRoot(ParentFcb)) {
	ASSERT(DirContext->DirIndex >= 2 && DirContext->StartIndex >= 2);
	Fcb->dirIndex = DirContext->DirIndex - 2;
	Fcb->startIndex = DirContext->StartIndex - 2;
    }
    Fcb->RFCB.FileSize.QuadPart = Size;
    Fcb->RFCB.ValidDataLength.QuadPart = Size;
    Fcb->RFCB.AllocationSize.QuadPart = ROUND_UP_64(Size, Vcb->FatInfo.BytesPerCluster);
}

NTSTATUS FatSetFCBNewDirName(PDEVICE_EXTENSION pVCB,
			     PFATFCB Fcb,
			     PFATFCB ParentFcb)
{
    NTSTATUS Status;
    UNICODE_STRING NewNameU;

    /* Get full path name */
    Status = FatMakeFullName(ParentFcb, &Fcb->LongNameU, &Fcb->ShortNameU,
			     &NewNameU);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Delete old name */
    if (Fcb->PathNameBuffer) {
	ExFreePoolWithTag(Fcb->PathNameBuffer, TAG_FCB);
    }
    Fcb->PathNameU = NewNameU;

    /* Delete from table */
    FatDelFCBFromTable(pVCB, Fcb);

    /* Split it properly */
    Fcb->PathNameBuffer = Fcb->PathNameU.Buffer;
    Fcb->DirNameU.Buffer = Fcb->PathNameU.Buffer;
    FatSplitPathName(&Fcb->PathNameU, &Fcb->DirNameU, &Fcb->LongNameU);
    Fcb->Hash.Hash = FatNameHash(0, &Fcb->PathNameU);
    if (FatVolumeIsFatX(pVCB)) {
	Fcb->ShortHash.Hash = Fcb->Hash.Hash;
    } else {
	Fcb->ShortHash.Hash = FatNameHash(0, &Fcb->DirNameU);
	Fcb->ShortHash.Hash = FatNameHash(Fcb->ShortHash.Hash, &Fcb->ShortNameU);
    }

    FatAddFCBToTable(pVCB, Fcb);
    FatReleaseFCB(pVCB, ParentFcb);

    return STATUS_SUCCESS;
}

NTSTATUS FatUpdateFCB(PDEVICE_EXTENSION pVCB,
		      PFATFCB Fcb,
		      PFAT_DIRENTRY_CONTEXT DirContext,
		      PFATFCB ParentFcb)
{
    NTSTATUS Status;
    PFATFCB OldParent;

    DPRINT("FatUpdateFCB(%p, %p, %p, %p)\n", pVCB, Fcb, DirContext,
	   ParentFcb);

    /* Get full path name */
    Status = FatMakeFullName(ParentFcb, &DirContext->LongNameU,
			     &DirContext->ShortNameU, &Fcb->PathNameU);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Delete old name */
    if (Fcb->PathNameBuffer) {
	ExFreePoolWithTag(Fcb->PathNameBuffer, TAG_FCB);
    }

    /* Delete from table */
    FatDelFCBFromTable(pVCB, Fcb);

    /* Split it properly */
    Fcb->PathNameBuffer = Fcb->PathNameU.Buffer;
    Fcb->DirNameU.Buffer = Fcb->PathNameU.Buffer;
    FatSplitPathName(&Fcb->PathNameU, &Fcb->DirNameU, &Fcb->LongNameU);

    /* Save old parent */
    OldParent = Fcb->parentFcb;
    RemoveEntryList(&Fcb->ParentListEntry);

    /* Reinit FCB */
    FatInitFCBFromDirEntry(pVCB, ParentFcb, Fcb, DirContext);

    if (FatFCBIsDirectory(Fcb)) {
	CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, NULL);
    }
    InsertTailList(&ParentFcb->ParentListHead, &Fcb->ParentListEntry);
    FatAddFCBToTable(pVCB, Fcb);

    /* If we moved across directories, dereference our old parent
     * We also dereference in case we're just renaming since AddFCBToTable references it
     */
    FatReleaseFCB(pVCB, OldParent);

    return STATUS_SUCCESS;
}

PFATFCB FatGrabFCBFromTable(PDEVICE_EXTENSION pVCB,
			    PUNICODE_STRING PathNameU)
{
    PFATFCB rcFCB;
    ULONG Hash;
    UNICODE_STRING DirNameU;
    UNICODE_STRING FileNameU;
    PUNICODE_STRING FcbNameU;

    HASHENTRY *entry;

    DPRINT("'%wZ'\n", PathNameU);

    ASSERT(PathNameU->Length >= sizeof(WCHAR)
	   && PathNameU->Buffer[0] == L'\\');
    Hash = FatNameHash(0, PathNameU);

    entry = pVCB->FcbHashTable[Hash % pVCB->HashTableSize];
    if (entry) {
	FatSplitPathName(PathNameU, &DirNameU, &FileNameU);
    }

    while (entry) {
	if (entry->Hash == Hash) {
	    rcFCB = entry->self;
	    DPRINT("'%wZ' '%wZ'\n", &DirNameU, &rcFCB->DirNameU);
	    if (RtlEqualUnicodeString(&DirNameU, &rcFCB->DirNameU, TRUE)) {
		if (rcFCB->Hash.Hash == Hash) {
		    FcbNameU = &rcFCB->LongNameU;
		} else {
		    FcbNameU = &rcFCB->ShortNameU;
		}
		/* compare the file name */
		DPRINT("'%wZ' '%wZ'\n", &FileNameU, FcbNameU);
		if (RtlEqualUnicodeString(&FileNameU, FcbNameU, TRUE)) {
		    FatGrabFCB(pVCB, rcFCB);
		    return rcFCB;
		}
	    }
	}
	entry = entry->next;
    }
    return NULL;
}

PFATFCB FatMakeRootFCB(PDEVICE_EXTENSION pVCB)
{
    PFATFCB FCB;
    ULONG FirstCluster, CurrentCluster, Size = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING NameU = RTL_CONSTANT_STRING(L"\\");

    ASSERT(pVCB->RootFcb == NULL);

    FCB = FatNewFCB(pVCB, &NameU);
    if (FatVolumeIsFatX(pVCB)) {
	memset(FCB->entry.FatX.Filename, ' ', 42);
	FCB->entry.FatX.FileSize = pVCB->FatInfo.rootDirectorySectors *
	    pVCB->FatInfo.BytesPerSector;
	FCB->entry.FatX.Attrib = FILE_ATTRIBUTE_DIRECTORY;
	FCB->entry.FatX.FirstCluster = 1;
	Size = pVCB->FatInfo.rootDirectorySectors *
	    pVCB->FatInfo.BytesPerSector;
    } else {
	memset(FCB->entry.Fat.ShortName, ' ', 11);
	FCB->entry.Fat.FileSize = pVCB->FatInfo.rootDirectorySectors *
	    pVCB->FatInfo.BytesPerSector;
	FCB->entry.Fat.Attrib = FILE_ATTRIBUTE_DIRECTORY;
	if (pVCB->FatInfo.FatType == FAT32) {
	    CurrentCluster = FirstCluster = pVCB->FatInfo.RootCluster;
	    FCB->entry.Fat.FirstCluster = (unsigned short) (FirstCluster & 0xffff);
	    FCB->entry.Fat.FirstClusterHigh = (unsigned short) (FirstCluster >> 16);

	    while (CurrentCluster != 0xffffffff && NT_SUCCESS(Status)) {
		Size += pVCB->FatInfo.BytesPerCluster;
		Status = NextCluster(pVCB, FirstCluster, &CurrentCluster, FALSE);
	    }
	} else {
	    FCB->entry.Fat.FirstCluster = 1;
	    Size = pVCB->FatInfo.rootDirectorySectors * pVCB->FatInfo.BytesPerSector;
	}
    }
    FCB->ShortHash.Hash = FCB->Hash.Hash;
    FCB->RefCount = 2;
    FCB->dirIndex = 0;
    FCB->RFCB.FileSize.QuadPart = Size;
    FCB->RFCB.ValidDataLength.QuadPart = Size;
    FCB->RFCB.AllocationSize.QuadPart = Size;
    FCB->RFCB.IsFastIoPossible = FastIoIsNotPossible;

    FatFCBInitializeCacheFromVolume(pVCB, FCB);
    FatAddFCBToTable(pVCB, FCB);

    /* Cache it */
    pVCB->RootFcb = FCB;

    return FCB;
}

PFATFCB FatOpenRootFCB(PDEVICE_EXTENSION pVCB)
{
    PFATFCB FCB;
    UNICODE_STRING NameU = RTL_CONSTANT_STRING(L"\\");

    FCB = FatGrabFCBFromTable(pVCB, &NameU);
    if (FCB == NULL) {
	FCB = FatMakeRootFCB(pVCB);
    }
    ASSERT(FCB == pVCB->RootFcb);

    return FCB;
}

NTSTATUS FatMakeFCBFromDirEntry(PVCB vcb,
				PFATFCB directoryFCB,
				PFAT_DIRENTRY_CONTEXT DirContext,
				PFATFCB *fileFCB)
{
    PFATFCB rcFCB;
    UNICODE_STRING NameU;
    NTSTATUS Status;

    Status = FatMakeFullName(directoryFCB, &DirContext->LongNameU,
			     &DirContext->ShortNameU, &NameU);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    rcFCB = FatNewFCB(vcb, &NameU);
    FatInitFCBFromDirEntry(vcb, directoryFCB, rcFCB, DirContext);

    rcFCB->RefCount = 1;
    InsertTailList(&directoryFCB->ParentListHead, &rcFCB->ParentListEntry);
    FatAddFCBToTable(vcb, rcFCB);
    *fileFCB = rcFCB;

    ExFreePoolWithTag(NameU.Buffer, TAG_FCB);
    return STATUS_SUCCESS;
}

NTSTATUS FatAttachFCBToFileObject(PDEVICE_EXTENSION vcb,
				  PFATFCB fcb, PFILE_OBJECT fileObject)
{
    PFATCCB newCCB;

#ifdef KDBG
    if (DebugFile.Buffer != NULL
	&& FsRtlIsNameInExpression(&DebugFile, &fcb->LongNameU, FALSE,
				   NULL)) {
	DPRINT1("Attaching %p to %p (%d)\n", fcb, fileObject,
		fcb->RefCount);
    }
#endif

    newCCB = ExAllocateFromNPagedLookasideList(&FatGlobalData->
					       CcbLookasideList);
    if (newCCB == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(newCCB, sizeof(FATCCB));

    fileObject->SectionObjectPointer = &fcb->SectionObjectPointers;
    fileObject->FsContext = fcb;
    fileObject->FsContext2 = newCCB;
    fileObject->Vpb = vcb->IoVPB;
    DPRINT("file open: fcb:%p PathName:%wZ\n", fcb, &fcb->PathNameU);

#ifdef KDBG
    fcb->Flags &= ~FCB_CLEANED_UP;
    fcb->Flags &= ~FCB_CLOSED;
#endif

    return STATUS_SUCCESS;
}

NTSTATUS FatDirFindFile(PDEVICE_EXTENSION pDeviceExt,
			PFATFCB pDirectoryFCB,
			PUNICODE_STRING FileToFindU,
			PFATFCB *pFoundFCB)
{
    NTSTATUS status;
    PVOID Context = NULL;
    PVOID Page = NULL;
    BOOLEAN First = TRUE;
    FAT_DIRENTRY_CONTEXT DirContext;
    /* This buffer must have a size of 260 characters, because
       FatMakeFCBFromDirEntry can copy 20 name entries with 13 characters. */
    WCHAR LongNameBuffer[260];
    WCHAR ShortNameBuffer[13];
    BOOLEAN FoundLong = FALSE;
    BOOLEAN FoundShort = FALSE;
    BOOLEAN IsFatX = FatVolumeIsFatX(pDeviceExt);

    ASSERT(pDeviceExt);
    ASSERT(pDirectoryFCB);
    ASSERT(FileToFindU);

    DPRINT("FatDirFindFile(VCB:%p, dirFCB:%p, File:%wZ)\n",
	   pDeviceExt, pDirectoryFCB, FileToFindU);
    DPRINT("Dir Path:%wZ\n", &pDirectoryFCB->PathNameU);

    DirContext.DirIndex = 0;
    DirContext.LongNameU.Buffer = LongNameBuffer;
    DirContext.LongNameU.Length = 0;
    DirContext.LongNameU.MaximumLength = sizeof(LongNameBuffer);
    DirContext.ShortNameU.Buffer = ShortNameBuffer;
    DirContext.ShortNameU.Length = 0;
    DirContext.ShortNameU.MaximumLength = sizeof(ShortNameBuffer);
    DirContext.DeviceExt = pDeviceExt;

    while (TRUE) {
	status = FatGetNextDirEntry(pDeviceExt,
				    &Context,
				    &Page,
				    pDirectoryFCB, &DirContext, First);
	First = FALSE;
	if (status == STATUS_NO_MORE_ENTRIES) {
	    return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!NT_SUCCESS(status)) {
	    return status;
	}

	DPRINT("  Index:%u  longName:%wZ\n",
	       DirContext.DirIndex, &DirContext.LongNameU);

	if (!ENTRY_VOLUME(IsFatX, &DirContext.DirEntry)) {
	    if (DirContext.LongNameU.Length == 0 ||
		DirContext.ShortNameU.Length == 0) {
		DPRINT1("WARNING: File system corruption detected. You may "
			"need to run a disk repair utility.\n");
		if (FatGlobalData->Flags & FAT_BREAK_ON_CORRUPTION) {
		    ASSERT(DirContext.LongNameU.Length != 0 &&
			   DirContext.ShortNameU.Length != 0);
		}
		DirContext.DirIndex++;
		continue;
	    }
	    FoundLong = RtlEqualUnicodeString(FileToFindU, &DirContext.LongNameU,
					      TRUE);
	    if (FoundLong == FALSE) {
		FoundShort = RtlEqualUnicodeString(FileToFindU,
						   &DirContext.ShortNameU, TRUE);
	    }
	    if (FoundLong || FoundShort) {
		status = FatMakeFCBFromDirEntry(pDeviceExt,
						pDirectoryFCB,
						&DirContext, pFoundFCB);
		CcUnpinData(Context);
		return status;
	    }
	}
	DirContext.DirIndex++;
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS FatGetFCBForFile(PDEVICE_EXTENSION pVCB,
			  PFATFCB *pParentFCB,
			  PFATFCB *pFCB,
			  PUNICODE_STRING pFileNameU)
{
    NTSTATUS status;
    PFATFCB FCB = NULL;
    PFATFCB parentFCB;
    UNICODE_STRING NameU;
    UNICODE_STRING RootNameU = RTL_CONSTANT_STRING(L"\\");
    UNICODE_STRING FileNameU;
    WCHAR NameBuffer[260];
    PWCHAR curr, prev, last;
    ULONG Length;

    DPRINT("FatGetFCBForFile (%p,%p,%p,%wZ)\n",
	   pVCB, pParentFCB, pFCB, pFileNameU);

    RtlInitEmptyUnicodeString(&FileNameU, NameBuffer, sizeof(NameBuffer));

    parentFCB = *pParentFCB;

    if (parentFCB == NULL) {
	/* Passed-in name is the full name */
	RtlCopyUnicodeString(&FileNameU, pFileNameU);

	//  Trivial case, open of the root directory on volume
	if (RtlEqualUnicodeString(&FileNameU, &RootNameU, FALSE)) {
	    DPRINT("returning root FCB\n");

	    FCB = FatOpenRootFCB(pVCB);
	    *pFCB = FCB;
	    *pParentFCB = NULL;

	    return (FCB != NULL) ? STATUS_SUCCESS : STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/* Check for an existing FCB */
	FCB = FatGrabFCBFromTable(pVCB, &FileNameU);
	if (FCB) {
	    *pFCB = FCB;
	    *pParentFCB = FCB->parentFcb;
	    FatGrabFCB(pVCB, *pParentFCB);
	    return STATUS_SUCCESS;
	}

	last = curr = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
	while (*curr != L'\\' && curr > FileNameU.Buffer) {
	    curr--;
	}

	if (curr > FileNameU.Buffer) {
	    NameU.Buffer = FileNameU.Buffer;
	    NameU.Length = (curr - FileNameU.Buffer) * sizeof(WCHAR);
	    NameU.MaximumLength = NameU.Length;
	    FCB = FatGrabFCBFromTable(pVCB, &NameU);
	    if (FCB) {
		Length = (curr - FileNameU.Buffer) * sizeof(WCHAR);
		if (Length != FCB->PathNameU.Length) {
		    if (FileNameU.Length + FCB->PathNameU.Length - Length >
			FileNameU.MaximumLength) {
			FatReleaseFCB(pVCB, FCB);
			return STATUS_OBJECT_NAME_INVALID;
		    }
		    RtlMoveMemory(FileNameU.Buffer +
				  FCB->PathNameU.Length / sizeof(WCHAR),
				  curr, FileNameU.Length - Length);
		    FileNameU.Length += (USHORT) (FCB->PathNameU.Length - Length);
		    curr = FileNameU.Buffer + FCB->PathNameU.Length / sizeof(WCHAR);
		    last = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
		}
		RtlCopyMemory(FileNameU.Buffer, FCB->PathNameU.Buffer,
			      FCB->PathNameU.Length);
	    }
	} else {
	    FCB = NULL;
	}

	if (FCB == NULL) {
	    FCB = FatOpenRootFCB(pVCB);
	    curr = FileNameU.Buffer;
	}

	parentFCB = NULL;
	prev = curr;
    } else {
	/* Make absolute path */
	RtlCopyUnicodeString(&FileNameU, &parentFCB->PathNameU);
	curr = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
	if (*curr != L'\\') {
	    RtlAppendUnicodeToString(&FileNameU, L"\\");
	    curr++;
	}
	ASSERT(*curr == L'\\');
	RtlAppendUnicodeStringToString(&FileNameU, pFileNameU);

	FCB = parentFCB;
	parentFCB = NULL;
	prev = curr;
	last = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
    }

    while (curr <= last) {
	if (parentFCB) {
	    FatReleaseFCB(pVCB, parentFCB);
	    parentFCB = NULL;
	}
	//  fail if element in FCB is not a directory
	if (!FatFCBIsDirectory(FCB)) {
	    DPRINT("Element in requested path is not a directory\n");

	    FatReleaseFCB(pVCB, FCB);
	    FCB = NULL;
	    *pParentFCB = NULL;
	    *pFCB = NULL;

	    return STATUS_OBJECT_PATH_NOT_FOUND;
	}
	parentFCB = FCB;
	if (prev < curr) {
	    Length = (curr - prev) * sizeof(WCHAR);
	    if (Length != parentFCB->LongNameU.Length) {
		if (FileNameU.Length + parentFCB->LongNameU.Length -
		    Length > FileNameU.MaximumLength) {
		    FatReleaseFCB(pVCB, parentFCB);
		    *pParentFCB = NULL;
		    *pFCB = NULL;
		    return STATUS_OBJECT_NAME_INVALID;
		}
		RtlMoveMemory(prev +
			      parentFCB->LongNameU.Length / sizeof(WCHAR),
			      curr,
			      FileNameU.Length - (curr -
						  FileNameU.Buffer) *
			      sizeof(WCHAR));
		FileNameU.Length += (USHORT) (parentFCB->LongNameU.Length - Length);
		curr = prev + parentFCB->LongNameU.Length / sizeof(WCHAR);
		last = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) -
		    1;
	    }
	    RtlCopyMemory(prev, parentFCB->LongNameU.Buffer,
			  parentFCB->LongNameU.Length);
	}
	curr++;
	prev = curr;
	while (*curr != L'\\' && curr <= last) {
	    curr++;
	}
	NameU.Buffer = FileNameU.Buffer;
	NameU.Length = (curr - NameU.Buffer) * sizeof(WCHAR);
	NameU.MaximumLength = FileNameU.MaximumLength;
	DPRINT("%wZ\n", &NameU);
	FCB = FatGrabFCBFromTable(pVCB, &NameU);
	if (FCB == NULL) {
	    NameU.Buffer = prev;
	    NameU.MaximumLength = NameU.Length = (curr - prev) * sizeof(WCHAR);
	    status = FatDirFindFile(pVCB, parentFCB, &NameU, &FCB);
	    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
		*pFCB = NULL;
		if (curr > last) {
		    *pParentFCB = parentFCB;
		    return STATUS_OBJECT_NAME_NOT_FOUND;
		} else {
		    FatReleaseFCB(pVCB, parentFCB);
		    *pParentFCB = NULL;
		    return STATUS_OBJECT_PATH_NOT_FOUND;
		}
	    } else if (!NT_SUCCESS(status)) {
		FatReleaseFCB(pVCB, parentFCB);
		*pParentFCB = NULL;
		*pFCB = NULL;

		return status;
	    }
	}
    }

    *pParentFCB = parentFCB;
    *pFCB = FCB;

    return STATUS_SUCCESS;
}
