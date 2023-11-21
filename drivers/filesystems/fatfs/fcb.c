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
#include <ctype.h>

/*  --------------------------------------------------------  PUBLICS  */

static ULONG FatNameHash(ULONG Hash, PUNICODE_STRING NameU)
{
    // LFN could start from "."
    //ASSERT(NameU->Buffer[0] != L'.');
    PWCHAR Curr = NameU->Buffer;
    PWCHAR Last = NameU->Buffer + NameU->Length / sizeof(WCHAR);
    WCHAR c;
    while (Curr < Last) {
	c = towlower(*Curr++);
	Hash = (Hash + (c << 4) + (c >> 4)) * 11;
    }
    return Hash;
}

VOID FatSplitPathName(PUNICODE_STRING PathNameU,
		      PUNICODE_STRING DirNameU,
		      PUNICODE_STRING FileNameU)
{
    PWCHAR Name;
    USHORT Length = 0;
    Name = PathNameU->Buffer + PathNameU->Length / sizeof(WCHAR) - 1;
    while (*Name != L'\\' && Name >= PathNameU->Buffer) {
	Name--;
	Length++;
    }
    ASSERT(*Name == L'\\' || Name < PathNameU->Buffer);
    if (FileNameU) {
	FileNameU->Buffer = Name + 1;
	FileNameU->Length = FileNameU->MaximumLength = Length * sizeof(WCHAR);
    }
    if (DirNameU) {
	DirNameU->Buffer = PathNameU->Buffer;
	DirNameU->Length = (Name + 1 - PathNameU->Buffer) * sizeof(WCHAR);
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
	RtlRaiseStatus(STATUS_NO_MEMORY);
    }

    Fcb->Base.NodeTypeCode = NODE_TYPE_FCB;
    Fcb->Base.NodeByteSize = sizeof(FATFCB);

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

PFATFCB FatNewFCB(PDEVICE_EXTENSION Vcb, PUNICODE_STRING FileNameU)
{
    PFATFCB Fcb;

    DPRINT("'%wZ'\n", FileNameU);

    Fcb = ExAllocateFromLookasideList(&FatGlobalData->FcbLookasideList);
    if (Fcb == NULL) {
	return NULL;
    }
    RtlZeroMemory(Fcb, sizeof(FATFCB));
    FatInitFcb(Fcb, FileNameU);
    if (FatVolumeIsFatX(Vcb))
	Fcb->Attributes = &Fcb->Entry.FatX.Attrib;
    else
	Fcb->Attributes = &Fcb->Entry.Fat.Attrib;
    Fcb->Hash.Hash = FatNameHash(0, &Fcb->PathNameU);
    Fcb->Hash.Self = Fcb;
    Fcb->ShortHash.Self = Fcb;
    InitializeListHead(&Fcb->ParentListHead);

    return Fcb;
}

static VOID FatDelFCBFromTable(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
{
    ULONG Index;
    ULONG ShortIndex;
    HASHENTRY *Entry;

    Index = Fcb->Hash.Hash % Vcb->HashTableSize;
    ShortIndex = Fcb->ShortHash.Hash % Vcb->HashTableSize;

    if (Fcb->Hash.Hash != Fcb->ShortHash.Hash) {
	Entry = Vcb->FcbHashTable[ShortIndex];
	if (Entry->Self == Fcb) {
	    Vcb->FcbHashTable[ShortIndex] = Entry->Next;
	} else {
	    while (Entry->Next->Self != Fcb) {
		Entry = Entry->Next;
	    }
	    Entry->Next = Fcb->ShortHash.Next;
	}
    }
    Entry = Vcb->FcbHashTable[Index];
    if (Entry->Self == Fcb) {
	Vcb->FcbHashTable[Index] = Entry->Next;
    } else {
	while (Entry->Next->Self != Fcb) {
	    Entry = Entry->Next;
	}
	Entry->Next = Fcb->Hash.Next;
    }

    RemoveEntryList(&Fcb->FcbListEntry);
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
    PathNameBuffer = ExAllocatePoolWithTag(PathNameLength + sizeof(WCHAR),
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
    ExFreeToLookasideList(&FatGlobalData->CcbLookasideList, pCcb);
}

VOID FatDestroyFCB(PFATFCB Fcb)
{
#ifdef KDBG
    if (DebugFile.Buffer != NULL
	&& FsRtlIsNameInExpression(&DebugFile, &Fcb->LongNameU, FALSE,
				   NULL)) {
	DPRINT1("Destroying: %p (%wZ) %d\n", Fcb, &Fcb->PathNameU,
		Fcb->RefCount);
    }
#endif

    if (!FatFCBIsRoot(Fcb) && !BooleanFlagOn(Fcb->Flags, FCB_IS_FAT)
	&& !BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME)) {
	RemoveEntryList(&Fcb->ParentListEntry);
    }
    ExFreePool(Fcb->PathNameBuffer);
    ASSERT(IsListEmpty(&Fcb->ParentListHead));
    ExFreeToLookasideList(&FatGlobalData->FcbLookasideList, Fcb);
}

BOOLEAN FatFCBIsRoot(PFATFCB FCB)
{
    return FCB->PathNameU.Length == sizeof(WCHAR)
	&& FCB->PathNameU.Buffer[0] == L'\\' ? TRUE : FALSE;
}

VOID FatGrabFCB(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
{
    DPRINT("Grabbing FCB at %p: %wZ, refCount:%d\n",
	   Fcb, &Fcb->PathNameU, Fcb->RefCount);

    ASSERT(!BooleanFlagOn(Fcb->Flags, FCB_IS_FAT));
    ASSERT(Fcb != Vcb->VolumeFcb
	   && !BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME));
    ASSERT(Fcb->RefCount > 0);
    ++Fcb->RefCount;
}

VOID FatReleaseFCB(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
{
    PFATFCB tmpFcb;

    DPRINT("Releasing FCB at %p: %wZ, refCount:%d\n",
	   Fcb, &Fcb->PathNameU, Fcb->RefCount);

    while (Fcb) {
	ULONG RefCount;

	ASSERT(!BooleanFlagOn(Fcb->Flags, FCB_IS_FAT));
	ASSERT(Fcb != Vcb->VolumeFcb
	       && !BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME));
	ASSERT(Fcb->RefCount > 0);
	RefCount = --Fcb->RefCount;

	if (RefCount == 1
	    && BooleanFlagOn(Fcb->Flags, FCB_CACHE_INITIALIZED)) {
	    PFILE_OBJECT tmpFileObject;
	    tmpFileObject = Fcb->FileObject;

	    Fcb->FileObject = NULL;
	    CcUninitializeCacheMap(tmpFileObject, NULL);
	    ClearFlag(Fcb->Flags, FCB_CACHE_INITIALIZED);
	    ObDereferenceObject(tmpFileObject);
	}

	if (RefCount == 0) {
	    ASSERT(Fcb->OpenHandleCount == 0);
	    tmpFcb = Fcb->ParentFcb;
	    FatDelFCBFromTable(Vcb, Fcb);
	    FatDestroyFCB(Fcb);
	} else {
	    tmpFcb = NULL;
	}
	Fcb = tmpFcb;
    }
}

static VOID FatAddFCBToTable(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
{
    ULONG Index;
    ULONG ShortIndex;

    ASSERT(Fcb->Hash.Hash == FatNameHash(0, &Fcb->PathNameU));
    Index = Fcb->Hash.Hash % Vcb->HashTableSize;
    ShortIndex = Fcb->ShortHash.Hash % Vcb->HashTableSize;

    InsertTailList(&Vcb->FcbListHead, &Fcb->FcbListEntry);

    Fcb->Hash.Next = Vcb->FcbHashTable[Index];
    Vcb->FcbHashTable[Index] = &Fcb->Hash;
    if (Fcb->Hash.Hash != Fcb->ShortHash.Hash) {
	Fcb->ShortHash.Next = Vcb->FcbHashTable[ShortIndex];
	Vcb->FcbHashTable[ShortIndex] = &Fcb->ShortHash;
    }
    if (Fcb->ParentFcb) {
	FatGrabFCB(Vcb, Fcb->ParentFcb);
    }
}

static VOID FatInitFCBFromDirEntry(PDEVICE_EXTENSION Vcb,
				   PFATFCB ParentFcb,
				   PFATFCB Fcb,
				   PFAT_DIRENTRY_CONTEXT DirContext)
{
    ULONG Size;

    RtlCopyMemory(&Fcb->Entry, &DirContext->DirEntry, sizeof(DIR_ENTRY));
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
	FirstCluster = FatDirEntryGetFirstCluster(Vcb, &Fcb->Entry);
	if (FirstCluster == 1) {
	    Size = Vcb->FatInfo.RootDirectorySectors *
		Vcb->FatInfo.BytesPerSector;
	} else if (FirstCluster != 0) {
	    CurrentCluster = FirstCluster;
	    while (CurrentCluster != 0xffffffff && NT_SUCCESS(Status)) {
		Size += Vcb->FatInfo.BytesPerCluster;
		Status = NextCluster(Vcb, FirstCluster, &CurrentCluster, FALSE);
	    }
	}
    } else if (FatVolumeIsFatX(Vcb)) {
	Size = Fcb->Entry.FatX.FileSize;
    } else {
	Size = Fcb->Entry.Fat.FileSize;
    }
    Fcb->DirIndex = DirContext->DirIndex;
    Fcb->StartIndex = DirContext->StartIndex;
    Fcb->ParentFcb = ParentFcb;
    if (FatVolumeIsFatX(Vcb) && !FatFCBIsRoot(ParentFcb)) {
	ASSERT(DirContext->DirIndex >= 2 && DirContext->StartIndex >= 2);
	Fcb->DirIndex = DirContext->DirIndex - 2;
	Fcb->StartIndex = DirContext->StartIndex - 2;
    }
    Fcb->Base.FileSize.QuadPart = Size;
    Fcb->Base.ValidDataLength.QuadPart = Size;
    Fcb->Base.AllocationSize.QuadPart = ROUND_UP_64(Size, Vcb->FatInfo.BytesPerCluster);
}

NTSTATUS FatSetFCBNewDirName(PDEVICE_EXTENSION Vcb,
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
    FatDelFCBFromTable(Vcb, Fcb);

    /* Split it properly */
    Fcb->PathNameBuffer = Fcb->PathNameU.Buffer;
    Fcb->DirNameU.Buffer = Fcb->PathNameU.Buffer;
    FatSplitPathName(&Fcb->PathNameU, &Fcb->DirNameU, &Fcb->LongNameU);
    Fcb->Hash.Hash = FatNameHash(0, &Fcb->PathNameU);
    if (FatVolumeIsFatX(Vcb)) {
	Fcb->ShortHash.Hash = Fcb->Hash.Hash;
    } else {
	Fcb->ShortHash.Hash = FatNameHash(0, &Fcb->DirNameU);
	Fcb->ShortHash.Hash = FatNameHash(Fcb->ShortHash.Hash, &Fcb->ShortNameU);
    }

    FatAddFCBToTable(Vcb, Fcb);
    FatReleaseFCB(Vcb, ParentFcb);

    return STATUS_SUCCESS;
}

NTSTATUS FatUpdateFCB(PDEVICE_EXTENSION Vcb,
		      PFATFCB Fcb,
		      PFAT_DIRENTRY_CONTEXT DirContext,
		      PFATFCB ParentFcb)
{
    NTSTATUS Status;
    PFATFCB OldParent;

    DPRINT("FatUpdateFCB(%p, %p, %p, %p)\n", Vcb, Fcb, DirContext,
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
    FatDelFCBFromTable(Vcb, Fcb);

    /* Split it properly */
    Fcb->PathNameBuffer = Fcb->PathNameU.Buffer;
    Fcb->DirNameU.Buffer = Fcb->PathNameU.Buffer;
    FatSplitPathName(&Fcb->PathNameU, &Fcb->DirNameU, &Fcb->LongNameU);

    /* Save old parent */
    OldParent = Fcb->ParentFcb;
    RemoveEntryList(&Fcb->ParentListEntry);

    /* Reinit FCB */
    FatInitFCBFromDirEntry(Vcb, ParentFcb, Fcb, DirContext);

    if (FatFCBIsDirectory(Fcb)) {
	CcFlushCache(&Fcb->Base, NULL, 0, NULL);
    }
    InsertTailList(&ParentFcb->ParentListHead, &Fcb->ParentListEntry);
    FatAddFCBToTable(Vcb, Fcb);

    /* If we moved across directories, dereference our old parent
     * We also dereference in case we're just renaming since AddFCBToTable references it
     */
    FatReleaseFCB(Vcb, OldParent);

    return STATUS_SUCCESS;
}

PFATFCB FatGrabFCBFromTable(PDEVICE_EXTENSION Vcb,
			    PUNICODE_STRING PathNameU)
{
    PFATFCB Fcb;
    ULONG Hash;
    UNICODE_STRING DirNameU;
    UNICODE_STRING FileNameU;
    PUNICODE_STRING FcbNameU;

    HASHENTRY *Entry;

    DPRINT("'%wZ'\n", PathNameU);

    ASSERT(PathNameU->Length >= sizeof(WCHAR)
	   && PathNameU->Buffer[0] == L'\\');
    Hash = FatNameHash(0, PathNameU);

    Entry = Vcb->FcbHashTable[Hash % Vcb->HashTableSize];
    if (Entry) {
	FatSplitPathName(PathNameU, &DirNameU, &FileNameU);
    }

    while (Entry) {
	if (Entry->Hash == Hash) {
	    Fcb = Entry->Self;
	    DPRINT("'%wZ' '%wZ'\n", &DirNameU, &Fcb->DirNameU);
	    if (RtlEqualUnicodeString(&DirNameU, &Fcb->DirNameU, TRUE)) {
		if (Fcb->Hash.Hash == Hash) {
		    FcbNameU = &Fcb->LongNameU;
		} else {
		    FcbNameU = &Fcb->ShortNameU;
		}
		/* compare the file name */
		DPRINT("'%wZ' '%wZ'\n", &FileNameU, FcbNameU);
		if (RtlEqualUnicodeString(&FileNameU, FcbNameU, TRUE)) {
		    FatGrabFCB(Vcb, Fcb);
		    return Fcb;
		}
	    }
	}
	Entry = Entry->Next;
    }
    return NULL;
}

PFATFCB FatMakeRootFCB(PDEVICE_EXTENSION Vcb)
{
    PFATFCB FCB;
    ULONG FirstCluster, CurrentCluster, Size = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING NameU = RTL_CONSTANT_STRING(L"\\");

    ASSERT(Vcb->RootFcb == NULL);

    FCB = FatNewFCB(Vcb, &NameU);
    if (FatVolumeIsFatX(Vcb)) {
	memset(FCB->Entry.FatX.Filename, ' ', 42);
	FCB->Entry.FatX.FileSize = Vcb->FatInfo.RootDirectorySectors *
	    Vcb->FatInfo.BytesPerSector;
	FCB->Entry.FatX.Attrib = FILE_ATTRIBUTE_DIRECTORY;
	FCB->Entry.FatX.FirstCluster = 1;
	Size = Vcb->FatInfo.RootDirectorySectors *
	    Vcb->FatInfo.BytesPerSector;
    } else {
	memset(FCB->Entry.Fat.ShortName, ' ', 11);
	FCB->Entry.Fat.FileSize = Vcb->FatInfo.RootDirectorySectors *
	    Vcb->FatInfo.BytesPerSector;
	FCB->Entry.Fat.Attrib = FILE_ATTRIBUTE_DIRECTORY;
	if (Vcb->FatInfo.FatType == FAT32) {
	    CurrentCluster = FirstCluster = Vcb->FatInfo.RootCluster;
	    FCB->Entry.Fat.FirstCluster = (unsigned short) (FirstCluster & 0xffff);
	    FCB->Entry.Fat.FirstClusterHigh = (unsigned short) (FirstCluster >> 16);

	    while (CurrentCluster != 0xffffffff && NT_SUCCESS(Status)) {
		Size += Vcb->FatInfo.BytesPerCluster;
		Status = NextCluster(Vcb, FirstCluster, &CurrentCluster, FALSE);
	    }
	} else {
	    FCB->Entry.Fat.FirstCluster = 1;
	    Size = Vcb->FatInfo.RootDirectorySectors * Vcb->FatInfo.BytesPerSector;
	}
    }
    FCB->ShortHash.Hash = FCB->Hash.Hash;
    FCB->RefCount = 2;
    FCB->DirIndex = 0;
    FCB->Base.FileSize.QuadPart = Size;
    FCB->Base.ValidDataLength.QuadPart = Size;
    FCB->Base.AllocationSize.QuadPart = Size;

    FatFCBInitializeCacheFromVolume(Vcb, FCB);
    FatAddFCBToTable(Vcb, FCB);

    /* Cache it */
    Vcb->RootFcb = FCB;

    return FCB;
}

PFATFCB FatOpenRootFCB(PDEVICE_EXTENSION Vcb)
{
    PFATFCB FCB;
    UNICODE_STRING NameU = RTL_CONSTANT_STRING(L"\\");

    FCB = FatGrabFCBFromTable(Vcb, &NameU);
    if (FCB == NULL) {
	FCB = FatMakeRootFCB(Vcb);
    }
    ASSERT(FCB == Vcb->RootFcb);

    return FCB;
}

NTSTATUS FatMakeFCBFromDirEntry(PVCB Vcb,
				PFATFCB directoryFCB,
				PFAT_DIRENTRY_CONTEXT DirContext,
				PFATFCB *fileFCB)
{
    PFATFCB Fcb;
    UNICODE_STRING NameU;
    NTSTATUS Status;

    Status = FatMakeFullName(directoryFCB, &DirContext->LongNameU,
			     &DirContext->ShortNameU, &NameU);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Fcb = FatNewFCB(Vcb, &NameU);
    FatInitFCBFromDirEntry(Vcb, directoryFCB, Fcb, DirContext);

    Fcb->RefCount = 1;
    InsertTailList(&directoryFCB->ParentListHead, &Fcb->ParentListEntry);
    FatAddFCBToTable(Vcb, Fcb);
    *fileFCB = Fcb;

    ExFreePoolWithTag(NameU.Buffer, TAG_FCB);
    return STATUS_SUCCESS;
}

NTSTATUS FatAttachFCBToFileObject(PDEVICE_EXTENSION Vcb,
				  PFATFCB Fcb, PFILE_OBJECT FileObject)
{
    PFATCCB NewCCB;

#ifdef KDBG
    if (DebugFile.Buffer != NULL
	&& FsRtlIsNameInExpression(&DebugFile, &Fcb->LongNameU, FALSE,
				   NULL)) {
	DPRINT1("Attaching %p to %p (%d)\n", Fcb, FileObject,
		Fcb->RefCount);
    }
#endif

    NewCCB = ExAllocateFromLookasideList(&FatGlobalData->CcbLookasideList);
    if (NewCCB == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(NewCCB, sizeof(FATCCB));

    FileObject->FsContext = Fcb;
    FileObject->FsContext2 = NewCCB;
    FileObject->Vpb = Vcb->IoVPB;
    DPRINT("file open: Fcb:%p PathName:%wZ\n", Fcb, &Fcb->PathNameU);

#ifdef KDBG
    Fcb->Flags &= ~FCB_CLEANED_UP;
    Fcb->Flags &= ~FCB_CLOSED;
#endif

    return STATUS_SUCCESS;
}

NTSTATUS FatDirFindFile(PDEVICE_EXTENSION DevExt,
			PFATFCB DirFcb,
			PUNICODE_STRING FileToFindU,
			PFATFCB *pFoundFCB)
{
    NTSTATUS Status;
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
    BOOLEAN IsFatX = FatVolumeIsFatX(DevExt);

    ASSERT(DevExt);
    ASSERT(DirFcb);
    ASSERT(FileToFindU);

    DPRINT("FatDirFindFile(VCB:%p, dirFCB:%p, File:%wZ)\n",
	   DevExt, DirFcb, FileToFindU);
    DPRINT("Dir Path:%wZ\n", &DirFcb->PathNameU);

    DirContext.DirIndex = 0;
    DirContext.LongNameU.Buffer = LongNameBuffer;
    DirContext.LongNameU.Length = 0;
    DirContext.LongNameU.MaximumLength = sizeof(LongNameBuffer);
    DirContext.ShortNameU.Buffer = ShortNameBuffer;
    DirContext.ShortNameU.Length = 0;
    DirContext.ShortNameU.MaximumLength = sizeof(ShortNameBuffer);
    DirContext.DeviceExt = DevExt;

    while (TRUE) {
	Status = FatGetNextDirEntry(DevExt, &Context, &Page,
				    DirFcb, &DirContext, First);
	First = FALSE;
	if (Status == STATUS_NO_MORE_ENTRIES) {
	    return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!NT_SUCCESS(Status)) {
	    return Status;
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
		Status = FatMakeFCBFromDirEntry(DevExt, DirFcb,
						&DirContext, pFoundFCB);
		CcUnpinData(Context);
		return Status;
	    }
	}
	DirContext.DirIndex++;
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS FatGetFCBForFile(PDEVICE_EXTENSION Vcb,
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
	   Vcb, pParentFCB, pFCB, pFileNameU);

    RtlInitEmptyUnicodeString(&FileNameU, NameBuffer, sizeof(NameBuffer));

    parentFCB = *pParentFCB;

    if (parentFCB == NULL) {
	/* Passed-in name is the full name */
	RtlCopyUnicodeString(&FileNameU, pFileNameU);

	//  Trivial case, open of the root directory on volume
	if (RtlEqualUnicodeString(&FileNameU, &RootNameU, FALSE)) {
	    DPRINT("returning root FCB\n");

	    FCB = FatOpenRootFCB(Vcb);
	    *pFCB = FCB;
	    *pParentFCB = NULL;

	    return (FCB != NULL) ? STATUS_SUCCESS : STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/* Check for an existing FCB */
	FCB = FatGrabFCBFromTable(Vcb, &FileNameU);
	if (FCB) {
	    *pFCB = FCB;
	    *pParentFCB = FCB->ParentFcb;
	    FatGrabFCB(Vcb, *pParentFCB);
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
	    FCB = FatGrabFCBFromTable(Vcb, &NameU);
	    if (FCB) {
		Length = (curr - FileNameU.Buffer) * sizeof(WCHAR);
		if (Length != FCB->PathNameU.Length) {
		    if (FileNameU.Length + FCB->PathNameU.Length - Length >
			FileNameU.MaximumLength) {
			FatReleaseFCB(Vcb, FCB);
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
	    FCB = FatOpenRootFCB(Vcb);
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
	    FatReleaseFCB(Vcb, parentFCB);
	    parentFCB = NULL;
	}
	//  fail if element in FCB is not a directory
	if (!FatFCBIsDirectory(FCB)) {
	    DPRINT("Element in requested path is not a directory\n");

	    FatReleaseFCB(Vcb, FCB);
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
		    FatReleaseFCB(Vcb, parentFCB);
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
	FCB = FatGrabFCBFromTable(Vcb, &NameU);
	if (FCB == NULL) {
	    NameU.Buffer = prev;
	    NameU.MaximumLength = NameU.Length = (curr - prev) * sizeof(WCHAR);
	    status = FatDirFindFile(Vcb, parentFCB, &NameU, &FCB);
	    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
		*pFCB = NULL;
		if (curr > last) {
		    *pParentFCB = parentFCB;
		    return STATUS_OBJECT_NAME_NOT_FOUND;
		} else {
		    FatReleaseFCB(Vcb, parentFCB);
		    *pParentFCB = NULL;
		    return STATUS_OBJECT_PATH_NOT_FOUND;
		}
	    } else if (!NT_SUCCESS(status)) {
		FatReleaseFCB(Vcb, parentFCB);
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
