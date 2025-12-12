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

    Fcb->PathNameBuffer = ExAllocatePoolWithTag(NonPagedPool,
						PathNameBufferLength, TAG_FCB);
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
    RtlZeroMemory(&Fcb->FcbShareAccess, sizeof(SHARE_ACCESS));
    Fcb->OpenHandleCount = 0;
}

PFATFCB FatNewFcb(PDEVICE_EXTENSION Vcb, PUNICODE_STRING FileNameU)
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

static VOID FatDelFcbFromTable(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
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

static NTSTATUS FatMakeFullName(PFATFCB DirFcb,
				PUNICODE_STRING LongNameU,
				PUNICODE_STRING ShortNameU,
				PUNICODE_STRING NameU)
{
    USHORT PathNameLength = DirFcb->PathNameU.Length +
	max(LongNameU->Length, ShortNameU->Length);
    if (!FatFcbIsRoot(DirFcb)) {
	PathNameLength += sizeof(WCHAR);
    }

    if (PathNameLength > LONGNAME_MAX_LENGTH * sizeof(WCHAR)) {
	return STATUS_OBJECT_NAME_INVALID;
    }
    PWCHAR PathNameBuffer = ExAllocatePoolWithTag(NonPagedPool,
						  PathNameLength + sizeof(WCHAR),
						  TAG_FCB);
    if (!PathNameBuffer) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    NameU->Buffer = PathNameBuffer;
    NameU->Length = 0;
    NameU->MaximumLength = PathNameLength;

    RtlCopyUnicodeString(NameU, &DirFcb->PathNameU);
    if (!FatFcbIsRoot(DirFcb)) {
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

VOID FatDestroyCcb(PFATCCB Ccb)
{
    if (Ccb->SearchPattern.Buffer) {
	ExFreePoolWithTag(Ccb->SearchPattern.Buffer, TAG_SEARCH);
    }
    ExFreeToLookasideList(&FatGlobalData->CcbLookasideList, Ccb);
}

VOID FatDestroyFcb(PFATFCB Fcb)
{
    if (!FatFcbIsRoot(Fcb) && !BooleanFlagOn(Fcb->Flags, FCB_IS_FAT)
	&& !BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME)) {
	RemoveEntryList(&Fcb->ParentListEntry);
    }
    ExFreePool(Fcb->PathNameBuffer);
    ASSERT(IsListEmpty(&Fcb->ParentListHead));
    ExFreeToLookasideList(&FatGlobalData->FcbLookasideList, Fcb);
}

BOOLEAN FatFcbIsRoot(PFATFCB FCB)
{
    return FCB->PathNameU.Length == sizeof(WCHAR)
	&& FCB->PathNameU.Buffer[0] == L'\\' ? TRUE : FALSE;
}

VOID FatGrabFcb(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
{
    DPRINT("Grabbing FCB at %p: %wZ, refCount:%d\n",
	   Fcb, &Fcb->PathNameU, Fcb->RefCount);

    ASSERT(!BooleanFlagOn(Fcb->Flags, FCB_IS_FAT));
    ASSERT(Fcb != Vcb->VolumeFcb && !BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME));
    ASSERT(Fcb->RefCount > 0);
    ++Fcb->RefCount;
}

VOID FatReleaseFcb(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
{
    DPRINT("Releasing FCB at %p: %wZ, refCount:%d\n",
	   Fcb, &Fcb->PathNameU, Fcb->RefCount);

    while (Fcb) {
	ULONG RefCount;

	ASSERT(!BooleanFlagOn(Fcb->Flags, FCB_IS_FAT));
	ASSERT(Fcb != Vcb->VolumeFcb
	       && !BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME));
	ASSERT(Fcb->RefCount > 0);
	RefCount = --Fcb->RefCount;

	if (RefCount == 0) {
	    if (BooleanFlagOn(Fcb->Flags, FCB_CACHE_INITIALIZED)) {
		DPRINT("Uninitializing caching for FCB %p\n", Fcb);
		PFILE_OBJECT FileObj = Fcb->FileObject;
		Fcb->FileObject = NULL;
		CcUninitializeCacheMap(FileObj, NULL);
		ClearFlag(Fcb->Flags, FCB_CACHE_INITIALIZED);
		assert(FileObj->Flags & FO_STREAM_FILE);
		ObDereferenceObject(FileObj);
	    }

	    ASSERT(Fcb->OpenHandleCount == 0);
	    PFATFCB ParentFcb = Fcb->ParentFcb;
	    FatDelFcbFromTable(Vcb, Fcb);
	    FatDestroyFcb(Fcb);
	    Fcb = ParentFcb;
	} else {
	    break;
	}
    }
}

static VOID FatAddFcbToTable(PDEVICE_EXTENSION Vcb, PFATFCB Fcb)
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
	FatGrabFcb(Vcb, Fcb->ParentFcb);
    }
}

static VOID FatInitFcbFromDirEntry(PDEVICE_EXTENSION Vcb,
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

    if (FatFcbIsDirectory(Fcb)) {
	ULONG FirstCluster, CurrentCluster;
	NTSTATUS Status = STATUS_SUCCESS;
	Size = 0;
	FirstCluster = FatDirEntryGetFirstCluster(Vcb, &Fcb->Entry);
	if (FirstCluster == 0) {
	    DPRINT("FirstCluster == 0 (Fcb entry %wZ). You may "
		   "need to run a disk repair utility.\n", &Fcb->DirNameU);
	    Status = STATUS_FILE_CORRUPT_ERROR;
	    if (FatGlobalData->Flags & FAT_BREAK_ON_CORRUPTION) {
		assert(FALSE);
	    }
	} else if (FirstCluster == 1) {
	    Size = Vcb->FatInfo.RootDirectorySectors * Vcb->FatInfo.BytesPerSector;
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
    if (FatVolumeIsFatX(Vcb) && !FatFcbIsRoot(ParentFcb)) {
	ASSERT(DirContext->DirIndex >= 2 && DirContext->StartIndex >= 2);
	Fcb->DirIndex = DirContext->DirIndex - 2;
	Fcb->StartIndex = DirContext->StartIndex - 2;
    }
    Fcb->Base.FileSizes.FileSize.QuadPart = Size;
    Fcb->Base.FileSizes.ValidDataLength.QuadPart = Size;
    Fcb->Base.FileSizes.AllocationSize.QuadPart = ROUND_UP_64(Size, Vcb->FatInfo.BytesPerCluster);
}

NTSTATUS FatSetFcbNewDirName(PDEVICE_EXTENSION Vcb,
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
    FatDelFcbFromTable(Vcb, Fcb);

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

    FatAddFcbToTable(Vcb, Fcb);
    FatReleaseFcb(Vcb, ParentFcb);

    return STATUS_SUCCESS;
}

NTSTATUS FatUpdateFcb(PDEVICE_EXTENSION Vcb,
		      PFATFCB Fcb,
		      PFAT_DIRENTRY_CONTEXT DirContext,
		      PFATFCB ParentFcb)
{
    NTSTATUS Status;
    PFATFCB OldParent;

    DPRINT("FatUpdateFcb(%p, %p, %p, %p)\n", Vcb, Fcb, DirContext,
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
    FatDelFcbFromTable(Vcb, Fcb);

    /* Split it properly */
    Fcb->PathNameBuffer = Fcb->PathNameU.Buffer;
    Fcb->DirNameU.Buffer = Fcb->PathNameU.Buffer;
    FatSplitPathName(&Fcb->PathNameU, &Fcb->DirNameU, &Fcb->LongNameU);

    /* Save old parent */
    OldParent = Fcb->ParentFcb;
    RemoveEntryList(&Fcb->ParentListEntry);

    /* Reinit FCB */
    FatInitFcbFromDirEntry(Vcb, ParentFcb, Fcb, DirContext);

    InsertTailList(&ParentFcb->ParentListHead, &Fcb->ParentListEntry);
    FatAddFcbToTable(Vcb, Fcb);

    /* If we moved across directories, dereference our old parent
     * We also dereference in case we're just renaming since AddFCBToTable references it
     */
    FatReleaseFcb(Vcb, OldParent);

    return STATUS_SUCCESS;
}

PFATFCB FatGrabFcbFromTable(PDEVICE_EXTENSION Vcb,
			    PUNICODE_STRING PathNameU)
{
    PFATFCB Fcb;
    ULONG Hash;
    UNICODE_STRING DirNameU;
    UNICODE_STRING FileNameU;
    PUNICODE_STRING FcbNameU;

    HASHENTRY *Entry;

    DPRINT("FatGrabFcbFromTable: '%wZ'\n", PathNameU);

    ASSERT(PathNameU->Length >= sizeof(WCHAR) && PathNameU->Buffer[0] == L'\\');
    Hash = FatNameHash(0, PathNameU);

    Entry = Vcb->FcbHashTable[Hash % Vcb->HashTableSize];
    if (Entry) {
	FatSplitPathName(PathNameU, &DirNameU, &FileNameU);
    }

    while (Entry) {
	if (Entry->Hash == Hash) {
	    Fcb = Entry->Self;
	    DPRINT("Comparing dir names '%wZ' '%wZ'\n", &DirNameU, &Fcb->DirNameU);
	    if (RtlEqualUnicodeString(&DirNameU, &Fcb->DirNameU, TRUE)) {
		if (Fcb->Hash.Hash == Hash) {
		    FcbNameU = &Fcb->LongNameU;
		} else {
		    FcbNameU = &Fcb->ShortNameU;
		}
		/* Compare the file name */
		DPRINT("Comparing file names '%wZ' '%wZ'\n", &FileNameU, FcbNameU);
		if (RtlEqualUnicodeString(&FileNameU, FcbNameU, TRUE)) {
		    FatGrabFcb(Vcb, Fcb);
		    return Fcb;
		}
	    }
	}
	Entry = Entry->Next;
    }
    return NULL;
}

static PFATFCB FatMakeRootFcb(PDEVICE_EXTENSION Vcb)
{
    ULONG Size = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING NameU = RTL_CONSTANT_STRING(L"\\");

    ASSERT(Vcb->RootFcb == NULL);

    PFATFCB Fcb = FatNewFcb(Vcb, &NameU);
    if (FatVolumeIsFatX(Vcb)) {
	memset(Fcb->Entry.FatX.Filename, ' ', 42);
	Fcb->Entry.FatX.FileSize = Vcb->FatInfo.RootDirectorySectors * Vcb->FatInfo.BytesPerSector;
	Fcb->Entry.FatX.Attrib = FILE_ATTRIBUTE_DIRECTORY;
	Fcb->Entry.FatX.FirstCluster = 1;
	Size = Vcb->FatInfo.RootDirectorySectors * Vcb->FatInfo.BytesPerSector;
    } else {
	memset(Fcb->Entry.Fat.ShortName, ' ', 11);
	Fcb->Entry.Fat.FileSize = Vcb->FatInfo.RootDirectorySectors * Vcb->FatInfo.BytesPerSector;
	Fcb->Entry.Fat.Attrib = FILE_ATTRIBUTE_DIRECTORY;
	if (Vcb->FatInfo.FatType == FAT32) {
	    ULONG FirstCluster = Vcb->FatInfo.RootCluster;
	    ULONG CurrentCluster = FirstCluster;
	    Fcb->Entry.Fat.FirstCluster = (USHORT)(FirstCluster & 0xffff);
	    Fcb->Entry.Fat.FirstClusterHigh = (USHORT)(FirstCluster >> 16);

	    while (CurrentCluster != 0xffffffff && NT_SUCCESS(Status)) {
		Size += Vcb->FatInfo.BytesPerCluster;
		Status = NextCluster(Vcb, FirstCluster, &CurrentCluster, FALSE);
	    }
	} else {
	    Fcb->Entry.Fat.FirstCluster = 1;
	    Size = Vcb->FatInfo.RootDirectorySectors * Vcb->FatInfo.BytesPerSector;
	}
    }
    Fcb->ShortHash.Hash = Fcb->Hash.Hash;
    Fcb->RefCount = 2;
    Fcb->DirIndex = 0;
    Fcb->Base.FileSizes.FileSize.QuadPart = Size;
    Fcb->Base.FileSizes.ValidDataLength.QuadPart = Size;
    Fcb->Base.FileSizes.AllocationSize.QuadPart = Size;

    FatFcbInitializeCacheFromVolume(Vcb, Fcb);
    FatAddFcbToTable(Vcb, Fcb);

    /* Cache it */
    Vcb->RootFcb = Fcb;

    return Fcb;
}

PFATFCB FatOpenRootFcb(PDEVICE_EXTENSION Vcb)
{
    UNICODE_STRING NameU = RTL_CONSTANT_STRING(L"\\");

    PFATFCB Fcb = FatGrabFcbFromTable(Vcb, &NameU);
    if (Fcb == NULL) {
	Fcb = FatMakeRootFcb(Vcb);
    }
    ASSERT(Fcb == Vcb->RootFcb);

    return Fcb;
}

NTSTATUS FatMakeFcbFromDirEntry(PVCB Vcb,
				PFATFCB DirFcb,
				PFAT_DIRENTRY_CONTEXT DirContext,
				PFATFCB *FileFcb)
{
    PFATFCB Fcb;
    UNICODE_STRING NameU;
    NTSTATUS Status;

    Status = FatMakeFullName(DirFcb, &DirContext->LongNameU,
			     &DirContext->ShortNameU, &NameU);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Fcb = FatNewFcb(Vcb, &NameU);
    FatInitFcbFromDirEntry(Vcb, DirFcb, Fcb, DirContext);

    Fcb->RefCount = 1;
    InsertTailList(&DirFcb->ParentListHead, &Fcb->ParentListEntry);
    FatAddFcbToTable(Vcb, Fcb);
    *FileFcb = Fcb;

    ExFreePoolWithTag(NameU.Buffer, TAG_FCB);
    return STATUS_SUCCESS;
}

NTSTATUS FatAttachFcbToFileObject(PDEVICE_EXTENSION Vcb,
				  PFATFCB Fcb, PFILE_OBJECT FileObject)
{
    PFATCCB NewCcb = ExAllocateFromLookasideList(&FatGlobalData->CcbLookasideList);
    if (NewCcb == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(NewCcb, sizeof(FATCCB));

    FileObject->FsContext = Fcb;
    FileObject->FsContext2 = NewCcb;
    FileObject->Vpb = Vcb->VolumeDevice->Vpb;
    DPRINT("File open: Fcb:%p PathName:%wZ\n", Fcb, &Fcb->PathNameU);

    Fcb->Flags &= ~FCB_CLEANED_UP;
    Fcb->Flags &= ~FCB_CLOSED;

    return STATUS_SUCCESS;
}

static NTSTATUS FatDirFindFile(PDEVICE_EXTENSION DevExt,
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
       FatMakeFcbFromDirEntry can copy 20 name entries with 13 characters. */
    WCHAR LongNameBuffer[260];
    WCHAR ShortNameBuffer[13];
    BOOLEAN FoundLong = FALSE;
    BOOLEAN FoundShort = FALSE;
    BOOLEAN IsFatX = FatVolumeIsFatX(DevExt);

    ASSERT(DevExt);
    ASSERT(DirFcb);
    ASSERT(FileToFindU);

    DPRINT("FatDirFindFile(Vcb:%p, DirFcb:%p, File:%wZ)\n",
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

	DPRINT("  Index:%u  LongName:%wZ\n",
	       DirContext.DirIndex, &DirContext.LongNameU);

	if (!ENTRY_VOLUME(IsFatX, &DirContext.DirEntry)) {
	    if (!DirContext.LongNameU.Length || !DirContext.ShortNameU.Length) {
		DPRINT1("WARNING: File system corruption detected. You may "
			"need to run a disk repair utility.\n");
		if (FatGlobalData->Flags & FAT_BREAK_ON_CORRUPTION) {
		    ASSERT(DirContext.LongNameU.Length && DirContext.ShortNameU.Length);
		}
		DirContext.DirIndex++;
		continue;
	    }
	    FoundLong = RtlEqualUnicodeString(FileToFindU, &DirContext.LongNameU, TRUE);
	    if (FoundLong == FALSE) {
		FoundShort = RtlEqualUnicodeString(FileToFindU,
						   &DirContext.ShortNameU, TRUE);
	    }
	    if (FoundLong || FoundShort) {
		Status = FatMakeFcbFromDirEntry(DevExt, DirFcb,
						&DirContext, pFoundFCB);
		CcUnpinData(Context);
		return Status;
	    }
	}
	DirContext.DirIndex++;
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

NTSTATUS FatGetFcbForFile(PDEVICE_EXTENSION Vcb,
			  PFATFCB *pParentFcb,
			  PFATFCB *pFcb,
			  PUNICODE_STRING pFileNameU)
{
    PFATFCB Fcb = NULL;
    UNICODE_STRING NameU;
    UNICODE_STRING RootNameU = RTL_CONSTANT_STRING(L"\\");
    UNICODE_STRING FileNameU;
    WCHAR NameBuffer[260];
    PWCHAR Curr, Prev, Last;
    ULONG Length;

    DPRINT("FatGetFcbForFile (%p,%p,%p,%wZ)\n",
	   Vcb, pParentFcb, pFcb, pFileNameU);

    RtlInitEmptyUnicodeString(&FileNameU, NameBuffer, sizeof(NameBuffer));

    PFATFCB ParentFcb = *pParentFcb;
    if (!ParentFcb) {
	/* Passed-in name is the full name */
	RtlCopyUnicodeString(&FileNameU, pFileNameU);

	//  Trivial case, open of the root directory on volume
	if (RtlEqualUnicodeString(&FileNameU, &RootNameU, FALSE)) {
	    DPRINT("Returning root FCB\n");

	    Fcb = FatOpenRootFcb(Vcb);
	    *pFcb = Fcb;
	    *pParentFcb = NULL;

	    return Fcb ? STATUS_SUCCESS : STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/* Check for an existing FCB */
	Fcb = FatGrabFcbFromTable(Vcb, &FileNameU);
	if (Fcb) {
	    *pFcb = Fcb;
	    *pParentFcb = Fcb->ParentFcb;
	    FatGrabFcb(Vcb, *pParentFcb);
	    return STATUS_SUCCESS;
	}

	Last = Curr = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
	while (*Curr != L'\\' && Curr > FileNameU.Buffer) {
	    Curr--;
	}

	if (Curr > FileNameU.Buffer) {
	    NameU.Buffer = FileNameU.Buffer;
	    NameU.Length = (Curr - FileNameU.Buffer) * sizeof(WCHAR);
	    NameU.MaximumLength = NameU.Length;
	    Fcb = FatGrabFcbFromTable(Vcb, &NameU);
	    if (Fcb) {
		Length = (Curr - FileNameU.Buffer) * sizeof(WCHAR);
		if (Length != Fcb->PathNameU.Length) {
		    if (FileNameU.Length + Fcb->PathNameU.Length - Length >
			FileNameU.MaximumLength) {
			FatReleaseFcb(Vcb, Fcb);
			return STATUS_OBJECT_NAME_INVALID;
		    }
		    RtlMoveMemory(FileNameU.Buffer +
				  Fcb->PathNameU.Length / sizeof(WCHAR),
				  Curr, FileNameU.Length - Length);
		    FileNameU.Length += (USHORT)(Fcb->PathNameU.Length - Length);
		    Curr = FileNameU.Buffer + Fcb->PathNameU.Length / sizeof(WCHAR);
		    Last = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
		}
		RtlCopyMemory(FileNameU.Buffer, Fcb->PathNameU.Buffer,
			      Fcb->PathNameU.Length);
	    }
	} else {
	    Fcb = NULL;
	}

	if (Fcb == NULL) {
	    Fcb = FatOpenRootFcb(Vcb);
	    Curr = FileNameU.Buffer;
	}

	ParentFcb = NULL;
	Prev = Curr;
    } else {
	/* Make absolute path */
	RtlCopyUnicodeString(&FileNameU, &ParentFcb->PathNameU);
	Curr = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
	if (*Curr != L'\\') {
	    RtlAppendUnicodeToString(&FileNameU, L"\\");
	    Curr++;
	}
	ASSERT(*Curr == L'\\');
	RtlAppendUnicodeStringToString(&FileNameU, pFileNameU);

	Fcb = ParentFcb;
	ParentFcb = NULL;
	Prev = Curr;
	Last = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) - 1;
    }

    while (Curr <= Last) {
	if (ParentFcb) {
	    FatReleaseFcb(Vcb, ParentFcb);
	    ParentFcb = NULL;
	}
	// Fail if element in Fcb is not a directory
	if (!FatFcbIsDirectory(Fcb)) {
	    DPRINT("Element in requested path is not a directory\n");

	    FatReleaseFcb(Vcb, Fcb);
	    Fcb = NULL;
	    *pParentFcb = NULL;
	    *pFcb = NULL;

	    return STATUS_OBJECT_PATH_NOT_FOUND;
	}
	ParentFcb = Fcb;
	if (Prev < Curr) {
	    Length = (Curr - Prev) * sizeof(WCHAR);
	    if (Length != ParentFcb->LongNameU.Length) {
		if (FileNameU.Length + ParentFcb->LongNameU.Length -
		    Length > FileNameU.MaximumLength) {
		    FatReleaseFcb(Vcb, ParentFcb);
		    *pParentFcb = NULL;
		    *pFcb = NULL;
		    return STATUS_OBJECT_NAME_INVALID;
		}
		RtlMoveMemory(Prev +
			      ParentFcb->LongNameU.Length / sizeof(WCHAR),
			      Curr,
			      FileNameU.Length - (Curr -
						  FileNameU.Buffer) *
			      sizeof(WCHAR));
		FileNameU.Length += (USHORT) (ParentFcb->LongNameU.Length - Length);
		Curr = Prev + ParentFcb->LongNameU.Length / sizeof(WCHAR);
		Last = FileNameU.Buffer + FileNameU.Length / sizeof(WCHAR) -
		    1;
	    }
	    RtlCopyMemory(Prev, ParentFcb->LongNameU.Buffer,
			  ParentFcb->LongNameU.Length);
	}
	Curr++;
	Prev = Curr;
	while (*Curr != L'\\' && Curr <= Last) {
	    Curr++;
	}
	NameU.Buffer = FileNameU.Buffer;
	NameU.Length = (Curr - NameU.Buffer) * sizeof(WCHAR);
	NameU.MaximumLength = FileNameU.MaximumLength;
	DPRINT("Trying to grab fcb for %wZ\n", &NameU);
	Fcb = FatGrabFcbFromTable(Vcb, &NameU);
	if (!Fcb) {
	    NameU.Buffer = Prev;
	    NameU.MaximumLength = NameU.Length = (Curr - Prev) * sizeof(WCHAR);
	    NTSTATUS Status = FatDirFindFile(Vcb, ParentFcb, &NameU, &Fcb);
	    if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
		*pFcb = NULL;
		if (Curr > Last) {
		    *pParentFcb = ParentFcb;
		    return STATUS_OBJECT_NAME_NOT_FOUND;
		} else {
		    FatReleaseFcb(Vcb, ParentFcb);
		    *pParentFcb = NULL;
		    return STATUS_OBJECT_PATH_NOT_FOUND;
		}
	    } else if (!NT_SUCCESS(Status)) {
		FatReleaseFcb(Vcb, ParentFcb);
		*pParentFcb = NULL;
		*pFcb = NULL;

		return Status;
	    }
	}
    }

    *pParentFcb = ParentFcb;
    *pFcb = Fcb;

    return STATUS_SUCCESS;
}
