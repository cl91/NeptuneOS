/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     File creation routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2010-2019 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS *****************************************************************/

VOID Fat8Dot3ToString(PFAT_DIR_ENTRY Entry, PUNICODE_STRING NameU)
{
    OEM_STRING StringA;
    USHORT Length;
    CHAR cString[12];

    RtlCopyMemory(cString, Entry->ShortName, 11);
    cString[11] = 0;
    DPRINT("Fat8Dot3ToString: short name = %s\n", cString);
    if (cString[0] == 0x05) {
	cString[0] = 0xe5;
    }

    StringA.Buffer = cString;
    for (StringA.Length = 0;
	 StringA.Length < 8 && StringA.Buffer[StringA.Length] != ' ';
	 StringA.Length++) ;
    StringA.MaximumLength = StringA.Length;

    RtlOemStringToUnicodeString(NameU, &StringA, FALSE);

    if (BooleanFlagOn(Entry->Case, FAT_CASE_LOWER_BASE)) {
	RtlDowncaseUnicodeString(NameU, NameU, FALSE);
    }

    if (cString[8] != ' ') {
	Length = NameU->Length;
	NameU->Buffer += Length / sizeof(WCHAR);
	if (!FAT_ENTRY_VOLUME(Entry)) {
	    Length += sizeof(WCHAR);
	    NameU->Buffer[0] = L'.';
	    NameU->Buffer++;
	}
	NameU->Length = 0;
	NameU->MaximumLength -= Length;

	StringA.Buffer = &cString[8];
	for (StringA.Length = 0;
	     StringA.Length < 3 && StringA.Buffer[StringA.Length] != ' ';
	     StringA.Length++) ;
	StringA.MaximumLength = StringA.Length;
	RtlOemStringToUnicodeString(NameU, &StringA, FALSE);
	if (BooleanFlagOn(Entry->Case, FAT_CASE_LOWER_EXT)) {
	    RtlDowncaseUnicodeString(NameU, NameU, FALSE);
	}
	NameU->Buffer -= Length / sizeof(WCHAR);
	NameU->Length += Length;
	NameU->MaximumLength += Length;
    }

    NameU->Buffer[NameU->Length / sizeof(WCHAR)] = 0;
    DPRINT("'%wZ'\n", NameU);
}

/*
 * FUNCTION: Find a file
 */
NTSTATUS FindFile(PDEVICE_EXTENSION DeviceExt,
		  PFATFCB Parent,
		  PUNICODE_STRING FileToFindU,
		  PFAT_DIRENTRY_CONTEXT DirContext,
		  BOOLEAN First)
{
    BOOLEAN IsFatX = FatVolumeIsFatX(DeviceExt);

    DPRINT("FindFile(Parent %p, FileToFind '%wZ', DirIndex: %u)\n",
	   Parent, FileToFindU, DirContext->DirIndex);
    DPRINT("FindFile: Path %wZ\n", &Parent->PathNameU);

    USHORT PathNameBufferLength = LONGNAME_MAX_LENGTH * sizeof(WCHAR);
    PWCHAR PathNameBuffer = ExAllocatePoolWithTag(PathNameBufferLength + sizeof(WCHAR),
						  TAG_NAME);
    if (!PathNameBuffer) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    UNICODE_STRING PathNameU = {
	.Buffer = PathNameBuffer,
	.Length = 0,
	.MaximumLength = PathNameBufferLength
    };

    DirContext->LongNameU.Length = 0;
    DirContext->ShortNameU.Length = 0;

    BOOLEAN WildCard = FsRtlDoesNameContainWildCards(FileToFindU);

    if (!WildCard) {
	/* If there is no '*?' in the search name, then look first for an existing FCB. */
	RtlCopyUnicodeString(&PathNameU, &Parent->PathNameU);
	if (!FatFcbIsRoot(Parent)) {
	    PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = L'\\';
	    PathNameU.Length += sizeof(WCHAR);
	}
	RtlAppendUnicodeStringToString(&PathNameU, FileToFindU);
	PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = 0;
	PFATFCB Fcb = FatGrabFcbFromTable(DeviceExt, &PathNameU);
	if (Fcb) {
	    ULONG StartIndex = Fcb->StartIndex;
	    if (IsFatX && !FatFcbIsRoot(Parent)) {
		StartIndex += 2;
	    }
	    NTSTATUS Status;
	    if (StartIndex >= DirContext->DirIndex) {
		RtlCopyUnicodeString(&DirContext->LongNameU, &Fcb->LongNameU);
		RtlCopyUnicodeString(&DirContext->ShortNameU, &Fcb->ShortNameU);
		RtlCopyMemory(&DirContext->DirEntry, &Fcb->Entry, sizeof(DIR_ENTRY));
		DirContext->StartIndex = Fcb->StartIndex;
		DirContext->DirIndex = Fcb->DirIndex;
		DPRINT("FindFile: new Name %wZ, DirIndex %u (%u)\n",
		       &DirContext->LongNameU, DirContext->DirIndex,
		       DirContext->StartIndex);
		Status = STATUS_SUCCESS;
	    } else {
		DPRINT("FCB not found for %wZ\n", &PathNameU);
		Status = STATUS_UNSUCCESSFUL;
	    }
	    FatReleaseFcb(DeviceExt, Fcb);
	    ExFreePoolWithTag(PathNameBuffer, TAG_NAME);
	    return Status;
	}
    }

    /* FsRtlIsNameInExpression need the searched string to be upcase,
     * even if IgnoreCase is specified */
    UNICODE_STRING FileToFindUpcase;
    NTSTATUS Status = RtlUpcaseUnicodeString(&FileToFindUpcase, FileToFindU, TRUE);
    if (!NT_SUCCESS(Status)) {
	ExFreePoolWithTag(PathNameBuffer, TAG_NAME);
	return Status;
    }

    PVOID Context = NULL;
    while (TRUE) {
	PVOID Page;
	Status = FatGetNextDirEntry(DeviceExt, &Context, &Page, Parent,
				    DirContext, First);
	First = FALSE;
	if (Status == STATUS_NO_MORE_ENTRIES) {
	    break;
	}
	if (ENTRY_VOLUME(IsFatX, &DirContext->DirEntry)) {
	    DirContext->DirIndex++;
	    continue;
	}
	if (DirContext->LongNameU.Length == 0 ||
	    DirContext->ShortNameU.Length == 0) {
	    DPRINT1("WARNING: File system corruption detected. "
		    "You may need to run a disk repair utility.\n");
	    if (FatGlobalData->Flags & FAT_BREAK_ON_CORRUPTION) {
		ASSERT(DirContext->LongNameU.Length && DirContext->ShortNameU.Length);
	    }
	    DirContext->DirIndex++;
	    continue;
	}
	BOOLEAN Found;
	if (WildCard) {
	    Found = FsRtlIsNameInExpression(&FileToFindUpcase,
					    &DirContext->LongNameU, TRUE, NULL)
		|| FsRtlIsNameInExpression(&FileToFindUpcase,
					   &DirContext->ShortNameU, TRUE, NULL);
	} else {
	    Found = FsRtlAreNamesEqual(&DirContext->LongNameU, FileToFindU, TRUE, NULL)
		|| FsRtlAreNamesEqual(&DirContext->ShortNameU, FileToFindU, TRUE, NULL);
	}

	if (Found) {
	    if (WildCard) {
		RtlCopyUnicodeString(&PathNameU, &Parent->PathNameU);
		if (!FatFcbIsRoot(Parent)) {
		    PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = L'\\';
		    PathNameU.Length += sizeof(WCHAR);
		}
		RtlAppendUnicodeStringToString(&PathNameU, &DirContext->LongNameU);
		PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = 0;
		PFATFCB Fcb = FatGrabFcbFromTable(DeviceExt, &PathNameU);
		if (Fcb != NULL) {
		    RtlCopyMemory(&DirContext->DirEntry, &Fcb->Entry, sizeof(DIR_ENTRY));
		    FatReleaseFcb(DeviceExt, Fcb);
		}
	    }
	    DPRINT("%u\n", DirContext->LongNameU.Length);
	    DPRINT("FindFile: new Name %wZ, DirIndex %u\n",
		   &DirContext->LongNameU, DirContext->DirIndex);

	    if (Context) {
		CcUnpinData(Context);
	    }
	    RtlFreeUnicodeString(&FileToFindUpcase);
	    ExFreePoolWithTag(PathNameBuffer, TAG_NAME);
	    return STATUS_SUCCESS;
	}
	DirContext->DirIndex++;
    }

    if (Context) {
	CcUnpinData(Context);
    }

    RtlFreeUnicodeString(&FileToFindUpcase);
    ExFreePoolWithTag(PathNameBuffer, TAG_NAME);
    return Status;
}

/*
 * FUNCTION: Opens a file
 */
static NTSTATUS FatOpenFile(PDEVICE_EXTENSION DeviceExt,
			    PUNICODE_STRING PathNameU,
			    PFILE_OBJECT FileObject,
			    ULONG RequestedDisposition,
			    ULONG RequestedOptions,
			    PFATFCB *ParentFcb)
{
    DPRINT("FatOpenFile(%p, '%wZ', %p, %p)\n", DeviceExt, PathNameU,
	   FileObject, ParentFcb);

    if (FileObject->RelatedFileObject) {
	DPRINT("'%wZ'\n", &FileObject->RelatedFileObject->FileName);
	*ParentFcb = FileObject->RelatedFileObject->FsContext;
    } else {
	*ParentFcb = NULL;
    }

    if (!DeviceExt->FatInfo.FixedMedia) {
	NTSTATUS Status = FatBlockDeviceIoControl(DeviceExt->StorageDevice,
						  IOCTL_DISK_CHECK_VERIFY,
						  NULL, 0, NULL, 0, FALSE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT("Status %x\n", Status);
	    *ParentFcb = NULL;
	    return Status;
	}
    }

    if (*ParentFcb) {
	FatGrabFcb(DeviceExt, *ParentFcb);
    }

    /* Try first to find an existing FCB in memory. */
    DPRINT("Checking for existing FCB in memory\n");

    PFATFCB Fcb;
    NTSTATUS Status = FatGetFcbForFile(DeviceExt, ParentFcb, &Fcb, PathNameU);
    if (!NT_SUCCESS(Status)) {
	DPRINT("Could not make a new FCB, status: %x\n", Status);
	return Status;
    }

    /* Fail if we try to overwrite an existing directory */
    if ((FatFcbIsDirectory(Fcb) && !BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE))
	&& (RequestedDisposition == FILE_OVERWRITE
	    || RequestedDisposition == FILE_OVERWRITE_IF
	    || RequestedDisposition == FILE_SUPERSEDE)) {
	FatReleaseFcb(DeviceExt, Fcb);
	return STATUS_OBJECT_NAME_COLLISION;
    }

    if (BooleanFlagOn(Fcb->Flags, FCB_DELETE_PENDING)) {
	FatReleaseFcb(DeviceExt, Fcb);
	return STATUS_DELETE_PENDING;
    }

    /* Fail if we try to overwrite a read-only file */
    if (FatFcbIsReadOnly(Fcb) &&
	(RequestedDisposition == FILE_OVERWRITE ||
	 RequestedDisposition == FILE_OVERWRITE_IF)) {
	FatReleaseFcb(DeviceExt, Fcb);
	return STATUS_ACCESS_DENIED;
    }

    if (FatFcbIsReadOnly(Fcb) && (RequestedOptions & FILE_DELETE_ON_CLOSE)) {
	FatReleaseFcb(DeviceExt, Fcb);
	return STATUS_CANNOT_DELETE;
    }

    if ((FatFcbIsRoot(Fcb) || IsDotOrDotDot(&Fcb->LongNameU)) &&
	BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) {
	// We cannot delete a '.', '..' or the root directory.
	FatReleaseFcb(DeviceExt, Fcb);
	return STATUS_CANNOT_DELETE;
    }

    DPRINT("Attaching FCB to file object\n");
    Status = FatAttachFcbToFileObject(DeviceExt, Fcb, FileObject);
    if (!NT_SUCCESS(Status)) {
	FatReleaseFcb(DeviceExt, Fcb);
    }
    return Status;
}

/*
 * FUNCTION: Create or open a file
 */
static NTSTATUS FatCreateFile(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG RequestedDisposition = (Stack->Parameters.Create.Options >> 24) & 0xff;
    ULONG RequestedOptions = Stack->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    BOOLEAN PagingFileCreate = BooleanFlagOn(Stack->Flags, SL_OPEN_PAGING_FILE);
    PFILE_OBJECT FileObject = Stack->FileObject;
    PDEVICE_EXTENSION DeviceExt = DeviceObject->DeviceExtension;
    assert(DeviceExt);

    if (BooleanFlagOn(Stack->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
	return STATUS_NOT_IMPLEMENTED;
    }

    /* Deny request if the user wants to supersede a directory. */
    if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	RequestedDisposition == FILE_SUPERSEDE) {
	return STATUS_INVALID_PARAMETER;
    }

    if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	BooleanFlagOn(RequestedOptions, FILE_NON_DIRECTORY_FILE)) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Deny create if the volume is locked. */
    if (BooleanFlagOn(DeviceExt->Flags, VCB_VOLUME_LOCKED)) {
	return STATUS_ACCESS_DENIED;
    }

    NTSTATUS Status;
    BOOLEAN OpenTargetDir = BooleanFlagOn(Stack->Flags, SL_OPEN_TARGET_DIRECTORY);
    if (!FileObject->FileName.Length &&
	(!FileObject->RelatedFileObject || FileObject->RelatedFileObject->FsContext2 ||
	 FileObject->RelatedFileObject->FsContext == DeviceExt->VolumeFcb)) {
	/* This is an open operation for the volume itself */
	DPRINT("Opening volume file object\n");

	if (RequestedDisposition != FILE_OPEN &&
	    RequestedDisposition != FILE_OPEN_IF) {
	    return STATUS_ACCESS_DENIED;
	}

	if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	    (!FileObject->RelatedFileObject || !FileObject->RelatedFileObject->FsContext2
	     || FileObject->RelatedFileObject->FsContext == DeviceExt->VolumeFcb)) {
	    return STATUS_NOT_A_DIRECTORY;
	}

	if (OpenTargetDir) {
	    return STATUS_INVALID_PARAMETER;
	}

	if (BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) {
	    return STATUS_CANNOT_DELETE;
	}

	FatAddToStat(DeviceExt, Fat.CreateHits, 1);

	PFATFCB Fcb = DeviceExt->VolumeFcb;
	assert(Fcb);

	if (!Fcb->OpenHandleCount) {
	    IoSetShareAccess(Stack->Parameters.Create.SecurityContext->DesiredAccess,
			     Stack->Parameters.Create.ShareAccess,
			     FileObject, &Fcb->FcbShareAccess);
	} else {
	    Status = IoCheckShareAccess(Stack->Parameters.Create.SecurityContext->DesiredAccess,
					Stack->Parameters.Create.ShareAccess,
					FileObject, &Fcb->FcbShareAccess, TRUE);
	    if (!NT_SUCCESS(Status)) {
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return Status;
	    }
	}

	FatAttachFcbToFileObject(DeviceExt, Fcb, FileObject);
	DeviceExt->OpenHandleCount++;
	Fcb->OpenHandleCount++;
	FatAddToStat(DeviceExt, Fat.SuccessfulCreates, 1);

	Irp->IoStatus.Information = FILE_OPENED;
	return STATUS_SUCCESS;
    }

    if (FileObject->RelatedFileObject &&
	FileObject->RelatedFileObject->FsContext == DeviceExt->VolumeFcb) {
	ASSERT(FileObject->FileName.Length);
	return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    /* Check for illegal characters and illegal dot sequences in the file name. */
    UNICODE_STRING PathNameU = FileObject->FileName;
    PWCHAR c = PathNameU.Buffer + PathNameU.Length / sizeof(WCHAR);
    PWCHAR Last = c - 1;

    BOOLEAN Dots = TRUE;
    while (c-- > PathNameU.Buffer) {
	if (*c == L'\\' || c == PathNameU.Buffer) {
	    if (Dots && Last > c) {
		return STATUS_OBJECT_NAME_INVALID;
	    }
	    if (*c == L'\\' && (c - 1) > PathNameU.Buffer && *(c - 1) == L'\\') {
		return STATUS_OBJECT_NAME_INVALID;
	    }

	    Last = c - 1;
	    Dots = TRUE;
	} else if (*c != L'.') {
	    Dots = FALSE;
	}

	if (*c != '\\' && FatIsLongIllegal(*c)) {
	    return STATUS_OBJECT_NAME_INVALID;
	}
    }

    /* Check if we try to open target directory of root dir */
    if (OpenTargetDir && !FileObject->RelatedFileObject
	&& PathNameU.Length == sizeof(WCHAR) && PathNameU.Buffer[0] == L'\\') {
	return STATUS_INVALID_PARAMETER;
    }

    if (FileObject->RelatedFileObject && PathNameU.Length >= sizeof(WCHAR)
	&& PathNameU.Buffer[0] == L'\\') {
	return STATUS_OBJECT_NAME_INVALID;
    }

    BOOLEAN TrailingBackslash = FALSE;
    if (PathNameU.Length > sizeof(WCHAR)
	&& PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR) - 1] == L'\\') {
	PathNameU.Length -= sizeof(WCHAR);
	TrailingBackslash = TRUE;
    }

    if (PathNameU.Length > sizeof(WCHAR)
	&& PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR) - 1] == L'\\') {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* We are opening a target directory. This is used by the IO manager in
     * response to a file/directory rename operation. */
    if (OpenTargetDir) {
	FatAddToStat(DeviceExt, Fat.CreateHits, 1);

	PFATFCB ParentFcb = FileObject->RelatedFileObject ?
	    FileObject->RelatedFileObject->FsContext : NULL;
	if (ParentFcb) {
	    FatGrabFcb(DeviceExt, ParentFcb);
	}

	PFATFCB TargetFcb;
	Status = FatGetFcbForFile(DeviceExt, &ParentFcb, &TargetFcb, &PathNameU);
	if (NT_SUCCESS(Status)) {
	    FatReleaseFcb(DeviceExt, TargetFcb);
	    Irp->IoStatus.Information = FILE_EXISTS;
	} else {
	    Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
	}

	LONG Idx = FileObject->FileName.Length / sizeof(WCHAR) - 1;

	/* Skip trailing \ - if any */
	if (PathNameU.Buffer[Idx] == L'\\') {
	    --Idx;
	    PathNameU.Length -= sizeof(WCHAR);
	}

	/* Get file name */
	while (Idx >= 0 && PathNameU.Buffer[Idx] != L'\\') {
	    --Idx;
	}

	if (Idx > 0 || PathNameU.Buffer[0] == L'\\') {
	    /* We don't want to include / in the name */
	    LONG FileNameLen = PathNameU.Length - ((Idx + 1) * sizeof(WCHAR));

	    /* Update FO just to keep file name */
	    FileObject->FileName.Length = FileNameLen;
	    /* Skip first slash */
	    ++Idx;
	    RtlMoveMemory(&PathNameU.Buffer[0], &PathNameU.Buffer[Idx],
			  FileObject->FileName.Length);
#if 0
	    /* Terminate the string at the last backslash */
	    PathNameU.Buffer[Idx + 1] = UNICODE_NULL;
	    PathNameU.Length = (Idx + 1) * sizeof(WCHAR);
	    PathNameU.MaximumLength = PathNameU.Length + sizeof(WCHAR);

	    /* Update the file object as well */
	    FileObject->FileName.Length = PathNameU.Length;
	    FileObject->FileName.MaximumLength = PathNameU.MaximumLength;
#endif
	} else {
	    /* This is a relative open and we have only the filename, so
	     * open the parent directory. It is in RelatedFileObject.
	     */
	    ASSERT(FileObject->RelatedFileObject != NULL);
	    /* No need to modify the FO. It already has the name */
	}

	/* We're done with opening! */
	if (ParentFcb) {
	    Status = FatAttachFcbToFileObject(DeviceExt, ParentFcb, FileObject);
	}

	if (NT_SUCCESS(Status)) {
	    PFATFCB Fcb = FileObject->FsContext;
	    ASSERT(Fcb == ParentFcb);

	    if (!Fcb->OpenHandleCount) {
		IoSetShareAccess(Stack->Parameters.Create.SecurityContext->DesiredAccess,
				 Stack->Parameters.Create.ShareAccess,
				 FileObject, &Fcb->FcbShareAccess);
	    } else {
		Status = IoCheckShareAccess(
		    Stack->Parameters.Create.SecurityContext->DesiredAccess,
		    Stack->Parameters.Create.ShareAccess, FileObject,
		    &Fcb->FcbShareAccess, FALSE);
		if (!NT_SUCCESS(Status)) {
		    FatCloseFile(DeviceExt, FileObject);
		    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		    return Status;
		}
	    }

	    PFATCCB Ccb = FileObject->FsContext2;
	    if (BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) {
		Ccb->Flags |= CCB_DELETE_ON_CLOSE;
	    }

	    Fcb->OpenHandleCount++;
	    DeviceExt->OpenHandleCount++;
	} else if (ParentFcb) {
	    FatReleaseFcb(DeviceExt, ParentFcb);
	}

	if (NT_SUCCESS(Status)) {
	    FatAddToStat(DeviceExt, Fat.SuccessfulCreates, 1);
	} else {
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	}

	return Status;
    }

    /* This is a normal file open. */
    PFATFCB ParentFcb = NULL;
    FatAddToStat(DeviceExt, Fat.CreateHits, 1);
    Status = FatOpenFile(DeviceExt, &PathNameU, FileObject,
			 RequestedDisposition, RequestedOptions, &ParentFcb);

    /* If the directory containing the file to open doesn't exist then
     * fail immediately. */
    if (Status == STATUS_OBJECT_PATH_NOT_FOUND ||
	Status == STATUS_INVALID_PARAMETER ||
	Status == STATUS_DELETE_PENDING ||
	Status == STATUS_ACCESS_DENIED ||
	Status == STATUS_OBJECT_NAME_COLLISION) {
	if (ParentFcb) {
	    FatReleaseFcb(DeviceExt, ParentFcb);
	}
	FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	return Status;
    }

    if (!NT_SUCCESS(Status) && !ParentFcb) {
	DPRINT1("FatOpenFile failed for '%wZ', status %x\n", &PathNameU, Status);
	FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	return Status;
    }

    ULONG Attributes = Stack->Parameters.Create.FileAttributes &
	(FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN
	 | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY);

    /* If the file open failed then create the file (if requested). */
    PFATFCB Fcb = NULL;
    if (!NT_SUCCESS(Status)) {
	if (!(RequestedDisposition == FILE_CREATE ||
	      RequestedDisposition == FILE_OPEN_IF ||
	      RequestedDisposition == FILE_OVERWRITE_IF ||
	      RequestedDisposition == FILE_SUPERSEDE)) {
	    FatReleaseFcb(DeviceExt, ParentFcb);
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return Status;
	}
	if (!BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE)) {
	    if (TrailingBackslash) {
		FatReleaseFcb(DeviceExt, ParentFcb);
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return STATUS_OBJECT_NAME_INVALID;
	    }
	    Attributes |= FILE_ATTRIBUTE_ARCHIVE;
	}
	UNICODE_STRING FileNameU;
	FatSplitPathName(&PathNameU, NULL, &FileNameU);

	if (IsDotOrDotDot(&FileNameU)) {
	    FatReleaseFcb(DeviceExt, ParentFcb);
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return STATUS_OBJECT_NAME_INVALID;
	}
	Status = FatAddEntry(DeviceExt, &FileNameU, &Fcb, ParentFcb,
			     RequestedOptions, Attributes, NULL);
	FatReleaseFcb(DeviceExt, ParentFcb);
	if (!NT_SUCCESS(Status)) {
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return Status;
	}

	Status = FatAttachFcbToFileObject(DeviceExt, Fcb, FileObject);
	if (!NT_SUCCESS(Status)) {
	    goto Fail;
	}

	Status = FatSetFileSizeInformation(FileObject, Fcb, DeviceExt,
					   &Irp->AllocationSize);
	if (!NT_SUCCESS(Status)) {
	    goto Fail;
	}
	Irp->IoStatus.Information = FILE_CREATED;
	FatSetExtendedAttributes(FileObject, Irp->AssociatedIrp.SystemBuffer,
				 Stack->Parameters.Create.EaLength);

	if (PagingFileCreate) {
	    Fcb->Flags |= FCB_IS_PAGE_FILE;
	    SetFlag(DeviceExt->Flags, VCB_IS_SYS_OR_HAS_PAGE);
	}
	goto Done;

    Fail:
	FatReleaseFcb(DeviceExt, Fcb);
	FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	return Status;
    }

    /* If we got here, the file being opened/created has existed
     * before the open/create operation. */
    Fcb = FileObject->FsContext;
    if (ParentFcb) {
	FatReleaseFcb(DeviceExt, ParentFcb);
    }

    /* In this case we fail if the caller wanted to create a new file.  */
    if (RequestedDisposition == FILE_CREATE) {
	if (TrailingBackslash && !FatFcbIsDirectory(Fcb)) {
	    Status = STATUS_OBJECT_NAME_INVALID;
	} else {
	    Status = STATUS_OBJECT_NAME_COLLISION;
	}
	Irp->IoStatus.Information = FILE_EXISTS;
	goto OpenFail;
    }

    if (Fcb->OpenHandleCount) {
	Status = IoCheckShareAccess(Stack->Parameters.Create.SecurityContext->DesiredAccess,
				    Stack->Parameters.Create.ShareAccess,
				    FileObject, &Fcb->FcbShareAccess, FALSE);
	if (!NT_SUCCESS(Status)) {
	    goto OpenFail;
	}
    }

    /* Check the file has the requested attributes */
    if (BooleanFlagOn(RequestedOptions, FILE_NON_DIRECTORY_FILE) &&
	FatFcbIsDirectory(Fcb)) {
	Status = STATUS_FILE_IS_A_DIRECTORY;
	goto OpenFail;
    }
    if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	!FatFcbIsDirectory(Fcb)) {
	Status = STATUS_NOT_A_DIRECTORY;
	goto OpenFail;
    }
    if (TrailingBackslash && !FatFcbIsDirectory(Fcb)) {
	Status = STATUS_OBJECT_NAME_INVALID;
	goto OpenFail;
    }
#if 0 /* ifndef USE_ROS_CC_AND_FS */
    if (!FatFcbIsDirectory(Fcb)) {
	if (BooleanFlagOn(Stack->Parameters.Create.SecurityContext->DesiredAccess,
			  FILE_WRITE_DATA)
	    || RequestedDisposition == FILE_OVERWRITE
	    || RequestedDisposition == FILE_OVERWRITE_IF
	    || (RequestedOptions & FILE_DELETE_ON_CLOSE)) {
	    if (!MmFlushImageSection(&Fcb->SectionObjectPointers, MmFlushForWrite)) {
		DPRINT1("%wZ\n", &Fcb->PathNameU);
		DPRINT1("%d %d %d\n",
			Stack->Parameters.Create.SecurityContext->DesiredAccess & FILE_WRITE_DATA,
			RequestedDisposition == FILE_OVERWRITE,
			RequestedDisposition == FILE_OVERWRITE_IF);
		Status = (BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) ?
		    STATUS_CANNOT_DELETE : STATUS_SHARING_VIOLATION;
		goto OpenFail;
	    }
	}
    }
#endif
    if (PagingFileCreate) {
	/* FIXME:
	 *   Do more checking for page files. It is possible
	 *   that the file was opened and closed previously
	 *   as a normal cached file. In this case, the cache
	 *   manager has referenced the fileobject and the fcb
	 *   is held in memory. Try to remove the fileobject
	 *   from cache manager and use the fcb.
	 */
	if (Fcb->RefCount > 1) {
	    if (!BooleanFlagOn(Fcb->Flags, FCB_IS_PAGE_FILE)) {
		Status = STATUS_INVALID_PARAMETER;
		goto OpenFail;
	    }
	} else {
	    Fcb->Flags |= FCB_IS_PAGE_FILE;
	    SetFlag(DeviceExt->Flags, VCB_IS_SYS_OR_HAS_PAGE);
	}
    } else if (BooleanFlagOn(Fcb->Flags, FCB_IS_PAGE_FILE)) {
	Status = STATUS_INVALID_PARAMETER;
	goto OpenFail;
    }

    if (RequestedDisposition == FILE_OVERWRITE ||
	RequestedDisposition == FILE_OVERWRITE_IF ||
	RequestedDisposition == FILE_SUPERSEDE) {
	if ((BooleanFlagOn(*Fcb->Attributes, FILE_ATTRIBUTE_HIDDEN)
	     && !BooleanFlagOn(Attributes, FILE_ATTRIBUTE_HIDDEN))
	    || (BooleanFlagOn(*Fcb->Attributes, FILE_ATTRIBUTE_SYSTEM)
		&& !BooleanFlagOn(Attributes, FILE_ATTRIBUTE_SYSTEM))) {
	    Status = STATUS_ACCESS_DENIED;
	    goto OpenFail;
	}

	if (!FatFcbIsDirectory(Fcb)) {
	    LARGE_INTEGER SystemTime;

	    if (RequestedDisposition == FILE_SUPERSEDE) {
		*Fcb->Attributes = Attributes;
	    } else {
		*Fcb->Attributes |= Attributes;
	    }
	    *Fcb->Attributes |= FILE_ATTRIBUTE_ARCHIVE;

	    NtQuerySystemTime(&SystemTime);
	    if (FatVolumeIsFatX(DeviceExt)) {
		FsdSystemTimeToDosDateTime(DeviceExt, &SystemTime,
					   &Fcb->Entry.FatX.UpdateDate,
					   &Fcb->Entry.FatX.UpdateTime);
	    } else {
		FsdSystemTimeToDosDateTime(DeviceExt, &SystemTime,
					   &Fcb->Entry.Fat.UpdateDate,
					   &Fcb->Entry.Fat.UpdateTime);
	    }

	    FatUpdateEntry(DeviceExt, Fcb);
	}

	Status = FatSetFileSizeInformation(FileObject, Fcb, DeviceExt,
					   &Irp->AllocationSize);
	if (!NT_SUCCESS(Status)) {
	    goto OpenFail;
	}
    }

    if (RequestedDisposition == FILE_SUPERSEDE) {
	Irp->IoStatus.Information = FILE_SUPERSEDED;
    } else if (RequestedDisposition == FILE_OVERWRITE ||
	       RequestedDisposition == FILE_OVERWRITE_IF) {
	Irp->IoStatus.Information = FILE_OVERWRITTEN;
    } else {
	Irp->IoStatus.Information = FILE_OPENED;
    }
    goto Done;

OpenFail:
    ASSERT(!NT_SUCCESS(Status));
    FatCloseFile(DeviceExt, FileObject);
    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
    return Status;

Done:
    if (Fcb->OpenHandleCount == 0) {
	IoSetShareAccess(Stack->Parameters.Create.SecurityContext->DesiredAccess,
			 Stack->Parameters.Create.ShareAccess, FileObject,
			 &Fcb->FcbShareAccess);
    } else {
	IoUpdateShareAccess(FileObject, &Fcb->FcbShareAccess);
    }

    PFATCCB Ccb = FileObject->FsContext2;
    if (BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) {
	Ccb->Flags |= CCB_DELETE_ON_CLOSE;
    }

    if (Irp->IoStatus.Information == FILE_CREATED) {
	FatReportChange(DeviceExt, Fcb,
			(FatFcbIsDirectory(Fcb) ? FILE_NOTIFY_CHANGE_DIR_NAME :
			 FILE_NOTIFY_CHANGE_FILE_NAME), FILE_ACTION_ADDED);
    } else if (Irp->IoStatus.Information == FILE_OVERWRITTEN
	       || Irp->IoStatus.Information == FILE_SUPERSEDED) {
	FatReportChange(DeviceExt, Fcb,
			FILE_NOTIFY_CHANGE_LAST_WRITE |
			FILE_NOTIFY_CHANGE_ATTRIBUTES |
			FILE_NOTIFY_CHANGE_SIZE, FILE_ACTION_MODIFIED);
    }

    Fcb->OpenHandleCount++;
    DeviceExt->OpenHandleCount++;

    /* FIXME : test write access if requested */

    /* We cannot reach this code path with failure */
    ASSERT(NT_SUCCESS(Status));
    FatAddToStat(DeviceExt, Fat.SuccessfulCreates, 1);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Create or open a file
 */
NTSTATUS FatCreate(PFAT_IRP_CONTEXT IrpContext)
{
    ASSERT(IrpContext);

    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	/* DeviceObject represents FileSystem instead of logical volume */
	DPRINT("FsdCreate called with file system\n");
	IrpContext->Irp->IoStatus.Information = FILE_OPENED;
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;

	return STATUS_SUCCESS;
    }

    IrpContext->Irp->IoStatus.Information = 0;
    NTSTATUS Status = FatCreateFile(IrpContext->DeviceObject, IrpContext->Irp);

    if (NT_SUCCESS(Status))
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;

    return Status;
}
