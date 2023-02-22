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

VOID Fat8Dot3ToString(PFAT_DIR_ENTRY pEntry, PUNICODE_STRING NameU)
{
    OEM_STRING StringA;
    USHORT Length;
    CHAR cString[12];

    RtlCopyMemory(cString, pEntry->ShortName, 11);
    cString[11] = 0;
    if (cString[0] == 0x05) {
	cString[0] = 0xe5;
    }

    StringA.Buffer = cString;
    for (StringA.Length = 0;
	 StringA.Length < 8 && StringA.Buffer[StringA.Length] != ' ';
	 StringA.Length++);
    StringA.MaximumLength = StringA.Length;

    RtlOemStringToUnicodeString(NameU, &StringA, FALSE);

    if (BooleanFlagOn(pEntry->lCase, FAT_CASE_LOWER_BASE)) {
	RtlDowncaseUnicodeString(NameU, NameU, FALSE);
    }

    if (cString[8] != ' ') {
	Length = NameU->Length;
	NameU->Buffer += Length / sizeof(WCHAR);
	if (!FAT_ENTRY_VOLUME(pEntry)) {
	    Length += sizeof(WCHAR);
	    NameU->Buffer[0] = L'.';
	    NameU->Buffer++;
	}
	NameU->Length = 0;
	NameU->MaximumLength -= Length;

	StringA.Buffer = &cString[8];
	for (StringA.Length = 0;
	     StringA.Length < 3 && StringA.Buffer[StringA.Length] != ' ';
	     StringA.Length++);
	StringA.MaximumLength = StringA.Length;
	RtlOemStringToUnicodeString(NameU, &StringA, FALSE);
	if (BooleanFlagOn(pEntry->lCase, FAT_CASE_LOWER_EXT)) {
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
    PWCHAR PathNameBuffer;
    USHORT PathNameBufferLength;
    NTSTATUS Status;
    PVOID Context = NULL;
    PVOID Page;
    PFATFCB rcFcb;
    BOOLEAN Found;
    UNICODE_STRING PathNameU;
    UNICODE_STRING FileToFindUpcase;
    BOOLEAN WildCard;
    BOOLEAN IsFatX = FatVolumeIsFatX(DeviceExt);

    DPRINT("FindFile(Parent %p, FileToFind '%wZ', DirIndex: %u)\n",
	   Parent, FileToFindU, DirContext->DirIndex);
    DPRINT("FindFile: Path %wZ\n", &Parent->PathNameU);

    PathNameBufferLength = LONGNAME_MAX_LENGTH * sizeof(WCHAR);
    PathNameBuffer = ExAllocatePoolWithTag(NonPagedPool,
					   PathNameBufferLength + sizeof(WCHAR),
					   TAG_NAME);
    if (!PathNameBuffer) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    PathNameU.Buffer = PathNameBuffer;
    PathNameU.Length = 0;
    PathNameU.MaximumLength = PathNameBufferLength;

    DirContext->LongNameU.Length = 0;
    DirContext->ShortNameU.Length = 0;

    WildCard = FsRtlDoesNameContainWildCards(FileToFindU);

    if (WildCard == FALSE) {
	/* if there is no '*?' in the search name, than look first for an existing fcb */
	RtlCopyUnicodeString(&PathNameU, &Parent->PathNameU);
	if (!FatFCBIsRoot(Parent)) {
	    PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = L'\\';
	    PathNameU.Length += sizeof(WCHAR);
	}
	RtlAppendUnicodeStringToString(&PathNameU, FileToFindU);
	PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = 0;
	rcFcb = FatGrabFCBFromTable(DeviceExt, &PathNameU);
	if (rcFcb) {
	    ULONG startIndex = rcFcb->startIndex;
	    if (IsFatX && !FatFCBIsRoot(Parent)) {
		startIndex += 2;
	    }
	    if (startIndex >= DirContext->DirIndex) {
		RtlCopyUnicodeString(&DirContext->LongNameU,
				     &rcFcb->LongNameU);
		RtlCopyUnicodeString(&DirContext->ShortNameU,
				     &rcFcb->ShortNameU);
		RtlCopyMemory(&DirContext->DirEntry, &rcFcb->entry,
			      sizeof(DIR_ENTRY));
		DirContext->StartIndex = rcFcb->startIndex;
		DirContext->DirIndex = rcFcb->dirIndex;
		DPRINT("FindFile: new Name %wZ, DirIndex %u (%u)\n",
		       &DirContext->LongNameU, DirContext->DirIndex,
		       DirContext->StartIndex);
		Status = STATUS_SUCCESS;
	    } else {
		DPRINT("FCB not found for %wZ\n", &PathNameU);
		Status = STATUS_UNSUCCESSFUL;
	    }
	    FatReleaseFCB(DeviceExt, rcFcb);
	    ExFreePoolWithTag(PathNameBuffer, TAG_NAME);
	    return Status;
	}
    }

    /* FsRtlIsNameInExpression need the searched string to be upcase,
     * even if IgnoreCase is specified */
    Status = RtlUpcaseUnicodeString(&FileToFindUpcase, FileToFindU, TRUE);
    if (!NT_SUCCESS(Status)) {
	ExFreePoolWithTag(PathNameBuffer, TAG_NAME);
	return Status;
    }

    while (TRUE) {
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
	    DPRINT1("WARNING: File system corruption detected. You may need to run a disk repair utility.\n");
	    if (FatGlobalData->Flags & FAT_BREAK_ON_CORRUPTION) {
		ASSERT(DirContext->LongNameU.Length != 0 &&
		       DirContext->ShortNameU.Length != 0);
	    }
	    DirContext->DirIndex++;
	    continue;
	}
	if (WildCard) {
	    Found = FsRtlIsNameInExpression(&FileToFindUpcase,
					    &DirContext->LongNameU, TRUE, NULL)
		|| FsRtlIsNameInExpression(&FileToFindUpcase,
					   &DirContext->ShortNameU, TRUE,
					   NULL);
	} else {
	    Found = FsRtlAreNamesEqual(&DirContext->LongNameU, FileToFindU,
				       TRUE, NULL)
		|| FsRtlAreNamesEqual(&DirContext->ShortNameU, FileToFindU,
				      TRUE, NULL);
	}

	if (Found) {
	    if (WildCard) {
		RtlCopyUnicodeString(&PathNameU, &Parent->PathNameU);
		if (!FatFCBIsRoot(Parent)) {
		    PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = L'\\';
		    PathNameU.Length += sizeof(WCHAR);
		}
		RtlAppendUnicodeStringToString(&PathNameU,
					       &DirContext->LongNameU);
		PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR)] = 0;
		rcFcb = FatGrabFCBFromTable(DeviceExt, &PathNameU);
		if (rcFcb != NULL) {
		    RtlCopyMemory(&DirContext->DirEntry, &rcFcb->entry,
				  sizeof(DIR_ENTRY));
		    FatReleaseFCB(DeviceExt, rcFcb);
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
			    PFATFCB * ParentFcb)
{
    PFATFCB Fcb;
    NTSTATUS Status;

    DPRINT("FatOpenFile(%p, '%wZ', %p, %p)\n", DeviceExt, PathNameU,
	   FileObject, ParentFcb);

    if (FileObject->RelatedFileObject) {
	DPRINT("'%wZ'\n", &FileObject->RelatedFileObject->FileName);

	*ParentFcb = FileObject->RelatedFileObject->FsContext;
    } else {
	*ParentFcb = NULL;
    }

    if (!DeviceExt->FatInfo.FixedMedia) {
	Status = FatBlockDeviceIoControl(DeviceExt->StorageDevice,
					 IOCTL_DISK_CHECK_VERIFY,
					 NULL, 0, NULL, 0, FALSE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT("Status %lx\n", Status);
	    *ParentFcb = NULL;
	    return Status;
	}
    }

    if (*ParentFcb) {
	FatGrabFCB(DeviceExt, *ParentFcb);
    }

    /*  try first to find an existing FCB in memory  */
    DPRINT("Checking for existing FCB in memory\n");

    Status = FatGetFCBForFile(DeviceExt, ParentFcb, &Fcb, PathNameU);
    if (!NT_SUCCESS(Status)) {
	DPRINT("Could not make a new FCB, status: %x\n", Status);
	return Status;
    }

    /* Fail, if we try to overwrite an existing directory */
    if ((!BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE)
	 && FatFCBIsDirectory(Fcb))
	&& (RequestedDisposition == FILE_OVERWRITE
	    || RequestedDisposition == FILE_OVERWRITE_IF
	    || RequestedDisposition == FILE_SUPERSEDE)) {
	FatReleaseFCB(DeviceExt, Fcb);
	return STATUS_OBJECT_NAME_COLLISION;
    }

    if (BooleanFlagOn(Fcb->Flags, FCB_DELETE_PENDING)) {
	FatReleaseFCB(DeviceExt, Fcb);
	return STATUS_DELETE_PENDING;
    }

    /* Fail, if we try to overwrite a read-only file */
    if (FatFCBIsReadOnly(Fcb) &&
	(RequestedDisposition == FILE_OVERWRITE ||
	 RequestedDisposition == FILE_OVERWRITE_IF)) {
	FatReleaseFCB(DeviceExt, Fcb);
	return STATUS_ACCESS_DENIED;
    }

    if (FatFCBIsReadOnly(Fcb) && (RequestedOptions & FILE_DELETE_ON_CLOSE)) {
	FatReleaseFCB(DeviceExt, Fcb);
	return STATUS_CANNOT_DELETE;
    }

    if ((FatFCBIsRoot(Fcb) || IsDotOrDotDot(&Fcb->LongNameU)) &&
	BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) {
	// we cannot delete a '.', '..' or the root directory
	FatReleaseFCB(DeviceExt, Fcb);
	return STATUS_CANNOT_DELETE;
    }

    /* If that one was marked for closing, remove it */
    if (BooleanFlagOn(Fcb->Flags, FCB_DELAYED_CLOSE)) {
	BOOLEAN ConcurrentDeletion;
	PFAT_CLOSE_CONTEXT CloseContext;

	/* Get the context */
	CloseContext = Fcb->CloseContext;
	/* Is someone already taking over? */
	if (CloseContext != NULL) {
	    ConcurrentDeletion = FALSE;
	    /* Lock list */
	    ExAcquireFastMutex(&FatGlobalData->CloseMutex);
	    /* Check whether it was already removed, if not, do it */
	    if (!IsListEmpty(&CloseContext->CloseListEntry)) {
		RemoveEntryList(&CloseContext->CloseListEntry);
		--FatGlobalData->CloseCount;
		ConcurrentDeletion = TRUE;
	    }
	    ExReleaseFastMutex(&FatGlobalData->CloseMutex);

	    /* It's not delayed anymore! */
	    ClearFlag(Fcb->Flags, FCB_DELAYED_CLOSE);
	    /* Release the extra reference (would have been removed by IRP_MJ_CLOSE) */
	    FatReleaseFCB(DeviceExt, Fcb);
	    Fcb->CloseContext = NULL;
	    /* If no concurrent deletion, free work item */
	    if (!ConcurrentDeletion) {
		ExFreeToPagedLookasideList(&FatGlobalData->
					   CloseContextLookasideList,
					   CloseContext);
	    }
	}

	DPRINT("Reusing delayed close FCB for %wZ\n", &Fcb->PathNameU);
    }

    DPRINT("Attaching FCB to fileObject\n");
    Status = FatAttachFCBToFileObject(DeviceExt, Fcb, FileObject);
    if (!NT_SUCCESS(Status)) {
	FatReleaseFCB(DeviceExt, Fcb);
    }
    return Status;
}

/*
 * FUNCTION: Create or open a file
 */
static NTSTATUS FatCreateFile(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack;
    PFILE_OBJECT FileObject;
    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_EXTENSION DeviceExt;
    ULONG RequestedDisposition, RequestedOptions;
    PFATFCB pFcb = NULL;
    PFATFCB ParentFcb = NULL;
    PFATCCB pCcb = NULL;
    PWCHAR c, last;
    BOOLEAN PagingFileCreate;
    BOOLEAN Dots;
    BOOLEAN OpenTargetDir;
    BOOLEAN TrailingBackslash;
    UNICODE_STRING FileNameU;
    UNICODE_STRING PathNameU;
    ULONG Attributes;

    /* Unpack the various parameters. */
    Stack = IoGetCurrentIrpStackLocation(Irp);
    RequestedDisposition = ((Stack->Parameters.Create.Options >> 24) & 0xff);
    RequestedOptions = Stack->Parameters.Create.Options & FILE_VALID_OPTION_FLAGS;
    PagingFileCreate = BooleanFlagOn(Stack->Flags, SL_OPEN_PAGING_FILE);
    OpenTargetDir = BooleanFlagOn(Stack->Flags, SL_OPEN_TARGET_DIRECTORY);

    FileObject = Stack->FileObject;
    DeviceExt = DeviceObject->DeviceExtension;

    if (BooleanFlagOn
	(Stack->Parameters.Create.Options, FILE_OPEN_BY_FILE_ID)) {
	return STATUS_NOT_IMPLEMENTED;
    }

    /* Check their validity. */
    if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	RequestedDisposition == FILE_SUPERSEDE) {
	return STATUS_INVALID_PARAMETER;
    }

    if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	BooleanFlagOn(RequestedOptions, FILE_NON_DIRECTORY_FILE)) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Deny create if the volume is locked */
    if (BooleanFlagOn(DeviceExt->Flags, VCB_VOLUME_LOCKED)) {
	return STATUS_ACCESS_DENIED;
    }

    /* This a open operation for the volume itself */
    if (FileObject->FileName.Length == 0 &&
	(FileObject->RelatedFileObject == NULL ||
	 FileObject->RelatedFileObject->FsContext2 != NULL ||
	 FileObject->RelatedFileObject->FsContext == DeviceExt->VolumeFcb))
    {
	DPRINT("Volume opening\n");

	if (RequestedDisposition != FILE_OPEN &&
	    RequestedDisposition != FILE_OPEN_IF) {
	    return STATUS_ACCESS_DENIED;
	}

	if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	    (FileObject->RelatedFileObject == NULL
	     || FileObject->RelatedFileObject->FsContext2 == NULL
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

	pFcb = DeviceExt->VolumeFcb;

	if (pFcb->OpenHandleCount == 0) {
	    IoSetShareAccess(Stack->Parameters.Create.SecurityContext->
			     DesiredAccess,
			     Stack->Parameters.Create.ShareAccess,
			     FileObject, &pFcb->FCBShareAccess);
	} else {
	    Status = IoCheckShareAccess(Stack->Parameters.Create.
					SecurityContext->DesiredAccess,
					Stack->Parameters.Create.ShareAccess,
					FileObject, &pFcb->FCBShareAccess,
					TRUE);
	    if (!NT_SUCCESS(Status)) {
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return Status;
	    }
	}

	FatAttachFCBToFileObject(DeviceExt, pFcb, FileObject);
	DeviceExt->OpenHandleCount++;
	pFcb->OpenHandleCount++;
	FatAddToStat(DeviceExt, Fat.SuccessfulCreates, 1);

	Irp->IoStatus.Information = FILE_OPENED;
	return STATUS_SUCCESS;
    }

    if (FileObject->RelatedFileObject != NULL &&
	FileObject->RelatedFileObject->FsContext == DeviceExt->VolumeFcb) {
	ASSERT(FileObject->FileName.Length != 0);
	return STATUS_OBJECT_PATH_NOT_FOUND;
    }

    /* Check for illegal characters and illegal dot sequences in the file name */
    PathNameU = FileObject->FileName;
    c = PathNameU.Buffer + PathNameU.Length / sizeof(WCHAR);
    last = c - 1;

    Dots = TRUE;
    while (c-- > PathNameU.Buffer) {
	if (*c == L'\\' || c == PathNameU.Buffer) {
	    if (Dots && last > c) {
		return STATUS_OBJECT_NAME_INVALID;
	    }
	    if (*c == L'\\' && (c - 1) > PathNameU.Buffer &&
		*(c - 1) == L'\\') {
		return STATUS_OBJECT_NAME_INVALID;
	    }

	    last = c - 1;
	    Dots = TRUE;
	} else if (*c != L'.') {
	    Dots = FALSE;
	}

	if (*c != '\\' && FatIsLongIllegal(*c)) {
	    return STATUS_OBJECT_NAME_INVALID;
	}
    }

    /* Check if we try to open target directory of root dir */
    if (OpenTargetDir && FileObject->RelatedFileObject == NULL
	&& PathNameU.Length == sizeof(WCHAR)
	&& PathNameU.Buffer[0] == L'\\') {
	return STATUS_INVALID_PARAMETER;
    }

    if (FileObject->RelatedFileObject && PathNameU.Length >= sizeof(WCHAR)
	&& PathNameU.Buffer[0] == L'\\') {
	return STATUS_OBJECT_NAME_INVALID;
    }

    TrailingBackslash = FALSE;
    if (PathNameU.Length > sizeof(WCHAR)
	&& PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR) - 1] == L'\\') {
	PathNameU.Length -= sizeof(WCHAR);
	TrailingBackslash = TRUE;
    }

    if (PathNameU.Length > sizeof(WCHAR)
	&& PathNameU.Buffer[PathNameU.Length / sizeof(WCHAR) - 1] == L'\\') {
	return STATUS_OBJECT_NAME_INVALID;
    }

    /* Try opening the file. */
    if (!OpenTargetDir) {
	FatAddToStat(DeviceExt, Fat.CreateHits, 1);

	Status = FatOpenFile(DeviceExt, &PathNameU, FileObject,
			     RequestedDisposition, RequestedOptions,
			     &ParentFcb);
    } else {
	PFATFCB TargetFcb;
	LONG idx, FileNameLen;

	FatAddToStat(DeviceExt, Fat.CreateHits, 1);

	ParentFcb = (FileObject->RelatedFileObject != NULL) ? FileObject->RelatedFileObject->FsContext : NULL;
	if (ParentFcb) {
	    FatGrabFCB(DeviceExt, ParentFcb);
	}

	Status = FatGetFCBForFile(DeviceExt, &ParentFcb, &TargetFcb,
				  &PathNameU);
	if (NT_SUCCESS(Status)) {
	    FatReleaseFCB(DeviceExt, TargetFcb);
	    Irp->IoStatus.Information = FILE_EXISTS;
	} else {
	    Irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
	}

	idx = FileObject->FileName.Length / sizeof(WCHAR) - 1;

	/* Skip trailing \ - if any */
	if (PathNameU.Buffer[idx] == L'\\') {
	    --idx;
	    PathNameU.Length -= sizeof(WCHAR);
	}

	/* Get file name */
	while (idx >= 0 && PathNameU.Buffer[idx] != L'\\') {
	    --idx;
	}

	if (idx > 0 || PathNameU.Buffer[0] == L'\\') {
	    /* We don't want to include / in the name */
	    FileNameLen = PathNameU.Length - ((idx + 1) * sizeof(WCHAR));

	    /* Update FO just to keep file name */
	    /* Skip first slash */
	    ++idx;
	    FileObject->FileName.Length = FileNameLen;
	    RtlMoveMemory(&PathNameU.Buffer[0], &PathNameU.Buffer[idx],
			  FileObject->FileName.Length);
#if 0
	    /* Terminate the string at the last backslash */
	    PathNameU.Buffer[idx + 1] = UNICODE_NULL;
	    PathNameU.Length = (idx + 1) * sizeof(WCHAR);
	    PathNameU.MaximumLength = PathNameU.Length + sizeof(WCHAR);

	    /* Update the file object as well */
	    FileObject->FileName.Length = PathNameU.Length;
	    FileObject->FileName.MaximumLength = PathNameU.MaximumLength;
#endif
	} else {
	    /* This is a relative open and we have only the filename, so open the parent directory
	     * It is in RelatedFileObject
	     */
	    ASSERT(FileObject->RelatedFileObject != NULL);

	    /* No need to modify the FO, it already has the name */
	}

	/* We're done with opening! */
	if (ParentFcb != NULL) {
	    Status = FatAttachFCBToFileObject(DeviceExt, ParentFcb, FileObject);
	}

	if (NT_SUCCESS(Status)) {
	    pFcb = FileObject->FsContext;
	    ASSERT(pFcb == ParentFcb);

	    if (pFcb->OpenHandleCount == 0) {
		IoSetShareAccess(Stack->Parameters.Create.SecurityContext->
				 DesiredAccess,
				 Stack->Parameters.Create.ShareAccess,
				 FileObject, &pFcb->FCBShareAccess);
	    } else {
		Status = IoCheckShareAccess(Stack->Parameters.Create.
					    SecurityContext->DesiredAccess,
					    Stack->Parameters.Create.
					    ShareAccess, FileObject,
					    &pFcb->FCBShareAccess, FALSE);
		if (!NT_SUCCESS(Status)) {
		    FatCloseFile(DeviceExt, FileObject);
		    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		    return Status;
		}
	    }

	    pCcb = FileObject->FsContext2;
	    if (BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) {
		pCcb->Flags |= CCB_DELETE_ON_CLOSE;
	    }

	    pFcb->OpenHandleCount++;
	    DeviceExt->OpenHandleCount++;
	} else if (ParentFcb != NULL) {
	    FatReleaseFCB(DeviceExt, ParentFcb);
	}

	if (NT_SUCCESS(Status)) {
	    FatAddToStat(DeviceExt, Fat.SuccessfulCreates, 1);
	} else {
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	}

	return Status;
    }

    /*
     * If the directory containing the file to open doesn't exist then
     * fail immediately
     */
    if (Status == STATUS_OBJECT_PATH_NOT_FOUND ||
	Status == STATUS_INVALID_PARAMETER ||
	Status == STATUS_DELETE_PENDING ||
	Status == STATUS_ACCESS_DENIED ||
	Status == STATUS_OBJECT_NAME_COLLISION) {
	if (ParentFcb) {
	    FatReleaseFCB(DeviceExt, ParentFcb);
	}
	FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	return Status;
    }

    if (!NT_SUCCESS(Status) && ParentFcb == NULL) {
	DPRINT1("FatOpenFile failed for '%wZ', status %x\n", &PathNameU,
		Status);
	FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	return Status;
    }

    Attributes = (Stack->Parameters.Create.
		  FileAttributes & (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM |
				    FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_DIRECTORY
				    | FILE_ATTRIBUTE_READONLY));

    /* If the file open failed then create the required file */
    if (!NT_SUCCESS(Status)) {
	if (RequestedDisposition == FILE_CREATE ||
	    RequestedDisposition == FILE_OPEN_IF ||
	    RequestedDisposition == FILE_OVERWRITE_IF ||
	    RequestedDisposition == FILE_SUPERSEDE) {
	    if (!BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE)) {
		if (TrailingBackslash) {
		    FatReleaseFCB(DeviceExt, ParentFcb);
		    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		    return STATUS_OBJECT_NAME_INVALID;
		}
		Attributes |= FILE_ATTRIBUTE_ARCHIVE;
	    }
	    FatSplitPathName(&PathNameU, NULL, &FileNameU);

	    if (IsDotOrDotDot(&FileNameU)) {
		FatReleaseFCB(DeviceExt, ParentFcb);
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return STATUS_OBJECT_NAME_INVALID;
	    }
	    Status = FatAddEntry(DeviceExt, &FileNameU, &pFcb, ParentFcb,
				 RequestedOptions, Attributes, NULL);
	    FatReleaseFCB(DeviceExt, ParentFcb);
	    if (NT_SUCCESS(Status)) {
		Status = FatAttachFCBToFileObject(DeviceExt, pFcb, FileObject);
		if (!NT_SUCCESS(Status)) {
		    FatReleaseFCB(DeviceExt, pFcb);
		    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		    return Status;
		}

		Irp->IoStatus.Information = FILE_CREATED;
		FatSetAllocationSizeInformation(FileObject,
						pFcb,
						DeviceExt,
						&Irp->Overlay.
						AllocationSize);
		FatSetExtendedAttributes(FileObject,
					 Irp->AssociatedIrp.SystemBuffer,
					 Stack->Parameters.Create.
					 EaLength);

		if (PagingFileCreate) {
		    pFcb->Flags |= FCB_IS_PAGE_FILE;
		    SetFlag(DeviceExt->Flags, VCB_IS_SYS_OR_HAS_PAGE);
		}
	    } else {
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return Status;
	    }
	} else {
	    FatReleaseFCB(DeviceExt, ParentFcb);
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return Status;
	}
    } else {
	if (ParentFcb) {
	    FatReleaseFCB(DeviceExt, ParentFcb);
	}

	pFcb = FileObject->FsContext;

	/* Otherwise fail if the caller wanted to create a new file  */
	if (RequestedDisposition == FILE_CREATE) {
	    FatCloseFile(DeviceExt, FileObject);
	    if (TrailingBackslash && !FatFCBIsDirectory(pFcb)) {
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return STATUS_OBJECT_NAME_INVALID;
	    }
	    Irp->IoStatus.Information = FILE_EXISTS;
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return STATUS_OBJECT_NAME_COLLISION;
	}

	if (pFcb->OpenHandleCount != 0) {
	    Status = IoCheckShareAccess(Stack->Parameters.Create.
					SecurityContext->DesiredAccess,
					Stack->Parameters.Create.ShareAccess,
					FileObject, &pFcb->FCBShareAccess,
					FALSE);
	    if (!NT_SUCCESS(Status)) {
		FatCloseFile(DeviceExt, FileObject);
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return Status;
	    }
	}

	/*
	 * Check the file has the requested attributes
	 */
	if (BooleanFlagOn(RequestedOptions, FILE_NON_DIRECTORY_FILE) &&
	    FatFCBIsDirectory(pFcb)) {
	    FatCloseFile(DeviceExt, FileObject);
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return STATUS_FILE_IS_A_DIRECTORY;
	}
	if (BooleanFlagOn(RequestedOptions, FILE_DIRECTORY_FILE) &&
	    !FatFCBIsDirectory(pFcb)) {
	    FatCloseFile(DeviceExt, FileObject);
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return STATUS_NOT_A_DIRECTORY;
	}
	if (TrailingBackslash && !FatFCBIsDirectory(pFcb)) {
	    FatCloseFile(DeviceExt, FileObject);
	    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
	    return STATUS_OBJECT_NAME_INVALID;
	}
#ifndef USE_ROS_CC_AND_FS
	if (!FatFCBIsDirectory(pFcb)) {
	    if (BooleanFlagOn
		(Stack->Parameters.Create.SecurityContext->DesiredAccess,
		 FILE_WRITE_DATA) || RequestedDisposition == FILE_OVERWRITE
		|| RequestedDisposition == FILE_OVERWRITE_IF
		|| (RequestedOptions & FILE_DELETE_ON_CLOSE)) {
		if (!MmFlushImageSection
		    (&pFcb->SectionObjectPointers, MmFlushForWrite)) {
		    DPRINT1("%wZ\n", &pFcb->PathNameU);
		    DPRINT1("%d %d %d\n",
			    Stack->Parameters.Create.SecurityContext->
			    DesiredAccess & FILE_WRITE_DATA,
			    RequestedDisposition == FILE_OVERWRITE,
			    RequestedDisposition == FILE_OVERWRITE_IF);
		    FatCloseFile(DeviceExt, FileObject);
		    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		    return (BooleanFlagOn
			    (RequestedOptions,
			     FILE_DELETE_ON_CLOSE)) ? STATUS_CANNOT_DELETE
			: STATUS_SHARING_VIOLATION;
		}
	    }
	}
#endif
	if (PagingFileCreate) {
	    /* FIXME:
	     *   Do more checking for page files. It is possible,
	     *   that the file was opened and closed previously
	     *   as a normal cached file. In this case, the cache
	     *   manager has referenced the fileobject and the fcb
	     *   is held in memory. Try to remove the fileobject
	     *   from cache manager and use the fcb.
	     */
	    if (pFcb->RefCount > 1) {
		if (!BooleanFlagOn(pFcb->Flags, FCB_IS_PAGE_FILE)) {
		    FatCloseFile(DeviceExt, FileObject);
		    FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		    return STATUS_INVALID_PARAMETER;
		}
	    } else {
		pFcb->Flags |= FCB_IS_PAGE_FILE;
		SetFlag(DeviceExt->Flags, VCB_IS_SYS_OR_HAS_PAGE);
	    }
	} else {
	    if (BooleanFlagOn(pFcb->Flags, FCB_IS_PAGE_FILE)) {
		FatCloseFile(DeviceExt, FileObject);
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return STATUS_INVALID_PARAMETER;
	    }
	}

	if (RequestedDisposition == FILE_OVERWRITE ||
	    RequestedDisposition == FILE_OVERWRITE_IF ||
	    RequestedDisposition == FILE_SUPERSEDE) {
	    if ((BooleanFlagOn(*pFcb->Attributes, FILE_ATTRIBUTE_HIDDEN)
		 && !BooleanFlagOn(Attributes, FILE_ATTRIBUTE_HIDDEN))
		|| (BooleanFlagOn(*pFcb->Attributes, FILE_ATTRIBUTE_SYSTEM)
		    && !BooleanFlagOn(Attributes,
				      FILE_ATTRIBUTE_SYSTEM))) {
		FatCloseFile(DeviceExt, FileObject);
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return STATUS_ACCESS_DENIED;
	    }

	    if (!FatFCBIsDirectory(pFcb)) {
		LARGE_INTEGER SystemTime;

		if (RequestedDisposition == FILE_SUPERSEDE) {
		    *pFcb->Attributes = Attributes;
		} else {
		    *pFcb->Attributes |= Attributes;
		}
		*pFcb->Attributes |= FILE_ATTRIBUTE_ARCHIVE;

		KeQuerySystemTime(&SystemTime);
		if (FatVolumeIsFatX(DeviceExt)) {
		    FsdSystemTimeToDosDateTime(DeviceExt,
					       &SystemTime,
					       &pFcb->entry.FatX.
					       UpdateDate,
					       &pFcb->entry.FatX.
					       UpdateTime);
		} else {
		    FsdSystemTimeToDosDateTime(DeviceExt,
					       &SystemTime,
					       &pFcb->entry.Fat.UpdateDate,
					       &pFcb->entry.Fat.
					       UpdateTime);
		}

		FatUpdateEntry(DeviceExt, pFcb);
	    }

	    ExAcquireResourceExclusiveLite(&(pFcb->MainResource), TRUE);
	    Status = FatSetAllocationSizeInformation(FileObject,
						     pFcb,
						     DeviceExt,
						     &Irp->Overlay.
						     AllocationSize);
	    ExReleaseResourceLite(&(pFcb->MainResource));
	    if (!NT_SUCCESS(Status)) {
		FatCloseFile(DeviceExt, FileObject);
		FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
		return Status;
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
    }

    if (pFcb->OpenHandleCount == 0) {
	IoSetShareAccess(Stack->Parameters.Create.SecurityContext->
			 DesiredAccess,
			 Stack->Parameters.Create.ShareAccess, FileObject,
			 &pFcb->FCBShareAccess);
    } else {
	IoUpdateShareAccess(FileObject, &pFcb->FCBShareAccess);
    }

    pCcb = FileObject->FsContext2;
    if (BooleanFlagOn(RequestedOptions, FILE_DELETE_ON_CLOSE)) {
	pCcb->Flags |= CCB_DELETE_ON_CLOSE;
    }

    if (Irp->IoStatus.Information == FILE_CREATED) {
	FatReportChange(DeviceExt,
			pFcb,
			(FatFCBIsDirectory(pFcb) ?
			 FILE_NOTIFY_CHANGE_DIR_NAME :
			 FILE_NOTIFY_CHANGE_FILE_NAME), FILE_ACTION_ADDED);
    } else if (Irp->IoStatus.Information == FILE_OVERWRITTEN
	       || Irp->IoStatus.Information == FILE_SUPERSEDED) {
	FatReportChange(DeviceExt, pFcb,
			FILE_NOTIFY_CHANGE_LAST_WRITE |
			FILE_NOTIFY_CHANGE_ATTRIBUTES |
			FILE_NOTIFY_CHANGE_SIZE, FILE_ACTION_MODIFIED);
    }

    pFcb->OpenHandleCount++;
    DeviceExt->OpenHandleCount++;

    /* FIXME : test write access if requested */

    /* FIXME: That is broken, we cannot reach this code path with failure */
    ASSERT(NT_SUCCESS(Status));
    if (NT_SUCCESS(Status)) {
	FatAddToStat(DeviceExt, Fat.SuccessfulCreates, 1);
    } else {
	FatAddToStat(DeviceExt, Fat.FailedCreates, 1);
    }

    return Status;
}

/*
 * FUNCTION: Create or open a file
 */
NTSTATUS FatCreate(PFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status;

    ASSERT(IrpContext);

    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	/* DeviceObject represents FileSystem instead of logical volume */
	DPRINT("FsdCreate called with file system\n");
	IrpContext->Irp->IoStatus.Information = FILE_OPENED;
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;

	return STATUS_SUCCESS;
    }

    IrpContext->Irp->IoStatus.Information = 0;
    ExAcquireResourceExclusiveLite(&IrpContext->DeviceExt->DirResource,
				   TRUE);
    Status = FatCreateFile(IrpContext->DeviceObject, IrpContext->Irp);
    ExReleaseResourceLite(&IrpContext->DeviceExt->DirResource);

    if (NT_SUCCESS(Status))
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;

    return Status;
}
