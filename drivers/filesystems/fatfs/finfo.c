/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     File information routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2005 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2008-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"
#include "ntstatus.h"

/* GLOBALS ******************************************************************/

const char *FileInformationClassNames[] = {
    "??????",
    "FileDirectoryInformation",
    "FileFullDirectoryInformation",
    "FileBothDirectoryInformation",
    "FileBasicInformation",
    "FileStandardInformation",
    "FileInternalInformation",
    "FileEaInformation",
    "FileAccessInformation",
    "FileNameInformation",
    "FileRenameInformation",
    "FileLinkInformation",
    "FileNamesInformation",
    "FileDispositionInformation",
    "FilePositionInformation",
    "FileFullEaInformation",
    "FileModeInformation",
    "FileAlignmentInformation",
    "FileAllInformation",
    "FileAllocationInformation",
    "FileEndOfFileInformation",
    "FileAlternateNameInformation",
    "FileStreamInformation",
    "FilePipeInformation",
    "FilePipeLocalInformation",
    "FilePipeRemoteInformation",
    "FileMailslotQueryInformation",
    "FileMailslotSetInformation",
    "FileCompressionInformation",
    "FileObjectIdInformation",
    "FileCompletionInformation",
    "FileMoveClusterInformation",
    "FileQuotaInformation",
    "FileReparsePointInformation",
    "FileNetworkOpenInformation",
    "FileAttributeTagInformation",
    "FileTrackingInformation",
    "FileIdBothDirectoryInformation",
    "FileIdFullDirectoryInformation",
    "FileValidDataLengthInformation",
    "FileShortNameInformation",
    "FileMaximumInformation"
};

/* FUNCTIONS ****************************************************************/

/*
 * FUNCTION: Retrieve the standard file information
 */
NTSTATUS FatGetStandardInformation(PFATFCB Fcb,
				   PFILE_STANDARD_INFORMATION StandardInfo,
				   PULONG BufferLength)
{
    if (*BufferLength < sizeof(FILE_STANDARD_INFORMATION))
	return STATUS_BUFFER_OVERFLOW;

    /* PRECONDITION */
    ASSERT(StandardInfo != NULL);
    ASSERT(Fcb != NULL);

    if (FatFcbIsDirectory(Fcb)) {
	StandardInfo->AllocationSize.QuadPart = 0;
	StandardInfo->EndOfFile.QuadPart = 0;
	StandardInfo->Directory = TRUE;
    } else {
	StandardInfo->AllocationSize = Fcb->Base.FileSizes.AllocationSize;
	StandardInfo->EndOfFile = Fcb->Base.FileSizes.FileSize;
	StandardInfo->Directory = FALSE;
    }
    StandardInfo->NumberOfLinks = 1;
    StandardInfo->DeletePending = BooleanFlagOn(Fcb->Flags, FCB_DELETE_PENDING);

    *BufferLength -= sizeof(FILE_STANDARD_INFORMATION);
    return STATUS_SUCCESS;
}

static NTSTATUS FatSetBasicInformation(PFILE_OBJECT FileObject,
				       PFATFCB Fcb,
				       PDEVICE_EXTENSION DeviceExt,
				       PFILE_BASIC_INFORMATION BasicInfo)
{
    ULONG NotifyFilter;

    DPRINT("FatSetBasicInformation()\n");

    ASSERT(NULL != FileObject);
    ASSERT(NULL != Fcb);
    ASSERT(NULL != DeviceExt);
    ASSERT(NULL != BasicInfo);
    /* Check volume label bit */
    ASSERT(0 == (*Fcb->Attributes & _A_VOLID));

    NotifyFilter = 0;

    if (BasicInfo->FileAttributes != 0) {
	UCHAR Attributes;

	Attributes = (BasicInfo->FileAttributes & (FILE_ATTRIBUTE_ARCHIVE |
						   FILE_ATTRIBUTE_SYSTEM |
						   FILE_ATTRIBUTE_HIDDEN |
						   FILE_ATTRIBUTE_DIRECTORY |
						   FILE_ATTRIBUTE_READONLY));

	if (FatFcbIsDirectory(Fcb)) {
	    if (BooleanFlagOn(BasicInfo->FileAttributes, FILE_ATTRIBUTE_TEMPORARY)) {
		DPRINT("Setting temporary attribute on a directory!\n");
		return STATUS_INVALID_PARAMETER;
	    }

	    Attributes |= FILE_ATTRIBUTE_DIRECTORY;
	} else {
	    if (BooleanFlagOn(BasicInfo->FileAttributes, FILE_ATTRIBUTE_DIRECTORY)) {
		DPRINT("Setting directory attribute on a file!\n");
		return STATUS_INVALID_PARAMETER;
	    }
	}

	if (Attributes != *Fcb->Attributes) {
	    *Fcb->Attributes = Attributes;
	    DPRINT("Setting attributes 0x%02x\n", *Fcb->Attributes);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}
    }

    if (FatVolumeIsFatX(DeviceExt)) {
	if (BasicInfo->CreationTime.QuadPart != 0
	    && BasicInfo->CreationTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt, &BasicInfo->CreationTime,
				       &Fcb->Entry.FatX.CreationDate,
				       &Fcb->Entry.FatX.CreationTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_CREATION;
	}

	if (BasicInfo->LastAccessTime.QuadPart != 0
	    && BasicInfo->LastAccessTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastAccessTime,
				       &Fcb->Entry.FatX.AccessDate,
				       &Fcb->Entry.FatX.AccessTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}

	if (BasicInfo->LastWriteTime.QuadPart != 0
	    && BasicInfo->LastWriteTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastWriteTime,
				       &Fcb->Entry.FatX.UpdateDate,
				       &Fcb->Entry.FatX.UpdateTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	}
    } else {
	if (BasicInfo->CreationTime.QuadPart != 0
	    && BasicInfo->CreationTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt, &BasicInfo->CreationTime,
				       &Fcb->Entry.Fat.CreationDate,
				       &Fcb->Entry.Fat.CreationTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_CREATION;
	}

	if (BasicInfo->LastAccessTime.QuadPart != 0
	    && BasicInfo->LastAccessTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastAccessTime,
				       &Fcb->Entry.Fat.AccessDate, NULL);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}

	if (BasicInfo->LastWriteTime.QuadPart != 0
	    && BasicInfo->LastWriteTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastWriteTime,
				       &Fcb->Entry.Fat.UpdateDate,
				       &Fcb->Entry.Fat.UpdateTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	}
    }

    FatUpdateEntry(DeviceExt, Fcb);

    if (NotifyFilter != 0) {
	FatReportChange(DeviceExt,
			Fcb, NotifyFilter, FILE_ACTION_MODIFIED);
    }

    return STATUS_SUCCESS;
}

NTSTATUS FatGetBasicInformation(PFILE_OBJECT FileObject,
				PFATFCB Fcb,
				PDEVICE_EXTENSION DeviceExt,
				PFILE_BASIC_INFORMATION BasicInfo,
				PULONG BufferLength)
{
    UNREFERENCED_PARAMETER(FileObject);

    DPRINT("FatGetBasicInformation()\n");

    if (*BufferLength < sizeof(FILE_BASIC_INFORMATION))
	return STATUS_BUFFER_OVERFLOW;

    RtlZeroMemory(BasicInfo, sizeof(FILE_BASIC_INFORMATION));

    if (FatVolumeIsFatX(DeviceExt)) {
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.FatX.CreationDate,
				   Fcb->Entry.FatX.CreationTime,
				   &BasicInfo->CreationTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.FatX.AccessDate,
				   Fcb->Entry.FatX.AccessTime,
				   &BasicInfo->LastAccessTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.FatX.UpdateDate,
				   Fcb->Entry.FatX.UpdateTime,
				   &BasicInfo->LastWriteTime);
	BasicInfo->ChangeTime = BasicInfo->LastWriteTime;
    } else {
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.Fat.CreationDate,
				   Fcb->Entry.Fat.CreationTime,
				   &BasicInfo->CreationTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.Fat.AccessDate,
				   0, &BasicInfo->LastAccessTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.Fat.UpdateDate,
				   Fcb->Entry.Fat.UpdateTime,
				   &BasicInfo->LastWriteTime);
	BasicInfo->ChangeTime = BasicInfo->LastWriteTime;
    }

    BasicInfo->FileAttributes = *Fcb->Attributes & 0x3f;
    /* Synthesize FILE_ATTRIBUTE_NORMAL */
    if (0 == (BasicInfo->FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
					   FILE_ATTRIBUTE_ARCHIVE |
					   FILE_ATTRIBUTE_SYSTEM |
					   FILE_ATTRIBUTE_HIDDEN |
					   FILE_ATTRIBUTE_READONLY))) {
	DPRINT("Synthesizing FILE_ATTRIBUTE_NORMAL\n");
	BasicInfo->FileAttributes |= FILE_ATTRIBUTE_NORMAL;
    }
    DPRINT("Getting attributes 0x%02x\n", BasicInfo->FileAttributes);

    *BufferLength -= sizeof(FILE_BASIC_INFORMATION);
    return STATUS_SUCCESS;
}


static NTSTATUS FatSetDispositionInformation(PFILE_OBJECT FileObject,
					     PFATFCB Fcb,
					     PDEVICE_EXTENSION DeviceExt,
					     PFILE_DISPOSITION_INFORMATION DispoInfo)
{
    DPRINT("FsdSetDispositionInformation(<%wZ>, Delete %u)\n",
	   &Fcb->PathNameU, DispoInfo->DeleteFile);

    ASSERT(DeviceExt != NULL);
    ASSERT(DeviceExt->FatInfo.BytesPerCluster != 0);
    ASSERT(Fcb != NULL);

    if (!DispoInfo->DeleteFile) {
	/* undelete the file */
	Fcb->Flags &= ~FCB_DELETE_PENDING;
	FileObject->DeletePending = FALSE;
	return STATUS_SUCCESS;
    }

    if (BooleanFlagOn(Fcb->Flags, FCB_DELETE_PENDING)) {
	/* stream already marked for deletion. just update the file object */
	FileObject->DeletePending = TRUE;
	return STATUS_SUCCESS;
    }

    if (FatFcbIsReadOnly(Fcb)) {
	return STATUS_CANNOT_DELETE;
    }

    if (FatFcbIsRoot(Fcb) || IsDotOrDotDot(&Fcb->LongNameU)) {
	/* we cannot delete a '.', '..' or the root directory */
	return STATUS_ACCESS_DENIED;
    }

#if 0
    if (!MmFlushImageSection(FileObject->SectionObjectPointer, MmFlushForDelete)) {
	/* can't delete a file if its mapped into a process */
	DPRINT("MmFlushImageSection returned FALSE\n");
	return STATUS_CANNOT_DELETE;
    }
#endif

    if (FatFcbIsDirectory(Fcb) && !FatIsDirectoryEmpty(DeviceExt, Fcb)) {
	/* can't delete a non-empty directory */

	return STATUS_DIRECTORY_NOT_EMPTY;
    }

    /* all good */
    Fcb->Flags |= FCB_DELETE_PENDING;
    FileObject->DeletePending = TRUE;

    return STATUS_SUCCESS;
}

static NTSTATUS FatPrepareTargetForRename(IN PDEVICE_EXTENSION DeviceExt,
					  IN PFATFCB *ParentFcb,
					  IN PUNICODE_STRING NewName,
					  IN BOOLEAN ReplaceIfExists,
					  IN PUNICODE_STRING ParentName,
					  OUT PBOOLEAN Deleted)
{
    NTSTATUS Status;
    PFATFCB TargetFcb;

    DPRINT("FatPrepareTargetForRename(%p, %p, %wZ, %d, %wZ)\n",
	   DeviceExt, ParentFcb, NewName, ReplaceIfExists, ParentName);

    *Deleted = FALSE;
    /* Try to open target */
    Status = FatGetFcbForFile(DeviceExt, ParentFcb, &TargetFcb, NewName);
    if (!NT_SUCCESS(Status)) {
	/* Target file does not exist. Return success if target directory exist,
	 * and failure if it doesn't. */
	return *ParentFcb ? STATUS_SUCCESS : Status;
    }

    DPRINT("Target file %wZ exists. FCB Flags %08x\n", NewName, TargetFcb->Flags);
    /* Check whether we are allowed to replace. */
    if (ReplaceIfExists) {
	/* If that's a directory or a read-only file, deny the replacement. */
	if (FatFcbIsDirectory(TargetFcb) || FatFcbIsReadOnly(TargetFcb)) {
	    DPRINT("And this is a readonly file!\n");
	    FatReleaseFcb(DeviceExt, *ParentFcb);
	    *ParentFcb = NULL;
	    FatReleaseFcb(DeviceExt, TargetFcb);
	    return STATUS_OBJECT_NAME_COLLISION;
	}

	/* If we still have a file object, close it. */
	if (TargetFcb->FileObject) {
	    TargetFcb->FileObject->DeletePending = TRUE;
	    FatCloseFile(DeviceExt, TargetFcb->FileObject);
	}

	/* If we are here, ensure the file isn't open by anyone! */
	if (TargetFcb->OpenHandleCount != 0) {
	    DPRINT("There are still open handles for this file.\n");
	    FatReleaseFcb(DeviceExt, *ParentFcb);
	    *ParentFcb = NULL;
	    FatReleaseFcb(DeviceExt, TargetFcb);
	    return STATUS_ACCESS_DENIED;
	}

	/* Effectively delete old file to allow renaming */
	DPRINT("Effectively deleting the file.\n");
	FatDelEntry(DeviceExt, TargetFcb, NULL);
	FatReleaseFcb(DeviceExt, TargetFcb);
	*Deleted = TRUE;
	return STATUS_SUCCESS;
    } else {
	FatReleaseFcb(DeviceExt, *ParentFcb);
	*ParentFcb = NULL;
	FatReleaseFcb(DeviceExt, TargetFcb);
	return STATUS_OBJECT_NAME_COLLISION;
    }
}

static BOOLEAN IsThereAChildOpened(PFATFCB FCB)
{
    PLIST_ENTRY Entry;
    PFATFCB VolFCB;

    for (Entry = FCB->ParentListHead.Flink; Entry != &FCB->ParentListHead;
	 Entry = Entry->Flink) {
	VolFCB = CONTAINING_RECORD(Entry, FATFCB, ParentListEntry);
	if (VolFCB->OpenHandleCount != 0) {
	    ASSERT(VolFCB->ParentFcb == FCB);
	    DPRINT1("At least one children file opened! %wZ (%u, %u)\n",
		    &VolFCB->PathNameU, VolFCB->RefCount,
		    VolFCB->OpenHandleCount);
	    return TRUE;
	}

	if (FatFcbIsDirectory(VolFCB)
	    && !IsListEmpty(&VolFCB->ParentListHead)) {
	    if (IsThereAChildOpened(VolFCB)) {
		return TRUE;
	    }
	}
    }

    return FALSE;
}

static VOID FatRenameChildFcb(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb)
{
    PLIST_ENTRY Entry;
    PFATFCB Child;

    if (IsListEmpty(&Fcb->ParentListHead))
	return;

    for (Entry = Fcb->ParentListHead.Flink; Entry != &Fcb->ParentListHead;
	 Entry = Entry->Flink) {
	NTSTATUS Status;

	Child = CONTAINING_RECORD(Entry, FATFCB, ParentListEntry);
	DPRINT("Found %wZ with still %u references (parent: %u)!\n",
	       &Child->PathNameU, Child->RefCount, Fcb->RefCount);

	Status = FatSetFcbNewDirName(DeviceExt, Child, Fcb);
	if (!NT_SUCCESS(Status))
	    continue;

	if (FatFcbIsDirectory(Child)) {
	    FatRenameChildFcb(DeviceExt, Child);
	}
    }
}

/*
 * FUNCTION: Set the file name information
 */
static NTSTATUS FatSetRenameInformation(PFILE_OBJECT FileObject,
					PFATFCB Fcb,
					PDEVICE_EXTENSION DeviceExt,
					PFILE_RENAME_INFORMATION RenameInfo,
					PFILE_OBJECT TargetFileObject)
{
    DPRINT("FatSetRenameInfo(%p, %p, %p, %p, %p)\n", FileObject, Fcb,
	   DeviceExt, RenameInfo, TargetFileObject);

    /* Disallow renaming root */
    if (FatFcbIsRoot(Fcb)) {
	return STATUS_INVALID_PARAMETER;
    }

    assert(Fcb->ParentFcb);
    UNICODE_STRING NewName;
    RtlInitEmptyUnicodeString(&NewName, NULL, 0);
    PFATFCB ParentFcb = NULL;

    /* Before constructing the target name string, do a sanity check.
     * This is alredy done on the server side, but we just want to be sure. */
    NTSTATUS Status;
    if (TargetFileObject->DeviceObject != FileObject->DeviceObject) {
	Status = STATUS_NOT_SAME_DEVICE;
	goto Cleanup;
    }

    NewName.Length = 0;
    NewName.MaximumLength = TargetFileObject->FileName.Length +
	((PFATFCB)TargetFileObject->FsContext)->PathNameU.Length + sizeof(WCHAR);
    NewName.Buffer = ExAllocatePoolWithTag(NewName.MaximumLength, TAG_NAME);
    if (NewName.Buffer == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto Cleanup;
    }

    RtlCopyUnicodeString(&NewName, &((PFATFCB)TargetFileObject->FsContext)->PathNameU);
    /* If \, it's already backslash terminated, don't add it */
    if (!FatFcbIsRoot(TargetFileObject->FsContext)) {
	NewName.Buffer[NewName.Length / sizeof(WCHAR)] = L'\\';
	NewName.Length += sizeof(WCHAR);
    }
    RtlAppendUnicodeStringToString(&NewName, &TargetFileObject->FileName);

    /* Explode our paths to get path & filename */
    UNICODE_STRING SourcePath, SourceFile;
    FatSplitPathName(&Fcb->PathNameU, &SourcePath, &SourceFile);
    DPRINT("Old dir: %wZ, Old file: %wZ\n", &SourcePath, &SourceFile);
    UNICODE_STRING NewPath, NewFile;
    FatSplitPathName(&NewName, &NewPath, &NewFile);
    DPRINT("New dir: %wZ, New file: %wZ\n", &NewPath, &NewFile);

    if (IsDotOrDotDot(&NewFile)) {
	Status = STATUS_OBJECT_NAME_INVALID;
	goto Cleanup;
    }

    UNUSED ULONG OldReferences = Fcb->ParentFcb->RefCount;
    if (FatFcbIsDirectory(Fcb) && !IsListEmpty(&Fcb->ParentListHead) &&
	IsThereAChildOpened(Fcb)) {
	Status = STATUS_ACCESS_DENIED;
	ASSERT(OldReferences == Fcb->ParentFcb->RefCount);
	goto Cleanup;
    }

    ULONG DeletedTargetNotifyFlags =  FILE_NOTIFY_CHANGE_ATTRIBUTES |
	FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE |
	FILE_NOTIFY_CHANGE_LAST_ACCESS | FILE_NOTIFY_CHANGE_CREATION |
	FILE_NOTIFY_CHANGE_EA;
    ULONG NotifyFlag = FatFcbIsDirectory(Fcb) ?
	FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;
    /* Are we working in place? */
    if (FsRtlAreNamesEqual(&SourcePath, &NewPath, TRUE, NULL)) {
	if (FsRtlAreNamesEqual(&SourceFile, &NewFile, FALSE, NULL)) {
	    Status = STATUS_SUCCESS;
	    ASSERT(OldReferences == Fcb->ParentFcb->RefCount);
	    goto Cleanup;
	}

	if (FsRtlAreNamesEqual(&SourceFile, &NewFile, TRUE, NULL)) {
	    FatReportChange(DeviceExt, Fcb, NotifyFlag, FILE_ACTION_RENAMED_OLD_NAME);
	    Status = FatRenameEntry(DeviceExt, Fcb, &NewFile, TRUE);
	    if (NT_SUCCESS(Status)) {
		FatReportChange(DeviceExt, Fcb, NotifyFlag, FILE_ACTION_RENAMED_NEW_NAME);
	    }
	} else {
	    /* Try to find target */
	    ParentFcb = Fcb->ParentFcb;
	    FatGrabFcb(DeviceExt, ParentFcb);
	    BOOLEAN DeletedTarget;
	    Status = FatPrepareTargetForRename(DeviceExt, &ParentFcb, &NewFile,
					       RenameInfo->ReplaceIfExists,
					       &NewPath, &DeletedTarget);
	    if (!NT_SUCCESS(Status)) {
		ASSERT(OldReferences == Fcb->ParentFcb->RefCount - 1);
		ASSERT(OldReferences == ParentFcb->RefCount - 1);
		goto Cleanup;
	    }

	    FatReportChange(DeviceExt, Fcb, NotifyFlag,
			    DeletedTarget ? FILE_ACTION_REMOVED : FILE_ACTION_RENAMED_OLD_NAME);
	    Status = FatRenameEntry(DeviceExt, Fcb, &NewFile, FALSE);
	    if (NT_SUCCESS(Status)) {
		if (DeletedTarget) {
		    FatReportChange(DeviceExt, Fcb, DeletedTargetNotifyFlags,
				    FILE_ACTION_MODIFIED);
		} else {
		    FatReportChange(DeviceExt, Fcb, NotifyFlag, FILE_ACTION_RENAMED_NEW_NAME);
		}
	    }
	}

	ASSERT(OldReferences == Fcb->ParentFcb->RefCount - 1);	// extra grab
	ASSERT(OldReferences == ParentFcb->RefCount - 1);	// extra grab
    } else {
	/* Try to find target */
	ParentFcb = NULL;
	UNUSED PFATFCB OldParent = Fcb->ParentFcb;
	BOOLEAN DeletedTarget;
	Status = FatPrepareTargetForRename(DeviceExt, &ParentFcb, &NewName,
					   RenameInfo->ReplaceIfExists,
					   &NewPath, &DeletedTarget);
	if (!NT_SUCCESS(Status)) {
	    ASSERT(OldReferences == Fcb->ParentFcb->RefCount);
	    goto Cleanup;
	}

	UNUSED ULONG NewReferences = ParentFcb->RefCount;

	FatReportChange(DeviceExt, Fcb, NotifyFlag, FILE_ACTION_REMOVED);
	Status = FatMoveEntry(DeviceExt, Fcb, &NewFile, ParentFcb);
	if (NT_SUCCESS(Status)) {
	    if (DeletedTarget) {
		FatReportChange(DeviceExt, Fcb, DeletedTargetNotifyFlags,
				FILE_ACTION_MODIFIED);
	    } else {
		FatReportChange(DeviceExt, Fcb, NotifyFlag, FILE_ACTION_ADDED);
	    }
	}
	ASSERT(OldReferences == OldParent->RefCount + 1);	// removed file
	ASSERT(NewReferences == ParentFcb->RefCount - 1);	// new file
    }

    if (NT_SUCCESS(Status) && FatFcbIsDirectory(Fcb)) {
	FatRenameChildFcb(DeviceExt, Fcb);
    }
Cleanup:
    if (ParentFcb != NULL)
	FatReleaseFcb(DeviceExt, ParentFcb);
    if (NewName.Buffer != NULL)
	ExFreePoolWithTag(NewName.Buffer, TAG_NAME);

    return Status;
}

/*
 * FUNCTION: Retrieve the file name information
 */
static NTSTATUS FatGetNameInformation(IN PFILE_OBJECT FileObject,
				      IN PFATFCB Fcb,
				      IN PDEVICE_EXTENSION DeviceExt,
				      OUT PFILE_NAME_INFORMATION NameInfo,
				      IN OUT PULONG BufferLength)
{
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(DeviceExt);

    ASSERT(NameInfo != NULL);
    ASSERT(Fcb != NULL);

    /* If buffer can't hold at least the file name length, bail out */
    if (*BufferLength < (ULONG)FIELD_OFFSET(FILE_NAME_INFORMATION, FileName[0]))
	return STATUS_BUFFER_OVERFLOW;

    /* Save file name length, and as much file len, as buffer length allows */
    NameInfo->FileNameLength = Fcb->PathNameU.Length;

    /* Calculate amount of bytes to copy not to overflow the buffer */
    ULONG BytesToCopy = min(Fcb->PathNameU.Length,
			    *BufferLength - FIELD_OFFSET(FILE_NAME_INFORMATION, FileName[0]));

    /* Fill in the bytes */
    RtlCopyMemory(NameInfo->FileName, Fcb->PathNameU.Buffer, BytesToCopy);

    /* Check if we could write more but are not able to */
    if (*BufferLength < Fcb->PathNameU.Length + (ULONG)FIELD_OFFSET(FILE_NAME_INFORMATION,
								    FileName[0])) {
	/* Return number of bytes written */
	*BufferLength -= FIELD_OFFSET(FILE_NAME_INFORMATION, FileName[0]) + BytesToCopy;
	return STATUS_BUFFER_OVERFLOW;
    }

    /* We filled up as many bytes, as needed */
    *BufferLength -= FIELD_OFFSET(FILE_NAME_INFORMATION, FileName[0]) + Fcb->PathNameU.Length;

    return STATUS_SUCCESS;
}

static NTSTATUS FatGetInternalInformation(IN PFATFCB Fcb,
					  IN PDEVICE_EXTENSION DeviceExt,
					  OUT PFILE_INTERNAL_INFORMATION InternalInfo,
					  IN OUT PULONG BufferLength)
{
    ASSERT(InternalInfo);
    ASSERT(Fcb);

    if (*BufferLength < sizeof(FILE_INTERNAL_INFORMATION))
	return STATUS_BUFFER_OVERFLOW;

    InternalInfo->IndexNumber.QuadPart =
	(LONGLONG)FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry) *
	DeviceExt->FatInfo.BytesPerCluster;

    *BufferLength -= sizeof(FILE_INTERNAL_INFORMATION);
    return STATUS_SUCCESS;
}


/*
 * FUNCTION: Retrieve the file network open information
 */
static NTSTATUS FatGetNetworkOpenInformation(IN PFATFCB Fcb,
					     IN PDEVICE_EXTENSION DeviceExt,
					     OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInfo,
					     IN OUT PULONG BufferLength)
{
    ASSERT(NetworkInfo);
    ASSERT(Fcb);

    if (*BufferLength < sizeof(FILE_NETWORK_OPEN_INFORMATION))
	return (STATUS_BUFFER_OVERFLOW);

    if (FatVolumeIsFatX(DeviceExt)) {
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.FatX.CreationDate,
				   Fcb->Entry.FatX.CreationTime,
				   &NetworkInfo->CreationTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.FatX.AccessDate,
				   Fcb->Entry.FatX.AccessTime,
				   &NetworkInfo->LastAccessTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.FatX.UpdateDate,
				   Fcb->Entry.FatX.UpdateTime,
				   &NetworkInfo->LastWriteTime);
	NetworkInfo->ChangeTime.QuadPart = NetworkInfo->LastWriteTime.QuadPart;
    } else {
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.Fat.CreationDate,
				   Fcb->Entry.Fat.CreationTime,
				   &NetworkInfo->CreationTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.Fat.AccessDate,
				   0, &NetworkInfo->LastAccessTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   Fcb->Entry.Fat.UpdateDate,
				   Fcb->Entry.Fat.UpdateTime,
				   &NetworkInfo->LastWriteTime);
	NetworkInfo->ChangeTime.QuadPart = NetworkInfo->LastWriteTime.QuadPart;
    }

    if (FatFcbIsDirectory(Fcb)) {
	NetworkInfo->EndOfFile.QuadPart = 0L;
	NetworkInfo->AllocationSize.QuadPart = 0L;
    } else {
	NetworkInfo->AllocationSize = Fcb->Base.FileSizes.AllocationSize;
	NetworkInfo->EndOfFile = Fcb->Base.FileSizes.FileSize;
    }

    NetworkInfo->FileAttributes = *Fcb->Attributes & 0x3f;
    /* Synthesize FILE_ATTRIBUTE_NORMAL */
    if (!(NetworkInfo->FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
					 FILE_ATTRIBUTE_ARCHIVE |
					 FILE_ATTRIBUTE_SYSTEM |
					 FILE_ATTRIBUTE_HIDDEN |
					 FILE_ATTRIBUTE_READONLY))) {
	DPRINT("Synthesizing FILE_ATTRIBUTE_NORMAL\n");
	NetworkInfo->FileAttributes |= FILE_ATTRIBUTE_NORMAL;
    }

    *BufferLength -= sizeof(FILE_NETWORK_OPEN_INFORMATION);
    return STATUS_SUCCESS;
}


static NTSTATUS FatGetEaInformation(IN PFILE_OBJECT FileObject,
				    IN PFATFCB Fcb,
				    IN PDEVICE_EXTENSION DeviceExt,
				    OUT PFILE_EA_INFORMATION Info,
				    IN OUT PULONG BufferLength)
{
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Fcb);

    Info->EaSize = 0;
    *BufferLength -= sizeof(*Info);
    if (DeviceExt->FatInfo.FatType == FAT12 || DeviceExt->FatInfo.FatType == FAT16) {
	/* FIXME */
	DPRINT1("FAT: FileEaInformation not implemented!\n");
    }
    return STATUS_SUCCESS;
}


/*
 * FUNCTION: Retrieve the all file information
 */
static NTSTATUS FatGetAllInformation(IN PFILE_OBJECT FileObject,
				     IN PFATFCB Fcb,
				     IN PDEVICE_EXTENSION DeviceExt,
				     OUT PFILE_ALL_INFORMATION Info,
				     IN OUT PULONG BufferLength)
{
    NTSTATUS Status;

    ASSERT(Info);
    ASSERT(Fcb);

    if (*BufferLength < FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation.FileName))
	return STATUS_BUFFER_OVERFLOW;

    *BufferLength -= sizeof(FILE_ACCESS_INFORMATION) + sizeof(FILE_MODE_INFORMATION) +
	sizeof(FILE_ALIGNMENT_INFORMATION);

    /* Basic Information */
    Status = FatGetBasicInformation(FileObject, Fcb, DeviceExt,
				    &Info->BasicInformation, BufferLength);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Standard Information */
    Status = FatGetStandardInformation(Fcb, &Info->StandardInformation,
				       BufferLength);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Internal Information */
    Status = FatGetInternalInformation(Fcb, DeviceExt,
				       &Info->InternalInformation,
				       BufferLength);
    if (!NT_SUCCESS(Status))
	return Status;
    /* EA Information */
    Status = FatGetEaInformation(FileObject, Fcb, DeviceExt,
				 &Info->EaInformation, BufferLength);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Name Information */
    Status = FatGetNameInformation(FileObject, Fcb, DeviceExt,
				   &Info->NameInformation, BufferLength);

    return Status;
}

static VOID UpdateFileSize(IN PFILE_OBJECT FileObject,
			   IN PFATFCB Fcb,
			   IN ULONG FileSize,
			   IN ULONG ClusterSize,
			   IN BOOLEAN IsFatX)
{
    if (FileSize > 0) {
	Fcb->Base.FileSizes.AllocationSize.QuadPart = ROUND_UP_64(FileSize, ClusterSize);
    } else {
	Fcb->Base.FileSizes.AllocationSize.QuadPart = (LONGLONG) 0;
    }
    if (!FatFcbIsDirectory(Fcb)) {
	if (IsFatX)
	    Fcb->Entry.FatX.FileSize = FileSize;
	else
	    Fcb->Entry.Fat.FileSize = FileSize;
    }
    Fcb->Base.FileSizes.FileSize.QuadPart = FileSize;
    Fcb->Base.FileSizes.ValidDataLength.QuadPart = FileSize;

    CcSetFileSizes(FileObject, &Fcb->Base.FileSizes);
}

NTSTATUS FatSetFileSizeInformation(IN PFILE_OBJECT FileObject,
				   IN PFATFCB Fcb,
				   IN PDEVICE_EXTENSION DeviceExt,
				   IN PLARGE_INTEGER FileSize)
{
    BOOLEAN IsFatX = FatVolumeIsFatX(DeviceExt);
    ULONG OldSize = IsFatX ? Fcb->Entry.FatX.FileSize : Fcb->Entry.Fat.FileSize;
    ULONG NewSize = FileSize->LowPart;
    ULONG ClusterSize = DeviceExt->FatInfo.BytesPerCluster;
    LARGE_INTEGER NewAllocSize = {
	.QuadPart = ROUND_UP_64(FileSize->QuadPart, ClusterSize)
    };

    DPRINT("FatSetFileSizeInformation(File %wZ, FileSize 0x%x_%x)\n",
	   &Fcb->PathNameU, FileSize->HighPart, FileSize->LowPart);

    if (NewAllocSize.HighPart > 0) {
	return STATUS_END_OF_FILE;
    }

    if (OldSize == NewSize) {
	return STATUS_SUCCESS;
    }

    ULONG FirstCluster = FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry);

    if (NewAllocSize.LowPart == Fcb->Base.FileSizes.AllocationSize.LowPart) {
	/* Allocation size is not changed. Simply update the file size. */
	UpdateFileSize(FileObject, Fcb, NewSize, ClusterSize, IsFatX);
    } else if (NewAllocSize.LowPart > Fcb->Base.FileSizes.AllocationSize.LowPart) {
	/* New allocation size is larger, so we need to find more space. */
	NTSTATUS Status;
	if (FirstCluster == 0) {
	    Status = NextCluster(DeviceExt, FirstCluster, &FirstCluster, TRUE);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("NextCluster failed. Status = %x\n", Status);
		return Status;
	    }

	    if (FirstCluster == 0xffffffff) {
		return STATUS_DISK_FULL;
	    }

	    ULONG Cluster, NCluster;
	    Status = OffsetToCluster(DeviceExt, FirstCluster,
				     ROUND_DOWN(NewSize - 1, ClusterSize),
				     &NCluster, TRUE);
	    if (NCluster == 0xffffffff || !NT_SUCCESS(Status)) {
		/* disk is full */
		NCluster = Cluster = FirstCluster;
		Status = STATUS_SUCCESS;
		while (NT_SUCCESS(Status) && Cluster != 0xffffffff && Cluster > 1) {
		    Status = NextCluster(DeviceExt, FirstCluster, &NCluster, FALSE);
		    WriteCluster(DeviceExt, Cluster, 0);
		    Cluster = NCluster;
		}
		return STATUS_DISK_FULL;
	    }

	    if (IsFatX) {
		Fcb->Entry.FatX.FirstCluster = FirstCluster;
	    } else {
		if (DeviceExt->FatInfo.FatType == FAT32) {
		    Fcb->Entry.Fat.FirstCluster = (USHORT)(FirstCluster & 0x0000FFFF);
		    Fcb->Entry.Fat.FirstClusterHigh = FirstCluster >> 16;
		} else {
		    ASSERT((FirstCluster >> 16) == 0);
		    Fcb->Entry.Fat.FirstCluster = (USHORT)(FirstCluster & 0x0000FFFF);
		}
	    }
	} else {
	    ULONG Cluster;
	    ULONG OldOffset = Fcb->Base.FileSizes.AllocationSize.LowPart - ClusterSize;
	    Status = OffsetToCluster(DeviceExt, FirstCluster, OldOffset, &Cluster, FALSE);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }

	    /* FIXME: Check status */
	    /* Cluster points now to the last cluster within the chain */
	    ULONG NCluster;
	    Status = OffsetToCluster(DeviceExt, Cluster,
				     ROUND_DOWN(NewSize - 1, ClusterSize) - OldOffset,
				     &NCluster, TRUE);
	    if (NCluster == 0xffffffff || !NT_SUCCESS(Status)) {
		/* disk is full */
		NCluster = Cluster;
		Status = NextCluster(DeviceExt, FirstCluster, &NCluster, FALSE);
		WriteCluster(DeviceExt, Cluster, 0xffffffff);
		Cluster = NCluster;
		while (NT_SUCCESS(Status) && Cluster != 0xffffffff && Cluster > 1) {
		    Status = NextCluster(DeviceExt, FirstCluster, &NCluster, FALSE);
		    WriteCluster(DeviceExt, Cluster, 0);
		    Cluster = NCluster;
		}
		return STATUS_DISK_FULL;
	    }
	}
	UpdateFileSize(FileObject, Fcb, NewSize, ClusterSize, IsFatX);
    } else {
	/* New allocation size is smaller, so we need to shrink the file. */
	UpdateFileSize(FileObject, Fcb, NewSize, ClusterSize, IsFatX);
	NTSTATUS Status;
	ULONG Cluster, NCluster;
	if (NewSize > 0) {
	    Status = OffsetToCluster(DeviceExt, FirstCluster,
				     ROUND_DOWN(NewSize - 1, ClusterSize),
				     &Cluster, FALSE);

	    NCluster = Cluster;
	    Status = NextCluster(DeviceExt, FirstCluster, &NCluster, FALSE);
	    WriteCluster(DeviceExt, Cluster, 0xffffffff);
	    Cluster = NCluster;
	} else {
	    if (IsFatX) {
		Fcb->Entry.FatX.FirstCluster = 0;
	    } else {
		Fcb->Entry.Fat.FirstCluster = 0;
		if (DeviceExt->FatInfo.FatType == FAT32) {
		    Fcb->Entry.Fat.FirstClusterHigh = 0;
		}
	    }

	    NCluster = Cluster = FirstCluster;
	    Status = STATUS_SUCCESS;
	}

	while (NT_SUCCESS(Status) && 0xffffffff != Cluster && Cluster > 1) {
	    Status = NextCluster(DeviceExt, FirstCluster, &NCluster, FALSE);
	    WriteCluster(DeviceExt, Cluster, 0);
	    Cluster = NCluster;
	}

	if (DeviceExt->FatInfo.FatType == FAT32) {
	    Fat32UpdateFreeClustersCount(DeviceExt);
	}
    }

    /* Update the on-disk directory entry */
    Fcb->Flags |= FCB_IS_DIRTY;
    if (NewAllocSize.LowPart != Fcb->Base.FileSizes.AllocationSize.LowPart) {
	FatUpdateEntry(DeviceExt, Fcb);

	FatReportChange(DeviceExt, Fcb, FILE_NOTIFY_CHANGE_SIZE,
			FILE_ACTION_MODIFIED);
    }
    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Retrieve the specified file information
 */
NTSTATUS FatQueryInformation(PFAT_IRP_CONTEXT IrpContext)
{
    ASSERT(IrpContext);

    FILE_INFORMATION_CLASS Info = IrpContext->Stack->Parameters.QueryFile.FileInformationClass;
    PFATFCB Fcb = IrpContext->FileObject->FsContext;

    DPRINT("FatQueryInformation is called for '%s'\n",
	   (Info >= FileMaximumInformation - 1) ? "????" : FileInformationClassNames[Info]);

    if (Fcb == NULL) {
	DPRINT1("IRP_MJ_QUERY_INFORMATION without FCB!\n");
	assert(FALSE);
	IrpContext->Irp->IoStatus.Information = 0;
	return STATUS_INVALID_PARAMETER;
    }

    PVOID SystemBuffer = IrpContext->Irp->SystemBuffer;
    ULONG BufferLength = IrpContext->Stack->Parameters.QueryFile.Length;

    NTSTATUS Status = STATUS_SUCCESS;
    switch (Info) {
    case FileStandardInformation:
	Status = FatGetStandardInformation(Fcb, SystemBuffer, &BufferLength);
	break;

    case FilePositionInformation:
	/* This is handled on the server-side. */
	Status = STATUS_NOT_SUPPORTED;
	break;

    case FileBasicInformation:
	Status = FatGetBasicInformation(IrpContext->FileObject, Fcb,
					IrpContext->DeviceExt,
					SystemBuffer, &BufferLength);
	break;

    case FileNameInformation:
	Status = FatGetNameInformation(IrpContext->FileObject, Fcb,
				       IrpContext->DeviceExt,
				       SystemBuffer, &BufferLength);
	break;

    case FileInternalInformation:
	Status = FatGetInternalInformation(Fcb,IrpContext->DeviceExt,
					   SystemBuffer, &BufferLength);
	break;

    case FileNetworkOpenInformation:
	Status = FatGetNetworkOpenInformation(Fcb, IrpContext->DeviceExt,
					      SystemBuffer, &BufferLength);
	break;

    case FileAllInformation:
	Status = FatGetAllInformation(IrpContext->FileObject, Fcb,
				      IrpContext->DeviceExt,
				      SystemBuffer, &BufferLength);
	break;

    case FileEaInformation:
	Status = FatGetEaInformation(IrpContext->FileObject, Fcb,
				     IrpContext->DeviceExt,
				     SystemBuffer, &BufferLength);
	break;

    case FileAlternateNameInformation:
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    default:
	Status = STATUS_INVALID_PARAMETER;
    }

    ULONG Information = 0;
    if (NT_SUCCESS(Status) || Status == STATUS_BUFFER_OVERFLOW) {
	Information = IrpContext->Stack->Parameters.QueryFile.Length - BufferLength;
    }

    IrpContext->Irp->IoStatus.Information = Information;
    return Status;
}

/*
 * FUNCTION: Retrieve the specified file information
 */
NTSTATUS FatSetInformation(PFAT_IRP_CONTEXT IrpContext)
{
    ASSERT(IrpContext);
    DPRINT("FatSetInformation(IrpContext %p)\n", IrpContext);

    FILE_INFORMATION_CLASS Info = IrpContext->Stack->Parameters.SetFile.FileInformationClass;
    PFILE_OBJECT FileObj = IrpContext->FileObject;
    PFATFCB Fcb = (PFATFCB)IrpContext->FileObject->FsContext;
    PVOID SystemBuffer = IrpContext->Irp->SystemBuffer;

    DPRINT("FatSetInformation is called for '%s' (%d)\n",
	   (Info >= (FileMaximumInformation - 1)) ? "????" : FileInformationClassNames[Info],
	   Info);

    if (Fcb == NULL) {
	DPRINT1("IRP_MJ_SET_INFORMATION without FCB!\n");
	assert(FALSE);
	IrpContext->Irp->IoStatus.Information = 0;
	return STATUS_INVALID_PARAMETER;
    }

    PDEVICE_EXTENSION DevExt = IrpContext->DeviceExt;
    NTSTATUS Status = STATUS_SUCCESS;

    switch (Info) {
    case FilePositionInformation:
	/* This is handled on the server-side. */
	Status = STATUS_NOT_SUPPORTED;
	break;

    case FileDispositionInformation:
	Status = FatSetDispositionInformation(FileObj, Fcb, DevExt, SystemBuffer);
	break;

    case FileAllocationInformation:
    case FileEndOfFileInformation:
	Status = FatSetFileSizeInformation(FileObj, Fcb, DevExt,
					   (PLARGE_INTEGER)SystemBuffer);
	break;

    case FileBasicInformation:
	Status = FatSetBasicInformation(FileObj, Fcb, DevExt, SystemBuffer);
	break;

    case FileRenameInformation:
	Status = FatSetRenameInformation(FileObj, Fcb, DevExt, SystemBuffer,
					 IrpContext->Stack->Parameters.SetFile.FileObject);
	break;

    default:
	Status = STATUS_NOT_SUPPORTED;
    }

    IrpContext->Irp->IoStatus.Information = 0;
    return Status;
}
