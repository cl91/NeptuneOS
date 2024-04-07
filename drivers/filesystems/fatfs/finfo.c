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

#define NASSERTS_RENAME

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
NTSTATUS FatGetStandardInformation(PFATFCB FCB,
				   PFILE_STANDARD_INFORMATION StandardInfo,
				   PULONG BufferLength)
{
    if (*BufferLength < sizeof(FILE_STANDARD_INFORMATION))
	return STATUS_BUFFER_OVERFLOW;

    /* PRECONDITION */
    ASSERT(StandardInfo != NULL);
    ASSERT(FCB != NULL);

    if (FatFcbIsDirectory(FCB)) {
	StandardInfo->AllocationSize.QuadPart = 0;
	StandardInfo->EndOfFile.QuadPart = 0;
	StandardInfo->Directory = TRUE;
    } else {
	StandardInfo->AllocationSize = FCB->Base.FileSizes.AllocationSize;
	StandardInfo->EndOfFile = FCB->Base.FileSizes.FileSize;
	StandardInfo->Directory = FALSE;
    }
    StandardInfo->NumberOfLinks = 1;
    StandardInfo->DeletePending = BooleanFlagOn(FCB->Flags, FCB_DELETE_PENDING);

    *BufferLength -= sizeof(FILE_STANDARD_INFORMATION);
    return STATUS_SUCCESS;
}

static NTSTATUS FatSetPositionInformation(PFILE_OBJECT FileObject,
					  PFILE_POSITION_INFORMATION PositionInfo)
{
    DPRINT("FsdSetPositionInformation()\n");

    DPRINT("PositionInfo %p\n", PositionInfo);
    /* TODO: This should be handled on server side. */
    /* DPRINT("Setting position %u\n", */
    /* 	   PositionInfo->CurrentByteOffset.LowPart); */

    /* FileObject->CurrentByteOffset.QuadPart = PositionInfo->CurrentByteOffset.QuadPart; */

    return STATUS_SUCCESS;
}

static NTSTATUS FatGetPositionInformation(PFILE_OBJECT FileObject,
					  PFATFCB FCB,
					  PDEVICE_EXTENSION DeviceExt,
					  PFILE_POSITION_INFORMATION PositionInfo,
					  PULONG BufferLength)
{
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(FCB);
    UNREFERENCED_PARAMETER(DeviceExt);

    DPRINT("FatGetPositionInformation()\n");

    if (*BufferLength < sizeof(FILE_POSITION_INFORMATION))
	return STATUS_BUFFER_OVERFLOW;

    /* TODO: This should be handled on server side. */
    /* PositionInfo->CurrentByteOffset.QuadPart = FileObject->CurrentByteOffset.QuadPart; */

    /* DPRINT("Getting position %I64x\n", */
    /* 	   PositionInfo->CurrentByteOffset.QuadPart); */

    *BufferLength -= sizeof(FILE_POSITION_INFORMATION);
    return STATUS_SUCCESS;
}

static NTSTATUS FatSetBasicInformation(PFILE_OBJECT FileObject,
				       PFATFCB FCB,
				       PDEVICE_EXTENSION DeviceExt,
				       PFILE_BASIC_INFORMATION BasicInfo)
{
    ULONG NotifyFilter;

    DPRINT("FatSetBasicInformation()\n");

    ASSERT(NULL != FileObject);
    ASSERT(NULL != FCB);
    ASSERT(NULL != DeviceExt);
    ASSERT(NULL != BasicInfo);
    /* Check volume label bit */
    ASSERT(0 == (*FCB->Attributes & _A_VOLID));

    NotifyFilter = 0;

    if (BasicInfo->FileAttributes != 0) {
	UCHAR Attributes;

	Attributes = (BasicInfo->FileAttributes & (FILE_ATTRIBUTE_ARCHIVE |
						   FILE_ATTRIBUTE_SYSTEM |
						   FILE_ATTRIBUTE_HIDDEN |
						   FILE_ATTRIBUTE_DIRECTORY |
						   FILE_ATTRIBUTE_READONLY));

	if (FatFcbIsDirectory(FCB)) {
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

	if (Attributes != *FCB->Attributes) {
	    *FCB->Attributes = Attributes;
	    DPRINT("Setting attributes 0x%02x\n", *FCB->Attributes);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}
    }

    if (FatVolumeIsFatX(DeviceExt)) {
	if (BasicInfo->CreationTime.QuadPart != 0
	    && BasicInfo->CreationTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt, &BasicInfo->CreationTime,
				       &FCB->Entry.FatX.CreationDate,
				       &FCB->Entry.FatX.CreationTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_CREATION;
	}

	if (BasicInfo->LastAccessTime.QuadPart != 0
	    && BasicInfo->LastAccessTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastAccessTime,
				       &FCB->Entry.FatX.AccessDate,
				       &FCB->Entry.FatX.AccessTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}

	if (BasicInfo->LastWriteTime.QuadPart != 0
	    && BasicInfo->LastWriteTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastWriteTime,
				       &FCB->Entry.FatX.UpdateDate,
				       &FCB->Entry.FatX.UpdateTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	}
    } else {
	if (BasicInfo->CreationTime.QuadPart != 0
	    && BasicInfo->CreationTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt, &BasicInfo->CreationTime,
				       &FCB->Entry.Fat.CreationDate,
				       &FCB->Entry.Fat.CreationTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_CREATION;
	}

	if (BasicInfo->LastAccessTime.QuadPart != 0
	    && BasicInfo->LastAccessTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastAccessTime,
				       &FCB->Entry.Fat.AccessDate, NULL);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}

	if (BasicInfo->LastWriteTime.QuadPart != 0
	    && BasicInfo->LastWriteTime.QuadPart != -1) {
	    FsdSystemTimeToDosDateTime(DeviceExt,
				       &BasicInfo->LastWriteTime,
				       &FCB->Entry.Fat.UpdateDate,
				       &FCB->Entry.Fat.UpdateTime);
	    NotifyFilter |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	}
    }

    FatUpdateEntry(DeviceExt, FCB);

    if (NotifyFilter != 0) {
	FatReportChange(DeviceExt,
			FCB, NotifyFilter, FILE_ACTION_MODIFIED);
    }

    return STATUS_SUCCESS;
}

NTSTATUS FatGetBasicInformation(PFILE_OBJECT FileObject,
				PFATFCB FCB,
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
				   FCB->Entry.FatX.CreationDate,
				   FCB->Entry.FatX.CreationTime,
				   &BasicInfo->CreationTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   FCB->Entry.FatX.AccessDate,
				   FCB->Entry.FatX.AccessTime,
				   &BasicInfo->LastAccessTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   FCB->Entry.FatX.UpdateDate,
				   FCB->Entry.FatX.UpdateTime,
				   &BasicInfo->LastWriteTime);
	BasicInfo->ChangeTime = BasicInfo->LastWriteTime;
    } else {
	FsdDosDateTimeToSystemTime(DeviceExt,
				   FCB->Entry.Fat.CreationDate,
				   FCB->Entry.Fat.CreationTime,
				   &BasicInfo->CreationTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   FCB->Entry.Fat.AccessDate,
				   0, &BasicInfo->LastAccessTime);
	FsdDosDateTimeToSystemTime(DeviceExt,
				   FCB->Entry.Fat.UpdateDate,
				   FCB->Entry.Fat.UpdateTime,
				   &BasicInfo->LastWriteTime);
	BasicInfo->ChangeTime = BasicInfo->LastWriteTime;
    }

    BasicInfo->FileAttributes = *FCB->Attributes & 0x3f;
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
					     PFATFCB FCB,
					     PDEVICE_EXTENSION DeviceExt,
					     PFILE_DISPOSITION_INFORMATION DispoInfo)
{
    DPRINT("FsdSetDispositionInformation(<%wZ>, Delete %u)\n",
	   &FCB->PathNameU, DispoInfo->DeleteFile);

    ASSERT(DeviceExt != NULL);
    ASSERT(DeviceExt->FatInfo.BytesPerCluster != 0);
    ASSERT(FCB != NULL);

    if (!DispoInfo->DeleteFile) {
	/* undelete the file */
	FCB->Flags &= ~FCB_DELETE_PENDING;
	FileObject->DeletePending = FALSE;
	return STATUS_SUCCESS;
    }

    if (BooleanFlagOn(FCB->Flags, FCB_DELETE_PENDING)) {
	/* stream already marked for deletion. just update the file object */
	FileObject->DeletePending = TRUE;
	return STATUS_SUCCESS;
    }

    if (FatFcbIsReadOnly(FCB)) {
	return STATUS_CANNOT_DELETE;
    }

    if (FatFcbIsRoot(FCB) || IsDotOrDotDot(&FCB->LongNameU)) {
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

    if (FatFcbIsDirectory(FCB) && !FatIsDirectoryEmpty(DeviceExt, FCB)) {
	/* can't delete a non-empty directory */

	return STATUS_DIRECTORY_NOT_EMPTY;
    }

    /* all good */
    FCB->Flags |= FCB_DELETE_PENDING;
    FileObject->DeletePending = TRUE;

    return STATUS_SUCCESS;
}

static NTSTATUS FatPrepareTargetForRename(IN PDEVICE_EXTENSION DeviceExt,
					  IN PFATFCB *ParentFCB,
					  IN PUNICODE_STRING NewName,
					  IN BOOLEAN ReplaceIfExists,
					  IN PUNICODE_STRING ParentName,
					  OUT PBOOLEAN Deleted)
{
    NTSTATUS Status;
    PFATFCB TargetFcb;

    DPRINT("FatPrepareTargetForRename(%p, %p, %wZ, %d, %wZ)\n",
	   DeviceExt, ParentFCB, NewName, ReplaceIfExists, ParentName);

    *Deleted = FALSE;
    /* Try to open target */
    Status = FatGetFcbForFile(DeviceExt, ParentFCB, &TargetFcb, NewName);
    /* If it exists */
    if (NT_SUCCESS(Status)) {
	DPRINT("Target file %wZ exists. FCB Flags %08x\n", NewName,
	       TargetFcb->Flags);
	/* Check whether we are allowed to replace */
	if (ReplaceIfExists) {
	    /* If that's a directory or a read-only file, we're not allowed */
	    if (FatFcbIsDirectory(TargetFcb) || FatFcbIsReadOnly(TargetFcb)) {
		DPRINT("And this is a readonly file!\n");
		FatReleaseFcb(DeviceExt, *ParentFCB);
		*ParentFCB = NULL;
		FatReleaseFcb(DeviceExt, TargetFcb);
		return STATUS_OBJECT_NAME_COLLISION;
	    }


	    /* If we still have a file object, close it. */
	    if (TargetFcb->FileObject) {
#if 0	       /* TODO: This should probably be done on server-side */
		if (!MmFlushImageSection(TargetFcb->FileObject->SectionObjectPointer,
					 MmFlushForDelete)) {
		    DPRINT("MmFlushImageSection failed.\n");
		    FatReleaseFcb(DeviceExt, *ParentFCB);
		    *ParentFCB = NULL;
		    FatReleaseFcb(DeviceExt, TargetFcb);
		    return STATUS_ACCESS_DENIED;
		}
#endif

		TargetFcb->FileObject->DeletePending = TRUE;
		FatCloseFile(DeviceExt, TargetFcb->FileObject);
	    }

	    /* If we are here, ensure the file isn't open by anyone! */
	    if (TargetFcb->OpenHandleCount != 0) {
		DPRINT("There are still open handles for this file.\n");
		FatReleaseFcb(DeviceExt, *ParentFCB);
		*ParentFCB = NULL;
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
	    FatReleaseFcb(DeviceExt, *ParentFCB);
	    *ParentFCB = NULL;
	    FatReleaseFcb(DeviceExt, TargetFcb);
	    return STATUS_OBJECT_NAME_COLLISION;
	}
    } else if (*ParentFCB != NULL) {
	return STATUS_SUCCESS;
    }

    /* Failure */
    return Status;
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

static VOID FatRenameChildFCB(PDEVICE_EXTENSION DeviceExt, PFATFCB FCB)
{
    PLIST_ENTRY Entry;
    PFATFCB Child;

    if (IsListEmpty(&FCB->ParentListHead))
	return;

    for (Entry = FCB->ParentListHead.Flink; Entry != &FCB->ParentListHead;
	 Entry = Entry->Flink) {
	NTSTATUS Status;

	Child = CONTAINING_RECORD(Entry, FATFCB, ParentListEntry);
	DPRINT("Found %wZ with still %u references (parent: %u)!\n",
	       &Child->PathNameU, Child->RefCount, FCB->RefCount);

	Status = FatSetFcbNewDirName(DeviceExt, Child, FCB);
	if (!NT_SUCCESS(Status))
	    continue;

	if (FatFcbIsDirectory(Child)) {
	    FatRenameChildFCB(DeviceExt, Child);
	}
    }
}

/*
 * FUNCTION: Set the file name information
 */
static NTSTATUS FatSetRenameInformation(PFILE_OBJECT FileObject,
					PFATFCB FCB,
					PDEVICE_EXTENSION DeviceExt,
					PFILE_RENAME_INFORMATION RenameInfo,
					PFILE_OBJECT TargetFileObject)
{
#ifdef NASSERTS_RENAME
#pragma push_macro("ASSERT")
#undef ASSERT
#define ASSERT(x) ((VOID) 0)
#endif
    NTSTATUS Status;
    UNICODE_STRING NewName;
    UNICODE_STRING SourcePath;
    UNICODE_STRING SourceFile;
    UNICODE_STRING NewPath;
    UNICODE_STRING NewFile;
    PFILE_OBJECT RootFileObject;
    PFATFCB RootFCB;
    UNICODE_STRING RenameInfoString;
    PFATFCB ParentFCB;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE TargetHandle;
    BOOLEAN DeletedTarget;
    ULONG OldReferences, NewReferences;
    PFATFCB OldParent;

    DPRINT("FatSetRenameInfo(%p, %p, %p, %p, %p)\n", FileObject, FCB,
	   DeviceExt, RenameInfo, TargetFileObject);

    /* Disallow renaming root */
    if (FatFcbIsRoot(FCB)) {
	return STATUS_INVALID_PARAMETER;
    }

    OldReferences = FCB->ParentFcb->RefCount;
#ifdef NASSERTS_RENAME
    UNREFERENCED_PARAMETER(OldReferences);
#endif

    /* If we are performing relative opening for rename, get FO for getting FCB and path name */
    if (RenameInfo->RootDirectory != NULL) {
	/* We cannot tolerate relative opening with a full path */
	if (RenameInfo->FileName[0] == L'\\') {
	    return STATUS_OBJECT_NAME_INVALID;
	}

#if 0				/* TODO! */
	Status = ObReferenceObjectByHandle(RenameInfo->RootDirectory,
					   FILE_READ_DATA,
					   *IoFileObjectType,
					   ExGetPreviousMode(),
					   (PVOID *)&RootFileObject,
					   NULL);
#endif
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}

	RootFCB = RootFileObject->FsContext;
    }

    RtlInitEmptyUnicodeString(&NewName, NULL, 0);
    ParentFCB = NULL;

    if (TargetFileObject == NULL) {
	/* If we don't have target file object, construct paths thanks to relative FCB, if any, and with
	 * information supplied by the user
	 */

	/* First, setup a string we'll work on */
	RenameInfoString.Length = RenameInfo->FileNameLength;
	RenameInfoString.MaximumLength = RenameInfo->FileNameLength;
	RenameInfoString.Buffer = RenameInfo->FileName;

	/* Check whether we have FQN */
	if (RenameInfoString.Length > 6 * sizeof(WCHAR)) {
	    if (RenameInfoString.Buffer[0] == L'\\'
		&& RenameInfoString.Buffer[1] == L'?'
		&& RenameInfoString.Buffer[2] == L'?'
		&& RenameInfoString.Buffer[3] == L'\\'
		&& RenameInfoString.Buffer[5] == L':'
		&& (RenameInfoString.Buffer[4] >= L'A'
		    && RenameInfoString.Buffer[4] <= L'Z')) {
		/* If so, open its target directory */
		InitializeObjectAttributes(&ObjectAttributes,
					   &RenameInfoString,
					   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
					   NULL, NULL);

#if 0				/* TODO! */
		Status = IoCreateFile(&TargetHandle,
				      FILE_WRITE_DATA | SYNCHRONIZE,
				      &ObjectAttributes,
				      &IoStatusBlock,
				      NULL, 0,
				      FILE_SHARE_READ | FILE_SHARE_WRITE,
				      FILE_OPEN,
				      FILE_OPEN_FOR_BACKUP_INTENT,
				      NULL, 0,
				      CreateFileTypeNone,
				      NULL,
				      IO_FORCE_ACCESS_CHECK | IO_OPEN_TARGET_DIRECTORY);
		if (!NT_SUCCESS(Status)) {
		    goto Cleanup;
		}
#endif

		/* Get its FO to get the FCB */
#if 0		/* TODO */
		Status = ObReferenceObjectByHandle(TargetHandle,
						   FILE_WRITE_DATA,
						   *IoFileObjectType,
						   KernelMode,
						   (PVOID *) &
						   TargetFileObject, NULL);
#endif
		if (!NT_SUCCESS(Status)) {
		    NtClose(TargetHandle);
		    goto Cleanup;
		}

		/* Are we working on the same volume? */
#if 0		/* TODO! */
		if (IoGetRelatedDeviceObject(TargetFileObject) != IoGetRelatedDeviceObject(FileObject)) {
		    ObDereferenceObject(TargetFileObject);
		    ZwClose(TargetHandle);
		    TargetFileObject = NULL;
		    Status = STATUS_NOT_SAME_DEVICE;
		    goto Cleanup;
		}
#endif
	    }
	}

	NewName.Length = 0;
	NewName.MaximumLength = RenameInfo->FileNameLength;
	if (RenameInfo->RootDirectory != NULL) {
	    NewName.MaximumLength += sizeof(WCHAR) + RootFCB->PathNameU.Length;
	} else if (RenameInfo->FileName[0] != L'\\') {
	    /* We don't have full path, and we don't have root directory:
	     * => we move inside the same directory */
	    NewName.MaximumLength += sizeof(WCHAR) + FCB->DirNameU.Length;
	} else if (TargetFileObject != NULL) {
	    /* We had a FQN:
	     * => we need to use its correct path */
	    NewName.MaximumLength += sizeof(WCHAR) +
		((PFATFCB)TargetFileObject->FsContext)->PathNameU.Length;
	}

	NewName.Buffer = ExAllocatePoolWithTag(NewName.MaximumLength, TAG_NAME);
	if (NewName.Buffer == NULL) {
	    if (TargetFileObject != NULL) {
		ObDereferenceObject(TargetFileObject);
		ZwClose(TargetHandle);
		TargetFileObject = NULL;
	    }
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto Cleanup;
	}

	if (RenameInfo->RootDirectory != NULL) {
	    /* Here, copy first absolute and then append relative */
	    RtlCopyUnicodeString(&NewName, &RootFCB->PathNameU);
	    NewName.Buffer[NewName.Length / sizeof(WCHAR)] = L'\\';
	    NewName.Length += sizeof(WCHAR);
	    RtlAppendUnicodeStringToString(&NewName, &RenameInfoString);
	} else if (RenameInfo->FileName[0] != L'\\') {
	    /* Here, copy first work directory and then append filename */
	    RtlCopyUnicodeString(&NewName, &FCB->DirNameU);
	    NewName.Buffer[NewName.Length / sizeof(WCHAR)] = L'\\';
	    NewName.Length += sizeof(WCHAR);
	    RtlAppendUnicodeStringToString(&NewName, &RenameInfoString);
	} else if (TargetFileObject != NULL) {
	    /* Here, copy first path name and then append filename */
	    RtlCopyUnicodeString(&NewName,
				 &((PFATFCB)TargetFileObject->FsContext)->PathNameU);
	    NewName.Buffer[NewName.Length / sizeof(WCHAR)] = L'\\';
	    NewName.Length += sizeof(WCHAR);
	    RtlAppendUnicodeStringToString(&NewName, &RenameInfoString);
	} else {
	    /* Here we should have full path, so simply copy it */
	    RtlCopyUnicodeString(&NewName, &RenameInfoString);
	}

	/* Do we have to cleanup some stuff? */
	if (TargetFileObject != NULL) {
	    ObDereferenceObject(TargetFileObject);
	    ZwClose(TargetHandle);
	    TargetFileObject = NULL;
	}
    } else {
	/* At that point, we shouldn't care about whether we are relative opening
	 * Target FO FCB should already have full path
	 */

	/* Before constructing string, just make a sanity check (just to be sure!) */
#if 0	/* TODO! */
	if (IoGetRelatedDeviceObject(TargetFileObject) != IoGetRelatedDeviceObject(FileObject)) {
	    Status = STATUS_NOT_SAME_DEVICE;
	    goto Cleanup;
	}
#endif

	NewName.Length = 0;
	NewName.MaximumLength = TargetFileObject->FileName.Length +
	    ((PFATFCB)TargetFileObject->FsContext)->PathNameU.Length + sizeof(WCHAR);
	NewName.Buffer = ExAllocatePoolWithTag(NewName.MaximumLength, TAG_NAME);
	if (NewName.Buffer == NULL) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto Cleanup;
	}

	RtlCopyUnicodeString(&NewName,
			     &((PFATFCB)TargetFileObject->FsContext)->PathNameU);
	/* If \, it's already backslash terminated, don't add it */
	if (!FatFcbIsRoot(TargetFileObject->FsContext)) {
	    NewName.Buffer[NewName.Length / sizeof(WCHAR)] = L'\\';
	    NewName.Length += sizeof(WCHAR);
	}
	RtlAppendUnicodeStringToString(&NewName, &TargetFileObject->FileName);
    }

    /* Explode our paths to get path & filename */
    FatSplitPathName(&FCB->PathNameU, &SourcePath, &SourceFile);
    DPRINT("Old dir: %wZ, Old file: %wZ\n", &SourcePath, &SourceFile);
    FatSplitPathName(&NewName, &NewPath, &NewFile);
    DPRINT("New dir: %wZ, New file: %wZ\n", &NewPath, &NewFile);

    if (IsDotOrDotDot(&NewFile)) {
	Status = STATUS_OBJECT_NAME_INVALID;
	goto Cleanup;
    }

    if (FatFcbIsDirectory(FCB) && !IsListEmpty(&FCB->ParentListHead)) {
	if (IsThereAChildOpened(FCB)) {
	    Status = STATUS_ACCESS_DENIED;
	    ASSERT(OldReferences == FCB->ParentFcb->RefCount);
	    goto Cleanup;
	}
    }

    /* Are we working in place? */
    if (FsRtlAreNamesEqual(&SourcePath, &NewPath, TRUE, NULL)) {
	if (FsRtlAreNamesEqual(&SourceFile, &NewFile, FALSE, NULL)) {
	    Status = STATUS_SUCCESS;
	    ASSERT(OldReferences == FCB->ParentFcb->RefCount);
	    goto Cleanup;
	}

	if (FsRtlAreNamesEqual(&SourceFile, &NewFile, TRUE, NULL)) {
	    FatReportChange(DeviceExt,
			    FCB,
			    (FatFcbIsDirectory(FCB) ?
			     FILE_NOTIFY_CHANGE_DIR_NAME :
			     FILE_NOTIFY_CHANGE_FILE_NAME),
			    FILE_ACTION_RENAMED_OLD_NAME);
	    Status = FatRenameEntry(DeviceExt, FCB, &NewFile, TRUE);
	    if (NT_SUCCESS(Status)) {
		FatReportChange(DeviceExt,
				FCB,
				(FatFcbIsDirectory(FCB) ?
				 FILE_NOTIFY_CHANGE_DIR_NAME :
				 FILE_NOTIFY_CHANGE_FILE_NAME),
				FILE_ACTION_RENAMED_NEW_NAME);
	    }
	} else {
	    /* Try to find target */
	    ParentFCB = FCB->ParentFcb;
	    FatGrabFcb(DeviceExt, ParentFCB);
	    Status = FatPrepareTargetForRename(DeviceExt,
					       &ParentFCB,
					       &NewFile,
					       RenameInfo->ReplaceIfExists,
					       &NewPath, &DeletedTarget);
	    if (!NT_SUCCESS(Status)) {
		ASSERT(OldReferences == FCB->ParentFcb->RefCount - 1);
		ASSERT(OldReferences == ParentFCB->RefCount - 1);
		goto Cleanup;
	    }

	    FatReportChange(DeviceExt,
			    FCB,
			    (FatFcbIsDirectory(FCB) ?
			     FILE_NOTIFY_CHANGE_DIR_NAME :
			     FILE_NOTIFY_CHANGE_FILE_NAME),
			    (DeletedTarget ? FILE_ACTION_REMOVED :
			     FILE_ACTION_RENAMED_OLD_NAME));
	    Status = FatRenameEntry(DeviceExt, FCB, &NewFile, FALSE);
	    if (NT_SUCCESS(Status)) {
		if (DeletedTarget) {
		    FatReportChange(DeviceExt,
				    FCB,
				    FILE_NOTIFY_CHANGE_ATTRIBUTES |
				    FILE_NOTIFY_CHANGE_SIZE |
				    FILE_NOTIFY_CHANGE_LAST_WRITE |
				    FILE_NOTIFY_CHANGE_LAST_ACCESS |
				    FILE_NOTIFY_CHANGE_CREATION |
				    FILE_NOTIFY_CHANGE_EA,
				    FILE_ACTION_MODIFIED);
		} else {
		    FatReportChange(DeviceExt,
				    FCB,
				    (FatFcbIsDirectory(FCB) ?
				     FILE_NOTIFY_CHANGE_DIR_NAME :
				     FILE_NOTIFY_CHANGE_FILE_NAME),
				    FILE_ACTION_RENAMED_NEW_NAME);
		}
	    }
	}

	ASSERT(OldReferences == FCB->ParentFcb->RefCount - 1);	// extra grab
	ASSERT(OldReferences == ParentFCB->RefCount - 1);	// extra grab
    } else {

	/* Try to find target */
	ParentFCB = NULL;
	OldParent = FCB->ParentFcb;
#ifdef NASSERTS_RENAME
	UNREFERENCED_PARAMETER(OldParent);
#endif
	Status = FatPrepareTargetForRename(DeviceExt,
					   &ParentFCB,
					   &NewName,
					   RenameInfo->ReplaceIfExists,
					   &NewPath, &DeletedTarget);
	if (!NT_SUCCESS(Status)) {
	    ASSERT(OldReferences == FCB->ParentFcb->RefCount);
	    goto Cleanup;
	}

	NewReferences = ParentFCB->RefCount;
#ifdef NASSERTS_RENAME
	UNREFERENCED_PARAMETER(NewReferences);
#endif

	FatReportChange(DeviceExt,
			FCB,
			(FatFcbIsDirectory(FCB) ?
			 FILE_NOTIFY_CHANGE_DIR_NAME :
			 FILE_NOTIFY_CHANGE_FILE_NAME),
			FILE_ACTION_REMOVED);
	Status = FatMoveEntry(DeviceExt, FCB, &NewFile, ParentFCB);
	if (NT_SUCCESS(Status)) {
	    if (DeletedTarget) {
		FatReportChange(DeviceExt,
				FCB,
				FILE_NOTIFY_CHANGE_ATTRIBUTES |
				FILE_NOTIFY_CHANGE_SIZE |
				FILE_NOTIFY_CHANGE_LAST_WRITE |
				FILE_NOTIFY_CHANGE_LAST_ACCESS |
				FILE_NOTIFY_CHANGE_CREATION |
				FILE_NOTIFY_CHANGE_EA,
				FILE_ACTION_MODIFIED);
	    } else {
		FatReportChange(DeviceExt,
				FCB,
				(FatFcbIsDirectory(FCB) ?
				 FILE_NOTIFY_CHANGE_DIR_NAME :
				 FILE_NOTIFY_CHANGE_FILE_NAME),
				FILE_ACTION_ADDED);
	    }
	}
    }

    if (NT_SUCCESS(Status) && FatFcbIsDirectory(FCB)) {
	FatRenameChildFCB(DeviceExt, FCB);
    }

    ASSERT(OldReferences == OldParent->RefCount + 1);	// removed file
    ASSERT(NewReferences == ParentFCB->RefCount - 1);	// new file
Cleanup:
    if (ParentFCB != NULL)
	FatReleaseFcb(DeviceExt, ParentFCB);
    if (NewName.Buffer != NULL)
	ExFreePoolWithTag(NewName.Buffer, TAG_NAME);
    if (RenameInfo->RootDirectory != NULL)
	ObDereferenceObject(RootFileObject);

    return Status;
#ifdef NASSERTS_RENAME
#pragma pop_macro("ASSERT")
#endif
}

/*
 * FUNCTION: Retrieve the file name information
 */
static NTSTATUS FatGetNameInformation(PFILE_OBJECT FileObject,
				      PFATFCB FCB,
				      PDEVICE_EXTENSION DeviceExt,
				      PFILE_NAME_INFORMATION NameInfo, PULONG BufferLength)
{
    ULONG BytesToCopy;

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(DeviceExt);

    ASSERT(NameInfo != NULL);
    ASSERT(FCB != NULL);

    /* If buffer can't hold at least the file name length, bail out */
    if (*BufferLength <
	(ULONG) FIELD_OFFSET(FILE_NAME_INFORMATION, FileName[0]))
	return STATUS_BUFFER_OVERFLOW;

    /* Save file name length, and as much file len, as buffer length allows */
    NameInfo->FileNameLength = FCB->PathNameU.Length;

    /* Calculate amount of bytes to copy not to overflow the buffer */
    BytesToCopy = min(FCB->PathNameU.Length,
		      *BufferLength - FIELD_OFFSET(FILE_NAME_INFORMATION,
						   FileName[0]));

    /* Fill in the bytes */
    RtlCopyMemory(NameInfo->FileName, FCB->PathNameU.Buffer, BytesToCopy);

    /* Check if we could write more but are not able to */
    if (*BufferLength <
	FCB->PathNameU.Length + (ULONG) FIELD_OFFSET(FILE_NAME_INFORMATION,
						     FileName[0])) {
	/* Return number of bytes written */
	*BufferLength -= FIELD_OFFSET(FILE_NAME_INFORMATION, FileName[0]) + BytesToCopy;
	return STATUS_BUFFER_OVERFLOW;
    }

    /* We filled up as many bytes, as needed */
    *BufferLength -= (FIELD_OFFSET(FILE_NAME_INFORMATION, FileName[0]) +
		      FCB->PathNameU.Length);

    return STATUS_SUCCESS;
}

static NTSTATUS FatGetInternalInformation(PFATFCB Fcb,
					  PDEVICE_EXTENSION DeviceExt,
					  PFILE_INTERNAL_INFORMATION InternalInfo,
					  PULONG BufferLength)
{
    ASSERT(InternalInfo);
    ASSERT(Fcb);

    if (*BufferLength < sizeof(FILE_INTERNAL_INFORMATION))
	return STATUS_BUFFER_OVERFLOW;

    InternalInfo->IndexNumber.QuadPart = (LONGLONG) FatDirEntryGetFirstCluster(DeviceExt,
									       &Fcb->Entry) *
	DeviceExt->FatInfo.BytesPerCluster;

    *BufferLength -= sizeof(FILE_INTERNAL_INFORMATION);
    return STATUS_SUCCESS;
}


/*
 * FUNCTION: Retrieve the file network open information
 */
static NTSTATUS FatGetNetworkOpenInformation(PFATFCB Fcb,
					     PDEVICE_EXTENSION DeviceExt,
					     PFILE_NETWORK_OPEN_INFORMATION NetworkInfo,
					     PULONG BufferLength)
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
    if (0 == (NetworkInfo->FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
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


static NTSTATUS FatGetEaInformation(PFILE_OBJECT FileObject,
				    PFATFCB Fcb,
				    PDEVICE_EXTENSION DeviceExt,
				    PFILE_EA_INFORMATION Info, PULONG BufferLength)
{
    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(Fcb);

    /* FIXME - use SEH to access the buffer! */
    Info->EaSize = 0;
    *BufferLength -= sizeof(*Info);
    if (DeviceExt->FatInfo.FatType == FAT12 ||
	DeviceExt->FatInfo.FatType == FAT16) {
	/* FIXME */
	DPRINT1("FAT: FileEaInformation not implemented!\n");
    }
    return STATUS_SUCCESS;
}


/*
 * FUNCTION: Retrieve the all file information
 */
static NTSTATUS FatGetAllInformation(PFILE_OBJECT FileObject,
				     PFATFCB Fcb,
				     PDEVICE_EXTENSION DeviceExt,
				     PFILE_ALL_INFORMATION Info, PULONG BufferLength)
{
    NTSTATUS Status;

    ASSERT(Info);
    ASSERT(Fcb);

    if (*BufferLength <
	FIELD_OFFSET(FILE_ALL_INFORMATION, NameInformation.FileName))
	return STATUS_BUFFER_OVERFLOW;

    *BufferLength -= (sizeof(FILE_ACCESS_INFORMATION) + sizeof(FILE_MODE_INFORMATION) +
		      sizeof(FILE_ALIGNMENT_INFORMATION));

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
    /* Position Information */
    Status = FatGetPositionInformation(FileObject, Fcb, DeviceExt,
				       &Info->PositionInformation,
				       BufferLength);
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
	    Status = OffsetToCluster(DeviceExt, FirstCluster,
				     Fcb->Base.FileSizes.AllocationSize.LowPart - ClusterSize,
				     &Cluster, FALSE);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }

	    /* FIXME: Check status */
	    /* Cluster points now to the last cluster within the chain */
	    ULONG NCluster;
	    Status = OffsetToCluster(DeviceExt, Cluster,
				     ROUND_DOWN(NewSize - 1, ClusterSize),
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
	DPRINT("Check for the ability to set file size\n");
#if 0				/* TODO! */
	if (!MmCanFileBeTruncated(FileObject->SectionObjectPointer,
				  (PLARGE_INTEGER)AllocationSize)) {
	    DPRINT("Couldn't set file size!\n");
	    return STATUS_USER_MAPPED_FILE;
	}
#endif
	DPRINT("Can set file size\n");

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
	Status = FatGetPositionInformation(IrpContext->FileObject, Fcb,
					   IrpContext->DeviceExt,
					   SystemBuffer, &BufferLength);
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
    PFATFCB Fcb = (PFATFCB) IrpContext->FileObject->FsContext;
    PVOID SystemBuffer = IrpContext->Irp->SystemBuffer;

    DPRINT("FatSetInformation is called for '%s'\n",
	   (Info >= (FileMaximumInformation - 1)) ? "????" : FileInformationClassNames[Info]);

    DPRINT("FileInformationClass %d\n", Info);
    DPRINT("SystemBuffer %p\n", SystemBuffer);

    if (Fcb == NULL) {
	DPRINT1("IRP_MJ_SET_INFORMATION without FCB!\n");
	IrpContext->Irp->IoStatus.Information = 0;
	return STATUS_INVALID_PARAMETER;
    }

    /* Special: We should call MmCanFileBeTruncated here to determine if changing
       the file size would be allowed.  If not, we bail with the right error.
       We must do this before acquiring the lock. */
#if 0			/* TODO! */
    if (Info == FileEndOfFileInformation) {
	DPRINT("Check for the ability to set file size\n");
	if (!MmCanFileBeTruncated(IrpContext->FileObject->SectionObjectPointer,
				  (PLARGE_INTEGER)SystemBuffer)) {
	    DPRINT("Couldn't set file size!\n");
	    IrpContext->Irp->IoStatus.Information = 0;
	    return STATUS_USER_MAPPED_FILE;
	}
	DPRINT("Can set file size\n");
    }
#endif

    PFILE_OBJECT FileObj = IrpContext->FileObject;
    PDEVICE_EXTENSION DevExt = IrpContext->DeviceExt;
    NTSTATUS Status = STATUS_SUCCESS;

    switch (Info) {
    case FilePositionInformation:
	Status = FatSetPositionInformation(FileObj, SystemBuffer);
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
