/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Directory control
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2004-2005 Hervé Poussineau <hpoussin@reactos.org>
 *              Copyright 2012-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS ****************************************************************/

/* Function like DosDateTimeToFileTime */
BOOLEAN FsdDosDateTimeToSystemTime(PDEVICE_EXTENSION DeviceExt,
				   USHORT DosDate,
				   USHORT DosTime,
				   PLARGE_INTEGER SystemTime)
{
    PDOSTIME pdtime = (PDOSTIME) & DosTime;
    PDOSDATE pddate = (PDOSDATE) & DosDate;
    TIME_FIELDS TimeFields;
    LARGE_INTEGER LocalTime;

    if (SystemTime == NULL)
	return FALSE;

    TimeFields.Milliseconds = 0;
    TimeFields.Second = pdtime->Second * 2;
    TimeFields.Minute = pdtime->Minute;
    TimeFields.Hour = pdtime->Hour;

    TimeFields.Day = pddate->Day;
    TimeFields.Month = pddate->Month;
    TimeFields.Year = (CSHORT)(DeviceExt->BaseDateYear + pddate->Year);

    RtlTimeFieldsToTime(&TimeFields, &LocalTime);
    RtlLocalTimeToSystemTime(&LocalTime, SystemTime);

    return TRUE;
}

/* Function like FileTimeToDosDateTime */
BOOLEAN FsdSystemTimeToDosDateTime(PDEVICE_EXTENSION DeviceExt,
				   PLARGE_INTEGER SystemTime,
				   PUSHORT pDosDate,
				   PUSHORT pDosTime)
{
    PDOSTIME pdtime = (PDOSTIME)pDosTime;
    PDOSDATE pddate = (PDOSDATE)pDosDate;
    TIME_FIELDS TimeFields;
    LARGE_INTEGER LocalTime;

    if (SystemTime == NULL)
	return FALSE;

    RtlSystemTimeToLocalTime(SystemTime, &LocalTime);
    RtlTimeToTimeFields(&LocalTime, &TimeFields);

    if (pdtime) {
	pdtime->Second = TimeFields.Second / 2;
	pdtime->Minute = TimeFields.Minute;
	pdtime->Hour = TimeFields.Hour;
    }

    if (pddate) {
	pddate->Day = TimeFields.Day;
	pddate->Month = TimeFields.Month;
	pddate->Year =
	    (USHORT) (TimeFields.Year - DeviceExt->BaseDateYear);
    }

    return TRUE;
}

#define ULONG_ROUND_UP_32(x)   ROUND_UP_32((x), (sizeof(ULONG)))

static NTSTATUS FatGetFileNamesInformation(PFAT_DIRENTRY_CONTEXT DirContext,
					   PFILE_NAMES_INFORMATION pInfo,
					   ULONG BufferLength,
					   PULONG Written,
					   BOOLEAN First)
{
    *Written = 0;
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;

    if (FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) > BufferLength)
	return Status;

    if (First || (BufferLength > FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) +
		  DirContext->LongNameU.Length)) {
	pInfo->FileNameLength = DirContext->LongNameU.Length;

	*Written = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName);
	pInfo->NextEntryOffset = 0;
	if (BufferLength > FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName)) {
	    ULONG BytesToCopy = min(DirContext->LongNameU.Length,
				    BufferLength - FIELD_OFFSET(FILE_NAMES_INFORMATION,
								FileName));
	    RtlCopyMemory(pInfo->FileName, DirContext->LongNameU.Buffer, BytesToCopy);
	    *Written += BytesToCopy;

	    if (BytesToCopy == DirContext->LongNameU.Length) {
		pInfo->NextEntryOffset =
		    ULONG_ROUND_UP_32(sizeof(FILE_NAMES_INFORMATION) + BytesToCopy);
		Status = STATUS_SUCCESS;
	    }
	}
    }

    return Status;
}

static NTSTATUS FatGetFileDirectoryInformation(PFAT_DIRENTRY_CONTEXT DirContext,
					       PDEVICE_EXTENSION DeviceExt,
					       PFILE_DIRECTORY_INFORMATION pInfo,
					       ULONG BufferLength,
					       PULONG Written,
					       BOOLEAN First)
{
    *Written = 0;
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;

    if (FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) > BufferLength)
	return Status;

    if (First || (BufferLength > FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) +
		  DirContext->LongNameU.Length)) {
	pInfo->FileNameLength = DirContext->LongNameU.Length;
	/* pInfo->FileIndex = ; */

	*Written = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
	pInfo->NextEntryOffset = 0;
	if (BufferLength > FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName)) {
	    ULONG BytesToCopy =
		min(DirContext->LongNameU.Length,
		    BufferLength - FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName));
	    RtlCopyMemory(pInfo->FileName, DirContext->LongNameU.Buffer, BytesToCopy);
	    *Written += BytesToCopy;

	    if (BytesToCopy == DirContext->LongNameU.Length) {
		pInfo->NextEntryOffset =
		    ULONG_ROUND_UP_32(sizeof(FILE_DIRECTORY_INFORMATION) + BytesToCopy);
		Status = STATUS_SUCCESS;
	    }
	}

	if (FatVolumeIsFatX(DeviceExt)) {
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.FatX.
				       CreationDate,
				       DirContext->DirEntry.FatX.
				       CreationTime, &pInfo->CreationTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.FatX.
				       AccessDate,
				       DirContext->DirEntry.FatX.
				       AccessTime, &pInfo->LastAccessTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.FatX.
				       UpdateDate,
				       DirContext->DirEntry.FatX.
				       UpdateTime, &pInfo->LastWriteTime);

	    pInfo->ChangeTime = pInfo->LastWriteTime;

	    if (BooleanFlagOn(DirContext->DirEntry.FatX.Attrib,
			      FILE_ATTRIBUTE_DIRECTORY)) {
		pInfo->EndOfFile.QuadPart = 0;
		pInfo->AllocationSize.QuadPart = 0;
	    } else {
		pInfo->EndOfFile.HighPart = 0;
		pInfo->EndOfFile.LowPart = DirContext->DirEntry.FatX.FileSize;
		/* Make allocsize a rounded up multiple of BytesPerCluster */
		pInfo->AllocationSize.HighPart = 0;
		pInfo->AllocationSize.LowPart =
		    ROUND_UP_32(DirContext->DirEntry.FatX.FileSize,
				DeviceExt->FatInfo.BytesPerCluster);
	    }

	    pInfo->FileAttributes = DirContext->DirEntry.FatX.Attrib & 0x3f;
	} else {
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.
				       CreationDate,
				       DirContext->DirEntry.Fat.
				       CreationTime, &pInfo->CreationTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.AccessDate,
				       0, &pInfo->LastAccessTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.UpdateDate,
				       DirContext->DirEntry.Fat.UpdateTime,
				       &pInfo->LastWriteTime);

	    pInfo->ChangeTime = pInfo->LastWriteTime;

	    if (BooleanFlagOn(DirContext->DirEntry.Fat.Attrib,
			      FILE_ATTRIBUTE_DIRECTORY)) {
		pInfo->EndOfFile.QuadPart = 0;
		pInfo->AllocationSize.QuadPart = 0;
	    } else {
		pInfo->EndOfFile.HighPart = 0;
		pInfo->EndOfFile.LowPart = DirContext->DirEntry.Fat.FileSize;
		/* Make allocsize a rounded up multiple of BytesPerCluster */
		pInfo->AllocationSize.HighPart = 0;
		pInfo->AllocationSize.LowPart =
		    ROUND_UP_32(DirContext->DirEntry.Fat.FileSize,
				DeviceExt->FatInfo.BytesPerCluster);
	    }

	    pInfo->FileAttributes = DirContext->DirEntry.Fat.Attrib & 0x3f;
	}
    }

    return Status;
}

static NTSTATUS FatGetFileFullDirectoryInformation(PFAT_DIRENTRY_CONTEXT DirContext,
						   PDEVICE_EXTENSION DeviceExt,
						   PFILE_FULL_DIR_INFORMATION pInfo,
						   ULONG BufferLength,
						   PULONG Written,
						   BOOLEAN First)
{
    *Written = 0;
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;

    if (FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) > BufferLength)
	return Status;

    if (First || (BufferLength > FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) +
		  DirContext->LongNameU.Length)) {
	pInfo->FileNameLength = DirContext->LongNameU.Length;
	/* pInfo->FileIndex = ; */
	pInfo->EaSize = 0;

	*Written = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName);
	pInfo->NextEntryOffset = 0;
	if (BufferLength > FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName)) {
	    ULONG BytesToCopy =
		min(DirContext->LongNameU.Length,
		    BufferLength - FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName));
	    RtlCopyMemory(pInfo->FileName, DirContext->LongNameU.Buffer,
			  BytesToCopy);
	    *Written += BytesToCopy;

	    if (BytesToCopy == DirContext->LongNameU.Length) {
		pInfo->NextEntryOffset =
		    ULONG_ROUND_UP_32(sizeof(FILE_FULL_DIR_INFORMATION) + BytesToCopy);
		Status = STATUS_SUCCESS;
	    }
	}

	if (FatVolumeIsFatX(DeviceExt)) {
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.FatX.
				       CreationDate,
				       DirContext->DirEntry.FatX.
				       CreationTime, &pInfo->CreationTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.FatX.
				       AccessDate,
				       DirContext->DirEntry.FatX.
				       AccessTime, &pInfo->LastAccessTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.FatX.
				       UpdateDate,
				       DirContext->DirEntry.FatX.
				       UpdateTime, &pInfo->LastWriteTime);

	    pInfo->ChangeTime = pInfo->LastWriteTime;
	    pInfo->EndOfFile.HighPart = 0;
	    pInfo->EndOfFile.LowPart = DirContext->DirEntry.FatX.FileSize;
	    /* Make allocsize a rounded up multiple of BytesPerCluster */
	    pInfo->AllocationSize.HighPart = 0;
	    pInfo->AllocationSize.LowPart =
		ROUND_UP_32(DirContext->DirEntry.FatX.FileSize,
			    DeviceExt->FatInfo.BytesPerCluster);
	    pInfo->FileAttributes = DirContext->DirEntry.FatX.Attrib & 0x3f;
	} else {
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.
				       CreationDate,
				       DirContext->DirEntry.Fat.
				       CreationTime, &pInfo->CreationTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.AccessDate,
				       0, &pInfo->LastAccessTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.UpdateDate,
				       DirContext->DirEntry.Fat.UpdateTime,
				       &pInfo->LastWriteTime);

	    pInfo->ChangeTime = pInfo->LastWriteTime;
	    pInfo->EndOfFile.HighPart = 0;
	    pInfo->EndOfFile.LowPart = DirContext->DirEntry.Fat.FileSize;
	    /* Make allocsize a rounded up multiple of BytesPerCluster */
	    pInfo->AllocationSize.HighPart = 0;
	    pInfo->AllocationSize.LowPart =
		ROUND_UP_32(DirContext->DirEntry.Fat.FileSize,
			    DeviceExt->FatInfo.BytesPerCluster);
	    pInfo->FileAttributes = DirContext->DirEntry.Fat.Attrib & 0x3f;
	}
    }

    return Status;
}

static NTSTATUS FatGetFileBothInformation(PFAT_DIRENTRY_CONTEXT DirContext,
					  PDEVICE_EXTENSION DeviceExt,
					  PFILE_BOTH_DIR_INFORMATION pInfo,
					  ULONG BufferLength,
					  PULONG Written,
					  BOOLEAN First)
{
    *Written = 0;
    NTSTATUS Status = STATUS_BUFFER_OVERFLOW;

    if (FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) > BufferLength)
	return Status;

    if (First || (BufferLength > FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) +
		  DirContext->LongNameU.Length)) {
	pInfo->FileNameLength = DirContext->LongNameU.Length;
	pInfo->EaSize = 0;

	*Written = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
	pInfo->NextEntryOffset = 0;
	if (BufferLength > FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName)) {
	    ULONG BytesToCopy =
		min(DirContext->LongNameU.Length,
		    BufferLength - FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName));
	    RtlCopyMemory(pInfo->FileName, DirContext->LongNameU.Buffer, BytesToCopy);
	    *Written += BytesToCopy;

	    if (BytesToCopy == DirContext->LongNameU.Length) {
		pInfo->NextEntryOffset =
		    ULONG_ROUND_UP_32(sizeof(FILE_BOTH_DIR_INFORMATION) + BytesToCopy);
		Status = STATUS_SUCCESS;
	    }
	}

	if (FatVolumeIsFatX(DeviceExt)) {
	    pInfo->ShortName[0] = 0;
	    pInfo->ShortNameLength = 0;
	    /* pInfo->FileIndex = ; */

	    FsdDosDateTimeToSystemTime(DeviceExt, DirContext->DirEntry.FatX.
				       CreationDate, DirContext->DirEntry.FatX.
				       CreationTime, &pInfo->CreationTime);
	    FsdDosDateTimeToSystemTime(DeviceExt, DirContext->DirEntry.FatX.
				       AccessDate, DirContext->DirEntry.FatX.
				       AccessTime, &pInfo->LastAccessTime);
	    FsdDosDateTimeToSystemTime(DeviceExt, DirContext->DirEntry.FatX.
				       UpdateDate, DirContext->DirEntry.FatX.
				       UpdateTime, &pInfo->LastWriteTime);

	    pInfo->ChangeTime = pInfo->LastWriteTime;

	    if (BooleanFlagOn(DirContext->DirEntry.FatX.Attrib,
			      FILE_ATTRIBUTE_DIRECTORY)) {
		pInfo->EndOfFile.QuadPart = 0;
		pInfo->AllocationSize.QuadPart = 0;
	    } else {
		pInfo->EndOfFile.HighPart = 0;
		pInfo->EndOfFile.LowPart = DirContext->DirEntry.FatX.FileSize;
		/* Make allocsize a rounded up multiple of BytesPerCluster */
		pInfo->AllocationSize.HighPart = 0;
		pInfo->AllocationSize.LowPart =
		    ROUND_UP_32(DirContext->DirEntry.FatX.FileSize,
				DeviceExt->FatInfo.BytesPerCluster);
	    }

	    pInfo->FileAttributes = DirContext->DirEntry.FatX.Attrib & 0x3f;
	} else {
	    pInfo->ShortNameLength = (CCHAR)DirContext->ShortNameU.Length;

	    ASSERT(pInfo->ShortNameLength / sizeof(WCHAR) <= 12);
	    RtlCopyMemory(pInfo->ShortName,
			  DirContext->ShortNameU.Buffer,
			  DirContext->ShortNameU.Length);

	    /* pInfo->FileIndex = ; */

	    FsdDosDateTimeToSystemTime(DeviceExt, DirContext->DirEntry.Fat.
				       CreationDate, DirContext->DirEntry.Fat.
				       CreationTime, &pInfo->CreationTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.AccessDate,
				       0, &pInfo->LastAccessTime);
	    FsdDosDateTimeToSystemTime(DeviceExt,
				       DirContext->DirEntry.Fat.UpdateDate,
				       DirContext->DirEntry.Fat.UpdateTime,
				       &pInfo->LastWriteTime);

	    pInfo->ChangeTime = pInfo->LastWriteTime;

	    if (BooleanFlagOn(DirContext->DirEntry.Fat.Attrib,
			      FILE_ATTRIBUTE_DIRECTORY)) {
		pInfo->EndOfFile.QuadPart = 0;
		pInfo->AllocationSize.QuadPart = 0;
	    } else {
		pInfo->EndOfFile.HighPart = 0;
		pInfo->EndOfFile.LowPart = DirContext->DirEntry.Fat.FileSize;
		/* Make allocsize a rounded up multiple of BytesPerCluster */
		pInfo->AllocationSize.HighPart = 0;
		pInfo->AllocationSize.LowPart =
		    ROUND_UP_32(DirContext->DirEntry.Fat.FileSize,
				DeviceExt->FatInfo.BytesPerCluster);
	    }

	    pInfo->FileAttributes = DirContext->DirEntry.Fat.Attrib & 0x3f;
	}
    }

    return Status;
}

static NTSTATUS DoQuery(PFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PUNICODE_STRING SearchPattern = NULL;
    FILE_INFORMATION_CLASS FileInformationClass;
    PFILE_NAMES_INFORMATION Buffer0 = NULL;
    PFATFCB Fcb;
    PFATCCB Ccb;
    BOOLEAN FirstQuery = FALSE;
    BOOLEAN FirstCall = TRUE;
    FAT_DIRENTRY_CONTEXT DirContext;
    WCHAR LongNameBuffer[LONGNAME_MAX_LENGTH + 1];
    WCHAR ShortNameBuffer[13];
    ULONG Written;

    PIO_STACK_LOCATION Stack = IrpContext->Stack;

    Ccb = (PFATCCB)IrpContext->FileObject->FsContext2;
    assert(Ccb);
    Fcb = (PFATFCB)IrpContext->FileObject->FsContext;
    assert(Fcb);

    LONG BufferLength = Stack->Parameters.QueryDirectory.Length;
    PUCHAR Buffer = IrpContext->Irp->UserBuffer;

    /* Obtain the callers parameters */
    SearchPattern = (PUNICODE_STRING)Stack->Parameters.QueryDirectory.FileName;
    FileInformationClass = Stack->Parameters.QueryDirectory.FileInformationClass;

    /* Allocate search pattern in case:
     * -> We don't have one already in context
     * -> We have been given an input pattern
     * -> The pattern length is not null
     * -> The pattern buffer is not null
     * Otherwise, we'll fall later and allocate a match all (*) pattern
     */
    if (SearchPattern && SearchPattern->Length && SearchPattern->Buffer) {
	if (!Ccb->SearchPattern.Buffer) {
	    FirstQuery = TRUE;
	    Ccb->SearchPattern.MaximumLength = SearchPattern->Length + sizeof(WCHAR);
	    Ccb->SearchPattern.Buffer =	ExAllocatePoolWithTag(Ccb->SearchPattern.MaximumLength,
							      TAG_SEARCH);
	    if (!Ccb->SearchPattern.Buffer) {
		return STATUS_INSUFFICIENT_RESOURCES;
	    }
	    RtlCopyUnicodeString(&Ccb->SearchPattern, SearchPattern);
	    Ccb->SearchPattern.Buffer[Ccb->SearchPattern.Length/sizeof(WCHAR)] = 0;
	}
    } else if (!Ccb->SearchPattern.Buffer) {
	FirstQuery = TRUE;
	Ccb->SearchPattern.MaximumLength = 2 * sizeof(WCHAR);
	Ccb->SearchPattern.Buffer = ExAllocatePoolWithTag(2 * sizeof(WCHAR), TAG_SEARCH);
	if (!Ccb->SearchPattern.Buffer) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
	Ccb->SearchPattern.Buffer[0] = L'*';
	Ccb->SearchPattern.Buffer[1] = 0;
	Ccb->SearchPattern.Length = sizeof(WCHAR);
    }

    if (BooleanFlagOn(IrpContext->Stack->Flags, SL_INDEX_SPECIFIED)) {
	DirContext.DirIndex = Ccb->Entry = Stack->Parameters.QueryDirectory.FileIndex;
    } else if (FirstQuery || BooleanFlagOn(IrpContext->Stack->Flags, SL_RESTART_SCAN)) {
	DirContext.DirIndex = Ccb->Entry = 0;
    } else {
	DirContext.DirIndex = Ccb->Entry;
    }

    DPRINT("Buffer=%p tofind=%wZ FirstQuery=%d\n", Buffer, &Ccb->SearchPattern, FirstQuery);

    DirContext.DeviceExt = IrpContext->DeviceExt;
    DirContext.LongNameU.Buffer = LongNameBuffer;
    DirContext.LongNameU.MaximumLength = sizeof(LongNameBuffer);
    DirContext.ShortNameU.Buffer = ShortNameBuffer;
    DirContext.ShortNameU.MaximumLength = sizeof(ShortNameBuffer);

    Written = 0;
    while ((Status == STATUS_SUCCESS) && (BufferLength > 0)) {
	Status = FindFile(IrpContext->DeviceExt, Fcb,
			  &Ccb->SearchPattern, &DirContext, FirstCall);
	Ccb->Entry = DirContext.DirIndex;

	DPRINT("Found %wZ, Status=%x, entry %x\n", &DirContext.LongNameU,
	       Status, Ccb->Entry);

	FirstCall = FALSE;
	if (NT_SUCCESS(Status)) {
	    switch (FileInformationClass) {
	    case FileDirectoryInformation:
		Status = FatGetFileDirectoryInformation(&DirContext,
							IrpContext->DeviceExt,
							(PFILE_DIRECTORY_INFORMATION)Buffer,
							BufferLength,
							&Written,
							Buffer0 == NULL);
		break;

	    case FileFullDirectoryInformation:
		Status = FatGetFileFullDirectoryInformation(&DirContext,
							    IrpContext->DeviceExt,
							    (PFILE_FULL_DIR_INFORMATION)Buffer,
							    BufferLength,
							    &Written,
							    Buffer0 == NULL);
		break;

	    case FileBothDirectoryInformation:
		Status = FatGetFileBothInformation(&DirContext,
						   IrpContext->DeviceExt,
						   (PFILE_BOTH_DIR_INFORMATION)Buffer,
						   BufferLength,
						   &Written,
						   Buffer0 == NULL);
		break;

	    case FileNamesInformation:
		Status = FatGetFileNamesInformation(&DirContext,
						    (PFILE_NAMES_INFORMATION)Buffer,
						    BufferLength,
						    &Written,
						    Buffer0 == NULL);
		break;

	    default:
		Status = STATUS_INVALID_INFO_CLASS;
		break;
	    }

	    if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_INVALID_INFO_CLASS)
		break;
	} else {
	    Status = (FirstQuery ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES);
	    break;
	}

	Buffer0 = (PFILE_NAMES_INFORMATION)Buffer;
	Buffer0->FileIndex = DirContext.DirIndex;
	Ccb->Entry = ++DirContext.DirIndex;
	BufferLength -= Buffer0->NextEntryOffset;

	if (BooleanFlagOn(IrpContext->Stack->Flags, SL_RETURN_SINGLE_ENTRY))
	    break;

	Buffer += Buffer0->NextEntryOffset;
    }

    if (Buffer0) {
	Buffer0->NextEntryOffset = 0;
	Status = STATUS_SUCCESS;
	IrpContext->Irp->IoStatus.Information =
	    Stack->Parameters.QueryDirectory.Length - BufferLength;
    } else {
	ASSERT(Status != STATUS_SUCCESS || BufferLength == 0);
	ASSERT(Written <= Stack->Parameters.QueryDirectory.Length);
	IrpContext->Irp->IoStatus.Information = Written;
    }

    return Status;
}

/*
 * FUNCTION: directory control : read/write directory informations
 */
NTSTATUS FatDirectoryControl(PFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status = STATUS_SUCCESS;

    IrpContext->Irp->IoStatus.Information = 0;

    switch (IrpContext->MinorFunction) {
    case IRP_MN_QUERY_DIRECTORY:
	Status = DoQuery(IrpContext);
	break;

    case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
	/* Directory notify change is now implemented on server side. The IRP
	 * minor code is reserved for future use (probaby to let the file system
	 * driver know about the notify change request from the user). */
	Status = STATUS_NOT_IMPLEMENTED;
	break;

    default:
	/* Error */
	DPRINT("Unexpected minor function %x in FAT driver\n",
	       IrpContext->MinorFunction);
	Status = STATUS_INVALID_DEVICE_REQUEST;
	break;
    }

    assert(Status != STATUS_PENDING);

    return Status;
}
