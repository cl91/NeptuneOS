/*++

Copyright (c) Alex Ionescu.  All rights reserved.
Copyright (c) 2011 amdf.

Module Name:

    file.c

Abstract:

    The Native Command Line Interface is the command shell for Neptune OS.
    This module implements commands for dealing with files and directories.

Environment:

    Native

Revision History:

    Alex Ionescu - Started Implementation - 23-Mar-06
    amdf - changed RtlCliSetCurrentDirectory - 20-Feb-11

--*/
#include "ntcmd.h"
#include "ntdef.h"
#include "ntstatus.h"
#include "stdio.h"

/*++
 * @name RtlCliGetCurrentDirectory
 *
 * The RtlCliGetCurrentDirectory routine provides a way to get the current
 * directory.
 *
 * @param CurrentDirectory
 *        The current directory.
 *
 * @return ULONG
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
ULONG RtlCliGetCurrentDirectory(IN OUT PWSTR CurrentDirectory)
{
    //
    // Get the current directory into our buffer
    //
    return RtlGetCurrentDirectory_U(MAX_PATH * sizeof(WCHAR),
				    CurrentDirectory);
}

/*++
 * @name RtlCliSetCurrentDirectory
 *
 * The RtlCliSetCurrentDirectory routine provides a way to change the current
 * directory.
 *
 * @param Directory
 *        The directory to change to.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliSetCurrentDirectory(PCHAR Directory)
{
    UNICODE_STRING UnicodeString;

    if (NULL == Directory) {
	return STATUS_UNSUCCESSFUL;
    }
    // Full path contains at least two symbols, the second is ':'
    if (strnlen(Directory, MAX_PATH) >= 2 && Directory[1] == ':') {
	RtlCreateUnicodeStringFromAsciiz(&UnicodeString, Directory);
	NTSTATUS Status = RtlSetCurrentDirectory_U(&UnicodeString);
	RtlFreeUnicodeString(&UnicodeString);
	return Status;
    }

    WCHAR FullPath[MAX_PATH];
    NTSTATUS Status = GetFullPath(Directory, FullPath, sizeof(FullPath), TRUE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    RtlInitUnicodeString(&UnicodeString, FullPath);
    Status = RtlSetCurrentDirectory_U(&UnicodeString);

    return Status;
}

/*++
 * @name RtlCliDumpFileInfo
 *
 * Print the file information to the screen.
 *
 * @param DirInfo
 *        File information
 *
 * @return None.
 *
 *--*/
VOID RtlCliDumpFileInfo(PFILE_BOTH_DIR_INFORMATION DirInfo)
{
    PWCHAR Null;
    WCHAR Save;
    TIME_FIELDS Time;
    CHAR SizeString[16];
    WCHAR FileString[MAX_PATH + 1];

    WCHAR FileStringSize[100];

    UINT FileSize = 0;

    //
    // The filename isn't null-terminated, and the next structure follows
    // right after it. So, we save the next char (which ends up being the
    // NextEntryOffset of the next structure), then temporarly clear it so
    // that the RtlCliDisplayString can treat it as a null-terminated string
    //
    Null = (PWCHAR)((PBYTE) DirInfo->FileName + DirInfo->FileNameLength);
    Save = *Null;
    *Null = 0;

    //
    // Get the last access time
    //
    RtlSystemTimeToLocalTime(&DirInfo->CreationTime,
			     &DirInfo->CreationTime);
    RtlTimeToTimeFields(&DirInfo->CreationTime, &Time);

    //
    // Don't display sizes for directories
    //
    if (!(DirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
	snprintf(SizeString, sizeof(SizeString), "%d", DirInfo->AllocationSize.LowPart);
    } else {
	snprintf(SizeString, sizeof(SizeString), " ", DirInfo->AllocationSize.LowPart);
    }

    //
    // Display this entry
    //

    // 75 symbols.

    FileSize = DirInfo->FileNameLength / sizeof(WCHAR);

    _snwprintf(FileStringSize, sizeof(FileStringSize)/sizeof(WCHAR), L"%d", FileSize);

    if (DirInfo->FileNameLength) {
	memset(FileString, 0x00, (MAX_PATH + 1) * sizeof(WCHAR));
	wcsncpy_s(FileString, sizeof(FileString)/sizeof(WCHAR), DirInfo->FileName, FileSize);
    } else {
	_snwprintf(FileString, sizeof(FileString)/sizeof(WCHAR), L" ");
    }

    RtlCliDisplayString("%02d.%02d.%04d %02d:%02d %s %9s  %ws\n",
			Time.Day, Time.Month, Time.Year, Time.Hour, Time.Minute,
			DirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY ? "<DIR>" : "",
			SizeString, FileString);

    //
    // Restore the character that was here before
    //
    *Null = Save;
}

/*++
 * @name RtlCliListDirectory
 *
 * The RtlCliListDirectory routine lists the current directory contents.
 *
 * @param None.
 *
 * @return NTSTATUS
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
NTSTATUS RtlCliListDirectory(VOID)
{
    UNICODE_STRING DirectoryString;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE DirectoryHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    BOOLEAN FirstQuery = TRUE;
    WCHAR CurrentDirectory[MAX_PATH];
    PFILE_BOTH_DIR_INFORMATION DirectoryInfo, Entry;
    HANDLE EventHandle;
    CHAR i, c;

    //
    // For now, we only support the current directory (ie: you can't dir e:\
    // without CDing into it first
    //
    RtlCliGetCurrentDirectory(CurrentDirectory);

    //
    // Convert it to NT Format
    //
    NTSTATUS Status = RtlDosPathNameToNtPathName_U_WithStatus(CurrentDirectory,
							      &DirectoryString,
							      NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    //
    // Initialize the object attributes
    //
    RtlCliDisplayString(" Directory of %ws\n\n", CurrentDirectory);
    InitializeObjectAttributes(&ObjectAttributes, &DirectoryString,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // Open the directory
    //
    Status = ZwCreateFile(&DirectoryHandle,
			  FILE_LIST_DIRECTORY,
			  &ObjectAttributes,
			  &IoStatusBlock,
			  NULL,
			  0,
			  FILE_SHARE_READ | FILE_SHARE_WRITE,
			  FILE_OPEN, FILE_DIRECTORY_FILE, NULL, 0);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    //
    // Allocate space for directory entry information
    //
    DirectoryInfo = RtlAllocateHeap(RtlGetProcessHeap(), 0, 4096);

    if (!DirectoryInfo) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    //
    // Create the event to wait on
    //
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    Status = NtCreateEvent(&EventHandle,
			   EVENT_ALL_ACCESS,
			   &ObjectAttributes, SynchronizationEvent, FALSE);

    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    //
    // Start loop
    //
    i = 0;
    for (;;) {
	//
	// Get the contents of the directory, adding up the size as we go
	//
	Status = ZwQueryDirectoryFile(DirectoryHandle,
				      EventHandle,
				      NULL,
				      0,
				      &IoStatusBlock,
				      DirectoryInfo,
				      4096,
				      FileBothDirectoryInformation,
				      FALSE, NULL, FirstQuery);
	if (Status == STATUS_PENDING) {
	    //
	    // Wait on the event
	    //
	    NtWaitForSingleObject(EventHandle, FALSE, NULL);
	    Status = IoStatusBlock.Status;
	}
	//
	// Check for success
	//
	if (!NT_SUCCESS(Status)) {
	    //
	    // Nothing left to enumerate. Close handles and free memory
	    //
	    ZwClose(DirectoryHandle);
	    RtlFreeHeap(RtlGetProcessHeap(), 0, DirectoryInfo);
	    return STATUS_SUCCESS;
	}
	//
	// Loop every directory
	//
	Entry = DirectoryInfo;

	while (Entry) {
	    //
	    // List the file
	    //
	    RtlCliDumpFileInfo(Entry);

	    if (++i > 20) {
		i = 0;
		RtlCliDisplayString("Continue listing (Y/N): ");
		while (TRUE) {
		    c = RtlCliGetChar(hKeyboard);
		    if (c == 'n' || c == 'N') {
			RtlCliDisplayString("\n");
			return STATUS_SUCCESS;
		    }
		    if (c == 'y' || c == 'Y') {
			break;
		    }
		}
		RtlCliDisplayString("\n");
	    }
	    //
	    // Make sure we still have a file
	    //
	    if (!Entry->NextEntryOffset)
		break;

	    //
	    // Move to the next one
	    //
	    Entry = (PFILE_BOTH_DIR_INFORMATION)((ULONG_PTR)Entry + Entry->NextEntryOffset);
	}

	//
	// This isn't the first scan anymore
	//
	FirstQuery = FALSE;
    }
    return STATUS_SUCCESS;
}

NTSTATUS OpenDirectory(HANDLE *File, WCHAR *FileName, BOOLEAN Write, BOOLEAN Overwrite)
{
    UNICODE_STRING FileNameU;
    IO_STATUS_BLOCK IoStatusBlock;
    WCHAR FileNameBuffer[1024] = L"\\??\\";
    OBJECT_ATTRIBUTES ObjectAttributes;
    wcscat_s(FileNameBuffer, sizeof(FileNameBuffer)/sizeof(WCHAR), FileName);
    RtlInitUnicodeString(&FileNameU, FileNameBuffer);
    InitializeObjectAttributes(&ObjectAttributes, &FileNameU,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    return NtCreateFile(File, FILE_LIST_DIRECTORY | SYNCHRONIZE | FILE_OPEN_FOR_BACKUP_INTENT,
			&ObjectAttributes, &IoStatusBlock, 0, FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			Write ? (Overwrite ? FILE_OVERWRITE_IF : FILE_OPEN_IF) : FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE, NULL, 0);
}

NTSTATUS OpenFile(HANDLE *File, WCHAR *FileName, BOOLEAN Write, BOOLEAN Overwrite)
{
    UNICODE_STRING FileNameU;
    IO_STATUS_BLOCK IoStatusBlock;
    WCHAR FileNameBuffer[1024] = L"\\??\\";
    OBJECT_ATTRIBUTES ObjectAttributes;

    wcscat_s(FileNameBuffer, sizeof(FileNameBuffer)/sizeof(WCHAR), FileName);
    RtlInitUnicodeString(&FileNameU, FileNameBuffer);
    InitializeObjectAttributes(&ObjectAttributes, &FileNameU,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    return NtCreateFile(File, GENERIC_WRITE | SYNCHRONIZE | GENERIC_READ,
			&ObjectAttributes, &IoStatusBlock, 0, FILE_ATTRIBUTE_NORMAL, 0,
			Write ? (Overwrite ? FILE_OVERWRITE_IF : FILE_OPEN_IF) : FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
}

NTSTATUS WriteFile(HANDLE File, LPVOID Data, DWORD BufferSize, DWORD *SizeWritten)
{
    IO_STATUS_BLOCK IoStatus = {};
    NTSTATUS Status = NtWriteFile(File, NULL, NULL, NULL, &IoStatus, Data,
				  BufferSize, NULL, NULL);
    if (SizeWritten) {
	*SizeWritten = IoStatus.Information;
    }
    return Status;
}

NTSTATUS CopyFile(WCHAR *Src, WCHAR *Dest)
{
    HANDLE SrcFile = NULL;
    HANDLE DestFile = NULL;
    BYTE Data[8192];
    LONGLONG FileSize = 0;
    LONGLONG TotalSizeWritten = 0;
    DWORD SizeRead = 0;
    DWORD SizeWritten = 0;
    NTSTATUS Status = 0;

    Status = OpenFile(&SrcFile, Src, FALSE, FALSE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Status = OpenFile(&DestFile, Dest, TRUE, TRUE);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    Status = GetFileSize(SrcFile, &FileSize);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    TotalSizeWritten = 0;
    while (TotalSizeWritten < FileSize) {
	SizeRead = 0;

	Status = ReadFile(SrcFile, Data, sizeof(Data), &SizeRead);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}

        Status = WriteFile(DestFile, Data, SizeRead, &SizeWritten);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}

	if (SizeRead != SizeWritten) {
	    Status = STATUS_IO_DEVICE_ERROR;
	    goto out;
	}

	TotalSizeWritten += SizeWritten;
    }
    Status = STATUS_SUCCESS;

out:
    CloseFile(SrcFile);
    CloseFile(DestFile);

    return Status;
}

NTSTATUS ReadFile(HANDLE File, LPVOID OutBuffer,
		  DWORD BufferSize, DWORD *ReturnedLength)
{
    IO_STATUS_BLOCK IoStatus = {};
    NTSTATUS Status = NtReadFile(File, NULL, NULL, NULL, &IoStatus, OutBuffer,
				 BufferSize, NULL, NULL);
    if (ReturnedLength) {
	*ReturnedLength = IoStatus.Information;
    }
    return Status;
}

NTSTATUS GetFilePosition(HANDLE File, LONGLONG *CurrentPosition)
{
    IO_STATUS_BLOCK IoStatus = {};
    FILE_POSITION_INFORMATION FilePositionInfo = {};
    NTSTATUS Status = NtQueryInformationFile(File, &IoStatus, &FilePositionInfo,
					     sizeof(FILE_POSITION_INFORMATION),
					     FilePositionInformation);
    if (NT_SUCCESS(Status) && CurrentPosition) {
	*CurrentPosition = FilePositionInfo.CurrentByteOffset.QuadPart;
    }
    return Status;
}

NTSTATUS GetFileSize(HANDLE File, LONGLONG *FileSize)
{
    IO_STATUS_BLOCK IoStatus = {};
    FILE_STANDARD_INFORMATION FileInfo = {};
    NTSTATUS Status = NtQueryInformationFile(File, &IoStatus, &FileInfo,
					     sizeof(FILE_STANDARD_INFORMATION),
					     FileStandardInformation);
    if (NT_SUCCESS(Status) && FileSize) {
	*FileSize = FileInfo.EndOfFile.QuadPart;
    }
    return Status;
}

NTSTATUS SeekFile(HANDLE File, LONGLONG Offset)
{
    IO_STATUS_BLOCK IoStatus = {};
    FILE_POSITION_INFORMATION FilePosition = {
	.CurrentByteOffset.QuadPart = Offset
    };
    return NtSetInformationFile(File, &IoStatus, &FilePosition,
				sizeof(FILE_POSITION_INFORMATION),
				FilePositionInformation);
}

VOID CloseFile(HANDLE File)
{
    if (File) {
	NtClose(File);
    }
}

// FileName - full path in DOS format
NTSTATUS DeleteFile(PCWSTR FileName)
{
    UNICODE_STRING FileNameU;
    NTSTATUS Status = RtlDosPathNameToNtPathName_U_WithStatus(FileName, &FileNameU, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    OBJECT_ATTRIBUTES ObjAttr;
    InitializeObjectAttributes(&ObjAttr, &FileNameU, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtDeleteFile(&ObjAttr);
    RtlFreeUnicodeString(&FileNameU);
    return Status;
}

NTSTATUS CreateDirectory(PCWSTR DirName)
{
    UNICODE_STRING DirNameU;
    NTSTATUS Status = RtlDosPathNameToNtPathName_U_WithStatus(DirName, &DirNameU, NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    HANDLE File = NULL;
    OBJECT_ATTRIBUTES ObjAttr;
    IO_STATUS_BLOCK IoStatus;
    InitializeObjectAttributes(&ObjAttr, &DirNameU, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = NtCreateFile(&File,
			  FILE_LIST_DIRECTORY | SYNCHRONIZE | FILE_OPEN_FOR_BACKUP_INTENT,
			  &ObjAttr, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL,
			  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE,
			  FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE,  NULL, 0);
    RtlFreeUnicodeString(&DirNameU);
    if (File) {
	NtClose(File);
    }
    return Status;
}

/*
 * ExistingFileName - full path in DOS format
 * NewFileName - full path in DOS format, or filename
 */
NTSTATUS MoveFile(IN LPCWSTR ExistingFileName, IN LPCWSTR NewFileName,
		  BOOLEAN ReplaceIfExists)
{
    WCHAR NewFileNameBuffer[MAX_PATH] = L"\\??\\";

    if (!ExistingFileName || !NewFileName) {
	return STATUS_OBJECT_NAME_INVALID;
    }

    UNICODE_STRING ExistingFileNameU = {};
    NTSTATUS Status = RtlDosPathNameToNtPathName_U_WithStatus(ExistingFileName,
							      &ExistingFileNameU,
							      NULL, NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    if ((wcslen(NewFileName) > 2) && L':' == NewFileName[1]) {
	wcsncat_s(NewFileNameBuffer, sizeof(NewFileNameBuffer)/sizeof(WCHAR),
		  NewFileName, MAX_PATH);
    } else {
	wcsncpy_s(NewFileNameBuffer, sizeof(NewFileNameBuffer)/sizeof(WCHAR),
		  NewFileName, MAX_PATH);
    }

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &ExistingFileNameU,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatusBlock = {};
    HANDLE FileHandle = NULL;
    Status = NtCreateFile(&FileHandle, FILE_ALL_ACCESS, &ObjectAttributes,
			  &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
			  FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
			  FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    DWORD FileNameSize = wcslen(NewFileNameBuffer) * sizeof(WCHAR);
    PFILE_RENAME_INFORMATION FileRenameInfo =
	RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
			sizeof(FILE_RENAME_INFORMATION) + FileNameSize);

    if (!FileRenameInfo) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    FileRenameInfo->RootDirectory = NULL;
    FileRenameInfo->ReplaceIfExists = ReplaceIfExists;
    FileRenameInfo->FileNameLength = FileNameSize;
    RtlCopyMemory(FileRenameInfo->FileName, NewFileNameBuffer, FileNameSize);

    Status = NtSetInformationFile(FileHandle,
				  &IoStatusBlock,
				  FileRenameInfo,
				  sizeof(FILE_RENAME_INFORMATION) +
				  FileNameSize, FileRenameInformation);

    RtlFreeHeap(RtlGetProcessHeap(), 0, FileRenameInfo);

out:
    RtlFreeUnicodeString(&ExistingFileNameU);
    CloseFile(FileHandle);
    return Status;
}

NTSTATUS FlushBuffers(IN PCSTR Drive)
{
    HANDLE Volume = NULL;
    WCHAR Buffer[16];
    _snwprintf(Buffer, sizeof(Buffer)/sizeof(WCHAR), L"%s:", Drive);
    NTSTATUS Status = OpenFile(&Volume, Buffer, FALSE, FALSE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    IO_STATUS_BLOCK IoStatus;
    return NtFlushBuffersFile(Volume, &IoStatus);
}
