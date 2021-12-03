/*++

Copyright (c) Alex Ionescu.  All rights reserved.
Copyright (c) 2011 amdf.

    THIS CODE AND INFORMATION IS PROVIDED UNDER THE LESSER GNU PUBLIC LICENSE.
    PLEASE READ THE FILE "COPYING" IN THE TOP LEVEL DIRECTORY.

Module Name:

    file.c

Abstract:

    The Native Command Line Interface (NCLI) is the command shell for the
    TinyKRNL OS.
    This module implements commands for dealing with files and directories.

Environment:

    Native

Revision History:

    Alex Ionescu - Started Implementation - 23-Mar-06
    amdf - changed RtlCliSetCurrentDirectory - 20-Feb-11

--*/
#include "precomp.h"

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
    WCHAR buf[MAX_PATH];
    UNICODE_STRING us;

    if (NULL == Directory) {
	return STATUS_UNSUCCESSFUL;
    }
    // Full path contains at least two symbols, the second is ':'
    if (strnlen(Directory, MAX_PATH) >= 2 && Directory[1] == ':') {
	RtlCreateUnicodeStringFromAsciiz(&us, Directory);
	RtlSetCurrentDirectory_U(&us);
	RtlFreeUnicodeString(&us);
	return STATUS_SUCCESS;
    }

    GetFullPath(Directory, buf, sizeof(buf), TRUE);
    RtlInitUnicodeString(&us, buf);
    RtlSetCurrentDirectory_U(&us);
    RtlFreeUnicodeString(&us);

    return STATUS_SUCCESS;
}

/*++
 * @name RtlCliDumpFileInfo
 *
 * The RtlCliDumpFileInfo routine FILLMEIN
 *
 * @param DirInfo
 *        FILLMEIN
 *
 * @return None.
 *
 * @remarks Documentation for this routine needs to be completed.
 *
 *--*/
VOID RtlCliDumpFileInfo(PFILE_BOTH_DIR_INFORMATION DirInfo)
{
    PWCHAR Null;
    WCHAR Save;
    TIME_FIELDS Time;
    CHAR SizeString[16];
    WCHAR ShortString[12 + 1];
    WCHAR FileString[MAX_PATH + 1];

    WCHAR FileStringSize[100];
    WCHAR ShortStringSize[100];

    UINT file_size = 0;
    UINT short_size = 0;

    //
    // The filename isn't null-terminated, and the next structure follows
    // right after it. So, we save the next char (which ends up being the
    // NextEntryOffset of the next structure), then temporarly clear it so
    // that the RtlCliDisplayString can treat it as a null-terminated string
    //
    Null = (PWCHAR) ((PBYTE) DirInfo->FileName + DirInfo->FileNameLength);
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

    file_size = DirInfo->FileNameLength / sizeof(WCHAR);
    short_size = DirInfo->ShortNameLength / sizeof(WCHAR);

    _snwprintf(ShortStringSize, sizeof(ShortStringSize)/sizeof(WCHAR), L"%d", short_size);
    _snwprintf(FileStringSize, sizeof(FileStringSize)/sizeof(WCHAR), L"%d", file_size);

    if (DirInfo->ShortNameLength) {
	memset(ShortString, 0x00, (12 + 1) * sizeof(WCHAR));
	wcsncpy_s(ShortString, sizeof(ShortString)/sizeof(WCHAR), DirInfo->ShortName, short_size);
    } else {
	_snwprintf(ShortString, sizeof(ShortString)/sizeof(WCHAR), L" ");
    }

    if (DirInfo->FileNameLength) {
	memset(FileString, 0x00, (MAX_PATH + 1) * sizeof(WCHAR));
	wcsncpy_s(FileString, sizeof(FileString)/sizeof(WCHAR), DirInfo->FileName, file_size);
    } else {
	_snwprintf(FileString, sizeof(FileString)/sizeof(WCHAR), L" ");
    }

    RtlCliDisplayString("%02d.%02d.%04d %02d:%02d %s %9s %-28S %12S\n",
			Time.Day,
			Time.Month,
			Time.Year,
			Time.Hour,
			Time.Minute,
			DirInfo->
			FileAttributes & FILE_ATTRIBUTE_DIRECTORY ? "<DIR>"
			: "     ", SizeString, FileString, ShortString);

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
    NTSTATUS Status;
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
    if (!RtlDosPathNameToNtPathName_U(CurrentDirectory,
				      &DirectoryString, NULL, NULL)) {
	//
	// Fail
	//
	return STATUS_UNSUCCESSFUL;
    }
    //
    // Initialize the object attributes
    //
    RtlCliDisplayString(" Directory of %S\n\n", CurrentDirectory);
    InitializeObjectAttributes(&ObjectAttributes,
			       &DirectoryString,
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
		RtlCliDisplayString("Continue listing (Y/N):");
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
	    Entry = (PFILE_BOTH_DIR_INFORMATION) ((ULONG_PTR) Entry +
						  Entry->NextEntryOffset);
	}

	//
	// This isn't the first scan anymore
	//
	FirstQuery = FALSE;
    }
}
