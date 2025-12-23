#include "umtests.h"

NTSTATUS OpenVolume(IN PCSTR Path,
		    OUT HANDLE *Handle)
{
    OBJECT_ATTRIBUTES_ANSI ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, Path,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK IoStatus;
    return NtOpenFileA(Handle,
		       GENERIC_READ | SYNCHRONIZE,
		       &ObjectAttributes,
		       &IoStatus,
		       FILE_SHARE_READ | FILE_SHARE_WRITE,
		       FILE_NO_INTERMEDIATE_BUFFERING |
		       FILE_SYNCHRONOUS_IO_NONALERT |
		       FILE_NON_DIRECTORY_FILE);
}

NTSTATUS ReadFile(IN HANDLE Handle,
		  OUT PVOID Buffer,
		  IN ULONG Length,
		  IN ULONGLONG Offset)
{
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER FileOffset = { .QuadPart = Offset };

    return NtReadFile(Handle, NULL, NULL, NULL, &IoStatus,
		      Buffer, Length, &FileOffset, NULL);
}

NTSTATUS GetFileSize(IN HANDLE FileHandle,
		     OUT ULONGLONG *FileSize)
{
    IO_STATUS_BLOCK IoStatus;
    FILE_STANDARD_INFORMATION StandardInfo;

    NTSTATUS Status = NtQueryInformationFile(FileHandle,
					     &IoStatus,
					     &StandardInfo,
					     sizeof(StandardInfo),
					     FileStandardInformation);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // EndOfFile is the usable length in bytes
    *FileSize = StandardInfo.EndOfFile.QuadPart;
    return STATUS_SUCCESS;
}
