#include "k32.h"

#define NDEBUG
#include <debug.h>

#undef FIXME
#define FIXME DPRINT1

/* Taken from Wine kernel32/file.c */

/***********************************************************************
 *	GetFileInformationByHandleEx   (kernelbase.@)
 */
BOOL WINAPI DECLSPEC_HOTPATCH GetFileInformationByHandleEx(HANDLE Handle,
							   FILE_INFO_BY_HANDLE_CLASS Class,
							   LPVOID Info,
							   DWORD Size)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK Io;

    switch (Class) {
    case FileRemoteProtocolInfo:
    case FileStorageInfo:
    case FileDispositionInfoEx:
    case FileRenameInfoEx:
    case FileCaseSensitiveInfo:
    case FileNormalizedNameInfo:
	FIXME("%p, %u, %p, %lu\n", Handle, Class, Info, Size);
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;

    case FileStreamInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size, FileStreamInformation);
	break;

    case FileCompressionInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size,
					FileCompressionInformation);
	break;

    case FileAlignmentInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size,
					FileAlignmentInformation);
	break;

    case FileAttributeTagInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size,
					FileAttributeTagInformation);
	break;

    case FileBasicInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size, FileBasicInformation);
	break;

    case FileStandardInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size, FileStandardInformation);
	break;

    case FileNameInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size, FileNameInformation);
	break;

    case FileIdInfo:
	Status = NtQueryInformationFile(Handle, &Io, Info, Size, FileIdInformation);
	break;

    case FileIdBothDirectoryRestartInfo:
    case FileIdBothDirectoryInfo:
	Status = NtQueryDirectoryFile(Handle, NULL, NULL, NULL, &Io, Info, Size,
				      FileIdBothDirectoryInformation, FALSE, NULL,
				      (Class == FileIdBothDirectoryRestartInfo));
	break;

    case FileFullDirectoryInfo:
    case FileFullDirectoryRestartInfo:
	Status = NtQueryDirectoryFile(Handle, NULL, NULL, NULL, &Io, Info, Size,
				      FileFullDirectoryInformation, FALSE, NULL,
				      (Class == FileFullDirectoryRestartInfo));
	break;

    case FileIdExtdDirectoryInfo:
    case FileIdExtdDirectoryRestartInfo:
	Status = NtQueryDirectoryFile(Handle, NULL, NULL, NULL, &Io, Info, Size,
				      FileIdExtdDirectoryInformation, FALSE, NULL,
				      (Class == FileIdExtdDirectoryRestartInfo));
	break;

    case FileRenameInfo:
    case FileDispositionInfo:
    case FileAllocationInfo:
    case FileIoPriorityHintInfo:
    case FileEndOfFileInfo:
    default:
	SetLastError(ERROR_INVALID_PARAMETER);
	return FALSE;
    }

    if (!NT_SUCCESS(status)) {
	SetLastError(RtlNtStatusToDosError(status));
	return FALSE;
    }

    return TRUE;
}
