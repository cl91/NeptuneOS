#pragma once

#include <wdm.h>

typedef struct _FILESYSTEM_STATISTICS {
    USHORT FileSystemType;
    USHORT Version;
    ULONG SizeOfCompleteStructure;
    ULONG UserFileReads;
    ULONG UserFileReadBytes;
    ULONG UserDiskReads;
    ULONG UserFileWrites;
    ULONG UserFileWriteBytes;
    ULONG UserDiskWrites;
    ULONG MetaDataReads;
    ULONG MetaDataReadBytes;
    ULONG MetaDataDiskReads;
    ULONG MetaDataWrites;
    ULONG MetaDataWriteBytes;
    ULONG MetaDataDiskWrites;
} FILESYSTEM_STATISTICS, *PFILESYSTEM_STATISTICS;

#define FILESYSTEM_STATISTICS_TYPE_NTFS     1
#define FILESYSTEM_STATISTICS_TYPE_FAT      2
#define FILESYSTEM_STATISTICS_TYPE_EXFAT    3

typedef struct _FAT_STATISTICS {
    ULONG CreateHits;
    ULONG SuccessfulCreates;
    ULONG FailedCreates;
    ULONG NonCachedReads;
    ULONG NonCachedReadBytes;
    ULONG NonCachedWrites;
    ULONG NonCachedWriteBytes;
    ULONG NonCachedDiskReads;
    ULONG NonCachedDiskWrites;
} FAT_STATISTICS, *PFAT_STATISTICS;

typedef struct _EXFAT_STATISTICS {
    ULONG CreateHits;
    ULONG SuccessfulCreates;
    ULONG FailedCreates;
    ULONG NonCachedReads;
    ULONG NonCachedReadBytes;
    ULONG NonCachedWrites;
    ULONG NonCachedWriteBytes;
    ULONG NonCachedDiskReads;
    ULONG NonCachedDiskWrites;
} EXFAT_STATISTICS, *PEXFAT_STATISTICS;

typedef struct _NTFS_STATISTICS {
    ULONG LogFileFullExceptions;
    ULONG OtherExceptions;
    ULONG MftReads;
    ULONG MftReadBytes;
    ULONG MftWrites;
    ULONG MftWriteBytes;
    struct {
	USHORT Write;
	USHORT Create;
	USHORT SetInfo;
	USHORT Flush;
    } MftWritesUserLevel;
    USHORT MftWritesFlushForLogFileFull;
    USHORT MftWritesLazyWriter;
    USHORT MftWritesUserRequest;
    ULONG Mft2Writes;
    ULONG Mft2WriteBytes;
    struct {
	USHORT Write;
	USHORT Create;
	USHORT SetInfo;
	USHORT Flush;
    } Mft2WritesUserLevel;
    USHORT Mft2WritesFlushForLogFileFull;
    USHORT Mft2WritesLazyWriter;
    USHORT Mft2WritesUserRequest;
    ULONG RootIndexReads;
    ULONG RootIndexReadBytes;
    ULONG RootIndexWrites;
    ULONG RootIndexWriteBytes;
    ULONG BitmapReads;
    ULONG BitmapReadBytes;
    ULONG BitmapWrites;
    ULONG BitmapWriteBytes;
    USHORT BitmapWritesFlushForLogFileFull;
    USHORT BitmapWritesLazyWriter;
    USHORT BitmapWritesUserRequest;
    struct {
	USHORT Write;
	USHORT Create;
	USHORT SetInfo;
    } BitmapWritesUserLevel;
    ULONG MftBitmapReads;
    ULONG MftBitmapReadBytes;
    ULONG MftBitmapWrites;
    ULONG MftBitmapWriteBytes;
    USHORT MftBitmapWritesFlushForLogFileFull;
    USHORT MftBitmapWritesLazyWriter;
    USHORT MftBitmapWritesUserRequest;
    struct {
	USHORT Write;
	USHORT Create;
	USHORT SetInfo;
	USHORT Flush;
    } MftBitmapWritesUserLevel;
    ULONG UserIndexReads;
    ULONG UserIndexReadBytes;
    ULONG UserIndexWrites;
    ULONG UserIndexWriteBytes;
    ULONG LogFileReads;
    ULONG LogFileReadBytes;
    ULONG LogFileWrites;
    ULONG LogFileWriteBytes;
    struct {
	ULONG Calls;
	ULONG Clusters;
	ULONG Hints;
	ULONG RunsReturned;
	ULONG HintsHonored;
	ULONG HintsClusters;
	ULONG Cache;
	ULONG CacheClusters;
	ULONG CacheMiss;
	ULONG CacheMissClusters;
    } Allocate;
} NTFS_STATISTICS, *PNTFS_STATISTICS;

typedef struct _STARTING_VCN_INPUT_BUFFER {
    LARGE_INTEGER StartingVcn;
} STARTING_VCN_INPUT_BUFFER, *PSTARTING_VCN_INPUT_BUFFER;

typedef struct _RETRIEVAL_POINTERS_BUFFER {
    ULONG ExtentCount;
    LARGE_INTEGER StartingVcn;
    struct {
	LARGE_INTEGER NextVcn;
	LARGE_INTEGER Lcn;
    } Extents[];
} RETRIEVAL_POINTERS_BUFFER, *PRETRIEVAL_POINTERS_BUFFER;

/*
 * Flag manipulation macros
 */
#define FlagOn(_F,_SF)                      ((_F) & (_SF))
#define BooleanFlagOn(Flags, SingleFlag)    ((BOOLEAN)((((Flags) & (SingleFlag)) != 0)))
#define SetFlag(Flags, SetOfFlags)	    ((Flags) |= (SetOfFlags))
#define ClearFlag(Flags, SetOfFlags)	    ((Flags) &= ~(SetOfFlags))

/*
 * File System Registration Routine
 */
NTAPI NTSYSAPI NTSTATUS IoRegisterFileSystem(IN PDEVICE_OBJECT DeviceObject);

/*
 * Stream File Object Creation Routine
 */
NTAPI NTSYSAPI PFILE_OBJECT IoCreateStreamFileObject(IN PDEVICE_OBJECT DeviceObject);

/*
 * Access Control Types
 */
typedef struct _SHARE_ACCESS {
    ULONG OpenCount;
    ULONG Readers;
    ULONG Writers;
    ULONG Deleters;
    ULONG SharedRead;
    ULONG SharedWrite;
    ULONG SharedDelete;
} SHARE_ACCESS, *PSHARE_ACCESS;

/*
 * Access Control Routines
 */
FORCEINLINE NTAPI VOID IoSetShareAccess(IN ACCESS_MASK DesiredAccess,
					IN ULONG DesiredShareAccess,
					IN OUT PFILE_OBJECT FileObject,
					OUT PSHARE_ACCESS ShareAccess)
{
    BOOLEAN ReadAccess = DesiredAccess & (FILE_READ_DATA | FILE_EXECUTE);
    BOOLEAN WriteAccess = DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA);
    BOOLEAN DeleteAccess = DesiredAccess & DELETE;

    /* Update basic access */
    FileObject->ReadAccess = ReadAccess;
    FileObject->WriteAccess = WriteAccess;
    FileObject->DeleteAccess = DeleteAccess;

    /* Check if we have no access as all */
    if (!ReadAccess && !WriteAccess && !DeleteAccess) {
        ShareAccess->OpenCount = 0;
        ShareAccess->Readers = 0;
        ShareAccess->Writers = 0;
        ShareAccess->Deleters = 0;
        ShareAccess->SharedRead = 0;
        ShareAccess->SharedWrite = 0;
        ShareAccess->SharedDelete = 0;
    } else {
        BOOLEAN SharedRead = DesiredShareAccess & FILE_SHARE_READ;
        BOOLEAN SharedWrite = DesiredShareAccess & FILE_SHARE_WRITE;
        BOOLEAN SharedDelete = DesiredShareAccess & FILE_SHARE_DELETE;

        FileObject->SharedRead = SharedRead;
        FileObject->SharedWrite = SharedWrite;
        FileObject->SharedDelete = SharedDelete;

        ShareAccess->OpenCount = 1;
        ShareAccess->Readers = ReadAccess;
        ShareAccess->Writers = WriteAccess;
        ShareAccess->Deleters = DeleteAccess;
        ShareAccess->SharedRead = SharedRead;
        ShareAccess->SharedWrite = SharedWrite;
        ShareAccess->SharedDelete = SharedDelete;
    }
}

FORCEINLINE NTAPI NTSTATUS IoCheckShareAccess(IN ACCESS_MASK DesiredAccess,
					      IN ULONG DesiredShareAccess,
					      IN OUT PFILE_OBJECT FileObject,
					      IN OUT PSHARE_ACCESS ShareAccess,
					      IN BOOLEAN Update)
{
    BOOLEAN ReadAccess = DesiredAccess & (FILE_READ_DATA | FILE_EXECUTE);
    BOOLEAN WriteAccess = DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA);
    BOOLEAN DeleteAccess = DesiredAccess & DELETE;

    FileObject->ReadAccess = ReadAccess;
    FileObject->WriteAccess = WriteAccess;
    FileObject->DeleteAccess = DeleteAccess;

    /* Check if we have any access */
    if (ReadAccess || WriteAccess || DeleteAccess) {
        /* Get shared access masks */
        BOOLEAN SharedRead = DesiredShareAccess & FILE_SHARE_READ;
        BOOLEAN SharedWrite = DesiredShareAccess & FILE_SHARE_WRITE;
        BOOLEAN SharedDelete = DesiredShareAccess & FILE_SHARE_DELETE;

        /* Check if the shared access is violated */
        if ((ReadAccess && (ShareAccess->SharedRead < ShareAccess->OpenCount)) ||
            (WriteAccess && (ShareAccess->SharedWrite < ShareAccess->OpenCount)) ||
            (DeleteAccess && (ShareAccess->SharedDelete < ShareAccess->OpenCount)) ||
            (ShareAccess->Readers && !SharedRead) ||
            (ShareAccess->Writers && !SharedWrite) ||
            (ShareAccess->Deleters && !SharedDelete)) {
            /* Sharing violation, fail */
            return STATUS_SHARING_VIOLATION;
        }

        /* Set them */
        FileObject->SharedRead = SharedRead;
        FileObject->SharedWrite = SharedWrite;
        FileObject->SharedDelete = SharedDelete;

        /* It's not, check if caller wants us to update it */
        if (Update) {
            ShareAccess->OpenCount++;

            ShareAccess->Readers += ReadAccess;
            ShareAccess->Writers += WriteAccess;
            ShareAccess->Deleters += DeleteAccess;
            ShareAccess->SharedRead += SharedRead;
            ShareAccess->SharedWrite += SharedWrite;
            ShareAccess->SharedDelete += SharedDelete;
        }
    }
    return STATUS_SUCCESS;
}

FORCEINLINE NTAPI VOID IoUpdateShareAccess(IN PFILE_OBJECT FileObject,
					   IN OUT PSHARE_ACCESS ShareAccess)
{
    if (FileObject->ReadAccess || FileObject->WriteAccess || FileObject->DeleteAccess) {
        ShareAccess->OpenCount++;

        ShareAccess->Readers += FileObject->ReadAccess;
        ShareAccess->Writers += FileObject->WriteAccess;
        ShareAccess->Deleters += FileObject->DeleteAccess;
        ShareAccess->SharedRead += FileObject->SharedRead;
        ShareAccess->SharedWrite += FileObject->SharedWrite;
        ShareAccess->SharedDelete += FileObject->SharedDelete;
    }
}

FORCEINLINE NTAPI VOID IoRemoveShareAccess(IN PFILE_OBJECT FileObject,
					   IN OUT PSHARE_ACCESS ShareAccess)
{
    if (FileObject->ReadAccess || FileObject->WriteAccess || FileObject->DeleteAccess) {
        ShareAccess->OpenCount--;

        ShareAccess->Readers -= FileObject->ReadAccess;
        ShareAccess->Writers -= FileObject->WriteAccess;
        ShareAccess->Deleters -= FileObject->DeleteAccess;
        ShareAccess->SharedRead -= FileObject->SharedRead;
        ShareAccess->SharedWrite -= FileObject->SharedWrite;
        ShareAccess->SharedDelete -= FileObject->SharedDelete;
    }
}

/*
 * Common FCB Header
 */
typedef struct _FSRTL_COMMON_FCB_HEADER {
    CSHORT NodeTypeCode;
    CSHORT NodeByteSize;
    UCHAR Flags;
    UCHAR IsFastIoPossible;
    UCHAR Flags2;
    UCHAR Reserved : 4;
    UCHAR Version : 4;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER ValidDataLength;
} FSRTL_COMMON_FCB_HEADER, *PFSRTL_COMMON_FCB_HEADER;

/*
 * File Name Helper Routines
 */
NTAPI NTSYSAPI BOOLEAN FsRtlAreNamesEqual(IN PCUNICODE_STRING Name1,
					  IN PCUNICODE_STRING Name2,
					  IN BOOLEAN IgnoreCase,
					  IN OPTIONAL PCWCH UpcaseTable);
NTAPI NTSYSAPI BOOLEAN FsRtlDoesNameContainWildCards(IN PUNICODE_STRING Name);
NTAPI NTSYSAPI BOOLEAN FsRtlIsNameInExpression(IN PUNICODE_STRING Expression,
					       IN PUNICODE_STRING Name,
					       IN BOOLEAN IgnoreCase,
					       IN OPTIONAL PWCHAR UpcaseTable);

/*
 * File Notification Event Code
 */
#define FSRTL_VOLUME_DISMOUNT           1
#define FSRTL_VOLUME_DISMOUNT_FAILED    2
#define FSRTL_VOLUME_LOCK               3
#define FSRTL_VOLUME_LOCK_FAILED        4
#define FSRTL_VOLUME_UNLOCK             5
#define FSRTL_VOLUME_MOUNT              6
#define FSRTL_VOLUME_NEEDS_CHKDSK       7
#define FSRTL_VOLUME_WORM_NEAR_FULL     8
#define FSRTL_VOLUME_WEARING_OUT        9
#define FSRTL_VOLUME_FORCED_CLOSED      10
#define FSRTL_VOLUME_INFO_MAKE_COMPAT   11
#define FSRTL_VOLUME_PREPARING_EJECT    12
#define FSRTL_VOLUME_CHANGE_SIZE        13
#define FSRTL_VOLUME_BACKGROUND_FORMAT  14

/*
 * File Notification Routines
 */
FORCEINLINE NTAPI NTAPI VOID FsRtlNotifyCleanup(IN PFILE_OBJECT File) { /* TODO */ }
FORCEINLINE NTAPI NTAPI NTSTATUS FsRtlNotifyVolumeEvent(IN PFILE_OBJECT FileObject,
							IN ULONG EventCode)
{
    /* TODO */
    return 0;
}

/*
 * Cache Manager Types
 */
typedef struct _CC_FILE_SIZES {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER ValidDataLength;
} CC_FILE_SIZES, *PCC_FILE_SIZES;

#define PIN_WAIT                        (1)
#define PIN_EXCLUSIVE                   (2)
#define PIN_NO_READ                     (4)
#define PIN_IF_BCB                      (8)
#define PIN_CALLER_TRACKS_DIRTY_DATA    (32)
#define PIN_HIGH_PRIORITY               (64)

/* These must be defined to be the same flags used in the CcPinRead
 * interface, since CcMapData is now synonymous with CcPinRead. */
#define MAP_WAIT                        (PIN_WAIT)
#define MAP_NO_READ                     (PIN_NO_READ)
#define MAP_HIGH_PRIORITY               (PIN_HIGH_PRIORITY)

/*
 * Cache Manager Routines
 */
NTAPI NTSYSAPI NTSTATUS CcInitializeCacheMap(IN PFILE_OBJECT FileObject,
					     IN PCC_FILE_SIZES FileSizes,
					     IN BOOLEAN PinAccess,
					     IN PVOID LazyWriteContext);
NTAPI NTSYSAPI BOOLEAN CcUninitializeCacheMap(IN PFILE_OBJECT FileObject,
					      IN OPTIONAL PLARGE_INTEGER TruncateSize);
NTAPI NTSYSAPI NTSTATUS CcPinRead(IN PFILE_OBJECT FileObject,
				  IN PLARGE_INTEGER FileOffset,
				  IN ULONG Length,
				  IN ULONG Flags,
				  OUT PVOID *Bcb,
				  OUT PVOID *Buffer);
NTAPI NTSYSAPI VOID CcSetDirtyPinnedData(IN PVOID BcbVoid,
					 IN OPTIONAL PLARGE_INTEGER Lsn);
NTAPI NTSYSAPI VOID CcUnpinData(IN PVOID Bcb);
NTAPI NTSYSAPI NTSTATUS CcZeroData(IN PFILE_OBJECT FileObject,
				   IN PLARGE_INTEGER StartOffset,
				   IN PLARGE_INTEGER EndOffset,
				   IN BOOLEAN Wait);
NTAPI NTSYSAPI VOID CcSetFileSizes(IN PFILE_OBJECT FileObject,
				   IN PCC_FILE_SIZES FileSizes);

/* On Neptune OS, CcMapData is synonymous with CcPinRead. On Windows
 * they are not (CcMapData is a more restrictive function there). */
FORCEINLINE NTAPI NTSTATUS CcMapData(IN PFILE_OBJECT FileObject,
				     IN PLARGE_INTEGER FileOffset,
				     IN ULONG Length,
				     IN ULONG Flags,
				     OUT PVOID *Bcb,
				     OUT PVOID *Buffer)
{
    return CcPinRead(FileObject, FileOffset, Length, Flags, Bcb, Buffer);
}

/* On Neptune OS, CcFlushCache is a no-op. File system drivers do not need
 * to manually flush caches and in general should not do so. */
FORCEINLINE NTAPI VOID CcFlushCache(IN PFSRTL_COMMON_FCB_HEADER Fcb,
				    IN OPTIONAL PLARGE_INTEGER FileOffset,
				    IN ULONG Length,
				    OUT OPTIONAL PIO_STATUS_BLOCK IoStatus) {}
