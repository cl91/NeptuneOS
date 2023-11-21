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
NTAPI NTSYSAPI VOID IoRegisterFileSystem(IN PDEVICE_OBJECT DeviceObject);

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
NTAPI NTSYSAPI VOID IoSetShareAccess(IN ACCESS_MASK DesiredAccess,
				     IN ULONG DesiredShareAccess,
				     IN OUT PFILE_OBJECT FileObject,
				     OUT PSHARE_ACCESS ShareAccess);
NTAPI NTSYSAPI NTSTATUS IoCheckShareAccess(IN ACCESS_MASK DesiredAccess,
					   IN ULONG DesiredShareAccess,
					   IN OUT PFILE_OBJECT FileObject,
					   IN OUT PSHARE_ACCESS ShareAccess,
					   IN BOOLEAN Update);
NTAPI NTSYSAPI VOID IoUpdateShareAccess(IN PFILE_OBJECT FileObject,
					IN OUT PSHARE_ACCESS ShareAccess);
NTAPI NTSYSAPI VOID IoRemoveShareAccess(IN PFILE_OBJECT FileObject,
					IN OUT PSHARE_ACCESS ShareAccess);

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
FORCEINLINE NTAPI VOID FsRtlNotifyCleanup(IN PFILE_OBJECT File) { /* TODO */ }
FORCEINLINE NTAPI NTSTATUS FsRtlNotifyVolumeEvent(IN PFILE_OBJECT FileObject,
						  IN ULONG EventCode) {
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

#define MAP_WAIT                        1
#define MAP_NO_READ                     (16)
#define MAP_HIGH_PRIORITY               (64)

/*
 * Cache Manager Routines
 */
NTAPI NTSYSAPI VOID CcInitializeCacheMap(IN PFILE_OBJECT FileObject,
					 IN PCC_FILE_SIZES FileSizes,
					 IN BOOLEAN PinAccess,
					 IN PVOID LazyWriteContext);
NTAPI NTSYSAPI BOOLEAN CcUninitializeCacheMap(IN PFILE_OBJECT FileObject,
					      IN OPTIONAL PLARGE_INTEGER TruncateSize);
NTAPI NTSYSAPI BOOLEAN CcMapData(IN PFILE_OBJECT FileObject,
				 IN PLARGE_INTEGER FileOffset,
				 IN ULONG Length,
				 IN ULONG Flags,
				 OUT PVOID *Bcb,
				 OUT PVOID *Buffer);
NTAPI NTSYSAPI BOOLEAN CcPinRead(IN PFILE_OBJECT FileObject,
				 IN PLARGE_INTEGER FileOffset,
				 IN ULONG Length,
				 IN ULONG Flags,
				 OUT PVOID *Bcb,
				 OUT PVOID *Buffer);
NTAPI NTSYSAPI VOID CcSetDirtyPinnedData(IN PVOID BcbVoid,
					 IN OPTIONAL PLARGE_INTEGER Lsn);
NTAPI NTSYSAPI VOID CcUnpinData(IN PVOID Bcb);
NTAPI NTSYSAPI BOOLEAN CcZeroData(IN PFILE_OBJECT FileObject,
				  IN PLARGE_INTEGER StartOffset,
				  IN PLARGE_INTEGER EndOffset,
				  IN BOOLEAN Wait);
NTAPI NTSYSAPI VOID CcSetFileSizes(IN PFILE_OBJECT FileObject,
				   IN PCC_FILE_SIZES FileSizes);
NTAPI NTSYSAPI VOID CcFlushCache(IN PFSRTL_COMMON_FCB_HEADER Fcb,
				 IN OPTIONAL PLARGE_INTEGER FileOffset,
				 IN ULONG Length,
				 OUT OPTIONAL PIO_STATUS_BLOCK IoStatus);
