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

/*
 * Flag manipulation macros
 */
#define BooleanFlagOn(Flags, SingleFlag)    ((BOOLEAN)((((Flags) & (SingleFlag)) != 0)))
#define SetFlag(Flags, SetOfFlags)	    ((Flags) |= (SetOfFlags))
#define ClearFlag(Flags, SetOfFlags)	    ((Flags) &= ~(SetOfFlags))
