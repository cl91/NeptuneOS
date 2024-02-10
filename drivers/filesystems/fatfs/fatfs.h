#pragma once

#include <ntifs.h>
#include <ntdddisk.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define ENABLE_SWAPOUT

#define ROUND_DOWN(x, align)	ALIGN_DOWN_BY(x, align)
#define ROUND_DOWN_32(n, align)	(((ULONG)(n)) & ~((align)-1L))
#define ROUND_UP_32(n, align)	ROUND_DOWN_32(((ULONG)(n))+(align)-1, (align))
#define ROUND_DOWN_64(n, align)	(((ULONGLONG)(n)) & ~((align) - 1LL))
#define ROUND_UP_64(n, align)	ROUND_DOWN_64(((ULONGLONG)(n))+(align)-1LL, (align))

/* DOS File Attributes */
#define _A_NORMAL 0x00
#define _A_RDONLY 0x01
#define _A_HIDDEN 0x02
#define _A_SYSTEM 0x04
#define _A_VOLID  0x08
#define _A_SUBDIR 0x10
#define _A_ARCH   0x20

#include <pshpack1.h>
typedef struct _BOOT_SECTOR {
    UCHAR  Magic0, Res0, Magic1;
    UCHAR  OEMName[8];
    USHORT BytesPerSector;
    UCHAR  SectorsPerCluster;
    USHORT ReservedSectors;
    UCHAR  FATCount;
    USHORT RootEntries;
    USHORT Sectors;
    UCHAR  Media;
    USHORT FatSectors;
    USHORT SectorsPerTrack;
    USHORT Heads;
    ULONG  HiddenSectors;
    ULONG  SectorsHuge;
    UCHAR  Drive;
    UCHAR  Res1;
    UCHAR  Sig;
    ULONG  VolumeID;
    UCHAR  VolumeLabel[11];
    UCHAR  SysType[8];
    UCHAR  Res2[448];
    USHORT Signature1;
} BOOT_SECTOR, *PBOOT_SECTOR;

typedef struct _BOOT_SECTOR_FAT32 {
    UCHAR  Magic0, Res0, Magic1;	       // 0
    UCHAR  OEMName[8];			       // 3
    USHORT BytesPerSector;		       // 11
    UCHAR  SectorsPerCluster;		       // 13
    USHORT ReservedSectors;		       // 14
    UCHAR  FATCount;			       // 16
    USHORT RootEntries;			       // 17
    USHORT Sectors;			       // 19
    UCHAR  Media;			       // 21
    USHORT FatSectors;			       // 22
    USHORT SectorsPerTrack;		       // 24
    USHORT Heads;			       // 26
    ULONG  HiddenSectors;		       // 28
    ULONG  SectorsHuge;			       // 32
    ULONG  FatSectors32;		       // 36
    USHORT ExtFlag;			       // 40
    USHORT FSVersion;			       // 42
    ULONG  RootCluster;			       // 44
    USHORT FSInfoSector;		       // 48
    USHORT BootBackup;			       // 50
    UCHAR  Res3[12];			       // 52
    UCHAR  Drive;			       // 64
    UCHAR  Res4;			       // 65
    UCHAR  ExtBootSignature;		       // 66
    ULONG  VolumeID;			       // 67
    UCHAR  VolumeLabel[11];		       // 71
    UCHAR  SysType[8];			       // 82
    UCHAR  Res2[420];			       // 90
    USHORT Signature1;			       // 510
} BOOT_SECTOR_FAT32, *PBOOT_SECTOR_FAT32;

#define FAT_DIRTY_BIT 0x01

typedef struct _BOOT_SECTOR_FATX {
    UCHAR  SysType[4];		// 0
    ULONG  VolumeID;		// 4
    ULONG  SectorsPerCluster;	// 8
    USHORT FATCount;		// 12
    ULONG  Unknown;		// 14
    UCHAR  Unused[4078];	// 18
} BOOT_SECTOR_FATX, *PBOOT_SECTOR_FATX;

typedef struct _FSINFO_SECTOR {
    ULONG ExtBootSignature2;	// 0
    UCHAR Res6[480];		// 4
    ULONG FSINFOSignature;	// 484
    ULONG FreeCluster;		// 488
    ULONG NextCluster;		// 492
    UCHAR Res7[12];		// 496
    ULONG Signatur2;		// 508
} FSINFO_SECTOR, *PFSINFO_SECTOR;

typedef struct _FAT_DIR_ENTRY {
    union {
	struct {
	    UCHAR Filename[8], Ext[3];
	};
	UCHAR ShortName[11];
    };
    UCHAR Attrib;
    UCHAR Case;
    UCHAR CreationTimeMs;
    USHORT CreationTime, CreationDate, AccessDate;
    union {
	USHORT FirstClusterHigh;   // FAT32
	USHORT ExtendedAttributes; // FAT12/FAT16
    };
    USHORT UpdateTime;		// Time Create/Update
    USHORT UpdateDate;		// Date Create/Update
    USHORT FirstCluster;
    ULONG FileSize;
} FAT_DIR_ENTRY, *PFAT_DIR_ENTRY;

typedef struct _FATX_DIR_ENTRY {
    UCHAR FilenameLength;	// 0
    UCHAR Attrib;	// 1
    UCHAR Filename[42];	// 2
    ULONG FirstCluster;	// 44
    ULONG FileSize;	// 48
    USHORT UpdateTime;	// 52
    USHORT UpdateDate;	// 54
    USHORT CreationTime;	// 56
    USHORT CreationDate;	// 58
    USHORT AccessTime;	// 60
    USHORT AccessDate;	// 62
} FATX_DIR_ENTRY, *PFATX_DIR_ENTRY;

typedef union _DIR_ENTRY {
    FAT_DIR_ENTRY Fat;
    FATX_DIR_ENTRY FatX;
} DIR_ENTRY, *PDIR_ENTRY;

#define FAT_EAFILE  "EA DATA. SF"

typedef struct _FAT_EA_FILE_HEADER {
    USHORT Signature;	// ED
    USHORT Unknown[15];
    USHORT EASetTable[240];
} FAT_EA_FILE_HEADER, *PFAT_EA_FILE_HEADER;

typedef struct _FAT_EA_SET_HEADER {
    USHORT Signature;	// EA
    USHORT Offset;	// Relative offset, same value as in the EASetTable
    USHORT Unknown1[2];
    CHAR   TargetFileName[12];
    USHORT Unknown2[3];
    UINT   EALength;
    // EA Header
} FAT_EA_SET_HEADER, *PFAT_EA_SET_HEADER;

typedef struct _FAT_EA_HEADER {
    UCHAR  Unknown;
    UCHAR  EANameLength;
    USHORT EAValueLength;
    // Name Data
    // Value Data
} FAT_EA_HEADER, *PFAT_EA_HEADER;

typedef struct _SLOT {
    UCHAR Id;			// Sequence number for slot
    WCHAR Name0_4[5];		// First five characters in name
    UCHAR Attr;			// Attribute byte
    UCHAR Reserved;		// Always zero
    UCHAR AliasChecksum;	// Checksum for 8.3 alias
    WCHAR Name5_10[6];		// Six more characters in name
    UCHAR Start[2];		// Starting cluster number
    WCHAR Name11_12[2];		// Last two characters in name
} SLOT, *PSLOT;

#include <poppack.h>

#define FAT_CASE_LOWER_BASE	8	// Base is lower case
#define FAT_CASE_LOWER_EXT 	16	// Extension is lower case

#define LONGNAME_MAX_LENGTH 	256	// Max length for a long filename

#define ENTRY_DELETED(IsFatX, DirEntry)					\
    (IsFatX ? FATX_ENTRY_DELETED(&((DirEntry)->FatX)) : FAT_ENTRY_DELETED(&((DirEntry)->Fat)))
#define ENTRY_VOLUME(IsFatX, DirEntry)					\
    (IsFatX ? FATX_ENTRY_VOLUME(&((DirEntry)->FatX)) : FAT_ENTRY_VOLUME(&((DirEntry)->Fat)))
#define ENTRY_END(IsFatX, DirEntry)					\
    (IsFatX ? FATX_ENTRY_END(&((DirEntry)->FatX)) : FAT_ENTRY_END(&((DirEntry)->Fat)))

#define FAT_ENTRY_DELETED(DirEntry)  ((DirEntry)->Filename[0] == 0xe5)
#define FAT_ENTRY_END(DirEntry)      ((DirEntry)->Filename[0] == 0)
#define FAT_ENTRY_LONG(DirEntry)     (((DirEntry)->Attrib & 0x3f) == 0x0f)
#define FAT_ENTRY_VOLUME(DirEntry)   (((DirEntry)->Attrib & 0x1f) == 0x08)

#define FATX_ENTRY_DELETED(DirEntry) ((DirEntry)->FilenameLength == 0xe5)
#define FATX_ENTRY_END(DirEntry)     ((DirEntry)->FilenameLength == 0xff)
#define FATX_ENTRY_LONG(DirEntry)    (FALSE)
#define FATX_ENTRY_VOLUME(DirEntry)  (((DirEntry)->Attrib & 0x1f) == 0x08)

#define BLOCKSIZE 512

#define FAT16  (1)
#define FAT12  (2)
#define FAT32  (3)
#define FATX16 (4)
#define FATX32 (5)

#define VCB_VOLUME_LOCKED       0x0001
#define VCB_DISMOUNT_PENDING    0x0002
#define VCB_IS_FATX             0x0004
#define VCB_IS_SYS_OR_HAS_PAGE  0x0008
#define VCB_IS_DIRTY            0x4000	/* Volume is dirty */
#define VCB_CLEAR_DIRTY         0x8000	/* Clean dirty flag at shutdown */
/* VCB condition state */
#define VCB_GOOD                0x0010	/* If not set, the VCB is improper for usage */

typedef struct _FATINFO {
    ULONG   VolumeID;
    CHAR    VolumeLabel[11];
    ULONG   FatStart;
    ULONG   FATCount;
    ULONG   FatSectors;
    ULONG   RootDirectorySectors;
    ULONG   RootStart;
    ULONG   DataStart;
    ULONG   RootCluster;
    ULONG   SectorsPerCluster;
    ULONG   BytesPerSector;
    ULONG   BytesPerCluster;
    ULONG   NumberOfClusters;
    ULONG   FatType;
    ULONG   Sectors;
    BOOLEAN FixedMedia;
    ULONG   FSInfoSector;
} FATINFO, *PFATINFO;

struct _FATFCB;
struct _FAT_DIRENTRY_CONTEXT;
struct _FAT_MOVE_CONTEXT;
struct _FAT_CLOSE_CONTEXT;

typedef struct _HASHENTRY {
    ULONG Hash;
    struct _FATFCB *Self;
    struct _HASHENTRY *Next;
} HASHENTRY, *PHASHENTRY;

typedef struct _DEVICE_EXTENSION *PDEVICE_EXTENSION;

typedef BOOLEAN (*PIS_DIRECTORY_EMPTY)(PDEVICE_EXTENSION,
				       struct _FATFCB *);
typedef NTSTATUS (*PADD_ENTRY)(PDEVICE_EXTENSION, PUNICODE_STRING,
			       struct _FATFCB **, struct _FATFCB *,
			       ULONG, UCHAR, struct _FAT_MOVE_CONTEXT *);
typedef NTSTATUS (*PDEL_ENTRY)(PDEVICE_EXTENSION, struct _FATFCB *,
			       struct _FAT_MOVE_CONTEXT *);
typedef NTSTATUS (*PGET_NEXT_DIR_ENTRY)(PVOID *, PVOID *,
					struct _FATFCB *,
					struct _FAT_DIRENTRY_CONTEXT *,
					BOOLEAN);

typedef struct _FAT_DISPATCH {
    PIS_DIRECTORY_EMPTY IsDirectoryEmpty;
    PADD_ENTRY AddEntry;
    PDEL_ENTRY DelEntry;
    PGET_NEXT_DIR_ENTRY GetNextDirEntry;
} FAT_DISPATCH, *PFAT_DISPATCH;

#define STATISTICS_SIZE_NO_PAD (sizeof(FILESYSTEM_STATISTICS) + sizeof(FAT_STATISTICS))
typedef struct _STATISTICS {
    FILESYSTEM_STATISTICS Base;
    FAT_STATISTICS Fat;
    UCHAR Pad[((STATISTICS_SIZE_NO_PAD + 0x3f) & ~0x3f) - STATISTICS_SIZE_NO_PAD];
} STATISTICS, *PSTATISTICS;

typedef struct _DEVICE_EXTENSION {
    LIST_ENTRY FcbListHead;
    ULONG HashTableSize;
    PHASHENTRY *FcbHashTable;

    PDEVICE_OBJECT VolumeDevice;
    PDEVICE_OBJECT StorageDevice;
    PFILE_OBJECT FatFileObject;
    FATINFO FatInfo;
    ULONG LastAvailableCluster;
    ULONG AvailableClusters;
    BOOLEAN AvailableClustersValid;
    ULONG Flags;
    struct _FATFCB *VolumeFcb;
    struct _FATFCB *RootFcb;
    PSTATISTICS Statistics;

    ULONG BaseDateYear;

    LIST_ENTRY VolumeListEntry;

    /* Incremented on IRP_MJ_CREATE, decremented on IRP_MJ_CLOSE */
    ULONG OpenHandleCount;

    /* VPBs for dismount */
    PVPB IoVPB;
    PVPB SpareVPB;

    /* Pointers to functions for manipulating directory entries. */
    FAT_DISPATCH Dispatch;
} DEVICE_EXTENSION, VCB, *PVCB;

#define FAT_BREAK_ON_CORRUPTION 1

typedef struct _FAT_GLOBAL_DATA {
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    ULONG NumberProcessors;
    LIST_ENTRY VolumeListHead;
    LOOKASIDE_LIST FcbLookasideList;
    LOOKASIDE_LIST CcbLookasideList;
    LOOKASIDE_LIST IrpContextLookasideList;
} FAT_GLOBAL_DATA, *PFAT_GLOBAL_DATA;

extern PFAT_GLOBAL_DATA FatGlobalData;

#define FCB_CACHE_INITIALIZED   0x0001
#define FCB_DELETE_PENDING      0x0002
#define FCB_IS_FAT              0x0004
#define FCB_IS_PAGE_FILE        0x0008
#define FCB_IS_VOLUME           0x0010
#define FCB_IS_DIRTY            0x0020
#ifdef KDBG
#define FCB_CLEANED_UP          0x0080
#define FCB_CLOSED              0x0100
#endif

#define NODE_TYPE_FCB ((CSHORT)0x0502)

typedef struct _FATFCB {
    /* Required common FCB header */
    FSRTL_COMMON_FCB_HEADER Base;

    /* Directory entry for this file or directory */
    DIR_ENTRY Entry;

    /* Pointer to attributes in entry */
    PUCHAR Attributes;

    /* Long file name, points into PathNameBuffer */
    UNICODE_STRING LongNameU;

    /* Short file name */
    UNICODE_STRING ShortNameU;

    /* Directory name, points into PathNameBuffer */
    UNICODE_STRING DirNameU;

    /* Path + long file name 260 max */
    UNICODE_STRING PathNameU;

    /* Buffer for PathNameU */
    PWCHAR PathNameBuffer;

    /* Buffer for ShortNameU */
    WCHAR ShortNameBuffer[13];

    /* Reference count */
    LONG RefCount;

    /* List of FCBs for this volume */
    LIST_ENTRY FcbListEntry;

    /* List of FCBs for the parent */
    LIST_ENTRY ParentListEntry;

    /* Pointer to the parent fcb */
    struct _FATFCB *ParentFcb;

    /* List for the children */
    LIST_ENTRY ParentListHead;

    /* Flags for the FCB */
    ULONG Flags;

    /* Pointer to the file object which has initialized the FCB */
    PFILE_OBJECT FileObject;

    /* Directory index for the short name entry */
    ULONG DirIndex;

    /* Directory index where the long name starts */
    ULONG StartIndex;

    /* Share access for the file object */
    SHARE_ACCESS FcbShareAccess;

    /* Incremented on IRP_MJ_CREATE, decremented on IRP_MJ_CLEANUP */
    ULONG OpenHandleCount;

    /* Entry into the hash table for the path + long name */
    HASHENTRY Hash;

    /* Entry into the hash table for the path + short name */
    HASHENTRY ShortHash;

    /* Optimization: caching of last read/write cluster+offset pair. Can't
     * be in FATCCB because it must be reset everytime the allocated clusters
     * change. */
    ULONG LastCluster;
    ULONG LastOffset;
} FATFCB, *PFATFCB;

#define CCB_DELETE_ON_CLOSE     0x0001

typedef struct _FATCCB {
    LARGE_INTEGER CurrentByteOffset;
    ULONG Flags;		/* For DirectoryControl */
    ULONG Entry;		/* For DirectoryControl */
    UNICODE_STRING SearchPattern;
} FATCCB, *PFATCCB;

#define TAG_CCB  'CtaF'
#define TAG_FCB  'FtaF'
#define TAG_IRP  'ItaF'
#define TAG_STATS 'VtaF'
#define TAG_BUFFER 'OtaF'
#define TAG_VPB 'vtaF'
#define TAG_NAME 'ntaF'
#define TAG_SEARCH 'LtaF'
#define TAG_DIRENT 'DtaF'

#define ENTRIES_PER_SECTOR (BLOCKSIZE / sizeof(FATDirEntry))

typedef struct __DOSTIME {
    USHORT Second:5;
    USHORT Minute:6;
    USHORT Hour:5;
} DOSTIME, *PDOSTIME;

typedef struct __DOSDATE {
    USHORT Day:5;
    USHORT Month:4;
    USHORT Year:7;
} DOSDATE, *PDOSDATE;

#define IRPCONTEXT_PENDINGRETURNED  0x0001
#define IRPCONTEXT_DEFERRED_WRITE   0x0002

typedef struct _FAT_IRP_CONTEXT {
    PIRP Irp;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_EXTENSION DeviceExt;
    PIO_STACK_LOCATION Stack;
    PFILE_OBJECT FileObject;
    ULONG Flags;
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    ULONG RefCount;
    CCHAR PriorityBoost;
} FAT_IRP_CONTEXT, *PFAT_IRP_CONTEXT;

typedef struct _FAT_DIRENTRY_CONTEXT {
    ULONG StartIndex;
    ULONG DirIndex;
    DIR_ENTRY DirEntry;
    UNICODE_STRING LongNameU;
    UNICODE_STRING ShortNameU;
    PDEVICE_EXTENSION DeviceExt;
} FAT_DIRENTRY_CONTEXT, *PFAT_DIRENTRY_CONTEXT;

typedef struct _FAT_MOVE_CONTEXT {
    ULONG FirstCluster;
    ULONG FileSize;
    USHORT CreationDate;
    USHORT CreationTime;
    BOOLEAN InPlace;
} FAT_MOVE_CONTEXT, *PFAT_MOVE_CONTEXT;

FORCEINLINE BOOLEAN FatIsLongIllegal(WCHAR c)
{
    const WCHAR *long_illegals = L"\"*\\<>/?:|";
    return wcschr(long_illegals, c) ? TRUE : FALSE;
}

FORCEINLINE BOOLEAN IsDotOrDotDot(PCUNICODE_STRING Name)
{
    return ((Name->Length == sizeof(WCHAR) && Name->Buffer[0] == L'.') ||
	    (Name->Length == 2 * sizeof(WCHAR) && Name->Buffer[0] == L'.'
	     && Name->Buffer[1] == L'.'));
}

FORCEINLINE BOOLEAN FatFcbIsDirectory(PFATFCB FCB)
{
    return BooleanFlagOn(*FCB->Attributes, FILE_ATTRIBUTE_DIRECTORY);
}

FORCEINLINE BOOLEAN FatFcbIsReadOnly(PFATFCB FCB)
{
    return BooleanFlagOn(*FCB->Attributes, FILE_ATTRIBUTE_READONLY);
}

FORCEINLINE BOOLEAN FatVolumeIsFatX(PDEVICE_EXTENSION DeviceExt)
{
    return BooleanFlagOn(DeviceExt->Flags, VCB_IS_FATX);
}

FORCEINLINE VOID FatReportChange(IN PDEVICE_EXTENSION DeviceExt,
				 IN PFATFCB Fcb,
				 IN ULONG FilterMatch,
				 IN ULONG Action)
{
#if 0
    /* TODO: We need to either handle file notifications entirely on server-side,
     * or have the client report the file changes to the server at the same time
     * of IRP reply, in order to avoid an extra trip to the server. */
    FsRtlNotifyFullReportChange(DeviceExt->NotifySync,
				&(DeviceExt->NotifyList),
				(PSTRING) & Fcb->PathNameU,
				Fcb->PathNameU.Length - Fcb->LongNameU.Length,
				NULL, NULL, FilterMatch, Action, NULL);
#endif
}

#define FatAddToStat(Vcb, Stat, Inc) {					\
	PSTATISTICS Stats = &(Vcb)->Statistics[NtGetCurrentProcessorNumber() % FatGlobalData->NumberProcessors]; \
	Stats->Stat += Inc;						\
    }

/* cleanup.c */
NTSTATUS FatCleanup(PFAT_IRP_CONTEXT IrpContext);

/* close.c */
BOOLEAN FatCheckForDismount(IN PDEVICE_EXTENSION DeviceExt,
			    IN BOOLEAN Create);
NTSTATUS FatClose(PFAT_IRP_CONTEXT IrpContext);
NTSTATUS FatCloseFile(PDEVICE_EXTENSION DeviceExt,
		      PFILE_OBJECT FileObject);

/* create.c */
NTSTATUS FatCreate(PFAT_IRP_CONTEXT IrpContext);
NTSTATUS FindFile(PDEVICE_EXTENSION DeviceExt,
		  PFATFCB Parent,
		  PUNICODE_STRING FileToFindU,
		  PFAT_DIRENTRY_CONTEXT DirContext,
		  BOOLEAN First);
VOID Fat8Dot3ToString(PFAT_DIR_ENTRY pEntry,
		      PUNICODE_STRING NameU);

/* dir.c */
NTSTATUS FatDirectoryControl(PFAT_IRP_CONTEXT IrpContext);
BOOLEAN FsdDosDateTimeToSystemTime(PDEVICE_EXTENSION DeviceExt,
				   USHORT DosDate,
				   USHORT DosTime,
				   PLARGE_INTEGER SystemTime);
BOOLEAN FsdSystemTimeToDosDateTime(PDEVICE_EXTENSION DeviceExt,
				   PLARGE_INTEGER SystemTime,
				   USHORT *pDosDate,
				   USHORT *pDosTime);

/* dirwr.c */
NTSTATUS FatFcbInitializeCacheFromVolume(PVCB Vcb, PFATFCB Fcb);
NTSTATUS FatUpdateEntry(IN PDEVICE_EXTENSION DeviceExt,
			PFATFCB Fcb);
BOOLEAN FatFindDirSpace(PDEVICE_EXTENSION DeviceExt,
			PFATFCB DirFcb,
			ULONG Slots,
			PULONG start);
NTSTATUS FatRenameEntry(IN PDEVICE_EXTENSION DeviceExt,
			IN PFATFCB Fcb,
			IN PUNICODE_STRING FileName,
			IN BOOLEAN CaseChangeOnly);
NTSTATUS FatMoveEntry(IN PDEVICE_EXTENSION DeviceExt,
		      IN PFATFCB Fcb,
		      IN PUNICODE_STRING FileName,
		      IN PFATFCB ParentFcb);

FORCEINLINE ULONG FatDirEntryGetFirstCluster(PDEVICE_EXTENSION DevExt,
					     PDIR_ENTRY DirEnt)
{
    if (DevExt->FatInfo.FatType == FAT32) {
	return DirEnt->Fat.FirstCluster | ((ULONG)DirEnt->Fat.FirstClusterHigh << 16);
    } else if (FatVolumeIsFatX(DevExt)) {
	return DirEnt->FatX.FirstCluster;
    } else {
	return DirEnt->Fat.FirstCluster;
    }
}

FORCEINLINE BOOLEAN FatIsDirectoryEmpty(PDEVICE_EXTENSION DeviceExt,
					struct _FATFCB *Fcb)
{
    return DeviceExt->Dispatch.IsDirectoryEmpty(DeviceExt, Fcb);
}

FORCEINLINE NTSTATUS FatAddEntry(PDEVICE_EXTENSION DeviceExt,
				 PUNICODE_STRING NameU,
				 struct _FATFCB **Fcb,
				 struct _FATFCB *ParentFcb,
				 ULONG RequestedOptions,
				 UCHAR ReqAttr,
				 struct _FAT_MOVE_CONTEXT *MoveContext)
{
    return DeviceExt->Dispatch.AddEntry(DeviceExt, NameU, Fcb, ParentFcb,
					RequestedOptions, ReqAttr,
					MoveContext);
}

FORCEINLINE NTSTATUS FatDelEntry(PDEVICE_EXTENSION DeviceExt,
				 struct _FATFCB *Fcb,
				 struct _FAT_MOVE_CONTEXT *MoveContext)
{
    return DeviceExt->Dispatch.DelEntry(DeviceExt, Fcb, MoveContext);
}

FORCEINLINE NTSTATUS FatGetNextDirEntry(PDEVICE_EXTENSION DeviceExt,
					PVOID *pContext,
					PVOID *pPage,
					struct _FATFCB *pDirFcb,
					struct _FAT_DIRENTRY_CONTEXT *DirContext,
					BOOLEAN First)
{
    return DeviceExt->Dispatch.GetNextDirEntry(pContext, pPage, pDirFcb,
					       DirContext, First);
}

/* ea.h */
NTSTATUS FatSetExtendedAttributes(PFILE_OBJECT FileObject,
				  PVOID Ea, ULONG EaLength);

/* fat.c */
NTSTATUS FindAndMarkAvailableCluster(PDEVICE_EXTENSION DeviceExt,
				     PULONG Cluster);
NTSTATUS OffsetToCluster(PDEVICE_EXTENSION DeviceExt,
			 ULONG FirstCluster,
			 ULONG FileOffset,
			 PULONG Cluster,
			 BOOLEAN Extend);
ULONGLONG ClusterToSector(PDEVICE_EXTENSION DeviceExt,
			  ULONG Cluster);
NTSTATUS GetNextCluster(PDEVICE_EXTENSION DeviceExt,
			ULONG CurrentCluster,
			PULONG NextCluster);
NTSTATUS GetNextClusterExtend(PDEVICE_EXTENSION DeviceExt,
			      ULONG CurrentCluster,
			      PULONG NextCluster);
NTSTATUS CountAvailableClusters(PDEVICE_EXTENSION DeviceExt,
				PLARGE_INTEGER Clusters);
NTSTATUS WriteCluster(PDEVICE_EXTENSION DeviceExt,
		      ULONG ClusterToWrite,
		      ULONG NewValue);
NTSTATUS GetDirtyStatus(PDEVICE_EXTENSION DeviceExt,
			PBOOLEAN DirtyStatus);
NTSTATUS SetDirtyStatus(PDEVICE_EXTENSION DeviceExt,
			BOOLEAN DirtyStatus);
NTSTATUS Fat32UpdateFreeClustersCount(PDEVICE_EXTENSION DeviceExt);

/* fcb.c */
VOID FatSplitPathName(PUNICODE_STRING PathNameU,
		      PUNICODE_STRING DirNameU,
		      PUNICODE_STRING FileNameU);
PFATFCB FatNewFcb(PDEVICE_EXTENSION Vcb, PUNICODE_STRING FileNameU);
NTSTATUS FatSetFcbNewDirName(PDEVICE_EXTENSION Vcb,
			     PFATFCB Fcb, PFATFCB ParentFcb);
NTSTATUS FatUpdateFcb(PDEVICE_EXTENSION Vcb,
		      PFATFCB Fcb,
		      PFAT_DIRENTRY_CONTEXT DirContext,
		      PFATFCB ParentFcb);
VOID FatDestroyFcb(PFATFCB Fcb);
VOID FatDestroyCcb(PFATCCB Ccb);
VOID FatGrabFcb(PDEVICE_EXTENSION Vcb, PFATFCB Fcb);
VOID FatReleaseFcb(PDEVICE_EXTENSION Vcb, PFATFCB Fcb);
PFATFCB FatGrabFcbFromTable(PDEVICE_EXTENSION DeviceExt,
			    PUNICODE_STRING FileNameU);
PFATFCB FatMakeRootFcb(PDEVICE_EXTENSION Vcb);
PFATFCB FatOpenRootFcb(PDEVICE_EXTENSION Vcb);
BOOLEAN FatFcbIsDirectory(PFATFCB Fcb);
BOOLEAN FatFcbIsRoot(PFATFCB Fcb);
NTSTATUS FatAttachFcbToFileObject(PDEVICE_EXTENSION Vcb,
				  PFATFCB Fcb, PFILE_OBJECT FileObject);
NTSTATUS FatDirFindFile(PDEVICE_EXTENSION Vcb,
			PFATFCB ParentFcb,
			PUNICODE_STRING FileToFindU, PFATFCB *FileFcb);
NTSTATUS FatGetFcbForFile(PDEVICE_EXTENSION Vcb,
			  PFATFCB *pParentFcb,
			  PFATFCB *pFcb, PUNICODE_STRING FileNameU);
NTSTATUS FatMakeFcbFromDirEntry(PVCB Vcb,
				PFATFCB DirectoryFcb,
				PFAT_DIRENTRY_CONTEXT DirContext,
				PFATFCB *FileFcb);

/* finfo.c */
NTSTATUS FatGetStandardInformation(PFATFCB FCB,
				   PFILE_STANDARD_INFORMATION StandardInfo,
				   PULONG BufferLength);
NTSTATUS FatGetBasicInformation(PFILE_OBJECT FileObject,
				PFATFCB FCB,
				PDEVICE_EXTENSION DeviceExt,
				PFILE_BASIC_INFORMATION BasicInfo,
				PULONG BufferLength);
NTSTATUS FatQueryInformation(PFAT_IRP_CONTEXT IrpContext);
NTSTATUS FatSetInformation(PFAT_IRP_CONTEXT IrpContext);
NTSTATUS FatSetFileSizeInformation(PFILE_OBJECT FileObject,
				   PFATFCB Fcb,
				   PDEVICE_EXTENSION DeviceExt,
				   PLARGE_INTEGER FileSize);

/* flush.c */
NTSTATUS FatFlush(PFAT_IRP_CONTEXT IrpContext);
NTSTATUS FatFlushVolume(PDEVICE_EXTENSION DeviceExt, PFATFCB VolumeFcb);

/* fsctl.c */
NTSTATUS FatBlockDeviceIoControl(IN PDEVICE_OBJECT DeviceObject,
				 IN ULONG CtlCode,
				 IN PVOID InputBuffer,
				 IN ULONG InputBufferSize,
				 IN OUT PVOID OutputBuffer,
				 IN OUT PULONG pOutputBufferSize,
				 IN BOOLEAN Override);
NTSTATUS FatFileSystemControl(PFAT_IRP_CONTEXT IrpContext);

/* pnp.c */
NTSTATUS FatPnp(PFAT_IRP_CONTEXT IrpContext);

/* rw.c */
NTSTATUS FatRead(PFAT_IRP_CONTEXT IrpContext);
NTSTATUS FatWrite(PFAT_IRP_CONTEXT * pIrpContext);
NTSTATUS NextCluster(PDEVICE_EXTENSION DeviceExt,
		     ULONG FirstCluster,
		     PULONG CurrentCluster,
		     BOOLEAN Extend);

/* shutdown.c */
DRIVER_DISPATCH FatShutdown;
NTSTATUS NTAPI FatShutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* volume.c */
NTSTATUS FatQueryVolumeInformation(PFAT_IRP_CONTEXT IrpContext);
NTSTATUS FatSetVolumeInformation(PFAT_IRP_CONTEXT IrpContext);
