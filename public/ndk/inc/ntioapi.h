#pragma once

#define FILE_LIST_DIRECTORY               0x00000001
#define FILE_READ_DATA                    0x00000001
#define FILE_ADD_FILE                     0x00000002
#define FILE_WRITE_DATA                   0x00000002
#define FILE_ADD_SUBDIRECTORY             0x00000004
#define FILE_APPEND_DATA                  0x00000004
#define FILE_CREATE_PIPE_INSTANCE         0x00000004
#define FILE_READ_EA                      0x00000008
#define FILE_WRITE_EA                     0x00000010
#define FILE_EXECUTE                      0x00000020
#define FILE_TRAVERSE                     0x00000020
#define FILE_DELETE_CHILD                 0x00000040
#define FILE_READ_ATTRIBUTES              0x00000080
#define FILE_WRITE_ATTRIBUTES             0x00000100

#define FILE_SHARE_READ                   0x00000001
#define FILE_SHARE_WRITE                  0x00000002
#define FILE_SHARE_DELETE                 0x00000004
#define FILE_SHARE_VALID_FLAGS            0x00000007

#define FILE_ATTRIBUTE_READONLY           0x00000001
#define FILE_ATTRIBUTE_HIDDEN             0x00000002
#define FILE_ATTRIBUTE_SYSTEM             0x00000004
#define FILE_ATTRIBUTE_DIRECTORY          0x00000010
#define FILE_ATTRIBUTE_ARCHIVE            0x00000020
#define FILE_ATTRIBUTE_DEVICE             0x00000040
#define FILE_ATTRIBUTE_NORMAL             0x00000080
#define FILE_ATTRIBUTE_TEMPORARY          0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE        0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT      0x00000400
#define FILE_ATTRIBUTE_COMPRESSED         0x00000800
#define FILE_ATTRIBUTE_OFFLINE            0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED          0x00004000
#define FILE_ATTRIBUTE_INTEGRITY_STREAM   0x00008000
#define FILE_ATTRIBUTE_VIRTUAL            0x00010000

#define FILE_ATTRIBUTE_VALID_FLAGS        0x00007fb7
#define FILE_ATTRIBUTE_VALID_SET_FLAGS    0x000031a7

#define FILE_VALID_OPTION_FLAGS           0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS      0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS  0x00000032
#define FILE_VALID_SET_FLAGS              0x00000036

#define FILE_SUPERSEDE                    0x00000000
#define FILE_OPEN                         0x00000001
#define FILE_CREATE                       0x00000002
#define FILE_OPEN_IF                      0x00000003
#define FILE_OVERWRITE                    0x00000004
#define FILE_OVERWRITE_IF                 0x00000005
#define FILE_MAXIMUM_DISPOSITION          0x00000005

#define FILE_DIRECTORY_FILE               0x00000001
#define FILE_WRITE_THROUGH                0x00000002
#define FILE_SEQUENTIAL_ONLY              0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING    0x00000008
#define FILE_SYNCHRONOUS_IO_ALERT         0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT      0x00000020
#define FILE_NON_DIRECTORY_FILE           0x00000040
#define FILE_CREATE_TREE_CONNECTION       0x00000080
#define FILE_COMPLETE_IF_OPLOCKED         0x00000100
#define FILE_NO_EA_KNOWLEDGE              0x00000200
#define FILE_OPEN_REMOTE_INSTANCE         0x00000400
#define FILE_RANDOM_ACCESS                0x00000800
#define FILE_DELETE_ON_CLOSE              0x00001000
#define FILE_OPEN_BY_FILE_ID              0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT       0x00004000
#define FILE_NO_COMPRESSION               0x00008000
#define FILE_OPEN_REQUIRING_OPLOCK        0x00010000
#define FILE_DISALLOW_EXCLUSIVE           0x00020000
#define FILE_RESERVE_OPFILTER             0x00100000
#define FILE_OPEN_REPARSE_POINT           0x00200000
#define FILE_OPEN_NO_RECALL               0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY    0x00800000

/*
 * DEVICE_OBJECT.DeviceType
 */
typedef ULONG DEVICE_TYPE;

#define FILE_DEVICE_BEEP                  0x00000001
#define FILE_DEVICE_CD_ROM                0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM    0x00000003
#define FILE_DEVICE_CONTROLLER            0x00000004
#define FILE_DEVICE_DATALINK              0x00000005
#define FILE_DEVICE_DFS                   0x00000006
#define FILE_DEVICE_DISK                  0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM      0x00000008
#define FILE_DEVICE_FILE_SYSTEM           0x00000009
#define FILE_DEVICE_INPORT_PORT           0x0000000a
#define FILE_DEVICE_KEYBOARD              0x0000000b
#define FILE_DEVICE_MAILSLOT              0x0000000c
#define FILE_DEVICE_MIDI_IN               0x0000000d
#define FILE_DEVICE_MIDI_OUT              0x0000000e
#define FILE_DEVICE_MOUSE                 0x0000000f
#define FILE_DEVICE_MULTI_UNC_PROVIDER    0x00000010
#define FILE_DEVICE_NAMED_PIPE            0x00000011
#define FILE_DEVICE_NETWORK               0x00000012
#define FILE_DEVICE_NETWORK_BROWSER       0x00000013
#define FILE_DEVICE_NETWORK_FILE_SYSTEM   0x00000014
#define FILE_DEVICE_NULL                  0x00000015
#define FILE_DEVICE_PARALLEL_PORT         0x00000016
#define FILE_DEVICE_PHYSICAL_NETCARD      0x00000017
#define FILE_DEVICE_PRINTER               0x00000018
#define FILE_DEVICE_SCANNER               0x00000019
#define FILE_DEVICE_SERIAL_MOUSE_PORT     0x0000001a
#define FILE_DEVICE_SERIAL_PORT           0x0000001b
#define FILE_DEVICE_SCREEN                0x0000001c
#define FILE_DEVICE_SOUND                 0x0000001d
#define FILE_DEVICE_STREAMS               0x0000001e
#define FILE_DEVICE_TAPE                  0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM      0x00000020
#define FILE_DEVICE_TRANSPORT             0x00000021
#define FILE_DEVICE_UNKNOWN               0x00000022
#define FILE_DEVICE_VIDEO                 0x00000023
#define FILE_DEVICE_VIRTUAL_DISK          0x00000024
#define FILE_DEVICE_WAVE_IN               0x00000025
#define FILE_DEVICE_WAVE_OUT              0x00000026
#define FILE_DEVICE_8042_PORT             0x00000027
#define FILE_DEVICE_NETWORK_REDIRECTOR    0x00000028
#define FILE_DEVICE_BATTERY               0x00000029
#define FILE_DEVICE_BUS_EXTENDER          0x0000002a
#define FILE_DEVICE_MODEM                 0x0000002b
#define FILE_DEVICE_VDM                   0x0000002c
#define FILE_DEVICE_MASS_STORAGE          0x0000002d
#define FILE_DEVICE_SMB                   0x0000002e
#define FILE_DEVICE_KS                    0x0000002f
#define FILE_DEVICE_CHANGER               0x00000030
#define FILE_DEVICE_SMARTCARD             0x00000031
#define FILE_DEVICE_ACPI                  0x00000032
#define FILE_DEVICE_DVD                   0x00000033
#define FILE_DEVICE_FULLSCREEN_VIDEO      0x00000034
#define FILE_DEVICE_DFS_FILE_SYSTEM       0x00000035
#define FILE_DEVICE_DFS_VOLUME            0x00000036
#define FILE_DEVICE_SERENUM               0x00000037
#define FILE_DEVICE_TERMSRV               0x00000038
#define FILE_DEVICE_KSEC                  0x00000039
#define FILE_DEVICE_FIPS                  0x0000003a
#define FILE_DEVICE_INFINIBAND            0x0000003b
#define FILE_DEVICE_VMBUS                 0x0000003e
#define FILE_DEVICE_CRYPT_PROVIDER        0x0000003f
#define FILE_DEVICE_WPD                   0x00000040
#define FILE_DEVICE_BLUETOOTH             0x00000041
#define FILE_DEVICE_MT_COMPOSITE          0x00000042
#define FILE_DEVICE_MT_TRANSPORT          0x00000043
#define FILE_DEVICE_BIOMETRIC             0x00000044
#define FILE_DEVICE_PMI                   0x00000045
#define FILE_DEVICE_EHSTOR                0x00000046
#define FILE_DEVICE_DEVAPI                0x00000047
#define FILE_DEVICE_GPIO                  0x00000048
#define FILE_DEVICE_USBEX                 0x00000049
#define FILE_DEVICE_CONSOLE               0x00000050
#define FILE_DEVICE_NFP                   0x00000051
#define FILE_DEVICE_SYSENV                0x00000052
#define FILE_DEVICE_VIRTUAL_BLOCK         0x00000053
#define FILE_DEVICE_POINT_OF_SERVICE      0x00000054
#define FILE_DEVICE_STORAGE_REPLICATION   0x00000055
#define FILE_DEVICE_TRUST_ENV             0x00000056
#define FILE_DEVICE_UCM                   0x00000057
#define FILE_DEVICE_UCMTCPCI              0x00000058
#define FILE_DEVICE_PERSISTENT_MEMORY     0x00000059
#define FILE_DEVICE_NVDIMM                0x0000005a
#define FILE_DEVICE_HOLOGRAPHIC           0x0000005b
#define FILE_DEVICE_SDFXHCI               0x0000005c
#define FILE_DEVICE_UCMUCSI               0x0000005d

/* DEVICE_OBJECT.Characteristics */
#define FILE_REMOVABLE_MEDIA              0x00000001
#define FILE_READ_ONLY_DEVICE             0x00000002
#define FILE_FLOPPY_DISKETTE              0x00000004
#define FILE_WRITE_ONCE_MEDIA             0x00000008
#define FILE_REMOTE_DEVICE                0x00000010
#define FILE_DEVICE_IS_MOUNTED            0x00000020
#define FILE_VIRTUAL_VOLUME               0x00000040
#define FILE_AUTOGENERATED_DEVICE_NAME    0x00000080
#define FILE_DEVICE_SECURE_OPEN           0x00000100
#define FILE_CHARACTERISTIC_PNP_DEVICE    0x00000800
#define FILE_CHARACTERISTIC_TS_DEVICE     0x00001000
#define FILE_CHARACTERISTIC_WEBDAV_DEVICE 0x00002000
#define FILE_PORTABLE_DEVICE              0x00004000
#define FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL 0x00020000

typedef enum _IO_NOTIFICATION_EVENT_CATEGORY {
    EventCategoryReserved,
    EventCategoryHardwareProfileChange,
    EventCategoryDeviceInterfaceChange,
    EventCategoryTargetDeviceChange
} IO_NOTIFICATION_EVENT_CATEGORY;

typedef enum _IO_PRIORITY_HINT {
    IoPriorityVeryLow = 0,
    IoPriorityLow,
    IoPriorityNormal,
    IoPriorityHigh,
    IoPriorityCritical,
    MaxIoPriorityTypes
} IO_PRIORITY_HINT;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileIdBothDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileValidDataLengthInformation,
    FileShortNameInformation,
    FileIoCompletionNotificationInformation,
    FileIoStatusBlockRangeInformation,
    FileIoPriorityHintInformation,
    FileSfioReserveInformation,
    FileSfioVolumeInformation,
    FileHardLinkInformation,
    FileProcessIdsUsingFileInformation,
    FileNormalizedNameInformation,
    FileNetworkPhysicalNameInformation,
    FileIdGlobalTxDirectoryInformation,
    FileIsRemoteDeviceInformation,
    FileAttributeCacheInformation,
    FileNumaNodeInformation,
    FileStandardLinkInformation,
    FileRemoteProtocolInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS {
    DirectoryNotifyInformation = 1,
    DirectoryNotifyExtendedInformation
} DIRECTORY_NOTIFY_INFORMATION_CLASS, *PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef struct _FILE_POSITION_INFORMATION {
    LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;

typedef struct _FILE_BASIC_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_IO_PRIORITY_HINT_INFORMATION {
    IO_PRIORITY_HINT PriorityHint;
} FILE_IO_PRIORITY_HINT_INFORMATION, *PFILE_IO_PRIORITY_HINT_INFORMATION;

typedef struct _FILE_IO_COMPLETION_NOTIFICATION_INFORMATION {
    ULONG Flags;
} FILE_IO_COMPLETION_NOTIFICATION_INFORMATION, *PFILE_IO_COMPLETION_NOTIFICATION_INFORMATION;

typedef struct _FILE_IOSTATUSBLOCK_RANGE_INFORMATION {
    PUCHAR IoStatusBlockRange;
    ULONG Length;
} FILE_IOSTATUSBLOCK_RANGE_INFORMATION, *PFILE_IOSTATUSBLOCK_RANGE_INFORMATION;

typedef struct _FILE_IS_REMOTE_DEVICE_INFORMATION {
    BOOLEAN IsRemote;
} FILE_IS_REMOTE_DEVICE_INFORMATION, *PFILE_IS_REMOTE_DEVICE_INFORMATION;

typedef struct _FILE_NUMA_NODE_INFORMATION {
    USHORT NodeNumber;
} FILE_NUMA_NODE_INFORMATION, *PFILE_NUMA_NODE_INFORMATION;

typedef struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION {
    ULONG NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, *PFILE_PROCESS_IDS_USING_FILE_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FSINFOCLASS {
    FileFsVolumeInformation = 1,
    FileFsLabelInformation,
    FileFsSizeInformation,
    FileFsDeviceInformation,
    FileFsAttributeInformation,
    FileFsControlInformation,
    FileFsFullSizeInformation,
    FileFsObjectIdInformation,
    FileFsDriverPathInformation,
    FileFsVolumeFlagsInformation,
    FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

typedef struct _IO_STATUS_BLOCK {
    union {
	NTSTATUS Status;
	PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

/*
 * System service interface of the IO manager.
 */
#ifndef _NTOSKRNL_
NTAPI NTSYSAPI NTSTATUS NtLoadDriver(IN PUNICODE_STRING DriverServiceName);

NTAPI NTSYSAPI NTSTATUS NtLoadDriverA(IN PCSTR DriverServiceName);
#endif
