/**
 * This file has no copyright assigned and is placed in the Public Domain.
 * This file is part of the w64 mingw-runtime package.
 * No warranty is given; refer to the file DISCLAIMER.PD within this package.
 */
#ifdef DEFINE_GUID

#ifndef FAR
#define FAR
#endif

DEFINE_GUID(ScsiRawInterfaceGuid, 0x53f56309L, 0xb6bf, 0x11d0, 0x94, 0xf2, 0x00, 0xa0,
	    0xc9, 0x1e, 0xfb, 0x8b);
#define WmiScsiAddressGuid MSIde_PortDeviceInfo_GUID
#endif /* DEFINE_GUID */

#ifndef _NTDDSCSIH_
#define _NTDDSCSIH_

#define IOCTL_SCSI_BASE FILE_DEVICE_CONTROLLER

#define DD_SCSI_DEVICE_NAME "\\Device\\ScsiPort"
#define DD_SCSI_DEVICE_NAME_U L"\\Device\\ScsiPort"

#define IOCTL_SCSI_PASS_THROUGH				\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_MINIPORT				\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0402, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_GET_INQUIRY_DATA					\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0403, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_GET_CAPABILITIES					\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0404, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH_DIRECT			\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0405, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_GET_ADDRESS						\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0406, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_RESCAN_BUS						\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0407, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_GET_DUMP_POINTERS					\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0408, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_FREE_DUMP_POINTERS					\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0409, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH_EX			\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0411, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH_DIRECT_EX		\
    CTL_CODE(IOCTL_SCSI_BASE, 0x0412, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_IDE_PASS_THROUGH				\
    CTL_CODE(IOCTL_SCSI_BASE, 0x040a, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_ATA_PASS_THROUGH				\
    CTL_CODE(IOCTL_SCSI_BASE, 0x040b, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_ATA_PASS_THROUGH_DIRECT			\
    CTL_CODE(IOCTL_SCSI_BASE, 0x040c, METHOD_BUFFERED,	\
	     FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _SCSI_PASS_THROUGH {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG_PTR DataBufferOffset;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
} SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;

typedef struct _SCSI_PASS_THROUGH_DIRECT {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    PVOID DataBuffer;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
} SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;

#if defined(_WIN64)
typedef struct _SCSI_PASS_THROUGH32 {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG DataBufferOffset;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
} SCSI_PASS_THROUGH32, *PSCSI_PASS_THROUGH32;

typedef struct _SCSI_PASS_THROUGH_DIRECT32 {
    USHORT Length;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR CdbLength;
    UCHAR SenseInfoLength;
    UCHAR DataIn;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    VOID *POINTER_32 DataBuffer;
    ULONG SenseInfoOffset;
    UCHAR Cdb[16];
} SCSI_PASS_THROUGH_DIRECT32, *PSCSI_PASS_THROUGH_DIRECT32;
#endif /* _WIN64 */

typedef struct _SCSI_PASS_THROUGH_EX {
    ULONG Version;
    ULONG Length;
    ULONG CdbLength;
    ULONG StorAddressLength;
    UCHAR ScsiStatus;
    UCHAR SenseInfoLength;
    UCHAR DataDirection;
    UCHAR Reserved;
    ULONG TimeOutValue;
    ULONG StorAddressOffset;
    ULONG SenseInfoOffset;
    ULONG DataOutTransferLength;
    ULONG DataInTransferLength;
    ULONG_PTR DataOutBufferOffset;
    ULONG_PTR DataInBufferOffset;
    UCHAR Cdb[ANYSIZE_ARRAY];
} SCSI_PASS_THROUGH_EX, *PSCSI_PASS_THROUGH_EX;

typedef struct _SCSI_PASS_THROUGH_DIRECT_EX {
    ULONG Version;
    ULONG Length;
    ULONG CdbLength;
    ULONG StorAddressLength;
    UCHAR ScsiStatus;
    UCHAR SenseInfoLength;
    UCHAR DataDirection;
    UCHAR Reserved;
    ULONG TimeOutValue;
    ULONG StorAddressOffset;
    ULONG SenseInfoOffset;
    ULONG DataOutTransferLength;
    ULONG DataInTransferLength;
    PVOID DataOutBuffer;
    PVOID DataInBuffer;
    UCHAR Cdb[ANYSIZE_ARRAY];
} SCSI_PASS_THROUGH_DIRECT_EX, *PSCSI_PASS_THROUGH_DIRECT_EX;

#if defined(_WIN64)
typedef struct _SCSI_PASS_THROUGH32_EX {
    ULONG Version;
    ULONG Length;
    ULONG CdbLength;
    ULONG StorAddressLength;
    UCHAR ScsiStatus;
    UCHAR SenseInfoLength;
    UCHAR DataDirection;
    UCHAR Reserved;
    ULONG TimeOutValue;
    ULONG StorAddressOffset;
    ULONG SenseInfoOffset;
    ULONG DataOutTransferLength;
    ULONG DataInTransferLength;
    ULONG DataOutBufferOffset;
    ULONG DataInBufferOffset;
    UCHAR Cdb[ANYSIZE_ARRAY];
} SCSI_PASS_THROUGH32_EX, *PSCSI_PASS_THROUGH32_EX;

typedef struct _SCSI_PASS_THROUGH_DIRECT32_EX {
    ULONG Version;
    ULONG Length;
    ULONG CdbLength;
    ULONG StorAddressLength;
    UCHAR ScsiStatus;
    UCHAR SenseInfoLength;
    UCHAR DataDirection;
    UCHAR Reserved;
    ULONG TimeOutValue;
    ULONG StorAddressOffset;
    ULONG SenseInfoOffset;
    ULONG DataOutTransferLength;
    ULONG DataInTransferLength;
    VOID *POINTER_32 DataOutBuffer;
    VOID *POINTER_32 DataInBuffer;
    UCHAR Cdb[ANYSIZE_ARRAY];
} SCSI_PASS_THROUGH_DIRECT32_EX, *PSCSI_PASS_THROUGH_DIRECT32_EX;
#endif

typedef struct _ATA_PASS_THROUGH_EX {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR ReservedAsUchar;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG ReservedAsUlong;
    ULONG_PTR DataBufferOffset;
    UCHAR PreviousTaskFile[8];
    UCHAR CurrentTaskFile[8];
} ATA_PASS_THROUGH_EX, *PATA_PASS_THROUGH_EX;

typedef struct _ATA_PASS_THROUGH_DIRECT {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR ReservedAsUchar;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG ReservedAsUlong;
    PVOID DataBuffer;
    UCHAR PreviousTaskFile[8];
    UCHAR CurrentTaskFile[8];
} ATA_PASS_THROUGH_DIRECT, *PATA_PASS_THROUGH_DIRECT;

#if defined(_WIN64)

typedef struct _ATA_PASS_THROUGH_EX32 {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR ReservedAsUchar;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG ReservedAsUlong;
    ULONG DataBufferOffset;
    UCHAR PreviousTaskFile[8];
    UCHAR CurrentTaskFile[8];
} ATA_PASS_THROUGH_EX32, *PATA_PASS_THROUGH_EX32;

typedef struct _ATA_PASS_THROUGH_DIRECT32 {
    USHORT Length;
    USHORT AtaFlags;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR ReservedAsUchar;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    ULONG ReservedAsUlong;
    VOID *POINTER_32 DataBuffer;
    UCHAR PreviousTaskFile[8];
    UCHAR CurrentTaskFile[8];
} ATA_PASS_THROUGH_DIRECT32, *PATA_PASS_THROUGH_DIRECT32;
#endif /* _WIN64 */

#define ATA_FLAGS_DRDY_REQUIRED (1 << 0)
#define ATA_FLAGS_DATA_IN (1 << 1)
#define ATA_FLAGS_DATA_OUT (1 << 2)
#define ATA_FLAGS_48BIT_COMMAND (1 << 3)
#define ATA_FLAGS_USE_DMA (1 << 4)

typedef struct _SCSI_BUS_DATA {
    UCHAR NumberOfLogicalUnits;
    UCHAR InitiatorBusId;
    ULONG InquiryDataOffset;
} SCSI_BUS_DATA, *PSCSI_BUS_DATA;

typedef struct _SCSI_ADAPTER_BUS_INFO {
    UCHAR NumberOfBuses;
    SCSI_BUS_DATA BusData[1];
} SCSI_ADAPTER_BUS_INFO, *PSCSI_ADAPTER_BUS_INFO;

typedef struct _SCSI_INQUIRY_DATA {
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    BOOLEAN DeviceClaimed;
    ULONG InquiryDataLength;
    ULONG NextInquiryDataOffset;
    UCHAR InquiryData[1];
} SCSI_INQUIRY_DATA, *PSCSI_INQUIRY_DATA;

/*
 * Acceptable signatures for SCSI IOCTL MINIPORT calls.
 * Must be equal in byte size to sizeof(SrbIoctl->Signature)
 */
#define IOCTL_MINIPORT_SIGNATURE_SCSIDISK           "SCSIDISK"
#define IOCTL_MINIPORT_SIGNATURE_HYBRDISK           "HYBRDISK"
#define IOCTL_MINIPORT_SIGNATURE_DSM_NOTIFICATION   "MPDSM   "
#define IOCTL_MINIPORT_SIGNATURE_DSM_GENERAL        "MPDSMGEN"

#define IOCTL_MINIPORT_SIGNATURE_FIRMWARE           "FIRMWARE"
#define IOCTL_MINIPORT_SIGNATURE_QUERY_PROTOCOL     "PROTOCOL"
#define IOCTL_MINIPORT_SIGNATURE_QUERY_TEMPERATURE  "TEMPERAT"
#define IOCTL_MINIPORT_SIGNATURE_SET_TEMPERATURE_THRESHOLD  "SETTEMPT"
#define IOCTL_MINIPORT_SIGNATURE_QUERY_PHYSICAL_TOPOLOGY    "TOPOLOGY"

typedef struct _SRB_IO_CONTROL {
    ULONG HeaderLength;
    UCHAR Signature[8];
    ULONG Timeout;
    ULONG ControlCode;
    ULONG ReturnCode;
    ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;

typedef struct _IO_SCSI_CAPABILITIES {
    ULONG Length;
    ULONG MaximumTransferLength;
    ULONG MaximumPhysicalPages;
    ULONG SupportedAsynchronousEvents;
    ULONG AlignmentMask;
    BOOLEAN TaggedQueuing;
    BOOLEAN AdapterScansDown;
    BOOLEAN AdapterUsesPio;
} IO_SCSI_CAPABILITIES, *PIO_SCSI_CAPABILITIES;

typedef struct _SCSI_ADDRESS {
    ULONG Length;
    UCHAR PortNumber;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
} SCSI_ADDRESS, *PSCSI_ADDRESS;

struct _ADAPTER_OBJECT;

typedef struct _DUMP_POINTERS {
    struct _ADAPTER_OBJECT *AdapterObject;
    PVOID MappedRegisterBase;
    PVOID DumpData;
    PVOID CommonBufferVa;
    LARGE_INTEGER CommonBufferPa;
    ULONG CommonBufferSize;
    BOOLEAN AllocateCommonBuffers;
    BOOLEAN UseDiskDump;
    UCHAR Spare1[2];
    PVOID DeviceObject;
} DUMP_POINTERS, *PDUMP_POINTERS;

#define SCSI_IOCTL_DATA_OUT 0
#define SCSI_IOCTL_DATA_IN 1
#define SCSI_IOCTL_DATA_UNSPECIFIED 2

typedef struct _NVCACHE_REQUEST_BLOCK {
    ULONG           NRBSize;
    USHORT          Function;
    ULONG           NRBFlags;
    ULONG           NRBStatus;
    ULONG           Count;
    ULONGLONG       LBA;
    ULONG           DataBufSize;
    ULONG           NVCacheStatus;
    ULONG           NVCacheSubStatus;
} NVCACHE_REQUEST_BLOCK, *PNVCACHE_REQUEST_BLOCK;

#define NRB_FUNCTION_NVCACHE_INFO               0xEC
#define NRB_FUNCTION_SPINDLE_STATUS             0xE5
#define NRB_FUNCTION_NVCACHE_POWER_MODE_SET     0x00
#define NRB_FUNCTION_NVCACHE_POWER_MODE_RETURN  0x01
#define NRB_FUNCTION_FLUSH_NVCACHE              0x14
#define NRB_FUNCTION_QUERY_PINNED_SET           0x12
#define NRB_FUNCTION_QUERY_CACHE_MISS           0x13
#define NRB_FUNCTION_ADD_LBAS_PINNED_SET        0x10
#define NRB_FUNCTION_REMOVE_LBAS_PINNED_SET     0x11
#define NRB_FUNCTION_QUERY_ASCENDER_STATUS      0xD0
#define NRB_FUNCTION_QUERY_HYBRID_DISK_STATUS   0xD1
#define NRB_FUNCTION_PASS_HINT_PAYLOAD          0xE0

#define NRB_FUNCTION_NVSEPARATED_INFO              0xc0
#define NRB_FUNCTION_NVSEPARATED_FLUSH             0xc1
#define NRB_FUNCTION_NVSEPARATED_WB_DISABLE        0xc2
#define NRB_FUNCTION_NVSEPARATED_WB_REVERT_DEFAULT 0xc3

#define NRB_SUCCESS                             0
#define NRB_ILLEGAL_REQUEST                     1
#define NRB_INVALID_PARAMETER                   2
#define NRB_INPUT_DATA_OVERRUN                  3
#define NRB_INPUT_DATA_UNDERRUN                 4
#define NRB_OUTPUT_DATA_OVERRUN                 5
#define NRB_OUTPUT_DATA_UNDERRUN                6

typedef struct _NV_FEATURE_PARAMETER {
    USHORT NVPowerModeEnabled;
    USHORT NVParameterReserv1;
    USHORT NVCmdEnabled;
    USHORT NVParameterReserv2;
    USHORT NVPowerModeVer;
    USHORT NVCmdVer;
    ULONG  NVSize;
    USHORT NVReadSpeed;
    USHORT NVWrtSpeed;
    ULONG  DeviceSpinUpTime;
} NV_FEATURE_PARAMETER, *PNV_FEATURE_PARAMETER;

/*
 * Data structure and definitions related to data set management notifications
 */

typedef struct _MP_DEVICE_DATA_SET_RANGE {
    LONGLONG    StartingOffset;
    ULONGLONG   LengthInBytes;
} MP_DEVICE_DATA_SET_RANGE, *PMP_DEVICE_DATA_SET_RANGE;

typedef struct _DSM_NOTIFICATION_REQUEST_BLOCK {
    ULONG   Size;
    ULONG   Version;
    ULONG   NotifyFlags;
    ULONG   DataSetProfile;
    ULONG   Reserved[3];
    ULONG   DataSetRangesCount;
    MP_DEVICE_DATA_SET_RANGE DataSetRanges[ANYSIZE_ARRAY];
} DSM_NOTIFICATION_REQUEST_BLOCK,*PDSM_NOTIFICATION_REQUEST_BLOCK;

#define MINIPORT_DSM_NOTIFICATION_VERSION_1     1
#define MINIPORT_DSM_NOTIFICATION_VERSION       MINIPORT_DSM_NOTIFICATION_VERSION_1

#define MINIPORT_DSM_PROFILE_UNKNOWN    0
#define MINIPORT_DSM_PROFILE_PAGE_FILE  1
#define MINIPORT_DSM_PROFILE_HIBERNATION_FILE   2
#define MINIPORT_DSM_PROFILE_CRASHDUMP_FILE     3

#define MINIPORT_DSM_NOTIFY_FLAG_BEGIN            0x00000001
#define MINIPORT_DSM_NOTIFY_FLAG_END              0x00000002

/*
 * Data structure and definitions related to IOCTL_SCSI_MINIPORT_HYBRID
 */

#define HYBRID_FUNCTION_GET_INFO                            0x01

#define HYBRID_FUNCTION_DISABLE_CACHING_MEDIUM              0x10
#define HYBRID_FUNCTION_ENABLE_CACHING_MEDIUM               0x11
#define HYBRID_FUNCTION_SET_DIRTY_THRESHOLD                 0x12
#define HYBRID_FUNCTION_DEMOTE_BY_SIZE                      0x13

#define HYBRID_STATUS_SUCCESS                             0x0
#define HYBRID_STATUS_ILLEGAL_REQUEST                     0x1
#define HYBRID_STATUS_INVALID_PARAMETER                   0x2
#define HYBRID_STATUS_OUTPUT_BUFFER_TOO_SMALL             0x3

#define HYBRID_STATUS_ENABLE_REFCOUNT_HOLD                0x10

#define HYBRID_REQUEST_BLOCK_STRUCTURE_VERSION          0x1

typedef struct _HYBRID_REQUEST_BLOCK {
    ULONG   Version;
    ULONG   Size;
    ULONG   Function;
    ULONG   Flags;
    ULONG   DataBufferOffset;
    ULONG   DataBufferLength;
} HYBRID_REQUEST_BLOCK, *PHYBRID_REQUEST_BLOCK;

typedef enum _NVCACHE_TYPE {
    NvCacheTypeUnknown        = 0,
    NvCacheTypeNone           = 1,
    NvCacheTypeWriteBack      = 2,
    NvCacheTypeWriteThrough   = 3
} NVCACHE_TYPE;

typedef enum _NVCACHE_STATUS {
    NvCacheStatusUnknown     = 0,
    NvCacheStatusDisabling   = 1,
    NvCacheStatusDisabled    = 2,
    NvCacheStatusEnabled     = 3
} NVCACHE_STATUS;

typedef struct _NVCACHE_PRIORITY_LEVEL_DESCRIPTOR {
    UCHAR   PriorityLevel;
    UCHAR   Reserved0[3];
    ULONG   ConsumedNVMSizeFraction;
    ULONG   ConsumedMappingResourcesFraction;
    ULONG   ConsumedNVMSizeForDirtyDataFraction;
    ULONG   ConsumedMappingResourcesForDirtyDataFraction;
    ULONG   Reserved1;
} NVCACHE_PRIORITY_LEVEL_DESCRIPTOR, *PNVCACHE_PRIORITY_LEVEL_DESCRIPTOR;

#define HYBRID_REQUEST_INFO_STRUCTURE_VERSION           0x1

typedef struct _HYBRID_INFORMATION {
    ULONG           Version;
    ULONG           Size;
    BOOLEAN         HybridSupported;
    NVCACHE_STATUS  Status;
    NVCACHE_TYPE    CacheTypeEffective;
    NVCACHE_TYPE    CacheTypeDefault;
    ULONG           FractionBase;
    ULONGLONG       CacheSize;
    struct {
        ULONG   WriteCacheChangeable    : 1;
        ULONG   WriteThroughIoSupported : 1;
        ULONG   FlushCacheSupported     : 1;
        ULONG   Removable               : 1;
        ULONG   ReservedBits            : 28;
    } Attributes;
    struct {
        UCHAR     PriorityLevelCount;
        BOOLEAN   MaxPriorityBehavior;
        UCHAR     OptimalWriteGranularity;
        UCHAR     Reserved;
        ULONG     DirtyThresholdLow;
        ULONG     DirtyThresholdHigh;
        struct {
            ULONG   CacheDisable                : 1;
            ULONG   SetDirtyThreshold           : 1;
            ULONG   PriorityDemoteBySize        : 1;
            ULONG   PriorityChangeByLbaRange    : 1;
            ULONG   Evict                       : 1;
            ULONG   ReservedBits                : 27;
            ULONG   MaxEvictCommands;
            ULONG   MaxLbaRangeCountForEvict;
            ULONG   MaxLbaRangeCountForChangeLba;
        } SupportedCommands;
        NVCACHE_PRIORITY_LEVEL_DESCRIPTOR   Priority[0];
    } Priorities;
} HYBRID_INFORMATION, *PHYBRID_INFORMATION;

typedef struct _HYBRID_DIRTY_THRESHOLDS {
    ULONG   Version;
    ULONG   Size;
    ULONG   DirtyLowThreshold;
    ULONG   DirtyHighThreshold;
} HYBRID_DIRTY_THRESHOLDS, *PHYBRID_DIRTY_THRESHOLDS;

typedef struct _HYBRID_DEMOTE_BY_SIZE {
    ULONG       Version;
    ULONG       Size;
    UCHAR       SourcePriority;
    UCHAR       TargetPriority;
    USHORT      Reserved0;
    ULONG       Reserved1;
    ULONGLONG   LbaCount;
} HYBRID_DEMOTE_BY_SIZE, *PHYBRID_DEMOTE_BY_SIZE;

/*
 * Data structure and definitions related to IOCTL_SCSI_MINIPORT_FIRMWARE
 */

#define FIRMWARE_FUNCTION_GET_INFO                          0x01
#define FIRMWARE_FUNCTION_DOWNLOAD                          0x02
#define FIRMWARE_FUNCTION_ACTIVATE                          0x03

#define FIRMWARE_STATUS_SUCCESS                             0x0
#define FIRMWARE_STATUS_ERROR                               0x1
#define FIRMWARE_STATUS_ILLEGAL_REQUEST                     0x2
#define FIRMWARE_STATUS_INVALID_PARAMETER                   0x3
#define FIRMWARE_STATUS_INPUT_BUFFER_TOO_BIG                0x4
#define FIRMWARE_STATUS_OUTPUT_BUFFER_TOO_SMALL             0x5
#define FIRMWARE_STATUS_INVALID_SLOT                        0x6
#define FIRMWARE_STATUS_INVALID_IMAGE                       0x7
#define FIRMWARE_STATUS_CONTROLLER_ERROR                    0x10
#define FIRMWARE_STATUS_POWER_CYCLE_REQUIRED                0x20
#define FIRMWARE_STATUS_DEVICE_ERROR                        0x40
#define FIRMWARE_STATUS_INTERFACE_CRC_ERROR		    0x80
#define FIRMWARE_STATUS_UNCORRECTABLE_DATA_ERROR            0x81
#define FIRMWARE_STATUS_MEDIA_CHANGE                        0x82
#define FIRMWARE_STATUS_ID_NOT_FOUND                        0x83
#define FIRMWARE_STATUS_MEDIA_CHANGE_REQUEST                0x84
#define FIRMWARE_STATUS_COMMAND_ABORT                       0x85
#define FIRMWARE_STATUS_END_OF_MEDIA                        0x86
#define FIRMWARE_STATUS_ILLEGAL_LENGTH                      0x87

#define FIRMWARE_REQUEST_BLOCK_STRUCTURE_VERSION            0x1

typedef struct _FIRMWARE_REQUEST_BLOCK {
    ULONG   Version;
    ULONG   Size;
    ULONG   Function;
    ULONG   Flags;
    ULONG   DataBufferOffset;
    ULONG   DataBufferLength;
} FIRMWARE_REQUEST_BLOCK, *PFIRMWARE_REQUEST_BLOCK;

#define FIRMWARE_REQUEST_FLAG_CONTROLLER                    0x00000001
#define FIRMWARE_REQUEST_FLAG_SWITCH_TO_EXISTING_FIRMWARE   0x80000000

#define STORAGE_FIRMWARE_INFO_STRUCTURE_VERSION         0x1
#define STORAGE_FIRMWARE_INFO_STRUCTURE_VERSION_V2      0x2

#define STORAGE_FIRMWARE_INFO_INVALID_SLOT              0xFF

typedef struct _STORAGE_FIRMWARE_SLOT_INFO {
    UCHAR   SlotNumber;
    BOOLEAN ReadOnly;
    UCHAR   Reserved[6];
    union {
        UCHAR     Info[8];
        ULONGLONG AsUlonglong;
    } Revision;
} STORAGE_FIRMWARE_SLOT_INFO, *PSTORAGE_FIRMWARE_SLOT_INFO;

#define STORAGE_FIRMWARE_SLOT_INFO_V2_REVISION_LENGTH   16

typedef struct _STORAGE_FIRMWARE_SLOT_INFO_V2 {
    UCHAR   SlotNumber;
    BOOLEAN ReadOnly;
    UCHAR   Reserved[6];
    UCHAR   Revision[STORAGE_FIRMWARE_SLOT_INFO_V2_REVISION_LENGTH];
} STORAGE_FIRMWARE_SLOT_INFO_V2, *PSTORAGE_FIRMWARE_SLOT_INFO_V2;

typedef struct _STORAGE_FIRMWARE_INFO {
    ULONG   Version;
    ULONG   Size;
    BOOLEAN UpgradeSupport;
    UCHAR   SlotCount;
    UCHAR   ActiveSlot;
    UCHAR   PendingActivateSlot;
    ULONG   Reserved;
    STORAGE_FIRMWARE_SLOT_INFO Slot[0];
} STORAGE_FIRMWARE_INFO, *PSTORAGE_FIRMWARE_INFO;

typedef struct _STORAGE_FIRMWARE_INFO_V2 {
    ULONG   Version;
    ULONG   Size;
    BOOLEAN UpgradeSupport;
    UCHAR   SlotCount;
    UCHAR   ActiveSlot;
    UCHAR   PendingActivateSlot;
    BOOLEAN FirmwareShared;
    UCHAR   Reserved[3];
    ULONG   ImagePayloadAlignment;
    ULONG   ImagePayloadMaxSize;
    STORAGE_FIRMWARE_SLOT_INFO_V2 Slot[0];
} STORAGE_FIRMWARE_INFO_V2, *PSTORAGE_FIRMWARE_INFO_V2;

#define STORAGE_FIRMWARE_DOWNLOAD_STRUCTURE_VERSION         0x1
#define STORAGE_FIRMWARE_DOWNLOAD_STRUCTURE_VERSION_V2      0x2

typedef struct _STORAGE_FIRMWARE_DOWNLOAD {
    ULONG       Version;
    ULONG       Size;
    ULONGLONG   Offset;
    ULONGLONG   BufferSize;
    UCHAR       ImageBuffer[0];
} STORAGE_FIRMWARE_DOWNLOAD, *PSTORAGE_FIRMWARE_DOWNLOAD;

typedef struct _STORAGE_FIRMWARE_DOWNLOAD_V2 {
    ULONG       Version;
    ULONG       Size;
    ULONGLONG   Offset;
    ULONGLONG   BufferSize;
    UCHAR       Slot;
    UCHAR       Reserved[7];
    UCHAR       ImageBuffer[0];
} STORAGE_FIRMWARE_DOWNLOAD_V2, *PSTORAGE_FIRMWARE_DOWNLOAD_V2;

#define STORAGE_FIRMWARE_ACTIVATE_STRUCTURE_VERSION         0x1

typedef struct _STORAGE_FIRMWARE_ACTIVATE {
    ULONG   Version;
    ULONG   Size;
    UCHAR   SlotToActivate;
    UCHAR   Reserved0[3];
} STORAGE_FIRMWARE_ACTIVATE, *PSTORAGE_FIRMWARE_ACTIVATE;

#endif /* _NTDDSCSIH_ */
