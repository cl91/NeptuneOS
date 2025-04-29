/*
 * srb.h
 *
 * Defines the structures and constants pertaining to the SCSI request blocks
 *
 * This file is part of the w32api package.
 *
 * Contributors:
 *   Created by Casper S. Hornstrup <chorns@users.sourceforge.net>
 *
 * THIS SOFTWARE IS NOT COPYRIGHTED
 *
 * This source code is offered for use in the public domain. You may
 * use, modify or distribute it freely.
 *
 * This code is distributed in the hope that it will be useful but
 * WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 * DISCLAIMED. This includes but is not limited to warranties of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#ifndef _NTSRB_
#define _NTSRB_

#include <nt.h>
#include "hal.h"

/* NOTE: the current SCSI_MAXIMUM_TARGETS_PER_BUS is applicable
 * only on scsiport miniports. For storport miniports, the max
 * target supported is 255. */
#if (NTDDI_VERSION >= NTDDI_WIN8)
#define SCSI_MAXIMUM_BUSES_PER_ADAPTER 255
#endif
#define SCSI_MAXIMUM_TARGETS_PER_BUS 128
#define SCSI_MAXIMUM_LUNS_PER_TARGET 255
#define SCSI_MINIMUM_PHYSICAL_BREAKS 16
#define SCSI_MAXIMUM_PHYSICAL_BREAKS 255

/* These constants are for backward compatibility.
 * They used to be the maximum supported. */
#define SCSI_MAXIMUM_BUSES 8
#define SCSI_MAXIMUM_TARGETS 8
#define SCSI_MAXIMUM_LOGICAL_UNITS 8

/* PORT_CONFIGURATION_INFORMATION.Dma64BitAddresses constants */
#define SCSI_DMA64_MINIPORT_SUPPORTED 0x01
#define SCSI_DMA64_SYSTEM_SUPPORTED 0x80
#if (NTDDI_VERSION > NTDDI_WS03SP1)
#define SCSI_DMA64_MINIPORT_FULL64BIT_SUPPORTED 0x02
#endif

#define SP_UNINITIALIZED_VALUE ((ULONG)~0)
#define SP_UNTAGGED ((UCHAR)~0)

/* Asynchronous events */
#define SRBEV_BUS_RESET 0x0001
#define SRBEV_SCSI_ASYNC_NOTIFICATION 0x0002

#define MAXIMUM_CDB_SIZE 12

#define SCSI_COMBINE_BUS_TARGET(Bus, Target)                            \
    (((((UCHAR)(Target)) & ~(0x20 - 1)) << 8) | (((UCHAR)(Bus)) << 5) | \
     (((UCHAR)(Target)) & (0x20 - 1)))

#define SCSI_DECODE_BUS_TARGET(Value, Bus, Target) \
    (Bus = (UCHAR)((Value) >> 5),                  \
     Target = (UCHAR)((((Value) >> 8) & ~(0x20 - 1)) | ((Value) & (0x20 - 1))))

/* SCSI_REQUEST_BLOCK.Function constants */
#define SRB_FUNCTION_EXECUTE_SCSI 0x00
#define SRB_FUNCTION_CLAIM_DEVICE 0x01
#define SRB_FUNCTION_IO_CONTROL 0x02
#define SRB_FUNCTION_RECEIVE_EVENT 0x03
#define SRB_FUNCTION_RELEASE_QUEUE 0x04
#define SRB_FUNCTION_ATTACH_DEVICE 0x05
#define SRB_FUNCTION_RELEASE_DEVICE 0x06
#define SRB_FUNCTION_SHUTDOWN 0x07
#define SRB_FUNCTION_FLUSH 0x08
#define SRB_FUNCTION_PROTOCOL_COMMAND 0x09
#define SRB_FUNCTION_ABORT_COMMAND 0x10
#define SRB_FUNCTION_RELEASE_RECOVERY 0x11
#define SRB_FUNCTION_RESET_BUS 0x12
#define SRB_FUNCTION_RESET_DEVICE 0x13
#define SRB_FUNCTION_TERMINATE_IO 0x14
#define SRB_FUNCTION_FLUSH_QUEUE 0x15
#define SRB_FUNCTION_REMOVE_DEVICE 0x16
#define SRB_FUNCTION_WMI 0x17
#define SRB_FUNCTION_LOCK_QUEUE 0x18
#define SRB_FUNCTION_UNLOCK_QUEUE 0x19
#define SRB_FUNCTION_QUIESCE_DEVICE 0x1a
#define SRB_FUNCTION_RESET_LOGICAL_UNIT 0x20
#define SRB_FUNCTION_SET_LINK_TIMEOUT 0x21
#define SRB_FUNCTION_LINK_TIMEOUT_OCCURRED 0x22
#define SRB_FUNCTION_LINK_TIMEOUT_COMPLETE 0x23
#define SRB_FUNCTION_POWER 0x24
#define SRB_FUNCTION_PNP 0x25
#define SRB_FUNCTION_DUMP_POINTERS 0x26
#define SRB_FUNCTION_FREE_DUMP_POINTERS 0x27
#define SRB_FUNCTION_STORAGE_REQUEST_BLOCK 0x28 // special value
#define SRB_FUNCTION_CRYPTO_OPERATION 0x29
#define SRB_FUNCTION_GET_DUMP_INFO 0x2a
#define SRB_FUNCTION_FREE_DUMP_INFO 0x2b

/* SCSI_REQUEST_BLOCK.SrbStatus constants */
#define SRB_STATUS_PENDING 0x00
#define SRB_STATUS_SUCCESS 0x01
#define SRB_STATUS_ABORTED 0x02
#define SRB_STATUS_ABORT_FAILED 0x03
#define SRB_STATUS_ERROR 0x04
#define SRB_STATUS_BUSY 0x05
#define SRB_STATUS_INVALID_REQUEST 0x06
#define SRB_STATUS_INVALID_PATH_ID 0x07
#define SRB_STATUS_NO_DEVICE 0x08
#define SRB_STATUS_TIMEOUT 0x09
#define SRB_STATUS_SELECTION_TIMEOUT 0x0A
#define SRB_STATUS_COMMAND_TIMEOUT 0x0B
#define SRB_STATUS_MESSAGE_REJECTED 0x0D
#define SRB_STATUS_BUS_RESET 0x0E
#define SRB_STATUS_PARITY_ERROR 0x0F
#define SRB_STATUS_REQUEST_SENSE_FAILED 0x10
#define SRB_STATUS_NO_HBA 0x11
#define SRB_STATUS_DATA_OVERRUN 0x12
#define SRB_STATUS_UNEXPECTED_BUS_FREE 0x13
#define SRB_STATUS_PHASE_SEQUENCE_FAILURE 0x14
#define SRB_STATUS_BAD_SRB_BLOCK_LENGTH 0x15
#define SRB_STATUS_REQUEST_FLUSHED 0x16
#define SRB_STATUS_INVALID_LUN 0x20
#define SRB_STATUS_INVALID_TARGET_ID 0x21
#define SRB_STATUS_BAD_FUNCTION 0x22
#define SRB_STATUS_ERROR_RECOVERY 0x23
#define SRB_STATUS_NOT_POWERED 0x24
#define SRB_STATUS_LINK_DOWN 0x25
#define SRB_STATUS_INSUFFICIENT_RESOURCES 0x26
#define SRB_STATUS_THROTTLED_REQUEST 0x27
#define SRB_STATUS_INTERNAL_ERROR 0x30

#define SRB_STATUS_QUEUE_FROZEN 0x40
#define SRB_STATUS_AUTOSENSE_VALID 0x80

#define SRB_STATUS(Status) \
    (Status & ~(SRB_STATUS_AUTOSENSE_VALID | SRB_STATUS_QUEUE_FROZEN))

/* SCSI_REQUEST_BLOCK.SrbFlags constants */
#define SRB_FLAGS_QUEUE_ACTION_ENABLE 0x00000002
#define SRB_FLAGS_DISABLE_DISCONNECT 0x00000004
#define SRB_FLAGS_DISABLE_SYNCH_TRANSFER 0x00000008
#define SRB_FLAGS_BYPASS_FROZEN_QUEUE 0x00000010
#define SRB_FLAGS_DISABLE_AUTOSENSE 0x00000020
#define SRB_FLAGS_DATA_IN 0x00000040
#define SRB_FLAGS_DATA_OUT 0x00000080
#define SRB_FLAGS_NO_DATA_TRANSFER 0x00000000
#define SRB_FLAGS_UNSPECIFIED_DIRECTION (SRB_FLAGS_DATA_IN | SRB_FLAGS_DATA_OUT)
#define SRB_FLAGS_NO_QUEUE_FREEZE 0x00000100
#define SRB_FLAGS_ADAPTER_CACHE_ENABLE 0x00000200
#define SRB_FLAGS_FREE_SENSE_BUFFER 0x00000400
#define SRB_FLAGS_D3_PROCESSING 0x00000800
#define SRB_FLAGS_SEQUENTIAL_REQUIRED 0x00001000
#define SRB_FLAGS_IS_ACTIVE 0x00010000
#define SRB_FLAGS_ALLOCATED_FROM_ZONE 0x00020000
#define SRB_FLAGS_SGLIST_FROM_POOL 0x00040000
#define SRB_FLAGS_BYPASS_LOCKED_QUEUE 0x00080000
#define SRB_FLAGS_NO_KEEP_AWAKE 0x00100000
#define SRB_FLAGS_PORT_DRIVER_ALLOCSENSE 0x00200000
#define SRB_FLAGS_PORT_DRIVER_SENSEHASPORT 0x00400000
#define SRB_FLAGS_DONT_START_NEXT_PACKET 0x00800000
#define SRB_FLAGS_PORT_DRIVER_RESERVED 0x0F000000
#define SRB_FLAGS_CLASS_DRIVER_RESERVED 0xF0000000

#define SRB_SIMPLE_TAG_REQUEST 0x20
#define SRB_HEAD_OF_QUEUE_TAG_REQUEST 0x21
#define SRB_ORDERED_QUEUE_TAG_REQUEST 0x22

#define SRB_WMI_FLAGS_ADAPTER_REQUEST 0x0001
#define SRB_POWER_FLAGS_ADAPTER_REQUEST 0x0001
#define SRB_PNP_FLAGS_ADAPTER_REQUEST 0x0001

#define SP_BUS_PARITY_ERROR 0x0001
#define SP_UNEXPECTED_DISCONNECT 0x0002
#define SP_INVALID_RESELECTION 0x0003
#define SP_BUS_TIME_OUT 0x0004
#define SP_PROTOCOL_ERROR 0x0005
#define SP_INTERNAL_ADAPTER_ERROR 0x0006
#define SP_REQUEST_TIMEOUT 0x0007
#define SP_IRQ_NOT_RESPONDING 0x0008
#define SP_BAD_FW_WARNING 0x0009
#define SP_BAD_FW_ERROR 0x000a
#define SP_LOST_WMI_MINIPORT_REQUEST 0x000b

#define SP_VER_TRACE_SUPPORT 0x0010

#define SP_RETURN_NOT_FOUND 0
#define SP_RETURN_FOUND 1
#define SP_RETURN_ERROR 2
#define SP_RETURN_BAD_CONFIG 3

typedef enum _SCSI_ADAPTER_CONTROL_TYPE {
    ScsiQuerySupportedControlTypes = 0,
    ScsiStopAdapter,
    ScsiRestartAdapter,
    ScsiSetBootConfig,
    ScsiSetRunningConfig,
    ScsiAdapterControlMax,
    MakeAdapterControlTypeSizeOfUlong = 0xffffffff
} SCSI_ADAPTER_CONTROL_TYPE, *PSCSI_ADAPTER_CONTROL_TYPE;

typedef enum _SCSI_ADAPTER_CONTROL_STATUS {
    ScsiAdapterControlSuccess = 0,
    ScsiAdapterControlUnsuccessful
} SCSI_ADAPTER_CONTROL_STATUS, *PSCSI_ADAPTER_CONTROL_STATUS;

typedef struct _SCSI_SUPPORTED_CONTROL_TYPE_LIST {
    ULONG MaxControlType;
    BOOLEAN SupportedTypeList[0];
} SCSI_SUPPORTED_CONTROL_TYPE_LIST, *PSCSI_SUPPORTED_CONTROL_TYPE_LIST;

typedef struct _SCSI_REQUEST_BLOCK {
    USHORT Length;
    UCHAR Function;
    UCHAR SrbStatus;
    UCHAR ScsiStatus;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR QueueTag;
    UCHAR QueueAction;
    UCHAR CdbLength;
    UCHAR SenseInfoBufferLength;
    ULONG SrbFlags;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    _Field_size_bytes_(DataTransferLength) PVOID DataBuffer;
    PVOID SenseInfoBuffer;
    struct _SCSI_REQUEST_BLOCK *NextSrb;
    PVOID OriginalRequest;
    PVOID SrbExtension;
    _ANONYMOUS_UNION union {
	ULONG InternalStatus;
	ULONG QueueSortKey;
	ULONG LinkTimeoutValue;
    } DUMMYUNIONNAME;
#if defined(_WIN64)
    ULONG Reserved;
#endif
    UCHAR Cdb[16];
} SCSI_REQUEST_BLOCK, *PSCSI_REQUEST_BLOCK;

#define SCSI_REQUEST_BLOCK_SIZE sizeof(SCSI_REQUEST_BLOCK)

typedef struct _SCSI_WMI_REQUEST_BLOCK {
    USHORT Length;
    UCHAR Function;
    UCHAR SrbStatus;
    UCHAR WMISubFunction;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    UCHAR Reserved1;
    UCHAR WMIFlags;
    UCHAR Reserved2[2];
    ULONG SrbFlags;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    PVOID DataBuffer;
    PVOID DataPath;
    PVOID Reserved3;
    PVOID OriginalRequest;
    PVOID SrbExtension;
    ULONG Reserved4;
#if (NTDDI_VERSION >= NTDDI_WS03SP1) && defined(_WIN64)
    ULONG Reserved6;
#endif
    UCHAR Reserved5[16];
} SCSI_WMI_REQUEST_BLOCK, *PSCSI_WMI_REQUEST_BLOCK;

typedef enum _STOR_DEVICE_POWER_STATE {
    StorPowerDeviceUnspecified = 0,
    StorPowerDeviceD0,
    StorPowerDeviceD1,
    StorPowerDeviceD2,
    StorPowerDeviceD3,
    StorPowerDeviceMaximum
} STOR_DEVICE_POWER_STATE, *PSTOR_DEVICE_POWER_STATE;

typedef enum _STOR_POWER_ACTION {
    StorPowerActionNone = 0,
    StorPowerActionReserved,
    StorPowerActionSleep,
    StorPowerActionHibernate,
    StorPowerActionShutdown,
    StorPowerActionShutdownReset,
    StorPowerActionShutdownOff,
    StorPowerActionWarmEject
} STOR_POWER_ACTION, *PSTOR_POWER_ACTION;

typedef struct _SCSI_POWER_REQUEST_BLOCK {
    USHORT Length;
    UCHAR Function;
    UCHAR SrbStatus;
    UCHAR SrbPowerFlags;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    STOR_DEVICE_POWER_STATE DevicePowerState;
    ULONG SrbFlags;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    PVOID DataBuffer;
    PVOID SenseInfoBuffer;
    struct _SCSI_REQUEST_BLOCK *NextSrb;
    PVOID OriginalRequest;
    PVOID SrbExtension;
    STOR_POWER_ACTION PowerAction;
#if defined(_WIN64)
    ULONG Reserved;
#endif
    UCHAR Reserved5[16];
} SCSI_POWER_REQUEST_BLOCK, *PSCSI_POWER_REQUEST_BLOCK;

typedef enum _STOR_PNP_ACTION {
    StorStartDevice = 0x0,
    StorRemoveDevice = 0x2,
    StorStopDevice = 0x4,
    StorQueryCapabilities = 0x9,
    StorQueryResourceRequirements = 0xB,
    StorFilterResourceRequirements = 0xD,
    StorSurpriseRemoval = 0x17
} STOR_PNP_ACTION, *PSTOR_PNP_ACTION;

typedef struct _STOR_DEVICE_CAPABILITIES {
    USHORT Version;
    ULONG DeviceD1 : 1;
    ULONG DeviceD2 : 1;
    ULONG LockSupported : 1;
    ULONG EjectSupported : 1;
    ULONG Removable : 1;
    ULONG DockDevice : 1;
    ULONG UniqueID : 1;
    ULONG SilentInstall : 1;
    ULONG SurpriseRemovalOK : 1;
    ULONG NoDisplayInUI : 1;
} STOR_DEVICE_CAPABILITIES, *PSTOR_DEVICE_CAPABILITIES;

typedef struct _SCSI_PNP_REQUEST_BLOCK {
    USHORT Length;
    UCHAR Function;
    UCHAR SrbStatus;
    UCHAR PnPSubFunction;
    UCHAR PathId;
    UCHAR TargetId;
    UCHAR Lun;
    STOR_PNP_ACTION PnPAction;
    ULONG SrbFlags;
    ULONG DataTransferLength;
    ULONG TimeOutValue;
    PVOID DataBuffer;
    PVOID SenseInfoBuffer;
    struct _SCSI_REQUEST_BLOCK *NextSrb;
    PVOID OriginalRequest;
    PVOID SrbExtension;
    ULONG SrbPnPFlags;
#if defined(_WIN64)
    ULONG Reserved;
#endif
    UCHAR Reserved4[16];
} SCSI_PNP_REQUEST_BLOCK, *PSCSI_PNP_REQUEST_BLOCK;

#if (NTDDI_VERSION >= NTDDI_WIN8)
#if defined(_WIN64)
#define SRB_ALIGN DECLSPEC_ALIGN(8)
#define POINTER_ALIGN DECLSPEC_ALIGN(8)
#else
#define SRB_ALIGN
#define POINTER_ALIGN
#endif

typedef enum _SRBEXDATATYPE {
    SrbExDataTypeUnknown = 0,
    SrbExDataTypeBidirectional,
    SrbExDataTypeScsiCdb16 = 0x40,
    SrbExDataTypeScsiCdb32,
    SrbExDataTypeScsiCdbVar,
    SrbExDataTypeWmi = 0x60,
    SrbExDataTypePower,
    SrbExDataTypePnP,
    SrbExDataTypeIoInfo = 0x80,
    SrbExDataTypeMSReservedStart = 0xf0000000,
    SrbExDataTypeReserved = 0xffffffff
} SRBEXDATATYPE, *PSRBEXDATATYPE;

typedef struct SRB_ALIGN _SRBEX_DATA {
    SRBEXDATATYPE Type;
    ULONG Length;
    _Field_size_bytes_(Length) UCHAR Data[ANYSIZE_ARRAY];
} SRBEX_DATA, *PSRBEX_DATA;

#define SRBEX_DATA_BIDIRECTIONAL_LENGTH ((2 * sizeof(ULONG)) + sizeof(PVOID))

typedef struct SRB_ALIGN _SRBEX_DATA_BIDIRECTIONAL {
    _Field_range_(SrbExDataTypeBidirectional,
		  SrbExDataTypeBidirectional) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_BIDIRECTIONAL_LENGTH,
		  SRBEX_DATA_BIDIRECTIONAL_LENGTH) ULONG Length;
    ULONG DataInTransferLength;
    ULONG Reserved1;
    _Field_size_bytes_full_(DataInTransferLength) PVOID POINTER_ALIGN DataInBuffer;
} SRBEX_DATA_BIDIRECTIONAL, *PSRBEX_DATA_BIDIRECTIONAL;

#define SRBEX_DATA_SCSI_CDB16_LENGTH \
    ((20 * sizeof(UCHAR)) + sizeof(ULONG) + sizeof(PVOID))

typedef struct SRB_ALIGN _SRBEX_DATA_SCSI_CDB16 {
    _Field_range_(SrbExDataTypeScsiCdb16, SrbExDataTypeScsiCdb16) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_SCSI_CDB16_LENGTH,
		  SRBEX_DATA_SCSI_CDB16_LENGTH) ULONG Length;
    UCHAR ScsiStatus;
    UCHAR SenseInfoBufferLength;
    UCHAR CdbLength;
    UCHAR Reserved;
    ULONG Reserved1;
    _Field_size_bytes_full_(SenseInfoBufferLength) PVOID POINTER_ALIGN SenseInfoBuffer;
    UCHAR POINTER_ALIGN Cdb[16];
} SRBEX_DATA_SCSI_CDB16, *PSRBEX_DATA_SCSI_CDB16;

#define SRBEX_DATA_SCSI_CDB32_LENGTH \
    ((36 * sizeof(UCHAR)) + sizeof(ULONG) + sizeof(PVOID))

typedef struct SRB_ALIGN _SRBEX_DATA_SCSI_CDB32 {
    _Field_range_(SrbExDataTypeScsiCdb32, SrbExDataTypeScsiCdb32) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_SCSI_CDB32_LENGTH,
		  SRBEX_DATA_SCSI_CDB32_LENGTH) ULONG Length;
    UCHAR ScsiStatus;
    UCHAR SenseInfoBufferLength;
    UCHAR CdbLength;
    UCHAR Reserved;
    ULONG Reserved1;
    _Field_size_bytes_full_(SenseInfoBufferLength) PVOID POINTER_ALIGN SenseInfoBuffer;
    UCHAR POINTER_ALIGN Cdb[32];
} SRBEX_DATA_SCSI_CDB32, *PSRBEX_DATA_SCSI_CDB32;

#define SRBEX_DATA_SCSI_CDB_VAR_LENGTH_MIN \
    ((4 * sizeof(UCHAR)) + (3 * sizeof(ULONG)) + sizeof(PVOID))
#define SRBEX_DATA_SCSI_CDB_VAR_LENGTH_MAX 0xffffffffUL

typedef struct SRB_ALIGN _SRBEX_DATA_SCSI_CDB_VAR {
    _Field_range_(SrbExDataTypeScsiCdbVar, SrbExDataTypeScsiCdbVar) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_SCSI_CDB_VAR_LENGTH_MIN,
		  SRBEX_DATA_SCSI_CDB_VAR_LENGTH_MAX) ULONG Length;
    UCHAR ScsiStatus;
    UCHAR SenseInfoBufferLength;
    UCHAR Reserved[2];
    ULONG CdbLength;
    ULONG Reserved1[2];
    _Field_size_bytes_full_(SenseInfoBufferLength) PVOID POINTER_ALIGN SenseInfoBuffer;
    _Field_size_bytes_full_(CdbLength) UCHAR POINTER_ALIGN Cdb[ANYSIZE_ARRAY];
} SRBEX_DATA_SCSI_CDB_VAR, *PSRBEX_DATA_SCSI_CDB_VAR;

#define SRBEX_DATA_WMI_LENGTH ((4 * sizeof(UCHAR)) + sizeof(ULONG) + sizeof(PVOID))

typedef struct SRB_ALIGN _SRBEX_DATA_WMI {
    _Field_range_(SrbExDataTypeWmi, SrbExDataTypeWmi) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_WMI_LENGTH, SRBEX_DATA_WMI_LENGTH) ULONG Length;
    UCHAR WMISubFunction;
    UCHAR WMIFlags;
    UCHAR Reserved[2];
    ULONG Reserved1;
    PVOID POINTER_ALIGN DataPath;
} SRBEX_DATA_WMI, *PSRBEX_DATA_WMI;

#define SRBEX_DATA_POWER_LENGTH \
    ((4 * sizeof(UCHAR)) + sizeof(STOR_DEVICE_POWER_STATE) + sizeof(STOR_POWER_ACTION))

typedef struct SRB_ALIGN _SRBEX_DATA_POWER {
    _Field_range_(SrbExDataTypePower, SrbExDataTypePower) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_POWER_LENGTH, SRBEX_DATA_POWER_LENGTH) ULONG Length;
    UCHAR SrbPowerFlags;
    UCHAR Reserved[3];
    STOR_DEVICE_POWER_STATE DevicePowerState;
    STOR_POWER_ACTION PowerAction;
} SRBEX_DATA_POWER, *PSRBEX_DATA_POWER;

#define SRBEX_DATA_PNP_LENGTH \
    ((4 * sizeof(UCHAR)) + sizeof(STOR_PNP_ACTION) + (2 * sizeof(ULONG)))

typedef struct SRB_ALIGN _SRBEX_DATA_PNP {
    _Field_range_(SrbExDataTypePnP, SrbExDataTypePnP) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_PNP_LENGTH, SRBEX_DATA_PNP_LENGTH) ULONG Length;
    UCHAR PnPSubFunction;
    UCHAR Reserved[3];
    STOR_PNP_ACTION PnPAction;
    ULONG SrbPnPFlags;
    ULONG Reserved1;
} SRBEX_DATA_PNP, *PSRBEX_DATA_PNP;

#define SRBEX_DATA_IO_INFO_LENGTH ((5 * sizeof(ULONG)) + (4 * sizeof(UCHAR)))

#define REQUEST_INFO_NO_CACHE_FLAG 0x00000001
#define REQUEST_INFO_PAGING_IO_FLAG 0x00000002
#define REQUEST_INFO_SEQUENTIAL_IO_FLAG 0x00000004
#define REQUEST_INFO_TEMPORARY_FLAG 0x00000008
#define REQUEST_INFO_WRITE_THROUGH_FLAG 0x00000010
#define REQUEST_INFO_HYBRID_WRITE_THROUGH_FLAG 0x00000020

#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)

#define REQUEST_INFO_NO_FILE_OBJECT_FLAG 0x00000040
#define REQUEST_INFO_VOLSNAP_IO_FLAG 0x00000080
#define REQUEST_INFO_STREAM_FLAG 0x00000100

#endif /* (NTDDI_VERSION >= NTDDI_WINTHRESHOLD) */

#define REQUEST_INFO_VALID_CACHEPRIORITY_FLAG 0x80000000

typedef struct SRB_ALIGN _SRBEX_DATA_IO_INFO {
    _Field_range_(SrbExDataTypeIoInfo, SrbExDataTypeIoInfo) SRBEXDATATYPE Type;
    _Field_range_(SRBEX_DATA_IO_INFO_LENGTH, SRBEX_DATA_IO_INFO_LENGTH) ULONG Length;
    ULONG Flags;
    ULONG Key;
    ULONG RWLength;
    BOOLEAN IsWriteRequest;
    UCHAR CachePriority;
    UCHAR Reserved[2];
    ULONG Reserved1[2];
} SRBEX_DATA_IO_INFO, *PSRBEX_DATA_IO_INFO;

#define SRB_SIGNATURE 0x53524258
#define STORAGE_REQUEST_BLOCK_VERSION_1 0x1

typedef struct SRB_ALIGN _STORAGE_REQUEST_BLOCK_HEADER {
    USHORT Length;
    _Field_range_(SRB_FUNCTION_STORAGE_REQUEST_BLOCK,
		  SRB_FUNCTION_STORAGE_REQUEST_BLOCK) UCHAR Function;
    UCHAR SrbStatus;
} STORAGE_REQUEST_BLOCK_HEADER, *PSTORAGE_REQUEST_BLOCK_HEADER;

typedef _Struct_size_bytes_(SrbLength) struct SRB_ALIGN _STORAGE_REQUEST_BLOCK {
    USHORT Length;
    _Field_range_(SRB_FUNCTION_STORAGE_REQUEST_BLOCK,
		  SRB_FUNCTION_STORAGE_REQUEST_BLOCK) UCHAR Function;
    UCHAR SrbStatus;
    UCHAR ReservedUchar[4];
    _Field_range_(SRB_SIGNATURE, SRB_SIGNATURE) ULONG Signature;
    _Field_range_(STORAGE_REQUEST_BLOCK_VERSION_1,
		  STORAGE_REQUEST_BLOCK_VERSION_1) ULONG Version;
    ULONG SrbLength;
    ULONG SrbFunction;
    ULONG SrbFlags;
    ULONG ReservedUlong;
    ULONG RequestTag;
    USHORT RequestPriority;
    USHORT RequestAttribute;
    ULONG TimeOutValue;
    ULONG SystemStatus;
    ULONG ZeroGuard1;
    _Field_range_(sizeof(STORAGE_REQUEST_BLOCK),
		  SrbLength - sizeof(STOR_ADDRESS)) ULONG AddressOffset;
    ULONG NumSrbExData;
    ULONG DataTransferLength;
    _Field_size_bytes_full_(DataTransferLength) PVOID POINTER_ALIGN DataBuffer;
    PVOID POINTER_ALIGN ZeroGuard2;
    PVOID POINTER_ALIGN OriginalRequest;
    PVOID POINTER_ALIGN ClassContext;
    PVOID POINTER_ALIGN PortContext;
    PVOID POINTER_ALIGN MiniportContext;
    struct _STORAGE_REQUEST_BLOCK POINTER_ALIGN *NextSrb;
    _At_buffer_(SrbExDataOffset, _Iter_, NumSrbExData,
		_Field_range_(0, SrbLength - sizeof(SRBEX_DATA)))
	_Field_size_(NumSrbExData) ULONG SrbExDataOffset[ANYSIZE_ARRAY];
} STORAGE_REQUEST_BLOCK, *PSTORAGE_REQUEST_BLOCK;

#define SRB_TYPE_SCSI_REQUEST_BLOCK 0
#define SRB_TYPE_STORAGE_REQUEST_BLOCK 1

#define STORAGE_ADDRESS_TYPE_BTL8 0
#endif /* (NTDDI_VERSION >= NTDDI_WIN8) */

#endif /* _NTSRB_ */
