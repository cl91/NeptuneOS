
#pragma once

#define _CLASS_

#include <ntddk.h>
#include <srb.h>
#include <srbhelper.h>
#include <ntdddisk.h>
#include <ntddcdrm.h>
#include <ntddtape.h>
#include <ntddscsi.h>
#include <ntddstor.h>

#include <stdio.h>

#include <scsi.h>

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))

#define SRB_CLASS_FLAGS_LOW_PRIORITY 0x10000000
#define SRB_CLASS_FLAGS_PERSISTANT 0x20000000
#define SRB_CLASS_FLAGS_PAGING 0x40000000
#define SRB_CLASS_FLAGS_FREE_MDL 0x80000000

#define ASSERT_FDO(x) ASSERT(((PCOMMON_DEVICE_EXTENSION)(x)->DeviceExtension)->IsFdo)

#define ASSERT_PDO(x) ASSERT(!(((PCOMMON_DEVICE_EXTENSION)(x)->DeviceExtension)->IsFdo))

#define IS_CLEANUP_REQUEST(majorFunction)				\
    ((majorFunction == IRP_MJ_CLOSE) || (majorFunction == IRP_MJ_CLEANUP) || \
     (majorFunction == IRP_MJ_SHUTDOWN))

#define DO_MCD(fdoExtension)						\
    (((fdoExtension)->MediaChangeDetectionInfo != NULL) &&		\
     ((fdoExtension)->MediaChangeDetectionInfo->MediaChangeDetectionDisableCount == 0))

#define IS_SCSIOP_READ(opCode)						\
    ((opCode == SCSIOP_READ6) || (opCode == SCSIOP_READ) || (opCode == SCSIOP_READ12) || \
     (opCode == SCSIOP_READ16))

#define IS_SCSIOP_WRITE(opCode)					\
    ((opCode == SCSIOP_WRITE6) || (opCode == SCSIOP_WRITE) ||	\
     (opCode == SCSIOP_WRITE12) || (opCode == SCSIOP_WRITE16))

#define IS_SCSIOP_READWRITE(opCode) (IS_SCSIOP_READ(opCode) || IS_SCSIOP_WRITE(opCode))

#define ADJUST_FUA_FLAG(fdoExt)						\
    {									\
	if (TEST_FLAG(fdoExt->DeviceFlags, DEV_WRITE_CACHE) &&		\
	    !TEST_FLAG(fdoExt->DeviceFlags, DEV_POWER_PROTECTED) &&	\
	    !TEST_FLAG(fdoExt->ScanForSpecialFlags, CLASS_SPECIAL_FUA_NOT_SUPPORTED)) { \
	    fdoExt->CdbForceUnitAccess = TRUE;				\
	} else {							\
	    fdoExt->CdbForceUnitAccess = FALSE;				\
	}								\
    }

#define FREE_POOL(_PoolPtr)			\
    if (_PoolPtr != NULL) {			\
	ExFreePool(_PoolPtr);			\
	_PoolPtr = NULL;			\
    }

#ifdef POOL_TAGGING
#undef ExAllocatePool
#undef ExAllocatePoolWithQuota
#define ExAllocatePool(a, b) ExAllocatePoolWithTag(a, b, 'nUcS')
#define ExAllocatePoolWithQuota(a, b) ExAllocatePoolWithQuotaTag(a, b, 'nUcS')
#endif

#define CLASS_TAG_AUTORUN_DISABLE 'ALcS'
#define CLASS_TAG_FILE_OBJECT_EXTENSION 'FLcS'
#define CLASS_TAG_MEDIA_CHANGE_DETECTION 'MLcS'
#define CLASS_TAG_MOUNT 'mLcS'
#define CLASS_TAG_RELEASE_QUEUE 'qLcS'
#define CLASS_TAG_POWER 'WLcS'
#define CLASS_TAG_WMI 'wLcS'
#define CLASS_TAG_FAILURE_PREDICT 'fLcS'
#define CLASS_TAG_DEVICE_CONTROL 'OIcS'
#define CLASS_TAG_MODE_DATA 'oLcS'
#define CLASS_TAG_MULTIPATH 'mPcS'
#define CLASS_TAG_LOCK_TRACKING 'TLcS'
#define CLASS_TAG_LB_PROVISIONING 'PLcS'
#define CLASS_TAG_MANAGE_DATASET 'MDcS'

#define MAXIMUM_RETRIES 4

#define CLASS_DRIVER_EXTENSION_KEY ((PVOID)ClassInitialize)

#define NO_REMOVE 0
#define REMOVE_PENDING 1
#define REMOVE_COMPLETE 2

#define ClassAcquireRemoveLock(devobj, tag)			\
    ClassAcquireRemoveLockEx(devobj, tag, __FILE__, __LINE__)

#ifdef DebugPrint
#undef DebugPrint
#endif

#if DBG
#define DebugPrint(x) ClassDebugPrint x
#else
#define DebugPrint(x)
#endif

#define DEBUG_BUFFER_LENGTH 256

#define START_UNIT_TIMEOUT (60 * 4)

#define MEDIA_CHANGE_DEFAULT_TIME 1
#define MEDIA_CHANGE_TIMEOUT_TIME 300

#ifdef ALLOCATE_SRB_FROM_POOL

#define ClasspAllocateSrb(ext)						\
    ExAllocatePoolWithTag(sizeof(SCSI_REQUEST_BLOCK), 'sBRS')

#define ClasspFreeSrb(ext, srb) ExFreePool((srb));

#else /* ALLOCATE_SRB_FROM_POOL */

#define ClasspAllocateSrb(ext)						\
    ExAllocateFromLookasideList(&((ext)->CommonExtension.SrbLookasideList))

#define ClasspFreeSrb(ext, srb)						\
    ExFreeToLookasideList(&((ext)->CommonExtension.SrbLookasideList), (srb))

#endif /* ALLOCATE_SRB_FROM_POOL */

#define CLASS_WORKING_SET_MAXIMUM 2048

#define CLASS_INTERPRET_SENSE_INFO2_MAXIMUM_HISTORY_COUNT 30000

#define CLASS_SPECIAL_DISABLE_SPIN_DOWN 0x00000001
#define CLASS_SPECIAL_DISABLE_SPIN_UP 0x00000002
#define CLASS_SPECIAL_NO_QUEUE_LOCK 0x00000008
#define CLASS_SPECIAL_DISABLE_WRITE_CACHE 0x00000010
#define CLASS_SPECIAL_CAUSE_NOT_REPORTABLE_HACK 0x00000020
#define CLASS_SPECIAL_MODIFY_CACHE_UNSUCCESSFUL 0x00000040
#define CLASS_SPECIAL_FUA_NOT_SUPPORTED 0x00000080
#define CLASS_SPECIAL_VALID_MASK 0x000000FB
#define CLASS_SPECIAL_RESERVED (~CLASS_SPECIAL_VALID_MASK)

#define DEV_WRITE_CACHE 0x00000001
#define DEV_USE_SCSI1 0x00000002
#define DEV_SAFE_START_UNIT 0x00000004
#define DEV_NO_12BYTE_CDB 0x00000008
#define DEV_POWER_PROTECTED 0x00000010
#define DEV_USE_16BYTE_CDB 0x00000020

#define GUID_CLASSPNP_QUERY_REGINFOEX				\
    {								\
	0x00e34b11, 0x2444, 0x4745,				\
	{							\
	    0xa5, 0x3d, 0x62, 0x01, 0x00, 0xcd, 0x82, 0xf7	\
	}							\
    }
#define GUID_CLASSPNP_SENSEINFO2				\
    {								\
	0x509a8c5f, 0x71d7, 0x48f6,				\
	{							\
	    0x82, 0x1e, 0x17, 0x3c, 0x49, 0xbf, 0x2f, 0x18	\
	}							\
    }
#define GUID_CLASSPNP_WORKING_SET				\
    {								\
	0x105701b0, 0x9e9b, 0x47cb,				\
	{							\
	    0x97, 0x80, 0x81, 0x19, 0x8a, 0xf7, 0xb5, 0x24	\
	}							\
    }
#define GUID_CLASSPNP_SRB_SUPPORT				\
    {								\
	0x0a483941, 0xbdfd, 0x4f7b,				\
	{							\
	    0xbe, 0x95, 0xce, 0xe2, 0xa2, 0x16, 0x09, 0x0c	\
	}							\
    }

#define DEFAULT_FAILURE_PREDICTION_PERIOD 60 * 60 * 1

#define MAXIMUM_RETRY_FOR_SINGLE_IO_IN_100NS_UNITS (0x3b9aca00)

FORCEINLINE ULONG CountOfSetBitsUChar(UCHAR X)
{
    ULONG i = 0;
    while (X) {
	X &= X - 1;
	i++;
    }
    return i;
}
FORCEINLINE ULONG CountOfSetBitsULong(ULONG X)
{
    ULONG i = 0;
    while (X) {
	X &= X - 1;
	i++;
    }
    return i;
}
FORCEINLINE ULONG CountOfSetBitsULong32(ULONG X)
{
    ULONG i = 0;
    while (X) {
	X &= X - 1;
	i++;
    }
    return i;
}
FORCEINLINE ULONG CountOfSetBitsULong64(ULONG64 X)
{
    ULONG i = 0;
    while (X) {
	X &= X - 1;
	i++;
    }
    return i;
}
FORCEINLINE ULONG CountOfSetBitsUlongPtr(ULONG_PTR X)
{
    ULONG i = 0;
    while (X) {
	X &= X - 1;
	i++;
    }
    return i;
}

typedef enum _MEDIA_CHANGE_DETECTION_STATE {
    MediaUnknown,
    MediaPresent,
    MediaNotPresent,
    MediaUnavailable
} MEDIA_CHANGE_DETECTION_STATE, *PMEDIA_CHANGE_DETECTION_STATE;

typedef enum _CLASS_DEBUG_LEVEL {
    ClassDebugError = 0,
    ClassDebugWarning = 1,
    ClassDebugTrace = 2,
    ClassDebugInfo = 3,
    ClassDebugMediaLocks = 8,
    ClassDebugMCN = 9,
    ClassDebugDelayedRetry = 10,
    ClassDebugSenseInfo = 11,
    ClassDebugRemoveLock = 12,
    ClassDebugExternal4 = 13,
    ClassDebugExternal3 = 14,
    ClassDebugExternal2 = 15,
    ClassDebugExternal1 = 16
} CLASS_DEBUG_LEVEL, *PCLASS_DEBUG_LEVEL;

typedef enum { EventGeneration, DataBlockCollection } CLASSENABLEDISABLEFUNCTION;

typedef enum {
    FailurePredictionNone = 0,
    FailurePredictionIoctl,
    FailurePredictionSmart,
    FailurePredictionSense
} FAILURE_PREDICTION_METHOD, *PFAILURE_PREDICTION_METHOD;

typedef enum {
    PowerDownDeviceInitial,
    PowerDownDeviceLocked,
    PowerDownDeviceStopped,
    PowerDownDeviceOff,
    PowerDownDeviceUnlocked
} CLASS_POWER_DOWN_STATE;

typedef enum {
    PowerDownDeviceInitial2,
    PowerDownDeviceLocked2,
    PowerDownDeviceFlushed2,
    PowerDownDeviceStopped2,
    PowerDownDeviceOff2,
    PowerDownDeviceUnlocked2
} CLASS_POWER_DOWN_STATE2;

typedef enum {
    PowerDownDeviceInitial3 = 0,
    PowerDownDeviceLocked3,
    PowerDownDeviceQuiesced3,
    PowerDownDeviceFlushed3,
    PowerDownDeviceStopped3,
    PowerDownDeviceOff3,
    PowerDownDeviceUnlocked3
} CLASS_POWER_DOWN_STATE3;

typedef enum {
    PowerUpDeviceInitial,
    PowerUpDeviceLocked,
    PowerUpDeviceOn,
    PowerUpDeviceStarted,
    PowerUpDeviceUnlocked
} CLASS_POWER_UP_STATE;

struct _CLASS_INIT_DATA;
typedef struct _CLASS_INIT_DATA CLASS_INIT_DATA, *PCLASS_INIT_DATA;

struct _CLASS_PRIVATE_FDO_DATA;
typedef struct _CLASS_PRIVATE_FDO_DATA CLASS_PRIVATE_FDO_DATA, *PCLASS_PRIVATE_FDO_DATA;

struct _MEDIA_CHANGE_DETECTION_INFO;
typedef struct _MEDIA_CHANGE_DETECTION_INFO MEDIA_CHANGE_DETECTION_INFO, *PMEDIA_CHANGE_DETECTION_INFO;

struct _DICTIONARY_HEADER;
typedef struct _DICTIONARY_HEADER DICTIONARY_HEADER, *PDICTIONARY_HEADER;

typedef struct _DICTIONARY {
    ULONGLONG Signature;
    struct _DICTIONARY_HEADER *List;
} DICTIONARY, *PDICTIONARY;

typedef struct _CLASSPNP_SCAN_FOR_SPECIAL_INFO {
    PCHAR VendorId;
    PCHAR ProductId;
    PCHAR ProductRevision;
    ULONG_PTR Data;
} CLASSPNP_SCAN_FOR_SPECIAL_INFO, *PCLASSPNP_SCAN_FOR_SPECIAL_INFO;

typedef VOID (NTAPI *PCLASS_ERROR)(IN PDEVICE_OBJECT DeviceObject,
				   IN PSTORAGE_REQUEST_BLOCK Srb,
				   OUT NTSTATUS *Status, IN OUT BOOLEAN *Retry);

typedef NTSTATUS (NTAPI *PCLASS_ADD_DEVICE)(IN PDRIVER_OBJECT DriverObject,
					    IN PDEVICE_OBJECT Pdo);

typedef NTSTATUS (NTAPI *PCLASS_POWER_DEVICE)(IN PDEVICE_OBJECT DeviceObject,
					      IN PIRP Irp);

typedef NTSTATUS (NTAPI *PCLASS_START_DEVICE)(IN PDEVICE_OBJECT DeviceObject);

typedef NTSTATUS (NTAPI *PCLASS_STOP_DEVICE)(IN PDEVICE_OBJECT DeviceObject,
					     IN UCHAR Type);

typedef NTSTATUS (NTAPI *PCLASS_INIT_DEVICE)(IN PDEVICE_OBJECT DeviceObject);

typedef NTSTATUS (NTAPI *PCLASS_ENUM_DEVICE)(IN PDEVICE_OBJECT DeviceObject);

typedef NTSTATUS (NTAPI *PCLASS_READ_WRITE)(IN PDEVICE_OBJECT DeviceObject,
					    IN PIRP Irp);

typedef NTSTATUS (NTAPI *PCLASS_DEVICE_CONTROL)(IN PDEVICE_OBJECT DeviceObject,
						IN PIRP Irp);

typedef NTSTATUS (NTAPI *PCLASS_SHUTDOWN_FLUSH)(IN PDEVICE_OBJECT DeviceObject,
						IN PIRP Irp);

typedef NTSTATUS (NTAPI *PCLASS_CREATE_CLOSE)(IN PDEVICE_OBJECT DeviceObject,
					      IN PIRP Irp);

typedef NTSTATUS (NTAPI *PCLASS_QUERY_ID)(IN PDEVICE_OBJECT DeviceObject,
					  IN BUS_QUERY_ID_TYPE IdType,
					  IN PUNICODE_STRING IdString);

typedef NTSTATUS (NTAPI *PCLASS_REMOVE_DEVICE)(IN PDEVICE_OBJECT DeviceObject,
					       IN UCHAR Type);

typedef VOID (NTAPI *PCLASS_UNLOAD)(IN PDRIVER_OBJECT DriverObject);

typedef NTSTATUS (NTAPI *PCLASS_QUERY_PNP_CAPABILITIES)(IN PDEVICE_OBJECT PhysicalDeviceObject,
							IN PDEVICE_CAPABILITIES Capabilities);

typedef VOID (NTAPI *PCLASS_TICK)(IN PDEVICE_OBJECT DeviceObject);

typedef NTSTATUS (NTAPI *PCLASS_QUERY_WMI_REGINFO_EX)(IN PDEVICE_OBJECT DeviceObject,
						      OUT ULONG *RegFlags,
						      OUT PUNICODE_STRING Name,
						      OUT PUNICODE_STRING MofResourceName);

typedef NTSTATUS (NTAPI *PCLASS_QUERY_WMI_REGINFO)(IN PDEVICE_OBJECT DeviceObject,
						   OUT ULONG *RegFlags,
						   OUT PUNICODE_STRING Name);

typedef NTSTATUS (NTAPI *PCLASS_QUERY_WMI_DATABLOCK)(IN PDEVICE_OBJECT DeviceObject,
						     IN PIRP Irp,
						     IN ULONG GuidIndex,
						     IN ULONG BufferAvail,
						     OUT PUCHAR Buffer);

typedef NTSTATUS (NTAPI *PCLASS_SET_WMI_DATABLOCK)(IN PDEVICE_OBJECT DeviceObject,
						   IN PIRP Irp,
						   IN ULONG GuidIndex,
						   IN ULONG BufferSize,
						   IN PUCHAR Buffer);

typedef NTSTATUS (NTAPI *PCLASS_SET_WMI_DATAITEM)(IN PDEVICE_OBJECT DeviceObject,
						  IN PIRP Irp,
						  IN ULONG GuidIndex,
						  IN ULONG DataItemId,
						  IN ULONG BufferSize,
						  IN PUCHAR Buffer);

typedef NTSTATUS (NTAPI *PCLASS_EXECUTE_WMI_METHOD)(IN PDEVICE_OBJECT DeviceObject,
						    IN PIRP Irp,
						    IN ULONG GuidIndex,
						    IN ULONG MethodId,
						    IN ULONG InBufferSize,
						    IN ULONG OutBufferSize,
						    IN PUCHAR Buffer);

typedef NTSTATUS (NTAPI *PCLASS_WMI_FUNCTION_CONTROL)(IN PDEVICE_OBJECT DeviceObject,
						      IN PIRP Irp,
						      IN ULONG GuidIndex,
						      IN CLASSENABLEDISABLEFUNCTION Function,
						      IN BOOLEAN Enable);

typedef struct _SRB_HISTORY_ITEM {
    LARGE_INTEGER TickCountSent;
    LARGE_INTEGER TickCountCompleted;
    ULONG MillisecondsDelayOnRetry;
    SENSE_DATA NormalizedSenseData;
    UCHAR SrbStatus;
    UCHAR ClassDriverUse;
} SRB_HISTORY_ITEM, *PSRB_HISTORY_ITEM;

typedef struct _SRB_HISTORY {
    ULONG_PTR ClassDriverUse[4];
    ULONG TotalHistoryCount;
    ULONG UsedHistoryCount;
    SRB_HISTORY_ITEM History[1];
} SRB_HISTORY, *PSRB_HISTORY;

typedef BOOLEAN (NTAPI *PCLASS_INTERPRET_SENSE_INFO)(IN PDEVICE_OBJECT Fdo,
						     IN OPTIONAL PIRP OriginalRequest,
						     IN PSTORAGE_REQUEST_BLOCK Srb,
						     IN UCHAR MajorFunctionCode,
						     IN ULONG IoDeviceCode,
						     IN ULONG PreviousRetryCount,
						     IN OPTIONAL SRB_HISTORY *RequestHistory,
						     OUT NTSTATUS *Status,
						     OUT LONGLONG *RetryIn100nsUnits);

typedef VOID (NTAPI *PCLASS_COMPRESS_RETRY_HISTORY_DATA)(IN PDEVICE_OBJECT DeviceObject,
							 IN OUT PSRB_HISTORY RequestHistory);

typedef struct {
    GUID Guid;
    ULONG InstanceCount;
    ULONG Flags;
} GUIDREGINFO, *PGUIDREGINFO;

typedef struct _CLASS_WMI_INFO {
    ULONG GuidCount;
    PGUIDREGINFO GuidRegInfo;
    PCLASS_QUERY_WMI_REGINFO ClassQueryWmiRegInfo;
    PCLASS_QUERY_WMI_DATABLOCK ClassQueryWmiDataBlock;
    PCLASS_SET_WMI_DATABLOCK ClassSetWmiDataBlock;
    PCLASS_SET_WMI_DATAITEM ClassSetWmiDataItem;
    PCLASS_EXECUTE_WMI_METHOD ClassExecuteWmiMethod;
    PCLASS_WMI_FUNCTION_CONTROL ClassWmiFunctionControl;
} CLASS_WMI_INFO, *PCLASS_WMI_INFO;

typedef struct _CLASS_DEV_INFO {
    ULONG DeviceExtensionSize;
    DEVICE_TYPE DeviceType;
    UCHAR StackSize;
    ULONG DeviceCharacteristics;
    PCLASS_ERROR ClassError;
    PCLASS_READ_WRITE ClassReadWriteVerification;
    PCLASS_DEVICE_CONTROL ClassDeviceControl;
    PCLASS_SHUTDOWN_FLUSH ClassShutdownFlush;
    PCLASS_CREATE_CLOSE ClassCreateClose;
    PCLASS_INIT_DEVICE ClassInitDevice;
    PCLASS_START_DEVICE ClassStartDevice;
    PCLASS_POWER_DEVICE ClassPowerDevice;
    PCLASS_STOP_DEVICE ClassStopDevice;
    PCLASS_REMOVE_DEVICE ClassRemoveDevice;
    PCLASS_QUERY_PNP_CAPABILITIES ClassQueryPnpCapabilities;
    CLASS_WMI_INFO ClassWmiInfo;
} CLASS_DEV_INFO, *PCLASS_DEV_INFO;

struct _CLASS_INIT_DATA {
    ULONG InitializationDataSize;
    CLASS_DEV_INFO FdoData;
    CLASS_DEV_INFO PdoData;
    PCLASS_ADD_DEVICE ClassAddDevice;
    PCLASS_ENUM_DEVICE ClassEnumerateDevice;
    PCLASS_QUERY_ID ClassQueryId;
    PDRIVER_STARTIO ClassStartIo;
    PCLASS_UNLOAD ClassUnload;
    PCLASS_TICK ClassTick;
};

typedef struct _FILE_OBJECT_EXTENSION {
    PFILE_OBJECT FileObject;
    PDEVICE_OBJECT DeviceObject;
    ULONG LockCount;
    ULONG McnDisableCount;
} FILE_OBJECT_EXTENSION, *PFILE_OBJECT_EXTENSION;

typedef struct _CLASS_WORKING_SET {
    ULONG Size;
    ULONG XferPacketsWorkingSetMaximum;
    ULONG XferPacketsWorkingSetMinimum;
} CLASS_WORKING_SET, *PCLASS_WORKING_SET;

typedef struct _CLASS_INTERPRET_SENSE_INFO2 {
    ULONG Size;
    ULONG HistoryCount;
    PCLASS_COMPRESS_RETRY_HISTORY_DATA Compress;
    PCLASS_INTERPRET_SENSE_INFO Interpret;
} CLASS_INTERPRET_SENSE_INFO2, *PCLASS_INTERPRET_SENSE_INFO2;

C_ASSERT((MAXULONG - sizeof(SRB_HISTORY)) / 30000 >= sizeof(SRB_HISTORY_ITEM));

// Valid data for SrbSupport. Windows/ReactOS had defined
// CLASS_SRB_SCSI_REQUEST_BLOCK as 0x1 which we do not support.
#define CLASS_SRB_STORAGE_REQUEST_BLOCK 0x2

typedef struct _CLASS_DRIVER_EXTENSION {
    UNICODE_STRING RegistryPath;
    CLASS_INIT_DATA InitData;
    ULONG DeviceCount;
    PCLASS_QUERY_WMI_REGINFO_EX ClassFdoQueryWmiRegInfoEx;
    PCLASS_QUERY_WMI_REGINFO_EX ClassPdoQueryWmiRegInfoEx;
    REGHANDLE EtwHandle;
    PDRIVER_DISPATCH DeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
    PDRIVER_DISPATCH MpDeviceMajorFunctionTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
    PCLASS_INTERPRET_SENSE_INFO2 InterpretSenseInfo;
    PCLASS_WORKING_SET WorkingSet;
} CLASS_DRIVER_EXTENSION, *PCLASS_DRIVER_EXTENSION;

typedef struct _COMMON_DEVICE_EXTENSION {
    ULONG Version;
    PDEVICE_OBJECT DeviceObject;
    PDEVICE_OBJECT LowerDeviceObject;
    struct _FUNCTIONAL_DEVICE_EXTENSION *PartitionZeroExtension;
    PCLASS_DRIVER_EXTENSION DriverExtension;
    KEVENT RemoveEvent;
    PVOID DriverData;
    struct {
	BOOLEAN IsFdo : 1;
	BOOLEAN IsInitialized : 1;
	BOOLEAN IsSrbLookasideListInitialized : 1;
    };
    UCHAR PreviousState;
    UCHAR CurrentState;
    ULONG IsRemoved;
    UNICODE_STRING DeviceName;
    struct _PHYSICAL_DEVICE_EXTENSION *ChildList;
    ULONG PartitionNumber;
    LARGE_INTEGER PartitionLength;
    LARGE_INTEGER StartingOffset;
    PCLASS_DEV_INFO DevInfo;
    ULONG PagingPathCount;
    ULONG DumpPathCount;
    ULONG HibernationPathCount;
    KEVENT PathCountEvent;
#ifndef ALLOCATE_SRB_FROM_POOL
    LOOKASIDE_LIST SrbLookasideList;
#endif
    UNICODE_STRING MountedDeviceInterfaceName;
    ULONG GuidCount;
    PGUIDREGINFO GuidRegInfo;
    DICTIONARY FileObjectDictionary;
    ULONG_PTR Reserved1;
    PDRIVER_DISPATCH *DispatchTable;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} COMMON_DEVICE_EXTENSION, *PCOMMON_DEVICE_EXTENSION;

typedef struct _PHYSICAL_DEVICE_EXTENSION {
    union {
	struct {
	    ULONG Version;
	    PDEVICE_OBJECT DeviceObject;
	};
	COMMON_DEVICE_EXTENSION CommonExtension;
    };
    BOOLEAN IsMissing;
    BOOLEAN IsEnumerated;
    ULONG_PTR Reserved1;
    ULONG_PTR Reserved2;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} PHYSICAL_DEVICE_EXTENSION, *PPHYSICAL_DEVICE_EXTENSION;

typedef struct _CLASS_POWER_OPTIONS {
    ULONG PowerDown : 1;
    ULONG LockQueue : 1;
    ULONG HandleSpinDown : 1;
    ULONG HandleSpinUp : 1;
    ULONG Reserved : 27;
} CLASS_POWER_OPTIONS, *PCLASS_POWER_OPTIONS;

#define CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE	(SRBEX_SCSI_CDB16_BUFFER_SIZE)
#define CLASS_SRBEX_NO_SRBEX_DATA_BUFFER_SIZE	(SRBEX_NO_SRBEX_DATA_BUFFER_SIZE)

typedef struct _CLASS_POWER_CONTEXT {
    union {
	CLASS_POWER_DOWN_STATE PowerDown;
	CLASS_POWER_DOWN_STATE2 PowerDown2;
	CLASS_POWER_DOWN_STATE3 PowerDown3;
	CLASS_POWER_UP_STATE PowerUp;
    } PowerChangeState;
    CLASS_POWER_OPTIONS Options;
    BOOLEAN InUse;
    BOOLEAN QueueLocked;
    NTSTATUS FinalStatus;
    ULONG RetryCount;
    ULONG RetryInterval;
    PIO_COMPLETION_ROUTINE CompletionRoutine;
    PDEVICE_OBJECT DeviceObject;
    PIRP Irp;
    union {
	STORAGE_REQUEST_BLOCK Srb;
	UCHAR SrbExBuffer[CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE];
    };
} CLASS_POWER_CONTEXT, *PCLASS_POWER_CONTEXT;

typedef struct _COMPLETION_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    union {
	STORAGE_REQUEST_BLOCK SrbEx;
	UCHAR SrbExBuffer[CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE];
    } Srb;
} COMPLETION_CONTEXT, *PCOMPLETION_CONTEXT;

#ifdef _CLASSPNP_
#define CLASSPNP_API
#else
#define CLASSPNP_API DECLSPEC_IMPORT
#endif

NTAPI CLASSPNP_API ULONG ClassInitialize(IN PVOID Argument1, IN PVOID Argument2,
					 IN PCLASS_INIT_DATA InitializationData);

typedef struct _CLASS_QUERY_WMI_REGINFO_EX_LIST {
    ULONG Size;
    PCLASS_QUERY_WMI_REGINFO_EX ClassFdoQueryWmiRegInfoEx;
    PCLASS_QUERY_WMI_REGINFO_EX ClassPdoQueryWmiRegInfoEx;
} CLASS_QUERY_WMI_REGINFO_EX_LIST, *PCLASS_QUERY_WMI_REGINFO_EX_LIST;

typedef enum { SupportUnknown = 0, Supported, NotSupported } CLASS_FUNCTION_SUPPORT;

typedef struct _CLASS_VPD_B1_DATA {
    NTSTATUS CommandStatus;
    USHORT MediumRotationRate;
    UCHAR NominalFormFactor;
    UCHAR Zoned;
    ULONG MediumProductType;
    ULONG DepopulationTime;
} CLASS_VPD_B1_DATA, *PCLASS_VPD_B1_DATA;

typedef struct _CLASS_VPD_B0_DATA {
    NTSTATUS CommandStatus;
    ULONG MaxUnmapLbaCount;
    ULONG MaxUnmapBlockDescrCount;
    ULONG OptimalUnmapGranularity;
    ULONG UnmapGranularityAlignment;
    BOOLEAN UGAVALID;
    UCHAR Reserved0;
    USHORT OptimalTransferLengthGranularity;
    ULONG MaximumTransferLength;
    ULONG OptimalTransferLength;
} CLASS_VPD_B0_DATA, *PCLASS_VPD_B0_DATA;

typedef struct _CLASS_VPD_B2_DATA {
    NTSTATUS CommandStatus;
    UCHAR ThresholdExponent;
    UCHAR DP : 1;
    UCHAR ANC_SUP : 1;
    UCHAR Reserved0 : 2;
    UCHAR LBPRZ : 1;
    UCHAR LBPWS10 : 1;
    UCHAR LBPWS : 1;
    UCHAR LBPU : 1;
    UCHAR ProvisioningType : 3;
    UCHAR Reserved1 : 5;
    ULONG SoftThresholdEventPending;
} CLASS_VPD_B2_DATA, *PCLASS_VPD_B2_DATA;

typedef struct _CLASS_READ_CAPACITY16_DATA {
    NTSTATUS CommandStatus;
    ULONG BytesPerLogicalSector;
    ULONG BytesPerPhysicalSector;
    ULONG BytesOffsetForSectorAlignment;
    BOOLEAN LBProvisioningEnabled;
    BOOLEAN LBProvisioningReadZeros;
    UCHAR Reserved0[2];
    ULONG Reserved1;
} CLASS_READ_CAPACITY16_DATA, *PCLASS_READ_CAPACITY16_DATA;

typedef struct _CLASS_VPD_ECOP_BLOCK_DEVICE_ROD_LIMITS {
    NTSTATUS CommandStatus;
    USHORT MaximumRangeDescriptors;
    UCHAR Restricted;
    UCHAR Reserved;
    ULONG MaximumInactivityTimer;
    ULONG DefaultInactivityTimer;
    ULONGLONG MaximumTokenTransferSize;
    ULONGLONG OptimalTransferCount;
} CLASS_VPD_ECOP_BLOCK_DEVICE_ROD_LIMITS, *PCLASS_VPD_ECOP_BLOCK_DEVICE_ROD_LIMITS;

typedef struct _CLASS_FUNCTION_SUPPORT_INFO {
    ULONG GenerationCount;
    volatile ULONG ChangeRequestCount;
    struct {
	ULONG BlockLimits : 1;
	ULONG BlockDeviceCharacteristics : 1;
	ULONG LBProvisioning : 1;
	ULONG BlockDeviceRODLimits : 1;
	ULONG ZonedBlockDeviceCharacteristics : 1;
	ULONG Reserved : 22;
	ULONG DeviceType : 5;
    } ValidInquiryPages;
    struct {
	CLASS_FUNCTION_SUPPORT SeekPenaltyProperty;
	CLASS_FUNCTION_SUPPORT AccessAlignmentProperty;
	CLASS_FUNCTION_SUPPORT TrimProperty;
	CLASS_FUNCTION_SUPPORT TrimProcess;
    } LowerLayerSupport;
    BOOLEAN RegAccessAlignmentQueryNotSupported;
    BOOLEAN AsynchronousNotificationSupported;
    BOOLEAN UseModeSense10;
    UCHAR Reserved;
    CLASS_VPD_B0_DATA BlockLimitsData;
    CLASS_VPD_B1_DATA DeviceCharacteristicsData;
    CLASS_VPD_B2_DATA LBProvisioningData;
    CLASS_READ_CAPACITY16_DATA ReadCapacity16Data;
    CLASS_VPD_ECOP_BLOCK_DEVICE_ROD_LIMITS BlockDeviceRODLimitsData;
    struct {
	ULONG D3ColdSupported : 1;
	ULONG DeviceWakeable : 1;
	ULONG IdlePowerEnabled : 1;
	ULONG D3IdleTimeoutOverridden : 1;
	ULONG NoVerifyDuringIdlePower : 1;
	ULONG Reserved2 : 27;
	ULONG D3IdleTimeout;
    } IdlePower;

    CLASS_FUNCTION_SUPPORT HwFirmwareGetInfoSupport;
} CLASS_FUNCTION_SUPPORT_INFO, *PCLASS_FUNCTION_SUPPORT_INFO;

typedef struct _FUNCTIONAL_DEVICE_EXTENSION {
    union {
	struct {
	    ULONG Version;
	    PDEVICE_OBJECT DeviceObject;
	};
	COMMON_DEVICE_EXTENSION CommonExtension;
    };
    PDEVICE_OBJECT LowerPdo;
    PSTORAGE_DEVICE_DESCRIPTOR DeviceDescriptor;
    PSTORAGE_ADAPTER_DESCRIPTOR AdapterDescriptor;
    DEVICE_POWER_STATE DevicePowerState;
    ULONG DMByteSkew;
    ULONG DMSkew;
    BOOLEAN DMActive;
    UCHAR SenseDataLength;
    UCHAR Reserved0[2];
    DISK_GEOMETRY DiskGeometry;
    PSENSE_DATA SenseData;
    ULONG TimeOutValue;
    ULONG DeviceNumber;
    ULONG SrbFlags;
    ULONG ErrorCount;
    LONG LockCount;
    LONG ProtectedLockCount;
    LONG InternalLockCount;
    KEVENT EjectSynchronizationEvent;
    USHORT DeviceFlags;
    UCHAR SectorShift;
    UCHAR CdbForceUnitAccess;
    PMEDIA_CHANGE_DETECTION_INFO MediaChangeDetectionInfo;
    PKEVENT Unused1;
    HANDLE Unused2;
    FILE_OBJECT_EXTENSION KernelModeMcnContext;
    ULONG MediaChangeCount;
    HANDLE DeviceDirectory;
    PIRP ReleaseQueueIrp;
    BOOLEAN ReleaseQueueNeeded;
    BOOLEAN ReleaseQueueInProgress;
    BOOLEAN ReleaseQueueIrpFromPool;
    BOOLEAN FailurePredicted;
    ULONG FailureReason;
    struct _FAILURE_PREDICTION_INFO *FailurePredictionInfo;
    BOOLEAN PowerDownInProgress;
    ULONG EnumerationInterlock;
    ULONG ScanForSpecialFlags;
    KDPC PowerRetryDpc;
    KTIMER PowerRetryTimer;
    CLASS_POWER_CONTEXT PowerContext;

    PCLASS_PRIVATE_FDO_DATA PrivateFdoData;
    PCLASS_FUNCTION_SUPPORT_INFO FunctionSupportInfo;
    PSTORAGE_MINIPORT_DESCRIPTOR MiniportDescriptor;

    ULONG_PTR Reserved4;
} FUNCTIONAL_DEVICE_EXTENSION, *PFUNCTIONAL_DEVICE_EXTENSION;

/* Flags for ClassCreateDeviceObject */
#define CLASS_DO_IS_FDO			1UL
#define CLASS_DO_RAW_MOUNT_ONLY		2UL
#define CLASS_DO_DIRECT_IO		4UL

NTAPI CLASSPNP_API ULONG ClassInitializeEx(IN PDRIVER_OBJECT DriverObject,
					   IN LPGUID Guid,
					   IN PVOID Data);

NTAPI CLASSPNP_API NTSTATUS ClassCreateDeviceObject(IN PDRIVER_OBJECT DriverObject,
						    IN PCCHAR ObjectNameBuffer,
						    IN PDEVICE_OBJECT LowerDeviceObject,
						    IN ULONG Flags,
						    OUT PDEVICE_OBJECT *DeviceObject);

NTAPI CLASSPNP_API NTSTATUS ClassReadDriveCapacity(IN PDEVICE_OBJECT DeviceObject);

NTAPI CLASSPNP_API VOID ClassReleaseQueue(IN PDEVICE_OBJECT DeviceObject);

NTAPI CLASSPNP_API VOID ClassSplitRequest(IN PDEVICE_OBJECT DeviceObject,
					  IN PIRP Irp,
					  IN ULONG MaximumBytes);

NTAPI CLASSPNP_API NTSTATUS ClassDeviceControl(IN PDEVICE_OBJECT DeviceObject,
					       IN OUT PIRP Irp);

NTAPI CLASSPNP_API NTSTATUS ClassIoComplete(PDEVICE_OBJECT DeviceObject,
					    PIRP Irp,
					    PVOID Context);

NTAPI CLASSPNP_API NTSTATUS ClassIoCompleteAssociated(PDEVICE_OBJECT DeviceObject,
						      PIRP Irp,
						      PVOID Context);

NTAPI CLASSPNP_API BOOLEAN ClassInterpretSenseInfo(IN PDEVICE_OBJECT DeviceObject,
						   IN PSTORAGE_REQUEST_BLOCK Srb,
						   IN UCHAR MajorFunctionCode,
						   IN ULONG IoDeviceCode,
						   IN ULONG RetryCount,
						   OUT NTSTATUS *Status,
						   OUT OPTIONAL ULONG *RetryInterval);

NTAPI VOID ClassSendDeviceIoControlSynchronous(IN ULONG IoControlCode,
					       IN PDEVICE_OBJECT TargetDeviceObject,
					       IN OUT OPTIONAL PVOID Buffer,
					       IN ULONG InputBufferLength,
					       IN ULONG OutputBufferLength,
					       IN BOOLEAN InternalDeviceIoControl,
					       OUT PIO_STATUS_BLOCK IoStatus);

NTAPI CLASSPNP_API NTSTATUS ClassSendIrpSynchronous(IN PDEVICE_OBJECT TargetDeviceObject,
						    IN PIRP Irp);

NTAPI CLASSPNP_API NTSTATUS ClassForwardIrpSynchronous(IN PCOMMON_DEVICE_EXTENSION Ext,
						       IN PIRP Irp);

NTAPI CLASSPNP_API NTSTATUS ClassSendSrbSynchronous(IN PDEVICE_OBJECT DeviceObject,
						    IN OUT PSTORAGE_REQUEST_BLOCK Srb,
						    IN OPTIONAL PVOID BufferAddress,
						    IN ULONG BufferLength,
						    IN BOOLEAN WriteToDevice);

NTAPI CLASSPNP_API NTSTATUS ClassSendSrbAsynchronous(IN PDEVICE_OBJECT DeviceObject,
						     IN OUT PSTORAGE_REQUEST_BLOCK Srb,
						     IN PIRP Irp,
						     IN PVOID BufferAddress,
						     IN ULONG BufferLength,
						     IN BOOLEAN WriteToDevice);

NTAPI CLASSPNP_API NTSTATUS ClassBuildRequest(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTAPI CLASSPNP_API ULONG ClassModeSense(IN PDEVICE_OBJECT DeviceObject,
					IN PCHAR ModeSenseBuffer,
					IN ULONG Length,
					IN UCHAR PageMode);

NTAPI CLASSPNP_API ULONG ClassModeSenseEx(IN PDEVICE_OBJECT Fdo,
					  IN PCHAR ModeSenseBuffer,
					  IN ULONG Length,
					  IN UCHAR PageMode,
					  IN UCHAR PageControl);

NTAPI CLASSPNP_API NTSTATUS ClassModeSelect(IN PDEVICE_OBJECT Fdo,
					    IN PCHAR ModeSelectBuffer,
					    IN ULONG Length,
					    IN BOOLEAN SavePages);

NTAPI CLASSPNP_API PVOID ClassFindModePage(IN PCHAR ModeSenseBuffer,
					   IN ULONG Length,
					   IN UCHAR PageMode,
					   IN BOOLEAN Use6Byte);

NTAPI CLASSPNP_API NTSTATUS ClassClaimDevice(IN PDEVICE_OBJECT LowerDeviceObject,
					     IN BOOLEAN Release);

NTAPI CLASSPNP_API NTSTATUS ClassInternalIoControl(PDEVICE_OBJECT DeviceObject,
						   PIRP Irp);

NTAPI CLASSPNP_API VOID ClassInitializeSrbLookasideList(IN OUT PCOMMON_DEVICE_EXTENSION Ext,
							IN ULONG NumberElements);

NTAPI CLASSPNP_API VOID ClassDeleteSrbLookasideList(IN OUT PCOMMON_DEVICE_EXTENSION Ext);

NTAPI CLASSPNP_API ULONG ClassQueryTimeOutRegistryValue(IN PDEVICE_OBJECT DeviceObject);

NTAPI CLASSPNP_API NTSTATUS ClassGetDescriptor(IN PDEVICE_OBJECT DeviceObject,
					       IN PSTORAGE_PROPERTY_ID PropertyId,
					       OUT PVOID *Descriptor);

NTAPI CLASSPNP_API VOID ClassInvalidateBusRelations(IN PDEVICE_OBJECT Fdo);

NTAPI CLASSPNP_API VOID ClassMarkChildrenMissing(IN PFUNCTIONAL_DEVICE_EXTENSION Fdo);

NTAPI CLASSPNP_API BOOLEAN ClassMarkChildMissing(IN PPHYSICAL_DEVICE_EXTENSION PdoExtension,
						 IN BOOLEAN AcquireChildLock);

CLASSPNP_API VOID ClassDebugPrint(IN CLASS_DEBUG_LEVEL DebugPrintLevel,
				  IN PCCHAR DebugMessage, ...);

NTAPI CLASSPNP_API PCLASS_DRIVER_EXTENSION ClassGetDriverExtension(IN PDRIVER_OBJECT Drv);

NTAPI CLASSPNP_API VOID ClassCompleteRequest(IN PDEVICE_OBJECT DeviceObject,
					     IN PIRP Irp,
					     IN CCHAR PriorityBoost);

NTAPI CLASSPNP_API VOID ClassReleaseRemoveLock(IN PDEVICE_OBJECT DeviceObject,
					       PIRP Tag);

NTAPI CLASSPNP_API ULONG ClassAcquireRemoveLockEx(IN PDEVICE_OBJECT DeviceObject,
						  PVOID Tag,
						  IN PCSTR File,
						  IN ULONG Line);

NTAPI CLASSPNP_API VOID ClassUpdateInformationInRegistry(IN PDEVICE_OBJECT Fdo,
							 IN PCHAR DeviceName,
							 IN ULONG DeviceNumber,
							 IN OPTIONAL PINQUIRYDATA InquiryData,
							 IN ULONG InquiryDataLength);

NTAPI CLASSPNP_API NTSTATUS ClassWmiCompleteRequest(IN PDEVICE_OBJECT DeviceObject,
						    IN OUT PIRP Irp,
						    IN NTSTATUS Status,
						    IN ULONG BufferUsed,
						    IN CCHAR PriorityBoost);

NTAPI CLASSPNP_API NTSTATUS ClassWmiFireEvent(IN PDEVICE_OBJECT DeviceObject,
					      IN LPGUID Guid,
					      IN ULONG InstanceIndex,
					      IN ULONG EventDataSize,
					      IN PVOID EventData);

NTAPI CLASSPNP_API VOID ClassResetMediaChangeTimer(IN PFUNCTIONAL_DEVICE_EXTENSION Ext);

NTAPI CLASSPNP_API VOID ClassInitializeMediaChangeDetection(IN PFUNCTIONAL_DEVICE_EXTENSION Ext,
							    IN PUCHAR EventPrefix);

NTAPI CLASSPNP_API NTSTATUS ClassInitializeTestUnitPolling(IN PFUNCTIONAL_DEVICE_EXTENSION Ext,
							   IN BOOLEAN AllowDriveToSleep);

NTAPI CLASSPNP_API PVPB ClassGetVpb(IN PDEVICE_OBJECT DeviceObject);

NTAPI CLASSPNP_API NTSTATUS ClassSpinDownPowerHandler(IN PDEVICE_OBJECT DeviceObject,
						      IN PIRP Irp);

NTAPI NTSTATUS ClassStopUnitPowerHandler(IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp);

NTAPI NTSTATUS ClassSetFailurePredictionPoll(IN OUT PFUNCTIONAL_DEVICE_EXTENSION Ext,
					     IN FAILURE_PREDICTION_METHOD Method,
					     IN ULONG PollingPeriod);

NTAPI VOID ClassNotifyFailurePredicted(IN PFUNCTIONAL_DEVICE_EXTENSION Ext,
				       IN PUCHAR Buffer,
				       IN ULONG BufferSize,
				       IN BOOLEAN LogError,
				       IN ULONG UniqueErrorValue,
				       IN UCHAR PathId,
				       IN UCHAR TargetId,
				       IN UCHAR Lun);

NTAPI CLASSPNP_API VOID ClassAcquireChildLock(IN PFUNCTIONAL_DEVICE_EXTENSION Ext);

NTAPI CLASSPNP_API VOID ClassReleaseChildLock(IN PFUNCTIONAL_DEVICE_EXTENSION Ext);

IO_COMPLETION_ROUTINE ClassSignalCompletion;

NTAPI NTSTATUS ClassSendStartUnit(IN PDEVICE_OBJECT DeviceObject);

NTAPI CLASSPNP_API NTSTATUS ClassRemoveDevice(IN PDEVICE_OBJECT DeviceObject,
					      IN UCHAR RemoveType);

NTAPI CLASSPNP_API NTSTATUS ClassAsynchronousCompletion(PDEVICE_OBJECT DeviceObject,
							PIRP Irp,
							PVOID Event);

NTAPI CLASSPNP_API VOID ClassCheckMediaState(IN PFUNCTIONAL_DEVICE_EXTENSION Ext);

NTAPI CLASSPNP_API NTSTATUS ClassCheckVerifyComplete(PDEVICE_OBJECT DeviceObject,
						     PIRP Irp,
						     PVOID Context);

NTAPI CLASSPNP_API VOID ClassSetMediaChangeState(IN PFUNCTIONAL_DEVICE_EXTENSION Ext,
						 IN MEDIA_CHANGE_DETECTION_STATE State,
						 IN BOOLEAN Wait);

NTAPI CLASSPNP_API VOID ClassEnableMediaChangeDetection(IN PFUNCTIONAL_DEVICE_EXTENSION Ext);

NTAPI CLASSPNP_API VOID ClassDisableMediaChangeDetection(IN PFUNCTIONAL_DEVICE_EXTENSION Ext);

NTAPI CLASSPNP_API VOID ClassCleanupMediaChangeDetection(IN PFUNCTIONAL_DEVICE_EXTENSION Ext);

NTAPI VOID ClassGetDeviceParameter(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
				   IN OPTIONAL PWSTR SubkeyName,
				   IN PWSTR ParameterName,
				   IN OUT PULONG ParameterValue);

NTAPI NTSTATUS ClassSetDeviceParameter(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
				       IN OPTIONAL PWSTR SubkeyName,
				       IN PWSTR ParameterName,
				       IN ULONG ParameterValue);

NTAPI PFILE_OBJECT_EXTENSION ClassGetFsContext(IN PCOMMON_DEVICE_EXTENSION CommonExtension,
					       IN PFILE_OBJECT FileObject);
NTAPI VOID ClassSendNotification(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
				 IN const GUID *Guid, IN ULONG ExtraDataSize,
				 IN OPTIONAL PVOID ExtraData);

FORCEINLINE UCHAR GET_FDO_EXTENSON_SENSE_DATA_LENGTH(IN PFUNCTIONAL_DEVICE_EXTENSION Ext)
{
    UCHAR SenseDataLength = 0;

    if (Ext->SenseData != NULL) {
	if (Ext->SenseDataLength > 0) {
	    SenseDataLength = Ext->SenseDataLength;
	} else {
	    // For backward compatibility with Windows 7 and earlier
	    SenseDataLength = SENSE_BUFFER_SIZE;
	}
    }

    return SenseDataLength;
}

FORCEINLINE BOOLEAN PORT_ALLOCATED_SENSE(IN PFUNCTIONAL_DEVICE_EXTENSION Ext,
					 IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return ((BOOLEAN)((TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_PORT_DRIVER_ALLOCSENSE) &&
		       TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_FREE_SENSE_BUFFER)) &&
		      (SrbGetSenseInfoBuffer(Srb) != Ext->SenseData)));
}

FORCEINLINE VOID FREE_PORT_ALLOCATED_SENSE_BUFFER(IN PFUNCTIONAL_DEVICE_EXTENSION Ext,
						  IN PSTORAGE_REQUEST_BLOCK Srb)
{
    ASSERT(TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_PORT_DRIVER_ALLOCSENSE));
    ASSERT(TEST_FLAG(Srb->SrbFlags, SRB_FLAGS_FREE_SENSE_BUFFER));
    ASSERT(SrbGetSenseInfoBuffer(Srb) != Ext->SenseData);

    ExFreePool(SrbGetSenseInfoBuffer(Srb));
    SrbSetSenseInfoBuffer(Srb, Ext->SenseData);
    SrbSetSenseInfoBufferLength(Srb, SENSE_BUFFER_SIZE);
    CLEAR_FLAG(Srb->SrbFlags, SRB_FLAGS_FREE_SENSE_BUFFER);
    return;
}

typedef VOID (NTAPI *PCLASS_SCAN_FOR_SPECIAL_HANDLER)(IN PFUNCTIONAL_DEVICE_EXTENSION Ext,
						      IN ULONG_PTR Data);

NTAPI VOID ClassScanForSpecial(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			       IN CLASSPNP_SCAN_FOR_SPECIAL_INFO DeviceList[],
			       IN PCLASS_SCAN_FOR_SPECIAL_HANDLER Function);
