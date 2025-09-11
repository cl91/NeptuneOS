/*++

  Copyright (C) Microsoft Corporation, 1991 - 2010

  Module Name:

  classp.h

  Abstract:

  Private header file for classpnp.sys modules.  This contains private
  structure and function declarations as well as constant values which do
  not need to be exported.

  Author:

  Environment:

  kernel mode only

  Notes:


  Revision History:

--*/

#define RTL_USE_AVL_TABLES 0

//
// Set component ID for DbgPrintEx calls
//
#ifndef DEBUG_COMP_ID
#define DEBUG_COMP_ID DPFLTR_CLASSPNP_ID
#endif

#if CLASS_INIT_GUID
#include <initguid.h>
#endif

#include <stddef.h>
#include <ntddk.h>
#include <scsi.h>
#include <storswtr.h>
#include <wmidata.h>
#include <classpnp.h>
#include <storduid.h>

#include <mountdev.h>
#include <ioevent.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#include <wdmguid.h>

#include <ntpoapi.h>
#include <srbhelper.h>

//
// Include header file and setup GUID for tracing
//
#include <storswtr.h>
#define WPP_GUID_CLASSPNP (FA8DE7C4, ACDE, 4443, 9994, C4E2359A9EDB)
#ifndef WPP_CONTROL_GUIDS
#define WPP_CONTROL_GUIDS WPP_CONTROL_GUIDS_NORMAL_FLAGS(WPP_GUID_CLASSPNP)
#endif

/*
 * IA64 requires 8-byte alignment for pointers, but the IA64 NT kernel expects 16-byte alignment
 */
#ifdef _WIN64
#define PTRALIGN DECLSPEC_ALIGN(16)
#else
#define PTRALIGN
#endif

extern CLASSPNP_SCAN_FOR_SPECIAL_INFO ClassBadItems[];

extern GUID ClassGuidQueryRegInfoEx;
extern GUID ClassGuidSenseInfo2;
extern GUID ClassGuidWorkingSet;
extern GUID ClassGuidSrbSupport;

extern ULONG ClassMaxInterleavePerCriticalIo;

#define Add2Ptr(P, I) ((PVOID)((PUCHAR)(P) + (I)))

#define CLASSP_REG_SUBKEY_NAME (L"Classpnp")

#define CLASSP_REG_HACK_VALUE_NAME (L"HackMask")
#define CLASSP_REG_MMC_DETECTION_VALUE_NAME (L"MMCDetectionState")
#define CLASSP_REG_WRITE_CACHE_VALUE_NAME (L"WriteCacheEnableOverride")
#define CLASSP_REG_PERF_RESTORE_VALUE_NAME (L"RestorePerfAtCount")
#define CLASSP_REG_REMOVAL_POLICY_VALUE_NAME (L"UserRemovalPolicy")
#define CLASSP_REG_IDLE_INTERVAL_NAME (L"IdleInterval")
#define CLASSP_REG_IDLE_ACTIVE_MAX (L"IdleOutstandingIoMax")
#define CLASSP_REG_IDLE_PRIORITY_SUPPORTED (L"IdlePrioritySupported")
#define CLASSP_REG_ACCESS_ALIGNMENT_NOT_SUPPORTED (L"AccessAlignmentQueryNotSupported")
#define CLASSP_REG_DISBALE_IDLE_POWER_NAME (L"DisableIdlePowerManagement")
#define CLASSP_REG_IDLE_TIMEOUT_IN_SECONDS (L"IdleTimeoutInSeconds")
#define CLASSP_REG_DISABLE_D3COLD (L"DisableD3Cold")
#define CLASSP_REG_QERR_OVERRIDE_MODE (L"QERROverrideMode")
#define CLASSP_REG_LEGACY_ERROR_HANDLING (L"LegacyErrorHandling")
#define CLASSP_REG_COPY_OFFLOAD_MAX_TARGET_DURATION (L"CopyOffloadMaxTargetDuration")

#define CLASS_PERF_RESTORE_MINIMUM (0x10)
#define CLASS_ERROR_LEVEL_1 (0x4)
#define CLASS_ERROR_LEVEL_2 (0x8)
#define CLASS_MAX_INTERLEAVE_PER_CRITICAL_IO (0x4)

#define FDO_HACK_CANNOT_LOCK_MEDIA (0x00000001)
#define FDO_HACK_GESN_IS_BAD (0x00000002)
#define FDO_HACK_NO_SYNC_CACHE (0x00000004)
#define FDO_HACK_NO_RESERVE6 (0x00000008)
#define FDO_HACK_GESN_IGNORE_OPCHANGE (0x00000010)

#define FDO_HACK_VALID_FLAGS (0x0000001F)
#define FDO_HACK_INVALID_FLAGS (~FDO_HACK_VALID_FLAGS)

/*
 *  Lots of retries of synchronized SCSI commands that devices may not
 *  even support really slows down the system (especially while booting).
 *  (Even GetDriveCapacity may be failed on purpose if an external disk is powered off).
 *  If a disk cannot return a small initialization buffer at startup
 *  in two attempts (with delay interval) then we cannot expect it to return
 *  data consistently with four retries.
 *  So don't set the retry counts as high here as for data SRBs.
 *
 *  If we find that these requests are failing consecutively,
 *  despite the retry interval, on otherwise reliable media,
 *  then we should either increase the retry interval for
 *  that failure or (by all means) increase these retry counts as appropriate.
 */
#define NUM_LOCKMEDIAREMOVAL_RETRIES 1
#define NUM_MODESENSE_RETRIES 1
#define NUM_MODESELECT_RETRIES 1
#define NUM_DRIVECAPACITY_RETRIES 1
#define NUM_THIN_PROVISIONING_RETRIES 32

/*
 *  We retry failed I/O requests at 1-second intervals.
 *  In the case of a failure due to bus reset, we want to make sure that we retry
 *  after the allowable reset time.  For SCSI, the allowable reset time is 5 seconds.
 *  ScsiPort queues requests during a bus reset, which should cause us to retry after
 *  the reset is over; but the requests queued in the miniport are failed all the way
 *  back to us immediately.  In any event, in order to make extra sure that our retries
 *  span the allowable reset time, we should retry more than 5 times.
 */
#define NUM_IO_RETRIES 8

#define CLASS_FILE_OBJECT_EXTENSION_KEY 'eteP'
#define CLASSP_VOLUME_VERIFY_CHECKED 0x34

#define CLASS_TAG_PRIVATE_DATA 'CPcS'
#define CLASS_TAG_SENSE2 '2ScS'
#define CLASS_TAG_WORKING_SET 'sWcS'
#define CLASSPNP_POOL_TAG_GENERIC 'pCcS'
#define CLASSPNP_POOL_TAG_TOKEN_OPERATION 'oTcS'
#define CLASSPNP_POOL_TAG_SRB 'rScS'
#define CLASSPNP_POOL_TAG_VPD 'pVcS'
#define CLASSPNP_POOL_TAG_LOG_MESSAGE 'mlcS'
#define CLASSPNP_POOL_TAG_ADDITIONAL_DATA 'DAcS'
#define CLASSPNP_POOL_TAG_FIRMWARE 'wFcS'

//
// Macros related to Token Operation commands
//
#define MAX_LIST_IDENTIFIER MAXULONG
#define NUM_POPULATE_TOKEN_RETRIES 1
#define NUM_WRITE_USING_TOKEN_RETRIES 2
#define NUM_RECEIVE_TOKEN_INFORMATION_RETRIES 2
#define MAX_TOKEN_OPERATION_PARAMETER_DATA_LENGTH MAXUSHORT
#define MAX_RECEIVE_TOKEN_INFORMATION_PARAMETER_DATA_LENGTH MAXULONG
#define MAX_TOKEN_TRANSFER_SIZE MAXULONGLONG
#define MAX_NUMBER_BLOCKS_PER_BLOCK_DEVICE_RANGE_DESCRIPTOR MAXULONG
#define DEFAULT_MAX_TARGET_DURATION 4 // 4sec
#define DEFAULT_MAX_NUMBER_BYTES_PER_SYNC_WRITE_USING_TOKEN (64ULL * 1024 * 1024) // 64MB
#define MAX_NUMBER_BYTES_PER_SYNC_WRITE_USING_TOKEN (256ULL * 1024 * 1024) // 256MB
#define MIN_TOKEN_LIST_IDENTIFIERS 256
#define MAX_TOKEN_LIST_IDENTIFIERS MAXULONG
#define MAX_NUMBER_BLOCK_DEVICE_DESCRIPTORS 64

#define REG_DISK_CLASS_CONTROL						\
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\DISK"
#define REG_MAX_LIST_IDENTIFIER_VALUE L"MaximumListIdentifier"

#define VPD_PAGE_HEADER_SIZE 0x04

//
// Number of times to retry get LBA status in case of an error
// that can be caused by VPD data change
//

#define GET_LBA_STATUS_RETRY_COUNT_MAX (2)

extern ULONG MaxTokenOperationListIdentifier;
extern volatile ULONG TokenOperationListIdentifier;

extern LIST_ENTRY IdlePowerFDOList;
extern PVOID PowerSettingNotificationHandle;
extern PVOID ScreenStateNotificationHandle;
extern BOOLEAN ClasspScreenOff;
extern ULONG DiskIdleTimeoutInMS;

//
// Definitions from ntos\rtl\time.c
//

extern CONST LARGE_INTEGER Magic10000;
#define SHIFT10000 13

//
// Constant to help wih various time conversions
//
#define CONST_MSECS_PER_SEC 1000

#define Convert100nsToMilliseconds(LARGE_INTEGER)			\
    (RtlExtendedMagicDivide((LARGE_INTEGER), Magic10000, SHIFT10000))

#define ConvertMillisecondsTo100ns(MILLISECONDS)	\
    (RtlExtendedIntegerMultiply((MILLISECONDS), 10000))

typedef struct _MEDIA_CHANGE_DETECTION_INFO {
    //
    // The current state of the media (present, not present, unknown)
    // protected by MediaChangeSynchronizationEvent
    //

    MEDIA_CHANGE_DETECTION_STATE MediaChangeDetectionState;

    //
    // This is a count of how many time MCD has been disabled.  if it is
    // set to zero, then we'll poll the device for MCN events with the
    // then-current method (ie. TEST UNIT READY or GESN).  this is
    // protected by MediaChangeMutex
    //

    LONG MediaChangeDetectionDisableCount;

    //
    // The timer value to support media change events.  This is a countdown
    // value used to determine when to poll the device for a media change.
    // The max value for the timer is 255 seconds.  This is not protected
    // by an event -- simply InterlockedExchanged() as needed.
    //

    LONG MediaChangeCountDown;

    //
    // recent changes allowed instant retries of the MCN irp.  Since this
    // could cause an infinite loop, keep a count of how many times we've
    // retried immediately so that we can catch if the count exceeds an
    // arbitrary limit.
    //

    LONG MediaChangeRetryCount;

    //
    // use GESN if it's available
    //

    struct {
	BOOLEAN Supported;
	BOOLEAN HackEventMask;
	UCHAR EventMask;
	UCHAR NoChangeEventMask;
	PUCHAR Buffer;
	ULONG BufferSize;
    } Gesn;

    //
    // If this value is one, then the irp is currently in use.
    // If this value is zero, then the irp is available.
    // Use InterlockedCompareExchange() to set from "available" to "in use".
    // ASSERT that InterlockedCompareExchange() showed previous value of
    //    "in use" when changing back to "available" state.
    // This also implicitly protects the MediaChangeSrb and SenseBuffer
    //

    LONG MediaChangeIrpInUse;

    //
    // Pointer to the irp to be used for media change detection.
    // protected by Interlocked MediaChangeIrpInUse
    //

    PIRP MediaChangeIrp;

    //
    // The srb for the media change detection.
    // protected by Interlocked MediaChangeIrpInUse
    //

    union {
	STORAGE_REQUEST_BLOCK SrbEx;
	UCHAR SrbExBuffer[CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE];
    } MediaChangeSrb;
    PUCHAR SenseBuffer;
    ULONG SrbFlags;

    //
    // Second timer to keep track of how long the media change IRP has been
    // in use.  If this value exceeds the timeout (#defined) then we should
    // print out a message to the user and set the MediaChangeIrpLost flag
    // protected by using Interlocked() operations in ClasspSendMediaStateIrp,
    // the only routine which should modify this value.
    //

    LONG MediaChangeIrpTimeInUse;

    //
    // Set by CdRomTickHandler when we determine that the media change irp has
    // been lost
    //

    BOOLEAN MediaChangeIrpLost;

    //
    // Buffer size of SenseBuffer
    //
    UCHAR SenseBufferLength;
} MEDIA_CHANGE_DETECTION_INFO, *PMEDIA_CHANGE_DETECTION_INFO;

typedef enum {
    SimpleMediaLock,
    SecureMediaLock,
    InternalMediaLock
} MEDIA_LOCK_TYPE, *PMEDIA_LOCK_TYPE;

typedef struct _FAILURE_PREDICTION_INFO {
    FAILURE_PREDICTION_METHOD Method;
    ULONG CountDown; // Countdown timer
    ULONG Period; // Countdown period

    PIO_WORKITEM WorkQueueItem;

    KEVENT Event;

    //
    // Timestamp of last time the failure prediction info was queried.
    //
    LARGE_INTEGER LastFailurePredictionQueryTime;
} FAILURE_PREDICTION_INFO, *PFAILURE_PREDICTION_INFO;

//
// This struct must always fit within four PVOIDs of info,
// as it uses the irp's "PVOID DriverContext[4]" to store
// this info
//
typedef struct _CLASS_RETRY_INFO {
    struct _CLASS_RETRY_INFO *Next;
} CLASS_RETRY_INFO, *PCLASS_RETRY_INFO;

typedef struct _CSCAN_LIST {
    //
    // The current block which has an outstanding request.
    //

    ULONGLONG BlockNumber;

    //
    // The list of blocks past the CurrentBlock to which we're going to do
    // i/o.  This list is maintained in sorted order.
    //

    LIST_ENTRY CurrentSweep;

    //
    // The list of blocks behind the current block for which we'll have to
    // wait until the next scan across the disk.  This is kept as a stack,
    // the cost of sorting it is taken when it's moved over to be the
    // running list.
    //

    LIST_ENTRY NextSweep;

} CSCAN_LIST, *PCSCAN_LIST;

//
// add to the front of this structure to help prevent illegal
// snooping by other utilities.
//

typedef enum _CLASS_DETECTION_STATE {
    ClassDetectionUnknown = 0,
    ClassDetectionUnsupported = 1,
    ClassDetectionSupported = 2
} CLASS_DETECTION_STATE, *PCLASS_DETECTION_STATE;

typedef struct _CLASS_ERROR_LOG_DATA {
    LARGE_INTEGER TickCount; // Offset 0x00
    ULONG PortNumber; // Offset 0x08

    UCHAR ErrorPaging : 1; // Offset 0x0c
    UCHAR ErrorRetried : 1;
    UCHAR ErrorUnhandled : 1;
    UCHAR ErrorReserved : 5;

    UCHAR Reserved[3];

    union {
	STORAGE_REQUEST_BLOCK SrbEx; // Offset 0x10
	UCHAR SrbExBuffer[CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE];
    };

    /*
     * We define the SenseData as the default length.
     * Since the sense data returned by the port driver may be longer,
     * SenseData must be at the end of this structure.
     * For our internal error log, we only log the default length.
     */
    SENSE_DATA SenseData;
} CLASS_ERROR_LOG_DATA, *PCLASS_ERROR_LOG_DATA;

C_ASSERT(ERROR_LOG_MAXIMUM_SIZE > sizeof(IO_ERROR_LOG_PACKET) + sizeof(CLASS_ERROR_LOG_DATA));

#define NUM_ERROR_LOG_ENTRIES 16
#define DBG_NUM_PACKET_LOG_ENTRIES (64 * 2) // 64 send&receive's

typedef VOID (*PCONTINUATION_ROUTINE)(IN PVOID Context);

typedef struct _TRANSFER_PACKET {
    LIST_ENTRY AllPktsListEntry; // entry in fdoData's static AllTransferPacketsList
    SLIST_ENTRY SlistEntry; // for when in free list (use fast slist)

    PIRP Irp;
    PDEVICE_OBJECT Fdo;

    /*
     *  This is the client IRP that this TRANSFER_PACKET is currently
     *  servicing.
     */
    PIRP OriginalIrp;
    BOOLEAN CompleteOriginalIrpWhenLastPacketCompletes;

    /*
     *  Stuff for retrying the transfer.
     */
    ULONG NumRetries;
    KTIMER RetryTimer;
    PIO_WORKITEM RetryWorkItem;

    _Field_range_(0, MAXIMUM_RETRY_FOR_SINGLE_IO_IN_100NS_UNITS) LONGLONG RetryIn100nsUnits;

    /*
     *  Event for synchronizing the transfer (optional).
     *  (Note that we can't have the event in the packet itself because
     *  by the time a thread waits on an event the packet may have
     *  been completed and re-issued.
     */
    PKEVENT SyncEventPtr;

    /*
     *  Stuff for retrying during extreme low-memory stress
     *  (when we retry 1 page at a time).
     *  NOTE: These fields are also used for StartIO-based
     *  class drivers, even when not in low memory conditions.
     */
    BOOLEAN DriverUsesStartIO; // if this is set, then the below low-mem flags are always used
    BOOLEAN InLowMemRetry;
    PUCHAR LowMemRetry_remainingBufPtr;
    ULONG LowMemRetry_remainingBufLen;
    LARGE_INTEGER LowMemRetry_nextChunkTargetLocation;

    /*
     *  Fields used for cancelling the packet.
     */
    // BOOLEAN Cancelled;
    // KEVENT CancelledEvent;

    /*
     *  We keep the buffer and length values here as well
     *  as in the SRB because some miniports return
     *  the transferred length in SRB.DataTransferLength,
     *  and if the SRB failed we need that value again for the retry.
     *  We don't trust the lower stack to preserve any of these values in the SRB.
     */
    PUCHAR BufPtrCopy;
    ULONG BufLenCopy;
    LARGE_INTEGER TargetLocationCopy;

    /*
     *  This is a standard SCSI structure that receives a detailed
     *  report about a SCSI error on the hardware.
     */
    SENSE_DATA_EX SrbErrorSenseData;

    /*
     *  This is the SRB block for this TRANSFER_PACKET.
     *  For IOCTLs, the SRB block includes two DWORDs for
     *  device object and ioctl code; so these must
     *  immediately follow the SRB block.
     */
    PSTORAGE_REQUEST_BLOCK Srb;
    // ULONG SrbIoctlDevObj;        // not handling ioctls yet
    // ULONG SrbIoctlCode;

#if DBG
    LARGE_INTEGER DbgTimeSent;
    LARGE_INTEGER DbgTimeReturned;
    ULONG DbgPktId;
    IRP DbgOriginalIrpCopy;
    MDL DbgMdlCopy;
#endif

    BOOLEAN UsePartialMdl;

    PSRB_HISTORY RetryHistory;

    // The time at which this request was sent to port driver.
    ULONGLONG RequestStartTime;

    // ActivityId that is associated with the IRP that this transfer packet services.
    GUID ActivityId;

    // If non-NULL, called at packet completion with this context.
    PCONTINUATION_ROUTINE ContinuationRoutine;
    PVOID ContinuationContext;
    ULONGLONG TransferCount;
    ULONG AllocateNode;
} TRANSFER_PACKET, *PTRANSFER_PACKET;

/*
 *  MIN_INITIAL_TRANSFER_PACKETS is the minimum number of packets that
 *  we preallocate at startup for each device (we need at least one packet
 *  to guarantee forward progress during memory stress).
 *  MIN_WORKINGSET_TRANSFER_PACKETS is the number of TRANSFER_PACKETs
 *  we allow to build up and remain for each device;
 *  we _lazily_ work down to this number when they're not needed.
 *  MAX_WORKINGSET_TRANSFER_PACKETS is the number of TRANSFER_PACKETs
 *  that we _immediately_ reduce to when they are not needed.
 *
 *  The absolute maximum number of packets that we will allocate is
 *  whatever is required by the current activity, up to the memory limit;
 *  as soon as stress ends, we snap down to MAX_WORKINGSET_TRANSFER_PACKETS;
 *  we then lazily work down to MIN_WORKINGSET_TRANSFER_PACKETS.
 */
#define MIN_INITIAL_TRANSFER_PACKETS 1
#define MIN_WORKINGSET_TRANSFER_PACKETS_Client 16
#define MAX_WORKINGSET_TRANSFER_PACKETS_Client 32
#define MIN_WORKINGSET_TRANSFER_PACKETS_Server_UpperBound 256
#define MIN_WORKINGSET_TRANSFER_PACKETS_Server_LowerBound 32
#define MAX_WORKINGSET_TRANSFER_PACKETS_Server 1024
#define MIN_WORKINGSET_TRANSFER_PACKETS_SPACES 512
#define MAX_WORKINGSET_TRANSFER_PACKETS_SPACES 2048
#define MAX_OUTSTANDING_IO_PER_LUN_DEFAULT 16
#define MAX_CLEANUP_TRANSFER_PACKETS_AT_ONCE 8192

typedef struct _PNL_SLIST_HEADER {
    DECLSPEC_CACHEALIGN SLIST_HEADER SListHeader;
    DECLSPEC_CACHEALIGN ULONG NumFreeTransferPackets;
    ULONG NumTotalTransferPackets;
    ULONG DbgPeakNumTransferPackets;
} PNL_SLIST_HEADER, *PPNL_SLIST_HEADER;

//
// !!! WARNING !!!
// DO NOT use the following structure in code outside of classpnp
// as structure will not be guaranteed between OS versions.
//
// add to the front of this structure to help prevent illegal
// snooping by other utilities.
//
struct _CLASS_PRIVATE_FDO_DATA {
    //
    // The amount of time allowed for a target to complete a copy offload
    // operation, in seconds.  Default is 4s, but it can be modified via
    // registry key.
    //
    ULONG CopyOffloadMaxTargetDuration;

    //
    // Periodic timer for polling for media change detection, failure prediction
    // and class tick function.
    //

    KTIMER TickTimer;
    PIO_WORKITEM TickTimerWorkItem;

    //
    // Power related and release queue SRBs
    //
    union {
	STORAGE_REQUEST_BLOCK SrbEx;
	UCHAR PowerSrbBuffer[CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE];
    } PowerSrb;

    union {
	STORAGE_REQUEST_BLOCK SrbEx;
	UCHAR ReleaseQueueSrbBuffer[CLASS_SRBEX_NO_SRBEX_DATA_BUFFER_SIZE];
    } ReleaseQueueSrb;

    ULONG TrackingFlags;

    /*
     * Flag to detect recursion caused by devices
     * reporting different capacity per each request
     */
    ULONG UpdateDiskPropertiesWorkItemActive;

    //
    // Local equivalents of MinWorkingSetTransferPackets and MaxWorkingSetTransferPackets.
    // These values are initialized by the global equivalents but are then adjusted as
    // requested by the class driver.
    //
    ULONG LocalMinWorkingSetTransferPackets;
    ULONG LocalMaxWorkingSetTransferPackets;

#if DBG

    ULONG MaxOutstandingIOPerLUN;

#endif

    /*
     *  Entry in static list used by debug extension to quickly find all class FDOs.
     */
    LIST_ENTRY AllFdosListEntry;

    //
    // this private structure allows us to
    // dynamically re-enable the perf benefits
    // lost due to transient error conditions.
    // in w2k, a reboot was required. :(
    //
    struct {
	ULONG OriginalSrbFlags;
	ULONG SuccessfulIO;
	ULONG ReEnableThreshhold; // 0 means never
    } Perf;

    ULONG_PTR HackFlags;

    STORAGE_HOTPLUG_INFO HotplugInfo;

    // Legacy.  Still used by obsolete legacy code.
    struct {
	LARGE_INTEGER Delta; // in ticks
	LARGE_INTEGER Tick; // when it should fire
	PCLASS_RETRY_INFO ListHead; // singly-linked list
	ULONG Granularity; // static
	PIO_WORKITEM WorkItem; // IO work item object
	KTIMER Timer; // timer to fire IO work item
    } Retry;

    BOOLEAN TimerInitialized;
    BOOLEAN LoggedTURFailureSinceLastIO;
    BOOLEAN LoggedSYNCFailure;

    //
    // privately allocated release queue irp
    // protected by fdoExtension->ReleaseQueueSpinLock
    //
    BOOLEAN ReleaseQueueIrpAllocated;
    PIRP ReleaseQueueIrp;

    /*
     *  Queues for TRANSFER_PACKETs that contextualize the IRPs and SRBs
     *  that we send down to the port driver.
     *  (The free list is an slist so that we can use fast
     *   interlocked operations on it; but the relatively-static
     *   AllTransferPacketsList list has to be
     *   a doubly-linked list since we have to dequeue from the middle).
     */
    LIST_ENTRY AllTransferPacketsList;
    PPNL_SLIST_HEADER FreeTransferPacketsLists;

    /*
     *  Queue for deferred client irps
     */
    LIST_ENTRY DeferredClientIrpList;

    /*
     *  Precomputed maximum transfer length for the hardware.
     */
    ULONG HwMaxXferLen;

    /*
     *  STORAGE_REQUEST_BLOCK template preconfigured with the constant values.
     *  This is slapped into the SRB in the TRANSFER_PACKET for each transfer.
     */
    PSTORAGE_REQUEST_BLOCK SrbTemplate;

    /*
     *  For non-removable media, we read the drive capacity at start time and cache it.
     *  This is so that ReadDriveCapacity failures at runtime (e.g. due to memory stress)
     *  don't cause I/O on the paging disk to start failing.
     */
    READ_CAPACITY_DATA_EX LastKnownDriveCapacityData;
    BOOLEAN IsCachedDriveCapDataValid;

    //
    // Idle priority support flag
    //
    BOOLEAN IdlePrioritySupported;

    //
    // Tick timer enabled
    //
    BOOLEAN TickTimerEnabled;

    BOOLEAN ReservedBoolean;

    /*
     *  Circular array of timestamped logs of errors that occurred on this device.
     */
    ULONG ErrorLogNextIndex;
    CLASS_ERROR_LOG_DATA ErrorLogs[NUM_ERROR_LOG_ENTRIES];

    //
    // Number of outstanding critical Io requests from Mm
    //
    ULONG NumHighPriorityPagingIo;

    //
    // Maximum number of normal Io requests that can be interleaved with the critical ones
    //
    ULONG MaxInterleavedNormalIo;

    //
    // The timestamp when entering throttle mode
    //
    LARGE_INTEGER ThrottleStartTime;

    //
    // The timestamp when exiting throttle mode
    //
    LARGE_INTEGER ThrottleStopTime;

    //
    // The longest time ever spent in throttle mode
    //
    LARGE_INTEGER LongestThrottlePeriod;

#if DBG
    ULONG DbgMaxPktId;

    /*
     *  Logging fields for ForceUnitAccess and Flush
     */
    BOOLEAN DbgInitFlushLogging; // must reset this to 1 for each logging session
    ULONG DbgNumIORequests;
    ULONG DbgNumFUAs; // num I/O requests with ForceUnitAccess bit set
    ULONG DbgNumFlushes; // num SRB_FUNCTION_FLUSH_QUEUE
    ULONG DbgIOsSinceFUA;
    ULONG DbgIOsSinceFlush;
    ULONG DbgAveIOsToFUA; // average number of I/O requests between FUAs
    ULONG DbgAveIOsToFlush; // ...
    ULONG DbgMaxIOsToFUA;
    ULONG DbgMaxIOsToFlush;
    ULONG DbgMinIOsToFUA;
    ULONG DbgMinIOsToFlush;

    /*
     *  Debug log of previously sent packets (including retries).
     */
    ULONG DbgPacketLogNextIndex;
    TRANSFER_PACKET DbgPacketLogs[DBG_NUM_PACKET_LOG_ENTRIES];
#endif

    //
    // Queue for low priority I/O
    //
    LIST_ENTRY IdleIrpList;

    //
    // Timer for low priority I/O
    //
    KTIMER IdleTimer;

    //
    // IO work item for low priority I/O
    //
    PIO_WORKITEM IdleWorkItem;

    //
    // Time (ms) since the completion of the last non-idle request before the
    // first idle request should be issued. Due to the coarseness of the idle
    // timer frequency, some variability in the idle interval will be tolerated
    // such that it is the desired idle interval on average.
    //
    USHORT IdleInterval;

    //
    // Max number of active idle requests.
    //
    USHORT IdleActiveIoMax;

    //
    // Idle duration required to process idle request
    // to avoid starvation
    //
    USHORT StarvationDuration;

    //
    // Idle I/O count
    //
    ULONG IdleIoCount;

    //
    // Flag to indicate timer status
    //
    LONG IdleTimerStarted;

    //
    // Time when the Idle timer was started
    //
    LARGE_INTEGER AntiStarvationStartTime;

    //
    // Normal priority I/O time
    //
    LARGE_INTEGER LastNonIdleIoTime;

    //
    // Time when the last IO of any priority completed.
    //
    LARGE_INTEGER LastIoCompletionTime;

    //
    // Count of active normal priority I/O
    //
    LONG ActiveIoCount;

    //
    // Count of active idle priority I/O
    //
    LONG ActiveIdleIoCount;

    //
    // Support for class drivers to extend
    // the interpret sense information routine
    // and retry history per-packet.  Copy of
    // values in driver extension.
    //
    PCLASS_INTERPRET_SENSE_INFO2 InterpretSenseInfo;

    //
    // power process parameters. they work closely with CLASS_POWER_CONTEXT structure.
    //
    ULONG MaxPowerOperationRetryCount;
    PIRP PowerProcessIrp;

    //
    // Indicates legacy error handling should be used.
    // This means:
    //  - Max number of retries for an IO request is 8 (instead of 4).
    //
    BOOLEAN LegacyErrorHandling;

    //
    // Maximum number of retries allowed for IO requests for this device.
    //
    UCHAR MaxNumberOfIoRetries;

    //
    // Disable All Throttling in case of Error
    //
    BOOLEAN DisableThrottling;
};

typedef struct _IDLE_POWER_FDO_LIST_ENTRY {
    LIST_ENTRY ListEntry;
    PDEVICE_OBJECT Fdo;
} IDLE_POWER_FDO_LIST_ENTRY, *PIDLE_POWER_FDO_LIST_ENTRY;

typedef struct _OFFLOAD_READ_CONTEXT {
    PDEVICE_OBJECT Fdo;

    //
    // Upper offload read DSM irp.
    //

    PIRP OffloadReadDsmIrp;

    //
    // A pseudo-irp is used despite the operation being async.  This is in
    // contrast to normal read and write, which let TransferPktComplete()
    // complete the upper IRP directly.  Offload requests are different enough
    // that it makes more sense to let them manage their own async steps with
    // minimal help from TransferPktComplete() (just a continuation function
    // call during TransferPktComplete()).
    //

    IRP PseudoIrp;

    //
    // The offload read context tracks one packet in flight at a time - it'll be
    // the POPULATE TOKEN packet first, then RECEIVE ROD TOKEN INFORMATION.
    //
    // This field exists only for debug purposes.
    //

    PTRANSFER_PACKET Pkt;

    ULONG BufferLength;

    ULONG ListIdentifier;

    ULONG ReceiveTokenInformationBufferLength;

    //
    // Total sectors that the operation is attempting to process.
    //

    ULONGLONG TotalSectorsToProcess;

    //
    // Total sectors actually processed.
    //

    ULONGLONG TotalSectorsProcessed;

    //
    // Total upper request size in bytes.
    //

    ULONGLONG EntireXferLen;

    //
    // Just a cached copy of what was in the transfer packet.
    //

    union {
	STORAGE_REQUEST_BLOCK SrbEx;
	UCHAR SrbExBuffer[CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE];
    };

    //
    // Pointer into the token part of the SCSI buffer (the buffer immediately
    // after this struct), for easy reference.
    //

    PUCHAR Token;

    // The SCSI buffer (in/out buffer, not CDB) for the commands immediately
    // follows this struct, so no need to have a field redundantly pointing to
    // the buffer.
} OFFLOAD_READ_CONTEXT, *POFFLOAD_READ_CONTEXT;

typedef struct _OFFLOAD_WRITE_CONTEXT {
    PDEVICE_OBJECT Fdo;

    PIRP OffloadWriteDsmIrp;

    ULONGLONG EntireXferLen;
    ULONGLONG TotalRequestSizeSectors;

    ULONG DataSetRangesCount;

    PDEVICE_MANAGE_DATA_SET_ATTRIBUTES DsmAttributes;
    PDEVICE_DATA_SET_RANGE DataSetRanges;
    PDEVICE_DSM_OFFLOAD_WRITE_PARAMETERS OffloadWriteParameters;
    ULONGLONG LogicalBlockOffset;

    ULONG MaxBlockDescrCount;
    ULONGLONG MaxLbaCount;

    ULONG BufferLength;
    ULONG ReceiveTokenInformationBufferLength;

    IRP PseudoIrp;

    ULONGLONG TotalSectorsProcessedSuccessfully;
    ULONG DataSetRangeIndex;
    ULONGLONG DataSetRangeByteOffset;

    PTRANSFER_PACKET Pkt;

    //
    // Per-WUT (WRITE USING TOKEN), not overall.
    //

    ULONGLONG TotalSectorsToProcess;
    ULONGLONG TotalSectorsProcessed;

    ULONG ListIdentifier;

    BOOLEAN TokenInvalidated;

    //
    // Just a cached copy of what was in the transfer packet.
    //

    union {
	STORAGE_REQUEST_BLOCK SrbEx;
	UCHAR SrbExBuffer[CLASS_SRBEX_SCSI_CDB16_BUFFER_SIZE];
    };

    ULONGLONG OperationStartTime;
} OFFLOAD_WRITE_CONTEXT, *POFFLOAD_WRITE_CONTEXT;

typedef struct _OPCODE_SENSE_DATA_IO_LOG_MESSAGE_CONTEXT_HEADER {
    PIO_WORKITEM WorkItem;
    PVOID SenseData;
    ULONG SenseDataSize;
    UCHAR SrbStatus;
    UCHAR ScsiStatus;
    UCHAR OpCode;
    UCHAR Reserved;
    ULONG ErrorCode;
} OPCODE_SENSE_DATA_IO_LOG_MESSAGE_CONTEXT_HEADER, *POPCODE_SENSE_DATA_IO_LOG_MESSAGE_CONTEXT_HEADER;

typedef struct _IO_RETRIED_LOG_MESSAGE_CONTEXT {
    OPCODE_SENSE_DATA_IO_LOG_MESSAGE_CONTEXT_HEADER ContextHeader;
    LARGE_INTEGER Lba;
    ULONG DeviceNumber;
} IO_RETRIED_LOG_MESSAGE_CONTEXT, *PIO_RETRIED_LOG_MESSAGE_CONTEXT;

#define QERR_SET_ZERO_ODX_OR_TP_ONLY 0
#define QERR_SET_ZERO_ALWAYS 1
#define QERR_SET_ZERO_NEVER 2

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define NOT_READY_RETRY_INTERVAL 10
#define MINIMUM_RETRY_UNITS ((LONGLONG)32)
#define MODE_PAGE_DATA_SIZE 192

#define CLASS_IDLE_INTERVAL_MIN 12 // 12 milliseconds
#define CLASS_IDLE_INTERVAL 12 // 12 milliseconds
#define CLASS_STARVATION_INTERVAL 500 // 500 milliseconds

//
// Value of 50 milliseconds in 100 nanoseconds units
//
#define FIFTY_MS_IN_100NS_UNITS 50 * 100

/*
 *  Simple singly-linked-list queuing macros, with no synchronization.
 */
FORCEINLINE VOID SimpleInitSlistHdr(SINGLE_LIST_ENTRY *SListHdr)
{
    SListHdr->Next = NULL;
}
FORCEINLINE VOID SimplePushSlist(SINGLE_LIST_ENTRY *SListHdr,
				 SINGLE_LIST_ENTRY *SListEntry)
{
    SListEntry->Next = SListHdr->Next;
    SListHdr->Next = SListEntry;
}
FORCEINLINE SINGLE_LIST_ENTRY *SimplePopSlist(SINGLE_LIST_ENTRY *SListHdr)
{
    SINGLE_LIST_ENTRY *sListEntry = SListHdr->Next;
    if (sListEntry) {
	SListHdr->Next = sListEntry->Next;
	sListEntry->Next = NULL;
    }
    return sListEntry;
}
FORCEINLINE BOOLEAN SimpleIsSlistEmpty(SINGLE_LIST_ENTRY *SListHdr)
{
    return (SListHdr->Next == NULL);
}

FORCEINLINE BOOLEAN ClasspIsIdleRequestSupported(PCLASS_PRIVATE_FDO_DATA FdoData,
						 PIRP Irp)
{
    return (FdoData->IdlePrioritySupported == TRUE);
}

FORCEINLINE VOID ClasspMarkIrpAsIdle(PIRP Irp, BOOLEAN Idle)
{
    ((PULONG_PTR)Irp->Tail.DriverContext)[1] = Idle;
}

FORCEINLINE BOOLEAN ClasspIsIdleRequest(PIRP Irp)
{
    return ((BOOLEAN)Irp->Tail.DriverContext[1]);
}

FORCEINLINE LARGE_INTEGER ClasspGetCurrentTime(VOID)
{
    LARGE_INTEGER CurrentTime = { .QuadPart = KeQueryInterruptTime() };
    return CurrentTime;
}

FORCEINLINE ULONGLONG ClasspTimeDiffToMs(ULONGLONG TimeDiff)
{
    TimeDiff /= (10 * 1000);

    return TimeDiff;
}

FORCEINLINE BOOLEAN ClasspSupportsUnmap(IN PCLASS_FUNCTION_SUPPORT_INFO SupportInfo)
{
    return SupportInfo->LBProvisioningData.LBPU;
}

FORCEINLINE BOOLEAN ClasspIsThinProvisioned(IN PCLASS_FUNCTION_SUPPORT_INFO SupportInfo)
{
    //
    // We only support thinly provisioned devices that also support UNMAP.
    //
    if (SupportInfo->LBProvisioningData.ProvisioningType == PROVISIONING_TYPE_THIN &&
	SupportInfo->LBProvisioningData.LBPU == TRUE) {
	return TRUE;
    }

    return FALSE;
}

FORCEINLINE BOOLEAN ClasspIsObsoletePortDriver(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension)
{
    if ((FdoExtension->MiniportDescriptor != NULL) &&
	(FdoExtension->MiniportDescriptor->Portdriver == StoragePortCodeSetSCSIport)) {
	return TRUE;
    }

    return FALSE;
}

ULONG ClasspCalculateLogicalSectorSize(IN PDEVICE_OBJECT Fdo,
				       IN ULONG BytesPerBlockInBigEndian);

DRIVER_INITIALIZE DriverEntry;

DRIVER_UNLOAD ClassUnload;

DRIVER_DISPATCH ClassCreateClose;

NTSTATUS ClasspCreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

VOID ClasspCleanupProtectedLocks(IN PFILE_OBJECT_EXTENSION FsContext);

NTSTATUS ClasspEjectionControl(IN PDEVICE_OBJECT Fdo,
			       IN PIRP Irp,
			       IN MEDIA_LOCK_TYPE LockType,
			       IN BOOLEAN Lock);

DRIVER_DISPATCH ClassReadWrite;

DRIVER_DISPATCH ClassDeviceControlDispatch;

DRIVER_DISPATCH ClassDispatchPnp;

NTSTATUS ClassPnpStartDevice(IN PDEVICE_OBJECT DeviceObject);

DRIVER_DISPATCH ClassShutdownFlush;

DRIVER_DISPATCH ClassSystemControl;

//
// Class internal routines
//

DRIVER_ADD_DEVICE ClassAddDevice;

IO_COMPLETION_ROUTINE ClasspSendSynchronousCompletion;

VOID RetryRequest(PDEVICE_OBJECT DeviceObject,
		  PIRP Irp,
		  PSTORAGE_REQUEST_BLOCK Srb,
		  BOOLEAN Associated,
		  LONGLONG TimeDelta100ns);

NTSTATUS ClassIoCompletion(IN PDEVICE_OBJECT DeviceObject,
			   IN PIRP Irp,
			   IN PVOID Context);

NTSTATUS ClassPnpQueryFdoRelations(IN PDEVICE_OBJECT Fdo, IN PIRP Irp);

NTSTATUS ClassRetrieveDeviceRelations(IN PDEVICE_OBJECT Fdo,
				      IN DEVICE_RELATION_TYPE RelationType,
				      OUT PDEVICE_RELATIONS *DeviceRelations);

NTSTATUS ClassGetPdoId(IN PDEVICE_OBJECT Pdo,
		       IN BUS_QUERY_ID_TYPE IdType,
		       IN PUNICODE_STRING IdString);

NTSTATUS ClassQueryPnpCapabilities(IN PDEVICE_OBJECT PhysicalDeviceObject,
				   IN PDEVICE_CAPABILITIES Capabilities);

DRIVER_STARTIO ClasspStartIo;

NTSTATUS ClasspPagingNotificationCompletion(IN PDEVICE_OBJECT DeviceObject,
					    IN PIRP Irp,
					    IN PDEVICE_OBJECT RealDeviceObject);

NTSTATUS ClasspMediaChangeCompletion(PDEVICE_OBJECT DeviceObject,
				     PIRP Irp,
				     PVOID Context);

NTSTATUS ClasspMcnControl(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			  IN PIRP Irp,
			  IN PSTORAGE_REQUEST_BLOCK Srb);

VOID ClasspRegisterMountedDeviceInterface(IN PDEVICE_OBJECT DeviceObject);

VOID ClasspDisableTimer(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

VOID ClasspEnableTimer(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClasspInitializeTimer(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

VOID ClasspDeleteTimer(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClasspDuidQueryProperty(PDEVICE_OBJECT DeviceObject, PIRP Irp);

DRIVER_DISPATCH ClassGlobalDispatch;

VOID ClassInitializeDispatchTables(PCLASS_DRIVER_EXTENSION DriverExtension);

NTSTATUS ClasspPersistentReserve(IN PDEVICE_OBJECT DeviceObject,
				 IN PIRP Irp,
				 IN OUT PSTORAGE_REQUEST_BLOCK Srb);

//
// routines for dictionary list support
//

VOID InitializeDictionary(IN PDICTIONARY Dictionary);

BOOLEAN TestDictionarySignature(IN PDICTIONARY Dictionary);

NTSTATUS AllocateDictionaryEntry(IN PDICTIONARY Dictionary,
				 IN ULONGLONG Key,
				 IN ULONG Size,
				 IN ULONG Tag,
				 OUT PVOID *Entry);

PVOID GetDictionaryEntry(IN PDICTIONARY Dictionary, IN ULONGLONG Key);

VOID FreeDictionaryEntry(IN PDICTIONARY Dictionary, IN PVOID Entry);

NTSTATUS ClasspAllocateReleaseRequest(IN PDEVICE_OBJECT Fdo);

VOID ClasspFreeReleaseRequest(IN PDEVICE_OBJECT Fdo);

IO_COMPLETION_ROUTINE ClassReleaseQueueCompletion;

VOID ClasspReleaseQueue(IN PDEVICE_OBJECT DeviceObject, IN PIRP ReleaseQueueIrp);

VOID ClasspDisablePowerNotification(PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

//
// class power routines
//

DRIVER_DISPATCH ClassDispatchPower;

NTAPI NTSTATUS ClassMinimalPowerHandler(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp);

NTSTATUS ClasspEnableIdlePower(IN PDEVICE_OBJECT DeviceObject);

POWER_SETTING_CALLBACK ClasspPowerSettingCallback;

//
// Child list routines
//

VOID ClassAddChild(IN PFUNCTIONAL_DEVICE_EXTENSION Parent,
		   IN PPHYSICAL_DEVICE_EXTENSION Child,
		   IN BOOLEAN AcquireLock);

PPHYSICAL_DEVICE_EXTENSION ClassRemoveChild(IN PFUNCTIONAL_DEVICE_EXTENSION Parent,
					    IN PPHYSICAL_DEVICE_EXTENSION Child,
					    IN BOOLEAN AcquireLock);

VOID ClassFreeOrReuseSrb(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			 IN PSTORAGE_REQUEST_BLOCK Srb);

VOID ClassRetryRequest(IN PDEVICE_OBJECT SelfDeviceObject, IN PIRP Irp,
		       IN LONGLONG TimeDelta100ns); // in 100ns units

VOID ClasspBuildRequestEx(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			  IN PIRP Irp,
			  IN PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspAllocateReleaseQueueIrp(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClasspAllocatePowerProcessIrp(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClasspInitializeGesn(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			      IN PMEDIA_CHANGE_DETECTION_INFO Info);

VOID ClassSendEjectionNotification(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

VOID ClasspScanForSpecialInRegistry(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTAPI VOID ClasspScanForClassHacks(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
				   IN ULONG_PTR Data);

NTSTATUS ClasspInitializeHotplugInfo(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

VOID ClasspPerfIncrementErrorCount(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);
VOID ClasspPerfIncrementSuccessfulIo(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

IO_WORKITEM_ROUTINE ClasspUpdateDiskProperties;

VOID DestroyTransferPacket(IN PTRANSFER_PACKET Pkt);
VOID EnqueueFreeTransferPacket(PDEVICE_OBJECT Fdo,
			       PTRANSFER_PACKET Pkt);
PTRANSFER_PACKET DequeueFreeTransferPacket(PDEVICE_OBJECT Fdo,
					   BOOLEAN AllocIfNeeded);
PTRANSFER_PACKET DequeueFreeTransferPacketEx(IN PDEVICE_OBJECT Fdo,
					     IN BOOLEAN AllocIfNeeded,
					     IN ULONG Node);
VOID SetupReadWriteTransferPacket(PTRANSFER_PACKET Pkt,
				  PVOID Buf,
				  ULONG Len,
				  LARGE_INTEGER DiskLocation,
				  PIRP OriginalIrp);
NTSTATUS SubmitTransferPacket(PTRANSFER_PACKET Pkt);
IO_COMPLETION_ROUTINE TransferPktComplete;
NTSTATUS ServiceTransferRequest(PDEVICE_OBJECT Fdo,
				PIRP Irp,
				BOOLEAN PostToTimer);
VOID TransferPacketSetRetryTimer(PTRANSFER_PACKET Pkt);
BOOLEAN InterpretTransferPacketError(PTRANSFER_PACKET Pkt);
BOOLEAN RetryTransferPacket(PTRANSFER_PACKET Pkt);
VOID EnqueueDeferredClientIrp(PDEVICE_OBJECT Fdo, PIRP Irp);
PIRP DequeueDeferredClientIrp(PDEVICE_OBJECT Fdo);
VOID InitLowMemRetry(PTRANSFER_PACKET Pkt,
		     PVOID BufPtr,
		     ULONG Len,
		     LARGE_INTEGER TargetLocation);
BOOLEAN StepLowMemRetry(PTRANSFER_PACKET Pkt);
VOID SetupEjectionTransferPacket(TRANSFER_PACKET *Pkt,
				 BOOLEAN PreventMediaRemoval,
				 PKEVENT SyncEventPtr,
				 PIRP OriginalIrp);
VOID SetupModeSenseTransferPacket(TRANSFER_PACKET *Pkt,
				  PKEVENT SyncEventPtr,
				  PVOID ModeSenseBuffer,
				  UCHAR ModeSenseBufferLen,
				  UCHAR PageMode,
				  UCHAR SubPage,
				  PIRP OriginalIrp,
				  UCHAR PageControl);
VOID SetupModeSelectTransferPacket(TRANSFER_PACKET *Pkt,
				   PKEVENT SyncEventPtr,
				   PVOID ModeSelectBuffer,
				   UCHAR ModeSelectBufferLen,
				   BOOLEAN SavePages,
				   PIRP OriginalIrp);
VOID SetupDriveCapacityTransferPacket(TRANSFER_PACKET *Pkt,
				      PVOID ReadCapacityBuffer,
				      ULONG ReadCapacityBufferLen,
				      PKEVENT SyncEventPtr,
				      PIRP OriginalIrp,
				      BOOLEAN Use16ByteCdb);
NTSTATUS InitializeTransferPackets(PDEVICE_OBJECT Fdo);
VOID DestroyAllTransferPackets(PDEVICE_OBJECT Fdo);
VOID InterpretCapacityData(PDEVICE_OBJECT Fdo,
			   PREAD_CAPACITY_DATA_EX ReadCapacityData);
IO_WORKITEM_ROUTINE_EX CleanupTransferPacketToWorkingSetSizeWorker;
VOID CleanupTransferPacketToWorkingSetSize(IN PDEVICE_OBJECT Fdo,
					   IN BOOLEAN LimitNumPktToDelete,
					   IN ULONG Node);

VOID ClasspSetupPopulateTokenTransferPacket(IN POFFLOAD_READ_CONTEXT Context,
					    IN PTRANSFER_PACKET Pkt,
					    IN ULONG Length,
					    IN PUCHAR PopulateTokenBuffer,
					    IN PIRP OriginalIrp,
					    IN ULONG ListIdentifier);

VOID ClasspSetupReceivePopulateTokenInformationTransferPacket(IN POFFLOAD_READ_CONTEXT Context,
							      IN PTRANSFER_PACKET Pkt,
							      IN ULONG Length,
							      IN PUCHAR Buffer,
							      IN PIRP OriginalIrp,
							      IN ULONG ListIdentifier);

VOID ClasspSetupWriteUsingTokenTransferPacket(IN POFFLOAD_WRITE_CONTEXT Context,
					      IN PTRANSFER_PACKET Pkt,
					      IN ULONG Length,
					      IN PUCHAR Buffer,
					      IN PIRP OriginalIrp,
					      IN ULONG ListIdentifier);

VOID ClasspSetupReceiveWriteUsingTokenInformationTransferPacket(IN POFFLOAD_WRITE_CONTEXT Context,
								IN PTRANSFER_PACKET Pkt,
								IN ULONG Length,
								IN PUCHAR Buffer,
								IN PIRP OriginalIrp,
								IN ULONG ListIdentifier);

ULONG ClasspModeSense(IN PDEVICE_OBJECT Fdo,
		      IN PCHAR ModeSenseBuffer,
		      IN ULONG Length,
		      IN UCHAR PageMode,
		      IN UCHAR PageControl);

NTSTATUS ClasspModeSelect(IN PDEVICE_OBJECT Fdo,
			  IN PCHAR ModeSelectBuffer,
			  IN ULONG Length,
			  IN BOOLEAN SavePages);

NTSTATUS ClasspWriteCacheProperty(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp,
				  IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspAccessAlignmentProperty(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp,
				       IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceSeekPenaltyProperty(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp,
					 IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceGetLBProvisioningVPDPage(IN PDEVICE_OBJECT DeviceObject,
					      IN OUT OPTIONAL PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceGetBlockDeviceCharacteristicsVPDPage(IN PFUNCTIONAL_DEVICE_EXTENSION fdoExtension,
							  IN PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceGetBlockLimitsVPDPage(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
					   IN OUT PSTORAGE_REQUEST_BLOCK Srb,
					   IN ULONG SrbSize,
					   OUT PCLASS_VPD_B0_DATA BlockLimitsData);

NTSTATUS ClasspDeviceTrimProperty(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp,
				  IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceLBProvisioningProperty(IN PDEVICE_OBJECT DeviceObject,
					    IN OUT PIRP Irp,
					    IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceTrimProcess(IN PDEVICE_OBJECT DeviceObject,
				 IN PIRP Irp,
				 IN PGUID ActivityId,
				 IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceGetLBAStatus(IN PDEVICE_OBJECT DeviceObject,
				  IN OUT PIRP Irp,
				  IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspDeviceGetLBAStatusWorker(IN PDEVICE_OBJECT DeviceObject,
					IN PCLASS_VPD_B0_DATA BlockLimitsData,
					IN ULONGLONG StartingOffset,
					IN ULONGLONG LengthInBytes,
					OUT PDEVICE_MANAGE_DATA_SET_ATTRIBUTES_OUTPUT DsmOutput,
					IN OUT PULONG DsmOutputLength,
					IN OUT PSTORAGE_REQUEST_BLOCK Srb,
					IN BOOLEAN ConsolidateableBlocksOnly,
					IN ULONG OutputVersion,
					OUT PBOOLEAN BlockLimitsDataMayHaveChanged);

VOID ClassQueueThresholdEventWorker(IN PDEVICE_OBJECT DeviceObject);

VOID ClassQueueResourceExhaustionEventWorker(IN PDEVICE_OBJECT DeviceObject);

VOID ClassQueueCapacityChangedEventWorker(IN PDEVICE_OBJECT DeviceObject);

VOID ClassQueueProvisioningTypeChangedEventWorker(IN PDEVICE_OBJECT DeviceObject);

IO_WORKITEM_ROUTINE ClasspLogIOEventWithContext;

VOID ClasspQueueLogIOEventWithContextWorker(IN PDEVICE_OBJECT DeviceObject,
					    IN ULONG SenseBufferSize,
					    IN PVOID SenseData,
					    IN UCHAR SrbStatus,
					    IN UCHAR ScsiStatus,
					    IN ULONG ErrorCode,
					    IN ULONG CdbLength,
					    IN OPTIONAL PCDB Cdb,
					    IN OPTIONAL PTRANSFER_PACKET Pkt);

VOID ClasspZeroQERR(IN PDEVICE_OBJECT DeviceObject);

NTSTATUS ClasspGetMaximumTokenListIdentifier(IN PDEVICE_OBJECT DeviceObject,
					     IN PWSTR RegistryPath,
					     OUT PULONG MaximumListIdentifier);

NTSTATUS ClasspGetCopyOffloadMaxDuration(IN PDEVICE_OBJECT DeviceObject,
					 IN PWSTR RegistryPath,
					 OUT PULONG MaxDuration);

NTSTATUS ClasspDeviceCopyOffloadProperty(IN PDEVICE_OBJECT DeviceObject,
					 IN OUT PIRP Irp,
					 IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspValidateOffloadSupported(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp);

NTSTATUS ClasspValidateOffloadInputParameters(IN PDEVICE_OBJECT DeviceObject,
					      IN PIRP Irp);

NTSTATUS ClasspGetTokenOperationCommandBufferLength(IN PDEVICE_OBJECT Fdo,
						    IN ULONG ServiceAction,
						    IN OUT PULONG CommandBufferLength,
						    OUT OPTIONAL PULONG TokenOperationBufferLength,
						    OUT OPTIONAL PULONG ReceiveTokenInformationBufferLength);

NTSTATUS ClasspGetTokenOperationDescriptorLimits(IN PDEVICE_OBJECT Fdo,
						 IN ULONG ServiceAction,
						 IN ULONG MaxParameterBufferLength,
						 OUT PULONG MaxBlockDescriptorsCount,
						 OUT PULONGLONG MaxBlockDescriptorsLength);

VOID ClasspConvertDataSetRangeToBlockDescr(IN PDEVICE_OBJECT Fdo,
					   IN PVOID BlockDescr,
					   IN OUT PULONG CurrentBlockDescrIndex,
					   IN ULONG MaxBlockDescrCount,
					   IN OUT PULONG CurrentLbaCount,
					   IN ULONGLONG MaxLbaCount,
					   IN OUT PDEVICE_DATA_SET_RANGE DataSetRange,
					   IN OUT PULONGLONG TotalSectorsProcessed);

NTSTATUS ClasspDeviceMediaTypeProperty(IN PDEVICE_OBJECT DeviceObject,
				       IN OUT PIRP Irp,
				       IN OUT PSTORAGE_REQUEST_BLOCK Srb);

PUCHAR ClasspBinaryToAscii(IN PUCHAR HexBuffer,
			   IN ULONG Length,
			   IN OUT PULONG UpdateLength);

FORCEINLINE BOOLEAN ClasspIsTokenOperationComplete(IN ULONG CurrentStatus)
{
    BOOLEAN operationCompleted = FALSE;

    switch (CurrentStatus) {
    case OPERATION_COMPLETED_WITH_SUCCESS:
    case OPERATION_COMPLETED_WITH_ERROR:
    case OPERATION_COMPLETED_WITH_RESIDUAL_DATA:
    case OPERATION_TERMINATED: {
	operationCompleted = TRUE;
    }
    }

    return operationCompleted;
}

FORCEINLINE BOOLEAN ClasspIsTokenOperation(IN PCDB Cdb)
{
    BOOLEAN tokenOperation = FALSE;

    if (Cdb) {
	ULONG opCode = Cdb->AsByte[0];
	ULONG serviceAction = Cdb->AsByte[1];

	if ((opCode == SCSIOP_POPULATE_TOKEN &&
	     serviceAction == SERVICE_ACTION_POPULATE_TOKEN) ||
	    (opCode == SCSIOP_WRITE_USING_TOKEN &&
	     serviceAction == SERVICE_ACTION_WRITE_USING_TOKEN)) {
	    tokenOperation = TRUE;
	}
    }

    return tokenOperation;
}

FORCEINLINE BOOLEAN ClasspIsReceiveTokenInformation(IN PCDB Cdb)
{
    BOOLEAN receiveTokenInformation = FALSE;

    if (Cdb) {
	ULONG opCode = Cdb->AsByte[0];
	ULONG serviceAction = Cdb->AsByte[1];

	if (opCode == SCSIOP_RECEIVE_ROD_TOKEN_INFORMATION &&
	    serviceAction == SERVICE_ACTION_RECEIVE_TOKEN_INFORMATION) {
	    receiveTokenInformation = TRUE;
	}
    }

    return receiveTokenInformation;
}

FORCEINLINE BOOLEAN ClasspIsOffloadDataTransferCommand(IN PCDB Cdb)
{
    return ClasspIsTokenOperation(Cdb) || ClasspIsReceiveTokenInformation(Cdb);
}

extern LIST_ENTRY AllFdosList;

NTSTATUS ClasspInitializeIdleTimer(IN PDEVICE_OBJECT Fdo,
				   IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClasspIsPortable(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			  OUT PBOOLEAN IsPortable);

VOID ClasspGetInquiryVpdSupportInfo(IN OUT PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClasspGetLBProvisioningInfo(IN OUT PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClassDetermineTokenOperationCommandSupport(IN PDEVICE_OBJECT DeviceObject);

NTSTATUS ClasspGetBlockDeviceTokenLimitsInfo(IN OUT PDEVICE_OBJECT DeviceObject);

NTSTATUS ClassDeviceProcessOffloadRead(IN PDEVICE_OBJECT DeviceObject,
				       IN PIRP Irp,
				       IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClassDeviceProcessOffloadWrite(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp,
					IN OUT PSTORAGE_REQUEST_BLOCK Srb);

VOID ClasspReceivePopulateTokenInformation(IN POFFLOAD_READ_CONTEXT OffloadReadContext);

NTSTATUS ClasspServiceWriteUsingTokenTransferRequest(IN PDEVICE_OBJECT Fdo,
						     IN PIRP Irp);

VOID ClasspReceiveWriteUsingTokenInformation(IN POFFLOAD_WRITE_CONTEXT OffloadWriteContext);

VOID ClasspCompleteOffloadRequest(IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp,
				  IN NTSTATUS CompletionStatus);

VOID ClasspCleanupOffloadReadContext(IN POFFLOAD_READ_CONTEXT OffloadReadContext);

VOID ClasspCompleteOffloadRead(IN POFFLOAD_READ_CONTEXT OffloadReadContext,
			       IN NTSTATUS CompletionStatus);

// PCONTINUATION_ROUTINE
VOID ClasspPopulateTokenTransferPacketDone(IN PVOID Context);

// PCONTINUATION_ROUTINE
VOID ClasspReceivePopulateTokenInformationTransferPacketDone(IN PVOID Context);

VOID ClasspContinueOffloadWrite(IN POFFLOAD_WRITE_CONTEXT OffloadWriteContext);

VOID ClasspCleanupOffloadWriteContext(IN POFFLOAD_WRITE_CONTEXT OffloadWriteContext);

VOID ClasspCompleteOffloadWrite(IN POFFLOAD_WRITE_CONTEXT OffloadWriteContext,
				IN NTSTATUS CompletionCausingStatus);

VOID ClasspReceiveWriteUsingTokenInformationDone(IN POFFLOAD_WRITE_CONTEXT
						 OffloadWriteContext,
						 IN NTSTATUS CompletionCausingStatus);

VOID ClasspWriteUsingTokenTransferPacketDone(IN PVOID Context);

VOID ClasspReceiveWriteUsingTokenInformationTransferPacketDone(IN POFFLOAD_WRITE_CONTEXT OffloadWriteContext);

NTSTATUS ClasspRefreshFunctionSupportInfo(IN OUT PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
					  IN BOOLEAN ForceQuery);

NTSTATUS ClasspBlockLimitsDataSnapshot(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
				       IN BOOLEAN ForceQuery,
				       OUT PCLASS_VPD_B0_DATA BlockLimitsData,
				       OUT PULONG GenerationCount);

NTSTATUS InterpretReadCapacity16Data(IN OUT PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
				     IN PREAD_CAPACITY16_DATA ReadCapacity16Data);

NTSTATUS ClassReadCapacity16(IN OUT PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
			     IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClassDeviceGetLBProvisioningResources(IN PDEVICE_OBJECT DeviceObject,
					       IN OUT PIRP Irp,
					       IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClasspStorageEventNotification(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

NTSTATUS ClasspPowerActivateDevice(IN PDEVICE_OBJECT DeviceObject);

NTSTATUS ClasspPowerIdleDevice(IN PDEVICE_OBJECT DeviceObject);

IO_WORKITEM_ROUTINE ClassLogThresholdEvent;

NTSTATUS ClasspLogSystemEventWithDeviceNumber(IN PDEVICE_OBJECT DeviceObject,
					      IN NTSTATUS IoErrorCode);

IO_WORKITEM_ROUTINE ClassLogResourceExhaustionEvent;

NTSTATUS ClasspEnqueueIdleRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp);

VOID ClasspCompleteIdleRequest(PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

NTSTATUS ClasspPriorityHint(PDEVICE_OBJECT DeviceObject, PIRP Irp);

VOID HistoryInitializeRetryLogs(OUT PSRB_HISTORY History, ULONG HistoryCount);
#define HISTORYINITIALIZERETRYLOGS(_packet)				\
    {									\
	if (_packet->RetryHistory != NULL) {				\
	    HistoryInitializeRetryLogs(_packet->RetryHistory,		\
				       _packet->RetryHistory->TotalHistoryCount); \
	}								\
    }

VOID HistoryLogSendPacket(TRANSFER_PACKET *Pkt);
#define HISTORYLOGSENDPACKET(_packet)		\
    {						\
	if (_packet->RetryHistory != NULL) {	\
	    HistoryLogSendPacket(_packet);	\
	}					\
    }

VOID HistoryLogReturnedPacket(TRANSFER_PACKET *Pkt);

#define HISTORYLOGRETURNEDPACKET(_packet)	\
    {						\
	if (_packet->RetryHistory != NULL) {	\
	    HistoryLogReturnedPacket(_packet);	\
	}					\
    }

BOOLEAN InterpretSenseInfoWithoutHistory(IN PDEVICE_OBJECT Fdo,
					 IN OPTIONAL PIRP OriginalRequest,
					 IN PSTORAGE_REQUEST_BLOCK Srb,
					 UCHAR MajorFunctionCode,
					 ULONG IoDeviceCode,
					 ULONG PreviousRetryCount,
					 OUT NTSTATUS *Status,
					 OUT OPTIONAL LONGLONG *RetryIn100nsUnits);

BOOLEAN ClasspMyStringMatches(IN OPTIONAL PCHAR StringToMatch, IN PCHAR TargetString);

#define TRACKING_FORWARD_PROGRESS_PATH1 (0x00000001)
#define TRACKING_FORWARD_PROGRESS_PATH2 (0x00000002)
#define TRACKING_FORWARD_PROGRESS_PATH3 (0x00000004)

RTL_GENERIC_COMPARE_ROUTINE RemoveTrackingCompareRoutine;

RTL_GENERIC_ALLOCATE_ROUTINE RemoveTrackingAllocateRoutine;

RTL_GENERIC_FREE_ROUTINE RemoveTrackingFreeRoutine;

typedef PVOID (*PSRB_ALLOCATE_ROUTINE)(IN CLONG ByteSize);

PVOID DefaultStorageRequestBlockAllocateRoutine(IN CLONG ByteSize);

NTSTATUS CreateStorageRequestBlock(IN OUT PSTORAGE_REQUEST_BLOCK *Srb,
				   IN USHORT AddressType,
				   IN OPTIONAL PSRB_ALLOCATE_ROUTINE AllocateRoutine,
				   IN OUT OPTIONAL ULONG *ByteSize,
				   IN ULONG NumSrbExData, ...);

NTSTATUS InitializeStorageRequestBlock(IN OUT PSTORAGE_REQUEST_BLOCK Srb,
				       IN USHORT AddressType,
				       IN ULONG ByteSize,
				       IN ULONG NumSrbExData, ...);

FORCEINLINE PCDB ClasspTransferPacketGetCdb(IN PTRANSFER_PACKET Pkt)
{
    return SrbGetCdb(Pkt->Srb);
}

//
// This inline function calculates number of retries already happened till now for known operation codes
// and set the out parameter - TimesAlreadyRetried with the value,  returns True
//
// For unknown operation codes this function will return false and will set TimesAlreadyRetried with zero
//
FORCEINLINE BOOLEAN ClasspTransferPacketGetNumberOfRetriesDone(IN PTRANSFER_PACKET Pkt,
							       IN PCDB Cdb,
							       OUT PULONG TimesAlreadyRetried)
{
    PFUNCTIONAL_DEVICE_EXTENSION fdoExtension = Pkt->Fdo->DeviceExtension;
    PCLASS_PRIVATE_FDO_DATA fdoData = fdoExtension->PrivateFdoData;

    if (Cdb->MEDIA_REMOVAL.OperationCode == SCSIOP_MEDIUM_REMOVAL) {
	*TimesAlreadyRetried = NUM_LOCKMEDIAREMOVAL_RETRIES - Pkt->NumRetries;
    } else if ((Cdb->MODE_SENSE.OperationCode == SCSIOP_MODE_SENSE) ||
	       (Cdb->MODE_SENSE.OperationCode == SCSIOP_MODE_SENSE10)) {
	*TimesAlreadyRetried = NUM_MODESENSE_RETRIES - Pkt->NumRetries;
    } else if ((Cdb->CDB10.OperationCode == SCSIOP_READ_CAPACITY) ||
	       (Cdb->CDB16.OperationCode == SCSIOP_READ_CAPACITY16)) {
	*TimesAlreadyRetried = NUM_DRIVECAPACITY_RETRIES - Pkt->NumRetries;
    } else if (IS_SCSIOP_READWRITE(Cdb->CDB10.OperationCode)) {
	*TimesAlreadyRetried = fdoData->MaxNumberOfIoRetries - Pkt->NumRetries;
    } else if (Cdb->TOKEN_OPERATION.OperationCode == SCSIOP_POPULATE_TOKEN &&
	       Cdb->TOKEN_OPERATION.ServiceAction == SERVICE_ACTION_POPULATE_TOKEN) {
	*TimesAlreadyRetried = NUM_POPULATE_TOKEN_RETRIES - Pkt->NumRetries;
    } else if (Cdb->TOKEN_OPERATION.OperationCode == SCSIOP_WRITE_USING_TOKEN &&
	       Cdb->TOKEN_OPERATION.ServiceAction == SERVICE_ACTION_WRITE_USING_TOKEN) {
	*TimesAlreadyRetried = NUM_WRITE_USING_TOKEN_RETRIES - Pkt->NumRetries;
    } else if (ClasspIsReceiveTokenInformation(Cdb)) {
	*TimesAlreadyRetried = NUM_RECEIVE_TOKEN_INFORMATION_RETRIES - Pkt->NumRetries;
    }

    else {
	*TimesAlreadyRetried = 0;
	return FALSE;
    }

    return TRUE;
}

FORCEINLINE PVOID ClasspTransferPacketGetSenseInfoBuffer(IN PTRANSFER_PACKET Pkt)
{
    return SrbGetSenseInfoBuffer(Pkt->Srb);
}

FORCEINLINE UCHAR ClasspTransferPacketGetSenseInfoBufferLength(IN PTRANSFER_PACKET Pkt)
{
    return SrbGetSenseInfoBufferLength(Pkt->Srb);
}

FORCEINLINE BOOLEAN PORT_ALLOCATED_SENSE_EX(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
					    IN PSTORAGE_REQUEST_BLOCK Srb)
{
    return ((BOOLEAN)((TEST_FLAG(SrbGetSrbFlags(Srb), SRB_FLAGS_PORT_DRIVER_ALLOCSENSE) &&
		       TEST_FLAG(SrbGetSrbFlags(Srb), SRB_FLAGS_FREE_SENSE_BUFFER)) &&
		      (SrbGetSenseInfoBuffer(Srb) != FdoExtension->SenseData)));
}

FORCEINLINE VOID FREE_PORT_ALLOCATED_SENSE_BUFFER_EX(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension,
						     IN PSTORAGE_REQUEST_BLOCK Srb)
{
    NT_ASSERT(TEST_FLAG(SrbGetSrbFlags(Srb), SRB_FLAGS_PORT_DRIVER_ALLOCSENSE));
    NT_ASSERT(TEST_FLAG(SrbGetSrbFlags(Srb), SRB_FLAGS_FREE_SENSE_BUFFER));
    NT_ASSERT(SrbGetSenseInfoBuffer(Srb) != FdoExtension->SenseData);

    ExFreePool(SrbGetSenseInfoBuffer(Srb));
    SrbSetSenseInfoBuffer(Srb, FdoExtension->SenseData);
    SrbSetSenseInfoBufferLength(Srb, GET_FDO_EXTENSON_SENSE_DATA_LENGTH(FdoExtension));
    SrbClearSrbFlags(Srb, SRB_FLAGS_FREE_SENSE_BUFFER);
    return;
}

BOOLEAN ClasspFailurePredictionPeriodMissed(IN PFUNCTIONAL_DEVICE_EXTENSION FdoExtension);

/*++

  Routine Description:

  This routine returns the maximum size of a buffer that starts at a given offset,
  based on the size of the containing structure.

  Arguments:

  BaseAddress - The base address of the structure. The offset is computed relative to this.

  OffsetInBytes - (BaseAddress + OffsetInBytes) points to the beginning of the buffer.

  BaseStructureSizeInBytes - The size of the structure which contains the buffer.

  Return Value:

  max(BaseStructureSizeInBytes - OffsetInBytes, 0). If any operations wrap around,
  the return value is 0.

  --*/
FORCEINLINE ULONG ClasspGetMaxUsableBufferLengthFromOffset(IN PVOID BaseAddress,
							   IN ULONG OffsetInBytes,
							   IN ULONG BaseStructureSizeInBytes)
{
    ULONG_PTR offsetAddress = ((ULONG_PTR)BaseAddress + OffsetInBytes);

    if (offsetAddress < (ULONG_PTR)BaseAddress) {
	//
	// This means BaseAddress + OffsetInBytes > ULONG_PTR_MAX.
	//
	return 0;
    }

    if (OffsetInBytes > BaseStructureSizeInBytes) {
	return 0;
    }

    return BaseStructureSizeInBytes - OffsetInBytes;
}

BOOLEAN ClasspIsThinProvisioningError(IN PSTORAGE_REQUEST_BLOCK Srb);

FORCEINLINE BOOLEAN ClasspLowerLayerNotSupport(IN NTSTATUS Status)
{
    return ((Status == STATUS_NOT_SUPPORTED) || (Status == STATUS_NOT_IMPLEMENTED) ||
	    (Status == STATUS_INVALID_DEVICE_REQUEST) ||
	    (Status == STATUS_INVALID_PARAMETER_1));
}

FORCEINLINE BOOLEAN ClasspSrbTimeOutStatus(IN PSTORAGE_REQUEST_BLOCK Srb)
{
    UCHAR srbStatus = SrbGetSrbStatus(Srb);
    return ((srbStatus == SRB_STATUS_BUS_RESET) || (srbStatus == SRB_STATUS_TIMEOUT) ||
	    (srbStatus == SRB_STATUS_COMMAND_TIMEOUT) ||
	    (srbStatus == SRB_STATUS_ABORTED));
}

NTSTATUS ClassDeviceHwFirmwareGetInfoProcess(IN PDEVICE_OBJECT DeviceObject,
					     IN OUT PIRP Irp);

NTSTATUS ClassDeviceHwFirmwareDownloadProcess(IN PDEVICE_OBJECT DeviceObject,
					      IN OUT PIRP Irp,
					      IN OUT PSTORAGE_REQUEST_BLOCK Srb);

NTSTATUS ClassDeviceHwFirmwareActivateProcess(IN PDEVICE_OBJECT DeviceObject,
					      IN OUT PIRP Irp,
					      IN OUT PSTORAGE_REQUEST_BLOCK Srb);
