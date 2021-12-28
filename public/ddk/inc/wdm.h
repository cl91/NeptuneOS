#pragma once

#include <nt.h>
#include <string.h>
#include <assert.h>

/* We are running in user space. */
FORCEINLINE DECLSPEC_DEPRECATED VOID PAGED_CODE() {}

/*
 * Returned by IoCallDriver to indicate that the IRP has been
 * forwarded to the lower-level drivers and has been deallocated
 * in the current driver.
 */
#define STATUS_IRP_FORWARDED		STATUS_PENDING

/*
 * Returned by IO completion routines to indicate that the system
 * should continue to execute the higher-level completion routines.
 *
 * To stop the IO completion process at this level, return StopCompletion.
 */
#define STATUS_CONTINUE_COMPLETION	STATUS_SUCCESS

typedef enum _IO_COMPLETION_ROUTINE_RESULT {
    ContinueCompletion = STATUS_CONTINUE_COMPLETION,
    StopCompletion = STATUS_MORE_PROCESSING_REQUIRED
} IO_COMPLETION_ROUTINE_RESULT, *PIO_COMPLETION_ROUTINE_RESULT;

/* VPB.Flags */
#define VPB_MOUNTED                       0x0001
#define VPB_LOCKED                        0x0002
#define VPB_PERSISTENT                    0x0004
#define VPB_REMOVE_PENDING                0x0008
#define VPB_RAW_MOUNT                     0x0010
#define VPB_DIRECT_WRITES_ALLOWED         0x0020

/* IO_STACK_LOCATION.Flags */
#define SL_FORCE_ACCESS_CHECK             0x01
#define SL_OPEN_PAGING_FILE               0x02
#define SL_OPEN_TARGET_DIRECTORY          0x04
#define SL_STOP_ON_SYMLINK                0x08
#define SL_CASE_SENSITIVE                 0x80

#define SL_KEY_SPECIFIED                  0x01
#define SL_OVERRIDE_VERIFY_VOLUME         0x02
#define SL_WRITE_THROUGH                  0x04
#define SL_FT_SEQUENTIAL_WRITE            0x08
#define SL_FORCE_DIRECT_WRITE             0x10
#define SL_REALTIME_STREAM                0x20

#define SL_READ_ACCESS_GRANTED            0x01
#define SL_WRITE_ACCESS_GRANTED           0x04

#define SL_FAIL_IMMEDIATELY               0x01
#define SL_EXCLUSIVE_LOCK                 0x02

#define SL_RESTART_SCAN                   0x01
#define SL_RETURN_SINGLE_ENTRY            0x02
#define SL_INDEX_SPECIFIED                0x04

#define SL_WATCH_TREE                     0x01

#define SL_ALLOW_RAW_MOUNT                0x01

/* IO_STACK_LOCATION.Control */
#define SL_PENDING_RETURNED               0x01
#define SL_ERROR_RETURNED                 0x02
#define SL_INVOKE_ON_CANCEL               0x20
#define SL_INVOKE_ON_SUCCESS              0x40
#define SL_INVOKE_ON_ERROR                0x80

/* IRP.Flags */
#define IRP_NOCACHE                     0x00000001
#define IRP_PAGING_IO                   0x00000002
#define IRP_MOUNT_COMPLETION            0x00000002
#define IRP_SYNCHRONOUS_API             0x00000004
#define IRP_ASSOCIATED_IRP              0x00000008
#define IRP_BUFFERED_IO                 0x00000010
#define IRP_DEALLOCATE_BUFFER           0x00000020
#define IRP_INPUT_OPERATION             0x00000040
#define IRP_SYNCHRONOUS_PAGING_IO       0x00000040
#define IRP_CREATE_OPERATION            0x00000080
#define IRP_READ_OPERATION              0x00000100
#define IRP_WRITE_OPERATION             0x00000200
#define IRP_CLOSE_OPERATION             0x00000400
#define IRP_DEFER_IO_COMPLETION         0x00000800
#define IRP_OB_QUERY_NAME               0x00001000
#define IRP_HOLD_DEVICE_QUEUE           0x00002000
/* The following 2 are missing in latest WDK */
#define IRP_RETRY_IO_COMPLETION         0x00004000
#define IRP_CLASS_CACHE_OPERATION       0x00008000

/* IRP.AllocationFlags */
#define IRP_QUOTA_CHARGED                 0x01
#define IRP_ALLOCATED_MUST_SUCCEED        0x02
#define IRP_ALLOCATED_FIXED_SIZE          0x04
#define IRP_LOOKASIDE_ALLOCATION          0x08

/* DRIVER_OBJECT.Flags */
#define DRVO_UNLOAD_INVOKED               0x00000001
#define DRVO_LEGACY_DRIVER                0x00000002
#define DRVO_BUILTIN_DRIVER               0x00000004
#define DRVO_REINIT_REGISTERED            0x00000008
#define DRVO_INITIALIZED                  0x00000010
#define DRVO_BOOTREINIT_REGISTERED        0x00000020
#define DRVO_LEGACY_RESOURCES             0x00000040

/* DEVICE_OBJECT.Flags */
#define DO_DEVICE_HAS_NAME                0x00000040
#define DO_SYSTEM_BOOT_PARTITION          0x00000100
#define DO_LONG_TERM_REQUESTS             0x00000200
#define DO_NEVER_LAST_DEVICE              0x00000400
#define DO_LOW_PRIORITY_FILESYSTEM        0x00010000
#define DO_SUPPORTS_TRANSACTIONS          0x00040000
#define DO_FORCE_NEITHER_IO               0x00080000
#define DO_VOLUME_DEVICE_OBJECT           0x00100000
#define DO_SYSTEM_SYSTEM_PARTITION        0x00200000
#define DO_SYSTEM_CRITICAL_PARTITION      0x00400000
#define DO_DISALLOW_EXECUTE               0x00800000

/* DEVICE_OBJECT.Flags */
#define DO_UNLOAD_PENDING                 0x00000001
#define DO_VERIFY_VOLUME                  0x00000002
#define DO_BUFFERED_IO                    0x00000004
#define DO_EXCLUSIVE                      0x00000008
#define DO_DIRECT_IO                      0x00000010
#define DO_MAP_IO_BUFFER                  0x00000020
#define DO_DEVICE_INITIALIZING            0x00000080
#define DO_SHUTDOWN_REGISTERED            0x00000800
#define DO_BUS_ENUMERATED_DEVICE          0x00001000
#define DO_POWER_PAGABLE                  0x00002000
#define DO_POWER_INRUSH                   0x00004000

/* DEVICE_OBJECT.AlignmentRequirement */
#define FILE_BYTE_ALIGNMENT             0x00000000
#define FILE_WORD_ALIGNMENT             0x00000001
#define FILE_LONG_ALIGNMENT             0x00000003
#define FILE_QUAD_ALIGNMENT             0x00000007
#define FILE_OCTA_ALIGNMENT             0x0000000f
#define FILE_32_BYTE_ALIGNMENT          0x0000001f
#define FILE_64_BYTE_ALIGNMENT          0x0000003f
#define FILE_128_BYTE_ALIGNMENT         0x0000007f
#define FILE_256_BYTE_ALIGNMENT         0x000000ff
#define FILE_512_BYTE_ALIGNMENT         0x000001ff

/*
 * Device Object StartIo Flags
 */
#define DOE_SIO_NO_KEY                          0x20
#define DOE_SIO_WITH_KEY                        0x40
#define DOE_SIO_CANCELABLE                      0x80
#define DOE_SIO_DEFERRED                        0x100
#define DOE_SIO_NO_CANCEL                       0x200

/*
 * Priority boost for the thread initiating an IO request
 */
#define EVENT_INCREMENT                   1
#define IO_NO_INCREMENT                   0
#define IO_CD_ROM_INCREMENT               1
#define IO_DISK_INCREMENT                 1
#define IO_KEYBOARD_INCREMENT             6
#define IO_MAILSLOT_INCREMENT             2
#define IO_MOUSE_INCREMENT                6
#define IO_NAMED_PIPE_INCREMENT           2
#define IO_NETWORK_INCREMENT              2
#define IO_PARALLEL_INCREMENT             1
#define IO_SERIAL_INCREMENT               2
#define IO_SOUND_INCREMENT                8
#define IO_VIDEO_INCREMENT                1
#define SEMAPHORE_INCREMENT               1

#define IO_TYPE_ADAPTER                 1
#define IO_TYPE_CONTROLLER              2
#define IO_TYPE_DEVICE                  3
#define IO_TYPE_DRIVER                  4
#define IO_TYPE_FILE                    5
#define IO_TYPE_IRP                     6
#define IO_TYPE_MASTER_ADAPTER          7
#define IO_TYPE_OPEN_PACKET             8
#define IO_TYPE_TIMER                   9
#define IO_TYPE_VPB                     10
#define IO_TYPE_ERROR_LOG               11
#define IO_TYPE_ERROR_MESSAGE           12
#define IO_TYPE_DEVICE_OBJECT_EXTENSION 13

#define IO_TYPE_CSQ_IRP_CONTEXT 1
#define IO_TYPE_CSQ 2
#define IO_TYPE_CSQ_EX 3

/*
 * Memory allocation and deallocation.
 *
 * PORTING GUIDE: Since we run drivers in their container process
 * there is no distinction between paged pool and non-paged pool.
 * To port Windows/ReactOS driver simply remove the first argument
 * in ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag).
 */
FORCEINLINE PVOID ExAllocatePoolWithTag(IN SIZE_T Size,
					IN ULONG Tag)
{
    return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

FORCEINLINE VOID ExFreePoolWithTag(IN PVOID Pointer,
				   IN ULONG Tag)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Pointer);
}

FORCEINLINE PVOID ExAllocatePool(IN SIZE_T Size)
{
    return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

FORCEINLINE VOID ExFreePool(IN PVOID Pointer)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Pointer);
}

struct _DEVICE_OBJECT;
struct _DRIVER_OBJECT;
struct _IRP;

#define MAXIMUM_VOLUME_LABEL_LENGTH       (32 * sizeof(WCHAR))

typedef struct _VPB {
    SHORT Type;
    SHORT Size;
    USHORT Flags;
    USHORT VolumeLabelLength;
    struct _DEVICE_OBJECT *DeviceObject;
    struct _DEVICE_OBJECT *RealDevice;
    ULONG SerialNumber;
    ULONG ReferenceCount;
    WCHAR VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
} VPB, *PVPB;

typedef struct _FILE_OBJECT {
    SHORT Type;
    SHORT Size;
    struct _DEVICE_OBJECT *DeviceObject;
    BOOLEAN LockOperation;
    BOOLEAN DeletePending;
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    UNICODE_STRING FileName;
} FILE_OBJECT, *PFILE_OBJECT;

/*
 * DPC routine
 */
struct _KDPC;
typedef VOID (NTAPI KDEFERRED_ROUTINE)(IN struct _KDPC *Dpc,
				       IN OPTIONAL PVOID DeferredContext,
				       IN OPTIONAL PVOID SystemArgument1,
				       IN OPTIONAL PVOID SystemArgument2);
typedef KDEFERRED_ROUTINE *PKDEFERRED_ROUTINE;

/*
 * DPC Object. Note: despite being called 'KDPC' this is a client
 * (ie. driver process) side structure. The name KDPC is kept to
 * to ease porting Windows/ReactOS drivers.
 */
typedef struct _KDPC {
    LIST_ENTRY DpcListEntry;
    PKDEFERRED_ROUTINE DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
} KDPC, *PKDPC;

/*
 * Device queue. Used for queuing an IRP for serialized IO processing
 */
typedef struct _KDEVICE_QUEUE {
    LIST_ENTRY DeviceListHead;
    BOOLEAN Busy;
} KDEVICE_QUEUE, *PKDEVICE_QUEUE;

/*
 * Entry for a device queue.
 */
typedef struct _KDEVICE_QUEUE_ENTRY {
    LIST_ENTRY DeviceListEntry;
    ULONG SortKey;
    BOOLEAN Inserted;
} KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY;

/*
 * Device object.
 */
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
    SHORT Type;
    ULONG Size;
    struct _DRIVER_OBJECT *DriverObject;
    struct _IRP *CurrentIrp;
    UNICODE_STRING DeviceName;
    ULONG Flags;
    ULONG Characteristics;
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;
    ULONG AlignmentRequirement;
    KDEVICE_QUEUE DeviceQueue;
    KDPC Dpc;
    ULONG ActiveThreadCount;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    USHORT SectorSize;
    ULONG PowerFlags;
    ULONG ExtensionFlags;
    struct _DEVICE_NODE *DeviceNode;
    LONG StartIoCount;
    LONG StartIoKey;
    ULONG StartIoFlags;
    PVPB Vpb;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _MDL {
    struct _MDL *Next;
    SHORT MdlFlags;
    PVOID MappedSystemVa;
    ULONG ByteCount;
} MDL, *PMDL;

typedef VOID (NTAPI DRIVER_CANCEL)(IN OUT struct _DEVICE_OBJECT *DeviceObject,
				   IN OUT struct _IRP *Irp);
typedef DRIVER_CANCEL *PDRIVER_CANCEL;

/*
 * Client (ie. driver) side data structure for the IO request packet.
 */
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _IRP {
    SHORT Type;
    USHORT Size;
    PMDL MdlAddress;
    ULONG Flags;

    /* We need to figure out master/associated IRPs and buffered IO */
    union {
	struct _IRP *MasterIrp;
	volatile LONG IrpCount;
	PVOID SystemBuffer;
    } AssociatedIrp;

    /* IO status block returned by the driver */
    IO_STATUS_BLOCK IoStatus;

    /* IO status block supplied by the user that will be populated
     * once the IRP has been completed. This makes the IRP synchronous. */
    PIO_STATUS_BLOCK UserIosb;

    /* TODO. */
    BOOLEAN PendingReturned;

    /* Indicates whether this IRP has been canceled */
    BOOLEAN Cancel;

    /* Cancel routine to call when canceling this IRP */
    PDRIVER_CANCEL CancelRoutine;

    /* Indicates that this IRP has been completed */
    BOOLEAN Completed;

    /* The priority boost that is to be added to the thread which
     * originally initiated this IO request when the IRP is completed */
    CHAR PriorityBoost;

    /* User buffer for NEITHER_IO */
    PVOID UserBuffer;

    /* Porting guide: in the original Windows/ReactOS definition
     * this is a union of the following struct with other things.
     * Since we do not need the other "things" this can simply be
     * a struct. To port Windows/ReactOS drivers to NeptuneOS
     * simply change Tail.Overlay to Tail */
    struct {
	union {
	    /* Used by the driver to queue the IRP to the device
	     * queue. This is optional. The driver can also use
	     * the StartIo routine to serialize IO processing. */
	    KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
	    /* If the driver does not use device queue, these are
	     * available for driver use */
	    PVOID DriverContext[4];
	};
	/* Available for driver use. Typically used to queue IRP to
	 * a driver-defined queue. */
	LIST_ENTRY ListEntry;
	/* The following member is used by the network packet filter
	 * to queue IRP to an I/O completion queue. */
	ULONG PacketType;
	PFILE_OBJECT OriginalFileObject;
    } Tail;
} IRP, *PIRP;

/*
 * Executive objects. These are simply handles to the server-side objects.
 */
typedef struct _EPROCESS {
    HANDLE Handle;
} EPROCESS, *PEPROCESS;

typedef struct _ERESOURCE {
    HANDLE Handle;
} ERESOURCE, *PERESOURCE;

/*
 * Driver entry point
 */
typedef NTSTATUS (NTAPI DRIVER_INITIALIZE)(IN struct _DRIVER_OBJECT *DriverObject,
					   IN PUNICODE_STRING RegistryPath);
typedef DRIVER_INITIALIZE *PDRIVER_INITIALIZE;

/*
 * AddDevice routine, called by the PNP manager when enumerating devices
 */
typedef NTSTATUS (NTAPI DRIVER_ADD_DEVICE)(IN struct _DRIVER_OBJECT *DriverObject,
					   IN PDEVICE_OBJECT PhysicalDeviceObject);
typedef DRIVER_ADD_DEVICE *PDRIVER_ADD_DEVICE;

/*
 * Driver's StartIO routine
 */
typedef VOID (NTAPI DRIVER_STARTIO)(IN OUT PDEVICE_OBJECT DeviceObject,
				    IN OUT PIRP Irp);
typedef DRIVER_STARTIO *PDRIVER_STARTIO;

/*
 * DriverUnload routine
 */
typedef VOID (NTAPI DRIVER_UNLOAD)(IN struct _DRIVER_OBJECT *DriverObject);
typedef DRIVER_UNLOAD *PDRIVER_UNLOAD;

/*
 * Dispatch routines for the driver object
 */
typedef NTSTATUS (NTAPI DRIVER_DISPATCH)(IN PDEVICE_OBJECT DeviceObject,
					 IN OUT PIRP Irp);
typedef DRIVER_DISPATCH *PDRIVER_DISPATCH;
typedef DRIVER_DISPATCH DRIVER_DISPATCH_RAISED;

typedef NTSTATUS (NTAPI DRIVER_DISPATCH_PAGED)(IN PDEVICE_OBJECT DeviceObject,
					       IN OUT PIRP Irp);
typedef DRIVER_DISPATCH_PAGED *PDRIVER_DISPATCH_PAGED;

typedef BOOLEAN (NTAPI FAST_IO_CHECK_IF_POSSIBLE)(IN PFILE_OBJECT FileObject,
						  IN PLARGE_INTEGER FileOffset,
						  IN ULONG Length,
						  IN BOOLEAN Wait,
						  IN ULONG LockKey,
						  IN BOOLEAN CheckForReadOperation,
						  _Out_ PIO_STATUS_BLOCK IoStatus,
						  IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_CHECK_IF_POSSIBLE *PFAST_IO_CHECK_IF_POSSIBLE;

typedef BOOLEAN (NTAPI FAST_IO_READ)(IN PFILE_OBJECT FileObject,
				     IN PLARGE_INTEGER FileOffset,
				     IN ULONG Length,
				     IN BOOLEAN Wait,
				     IN ULONG LockKey,
				     OUT PVOID Buffer,
				     OUT PIO_STATUS_BLOCK IoStatus,
				     IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_READ *PFAST_IO_READ;

typedef BOOLEAN (NTAPI FAST_IO_WRITE)(IN PFILE_OBJECT FileObject,
				      IN PLARGE_INTEGER FileOffset,
				      IN ULONG Length,
				      IN BOOLEAN Wait,
				      IN ULONG LockKey,
				      IN PVOID Buffer,
				      OUT PIO_STATUS_BLOCK IoStatus,
				      IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_WRITE *PFAST_IO_WRITE;

typedef BOOLEAN (NTAPI FAST_IO_QUERY_BASIC_INFO)(IN PFILE_OBJECT FileObject,
						 IN BOOLEAN Wait,
						 OUT PFILE_BASIC_INFORMATION Buffer,
						 OUT PIO_STATUS_BLOCK IoStatus,
						 IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_QUERY_BASIC_INFO *PFAST_IO_QUERY_BASIC_INFO;

typedef BOOLEAN (NTAPI FAST_IO_QUERY_STANDARD_INFO)(IN PFILE_OBJECT FileObject,
						    IN BOOLEAN Wait,
						    OUT PFILE_STANDARD_INFORMATION Buffer,
						    OUT PIO_STATUS_BLOCK IoStatus,
						    IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_QUERY_STANDARD_INFO *PFAST_IO_QUERY_STANDARD_INFO;

typedef BOOLEAN (NTAPI FAST_IO_LOCK)(IN PFILE_OBJECT FileObject,
				     IN PLARGE_INTEGER FileOffset,
				     IN PLARGE_INTEGER Length,
				     IN PEPROCESS ProcessId,
				     IN ULONG Key,
				     IN BOOLEAN FailImmediately,
				     IN BOOLEAN ExclusiveLock,
				     OUT PIO_STATUS_BLOCK IoStatus,
				     IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_LOCK *PFAST_IO_LOCK;

typedef BOOLEAN (NTAPI FAST_IO_UNLOCK_SINGLE)(IN PFILE_OBJECT FileObject,
					      IN PLARGE_INTEGER FileOffset,
					      IN PLARGE_INTEGER Length,
					      IN PEPROCESS ProcessId,
					      IN ULONG Key,
					      OUT PIO_STATUS_BLOCK IoStatus,
					      IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_UNLOCK_SINGLE *PFAST_IO_UNLOCK_SINGLE;

typedef BOOLEAN (NTAPI FAST_IO_UNLOCK_ALL)(IN PFILE_OBJECT FileObject,
					   IN struct _EPROCESS *ProcessId,
					   OUT PIO_STATUS_BLOCK IoStatus,
					   IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_UNLOCK_ALL *PFAST_IO_UNLOCK_ALL;

typedef BOOLEAN (NTAPI FAST_IO_UNLOCK_ALL_BY_KEY)(IN PFILE_OBJECT FileObject,
						  IN PVOID ProcessId,
						  IN ULONG Key,
						  OUT PIO_STATUS_BLOCK IoStatus,
						  IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_UNLOCK_ALL_BY_KEY *PFAST_IO_UNLOCK_ALL_BY_KEY;

typedef BOOLEAN (NTAPI FAST_IO_DEVICE_CONTROL)(IN PFILE_OBJECT FileObject,
					       IN BOOLEAN Wait,
					       IN OPTIONAL PVOID InputBuffer,
					       IN ULONG InputBufferLength,
					       OUT OPTIONAL PVOID OutputBuffer,
					       IN ULONG OutputBufferLength,
					       IN ULONG IoControlCode,
					       OUT PIO_STATUS_BLOCK IoStatus,
					       IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_DEVICE_CONTROL *PFAST_IO_DEVICE_CONTROL;

typedef VOID (NTAPI FAST_IO_ACQUIRE_FILE)(IN PFILE_OBJECT FileObject);
typedef FAST_IO_ACQUIRE_FILE *PFAST_IO_ACQUIRE_FILE;

typedef VOID (NTAPI FAST_IO_RELEASE_FILE)(IN PFILE_OBJECT FileObject);
typedef FAST_IO_RELEASE_FILE *PFAST_IO_RELEASE_FILE;

typedef VOID (NTAPI FAST_IO_DETACH_DEVICE)(IN PDEVICE_OBJECT SourceDevice,
					   IN PDEVICE_OBJECT TargetDevice);
typedef FAST_IO_DETACH_DEVICE *PFAST_IO_DETACH_DEVICE;

typedef BOOLEAN (NTAPI FAST_IO_QUERY_NETWORK_OPEN_INFO)(IN PFILE_OBJECT FileObject,
							IN BOOLEAN Wait,
							OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
							OUT PIO_STATUS_BLOCK IoStatus,
							IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_QUERY_NETWORK_OPEN_INFO *PFAST_IO_QUERY_NETWORK_OPEN_INFO;

typedef NTSTATUS (NTAPI FAST_IO_ACQUIRE_FOR_MOD_WRITE)(IN PFILE_OBJECT FileObject,
						       IN PLARGE_INTEGER EndingOffset,
						       OUT PERESOURCE *ResourceToRelease,
						       IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_ACQUIRE_FOR_MOD_WRITE *PFAST_IO_ACQUIRE_FOR_MOD_WRITE;

typedef BOOLEAN (NTAPI FAST_IO_MDL_READ)(IN PFILE_OBJECT FileObject,
					 IN PLARGE_INTEGER FileOffset,
					 IN ULONG Length,
					 IN ULONG LockKey,
					 OUT PMDL *MdlChain,
					 OUT PIO_STATUS_BLOCK IoStatus,
					 IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_MDL_READ *PFAST_IO_MDL_READ;

typedef BOOLEAN (NTAPI FAST_IO_MDL_READ_COMPLETE)(IN PFILE_OBJECT FileObject,
						  IN PMDL MdlChain,
						  IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_MDL_READ_COMPLETE *PFAST_IO_MDL_READ_COMPLETE;

typedef BOOLEAN (NTAPI FAST_IO_PREPARE_MDL_WRITE)(IN PFILE_OBJECT FileObject,
						  IN PLARGE_INTEGER FileOffset,
						  IN ULONG Length,
						  IN ULONG LockKey,
						  OUT PMDL *MdlChain,
						  OUT PIO_STATUS_BLOCK IoStatus,
						  IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_PREPARE_MDL_WRITE *PFAST_IO_PREPARE_MDL_WRITE;

typedef BOOLEAN (NTAPI FAST_IO_MDL_WRITE_COMPLETE)(IN PFILE_OBJECT FileObject,
						   IN PLARGE_INTEGER FileOffset,
						   IN PMDL MdlChain,
						   IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_MDL_WRITE_COMPLETE *PFAST_IO_MDL_WRITE_COMPLETE;

typedef BOOLEAN (NTAPI FAST_IO_READ_COMPRESSED)(IN PFILE_OBJECT FileObject,
						IN PLARGE_INTEGER FileOffset,
						IN ULONG Length,
						IN ULONG LockKey,
						OUT PVOID Buffer,
						OUT PMDL *MdlChain,
						OUT PIO_STATUS_BLOCK IoStatus,
						OUT PCOMPRESSED_DATA_INFO CompressedDataInfo,
						IN ULONG CompressedDataInfoLength,
						IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_READ_COMPRESSED *PFAST_IO_READ_COMPRESSED;

typedef BOOLEAN (NTAPI FAST_IO_WRITE_COMPRESSED)(IN PFILE_OBJECT FileObject,
						 IN PLARGE_INTEGER FileOffset,
						 IN ULONG Length,
						 IN ULONG LockKey,
						 IN PVOID Buffer,
						 OUT PMDL *MdlChain,
						 OUT PIO_STATUS_BLOCK IoStatus,
						 IN PCOMPRESSED_DATA_INFO CompressedDataInfo,
						 IN ULONG CompressedDataInfoLength,
						 IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_WRITE_COMPRESSED *PFAST_IO_WRITE_COMPRESSED;

typedef BOOLEAN (NTAPI FAST_IO_MDL_READ_COMPLETE_COMPRESSED)(IN PFILE_OBJECT FileObject,
							     IN PMDL MdlChain,
							     IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_MDL_READ_COMPLETE_COMPRESSED *PFAST_IO_MDL_READ_COMPLETE_COMPRESSED;

typedef BOOLEAN (NTAPI FAST_IO_MDL_WRITE_COMPLETE_COMPRESSED)(IN PFILE_OBJECT FileObject,
							      IN PLARGE_INTEGER FileOffset,
							      IN PMDL MdlChain,
							      IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_MDL_WRITE_COMPLETE_COMPRESSED *PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED;

typedef BOOLEAN (NTAPI FAST_IO_QUERY_OPEN)(IN OUT PIRP Irp,
					   OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
					   IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_QUERY_OPEN *PFAST_IO_QUERY_OPEN;

typedef NTSTATUS (NTAPI FAST_IO_RELEASE_FOR_MOD_WRITE)(IN PFILE_OBJECT FileObject,
						       IN PERESOURCE ResourceToRelease,
						       IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_RELEASE_FOR_MOD_WRITE *PFAST_IO_RELEASE_FOR_MOD_WRITE;

typedef NTSTATUS (NTAPI FAST_IO_ACQUIRE_FOR_CCFLUSH)(IN PFILE_OBJECT FileObject,
						     IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_ACQUIRE_FOR_CCFLUSH *PFAST_IO_ACQUIRE_FOR_CCFLUSH;

typedef NTSTATUS (NTAPI FAST_IO_RELEASE_FOR_CCFLUSH)(IN PFILE_OBJECT FileObject,
						     IN PDEVICE_OBJECT DeviceObject);
typedef FAST_IO_RELEASE_FOR_CCFLUSH *PFAST_IO_RELEASE_FOR_CCFLUSH;

typedef struct _FAST_IO_DISPATCH {
    ULONG SizeOfFastIoDispatch;
    PFAST_IO_CHECK_IF_POSSIBLE FastIoCheckIfPossible;
    PFAST_IO_READ FastIoRead;
    PFAST_IO_WRITE FastIoWrite;
    PFAST_IO_QUERY_BASIC_INFO FastIoQueryBasicInfo;
    PFAST_IO_QUERY_STANDARD_INFO FastIoQueryStandardInfo;
    PFAST_IO_LOCK FastIoLock;
    PFAST_IO_UNLOCK_SINGLE FastIoUnlockSingle;
    PFAST_IO_UNLOCK_ALL FastIoUnlockAll;
    PFAST_IO_UNLOCK_ALL_BY_KEY FastIoUnlockAllByKey;
    PFAST_IO_DEVICE_CONTROL FastIoDeviceControl;
    PFAST_IO_ACQUIRE_FILE AcquireFileForNtCreateSection;
    PFAST_IO_RELEASE_FILE ReleaseFileForNtCreateSection;
    PFAST_IO_DETACH_DEVICE FastIoDetachDevice;
    PFAST_IO_QUERY_NETWORK_OPEN_INFO FastIoQueryNetworkOpenInfo;
    PFAST_IO_ACQUIRE_FOR_MOD_WRITE AcquireForModWrite;
    PFAST_IO_MDL_READ MdlRead;
    PFAST_IO_MDL_READ_COMPLETE MdlReadComplete;
    PFAST_IO_PREPARE_MDL_WRITE PrepareMdlWrite;
    PFAST_IO_MDL_WRITE_COMPLETE MdlWriteComplete;
    PFAST_IO_READ_COMPRESSED FastIoReadCompressed;
    PFAST_IO_WRITE_COMPRESSED FastIoWriteCompressed;
    PFAST_IO_MDL_READ_COMPLETE_COMPRESSED MdlReadCompleteCompressed;
    PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED MdlWriteCompleteCompressed;
    PFAST_IO_QUERY_OPEN FastIoQueryOpen;
    PFAST_IO_RELEASE_FOR_MOD_WRITE ReleaseForModWrite;
    PFAST_IO_ACQUIRE_FOR_CCFLUSH AcquireForCcFlush;
    PFAST_IO_RELEASE_FOR_CCFLUSH ReleaseForCcFlush;
} FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;

/*
 * IO completion routines
 */
typedef NTSTATUS (NTAPI IO_COMPLETION_ROUTINE)(IN PDEVICE_OBJECT DeviceObject,
					       IN PIRP Irp,
					       IN OPTIONAL PVOID Context);
typedef IO_COMPLETION_ROUTINE *PIO_COMPLETION_ROUTINE;

/*
 * Driver Extension
 */
typedef struct _IO_CLIENT_EXTENSION {
    struct _IO_CLIENT_EXTENSION *NextExtension;
    PVOID ClientIdentificationAddress;
} IO_CLIENT_EXTENSION, *PIO_CLIENT_EXTENSION;

/*
 * Driver object
 */
typedef struct _DRIVER_OBJECT {
    SHORT Type;
    SHORT Size;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    UNICODE_STRING ServiceKeyName;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PIO_CLIENT_EXTENSION ClientDriverExtension;
    LIST_ENTRY ReinitListHead;
    PFAST_IO_DISPATCH FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO DriverStartIo;
    PDRIVER_ADD_DEVICE AddDevice;
    PDRIVER_UNLOAD DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

/*
 * Driver reinitialize routine
 */
typedef VOID (NTAPI *PDRIVER_REINITIALIZE)(IN PDRIVER_OBJECT DriverObject,
					   IN OPTIONAL PVOID Context,
					   IN ULONG Count);

typedef struct _IO_SECURITY_CONTEXT {
    ACCESS_MASK DesiredAccess;
    ULONG FullCreateOptions;
} IO_SECURITY_CONTEXT, *PIO_SECURITY_CONTEXT;

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    union {
	struct {
	    PIO_SECURITY_CONTEXT SecurityContext;
	    ULONG Options;
	    USHORT POINTER_ALIGNMENT FileAttributes;
	    USHORT ShareAccess;
	    ULONG POINTER_ALIGNMENT EaLength;
	} Create;
	struct {
	    struct _IO_SECURITY_CONTEXT *SecurityContext;
	    ULONG Options;
	    USHORT POINTER_ALIGNMENT Reserved;
	    USHORT ShareAccess;
	    struct _NAMED_PIPE_CREATE_PARAMETERS *Parameters;
	} CreatePipe;
	struct {
	    PIO_SECURITY_CONTEXT SecurityContext;
	    ULONG Options;
	    USHORT POINTER_ALIGNMENT Reserved;
	    USHORT ShareAccess;
	    struct _MAILSLOT_CREATE_PARAMETERS *Parameters;
	} CreateMailslot;
	struct {
	    ULONG Length;
	    ULONG POINTER_ALIGNMENT Key;
	    LARGE_INTEGER ByteOffset;
	} Read;
	struct {
	    ULONG Length;
	    ULONG POINTER_ALIGNMENT Key;
	    LARGE_INTEGER ByteOffset;
	} Write;
	struct {
	    ULONG Length;
	    PUNICODE_STRING FileName;
	    FILE_INFORMATION_CLASS FileInformationClass;
	    ULONG POINTER_ALIGNMENT FileIndex;
	} QueryDirectory;
	struct {
	    ULONG Length;
	    ULONG POINTER_ALIGNMENT CompletionFilter;
	} NotifyDirectory;
	struct {
	    ULONG Length;
	    ULONG POINTER_ALIGNMENT CompletionFilter;
	    DIRECTORY_NOTIFY_INFORMATION_CLASS POINTER_ALIGNMENT DirectoryNotifyInformationClass;
	} NotifyDirectoryEx;
	struct {
	    ULONG Length;
	    FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
	} QueryFile;
	struct {
	    ULONG Length;
	    FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
	    PFILE_OBJECT FileObject;
	    union {
		struct {
		    BOOLEAN ReplaceIfExists;
		    BOOLEAN AdvanceOnly;
		};
		ULONG ClusterCount;
		HANDLE DeleteHandle;
	    };
	} SetFile;
	struct {
	    ULONG Length;
	    PVOID EaList;
	    ULONG EaListLength;
	    ULONG POINTER_ALIGNMENT EaIndex;
	} QueryEa;
	struct {
	    ULONG Length;
	} SetEa;
	struct {
	    ULONG Length;
	    FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
	} QueryVolume;
	struct {
	    ULONG Length;
	    FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
	} SetVolume;
	struct {
	    ULONG OutputBufferLength;
	    ULONG POINTER_ALIGNMENT InputBufferLength;
	    ULONG POINTER_ALIGNMENT FsControlCode;
	    PVOID Type3InputBuffer;
	} FileSystemControl;
	struct {
	    PLARGE_INTEGER Length;
	    ULONG POINTER_ALIGNMENT Key;
	    LARGE_INTEGER ByteOffset;
	} LockControl;
	struct {
	    ULONG OutputBufferLength;
	    ULONG POINTER_ALIGNMENT InputBufferLength;
	    ULONG POINTER_ALIGNMENT IoControlCode;
	    PVOID Type3InputBuffer;
	} DeviceIoControl;
	struct {
	    SECURITY_INFORMATION SecurityInformation;
	    ULONG POINTER_ALIGNMENT Length;
	} QuerySecurity;
	struct {
	    SECURITY_INFORMATION SecurityInformation;
	    PSECURITY_DESCRIPTOR SecurityDescriptor;
	} SetSecurity;
	struct {
	    PVPB Vpb;
	    PDEVICE_OBJECT DeviceObject;
	} MountVolume;
	struct {
	    PVPB Vpb;
	    PDEVICE_OBJECT DeviceObject;
	} VerifyVolume;
	struct {
	    struct _SCSI_REQUEST_BLOCK *Srb;
	} Scsi;
	struct {
	    ULONG Length;
	    PSID StartSid;
	    struct _FILE_GET_QUOTA_INFORMATION *SidList;
	    ULONG SidListLength;
	} QueryQuota;
	struct {
	    ULONG Length;
	} SetQuota;
	struct {
	    DEVICE_RELATION_TYPE Type;
	} QueryDeviceRelations;
	struct {
	    ULONG WhichSpace;
	    PVOID Buffer;
	    ULONG Offset;
	    ULONG POINTER_ALIGNMENT Length;
	} ReadWriteConfig;
	struct {
	    BOOLEAN Lock;
	} SetLock;
	struct {
	    BUS_QUERY_ID_TYPE IdType;
	} QueryId;
	struct {
	    DEVICE_TEXT_TYPE DeviceTextType;
	    LCID POINTER_ALIGNMENT LocaleId;
	} QueryDeviceText;
	struct {
	    BOOLEAN InPath;
	    BOOLEAN Reserved[3];
	    DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT Type;
	} UsageNotification;
	struct {
	    SYSTEM_POWER_STATE PowerState;
	} WaitWake;
	struct {
	    PPOWER_SEQUENCE PowerSequence;
	} PowerSequence;
	struct {
	    union {
		ULONG SystemContext;
		SYSTEM_POWER_STATE_CONTEXT SystemPowerStateContext;
	    };
	    POWER_STATE_TYPE POINTER_ALIGNMENT Type;
	    POWER_STATE POINTER_ALIGNMENT State;
	    POWER_ACTION POINTER_ALIGNMENT ShutdownType;
	} Power;
	struct {
	    PCM_RESOURCE_LIST AllocatedResources;
	    PCM_RESOURCE_LIST AllocatedResourcesTranslated;
	} StartDevice;
	struct {
	    ULONG_PTR ProviderId;
	    PVOID DataPath;
	    ULONG BufferSize;
	    PVOID Buffer;
	} WMI;
	struct {
	    PVOID Argument1;
	    PVOID Argument2;
	    PVOID Argument3;
	    PVOID Argument4;
	} Others;
    } Parameters;
    PDEVICE_OBJECT DeviceObject;
    PFILE_OBJECT FileObject;
    PIO_COMPLETION_ROUTINE CompletionRoutine;
    PVOID Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

#define IO_SIZE_OF_IRP	(sizeof(IRP) + sizeof(IO_STACK_LOCATION))

/*
 * Returns the full size of an IRP object including the header and the
 * IO stack location.
 */
DEPRECATED("IRPs always have exactly one stack location. Use IO_SIZE_OF_IRP instead.")
FORCEINLINE USHORT IoSizeOfIrp(IN CCHAR StackSize)
{
    return IO_SIZE_OF_IRP;
}

/*
 * Note: The Irp object must be zeroed before calling this function.
 *
 * Porting guide: IRPs always have exactly one stack location, so remove
 * the PacketSize and StackSize argument if you are porting from ReactOS.
 */
FORCEINLINE VOID IoInitializeIrp(IN PIRP Irp)
{
    /* Set the Header and other data */
    Irp->Type = IO_TYPE_IRP;
    Irp->Size = IO_SIZE_OF_IRP;
}

/*
 * Porting guide: IRPs always have exactly one stack location, and we don't
 * have "pool memory" since we are running in userspace, so remove the
 * StackSize and ChargeQuota argument if you are porting from ReactOS.
 */
FORCEINLINE PIRP IoAllocateIrp()
{
    PIRP Irp = (PIRP) ExAllocatePool(IO_SIZE_OF_IRP);
    if (Irp == NULL) {
	return NULL;
    }
    IoInitializeIrp(Irp);
    return Irp;
}

FORCEINLINE VOID IoFreeIrp(IN PIRP Irp)
{
    ExFreePool(Irp);
}

/*
 * Returns the current (and only) IO stack location pointer. The (only)
 * IO stack location follows immediately after the IRP header.
 */
FORCEINLINE PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(IN PIRP Irp)
{
    return (PIO_STACK_LOCATION)(Irp + 1);
}

/*
 * IO stack location manipulation routines. These are all deprecated and
 * are effectively no-op since our IRPs always have exactly one stack location.
 */
DEPRECATED("IRPs always have exactly one stack location. Remove this.")
FORCEINLINE VOID IoSkipCurrentIrpStackLocation(IN OUT PIRP Irp)
{
}

DEPRECATED("IRPs always have exactly one stack location. Remove this.")
FORCEINLINE VOID IoCopyCurrentIrpStackLocationToNext(IN OUT PIRP Irp)
{
}

DEPRECATED("IRPs always have exactly one stack location. Remove this")
FORCEINLINE VOID IoSetNextIrpStackLocation(IN OUT PIRP Irp)
{
}

DEPRECATED_BY("IRPs always have exactly one stack location.",
	      IoGetCurrentIrpStackLocation)
FORCEINLINE PIO_STACK_LOCATION IoGetNextIrpStackLocation(IN PIRP Irp)
{
    return IoGetCurrentIrpStackLocation(Irp);
}

/*
 * Device object creation routine
 */
NTAPI NTSYSAPI NTSTATUS IoCreateDevice(IN PDRIVER_OBJECT DriverObject,
				       IN ULONG DeviceExtensionSize,
				       IN PUNICODE_STRING DeviceName OPTIONAL,
				       IN DEVICE_TYPE DeviceType,
				       IN ULONG DeviceCharacteristics,
				       IN BOOLEAN Exclusive,
				       OUT PDEVICE_OBJECT *DeviceObject);

/*
 * Device object deletion routine
 */
NTAPI NTSYSAPI VOID IoDeleteDevice(IN PDEVICE_OBJECT DeviceObject);

/*
 * Queries the device name from server and returns the cached local FILE
 * and DEVICE object.
 */
NTAPI NTSYSAPI NTSTATUS IoGetDeviceObjectPointer(IN PUNICODE_STRING ObjectName,
						 IN ACCESS_MASK DesiredAccess,
						 OUT PFILE_OBJECT *FileObject,
						 OUT PDEVICE_OBJECT *DeviceObject);

/*
 * Attach the SourceDevice on top of the device stack of TargetDevice,
 * returning the previous topmost device object in the device stack.
 */
NTAPI NTSYSAPI PDEVICE_OBJECT IoAttachDeviceToDeviceStack(IN PDEVICE_OBJECT SourceDevice,
							  IN PDEVICE_OBJECT TargetDevice);

DEPRECATED_BY("Unlike Windows/ReactOS we don't have synchronization issues "
	      "since drivers run in their own process.",
	      IoAttachDeviceToDeviceStack)
FORCEINLINE NTSTATUS
IoAttachDeviceToDeviceStackSafe(IN PDEVICE_OBJECT SourceDevice,
				IN PDEVICE_OBJECT TargetDevice,
				IN OUT PDEVICE_OBJECT *AttachedToDeviceObject)
{
    PDEVICE_OBJECT OldTopDevice = IoAttachDeviceToDeviceStack(SourceDevice,
							      TargetDevice);
    if (OldTopDevice == NULL) {
	/* Nothing found */
	return STATUS_NO_SUCH_DEVICE;
    }

    /* Success! */
    *AttachedToDeviceObject = OldTopDevice;
    return STATUS_SUCCESS;
}

/*
 * Registers a device interface class if it has not been previously registered,
 * and creates a new instance of the interface class, which a driver can
 * subsequently enable for use by applications or other system components.
 */
NTAPI NTSYSAPI NTSTATUS IoRegisterDeviceInterface(IN PDEVICE_OBJECT PhysicalDeviceObject,
						  IN CONST GUID *InterfaceClassGuid,
						  IN PUNICODE_STRING ReferenceString OPTIONAL,
						  OUT PUNICODE_STRING SymbolicLinkName);

NTAPI NTSYSAPI NTSTATUS IoSetDeviceInterfaceState(IN PUNICODE_STRING SymbolicLinkName,
						  IN BOOLEAN Enable);

NTAPI NTSYSAPI VOID IoDetachDevice(IN PDEVICE_OBJECT TargetDevice);

DEPRECATED("Drivers run in userspace and are always paged entirely. Remove this.")
NTAPI NTSYSAPI PVOID MmPageEntireDriver(IN PVOID AddressWithinSection);

/*
 * IO DPC routine
 */
typedef VOID (NTAPI IO_DPC_ROUTINE)(IN PKDPC Dpc,
				    IN PDEVICE_OBJECT DeviceObject,
				    IN OUT PIRP Irp,
				    IN OPTIONAL PVOID Context);
typedef IO_DPC_ROUTINE *PIO_DPC_ROUTINE;

/*
 * TIMER object. Note: just like KDPC despite being called 'KTIMER'
 * this is the client-side handle to the server side KTIMER object.
 * There is no name collision because the NTOS server does not
 * include files under public/ddk.
 */
typedef struct _KTIMER {
    HANDLE Handle;
    LIST_ENTRY TimerListEntry;
    PKDPC Dpc;
    BOOLEAN State;		/* TRUE if the timer is set. */
    BOOLEAN Canceled;
} KTIMER, *PKTIMER;

/*
 * Device queue initialization function
 */
FORCEINLINE VOID KeInitializeDeviceQueue(IN PKDEVICE_QUEUE Queue)
{
    assert(Queue != NULL);
    InitializeListHead(&Queue->DeviceListHead);
    Queue->Busy = FALSE;
}

NTAPI NTSYSAPI BOOLEAN KeInsertDeviceQueue(IN PKDEVICE_QUEUE Queue,
					   IN PKDEVICE_QUEUE_ENTRY Entry);

NTAPI NTSYSAPI BOOLEAN KeInsertByKeyDeviceQueue(IN PKDEVICE_QUEUE Queue,
						IN PKDEVICE_QUEUE_ENTRY Entry,
						IN ULONG SortKey);

NTAPI NTSYSAPI PKDEVICE_QUEUE_ENTRY KeRemoveDeviceQueue(IN PKDEVICE_QUEUE Queue);

NTAPI NTSYSAPI PKDEVICE_QUEUE_ENTRY KeRemoveByKeyDeviceQueue(IN PKDEVICE_QUEUE Queue,
							     IN ULONG SortKey);

/*
 * Same as KeRemoveByKeyDeviceQueue, except it doesn't assert if the queue is not busy.
 * Instead, NULL is returned if queue is not busy.
 */
FORCEINLINE PKDEVICE_QUEUE_ENTRY KeRemoveByKeyDeviceQueueIfBusy(IN PKDEVICE_QUEUE Queue,
								IN ULONG SortKey)
{
    assert(Queue != NULL);
    if (!Queue->Busy) {
	return NULL;
    }
    return KeRemoveByKeyDeviceQueue(Queue, SortKey);
}

/*
 * Removes the specified entry from the queue, returning TRUE.
 * If the entry is not inserted, nothing is done and we return FALSE.
 */
FORCEINLINE BOOLEAN KeRemoveEntryDeviceQueue(IN PKDEVICE_QUEUE Queue,
					     IN PKDEVICE_QUEUE_ENTRY Entry)
{
    assert(Queue != NULL);
    assert(Queue->Busy);
    if (Entry->Inserted) {
        Entry->Inserted = FALSE;
        RemoveEntryList(&Entry->DeviceListEntry);
	return TRUE;
    }
    return FALSE;
}

/*
 * Set the IO cancel routine of the given IRP, returning the previous one.
 *
 * NOTE: As opposed to Windows/ReactOS we do NOT need the interlocked (atomic)
 * operation here, since in NeptuneOS driver dispatch routines run in a single thread.
 */
FORCEINLINE PDRIVER_CANCEL IoSetCancelRoutine(IN OUT PIRP Irp,
					      IN OPTIONAL PDRIVER_CANCEL CancelRoutine)
{
    PDRIVER_CANCEL Old = Irp->CancelRoutine;
    Irp->CancelRoutine = CancelRoutine;
    return Old;
}

/*
 * DPC initialization function
 */
FORCEINLINE VOID KeInitializeDpc(IN PKDPC Dpc,
				 IN PKDEFERRED_ROUTINE DeferredRoutine,
				 IN PVOID DeferredContext)
{
    Dpc->DeferredRoutine = DeferredRoutine;
    Dpc->DeferredContext = DeferredContext;
}

/*
 * Initialize the device object's built-in DPC object
 */
FORCEINLINE VOID IoInitializeDpcRequest(IN PDEVICE_OBJECT DeviceObject,
					IN PIO_DPC_ROUTINE DpcRoutine)
{
    KeInitializeDpc(&DeviceObject->Dpc, (PKDEFERRED_ROUTINE)DpcRoutine,
		    DeviceObject);
}

/*
 * Complete the IRP. We simply mark the IRP as completed and the
 * IO manager will inform the NTOS server of IRP completion.
 */
FORCEINLINE VOID IoCompleteRequest(IN PIRP Irp,
				   IN CHAR PriorityBoost)
{
    assert(Irp != NULL);
    /* Never complete an IRP with pending status */
    assert(Irp->IoStatus.Status != STATUS_PENDING);
    /* -1 is an invalid NTSTATUS */
    assert(Irp->IoStatus.Status != -1);
    Irp->Completed = TRUE;
    Irp->PriorityBoost = PriorityBoost;
}

/*
 * Mark the current IRP as pending
 */
DEPRECATED("IRPs no longer need to be marked pending. Remove this.")
FORCEINLINE VOID IoMarkIrpPending(IN OUT PIRP Irp)
{
    IoGetCurrentIrpStackLocation((Irp))->Control |= SL_PENDING_RETURNED;
}

/*
 * Start the IO packet.
 */
NTAPI NTSYSAPI VOID IoStartPacket(IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp,
				  IN OPTIONAL PULONG Key,
				  IN OPTIONAL PDRIVER_CANCEL CancelFunction);

NTAPI NTSYSAPI VOID IoStartNextPacket(IN PDEVICE_OBJECT DeviceObject,
				      IN BOOLEAN Cancelable);

/*
 * Timer routines
 */
NTAPI NTSYSAPI VOID KeInitializeTimer(OUT PKTIMER Timer);

NTAPI NTSYSAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
				  IN LARGE_INTEGER DueTime,
				  IN OPTIONAL PKDPC Dpc);

/* TODO: Inform the server to actually cancel the timer */
FORCEINLINE BOOLEAN KeCancelTimer(IN OUT PKTIMER Timer)
{
    BOOLEAN PreviousState = Timer->State;
    /* Mark the timer as canceled. The driver process will
     * later inform the server about timer cancellation. */
    Timer->Canceled = TRUE;
    Timer->State = FALSE;
    return PreviousState;
}

/*
 * System time and interrupt time routines
 */
NTAPI NTSYSAPI ULONGLONG KeQueryInterruptTime(VOID);

/*
 * Stalls the current processor for the given microseconds. This is the preferred
 * routine to call if you want to stall the processor for a small amount of time
 * without involving the scheduler, for instance, in an interrupt service routine.
 */
NTAPI NTSYSAPI VOID KeStallExecutionProcessor(ULONG MicroSeconds);

/*
 * Per-driver context area routines
 */
NTAPI NTSYSAPI NTSTATUS IoAllocateDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
							IN PVOID ClientIdentAddr,
							IN ULONG DriverExtensionSize,
							OUT PVOID *pDriverExtension);

NTAPI NTSYSAPI PVOID IoGetDriverObjectExtension(IN PDRIVER_OBJECT DriverObject,
						IN PVOID ClientIdentAddr);

/*
 * Driver reinitialization routine registration
 */
NTAPI VOID IoRegisterDriverReinitialization(IN PDRIVER_OBJECT DriverObject,
					    IN PDRIVER_REINITIALIZE ReinitRoutine,
					    IN PVOID Context);

/*
 * Set device StartIo flags
 */
FORCEINLINE VOID IoSetStartIoAttributes(IN PDEVICE_OBJECT DeviceObject,
					IN BOOLEAN DeferredStartIo,
					IN BOOLEAN NonCancelable)
{
    /* Set the flags the caller requested */
    DeviceObject->StartIoFlags |= (DeferredStartIo) ? DOE_SIO_DEFERRED : 0;
    DeviceObject->StartIoFlags |= (NonCancelable) ? DOE_SIO_NO_CANCEL : 0;
}

/*
 * MDL (memory descriptor list) routines
 */
FORCEINLINE PVOID MmGetSystemAddressForMdl(IN PMDL Mdl)
{
    return Mdl->MappedSystemVa;
}

DEPRECATED_BY("Since user buffers are mapped directly into driver process they are always safe to access",
	      MmGetSystemAddressForMld)
FORCEINLINE PVOID MmGetSystemAddressForMdlSafe(IN PMDL Mdl,
					       IN ULONG Priority)
{
    return MmGetSystemAddressForMdl(Mdl);
}

NTAPI NTSYSAPI PIRP IoBuildDeviceIoControlRequest(IN ULONG IoControlCode,
						  IN PDEVICE_OBJECT DeviceObject,
						  IN PVOID InputBuffer,
						  IN ULONG InputBufferLength,
						  IN PVOID OutputBuffer,
						  IN ULONG OutputBufferLength,
						  IN BOOLEAN InternalDeviceIoControl,
						  IN PIO_STATUS_BLOCK IoStatusBlock);

NTAPI NTSYSAPI PIRP IoBuildAsynchronousFsdRequest(IN ULONG MajorFunction,
						  IN PDEVICE_OBJECT DeviceObject,
						  IN PVOID Buffer,
						  IN ULONG Length,
						  IN PLARGE_INTEGER StartingOffset);

NTAPI NTSYSAPI PIRP IoBuildSynchronousFsdRequest(IN ULONG MajorFunction,
						 IN PDEVICE_OBJECT DeviceObject,
						 IN PVOID Buffer,
						 IN ULONG Length,
						 IN PLARGE_INTEGER StartingOffset,
						 IN PIO_STATUS_BLOCK IoStatusBlock);

/*
 * See private/wdm/src/irp.c for documentation.
 */
NTAPI NTSYSAPI NTSTATUS IoCallDriverEx(IN PDEVICE_OBJECT DeviceObject,
				       IN OUT PIRP Irp,
				       IN PLARGE_INTEGER Timeout);

/*
 * Forward the specified IRP to the specified device and return immediately,
 * with STATUS_IRP_FORWARDED, unless the IRP has supplied a UserIoSb,
 * in which case the current coroutine is suspended and waits for the
 * completion of the IRP.
 */
FORCEINLINE NTSTATUS IoCallDriver(IN PDEVICE_OBJECT DeviceObject,
				  IN OUT PIRP Irp)
{
    LARGE_INTEGER Timeout = { .QuadPart = 0 };
    return IoCallDriverEx(DeviceObject, Irp, &Timeout);
}

/*
 * This was needed by the power manager in Windows XP/ReactOS and is
 * now deprecated in Windows Vista and later. We follow Vista+.
 */
DEPRECATED_BY("Power IRP synchronization is now automatic. You no longer need to call the Po-specific versions",
	      IoCallDriver)
FORCEINLINE NTSTATUS PoCallDriver(IN PDEVICE_OBJECT DeviceObject,
				  IN OUT PIRP Irp)
{
    return IoCallDriver(DeviceObject, Irp);
}

DEPRECATED("Power IRP synchronization is now automatic. Remove this.")
FORCEINLINE VOID PoStartNextPowerIrp(IN OUT PIRP Irp)
{
    /* Do nothing */
}

/*
 * IO Work item.
 */
struct _IO_WORKITEM;
typedef VOID (NTAPI IO_WORKITEM_ROUTINE)(IN PDEVICE_OBJECT DeviceObject,
					 IN OPTIONAL PVOID Context);
typedef IO_WORKITEM_ROUTINE *PIO_WORKITEM_ROUTINE;

typedef VOID (NTAPI IO_WORKITEM_ROUTINE_EX)(IN PVOID IoObject,
					    IN OPTIONAL PVOID Context,
					    IN struct _IO_WORKITEM *IoWorkItem);
typedef IO_WORKITEM_ROUTINE_EX *PIO_WORKITEM_ROUTINE_EX;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _IO_WORKITEM {
    SLIST_ENTRY Next;		/* Must be first */
    union {
	PDEVICE_OBJECT DeviceObject;
	PDRIVER_OBJECT DriverObject;
    };
    HANDLE WorkerThreadHandle;
    union {
	PIO_WORKITEM_ROUTINE WorkerRoutine;
	PIO_WORKITEM_ROUTINE_EX WorkerRoutineEx;
    };
    PVOID Context;
    BOOLEAN ExtendedRoutine; /* TRUE if the union above is WorkerRoutineEx */
} IO_WORKITEM, *PIO_WORKITEM;

/*
 * Work queue type
 */
typedef enum _WORK_QUEUE_TYPE {
    CriticalWorkQueue,
    DelayedWorkQueue,
    HyperCriticalWorkQueue,
    MaximumWorkQueue
} WORK_QUEUE_TYPE;

/*
 * Work item allocation
 */
FORCEINLINE PIO_WORKITEM IoAllocateWorkItem(IN PDEVICE_OBJECT DeviceObject)
{
    PIO_WORKITEM IoWorkItem = ExAllocatePool(sizeof(IO_WORKITEM));
    if (IoWorkItem == NULL) {
	return NULL;
    }
    IoWorkItem->DeviceObject = DeviceObject;
    return IoWorkItem;
}

/*
 * Work item deallocation
 */
FORCEINLINE VOID IoFreeWorkItem(IN PIO_WORKITEM IoWorkItem)
{
    ExFreePool(IoWorkItem);
}

/*
 * Interrupt Object. We keep the name KINTERRUPT to remain compatible
 * with Windows/ReactOS. This is an opaque object.
 */
typedef struct _KINTERRUPT *PKINTERRUPT;

/*
 * Interrupt request level
 */
typedef UCHAR KIRQL, *PKIRQL;

/*
 * Interrupt mode
 */
typedef enum _KINTERRUPT_MODE {
    LevelSensitive,
    Latched
} KINTERRUPT_MODE;

/*
 * Interrupt service routine
 */
typedef BOOLEAN (NTAPI KSERVICE_ROUTINE)(IN PKINTERRUPT Interrupt,
					 IN PVOID ServiceContext);
typedef KSERVICE_ROUTINE *PKSERVICE_ROUTINE;

NTAPI NTSYSAPI NTSTATUS IoConnectInterrupt(OUT PKINTERRUPT *InterruptObject,
					   IN PKSERVICE_ROUTINE ServiceRoutine,
					   IN OPTIONAL PVOID ServiceContext,
					   IN ULONG Vector,
					   IN KIRQL Irql,
					   IN KIRQL SynchronizeIrql,
					   IN KINTERRUPT_MODE InterruptMode,
					   IN BOOLEAN ShareVector,
					   IN KAFFINITY ProcessorEnableMask,
					   IN BOOLEAN FloatingSave);

NTAPI NTSYSAPI VOID IoDisconnectInterrupt(IN PKINTERRUPT InterruptObject);

/*
 * Returns the pointer to the highest level device object in a device stack
 */
NTAPI NTSYSAPI PDEVICE_OBJECT IoGetAttachedDevice(IN PDEVICE_OBJECT DeviceObject);

/*
 * This is the same function as IoGetAttachedDevice, since we don't have
 * reference counting for client-side objects.
 */
FORCEINLINE PDEVICE_OBJECT IoGetAttachedDeviceReference(IN PDEVICE_OBJECT DeviceObject)
{
    return IoGetAttachedDevice(DeviceObject);
}
