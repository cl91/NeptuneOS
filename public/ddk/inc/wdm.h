#pragma once

#include <nt.h>
#include <string.h>

#define PAGED_CODE()

#if defined(_WIN64)
#define POINTER_ALIGNMENT DECLSPEC_ALIGN(8)
#else
#define POINTER_ALIGNMENT
#endif

#if defined(_WIN64) || defined(_M_ALPHA)
#define MAX_NATURAL_ALIGNMENT sizeof(ULONGLONG)
#define MEMORY_ALLOCATION_ALIGNMENT 16
#else
#define MAX_NATURAL_ALIGNMENT sizeof(ULONG)
#define MEMORY_ALLOCATION_ALIGNMENT 8
#endif

/* FILE_OBJECT.Flags */
#define FO_FILE_OPEN                 0x00000001
#define FO_SYNCHRONOUS_IO            0x00000002
#define FO_ALERTABLE_IO              0x00000004
#define FO_NO_INTERMEDIATE_BUFFERING 0x00000008
#define FO_WRITE_THROUGH             0x00000010
#define FO_SEQUENTIAL_ONLY           0x00000020
#define FO_CACHE_SUPPORTED           0x00000040
#define FO_NAMED_PIPE                0x00000080
#define FO_STREAM_FILE               0x00000100
#define FO_MAILSLOT                  0x00000200
#define FO_GENERATE_AUDIT_ON_CLOSE   0x00000400
#define FO_QUEUE_IRP_TO_THREAD       0x00000400
#define FO_DIRECT_DEVICE_OPEN        0x00000800
#define FO_FILE_MODIFIED             0x00001000
#define FO_FILE_SIZE_CHANGED         0x00002000
#define FO_CLEANUP_COMPLETE          0x00004000
#define FO_TEMPORARY_FILE            0x00008000
#define FO_DELETE_ON_CLOSE           0x00010000
#define FO_OPENED_CASE_SENSITIVE     0x00020000
#define FO_HANDLE_CREATED            0x00040000
#define FO_FILE_FAST_IO_READ         0x00080000
#define FO_RANDOM_ACCESS             0x00100000
#define FO_FILE_OPEN_CANCELLED       0x00200000
#define FO_VOLUME_OPEN               0x00400000
#define FO_REMOTE_ORIGIN             0x01000000
#define FO_DISALLOW_EXCLUSIVE        0x02000000
#define FO_SKIP_COMPLETION_PORT      0x02000000
#define FO_SKIP_SET_EVENT            0x04000000
#define FO_SKIP_SET_FAST_IO          0x08000000
#define FO_FLAGS_VALID_ONLY_DURING_CREATE FO_DISALLOW_EXCLUSIVE

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

/*
** IRP function codes
*/

#define IRP_MJ_CREATE                     0x00
#define IRP_MJ_CREATE_NAMED_PIPE          0x01
#define IRP_MJ_CLOSE                      0x02
#define IRP_MJ_READ                       0x03
#define IRP_MJ_WRITE                      0x04
#define IRP_MJ_QUERY_INFORMATION          0x05
#define IRP_MJ_SET_INFORMATION            0x06
#define IRP_MJ_QUERY_EA                   0x07
#define IRP_MJ_SET_EA                     0x08
#define IRP_MJ_FLUSH_BUFFERS              0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION   0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION     0x0b
#define IRP_MJ_DIRECTORY_CONTROL          0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL        0x0d
#define IRP_MJ_DEVICE_CONTROL             0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL    0x0f
#define IRP_MJ_SCSI                       0x0f
#define IRP_MJ_SHUTDOWN                   0x10
#define IRP_MJ_LOCK_CONTROL               0x11
#define IRP_MJ_CLEANUP                    0x12
#define IRP_MJ_CREATE_MAILSLOT            0x13
#define IRP_MJ_QUERY_SECURITY             0x14
#define IRP_MJ_SET_SECURITY               0x15
#define IRP_MJ_POWER                      0x16
#define IRP_MJ_SYSTEM_CONTROL             0x17
#define IRP_MJ_DEVICE_CHANGE              0x18
#define IRP_MJ_QUERY_QUOTA                0x19
#define IRP_MJ_SET_QUOTA                  0x1a
#define IRP_MJ_PNP                        0x1b
#define IRP_MJ_PNP_POWER                  0x1b
#define IRP_MJ_MAXIMUM_FUNCTION           0x1b

#define IRP_MN_SCSI_CLASS                 0x01

#define IRP_MN_START_DEVICE               0x00
#define IRP_MN_QUERY_REMOVE_DEVICE        0x01
#define IRP_MN_REMOVE_DEVICE              0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE       0x03
#define IRP_MN_STOP_DEVICE                0x04
#define IRP_MN_QUERY_STOP_DEVICE          0x05
#define IRP_MN_CANCEL_STOP_DEVICE         0x06

#define IRP_MN_QUERY_DEVICE_RELATIONS       0x07
#define IRP_MN_QUERY_INTERFACE              0x08
#define IRP_MN_QUERY_CAPABILITIES           0x09
#define IRP_MN_QUERY_RESOURCES              0x0A
#define IRP_MN_QUERY_RESOURCE_REQUIREMENTS  0x0B
#define IRP_MN_QUERY_DEVICE_TEXT            0x0C
#define IRP_MN_FILTER_RESOURCE_REQUIREMENTS 0x0D

#define IRP_MN_READ_CONFIG                  0x0F
#define IRP_MN_WRITE_CONFIG                 0x10
#define IRP_MN_EJECT                        0x11
#define IRP_MN_SET_LOCK                     0x12
#define IRP_MN_QUERY_ID                     0x13
#define IRP_MN_QUERY_PNP_DEVICE_STATE       0x14
#define IRP_MN_QUERY_BUS_INFORMATION        0x15
#define IRP_MN_DEVICE_USAGE_NOTIFICATION    0x16
#define IRP_MN_SURPRISE_REMOVAL             0x17
#define IRP_MN_DEVICE_ENUMERATED            0x19

#define IRP_MN_WAIT_WAKE                  0x00
#define IRP_MN_POWER_SEQUENCE             0x01
#define IRP_MN_SET_POWER                  0x02
#define IRP_MN_QUERY_POWER                0x03

#define IRP_MN_QUERY_ALL_DATA             0x00
#define IRP_MN_QUERY_SINGLE_INSTANCE      0x01
#define IRP_MN_CHANGE_SINGLE_INSTANCE     0x02
#define IRP_MN_CHANGE_SINGLE_ITEM         0x03
#define IRP_MN_ENABLE_EVENTS              0x04
#define IRP_MN_DISABLE_EVENTS             0x05
#define IRP_MN_ENABLE_COLLECTION          0x06
#define IRP_MN_DISABLE_COLLECTION         0x07
#define IRP_MN_REGINFO                    0x08
#define IRP_MN_EXECUTE_METHOD             0x09

#define IRP_MN_REGINFO_EX                 0x0b

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
    PVOID PrivateCacheMap;
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
    LIST_ENTRY IrpList;
} FILE_OBJECT, *PFILE_OBJECT;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
    SHORT Type;
    ULONG Size;
    LONG ReferenceCount;
    HANDLE DeviceHandle;
    struct _DRIVER_OBJECT *DriverObject;
    struct _DEVICE_OBJECT *NextDevice;
    struct _DEVICE_OBJECT *AttachedDevice;
    struct _DEVICE_OBJECT *AttachedTo;
    struct _IRP *CurrentIrp;
    ULONG Flags;
    ULONG Characteristics;
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;
    CCHAR StackSize;
    union {
	LIST_ENTRY ListEntry;
    } Queue;
    ULONG AlignmentRequirement;
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
    SHORT Size;
    SHORT MdlFlags;
    PVOID MappedSystemVa;
    PVOID StartVa;
    ULONG ByteCount;
    ULONG ByteOffset;
} MDL, *PMDL;

typedef VOID (NTAPI DRIVER_CANCEL)(IN OUT struct _DEVICE_OBJECT *DeviceObject,
				   IN OUT struct _IRP *Irp);
typedef DRIVER_CANCEL *PDRIVER_CANCEL;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _IRP {
    SHORT Type;
    USHORT Size;
    PMDL MdlAddress;
    ULONG Flags;
    union {
	struct _IRP *MasterIrp;
	volatile LONG IrpCount;
	PVOID SystemBuffer;
    } AssociatedIrp;
    LIST_ENTRY ThreadListEntry;
    IO_STATUS_BLOCK IoStatus;
    BOOLEAN PendingReturned;
    CHAR StackCount;
    CHAR CurrentLocation;
    BOOLEAN Cancel;
    CCHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PIO_STATUS_BLOCK UserIosb;
    union {
	struct {
	    union {
		PIO_APC_ROUTINE UserApcRoutine;
		PVOID IssuingProcess;
	    };
	    PVOID UserApcContext;
	} AsynchronousParameters;
	LARGE_INTEGER AllocationSize;
    } Overlay;
    volatile PDRIVER_CANCEL CancelRoutine;
    PVOID UserBuffer;
    union {
	struct {
	    union {
		struct {
		    PVOID DriverContext[4];
		};
	    };
	    PCHAR AuxiliaryBuffer;
	    struct {
		LIST_ENTRY ListEntry;
		union {
		    struct _IO_STACK_LOCATION *CurrentStackLocation;
		    ULONG PacketType;
		};
	    };
	    PFILE_OBJECT OriginalFileObject;
	} Overlay;
	PVOID CompletionKey;
    } Tail;
} IRP, *PIRP;

typedef struct _IO_ERROR_LOG_PACKET {
    UCHAR MajorFunctionCode;
    UCHAR RetryCount;
    USHORT DumpDataSize;
    USHORT NumberOfStrings;
    USHORT StringOffset;
    USHORT EventCategory;
    NTSTATUS ErrorCode;
    ULONG UniqueErrorValue;
    NTSTATUS FinalStatus;
    ULONG SequenceNumber;
    ULONG IoControlCode;
    LARGE_INTEGER DeviceOffset;
    ULONG DumpData[1];
} IO_ERROR_LOG_PACKET, *PIO_ERROR_LOG_PACKET;

typedef struct _IO_ERROR_LOG_MESSAGE {
    USHORT Type;
    USHORT Size;
    USHORT DriverNameLength;
    LARGE_INTEGER TimeStamp;
    ULONG DriverNameOffset;
    IO_ERROR_LOG_PACKET EntryData;
} IO_ERROR_LOG_MESSAGE, *PIO_ERROR_LOG_MESSAGE;

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
 * Driver object
 */
typedef struct _DRIVER_OBJECT {
    SHORT Type;
    SHORT Size;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    UNICODE_STRING ServiceKeyName;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    struct _FAST_IO_DISPATCH *FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO DriverStartIo;
    PDRIVER_ADD_DEVICE AddDevice;
    PDRIVER_UNLOAD DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

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
	    ULONG WhichSpace;
	    PVOID Buffer;
	    ULONG Offset;
	    ULONG POINTER_ALIGNMENT Length;
	} ReadWriteConfig;
	struct {
	    BOOLEAN Lock;
	} SetLock;
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

NTAPI NTSYSAPI NTSTATUS IoCreateDevice(IN PDRIVER_OBJECT DriverObject,
				       IN ULONG DeviceExtensionSize,
				       IN PUNICODE_STRING DeviceName OPTIONAL,
				       IN DEVICE_TYPE DeviceType,
				       IN ULONG DeviceCharacteristics,
				       IN BOOLEAN Exclusive,
				       OUT PDEVICE_OBJECT *DeviceObject);

NTAPI NTSYSAPI VOID IoCompleteRequest(IN PIRP Irp,
				      IN CHAR PriorityBoost);

NTAPI NTSYSAPI VOID IoDeleteDevice(IN PDEVICE_OBJECT DeviceObject);

NTAPI NTSYSAPI PVOID MmPageEntireDriver(IN PVOID AddressWithinSection);

FORCEINLINE PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(IN PIRP Irp)
{
    return Irp->Tail.Overlay.CurrentStackLocation;
}
