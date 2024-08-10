#pragma once

#define _NTDDK_

#include <nt.h>
#include <string.h>
#include <assert.h>

#define UNUSED	__attribute__((unused))

/* We are running in user space. */
FORCEINLINE DECLSPEC_DEPRECATED VOID PAGED_CODE() {}

/*
 * Returned by IoCallDriver to indicate that the IRP has been
 * forwarded to the lower-level drivers and will be deallocated
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

/* Device Object StartIo Flags */
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
FORCEINLINE NTAPI PVOID ExAllocatePoolWithTag(IN SIZE_T Size,
					      IN ULONG Tag)
{
    return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

FORCEINLINE NTAPI VOID ExFreePoolWithTag(IN PVOID Pointer,
					 IN ULONG Tag)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Pointer);
}

FORCEINLINE NTAPI PVOID ExAllocatePool(IN SIZE_T Size)
{
    return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

FORCEINLINE NTAPI VOID ExFreePool(IN PVOID Pointer)
{
    RtlFreeHeap(RtlGetProcessHeap(), 0, Pointer);
}

/*
 * Object manager routines
 */
NTAPI NTSYSAPI VOID ObDereferenceObject(IN PVOID Obj);

struct _DEVICE_OBJECT;
struct _DRIVER_OBJECT;
struct _IRP;

#define MAXIMUM_VOLUME_LABEL_LENGTH       (32 * sizeof(WCHAR))

/*
 * Volume Parameter Block
 */
typedef struct _VPB {
    SHORT Type;
    SHORT Size;
    USHORT Flags;
    USHORT VolumeLabelLength;
    struct _DEVICE_OBJECT *DeviceObject;
    struct _DEVICE_OBJECT *RealDevice;
    ULONG64 VolumeSize;
    ULONG ClusterSize;
    ULONG SerialNumber;
    ULONG ReferenceCount;
    WCHAR VolumeLabel[MAXIMUM_VOLUME_LABEL_LENGTH / sizeof(WCHAR)];
} VPB, *PVPB;

/*
 * Common header for client-side objects.
 */
typedef struct _OBJECT_HEADER {
    UCHAR Type;
    UCHAR Flags;
    USHORT Size;
    LONG RefCount;
    union {
	ULONG_PTR GlobalHandle;   /* Unique handle supplied by the server */
	HANDLE Handle;		  /* Regular NT handle */
    };
} OBJECT_HEADER, *POBJECT_HEADER;

/*
 * File Object
 */
typedef struct _FILE_OBJECT {
    OBJECT_HEADER Header;	/* Must be first member */
    struct _DEVICE_OBJECT *DeviceObject;
    PVOID FsContext;
    PVOID FsContext2;
    PVPB Vpb;
    struct _FILE_OBJECT *RelatedFileObject;
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
    struct {
	LIST_ENTRY Link; /* List entry for the list of all known file objects */
    } Private;	   /* Drivers shall not access this struct directly */
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
    LIST_ENTRY Entry;
    PKDEFERRED_ROUTINE DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    BOOLEAN Queued;
} KDPC, *PKDPC;

/*
 * DPC initialization function
 */
FORCEINLINE NTAPI VOID KeInitializeDpc(IN PKDPC Dpc,
				       IN PKDEFERRED_ROUTINE DeferredRoutine,
				       IN PVOID DeferredContext)
{
    Dpc->DeferredRoutine = DeferredRoutine;
    Dpc->DeferredContext = DeferredContext;
}

/*
 * Insert the DPC to the DPC queue
 */
NTAPI NTSYSAPI BOOLEAN KeInsertQueueDpc(IN PKDPC Dpc,
					IN PVOID SystemArgument1,
					IN PVOID SystemArgument2);

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
 * Device queue initialization function
 */
FORCEINLINE NTAPI VOID KeInitializeDeviceQueue(IN PKDEVICE_QUEUE Queue)
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
FORCEINLINE NTAPI PKDEVICE_QUEUE_ENTRY KeRemoveByKeyDeviceQueueIfBusy(IN PKDEVICE_QUEUE Queue,
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
FORCEINLINE NTAPI BOOLEAN KeRemoveEntryDeviceQueue(IN PKDEVICE_QUEUE Queue,
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
 * Device object.
 */
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _DEVICE_OBJECT {
    OBJECT_HEADER Header;
    struct _DRIVER_OBJECT *DriverObject;
    struct _IRP *CurrentIrp;
    UNICODE_STRING DeviceName;
    ULONG64 Flags; /* Low 32 bits are device characteristics. High 32 bits are flags. */
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;
    ULONG AlignmentRequirement;
    KDEVICE_QUEUE DeviceQueue;
    KDPC Dpc;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    USHORT SectorSize;
    ULONG PowerFlags;
    ULONG ExtensionFlags;
    LONG StartIoCount;
    LONG StartIoKey;
    ULONG StartIoFlags;
    PVPB Vpb;
    struct {
	LIST_ENTRY Link; /* List entry for the list of all known device objects */
    } Private;		 /* Drivers shall not access this struct directly */
} DEVICE_OBJECT, *PDEVICE_OBJECT;

/*
 * Memory Descriptor List (MDL)
 *
 * An MDL describes a virtually contiguous (but not necessarily physically
 * contiguous) I/O buffer.
 */
typedef struct _MDL {
    struct _MDL *Next;
    PVOID MappedSystemVa;
    ULONG Flags;
    ULONG ByteOffset;	/* Page offset to the start of the buffer */
    ULONG ByteCount;	/* Number of bytes of this buffer */
    ULONG PfnCount;	/* Number of entries in PfnEntries */
    ULONG_PTR PfnEntries[];
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
    ULONG Flags;

    /* Address to the MDL chain associated with this IRP. */
    PMDL MdlAddress;

    /* For an associated IRP, this is the pointer to its master IRP. */
    struct _IRP *MasterIrp;

    /* For BUFFERED_IO, this is the pointer to the system-allocated buffer. */
    PVOID SystemBuffer;

    /* IO status block returned by the driver */
    IO_STATUS_BLOCK IoStatus;

    /* IO status block supplied by the client driver that will be populated
     * once the IRP has been completed. This makes the IRP synchronous. */
    PIO_STATUS_BLOCK UserIosb;

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

    /* Initial allocation size of the file object associated with the IRP.
     * This is only set for IRP_MJ_CREATE and is a read-only member. */
    LARGE_INTEGER AllocationSize;

    struct {
	ULONG_PTR OriginalRequestor; /* Original requestor handle, used for
				      * disambiguating the Identifier. */
	HANDLE Identifier; /* Identifier of the IRP object, temporarily
			    * unique up to the original requestor. */
	PVOID OutputBuffer; /* Output buffer provided by the client
			     * process, mapped here */
	LIST_ENTRY Link;    /* List entry for IrpQueue, PendingIrpList,
			     * CleanupIrpList, and ReplyIrpList */
	PDEVICE_OBJECT ForwardedTo; /* Device object that the IRP is
				     * being forwarded to */
	PVOID ExecEnv; /* Execution environment associated with this IRP */
	PVOID EnvToWakeUp; /* Execution environment to wake up when this IRP
			    * is completed. */
	union {
	    LIST_ENTRY PendingList; /* For master IRP, this is the list of
				     * all pending assoicated IRPs. */
	    LIST_ENTRY Link;	/* For associated IRPs, this is the list link
				 * for PendingList. */
	} AssociatedIrp;
	ULONG AssociatedIrpCount; /* Number of associated IRPs of a master IRP. */
	BOOLEAN MasterCompleted;  /* TRUE if the master IRP is completed but
				   * its pending associated IRPs have not. */
	BOOLEAN NotifyCompletion; /* TRUE if the server will notify the
				   * completion of this forwarded IRP. */
	BOOLEAN MasterIrpSent; /* TRUE if this is an associated IRP of a master
				* IRP and the server has been informed of the
				* master IRP's identifier. */
    } Private;	   /* Drivers shall not access this struct directly */

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
	    /* If driver does not use the device queue, these are
	     * available for driver use */
	    PVOID DriverContext[4];
	};
	/* Available for driver use. Typically used to queue IRP to
	 * a driver-defined queue. */
	union {
	    LIST_ENTRY ListEntry;
	    SLIST_ENTRY SListEntry;
	};
	/* The following member is used by the network packet filter
	 * to queue IRP to an I/O completion queue. */
	ULONG PacketType;
	PFILE_OBJECT OriginalFileObject;
    } Tail;
} IRP, *PIRP;

/*
 * IO DPC routine
 */
typedef VOID (NTAPI IO_DPC_ROUTINE)(IN PKDPC Dpc,
				    IN PDEVICE_OBJECT DeviceObject,
				    IN OUT PIRP Irp,
				    IN OPTIONAL PVOID Context);
typedef IO_DPC_ROUTINE *PIO_DPC_ROUTINE;

/*
 * Initialize the device object's built-in DPC object
 */
FORCEINLINE NTAPI VOID IoInitializeDpcRequest(IN PDEVICE_OBJECT DeviceObject,
					      IN PIO_DPC_ROUTINE DpcRoutine)
{
    KeInitializeDpc(&DeviceObject->Dpc, (PKDEFERRED_ROUTINE)DpcRoutine,
		    DeviceObject);
}

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
    CSHORT Type;
    CSHORT Size;
    PDEVICE_OBJECT DeviceObject; /* Points to the last device created by IoCreateDevice.
				  * Deprecated! Do not use in PnP drivers. */
    ULONG Flags;
    PVOID DriverStart;
    UNICODE_STRING ServiceKeyName;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PIO_CLIENT_EXTENSION ClientDriverExtension;
    LIST_ENTRY ReinitListHead;
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
	    PDEVICE_CAPABILITIES Capabilities;
	} DeviceCapabilities;
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
    PVOID Context; /* Driver-defined context for the IO Completion routine */
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

#define IO_SIZE_OF_IRP	(sizeof(IRP) + sizeof(IO_STACK_LOCATION))

/*
 * Returns the full size of an IRP object including the header and the
 * IO stack location.
 */
DEPRECATED("IRPs always have exactly one stack location. Use IO_SIZE_OF_IRP instead.")
FORCEINLINE NTAPI USHORT IoSizeOfIrp(IN CCHAR StackSize)
{
    return IO_SIZE_OF_IRP;
}

/*
 * Note: The Irp object must be zeroed before calling this function.
 *
 * Porting guide: IRPs always have exactly one stack location, so remove
 * the PacketSize and StackSize argument if you are porting from ReactOS.
 */
FORCEINLINE NTAPI VOID IoInitializeIrp(IN PIRP Irp)
{
    /* Set the Header and other data */
    Irp->Type = IO_TYPE_IRP;
    Irp->Size = IO_SIZE_OF_IRP;
    InitializeListHead(&Irp->Private.AssociatedIrp.PendingList);
}

/*
 * Porting guide: IRPs always have exactly one stack location, and we don't
 * have "pool memory" since we are running in userspace, so remove the
 * StackSize and ChargeQuota argument if you are porting from ReactOS.
 */
FORCEINLINE NTAPI PIRP IoAllocateIrp()
{
    PIRP Irp = (PIRP)ExAllocatePool(IO_SIZE_OF_IRP);
    if (Irp == NULL) {
	return NULL;
    }
    IoInitializeIrp(Irp);
    return Irp;
}

FORCEINLINE NTAPI VOID IoFreeIrp(IN PIRP Irp)
{
    PMDL Mdl = Irp->MdlAddress;
    while (Mdl) {
	PMDL Next = Mdl->Next;
	ExFreePool(Mdl);
	Mdl = Next;
    }
    ExFreePool(Irp);
}

/*
 * Returns the current (and only) IO stack location pointer. The (only)
 * IO stack location follows immediately after the IRP header.
 */
FORCEINLINE NTAPI PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(IN PIRP Irp)
{
    return (PIO_STACK_LOCATION)(Irp + 1);
}

/*
 * IO stack location manipulation routines. These are all deprecated and
 * are effectively no-op since our IRPs always have exactly one stack location.
 */
DEPRECATED("IRPs always have exactly one stack location. Remove this.")
FORCEINLINE NTAPI VOID IoSkipCurrentIrpStackLocation(IN OUT PIRP Irp)
{
}

DEPRECATED("IRPs always have exactly one stack location. Remove this.")
FORCEINLINE NTAPI VOID IoCopyCurrentIrpStackLocationToNext(IN OUT PIRP Irp)
{
}

DEPRECATED("IRPs always have exactly one stack location. Remove this")
FORCEINLINE NTAPI VOID IoSetNextIrpStackLocation(IN OUT PIRP Irp)
{
}

DEPRECATED_BY("IRPs always have exactly one stack location.",
	      IoGetCurrentIrpStackLocation)
FORCEINLINE NTAPI PIO_STACK_LOCATION IoGetNextIrpStackLocation(IN PIRP Irp)
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
				       IN ULONG64 Flags,
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

FORCEINLINE NTAPI NTSTATUS
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

#define DEVICE_INTERFACE_INCLUDE_NONACTIVE 0x00000001

NTAPI NTSYSAPI NTSTATUS IoGetDeviceInterfaces(IN CONST GUID *InterfaceClassGuid,
					      IN OPTIONAL PDEVICE_OBJECT PhysicalDeviceObject,
					      IN ULONG Flags,
					      OUT PWSTR *SymbolicLinkList);

NTAPI NTSYSAPI NTSTATUS IoGetDeviceProperty(IN PDEVICE_OBJECT DeviceObject,
					    IN DEVICE_REGISTRY_PROPERTY DeviceProperty,
					    IN ULONG BufferLength,
					    OUT PVOID PropertyBuffer,
					    OUT PULONG ResultLength);

NTAPI NTSYSAPI NTSTATUS IoCreateSymbolicLink(IN PUNICODE_STRING SymbolicLinkName,
					     IN PUNICODE_STRING DeviceName);

#define PLUGPLAY_REGKEY_DEVICE                            1
#define PLUGPLAY_REGKEY_DRIVER                            2
#define PLUGPLAY_REGKEY_CURRENT_HWPROFILE                 4
#define PLUGPLAY_REGKEY_BOOT_CONFIGURATION                8

NTAPI NTSYSAPI NTSTATUS IoOpenDeviceRegistryKey(IN PDEVICE_OBJECT DeviceObject,
						IN ULONG DevInstKeyType,
						IN ACCESS_MASK DesiredAccess,
						IN PHANDLE DevInstRegKey);

NTAPI NTSYSAPI VOID IoDetachDevice(IN PDEVICE_OBJECT TargetDevice);

DEPRECATED("Drivers run in userspace and are always paged entirely. Remove this.")
NTAPI NTSYSAPI PVOID MmPageEntireDriver(IN PVOID AddressWithinSection);

/*
 * TIMER object. Note: just like KDPC despite being called 'KTIMER'
 * this is the client-side handle to the server side KTIMER object.
 * There is no name collision because the NTOS server does not
 * include files under public/ddk.
 */
typedef struct _KTIMER {
    OBJECT_HEADER Header;	/* Must be first member. */
    LIST_ENTRY TimerListEntry;
    PKDPC Dpc;
    BOOLEAN State;		/* TRUE if the timer is set. */
    BOOLEAN Canceled;
} KTIMER, *PKTIMER;

/*
 * Timer routines
 */
NTAPI NTSYSAPI VOID KeInitializeTimer(OUT PKTIMER Timer);

NTAPI NTSYSAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
				  IN LARGE_INTEGER DueTime,
				  IN OPTIONAL PKDPC Dpc);

/* TODO: Inform the server to actually cancel the timer */
FORCEINLINE NTAPI BOOLEAN KeCancelTimer(IN OUT PKTIMER Timer)
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
 * EVENT object.
 */
typedef struct _KEVENT {
    OBJECT_HEADER Header;	/* Must be first member */
    LIST_ENTRY EventListEntry;
    EVENT_TYPE Type;
    BOOLEAN State;
} KEVENT, *PKEVENT;

NTAPI NTSYSAPI VOID KeInitializeEvent(OUT PKEVENT Event,
				      IN EVENT_TYPE Type,
				      IN BOOLEAN InitialState);

NTAPI NTSYSAPI LONG KeSetEvent(IN PKEVENT Event);

NTAPI NTSYSAPI LONG KeResetEvent(IN PKEVENT Event);

NTAPI NTSYSAPI VOID KeClearEvent(IN PKEVENT Event);

/* As should be apparent from the code below, the only objects
 * waitable are those that has OBJECT_HEADER as the first member and
 * OBJ_WAITABLE_OBJECT set. These include KTIMER, KEVENT, etc. */
#define OBJ_WAITABLE_OBJECT	(1)
#define KeWaitForSingleObject(obj, _1, _2, alert, timeout)	\
    ({								\
	POBJECT_HEADER Header = &(obj)->Header;			\
	assert(Header->Flags & OBJ_WAITABLE_OBJECT);		\
	NtWaitForSingleObject(Header->Handle, alert, timeout);	\
    })

/*
 * Set the IO cancel routine of the given IRP, returning the previous one.
 *
 * NOTE: As opposed to Windows/ReactOS we do NOT need the interlocked (atomic)
 * operation here, since in NeptuneOS driver dispatch routines run in a single thread.
 */
FORCEINLINE NTAPI PDRIVER_CANCEL IoSetCancelRoutine(IN OUT PIRP Irp,
						    IN OPTIONAL PDRIVER_CANCEL CancelRoutine)
{
    PDRIVER_CANCEL Old = Irp->CancelRoutine;
    Irp->CancelRoutine = CancelRoutine;
    return Old;
}

/*
 * Mark the current IRP as pending
 */
FORCEINLINE NTAPI VOID IoMarkIrpPending(IN OUT PIRP Irp)
{
    assert(!Irp->Completed);
    IoGetCurrentIrpStackLocation((Irp))->Control |= SL_PENDING_RETURNED;
}

/*
 * Complete the given IRP
 */
NTAPI NTSYSAPI VOID IoCompleteRequest(IN PIRP Irp,
				      IN CHAR PriorityBoost);

/*
 * Cancel the given IRP
 */
NTAPI NTSYSAPI VOID IoCancelIrp(IN PIRP Irp);

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
FORCEINLINE NTAPI VOID IoSetStartIoAttributes(IN PDEVICE_OBJECT DeviceObject,
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
FORCEINLINE NTAPI PVOID MmGetSystemAddressForMdl(IN PMDL Mdl)
{
    if (Mdl->MappedSystemVa) {
	return Mdl->MappedSystemVa;
    }
    RtlRaiseStatus(STATUS_INVALID_ADDRESS);
}

FORCEINLINE NTAPI PVOID MmGetSystemAddressForMdlSafe(IN PMDL Mdl)
{
    /* Note that if the driver wants to access the memory described by the MDL,
     * it must enable DO_MAP_IO_BUFFER when creating the device to map the memory
     * into driver address space. Otherwise Mdl->MappedSystemVa is always NULL. */
    return Mdl->MappedSystemVa;
}

/* On Windows this routine returns the virtual address for the IO buffer in original
 * requestor's process address space. The only use for this is to obtain an offset
 * into the IO buffer for the CurrentVa parameter of IoMapTransfer. Since Neptune OS
 * uses separate address spaces for drivers, we simply treat the original buffer as
 * if it is mapped at the very beginning of the virtual address space. */
FORCEINLINE NTAPI PVOID MmGetMdlVirtualAddress(IN PMDL Mdl)
{
    return (PVOID)(ULONG_PTR)Mdl->ByteOffset;
}

NTAPI PHYSICAL_ADDRESS MmGetMdlPhysicalAddress(IN PMDL Mdl,
					       IN PVOID StartVa);

NTAPI NTSYSAPI SIZE_T MmGetMdlPhysicallyContiguousSize(IN PMDL Mdl,
						       IN PVOID StartVa,
						       IN ULONG BoundAddrBits);

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
 * with STATUS_IRP_FORWARDED, unless the IRP has supplied a UserIosb,
 * in which case the current coroutine is suspended and waits for the
 * completion of the IRP.
 */
FORCEINLINE NTAPI NTSTATUS IoCallDriver(IN PDEVICE_OBJECT DeviceObject,
					IN OUT PIRP Irp)
{
    LARGE_INTEGER Timeout = { .QuadPart = 0 };
    return IoCallDriverEx(DeviceObject, Irp, &Timeout);
}

/*
 * @implemented
 *
 * Forward the IRP to the device object and wait for its completion.
 */
FORCEINLINE NTAPI BOOLEAN IoForwardIrpSynchronously(IN PDEVICE_OBJECT DeviceObject,
						    IN PIRP Irp)
{
    UNUSED NTSTATUS Status = IoCallDriverEx(DeviceObject, Irp, NULL);
    assert(Status == Irp->IoStatus.Status);
    return TRUE;
}

/*
 * This was needed by the power manager in Windows XP/ReactOS and is
 * now deprecated in Windows Vista and later. We follow Vista+.
 */
DEPRECATED_BY("Power IRP synchronization is now automatic. You no longer "
	      "need to call the Po-specific versions",
	      IoCallDriver)
FORCEINLINE NTAPI NTSTATUS PoCallDriver(IN PDEVICE_OBJECT DeviceObject,
					IN OUT PIRP Irp)
{
    return IoCallDriver(DeviceObject, Irp);
}

DEPRECATED("Power IRP synchronization is now automatic. Remove this.")
FORCEINLINE NTAPI VOID PoStartNextPowerIrp(IN OUT PIRP Irp)
{
    /* Do nothing */
}

/*
 * IO Work item. This is an opaque object.
 */
typedef struct _IO_WORKITEM *PIO_WORKITEM;

typedef VOID (NTAPI IO_WORKITEM_ROUTINE)(IN PDEVICE_OBJECT DeviceObject,
					 IN OPTIONAL PVOID Context);
typedef IO_WORKITEM_ROUTINE *PIO_WORKITEM_ROUTINE;

typedef VOID (NTAPI IO_WORKITEM_ROUTINE_EX)(IN PVOID IoObject,
					    IN OPTIONAL PVOID Context,
					    IN PIO_WORKITEM IoWorkItem);
typedef IO_WORKITEM_ROUTINE_EX *PIO_WORKITEM_ROUTINE_EX;

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
NTAPI NTSYSAPI PIO_WORKITEM IoAllocateWorkItem(IN PDEVICE_OBJECT DeviceObject);

/*
 * Work item deallocation
 */
NTAPI NTSYSAPI VOID IoFreeWorkItem(IN PIO_WORKITEM IoWorkItem);

/*
 * Work item queuing
 */
NTAPI NTSYSAPI VOID IoQueueWorkItem(IN OUT PIO_WORKITEM IoWorkItem,
				    IN PIO_WORKITEM_ROUTINE WorkerRoutine,
				    IN WORK_QUEUE_TYPE QueueType,
				    IN OPTIONAL PVOID Context);

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

NTAPI NTSYSAPI VOID IoAcquireInterruptMutex(IN PKINTERRUPT Interrupt);

NTAPI NTSYSAPI VOID IoReleaseInterruptMutex(IN PKINTERRUPT Interrupt);

/*
 * Interrupt "spinlock" acquisition. This is is actually a mutex. The function
 * redirects to IoAcquireInterruptMutex and is kept for compatibility with
 * Windows/ReactOS drivers.
 */
DEPRECATED_BY("Interrupt \"spinlock\" is actually a mutex.",
	      IoAcquireInterruptMutex)
FORCEINLINE NTAPI KIRQL KeAcquireInterruptSpinLock(IN PKINTERRUPT Interrupt)
{
    IoAcquireInterruptMutex(Interrupt);
    /* Return PASSIVE_LEVEL */
    return 0;
}

/*
 * Interrupt "spinlock" release. OldIrql is ignored.
 */
DEPRECATED_BY("Interrupt \"spinlock\" is actually a mutex.",
	      IoReleaseInterruptMutex)
FORCEINLINE NTAPI VOID KeReleaseInterruptSpinLock(IN PKINTERRUPT Interrupt,
						  IN KIRQL OldIrql)
{
    IoReleaseInterruptMutex(Interrupt);
}

/*
 * Returns the pointer to the highest level device object in a device stack
 */
NTAPI NTSYSAPI PDEVICE_OBJECT IoGetAttachedDevice(IN PDEVICE_OBJECT DeviceObject);

/*
 * This is the same function as IoGetAttachedDevice, but we increase the reference
 * count of the attached device object.
 */
NTAPI NTSYSAPI PDEVICE_OBJECT IoGetAttachedDeviceReference(IN PDEVICE_OBJECT DeviceObject);

/*
 * PNP device relation list, which is simply an array of (physical) device objects.
 */
typedef struct _DEVICE_RELATIONS {
    ULONG Count;
    PDEVICE_OBJECT Objects[];
} DEVICE_RELATIONS, *PDEVICE_RELATIONS;

/*
 * Controller or peripheral type.
 */
typedef enum _CONFIGURATION_TYPE {
    ArcSystem,
    CentralProcessor,
    FloatingPointProcessor,
    PrimaryIcache,
    PrimaryDcache,
    SecondaryIcache,
    SecondaryDcache,
    SecondaryCache,
    EisaAdapter,
    TcAdapter,
    ScsiAdapter,
    DtiAdapter,
    MultiFunctionAdapter,
    DiskController,
    TapeController,
    CdromController,
    WormController,
    SerialController,
    NetworkController,
    DisplayController,
    ParallelController,
    PointerController,
    KeyboardController,
    AudioController,
    OtherController,
    DiskPeripheral,
    FloppyDiskPeripheral,
    TapePeripheral,
    ModemPeripheral,
    MonitorPeripheral,
    PrinterPeripheral,
    PointerPeripheral,
    KeyboardPeripheral,
    TerminalPeripheral,
    OtherPeripheral,
    LinePeripheral,
    NetworkPeripheral,
    SystemMemory,
    DockingInformation,
    RealModeIrqRoutingTable,
    RealModePCIEnumeration,
    MaximumType
} CONFIGURATION_TYPE, *PCONFIGURATION_TYPE;

/*
 * Call-back routine for IoQueryDeviceDescription
 */
typedef NTSTATUS (NTAPI *PIO_QUERY_DEVICE_ROUTINE)(IN PVOID Context,
						   IN PUNICODE_STRING PathName,
						   IN INTERFACE_TYPE BusType,
						   IN ULONG BusNumber,
						   IN PKEY_VALUE_FULL_INFORMATION *BusInformation,
						   IN CONFIGURATION_TYPE ControllerType,
						   IN ULONG ControllerNumber,
						   IN PKEY_VALUE_FULL_INFORMATION *ControllerInformation,
						   IN CONFIGURATION_TYPE PeripheralType,
						   IN ULONG PeripheralNumber,
						   IN PKEY_VALUE_FULL_INFORMATION *PeripheralInformation);

/*
 * Specifies the data format returned by IoQueryDeviceDescription.
 */
typedef enum _IO_QUERY_DEVICE_DATA_FORMAT {
    IoQueryDeviceIdentifier = 0,
    IoQueryDeviceConfigurationData,
    IoQueryDeviceComponentInformation,
    IoQueryDeviceMaxData
} IO_QUERY_DEVICE_DATA_FORMAT, *PIO_QUERY_DEVICE_DATA_FORMAT;

/*
 * Retrieves hardware configuration information about a given bus,
 * controller or peripheral object (or any combination thereof) from
 * the \Registry\Machine\Hardware\Description tree
 */
NTAPI NTSYSAPI NTSTATUS IoQueryDeviceDescription(IN OPTIONAL PINTERFACE_TYPE BusType,
						 IN OPTIONAL PULONG BusNumber,
						 IN OPTIONAL PCONFIGURATION_TYPE ControllerType,
						 IN OPTIONAL PULONG ControllerNumber,
						 IN OPTIONAL PCONFIGURATION_TYPE PeripheralType,
						 IN OPTIONAL PULONG PeripheralNumber,
						 IN PIO_QUERY_DEVICE_ROUTINE CalloutRoutine,
						 IN OUT OPTIONAL PVOID Context);

typedef struct _CONFIGURATION_INFORMATION {
    ULONG DiskCount;
    ULONG FloppyCount;
    ULONG CdRomCount;
    ULONG TapeCount;
    ULONG ScsiPortCount;
    ULONG SerialCount;
    ULONG ParallelCount;
    BOOLEAN AtDiskPrimaryAddressClaimed;
    BOOLEAN AtDiskSecondaryAddressClaimed;
    ULONG Version;
    ULONG MediumChangerCount;
} CONFIGURATION_INFORMATION, *PCONFIGURATION_INFORMATION;

/*
 * Porting guide: remove the WaitMode parameter as all wait happens
 * in user mode.
 */
NTAPI NTSYSAPI NTSTATUS KeDelayExecutionThread(IN BOOLEAN Alertable,
					       IN PLARGE_INTEGER Interval);

/*
 * Look-aside list
 */
#define LOOKASIDE_ALIGN DECLSPEC_CACHEALIGN
typedef PVOID (NTAPI *PALLOCATE_FUNCTION)(IN SIZE_T NumberOfBytes,
					  IN ULONG Tag);
typedef VOID (NTAPI *PFREE_FUNCTION)(IN PVOID Buffer);

typedef struct LOOKASIDE_ALIGN _LOOKASIDE_LIST {
    SLIST_HEADER ListHead;
    USHORT Depth;
    USHORT MaximumDepth;
    ULONG TotalAllocates;
    union {
        ULONG AllocateMisses;
        ULONG AllocateHits;
    };
    ULONG TotalFrees;
    union {
        ULONG FreeMisses;
        ULONG FreeHits;
    };
    ULONG Tag;
    ULONG Size;
    PALLOCATE_FUNCTION Allocate;
    PFREE_FUNCTION Free;
    ULONG LastTotalAllocates;
    union {
        ULONG LastAllocateMisses;
        ULONG LastAllocateHits;
    };
} LOOKASIDE_LIST, *PLOOKASIDE_LIST;

FORCEINLINE NTAPI VOID ExInitializeLookasideList(OUT PLOOKASIDE_LIST List,
						 IN OPTIONAL PALLOCATE_FUNCTION Allocate,
						 IN OPTIONAL PFREE_FUNCTION Free,
						 IN SIZE_T Size,
						 IN ULONG Tag) {
    List->Tag = Tag;
    List->Size = Size;
    List->MaximumDepth = 256;
    List->Depth = 4;
    List->Allocate = Allocate ? Allocate : ExAllocatePoolWithTag;
    List->Free = Free ? Free : ExFreePool;
    RtlInitializeSListHead(&List->ListHead);
    List->TotalAllocates = 0;
    List->AllocateHits = 0;
    List->TotalFrees = 0;
    List->FreeHits = 0;
    List->LastTotalAllocates = 0;
    List->LastAllocateHits = 0;
}

FORCEINLINE NTAPI PVOID ExAllocateFromLookasideList(IN OUT PLOOKASIDE_LIST Lookaside)
{
    Lookaside->TotalAllocates += 1;
    PVOID Entry = RtlInterlockedPopEntrySList(&Lookaside->ListHead);
    if (Entry == NULL) {
	Lookaside->AllocateMisses += 1;
	assert(Lookaside->Allocate != NULL);
	Entry = Lookaside->Allocate(Lookaside->Size, Lookaside->Tag);
    }
    return Entry;
}

FORCEINLINE NTAPI USHORT ExQueryDepthSList(IN PSLIST_HEADER SListHead)
{
#ifdef _WIN64
    return (USHORT)SListHead->Header8.Depth;
#else
    return (USHORT)SListHead->Depth;
#endif
}

FORCEINLINE NTAPI VOID ExFreeToLookasideList(IN OUT PLOOKASIDE_LIST Lookaside,
					     IN PVOID Entry)
{
    Lookaside->TotalFrees++;
    if (ExQueryDepthSList(&Lookaside->ListHead) >= Lookaside->Depth) {
	Lookaside->FreeMisses++;
	Lookaside->Free(Entry);
    } else {
	RtlInterlockedPushEntrySList(&Lookaside->ListHead, (PSLIST_ENTRY)Entry);
    }
}

FORCEINLINE VOID IoSetCompletionRoutine(IN PIRP Irp,
					IN OPTIONAL PIO_COMPLETION_ROUTINE CompletionRoutine,
					IN OPTIONAL PVOID Context,
					IN BOOLEAN InvokeOnSuccess,
					IN BOOLEAN InvokeOnError,
					IN BOOLEAN InvokeOnCancel)
{
    if (InvokeOnSuccess || InvokeOnError || InvokeOnCancel) {
	ASSERT(CompletionRoutine);
    }
    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    IoStack->CompletionRoutine = CompletionRoutine;
    IoStack->Context = Context;
    IoStack->Control = 0;
    if (InvokeOnSuccess) {
	IoStack->Control = SL_INVOKE_ON_SUCCESS;
    }
    if (InvokeOnError) {
	IoStack->Control |= SL_INVOKE_ON_ERROR;
    }
    if (InvokeOnCancel) {
	IoStack->Control |= SL_INVOKE_ON_CANCEL;
    }
}

/*
 * Power management data types and routines
 */
NTAPI NTSYSAPI POWER_STATE PoSetPowerState(IN PDEVICE_OBJECT DeviceObject,
					   IN POWER_STATE_TYPE Type,
					   IN POWER_STATE State);

typedef VOID (NTAPI *PREQUEST_POWER_COMPLETE)(IN PDEVICE_OBJECT DeviceObject,
					      IN UCHAR MinorFunction,
					      IN POWER_STATE PowerState,
					      IN OPTIONAL PVOID Context,
					      IN PIO_STATUS_BLOCK IoStatus);

NTAPI NTSYSAPI NTSTATUS PoRequestPowerIrp(IN PDEVICE_OBJECT DeviceObject,
					  IN UCHAR MinorFunction,
					  IN POWER_STATE PowerState,
					  IN OPTIONAL PREQUEST_POWER_COMPLETE CompletionFunction,
					  IN OPTIONAL PVOID Context,
					  OUT PIRP *Irp);

/*
 * Windows Management Instrumentation data types and routines
 */
#define WMIREG_ACTION_REGISTER      1
#define WMIREG_ACTION_DEREGISTER    2
#define WMIREG_ACTION_REREGISTER    3
#define WMIREG_ACTION_UPDATE_GUIDS  4
#define WMIREG_ACTION_BLOCK_IRPS    5

#define WMIREGISTER                 0
#define WMIUPDATE                   1

typedef VOID (NTAPI *WMI_NOTIFICATION_CALLBACK)(PVOID Wnode,
						PVOID Context);

NTAPI NTSYSAPI NTSTATUS IoWMIRegistrationControl(IN PDEVICE_OBJECT DeviceObject,
						 IN ULONG Action);

/*
 * PnP notification data types and routines
 */
typedef NTSTATUS (NTAPI *PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)(IN PVOID NotificationStructure,
								IN OUT OPTIONAL PVOID Context);

NTAPI NTSYSAPI NTSTATUS
IoRegisterPlugPlayNotification(IN IO_NOTIFICATION_EVENT_CATEGORY EventCategory,
			       IN ULONG EventCategoryFlags,
			       IN OPTIONAL PVOID EventCategoryData,
			       IN PDRIVER_OBJECT DriverObject,
			       IN PDRIVER_NOTIFICATION_CALLBACK_ROUTINE CallbackRoutine,
			       IN OUT OPTIONAL PVOID Context,
			       OUT PVOID *NotificationEntry);

typedef struct _DEVICE_INTERFACE_CHANGE_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
    GUID InterfaceClassGuid;
    PUNICODE_STRING SymbolicLinkName;
} DEVICE_INTERFACE_CHANGE_NOTIFICATION, *PDEVICE_INTERFACE_CHANGE_NOTIFICATION;

typedef struct _HWPROFILE_CHANGE_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
} HWPROFILE_CHANGE_NOTIFICATION, *PHWPROFILE_CHANGE_NOTIFICATION;
