#pragma once

#define _NTDDK_

#include <nt.h>
#include <devpropdef.h>
#include <assert.h>

#define UNUSED	__attribute__((unused))

FORCEINLINE BOOLEAN IoThreadIsAtPassiveLevel()
{
    PTEB Teb = NtCurrentTeb();
    BOOLEAN Val = Teb->Wdm.IsMainThread;
    if (Val) {
	assert(!Teb->Wdm.IsDpcThread && !Teb->Wdm.IsIsrThread);
    }
    return Val;
}

/* This routines asserts that we are at PASSIVE_LEVEL. */
FORCEINLINE VOID PAGED_CODE()
{
    assert(IoThreadIsAtPassiveLevel());
}

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
 */

typedef enum _POOL_TYPES {
    NonPagedPool,
    PagedPool = NonPagedPool,
    CachedDmaPool,
    UncachedDmaPool,
    MaxPoolType
} POOL_TYPE;

NTAPI NTSYSAPI PVOID ExAllocatePoolWithTag(IN POOL_TYPE PoolType,
					   IN SIZE_T Size,
					   IN ULONG Tag);

NTAPI NTSYSAPI VOID ExFreePoolWithTag(IN PVOID Pointer,
				      IN ULONG Tag);

FORCEINLINE NTAPI PVOID ExAllocatePool(IN POOL_TYPE PoolType,
				       IN SIZE_T Size)
{
    return ExAllocatePoolWithTag(PoolType, Size, 0);
}

FORCEINLINE NTAPI VOID ExFreePool(IN PVOID Pointer)
{
    ExFreePoolWithTag(Pointer, 0);
}

/*
 * Object manager routines
 */
NTAPI NTSYSAPI VOID ObReferenceObject(IN PVOID Obj);
NTAPI NTSYSAPI VOID ObDereferenceObject(IN PVOID Obj);
#define ObReferenceObjectByPointer(Obj, _1, _2, _3) ({	\
	    ObReferenceObject(Obj);			\
	    STATUS_SUCCESS;				\
	})

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
    ULONG_PTR GlobalHandle;   /* Unique handle supplied by the server */
} OBJECT_HEADER, *POBJECT_HEADER;

/*
 * Header for the waitable objects, such as KTIMER and KEVENT. These
 * are called dispatcher objects in NT terminology, and there is an
 * NT Executive server-side structure called DISPATCHER_HEADER that
 * represents waitable objects on the server. However we avoid using
 * this name on the driver side due to potential confusion with the
 * dispatch routines of IRPs (dispatcher objects have nothing to do
 * with dispatch routines of IRPs). The waitable objects on the driver
 * side may or may not have a corresponding server-side object (KTIMER
 * does have a server-side object, but KEVENT does not).
 */
typedef struct POINTER_ALIGNMENT _WAITABLE_OBJECT_HEADER {
    OBJECT_HEADER Header;
    LIST_ENTRY QueueListEntry;
    LIST_ENTRY EnvList;	/* List of execution environments suspended on the object */
    EVENT_TYPE Type;
    BOOLEAN Signaled;
} WAITABLE_OBJECT_HEADER, *PWAITABLE_OBJECT_HEADER;

/*
 * EVENT object.
 */
typedef struct _KEVENT {
    WAITABLE_OBJECT_HEADER Header; /* Must be first member */
} KEVENT, *PKEVENT;

NTAPI NTSYSAPI VOID KeInitializeEvent(OUT PKEVENT Event,
				      IN EVENT_TYPE Type,
				      IN BOOLEAN InitialState);

NTAPI NTSYSAPI LONG KeSetEvent(IN PKEVENT Event);

NTAPI NTSYSAPI LONG KeResetEvent(IN PKEVENT Event);

NTAPI NTSYSAPI VOID KeClearEvent(IN PKEVENT Event);

/*
 * Specify the reason for the wait in KeWaitForSingleObject.
 */
typedef enum _KWAIT_REASON {
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    MaximumWaitReason
} KWAIT_REASON;

/*
 * Processor Execution Modes. This is only used by KeWaitForSingleObject
 * in order to remain compatible with NTDDK API, and does not refer to the
 * actual processor mode in which the drivers run (the drivers always run
 * in user mode).
 */
typedef enum _KPROCESSOR_MODE {
    KernelMode,
    UserMode,
    MaximumMode
} KPROCESSOR_MODE;

NTAPI NTSYSAPI NTSTATUS KeWaitForSingleObject(IN PVOID Object,
					      IN KWAIT_REASON WaitReason,
					      IN KPROCESSOR_MODE WaitMode,
					      IN BOOLEAN Alertable,
					      IN PLARGE_INTEGER Timeout);

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
    LIST_ENTRY QueueEntry;
    PKDEFERRED_ROUTINE DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    BOOLEAN Queued;
} KDPC, *PKDPC;

NTAPI NTSYSAPI VOID KeInitializeDpc(IN PKDPC Dpc,
				    IN PKDEFERRED_ROUTINE DeferredRoutine,
				    IN PVOID DeferredContext);

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
 * Device queue initialization function. This routine can only be
 * called at PASSIVE_LEVEL (ie. not in an ISR thread or DPC thread).
 */
FORCEINLINE NTAPI VOID KeInitializeDeviceQueue(IN PKDEVICE_QUEUE Queue)
{
    assert(Queue != NULL);
    assert(!NtCurrentTeb()->Wdm.IsDpcThread);
    assert(!NtCurrentTeb()->Wdm.IsIsrThread);
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

NTAPI NTSYSAPI BOOLEAN KeRemoveEntryDeviceQueue(IN PKDEVICE_QUEUE Queue,
						IN PKDEVICE_QUEUE_ENTRY Entry);

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
    CCHAR StackSize;
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
    PVOID MappedSystemVa; /* Virtual address of the start of the buffer */
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
 * Client (ie. driver) side data structure for the IO request packet. This
 * structure defines the header of the IO request packet. It is followed by
 * one or more IO stack locations.
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
     * once the IRP has been completed. */
    PIO_STATUS_BLOCK UserIosb;

    /* Event object which will be signaled when the IRP is completed. */
    PKEVENT UserEvent;

    /* The priority boost that is to be added to the thread which
     * originally initiated this IO request when the IRP is completed */
    CHAR PriorityBoost;

    /* Total number of IO stack locations. Must be greater than zero. */
    CHAR StackCount;

    /* Current IO stack location. The stack grows downward (ie. toward lower
     * memory address). The stack top is at (StackCount + 1) which points to
     * the stack location immediately after the stack space. The stack location
     * for the highest-level driver has CurrentLocation == StackCount which
     * points to the stack location immediately below the stack top. As the
     * IRP is passed on to lower drivers, CurrentLocation decreases. The lowest-
     * level driver has CurrentLocation == 1 which points to the stack location
     * immediately after the IRP header. A newly allocation IRP has CurrentLocation
     * pointing to the stack top, indicating that its IO stack is empty. */
    CHAR CurrentLocation;

    /* Indicates that this IRP has been completed */
    BOOLEAN Completed;

    /* Indicates that a lower driver has returned pending in its dispatch routine */
    BOOLEAN PendingReturned;

    /* Indicates whether this IRP has been canceled */
    BOOLEAN Cancel;

    /* Cancel routine to call when canceling this IRP */
    PDRIVER_CANCEL CancelRoutine;

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
	PFILE_OBJECT CreatedFileObject;
	LIST_ENTRY Link;    /* List entry for IrpQueue, PendingIrpList,
			     * CleanupIrpList, and ReplyIrpList */
	LIST_ENTRY MasterPendingList; /* For master IRP, this is the list of
				       * all pending assoicated IRPs. */
	LIST_ENTRY AssociatedIrpLink;	/* For associated IRPs, this is the list link
					 * for PendingList. */
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
	     * available for driver use. */
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
    ULONG Flags;
    PVOID DriverStart;
    UNICODE_STRING RegistryPath;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PIO_CLIENT_EXTENSION ClientDriverExtension;
    LIST_ENTRY ReinitListHead;
    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO DriverStartIo;
    PDRIVER_ADD_DEVICE AddDevice;
    PDRIVER_UNLOAD DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
    LIST_ENTRY ListEntry;
} DRIVER_OBJECT, *PDRIVER_OBJECT;

/*
 * Driver reinitialize routine
 */
typedef VOID (NTAPI *PDRIVER_REINITIALIZE)(IN PDRIVER_OBJECT DriverObject,
					   IN OPTIONAL PVOID Context,
					   IN ULONG Count);

/*
 * This routine returns TRUE if the driver object is being loaded in its own
 * address space. Class and filter drivers can use this to determine whether
 * they should register global resources.
 */
FORCEINLINE BOOLEAN IoIsSingletonMode(IN PDRIVER_OBJECT DriverObject)
{
    return DriverObject->DriverStart == NtCurrentPeb()->ImageBaseAddress;
}

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
	    struct _STORAGE_REQUEST_BLOCK *Srb;
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
	    PIO_RESOURCE_REQUIREMENTS_LIST IoResourceRequirementList;
	} FilterResourceRequirements;
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

/*
 * Returns the full size of an IRP object including the header and the
 * IO stack location.
 */
FORCEINLINE NTAPI USHORT IoSizeOfIrp(IN CCHAR StackSize)
{
    return sizeof(IRP) + sizeof(IO_STACK_LOCATION) * StackSize;
}

/*
 * Note: The Irp object must be zeroed before calling this function.
 */
FORCEINLINE NTAPI VOID IoInitializeIrp(IN PIRP Irp,
				       IN USHORT PacketSize,
				       IN CCHAR StackSize)
{
    assert(StackSize > 0);
    assert(PacketSize >= IoSizeOfIrp(StackSize));
    /* Set the Header and other data */
    Irp->Type = IO_TYPE_IRP;
    Irp->Size = PacketSize;
    Irp->StackCount = StackSize;
    /* CurrentLocation points to the top of the IO stack, ie. immediately
     * after the IO stack space, indicating that the IO stack is empty. */
    Irp->CurrentLocation = StackSize + 1;
    InitializeListHead(&Irp->Private.MasterPendingList);
}

/*
 * Porting guide: remove the second parameter (ChargeQuota). In Windows this
 * parameter is used to determine whether IRP allocation should charge quota
 * against the process initiating the IO. This only makes sense if drivers
 * are running in kernel mode, so we have removed this parameter.
 */
FORCEINLINE NTAPI PIRP IoAllocateIrp(IN CCHAR StackSize)
{
    assert(StackSize > 0);
    PIRP Irp = (PIRP)ExAllocatePool(NonPagedPool, IoSizeOfIrp(StackSize));
    if (!Irp) {
	return NULL;
    }
    IoInitializeIrp(Irp, IoSizeOfIrp(StackSize), StackSize);
    return Irp;
}

NTAPI NTSYSAPI VOID IoReuseIrp(IN OUT PIRP Irp,
			       IN NTSTATUS Status);

NTAPI NTSYSAPI VOID IoFreeIrp(IN PIRP Irp);

FORCEINLINE NTAPI VOID IoFreeMdl(IN PMDL Mdl)
{
    while (Mdl) {
	PMDL Next = Mdl->Next;
	ExFreePool(Mdl);
	Mdl = Next;
    }
}

/*
 * Returns the current IO stack location pointer.
 */
FORCEINLINE NTAPI PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(IN PIRP Irp)
{
    assert(Irp->CurrentLocation >= 1);
    assert(Irp->CurrentLocation <= Irp->StackCount + 1);
    return (PIO_STACK_LOCATION)(Irp + 1) + Irp->CurrentLocation - 1;
}

/*
 * Skip the current IO stack location, ie. set the current IO stack
 * location to point to the one for the immediate higher-level driver.
 */
FORCEINLINE NTAPI VOID IoSkipCurrentIrpStackLocation(IN OUT PIRP Irp)
{
    assert(Irp->CurrentLocation >= 1);
    assert(Irp->CurrentLocation <= Irp->StackCount);
    Irp->CurrentLocation++;
}

/*
 * Set the IO stack location to point to the one immediately below the
 * current IO stack location.
 */
FORCEINLINE NTAPI VOID IoSetNextIrpStackLocation(IN OUT PIRP Irp)
{
    assert(Irp->CurrentLocation >= 2);
    assert(Irp->CurrentLocation <= Irp->StackCount + 1);
    Irp->CurrentLocation--;
}

/*
 * Returns the IO stack location immediately below the current IO stack
 * location.
 */
FORCEINLINE NTAPI PIO_STACK_LOCATION IoGetNextIrpStackLocation(IN PIRP Irp)
{
    assert(Irp->CurrentLocation >= 2);
    assert(Irp->CurrentLocation <= Irp->StackCount + 1);
    return IoGetCurrentIrpStackLocation(Irp) - 1;
}

/*
 * Copy the content in the current IO stack location to the next, ie. the
 * one for the lower-level driver immediately below the current driver.
 */
FORCEINLINE NTAPI VOID IoCopyCurrentIrpStackLocationToNext(IN OUT PIRP Irp)
{
    assert(Irp->CurrentLocation >= 2);
    assert(Irp->CurrentLocation <= Irp->StackCount);
    PIO_STACK_LOCATION Current = IoGetCurrentIrpStackLocation(Irp);
    PIO_STACK_LOCATION Next = IoGetNextIrpStackLocation(Irp);
    RtlCopyMemory(Next, Current, sizeof(IO_STACK_LOCATION));
    Next->CompletionRoutine = NULL;
    Next->Control = 0;
    if (Next->DeviceObject) {
	ObReferenceObject(Next->DeviceObject);
    }
    if (Next->FileObject) {
	ObReferenceObject(Next->FileObject);
    }
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

NTAPI NTSYSAPI NTSTATUS IoGetDevicePropertyData(IN PDEVICE_OBJECT Pdo,
						IN CONST DEVPROPKEY *PropertyKey,
						IN LCID Lcid,
						IN ULONG Flags,
						IN ULONG Size,
						OUT PVOID Data,
						OUT PULONG RequiredSize,
						OUT PDEVPROPTYPE Type);

NTAPI NTSYSAPI NTSTATUS IoCreateSymbolicLink(IN PUNICODE_STRING SymbolicLinkName,
					     IN PUNICODE_STRING DeviceName);

NTAPI NTSYSAPI NTSTATUS IoDeleteSymbolicLink(IN PUNICODE_STRING SymbolicLinkName);

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
    if (!Mdl) {
	return NULL;
    }
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

NTAPI NTSYSAPI PMDL IoBuildPartialMdl(IN PMDL SourceMdl,
				      IN PVOID VirtualAddress,
				      IN ULONG Length);

NTAPI NTSYSAPI PMDL IoAllocateMdl(IN PVOID VirtualAddress,
				  IN ULONG Length);

NTAPI NTSYSAPI PIRP IoBuildDeviceIoControlRequest(IN ULONG IoControlCode,
						  IN PDEVICE_OBJECT DeviceObject,
						  IN PVOID InputBuffer,
						  IN ULONG InputBufferLength,
						  IN PVOID OutputBuffer,
						  IN ULONG OutputBufferLength,
						  IN BOOLEAN InternalDeviceIoControl,
						  IN OPTIONAL PKEVENT Event,
						  IN OPTIONAL PIO_STATUS_BLOCK IoStatusBlock);

NTAPI NTSYSAPI PIRP IoBuildAsynchronousFsdRequest(IN ULONG MajorFunction,
						  IN PDEVICE_OBJECT DeviceObject,
						  IN PVOID Buffer,
						  IN ULONG Length,
						  IN PLARGE_INTEGER StartingOffset,
						  IN OPTIONAL PIO_STATUS_BLOCK IoStatusBlock);

NTAPI NTSYSAPI PIRP IoBuildSynchronousFsdRequest(IN ULONG MajorFunction,
						 IN PDEVICE_OBJECT DeviceObject,
						 IN PVOID Buffer,
						 IN ULONG Length,
						 IN PLARGE_INTEGER StartingOffset,
						 IN PKEVENT Event,
						 IN PIO_STATUS_BLOCK IoStatusBlock);

NTAPI NTSYSAPI NTSTATUS IoCallDriver(IN PDEVICE_OBJECT DeviceObject,
				     IN OUT PIRP Irp);

/*
 * @implemented
 *
 * Forward the IRP to the device object and wait for its completion.
 */
NTAPI NTSYSAPI BOOLEAN IoForwardIrpSynchronously(IN PDEVICE_OBJECT DeviceObject,
						 IN PIRP Irp);

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
 * Power management support routines
 */

NTAPI NTSYSAPI BOOLEAN PoQueryWatchdogTime(IN PDEVICE_OBJECT Pdo,
					   OUT PULONG SecondsRemaining);

NTAPI NTSYSAPI NTSTATUS PoRegisterPowerSettingCallback(IN OPTIONAL PDEVICE_OBJECT DeviceObject,
						       IN LPCGUID SettingGuid,
						       IN PPOWER_SETTING_CALLBACK Callback,
						       IN OPTIONAL PVOID Context,
						       OUT OPTIONAL PVOID *Handle);

NTAPI NTSYSAPI NTSTATUS PoUnregisterPowerSettingCallback(IN OUT PVOID Handle);

typedef struct _IO_WORKITEM *PIO_WORKITEM;

typedef VOID (NTAPI IO_WORKITEM_ROUTINE)(IN PDEVICE_OBJECT DeviceObject,
					 IN OPTIONAL PVOID Context);
typedef IO_WORKITEM_ROUTINE *PIO_WORKITEM_ROUTINE;

typedef VOID (NTAPI IO_WORKITEM_ROUTINE_EX)(IN PVOID IoObject,
					    IN OPTIONAL PVOID Context,
					    IN PIO_WORKITEM IoWorkItem);
typedef IO_WORKITEM_ROUTINE_EX *PIO_WORKITEM_ROUTINE_EX;

/*
 * IO work item object.
 */
typedef struct _IO_WORKITEM {
    PDEVICE_OBJECT DeviceObject;
    LIST_ENTRY QueueEntry;
    union {
	PIO_WORKITEM_ROUTINE WorkerRoutine;
	PIO_WORKITEM_ROUTINE_EX WorkerRoutineEx;
    };
    PVOID Context;
    BOOLEAN Queued;
    BOOLEAN ExtendedRoutine; /* TRUE if the union above is WorkerRoutineEx */
} IO_WORKITEM;

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
 * Work item allocation. This routine allocates and initializes the work item, so
 * you do not need to call IoInitializeWorkItem for the object you just allocated.
 */
NTAPI NTSYSAPI PIO_WORKITEM IoAllocateWorkItem(IN PDEVICE_OBJECT DeviceObject);

/*
 * Work item initialization. You should only call this routine if you allocate the
 * space for the IO_WORKITEM yourself.
 */
NTAPI VOID IoInitializeWorkItem(IN PDEVICE_OBJECT DeviceObject,
				OUT PIO_WORKITEM WorkItem);

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

NTAPI NTSYSAPI VOID IoQueueWorkItemEx(IN OUT PIO_WORKITEM IoWorkItem,
				      IN PIO_WORKITEM_ROUTINE_EX WorkerRoutine,
				      IN WORK_QUEUE_TYPE QueueType,
				      IN OPTIONAL PVOID Context);


/*
 * TIMER object. Note: just like KDPC despite being called 'KTIMER'
 * this is the client-side handle to the server side KTIMER object.
 * There is no name collision because the NTOS server does not
 * include files under public/ddk.
 */
typedef struct POINTER_ALIGNMENT _KTIMER {
    WAITABLE_OBJECT_HEADER Header;	/* Must be first member. */
    union {
	PKDPC Dpc;
	PIO_WORKITEM WorkItem;
    };
    PIO_WORKITEM_ROUTINE WorkerRoutine;
    PVOID WorkerContext;
    ULONGLONG AbsoluteDueTime;
    LONG Period;
    BOOLEAN State;
    BOOLEAN LowPriority;    /* If TRUE, the union is a PIO_WORKITEM */
} KTIMER, *PKTIMER;

/*
 * Timer routines
 */
NTAPI NTSYSAPI VOID KeInitializeTimer(OUT PKTIMER Timer);

NTAPI NTSYSAPI BOOLEAN KeSetTimer(IN OUT PKTIMER Timer,
				  IN LARGE_INTEGER DueTime,
				  IN OPTIONAL PKDPC Dpc);

NTAPI NTSYSAPI BOOLEAN KeSetTimerEx(IN OUT PKTIMER Timer,
				    IN LARGE_INTEGER DueTime,
				    IN LONG Period,
				    IN OPTIONAL PKDPC Dpc);

NTAPI BOOLEAN KeSetLowPriorityTimer(IN OUT PKTIMER Timer,
				    IN LARGE_INTEGER DueTime,
				    IN LONG Period,
				    IN PIO_WORKITEM WorkItem,
				    IN PIO_WORKITEM_ROUTINE WorkerRoutine,
				    IN OPTIONAL PVOID WorkerContext);

NTAPI NTSYSAPI BOOLEAN KeCancelTimer(IN OUT PKTIMER Timer);

/*
 * System time and interrupt time routines
 */
NTAPI NTSYSAPI VOID KeQuerySystemTime(OUT PLARGE_INTEGER CurrentTime);
NTAPI NTSYSAPI ULONGLONG KeQueryInterruptTime(VOID);
NTAPI NTSYSAPI VOID KeQueryTickCount(OUT PLARGE_INTEGER CurrentCount);
NTAPI NTSYSAPI ULONG KeQueryTimeIncrement(VOID);

/*
 * Stalls the current processor for the given microseconds. This is the preferred
 * routine to call if you want to stall the processor for a small amount of time
 * without involving the scheduler, for instance, in an interrupt service routine.
 */
NTAPI NTSYSAPI VOID KeStallExecutionProcessor(ULONG MicroSeconds);

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
 * Returns the pointer to the highest level device object in a device stack and
 * increase the reference count of the attached device object.
 */
NTAPI NTSYSAPI PDEVICE_OBJECT IoGetAttachedDeviceReference(IN PDEVICE_OBJECT DeviceObject);

/*
 * PNP device relation list, which is simply an array of (physical) device objects.
 */
typedef struct _DEVICE_RELATIONS {
    ULONG Count;
    PDEVICE_OBJECT Objects[];
} DEVICE_RELATIONS, *PDEVICE_RELATIONS;

NTAPI NTSYSAPI VOID IoInvalidateDeviceRelations(IN PDEVICE_OBJECT DeviceObject,
						IN DEVICE_RELATION_TYPE Type);

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

typedef enum _BUS_DATA_TYPE {
    ConfigurationSpaceUndefined = -1,
    Cmos,
    EisaConfiguration,
    Pos,
    CbusConfiguration,
    PCIConfiguration,
    VMEConfiguration,
    NuBusConfiguration,
    PCMCIAConfiguration,
    MPIConfiguration,
    MPSAConfiguration,
    PNPISAConfiguration,
    SgiInternalConfiguration,
    MaximumBusDataType
} BUS_DATA_TYPE, *PBUS_DATA_TYPE;

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

NTSYSAPI PCONFIGURATION_INFORMATION IoGetConfigurationInformation();

typedef struct _DISK_SIGNATURE {
    ULONG PartitionStyle;
    union {
	struct {
	    ULONG Signature;
	    ULONG CheckSum;
	} Mbr;
	struct {
	    GUID DiskId;
	} Gpt;
    };
} DISK_SIGNATURE, *PDISK_SIGNATURE;

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
typedef PVOID (NTAPI *PALLOCATE_FUNCTION)(IN POOL_TYPE PoolType,
					  IN SIZE_T NumberOfBytes,
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
						 IN ULONG Tag)
{
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
	Entry = Lookaside->Allocate(NonPagedPool, Lookaside->Size, Lookaside->Tag);
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

FORCEINLINE NTAPI VOID ExDeleteLookasideList(IN PLOOKASIDE_LIST Lookaside)
{
    /* Pop all entries off the stack and release their resources */
    while (TRUE) {
	PVOID Entry = RtlInterlockedPopEntrySList(&Lookaside->ListHead);
        if (!Entry) {
	    break;
	}
        (*Lookaside->Free)(Entry);
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
    PIO_STACK_LOCATION IoStack = IoGetNextIrpStackLocation(Irp);
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

FORCEINLINE VOID IoSetMasterIrpStatus(IN OUT PIRP MasterIrp,
				      IN NTSTATUS Status)
{
    NTSTATUS MasterStatus = MasterIrp->IoStatus.Status;

    if (Status == STATUS_FT_READ_FROM_COPY) {
        return;
    }

    if ((Status == STATUS_VERIFY_REQUIRED) ||
        (MasterStatus == STATUS_SUCCESS && !NT_SUCCESS(Status)) ||
        (!NT_SUCCESS(MasterStatus) && !NT_SUCCESS(Status) && Status > MasterStatus)) {
        MasterIrp->IoStatus.Status = Status;
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

typedef ULONGLONG REGHANDLE, *PREGHANDLE;

#define MAX_EVENT_DATA_DESCRIPTORS           (128)
#define MAX_EVENT_FILTER_DATA_SIZE           (1024)

#define EVENT_FILTER_TYPE_SCHEMATIZED        (0x80000000)

typedef struct _EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Reserved;
} EVENT_DATA_DESCRIPTOR, *PEVENT_DATA_DESCRIPTOR;

typedef struct _EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR, *PEVENT_DESCRIPTOR;
typedef const EVENT_DESCRIPTOR *PCEVENT_DESCRIPTOR;

typedef struct _EVENT_FILTER_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Type;
} EVENT_FILTER_DESCRIPTOR, *PEVENT_FILTER_DESCRIPTOR;

typedef struct _EVENT_FILTER_HEADER {
    USHORT Id;
    UCHAR Version;
    UCHAR Reserved[5];
    ULONGLONG InstanceId;
    ULONG Size;
    ULONG NextOffset;
} EVENT_FILTER_HEADER, *PEVENT_FILTER_HEADER;

typedef VOID (NTAPI *WMI_NOTIFICATION_CALLBACK)(PVOID Wnode,
						PVOID Context);

typedef VOID (NTAPI *PETWENABLECALLBACK)(IN LPCGUID SourceId,
					 IN ULONG ControlCode,
					 IN UCHAR Level,
					 IN ULONGLONG MatchAnyKeyword,
					 IN ULONGLONG MatchAllKeyword,
					 IN OPTIONAL PEVENT_FILTER_DESCRIPTOR FilterData,
					 IN OUT OPTIONAL PVOID CallbackContext);

NTAPI NTSYSAPI NTSTATUS IoWMIRegistrationControl(IN PDEVICE_OBJECT DeviceObject,
						 IN ULONG Action);

NTAPI NTSYSAPI ULONG IoWMIDeviceObjectToProviderId(IN PDEVICE_OBJECT DeviceObject);

NTAPI NTSYSAPI NTSTATUS IoWMIWriteEvent(IN OUT PVOID WnodeEventItem);

NTAPI NTSYSAPI NTSTATUS IoWMIOpenBlock(IN LPCGUID DataBlockGuid,
				       IN ULONG DesiredAccess,
				       OUT HANDLE *DataBlockObject);

NTAPI NTSYSAPI NTSTATUS IoWMIQueryAllData(IN HANDLE DataBlockObject,
					  IN OUT ULONG *InOutBufferSize,
					  OUT PVOID OutBuffer);

NTAPI NTSYSAPI NTSTATUS EtwRegister(IN LPCGUID ProviderId,
				    IN OPTIONAL PETWENABLECALLBACK EnableCallback,
				    IN OPTIONAL PVOID CallbackContext,
				    OUT PREGHANDLE RegHandle);

NTAPI NTSYSAPI NTSTATUS EtwUnregister(IN REGHANDLE RegHandle);

NTAPI NTSYSAPI NTSTATUS EtwWrite(IN REGHANDLE RegHandle,
				 IN PCEVENT_DESCRIPTOR EventDescriptor,
				 IN OPTIONAL LPCGUID ActivityId,
				 IN ULONG UserDataCount,
				 IN PEVENT_DATA_DESCRIPTOR UserData);

FORCEINLINE VOID EventDataDescCreate(OUT PEVENT_DATA_DESCRIPTOR EventDataDescriptor,
				     IN const VOID* DataPtr,
				     IN ULONG DataSize)
{
    EventDataDescriptor->Ptr = (ULONGLONG)(ULONG_PTR)DataPtr;
    EventDataDescriptor->Size = DataSize;
    EventDataDescriptor->Reserved = 0;
}

FORCEINLINE VOID EventDescCreate(OUT PEVENT_DESCRIPTOR EventDescriptor,
				 IN USHORT Id,
				 IN UCHAR Version,
				 IN UCHAR Channel,
				 IN UCHAR Level,
				 IN USHORT Task,
				 IN UCHAR Opcode,
				 IN ULONGLONG Keyword)
{
    EventDescriptor->Id = Id;
    EventDescriptor->Version = Version;
    EventDescriptor->Channel = Channel;
    EventDescriptor->Level = Level;
    EventDescriptor->Task = Task;
    EventDescriptor->Opcode = Opcode;
    EventDescriptor->Keyword = Keyword;
}

FORCEINLINE VOID EventDescZero(OUT PEVENT_DESCRIPTOR EventDescriptor)
{
    memset(EventDescriptor, 0, sizeof(EVENT_DESCRIPTOR));
}

FORCEINLINE USHORT EventDescGetId(IN PCEVENT_DESCRIPTOR EventDescriptor)
{
    return EventDescriptor->Id;
}

FORCEINLINE UCHAR EventDescGetVersion(IN PCEVENT_DESCRIPTOR EventDescriptor)
{
    return EventDescriptor->Version;
}

FORCEINLINE USHORT EventDescGetTask(IN PCEVENT_DESCRIPTOR EventDescriptor)
{
    return EventDescriptor->Task;
}

FORCEINLINE UCHAR EventDescGetOpcode(IN PCEVENT_DESCRIPTOR EventDescriptor)
{
    return EventDescriptor->Opcode;
}

FORCEINLINE UCHAR EventDescGetChannel(IN PCEVENT_DESCRIPTOR EventDescriptor)
{
    return EventDescriptor->Channel;
}

FORCEINLINE UCHAR EventDescGetLevel(IN PCEVENT_DESCRIPTOR EventDescriptor)
{
    return EventDescriptor->Level;
}

FORCEINLINE ULONGLONG EventDescGetKeyword(IN PCEVENT_DESCRIPTOR EventDescriptor)
{
    return EventDescriptor->Keyword;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescSetId(IN PEVENT_DESCRIPTOR EventDescriptor,
					     IN USHORT Id)
{
    EventDescriptor->Id = Id;
    return EventDescriptor;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescSetVersion(IN PEVENT_DESCRIPTOR EventDescriptor,
						  IN UCHAR Version)
{
    EventDescriptor->Version = Version;
    return EventDescriptor;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescSetTask(IN PEVENT_DESCRIPTOR EventDescriptor,
					       IN USHORT Task)
{
    EventDescriptor->Task = Task;
    return EventDescriptor;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescSetOpcode(IN PEVENT_DESCRIPTOR EventDescriptor,
						 IN UCHAR Opcode)
{
    EventDescriptor->Opcode = Opcode;
    return EventDescriptor;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescSetLevel(IN PEVENT_DESCRIPTOR EventDescriptor,
						IN UCHAR  Level)
{
    EventDescriptor->Level = Level;
    return EventDescriptor;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescSetChannel(IN PEVENT_DESCRIPTOR EventDescriptor,
						  IN UCHAR Channel)
{
    EventDescriptor->Channel = Channel;
    return EventDescriptor;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescSetKeyword(IN PEVENT_DESCRIPTOR EventDescriptor,
						  IN ULONGLONG Keyword)
{
    EventDescriptor->Keyword = Keyword;
    return EventDescriptor;
}

FORCEINLINE PEVENT_DESCRIPTOR EventDescOrKeyword(IN PEVENT_DESCRIPTOR EventDescriptor,
						 IN ULONGLONG Keyword)
{
    EventDescriptor->Keyword |= Keyword;
    return EventDescriptor;
}


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

typedef struct _TARGET_DEVICE_CUSTOM_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
    PFILE_OBJECT FileObject;
    LONG NameBufferOffset;
    UCHAR CustomDataBuffer[1];
} TARGET_DEVICE_CUSTOM_NOTIFICATION, *PTARGET_DEVICE_CUSTOM_NOTIFICATION;

typedef struct _TARGET_DEVICE_REMOVAL_NOTIFICATION {
    USHORT Version;
    USHORT Size;
    GUID Event;
    PFILE_OBJECT FileObject;
} TARGET_DEVICE_REMOVAL_NOTIFICATION, *PTARGET_DEVICE_REMOVAL_NOTIFICATION;

typedef VOID (NTAPI DEVICE_CHANGE_COMPLETE_CALLBACK)(IN OUT OPTIONAL PVOID Context);
typedef DEVICE_CHANGE_COMPLETE_CALLBACK *PDEVICE_CHANGE_COMPLETE_CALLBACK;

NTAPI NTSYSAPI NTSTATUS
IoReportTargetDeviceChangeAsynchronous(IN PDEVICE_OBJECT Pdo,
				       IN PVOID Notification,
				       IN OPTIONAL PDEVICE_CHANGE_COMPLETE_CALLBACK Callback,
				       IN OPTIONAL PVOID Context);

#define IoAdjustPagingPathCount(_Count, _Increment)	\
    {							\
	if (_Increment) {				\
	    InterlockedIncrement(_Count);		\
	} else {					\
	    InterlockedDecrement(_Count);		\
	}						\
    }

NTAPI NTSYSAPI PVOID IoAllocateErrorLogEntry(IN PVOID IoObject,
					     IN UCHAR EntrySize);
NTAPI NTSYSAPI VOID IoWriteErrorLogEntry(IN PVOID ElEntry);

FORCEINLINE USHORT KeQueryHighestNodeNumber()
{
    return 0;
}

FORCEINLINE USHORT KeGetCurrentNodeNumber()
{
    return 0;
}

FORCEINLINE IO_PRIORITY_HINT IoGetIoPriorityHint(IN PIRP Irp)
{
    return IoPriorityNormal;
}
