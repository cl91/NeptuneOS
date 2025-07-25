#pragma once

#include <ntddk.h>
#include <ntifs.h>
#include <hal.h>
#include <assert.h>
#include <debug.h>
#include "coroutine.h"

#include <util.h>
#include <wdmsvc.h>
#include <wdm_wdmsvc_gen.h>

#define TAG_DRIVER_EXTENSION	'EVRD'
#define TAG_REINIT		'iRoI'
#define TAG_SYS_BUF		'BSYS'

#define CONTROL_KEY_NAME L"\\Registry\\Machine\\System\\CurrentControlSet\\"

/* Shared kernel data that is accessible from user space */
#define SharedUserData ((const volatile KUSER_SHARED_DATA *const) KUSER_SHARED_DATA_CLIENT_ADDR)

#define IopAllocatePoolEx(Ptr, Type, Size, OnError)		\
    Type *Ptr = (Type *)RtlAllocateHeap(RtlGetProcessHeap(),	\
					HEAP_ZERO_MEMORY,	\
					Size);			\
    if (Ptr == NULL) {						\
	OnError;						\
	return STATUS_NO_MEMORY;				\
    }

#define IopAllocatePool(Ptr, Type, Size)	\
    IopAllocatePoolEx(Ptr, Type, Size, {})

#define IopAllocateObjectEx(Ptr, Type, OnError)		\
    IopAllocatePoolEx(Ptr, Type, sizeof(Type), OnError)

#define IopAllocateObject(Ptr, Type)		\
    IopAllocateObjectEx(Ptr, Type, {})

#define IopFreePool(Ptr)			\
    RtlFreeHeap(RtlGetProcessHeap(), 0, Ptr)

/*
 * Open the specified registry key
 */
static inline NTSTATUS IopOpenKey(IN UNICODE_STRING Key,
				  OUT HANDLE *KeyHandle)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, &Key,
			       OBJ_CASE_INSENSITIVE, NULL, NULL);
    TRACE_(NTOSPNP, "Opening key %wZ\n", &Key);
    return NtOpenKey(KeyHandle, KEY_READ, &ObjectAttributes);
}


static inline NTSTATUS IopQueryValueKey(IN HANDLE KeyHandle,
					IN PWCHAR ValueName,
					OUT PKEY_VALUE_PARTIAL_INFORMATION *PartialInfo)
{
    ULONG BufferSize;
    UNICODE_STRING ValueNameU;
    RtlInitUnicodeString(&ValueNameU, ValueName);
    NTSTATUS Status = NtQueryValueKey(KeyHandle, &ValueNameU,
				      KeyValuePartialInformation,
				      NULL, 0, &BufferSize);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
	return Status;
    }

    *PartialInfo = ExAllocatePool(BufferSize);
    if (!*PartialInfo) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = NtQueryValueKey(KeyHandle, &ValueNameU,
			     KeyValuePartialInformation, *PartialInfo,
			     BufferSize, &BufferSize);
    if (!NT_SUCCESS(Status)) {
	ExFreePool(*PartialInfo);
    }
    return Status;
}

/*
 * Driver Re-Initialization Entry
 */
typedef struct _DRIVER_REINIT_ITEM {
    LIST_ENTRY ItemEntry;
    PDRIVER_OBJECT DriverObject;
    PDRIVER_REINITIALIZE ReinitRoutine;
    PVOID Context;
    ULONG Count;
} DRIVER_REINIT_ITEM, *PDRIVER_REINIT_ITEM;

/*
 * X86 IO port object
 */
typedef struct _X86_IOPORT {
    MWORD Cap;
    LIST_ENTRY Link;
    USHORT PortNum;
    USHORT Count;
} X86_IOPORT, *PX86_IOPORT;

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
 * Lightweight mutex, used to synchronize data shared between two driver threads.
 *
 * This is used to implement what the Windows driver model calls the "interrupt
 * spinlock", which protects data structures accessed by both the dispatch routines
 * and the interrupt service routines. We don't want to use spinlocks here since our
 * drivers runs in a userspace process (and may get scheduled out).
 */
typedef struct POINTER_ALIGNMENT _KMUTEX {
    MWORD Notification;		/* Notification capability */
    LONG Counter;		/* 0 -- Mutex available.
				 * >= 1 -- Lock is held. Number indicates
				 * number of contenting threads. */
} KMUTEX, *PKMUTEX;

static inline VOID KeInitializeMutex(IN PKMUTEX Mutex,
				     IN MWORD Cap)
{
    assert(Mutex != NULL);
    Mutex->Notification = Cap;
    Mutex->Counter = 0;
}

/*
 * Acquire the lock. If the lock is free, simply acquire the lock and return.
 * If the lock has already been acquired by another thread, wait on the notification
 * object.
 */
static inline VOID KeAcquireMutex(IN PKMUTEX Mutex)
{
    assert(Mutex != NULL);
    assert(Mutex->Notification != 0);
    if (InterlockedIncrement(&Mutex->Counter) != 1) {
	seL4_Wait(RtlGetGuardedCapInProcessCNode(Mutex->Notification), NULL);
    }
}

/*
 * Release the mutex that is previously acquired. Note that you must only call
 * this function after you have acquired the mutex (KeTryAcquireMutex returns TRUE).
 * On debug build we assert if this has not been enforced.
 */
static inline VOID KeReleaseMutex(IN PKMUTEX Mutex)
{
    assert(Mutex != NULL);
    assert(Mutex->Notification != 0);
    LONG Counter = InterlockedDecrement(&Mutex->Counter);
    assert(Counter >= 0);
    if (Counter >= 1) {
	seL4_Signal(RtlGetGuardedCapInProcessCNode(Mutex->Notification));
    }
}

/*
 * Interrupt object.
 */
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _KINTERRUPT {
    ULONG Vector;
    KIRQL Irql;
    KIRQL SynchronizeIrql;
    KINTERRUPT_MODE InterruptMode;
    KMUTEX Mutex;
    PKSERVICE_ROUTINE ServiceRoutine;
    PVOID ServiceContext;
    HANDLE ThreadHandle;
    MWORD IrqHandlerCap;
    MWORD NotificationCap;
} KINTERRUPT;

/* cache.c */
VOID CiInitialzeCacheManager();
ULONG CiProcessDirtyBufferList(IN ULONG RemainingBufferSize,
			       IN PIO_PACKET DestIrp);
ULONG CiProcessFlushCacheRequestList(IN ULONG RemainingBufferSize,
				     IN PIO_PACKET DestIrp);
VOID CiHandleCacheFlushedServerMessage(PIO_PACKET SrvMsg);

/* device.c */
extern LIST_ENTRY IopDeviceList;
PDEVICE_OBJECT IopGetDeviceObject(IN GLOBAL_HANDLE Handle);
GLOBAL_HANDLE IopGetDeviceHandle(IN PDEVICE_OBJECT Device);
PDEVICE_OBJECT IopGetDeviceObjectOrCreate(IN GLOBAL_HANDLE DeviceHandle,
					  IN IO_DEVICE_INFO DevInfo,
					  IN CHAR StackSize);

/* dma.c */
VOID HalpInitDma(VOID);

/* driver.c */
NTSTATUS IopInitDriverObject(IN PUNICODE_STRING RegistryPath);
PDRIVER_OBJECT IopLocateDriverObject(IN PCSTR BaseName);
NTSTATUS IopLoadDriver(IN PCSTR BaseName);

/* event.c */
BOOLEAN KiSignalWaitableObject(IN PWAITABLE_OBJECT_HEADER Object,
			       IN BOOLEAN AcquireLock);
BOOLEAN KiCancelWaitableObject(IN PWAITABLE_OBJECT_HEADER Object,
			       IN BOOLEAN AcquireLock);

/* file.c */
extern LIST_ENTRY IopFileObjectList;
NTSTATUS IopCreateFileObject(IN PIO_PACKET IoPacket,
			     IN PDEVICE_OBJECT DeviceObject,
			     IN PFILE_OBJECT_CREATE_PARAMETERS Params,
			     IN GLOBAL_HANDLE Handle,
			     OUT PFILE_OBJECT *pFileObject);
VOID IopDeleteFileObject(IN PFILE_OBJECT FileObject);

/* irp.c */
extern PIO_PACKET IopIncomingIoPacketBuffer;
extern PIO_PACKET IopOutgoingIoPacketBuffer;
extern LIST_ENTRY IopSignaledObjectList;
extern LIST_ENTRY IopExecEnvList;
extern PIOP_EXEC_ENV IopCurrentEnv;
VOID IopInitIrpProcessing();
VOID IopProcessIoPackets(OUT ULONG *pNumResponses,
			 IN ULONG NumRequests);
VOID IoDbgDumpIrp(IN PIRP Irp);

/* isr.c */
extern LIST_ENTRY IopDpcQueue;
extern KMUTEX IopDpcMutex;
VOID IopSignalDpcNotification();
VOID IopInitializeDpcThread();

/* ioport.c */
extern LIST_ENTRY IopX86PortList;

/* timer.c */
extern LIST_ENTRY IopPendingTimerList;
extern ULONG KiStallScaleFactor;
VOID IopProcessTimerList();

/* workitem.c */
extern LIST_ENTRY IopWorkItemQueue;
extern LIST_ENTRY IopSuspendedWorkItemList;
extern KMUTEX IopWorkItemMutex;
VOID IopProcessWorkItemQueue();
BOOLEAN IopWorkItemIsInSuspendedList(IN PIO_WORKITEM Item);
VOID IopDbgDumpWorkItem(IN PIO_WORKITEM WorkItem);

FORCEINLINE BOOLEAN IopDeviceObjectIsLocal(IN PDEVICE_OBJECT DeviceObject)
{
    assert(DeviceObject);
    return DeviceObject->DriverObject;
}

/*
 * Search the list of all files created by this driver and return
 * the one matching the given GLOBAL_HANDLE. Returns NULL if not found.
 */
FORCEINLINE PFILE_OBJECT IopGetFileObject(IN GLOBAL_HANDLE Handle)
{
    LoopOverList(Object, &IopFileObjectList, FILE_OBJECT, Private.Link) {
	if (Handle == Object->Header.GlobalHandle) {
	    return Object;
	}
    }
    return NULL;
}

FORCEINLINE GLOBAL_HANDLE IopGetFileHandle(IN PFILE_OBJECT File)
{
    return File ? File->Header.GlobalHandle : 0;
}

typedef enum _CLIENT_OBJECT_TYPE {
    CLIENT_OBJECT_TIMER,
    CLIENT_OBJECT_EVENT,
    CLIENT_OBJECT_DEVICE,
    CLIENT_OBJECT_FILE
} CLIENT_OBJECT_TYPE;

FORCEINLINE BOOLEAN ObjectTypeIsWaitable(IN CLIENT_OBJECT_TYPE Ty)
{
    return Ty == CLIENT_OBJECT_TIMER || Ty == CLIENT_OBJECT_EVENT;
}

#define ObInitializeObject(Obj, Ty, TyName)	\
    {						\
	(Obj)->Header.Type = Ty;		\
	(Obj)->Header.Flags = 0;		\
	(Obj)->Header.Size = sizeof(TyName);	\
	(Obj)->Header.RefCount = 1;		\
    }

FORCEINLINE LONG ObGetObjectRefCount(PVOID Obj)
{
    return ((POBJECT_HEADER)Obj)->RefCount;
}
