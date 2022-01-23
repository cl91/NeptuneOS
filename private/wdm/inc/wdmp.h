#pragma once

#include <nt.h>
#include <wdm.h>
#include <assert.h>
#include <debug.h>
#include <util.h>
#include <wdmsvc.h>
#include <wdm_wdmsvc_gen.h>
#include <irp.h>

#define TAG_DRIVER_EXTENSION	'EVRD'
#define TAG_REINIT		'iRoI'
#define TAG_SYS_BUF		'BSYS'

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

/* Prevent the compiler from inlining the function */
#define NO_INLINE	__attribute__((noinline))

/* Inform the compiler that the function does not return */
#define NORETURN	__attribute__((__noreturn__))

/* Shared kernel data that is accessible from user space */
#define SharedUserData ((KUSER_SHARED_DATA *CONST) KUSER_SHARED_DATA_CLIENT_ADDR)

#define IopAllocatePoolEx(Ptr, Type, Size, OnError)		\
    Type *Ptr = (Type *) RtlAllocateHeap(RtlGetProcessHeap(),	\
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
 * An entry in the list of files created by this driver.
 * The Handle member is a global handle to the NTOS Executive's IO_FILE_OBJECT.
 */
typedef struct _FILE_LIST_ENTRY {
    PFILE_OBJECT Object;    /* Points to the driver readable object */
    GLOBAL_HANDLE Handle;   /* Unique handle supplied by the server */
    LIST_ENTRY Link; /* List entry for the list of all known file objects */
} FILE_LIST_ENTRY, *PFILE_LIST_ENTRY;

/*
 * An entry in the list of devices created by this driver.
 * The Handle member is a global handle to the NTOS Executive's IO_DEVICE_OBJECT.
 */
typedef struct _DEVICE_LIST_ENTRY {
    PDEVICE_OBJECT Object;  /* Points to the driver readable object */
    GLOBAL_HANDLE Handle;   /* Unique handle supplied by the server */
    LIST_ENTRY Link; /* List entry for the list of all known device objects */
} DEVICE_LIST_ENTRY, *PDEVICE_LIST_ENTRY;

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
} X86_IOPORT, *PX86_IOPORT;

/*
 * IO work item object.
 */
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _IO_WORKITEM {
    SLIST_ENTRY Entry;	 /* Must be first, or at least aligned by 8 */
    union {
	PDEVICE_OBJECT DeviceObject;
	PDRIVER_OBJECT DriverObject;
    };
    union {
	PIO_WORKITEM_ROUTINE WorkerRoutine;
	PIO_WORKITEM_ROUTINE_EX WorkerRoutineEx;
    };
    PVOID Context;
    BOOLEAN ExtendedRoutine; /* TRUE if the union above is WorkerRoutineEx */
} IO_WORKITEM;

/*
 * Lightweight mutex, used to synchronize data shared between two driver threads.
 *
 * This is used to implement what the Windows driver model calls the "interrupt
 * spinlock", which protects data structures accessed by both the dispatch routines
 * and the interrupt service routines. We cannot use a spinlock here since our
 * drivers runs in a userspace process.
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
	seL4_Wait(Mutex->Notification, NULL);
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
	seL4_Signal(Mutex->Notification);
    }
}

/*
 * Interrupt object.
 */
typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) _KINTERRUPT {
    SLIST_ENTRY Entry; /* Must be first, or at least aligned by 8 bytes */
    KMUTEX Mutex;
    PKSERVICE_ROUTINE ServiceRoutine;
    PVOID ServiceContext;
    ULONG Vector;
    KIRQL Irql;
    KIRQL SynchronizeIrql;
    KINTERRUPT_MODE InterruptMode;
} KINTERRUPT;

/* device.c */
extern LIST_ENTRY IopDeviceList;
PDEVICE_OBJECT IopGetDeviceObject(IN GLOBAL_HANDLE Handle);
GLOBAL_HANDLE IopGetDeviceHandle(IN PDEVICE_OBJECT Device);

/* irp.c */
extern PIO_PACKET IopIncomingIoPacketBuffer;
extern PIO_PACKET IopOutgoingIoPacketBuffer;
extern LIST_ENTRY IopIrpQueue;
extern LIST_ENTRY IopFileObjectList;
extern LIST_ENTRY IopCompletedIrpList;
extern LIST_ENTRY IopForwardedIrpList;
extern LIST_ENTRY IopCleanupIrpList;
VOID IopProcessIoPackets(OUT ULONG *pNumResponses,
			 IN ULONG NumRequests);

/* isr.c */
extern SLIST_HEADER IopDpcQueue;
extern SLIST_HEADER IopInterruptServiceRoutineList;

/* ioport.c */
extern LIST_ENTRY IopX86PortList;

/* main.c */
extern DRIVER_OBJECT IopDriverObject;

/* timer.c */
extern LIST_ENTRY IopTimerList;
extern ULONG KiStallScaleFactor;

/* workitem.c */
extern SLIST_HEADER IopWorkItemQueue;
