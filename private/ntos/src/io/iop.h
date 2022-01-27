#pragma once

#include <nt.h>
#include <ntos.h>
#include <wdmsvc.h>

#define NTOS_IO_TAG	(EX_POOL_TAG('n','t','i','o'))

#define IopAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_IO_TAG, OnError)
#define IopAllocatePool(Var, Type)	IopAllocatePoolEx(Var, Type, {})
#define IopAllocateArrayEx(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_IO_TAG, OnError)
#define IopAllocateArray(Var, Type, Size)	\
    IopAllocateArrayEx(Var, Type, Size, {})

static inline NTSTATUS IopAllocateIoPacket(IN IO_PACKET_TYPE Type,
					   IN ULONG Size,
					   OUT PIO_PACKET *pIoPacket)
{
    assert(pIoPacket != NULL);
    assert(Size >= sizeof(IO_PACKET));
    ExAllocatePoolEx(IoPacket, IO_PACKET, Size, NTOS_IO_TAG, {});
    IoPacket->Type = Type;
    IoPacket->Size = Size;
    *pIoPacket = IoPacket;
    return STATUS_SUCCESS;
}

static inline NTSTATUS IopAllocatePendingIrp(IN PIO_PACKET IoPacket,
					     OUT PPENDING_IRP *pPendingIrp)
{
    assert(pPendingIrp != NULL);
    IopAllocatePool(PendingIrp, PENDING_IRP);
    PendingIrp->IoPacket = IoPacket;
    *pPendingIrp = PendingIrp;
    return STATUS_SUCCESS;
}

static inline VOID IopDetachPendingIrpFromThread(IN PPENDING_IRP PendingIrp)
{
    RemoveEntryList(&PendingIrp->Link);
}

static inline VOID IopFreeIoResponseData(IN PPENDING_IRP PendingIrp)
{
    if (PendingIrp->IoResponseData != NULL) {
	ExFreePool(PendingIrp->IoResponseData);
	PendingIrp->IoResponseData = NULL;
    }
}

/*
 * Detach the given pending IRP from the thread that it has been queued on.
 * Free the IO response data, and delete both the IO packet struct and the
 * PENDING_IRP struct itself.
 */
static inline VOID IopCleanupPendingIrp(IN PPENDING_IRP PendingIrp)
{
    IopDetachPendingIrpFromThread(PendingIrp);
    IopFreeIoResponseData(PendingIrp);
    if (PendingIrp->IoPacket != NULL) {
	ExFreePool(PendingIrp->IoPacket);
    }
    ExFreePool(PendingIrp);
}

static inline VOID IopCleanupPendingIrpList(IN PTHREAD Thread)
{
    LoopOverList(PendingIrp, &Thread->PendingIrpList, PENDING_IRP, Link) {
	IopCleanupPendingIrp(PendingIrp);
    }
}

static inline PPENDING_IRP IopGetPendingIrp(IN PTHREAD Thread,
					    IN PIO_PACKET IoPacket)
{
    LoopOverList(PendingIrp, &Thread->PendingIrpList, PENDING_IRP, Link) {
	if (PendingIrp->IoPacket == IoPacket) {
	    return PendingIrp;
	}
    }
    return NULL;
}

static inline VOID IopQueueIoPacket(IN PPENDING_IRP PendingIrp,
				    IN PIO_DRIVER_OBJECT Driver,
				    IN PTHREAD Thread)
{
    /* We can only queue IO request packets */
    assert(PendingIrp != NULL);
    assert(PendingIrp->IoPacket != NULL);
    assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
    /* Queue the IRP to the driver */
    InsertTailList(&Driver->IoPacketQueue, &PendingIrp->IoPacket->IoPacketLink);
    PendingIrp->IoPacket->Request.OriginatingThread.Object = Thread;
    /* Use the GLOBAL_HANDLE of the IoPacket as the Identifier */
    PendingIrp->IoPacket->Request.Identifier = (HANDLE)POINTER_TO_GLOBAL_HANDLE(PendingIrp->IoPacket);
    InsertTailList(&Thread->PendingIrpList, &PendingIrp->Link);
    KeInitializeEvent(&PendingIrp->IoCompletionEvent, NotificationEvent);
    KeSetEvent(&Driver->IoPacketQueuedEvent);
}

static inline BOOLEAN IopFileIsSynchronous(IN PIO_FILE_OBJECT File)
{
    return !!(File->Flags & FO_SYNCHRONOUS_IO);
}

/*
 * Creation context for the driver object creation routine
 */
typedef struct _DRIVER_OBJ_CREATE_CONTEXT {
    PCSTR DriverImagePath;
    PCSTR DriverServicePath;
    PCSTR DriverName;
} DRIVER_OBJ_CREATE_CONTEXT, *PDRIVER_OBJ_CREATE_CONTEXT;

/*
 * Creation context for the device object creation routine
 */
typedef struct _DEVICE_OBJ_CREATE_CONTEXT {
    PIO_DRIVER_OBJECT DriverObject;
    PCSTR DeviceName;
    IO_DEVICE_INFO DeviceInfo;
    BOOLEAN Exclusive;
} DEVICE_OBJ_CREATE_CONTEXT, *PDEVICE_OBJ_CREATE_CONTEXT;

/*
 * Creation context for the file object creation routine
 */
typedef struct _FILE_OBJ_CREATE_CONTEXT {
    PCSTR FileName;
    PIO_DEVICE_OBJECT DeviceObject;
    PVOID BufferPtr;
    MWORD FileSize;
} FILE_OBJ_CREATE_CONTEXT, *PFILE_OBJ_CREATE_CONTEXT;

/*
 * Worker thread of a driver object
 */
typedef struct _WORKER_THREAD {
    PTHREAD Thread;
    NOTIFICATION Notification;	/* Client side capability */
} WORKER_THREAD, *PWORKER_THREAD;

/*
 * Interrupt service thread of a driver object
 */
typedef struct _INTERRUPT_SERVICE_THREAD {
    PTHREAD Thread;
    NOTIFICATION Notification;	     /* Server side capability */
    NOTIFICATION ClientNotification; /* Client side capability */
    NOTIFICATION InterruptMutex;     /* Client side capability */
} INTERRUPT_SERVICE_THREAD, *PINTERRUPT_SERVICE_THREAD;

/*
 * Maps the specified user IO buffer to the driver process's VSpace.
 *
 * If ReadOnly is TRUE, the driver pages will be mapped read-only. Otherwise
 * the driver pages will be mapped read-write.
 *
 * If ReadOnly is FALSE, the user IO buffer must be writable by the user.
 * Otherwise STATUS_INVALID_PAGE_PROTECTION is returned.
 */
static inline NTSTATUS IopMapUserBuffer(IN PPROCESS User,
					IN PIO_DRIVER_OBJECT Driver,
					IN MWORD UserBufferStart,
					IN MWORD UserBufferLength,
					OUT MWORD *DriverBufferStart,
					IN BOOLEAN ReadOnly)
{
    PVIRT_ADDR_SPACE UserVSpace = &User->VSpace;
    assert(UserVSpace != NULL);
    assert(Driver->DriverProcess != NULL);
    PVIRT_ADDR_SPACE DriverVSpace = &Driver->DriverProcess->VSpace;
    assert(DriverVSpace != NULL);
    return MmMapUserBufferEx(UserVSpace, UserBufferStart,
			     UserBufferLength, DriverVSpace,
			     USER_IMAGE_REGION_START,
			     USER_IMAGE_REGION_END,
			     DriverBufferStart, ReadOnly);
}

/*
 * Unmap the user buffer mapped by IopMapUserBuffer
 */
static inline VOID IopUnmapUserBuffer(IN PIO_DRIVER_OBJECT Driver,
				      IN MWORD DriverBuffer)
{
    assert(Driver != NULL);
    assert(Driver->DriverProcess != NULL);
    MmUnmapUserBufferEx(&Driver->DriverProcess->VSpace, DriverBuffer);
}

/* init.c */
extern LIST_ENTRY IopDriverList;

/*
 * Returns the device object of the given device handle, optionally
 * checking whether the device belongs to the driver object
 */
static inline PIO_DEVICE_OBJECT IopGetDeviceObject(IN GLOBAL_HANDLE DeviceHandle,
						   IN PIO_DRIVER_OBJECT DriverObject)
{
    /* If driver object is not NULL, only check its device for a match */
    if (DriverObject != NULL) {
	LoopOverList(DevObj, &DriverObject->DeviceList, IO_DEVICE_OBJECT, DeviceLink) {
	    if (DevObj == GLOBAL_HANDLE_TO_OBJECT(DeviceHandle)) {
		return DevObj;
	    }
	}
    } else {
	/* Traverse the list of all driver objects, and check if there is a match */
	LoopOverList(DrvObj, &IopDriverList, IO_DRIVER_OBJECT, DriverLink) {
	    LoopOverList(DevObj, &DrvObj->DeviceList, IO_DEVICE_OBJECT, DeviceLink) {
		if (DevObj == GLOBAL_HANDLE_TO_OBJECT(DeviceHandle)) {
		    return DevObj;
		}
	    }
	}
    }
    return NULL;
}

/* irp.c */
NTSTATUS IopThreadWaitForIoCompletion(IN ASYNC_STATE State,
				      IN PTHREAD Thread,
				      IN BOOLEAN Alertable,
				      IN WAIT_TYPE WaitType);

/* file.c */
NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx);
NTSTATUS IopFileObjectOpenProc(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN POBJECT Object,
			       IN PCSTR SubPath,
			       IN POB_PARSE_CONTEXT ParseContext,
			       OUT POBJECT *pOpenedInstance,
			       OUT PCSTR *pRemainingPath);
NTSTATUS IopCreateFileObject(IN PCSTR FileName,
			     IN PIO_DEVICE_OBJECT DeviceObject,
			     IN PVOID BufferPtr,
			     IN MWORD FileSize,
			     OUT PIO_FILE_OBJECT *pFile);

/* device.c */
NTSTATUS IopDeviceObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx);
NTSTATUS IopDeviceObjectOpenProc(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN POBJECT Object,
				 IN PCSTR SubPath,
				 IN POB_PARSE_CONTEXT ParseContext,
				 OUT POBJECT *pOpenedInstance,
				 OUT PCSTR *pRemainingPath);

/* driver.c */
NTSTATUS IopDriverObjectCreateProc(POBJECT Object,
				   IN PVOID CreaCtx);

