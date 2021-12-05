#pragma once

#include <nt.h>
#include <ntos.h>
#include <halsvc.h>

#define NTOS_IO_TAG	(EX_POOL_TAG('n','t','i','o'))

#define IopAllocatePoolEx(Var, Type, OnError)				\
    ExAllocatePoolEx(Var, Type, sizeof(Type), NTOS_IO_TAG, OnError)
#define IopAllocatePool(Var, Type)	IopAllocatePoolEx(Var, Type, {})
#define IopAllocateArrayEx(Var, Type, Size, OnError)			\
    ExAllocatePoolEx(Var, Type, sizeof(Type) * (Size), NTOS_IO_TAG, OnError)
#define IopAllocateArray(Var, Type, Size)	\
    IopAllocateArrayEx(Var, Type, Size, {})

static inline NTSTATUS IopAllocateIrp(IN IO_REQUEST_PACKET_TYPE Type,
				      OUT PIO_REQUEST_PACKET *pIrp)
{
    assert(pIrp != NULL);
    IopAllocatePool(Irp, IO_REQUEST_PACKET);
    Irp->Type = Type;
    *pIrp = Irp;
    return STATUS_SUCCESS;
}

static inline VOID IopFreePendingIrp(IN PTHREAD Thread)
{
    PIO_REQUEST_PACKET Irp = Thread->PendingIrp;
    ExFreePool(Irp);
    Thread->PendingIrp = NULL;
}

static inline VOID IopQueueIrp(IN PIO_REQUEST_PACKET Irp,
			       IN PIO_DRIVER_OBJECT Driver,
			       IN PTHREAD Thread)
{
    /* We can only have exactly one pending IRP per thread */
    assert(Thread->PendingIrp == NULL);
    InsertTailList(&Driver->IrpQueue, &Irp->IrpLink);
    Irp->Thread.Object = Thread;
    Thread->PendingIrp = Irp;
    KeInitializeEvent(&Thread->IoCompletionEvent, NotificationEvent);
    KeSetEvent(&Driver->IrpQueuedEvent);
}

static inline BOOLEAN IopFileIsSynchronous(IN PIO_FILE_OBJECT File)
{
    return !!(File->Flags & FO_SYNCHRONOUS_IO);
}

typedef enum _CREATE_FILE_TYPE {
    CreateFileTypeNone,
    CreateFileTypeNamedPipe,
    CreateFileTypeMailslot
} CREATE_FILE_TYPE;

/*
 * An open packet is used as a context for opening a Device object so
 * the device open routine can know what operation is being requested.
 */
typedef struct _OPEN_PACKET {
    CREATE_FILE_TYPE CreateFileType;
    ULONG CreateOptions;
    ULONG FileAttributes;
    ULONG ShareAccess;
    ULONG Disposition;
    union {
	PNAMED_PIPE_CREATE_PARAMETERS NamedPipeCreateParameters;
	PMAILSLOT_CREATE_PARAMETERS MailslotCreateParameters;
    };
} OPEN_PACKET, *POPEN_PACKET;

/*
 * Response returned by the driver for the open operation. This is
 * passed into the open routine by pointer.
 */
typedef struct _OPEN_RESPONSE {
    ULONG_PTR Information; /* IO_STATUS_BLOCK.Information returned by the driver call */
} OPEN_RESPONSE, *POPEN_RESPONSE;

/*
 * Creation context for the driver object creation routine
 */
typedef struct _DRIVER_OBJ_CREATE_CONTEXT {
    PCSTR DriverPath;
    PCSTR DriverName;
} DRIVER_OBJ_CREATE_CONTEXT, *PDRIVER_OBJ_CREATE_CONTEXT;

/*
 * Creation context for the device object creation routine
 */
typedef struct _DEVICE_OBJ_CREATE_CONTEXT {
    PIO_DRIVER_OBJECT DriverObject;
    PCSTR DeviceName;
    DEVICE_TYPE DeviceType;
    ULONG DeviceCharacteristics;
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
static inline  VOID IopUnmapUserBuffer(IN PIO_DRIVER_OBJECT Driver,
				       IN MWORD DriverBuffer)
{
    assert(Driver != NULL);
    assert(Driver->DriverProcess != NULL);
    MmUnmapUserBufferEx(&Driver->DriverProcess->VSpace, DriverBuffer);
}

/* init.c */
PSECTION IopHalDllSection;

/* file.c */
NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx);
NTSTATUS IopFileObjectOpenProc(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN POBJECT Object,
			       IN PVOID Context,
			       IN PVOID OpenResponse,
			       OUT POBJECT *pOpenedInstance);
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
				 IN PVOID OpenPacket,
				 IN PVOID OpenResponse,
				 OUT POBJECT *pOpenedInstance);

/* driver.c */
NTSTATUS IopDriverObjectCreateProc(POBJECT Object,
				   IN PVOID CreaCtx);
