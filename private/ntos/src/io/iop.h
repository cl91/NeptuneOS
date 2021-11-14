#pragma once

#include <nt.h>
#include <ntos.h>
#include <halsvc.h>

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

/* init.c */
PSECTION IopHalDllSection;

/* file.c */
NTSTATUS IopFileObjectInitProc(POBJECT Object);
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
NTSTATUS IopDeviceObjectInitProc(POBJECT Object);
NTSTATUS IopDeviceObjectOpenProc(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN POBJECT Object,
				 IN PVOID OpenPacket,
				 IN PVOID OpenResponse,
				 OUT POBJECT *pOpenedInstance);

/* driver.c */
NTSTATUS IopDriverObjectInitProc(POBJECT Object);
