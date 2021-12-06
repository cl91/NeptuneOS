#pragma once

#include <nt.h>
#include <wdm.h>
#include <assert.h>
#include <debug.h>
#include <util.h>
#include <halsvc.h>
#include <hal_halsvc_gen.h>
#include <irp.h>

#define TAG_DRIVER_EXTENSION	'EVRD'
#define TAG_REINIT		'iRoI'

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

/* Prevent the compiler from inlining the function */
#define NO_INLINE	__attribute__((noinline))

/* Function does not return */
#define NORETURN	__attribute__((__noreturn__))

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
} DRIVER_REINIT_ITEM, *PDRIVER_REINIT_ITEM;

/* device.c */
extern LIST_ENTRY IopDeviceList;
PDEVICE_OBJECT IopGetDeviceObject(IN GLOBAL_HANDLE Handle);

/* irp.c */
extern PIO_REQUEST_PACKET IopIncomingIrpBuffer;
extern PIO_REQUEST_PACKET IopOutgoingIrpBuffer;
extern LIST_ENTRY IopIrpQueue;
extern LIST_ENTRY IopFileObjectList;
extern LIST_ENTRY IopCompletedIrpList;
VOID IopProcessIrp(OUT ULONG *pNumResponses,
		   IN ULONG NumRequests);

/* main.c */
extern DRIVER_OBJECT IopDriverObject;

/* timer.c */
extern LIST_ENTRY IopTimerList;
