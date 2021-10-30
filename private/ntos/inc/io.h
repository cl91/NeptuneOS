#pragma once

#define NTOS_IO_TAG	(EX_POOL_TAG('n','t','i','o'))

#define DRIVER_OBJECT_DIRECTORY		"\\Driver"
#define DEVICE_OBJECT_DIRECTORY		"\\Device"

struct _PROCESS;

/*
 * Server-side object of the client side DRIVER_OBJECT.
 */
typedef struct _IO_DRIVER_OBJECT {
    PCSTR DriverImageName;
    LIST_ENTRY DeviceList;    /* All devices created by this driver */
    struct _PROCESS *DriverProcess;   /* TODO: We need to figure out Driver and Mini-driver */
    KEVENT InitializationDoneEvent; /* Signaled when the client process starts accepting IRP */
} IO_DRIVER_OBJECT, *PIO_DRIVER_OBJECT;

/*
 * Server-side object of the client side DEVICE_OBJECT
 */
typedef struct _IO_DEVICE_OBJECT {
    PCSTR DeviceName;
    PIO_DRIVER_OBJECT DriverObject;
    LIST_ENTRY DeviceLink; /* Links all devices created by the driver object */
    DEVICE_TYPE DeviceType;
    ULONG DeviceCharacteristics;
    BOOLEAN Exclusive;
} IO_DEVICE_OBJECT, *PIO_DEVICE_OBJECT;

typedef struct _SECTION_OBJECT_POINTERS {
    PDATA_SECTION_OBJECT DataSectionObject;
    PIMAGE_SECTION_OBJECT ImageSectionObject;
} SECTION_OBJECT_POINTERS;

/*
 * Server-side object of the client side FILE_OBJECT. Represents
 * an open instance of a DEVICE_OBJECT.
 */
typedef struct _IO_FILE_OBJECT {
    PIO_DEVICE_OBJECT DeviceObject;
    PCSTR FileName;
    SECTION_OBJECT_POINTERS SectionObject;
    PVOID BufferPtr;
    MWORD Size;
} IO_FILE_OBJECT, *PIO_FILE_OBJECT;

/*
 * Forward declarations.
 */

/* init.c */
NTSTATUS IoInitSystemPhase0();
NTSTATUS IoInitSystemPhase1();

/* create.c */
NTSTATUS IoCreateFile(IN PCSTR FileName,
		      IN PVOID BufferPtr,
		      IN MWORD FileSize,
		      OUT PIO_FILE_OBJECT *pFile);
