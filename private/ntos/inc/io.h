#pragma once

#define DRIVER_OBJECT_DIRECTORY		"\\Driver"
#define DEVICE_OBJECT_DIRECTORY		"\\Device"

struct _PROCESS;
struct _IO_FILE_OBJECT;

/*
 * Server-side object of the client side DRIVER_OBJECT.
 */
typedef struct _IO_DRIVER_OBJECT {
    PCSTR DriverImageName;
    LIST_ENTRY DeviceList;    /* All devices created by this driver */
    struct _IO_FILE_OBJECT *DriverFile;
    struct _PROCESS *DriverProcess;   /* TODO: We need to figure out Driver and Mini-driver */
    struct _THREAD *MainEventLoopThread; /* Main event loop thread of the driver process */
    LIST_ENTRY IoPortList; /* List of all X86 IO ports enabled for this driver */
    LIST_ENTRY IoPacketQueue; /* IO packets queued on this driver object but has not been processed yet. */
    LIST_ENTRY PendingIoPacketList;	/* IO packets that have already been moved to driver process's
					 * incoming IO packet buffer. Note that the driver may choose to
					 * save this IO packet to its internal buffer and withhold the
					 * response until much later (say, after several calls to
					 * IopRequestIrp). Therefore this list does NOT in general correspond
					 * to the IO packets in the driver's in/out IO packet buffer. */
    KEVENT InitializationDoneEvent; /* Signaled when the client process starts accepting IO packet */
    KEVENT IoPacketQueuedEvent;	    /* Signaled when an IO packet is queued on the driver object. */
    MWORD IncomingIoPacketsServerAddr; /* IO Request Packets sent to the driver */
    MWORD IncomingIoPacketsClientAddr;
    MWORD OutgoingIoPacketsServerAddr; /* Driver's IO response packets */
    MWORD OutgoingIoPacketsClientAddr;
    ULONG NumRequestPackets; /* Number of IO request packets currently in the incoming IO packet buffer */
} IO_DRIVER_OBJECT, *PIO_DRIVER_OBJECT;

/*
 * Server-side object of the client side DEVICE_OBJECT
 */
typedef struct _IO_DEVICE_OBJECT {
    PCSTR DeviceName;
    PIO_DRIVER_OBJECT DriverObject;
    LIST_ENTRY DeviceLink; /* Links all devices created by the driver object */
    struct _IO_DEVICE_OBJECT *HigherDevice; /* Higher-level device object immediately above this one */
    struct _IO_DEVICE_OBJECT *LowerDevice; /* Lower-level device object immediately below this one */
    IO_DEVICE_OBJECT_INFO DeviceInfo;
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
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
} IO_FILE_OBJECT, *PIO_FILE_OBJECT;

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
