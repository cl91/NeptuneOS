#pragma once

#include <nt.h>
#include <debug.h>
#include <util.h>
#include <services.h>
#include <wdmsvc_gen.h>

compile_assert(TOO_MANY_WDM_SERVICES, NUMBER_OF_WDM_SERVICES < 0x1000UL);

#define DRIVER_IO_PACKET_BUFFER_RESERVE	(64 * 1024)
#define DRIVER_IO_PACKET_BUFFER_COMMIT	(16 * 1024)
#define DRIVER_COROUTINE_STACK_RESERVE	(4 * PAGE_SIZE)
#define DRIVER_COROUTINE_STACK_COMMIT	(2 * PAGE_SIZE)

#define PNP_ROOT_ENUMERATOR	"\\Device\\pnp"

/* When the driver DPC thread gets notified, we use the following flag to
 * indicate that it comes from timer expiration. */
#define TIMER_NOTIFICATION_BADGE	(1)

#define VIEWS_PER_TABLE		(PAGE_SIZE / sizeof(PVOID))
#define VIEW_TABLE_ADDRESS_BITS	(PAGE_LOG2SIZE - MWORD_LOG2SIZE)
#define VIEW_TABLE_BITMAP_SIZE	(VIEWS_PER_TABLE / MWORD_BITS)
#define PAGES_IN_VIEW		(64)
#define VIEW_SIZE		(PAGE_SIZE * PAGES_IN_VIEW)
#define VIEW_LOG2SIZE		(PAGE_LOG2SIZE + 6)
#define VIEW_ALIGN(p)		ALIGN_DOWN_BY(p, VIEW_SIZE)
#define VIEW_ALIGN_UP(p)	ALIGN_UP_BY(p, VIEW_SIZE)
#define VIEW_ALIGN64(p)		((ULONG64)(p) & ~((ULONG64)VIEW_SIZE - 1))
#define VIEW_ALIGN_UP64(p)	(VIEW_ALIGN64((ULONG64)(p) + VIEW_SIZE - 1))
#define IS_VIEW_ALIGNED(p)	(((MWORD)(p)) == VIEW_ALIGN(p))
#define IS_VIEW_ALIGNED64(p)	(((ULONG64)(p)) == VIEW_ALIGN64(p))

/*
 * Defines the structure of the page frame database following an MDL
 *
 * ULONG_PTR PfnEntry;
 * |==============================================================|
 * | STARTING PHYSICAL PAGE FRAME NUMBER | PAGE COUNT | ATTR BITS |
 * |--------------------------------------------------------------|
 * | 32/63 .......................... 12 | 11 ..... 2 |  1 ... 0  |
 * |==============================================================|
 *
 * If bit 0 is set, all pages frames in this pfn entry are large pages
 * (second lowest level of page size offered by the architecture).
 * Otherwise they are all pages with the lowest level of page size.
 */
#define MDL_PFN_ATTR_BITS	(2)
#define MDL_PFN_PAGE_COUNT_BITS	(10)
#define MDL_PFN_ATTR_MASK	((1ULL << MDL_PFN_ATTR_BITS) - 1)
#define MDL_PFN_PAGE_COUNT_MASK	((1ULL << MDL_PFN_PAGE_COUNT_BITS) - 1)
#define MDL_PFN_ATTR_LARGE_PAGE	(0x1ULL)

#define MDL_PFN_PAGE_SIZE(Pfn)						\
    (((Pfn) & MDL_PFN_ATTR_LARGE_PAGE) ? LARGE_PAGE_SIZE : PAGE_SIZE)
#define MDL_PFN_PAGE_ADDRESS(Pfn)		\
    (((Pfn) >> PAGE_SHIFT) << PAGE_SHIFT)
#define MDL_PFN_PAGE_COUNT(Pfn)					\
    (((Pfn) >> MDL_PFN_ATTR_BITS) & MDL_PFN_PAGE_COUNT_MASK)

#if (MDL_PFN_ATTR_BITS + MDL_PFN_PAGE_COUNT_BITS) > PAGE_LOG2SIZE
#error "Invalid encoding for MDL page frame database"
#endif

/*
 * This is our custom IRP major function which shall never be seen by client drivers
 */
#define IRP_MJ_ADD_DEVICE	(IRP_MJ_MAXIMUM_FUNCTION + 1)
#if IRP_MJ_ADD_DEVICE > 0xff
#error "Too many IRP major functions"
#endif

/*
 * Global handle type.
 *
 * See ntos/inc/ob.h
 */
typedef MWORD GLOBAL_HANDLE, *PGLOBAL_HANDLE;

/* Make sure the struct packing matches on both ELF and PE targets */
#include <pshpack4.h>

/*
 * Device object information shared between server and client drivers
 */
typedef struct _IO_DEVICE_INFO {
    DEVICE_TYPE DeviceType;
    ULONG64 Flags;
} IO_DEVICE_INFO, *PIO_DEVICE_INFO;

/*
 * Parameters for NtCreateMailslotFile/NtCreateNamedPipeFile
 */
typedef struct _MAILSLOT_CREATE_PARAMETERS {
    ULONG MailslotQuota;
    ULONG MaximumMessageSize;
    LARGE_INTEGER ReadTimeout;
    BOOLEAN TimeoutSpecified;
} MAILSLOT_CREATE_PARAMETERS, *PMAILSLOT_CREATE_PARAMETERS;

typedef struct _NAMED_PIPE_CREATE_PARAMETERS {
    ULONG NamedPipeType;
    ULONG ReadMode;
    ULONG CompletionMode;
    ULONG MaximumInstances;
    ULONG InboundQuota;
    ULONG OutboundQuota;
    LARGE_INTEGER DefaultTimeout;
    BOOLEAN TimeoutSpecified;
} NAMED_PIPE_CREATE_PARAMETERS, *PNAMED_PIPE_CREATE_PARAMETERS;

/*
 * Parameters for CREATE, CREATE_MAILSLOT, and CREATE_NAMED_PIPE
 */
typedef struct _FILE_OBJECT_CREATE_PARAMETERS {
    ULONG64 AllocationSize;
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    ULONG FileNameOffset; /* Offset to the NUL-terminated file name buffer, with
			   * respect to the beginning of the IO_REQUEST_PARAMETERS. */
} FILE_OBJECT_CREATE_PARAMETERS, *PFILE_OBJECT_CREATE_PARAMETERS;

/*
 * IO packet type that is being sent between NTOS server and drivers.
 *
 * The difference between IoPacketTypeRequest and Server/Client message is that
 * server/client messages do not require any reply, while IoPacketTypeRequest
 * generates a reply that the requestor (either the server or a client driver) expects.
 */
typedef enum _IO_PACKET_TYPE {
    IoPacketTypeRequest, /* An IO request packet, from either an NT client or a driver */
    IoPacketTypeServerMessage, /* Message sent from the server */
    IoPacketTypeClientMessage  /* Message to the server from the client */
} IO_PACKET_TYPE;

/*
 * Declares a union type of server-side pointer and
 * client-side global handle
 */
#define DECLARE_POINTER_TYPE(Type)		\
    typedef union _ ## Type ## _PTR {		\
	struct _ ## Type *Object;		\
	GLOBAL_HANDLE Handle;			\
    } Type ## _PTR

DECLARE_POINTER_TYPE(IO_DEVICE_OBJECT);
DECLARE_POINTER_TYPE(IO_FILE_OBJECT);

#undef DECLARE_POINTER_TYPE

/* These must not be less than 1ULL << 16 as low 16 bits are public flags. */
#define IOP_IRP_INPUT_DIRECT_IO			(1UL << 16)
#define IOP_IRP_OUTPUT_DIRECT_IO		(1UL << 17)
#define IOP_IRP_COMPLETION_CALLBACK		(1UL << 18)
#define IOP_IRP_INTERCEPTION_CALLBACK		(1UL << 19)
#define IOP_IRP_NOTIFY_COMPLETION		(1UL << 20)
#define IOP_IRP_OVERRIDE_VERIFY			(1UL << 21)

/*
 * Parameters for an IO request.
 */
typedef struct POINTER_ALIGNMENT _IO_REQUEST_PARAMETERS {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    USHORT DataSize; /* Size of the extra data following the fixed part of this IRP. */
    ULONG Flags;
    IO_DEVICE_OBJECT_PTR Device;
    IO_FILE_OBJECT_PTR File;
    MWORD InputBuffer; /* If InputBufferLength is less than IRP_DATA_BUFFER_SIZE,
			* this is the offset of input data embedded in this IRP.
			* In this case InputBuffer will be smaller than PAGE_SIZE.
			* Otherwise it is a pointer to the input data buffer in
			* the address space of (1) when creating a new IRP, the
			* original requestor or (2) when the IRP is queued on a
			* driver object, the target driver. In the latter case
			* the original address is saved in the PENDING_IRP struct.
			* InputBuffer is used by IRP_MJ_WRITE and IOCTL IRPs.
			* It should be apparent from the usage that input and
			* output here is with respect to the device. In other
			* words, READ IRP will read from the device and write to
			* the OutputBuffer and WRITE IRP will read from the
			* InputBuffer and write to the device. */
    MWORD OutputBuffer;	/* See InputBuffer. This is used by IRP_MJ_READ and
			 * IOCTL IRPs. Note if the OutputBuffer is less than
			 * IRP_DATA_BUFFER_SIZE, when the IRP is queued on a
			 * driver object this field is zero, and the driver
			 * will store the output data in the ResponseData
			 * member of IO_COMPLETED_MESSAGE, defined below. */
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    ULONG InputBufferPfnCount;
    ULONG OutputBufferPfnCount;
    MWORD InputBufferPfn; /* Page frame database of the input buffer. Before
			   * an IO_PACKET is sent to the client driver, this is
			   * a pointer in the NT Executive address space that
			   * points to the PFN database of the input buffer.
			   * When the IO_PACKET is copied into the driver's
			   * incoming IO packet buffer, it will become an offset
			   * from the beginning of the IO_PACKET. */
    MWORD OutputBufferPfn; /* Page frame database of the output buffer. See above. */
    GLOBAL_HANDLE OriginalRequestor; /* Original thread or driver object that
				      * requested this IRP. Together with
				      * Identifier, this uniquely identifies
				      * the IRP among all IRPs being processed
				      * by the system at a given time. For new
				      * IRPs requested by a driver object, the
				      * client should set this to NULL. The
				      * server will assign the correct handle
				      * when it forwards the IRP to the
				      * destination driver object. */
    HANDLE Identifier; /* Handle to identify the original IRP. For IRPs
			* generated by the NTOS Executive, this handle
			* is the GLOBAL_HANDLE of the IO packet (allocated
			* on the ExPool) queued on a thread object, and
			* is unique among all IO packets currently being
			* processed by the system. For (new) IRPs generated
			* by a driver, this handle is assigned by the driver.
			* The driver must guarantee that it is unique among
			* all IRPs currently being requested by the driver.
			* Both the system and the driver may reuse old handles
			* of IO packets that have already been processed. */
    union {
	struct {
	    MWORD Placeholder;
	    PVOID Ptr;
	};
	struct {
	    GLOBAL_HANDLE OriginalRequestor;
	    HANDLE Identifier;
	};
    } MasterIrp; /* Master IRP that this IRP is associated with. If the
		  * IO_PACKET is in server address space, this union contains
		  * the pointer to the master IRP's PENDING_IRP object. When
		  * the IO_PACKET is in driver address space, this union is the
		  * (OriginalRequestor,Identifier) pair of the master IRP. */
    LONG AssociatedIrpCount; /* Number of pending associated IRPs. */
    struct {
	PVOID Callback;	/* Irp completion or interception callback. */
	PVOID Context;	/* Context for the IRP callback function. */
	BOOLEAN MasterCompleted;
    } ServerPrivate;   /* These fields are only used by the server. The
			* client side routines should not access them. */
    union {
	struct {
	    IO_DEVICE_INFO PhysicalDeviceInfo; /* Request.Device is the physical
						* device object */
	    CHAR BaseName[64];    /* Driver object to which this AddDevice is sent */
	} AddDevice; /* Used by the PNP manager to inform the
		      * driver to add a new device */
	struct {
	    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters;
	    ULONG Options;
	    ULONG FileAttributes;
	    ULONG ShareAccess;
	    BOOLEAN OpenTargetDirectory;
	} Create;
	struct {
	    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters;
	    ULONG Options;
	    USHORT ShareAccess;
	    NAMED_PIPE_CREATE_PARAMETERS Parameters;
	} CreatePipe;
	struct {
	    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters;
	    ULONG Options;
	    USHORT ShareAccess;
	    MAILSLOT_CREATE_PARAMETERS Parameters;
	} CreateMailslot;
	struct {
	    ULONG Key;
	    LARGE_INTEGER ByteOffset;
	} Read;
	struct {
	    ULONG Key;
	    LARGE_INTEGER ByteOffset;
	} Write;
	struct {
	    ULONG IoControlCode;
	} DeviceIoControl;
	struct {
	    FILE_INFORMATION_CLASS FileInformationClass;
	} QueryFile;
	struct {
	    FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
	    GLOBAL_HANDLE TargetDirectory;
	} SetFile;
	struct {
	    FILE_INFORMATION_CLASS FileInformationClass;
	    ULONG FileIndex;
	    BOOLEAN ReturnSingleEntry;
	    BOOLEAN RestartScan;
	    CHAR FileName[];
	} QueryDirectory;
	struct {
	    FS_INFORMATION_CLASS FsInformationClass;
	} QueryVolume;
	struct {
	    DEVICE_RELATION_TYPE Type;
	} QueryDeviceRelations;
	struct {
	    BUS_QUERY_ID_TYPE IdType;
	} QueryId;
	struct {
	    ULONG ResourceListSize;
	    ULONG TranslatedListSize;
	    CHAR Data[]; /* The translated list always follows
			  * the non-translated list */
	} StartDevice;
	struct {
	    GLOBAL_HANDLE StorageDevice;
	    IO_DEVICE_INFO StorageDeviceInfo;
	} MountVolume;
    };
} IO_REQUEST_PARAMETERS, *PIO_REQUEST_PARAMETERS;

/*
 * Additional response data that are sent back to the server
 * when the driver has finished processing an IO request. This
 * is stored in the ResponseData member of IO_COMPLETED_MESSAGE
 * Note this union is an incomplete list of possible forms of
 * response data and some IRPs define additional format. See
 * IopPopulateIoCompleteMessageFromLocalIrp in wdm.dll for details.
 */
typedef union _IO_RESPONSE_DATA {
    struct {
	ULONG64 FileSize;
	ULONG64 AllocationSize;
	ULONG64 ValidDataLength;
    } FileSizes; /* For IRP_MJ_CREATE, IRP_MJ_WRITE and IRP_MJ_SET_INFORMATION */
    struct {
	ULONG64 VolumeSize;
	GLOBAL_HANDLE VolumeDeviceHandle;
	ULONG ClusterSize;
    } VolumeMounted;
    struct {
	ULONG_PTR MdlCount; /* Number of MDLs embedded in this message. This is used
			     * by IRP_MJ_READ with the IRP_MN_MDL minor code where
			     * the server needs to send the MDL chain to the client. */
	struct {
	    PVOID MappedSystemVa;
	    ULONG_PTR ByteCount;
	} Mdl[];
    } MdlChain;
} IO_RESPONSE_DATA, *PIO_RESPONSE_DATA;

/*
 * Message to notify that an IRP has been completed.
 * Can be either a message from server to client or from client to server.
 */
typedef struct _IO_COMPLETED_MESSAGE {
    GLOBAL_HANDLE OriginalRequestor; /* Driver must set this to the OriginalRequestor
				      * member of the original IRP. This is used to
				      * disambiguate the IRP being completed */
    HANDLE Identifier;	/* The OriginalIrp handle of the IRP being completed. */
    IO_STATUS_BLOCK IoStatus;
    ULONG ResponseDataSize;
    ULONG_PTR ResponseData[];
} IO_COMPLETED_MESSAGE, *PIO_COMPLETED_MESSAGE;

/*
 * Message type of server messages
 */
typedef enum _IO_SERVER_MESSAGE_TYPE {
    IoSrvMsgIoCompleted,
    IoSrvMsgLoadDriver,
    IoSrvMsgCacheFlushed,
    IoSrvMsgCloseFile,
    IoSrvMsgCloseDevice,
    IoSrvMsgForceDismount
} IO_SERVER_MESSAGE_TYPE;

/*
 * Message packet from the server.
 */
typedef struct _IO_PACKET_SERVER_MESSAGE {
    IO_SERVER_MESSAGE_TYPE Type;
    union {
	IO_COMPLETED_MESSAGE IoCompleted;
	struct {
	    ULONG BaseNameLength; /* Including trailing '\0' */
	    CHAR BaseName[];
	} LoadDriver;
	struct {
	    GLOBAL_HANDLE DeviceObject;
	    GLOBAL_HANDLE FileObject;
	    IO_STATUS_BLOCK IoStatus;
	} CacheFlushed;
	struct {
	    GLOBAL_HANDLE FileObject;
	} CloseFile;
	struct {
	    GLOBAL_HANDLE DeviceObject;
	} CloseDevice;
	struct {
	    GLOBAL_HANDLE VolumeDevice;
	} ForceDismount;
    };
} IO_PACKET_SERVER_MESSAGE, *PIO_PACKET_SERVER_MESSAGE;

/*
 * Message type of client messages
 */
typedef enum _IO_CLIENT_MESSAGE_TYPE {
    IoCliMsgIoCompleted,
    IoCliMsgForwardIrp,
    IoCliMsgDirtyBuffers,
    IoCliMsgFlushCache
} IO_CLIENT_MESSAGE_TYPE;

#define IO_CLI_MSG_MAX_DIRTY_BUFFER_COUNT	(8)

/*
 * Message packet from the client.
 */
typedef struct _IO_PACKET_CLIENT_MESSAGE {
    IO_CLIENT_MESSAGE_TYPE Type;
    union {
	IO_COMPLETED_MESSAGE IoCompleted;
	struct {
	    GLOBAL_HANDLE OriginalRequestor; /* Driver must set this to the
					      * OriginalRequestor member of the
					      * original IRP. This is to disambiguate
					      * the IRP being forwarded. */
	    HANDLE Identifier;
	    GLOBAL_HANDLE DeviceObject;
	    ULONG AssociatedIrpCount; /* Number of additional associated IRPs. */
	    LARGE_INTEGER NewOffset; /* For IRP_MJ_READ and IRP_MJ_WRITE, this stores
				      * the ByteOffset of the IRP being forwarded. */
	    ULONG NewLength; /* For IRP_MJ_READ and IRP_MJ_WRITE, this stores the new
			      * Length of the requested read/write. It must be less than
			      * or equal to the original length parameter. */
	    ULONG64 NewFileSize; /* File system driver only. */
	    ULONG64 NewAllocationSize; /* File system driver only. */
	    ULONG64 NewValidDataLength; /* File system driver only. */
	    BOOLEAN NotifyCompletion; /* TRUE if the client driver wants the server to
				       * notify it after the IRP has been processed. */
	    BOOLEAN OverrideVerify; /* TRUE if the forwarded IRP should be marked
				     * with SL_OVERRIDE_VERIFY_VOLUME. */
	} ForwardIrp;
	struct {
	    MWORD ViewAddress;
	    ULONG64 DirtyBits;
	} DirtyBuffers[IO_CLI_MSG_MAX_DIRTY_BUFFER_COUNT];
	struct {
	    GLOBAL_HANDLE DeviceObject;
	    GLOBAL_HANDLE FileObject;
	} FlushCache;
    };
} IO_PACKET_CLIENT_MESSAGE, *PIO_PACKET_CLIENT_MESSAGE;

/*
 * This is the actual data structure being passed between the server
 * task and the client driver processes. The public IRP struct is exposed
 * in ntddk.h in order to remain (semi-)compatible with Windows/ReactOS.
 */
typedef struct POINTER_ALIGNMENT _IO_PACKET {
    IO_PACKET_TYPE Type;
    ULONG Size;	/* Size of the IO packet in bytes.
		 * This includes all the trailing data. */
    LIST_ENTRY IoPacketLink; /* List entry for either IoPacketQueue or
			      * PendingIoPacketList of the driver object.
			      * This is only valid when the IoPacket object
			      * is being queued on the driver object or is
			      * in the driver's pending IoPacket list. */
    union {
	IO_REQUEST_PARAMETERS Request; /* Type == IoPacketTypeRequest */
	IO_PACKET_SERVER_MESSAGE ServerMsg; /* For Type == IoPacketTypeServerMessage */
	IO_PACKET_CLIENT_MESSAGE ClientMsg; /* For Type == IoPacketTypeClientMessage */
    }; /* This must be at the end of the struct since it might have variable length */
} IO_PACKET, *PIO_PACKET;

typedef PTHREAD_START_ROUTINE PIO_WORKER_THREAD_ENTRY;
typedef PTHREAD_START_ROUTINE PIO_INTERRUPT_SERVICE_THREAD_ENTRY;

#include <poppack.h>

/*
 * Inline functions
 */
static inline USHORT IopDeviceTypeToSectorSize(IN DEVICE_TYPE DeviceType)
{
    switch (DeviceType) {
    case FILE_DEVICE_DISK_FILE_SYSTEM:
    case FILE_DEVICE_DISK:
    case FILE_DEVICE_VIRTUAL_DISK:
	return 512;
    case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
	return 2048;
    }
    return 0;
}

static inline VOID IoDbgDumpFileObjectCreateParameters(IN PIO_PACKET IoPacket,
						       IN PFILE_OBJECT_CREATE_PARAMETERS Params)
{
    DbgPrint("AllocationSize 0x%llx ReadAccess %s WriteAccess %s DeleteAccess %s SharedRead %s "
	     "SharedWrite %s SharedDelete %s Flags 0x%08x FileNameOffset 0x%x FileName %s\n",
	     Params->AllocationSize, Params->ReadAccess ? "TRUE" : "FALSE",
	     Params->WriteAccess ? "TRUE" : "FALSE",
	     Params->DeleteAccess ? "TRUE" : "FALSE",
	     Params->SharedRead ? "TRUE" : "FALSE",
	     Params->SharedWrite ? "TRUE" : "FALSE",
	     Params->SharedDelete ? "TRUE" : "FALSE",
	     Params->Flags, Params->FileNameOffset,
	     (PUCHAR)(&IoPacket->Request) + Params->FileNameOffset);
}

static inline PCSTR IopDbgDeviceRelationTypeStr(IN DEVICE_RELATION_TYPE Type)
{
    switch (Type) {
    case BusRelations:
	return "BusRelations";
    case EjectionRelations:
	return "EjectionRelations";
    case PowerRelations:
	return "PowerRelations";
    case RemovalRelations:
	return "RemovalRelations";
    case TargetDeviceRelation:
	return "TargetDeviceRelation";
    case SingleBusRelations:
	return "SingleBusRelations";
    case TransportRelations:
	return "TransportRelations";
    }
    return "UNKNOWN";
}

static inline PCSTR IopDbgQueryIdTypeStr(IN BUS_QUERY_ID_TYPE IdType)
{
    switch (IdType) {
    case BusQueryDeviceID:
	return "BusQueryDeviceID";
    case BusQueryHardwareIDs:
	return "BusQueryHardwareIDs";
    case BusQueryCompatibleIDs:
	return "BusQueryCompatibleIDs";
    case BusQueryInstanceID:
	return "BusQueryInstanceID";
    case BusQueryDeviceSerialNumber:
	return "BusQueryDeviceSerialNumber";
    case BusQueryContainerID:
	return "BusQueryContainerID";
    }
    return "UNKNOWN";
}

static inline VOID IoDbgDumpIoPacket(IN PIO_PACKET IoPacket,
				     IN BOOLEAN ClientSide)
{
    DbgTrace("Dumping IO Packet %p size 0x%x\n", IoPacket, IoPacket->Size);
    DbgPrint("    TYPE: ");
    switch (IoPacket->Type) {
    case IoPacketTypeRequest:
	DbgPrint("IO REQUEST\n");
	break;
    case IoPacketTypeServerMessage:
	DbgPrint("SERVER MESSAGE\n");
	break;
    case IoPacketTypeClientMessage:
	DbgPrint("CLIENT MESSAGE\n");
	break;
    default:
	DbgPrint("INVALID!!\n");
	return;
    }
    if (IoPacket->Type == IoPacketTypeRequest) {
	if (ClientSide) {
	    DbgPrint("    DeviceHandle %p FileHandle %p",
		     (PVOID)IoPacket->Request.Device.Handle,
		     (PVOID)IoPacket->Request.File.Handle);
	} else {
	    DbgPrint("    DeviceObject %p FileObject %p",
		     IoPacket->Request.Device.Object,
		     IoPacket->Request.File.Object);
	}
	DbgPrint(" OriginalRequestor %p Identifier %p\n",
		 (PVOID)IoPacket->Request.OriginalRequestor,
		 IoPacket->Request.Identifier);
	if (ClientSide) {
	    DbgPrint("    MasterIrp's OriginalRequestor %p Identifier %p\n",
		     (PVOID)IoPacket->Request.MasterIrp.OriginalRequestor,
		     IoPacket->Request.MasterIrp.Identifier);
	} else {
	    struct {
		PVOID IoPacket;
		PVOID Requestor;
	    } *PendingIrp = IoPacket->Request.MasterIrp.Ptr;
	    DbgPrint("    MasterIrp's PENDING_IRP %p (OriginalRequestor %p IO_PACKET %p)\n",
		     PendingIrp, PendingIrp ? PendingIrp->Requestor : NULL,
		     PendingIrp ? PendingIrp->IoPacket : NULL);
	}
	DbgPrint("    AssociatedIrpCount %d\n", IoPacket->Request.AssociatedIrpCount);
	DbgPrint("    InputBuffer %p Length 0x%x PfnCount %d "
		 " OutputBuffer %p Length 0x%x PfnCount %d\n",
		 (PVOID)IoPacket->Request.InputBuffer,
		 IoPacket->Request.InputBufferLength,
		 IoPacket->Request.InputBufferPfnCount,
		 (PVOID)IoPacket->Request.OutputBuffer,
		 IoPacket->Request.OutputBufferLength,
		 IoPacket->Request.OutputBufferPfnCount);
	if (IoPacket->Request.InputBufferPfnCount) {
	    DbgPrint("    Input PFN(s):");
	    for (ULONG i = 0; i < IoPacket->Request.InputBufferPfnCount; i++) {
		if (ClientSide) {
		    PULONG_PTR PfnDb = (PULONG_PTR)((PUCHAR)IoPacket + IoPacket->Request.InputBufferPfn);
		    DbgPrint("  %p", (PVOID)PfnDb[i]);
		} else {
		    PULONG_PTR PfnDb = (PVOID)IoPacket->Request.InputBufferPfn;
		    DbgPrint("  %p", (PVOID)PfnDb[i]);
		}
	    }
	    DbgPrint("\n");
	}
	if (IoPacket->Request.OutputBufferPfnCount) {
	    DbgPrint("    Output PFN(s):");
	    for (ULONG i = 0; i < IoPacket->Request.OutputBufferPfnCount; i++) {
		if (ClientSide) {
		    PULONG_PTR PfnDb = (PULONG_PTR)((PUCHAR)IoPacket + IoPacket->Request.OutputBufferPfn);
		    DbgPrint("  %p", (PVOID)PfnDb[i]);
		} else {
		    PULONG_PTR PfnDb = (PVOID)IoPacket->Request.OutputBufferPfn;
		    DbgPrint("  %p", (PVOID)PfnDb[i]);
		}
	    }
	    DbgPrint("\n");
	}
	DbgPrint("    Major function %d.  Minor function %d.  DataSize 0x%x.  Flags 0x%x\n",
		 IoPacket->Request.MajorFunction, IoPacket->Request.MinorFunction,
		 IoPacket->Request.DataSize, IoPacket->Request.Flags);
	switch (IoPacket->Request.MajorFunction) {
	case IRP_MJ_ADD_DEVICE:
	    DbgPrint("    ADD-DEVICE\n");
	    break;
	case IRP_MJ_CREATE:
	    DbgPrint("    CREATE  Options 0x%x FileAttr 0x%x ShareAccess 0x%x\n",
		     IoPacket->Request.Create.Options,
		     IoPacket->Request.Create.FileAttributes,
		     IoPacket->Request.Create.ShareAccess);
	    DbgPrint("        FileObjectCreateParameters ");
	    IoDbgDumpFileObjectCreateParameters(IoPacket,
						&IoPacket->Request.Create.FileObjectParameters);
	    break;
	case IRP_MJ_CLOSE:
	    DbgPrint("    CLOSE\n");
	    break;
	case IRP_MJ_READ:
	    DbgPrint("    READ%s  Key 0x%x ByteOffset 0x%llx\n",
		     IoPacket->Request.MinorFunction == IRP_MN_MDL ? " MDL" : "",
		     IoPacket->Request.Read.Key,
		     IoPacket->Request.Read.ByteOffset.QuadPart);
	    break;
	case IRP_MJ_WRITE:
	    DbgPrint("    WRITE%s  Key 0x%x ByteOffset 0x%llx\n",
		     IoPacket->Request.MinorFunction == IRP_MN_MDL ? " MDL" : "",
		     IoPacket->Request.Write.Key,
		     IoPacket->Request.Write.ByteOffset.QuadPart);
	    break;
	case IRP_MJ_DIRECTORY_CONTROL:
	    DbgPrint("    DIRECTORY-CONTROL  ");
	    switch (IoPacket->Request.MinorFunction) {
	    case IRP_MN_QUERY_DIRECTORY:
		DbgPrint("QUERY-DIRECTORY  FileInformationClass %d FileIndex %d "
			 "ReturnSingleEntry %d RestartScan %d FileName %s\n",
			 IoPacket->Request.QueryDirectory.FileInformationClass,
			 IoPacket->Request.QueryDirectory.FileIndex,
			 IoPacket->Request.QueryDirectory.ReturnSingleEntry,
			 IoPacket->Request.QueryDirectory.RestartScan,
			 IoPacket->Request.QueryDirectory.FileName);
		break;
	    default:
		DbgPrint("UNKNOWN-MINOR-CODE\n");
		assert(FALSE);
	    }
	    break;
	case IRP_MJ_QUERY_INFORMATION:
	    DbgPrint("    QUERY-INFORMATION FileInformationClass %d\n",
		     IoPacket->Request.QueryFile.FileInformationClass);
	    break;
	case IRP_MJ_SET_INFORMATION:
	    DbgPrint("    SET-INFORMATION FileInformationClass %d TargetDirectory 0x%zx\n",
		     IoPacket->Request.SetFile.FileInformationClass,
		     IoPacket->Request.SetFile.TargetDirectory);
	    break;
	case IRP_MJ_QUERY_VOLUME_INFORMATION:
	    DbgPrint("    QUERY-VOLUME-INFORMATION FsInformationClass %d\n",
		     IoPacket->Request.QueryVolume.FsInformationClass);
	    break;
	case IRP_MJ_FLUSH_BUFFERS:
	    DbgPrint("    FLUSH-BUFFERS\n");
	    break;
	case IRP_MJ_DEVICE_CONTROL:
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
	    DbgPrint("    %sDEVICE-CONTROL  IoControlCode 0x%x\n",
		     IoPacket->Request.MajorFunction == IRP_MJ_DEVICE_CONTROL ? "" : "INTERNAL-",
		     IoPacket->Request.DeviceIoControl.IoControlCode);
	    break;
	case IRP_MJ_FILE_SYSTEM_CONTROL:
	    DbgPrint("    FILE-SYSTEM-CONTROL  ");
	    switch (IoPacket->Request.MinorFunction) {
	    case IRP_MN_USER_FS_REQUEST:
		DbgPrint("    USER-FS-REQUEST  FsControlCode 0x%x\n",
			 IoPacket->Request.DeviceIoControl.IoControlCode);
		break;
	    case IRP_MN_MOUNT_VOLUME:
		DbgPrint("MOUNT-VOLUME  StorageDeviceHandle 0x%zx\n",
			 IoPacket->Request.MountVolume.StorageDevice);
		break;
	    default:
		DbgPrint("UNKNOWN-MINOR-CODE\n");
	    }
	    break;
	case IRP_MJ_CLEANUP:
	    DbgPrint("    CLEANUP\n");
	    break;
	case IRP_MJ_PNP:
	    switch (IoPacket->Request.MinorFunction) {
	    case IRP_MN_QUERY_DEVICE_RELATIONS:
		DbgPrint("    PNP  QUERY-DEVICE-RELATIONS  Type %s\n",
			 IopDbgDeviceRelationTypeStr(IoPacket->Request.QueryDeviceRelations.Type));
		break;
	    case IRP_MN_QUERY_ID:
		DbgPrint("    PNP  QUERY-ID  Type %s\n",
			 IopDbgQueryIdTypeStr(IoPacket->Request.QueryId.IdType));
		break;
	    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
		DbgPrint("    PNP  QUERY-RESOURCE-REQUIREMENTS\n");
		break;
	    case IRP_MN_QUERY_BUS_INFORMATION:
		DbgPrint("    PNP  QUERY-BUS-INFORMATION\n");
		break;
	    case IRP_MN_START_DEVICE:
		DbgPrint("    PNP  START-DEVICE  ResourceListSize %d TranslatedListSize %d\n",
			 IoPacket->Request.StartDevice.ResourceListSize,
			 IoPacket->Request.StartDevice.TranslatedListSize);
		break;
	    default:
		DbgPrint("    PNP  UNKNOWN-MINOR-FUNCTION\n");
	    }
	    break;
	default:
	    DbgPrint("    UNKNOWN-MAJOR-FUNCTION\n");
	    assert(FALSE);
	}
    } else if (IoPacket->Type == IoPacketTypeServerMessage) {
	switch (IoPacket->ServerMsg.Type) {
	case IoSrvMsgIoCompleted:
	    DbgPrint("    SERVER-MSG IO-COMPLETED OriginalRequestor %p Identifier %p "
		     "Final IO status 0x%08x Information %p ResponseDataSize 0x%x\n",
		     (PVOID)IoPacket->ServerMsg.IoCompleted.OriginalRequestor,
		     IoPacket->ServerMsg.IoCompleted.Identifier,
		     IoPacket->ServerMsg.IoCompleted.IoStatus.Status,
		     (PVOID)IoPacket->ServerMsg.IoCompleted.IoStatus.Information,
		     IoPacket->ServerMsg.IoCompleted.ResponseDataSize);
	    break;
	case IoSrvMsgLoadDriver:
	    DbgPrint("    SERVER-MSG LOAD-DRIVER BaseNameLength %d BaseName %s\n",
		     IoPacket->ServerMsg.LoadDriver.BaseNameLength,
		     IoPacket->ServerMsg.LoadDriver.BaseName);
	    break;
	case IoSrvMsgCacheFlushed:
	    DbgPrint("    SERVER-MSG CACHE-FLUSHED DeviceHandle %p FileHandle %p "
		     "IO status 0x%08x Information %p\n",
		     (PVOID)IoPacket->ServerMsg.CacheFlushed.DeviceObject,
		     (PVOID)IoPacket->ServerMsg.CacheFlushed.FileObject,
		     IoPacket->ServerMsg.CacheFlushed.IoStatus.Status,
		     (PVOID)IoPacket->ServerMsg.CacheFlushed.IoStatus.Information);
	    break;
	case IoSrvMsgCloseFile:
	    DbgPrint("    SERVER-MSG CLOSE-FILE FileHandle %p\n",
		     (PVOID)IoPacket->ServerMsg.CloseFile.FileObject);
	    break;
	case IoSrvMsgCloseDevice:
	    DbgPrint("    SERVER-MSG CLOSE-DEVICE DeviceHandle %p\n",
		     (PVOID)IoPacket->ServerMsg.CloseDevice.DeviceObject);
	    break;
	case IoSrvMsgForceDismount:
	    DbgPrint("    SERVER-MSG FORCE-DISMOUNT VolumeDevice %p\n",
		     (PVOID)IoPacket->ServerMsg.ForceDismount.VolumeDevice);
	    break;
	default:
	    DbgPrint("    INVALID SERVER MESSAGE TYPE %d\n", IoPacket->ServerMsg.Type);
	    assert(FALSE);
	}
    } else if (IoPacket->Type == IoPacketTypeClientMessage) {
	switch (IoPacket->ClientMsg.Type) {
	case IoCliMsgIoCompleted:
	    DbgPrint("    CLIENT-MSG IO-COMPLETED OriginalRequestor %p Identifier %p "
		     "Final IO status 0x%08x Information %p ResponseDataSize 0x%x\n",
		     (PVOID)IoPacket->ClientMsg.IoCompleted.OriginalRequestor,
		     IoPacket->ClientMsg.IoCompleted.Identifier,
		     IoPacket->ClientMsg.IoCompleted.IoStatus.Status,
		     (PVOID)IoPacket->ClientMsg.IoCompleted.IoStatus.Information,
		     IoPacket->ServerMsg.IoCompleted.ResponseDataSize);
	    break;
	case IoCliMsgForwardIrp:
	    DbgPrint("    CLIENT-MSG FORWARD-IRP OriginalRequestor %p Identifier %p "
		     "DeviceHandle %p NotifyCompletion %s AssociatedIrpCount %d "
		     "NewOffset 0x%llx NewLength 0x%x NewFileSize 0x%llx "
		     "NewAllocationSize 0x%llx NewValidDataLength 0x%llx\n",
		     (PVOID)IoPacket->ClientMsg.IoCompleted.OriginalRequestor,
		     IoPacket->ClientMsg.IoCompleted.Identifier,
		     (PVOID)IoPacket->ClientMsg.ForwardIrp.DeviceObject,
		     IoPacket->ClientMsg.ForwardIrp.NotifyCompletion ? "TRUE" : "FALSE",
		     IoPacket->ClientMsg.ForwardIrp.AssociatedIrpCount,
		     IoPacket->ClientMsg.ForwardIrp.NewOffset.QuadPart,
		     IoPacket->ClientMsg.ForwardIrp.NewLength,
		     IoPacket->ClientMsg.ForwardIrp.NewFileSize,
		     IoPacket->ClientMsg.ForwardIrp.NewAllocationSize,
		     IoPacket->ClientMsg.ForwardIrp.NewValidDataLength);
	    break;
	case IoCliMsgDirtyBuffers:
	    DbgPrint("    CLIENT-MSG DIRTY-BUFFERS");
	    for (ULONG i = 0; i < IO_CLI_MSG_MAX_DIRTY_BUFFER_COUNT; i++) {
		PVOID ViewAddress = (PVOID)IoPacket->ClientMsg.DirtyBuffers[i].ViewAddress;
		if (!ViewAddress) {
		    break;
		}
		DbgPrint("  ViewAddress[%d] %p DirtyBits[%d] 0x%llx", i, ViewAddress,
			 i, IoPacket->ClientMsg.DirtyBuffers[i].DirtyBits);
	    }
	    DbgPrint("\n");
	    break;
	case IoCliMsgFlushCache:
	    DbgPrint("    CLIENT-MSG FLUSH-CACHE DeviceHandle %p FileHandle %p\n",
		     (PVOID)IoPacket->ClientMsg.FlushCache.DeviceObject,
		     (PVOID)IoPacket->ClientMsg.FlushCache.FileObject);
	    break;
	default:
	    DbgPrint("    INVALID CLIENT MESSAGE TYPE %d\n", IoPacket->ClientMsg.Type);
	    assert(FALSE);
	}
    }
}
