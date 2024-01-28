#pragma once

#include <nt.h>
#include <services.h>
#include <wdmsvc_gen.h>

compile_assert(TOO_MANY_WDM_SERVICES, NUMBER_OF_WDM_SERVICES < 0x1000UL);

#define DRIVER_IO_PACKET_BUFFER_RESERVE	(64 * 1024)
#define DRIVER_IO_PACKET_BUFFER_COMMIT	(8 * 1024)

#define PNP_ROOT_ENUMERATOR	"\\Device\\pnp"

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
#define MDL_PFN_ATTR_MASK	((1UL << (MDL_PFN_ATTR_BITS+1)) - 1)
#define MDL_PFN_PAGE_COUNT_MASK	((1UL << (MDL_PFN_PAGE_COUNT_BITS+1)) - 1)
#define MDL_PFN_ATTR_LARGE_PAGE	(0x1)

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
    ULONG DeviceCharacteristics;
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
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    ULONG FileNameOffset; /* Offset to the NUL-terminated file name buffer,
			   * starting from the beginning of the IO packet. */
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

/*
 * Parameters for an IO request.
 */
typedef struct _IO_REQUEST_PARAMETERS {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    IO_DEVICE_OBJECT_PTR Device;
    IO_FILE_OBJECT_PTR File;
    MWORD InputBuffer; /* Client-side pointer! When creating a new IRP, this is
			* in the original requestor's address space. When the
			* IRP is queued on a driver object, this is the buffer
			* address mapped in the driver address space. The
			* original address is saved in the PENDING_IRP struct.
			* Same goes for the output buffer below. This is used
			* by IRP_MJ_WRITE and IOCTL IRPs. */
    MWORD OutputBuffer;	/* See InputBuffer. This is used by IRP_MJ_READ and
			 * IOCTL IRPs. Note it should be apparent from the
			 * usage that input and output here is with respect
			 * to the device. In other words, READ IRP will read
			 * from the device and write to the OutputBuffer and
			 * WRITE IRP will read from the InputBuffer and write
			 * to the device. */
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    ULONG InputBufferPfn; /* Page frame database of the input buffer. This is
			   * an offset from the beginning of the IO_PACKET */
    ULONG InputBufferPfnCount;
    ULONG OutputBufferPfn; /* Page frame database of the output buffer. This is
			    * an offset from the beginning of the IO_PACKET */
    ULONG OutputBufferPfnCount;
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
	    IO_DEVICE_INFO PhysicalDeviceInfo; /* Request.Device is the physical
						* device object */
	} AddDevice; /* Used by the PNP manager to inform the
		      * driver to add a new device */
	struct {
	    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters;
	    ULONG Options;
	    ULONG FileAttributes;
	    ULONG ShareAccess;
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
    IoSrvMsgIoCompleted
} IO_SERVER_MESSAGE_TYPE;

/*
 * Message packet from the server.
 */
typedef struct _IO_PACKET_SERVER_MESSAGE {
    IO_SERVER_MESSAGE_TYPE Type;
    union {
	IO_COMPLETED_MESSAGE IoCompleted;
    };
} IO_PACKET_SERVER_MESSAGE, *PIO_PACKET_SERVER_MESSAGE;

/*
 * Message type of client messages
 */
typedef enum _IO_CLIENT_MESSAGE_TYPE {
    IoCliMsgIoCompleted,
    IoCliMsgForwardIrp
} IO_CLIENT_MESSAGE_TYPE;

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
	    BOOLEAN NotifyCompletion; /* TRUE if the client driver wants the server to
				       * notify it after the IRP has been processed. */
	    LARGE_INTEGER NewOffset; /* For IRP_MJ_READ and IRP_MJ_WRITE, this stores
				      * the ByteOffset of the IRP being forwarded. */
	    ULONG NewLength; /* For IRP_MJ_READ and IRP_MJ_WRITE, this stores the new
			      * Length of the requested read/write. It must be less than
			      * or equal to the original length parameter. */
	} ForwardIrp;
    };
} IO_PACKET_CLIENT_MESSAGE, *PIO_PACKET_CLIENT_MESSAGE;

/*
 * This is the actual data structure being passed between the server
 * task and the client driver processes. The public IRP struct is exposed
 * in wdm.h in order to remain (semi-)compatible with Windows/ReactOS.
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
static inline VOID IoDbgDumpFileObjectCreateParameters(IN PIO_PACKET IoPacket,
						       IN PFILE_OBJECT_CREATE_PARAMETERS Params)
{
    DbgPrint("ReadAccess %s WriteAccess %s DeleteAccess %s SharedRead %s "
	     "SharedWrite %s SharedDelete %s Flags 0x%08x FileName %p\n",
	     Params->ReadAccess ? "TRUE" : "FALSE",
	     Params->WriteAccess ? "TRUE" : "FALSE",
	     Params->DeleteAccess ? "TRUE" : "FALSE",
	     Params->SharedRead ? "TRUE" : "FALSE",
	     Params->SharedWrite ? "TRUE" : "FALSE",
	     Params->SharedDelete ? "TRUE" : "FALSE",
	     Params->Flags, (PUCHAR)IoPacket + Params->FileNameOffset);
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
    DbgTrace("Dumping IO Packet %p size %d\n", IoPacket, IoPacket->Size);
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
	DbgPrint("    InputBuffer %p Length 0x%x PfnCount %d "
		 " OutputBuffer %p Length 0x%x PfnCount %d\n",
		 (PVOID)IoPacket->Request.InputBuffer,
		 IoPacket->Request.InputBufferLength,
		 IoPacket->Request.InputBufferPfnCount,
		 (PVOID)IoPacket->Request.OutputBuffer,
		 IoPacket->Request.OutputBufferLength,
		 IoPacket->Request.OutputBufferPfnCount);
	DbgPrint("    Major function %d.  Minor function %d.  Flags 0x%x.  Control 0x%x\n",
		 IoPacket->Request.MajorFunction, IoPacket->Request.MinorFunction,
		 IoPacket->Request.Flags, IoPacket->Request.Control);
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
	case IRP_MJ_READ:
	    DbgPrint("    READ  Key 0x%x ByteOffset 0x%llx\n",
		     IoPacket->Request.Read.Key, IoPacket->Request.Read.ByteOffset.QuadPart);
	    break;
	case IRP_MJ_DEVICE_CONTROL:
	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
	    DbgPrint("    %sDEVICE-CONTROL  IoControlCode 0x%x\n",
		     IoPacket->Request.MajorFunction == IRP_MJ_DEVICE_CONTROL ? "" : "INTERNAL-",
		     IoPacket->Request.DeviceIoControl.IoControlCode);
	    break;
	case IRP_MJ_FILE_SYSTEM_CONTROL:
	    switch (IoPacket->Request.MinorFunction) {
	    case IRP_MN_MOUNT_VOLUME:
		DbgPrint("    FILE-SYSTEM-CONTROL  MOUNT-VOLUME  StorageDeviceHandle 0x%zx\n",
			 IoPacket->Request.MountVolume.StorageDevice);
		break;
	    default:
		DbgPrint("    FILE-SYSTEM-CONTROL  UNKNOWN-MINOR-CODE\n");
	    }
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
		     "DeviceHandle %p NotifyCompletion %s\n",
		     (PVOID)IoPacket->ClientMsg.IoCompleted.OriginalRequestor,
		     IoPacket->ClientMsg.IoCompleted.Identifier,
		     (PVOID)IoPacket->ClientMsg.ForwardIrp.DeviceObject,
		     IoPacket->ClientMsg.ForwardIrp.NotifyCompletion ? "TRUE" : "FALSE");
	    break;
	default:
	    DbgPrint("    INVALID CLIENT MESSAGE TYPE %d\n", IoPacket->ClientMsg.Type);
	}
    }
}
