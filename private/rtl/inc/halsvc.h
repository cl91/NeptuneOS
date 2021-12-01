#pragma once

#include <services.h>
#include <halsvc_gen.h>

compile_assert(TOO_MANY_HAL_SERVICES, NUMBER_OF_HAL_SERVICES < 0x1000UL);

#define DRIVER_IRP_BUFFER_RESERVE	(64 * 1024)
#define DRIVER_IRP_BUFFER_COMMIT	(8 * 1024)

/*
 * Global handle type.
 *
 * See ntos/inc/ob.h
 */
typedef MWORD GLOBAL_HANDLE;

/* Make sure we match MSVC's struct packing */
#include <pshpack4.h>

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

/* Parameters to communicate with client drivers about file object creation,
 * passed by CREATE, CREATE_MAILSLOT, CREATE_NAMED_PIPE
 */
typedef struct _FILE_OBJECT_CREATE_PARAMETERS {
    BOOLEAN ReadAccess;
    BOOLEAN WriteAccess;
    BOOLEAN DeleteAccess;
    BOOLEAN SharedRead;
    BOOLEAN SharedWrite;
    BOOLEAN SharedDelete;
    ULONG Flags;
    PCSTR FileName; /* CLIENT Pointer to the file name buffer. NUL-terminated. */
} FILE_OBJECT_CREATE_PARAMETERS, *PFILE_OBJECT_CREATE_PARAMETERS;

typedef enum _IO_REQUEST_PACKET_TYPE {
    IrpTypeRequest,
    IrpTypeIoCompleted
} IO_REQUEST_PACKET_TYPE;

/*
 * Declares a union type of server-side pointer and
 * client-side global handle
 */
#define DECLARE_POINTER_TYPE(Type)		\
    typedef union _ ## Type ## _PTR {		\
	struct _ ## Type *Object;		\
	GLOBAL_HANDLE Handle;			\
    } Type ## _PTR

DECLARE_POINTER_TYPE(THREAD);
DECLARE_POINTER_TYPE(IO_DEVICE_OBJECT);
DECLARE_POINTER_TYPE(IO_FILE_OBJECT);
DECLARE_POINTER_TYPE(IO_REQUEST_PACKET);

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
    union {
	struct {
	    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters; /* Must be first. See ntos/irp.c */
	    ULONG Options;
	    ULONG FileAttributes;
	    ULONG ShareAccess;
	} Create;
	struct {
	    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters; /* Must be first */
	    ULONG Options;
	    USHORT ShareAccess;
	    NAMED_PIPE_CREATE_PARAMETERS Parameters;
	} CreatePipe;
	struct {
	    FILE_OBJECT_CREATE_PARAMETERS FileObjectParameters; /* Must be first */
	    ULONG Options;
	    USHORT ShareAccess;
	    MAILSLOT_CREATE_PARAMETERS Parameters;
	} CreateMailslot;
	struct {
	    ULONG Length;
	    ULONG Key;
	    LARGE_INTEGER ByteOffset;
	} Read;
	struct {
	    ULONG Length;
	    ULONG Key;
	    LARGE_INTEGER ByteOffset;
	} Write;
	struct {
	    PVOID InputBuffer;	/* Client-side pointer! */
	    PVOID OutputBuffer;	/* Client-side pointer! */
	    ULONG InputBufferLength;
	    ULONG OutputBufferLength;
	    ULONG IoControlCode;
	} DeviceIoControl;
    } Parameters;
} IO_REQUEST_PARAMETERS, *PIO_REQUEST_PARAMETERS;

/*
 * This is the actual data structure being passed between the server
 * task and the client driver processes. The public struct IRP is exposed
 * in wdm.h in order to remain semi-compatible with Windows/ReactOS.
 */
typedef struct _IO_REQUEST_PACKET {
    IO_REQUEST_PACKET_TYPE Type;
    union {
	IO_STATUS_BLOCK IoStatus; /* For Type == IrpTypeIoCompleted */
	IO_REQUEST_PARAMETERS Request; /* Type == IrpTypeRequest */
    };
    IO_REQUEST_PACKET_PTR ParentIrp; /* Pointer to the parent IRP in the IO stack. When the IRP
				      * is the initial request from a thread, ParentIrp is NULL.
				      * For IrpTypeIoCompleted, ParentIrp points to the ThisIrp handle
				      * of the request IRP that the response packet is replying to.
				      * Note that once the system has completed the IO operation
				      * and has replied to the client thread, the system
				      * may reuse old IRP handles for new IRPs. */
    THREAD_PTR Thread; /* Originating thread. Valid only when this is the top-level IRP in the IO stack. */
    union {
	LIST_ENTRY IrpLink; /* List entry for either IrpQueue or PendingIrpList of the driver object.
			     * This is only valid when the IRP object is being queued on the driver
			     * object or is in the driver's pending IRP list. */
	struct {
	    GLOBAL_HANDLE ThisIrp; /* Global handle to identify this IRP. This is only valid when the IRP
				    * object is in the driver's IRP buffers. When we pass the IRP to the
				    * driver process we copy the server-side IRP (allocated on the ExPool)
				    * to the driver process's incoming IRP buffer. This handle then refers
				    * to the server-side IRP, and is unique among all IRPs currently being
				    * processed by the system. The system may reuse old handles of IRPs that
				    * have already been processed. */
	    NTSTATUS ErrorStatus; /* If the driver for some reason cannot process this IRP (for instance,
				   * if it ran out of memory), the error status indicates that error.
				   * Server checks this parameter when driver has replied after processing
				   * the previous batch of IRPs. If this is not STATUS_SUCCESS, this IRP
				   * is canceled immediately and the thread initiating the IO is informed.
				   * Note that we rely on the driver's cooperation for this to function.
				   * Since the server always validates the ThisIrp pointer, malicious
				   * driver can only cancel its own IRPs (ie. only IRPs sent to this driver
				   * will be affected). */
	};
    }; /* IRP objects are either physically located in the ExPool and attached to a driver
	* object (ie. in the IrqQueue or in the PendingIrqList of the driver object), or
	* located in the driver's IRP buffers. The IRP in the driver's buffers always points
	* to its original via the ThisIrp handle. The driver process can then use ThisIrp to
	* uniquely identify different IRPs being sent to it, and set the ParentIrp member of
	* the response IRP. If a malicious driver passes an invalid ParentIrp pointer in its
	* response IRP, we reject the response IRP. */
} IO_REQUEST_PACKET, *PIO_REQUEST_PACKET;

#include <poppack.h>

/*
 * Inline functions
 */
static inline VOID IoDbgDumpFileObjectCreateParameters(IN PFILE_OBJECT_CREATE_PARAMETERS Params)
{
    /* CAREFUL: We must not read FileName directly. It's a CLIENT pointer! */
    DbgPrint("ReadAccess %s WriteAccess %s DeleteAccess %s SharedRead %s "
	     "SharedWrite %s SharedDelete %s Flags 0x%08x FileName %p\n",
	     Params->ReadAccess ? "TRUE" : "FALSE",
	     Params->WriteAccess ? "TRUE" : "FALSE",
	     Params->DeleteAccess ? "TRUE" : "FALSE",
	     Params->SharedRead ? "TRUE" : "FALSE",
	     Params->SharedWrite ? "TRUE" : "FALSE",
	     Params->SharedDelete ? "TRUE" : "FALSE",
	     Params->Flags, Params->FileName);
}

static inline VOID IoDbgDumpIoRequestPacket(IN PIO_REQUEST_PACKET Irp,
					    IN BOOLEAN ClientSide)
{
    DbgTrace("Dumping IO Request Packet %p size %zd\n", Irp, sizeof(IO_REQUEST_PACKET));
    DbgPrint("    TYPE ");
    switch (Irp->Type) {
    case IrpTypeRequest:
	DbgPrint("IO REQUEST\n");
	break;
    case IrpTypeIoCompleted:
	DbgPrint("IO COMPLETION\n");
	break;
    default:
	DbgPrint("INVALID!!\n");
	return;
    }
    if (Irp->Type == IrpTypeRequest) {
	DbgPrint("    Major function %d.  Minor function %d.  Flags 0x%x.  Control 0x%x\n",
		 Irp->Request.MajorFunction, Irp->Request.MinorFunction,
		 Irp->Request.Flags, Irp->Request.Control);
	switch (Irp->Request.MajorFunction) {
	case IRP_MJ_CREATE:
	    DbgPrint("    CREATE  Options 0x%x FileAttr 0x%x ShareAccess 0x%x\n",
		     Irp->Request.Parameters.Create.Options,
		     Irp->Request.Parameters.Create.FileAttributes,
		     Irp->Request.Parameters.Create.ShareAccess);
	    DbgPrint("        FileObjectCreateParameters ");
	    IoDbgDumpFileObjectCreateParameters(&Irp->Request.Parameters.Create.FileObjectParameters);
	case IRP_MJ_DEVICE_CONTROL:
	    DbgPrint("    DEVICE-CONTROL  IoControlCode %d InputBuffer %p Length 0x%x OutputBuffer %p Length 0x%x\n",
		     Irp->Request.Parameters.DeviceIoControl.IoControlCode,
		     Irp->Request.Parameters.DeviceIoControl.InputBuffer,
		     Irp->Request.Parameters.DeviceIoControl.InputBufferLength,
		     Irp->Request.Parameters.DeviceIoControl.OutputBuffer,
		     Irp->Request.Parameters.DeviceIoControl.OutputBufferLength);
	}
	if (ClientSide) {
	    DbgPrint("    DeviceHandle %p FileHandle %p\n",
		     (PVOID)Irp->Request.Device.Handle, (PVOID)Irp->Request.File.Handle);
	} else {
	    DbgPrint("    DeviceObject %p FileObject %p\n",
		     Irp->Request.Device.Object, Irp->Request.File.Object);
	}
    } else if (Irp->Type == IrpTypeIoCompleted) {
	DbgPrint("    Final IO status 0x%08x Information %p\n", Irp->IoStatus.Status,
		 (PVOID) Irp->IoStatus.Information);
    }
    if (ClientSide) {
	DbgPrint("    Parent IRP handle in IO stack %p\n", (PVOID)Irp->ParentIrp.Handle);
	DbgPrint("    ThreadHandle %p\n", (PVOID)Irp->Thread.Handle);
    } else {
	DbgPrint("    Parent IRP object in IO stack %p\n", Irp->ParentIrp.Object);
	DbgPrint("    ThreadObject %p\n", Irp->Thread.Object);
    }
    if (ClientSide) {
	DbgPrint("    ThisIrp %p\n", (PVOID) Irp->ThisIrp);
    }
}
