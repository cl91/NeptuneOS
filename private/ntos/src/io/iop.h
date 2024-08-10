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
#define IopFreePool(Var) ExFreePoolWithTag(Var, NTOS_IO_TAG)

/* Pseudo requestor object that represents the NTOS Executive thread.
 * This is used by the cache manager to generate the paging IO requests. */
#define IOP_PAGING_IO_REQUESTOR		(PTHREAD)((MWORD)(~0ULL))

/* List of PENDING_IRPs queued by the NTOS Executive for paging IO. */
extern LIST_ENTRY IopNtosPendingIrpList;

/*
 * The PENDING_IRP represents a pending IRP that is queued by either a THREAD object
 * or a DRIVER object. There are several possible scenarios when it comes to IRP
 * flow. These are
 *
 * 1) If a THREAD object queues an IRP to a driver object, we add PENDING_IRP to the
 * THREAD object's pending IRP list and queue the IO_PACKET to the driver object's
 * IoPacketQueue. When the driver completes the IRP, the thread is notified by
 * signalling PENDING_IRP.IoCompletionEvent.
 *
 * 2) If a DRIVER object Drv0 queues a new IRP to another driver object Drv1, we add
 * the PENDING_IRP struct to Drv0's ForwardedIrpList and queue the IO_PACKET to Drv1's
 * IrpQueue. When Drv1 completes the IRP, Drv0 is notified via a IoCompleted message.
 *
 * 3) If a driver object Drv1 forwards an existing IRP to another driver object Drv2
 * without requesting server notification (NotifyCompletion == FALSE), we detach the
 * IO_PACKET from Drv1's PendingIoPacketList and queues it to Drv2's IoPacketQueue.
 * Whichever object has queued the IRP will be notified once the IRP is completed by
 * Drv2. Drv1 is never notified.
 *
 * 4) However, if the client has requested that the server notify it of the completion
 * of an IRP that it has forwarded (by setting NotifyCompletion to TRUE in the client
 * message), in addition to moving the IO_PACKET from Drv1 to Drv2, we also create a
 * new PENDING_IRP struct that points to the existing PENDING_IRP so we can later reply
 * to the higher-level driver (Drv1) to notify the completion of the IRP that was
 * forwarded. Note that although on client side the IRP IoCompletion routine may return
 * StopCompletion (STATUS_MORE_PROCESSING_REQUIRED) to halt the IRP completion (usually
 * the driver adds the IRP back to a driver-defined queue and completes the IRP at a
 * later time), this is transparent to the server as the client side dll (wdm.dll)
 * will not reply to server until the IRP has been completed at that level.
 *
 * See the following diagrams for details.
 *
 * NOTE: do not confuse this with the driver object's PendingIoPacketList. That list
 * is used to keep track of the IO packets that have been sent over to the driver.
 *
 * Flow of IO packets:
 *
 * Case 1: THREAD object queues an IRP on a DRIVER object
 *
 *  |-------------|       |-----------------------|       |-------------------------|
 *  |  IO_PACKET  |       | DRIVER.IoPacketQueue  |       | DRV.PendingIoPacketList |
 *  |-------------| ----> |-----------------------| ----> |-------------------------|
 *  | PENDING_IRP |       | THREAD.PendingIrpList |       | THREAD.PendingIrpList   |
 *  |-------------|       |-----------------------|       |-------------------------|
 *                                                               |       |
 *                                            or Case 3,4 <------|       |
 *                                                                      \|/
 *                                     |---------|            |------------------|
 *                                     | Server  |            | Driver completes |
 *                                     | signals |  <-------  | IRP, replies     |
 *                                     | THREAD  |            | to server        |
 *                                     |---------|            |------------------|
 *
 *
 * Case 2: Driver0 queues a new IRP on Driver1 via IoCallDriver
 *
 *  |-------------|       |-----------------------|       |--------------------------|
 *  |  IO_PACKET  |       |   Drv1.IoPacketQueue  |       | Drv1.PendingIoPacketList |
 *  |-------------| ----> |-----------------------| ----> |--------------------------|
 *  | PENDING_IRP |       | Drv0.ForwardedIrpList |       |  Drv0.ForwardedIrpList   |
 *  |-------------|       |-----------------------|       |--------------------------|
 *                                                              |         |
 *                                              or Case 3,4 <---|         |
 *                                                                       \|/
 *                                        |---------|            |----------------|
 *                                        | Server  |            | Drv1 completes |
 *                                        | replies | <--------- | IRP, replies   |
 *                                        | to Drv0 |            | to server      |
 *                                        |---------|            |----------------|
 *
 * Case 3: Driver1 forwards an existing IRP to Driver2 via IoCallDriver, NotifyCompletion == FALSE
 *
 *  |--------------------------|       |--------------------------|       |----------------|
 *  | Drv1.PendingIoPacketList |       | Drv2.PendingIoPacketList |       | Drv2 completes |
 *  |--------------------------| ----> |--------------------------| ----> | IRP, replies   |
 *  |       PENDING_IRP        |       |     DOES NOT CHANGE      |   |   | to server      |
 *  |--------------------------|       |--------------------------|   |   |----------------|
 *                                                                    |            |
 *                                                    or Case 3,4 <---|            |
 *                                                                                \|/
 *                                                                        |----------------|
 *                                                                        | Server signals |
 *                                                                        | thread/replies |
 *                                                                        | to driver      |
 *                                                                        |----------------|
 *
 * Case 4: Driver2 forwards an existing IRP to Driver3 via IoCallDriver, NotifyCompletion == TRUE
 *
 *  |--------------------------|       |--------------------------|       |----------------|
 *  | Drv2.PendingIoPacketList |       | Drv3.PendingIoPacketList |       | Drv3 completes |
 *  |--------------------------| ----> |--------------------------| ----> | IRP, replies   |
 *  |       PENDING_IRP        |       |     DOES NOT CHANGE      |   |   | to server      |
 *  |--------------------------|       |--------------------------|   |   |----------------|
 *              /|\                                                 or|           |
 *               |                                      Case 3,4 <----|          \|/
 *  |-----------------------------|       |-----------------------|       |----------------|
 *  | New PENDING_IRP that links  | ----> | Drv2.ForwardedIrpList | ----> | Server replies |
 *  | to the existing PENDING_IRP |       |-----------------------|       | to Drv2, waits |
 *  |-----------------------------|                                       | for Drv2 reply |
 *                                                                        |----------------|
 *                                                                                |
 *                                                                               \|/
 *                                                                        |----------------|
 *                                                                        | Server signals |
 *                                                                        | thread/replies |
 *                                                                        | to driver      |
 *                                                                        |----------------|
 */
typedef struct _PENDING_IRP {
    PIO_PACKET IoPacket; /* IO packet that the thread is waiting for a response for.
			  * The pending IO packet must be of type IoPacketTypeRequest.
			  * This must be the first member of this struct due to
			  * IoDbgDumpIoPacket. */
    POBJECT Requestor; /* Points to the THREAD or DRIVER object at this level.
			* This must be the second member of this struct due to
			* IoDbgDumpIoPacket. */
    LIST_ENTRY Link; /* List entry for THREAD.PendingIrpList or DRIVER.ForwardedIrpList */
    struct _PENDING_IRP *ForwardedTo; /* Points to the driver object that this IRP
				       * has been forwarded to. */
    struct _PENDING_IRP *ForwardedFrom; /* Back pointer for ForwardedTo. */
    MWORD InputBuffer; /* Pointer in the address space of the THREAD or DRIVER at this level */
    MWORD OutputBuffer;	/* Pointer in the address space of the THREAD or DRIVER at this level */
    BOOLEAN InterceptorCalled;	/* The IRP interception/completion callback can use this
				 * member to indicate whether the interception callback
				 * has been called on this PENDING_IRP. */
    /* ---- The following four members are only valid if Requestor is a THREAD object ---- */
    KEVENT IoCompletionEvent; /* Signaled when the IO request has been completed. */
    IO_STATUS_BLOCK IoResponseStatus; /* Response status to the pending IO packet. */
    ULONG IoResponseDataSize; /* Size of the response data to the pending IO packet. */
    PVOID IoResponseData; /* Response data to the pending IO packet. NULL if not supplied
			   * or if server-side allocation failed. */
    /* ---- The following member is only valid if Requestor is a DRIVER object ---- */
    PIO_DEVICE_OBJECT PreviousDeviceObject; /* Device object of this IRP before it is forwarded
					     * (this is called ForwardedFrom in irp.c). The
					     * device object in the IRP is always from the
					     * driver currently handling it (ie. the device
					     * it has been forwarded to). This is only valid
					     * if Requestor is a DRIVER object. */
} PENDING_IRP, *PPENDING_IRP;

/*
 * IRP completion callback and IRP interception callback
 *
 * A function in the main NT Executive thread can register a completion callback
 * or an interception callback when creating an IRP. Later when the IRP is completed
 * by a driver or when the higher driver forwards the IRP to a lower driver, the
 * IRP completion or interception callback is called. The completion callback is
 * called only when the IRP is completed by the top-level driver and in this case
 * the return value of the callback is ignored. The interception callback is called
 * every time the IRP is forwarded. If the interception callback returns TRUE, the
 * IRP is forwarded as normal. If the interception callback returns FALSE, the IRP
 * forwarding is stopped. Typically the callback function will save the IoPacket and
 * schedule the relevant work so another function can later call IopCompletePendingIrp
 * to complete the IRP. The callback function can also simply call it to complete the
 * IRP immediately. Note that IopCompletePendingIrp may deallocate the PENDING_IRP so
 * the caller should not access it after calling IopCompletePendingIrp. Note also that
 * completion callbacks should never call IopCompletePendingIrp. Only interception
 * callbacks can call it (when returning FALSE). Completion callbacks can call
 * IopCleanupPendingIrp if the original requestor is a thread object (or the NTOS
 * Executive). If a master IRP has associated IRPs, its completion/interception
 * callback will be called when the associated IRPs are completed or created/forwarded,
 * respectively.
 */
typedef BOOLEAN (*PIRP_CALLBACK)(IN PPENDING_IRP PendingIrp,
				 IN OUT PVOID Context,
				 IN BOOLEAN Completion);

FORCEINLINE BOOLEAN IopFileIsSynchronous(IN PIO_FILE_OBJECT File)
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
    ULONG64 AllocationSize;
    BOOLEAN OpenTargetDirectory;
    union {
	PNAMED_PIPE_CREATE_PARAMETERS NamedPipeCreateParameters;
	PMAILSLOT_CREATE_PARAMETERS MailslotCreateParameters;
    };
} OPEN_PACKET, *POPEN_PACKET;

/*
 * Extension of the OB_PARSE_CONTEXT.
 */
typedef struct _IO_OPEN_CONTEXT {
    IN OB_OPEN_CONTEXT Header;
    IN OPEN_PACKET OpenPacket;
    OUT ULONG_PTR Information; /* IO_STATUS_BLOCK.Information returned by the driver call */
} IO_OPEN_CONTEXT, *PIO_OPEN_CONTEXT;

/*
 * Creation context for the file object creation routine
 */
typedef struct _FILE_OBJ_CREATE_CONTEXT {
    PIO_DEVICE_OBJECT DeviceObject;
    PCSTR FileName;
    ULONG64 FileSize;
    PIO_FILE_CONTROL_BLOCK Fcb;
    PIO_VOLUME_CONTROL_BLOCK Vcb;
    PIO_FILE_OBJECT MasterFileObject;
    ULONG FileAttributes;
    ACCESS_MASK DesiredAccess;
    ULONG ShareAccess;
    BOOLEAN NoFcb;
    BOOLEAN AllocateCloseMsg;
} FILE_OBJ_CREATE_CONTEXT, *PFILE_OBJ_CREATE_CONTEXT;

/*
 * CloseDevice server message queued on a device object.
 */
typedef struct _CLOSE_DEVICE_MESSAGE {
    PIO_DRIVER_OBJECT DriverObject;
    PIO_DEVICE_OBJECT DeviceObject;
    PIO_PACKET Msg;
    LIST_ENTRY DeviceLink;
    LIST_ENTRY DriverLink;
} CLOSE_DEVICE_MESSAGE, *PCLOSE_DEVICE_MESSAGE;

/*
 * Worker thread of a driver object
 */
typedef struct _WORKER_THREAD {
    PTHREAD Thread;
    NOTIFICATION Notification;	/* Client side capability */
} WORKER_THREAD, *PWORKER_THREAD;

/*
 * Interrupt service of a driver object
 */
typedef struct _INTERRUPT_SERVICE {
    ULONG Vector;
    LIST_ENTRY Link;
    IRQ_HANDLER IrqHandler;
    PTHREAD IsrThread;
    CAP_TREE_NODE IsrThreadClientCap; /* Client side cap of the ISR thread cap */
    NOTIFICATION Notification;	      /* Client side capability */
    NOTIFICATION InterruptMutex;      /* Client side capability */
} INTERRUPT_SERVICE, *PINTERRUPT_SERVICE;

/*
 * Device node state.
 */
typedef enum _DEVICE_NODE_STATE {
    DeviceNodeUnspecified,
    DeviceNodeInitialized,
    DeviceNodeLoadDriverFailed,
    DeviceNodeDriversLoaded,
    DeviceNodeAddDeviceFailed,
    DeviceNodeDevicesAdded,
    DeviceNodeResourcesAssignmentFailed,
    DeviceNodeResourcesAssigned,
    DeviceNodeStartPending,
    DeviceNodeStartCompletion,
    DeviceNodeStartPostWork,
    DeviceNodeStartFailed,
    DeviceNodeStarted,
    DeviceNodeQueryStopped,
    DeviceNodeStopped,
    DeviceNodeRestartCompletion,
    DeviceNodeEnumeratePending,
    DeviceNodeEnumerateFailed,
    DeviceNodeEnumerateCompletion,
    DeviceNodeAwaitingQueuedDeletion,
    DeviceNodeAwaitingQueuedRemoval,
    DeviceNodeQueryRemoved,
    DeviceNodeRemovePendingCloses,
    DeviceNodeRemoved,
    DeviceNodeDeletePendingCloses,
    DeviceNodeDeleted,
    MaxDeviceNodeState
} DEVICE_NODE_STATE, *PDEVICE_NODE_STATE;

#define DEVNODE_HISTORY_SIZE	(16)	/* must be a multiple of two */

/*
 * Device Node for the PNP manager
 */
typedef struct _DEVICE_NODE {
    DEVICE_NODE_STATE StateHistory[DEVNODE_HISTORY_SIZE];
    ULONG CurrentState;		/* Index into StateHistory */
    NTSTATUS ErrorStatus;
    PIO_DEVICE_OBJECT PhyDevObj;
    PCSTR DeviceId;
    PCSTR InstanceId;
    struct _DEVICE_NODE *Parent;
    LIST_ENTRY ChildrenList;
    LIST_ENTRY SiblingLink;
    PCSTR DriverServiceName;
    ULONG UpperFilterCount;
    ULONG LowerFilterCount;
    PCSTR *UpperFilterDriverNames;
    PCSTR *LowerFilterDriverNames;
    PIO_DRIVER_OBJECT FunctionDriverObject;
    PIO_DRIVER_OBJECT *UpperFilterDrivers;
    PIO_DRIVER_OBJECT *LowerFilterDrivers;
    PCM_RESOURCE_LIST Resources;
} DEVICE_NODE, *PDEVICE_NODE;

/*
 * Call this if you need to get the device node of a device object.
 * DO NOT just do DeviceObject->DeviceNode since we only keep track
 * of device nodes for PDOs (lowest device object in a device stack).
 */
FORCEINLINE PDEVICE_NODE IopGetDeviceNode(IN PIO_DEVICE_OBJECT DeviceObject)
{
    assert(DeviceObject != NULL);
    /* Locate the lowest device object */
    PIO_DEVICE_OBJECT Pdo = DeviceObject;
    while (Pdo->AttachedTo != NULL) {
	Pdo = Pdo->AttachedTo;
	assert(Pdo != NULL);
    }
    return Pdo->DeviceNode;
}

FORCEINLINE VOID IopDeviceNodeSetCurrentState(IN PDEVICE_NODE Node,
					      IN DEVICE_NODE_STATE State)
{
    assert(Node != NULL);
    assert(Node->CurrentState < DEVNODE_HISTORY_SIZE);
    Node->CurrentState++;
    Node->CurrentState %= DEVNODE_HISTORY_SIZE;
    Node->StateHistory[Node->CurrentState] = State;
}

/* init.c */
extern LIST_ENTRY IopDriverList;

/*
 * Returns the device object of the given device handle, optionally
 * checking whether the device belongs to the driver object
 */
FORCEINLINE PIO_DEVICE_OBJECT IopGetDeviceObject(IN GLOBAL_HANDLE DeviceHandle,
						 IN OPTIONAL PIO_DRIVER_OBJECT DriverObject)
{
    if (DeviceHandle == 0) {
	return NULL;
    }
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

FORCEINLINE PIO_DEVICE_OBJECT IopGetTopDevice(IN PIO_DEVICE_OBJECT Device)
{
    assert(Device != NULL);
    while (Device->AttachedDevice != NULL) {
	Device = Device->AttachedDevice;
    }
    return Device;
}

/* irp.c */
NTSTATUS IopWaitForMultipleIoCompletions(IN ASYNC_STATE State,
					 IN PTHREAD Thread,
					 IN BOOLEAN Alertable,
					 IN WAIT_TYPE WaitType,
					 IN PPENDING_IRP *PendingIrps,
					 IN ULONG IrpCount);
NTSTATUS IopCallDriverEx(IN PTHREAD Thread,
			 IN PIO_REQUEST_PARAMETERS Irp,
			 IN OPTIONAL PIO_DRIVER_OBJECT DriverObject,
			 OUT PPENDING_IRP *pPendingIrp);
VOID IopCleanupPendingIrp(IN PPENDING_IRP PendingIrp);
VOID IopCompletePendingIrp(IN OUT PPENDING_IRP PendingIrp,
			   IN IO_STATUS_BLOCK IoStatus,
			   IN PVOID ResponseData,
			   IN ULONG ResponseDataSize);
VOID IopCancelPendingIrp(IN PPENDING_IRP PendingIrp);
PPENDING_IRP IopLocateIrpInOriginalRequestor(IN GLOBAL_HANDLE OriginalRequestor,
					     IN PIO_PACKET IoPacket);

FORCEINLINE VOID IopCleanupPendingIrpList(IN PTHREAD Thread)
{
    LoopOverList(PendingIrp, &Thread->PendingIrpList, PENDING_IRP, Link) {
	IopCleanupPendingIrp(PendingIrp);
    }
}

FORCEINLINE NTSTATUS IopCallDriver(IN PTHREAD Thread,
				   IN PIO_REQUEST_PARAMETERS Irp,
				   OUT PPENDING_IRP *pPendingIrp)
{
    return IopCallDriverEx(Thread, Irp, NULL, pPendingIrp);
}

/* file.c */
NTSTATUS IopCreateFcb(OUT PIO_FILE_CONTROL_BLOCK *pFcb,
		      IN ULONG64 FileSize,
		      IN PCSTR FileName,
		      IN PIO_VOLUME_CONTROL_BLOCK Vcb,
		      IN ULONG FileAttributes);
VOID IopDeleteFcb(IN PIO_FILE_CONTROL_BLOCK Fcb);
NTSTATUS IopFileObjectCreateProc(IN POBJECT Object,
				 IN PVOID CreaCtx);
NTSTATUS IopFileObjectParseProc(IN POBJECT Self,
				IN PCSTR Path,
				IN BOOLEAN CaseInsensitive,
				OUT POBJECT *FoundObject,
				OUT PCSTR *RemainingPath);
NTSTATUS IopFileObjectOpenProc(IN ASYNC_STATE State,
			       IN PTHREAD Thread,
			       IN POBJECT Object,
			       IN PCSTR SubPath,
			       IN ACCESS_MASK DesiredAccess,
			       IN ULONG Attributes,
			       IN POB_OPEN_CONTEXT ParseContext,
			       OUT POBJECT *pOpenedInstance,
			       OUT PCSTR *pRemainingPath);
NTSTATUS IopFileObjectCloseProc(IN ASYNC_STATE State,
				IN struct _THREAD *Thread,
				IN POBJECT Self);
VOID IopFileObjectDeleteProc(IN POBJECT Self);
NTSTATUS IopCreateMasterFileObject(IN PCSTR FileName,
				   IN PIO_DEVICE_OBJECT DeviceObject,
				   IN ULONG FileAttributes,
				   IN ACCESS_MASK DesiredAccess,
				   IN ULONG ShareAccess,
				   OUT PIO_FILE_OBJECT *pFile);

/*
 * Returns the file object with the given global handle
 */
FORCEINLINE PIO_FILE_OBJECT IopGetFileObject(IN PIO_DEVICE_OBJECT DevObj,
					     IN GLOBAL_HANDLE Handle)
{
    assert(DevObj);
    if (Handle == 0) {
	return NULL;
    }
    LoopOverList(FileObj, &DevObj->OpenFileList, IO_FILE_OBJECT, DeviceLink) {
	if (FileObj == GLOBAL_HANDLE_TO_OBJECT(Handle)) {
	    return FileObj;
	}
    }
    return NULL;
}

/* device.c */
NTSTATUS IopDeviceObjectCreateProc(IN POBJECT Object,
				   IN PVOID CreaCtx);
NTSTATUS IopDeviceObjectParseProc(IN POBJECT Self,
				  IN PCSTR Path,
				  IN BOOLEAN CaseInsensitive,
				  OUT POBJECT *FoundObject,
				  OUT PCSTR *RemainingPath);
NTSTATUS IopDeviceObjectInsertProc(IN POBJECT Self,
				   IN POBJECT Object,
				   IN PCSTR Path);
VOID IopDeviceObjectRemoveProc(IN POBJECT Subobject);
NTSTATUS IopDeviceObjectOpenProc(IN ASYNC_STATE State,
				 IN PTHREAD Thread,
				 IN POBJECT Object,
				 IN PCSTR SubPath,
				 IN ACCESS_MASK DesiredAccess,
				 IN ULONG Attributes,
				 IN POB_OPEN_CONTEXT ParseContext,
				 OUT POBJECT *pOpenedInstance,
				 OUT PCSTR *pRemainingPath);
NTSTATUS IopDeviceObjectCloseProc(IN ASYNC_STATE State,
				  IN PTHREAD Thread,
				  IN POBJECT Object);
VOID IopDeviceObjectDeleteProc(IN POBJECT Self);
NTSTATUS IopOpenDevice(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
		       IN PIO_DEVICE_OBJECT Device,
		       IN PIO_FILE_OBJECT MasterFileObject,
		       IN PCSTR SubPath,
		       IN ACCESS_MASK DesiredAccess,
		       IN ULONG Attributes,
		       IN PIO_OPEN_CONTEXT OpenContext,
		       OUT PIO_FILE_OBJECT *pFileObject);
NTSTATUS IopGrantDeviceHandleToDriver(IN OPTIONAL PIO_DEVICE_OBJECT DeviceObject,
				      IN PIO_DRIVER_OBJECT DriverObject,
				      OUT GLOBAL_HANDLE *DeviceHandle);
VOID IopForceRemoveDevice(IN PIO_DEVICE_OBJECT DevObj);
VOID IopDbgDumpDeviceObject(IN PIO_DEVICE_OBJECT DeviceObject,
			    IN ULONG Indentation);

FORCEINLINE BOOLEAN IopDeviceHandleIsGranted(IN PIO_DEVICE_OBJECT DeviceObject,
					     IN PIO_DRIVER_OBJECT DriverObject)
{
    LoopOverList(ExistingReq, &DeviceObject->CloseMsgList, CLOSE_DEVICE_MESSAGE, DeviceLink) {
	if (ExistingReq->DriverObject == DriverObject) {
	    return TRUE;
	}
    }
    return FALSE;
}

/* driver.c */
NTSTATUS IopDriverObjectCreateProc(POBJECT Object,
				   IN PVOID CreaCtx);
VOID IopDriverObjectDeleteProc(IN POBJECT Self);
NTSTATUS IopLoadDriver(IN ASYNC_STATE State,
		       IN PTHREAD Thread,
		       IN PCSTR DriverServicePath,
		       OUT OPTIONAL PIO_DRIVER_OBJECT *pDriverObject);

/* cache.c */
NTSTATUS CcInitializeCacheManager();
VOID CcSetFileSize(IN PIO_FILE_CONTROL_BLOCK Fcb,
		   IN ULONG64 NewFileSize);
VOID CiFlushDirtyDataToVolume(IN PIO_FILE_CONTROL_BLOCK Fcb);
VOID CiFlushPrivateCacheToShared(IN PIO_FILE_CONTROL_BLOCK Fcb);

/* volume.c */
NTSTATUS IopInitFileSystem();
NTSTATUS IopMountVolume(IN ASYNC_STATE State,
			IN PTHREAD Thread,
			IN PIO_DEVICE_OBJECT DevObj);
VOID IopDismountVolume(IN PIO_VOLUME_CONTROL_BLOCK Vcb,
		       IN BOOLEAN Force);
VOID IopDbgDumpVcb(IN PIO_VOLUME_CONTROL_BLOCK Vcb);

FORCEINLINE BOOLEAN IopIsStorageDevice(IN PIO_DEVICE_OBJECT DevObj)
{
    DEVICE_TYPE Type = DevObj->DeviceInfo.DeviceType;
    return Type == FILE_DEVICE_DISK || Type == FILE_DEVICE_CD_ROM ||
	Type == FILE_DEVICE_TAPE || Type == FILE_DEVICE_VIRTUAL_DISK;
}

FORCEINLINE BOOLEAN IopIsVolumeMounted(IN PIO_DEVICE_OBJECT DevObj)
{
    return DevObj->Vcb && !DevObj->Vcb->MountInProgress;
}
