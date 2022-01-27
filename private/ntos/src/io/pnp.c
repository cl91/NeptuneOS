#include "iop.h"

static PDEVICE_NODE IopRootDeviceNode;

static inline VOID IopInitializeDeviceNode(IN PDEVICE_NODE DeviceNode,
					   IN PIO_DEVICE_OBJECT DeviceObject,
					   IN OPTIONAL PDEVICE_NODE ParentNode)
{
    assert(DeviceNode != NULL);
    assert(DeviceObject != NULL);
    /* Locate the lowest device object */
    PIO_DEVICE_OBJECT Pdo = DeviceObject;
    while (Pdo->AttachedTo != NULL) {
	Pdo = Pdo->AttachedTo;
    }
    DeviceNode->PhyDevObj = Pdo;
    DeviceNode->Parent = ParentNode;
    InitializeListHead(&DeviceNode->ChildrenList);
    if (ParentNode != NULL) {
	InsertTailList(&ParentNode->ChildrenList, &DeviceNode->SiblingLink);
    }
    DeviceObject = Pdo;
    while (DeviceObject != NULL) {
	DeviceObject->DeviceNode = DeviceNode;
	DeviceObject = DeviceObject->AttachedDevice;
    }
}

static inline NTSTATUS IopCreateDeviceNode(IN PIO_DEVICE_OBJECT DeviceObject,
					   IN OPTIONAL PDEVICE_NODE ParentNode,
					   OUT OPTIONAL PDEVICE_NODE *pDevNode)
{
    IopAllocatePool(DeviceNode, DEVICE_NODE);
    IopInitializeDeviceNode(DeviceNode, DeviceObject, ParentNode);
    if (pDevNode) {
	*pDevNode = DeviceNode;
    }
    return STATUS_SUCCESS;
}

static inline VOID IopFreeDeviceNode(IN PDEVICE_NODE DeviceNode)
{
}

static inline NTSTATUS IopDeviceNodeSetDeviceId(IN PDEVICE_NODE DeviceNode,
						IN PCSTR DeviceId,
						IN BUS_QUERY_ID_TYPE IdType)
{
    assert(DeviceNode != NULL);
    switch (IdType) {
    case BusQueryDeviceID:
	assert(DeviceNode->DeviceId == NULL);
	DeviceNode->DeviceId = RtlDuplicateString(DeviceId, NTOS_IO_TAG);
	if (DeviceNode->DeviceId == NULL) {
	    return STATUS_NO_MEMORY;
	}
	break;
    case BusQueryInstanceID:
	assert(DeviceNode->InstanceId == NULL);
	DeviceNode->InstanceId = RtlDuplicateString(DeviceId, NTOS_IO_TAG);
	if (DeviceNode->InstanceId == NULL) {
	    return STATUS_NO_MEMORY;
	}
	break;
    default:
	DbgTrace("Invalid id type %d\n", IdType);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS IopCreateBusDeviceNode(IN PIO_DRIVER_OBJECT DriverObject,
				       IN PCSTR BusDeviceId,
				       IN PCSTR BusInstanceId,
				       IN PIO_DEVICE_OBJECT BusFdo,
				       IN OPTIONAL ULONG DeviceCount,
				       IN OPTIONAL PGLOBAL_HANDLE DeviceHandles,
				       IN OPTIONAL PDEVICE_NODE ParentDeviceNode,
				       OUT PDEVICE_NODE *pDeviceNode)
{
    assert(DriverObject != NULL);
    assert(BusFdo != NULL);
    assert(DeviceCount == 0 || DeviceHandles != NULL);
    assert(pDeviceNode != NULL);
    PDEVICE_NODE BusDeviceNode = NULL;
    RET_ERR(IopCreateDeviceNode(BusFdo, ParentDeviceNode, &BusDeviceNode));
    assert(BusDeviceNode != NULL);
    RET_ERR(IopDeviceNodeSetDeviceId(BusDeviceNode, BusDeviceId, BusQueryDeviceID));
    RET_ERR(IopDeviceNodeSetDeviceId(BusDeviceNode, BusInstanceId, BusQueryInstanceID));
    for (ULONG i = 0; i < DeviceCount; i++) {
	PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(DeviceHandles[i],
							    DriverObject);
	if (DeviceObject == NULL) {
	    DbgTrace("Invalid device handle %p received for driver object %p\n",
		     (PVOID)DeviceHandles[i], DriverObject);
	    return STATUS_NO_SUCH_DEVICE;
	}
	RET_ERR(IopCreateDeviceNode(DeviceObject, BusDeviceNode, NULL));
    }
    *pDeviceNode = BusDeviceNode;
    return STATUS_SUCCESS;
}

static VOID IopPopulateQueryDeviceRelationsRequest(IN PIO_PACKET IoPacket,
						   IN PIO_DEVICE_OBJECT BusDevice,
						   IN DEVICE_RELATION_TYPE Type)
{
    IoPacket->Request.MajorFunction = IRP_MJ_PNP;
    IoPacket->Request.MinorFunction = IRP_MN_QUERY_DEVICE_RELATIONS;
    IoPacket->Request.Device.Object = BusDevice;
    IoPacket->Request.Parameters.QueryDeviceRelations.Type = Type;
}

static VOID IopPopulateQueryIdRequest(IN PIO_PACKET IoPacket,
				      IN PIO_DEVICE_OBJECT ChildPhyDev,
				      IN BUS_QUERY_ID_TYPE IdType)
{
    IoPacket->Request.MajorFunction = IRP_MJ_PNP;
    IoPacket->Request.MinorFunction = IRP_MN_QUERY_ID;
    IoPacket->Request.Device.Object = ChildPhyDev;
    IoPacket->Request.Parameters.QueryId.IdType = IdType;
}

static NTSTATUS IopQueueQueryDeviceRelationsRequest(IN PTHREAD Thread,
						    IN PIO_DRIVER_OBJECT BusDriver,
						    IN PIO_DEVICE_OBJECT Enumerator,
						    IN DEVICE_RELATION_TYPE Type,
						    OUT PPENDING_IRP *PendingIrp)
{
    PIO_PACKET IoPacket = NULL;
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
    assert(IoPacket != NULL);
    IopPopulateQueryDeviceRelationsRequest(IoPacket, Enumerator, Type);
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, PendingIrp),
	       ExFreePool(IoPacket));
    IopQueueIoPacket(*PendingIrp, BusDriver, Thread);
    return STATUS_SUCCESS;
}

static NTSTATUS IopQueueBusQueryChildDeviceIdRequests(IN PTHREAD Thread,
						      IN PDEVICE_NODE EnumeratorNode,
						      IN BUS_QUERY_ID_TYPE IdType)
{
    LoopOverList(ChildNode, &EnumeratorNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	PIO_PACKET IoPacket = NULL;
	RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
	assert(IoPacket != NULL);
	IopPopulateQueryIdRequest(IoPacket, ChildNode->PhyDevObj, IdType);
	PPENDING_IRP PendingIrp = NULL;
	RET_ERR_EX(IopAllocatePendingIrp(IoPacket, &PendingIrp),
		   ExFreePool(IoPacket));
	assert(PendingIrp != NULL);
	IopQueueIoPacket(PendingIrp, ChildNode->PhyDevObj->DriverObject, Thread);
    }
    return STATUS_SUCCESS;
}

static inline PCSTR IopSanitizeName(IN PCSTR Name)
{
    return Name ? Name : "????";
}

static VOID IopPrintDeviceNode(IN PDEVICE_NODE DeviceNode,
			       IN PCSTR EnumeratedBy,
			       IN ULONG IndentLevel)
{
    CHAR Indent[32];
    if (IndentLevel >= ARRAYSIZE(Indent)) {
	IndentLevel = ARRAYSIZE(Indent)-1;
    }
    for (ULONG i = 0; i < IndentLevel; i++) {
	Indent[i] = ' ';
    }
    Indent[IndentLevel] = '\0';
    HalVgaPrint("%sFound device \\%s\\%s\\%s\n", Indent,
		IopSanitizeName(EnumeratedBy),
		IopSanitizeName(DeviceNode->DeviceId),
		IopSanitizeName(DeviceNode->InstanceId));
}

#define DEVICE_TREE_INDENTATION	2
static VOID IopPrintDeviceTree(IN PDEVICE_NODE RootDeviceNode,
			       IN ULONG IndentLevel)
{
    LoopOverList(DeviceNode, &RootDeviceNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	PCSTR ParentDeviceName = DeviceNode->Parent ? DeviceNode->Parent->DeviceId : "HTREE";
	IopPrintDeviceNode(DeviceNode, ParentDeviceName, IndentLevel);
	IopPrintDeviceTree(DeviceNode, IndentLevel + DEVICE_TREE_INDENTATION);
    }
}

/*
 * Before calling this system service the session manager must have
 * already loaded the root enumerator driver pnp.sys.
 */
NTSTATUS NtPlugPlayInitialize(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PIO_DRIVER_OBJECT PnpDriver;
	    PIO_DEVICE_OBJECT RootEnumerator;
	    PPENDING_IRP PendingIrp;
	});
    assert(IsListEmpty(&Thread->PendingIrpList));
    assert(IopRootDeviceNode == NULL);
    Locals.PnpDriver = NULL;
    Locals.RootEnumerator = NULL;
    Locals.PendingIrp = NULL;
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByName(PNP_ROOT_BUS_DRIVER, OBJECT_TYPE_DRIVER,
					NULL, (POBJECT *)&Locals.PnpDriver));
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByName(PNP_ROOT_ENUMERATOR, OBJECT_TYPE_DEVICE,
					NULL, (POBJECT *)&Locals.RootEnumerator));

    /* Ask the root bus driver about its child devices */
    HalVgaPrint("Enumerating Plug and Play devices...\n");
    IF_ERR_GOTO(out, Status,
		IopQueueQueryDeviceRelationsRequest(Thread, Locals.PnpDriver,
						    Locals.RootEnumerator, BusRelations,
						    &Locals.PendingIrp));
    AWAIT(KeWaitForSingleObject, AsyncState, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);

    /* Get the PDO device handles from the response data */
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(AsyncState, Status);
    }
    ULONG DeviceCount = Locals.PendingIrp->IoResponseStatus.Information;
    PGLOBAL_HANDLE DeviceHandles = (PGLOBAL_HANDLE)Locals.PendingIrp->IoResponseData;
    /* IoResponseData can be NULL in which case the server most likely has run out of memory.
     * Otherwise, it means that bus driver does not have any child devices. Weird flex but ok. */
    if (DeviceHandles == NULL) {
	Status = Locals.PendingIrp->IoResponseDataSize != 0 ? STATUS_NO_MEMORY : STATUS_SUCCESS;
	goto out;
    }
    Locals.PendingIrp->IoResponseData = NULL;
    IopCleanupPendingIrp(Locals.PendingIrp);

    /* Create the root device node and insert the child device nodes under it */
    IF_ERR_GOTO(out, Status,
		IopCreateBusDeviceNode(Locals.PnpDriver, "Root", "0", Locals.RootEnumerator,
				       DeviceCount, DeviceHandles, NULL,
				       &IopRootDeviceNode));
    assert(IopRootDeviceNode != NULL);

    /* Send the QUERY_ID requests to the physical device objects */
    IF_ERR_GOTO(out, Status,
		IopQueueBusQueryChildDeviceIdRequests(Thread, IopRootDeviceNode,
						      BusQueryDeviceID));
    IF_ERR_GOTO(out, Status,
		IopQueueBusQueryChildDeviceIdRequests(Thread, IopRootDeviceNode,
						      BusQueryInstanceID));
    AWAIT(IopThreadWaitForIoCompletion, AsyncState, Locals, Thread, FALSE, WaitAll);

    /* Record the device IDs that the bus driver has provided */
    LoopOverList(PendingIrp, &Thread->PendingIrpList, PENDING_IRP, Link) {
	assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	assert(PendingIrp->IoPacket->Request.MajorFunction == IRP_MJ_PNP);
	assert(PendingIrp->IoPacket->Request.MinorFunction == IRP_MN_QUERY_ID);
	BUS_QUERY_ID_TYPE IdType = PendingIrp->IoPacket->Request.Parameters.QueryId.IdType;
	PIO_DEVICE_OBJECT DeviceObject = PendingIrp->IoPacket->Request.Device.Object;
	PDEVICE_NODE DeviceNode = DeviceObject->DeviceNode;
	assert(DeviceNode != NULL);
	IF_ERR_GOTO(out, Status,
		    IopDeviceNodeSetDeviceId(DeviceNode, PendingIrp->IoResponseData, IdType));
    }
    IopPrintDeviceTree(IopRootDeviceNode, 2);

    Status = STATUS_SUCCESS;

out:
    if (!NT_SUCCESS(Status)) {
	if (IopRootDeviceNode) {
	    IopFreeDeviceNode(IopRootDeviceNode);
	    IopRootDeviceNode = NULL;
	}
	if (Locals.RootEnumerator) {
	    ObDereferenceObject(Locals.RootEnumerator);
	}
	if (Locals.PnpDriver) {
	    ObDereferenceObject(Locals.PnpDriver);
	}
    }
    IopCleanupPendingIrpList(Thread);

    ASYNC_END(AsyncState, Status);
}

NTSTATUS NtPlugPlayControl(IN ASYNC_STATE AsyncState,
                           IN PTHREAD Thread,
                           IN PLUGPLAY_CONTROL_CLASS PlugPlayControlClass,
                           IN PVOID Buffer,
                           IN ULONG BufferSize)
{
    UNIMPLEMENTED;
}
