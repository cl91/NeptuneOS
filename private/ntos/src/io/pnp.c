#include "iop.h"

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
						    IN PIO_DEVICE_OBJECT BusDevice,
						    IN DEVICE_RELATION_TYPE Type,
						    OUT PPENDING_IRP *PendingIrp)
{
    PIO_PACKET IoPacket = NULL;
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
    assert(IoPacket != NULL);
    IopPopulateQueryDeviceRelationsRequest(IoPacket, BusDevice, Type);
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, PendingIrp),
	       ExFreePool(IoPacket));
    IopQueueIoPacket(*PendingIrp, BusDriver, Thread);
    return STATUS_SUCCESS;
}

static NTSTATUS IopQueueQueryIdRequest(IN PTHREAD Thread,
				       IN PIO_DRIVER_OBJECT BusDriver,
				       IN ULONG DeviceCount,
				       IN PIO_DEVICE_OBJECT *DeviceObjects,
				       IN BUS_QUERY_ID_TYPE IdType)
{
    for (ULONG i = 0; i < DeviceCount; i++) {
	PIO_PACKET IoPacket = NULL;
	RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
	assert(IoPacket != NULL);
	IopPopulateQueryIdRequest(IoPacket, DeviceObjects[i], IdType);
	PPENDING_IRP PendingIrp = NULL;
	RET_ERR_EX(IopAllocatePendingIrp(IoPacket, &PendingIrp),
		   ExFreePool(IoPacket));
	assert(PendingIrp != NULL);
	IopQueueIoPacket(PendingIrp, BusDriver, Thread);
    }
    return STATUS_SUCCESS;
}

/*
 * Validate the device handles and convert them into device object pointers.
 */
C_ASSERT(sizeof(GLOBAL_HANDLE) == sizeof(PIO_DEVICE_OBJECT));
static NTSTATUS IopDeviceHandlesToDeviceObjects(IN PIO_DRIVER_OBJECT DriverObject,
						IN ULONG DeviceCount,
						IN PGLOBAL_HANDLE DeviceHandles)
{
    for (ULONG i = 0; i < DeviceCount; i++) {
	PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(DeviceHandles[i],
							    DriverObject);
	if (DeviceObject == NULL) {
	    DbgTrace("No such device handle %p for driver object %p\n",
		     (PVOID)DeviceHandles[i], DriverObject);
	    return STATUS_NO_SUCH_DEVICE;
	}
	DeviceHandles[i] = (GLOBAL_HANDLE)DeviceObject;
    }
    return STATUS_SUCCESS;
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

    /* Validate the device handles supplied by the client and convert them into device objects */
    IF_ERR_GOTO(out, Status,
		IopDeviceHandlesToDeviceObjects(Locals.PnpDriver, DeviceCount, DeviceHandles));
    PIO_DEVICE_OBJECT *DeviceObjects = (PIO_DEVICE_OBJECT *)DeviceHandles;

    /* Send the QUERY_ID requests to the physical device objects */
    HalVgaPrint("Enumerating Plug and Play devices...\n");
    IF_ERR_GOTO(out, Status,
		IopQueueQueryIdRequest(Thread, Locals.PnpDriver,
				       DeviceCount, DeviceObjects, BusQueryDeviceID));
    IF_ERR_GOTO(out, Status,
		IopQueueQueryIdRequest(Thread, Locals.PnpDriver,
				       DeviceCount, DeviceObjects, BusQueryInstanceID));
    AWAIT(IopThreadWaitForIoCompletion, AsyncState, Locals, Thread, FALSE, WaitAll);

    Status = STATUS_SUCCESS;

out:
    if (Locals.RootEnumerator) {
	ObDereferenceObject(Locals.RootEnumerator);
    }
    if (Locals.PnpDriver) {
	ObDereferenceObject(Locals.PnpDriver);
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
