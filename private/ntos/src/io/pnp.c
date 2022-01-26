#include "iop.h"

static VOID IopPopulateQueryDeviceRelationsRequest(IN PIO_PACKET IoPacket,
						   IN PIO_DEVICE_OBJECT RootEnumerator,
						   IN DEVICE_RELATION_TYPE Type)
{
    IoPacket->Request.MajorFunction = IRP_MJ_PNP;
    IoPacket->Request.MinorFunction = IRP_MN_QUERY_DEVICE_RELATIONS;
    IoPacket->Request.Device.Object = RootEnumerator;
    IoPacket->Request.Parameters.QueryDeviceRelations.Type = Type;
}

static VOID IopPopulateQueryIdRequest(IN PIO_PACKET IoPacket,
				      IN PIO_DEVICE_OBJECT RootEnumerator,
				      IN BUS_QUERY_ID_TYPE IdType)
{
    IoPacket->Request.MajorFunction = IRP_MJ_PNP;
    IoPacket->Request.MinorFunction = IRP_MN_QUERY_ID;
    IoPacket->Request.Device.Object = RootEnumerator;
    IoPacket->Request.Parameters.QueryId.IdType = IdType;
}

/*
 * Before calling this system service the session manager must have
 * already loaded the root enumerator driver pnp.sys.
 */
NTSTATUS NtPlugPlayInitialize(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread)
{
    ASYNC_BEGIN(AsyncState, Locals, {
	    PIO_DRIVER_OBJECT PnpDriver;
	    PIO_DEVICE_OBJECT RootEnumerator;
	    PPENDING_IRP PendingIrp;
	});
    RET_ERR(ObReferenceObjectByName(PNP_ROOT_BUS_DRIVER, OBJECT_TYPE_DRIVER,
				    NULL, (POBJECT *)&Locals.PnpDriver));
    RET_ERR(ObReferenceObjectByName(PNP_ROOT_ENUMERATOR, OBJECT_TYPE_DEVICE,
				    NULL, (POBJECT *)&Locals.RootEnumerator));
    PIO_PACKET IoPacket = NULL;
    RET_ERR_EX(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket),
	       {
		   ObDereferenceObject(Locals.RootEnumerator);
		   ObDereferenceObject(Locals.PnpDriver);
	       });
    assert(IoPacket != NULL);
    IopPopulateQueryDeviceRelationsRequest(IoPacket, Locals.RootEnumerator, BusRelations);
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, &Locals.PendingIrp),
	       ExFreePool(IoPacket));
    IopQueueIoPacket(Locals.PendingIrp, Locals.PnpDriver, Thread);
    AWAIT(KeWaitForSingleObject, AsyncState, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);

    NTSTATUS Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    ULONG DeviceCount = Locals.PendingIrp->IoResponseStatus.Information;
    PGLOBAL_HANDLE DeviceHandles = (PGLOBAL_HANDLE)Locals.PendingIrp->IoResponseData;
    HalVgaPrint("Enumerating Plug and Play devices...\n");
    for (ULONG i = 0; i < DeviceCount; i++) {
	HalVgaPrint("  Device object %p\n", GLOBAL_HANDLE_TO_OBJECT(DeviceHandles[i]));
    }
    IopCleanupPendingIrp(Locals.PendingIrp);
    ASYNC_END(STATUS_SUCCESS);
}

NTSTATUS NtPlugPlayControl(IN ASYNC_STATE AsyncState,
                           IN PTHREAD Thread,
                           IN PLUGPLAY_CONTROL_CLASS PlugPlayControlClass,
                           IN PVOID Buffer,
                           IN ULONG BufferSize)
{
    UNIMPLEMENTED;
}
