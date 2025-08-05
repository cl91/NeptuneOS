/*++

Copyright (C) Microsoft Corporation, 1991 - 2005

Module Name:

    dispatch.c

Abstract:

    Code to support multiple dispatch tables.

Environment:

    kernel mode only

Notes:


Revision History:

--*/

#include "classp.h"

DRIVER_DISPATCH ClassDispatchUnimplemented;

//
// Routines start
//
VOID ClassInitializeDispatchTables(PCLASS_DRIVER_EXTENSION DriverExtension)
{
    //
    // Initialize the standard device dispatch table
    //

    for (ULONG idx = 0; idx <= IRP_MJ_MAXIMUM_FUNCTION; idx++) {
	DriverExtension->DeviceMajorFunctionTable[idx] = ClassDispatchUnimplemented;
    }

    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_CREATE] = ClassCreateClose;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_CLOSE] = ClassCreateClose;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_READ] = ClassReadWrite;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_WRITE] = ClassReadWrite;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_DEVICE_CONTROL] = ClassDeviceControlDispatch;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_SCSI] = ClassInternalIoControl;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_SHUTDOWN] = ClassShutdownFlush;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_FLUSH_BUFFERS] = ClassShutdownFlush;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_PNP] = ClassDispatchPnp;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_POWER] = ClassDispatchPower;
    DriverExtension->DeviceMajorFunctionTable[IRP_MJ_SYSTEM_CONTROL] = ClassSystemControl;
}

NTAPI NTSTATUS ClassGlobalDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)

{
    PCOMMON_DEVICE_EXTENSION commonExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    // Code Analysis cannot analyze the code paths specific to clients.
    _Analysis_assume_(FALSE);
    return (commonExtension->DispatchTable[irpStack->MajorFunction])(DeviceObject, Irp);
}

/*++

Routine Description:

    This function is the default dispatch routine.  Its
    responsibility is simply to set the status in the packet to indicate
    that the operation requested is invalid for this device type, and then
    complete the packet.

Arguments:

    DeviceObject - Specifies the device object for which this request is
        bound.  Ignored by this routine.

    Irp - Specifies the address of the I/O Request Packet (IRP) for this
        request.

Return Value:

    The final status is always STATUS_INVALID_DEVICE_REQUEST.


--*/
NTAPI NTSTATUS ClassDispatchUnimplemented(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Simply store the appropriate status, complete the request, and return
    // the same status stored in the packet.
    //

    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}
