/*
 * PROJECT:         ReactOS Kernel
 * LICENSE:         GPL - See COPYING in the top level directory
 * FILE:            drivers/base/beep/beep.c
 * PURPOSE:         Beep Device Driver
 * PROGRAMMERS:     Alex Ionescu (alex.ionescu@reactos.org)
 *                  Eric Kohl
 */

/* INCLUDES ******************************************************************/

#include <assert.h>
#include <ntddk.h>
#include <hal.h>
#include <ntddbeep.h>

/* TYPES *********************************************************************/

typedef struct _BEEP_DEVICE_EXTENSION {
    KTIMER Timer;
    BOOLEAN TimerActive;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

/* FUNCTIONS *****************************************************************/

NTAPI VOID BeepDPC(IN PKDPC Dpc,
		   IN PDEVICE_OBJECT DeviceObject,
		   IN OUT PIRP Irp,
		   IN OPTIONAL PVOID Context)
{
    PDEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(Context);

    /* Stop the beep */
    HalMakeBeep(0);

    /* Disable the timer */
    DeviceExtension->TimerActive = FALSE;
}

DRIVER_DISPATCH BeepCreate;
NTAPI NTSTATUS BeepCreate(IN PDEVICE_OBJECT DeviceObject,
			  IN PIRP Irp)
{
    /* Complete the request */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

DRIVER_DISPATCH BeepClose;
NTAPI NTSTATUS BeepClose(IN PDEVICE_OBJECT DeviceObject,
			 IN PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    /* Check for active timer */
    if (DeviceExtension->TimerActive) {
	/* Cancel it */
	if (KeCancelTimer(&DeviceExtension->Timer)) {
	    /* Mark it as cancelled */
	    DeviceExtension->TimerActive = FALSE;
	}
    }

    /* Complete the request */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

DRIVER_CANCEL BeepCancel;
NTAPI VOID BeepCancel(IN PDEVICE_OBJECT DeviceObject,
		      IN PIRP Irp)
{
    /* Check if this is the current request */
    if (Irp == DeviceObject->CurrentIrp) {
	/* Clear it */
	DeviceObject->CurrentIrp = NULL;

	/* Start the next packet */
	IoStartNextPacket(DeviceObject, TRUE);
    } else {
	/* Otherwise, remove the packet from the queue */
	KeRemoveEntryDeviceQueue(&DeviceObject->DeviceQueue,
				 &Irp->Tail.DeviceQueueEntry);
    }

    /* Complete the request */
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

DRIVER_DISPATCH BeepCleanup;
NTAPI NTSTATUS BeepCleanup(IN PDEVICE_OBJECT DeviceObject,
			   IN PIRP Irp)
{
    PKDEVICE_QUEUE_ENTRY Packet;
    PIRP CurrentIrp;

    /* Get the current IRP */
    CurrentIrp = DeviceObject->CurrentIrp;
    DeviceObject->CurrentIrp = NULL;
    while (CurrentIrp) {
	/* Clear its cancel routine */
	(VOID) IoSetCancelRoutine(CurrentIrp, NULL);

	/* Cancel the IRP */
	CurrentIrp->IoStatus.Status = STATUS_CANCELLED;
	CurrentIrp->IoStatus.Information = 0;

	/* Complete it */
	IoCompleteRequest(CurrentIrp, IO_NO_INCREMENT);

	/* Get the next queue packet */
	Packet = KeRemoveDeviceQueue(&DeviceObject->DeviceQueue);
	if (Packet) {
	    /* Get the IRP */
	    CurrentIrp = CONTAINING_RECORD(Packet, IRP, Tail.DeviceQueueEntry);
	} else {
	    /* No more IRPs */
	    CurrentIrp = NULL;
	}
    }

    /* Complete the IRP */
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    /* Stop and beep and return */
    HalMakeBeep(0);
    return STATUS_SUCCESS;
}

DRIVER_DISPATCH BeepDeviceControl;
NTAPI NTSTATUS BeepDeviceControl(IN PDEVICE_OBJECT DeviceObject,
				 IN PIRP Irp)
{
    PIO_STACK_LOCATION Stack;
    PBEEP_SET_PARAMETERS BeepParam;
    NTSTATUS Status;

    /* Get the stack location and parameters */
    Stack = IoGetCurrentIrpStackLocation(Irp);
    BeepParam = (PBEEP_SET_PARAMETERS) Irp->SystemBuffer;

    /* We only support one IOCTL */
    if (Stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_BEEP_SET) {
	/* Unsupported command */
	Status = STATUS_NOT_IMPLEMENTED;
    } else {
	/* Validate the input buffer length */
	if (Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(BEEP_SET_PARAMETERS)) {
	    /* Invalid buffer */
	    Status = STATUS_INVALID_PARAMETER;
	} else if ((BeepParam->Frequency != 0) && !(BeepParam->Duration)) {
	    /* No duration, return immediately */
	    Status = STATUS_SUCCESS;
	} else {
	    /* We'll queue this request */
	    Status = STATUS_PENDING;
	}
    }

    /* Set packet information */
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;

    /* Check if we're completing or queuing a packet */
    if (Status == STATUS_PENDING) {
	/* Start the queue */
	IoMarkIrpPending(Irp);
	IoStartPacket(DeviceObject, Irp, NULL, BeepCancel);
    } else {
	/* Complete the request */
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    /* Return */
    return Status;
}

DRIVER_UNLOAD BeepUnload;
NTAPI VOID BeepUnload(IN PDRIVER_OBJECT DriverObject)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT DeviceObject;

    /* Get DO and DE */
    DeviceObject = DriverObject->DeviceObject;
    DeviceExtension = DeviceObject->DeviceExtension;

    /* Check if the timer is active */
    if (DeviceExtension->TimerActive) {
	/* Cancel it */
	if (KeCancelTimer(&DeviceExtension->Timer)) {
	    /* All done */
	    DeviceExtension->TimerActive = FALSE;
	}
    }

    /* Delete the object */
    IoDeleteDevice(DeviceObject);
}

DRIVER_STARTIO BeepStartIo;
NTAPI VOID BeepStartIo(IN PDEVICE_OBJECT DeviceObject,
		       IN PIRP Irp)
{
    PDEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IoStack;
    PBEEP_SET_PARAMETERS BeepParam;
    LARGE_INTEGER DueTime;
    NTSTATUS Status;

    assert(Irp != NULL);

    /* Remove the cancel routine */
    (VOID) IoSetCancelRoutine(Irp, NULL);

    /* Get the I/O Stack and make sure the request is valid */
    BeepParam = (PBEEP_SET_PARAMETERS) Irp->SystemBuffer;
    IoStack = IoGetCurrentIrpStackLocation(Irp);
    if (IoStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_BEEP_SET) {
	/* Check if we have an active timer */
	if (DeviceExtension->TimerActive) {
	    /* Cancel it */
	    if (KeCancelTimer(&DeviceExtension->Timer)) {
		/* Set the state */
		DeviceExtension->TimerActive = FALSE;
	    }
	}

	/* Make the beep */
	if (HalMakeBeep(BeepParam->Frequency)) {
	    /* Beep successful, queue a DPC to stop it */
	    Status = STATUS_SUCCESS;
	    DueTime.QuadPart = BeepParam->Duration * -10000LL;
	    DeviceExtension->TimerActive = TRUE;
	    KeSetTimer(&DeviceExtension->Timer, DueTime, &DeviceObject->Dpc);
	} else {
	    /* Beep has failed */
	    Status = STATUS_INVALID_PARAMETER;
	}
    } else {
	/* Invalid request */
	Status = STATUS_INVALID_PARAMETER;
    }

    /* Complete the request and start the next packet */
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoStartNextPacket(DeviceObject, TRUE);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    PDEVICE_EXTENSION DeviceExtension;
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(DD_BEEP_DEVICE_NAME_U);
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    /* Create the device object with BUFFERED_IO as the IO transfer type */
    Status = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &DeviceName,
			    FILE_DEVICE_BEEP, DO_BUFFERED_IO, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Setup the Driver Object */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = BeepCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = BeepClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = BeepCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BeepDeviceControl;
    DriverObject->DriverUnload = BeepUnload;
    DriverObject->DriverStartIo = BeepStartIo;

    /* Set up device extension */
    DeviceExtension = DeviceObject->DeviceExtension;
    DeviceExtension->TimerActive = FALSE;
    IoInitializeDpcRequest(DeviceObject, BeepDPC);
    KeInitializeTimer(&DeviceExtension->Timer);

    return STATUS_SUCCESS;
}
