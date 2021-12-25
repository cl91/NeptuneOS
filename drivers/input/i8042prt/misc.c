/*
 * PROJECT:     ReactOS i8042 (ps/2 keyboard-mouse controller) driver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        drivers/input/i8042prt/misc.c
 * PURPOSE:     Miscellaneous operations
 * PROGRAMMERS: Copyright 2006-2007 Hervé Poussineau (hpoussin@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include "i8042prt.h"

#include <debug.h>

/* FUNCTIONS *****************************************************************/

static IO_COMPLETION_ROUTINE ForwardIrpAndWaitCompletion;

static NTSTATUS NTAPI
ForwardIrpAndWaitCompletion(IN PDEVICE_OBJECT DeviceObject,
			    IN PIRP Irp, IN PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    __analysis_assume(Context != NULL);
    if (Irp->PendingReturned)
	KeSetEvent(Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS NTAPI
ForwardIrpAndWait(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    KEVENT Event;
    NTSTATUS Status;
    PDEVICE_OBJECT LowerDevice =
	((PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->
	LowerDevice;
    ASSERT(LowerDevice);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);

    IoSetCompletionRoutine(Irp, ForwardIrpAndWaitCompletion, &Event, TRUE,
			   TRUE, TRUE);

    Status = IoCallDriver(LowerDevice, Irp);
    if (Status == STATUS_PENDING) {
	Status =
	    KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE,
				  NULL);
	if (NT_SUCCESS(Status))
	    Status = Irp->IoStatus.Status;
    }

    return Status;
}

NTSTATUS NTAPI
ForwardIrpAndForget(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PDEVICE_OBJECT LowerDevice =
	((PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->
	LowerDevice;

    ASSERT(LowerDevice);

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(LowerDevice, Irp);
}
