/*
 * PROJECT:         ReactOS WMI driver
 * COPYRIGHT:       GPL - See COPYING in the top level directory
 * FILE:            drivers/wmi/wmilib.c
 * PURPOSE:         Windows Management Instrumentation
 * PROGRAMMERS:     Aleksey Bragin (aleksey@reactos.org)
 *
 */

/* INCLUDES *****************************************************************/

#include <ntddk.h>
#include <wmilib.h>

/* FUNCTIONS ****************************************************************/

NTAPI NTSTATUS WmiCompleteRequest(IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp,
				  IN NTSTATUS Status,
				  IN ULONG BufferUsed,
				  IN CCHAR PriorityBoost)
{
    DPRINT1("WmiLib: WmiCompleteRequest() unimplemented\n");
    return STATUS_SUCCESS;
}

NTAPI NTSTATUS WmiFireEvent(IN PDEVICE_OBJECT DeviceObject,
			    IN LPCGUID Guid,
			    IN ULONG InstanceIndex,
			    IN ULONG EventDataSize,
			    IN PVOID EventData)
{
    DPRINT1("WmiLib: WmiFireEvent() unimplemented\n");
    return STATUS_SUCCESS;
}

NTAPI NTSTATUS WmiSystemControl(IN PWMILIB_CONTEXT WmiLibInfo,
				IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp,
				OUT PSYSCTL_IRP_DISPOSITION IrpDisposition)
{
    DPRINT1("WmiLib: WmiSystemControl() unimplemented\n");

    /* Return info that Irp is not completed */
    if (IrpDisposition)
	*IrpDisposition = IrpNotCompleted;

    return STATUS_SUCCESS;
}
