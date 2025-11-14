#include <wdmp.h>

static NTAPI NTSTATUS PopRequestPowerIrpCompletion(IN PDEVICE_OBJECT DeviceObject,
						   IN PIRP Irp,
						   IN OPTIONAL PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    PREQUEST_POWER_COMPLETE CompletionRoutine = Context;

    POWER_STATE PowerState = {
	.DeviceState = (ULONG_PTR)Stack->Parameters.Others.Argument3
    };

    if (CompletionRoutine) {
        CompletionRoutine(Stack->Parameters.Others.Argument1,
                          (UCHAR)(ULONG_PTR)Stack->Parameters.Others.Argument2,
                          PowerState, Stack->Parameters.Others.Argument4,
                          &Irp->IoStatus);
    }

    return STATUS_CONTINUE_COMPLETION;
}

/*
 * @implemented
 *
 * @remarks This routine must be called at PASSIVE_LEVEL.
 */
NTAPI NTSTATUS PoRequestPowerIrp(IN PDEVICE_OBJECT DeviceObject,
				 IN UCHAR MinorFunction,
				 IN POWER_STATE PowerState,
				 IN OPTIONAL PREQUEST_POWER_COMPLETE CompletionFunction,
				 IN OPTIONAL PVOID Context,
				 OUT OPTIONAL PIRP *pIrp)
{
    PAGED_CODE();

    if (MinorFunction != IRP_MN_QUERY_POWER && MinorFunction != IRP_MN_SET_POWER
        && MinorFunction != IRP_MN_WAIT_WAKE) {
        return STATUS_INVALID_PARAMETER_2;
    }

    /* Always call the top of the device stack */
    PDEVICE_OBJECT TopDeviceObject = IoGetAttachedDeviceReference(DeviceObject);

    PIRP Irp = IoAllocateIrp(TopDeviceObject->StackSize);
    if (!Irp) {
        ObDereferenceObject(TopDeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;

    PIO_STACK_LOCATION Stack = IoGetNextIrpStackLocation(Irp);
    Stack->DeviceObject = TopDeviceObject;
    Stack->MajorFunction = IRP_MJ_POWER;
    Stack->MinorFunction = MinorFunction;
    Stack->Parameters.Others.Argument1 = DeviceObject;
    Stack->Parameters.Others.Argument2 = (PVOID)(ULONG_PTR)MinorFunction;
    Stack->Parameters.Others.Argument3 = (PVOID)(ULONG_PTR)PowerState.DeviceState;
    Stack->Parameters.Others.Argument4 = Context;
    if (MinorFunction == IRP_MN_WAIT_WAKE) {
        Stack->Parameters.WaitWake.PowerState = PowerState.SystemState;
    } else {
        Stack->Parameters.Power.Type = DevicePowerState;
        Stack->Parameters.Power.State = PowerState;
    }
    if (pIrp != NULL)
        *pIrp = Irp;

    IoSetCompletionRoutine(Irp, PopRequestPowerIrpCompletion,
			   CompletionFunction, TRUE, TRUE, TRUE);
    IoCallDriver(TopDeviceObject, Irp);

    /* Always return STATUS_PENDING. The completion routine
     * will call CompletionFunction and complete the Irp. */
    return STATUS_PENDING;
}

/*
 * @unimplemented
 */
NTAPI POWER_STATE PoSetPowerState(IN PDEVICE_OBJECT DeviceObject,
				  IN POWER_STATE_TYPE Type,
				  IN POWER_STATE State)
{
    POWER_STATE PowerState = {
	.SystemState = PowerSystemWorking, // Fully on
    };
    return PowerState;
}

NTAPI BOOLEAN PoQueryWatchdogTime(IN PDEVICE_OBJECT Pdo,
				  OUT PULONG SecondsRemaining)
{
    UNIMPLEMENTED;
    return FALSE;
}

NTAPI NTSTATUS PoRegisterPowerSettingCallback(IN OPTIONAL PDEVICE_OBJECT DeviceObject,
					      IN LPCGUID SettingGuid,
					      IN PPOWER_SETTING_CALLBACK Callback,
					      IN OPTIONAL PVOID Context,
					      OUT OPTIONAL PVOID *Handle)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

NTAPI NTSTATUS PoUnregisterPowerSettingCallback(IN OUT PVOID Handle)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}
