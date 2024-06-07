#include "precomp.h"

#ifndef NDEBUG
static PCHAR PowerMinorFunctionString(UCHAR MinorFunction)
{
    switch (MinorFunction) {
    case IRP_MN_SET_POWER:
	return "IRP_MN_SET_POWER";
    case IRP_MN_QUERY_POWER:
	return "IRP_MN_QUERY_POWER";
    case IRP_MN_POWER_SEQUENCE:
	return "IRP_MN_POWER_SEQUENCE";
    case IRP_MN_WAIT_WAKE:
	return "IRP_MN_WAIT_WAKE";

    default:
	return "unknown_power_irp";
    }
}

static PCHAR DbgSystemPowerString(SYSTEM_POWER_STATE Type)
{
    switch (Type) {
    case PowerSystemUnspecified:
	return "PowerSystemUnspecified";
    case PowerSystemWorking:
	return "PowerSystemWorking";
    case PowerSystemSleeping1:
	return "PowerSystemSleeping1";
    case PowerSystemSleeping2:
	return "PowerSystemSleeping2";
    case PowerSystemSleeping3:
	return "PowerSystemSleeping3";
    case PowerSystemHibernate:
	return "PowerSystemHibernate";
    case PowerSystemShutdown:
	return "PowerSystemShutdown";
    case PowerSystemMaximum:
	return "PowerSystemMaximum";
    default:
	return "UnKnown System Power State";
    }
}

static PCHAR DbgDevicePowerString(DEVICE_POWER_STATE Type)
{
    switch (Type) {
    case PowerDeviceUnspecified:
	return "PowerDeviceUnspecified";
    case PowerDeviceD0:
	return "PowerDeviceD0";
    case PowerDeviceD1:
	return "PowerDeviceD1";
    case PowerDeviceD2:
	return "PowerDeviceD2";
    case PowerDeviceD3:
	return "PowerDeviceD3";
    case PowerDeviceMaximum:
	return "PowerDeviceMaximum";
    default:
	return "Unknown Device Power State";
    }
}
#else
#define PowerMinorFunctionString(MinorFunction) ""
#define DbgSystemPowerString(Type) ""
#define DbgDevicePowerString(Type) ""
#endif

static NTSTATUS Bus_FDO_Power(PFDO_DEVICE_DATA Data, PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    POWER_STATE powerState;
    POWER_STATE_TYPE powerType;
    PIO_STACK_LOCATION stack;
    ULONG AcpiState;
    ACPI_STATUS AcpiStatus;
    SYSTEM_POWER_STATE oldPowerState;

    stack = IoGetCurrentIrpStackLocation(Irp);
    powerType = stack->Parameters.Power.Type;
    powerState = stack->Parameters.Power.State;

    if (stack->MinorFunction == IRP_MN_SET_POWER) {
	DPRINT("\tRequest to set %s state to %s\n",
	       ((powerType == SystemPowerState) ? "System" : "Device"),
	       ((powerType == SystemPowerState) ?
		    DbgSystemPowerString(powerState.SystemState) :
		    DbgDevicePowerString(powerState.DeviceState)));

	if (powerType == SystemPowerState) {
	    switch (powerState.SystemState) {
	    case PowerSystemSleeping1:
		AcpiState = ACPI_STATE_S1;
		break;
	    case PowerSystemSleeping2:
		AcpiState = ACPI_STATE_S2;
		break;
	    case PowerSystemSleeping3:
		AcpiState = ACPI_STATE_S3;
		break;
	    case PowerSystemHibernate:
		AcpiState = ACPI_STATE_S4;
		break;
	    case PowerSystemShutdown:
		AcpiState = ACPI_STATE_S5;
		break;
	    default:
		AcpiState = ACPI_STATE_UNKNOWN;
		ASSERT(FALSE);
		break;
	    }
	    oldPowerState = Data->Common.SystemPowerState;
	    Data->Common.SystemPowerState = powerState.SystemState;
	    AcpiStatus = AcpiBusSuspendSystem(AcpiState);
	    if (!ACPI_SUCCESS(AcpiStatus)) {
		DPRINT1("Failed to enter sleep state %d (Status 0x%X)\n", AcpiState,
			AcpiStatus);
		Data->Common.SystemPowerState = oldPowerState;
		status = STATUS_UNSUCCESSFUL;
	    }
	}
    }
    status = IoCallDriver(Data->NextLowerDriver, Irp);
    return status;
}

static NTSTATUS Bus_PDO_Power(PPDO_DEVICE_DATA PdoData, PIRP Irp)
{
    NTSTATUS status;
    PIO_STACK_LOCATION stack;
    POWER_STATE powerState;
    POWER_STATE_TYPE powerType;
    ULONG error;

    stack = IoGetCurrentIrpStackLocation(Irp);
    powerType = stack->Parameters.Power.Type;
    powerState = stack->Parameters.Power.State;

    switch (stack->MinorFunction) {
    case IRP_MN_SET_POWER:

	DPRINT("\tSetting %s power state to %s\n",
	       ((powerType == SystemPowerState) ? "System" : "Device"),
	       ((powerType == SystemPowerState) ?
		    DbgSystemPowerString(powerState.SystemState) :
		    DbgDevicePowerString(powerState.DeviceState)));

	switch (powerType) {
	case DevicePowerState:
	    if (!PdoData->AcpiHandle || !acpi_bus_power_manageable(PdoData->AcpiHandle)) {
		PoSetPowerState(PdoData->Common.Self, DevicePowerState, powerState);
		PdoData->Common.DevicePowerState = powerState.DeviceState;
		status = STATUS_SUCCESS;
		break;
	    }

	    switch (powerState.DeviceState) {
	    case PowerDeviceD0:
		error = acpi_bus_set_power(PdoData->AcpiHandle, ACPI_STATE_D0);
		break;

	    case PowerDeviceD1:
		error = acpi_bus_set_power(PdoData->AcpiHandle, ACPI_STATE_D1);
		break;

	    case PowerDeviceD2:
		error = acpi_bus_set_power(PdoData->AcpiHandle, ACPI_STATE_D2);
		break;

	    case PowerDeviceD3:
		error = acpi_bus_set_power(PdoData->AcpiHandle, ACPI_STATE_D3);
		break;

	    default:
		error = 0;
		break;
	    }

	    if (ACPI_SUCCESS(error)) {
		PoSetPowerState(PdoData->Common.Self, DevicePowerState, powerState);
		PdoData->Common.DevicePowerState = powerState.DeviceState;
		status = STATUS_SUCCESS;
	    } else
		status = STATUS_UNSUCCESSFUL;
	    break;

	case SystemPowerState:
	    PdoData->Common.SystemPowerState = powerState.SystemState;
	    status = STATUS_SUCCESS;
	    break;

	default:
	    status = STATUS_NOT_SUPPORTED;
	    break;
	}
	break;

    case IRP_MN_QUERY_POWER:
	status = STATUS_SUCCESS;
	break;

    case IRP_MN_WAIT_WAKE:
	//
	// We cannot support wait-wake because we are a root-enumerated
	// driver, and our parent, the PnP manager, doesn't support wait-wake.
	//
    case IRP_MN_POWER_SEQUENCE:
    default:
	status = STATUS_NOT_SUPPORTED;
	break;
    }

    if (status != STATUS_NOT_SUPPORTED) {
	Irp->IoStatus.Status = status;
    }

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTAPI NTSTATUS Bus_Power(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNUSED PIO_STACK_LOCATION IrpStack;
    NTSTATUS Status;
    PCOMMON_DEVICE_DATA CommonData;

    Status = STATUS_SUCCESS;
    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IRP_MJ_POWER == IrpStack->MajorFunction);

    CommonData = (PCOMMON_DEVICE_DATA)DeviceObject->DeviceExtension;

    if (CommonData->IsFDO) {
	DPRINT("FDO %s IRP:0x%p %s %s\n",
	       PowerMinorFunctionString(IrpStack->MinorFunction), Irp,
	       DbgSystemPowerString(CommonData->SystemPowerState),
	       DbgDevicePowerString(CommonData->DevicePowerState));

	Status = Bus_FDO_Power((PFDO_DEVICE_DATA)DeviceObject->DeviceExtension, Irp);
    } else {
	DPRINT("PDO %s IRP:0x%p %s %s\n",
	       PowerMinorFunctionString(IrpStack->MinorFunction), Irp,
	       DbgSystemPowerString(CommonData->SystemPowerState),
	       DbgDevicePowerString(CommonData->DevicePowerState));

	Status = Bus_PDO_Power((PPDO_DEVICE_DATA)DeviceObject->DeviceExtension, Irp);
    }

    return Status;
}
