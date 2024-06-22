/*
 *  acpi_bus.c - ACPI Bus Driver ($Revision: 80 $)
 *
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

/*
 * Modified for ReactOS and latest ACPICA
 * Copyright (C)2009  Samuel Serapion
 */

#include <stdio.h>
#include "../precomp.h"
#include "acpi_bus.h"
#include "acpi_drivers.h"

#define _COMPONENT ACPI_BUS_COMPONENT
ACPI_MODULE_NAME("acpi_bus")

#define WALK_UP 0
#define WALK_DOWN 1

#define STRUCT_TO_INT(s) (*((INT *)&s))
#define HAS_CHILDREN(d) ((d)->Children.Flink != &((d)->Children))
#define HAS_SIBLINGS(d) (((d)->Parent) && ((d)->Node.Flink != &(d)->Parent->Children))
#define NODE_TO_DEVICE(n) (CONTAINING_RECORD(n, ACPI_DEVICE, Node))

extern VOID AcpiPicSciSetTrigger(ULONG Irq, UINT16 Trigger);

typedef INT (*ACPI_BUS_WALK_CALLBACK)(PACPI_DEVICE , int, PVOID );

PACPI_DEVICE AcpiRoot;

INT ProcessorCount, PowerDeviceCount, PowerButtonCount, FixedPowerButtonCount;
INT FixedSleepButtonCount, SleepButtonCount, ThermalZoneCount;

static INT AcpiDeviceRegister(PACPI_DEVICE Device, PACPI_DEVICE Parent)
{
    INT Result = 0;

    if (!Device)
	return_VALUE(AE_BAD_PARAMETER);

    return_VALUE(Result);
}

static INT AcpiDeviceUnregister(PACPI_DEVICE Device)
{
    if (!Device)
	return_VALUE(AE_BAD_PARAMETER);

#ifdef CONFIG_LDM
    put_device(&device->dev);
#endif /*CONFIG_LDM*/

    return_VALUE(0);
}

/* --------------------------------------------------------------------------
   Device Management
   -------------------------------------------------------------------------- */

static VOID AcpiBusDataHandler(ACPI_HANDLE Handle, PVOID Context)
{
    DPRINT1("acpi_bus_data_handler not implemented\n");

    /* TBD */

    return;
}

INT AcpiBusGetDevice(ACPI_HANDLE Handle, PACPI_DEVICE *Device)
{
    ACPI_STATUS Status = AE_OK;

    if (!Device)
	return_VALUE(AE_BAD_PARAMETER);

    /* TBD: Support fixed-feature devices */

    Status = AcpiGetData(Handle, AcpiBusDataHandler, (PVOID *)Device);
    if (ACPI_FAILURE(Status) || !*Device) {
	DPRINT("Error getting context for object [%p]\n", Handle);
	return_VALUE(AE_NOT_FOUND);
    }

    return 0;
}

static ACPI_STATUS AcpiBusGetStatusHandle(ACPI_HANDLE Handle, ULONG64 *Sta)
{
    ACPI_STATUS Status;

    Status = AcpiEvaluateInteger(Handle, "_STA", NULL, Sta);
    if (ACPI_SUCCESS(Status))
	return AE_OK;

    if (Status == AE_NOT_FOUND) {
	*Sta = ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_ENABLED | ACPI_STA_DEVICE_UI |
	    ACPI_STA_DEVICE_FUNCTIONING;
	return AE_OK;
    }
    return Status;
}

static INT AcpiBusGetStatus(PACPI_DEVICE Device)
{
    ACPI_STATUS Status;
    ULONG64 Sta;

    Status = AcpiBusGetStatusHandle(Device->Handle, &Sta);
    if (ACPI_FAILURE(Status))
	return -1;

    STRUCT_TO_INT(Device->Status) = (int)Sta;

    if (Device->Status.Functional && !Device->Status.Present) {
	ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			  "Device [%s] status [%08x]: "
			  "functional but not present;\n",
			  Device->Pnp.BusId, (UINT32)STRUCT_TO_INT(Device->Status)));
    }

    ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Device [%s] status [%08x]\n", Device->Pnp.BusId,
		      (UINT32)STRUCT_TO_INT(Device->Status)));
    return 0;
}

VOID AcpiBusPrivateDataHandler(ACPI_HANDLE Handle, PVOID Context)
{
    return;
}

INT AcpiBusGetPrivateData(ACPI_HANDLE Handle, PVOID *Data)
{
    ACPI_STATUS Status = AE_OK;

    if (!*Data)
	return -1;

    Status = AcpiGetData(Handle, AcpiBusPrivateDataHandler, Data);
    if (ACPI_FAILURE(Status) || !*Data) {
	DPRINT("No context for object [%p]\n", Handle);
	return -1;
    }

    return 0;
}

/* --------------------------------------------------------------------------
   Power Management
   -------------------------------------------------------------------------- */

INT AcpiBusGetPower(ACPI_HANDLE Handle, INT *State)
{
    INT Result = 0;
    ACPI_STATUS Status = 0;
    PACPI_DEVICE Device = NULL;
    ULONG64 Psc = 0;

    Result = AcpiBusGetDevice(Handle, &Device);
    if (Result)
	return_VALUE(Result);

    *State = ACPI_STATE_UNKNOWN;

    if (!Device->Flags.PowerManageable) {
	/* TBD: Non-recursive algorithm for walking up hierarchy */
	if (Device->Parent)
	    *State = Device->Parent->Power.State;
	else
	    *State = ACPI_STATE_D0;
    } else {
	/*
	 * Get the device's power state either directly (via _PSC) or
	 * indirectly (via power resources).
	 */
	if (Device->Power.Flags.ExplicitGet) {
	    Status = AcpiEvaluateInteger(Device->Handle, "_PSC", NULL, &Psc);
	    if (ACPI_FAILURE(Status))
		return_VALUE(AE_NOT_FOUND);
	    Device->Power.State = (int)Psc;
	} else if (Device->Power.Flags.PowerResources) {
	    Result = AcpiPowerGetInferredState(Device);
	    if (Result)
		return_VALUE(Result);
	}

	*State = Device->Power.State;
    }

    DPRINT("Device [%s] power state is D%d\n", Device->Pnp.BusId, Device->Power.State);

    return_VALUE(0);
}

INT AcpiBusSetPower(ACPI_HANDLE Handle, INT State)
{
    INT Result = 0;
    ACPI_STATUS Status = AE_OK;
    PACPI_DEVICE Device = NULL;
    CHAR ObjectName[5] = { '_', 'P', 'S', '0' + State, '\0' };

    Result = AcpiBusGetDevice(Handle, &Device);
    if (Result)
	return_VALUE(Result);

    if ((State < ACPI_STATE_D0) || (State > ACPI_STATE_D3))
	return_VALUE(AE_BAD_PARAMETER);

    /* Make sure this is a valid target state */

    if (!Device->Flags.PowerManageable) {
	DPRINT1("Device is not power manageable\n");
	return_VALUE(AE_NOT_FOUND);
    }
    /*
     * Get device's current power state
     */
    AcpiBusGetPower(Device->Handle, &Device->Power.State);

    if ((State == Device->Power.State) && !Device->Flags.ForcePowerState) {
	DPRINT1("Device is already at D%d\n", State);
	return 0;
    }
    if (!Device->Power.States[State].Flags.Valid) {
	DPRINT1("Device does not support D%d\n", State);
	return AE_NOT_FOUND;
    }
    if (Device->Parent && (State < Device->Parent->Power.State)) {
	DPRINT1("Cannot set device to a higher-powered state than parent\n");
	return AE_NOT_FOUND;
    }

    /*
     * Transition Power
     * ----------------
     * On transitions to a high-powered state we first apply power (via
     * power resources) then evalute _PSx.  Conversely for transitions to
     * a lower-powered state.
     */
    if (State < Device->Power.State) {
	if (Device->Power.Flags.PowerResources) {
	    Result = AcpiPowerTransition(Device, State);
	    if (Result)
		goto end;
	}
	if (Device->Power.States[State].Flags.ExplicitSet) {
	    Status = AcpiEvaluateObject(Device->Handle, ObjectName, NULL, NULL);
	    if (ACPI_FAILURE(Status)) {
		Result = AE_NOT_FOUND;
		goto end;
	    }
	}
    } else {
	if (Device->Power.States[State].Flags.ExplicitSet) {
	    Status = AcpiEvaluateObject(Device->Handle, ObjectName, NULL, NULL);
	    if (ACPI_FAILURE(Status)) {
		Result = AE_NOT_FOUND;
		goto end;
	    }
	}
	if (Device->Power.Flags.PowerResources) {
	    Result = AcpiPowerTransition(Device, State);
	    if (Result)
		goto end;
	}
    }

end:
    if (Result)
	DPRINT("Error transitioning device [%s] to D%d\n", Device->Pnp.BusId, State);
    else
	DPRINT("Device [%s] transitioned to D%d\n", Device->Pnp.BusId, State);

    return Result;
}

BOOLEAN AcpiBusPowerManageable(ACPI_HANDLE Handle)
{
    PACPI_DEVICE Device;
    INT Result;

    Result = AcpiBusGetDevice(Handle, &Device);
    return Result ? 0 : Device->Flags.PowerManageable;
}

BOOLEAN AcpiBusCanWakeup(ACPI_HANDLE Handle)
{
    PACPI_DEVICE Device;
    INT Result;

    Result = AcpiBusGetDevice(Handle, &Device);
    return Result ? 0 : Device->Wakeup.Flags.Valid;
}

static INT AcpiBusGetPowerFlags(PACPI_DEVICE Device)
{
    ACPI_STATUS Status = 0;
    ACPI_HANDLE Handle = 0;

    if (!Device)
	return AE_NOT_FOUND;

    /*
     * Power Management Flags
     */
    Status = AcpiGetHandle(Device->Handle, "_PSC", &Handle);
    if (ACPI_SUCCESS(Status))
	Device->Power.Flags.ExplicitGet = 1;
    Status = AcpiGetHandle(Device->Handle, "_IRC", &Handle);
    if (ACPI_SUCCESS(Status))
	Device->Power.Flags.InrushCurrent = 1;
    Status = AcpiGetHandle(Device->Handle, "_PRW", &Handle);
    if (ACPI_SUCCESS(Status))
	Device->Flags.WakeCapable = 1;

    /*
     * Enumerate supported power management states
     */
    for (UINT32 i = ACPI_STATE_D0; i <= ACPI_STATE_D3; i++) {
	PACPI_DEVICE_POWER_STATE Ps = &Device->Power.States[i];
	CHAR ObjectName[5] = { '_', 'P', 'R', '0' + i, '\0' };

	/* Evaluate "_PRx" to se if power resources are referenced */
	Status = AcpiEvaluateReference(Device->Handle, ObjectName, NULL,
				       &Ps->Resources);
	if (ACPI_SUCCESS(Status) && Ps->Resources.Count) {
	    Device->Power.Flags.PowerResources = 1;
	    Ps->Flags.Valid = 1;
	}

	/* Evaluate "_PSx" to see if we can do explicit sets */
	ObjectName[2] = 'S';
	Status = AcpiGetHandle(Device->Handle, ObjectName, &Handle);
	if (ACPI_SUCCESS(Status)) {
	    Ps->Flags.ExplicitSet = 1;
	    Ps->Flags.Valid = 1;
	}

	/* State is valid if we have some power control */
	if (Ps->Resources.Count || Ps->Flags.ExplicitSet)
	    Ps->Flags.Valid = 1;

	Ps->Power = -1; /* Unknown - driver assigned */
	Ps->Latency = -1; /* Unknown - driver assigned */
    }

    /* Set defaults for D0 and D3 states (always valid) */
    Device->Power.States[ACPI_STATE_D0].Flags.Valid = 1;
    Device->Power.States[ACPI_STATE_D0].Power = 100;
    Device->Power.States[ACPI_STATE_D3].Flags.Valid = 1;
    Device->Power.States[ACPI_STATE_D3].Power = 0;

    Device->Power.State = ACPI_STATE_UNKNOWN;

    return 0;
}

/* --------------------------------------------------------------------------
   Performance Management
   -------------------------------------------------------------------------- */

static INT AcpiBusGetPerfFlags(PACPI_DEVICE Device)
{
    if (!Device)
	return AE_NOT_FOUND;

    Device->Performance.State = ACPI_STATE_UNKNOWN;

    return 0;
}

/* --------------------------------------------------------------------------
   Namespace Management
   -------------------------------------------------------------------------- */

/**
 * AcpiBusWalk
 * -------------
 * Used to walk the ACPI Bus's device namespace.  Can walk down (depth-first)
 * or up.  Able to parse starting at any node in the namespace.  Note that a
 * callback return value of -249 will terminate the walk.
 *
 * @Start:	starting point
 * Callback:	function to call for every device encountered while parsing
 * Direction:	direction to parse (up or down)
 * @Data:	context for this search operation
 */
static INT AcpiBusWalk(PACPI_DEVICE Start, ACPI_BUS_WALK_CALLBACK Callback,
		       INT Direction, PVOID Data)
{
    INT Result = 0;
    INT Level = 0;
    PACPI_DEVICE Device = NULL;

    if (!Start || !Callback)
	return AE_BAD_PARAMETER;

    Device = Start;

    /*
     * Parse Namespace
     * ---------------
     * Parse a given subtree (specified by start) in the given direction.
     * Walking 'up' simply means that we execute the callback on leaf
     * devices prior to their parents (useful for things like removing
     * or powering down a subtree).
     */

    while (Device) {
	if (Direction == WALK_DOWN)
	    if (-249 == Callback(Device, Level, Data))
		break;

	/* Depth First */

	if (HAS_CHILDREN(Device)) {
	    Device = NODE_TO_DEVICE(Device->Children.Flink);
	    ++Level;
	    continue;
	}

	if (Direction == WALK_UP)
	    if (-249 == Callback(Device, Level, Data))
		break;

	/* Now Breadth */

	if (HAS_SIBLINGS(Device)) {
	    Device = NODE_TO_DEVICE(Device->Node.Flink);
	    continue;
	}

	/* Scope Exhausted - Find Next */

	while ((Device = Device->Parent)) {
	    --Level;
	    if (HAS_SIBLINGS(Device)) {
		Device = NODE_TO_DEVICE(Device->Node.Flink);
		break;
	    }
	}
    }

    if ((Direction == WALK_UP) && (Result == 0))
	Callback(Start, Level, Data);

    return Result;
}

/* --------------------------------------------------------------------------
   Notification Handling
   -------------------------------------------------------------------------- */

static VOID AcpiBusCheckDevice(ACPI_HANDLE Handle)
{
    PACPI_DEVICE Device;
    ACPI_STATUS Status = 0;
    ACPI_DEVICE_STATUS OldStatus;

    if (AcpiBusGetDevice(Handle, &Device))
	return;
    if (!Device)
	return;

    OldStatus = Device->Status;

    /*
     * Make sure this device's parent is present before we go about
     * messing with the device.
     */
    if (Device->Parent && !Device->Parent->Status.Present) {
	Device->Status = Device->Parent->Status;
	return;
    }

    Status = AcpiBusGetStatus(Device);
    if (ACPI_FAILURE(Status))
	return;

    if (STRUCT_TO_INT(OldStatus) == STRUCT_TO_INT(Device->Status))
	return;

    /*
     * Device Insertion/Removal
     */
    if ((Device->Status.Present) && !(OldStatus.Present)) {
	DPRINT("Device insertion detected\n");
	/* TBD: Handle device insertion */
    } else if (!(Device->Status.Present) && (OldStatus.Present)) {
	DPRINT("Device removal detected\n");
	/* TBD: Handle device removal */
    }
}

static VOID AcpiBusCheckScope(ACPI_HANDLE Handle)
{
    /* Status Change? */
    AcpiBusCheckDevice(Handle);

    /*
     * TBD: Enumerate child devices within this device's scope and
     *       run AcpiBusCheckDevice()'s on them.
     */
}

/**
 * AcpiBusNotify
 * ---------------
 * Callback for all 'system-level' device notifications (values 0x00-0x7F).
 */
static VOID AcpiBusNotify(ACPI_HANDLE Handle, UINT32 Type, PVOID Data)
{
    PACPI_DEVICE Device = NULL;
    PACPI_BUSMGR_COMPONENT Driver;

    DPRINT1("Notification %#02x to handle %p\n", Type, Handle);

    AcpiBusGetDevice(Handle, &Device);

    switch (Type) {
    case ACPI_NOTIFY_BUS_CHECK:
	DPRINT("Received BUS CHECK notification for device [%s]\n",
	       Device ? Device->Pnp.BusId : "n/a");
	AcpiBusCheckScope(Handle);
	/*
	 * TBD: We'll need to outsource certain events to non-ACPI
	 *	drivers via the device manager (device.c).
	 */
	break;

    case ACPI_NOTIFY_DEVICE_CHECK:
	DPRINT("Received DEVICE CHECK notification for device [%s]\n",
	       Device ? Device->Pnp.BusId : "n/a");
	AcpiBusCheckDevice(Handle);
	/*
	 * TBD: We'll need to outsource certain events to non-ACPI
	 *	drivers via the device manager (device.c).
	 */
	break;

    case ACPI_NOTIFY_DEVICE_WAKE:
	DPRINT("Received DEVICE WAKE notification for device [%s]\n",
	       Device ? Device->Pnp.BusId : "n/a");
	AcpiBusCheckDevice(Handle);
	/*
	 * TBD: We'll need to outsource certain events to non-ACPI
	 *      drivers via the device manager (device.c).
	 */
	break;

    case ACPI_NOTIFY_EJECT_REQUEST:
	DPRINT1("Received EJECT REQUEST notification for device [%s]\n",
		Device ? Device->Pnp.BusId : "n/a");
	/* TBD */
	break;

    case ACPI_NOTIFY_DEVICE_CHECK_LIGHT:
	DPRINT1("Received DEVICE CHECK LIGHT notification for device [%s]\n",
		Device ? Device->Pnp.BusId : "n/a");
	/* TBD: Exactly what does 'light' mean? */
	break;

    case ACPI_NOTIFY_FREQUENCY_MISMATCH:
	DPRINT1("Received FREQUENCY MISMATCH notification for device [%s]\n",
		Device ? Device->Pnp.BusId : "n/a");
	/* TBD */
	break;

    case ACPI_NOTIFY_BUS_MODE_MISMATCH:
	DPRINT1("Received BUS MODE MISMATCH notification for device [%s]\n",
		Device ? Device->Pnp.BusId : "n/a");
	/* TBD */
	break;

    case ACPI_NOTIFY_POWER_FAULT:
	DPRINT1("Received POWER FAULT notification for device [%s]\n",
		Device ? Device->Pnp.BusId : "n/a");
	/* TBD */
	break;

    default:
	DPRINT1("Received unknown/unsupported notification [%08x] for device [%s]\n",
		Type, Device ? Device->Pnp.BusId : "n/a");
	break;
    }

    if (Device) {
	Driver = Device->Driver;
	if (Driver && Driver->Ops.Notify &&
	    (Driver->Flags & ACPI_BUSMGR_COMPONENT_ALL_NOTIFY_EVENTS))
	    Driver->Ops.Notify(Device, Type);
    }
}

/* --------------------------------------------------------------------------
   Driver Management
   -------------------------------------------------------------------------- */

static LIST_HEAD(AcpiBusDrivers);

/**
 * AcpiBusMatch
 * --------------
 * Checks the device's hardware (_HID) or compatible (_CID) ids to see if it
 * matches the specified driver's criteria.
 */
static INT AcpiBusMatch(PACPI_DEVICE Device, PACPI_BUSMGR_COMPONENT Driver)
{
    INT Error = 0;

    if (Device->Flags.HardwareId)
	if (strstr(Driver->Ids, Device->Pnp.HardwareId))
	    goto Done;

    if (Device->Flags.CompatibleIds) {
	ACPI_PNP_DEVICE_ID_LIST *CidList = Device->Pnp.CidList;

	/* compare multiple _CID entries against driver ids */
	for (INT i = 0; i < CidList->Count; i++) {
	    if (strstr(Driver->Ids, CidList->Ids[i].String))
		goto Done;
	}
    }
    Error = -2;

Done:

    return Error;
}

/**
 * AcpiBusDriverInit
 * --------------------
 * Used to initialize a device via its device driver.  Called whenever a
 * driver is bound to a device.  Invokes the driver's add() and start() Ops.
 */
static INT AcpiBusDriverInit(PACPI_DEVICE Device, PACPI_BUSMGR_COMPONENT Driver)
{
    INT Result = 0;

    if (!Device || !Driver)
	return_VALUE(AE_BAD_PARAMETER);

    if (!Driver->Ops.Add)
	return_VALUE(-38);

    Result = Driver->Ops.Add(Device);
    if (Result) {
	Device->Driver = NULL;
	return_VALUE(Result);
    }

    Device->Driver = Driver;

    /*
     * TBD - Configuration Management: Assign resources to device based
     * upon possible configuration and currently allocated resources.
     */

    if (Driver->Ops.Start) {
	Result = Driver->Ops.Start(Device);
	if (Result && Driver->Ops.Remove)
	    Driver->Ops.Remove(Device, ACPI_BUS_REMOVAL_NORMAL);
	return_VALUE(Result);
    }

    DPRINT("Driver successfully bound to device\n");

    if (Driver->Ops.Scan) {
	Driver->Ops.Scan(Device);
    }

    return_VALUE(0);
}

/**
 * AcpiBusAttach
 * -------------
 * Callback for AcpiBusWalk() used to find devices that match a specific
 * driver's criteria and then attach the driver.
 */
static INT AcpiBusAttach(PACPI_DEVICE Device, INT Level, PVOID Data)
{
    INT Result = 0;
    PACPI_BUSMGR_COMPONENT Driver = NULL;

    if (!Device || !Data)
	return_VALUE(AE_BAD_PARAMETER);

    Driver = (PACPI_BUSMGR_COMPONENT)Data;

    if (Device->Driver)
	return_VALUE(-9);

    if (!Device->Status.Present)
	return_VALUE(AE_NOT_FOUND);

    Result = AcpiBusMatch(Device, Driver);
    if (Result)
	return_VALUE(Result);

    DPRINT("Found driver [%s] for device [%s]\n", Driver->Name, Device->Pnp.BusId);

    Result = AcpiBusDriverInit(Device, Driver);
    if (Result)
	return_VALUE(Result);

    ++Driver->References;

    return_VALUE(0);
}

/**
 * AcpiBusUnattach
 * -----------------
 * Callback for AcpiBusWalk() used to find devices that match a specific
 * driver's criteria and unattach the driver.
 */
static INT AcpiBusUnattach(PACPI_DEVICE Device, INT Level, PVOID Data)
{
    INT Result = 0;
    PACPI_BUSMGR_COMPONENT Driver = (PACPI_BUSMGR_COMPONENT )Data;

    if (!Device || !Driver)
	return_VALUE(AE_BAD_PARAMETER);

    if (Device->Driver != Driver)
	return_VALUE(-6);

    if (!Driver->Ops.Remove)
	return_VALUE(-23);

    Result = Driver->Ops.Remove(Device, ACPI_BUS_REMOVAL_NORMAL);
    if (Result)
	return_VALUE(Result);

    Device->Driver = NULL;
    ACPI_BUSMGR_COMPONENT_DATA(Device) = NULL;

    Driver->References--;

    return_VALUE(0);
}

/**
 * AcpiBusFindDriver
 * --------------------
 * Parses the list of registered drivers looking for a driver applicable for
 * the specified device.
 */
static INT AcpiBusFindDriver(PACPI_DEVICE Device)
{
    INT Result = AE_NOT_FOUND;

    if (!Device || Device->Driver)
	return_VALUE(AE_BAD_PARAMETER);

    LoopOverList(driver, &AcpiBusDrivers, ACPI_BUSMGR_COMPONENT, Node) {
	if (AcpiBusMatch(Device, driver))
	    continue;

	Result = AcpiBusDriverInit(Device, driver);
	if (!Result)
	    ++driver->References;

	break;
    }

    return_VALUE(Result);
}

/**
 * AcpiBusRegisterDriver
 * ------------------------
 * Registers a driver with the ACPI bus.  Searches the namespace for all
 * devices that match the driver's criteria and binds.
 */
INT AcpiBusRegisterDriver(PACPI_BUSMGR_COMPONENT Driver)
{
    if (!Driver)
	return_VALUE(AE_BAD_PARAMETER);

    InsertTailList(&AcpiBusDrivers, &Driver->Node);

    AcpiBusWalk(AcpiRoot, AcpiBusAttach, WALK_DOWN, Driver);

    return_VALUE(Driver->References);
}

/**
 * AcpiBusUnregisterDriver
 * --------------------------
 * Unregisters a driver with the ACPI bus.  Searches the namespace for all
 * devices that match the driver's criteria and unbinds.
 */
VOID AcpiBusUnregisterDriver(PACPI_BUSMGR_COMPONENT Driver)
{
    if (!Driver)
	return;

    AcpiBusWalk(AcpiRoot, AcpiBusUnattach, WALK_UP, Driver);

    if (Driver->References)
	return;

    RemoveEntryList(&Driver->Node);

    return;
}

/* --------------------------------------------------------------------------
   Device Enumeration
   -------------------------------------------------------------------------- */

static INT AcpiBusGetFlags(PACPI_DEVICE Device)
{
    ACPI_STATUS Status = AE_OK;
    ACPI_HANDLE Temp = NULL;

    /* Presence of _STA indicates 'dynamic_status' */
    Status = AcpiGetHandle(Device->Handle, "_STA", &Temp);
    if (ACPI_SUCCESS(Status))
	Device->Flags.DynamicStatus = 1;

    /* Presence of _CID indicates 'compatible_ids' */
    Status = AcpiGetHandle(Device->Handle, "_CID", &Temp);
    if (ACPI_SUCCESS(Status))
	Device->Flags.CompatibleIds = 1;

    /* Presence of _RMV indicates 'removable' */
    Status = AcpiGetHandle(Device->Handle, "_RMV", &Temp);
    if (ACPI_SUCCESS(Status))
	Device->Flags.Removable = 1;

    /* Presence of _EJD|_EJ0 indicates 'ejectable' */
    Status = AcpiGetHandle(Device->Handle, "_EJD", &Temp);
    if (ACPI_SUCCESS(Status))
	Device->Flags.Ejectable = 1;
    else {
	Status = AcpiGetHandle(Device->Handle, "_EJ0", &Temp);
	if (ACPI_SUCCESS(Status))
	    Device->Flags.Ejectable = 1;
    }

    /* Presence of _LCK indicates 'lockable' */
    Status = AcpiGetHandle(Device->Handle, "_LCK", &Temp);
    if (ACPI_SUCCESS(Status))
	Device->Flags.Lockable = 1;

    /* Presence of _PS0|_PR0 indicates 'power manageable' */
    Status = AcpiGetHandle(Device->Handle, "_PS0", &Temp);
    if (ACPI_FAILURE(Status))
	Status = AcpiGetHandle(Device->Handle, "_PR0", &Temp);
    if (ACPI_SUCCESS(Status))
	Device->Flags.PowerManageable = 1;

    /* TBD: Performance management */

    return_VALUE(0);
}

static INT AcpiBusAdd(PACPI_DEVICE *Child, PACPI_DEVICE Parent,
		      ACPI_HANDLE Handle, INT Type)
{
    INT Result = 0;
    ACPI_STATUS Status = AE_OK;
    PACPI_DEVICE Device = NULL;
    CHAR BusId[5] = { '?', 0 };
    ACPI_BUFFER Buffer;
    ACPI_DEVICE_INFO *Info = NULL;
    PCHAR Hid = NULL;
    PCHAR Uid = NULL;
    ACPI_PNP_DEVICE_ID_LIST *CidList = NULL;
    ACPI_UNIQUE_ID StaticUidBuffer;

    if (!Child)
	return_VALUE(AE_BAD_PARAMETER);

    Device = ExAllocatePoolWithTag(sizeof(ACPI_DEVICE), 'DpcA');
    if (!Device) {
	DPRINT1("Memory allocation error\n");
	return_VALUE(AE_NO_MEMORY);
    }
    memset(Device, 0, sizeof(ACPI_DEVICE));

    Device->Handle = Handle;
    Device->Parent = Parent;

    /*
     * Bus ID
     * ------
     * The device's Bus ID is simply the object name.
     * TBD: Shouldn't this value be unique (within the ACPI namespace)?
     */
    switch (Type) {
    case ACPI_BUS_TYPE_SYSTEM:
	snprintf(Device->Pnp.BusId, sizeof(Device->Pnp.BusId), "%s", "ACPI");
	break;
    case ACPI_BUS_TYPE_POWER_BUTTONF:
    case ACPI_BUS_TYPE_POWER_BUTTON:
	snprintf(Device->Pnp.BusId, sizeof(Device->Pnp.BusId), "%s", "PWRF");
	break;
    case ACPI_BUS_TYPE_SLEEP_BUTTONF:
    case ACPI_BUS_TYPE_SLEEP_BUTTON:
	snprintf(Device->Pnp.BusId, sizeof(Device->Pnp.BusId), "%s", "SLPF");
	break;
    default:
	Buffer.Length = sizeof(BusId);
	Buffer.Pointer = BusId;
	AcpiGetName(Handle, ACPI_SINGLE_NAME, &Buffer);

	/* Clean up trailing underscores (if any) */
	for (INT i = 3; i > 1; i--) {
	    if (BusId[i] == '_')
		BusId[i] = '\0';
	    else
		break;
	}
	snprintf(Device->Pnp.BusId, sizeof(Device->Pnp.BusId), "%s", BusId);
	Buffer.Pointer = NULL;

	break;
    }

    /*
     * Flags
     * -----
     * Get prior to calling acpi_bus_get_status() so we know whether
     * or not _STA is present.  Note that we only look for object
     * handles -- cannot evaluate objects until we know the device is
     * present and properly initialized.
     */
    Result = AcpiBusGetFlags(Device);
    if (Result)
	goto end;

    /*
     * Status
     * ------
     * See if the device is present.  We always assume that non-Device()
     * objects (e.g. thermal zones, power resources, processors, etc.) are
     * present, functioning, etc. (at least when parent object is present).
     * Note that _STA has a different meaning for some objects (e.g.
     * power resources) so we need to be careful how we use it.
     */
    switch (Type) {
    case ACPI_BUS_TYPE_DEVICE:
	Result = AcpiBusGetStatus(Device);
	if (Result)
	    goto end;
	break;
    default:
	STRUCT_TO_INT(Device->Status) = 0x0F;
	break;
    }
    if (!Device->Status.Present) {
	Result = -2;
	goto end;
    }

    /*
     * Initialize Device
     * -----------------
     * TBD: Synch with Core's enumeration/initialization process.
     */

    /*
     * Hardware ID, Unique ID, & Bus Address
     * -------------------------------------
     */
    switch (Type) {
    case ACPI_BUS_TYPE_DEVICE:
	Status = AcpiGetObjectInfo(Handle, &Info);
	if (ACPI_FAILURE(Status)) {
	    ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "Error reading device info\n"));
	    Result = AE_NOT_FOUND;
	    Info = NULL;
	    goto end;
	}
	if (Info->Valid & ACPI_VALID_HID)
	    Hid = Info->HardwareId.String;
	if (Info->Valid & ACPI_VALID_UID)
	    Uid = Info->UniqueId.String;
	if (Info->Valid & ACPI_VALID_CID) {
	    CidList = &Info->CompatibleIdList;
	    Device->Pnp.CidList = ExAllocatePoolWithTag(CidList->ListSize,
							'DpcA');
	    if (Device->Pnp.CidList) {
		PCHAR P = (PCHAR )&Device->Pnp.CidList->Ids[CidList->Count];
		Device->Pnp.CidList->Count = CidList->Count;
		Device->Pnp.CidList->ListSize = CidList->ListSize;
		for (INT i = 0; i < CidList->Count; i++) {
		    Device->Pnp.CidList->Ids[i].Length = CidList->Ids[i].Length;
		    Device->Pnp.CidList->Ids[i].String = P;
		    ASSERT(P + CidList->Ids[i].Length <=
			   (PCHAR )Device->Pnp.CidList + CidList->ListSize);
		    memcpy(Device->Pnp.CidList->Ids[i].String, CidList->Ids[i].String,
			   CidList->Ids[i].Length);
		    P += CidList->Ids[i].Length;
		}
	    } else
		DPRINT("Memory allocation error\n");
	}
	if (Info->Valid & ACPI_VALID_ADR) {
	    Device->Pnp.BusAddress = Info->Address;
	    Device->Flags.BusAddress = 1;
	}
	break;
    case ACPI_BUS_TYPE_POWER:
	Hid = ACPI_POWER_HID;
	Uid = StaticUidBuffer;
	snprintf(Uid, sizeof(StaticUidBuffer), "%d", (PowerDeviceCount++));
	break;
    case ACPI_BUS_TYPE_PROCESSOR:
	Hid = ACPI_PROCESSOR_HID;
	Uid = StaticUidBuffer;
	snprintf(Uid, sizeof(StaticUidBuffer), "_%d", (ProcessorCount++));
	break;
    case ACPI_BUS_TYPE_THERMAL:
	Hid = ACPI_THERMAL_HID;
	Uid = StaticUidBuffer;
	snprintf(Uid, sizeof(StaticUidBuffer), "%d", (ThermalZoneCount++));
	break;
    case ACPI_BUS_TYPE_POWER_BUTTON:
	Hid = ACPI_BUTTON_HID_POWER;
	Uid = StaticUidBuffer;
	snprintf(Uid, sizeof(StaticUidBuffer), "%d", (PowerButtonCount++));
	break;
    case ACPI_BUS_TYPE_POWER_BUTTONF:
	Hid = ACPI_BUTTON_HID_POWERF;
	Uid = StaticUidBuffer;
	snprintf(Uid, sizeof(StaticUidBuffer), "%d", (FixedPowerButtonCount++));
	break;
    case ACPI_BUS_TYPE_SLEEP_BUTTON:
	Hid = ACPI_BUTTON_HID_SLEEP;
	Uid = StaticUidBuffer;
	snprintf(Uid, sizeof(StaticUidBuffer), "%d", (SleepButtonCount++));
	break;
    case ACPI_BUS_TYPE_SLEEP_BUTTONF:
	Hid = ACPI_BUTTON_HID_SLEEPF;
	Uid = StaticUidBuffer;
	snprintf(Uid, sizeof(StaticUidBuffer), "%d", (FixedSleepButtonCount++));
	break;
    }

    /*
     * \_SB
     * ----
     * Fix for the system root bus device -- the only root-level device.
     */
    if (((ACPI_HANDLE)Parent == ACPI_ROOT_OBJECT) && (Type == ACPI_BUS_TYPE_DEVICE)) {
	Hid = ACPI_BUS_HID;
	snprintf(Device->Pnp.DeviceName, sizeof(Device->Pnp.DeviceName), "%s",
		 ACPI_BUS_DEVICE_NAME);
	snprintf(Device->Pnp.DeviceClass, sizeof(Device->Pnp.DeviceClass), "%s",
		 ACPI_BUS_CLASS);
    }

    if (Hid) {
	Device->Pnp.HardwareId = ExAllocatePoolWithTag(strlen(Hid) + 1,
						       'DpcA');
	if (Device->Pnp.HardwareId) {
	    snprintf(Device->Pnp.HardwareId, strlen(Hid) + 1, "%s", Hid);
	    Device->Flags.HardwareId = 1;
	}
    }
    if (Uid) {
	snprintf(Device->Pnp.UniqueId, sizeof(Device->Pnp.UniqueId), "%s", Uid);
	Device->Flags.UniqueId = 1;
    }

    /*
     * Power Management
     * ----------------
     */
    if (Device->Flags.PowerManageable) {
	Result = AcpiBusGetPowerFlags(Device);
	if (Result)
	    goto end;
    }

    /*
     * Performance Management
     * ----------------------
     */
    if (Device->Flags.PerformanceManageable) {
	Result = AcpiBusGetPerfFlags(Device);
	if (Result)
	    goto end;
    }

    /*
     * Context
     * -------
     * Attach this 'ACPI_DEVICE' to the ACPI object.  This makes
     * resolutions from handle->device very efficient.  Note that we need
     * to be careful with fixed-feature devices as they all attach to the
     * root object.
     */
    switch (Type) {
    case ACPI_BUS_TYPE_POWER_BUTTON:
    case ACPI_BUS_TYPE_POWER_BUTTONF:
    case ACPI_BUS_TYPE_SLEEP_BUTTON:
    case ACPI_BUS_TYPE_SLEEP_BUTTONF:
	break;
    default:
	Status = AcpiAttachData(Device->Handle, AcpiBusDataHandler, Device);
	break;
    }
    if (ACPI_FAILURE(Status)) {
	ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "Error attaching device data\n"));
	Result = AE_NOT_FOUND;
	goto end;
    }

    /*
     * Linkage
     * -------
     * Link this device to its parent and siblings.
     */
    InitializeListHead(&Device->Children);
    if (!Device->Parent)
	InitializeListHead(&Device->Node);
    else
	InsertTailList(&Device->Parent->Children, &Device->Node);

    /*
     * Global Device Hierarchy:
     * ------------------------
     * Register this device with the global device hierarchy.
     */
    AcpiDeviceRegister(Device, Parent);

    /*
     * Bind _ADR-Based Devices
     * -----------------------
     * If there's a a bus address (_ADR) then we utilize the parent's
     * 'bind' function (if exists) to bind the ACPI- and natively-
     * enumerated device representations.
     */
    if (Device->Flags.BusAddress) {
	if (Device->Parent && Device->Parent->Ops.Bind)
	    Device->Parent->Ops.Bind(Device);
    }

    /*
     * Locate & Attach Driver
     * ----------------------
     * If there's a hardware id (_HID) or compatible ids (_CID) we check
     * to see if there's a driver installed for this kind of device.  Note
     * that drivers can install before or after a device is enumerated.
     *
     * TBD: Assumes LDM provides driver hot-plug capability.
     */
    if (Device->Flags.HardwareId || Device->Flags.CompatibleIds)
	AcpiBusFindDriver(Device);

end:
    if (Info != NULL)
	ACPI_FREE(Info);
    if (Result) {
	if (Device->Pnp.CidList) {
	    ExFreePoolWithTag(Device->Pnp.CidList, 'DpcA');
	}
	if (Device->Pnp.HardwareId) {
	    ExFreePoolWithTag(Device->Pnp.HardwareId, 'DpcA');
	}
	ExFreePoolWithTag(Device, 'DpcA');
	return_VALUE(Result);
    }
    *Child = Device;

    return_VALUE(0);
}

static INT AcpiBusRemove(PACPI_DEVICE Device, INT Type)
{
    if (!Device)
	return_VALUE(AE_NOT_FOUND);

    AcpiDeviceUnregister(Device);

    if (Device->Pnp.CidList)
	ExFreePoolWithTag(Device->Pnp.CidList, 'DpcA');

    if (Device->Pnp.HardwareId)
	ExFreePoolWithTag(Device->Pnp.HardwareId, 'DpcA');

    if (Device)
	ExFreePoolWithTag(Device, 'DpcA');

    return_VALUE(0);
}

INT AcpiBusScan(PACPI_DEVICE Start)
{
    ACPI_STATUS Status = AE_OK;
    PACPI_DEVICE Parent = NULL;
    PACPI_DEVICE Child = NULL;
    ACPI_HANDLE Phandle = 0;
    ACPI_HANDLE Chandle = 0;
    ACPI_OBJECT_TYPE Type = 0;
    UINT32 Level = 1;

    if (!Start)
	return_VALUE(AE_BAD_PARAMETER);

    Parent = Start;
    Phandle = Start->Handle;

    /*
     * Parse through the ACPI namespace, identify all 'devices', and
     * create a new 'ACPI_DEVICE' for each.
     */
    while ((Level > 0) && Parent) {
	Status = AcpiGetNextObject(ACPI_TYPE_ANY, Phandle, Chandle, &Chandle);

	/*
	 * If this scope is exhausted then move our way back up.
	 */
	if (ACPI_FAILURE(Status)) {
	    Level--;
	    Chandle = Phandle;
	    AcpiGetParent(Phandle, &Phandle);
	    if (Parent->Parent)
		Parent = Parent->Parent;
	    continue;
	}

	Status = AcpiGetType(Chandle, &Type);
	if (ACPI_FAILURE(Status))
	    continue;

	/*
	 * If this is a scope object then parse it (depth-first).
	 */
	if (Type == ACPI_TYPE_LOCAL_SCOPE) {
	    Level++;
	    Phandle = Chandle;
	    Chandle = 0;
	    continue;
	}

	/*
	 * We're only interested in objects that we consider 'devices'.
	 */
	switch (Type) {
	case ACPI_TYPE_DEVICE:
	    Type = ACPI_BUS_TYPE_DEVICE;
	    break;
	case ACPI_TYPE_PROCESSOR:
	    Type = ACPI_BUS_TYPE_PROCESSOR;
	    break;
	case ACPI_TYPE_THERMAL:
	    Type = ACPI_BUS_TYPE_THERMAL;
	    break;
	case ACPI_TYPE_POWER:
	    Type = ACPI_BUS_TYPE_POWER;
	    break;
	default:
	    continue;
	}

	Status = AcpiBusAdd(&Child, Parent, Chandle, Type);
	if (ACPI_FAILURE(Status))
	    continue;

	/*
	 * If the device is present, enabled, and functioning then
	 * parse its scope (depth-first).  Note that we need to
	 * represent absent devices to facilitate PnP notifications
	 * -- but only the subtree head (not all of its children,
	 * which will be enumerated when the parent is inserted).
	 *
	 * TBD: Need notifications and other detection mechanisms
	 *	in place before we can fully implement this.
	 */
	if (Child->Status.Present) {
	    Status = AcpiGetNextObject(ACPI_TYPE_ANY, Chandle, 0, NULL);
	    if (ACPI_SUCCESS(Status)) {
		Level++;
		Phandle = Chandle;
		Chandle = 0;
		Parent = Child;
	    }
	}
    }

    return_VALUE(0);
}

static INT AcpiBusScanFixed(PACPI_DEVICE Root)
{
    INT Result = 0;
    PACPI_DEVICE Device = NULL;

    if (!Root)
	return_VALUE(AE_NOT_FOUND);

    /* If ACPI_FADT_POWER_BUTTON is set, then a control
     * method power button is present. Otherwise, a fixed
     * power button is present.
     */
    if (AcpiGbl_FADT.Flags & ACPI_FADT_POWER_BUTTON)
	Result = AcpiBusAdd(&Device, AcpiRoot, NULL, ACPI_BUS_TYPE_POWER_BUTTON);
    else {
	/* Enable the fixed power button so we get notified if it is pressed */
	AcpiWriteBitRegister(ACPI_BITREG_POWER_BUTTON_ENABLE, 1);

	Result = AcpiBusAdd(&Device, AcpiRoot, NULL, ACPI_BUS_TYPE_POWER_BUTTONF);
    }

    /* This one is a bit more complicated and we do it wrong
     * right now. If ACPI_FADT_SLEEP_BUTTON is set but no
     * device object is present then no sleep button is present, but
     * if the flags is clear and there is no device object then it is
     * a fixed sleep button. If the flag is set and there is a device object
     * the we have a control method button just like above.
     */
    if (AcpiGbl_FADT.Flags & ACPI_FADT_SLEEP_BUTTON)
	Result = AcpiBusAdd(&Device, AcpiRoot, NULL, ACPI_BUS_TYPE_SLEEP_BUTTON);
    else {
	/* Enable the fixed sleep button so we get notified if it is pressed */
	AcpiWriteBitRegister(ACPI_BITREG_SLEEP_BUTTON_ENABLE, 1);

	Result = AcpiBusAdd(&Device, AcpiRoot, NULL, ACPI_BUS_TYPE_SLEEP_BUTTONF);
    }

    return_VALUE(Result);
}

/* --------------------------------------------------------------------------
   Initialization/Cleanup
   -------------------------------------------------------------------------- */

INT AcpiBusInitializeManager(void)
{
    DPRINT("AcpiBusInitializeManager\n");

    DPRINT("Subsystem revision %08x\n", ACPI_CA_VERSION);

    ACPI_STATUS Status = AE_OK;

    Status = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(Status)) {
	DPRINT1("Unable to start the ACPI Interpreter\n");
	goto error1;
    }
    DPRINT1("AcpiEnableSubsystem OK\n");

    Status = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(Status)) {
	DPRINT1("Unable to initialize ACPI objects\n");
	goto error1;
    }
    DPRINT1("AcpiInitializeObjects OK\n");

    /*
     * Register the for all standard device notifications.
     */
    Status = AcpiInstallNotifyHandler(ACPI_ROOT_OBJECT, ACPI_SYSTEM_NOTIFY,
				      AcpiBusNotify, NULL);
    if (ACPI_FAILURE(Status)) {
	DPRINT1("Unable to register for device notifications\n");
	Status = AE_NOT_FOUND;
	goto error1;
    }
    DPRINT1("AcpiInstallNotifyHandler OK\n");

    /*
     * Create the root device in the bus's device tree
     */
    Status = AcpiBusAdd(&AcpiRoot, NULL, ACPI_ROOT_OBJECT, ACPI_BUS_TYPE_SYSTEM);
    if (ACPI_FAILURE(Status))
	goto error2;
    DPRINT1("AcpiBusAdd OK\n");

    /*
     * Enumerate devices in the ACPI namespace.
     */
    Status = AcpiBusScanFixed(AcpiRoot);
    if (ACPI_FAILURE(Status)) {
	DPRINT1("AcpiBusScanFixed failed\n");
    } else {
	DPRINT1("AcpiBusScanFixed OK\n");
    }
    Status = AcpiBusScan(AcpiRoot);
    if (ACPI_FAILURE(Status)) {
	DPRINT1("AcpiBusScan failed\n");
    } else {
	DPRINT1("AcpiBusScan OK\n");
    }

    /*
     * Install drivers required for proper enumeration of the
     * ACPI namespace.
     */
    Status = AcpiPowerInit(); /* ACPI Bus Power Management */
    if (ACPI_FAILURE(Status)) {
	DPRINT1("AcpiPowerInit failed\n");
    } else {
	DPRINT1("AcpiPowerInit OK\n");
    }
    Status = AcpiButtonInit();
    if (ACPI_FAILURE(Status)) {
	DPRINT1("AcpiButtonInit failed\n");
    } else {
	DPRINT1("AcpiButtonInit OK\n");
    }

    DPRINT1("AcpiBusInitializeManager OK\n");
    return_VALUE(AE_OK);

error2:
    AcpiRemoveNotifyHandler(ACPI_ROOT_OBJECT, ACPI_SYSTEM_NOTIFY, AcpiBusNotify);
error1:
    AcpiTerminate();

    return Status;
}

VOID AcpiBusTerminateManager(void)
{
    ACPI_STATUS Status = AE_OK;

    DPRINT1("AcpiBusExit\n");

    Status = AcpiRemoveNotifyHandler(ACPI_ROOT_OBJECT, ACPI_SYSTEM_NOTIFY,
				     AcpiBusNotify);
    if (ACPI_FAILURE(Status))
	DPRINT1("Error removing notify handler\n");

    AcpiBusRemove(AcpiRoot, ACPI_BUS_REMOVAL_NORMAL);

    Status = AcpiTerminate();
    if (ACPI_FAILURE(Status))
	DPRINT1("Unable to terminate the ACPI Interpreter\n");
    else
	DPRINT1("Interpreter disabled\n");
}
