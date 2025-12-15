/*
 *  acpi_power.c - ACPI Bus Power Management ($Revision: 39 $)
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
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
 * ACPI power-managed devices may be controlled in two ways:
 * 1. via "Device Specific (D-State) Control"
 * 2. via "Power Resource Control".
 * This module is used to manage devices relying on Power Resource Control.
 *
 * An ACPI "power resource object" describes a software controllable power
 * plane, clock plane, or other resource used by a power managed device.
 * A device may rely on multiple power resources, and a power resource
 * may be shared by multiple devices.
 */

/*
 * Modified for ReactOS and latest ACPICA
 * Copyright (C)2009  Samuel Serapion
 */

#include "../precomp.h"
#include "acpi_bus.h"
#include "acpi_drivers.h"

#define _COMPONENT ACPI_POWER_COMPONENT
ACPI_MODULE_NAME("acpi_power")

#define ACPI_POWER_RESOURCE_STATE_OFF 0x00
#define ACPI_POWER_RESOURCE_STATE_ON 0x01
#define ACPI_POWER_RESOURCE_STATE_UNKNOWN 0xFF

INT AcpiPowerNocheck;

static ACPI_STATUS AcpiPowerAdd(IN PDEVICE_OBJECT BusFdo, PACPI_DEVICE Device);
static ACPI_STATUS AcpiPowerRemove(PACPI_DEVICE Device, INT Type);
static ACPI_STATUS AcpiPowerResume(PACPI_DEVICE Device, INT State);

static ACPI_BUSMGR_COMPONENT AcpiPowerDriver = {
    { 0, 0 }, ACPI_POWER_DRIVER_NAME, ACPI_POWER_CLASS, 0, 0, ACPI_POWER_HID,
    { AcpiPowerAdd, AcpiPowerRemove, NULL, NULL, AcpiPowerResume }
};

typedef struct _ACPI_POWER_REFERENCE {
    LIST_ENTRY Node;
    PACPI_DEVICE Device;
} ACPI_POWER_REFERENCE, *PACPI_POWER_REFERENCE;

typedef struct _ACPI_POWER_RESOURCE {
    PACPI_DEVICE Device;
    ACPI_BUS_ID Name;
    UINT32 SystemLevel;
    UINT32 Order;
    LIST_ENTRY Reference;
} ACPI_POWER_RESOURCE, *PACPI_POWER_RESOURCE;

static LIST_ENTRY AcpiPowerResourceList;

/* --------------------------------------------------------------------------
   Power Resource Management
   -------------------------------------------------------------------------- */

static INT AcpiPowerGetContext(ACPI_HANDLE Handle,
			       PACPI_POWER_RESOURCE *Resource)
{
    INT Result = 0;
    PACPI_DEVICE Device = NULL;

    if (!Resource)
	return_VALUE(-15);

    Result = AcpiBusGetDevice(Handle, &Device);
    if (Result) {
	ACPI_DEBUG_PRINT((ACPI_DB_WARN, "Error getting context [%p]\n", Handle));
	return_VALUE(Result);
    }

    *Resource = (PACPI_POWER_RESOURCE)ACPI_BUSMGR_COMPONENT_DATA(Device);
    if (!*Resource)
	return_VALUE(-15);

    return 0;
}

static INT AcpiPowerGetState(ACPI_HANDLE Handle, INT *State)
{
    ACPI_STATUS Status = AE_OK;
    ULONG64 Sta = 0;
    CHAR NodeName[5];
    ACPI_BUFFER Buffer = { sizeof(NodeName), NodeName };

    if (!Handle || !State)
	return_VALUE(-1);

    Status = AcpiEvaluateInteger(Handle, "_STA", NULL, &Sta);
    if (ACPI_FAILURE(Status))
	return_VALUE(-15);

    *State = (Sta & 0x01) ? ACPI_POWER_RESOURCE_STATE_ON : ACPI_POWER_RESOURCE_STATE_OFF;

    AcpiGetName(Handle, ACPI_SINGLE_NAME, &Buffer);

    ACPI_DEBUG_PRINT(
	(ACPI_DB_INFO, "Resource [%s] is %s\n", NodeName, *State ? "on" : "off"));

    return 0;
}

static INT AcpiPowerGetListState(PACPI_HANDLE_LIST List, INT *State)
{
    INT Result = 0, State1;

    if (!List || !State)
	return_VALUE(-1);

    /* The state of the list is 'on' IFF all resources are 'on'. */

    for (ULONG i = 0; i < List->Count; i++) {
	/*
	 * The state of the power resource can be obtained by
	 * using the ACPI handle. In such case it is unnecessary to
	 * get the Power resource first and then get its state again.
	 */
	Result = AcpiPowerGetState(List->Handles[i], &State1);
	if (Result)
	    return Result;

	*State = State1;

	if (*State != ACPI_POWER_RESOURCE_STATE_ON)
	    break;
    }

    ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Resource list is %s\n", *State ? "on" : "off"));

    return Result;
}

static INT AcpiPowerOn(ACPI_HANDLE Handle, PACPI_DEVICE Dev)
{
    INT Result = 0;
    INT Found = 0;
    ACPI_STATUS Status = AE_OK;
    PACPI_POWER_RESOURCE Resource = NULL;

    Result = AcpiPowerGetContext(Handle, &Resource);
    if (Result)
	return Result;

    LoopOverList(ref, &Resource->Reference, ACPI_POWER_REFERENCE, Node) {
	if (Dev->Handle == ref->Device->Handle) {
	    ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			      "Device [%s] already referenced by resource [%s]\n",
			      Dev->Pnp.BusId, Resource->Name));
	    Found = 1;
	    break;
	}
    }

    if (!Found) {
	PACPI_POWER_REFERENCE Ref = ExAllocatePoolWithTag(NonPagedPool,
							  sizeof(ACPI_POWER_REFERENCE),
							  ACPI_TAG);
	if (!Ref) {
	    ACPI_DEBUG_PRINT((ACPI_DB_INFO, "kmalloc() failed\n"));
	    return -1; // -ENOMEM;
	}
	InsertTailList(&Resource->Reference, &Ref->Node);
	Ref->Device = Dev;
	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Device [%s] added to resource [%s] references\n",
			  Dev->Pnp.BusId, Resource->Name));
    }

    Status = AcpiEvaluateObject(Resource->Device->Handle, "_ON", NULL, NULL);
    if (ACPI_FAILURE(Status))
	return_VALUE(-15);

    /* Update the power resource's _device_ power state */
    Resource->Device->Power.State = ACPI_STATE_D0;

    return 0;
}

static INT AcpiPowerOffDevice(ACPI_HANDLE Handle, PACPI_DEVICE Dev)
{
    INT Result = 0;
    ACPI_STATUS Status = AE_OK;
    PACPI_POWER_RESOURCE Resource = NULL;

    Result = AcpiPowerGetContext(Handle, &Resource);
    if (Result)
	return Result;

    LoopOverList(ref, &Resource->Reference, ACPI_POWER_REFERENCE, Node) {
	if (Dev->Handle == ref->Device->Handle) {
	    RemoveEntryList(&ref->Node);
	    ExFreePool(ref);
	    ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			      "Device [%s] removed from resource [%s] references\n",
			      Dev->Pnp.BusId, Resource->Name));
	    break;
	}
    }

    if (!IsListEmpty(&Resource->Reference)) {
	ACPI_DEBUG_PRINT((ACPI_DB_INFO,
			  "Cannot turn resource [%s] off - resource is in use\n",
			  Resource->Name));
	return 0;
    }

    Status = AcpiEvaluateObject(Resource->Device->Handle, "_OFF", NULL, NULL);
    if (ACPI_FAILURE(Status))
	return -1;

    /* Update the power resource's _device_ power state */
    Resource->Device->Power.State = ACPI_STATE_D3;

    ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Resource [%s] turned off\n", Resource->Name));

    return 0;
}

/**
 * acpi_device_sleep_wake - execute _DSW (Device Sleep Wake) or (deprecated in
 *                          ACPI 3.0) _PSW (Power State Wake)
 * @dev: Device to handle.
 * @enable: 0 - disable, 1 - enable the wake capabilities of the device.
 * @sleep_state: Target sleep state of the system.
 * @dev_state: Target power state of the device.
 *
 * Execute _DSW (Device Sleep Wake) or (deprecated in ACPI 3.0) _PSW (Power
 * State Wake) for the device, if present.  On failure reset the device's
 * wakeup.flags.valid flag.
 *
 * RETURN VALUE:
 * 0 if either _DSW or _PSW has been successfully executed
 * 0 if neither _DSW nor _PSW has been found
 * -ENODEV if the execution of either _DSW or _PSW has failed
 */
INT AcpiDeviceSleepWake(PACPI_DEVICE Dev, INT Enable, INT SleepState,
			INT DevState)
{
    union acpi_object InArg[3];
    struct acpi_object_list ArgList = { 3, InArg };
    ACPI_STATUS Status = AE_OK;

    /*
     * Try to execute _DSW first.
     *
     * Three arguments are needed for the _DSW object:
     * Argument 0: enable/disable the wake capabilities
     * Argument 1: target system state
     * Argument 2: target device state
     * When _DSW object is called to disable the wake capabilities, maybe
     * the first argument is filled. The values of the other two arguments
     * are meaningless.
     */
    InArg[0].Type = ACPI_TYPE_INTEGER;
    InArg[0].Integer.Value = Enable;
    InArg[1].Type = ACPI_TYPE_INTEGER;
    InArg[1].Integer.Value = SleepState;
    InArg[2].Type = ACPI_TYPE_INTEGER;
    InArg[2].Integer.Value = DevState;
    Status = AcpiEvaluateObject(Dev->Handle, "_DSW", &ArgList, NULL);
    if (ACPI_SUCCESS(Status)) {
	return 0;
    } else if (Status != AE_NOT_FOUND) {
	DPRINT1("_DSW execution failed\n");
	Dev->Wakeup.Flags.Valid = 0;
	return -1;
    }

    /* Execute _PSW */
    ArgList.Count = 1;
    InArg[0].Integer.Value = Enable;
    Status = AcpiEvaluateObject(Dev->Handle, "_PSW", &ArgList, NULL);
    if (ACPI_FAILURE(Status) && (Status != AE_NOT_FOUND)) {
	DPRINT1("_PSW execution failed\n");
	Dev->Wakeup.Flags.Valid = 0;
	return -1;
    }

    return 0;
}

/*
 * Prepare a wakeup device, two steps (Ref ACPI 2.0:P229):
 * 1. Power on the power resources required for the wakeup device
 * 2. Execute _DSW (Device Sleep Wake) or (deprecated in ACPI 3.0) _PSW (Power
 *    State Wake) for the device, if present
 */
INT AcpiEnableWakeupDevicePower(PACPI_DEVICE Dev, INT SleepState)
{
    ULONG i;
    INT Err = 0;

    if (!Dev || !Dev->Wakeup.Flags.Valid)
	return -1;

    if (Dev->Wakeup.PrepareCount++)
	goto out;

    /* Open power resource */
    for (i = 0; i < Dev->Wakeup.Resources.Count; i++) {
	INT Ret = AcpiPowerOn(Dev->Wakeup.Resources.Handles[i], Dev);
	if (Ret) {
	    DPRINT("Transition power state\n");
	    Dev->Wakeup.Flags.Valid = 0;
	    Err = -1;
	    goto err_out;
	}
    }

    /*
     * Passing 3 as the third argument below means the device may be placed
     * in arbitrary power state afterwards.
     */
    Err = AcpiDeviceSleepWake(Dev, 1, SleepState, 3);

err_out:
    if (Err)
	Dev->Wakeup.PrepareCount = 0;

out:
    return Err;
}

/*
 * Shutdown a wakeup device, counterpart of above method
 * 1. Execute _DSW (Device Sleep Wake) or (deprecated in ACPI 3.0) _PSW (Power
 *    State Wake) for the device, if present
 * 2. Shutdown down the power resources
 */
INT AcpiDisableWakeupDevicePower(PACPI_DEVICE Dev)
{
    ULONG i;
    INT Err = 0;

    if (!Dev || !Dev->Wakeup.Flags.Valid)
	return -1;

    if (--Dev->Wakeup.PrepareCount > 0)
	goto out;

    /*
     * Executing the code below even if PrepareCount is already zero when
     * the function is called may be useful, for example for initialisation.
     */
    if (Dev->Wakeup.PrepareCount < 0)
	Dev->Wakeup.PrepareCount = 0;

    Err = AcpiDeviceSleepWake(Dev, 0, 0, 0);
    if (Err)
	goto out;

    /* Close power resource */
    for (i = 0; i < Dev->Wakeup.Resources.Count; i++) {
	INT Ret = AcpiPowerOffDevice(Dev->Wakeup.Resources.Handles[i], Dev);
	if (Ret) {
	    DPRINT("Transition power state\n");
	    Dev->Wakeup.Flags.Valid = 0;
	    Err = -1;
	    goto out;
	}
    }

out:
    return Err;
}

/* --------------------------------------------------------------------------
   Device Power Management
   -------------------------------------------------------------------------- */

INT AcpiPowerGetInferredState(PACPI_DEVICE Device)
{
    INT Result = 0;
    PACPI_HANDLE_LIST List = NULL;
    INT ListState = 0;
    INT i = 0;

    if (!Device)
	return_VALUE(-1);

    Device->Power.State = ACPI_STATE_UNKNOWN;

    /*
     * We know a device's inferred power state when all the resources
     * required for a given D-state are 'on'.
     */
    for (i = ACPI_STATE_D0; i < ACPI_STATE_D3; i++) {
	List = &Device->Power.States[i].Resources;
	if (List->Count < 1)
	    continue;

	Result = AcpiPowerGetListState(List, &ListState);
	if (Result)
	    return_VALUE(Result);

	if (ListState == ACPI_POWER_RESOURCE_STATE_ON) {
	    Device->Power.State = i;
	    return_VALUE(0);
	}
    }

    Device->Power.State = ACPI_STATE_D3;

    return_VALUE(0);
}

INT AcpiPowerTransition(PACPI_DEVICE Device, INT State)
{
    INT Result = 0;
    PACPI_HANDLE_LIST Cl = NULL; /* Current Resources */
    PACPI_HANDLE_LIST Tl = NULL; /* Target Resources */
    ULONG i = 0;

    if (!Device || (State < ACPI_STATE_D0) || (State > ACPI_STATE_D3))
	return_VALUE(-1);

    if ((Device->Power.State < ACPI_STATE_D0) || (Device->Power.State > ACPI_STATE_D3))
	return_VALUE(-15);

    Cl = &Device->Power.States[Device->Power.State].Resources;
    Tl = &Device->Power.States[State].Resources;

    /* TBD: Resources must be ordered. */

    /*
     * First we reference all power resources required in the target list
     * (e.g. so the device doesn't lose power while transitioning).
     */
    for (i = 0; i < Tl->Count; i++) {
	Result = AcpiPowerOn(Tl->Handles[i], Device);
	if (Result)
	    goto end;
    }

    if (Device->Power.State == State) {
	goto end;
    }

    /*
     * Then we dereference all power resources used in the current list.
     */
    for (i = 0; i < Cl->Count; i++) {
	Result = AcpiPowerOffDevice(Cl->Handles[i], Device);
	if (Result)
	    goto end;
    }

end:
    if (Result)
	Device->Power.State = ACPI_STATE_UNKNOWN;
    else {
	/* We shouldn't change the state till all above operations succeed */
	Device->Power.State = State;
    }

    return Result;
}

/* --------------------------------------------------------------------------
   Driver Interface
   -------------------------------------------------------------------------- */

static ACPI_STATUS AcpiPowerAdd(IN PDEVICE_OBJECT BusFdo, PACPI_DEVICE Device)
{
    INT Result = 0, State;
    ACPI_STATUS Status = AE_OK;
    PACPI_POWER_RESOURCE Resource = NULL;
    union acpi_object AcpiObject;
    ACPI_BUFFER Buffer = { sizeof(ACPI_OBJECT), &AcpiObject };

    if (!Device)
	return_VALUE(-1);

    Resource = ExAllocatePoolWithTag(NonPagedPool, sizeof(ACPI_POWER_RESOURCE),
				     ACPI_TAG);
    if (!Resource)
	return_VALUE(-4);

    Resource->Device = Device;
    InitializeListHead(&Resource->Reference);

    strcpy(Resource->Name, Device->Pnp.BusId);
    strcpy(ACPI_DEVICE_NAME(Device), ACPI_POWER_DEVICE_NAME);
    strcpy(ACPI_DEVICE_CLASS(Device), ACPI_POWER_CLASS);
    Device->DriverData = Resource;

    /* Evalute the object to get the system level and resource order. */
    Status = AcpiEvaluateObject(Device->Handle, NULL, NULL, &Buffer);
    if (ACPI_FAILURE(Status)) {
	Result = -15;
	goto end;
    }
    Resource->SystemLevel = AcpiObject.PowerResource.SystemLevel;
    Resource->Order = AcpiObject.PowerResource.ResourceOrder;

    Result = AcpiPowerGetState(Device->Handle, &State);
    if (Result)
	goto end;

    switch (State) {
    case ACPI_POWER_RESOURCE_STATE_ON:
	Device->Power.State = ACPI_STATE_D0;
	break;
    case ACPI_POWER_RESOURCE_STATE_OFF:
	Device->Power.State = ACPI_STATE_D3;
	break;
    default:
	Device->Power.State = ACPI_STATE_UNKNOWN;
	break;
    }

    DPRINT("%s [%s] (%s)\n", ACPI_DEVICE_NAME(Device), ACPI_DEVICE_BID(Device),
	   State ? "on" : "off");

end:
    if (Result)
	ExFreePool(Resource);

    return Result;
}

ACPI_STATUS AcpiPowerRemove(PACPI_DEVICE Device, INT Type)
{
    PACPI_POWER_RESOURCE Resource = NULL;

    if (!Device || !ACPI_BUSMGR_COMPONENT_DATA(Device))
	return_VALUE(-1);

    Resource = ACPI_BUSMGR_COMPONENT_DATA(Device);

    LoopOverList(ref, &Resource->Reference, ACPI_POWER_REFERENCE, Node) {
	RemoveEntryList(&ref->Node);
	ExFreePool(ref);
    }
    ExFreePool(Resource);

    return_VALUE(0);
}

static ACPI_STATUS AcpiPowerResume(PACPI_DEVICE Device, INT State)
{
    INT Result = 0;
    PACPI_POWER_RESOURCE Resource = NULL;
    PACPI_POWER_REFERENCE Ref;

    if (!Device || !ACPI_BUSMGR_COMPONENT_DATA(Device))
	return -1;

    Resource = ACPI_BUSMGR_COMPONENT_DATA(Device);

    Result = AcpiPowerGetState(Device->Handle, &State);
    if (Result)
	return Result;

    if (State == ACPI_POWER_RESOURCE_STATE_OFF && !IsListEmpty(&Resource->Reference)) {
	Ref = CONTAINING_RECORD(Resource->Reference.Flink, ACPI_POWER_REFERENCE, Node);
	Result = AcpiPowerOn(Device->Handle, Ref->Device);
	return Result;
    }

    return 0;
}

INT AcpiPowerInit(IN PDEVICE_OBJECT BusFdo)
{
    INT Result = 0;

    DPRINT("AcpiPowerInit\n");

    InitializeListHead(&AcpiPowerResourceList);

    Result = AcpiBusRegisterDriver(BusFdo, &AcpiPowerDriver);
    if (Result < 0) {
	return_VALUE(-15);
    }

    return_VALUE(0);
}

/**
 * AcpiBusSuspendSystem - Set the system power state to one of the S? sleep states.
 */
ACPI_STATUS AcpiBusSuspendSystem(UINT32 State, POWER_ACTION Action)
{
    AcpiEnterSleepStatePrep(State);

    ACPI_STATUS Status = (Action == PowerActionShutdownReset) ?
	AcpiReset() : AcpiEnterSleepState(State);
    if (!ACPI_SUCCESS(Status))
	return Status;

    /* For S5, if everything goes well, the machine should be powered off
     * at this point. If we are still running, something must be wrong. */
    return State == ACPI_STATE_S5 ? STATUS_ACPI_POWER_REQUEST_FAILED : STATUS_SUCCESS;
}
