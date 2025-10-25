/*
 *  acpi_button.c - ACPI Button Driver ($Revision: 29 $)
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

#include <stdio.h>
#include "../precomp.h"
#include <poclass.h>
#include "acpi_bus.h"
#include "acpi_drivers.h"

#define _COMPONENT ACPI_BUTTON_COMPONENT
ACPI_MODULE_NAME("acpi_button")

static ACPI_STATUS AcpiButtonAdd(IN PDEVICE_OBJECT DeviceObject, PACPI_DEVICE Device);
static ACPI_STATUS AcpiButtonRemove(PACPI_DEVICE Device, INT Type);

static ACPI_BUSMGR_COMPONENT AcpiButtonDriver = {
    { 0, 0 }, ACPI_BUTTON_DRIVER_NAME, ACPI_BUTTON_CLASS, 0, 0,
    "ACPI_FPB,ACPI_FSB,PNP0C0D,PNP0C0C,PNP0C0E",
    { AcpiButtonAdd, AcpiButtonRemove }
};

typedef struct _ACPI_BUTTON {
    ACPI_HANDLE Handle;
    PACPI_DEVICE Device; /* Fixed button kludge */
    IO_WORKITEM IrpWorkItem;
    UINT8 Type;
    ULONG64 Pushed;
} ACPI_BUTTON, *PACPI_BUTTON;

typedef struct _ACPI_BUTTON_EVENT {
    SLIST_ENTRY SListEntry;
    ULONG ButtonEvent;
} ACPI_BUTTON_EVENT, *PACPI_BUTTON_EVENT;

PACPI_DEVICE PowerButton;
PACPI_DEVICE SleepButton;
PACPI_DEVICE LidButton;

/* --------------------------------------------------------------------------
   Button Event Management
   -------------------------------------------------------------------------- */

static SLIST_HEADER GetButtonEventIrpList;
static SLIST_HEADER ButtonEventList;

NTSTATUS AcpiBusHandleGetButtonEventIrp(IN PIRP Irp)
{
    PSLIST_ENTRY Entry = RtlInterlockedPopEntrySList(&ButtonEventList);
    if (Entry) {
	PACPI_BUTTON_EVENT Event = CONTAINING_RECORD(Entry,
						     ACPI_BUTTON_EVENT,
						     SListEntry);
	RtlCopyMemory(Irp->SystemBuffer, &Event->ButtonEvent, sizeof(ULONG));
	Irp->IoStatus.Information = sizeof(ULONG);
	return STATUS_SUCCESS;
    } else {
	RtlInterlockedPushEntrySList(&GetButtonEventIrpList, &Irp->Tail.SListEntry);
	return STATUS_PENDING;
    }
}

static NTAPI VOID ButtonEventWorkItemRoutine(IN PDEVICE_OBJECT DeviceObject,
					     IN OPTIONAL PVOID Ctx)
{
    PIRP Irp = Ctx;
    ULONG ButtonEvent = Irp->IoStatus.Status;
    RtlCopyMemory(Irp->SystemBuffer, &ButtonEvent, sizeof(ULONG));
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(ULONG);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/*
 * Note this function is called in the interrupt thread, so we need to
 * synchronize access with the main thread.
 */
static INT HandleButtonEvent(PACPI_BUTTON Button, UINT8 Type, INT Data)
{
    DPRINT("AcpiBusGenerateEvent\n");

    PACPI_DEVICE Device = Button->Device;
    if (!Device)
	return_VALUE(AE_BAD_PARAMETER);

    ULONG ButtonEvent = 0;
    if (strstr(Device->Pnp.BusId, "PWRF"))
	ButtonEvent = SYS_BUTTON_POWER;
    else if (strstr(Device->Pnp.BusId, "SLPF"))
	ButtonEvent = SYS_BUTTON_SLEEP;

    PSLIST_ENTRY Entry = RtlInterlockedPopEntrySList(&GetButtonEventIrpList);
    /* If there is no queued IRP waiting for the button event, so we save the
     * button event into the event list. */
    if (!Entry) {
	PACPI_BUTTON_EVENT Event = ExAllocatePoolWithTag(NonPagedPool,
							 sizeof(ACPI_BUTTON_EVENT),
							 ACPI_TAG);
	if (!Event) {
	    return_VALUE(AE_NO_MEMORY);
	}
	Event->ButtonEvent = ButtonEvent;
	RtlInterlockedPushEntrySList(&ButtonEventList, &Event->SListEntry);
	return_VALUE(AE_OK);
    }
    PIRP Irp = CONTAINING_RECORD(Entry, IRP, Tail.SListEntry);
    /* We pass ButtonEvent in the IoStatus field of the IRP object
     * so we don't have to define and allocate a context for the work item. */
    Irp->IoStatus.Status = ButtonEvent;
    IoQueueWorkItem(&Button->IrpWorkItem, ButtonEventWorkItemRoutine,
		    DelayedWorkQueue, Irp);
    return_VALUE(AE_OK);
}

/* --------------------------------------------------------------------------
   Driver Interface
   -------------------------------------------------------------------------- */

static VOID AcpiButtonNotify(ACPI_HANDLE Handle, UINT32 Event, PVOID Data)
{
    PACPI_BUTTON Button = (PACPI_BUTTON)Data;

    ACPI_FUNCTION_TRACE("AcpiButtonNotify");

    if (!Button || !Button->Device)
	return_VOID;

    switch (Event) {
    case ACPI_BUTTON_NOTIFY_STATUS:
	HandleButtonEvent(Button, Event, ++Button->Pushed);
	break;
    default:
	ACPI_DEBUG_PRINT((ACPI_DB_INFO, "Unsupported event [0x%x]\n", Event));
	break;
    }

    return_VOID;
}

static ACPI_STATUS AcpiButtonNotifyFixed(PVOID Data)
{
    PACPI_BUTTON Button = (PACPI_BUTTON )Data;

    ACPI_FUNCTION_TRACE("AcpiButtonNotifyFixed");

    if (!Button)
	return_ACPI_STATUS(AE_BAD_PARAMETER);

    AcpiButtonNotify(Button->Handle, ACPI_BUTTON_NOTIFY_STATUS, Button);

    return_ACPI_STATUS(AE_OK);
}

static ACPI_STATUS AcpiButtonAdd(IN PDEVICE_OBJECT BusFdo, PACPI_DEVICE Device)
{
    INT Result = 0;
    ACPI_STATUS Status = AE_OK;
    PACPI_BUTTON Button = NULL;

    ACPI_FUNCTION_TRACE("AcpiButtonAdd");

    if (!Device)
	return_VALUE(-1);

    Button = ExAllocatePoolWithTag(NonPagedPool, sizeof(ACPI_BUTTON), ACPI_TAG);
    if (!Button)
	return_VALUE(-4);
    memset(Button, 0, sizeof(ACPI_BUTTON));

    Button->Device = Device;
    Button->Handle = Device->Handle;
    IoInitializeWorkItem(BusFdo, &Button->IrpWorkItem);
    ACPI_BUSMGR_COMPONENT_DATA(Device) = Button;

    /*
     * Determine the button type (via hid), as fixed-feature buttons
     * need to be handled a bit differently than generic-space.
     */
    if (!strcmp(ACPI_DEVICE_HID(Device), ACPI_BUTTON_HID_POWER)) {
	Button->Type = ACPI_BUTTON_TYPE_POWER;
	sprintf(ACPI_DEVICE_NAME(Device), "%s", ACPI_BUTTON_DEVICE_NAME_POWER);
	sprintf(ACPI_DEVICE_CLASS(Device), "%s/%s", ACPI_BUTTON_CLASS,
		ACPI_BUTTON_SUBCLASS_POWER);
    } else if (!strcmp(ACPI_DEVICE_HID(Device), ACPI_BUTTON_HID_POWERF)) {
	Button->Type = ACPI_BUTTON_TYPE_POWERF;
	sprintf(ACPI_DEVICE_NAME(Device), "%s", ACPI_BUTTON_DEVICE_NAME_POWERF);
	sprintf(ACPI_DEVICE_CLASS(Device), "%s/%s", ACPI_BUTTON_CLASS,
		ACPI_BUTTON_SUBCLASS_POWER);
    } else if (!strcmp(ACPI_DEVICE_HID(Device), ACPI_BUTTON_HID_SLEEP)) {
	Button->Type = ACPI_BUTTON_TYPE_SLEEP;
	sprintf(ACPI_DEVICE_NAME(Device), "%s", ACPI_BUTTON_DEVICE_NAME_SLEEP);
	sprintf(ACPI_DEVICE_CLASS(Device), "%s/%s", ACPI_BUTTON_CLASS,
		ACPI_BUTTON_SUBCLASS_SLEEP);
    } else if (!strcmp(ACPI_DEVICE_HID(Device), ACPI_BUTTON_HID_SLEEPF)) {
	Button->Type = ACPI_BUTTON_TYPE_SLEEPF;
	sprintf(ACPI_DEVICE_NAME(Device), "%s", ACPI_BUTTON_DEVICE_NAME_SLEEPF);
	sprintf(ACPI_DEVICE_CLASS(Device), "%s/%s", ACPI_BUTTON_CLASS,
		ACPI_BUTTON_SUBCLASS_SLEEP);
    } else if (!strcmp(ACPI_DEVICE_HID(Device), ACPI_BUTTON_HID_LID)) {
	Button->Type = ACPI_BUTTON_TYPE_LID;
	sprintf(ACPI_DEVICE_NAME(Device), "%s", ACPI_BUTTON_DEVICE_NAME_LID);
	sprintf(ACPI_DEVICE_CLASS(Device), "%s/%s", ACPI_BUTTON_CLASS,
		ACPI_BUTTON_SUBCLASS_LID);
    } else {
	ACPI_DEBUG_PRINT((ACPI_DB_ERROR,
			  "Unsupported hid [%s]\n", ACPI_DEVICE_HID(Device)));
	Result = -15;
	goto end;
    }

    /*
     * Ensure only one button of each type is used.
     */
    switch (Button->Type) {
    case ACPI_BUTTON_TYPE_POWER:
    case ACPI_BUTTON_TYPE_POWERF:
	if (!PowerButton)
	    PowerButton = Device;
	else {
	    ExFreePoolWithTag(Button, ACPI_TAG);
	    return_VALUE(-15);
	}
	break;
    case ACPI_BUTTON_TYPE_SLEEP:
    case ACPI_BUTTON_TYPE_SLEEPF:
	if (!SleepButton)
	    SleepButton = Device;
	else {
	    ExFreePoolWithTag(Button, ACPI_TAG);
	    return_VALUE(-15);
	}
	break;
    case ACPI_BUTTON_TYPE_LID:
	if (!LidButton)
	    LidButton = Device;
	else {
	    ExFreePoolWithTag(Button, ACPI_TAG);
	    return_VALUE(-15);
	}
	break;
    }

    switch (Button->Type) {
    case ACPI_BUTTON_TYPE_POWER:
    case ACPI_BUTTON_TYPE_POWERF:
	Status = AcpiInstallFixedEventHandler(ACPI_EVENT_POWER_BUTTON,
					      AcpiButtonNotifyFixed, Button);
	break;
    case ACPI_BUTTON_TYPE_SLEEP:
    case ACPI_BUTTON_TYPE_SLEEPF:
	Status = AcpiInstallFixedEventHandler(ACPI_EVENT_SLEEP_BUTTON,
					      AcpiButtonNotifyFixed, Button);
	break;
    default:
	Status = AcpiInstallNotifyHandler(Button->Handle, ACPI_DEVICE_NOTIFY,
					  AcpiButtonNotify, Button);
	break;
    }

    if (ACPI_FAILURE(Status)) {
	ACPI_DEBUG_PRINT((ACPI_DB_ERROR,
			  "Error installing notify handler for button device handle %p, "
			  "type %d, hid %s (%s), class %s, status = 0x%x\n",
			  Button->Handle, Button->Type, ACPI_DEVICE_HID(Device),
			  ACPI_DEVICE_NAME(Device), ACPI_DEVICE_CLASS(Device),
			  Status));
	Result = Status;
	goto end;
    }

    DPRINT("%s [%s]\n", ACPI_DEVICE_NAME(Device), ACPI_DEVICE_BID(Device));

end:
    if (Result) {
	ExFreePoolWithTag(Button, ACPI_TAG);
    }

    return_VALUE(Result);
}

static ACPI_STATUS AcpiButtonRemove(PACPI_DEVICE Device, INT Type)
{
    ACPI_STATUS Status = 0;
    PACPI_BUTTON Button = NULL;

    ACPI_FUNCTION_TRACE("AcpiButtonRemove");

    if (!Device || !ACPI_BUSMGR_COMPONENT_DATA(Device))
	return_VALUE(-1);

    Button = ACPI_BUSMGR_COMPONENT_DATA(Device);

    /* Unregister for device notifications. */
    switch (Button->Type) {
    case ACPI_BUTTON_TYPE_POWERF:
	Status = AcpiRemoveFixedEventHandler(ACPI_EVENT_POWER_BUTTON,
					     AcpiButtonNotifyFixed);
	break;
    case ACPI_BUTTON_TYPE_SLEEPF:
	Status = AcpiRemoveFixedEventHandler(ACPI_EVENT_SLEEP_BUTTON,
					     AcpiButtonNotifyFixed);
	break;
    case ACPI_BUTTON_TYPE_LID:
	Status = AcpiRemoveFixedEventHandler(ACPI_BUTTON_TYPE_LID,
					     AcpiButtonNotifyFixed);
	break;
    default:
	Status = AcpiRemoveNotifyHandler(Button->Handle, ACPI_DEVICE_NOTIFY,
					 AcpiButtonNotify);
	break;
    }

    if (ACPI_FAILURE(Status))
	ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "Error removing notify handler\n"));

    ExFreePoolWithTag(Button, ACPI_TAG);

    return_VALUE(0);
}

INT AcpiButtonInit(IN PDEVICE_OBJECT DeviceObject)
{
    INT Result = 0;

    ACPI_FUNCTION_TRACE("AcpiButtonInit");

    RtlInitializeSListHead(&GetButtonEventIrpList);
    RtlInitializeSListHead(&ButtonEventList);
    Result = AcpiBusRegisterDriver(DeviceObject, &AcpiButtonDriver);
    if (Result < 0) {
	return_VALUE(-15);
    }

    return_VALUE(0);
}

VOID AcpiButtonExit(IN PDEVICE_OBJECT DeviceObject)
{
    ACPI_FUNCTION_TRACE("AcpiButtonExit");

    AcpiBusUnregisterDriver(DeviceObject, &AcpiButtonDriver);

    return_VOID;
}
