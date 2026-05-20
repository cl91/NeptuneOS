/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/power.c
 * PURPOSE:         Bus/Device Power Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* GLOBALS ********************************************************************/

ULONG PciPowerDelayTable[PowerDeviceD3 * PowerDeviceD3] = {
    0, // D0 -> D0
    0, // D1 -> D0
    200, // D2 -> D0
    10000, // D3 -> D0

    0, // D0 -> D1
    0, // D1 -> D1
    200, // D2 -> D1
    10000, // D3 -> D1

    200, // D0 -> D2
    200, // D1 -> D2
    0, // D2 -> D2
    10000, // D3 -> D2

    10000, // D0 -> D3
    10000, // D1 -> D3
    10000, // D2 -> D3
    0 // D3 -> D3
};

/* FUNCTIONS ******************************************************************/

static NTSTATUS PcipStallForPowerChange(IN PPCI_PDO_EXTENSION PdoExtension,
					IN DEVICE_POWER_STATE PowerState,
					IN ULONG_PTR CapOffset)
{
    ULONG PciState, TimeoutEntry, PmcsrOffset, TryCount;
    LARGE_INTEGER Interval;
    PCI_PMCSR Pmcsr;

    /* Make sure the power state is valid, and the device can support it */
    ASSERT((PdoExtension->PowerState.CurrentDeviceState >= PowerDeviceD0) &&
	   (PdoExtension->PowerState.CurrentDeviceState <= PowerDeviceD3));
    ASSERT((PowerState >= PowerDeviceD0) && (PowerState <= PowerDeviceD3));
    ASSERT(!PdoExtension->NoPmCaps);

    /* Pick the expected timeout for this transition */
    TimeoutEntry =
	PciPowerDelayTable[PowerState * PdoExtension->PowerState.CurrentDeviceState];

    /* PCI power states are one less than NT power states */
    PciState = PowerState - 1;

    /* The state status is stored in the PMCSR offset */
    PmcsrOffset = CapOffset + FIELD_OFFSET(PCI_PM_CAPABILITY, PMCSR);

    /* Try changing the power state up to 100 times */
    TryCount = 100;
    while (--TryCount) {
	/* Check if this state transition will take time */
	if (TimeoutEntry > 0) {
	    /* Do a wait for the timeout specified instead */
	    Interval.QuadPart = -10LL * (LONGLONG)TimeoutEntry;
	    KeDelayExecutionThread(FALSE, &Interval);
	}

	/* Read the PMCSR and see if the state has changed */
	PciReadDeviceConfig(PdoExtension, &Pmcsr, PmcsrOffset, sizeof(PCI_PMCSR));
	if (Pmcsr.PowerState == PciState)
	    return STATUS_SUCCESS;

	/* Try again, forcing a timeout of 1ms */
	TimeoutEntry = 1000;
    }

    return STATUS_DEVICE_PROTOCOL_ERROR;
}

static BOOLEAN PcipCanDisableDecodes(IN PPCI_PDO_EXTENSION DeviceExtension,
				     IN BOOLEAN ForPowerDown)
{
    ASSERT(DeviceExtension);

    /* Get classification from the device extension */
    UCHAR SubClass = DeviceExtension->SubClass;
    UCHAR BaseClass = DeviceExtension->BaseClass;

    /* Is this a VGA adapter? */
    if ((BaseClass == PCI_CLASS_DISPLAY_CTLR) &&
	(SubClass == PCI_SUBCLASS_VID_VGA_CTLR)) {
	/* Never disable decodes if this is for power down */
	return ForPowerDown;
    }

    /* Check for legacy devices */
    if (BaseClass == PCI_CLASS_PRE_20) {
	/* Never disable video adapter cards if this is for power down */
	if (SubClass == PCI_SUBCLASS_PRE_20_VGA)
	    return ForPowerDown;
    } else if (BaseClass == PCI_CLASS_DISPLAY_CTLR) {
	/* Never disable VGA adapters if this is for power down */
	if (SubClass == PCI_SUBCLASS_VID_VGA_CTLR)
	    return ForPowerDown;
    } else if (BaseClass == PCI_CLASS_BRIDGE_DEV) {
	/* Check for legacy bridges */
	if ((SubClass == PCI_SUBCLASS_BR_ISA) || (SubClass == PCI_SUBCLASS_BR_EISA) ||
	    (SubClass == PCI_SUBCLASS_BR_MCA) || (SubClass == PCI_SUBCLASS_BR_HOST) ||
	    (SubClass == PCI_SUBCLASS_BR_OTHER)) {
	    /* Never disable these */
	    return FALSE;
	} else if ((SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI) ||
		   (SubClass == PCI_SUBCLASS_BR_CARDBUS)) {
	    /* This is a supported bridge, but does it have a VGA card? */
	    BOOLEAN IsVga = DeviceExtension->BridgeInfo.VgaBitSet;

	    /* Never disable VGA adapters if this is for power down */
	    if (IsVga)
		return ForPowerDown;
	}
    }

    /* Finally, never disable decodes if there's no power management */
    return DeviceExtension ? !DeviceExtension->NoPmCaps : TRUE;
}

NTSTATUS PciSetPowerManagedDevicePowerState(IN PPCI_PDO_EXTENSION DeviceExtension,
					    IN DEVICE_POWER_STATE DeviceState)
{
    /* Assume success */
    NTSTATUS Status = STATUS_SUCCESS;

    /* Check if this device can support low power states */
    if (!PcipCanDisableDecodes(DeviceExtension, TRUE) &&
	(DeviceState != PowerDeviceD0)) {
	/* Simply return success, ignoring this request */
	DPRINT1("Cannot disable decodes on this device, ignoring PM request...\n");
	return Status;
    }

    /* Does the device support power management at all? */
    if (DeviceExtension->NoPmCaps) {
	/* Nothing to do! */
	DPRINT1("No PM on this device, ignoring request\n");
	return Status;
    }

    /* Get the PM capabilities register */
    PCI_PM_CAPABILITY PmCaps;
    ULONG CapsOffset = PciReadDeviceCapability(DeviceExtension,
					       DeviceExtension->CapabilitiesPtr,
					       PCI_CAPABILITY_ID_POWER_MANAGEMENT,
					       &PmCaps.Header, sizeof(PCI_PM_CAPABILITY));
    ASSERT(CapsOffset);
    ASSERT(DeviceState != PowerDeviceUnspecified);

    /* Check if the device is being powered up */
    if (DeviceState == PowerDeviceD0) {
	/* Set full power state */
	PmCaps.PMCSR.ControlStatus.PowerState = 0;

	/* Check if the device supports Cold-D3 poweroff */
	if (PmCaps.PMC.Capabilities.Support.PMED3Cold) {
	    /* If there was a pending PME, clear it */
	    PmCaps.PMCSR.ControlStatus.PMEStatus = 1;
	}
    } else {
	/* Otherwise, just set the new power state, converting from NT */
	PmCaps.PMCSR.ControlStatus.PowerState = DeviceState - 1;
    }

    /* Write the new power state in the PMCSR */
    PciWriteDeviceConfig(DeviceExtension, &PmCaps.PMCSR,
			 CapsOffset + FIELD_OFFSET(PCI_PM_CAPABILITY, PMCSR),
			 sizeof(PCI_PMCSR));

    /* Now wait for the change to "stick" based on the spec-mandated time */
    return PcipStallForPowerChange(DeviceExtension, DeviceState, CapsOffset);
}

NTSTATUS PciFdoWaitWake(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED;
    while (TRUE)
	;
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS PciFdoSetPowerState(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			     IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED;
    /* For now we return success as our only supported power transition is
     * poweroff/reset. */
    return STATUS_SUCCESS;
}

NTSTATUS PciFdoIrpQueryPower(IN PIRP Irp, IN PIO_STACK_LOCATION IoStackLocation,
			     IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED;
    while (TRUE)
	;
    return STATUS_NOT_SUPPORTED;
}
