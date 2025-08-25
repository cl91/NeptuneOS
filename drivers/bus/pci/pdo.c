/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/pdo.c
 * PURPOSE:         PDO Device Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"
#include <stdio.h>

/* GLOBALS ********************************************************************/

LONG PciPdoSequenceNumber;

C_ASSERT(FIELD_OFFSET(PCI_FDO_EXTENSION, DeviceState) ==
	 FIELD_OFFSET(PCI_PDO_EXTENSION, DeviceState));
C_ASSERT(FIELD_OFFSET(PCI_FDO_EXTENSION, TentativeNextState) ==
	 FIELD_OFFSET(PCI_PDO_EXTENSION, TentativeNextState));
C_ASSERT(FIELD_OFFSET(PCI_FDO_EXTENSION, List) == FIELD_OFFSET(PCI_PDO_EXTENSION, Next));

/* FUNCTIONS ******************************************************************/

static NTSTATUS PciPdoWaitWake(IN PIRP Irp,
			       IN PIO_STACK_LOCATION IoStackLocation,
			       IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoSetPowerState(IN PIRP Irp,
				    IN PIO_STACK_LOCATION IoStackLocation,
				    IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoIrpQueryPower(IN PIRP Irp,
				    IN PIO_STACK_LOCATION IoStackLocation,
				    IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoStartDevice(IN PIRP Irp,
				  IN PIO_STACK_LOCATION IoStackLocation,
				  IN PPCI_PDO_EXTENSION DeviceExtension)
{
    NTSTATUS Status;
    BOOLEAN Changed, DoReset;
    POWER_STATE PowerState;

    UNREFERENCED_PARAMETER(Irp);

    DoReset = FALSE;

    /* Begin entering the start phase */
    Status = PciBeginStateTransition((PVOID)DeviceExtension, PciStarted);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Check if this is a VGA device */
    if (((DeviceExtension->BaseClass == PCI_CLASS_PRE_20) &&
	 (DeviceExtension->SubClass == PCI_SUBCLASS_PRE_20_VGA)) ||
	((DeviceExtension->BaseClass == PCI_CLASS_DISPLAY_CTLR) &&
	 (DeviceExtension->SubClass == PCI_SUBCLASS_VID_VGA_CTLR))) {
	/* Always force it on */
	DeviceExtension->CommandEnables |= (PCI_ENABLE_IO_SPACE |
					    PCI_ENABLE_MEMORY_SPACE);
    }

    /* Check if native IDE is enabled and it owns the I/O ports */
    if (DeviceExtension->IoSpaceUnderNativeIdeControl) {
	/* Then don't allow I/O access */
	DeviceExtension->CommandEnables &= ~PCI_ENABLE_IO_SPACE;
    }

    /* Always enable bus mastering */
    DeviceExtension->CommandEnables |= PCI_ENABLE_BUS_MASTER;

    /* Check if the OS assigned resources differ from the PCI configuration */
    Changed = PciComputeNewCurrentSettings(
	DeviceExtension, IoStackLocation->Parameters.StartDevice.AllocatedResources);
    if (Changed) {
	/* Remember this for later */
	DeviceExtension->MovedDevice = TRUE;
    } else {
	/* All good */
	DPRINT1("PCI - START not changing resource settings.\n");
    }

    /* Check if the device was sleeping */
    if (DeviceExtension->PowerState.CurrentDeviceState != PowerDeviceD0) {
	/* Power it up */
	Status = PciSetPowerManagedDevicePowerState(DeviceExtension, PowerDeviceD0,
						    FALSE);
	if (!NT_SUCCESS(Status)) {
	    /* Powerup fail, fail the request */
	    PciCancelStateTransition((PVOID)DeviceExtension, PciStarted);
	    return STATUS_DEVICE_POWER_FAILURE;
	}

	/* Tell the power manager that the device is powered up */
	PowerState.DeviceState = PowerDeviceD0;
	PoSetPowerState(DeviceExtension->PhysicalDeviceObject, DevicePowerState,
			PowerState);

	/* Update internal state */
	DeviceExtension->PowerState.CurrentDeviceState = PowerDeviceD0;

	/* This device's resources and decodes will need to be reset */
	DoReset = TRUE;
    }

    /* Update resource information now that the device is powered up and active */
    Status = PciSetResources(DeviceExtension, DoReset);
    if (!NT_SUCCESS(Status)) {
	/* That failed, so cancel the transition */
	PciCancelStateTransition((PVOID)DeviceExtension, PciStarted);
    } else {
	/* Fully commit, as the device is now started up and ready to go */
	PciCommitStateTransition((PVOID)DeviceExtension, PciStarted);
    }

    /* Return the result of the start request */
    return Status;
}

static NTSTATUS PciPdoQueryRemoveDevice(IN PIRP Irp,
					IN PIO_STACK_LOCATION IoStackLocation,
					IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoRemoveDevice(IN PIRP Irp,
				   IN PIO_STACK_LOCATION IoStackLocation,
				   IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoCancelRemoveDevice(IN PIRP Irp,
					 IN PIO_STACK_LOCATION IoStackLocation,
					 IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoStopDevice(IN PIRP Irp,
				 IN PIO_STACK_LOCATION IoStackLocation,
				 IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoQueryStopDevice(IN PIRP Irp,
				      IN PIO_STACK_LOCATION IoStackLocation,
				      IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoCancelStopDevice(IN PIRP Irp,
				       IN PIO_STACK_LOCATION IoStackLocation,
				       IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoQueryDeviceRelations(IN PIRP Irp,
					   IN PIO_STACK_LOCATION IoStackLocation,
					   IN PPCI_PDO_EXTENSION DeviceExtension)
{
    NTSTATUS Status;

    /* Are ejection relations being queried? */
    if (IoStackLocation->Parameters.QueryDeviceRelations.Type == EjectionRelations) {
	/* Call the worker function */
	Status = PciQueryEjectionRelations(
	    DeviceExtension, (PDEVICE_RELATIONS *)&Irp->IoStatus.Information);
    } else if (IoStackLocation->Parameters.QueryDeviceRelations.Type ==
	       TargetDeviceRelation) {
	/* The only other relation supported is the target device relation */
	Status = PciQueryTargetDeviceRelations(
	    DeviceExtension, (PDEVICE_RELATIONS *)&Irp->IoStatus.Information);
    } else {
	/* All other relations are unsupported */
	Status = STATUS_NOT_SUPPORTED;
    }

    /* Return either the result of the worker function, or unsupported status */
    return Status;
}

static NTSTATUS PciPdoQueryCapabilities(IN PIRP Irp,
					IN PIO_STACK_LOCATION IoStackLocation,
					IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);

    /* Call the worker function */
    return PciQueryCapabilities(
	DeviceExtension, IoStackLocation->Parameters.DeviceCapabilities.Capabilities);
}

static NTSTATUS PciPdoQueryResources(IN PIRP Irp,
				     IN PIO_STACK_LOCATION IoStackLocation,
				     IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(IoStackLocation);

    /* Call the worker function */
    return PciQueryResources(DeviceExtension,
			     (PCM_RESOURCE_LIST *)&Irp->IoStatus.Information);
}

static NTSTATUS PciPdoQueryResourceRequirements(IN PIRP Irp,
						IN PIO_STACK_LOCATION IoStackLocation,
						IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(IoStackLocation);

    /* Call the worker function */
    return PciQueryRequirements(
	DeviceExtension, (PIO_RESOURCE_REQUIREMENTS_LIST *)&Irp->IoStatus.Information);
}

static NTSTATUS PciPdoQueryDeviceText(IN PIRP Irp,
				      IN PIO_STACK_LOCATION IoStackLocation,
				      IN PPCI_PDO_EXTENSION DeviceExtension)
{
    /* Call the worker function */
    return PciQueryDeviceText(DeviceExtension,
			      IoStackLocation->Parameters.QueryDeviceText.DeviceTextType,
			      IoStackLocation->Parameters.QueryDeviceText.LocaleId,
			      (PWCHAR *)&Irp->IoStatus.Information);
}

static NTSTATUS PciPdoQueryId(IN PIRP Irp,
			      IN PIO_STACK_LOCATION IoStackLocation,
			      IN PPCI_PDO_EXTENSION DeviceExtension)
{
    /* Call the worker function */
    return PciQueryId(DeviceExtension, IoStackLocation->Parameters.QueryId.IdType,
		      (PWCHAR *)&Irp->IoStatus.Information);
}

static NTSTATUS PciPdoQueryBusInformation(IN PIRP Irp,
					  IN PIO_STACK_LOCATION IoStackLocation,
					  IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(IoStackLocation);

    /* Call the worker function */
    return PciQueryBusInformation(DeviceExtension,
				  (PPNP_BUS_INFORMATION *)&Irp->IoStatus.Information);
}

static NTSTATUS PciPdoReadWriteConfig(IN PIRP Irp,
				      IN PIO_STACK_LOCATION IoStack,
				      IN PPCI_PDO_EXTENSION DeviceExtension,
				      IN BOOLEAN Write)
{
    ASSERT_PDO(DeviceExtension);
    Irp->IoStatus.Information = 0;
    if (IoStack->Parameters.ReadWriteConfig.WhichSpace != PCI_WHICHSPACE_CONFIG) {
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    ULONG Offset = IoStack->Parameters.ReadWriteConfig.Offset;
    ULONG Length = IoStack->Parameters.ReadWriteConfig.Length;
    ULONG ConfigSpaceSize = DeviceExtension->InterfaceType == PciExpress ?
	PCI_EXTENDED_CONFIG_LENGTH : sizeof(PCI_COMMON_CONFIG);
    if (Offset + Length > ConfigSpaceSize) {
	return STATUS_INVALID_DEVICE_REQUEST;
    }
    __try {
	if (Write) {
	    PciWriteDeviceConfig(DeviceExtension,
				 IoStack->Parameters.ReadWriteConfig.Buffer,
				 Offset, Length);
	} else {
	    PciReadDeviceConfig(DeviceExtension,
				IoStack->Parameters.ReadWriteConfig.Buffer,
				Offset, Length);
	}
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	/* If we have a PDO the device must have been enumerated and is assumed to
	 * exist. If the IO failed, it is likely a hardware error. */
	return STATUS_DEVICE_HARDWARE_ERROR;
    }
    Irp->IoStatus.Information = Length;

    return STATUS_SUCCESS;
}

static NTSTATUS PciPdoReadConfig(IN PIRP Irp,
				 IN PIO_STACK_LOCATION IoStack,
				 IN PPCI_PDO_EXTENSION DeviceExtension)
{
    return PciPdoReadWriteConfig(Irp, IoStack, DeviceExtension, FALSE);
}

static NTSTATUS PciPdoWriteConfig(IN PIRP Irp,
				  IN PIO_STACK_LOCATION IoStack,
				  IN PPCI_PDO_EXTENSION DeviceExtension)
{
    return PciPdoReadWriteConfig(Irp, IoStack, DeviceExtension, TRUE);
}

static NTSTATUS PciPdoQueryDeviceState(IN PIRP Irp,
				       IN PIO_STACK_LOCATION IoStackLocation,
				       IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoDeviceUsageNotification(IN PIRP Irp,
					      IN PIO_STACK_LOCATION IoStackLocation,
					      IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoSurpriseRemoval(IN PIRP Irp,
				      IN PIO_STACK_LOCATION IoStackLocation,
				      IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciPdoQueryLegacyBusInformation(IN PIRP Irp,
						IN PIO_STACK_LOCATION IoStackLocation,
						IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static PCI_MN_DISPATCH_TABLE PciPdoDispatchPowerTable[] = {
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoWaitWake },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoSetPowerState },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoIrpQueryPower },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported }
};

static PCI_MN_DISPATCH_TABLE PciPdoDispatchPnpTable[] = {
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoStartDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryRemoveDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoRemoveDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoCancelRemoveDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoStopDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryStopDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoCancelStopDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryDeviceRelations },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryCapabilities },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryResources },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryResourceRequirements },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryDeviceText },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoReadConfig },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoWriteConfig },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryId },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryDeviceState },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryBusInformation },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoDeviceUsageNotification },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoSurpriseRemoval },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciPdoQueryLegacyBusInformation },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported }
};

static PCI_MJ_DISPATCH_TABLE PciPdoDispatchTable = {
    IRP_MN_DEVICE_ENUMERATED,
    PciPdoDispatchPnpTable,
    IRP_MN_QUERY_POWER,
    PciPdoDispatchPowerTable,
    IRP_COMPLETE,
    (PCI_DISPATCH_FUNCTION)PciIrpNotSupported,
    IRP_COMPLETE,
    (PCI_DISPATCH_FUNCTION)PciIrpInvalidDeviceRequest
};

NTSTATUS PciPdoCreate(IN PPCI_FDO_EXTENSION DeviceExtension,
		      IN PCI_SLOT_NUMBER Slot, OUT PDEVICE_OBJECT *PdoDeviceObject)
{
    PAGED_CODE();
    NTSTATUS Status;
    PDEVICE_OBJECT DeviceObject;
    PPCI_PDO_EXTENSION PdoExtension;
    ULONG SequenceNumber;

    /* Pick an atomically unique sequence number for this device */
    SequenceNumber = InterlockedIncrement(&PciPdoSequenceNumber);

    /* Create the standard PCI device name for a PDO */
    WCHAR DeviceName[32];
    _snwprintf(DeviceName, sizeof(DeviceName), L"\\Device\\NTPNP_PCI%04d", SequenceNumber);
    UNICODE_STRING DeviceString;
    RtlInitUnicodeString(&DeviceString, DeviceName);

    /* Create the actual device now */
    assert(DeviceExtension->FunctionalDeviceObject->DriverObject);
    Status = IoCreateDevice(DeviceExtension->FunctionalDeviceObject->DriverObject,
			    sizeof(PCI_PDO_EXTENSION), &DeviceString,
			    FILE_DEVICE_BUS_EXTENDER, 0, 0, &DeviceObject);
    ASSERT(NT_SUCCESS(Status));

    /* Get the extension for it */
    PdoExtension = (PPCI_PDO_EXTENSION)DeviceObject->DeviceExtension;
    DPRINT1("PCI: New PDO (b=0x%x, d=0x%x, f=0x%x) @ %p, ext @ %p\n",
	    DeviceExtension->BaseBus, Slot.Bits.DeviceNumber,
	    Slot.Bits.FunctionNumber, DeviceObject, DeviceObject->DeviceExtension);

    /* Configure the extension */
    PdoExtension->ExtensionType = PciPdoExtensionType;
    PdoExtension->IrpDispatchTable = &PciPdoDispatchTable;
    PdoExtension->PhysicalDeviceObject = DeviceObject;
    PdoExtension->Slot = Slot;
    PdoExtension->PowerState.CurrentSystemState = PowerSystemWorking;
    PdoExtension->PowerState.CurrentDeviceState = PowerDeviceD0;
    PdoExtension->ParentFdoExtension = DeviceExtension;

    /* Initialize the state machine */
    PciInitializeState((PPCI_FDO_EXTENSION)PdoExtension);

    /* Add the PDO to the parent's list */
    PdoExtension->Next = NULL;
    PciInsertEntryAtTail((PSINGLE_LIST_ENTRY)&DeviceExtension->ChildPdoList,
			 (PPCI_FDO_EXTENSION)PdoExtension);

    /* And finally return it to the caller */
    *PdoDeviceObject = DeviceObject;
    return STATUS_SUCCESS;
}

VOID PciPdoDestroy(IN PDEVICE_OBJECT Pdo)
{
    PPCI_PDO_EXTENSION PdoExtension = (PPCI_PDO_EXTENSION)Pdo->DeviceExtension;
    ASSERT_PDO(PdoExtension);
    PPCI_FDO_EXTENSION ParentFdo = PdoExtension->ParentFdoExtension;
    PciRemoveEntryFromList((PSINGLE_LIST_ENTRY)&ParentFdo->ChildPdoList,
                           (PSINGLE_LIST_ENTRY)PdoExtension);
    for (PPCI_PDO_EXTENSION *PrevBridge = &ParentFdo->ChildBridgePdoList;
         *PrevBridge; PrevBridge = &((*PrevBridge)->NextBridge)) {
        if (*PrevBridge == PdoExtension) {
            *PrevBridge = PdoExtension->NextBridge;
            PdoExtension->NextBridge = NULL;
            break;
        }
    }
    if (PdoExtension->Resources) {
        ExFreePool(PdoExtension->Resources);
    }
    IoDeleteDevice(Pdo);
}
