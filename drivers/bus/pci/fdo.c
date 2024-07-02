/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/fdo.c
 * PURPOSE:         FDO Device Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* GLOBALS ********************************************************************/

SINGLE_LIST_ENTRY PciFdoExtensionListHead;
BOOLEAN PciBreakOnDefault;

/* FUNCTIONS ******************************************************************/

static NTSTATUS PciFdoStartDevice(IN PIRP Irp,
				  IN PIO_STACK_LOCATION IoStackLocation,
				  IN PPCI_FDO_EXTENSION DeviceExtension)
{
    NTSTATUS Status;
    PCM_RESOURCE_LIST Resources;

    /* The device stack must be starting the FDO in a success path */
    if (!NT_SUCCESS(Irp->IoStatus.Status))
	return STATUS_NOT_SUPPORTED;

    /* Attempt to switch the state machine to the started state */
    Status = PciBeginStateTransition(DeviceExtension, PciStarted);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Check for any boot-provided resources */
    Resources = IoStackLocation->Parameters.StartDevice.AllocatedResources;
    if (!Resources) {
	goto commit;
    }
    if (PCI_IS_ROOT_FDO(DeviceExtension)) {
	/* We should be getting exactly one resource which is the base physical
	 * address of the Enhanced Configuration Mechanism Address Space. */
	ASSERT(Resources->Count == 1);
    } else {
	/* Unhandled for now */
	ASSERT(Resources->Count == 1);
	UNIMPLEMENTED_DBGBREAK();
    }

commit:
    /* Commit the transition to the started state */
    PciCommitStateTransition(DeviceExtension, PciStarted);
    return STATUS_SUCCESS;
}

static NTSTATUS PciFdoQueryRemoveDevice(IN PIRP Irp,
					IN PIO_STACK_LOCATION IoStackLocation,
					IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED;
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoRemoveDevice(IN PIRP Irp,
				   IN PIO_STACK_LOCATION IoStackLocation,
				   IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoCancelRemoveDevice(IN PIRP Irp,
					 IN PIO_STACK_LOCATION IoStackLocation,
					 IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoStopDevice(IN PIRP Irp,
				 IN PIO_STACK_LOCATION IoStackLocation,
				 IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoQueryStopDevice(IN PIRP Irp,
				      IN PIO_STACK_LOCATION IoStackLocation,
				      IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoCancelStopDevice(IN PIRP Irp,
				       IN PIO_STACK_LOCATION IoStackLocation,
				       IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoQueryDeviceRelations(IN PIRP Irp,
					   IN PIO_STACK_LOCATION IoStackLocation,
					   IN PPCI_FDO_EXTENSION DeviceExtension)
{
    NTSTATUS Status;

    /* Are bus relations being queried? */
    if (IoStackLocation->Parameters.QueryDeviceRelations.Type != BusRelations) {
	/* The FDO is a bus, so only bus relations can be obtained */
	Status = STATUS_NOT_SUPPORTED;
    } else {
	/* Scan the PCI bus and build the device relations for the caller */
	Status = PciQueryDeviceRelations(DeviceExtension,
					 (PDEVICE_RELATIONS *)&Irp->IoStatus.Information);
    }

    /* Return the enumeration status back */
    return Status;
}

static NTSTATUS PciFdoQueryCapabilities(IN PIRP Irp,
					IN PIO_STACK_LOCATION IoStackLocation,
					IN PPCI_FDO_EXTENSION DeviceExtension)
{
    PDEVICE_CAPABILITIES Capabilities;
    ASSERT_FDO(DeviceExtension);

    UNREFERENCED_PARAMETER(Irp);

    /* Get the capabilities */
    Capabilities = IoStackLocation->Parameters.DeviceCapabilities.Capabilities;

    /* Inherit wake levels and power mappings from the higher-up capabilities */
    DeviceExtension->PowerState.SystemWakeLevel = Capabilities->SystemWake;
    DeviceExtension->PowerState.DeviceWakeLevel = Capabilities->DeviceWake;
    RtlCopyMemory(DeviceExtension->PowerState.SystemStateMapping,
		  Capabilities->DeviceState,
		  sizeof(DeviceExtension->PowerState.SystemStateMapping));

    /* Dump the capabilities and return success */
    PciDebugDumpQueryCapabilities(Capabilities);
    return STATUS_SUCCESS;
}

static NTSTATUS PciFdoDeviceUsageNotification(IN PIRP Irp,
					      IN PIO_STACK_LOCATION IoStackLocation,
					      IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoSurpriseRemoval(IN PIRP Irp,
				      IN PIO_STACK_LOCATION IoStackLocation,
				      IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PciFdoQueryLegacyBusInformation(IN PIRP Irp,
						IN PIO_STACK_LOCATION IoStackLocation,
						IN PPCI_FDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IoStackLocation);
    UNREFERENCED_PARAMETER(DeviceExtension);

    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_SUPPORTED;
}

static VOID PciGetHotPlugParameters(IN PPCI_FDO_EXTENSION FdoExtension)
{
    ACPI_EVAL_INPUT_BUFFER InputBuffer;
    PACPI_EVAL_OUTPUT_BUFFER OutputBuffer;
    ULONG Length;
    NTSTATUS Status;

    /* We should receive 4 parameters, per the HPP specification */
    Length = sizeof(ACPI_EVAL_OUTPUT_BUFFER) + 4 * sizeof(ACPI_METHOD_ARGUMENT);

    /* Allocate the buffer to hold the parameters */
    OutputBuffer = ExAllocatePoolWithTag(Length, PCI_POOL_TAG);
    if (!OutputBuffer)
	return;

    /* Initialize the output and input buffers. The method is _HPP */
    RtlZeroMemory((PVOID)OutputBuffer, Length);
    *(PULONG)InputBuffer.MethodName = 'PPH_';
    InputBuffer.Signature = ACPI_EVAL_INPUT_BUFFER_SIGNATURE;

    /* Send the IOCTL to the ACPI driver */
    Status = PciSendIoctl(FdoExtension->PhysicalDeviceObject, IOCTL_ACPI_EVAL_METHOD,
			  &InputBuffer, sizeof(InputBuffer), (PVOID)OutputBuffer, Length);
    if (!NT_SUCCESS(Status)) {
	/* The method failed, check if we can salvage data from parent */
	if (!PCI_IS_ROOT_FDO(FdoExtension)) {
	    /* Copy the root bus' hot plug parameters */
	    FdoExtension->HotPlugParameters =
		FdoExtension->ParentFdoExtension->HotPlugParameters;
	}

	/* Nothing more to do on this path */
	goto out;
    }

    /* ACPI sent back some data. 4 parameters are expected in the output */
    if (OutputBuffer->Count != 4)
	goto out;

    /* HotPlug PCI Support not yet implemented */
    UNIMPLEMENTED_DBGBREAK();

    /* Free the buffer and return */
out:
    ExFreePoolWithTag((PVOID)OutputBuffer, 0);
}

static PCI_MN_DISPATCH_TABLE PciFdoDispatchPowerTable[] = {
    { IRP_DISPATCH, (PCI_DISPATCH_FUNCTION)PciFdoWaitWake },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoSetPowerState },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryPower },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported }
};

static PCI_MN_DISPATCH_TABLE PciFdoDispatchPnpTable[] = {
    { IRP_UPWARD, (PCI_DISPATCH_FUNCTION)PciFdoStartDevice },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryRemoveDevice },
    { IRP_DISPATCH, (PCI_DISPATCH_FUNCTION)PciFdoRemoveDevice },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoCancelRemoveDevice },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoStopDevice },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryStopDevice },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoCancelStopDevice },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryDeviceRelations },
    { IRP_DISPATCH, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_UPWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryCapabilities },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_UPWARD, (PCI_DISPATCH_FUNCTION)PciFdoDeviceUsageNotification },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoSurpriseRemoval },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryLegacyBusInformation },
    { IRP_DOWNWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported }
};

static PCI_MJ_DISPATCH_TABLE PciFdoDispatchTable = {
    IRP_MN_DEVICE_ENUMERATED,
    PciFdoDispatchPnpTable,
    IRP_MN_QUERY_POWER,
    PciFdoDispatchPowerTable,
    IRP_DOWNWARD,
    (PCI_DISPATCH_FUNCTION)PciIrpNotSupported,
    IRP_DOWNWARD,
    (PCI_DISPATCH_FUNCTION)PciIrpNotSupported
};

static VOID PciInitializeFdoExtensionCommonFields(PPCI_FDO_EXTENSION FdoExtension,
						  IN PDEVICE_OBJECT DeviceObject,
						  IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    /* Initialize the extension */
    RtlZeroMemory(FdoExtension, sizeof(PCI_FDO_EXTENSION));

    /* Setup the common fields */
    FdoExtension->PhysicalDeviceObject = PhysicalDeviceObject;
    FdoExtension->FunctionalDeviceObject = DeviceObject;
    FdoExtension->ExtensionType = PciFdoExtensionType;
    FdoExtension->PowerState.CurrentSystemState = PowerSystemWorking;
    FdoExtension->PowerState.CurrentDeviceState = PowerDeviceD0;
    FdoExtension->IrpDispatchTable = &PciFdoDispatchTable;

    /* Initialize the default state */
    PciInitializeState(FdoExtension);
}

NTAPI NTSTATUS PciAddDevice(IN PDRIVER_OBJECT DriverObject,
			    IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDEVICE_OBJECT AttachedTo;
    PPCI_FDO_EXTENSION FdoExtension;
    PPCI_FDO_EXTENSION ParentExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    PDEVICE_OBJECT DeviceObject;
    UCHAR Buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)Buffer;
    NTSTATUS Status;
    UNICODE_STRING ValueName;
    ULONG ResultLength;
    DPRINT1("PCI - AddDevice (a new bus). PDO: %p\n", PhysicalDeviceObject);

    /* Zero out variables so failure path knows what to do */
    AttachedTo = NULL;
    FdoExtension = NULL;
    PdoExtension = NULL;
    DeviceObject = NULL;

    /* Check if there's already a device extension for this bus */
    ParentExtension = PciFindParentPciFdoExtension(PhysicalDeviceObject);
    if (ParentExtension) {
	/* Make sure we find a real PDO */
	PdoExtension = PhysicalDeviceObject->DeviceExtension;
	ASSERT_PDO(PdoExtension);

	/* Make sure it's a PCI-to-PCI bridge */
	if ((PdoExtension->BaseClass != PCI_CLASS_BRIDGE_DEV) ||
	    (PdoExtension->SubClass != PCI_SUBCLASS_BR_PCI_TO_PCI)) {
	    /* This should never happen */
	    DPRINT1("PCI - PciAddDevice for Non-Root/Non-PCI-PCI bridge,\n"
		    "      Class %02x, SubClass %02x, will not add.\n",
		    PdoExtension->BaseClass, PdoExtension->SubClass);
	    ASSERT((PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
		   (PdoExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI));

	    /* Enter the failure path */
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    goto err;
	}

	/* Subordinate bus on the bridge */
	DPRINT1("PCI - AddDevice (new bus is child of bus 0x%x).\n",
		ParentExtension->BaseBus);

	/* Make sure PCI bus numbers are configured */
	if (!PciAreBusNumbersConfigured(PdoExtension)) {
	    /* This is a critical failure */
	    DPRINT1("PCI - Bus numbers not configured for bridge (0x%x.0x%x.0x%x)\n",
		    ParentExtension->BaseBus, PdoExtension->Slot.Bits.DeviceNumber,
		    PdoExtension->Slot.Bits.FunctionNumber);

	    /* Enter the failure path */
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    goto err;
	}
    }

    /* Create the FDO for the bus */
    Status = IoCreateDevice(DriverObject, sizeof(PCI_FDO_EXTENSION), NULL,
			    FILE_DEVICE_BUS_EXTENDER, 0, 0, &DeviceObject);
    if (!NT_SUCCESS(Status))
	goto err;

    /* Initialize the extension for the FDO */
    FdoExtension = DeviceObject->DeviceExtension;
    PciInitializeFdoExtensionCommonFields(DeviceObject->DeviceExtension, DeviceObject,
					  PhysicalDeviceObject);

    /* Attach to the root PDO */
    Status = STATUS_NO_SUCH_DEVICE;
    AttachedTo = IoAttachDeviceToDeviceStack(DeviceObject, PhysicalDeviceObject);
    ASSERT(AttachedTo != NULL);
    if (!AttachedTo)
	goto err;
    FdoExtension->AttachedDeviceObject = AttachedTo;

    /* Check if this is a child bus, or the root */
    if (ParentExtension) {
	/* The child inherits root data */
	FdoExtension->BaseBus = PdoExtension->Dependent.Type1.SecondaryBus;
	FdoExtension->BusRootFdoExtension = ParentExtension->BusRootFdoExtension;
	PdoExtension->BridgeFdoExtension = FdoExtension;
	FdoExtension->ParentFdoExtension = ParentExtension;
    } else {
	/* This is the root bus */
	FdoExtension->BusRootFdoExtension = FdoExtension;
    }

    /* Insert the FDO extension into the list */
    PciInsertEntryAtTail(&PciFdoExtensionListHead, FdoExtension);

    /* Open the device registry key so that we can query the errata flags */
    HANDLE KeyHandle = NULL;
    Status = IoOpenDeviceRegistryKey(DeviceObject, PLUGPLAY_REGKEY_DEVICE,
				     KEY_ALL_ACCESS, &KeyHandle);
    if (!NT_SUCCESS(Status)) {
	goto hotplug;
    }

    /* Open the value that contains errata flags for this bus instance */
    RtlInitUnicodeString(&ValueName, L"HackFlags");
    Status = NtQueryValueKey(KeyHandle, &ValueName, KeyValuePartialInformation,
			     ValueInfo, sizeof(Buffer), &ResultLength);
    NtClose(KeyHandle);
    if (NT_SUCCESS(Status)) {
	/* Make sure the data is of expected type and size */
	if ((ValueInfo->Type == REG_DWORD) &&
	    (ValueInfo->DataLength == sizeof(ULONG))) {
	    /* Read the flags for this bus */
	    FdoExtension->BusHackFlags = *(PULONG)&ValueInfo->Data;
	}
    }

    /* Query ACPI for PCI HotPlug Support */
hotplug:
    PciGetHotPlugParameters(FdoExtension);

    /* The Bus FDO is now initialized */
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;

    /* This is the failure path */
err:
    ASSERT(!NT_SUCCESS(Status));

    /* Check if the FDO extension exists */
    if (FdoExtension)
	DPRINT1("Should destroy secondaries\n");

    /* Delete device objects */
    if (AttachedTo)
	IoDetachDevice(AttachedTo);
    if (DeviceObject)
	IoDeleteDevice(DeviceObject);
    return Status;
}
