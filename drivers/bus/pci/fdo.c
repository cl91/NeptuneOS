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

/* FUNCTIONS ******************************************************************/

static NTSTATUS PciFdoStartDevice(IN PIRP Irp,
				  IN PIO_STACK_LOCATION IoStackLocation,
				  IN PPCI_FDO_EXTENSION DeviceExtension)
{
    /* The device stack must be starting the FDO in a success path */
    if (!NT_SUCCESS(Irp->IoStatus.Status))
	return STATUS_NOT_SUPPORTED;

    /* Attempt to switch the state machine to the started state */
    NTSTATUS Status = PciBeginStateTransition(DeviceExtension, PciStarted);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Check for any boot-provided resources */
    PCM_RESOURCE_LIST Res = IoStackLocation->Parameters.StartDevice.AllocatedResources;
    if (!Res) {
	goto commit;
    }
    if (PCI_IS_ROOT_FDO(DeviceExtension)) {
	ASSERT(Res->Count == 1);
	for (ULONG i = 0; i < Res->List[0].PartialResourceList.Count; i++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Desc =
		&Res->List[0].PartialResourceList.PartialDescriptors[i];
	    switch (Desc->Type) {
	    case CmResourceTypePort:
		/* We will not use the legacy 0xCF8 port to access the PCI
		 * configuration space so we simply ignore the port resource. */
		DPRINT("(Ignored) PCI Config Port: 0x%x (%u)\n",
		       Desc->Port.Start.LowPart,
		       Desc->Port.Length);
		break;
	    case CmResourceTypeMemory:
		DPRINT("PCI Config Memory: 0x%llx (0x%x)\n",
		       Desc->Memory.Start.QuadPart,
		       Desc->Memory.Length);
		DeviceExtension->ConfigBase = Desc->Memory.Start;
		break;
	    case CmResourceTypeDevicePrivate:
		DPRINT("PCI Root Bus Number: 0x%x\n",
		       Desc->DevicePrivate.Data[0]);
		DeviceExtension->BaseBus = Desc->DevicePrivate.Data[0];
		break;
	    }
	}
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

static VOID PcipGetEnhancedCapabilities(IN PPCI_PDO_EXTENSION PdoExtension,
					IN PPCI_COMMON_HEADER PciData)
{
    PAGED_CODE();

    /* Assume no known wake level */
    PdoExtension->PowerState.DeviceWakeLevel = PowerDeviceUnspecified;

    /* Make sure the device has capabilities */
    if (!(PciData->Status & PCI_STATUS_CAPABILITIES_LIST)) {
	/* If it doesn't, there will be no power management */
	PdoExtension->CapabilitiesPtr = 0;
	PdoExtension->NoPmCaps = TRUE;
	goto done;
    }

    /* There are capabilities. Need to figure out where to get the offset */
    ULONG HeaderType = PCI_CONFIGURATION_TYPE(PciData);
    ULONG CapPtr;
    if (HeaderType == PCI_CARDBUS_BRIDGE_TYPE) {
	/* Use the bridge's header */
	CapPtr = PciData->Type2.CapabilitiesPtr;
    } else {
	/* Use the device header */
	ASSERT(HeaderType <= PCI_CARDBUS_BRIDGE_TYPE);
	CapPtr = PciData->Type0.CapabilitiesPtr;
    }

    /* Skip garbage capabilities pointer */
    if (((CapPtr & 0x3) != 0) || (CapPtr < PCI_COMMON_HDR_LENGTH)) {
	/* Report no extended capabilities */
	PdoExtension->CapabilitiesPtr = 0;
	PdoExtension->NoPmCaps = TRUE;
	goto done;
    }

    DPRINT1("Device has capabilities at: %x\n", CapPtr);
    PdoExtension->CapabilitiesPtr = CapPtr;

    /* Check for PCI-to-PCI Bridges and AGP bridges */
    if ((PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
	((PdoExtension->SubClass == PCI_SUBCLASS_BR_HOST) ||
	 (PdoExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI))) {
	/* Query either the raw AGP capabilitity, or the Target AGP one */
	ULONG TargetAgpCapabilityId = (PdoExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI) ?
	    PCI_CAPABILITY_ID_AGP_TARGET : PCI_CAPABILITY_ID_AGP;
	PCI_CAPABILITIES_HEADER AgpCapability;
	if (PciReadDeviceCapability(PdoExtension, PdoExtension->CapabilitiesPtr,
				    TargetAgpCapabilityId, &AgpCapability,
				    sizeof(PCI_CAPABILITIES_HEADER))) {
	    /* AGP target ID was found, store it */
	    DPRINT1("AGP ID: %x\n", TargetAgpCapabilityId);
	    PdoExtension->TargetAgpCapabilityId = TargetAgpCapabilityId;
	}
    }

    /* Check if the device is a PCI express device. */
    PCI_CAPABILITIES_HEADER CapHeader = {};
    UCHAR Offset = PciReadDeviceCapability(PdoExtension, PdoExtension->CapabilitiesPtr,
					   PCI_CAPABILITY_ID_PCI_EXPRESS, &CapHeader,
					   sizeof(PCI_CAPABILITIES_HEADER));
    if (Offset) {
	assert(CapHeader.CapabilityID == PCI_CAPABILITY_ID_PCI_EXPRESS);
	PdoExtension->InterfaceType = PciExpress;
    } else if ((Offset = PciReadDeviceCapability(PdoExtension, PdoExtension->CapabilitiesPtr,
						 PCI_CAPABILITY_ID_PCIX, &CapHeader,
						 sizeof(PCI_CAPABILITIES_HEADER)))) {
	assert(CapHeader.CapabilityID == PCI_CAPABILITY_ID_PCIX);
	/* We won't bother detecting whether it's PCI-X Mode1 or Mode2.
	 * PCI-X is incredibly rare as of 2025, and Mode2 is even rarer. */
	PdoExtension->InterfaceType = PciXMode1;
    } else {
	PdoExtension->InterfaceType = PciConventional;
    }

    /* Check for devices that are known not to have proper power management */
    if (!PdoExtension->NoPmCaps) {
	/* Query if this device supports power management */
	PCI_PM_CAPABILITY PowerCapabilities;
	if (!PciReadDeviceCapability(PdoExtension, PdoExtension->CapabilitiesPtr,
				     PCI_CAPABILITY_ID_POWER_MANAGEMENT,
				     &PowerCapabilities.Header,
				     sizeof(PCI_PM_CAPABILITY))) {
	    /* No power management, so act as if it had the hackflag set */
	    DPRINT1("No PM caps, disabling PM\n");
	    PdoExtension->NoPmCaps = TRUE;
	} else {
	    /* Otherwise, pick the highest wake level that is supported */
	    DEVICE_POWER_STATE WakeLevel = PowerDeviceUnspecified;
	    if (PowerCapabilities.PMC.Capabilities.Support.PMED0)
		WakeLevel = PowerDeviceD0;
	    if (PowerCapabilities.PMC.Capabilities.Support.PMED1)
		WakeLevel = PowerDeviceD1;
	    if (PowerCapabilities.PMC.Capabilities.Support.PMED2)
		WakeLevel = PowerDeviceD2;
	    if (PowerCapabilities.PMC.Capabilities.Support.PMED3Hot)
		WakeLevel = PowerDeviceD3;
	    if (PowerCapabilities.PMC.Capabilities.Support.PMED3Cold)
		WakeLevel = PowerDeviceD3;
	    PdoExtension->PowerState.DeviceWakeLevel = WakeLevel;

	    /* Convert the PCI power state to the NT power state */
	    PdoExtension->PowerState.CurrentDeviceState =
		PowerCapabilities.PMCSR.ControlStatus.PowerState + 1;

	    /* Save all the power capabilities */
	    PdoExtension->PowerCapabilities = PowerCapabilities.PMC.Capabilities;
	    DPRINT1("PM Caps Found! Wake Level: %d Power State: %d\n", WakeLevel,
		    PdoExtension->PowerState.CurrentDeviceState);
	}
    }

    /* Check if the device supports MSI-X or MSI. Prefer MSI-X if it is supported. */
    PCI_MSI_CAPABILITY MsiCap = {};
    PCI_MSIX_CAPABILITY MsiXCap = {};
    if ((PdoExtension->MsiInfo.CapabilityOffset =
	 PciReadDeviceCapability(PdoExtension, PdoExtension->CapabilitiesPtr,
				 PCI_CAPABILITY_ID_MSIX, &MsiXCap.Header,
				 sizeof(PCI_MSIX_CAPABILITY)))) {
	assert(MsiXCap.Header.CapabilityID == PCI_CAPABILITY_ID_MSIX);
	PdoExtension->MsiInfo.ExtendedMessage = TRUE;
	PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl = MsiXCap.MessageControl;
	PdoExtension->MsiInfo.ExtendedMessageInfo.MessageTable = MsiXCap.MessageTable;
	PdoExtension->MsiInfo.ExtendedMessageInfo.PendingBitArray = MsiXCap.PendingBitArray;
    } else if ((PdoExtension->MsiInfo.CapabilityOffset =
		PciReadDeviceCapability(PdoExtension, PdoExtension->CapabilitiesPtr,
					PCI_CAPABILITY_ID_MSI, &MsiCap.Header,
					FIELD_OFFSET(PCI_MSI_CAPABILITY, Data32.Unused)))) {
	assert(MsiCap.Header.CapabilityID == PCI_CAPABILITY_ID_MSI);
	PdoExtension->MsiInfo.ExtendedMessage = FALSE;
	PdoExtension->MsiInfo.MessageInfo.MessageControl = MsiCap.MessageControl;
    } else {
	DPRINT1("Device does not support MSI or MSI-X. Interrupt will be disabled.\n");
    }

done:
    /* At the very end of all this, does this device not have power management? */
    if (PdoExtension->NoPmCaps) {
	/* Then guess the current state based on whether the decodes are on */
	PdoExtension->PowerState.CurrentDeviceState = PciData->Command &
	    (PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE | PCI_ENABLE_BUS_MASTER) ?
	    PowerDeviceD0 : PowerDeviceD3;
	DPRINT1("PM is off, so assumed device is: %d based on enables\n",
		PdoExtension->PowerState.CurrentDeviceState);
    }
}

static VOID PciDumpCapabilities(IN PPCI_PDO_EXTENSION NewExtension)
{
    ASSERT_PDO(NewExtension);
    /* Scan all capabilities and dump them */
    USHORT CapOffset = NewExtension->CapabilitiesPtr;
    while (CapOffset) {
	/* Read this header */
	union {
	    PCI_PM_CAPABILITY PmCap;
	    PCI_AGP_CAPABILITY AgpCap;
	    PCI_MSI_CAPABILITY MsiCap;
	    PCI_EXPRESS_CAPABILITY PcieCap;
	    PCI_MSIX_CAPABILITY MsiXCap;
	    PCI_CAPABILITIES_HEADER Header;
	} Cap;
	USHORT TempOffset = PciReadDeviceCapability(NewExtension, CapOffset, 0,
						    &Cap.Header,
						    sizeof(PCI_CAPABILITIES_HEADER));
	if (TempOffset != CapOffset) {
	    /* This is a strange issue that shouldn't happen normally */
	    DPRINT1("PCI - Failed to read PCI capability at offset 0x%02x\n",
		    CapOffset);
	    ASSERT(TempOffset == CapOffset);
	}

	/* Check for capabilities that this driver cares about */
	ULONG Size = 0;
	PCHAR Name = NULL;
	switch (Cap.Header.CapabilityID) {
	    /* Power management capability is heavily used by the bus */
	case PCI_CAPABILITY_ID_POWER_MANAGEMENT:

	    /* Dump the capability */
	    Name = "POWER";
	    Size = sizeof(PCI_PM_CAPABILITY);
	    break;

	    /* AGP capability is required for AGP bus functionality */
	case PCI_CAPABILITY_ID_AGP:

	    /* Dump the capability */
	    Name = "AGP";
	    Size = sizeof(PCI_AGP_CAPABILITY);
	    break;

	case PCI_CAPABILITY_ID_MSI:
	    Name = "MSI";
	    Size = FIELD_OFFSET(PCI_MSI_CAPABILITY, Data32.Unused);
	    break;

	case PCI_CAPABILITY_ID_PCI_EXPRESS:
	    Name = "PCI-EXPRESS";
	    Size = FIELD_OFFSET(PCI_EXPRESS_CAPABILITY, SlotCapabilities);
	    break;

	case PCI_CAPABILITY_ID_MSIX:
	    Name = "MSI-X";
	    Size = sizeof(PCI_MSIX_CAPABILITY);
	    break;

	    /* This driver doesn't really use anything other than those above */
	default:
	    /* Windows prints this, we could do a translation later */
	    Name = "UNKNOWN CAPABILITY";
	    break;
	}

	/* Check if this is a capability that should be dumped */
	if (Size) {
	    /* Read the whole capability data */
	    TempOffset = PciReadDeviceCapability(NewExtension, CapOffset,
						 Cap.Header.CapabilityID,
						 &Cap.Header, Size);

	    if (TempOffset != CapOffset) {
		/* Again, a strange issue that shouldn't be seen */
		DPRINT1("Failed to read capability data (cap offset 0x%x, got 0x%x)\n",
			CapOffset, TempOffset);
		ASSERT(FALSE);
	    }
	}

	/* Dump this capability */
	DPRINT1("CAP @%02x ID %02x (%s)\n", CapOffset, Cap.Header.CapabilityID,
		Name);
	for (ULONG k = 0; k < Size; k += 2)
	    DPRINT1("  %04x\n", *(PUSHORT)((ULONG_PTR)&Cap.Header + k));
	DPRINT1("\n");

	/* Check the next capability */
	CapOffset = Cap.Header.Next;
    }
}

static BOOLEAN PcipSkipThisFunction(IN PPCI_COMMON_HEADER PciData,
				    IN PCI_SLOT_NUMBER Slot,
				    IN UCHAR OperationType)
{
    if ((PciData->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
	!(PciData->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI ||
	  PciData->SubClass == PCI_SUBCLASS_BR_CARDBUS) &&
	(OperationType == PCI_SKIP_RESOURCE_ENUMERATION)) {
	/* If we are enumerating the IO resources of the PCI function, skip
	 * bridge class functions unless it is a PCI-to-PCI or Cardbus bridge.
	 * The reason is that other types of bridges (including host bridges)
	 * do not implement the proper BAR sizing semantics. */
	goto skip;
    } else if (PciData->BaseClass == PCI_CLASS_NOT_DEFINED) {
	/* Undefined base class (usually a PCI BIOS/ROM bug) */
	DPRINT1("    Vendor %04x, Device %04x has class code of PCI_CLASS_NOT_DEFINED\n",
		PciData->VendorID, PciData->DeviceID);

	/*
	 * The Alder has an Intel Extended Express System Support Controller
	 * which presents apparently spurious BARs. When the PCI resource
	 * code tries to reassign these BARs, the second IO-APIC gets
	 * disabled (with disastrous consequences). The first BAR is the
	 * actual IO-APIC, the remaining five bars seem to be spurious
	 * resources, so ignore this device completely.
	 */
	if ((PciData->VendorID == 0x8086) && (PciData->DeviceID == 8))
	    goto skip;
    }

    /* Other normal PCI cards and bridges are enumerated */
    if (PCI_CONFIGURATION_TYPE(PciData) <= PCI_CARDBUS_BRIDGE_TYPE)
	return FALSE;

skip:
    /* Hit one of the known bugs, so skip this function */
    DPRINT1("   Device skipped (not enumerated).\n");
    return TRUE;
}

static NTSTATUS PciGetFunctionLimits(IN PPCI_PDO_EXTENSION PdoExtension,
				     IN PPCI_COMMON_HEADER InitialConfig)
{
    PAGED_CODE();

    if (PcipSkipThisFunction(InitialConfig, PdoExtension->Slot,
			     PCI_SKIP_RESOURCE_ENUMERATION)) {
	/* Do not process its resources */
	return STATUS_SUCCESS;
    }

    /* Allocate the structure that will hold the discovered resources and limits */
    PdoExtension->Resources = ExAllocatePoolWithTag(NonPagedPool,
						    sizeof(PCI_FUNCTION_RESOURCES),
						    'BicP');
    if (!PdoExtension->Resources)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Before we disable decodes, save the initial command so we can later restore it. */
    USHORT InitialCommand = InitialConfig->Command;

    /* Disable all decodes before we probe the BAR limits */
    PciSetCommand(PdoExtension,
		  PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE | PCI_ENABLE_BUS_MASTER,
		  FALSE);

    /* Locate the correct resource configurator for this type of device */
    PPCI_CONFIGURATOR Configurator = &PciConfigurators[PdoExtension->HeaderType];

    /* Call the configurator to probe the BAR limits */
    PCI_COMMON_HEADER LimitCfg;
    RtlCopyMemory(&LimitCfg, InitialConfig, sizeof(PCI_COMMON_HEADER));
    Configurator->MassageHeaderForLimitsDetermination(&LimitCfg);
    Configurator->WriteResources(PdoExtension, &LimitCfg);
    Configurator->ReadResources(PdoExtension, &LimitCfg);
    Configurator->WriteResources(PdoExtension, InitialConfig);
    Configurator->SaveLimits(PdoExtension, &LimitCfg);
    Configurator->SaveCurrentSettings(PdoExtension, InitialConfig);
    PciDebugDumpResources(PdoExtension);

    /* Loop all the limit descriptors and check if we have at least one resource */
    BOOLEAN HasResource = FALSE;
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	if (PdoExtension->Resources->Limit[i].Type != CmResourceTypeNull) {
	    HasResource = TRUE;
	    break;
	}
    }
    if (!HasResource) {
	/* No resources will be assigned for the device */
	ExFreePoolWithTag(PdoExtension->Resources, 'BicP');
	PdoExtension->Resources = NULL;
    }

    /* Restore the initial command of the device */
    PciWriteDeviceConfig(PdoExtension, &InitialCommand,
			 FIELD_OFFSET(PCI_COMMON_HEADER, Command),
			 sizeof(InitialCommand));

    /* Return success here, even if the device has no assigned resources */
    return STATUS_SUCCESS;
}

static PPCI_PDO_EXTENSION PciFindPdoByFunction(IN PPCI_FDO_EXTENSION DeviceExtension,
					       IN ULONG FunctionNumber,
					       IN PPCI_COMMON_HEADER PciData)
{
    /* Loop every child PDO */
    for (PPCI_PDO_EXTENSION PdoExtension = DeviceExtension->ChildPdoList;
	 PdoExtension; PdoExtension = PdoExtension->Next) {
	/* Find only enumerated PDOs */
	if (PdoExtension->NotPresent) {
	    continue;
	}

	/* Check if the function number and header data matches. If so, this
	 * is considered to be the requested PDO. */
	if ((FunctionNumber == PdoExtension->Slot.AsULONG) &&
	    (PdoExtension->VendorId == PciData->VendorID) &&
	    (PdoExtension->DeviceId == PciData->DeviceID) &&
	    (PdoExtension->RevisionId == PciData->RevisionID)) {
	    return PdoExtension;
	}
    }

    return NULL;
}

static NTSTATUS PciScanBus(IN PPCI_FDO_EXTENSION DeviceExtension)
{
    ULONG MaxDevice = PCI_MAX_DEVICES;
    UCHAR Buffer[PCI_COMMON_HDR_LENGTH] = {};
    PPCI_COMMON_HEADER PciData = (PVOID)Buffer;
    DPRINT1("PCI Scan Bus: FDO Extension @ %p, Base Bus = 0x%x\n", DeviceExtension,
	    DeviceExtension->BaseBus);

    /* Loop every device on the bus */
    PCI_SLOT_NUMBER PciSlot = {};
    for (ULONG i = 0; i < MaxDevice; i++) {
	/* Loop every function of each device */
	PciSlot.AsULONG = 0;
	PciSlot.Bits.DeviceNumber = i;
	for (ULONG j = 0; j < PCI_MAX_FUNCTION; j++) {
	    /* Build the final slot structure */
	    PciSlot.Bits.FunctionNumber = j;

	    /* Read the vendor for this slot */
	    RtlZeroMemory(PciData, sizeof(Buffer));
	    PciReadSlotConfig(DeviceExtension, PciSlot, PciData, 0, sizeof(USHORT));

	    /* Skip invalid device */
	    if (PciData->VendorID == PCI_INVALID_VENDORID)
		continue;

	    /* Now read the whole header */
	    PciReadSlotConfig(DeviceExtension, PciSlot, &PciData->DeviceID,
			      sizeof(USHORT), PCI_COMMON_HDR_LENGTH - sizeof(USHORT));

	    /* Dump device that was found */
	    DPRINT1("Scan Found Device 0x%x (b=0x%x, d=0x%x, f=0x%x)\n",
		    PciSlot.AsULONG, DeviceExtension->BaseBus, i, j);

	    /* Dump the device's header */
	    PciDebugDumpCommonConfig(PciData);

	    /* Find description for this device for the debugger's sake */
	    PWCHAR DescriptionText = PciGetDeviceDescriptionMessage(PciData->BaseClass,
								    PciData->SubClass);
	    DPRINT1("Device Description \"%ws\".\n",
		    DescriptionText ? DescriptionText : L"(NULL)");
	    if (DescriptionText)
		ExFreePoolWithTag(DescriptionText, 0);

	    /* Check if the device should be skipped for whatever reason */
	    if (PcipSkipThisFunction(PciData, PciSlot, PCI_SKIP_DEVICE_ENUMERATION)) {
		/* Skip this device */
		continue;
	    }

	    /* Check if a PDO has already been created for this device */
	    if (PciFindPdoByFunction(DeviceExtension, PciSlot.AsULONG, PciData)) {
		/* Rescan scenarios are not yet implemented */
		UNIMPLEMENTED_DBGBREAK();
	    }

	    /* Create the PDO for this device */
	    PDEVICE_OBJECT DeviceObject = NULL;
	    NTSTATUS Status = PciPdoCreate(DeviceExtension, PciSlot, &DeviceObject);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	    ASSERT(DeviceObject);
	    PPCI_PDO_EXTENSION NewExtension = DeviceObject->DeviceExtension;

	    /* Clone all the information from the header */
	    NewExtension->VendorId = PciData->VendorID;
	    NewExtension->DeviceId = PciData->DeviceID;
	    NewExtension->RevisionId = PciData->RevisionID;
	    NewExtension->ProgIf = PciData->ProgIf;
	    NewExtension->SubClass = PciData->SubClass;
	    NewExtension->BaseClass = PciData->BaseClass;
	    NewExtension->HeaderType = PCI_CONFIGURATION_TYPE(PciData);

	    /* Check for modern bridge types, which are managed by this driver */
	    if ((NewExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
		((NewExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI) ||
		 (NewExtension->SubClass == PCI_SUBCLASS_BR_CARDBUS))) {
		/* Get to the end of the child bridge list of the parent FDO */
		PPCI_PDO_EXTENSION *BridgeExtension;
		for (BridgeExtension = &DeviceExtension->ChildBridgePdoList;
		     *BridgeExtension; BridgeExtension = &(*BridgeExtension)->NextBridge)
		    ;

		/* Append us to the end of the child bridge list */
		*BridgeExtension = NewExtension;
		ASSERT(NewExtension->NextBridge == NULL);
	    }

	    /* For PCI devices, save the sub-IDs that came directly from the PCI header */
	    if (NewExtension->HeaderType == PCI_DEVICE_TYPE) {
		NewExtension->SubsystemVendorId = PciData->Type0.SubVendorID;
		NewExtension->SubsystemId = PciData->Type0.SubSystemID;
	    } else if (NewExtension->HeaderType == PCI_BRIDGE_TYPE) {
		/* For bridges, save the bus numbers assigned by the firmware */
		NewExtension->BridgeInfo.PrimaryBus = PciData->Type1.PrimaryBus;
		NewExtension->BridgeInfo.SecondaryBus = PciData->Type1.SecondaryBus;
		NewExtension->BridgeInfo.SubordinateBus = PciData->Type1.SubordinateBus;
		/* And whether the bridge has the vga bit set. */
		NewExtension->BridgeInfo.VgaBitSet =
		    !!(PciData->Type1.BridgeControl & PCI_ENABLE_BRIDGE_VGA);
	    }

	    /* Get power, AGP, and other capability data */
	    PcipGetEnhancedCapabilities(NewExtension, PciData);
#if DBG
	    PciDumpCapabilities(NewExtension);
#endif

	    /* Now probe the limits of the BARs */
	    Status = PciGetFunctionLimits(NewExtension, PciData);

	    if (!NT_SUCCESS(Status)) {
		PciPdoDestroy(DeviceObject);
		return Status;
	    }

	    /* Power up the device */
	    PciSetPowerManagedDevicePowerState(NewExtension, PowerDeviceD0);

	    /* The PDO is now ready to go */
	    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PcipQueryDeviceRelations(IN PPCI_FDO_EXTENSION DeviceExtension,
					 IN OUT PDEVICE_RELATIONS *pDeviceRelations)
{
    PAGED_CODE();
    NTSTATUS Status;
    PPCI_PDO_EXTENSION PdoExtension;
    ULONG PdoCount = 0;
    PDEVICE_RELATIONS DeviceRelations, NewRelations;
    SIZE_T Size;
    PDEVICE_OBJECT DeviceObject, *ObjectArray;

    /* Make sure the FDO is started */
    ASSERT(DeviceExtension->DeviceState == PciStarted);

    /* Synchronize while we enumerate the bus */
    Status = PciBeginStateTransition(DeviceExtension, PciSynchronizedOperation);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Scan all children PDO */
    for (PdoExtension = DeviceExtension->ChildPdoList; PdoExtension;
	 PdoExtension = PdoExtension->Next) {
	/* Invalidate them */
	PdoExtension->NotPresent = TRUE;
    }

    /* Scan the PCI Bus */
    Status = PciScanBus(DeviceExtension);
    ASSERT(NT_SUCCESS(Status));

    /* Enumerate all child PDOs again */
    for (PdoExtension = DeviceExtension->ChildPdoList; PdoExtension;
	 PdoExtension = PdoExtension->Next) {
	/* Check for PDOs that are still invalidated */
	if (PdoExtension->NotPresent) {
	    /* This means this PDO existed before, but not anymore */
	    DPRINT1("PCI - Old device (pdox) %p not found on rescan.\n", PdoExtension);
	} else {
	    /* Increase count of detected PDOs */
	    PdoCount++;
	}
    }

    /* Read the current relations and add the newly discovered relations */
    DeviceRelations = *pDeviceRelations;
    Size = FIELD_OFFSET(DEVICE_RELATIONS, Objects) + PdoCount * sizeof(PDEVICE_OBJECT);
    if (DeviceRelations)
	Size += sizeof(PDEVICE_OBJECT) * DeviceRelations->Count;

    /* Allocate the device relations */
    NewRelations = (PDEVICE_RELATIONS)ExAllocatePoolWithTag(NonPagedPool, Size, 'BicP');
    if (!NewRelations) {
	/* Out of space, cancel the operation */
	PciCancelStateTransition(DeviceExtension, PciSynchronizedOperation);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Check if there were any older relations */
    NewRelations->Count = 0;
    if (DeviceRelations) {
	/* Copy the old relations into the new buffer, then free the old one */
	RtlCopyMemory(NewRelations, DeviceRelations,
		      FIELD_OFFSET(DEVICE_RELATIONS, Objects) +
		      DeviceRelations->Count * sizeof(PDEVICE_OBJECT));
	ExFreePoolWithTag(DeviceRelations, 0);
    }

    /* Print out that we're ready to dump relations */
    DPRINT1("PCI QueryDeviceRelations/BusRelations FDOx %p (bus 0x%02x)\n",
	    DeviceExtension, DeviceExtension->BaseBus);

    /* Loop the current PDO children and the device relation object array */
    PdoExtension = DeviceExtension->ChildPdoList;
    ObjectArray = &NewRelations->Objects[NewRelations->Count];
    while (PdoExtension) {
	/* Dump this relation */
	DPRINT1("  QDR PDO %p (x %p)%s\n", PdoExtension->PhysicalDeviceObject,
		PdoExtension,
		PdoExtension->NotPresent ? "<Omitted, device flaged not present>" : "");

	/* Is this PDO present? */
	if (!PdoExtension->NotPresent) {
	    /* Reference it and add it to the array */
	    DeviceObject = PdoExtension->PhysicalDeviceObject;
	    *ObjectArray++ = DeviceObject;
	}

	/* Go to the next PDO */
	PdoExtension = PdoExtension->Next;
    }

    /* Terminate dumping the relations */
    DPRINT1("  QDR Total PDO count = %u (%u already in list)\n",
	    NewRelations->Count + PdoCount, NewRelations->Count);

    /* Return the final count and the new buffer */
    NewRelations->Count += PdoCount;
    *pDeviceRelations = NewRelations;
    return STATUS_SUCCESS;
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
	Status = PcipQueryDeviceRelations(DeviceExtension,
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

static PCI_MN_DISPATCH_TABLE PciFdoDispatchPowerTable[] = {
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciFdoWaitWake },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoSetPowerState },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoIrpQueryPower },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported }
};

static PCI_MN_DISPATCH_TABLE PciFdoDispatchPnpTable[] = {
    { IRP_BOTTOM_UP, (PCI_DISPATCH_FUNCTION)PciFdoStartDevice },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryRemoveDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciFdoRemoveDevice },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoCancelRemoveDevice },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoStopDevice },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryStopDevice },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoCancelStopDevice },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciFdoQueryDeviceRelations },
    { IRP_COMPLETE, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_BOTTOM_UP, (PCI_DISPATCH_FUNCTION)PciFdoQueryCapabilities },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported },
    { IRP_BOTTOM_UP, (PCI_DISPATCH_FUNCTION)PciFdoDeviceUsageNotification },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoSurpriseRemoval },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciFdoQueryLegacyBusInformation },
    { IRP_FORWARD, (PCI_DISPATCH_FUNCTION)PciIrpNotSupported }
};

static PCI_MJ_DISPATCH_TABLE PciFdoDispatchTable = {
    .PnpIrpMaximumMinorFunction = IRP_MN_DEVICE_ENUMERATED,
    .PnpIrpDispatchTable = PciFdoDispatchPnpTable,
    .PowerIrpMaximumMinorFunction = IRP_MN_QUERY_POWER,
    .PowerIrpDispatchTable = PciFdoDispatchPowerTable,
    .SystemControlIrpDispatchStyle = IRP_FORWARD,
    .SystemControlIrpDispatchFunction = (PCI_DISPATCH_FUNCTION)PciIrpNotSupported,
    .OtherIrpDispatchStyle = IRP_FORWARD,
    .OtherIrpDispatchFunction = (PCI_DISPATCH_FUNCTION)PciIrpNotSupported
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

static BOOLEAN PcipAreBusNumbersConfigured(IN PPCI_PDO_EXTENSION PdoExtension)
{
    PAGED_CODE();
    UCHAR PrimaryBus, BaseBus, SecondaryBus, SubordinateBus;

    /* Get all relevant bus number details */
    PrimaryBus = PdoExtension->BridgeInfo.PrimaryBus;
    BaseBus = PdoExtension->ParentFdoExtension->BaseBus;
    SecondaryBus = PdoExtension->BridgeInfo.SecondaryBus;
    SubordinateBus = PdoExtension->BridgeInfo.SubordinateBus;

    /* The primary bus should be the base bus of the parent */
    if ((PrimaryBus != BaseBus) || (SecondaryBus <= PrimaryBus))
	return FALSE;

    /* The subordinate should be a higher bus number than the secondary */
    return SubordinateBus >= SecondaryBus;
}

static PPCI_FDO_EXTENSION PcipFindParentPciFdoExtension(IN PDEVICE_OBJECT DeviceObject)
{
    PPCI_FDO_EXTENSION DeviceExtension;
    PPCI_PDO_EXTENSION SearchExtension, FoundExtension;

    /* Assume we'll find nothing */
    SearchExtension = DeviceObject->DeviceExtension;
    FoundExtension = NULL;

    /* Now search for the extension */
    DeviceExtension = (PPCI_FDO_EXTENSION)PciFdoExtensionListHead.Next;
    while (DeviceExtension) {
	/* Scan all child PDOs, stop when no more PDOs, or found it */
	for (FoundExtension = DeviceExtension->ChildPdoList;
	     ((FoundExtension) && (FoundExtension != SearchExtension));
	     FoundExtension = FoundExtension->Next)
	    ;

	/* If we found it, break out */
	if (FoundExtension)
	    break;

	/* Move to the next device */
	DeviceExtension = (PPCI_FDO_EXTENSION)DeviceExtension->List.Next;
    }

    /* Return which extension was found, if any */
    return DeviceExtension;
}

NTAPI NTSTATUS PciAddDevice(IN PDRIVER_OBJECT DriverObject,
			    IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    PAGED_CODE();
    PDEVICE_OBJECT AttachedTo;
    PPCI_FDO_EXTENSION FdoExtension;
    PPCI_FDO_EXTENSION ParentExtension;
    PPCI_PDO_EXTENSION PdoExtension;
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS Status;
    DPRINT1("PCI - AddDevice (a new bus). PDO: %p\n", PhysicalDeviceObject);

    /* Zero out variables so failure path knows what to do */
    AttachedTo = NULL;
    FdoExtension = NULL;
    PdoExtension = NULL;
    DeviceObject = NULL;

    /* Check if we are adding a child bus. If ParentExtension is NULL, it means
     * we are being called for the root host bridge (in this case PDO is created
     * by the ACPI driver, or whoever enumerated us). */
    ParentExtension = PcipFindParentPciFdoExtension(PhysicalDeviceObject);
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
	    ASSERT(FALSE);

	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    goto err;
	}

	DPRINT1("PCI - AddDevice (new bus is child of bus 0x%x).\n",
		ParentExtension->BaseBus);

	/* Prior to enumerating the bridge PDO, the PciScanBus routine should have its
	 * PCI bus numbers configured. If this has not been done, we have a bug. */
	if (!PcipAreBusNumbersConfigured(PdoExtension)) {
	    /* This is a critical failure */
	    DPRINT1("PCI - Bus numbers not configured for bridge (0x%x.0x%x.0x%x)\n",
		    ParentExtension->BaseBus, PdoExtension->Slot.Bits.DeviceNumber,
		    PdoExtension->Slot.Bits.FunctionNumber);
	    ASSERT(FALSE);

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
	FdoExtension->BaseBus = PdoExtension->BridgeInfo.SecondaryBus;
	FdoExtension->BusRootFdoExtension = ParentExtension->BusRootFdoExtension;
	FdoExtension->ParentFdoExtension = ParentExtension;
    } else {
	/* This is the root bus */
	FdoExtension->BusRootFdoExtension = FdoExtension;
    }

    /* Insert the FDO extension into the list */
    PciInsertEntryAtTail(&PciFdoExtensionListHead, FdoExtension);

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
