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

PCI_CONFIGURATOR PciConfigurators[] = {
    {
	.MassageHeaderForLimitsDetermination = Device_MassageHeaderForLimitsDetermination,
	.ReadResources = Device_ReadResources,
	.WriteResources = Device_WriteResources,
	.SaveLimits = Device_SaveLimits,
	.SaveCurrentSettings = Device_SaveCurrentSettings,
	.ChangeResourceSettings =  Device_ChangeResourceSettings,
	.GetAdditionalResourceDescriptors = Device_GetAdditionalResourceDescriptors,
	.ResetDevice = Device_ResetDevice
    },
    {
	.MassageHeaderForLimitsDetermination = PCIBridge_MassageHeaderForLimitsDetermination,
	.ReadResources = PCIBridge_ReadResources,
	.WriteResources = PCIBridge_WriteResources,
	.SaveLimits = PCIBridge_SaveLimits,
	.SaveCurrentSettings = PCIBridge_SaveCurrentSettings,
	.ChangeResourceSettings =  PCIBridge_ChangeResourceSettings,
	.GetAdditionalResourceDescriptors = PCIBridge_GetAdditionalResourceDescriptors,
	.ResetDevice = PCIBridge_ResetDevice
    },
    {
	.MassageHeaderForLimitsDetermination = Cardbus_MassageHeaderForLimitsDetermination,
	.ReadResources = Cardbus_ReadResources,
	.WriteResources = Cardbus_WriteResources,
	.SaveLimits = Cardbus_SaveLimits,
	.SaveCurrentSettings = Cardbus_SaveCurrentSettings,
	.ChangeResourceSettings =  Cardbus_ChangeResourceSettings,
	.GetAdditionalResourceDescriptors = Cardbus_GetAdditionalResourceDescriptors,
	.ResetDevice = Cardbus_ResetDevice
    }
};

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
    /* For now we return success as our only supported power transition is
     * poweroff/reset. */
    return STATUS_SUCCESS;
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

static NTSTATUS PcipComputeNewCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
					      IN PCM_RESOURCE_LIST RawList,
					      IN PCM_RESOURCE_LIST TranslatedList)
{
    PAGED_CODE();

    /* Make sure we have either no resources, or at least one */
    ASSERT((RawList == NULL) || (RawList->Count == 1));

    /* Check if there's not actually any resources */
    if (!RawList || !RawList->Count || !TranslatedList || !TranslatedList->Count) {
	return STATUS_SUCCESS;
    }

    /* Print the new specified resource list */
    DPRINT("Raw list:\n");
    PciDebugPrintCmResList(RawList);
    DPRINT("Translated list:\n");
    PciDebugPrintCmResList(TranslatedList);

    /* Clear the temporary resource array */
    CM_PARTIAL_RESOURCE_DESCRIPTOR ResourceArray[PCI_MAX_RESOURCE_COUNT] = {};

    /* Copy the caller supplied resource list into ResourceArray, making sure
     * the order is the same as the current settings in PCI_FUNCTION_RESOURCES.
     * Also record how many interrupt resources we have got. If more than one,
     * interrupt resources must be contiguous. */
    PCM_FULL_RESOURCE_DESCRIPTOR FullRawList = RawList->List;
    ULONG InterruptCount = 0;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR RawInterrupt = NULL;
    for (ULONG i = 0; i < RawList->Count; i++) {
	/* Loop the partial descriptors */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Prev = NULL, Partial =
	    FullRawList->PartialResourceList.PartialDescriptors;
	for (ULONG j = 0; j < FullRawList->PartialResourceList.Count; j++) {
	    /* Check what kind of descriptor this was */
	    switch (Partial->Type) {
	    /* BAR resources */
	    case CmResourceTypePort:
	    case CmResourceTypeMemory:
		/* If we are behind a PCI bridge, make sure the IO resources assigned
		 * by the PnP manager falls within the forward windows of the bridge. */
		if (!PCI_IS_ROOT_FDO(PdoExtension->ParentFdoExtension)) {
		    PCM_PARTIAL_RESOURCE_DESCRIPTOR Res =
			PciGetBridgeForwardWindow(PdoExtension, Partial->Type, Partial->Flags);
		    if (Res->Type != Partial->Type) {
			assert(FALSE);
			return STATUS_RESOURCE_NOT_OWNED;
		    }
		    if (Res->Generic.Start.QuadPart > Partial->Generic.Start.QuadPart) {
			assert(FALSE);
			return STATUS_RESOURCE_NOT_OWNED;
		    }
		    if (Res->Generic.Start.QuadPart + Res->Generic.Length <
			Partial->Generic.Start.QuadPart + Partial->Generic.Length) {
			assert(FALSE);
			return STATUS_RESOURCE_NOT_OWNED;
		    }
		}
		break;

	    /* Interrupt resource */
	    case CmResourceTypeInterrupt:
		/* Skip legacy PIN-based interrupt resources, but assert in debug build. */
		if (!(Partial->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
		    assert(FALSE);
		    break;
		}
		if (!RawInterrupt) {
		    RawInterrupt = Partial;
		}
		InterruptCount++;
		break;

	    /* Check for specific device data */
	    case CmResourceTypeDevicePrivate:

		/* Check what kind of data this was */
		switch (Partial->DevicePrivate.Data[0]) {
		case PciBarIndex:
		    /* PciBarIndex means the device private data records the BAR
		     * index that the previous resource descriptor corresponds to.
		     * Copy the previous descriptor into the ResourceArray. */
		    assert(Prev);
		    assert(Partial->DevicePrivate.Data[1] < PCI_MAX_RESOURCE_COUNT);
		    ResourceArray[Partial->DevicePrivate.Data[1]] = *Prev;
		    break;

		case PciLockResource:
		    /* PciLockResource device private means we should skip the next
		     * several resource descriptors, the amount of which is given in
		     * the device private data. This is so these resources won't be
		     * changed below. */
		    assert(Partial->DevicePrivate.Data[1]);
		    ULONG NumberToSkip = min(Partial->DevicePrivate.Data[1],
					     FullRawList->PartialResourceList.Count-j-1);
		    j += NumberToSkip;
		    for (ULONG k = 0; k < NumberToSkip; k++) {
			Partial = CmGetNextPartialDescriptor(Partial);
		    }
		    break;

		default:
		    assert(FALSE);
		}
		break;

	    default:
		assert(FALSE);
	    }

	    /* Move to the next descriptor */
	    Prev = Partial;
	    Partial = CmGetNextPartialDescriptor(Partial);
	}

	/* We should be starting a new list now */
	FullRawList = (PVOID)Partial;
    }

    /* Check the current assigned PCI resources */
    PPCI_FUNCTION_RESOURCES PciResources = PdoExtension->Resources;
    if (!PciResources) {
	assert(FALSE);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    DPRINT("List of changed resources:\n");
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	/* Get the current function resource descriptor, and the new one */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR CurrentDescriptor = &PciResources->Current[i];
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial = &ResourceArray[i];

	PCM_PARTIAL_RESOURCE_DESCRIPTOR Prev = &PciResources->Current[(i == 0) ? 0 : (i-1)];

	/* Check if this new descriptor is different from the old one */
	if (((Partial->Type != CurrentDescriptor->Type) ||
	     (Partial->Type != CmResourceTypeNull)) &&
	    ((Partial->Generic.Start.QuadPart !=
	      CurrentDescriptor->Generic.Start.QuadPart) ||
	     (Partial->Generic.Length != CurrentDescriptor->Generic.Length))) {
	    /* Was there a range before? */
	    if (CurrentDescriptor->Type != CmResourceTypeNull) {
		/* Print it */
		DbgPrint("  Old range-\n");
		PciDebugPrintPartialResource(CurrentDescriptor);
	    } else {
		/* There was no range */
		DbgPrint("  Previously unset range\n");
	    }

	    /* Print new one */
	    DbgPrint("    changed to\n");
	    PciDebugPrintPartialResource(Partial);

	    /* Update to new range */
	    CurrentDescriptor->Type = Partial->Type;
	    Prev->Generic.Start = Partial->Generic.Start;
	    Prev->Generic.Length = Partial->Generic.Length;
	    CurrentDescriptor = Prev;
	}
    }

    /* Now check if the PnP manager has given us any interrupt resources and
     * copy the raw and translated resources into the PDO extension. */
    ULONG BufferSize = sizeof(PCI_INTERRUPT_RESOURCE) * InterruptCount;
    PdoExtension->InterruptResources = ExAllocatePoolWithTag(NonPagedPool, BufferSize,
							     PCI_POOL_TAG);
    if (!PdoExtension->InterruptResources) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    PdoExtension->InterruptResourceCount = InterruptCount;
    FullRawList = RawList->List;
    InterruptCount = 0;
    for (ULONG i = 0; i < RawList->Count; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial =
	    FullRawList->PartialResourceList.PartialDescriptors;
	for (ULONG j = 0; j < FullRawList->PartialResourceList.Count; j++) {
	    if (Partial->Type == CmResourceTypeInterrupt &&
		(Partial->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
		PdoExtension->InterruptResources[InterruptCount++].Raw = *Partial;
	    }
	    Partial = CmGetNextPartialDescriptor(Partial);
	}
	FullRawList = (PVOID)Partial;
    }
    assert(InterruptCount == PdoExtension->InterruptResourceCount);

    ULONG TranslatedInterruptCount = 0;
    PCM_FULL_RESOURCE_DESCRIPTOR FullTranslatedList = TranslatedList->List;
    for (ULONG i = 0; i < TranslatedList->Count; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial =
	    FullTranslatedList->PartialResourceList.PartialDescriptors;
	for (ULONG j = 0; j < FullTranslatedList->PartialResourceList.Count; j++) {
	    if (Partial->Type == CmResourceTypeInterrupt &&
		(Partial->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
		PdoExtension->InterruptResources[TranslatedInterruptCount++].Translated =
		    *Partial;
	    }
	    Partial = CmGetNextPartialDescriptor(Partial);
	}
	FullTranslatedList = (PVOID)Partial;
    }
    if (TranslatedInterruptCount != InterruptCount) {
	assert(FALSE);
	ExFreePoolWithTag(PdoExtension->InterruptResources, PCI_POOL_TAG);
	PdoExtension->InterruptResources = NULL;
	return STATUS_INTERNAL_ERROR;
    }

    return STATUS_SUCCESS;
}

static BOOLEAN PcipIsSameDevice(IN PPCI_PDO_EXTENSION DeviceExtension)
{
    PCI_COMMON_HEADER PciData = {};
    PCI_READ_CONFIG(DeviceExtension, &PciData, VendorID);
    PCI_READ_CONFIG(DeviceExtension, &PciData, DeviceID);

    /* Check if the IDs match */
    if ((PciData.VendorID != DeviceExtension->VendorId) ||
	(PciData.DeviceID != DeviceExtension->DeviceId))
	return FALSE;

    /* If the device has a valid revision, check if it matches */
    PCI_READ_CONFIG(DeviceExtension, &PciData, RevisionID);
    if (PciData.RevisionID != DeviceExtension->RevisionId)
	return FALSE;

    /* For multifunction devices, this is enough to assume they're the same */
    PCI_READ_CONFIG(DeviceExtension, &PciData, HeaderType);
    if (PCI_MULTIFUNCTION_DEVICE(&PciData))
	return TRUE;

    /* For bridge devices, there's also nothing else that can be checked */
    if (DeviceExtension->BaseClass == PCI_CLASS_BRIDGE_DEV)
	return TRUE;

    /* Devices, on the other hand, have subsystem data that can be compared */
    PCI_READ_CONFIG(DeviceExtension, &PciData, Type0.SubVendorID);
    PCI_READ_CONFIG(DeviceExtension, &PciData, Type0.SubSystemID);
    return (DeviceExtension->SubsystemVendorId == PciData.Type0.SubVendorID) &&
	(DeviceExtension->SubsystemId == PciData.Type0.SubSystemID);
}

static NTSTATUS PcipSetResources(IN PPCI_PDO_EXTENSION PdoExtension,
				 IN BOOLEAN DoReset)
{
    /* Make sure this is still the same device */
    if (!PcipIsSameDevice(PdoExtension)) {
	/* Fail */
	ASSERTMSG("PCI Set resources - not same device.\n", FALSE);
	return STATUS_DEVICE_DOES_NOT_EXIST;
    }

    /* Nothing to set for a host bridge */
    if ((PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
	(PdoExtension->SubClass == PCI_SUBCLASS_BR_HOST)) {
	/* Fake success */
	return STATUS_SUCCESS;
    }

    /* Disable interrupts (legacy, MSI or MSI-X) since we might modify the BAR ranges below.
     * Note to disable legacy interrupts we need to set the PCI_DISABLE_LEVEL_INTERRUPT bit */
    PciSetCommand(PdoExtension, PCI_DISABLE_LEVEL_INTERRUPT, TRUE);
    if (PdoExtension->InterruptResourceCount) {
	if (PdoExtension->MsiInfo.ExtendedMessage) {
	    if (PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl.Enable ||
		!PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl.FunctionMask) {
		PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl.Enable = 0;
		PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl.FunctionMask = 1;
		PciWriteDeviceConfig(PdoExtension,
				     &PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl,
				     PdoExtension->MsiInfo.CapabilityOffset +
				     FIELD_OFFSET(PCI_MSIX_CAPABILITY, MessageControl),
				     sizeof(PCI_MSIX_MESSAGE_CONTROL));
	    }
	} else {
	    if (PdoExtension->MsiInfo.MessageInfo.MessageControl.Enable) {
		PdoExtension->MsiInfo.MessageInfo.MessageControl.Enable = 0;
		PciWriteDeviceConfig(PdoExtension,
				     &PdoExtension->MsiInfo.MessageInfo.MessageControl,
				     PdoExtension->MsiInfo.CapabilityOffset +
				     FIELD_OFFSET(PCI_MSI_CAPABILITY, MessageControl),
				     sizeof(PCI_MSI_MESSAGE_CONTROL));
	    }
	}
    }

    /* Disable decoding because we might be modifying the BARs below. */
    PciSetCommand(PdoExtension,
		  PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE | PCI_ENABLE_BUS_MASTER,
		  FALSE);

    /* Locate the correct resource configurator for this type of device */
    PPCI_CONFIGURATOR Configurator = &PciConfigurators[PdoExtension->HeaderType];

    /* Apply the settings change */
    USHORT CommandEnables = 0;
    Configurator->ChangeResourceSettings(PdoExtension, &CommandEnables);

    /* Check if a reset is needed */
    if (DoReset) {
	/* Reset resources */
	Configurator->ResetDevice(PdoExtension);
    }

    /* Enable MSI/MSI-X if we are supplied interrupt resources */
    if (!PdoExtension->InterruptResourceCount) {
	goto enable;
    }
    assert(PdoExtension->MsiInfo.CapabilityOffset);
    /* If the device supports MSI-X, map the message table and program the table entries. */
    if (PdoExtension->MsiInfo.ExtendedMessage) {
	ULONG TableOffset = PdoExtension->MsiInfo.ExtendedMessageInfo.MessageTable;
	UCHAR TableIndex = TableOffset & PCI_MSIX_MESSAGE_TABLE_BAR_INDEX_MASK;
	TableOffset &= PCI_MSIX_MESSAGE_TABLE_OFFSET_MASK;
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Res = &PdoExtension->Resources->Current[TableIndex];
	assert(Res);
	assert(Res->Type == CmResourceTypeMemory);
	assert(Res->Memory.Start.QuadPart);
	assert(Res->Memory.Length > TableOffset);
	if (!Res || Res->Type != CmResourceTypeMemory || !Res->Memory.Start.QuadPart ||
	    Res->Memory.Length <= TableOffset) {
	    return STATUS_DEVICE_CONFIGURATION_ERROR;
	}
	/* Enable memory decoding temporarily because we need to modify the MSI-X table. */
	PciSetCommand(PdoExtension, PCI_ENABLE_MEMORY_SPACE, TRUE);
	PHYSICAL_ADDRESS TableAddress = { .QuadPart = Res->Memory.Start.QuadPart + TableOffset };
	ULONG LengthToMap = PdoExtension->InterruptResourceCount * sizeof(PCI_MSIX_TABLE_ENTRY);
	PPCI_MSIX_TABLE_ENTRY Table = MmMapIoSpace(TableAddress, LengthToMap, MmNonCached);
	if (!Table) {
	    assert(FALSE);
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
	for (ULONG i = 0; i < PdoExtension->InterruptResourceCount; i++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw = &PdoExtension->InterruptResources[i].Raw;
	    assert(Raw->Type == CmResourceTypeInterrupt);
	    assert(Raw->Flags & CM_RESOURCE_INTERRUPT_MESSAGE);
	    assert(Raw->MessageInterrupt.Raw.MessageCount == 1);
	    Table[i].MessageAddress.QuadPart = Raw->MessageInterrupt.Raw.MessageAddress;
	    Table[i].MessageData = Raw->MessageInterrupt.Raw.MessageData;
	    Table[i].VectorControl = 0;
	}
	MmUnmapIoSpace(Table, LengthToMap);
	PciSetCommand(PdoExtension, PCI_ENABLE_MEMORY_SPACE, FALSE);
    } else {
	/* Else, program the MSI capability. */
	assert(PdoExtension->InterruptResourceCount == 1);
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw = &PdoExtension->InterruptResources[0].Raw;
	assert(Raw->Type == CmResourceTypeInterrupt);
	assert(Raw->Flags & CM_RESOURCE_INTERRUPT_MESSAGE);
	PdoExtension->MsiInfo.MessageInfo.MessageAddress.QuadPart =
	    Raw->MessageInterrupt.Raw.MessageAddress;
	PciWriteDeviceConfig(PdoExtension,
			     &PdoExtension->MsiInfo.MessageInfo.MessageAddress.LowPart,
			     PdoExtension->MsiInfo.CapabilityOffset +
			     FIELD_OFFSET(PCI_MSI_CAPABILITY, MessageAddress),
			     sizeof(ULONG));
	PdoExtension->MsiInfo.MessageInfo.MessageData =
	    Raw->MessageInterrupt.Raw.MessageData;
	if (PdoExtension->MsiInfo.MessageInfo.MessageControl.Is64Bit) {
	    PciWriteDeviceConfig(PdoExtension,
				 &PdoExtension->MsiInfo.MessageInfo.MessageAddress.HighPart,
				 PdoExtension->MsiInfo.CapabilityOffset +
				 FIELD_OFFSET(PCI_MSI_CAPABILITY, Data64.MessageUpperAddress),
				 sizeof(ULONG));
	    PciWriteDeviceConfig(PdoExtension,
				 &PdoExtension->MsiInfo.MessageInfo.MessageData,
				 PdoExtension->MsiInfo.CapabilityOffset +
				 FIELD_OFFSET(PCI_MSI_CAPABILITY, Data64.MessageData),
				 sizeof(USHORT));
	} else {
	    PciWriteDeviceConfig(PdoExtension,
				 &PdoExtension->MsiInfo.MessageInfo.MessageData,
				 PdoExtension->MsiInfo.CapabilityOffset +
				 FIELD_OFFSET(PCI_MSI_CAPABILITY, Data32.MessageData),
				 sizeof(USHORT));
	}
	assert(Raw->MessageInterrupt.Raw.MessageCount <=
	       (1UL << PdoExtension->MsiInfo.MessageInfo.MessageControl.MaxMsgCountShift));
	PdoExtension->MsiInfo.MessageInfo.MessageControl.EnabledMsgCountShift =
	    PdoExtension->MsiInfo.MessageInfo.MessageControl.MaxMsgCountShift;
    }
    MemoryBarrier();

    /* Program the PCI config space to enable interrupts (MSI or MSI-X) */
    if (PdoExtension->MsiInfo.ExtendedMessage) {
	PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl.Enable = 1;
	PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl.FunctionMask = 0;
	PciWriteDeviceConfig(PdoExtension,
			     &PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl,
			     PdoExtension->MsiInfo.CapabilityOffset +
			     FIELD_OFFSET(PCI_MSIX_CAPABILITY, MessageControl),
			     sizeof(PCI_MSIX_MESSAGE_CONTROL));
    } else {
	/* At this point the message address and message data should have been programmed. */
	assert(PdoExtension->MsiInfo.MessageInfo.MessageAddress.QuadPart);
	assert(PdoExtension->MsiInfo.MessageInfo.MessageData);
	PdoExtension->MsiInfo.MessageInfo.MessageControl.Enable = 1;
	PciWriteDeviceConfig(PdoExtension,
			     &PdoExtension->MsiInfo.MessageInfo.MessageControl,
			     PdoExtension->MsiInfo.CapabilityOffset +
			     FIELD_OFFSET(PCI_MSI_CAPABILITY, MessageControl),
			     sizeof(PCI_MSI_MESSAGE_CONTROL));
	if (PdoExtension->MsiInfo.MessageInfo.MessageControl.Is64Bit) {
	    ULONG MessageCount =
		PdoExtension->InterruptResources[0].Raw.MessageInterrupt.Raw.MessageCount;
	    PdoExtension->MsiInfo.MessageInfo.MaskBits |= (1UL << MessageCount) - 1;
	    PciWriteDeviceConfig(PdoExtension,
				 &PdoExtension->MsiInfo.MessageInfo.MaskBits,
				 PdoExtension->MsiInfo.CapabilityOffset +
				 FIELD_OFFSET(PCI_MSI_CAPABILITY, Data64.MaskBits),
				 sizeof(ULONG));
	}
    }

enable:
    /* Enable decodes. We always enable bus mastering. */
    CommandEnables |= PCI_ENABLE_BUS_MASTER;
    PciSetCommand(PdoExtension, CommandEnables, TRUE);

    /* Update complete */
    return STATUS_SUCCESS;
}

static NTSTATUS PciPdoStartDevice(IN PIRP Irp,
				  IN PIO_STACK_LOCATION IoStack,
				  IN PPCI_PDO_EXTENSION DeviceExtension)
{
    UNREFERENCED_PARAMETER(Irp);

    /* Begin entering the start phase */
    NTSTATUS Status = PciBeginStateTransition((PVOID)DeviceExtension, PciStarted);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Check if the OS assigned resources differ from the PCI configuration */
    Status = PcipComputeNewCurrentSettings(
	DeviceExtension,
	IoStack->Parameters.StartDevice.AllocatedResources,
	IoStack->Parameters.StartDevice.AllocatedResourcesTranslated);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Check if the device was sleeping */
    BOOLEAN DoReset = FALSE;
    if (DeviceExtension->PowerState.CurrentDeviceState != PowerDeviceD0) {
	/* Power it up */
	Status = PciSetPowerManagedDevicePowerState(DeviceExtension, PowerDeviceD0);
	if (!NT_SUCCESS(Status)) {
	    /* Powerup fail, fail the request */
	    PciCancelStateTransition((PVOID)DeviceExtension, PciStarted);
	    return STATUS_DEVICE_POWER_FAILURE;
	}

	/* Tell the power manager that the device is powered up */
	POWER_STATE PowerState = {
	    .DeviceState = PowerDeviceD0
	};
	PoSetPowerState(DeviceExtension->PhysicalDeviceObject, DevicePowerState,
			PowerState);

	/* Update internal state */
	DeviceExtension->PowerState.CurrentDeviceState = PowerDeviceD0;

	/* This device's resources and decodes will need to be reset */
	DoReset = TRUE;
    }

    /* Update resource information now that the device is powered up and active */
    Status = PcipSetResources(DeviceExtension, DoReset);
out:
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

static NTSTATUS PcipQueryTargetDeviceRelations(IN PPCI_PDO_EXTENSION PdoExtension,
					       IN OUT PDEVICE_RELATIONS *pDeviceRelations)
{
    PAGED_CODE();
    PDEVICE_RELATIONS DeviceRelations;

    /* If there were existing relations, free them */
    if (*pDeviceRelations)
	ExFreePoolWithTag(*pDeviceRelations, 0);

    /* Allocate a new structure for the relations */
    DeviceRelations = ExAllocatePoolWithTag(NonPagedPool,
					    sizeof(DEVICE_RELATIONS) + sizeof(PDEVICE_OBJECT),
					    'BicP');
    if (!DeviceRelations)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Only one relation: the PDO */
    DeviceRelations->Count = 1;
    DeviceRelations->Objects[0] = PdoExtension->PhysicalDeviceObject;

    /* Return the new relations */
    *pDeviceRelations = DeviceRelations;
    return STATUS_SUCCESS;
}

static NTSTATUS PcipQueryEjectionRelations(IN PPCI_PDO_EXTENSION PdoExtension,
					   IN OUT PDEVICE_RELATIONS *pDeviceRelations)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(pDeviceRelations);

    /* Not yet implemented */
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PciPdoQueryDeviceRelations(IN PIRP Irp,
					   IN PIO_STACK_LOCATION IoStackLocation,
					   IN PPCI_PDO_EXTENSION DeviceExtension)
{
    NTSTATUS Status;

    /* Are ejection relations being queried? */
    if (IoStackLocation->Parameters.QueryDeviceRelations.Type == EjectionRelations) {
	/* Call the worker function */
	Status = PcipQueryEjectionRelations(
	    DeviceExtension, (PDEVICE_RELATIONS *)&Irp->IoStatus.Information);
    } else if (IoStackLocation->Parameters.QueryDeviceRelations.Type ==
	       TargetDeviceRelation) {
	/* The only other relation supported is the target device relation */
	Status = PcipQueryTargetDeviceRelations(
	    DeviceExtension, (PDEVICE_RELATIONS *)&Irp->IoStatus.Information);
    } else {
	/* All other relations are unsupported */
	Status = STATUS_NOT_SUPPORTED;
    }

    /* Return either the result of the worker function, or unsupported status */
    return Status;
}

static NTSTATUS PciDetermineSlotNumber(IN PPCI_PDO_EXTENSION PdoExtension,
				       OUT PULONG SlotNumber)
{
    /* We should call the ACPI driver to evaluate the _SUN method. So far this
     * is unimplemented. The slot number is used purely as a human-friendly UI
     * number so an operator can, say, replace a broken PCI device on slot 3. */
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PciGetDeviceCapabilities(IN PDEVICE_OBJECT DeviceObject,
					 IN OUT PDEVICE_CAPABILITIES DeviceCapability)
{
    PAGED_CODE();
    PIRP Irp;
    NTSTATUS Status;
    PDEVICE_OBJECT AttachedDevice;
    PIO_STACK_LOCATION IoStackLocation;
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

    /* Zero out capabilities and set undefined values to start with */
    RtlZeroMemory(DeviceCapability, sizeof(DEVICE_CAPABILITIES));
    DeviceCapability->Size = sizeof(DEVICE_CAPABILITIES);
    DeviceCapability->Version = 1;
    DeviceCapability->Address = -1;
    DeviceCapability->UINumber = -1;

    /* Find the device the PDO is attached to */
    AttachedDevice = IoGetAttachedDeviceReference(DeviceObject);

    /* And build an IRP for it */
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, AttachedDevice, NULL, 0, NULL,
				       &Event, &IoStatusBlock);
    if (!Irp) {
	/* The IRP failed, fail the request as well */
	ObDereferenceObject(AttachedDevice);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Set default status */
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    /* Get a stack location in this IRP */
    IoStackLocation = IoGetNextIrpStackLocation(Irp);
    ASSERT(IoStackLocation);

    /* Initialize it as a query capabilities IRP, with no completion routine */
    RtlZeroMemory(IoStackLocation, sizeof(IO_STACK_LOCATION));
    IoStackLocation->MajorFunction = IRP_MJ_PNP;
    IoStackLocation->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IoStackLocation->Parameters.DeviceCapabilities.Capabilities = DeviceCapability;
    IoSetCompletionRoutine(Irp, NULL, NULL, FALSE, FALSE, FALSE);

    /* Send the IOCTL to the driver */
    Status = IoCallDriver(AttachedDevice, Irp);
    if (Status == STATUS_PENDING) {
        /* Wait for a response */
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }

    /* Done, dereference the attached device and return the final result */
    ObDereferenceObject(AttachedDevice);
    return Status;
}

static NTSTATUS PciQueryPowerCapabilities(IN PPCI_PDO_EXTENSION PdoExtension,
					  IN PDEVICE_CAPABILITIES DeviceCapability)
{
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS Status;
    DEVICE_CAPABILITIES AttachedCaps;
    DEVICE_POWER_STATE NewPowerState, DevicePowerState, DeviceWakeLevel, DeviceWakeState;
    SYSTEM_POWER_STATE SystemWakeState, DeepestWakeState, CurrentState;

    /* Nothing is known at first */
    DeviceWakeState = PowerDeviceUnspecified;
    SystemWakeState = DeepestWakeState = PowerSystemUnspecified;

    /* Get the PCI capabilities for the parent PDO */
    DeviceObject = PdoExtension->ParentFdoExtension->PhysicalDeviceObject;
    Status = PciGetDeviceCapabilities(DeviceObject, &AttachedCaps);
    ASSERT(NT_SUCCESS(Status));
    if (!NT_SUCCESS(Status))
	return Status;

    /* Check if there's not an existing device state for S0 */
    if (!AttachedCaps.DeviceState[PowerSystemWorking]) {
	/* Set D0<->S0 mapping */
	AttachedCaps.DeviceState[PowerSystemWorking] = PowerDeviceD0;
    }

    /* Check if there's not an existing device state for S3 */
    if (!AttachedCaps.DeviceState[PowerSystemShutdown]) {
	/* Set D3<->S3 mapping */
	AttachedCaps.DeviceState[PowerSystemShutdown] = PowerDeviceD3;
    }

    /* Check for a PDO with broken, or no, power capabilities */
    if (PdoExtension->NoPmCaps) {
	/* Unknown wake device states */
	DeviceCapability->DeviceWake = PowerDeviceUnspecified;
	DeviceCapability->SystemWake = PowerSystemUnspecified;

	/* No device state support */
	DeviceCapability->DeviceD1 = FALSE;
	DeviceCapability->DeviceD2 = FALSE;

	/* No waking from any low-power device state is supported */
	DeviceCapability->WakeFromD0 = FALSE;
	DeviceCapability->WakeFromD1 = FALSE;
	DeviceCapability->WakeFromD2 = FALSE;
	DeviceCapability->WakeFromD3 = FALSE;

	/* For the rest, copy whatever the parent PDO had */
	RtlCopyMemory(DeviceCapability->DeviceState, AttachedCaps.DeviceState,
		      sizeof(DeviceCapability->DeviceState));
	return STATUS_SUCCESS;
    }

    /* The PCI Device has power capabilities, so read which ones are supported */
    DeviceCapability->DeviceD1 = PdoExtension->PowerCapabilities.Support.D1;
    DeviceCapability->DeviceD2 = PdoExtension->PowerCapabilities.Support.D2;
    DeviceCapability->WakeFromD0 = PdoExtension->PowerCapabilities.Support.PMED0;
    DeviceCapability->WakeFromD1 = PdoExtension->PowerCapabilities.Support.PMED1;
    DeviceCapability->WakeFromD2 = PdoExtension->PowerCapabilities.Support.PMED2;

    /* Can the attached device wake from D3? */
    if (AttachedCaps.DeviceWake != PowerDeviceD3) {
	/* It can't, so check if this PDO supports hot D3 wake */
	DeviceCapability->WakeFromD3 = PdoExtension->PowerCapabilities.Support.PMED3Hot;
    } else {
	/* It can, is this the root bus? */
	if (PCI_IS_ROOT_FDO(PdoExtension->ParentFdoExtension)) {
	    /* This is the root bus, so just check if it supports hot D3 wake */
	    DeviceCapability->WakeFromD3 =
		PdoExtension->PowerCapabilities.Support.PMED3Hot;
	} else {
	    /* Take the minimums? -- need to check with briang at work */
	    UNIMPLEMENTED;
	}
    }

    /* Now loop each system power state to determine its device state mapping */
    for (CurrentState = PowerSystemWorking; CurrentState < PowerSystemMaximum;
	 CurrentState++) {
	/* Read the current mapping from the attached device */
	DevicePowerState = AttachedCaps.DeviceState[CurrentState];
	NewPowerState = DevicePowerState;

	/* The attachee supports D1, but this PDO does not */
	if ((NewPowerState == PowerDeviceD1) &&
	    !(PdoExtension->PowerCapabilities.Support.D1)) {
	    /* Fall back to D2 */
	    NewPowerState = PowerDeviceD2;
	}

	/* The attachee supports D2, but this PDO does not */
	if ((NewPowerState == PowerDeviceD2) &&
	    !(PdoExtension->PowerCapabilities.Support.D2)) {
	    /* Fall back to D3 */
	    NewPowerState = PowerDeviceD3;
	}

	/* Set the mapping based on the best state supported */
	DeviceCapability->DeviceState[CurrentState] = NewPowerState;

	/* Check if sleep states are being processed, and a mapping was found */
	if ((CurrentState < PowerSystemHibernate) &&
	    (NewPowerState != PowerDeviceUnspecified)) {
	    /* Save this state as being the deepest one found until now */
	    DeepestWakeState = CurrentState;
	}

	/*
         * Finally, check if the computed sleep state is within the states that
         * this device can wake the system from, and if it's higher or equal to
         * the sleep state mapping that came from the attachee, assuming that it
         * had a valid mapping to begin with.
         *
         * It this is the case, then make sure that the computed sleep state is
         * matched by the device's ability to actually wake from that state.
         *
         * For devices that support D3, the PCI device only needs Hot D3 as long
         * as the attachee's state is less than D3. Otherwise, if the attachee
         * might also be at D3, this would require a Cold D3 wake, so check that
         * the device actually support this.
         */
	if ((CurrentState < AttachedCaps.SystemWake) &&
	    (NewPowerState >= DevicePowerState) &&
	    (DevicePowerState != PowerDeviceUnspecified) &&
	    (((NewPowerState == PowerDeviceD0) && (DeviceCapability->WakeFromD0)) ||
	     ((NewPowerState == PowerDeviceD1) && (DeviceCapability->WakeFromD1)) ||
	     ((NewPowerState == PowerDeviceD2) && (DeviceCapability->WakeFromD2)) ||
	     ((NewPowerState == PowerDeviceD3) &&
	      (PdoExtension->PowerCapabilities.Support.PMED3Hot) &&
	      ((DevicePowerState < PowerDeviceD3) ||
	       (PdoExtension->PowerCapabilities.Support.PMED3Cold))))) {
	    /* The mapping is valid, so this will be the lowest wake state */
	    SystemWakeState = CurrentState;
	    DeviceWakeState = NewPowerState;
	}
    }

    /* Read the current wake level */
    DeviceWakeLevel = PdoExtension->PowerState.DeviceWakeLevel;

    /* Check if the attachee's wake levels are valid, and the PDO's is higher */
    if ((AttachedCaps.SystemWake != PowerSystemUnspecified) &&
	(AttachedCaps.DeviceWake != PowerDeviceUnspecified) &&
	(DeviceWakeLevel != PowerDeviceUnspecified) &&
	(DeviceWakeLevel >= AttachedCaps.DeviceWake)) {
	/* Inherit the system wake from the attachee, and this PDO's wake level */
	DeviceCapability->SystemWake = AttachedCaps.SystemWake;
	DeviceCapability->DeviceWake = DeviceWakeLevel;

	/* Now check if the wake level is D0, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD0) &&
	    !(DeviceCapability->WakeFromD0)) {
	    /* Bump to D1 */
	    DeviceCapability->DeviceWake = PowerDeviceD1;
	}

	/* Now check if the wake level is D1, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD1) &&
	    !(DeviceCapability->WakeFromD1)) {
	    /* Bump to D2 */
	    DeviceCapability->DeviceWake = PowerDeviceD2;
	}

	/* Now check if the wake level is D2, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD2) &&
	    !(DeviceCapability->WakeFromD2)) {
	    /* Bump it to D3 */
	    DeviceCapability->DeviceWake = PowerDeviceD3;
	}

	/* Now check if the wake level is D3, but the PDO doesn't support it */
	if ((DeviceCapability->DeviceWake == PowerDeviceD3) &&
	    !(DeviceCapability->WakeFromD3)) {
	    /* Then no valid wake state exists */
	    DeviceCapability->DeviceWake = PowerDeviceUnspecified;
	    DeviceCapability->SystemWake = PowerSystemUnspecified;
	}

	/* Check if no valid wake state was found */
	if ((DeviceCapability->DeviceWake == PowerDeviceUnspecified) ||
	    (DeviceCapability->SystemWake == PowerSystemUnspecified)) {
	    /* Check if one was computed earlier */
	    if ((SystemWakeState != PowerSystemUnspecified) &&
		(DeviceWakeState != PowerDeviceUnspecified)) {
		/* Use the wake state that had been computed earlier */
		DeviceCapability->DeviceWake = DeviceWakeState;
		DeviceCapability->SystemWake = SystemWakeState;

		/* If that state was D3, then the device supports Hot/Cold D3 */
		if (DeviceWakeState == PowerDeviceD3)
		    DeviceCapability->WakeFromD3 = TRUE;
	    }
	}

	/*
         * Finally, check for off states (lower than S3, such as hibernate) and
         * make sure that the device both supports waking from D3 as well as
         * supports a Cold wake
         */
	if ((DeviceCapability->SystemWake > PowerSystemSleeping3) &&
	    ((DeviceCapability->DeviceWake != PowerDeviceD3) ||
	     !(PdoExtension->PowerCapabilities.Support.PMED3Cold))) {
	    /* It doesn't, so pick the computed lowest wake state from earlier */
	    DeviceCapability->SystemWake = DeepestWakeState;
	}

	/* Set the PCI Specification mandated maximum latencies for transitions */
	DeviceCapability->D1Latency = 0;
	DeviceCapability->D2Latency = 2;
	DeviceCapability->D3Latency = 100;

	/* Sanity check */
	ASSERT(DeviceCapability->DeviceState[PowerSystemWorking] == PowerDeviceD0);
    } else {
	/* No valid sleep states, no latencies to worry about */
	DeviceCapability->D1Latency = 0;
	DeviceCapability->D2Latency = 0;
	DeviceCapability->D3Latency = 0;
    }

    /* This function always succeeds, even without power management support */
    return STATUS_SUCCESS;
}

static NTSTATUS PciPdoQueryCapabilities(IN PIRP Irp,
					IN PIO_STACK_LOCATION IoStackLocation,
					IN PPCI_PDO_EXTENSION PdoExtension)
{
    UNREFERENCED_PARAMETER(Irp);
    PDEVICE_CAPABILITIES DeviceCapability =
	IoStackLocation->Parameters.DeviceCapabilities.Capabilities;

    /* A PDO ID is never unique, and its address is its function and device */
    DeviceCapability->UniqueID = FALSE;
    DeviceCapability->Address = PdoExtension->Slot.Bits.FunctionNumber |
	(PdoExtension->Slot.Bits.DeviceNumber << 16);

    /* Check for host bridges */
    if ((PdoExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
	(PdoExtension->SubClass == PCI_SUBCLASS_BR_HOST)) {
	/* Raw device opens to a host bridge are acceptable */
	DeviceCapability->RawDeviceOK = TRUE;
    } else {
	/* Otherwise, other PDOs cannot be directly opened */
	DeviceCapability->RawDeviceOK = FALSE;
    }

    /* PCI PDOs are pretty fixed things */
    DeviceCapability->LockSupported = FALSE;
    DeviceCapability->EjectSupported = FALSE;
    DeviceCapability->Removable = FALSE;
    DeviceCapability->DockDevice = FALSE;

    /* The slot number is stored as a device property, go query it */
    PciDetermineSlotNumber(PdoExtension, &DeviceCapability->UINumber);

    /* Finally, query any power capabilities and convert them for PnP usage */
    NTSTATUS Status = PciQueryPowerCapabilities(PdoExtension, DeviceCapability);

    /* Dump the capabilities if it all worked, and return the status */
    if (NT_SUCCESS(Status)) {
	PciDebugDumpQueryCapabilities(DeviceCapability);
    } else {
	DPRINT("PciQueryCapabilities returning error 0x%x\n", Status);
    }
    return Status;
}

static PIO_RESOURCE_REQUIREMENTS_LIST AllocateIoRequirementsList(IN ULONG Count,
								 IN ULONG BusNumber,
								 IN ULONG SlotNumber)
{
    /* Calculate the final size of the list, including each descriptor */
    SIZE_T Size = sizeof(IO_RESOURCE_REQUIREMENTS_LIST) + sizeof(IO_RESOURCE_LIST) +
	sizeof(IO_RESOURCE_DESCRIPTOR) * Count;

    /* Allocate the list */
    PIO_RESOURCE_REQUIREMENTS_LIST RequirementsList = ExAllocatePoolWithTag(NonPagedPool,
									    Size, 'BicP');
    if (!RequirementsList)
	return NULL;

    /* Initialize it */
    RtlZeroMemory(RequirementsList, Size);
    RequirementsList->AlternativeLists = 1;
    RequirementsList->BusNumber = BusNumber;
    RequirementsList->SlotNumber = SlotNumber;
    RequirementsList->InterfaceType = PCIBus;
    RequirementsList->ListSize = Size;
    RequirementsList->List[0].Count = Count;
    RequirementsList->List[0].Version = 1;
    RequirementsList->List[0].Revision = 1;

    /* Return it */
    return RequirementsList;
}

static PCM_RESOURCE_LIST AllocateCmResourceList(IN ULONG Count, IN ULONG BusNumber)
{
    /* Calculate the final size of the list, including each descriptor */
    SIZE_T Size = sizeof(CM_RESOURCE_LIST) + sizeof(CM_FULL_RESOURCE_DESCRIPTOR) +
	sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * Count;

    /* Allocate the list */
    PCM_RESOURCE_LIST ResourceList = ExAllocatePoolWithTag(NonPagedPool, Size, 'BicP');
    if (!ResourceList)
	return NULL;

    /* Initialize it */
    RtlZeroMemory(ResourceList, Size);
    ResourceList->Count = 1;
    ResourceList->List[0].BusNumber = BusNumber;
    ResourceList->List[0].InterfaceType = PCIBus;
    ResourceList->List[0].PartialResourceList.Version = 1;
    ResourceList->List[0].PartialResourceList.Revision = 1;
    ResourceList->List[0].PartialResourceList.Count = Count;

    /* Return it */
    return ResourceList;
}

static NTSTATUS PciPdoQueryResources(IN PIRP Irp,
				     IN PIO_STACK_LOCATION IoStackLocation,
				     IN PPCI_PDO_EXTENSION PdoExtension)
{
    UNREFERENCED_PARAMETER(IoStackLocation);
    PAGED_CODE();
    USHORT PciCommand;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial, Resource;
#if DBG
    PCM_PARTIAL_RESOURCE_DESCRIPTOR LastResource;
#endif
    PCM_RESOURCE_LIST ResourceList;

    /* Assume failure */
    ULONG Count = 0;
    BOOLEAN HaveVga = FALSE;
    Irp->IoStatus.Information = 0;

    /* Make sure there's some resources to query */
    PPCI_FUNCTION_RESOURCES PciResources = PdoExtension->Resources;
    if (!PciResources)
	return STATUS_SUCCESS;

    /* Read the decodes */
    PciReadDeviceConfig(PdoExtension, &PciCommand,
			FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));

    /* Check which ones are turned on */
    BOOLEAN HaveIoSpace = PciCommand & PCI_ENABLE_IO_SPACE;
    BOOLEAN HaveMemSpace = PciCommand & PCI_ENABLE_MEMORY_SPACE;

    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	/* Check if the decode for this descriptor is actually turned on */
	Partial = &PciResources->Current[i];
	if ((HaveMemSpace && Partial->Type == CmResourceTypeMemory) ||
	    (HaveIoSpace && Partial->Type == CmResourceTypePort)) {
	    /* One more fully active descriptor */
	    Count++;
	}
    }

    /* If the device has interrupt enabled, add the interrupt resource(s) */
    Count += PdoExtension->InterruptResourceCount;

    /* Check for PCI bridge */
    if (PdoExtension->HeaderType == PCI_BRIDGE_TYPE) {
	/* Read bridge settings, check if VGA is present */
	if (PdoExtension->BridgeInfo.VgaBitSet) {
	    /* Remember for later */
	    HaveVga = TRUE;

	    /* One memory descriptor for 0xA0000, plus the two I/O port ranges */
	    if (HaveMemSpace)
		Count++;
	    if (HaveIoSpace)
		Count += 2;
	}
    }

    /* If there's no descriptors in use, there's no resources, so return */
    if (!Count)
	return STATUS_SUCCESS;

    /* Allocate a resource list to hold the resources */
    ResourceList = AllocateCmResourceList(Count,
					  PdoExtension->ParentFdoExtension->BaseBus);
    if (!ResourceList)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* This is where the descriptors will be copied into */
    Resource = ResourceList->List[0].PartialResourceList.PartialDescriptors;
#if DBG
    LastResource = Resource + Count + 1;
#endif

    /* Loop maximum possible descriptors */
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	/* Check if the decode for this descriptor is actually turned on */
	Partial = &PciResources->Current[i];
	if ((HaveMemSpace && (Partial->Type == CmResourceTypeMemory)) ||
	    (HaveIoSpace && (Partial->Type == CmResourceTypePort))) {
	    /* Copy the descriptor into the resource list */
	    *Resource++ = *Partial;
	}
    }

    /* Check if earlier the code detected this was a PCI bridge with VGA on it */
    if (HaveVga) {
	/* Are the memory decodes enabled? */
	if (HaveMemSpace) {
	    /* Build a memory descriptor for a 128KB framebuffer at 0xA0000 */
	    Resource->Flags = CM_RESOURCE_MEMORY_READ_WRITE;
	    Resource->Generic.Start.HighPart = 0;
	    Resource->Type = CmResourceTypeMemory;
	    Resource->Generic.Start.LowPart = 0xA0000;
	    Resource->Generic.Length = 0x20000;
	    Resource++;
	}

	/* Are the I/O decodes enabled? */
	if (HaveIoSpace) {
	    /* Build an I/O descriptor for the graphic ports at 0x3B0 */
	    Resource->Type = CmResourceTypePort;
	    Resource->Flags = CM_RESOURCE_PORT_POSITIVE_DECODE |
		CM_RESOURCE_PORT_10_BIT_DECODE;
	    Resource->Port.Start.QuadPart = 0x3B0u;
	    Resource->Port.Length = 0xC;
	    Resource++;

	    /* Build an I/O descriptor for the graphic ports at 0x3C0 */
	    Resource->Type = CmResourceTypePort;
	    Resource->Flags = CM_RESOURCE_PORT_POSITIVE_DECODE |
		CM_RESOURCE_PORT_10_BIT_DECODE;
	    Resource->Port.Start.QuadPart = 0x3C0u;
	    Resource->Port.Length = 0x20;
	    Resource++;
	}
    }

    /* If device has interrupt(s) enabled, add the interrupt resource(s) */
    for (ULONG i = 0; i < PdoExtension->InterruptResourceCount; i++) {
	/* Make sure there's still space */
	ASSERT(&Resource[i] < LastResource);

	/* Add the interrupt descriptor */
	Resource[i] = PdoExtension->InterruptResources[i].Raw;
    }

    /* Return the resource list */
    Irp->IoStatus.Information = (ULONG_PTR)ResourceList;
    return STATUS_SUCCESS;
}

/*
 * Returns TRUE if the given IO resource descriptor that describes the port/memory
 * range limits (which we obtained from probing the device during enumeration) is
 * valid for reporting to the PNP manager. We only report a resource descriptor for
 * port or memory windows that have a non-zero length.
 */
FORCEINLINE BOOLEAN IsValidResourceLimit(IN PIO_RESOURCE_DESCRIPTOR Limit)
{
    return (Limit->Type == CmResourceTypePort || Limit->Type == CmResourceTypeMemory) &&
	Limit->Generic.Length;
}

/*
 * Returns TRUE if the specified partial resource descriptor represents a valid
 * resource setting, assigned (usually) by the boot firmware. This requires additionally
 * that the starting address of the port or memory be non-zero.
 */
FORCEINLINE BOOLEAN IsResourceAssigned(IN PCM_PARTIAL_RESOURCE_DESCRIPTOR Desc)
{
    return (Desc->Type == CmResourceTypePort || Desc->Type == CmResourceTypeMemory) &&
	Desc->Generic.Length && Desc->Generic.Start.QuadPart;
}

static NTSTATUS PcipBuildRequirementsList(IN PPCI_PDO_EXTENSION PdoExtension,
					  OUT PIO_RESOURCE_REQUIREMENTS_LIST *Buffer)
{

    DPRINT1("PciBuildRequirementsList: Bus 0x%x, Dev 0x%x, Func 0x%x.\n",
	    PdoExtension->ParentFdoExtension->BaseBus,
	    PdoExtension->Slot.Bits.DeviceNumber,
	    PdoExtension->Slot.Bits.FunctionNumber);

    ULONG ResCount = 0;
    if (!PdoExtension->Resources) {
	goto out;
    }

    /* Find out how many resource descriptors we need. For each resource (including
     * BAR, bridge forward window, and ROM) we need two kinds of resource descriptors,
     * one for the BAR resource followed by another device private IO resource recording
     * the index within the resource array. */
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	/* For each resource we generate the follwing resource descriptors:
	 * first the preferred resource descriptor, if the resource has been
	 * assigned (usually by the boot firmware), followed by the alternative
	 * resource requirement from the range limit we probed during device
	 * enumeration (if the bridge window is non-zero), followed by a
	 * CmResourceTypeDevicePrivate indicating the corresponding resource array
	 * index. Note this relies on the PNP manager respecting the order of the
	 * resource descriptors list. */
	BOOLEAN ValidLimit = IsValidResourceLimit(&PdoExtension->Resources->Limit[i]);
	BOOLEAN Assigned = IsResourceAssigned(&PdoExtension->Resources->Current[i]);
	if (ValidLimit) {
	    ResCount++;
	}
	if (Assigned) {
	    ResCount++;
	}
	if (ValidLimit || Assigned) {
	    ResCount++;
	}
    }
    ULONG InterruptCount = 0;
    if (PdoExtension->MsiInfo.CapabilityOffset) {
	if (PdoExtension->MsiInfo.ExtendedMessage) {
	    InterruptCount = PdoExtension->MsiInfo.ExtendedMessageInfo.MessageControl.NumEntries;
	} else {
	    InterruptCount = 1;
	}
    }
    ResCount += InterruptCount;
    ResCount += PdoExtension->AdditionalResourceCount;

out:
    DPRINT1("PCI - build resource reqs - baseResourceCount = %d\n",
	    ResCount);

    if (!ResCount) {
	/* No resource needed, return success */
	*Buffer = NULL;
	DPRINT1("PCI - build resource reqs - early out, 0 resources\n");
	return STATUS_SUCCESS;
    }

    PIO_RESOURCE_REQUIREMENTS_LIST ReqList =
	AllocateIoRequirementsList(ResCount,
				   PdoExtension->ParentFdoExtension->BaseBus,
				   PdoExtension->Slot.AsULONG);
    if (!ReqList) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Now build the resource requirements list */
    PIO_RESOURCE_DESCRIPTOR Res = ReqList->List[0].Descriptors;
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Current = &PdoExtension->Resources->Current[i];
	PIO_RESOURCE_DESCRIPTOR Limit = &PdoExtension->Resources->Limit[i];
	BOOLEAN Assigned = IsResourceAssigned(Current);
	BOOLEAN ValidLimit = IsValidResourceLimit(Limit);

	/* Write the resource requirement. If the current assigned resource has a
	 * non-zero base address, we make it a preferred resource (which precedes
	 * the alternative resource windows built from the resource limits). Otherwise,
	 * tell the PnP manager the acceptable resource window. */
	if (Assigned) {
	    if (ValidLimit) {
		Res->Option = IO_RESOURCE_PREFERRED;
	    }
	    Res->Type = Current->Type;
	    Res->ShareDisposition = Current->ShareDisposition;
	    Res->Flags = Current->Flags;
            Res->Generic.MinimumAddress = Current->Generic.Start;
            Res->Generic.MaximumAddress.QuadPart =
		Current->Generic.Start.QuadPart + Current->Generic.Length - 1;
	    Res->Generic.Length = Current->Generic.Length;
	    /* Since the preferred resource setting is a fixed window, we don't
	     * care about alignment. */
            Res->Generic.Alignment = 1;
	    Res++;
	}

        if (ValidLimit) {
	    *Res = *Limit;
	    assert(Res->Option == 0);
	    if (Assigned) {
		Res->Option = IO_RESOURCE_ALTERNATIVE;
	    }
	    Res++;
        }

	/* Populate a device private descriptor so we can know which array index this
	 * resource come from in PciComputeNewCurrentSettings. */
	if (Assigned || ValidLimit) {
	    RtlZeroMemory(Res, sizeof(IO_RESOURCE_DESCRIPTOR));
	    Res->Type = CmResourceTypeDevicePrivate;
	    Res->ShareDisposition = CmResourceShareDeviceExclusive;
	    Res->DevicePrivate.Data[0] = PciBarIndex;
	    Res->DevicePrivate.Data[1] = i;
	    Res++;
	}
    }

    ULONG MessageCount = 1;
    if (!PdoExtension->MsiInfo.ExtendedMessage) {
	MessageCount = 1UL << PdoExtension->MsiInfo.MessageInfo.MessageControl.MaxMsgCountShift;
    }
    for (ULONG i = 0; i < InterruptCount; i++) {
	Res->Type = CmResourceTypeInterrupt;
	Res->ShareDisposition = CmResourceShareDeviceExclusive;
	Res->Option = 0;
	Res->Flags = CM_RESOURCE_INTERRUPT_MESSAGE | CM_RESOURCE_INTERRUPT_POLICY_INCLUDED;
	if (PdoExtension->MsiInfo.ExtendedMessage) {
	    Res->Flags |= CM_RESOURCE_INTERRUPT_EXTENDED_MESSAGE;
	}
	Res->Interrupt.MinimumVector = CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN - MessageCount + 1;
	Res->Interrupt.MaximumVector = CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN;
	Res->Interrupt.AffinityPolicy = IrqPolicyOneCloseProcessor;
	Res->Interrupt.PriorityPolicy = IrqPriorityUndefined;
	Res->Interrupt.TargetedProcessors = (KAFFINITY)-1;
        Res++;
    }

    if (PdoExtension->AdditionalResourceCount != 0) {
	PPCI_CONFIGURATOR Configurator = &PciConfigurators[PdoExtension->HeaderType];
        Configurator->GetAdditionalResourceDescriptors(PdoExtension, Res);
        Res += PdoExtension->AdditionalResourceCount;
    }

    ASSERT(ReqList->ListSize == (ULONG_PTR)Res - (ULONG_PTR)ReqList);
    DPRINT1("Final resource count == %d\n",
	    (ULONG)(Res - ReqList->List[0].Descriptors));
    ASSERT((Res - ReqList->List[0].Descriptors) != 0);
    *Buffer = ReqList;

    return STATUS_SUCCESS;
}

static NTSTATUS PciPdoQueryResourceRequirements(IN PIRP Irp,
						IN PIO_STACK_LOCATION IoStackLocation,
						IN PPCI_PDO_EXTENSION PdoExtension)
{
    UNREFERENCED_PARAMETER(IoStackLocation);
    PAGED_CODE();
    PIO_RESOURCE_REQUIREMENTS_LIST RequirementsList = NULL;

    /* Check if the PDO has any resources, or at least an interrupt */
    if (PdoExtension->Resources || PdoExtension->MsiInfo.CapabilityOffset) {
	NTSTATUS Status = PcipBuildRequirementsList(PdoExtension,
						    &RequirementsList);
	if (!NT_SUCCESS(Status))
	    return Status;

	if (RequirementsList) {
	    PciDebugPrintIoResReqList(RequirementsList);
	}
    } else {
	/* There aren't any resources, so simply return NULL */
	DPRINT1("PciQueryRequirements returning NULL requirements list\n");
    }

    /* This call always succeeds (but maybe with no requirements) */
    Irp->IoStatus.Information = (ULONG_PTR)RequirementsList;
    return STATUS_SUCCESS;
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
					  IN PPCI_PDO_EXTENSION PdoExtension)
{
    UNREFERENCED_PARAMETER(IoStackLocation);

    /* Allocate a structure for the bus information */
    PPNP_BUS_INFORMATION BusInfo = ExAllocatePoolWithTag(NonPagedPool,
							 sizeof(PNP_BUS_INFORMATION),
							 'BicP');
    if (!BusInfo) {
	Irp->IoStatus.Information = 0;
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Write the correct GUID and bus type identifier, and fill the bus number */
    BusInfo->BusTypeGuid = GUID_BUS_TYPE_PCI;
    BusInfo->LegacyBusType = PCIBus;
    BusInfo->BusNumber = PdoExtension->ParentFdoExtension->BaseBus;
    Irp->IoStatus.Information = (ULONG_PTR)BusInfo;
    return STATUS_SUCCESS;
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
    UNUSED NTSTATUS Status;
    PDEVICE_OBJECT DeviceObject;
    PPCI_PDO_EXTENSION PdoExtension;
    ULONG SequenceNumber;

    /* Pick an atomically unique sequence number for this device */
    SequenceNumber = InterlockedIncrement(&PciPdoSequenceNumber);

    /* Create the standard PCI device name for a PDO */
    WCHAR DeviceName[32];
    _snwprintf(DeviceName, ARRAYSIZE(DeviceName), L"\\Device\\NTPNP_PCI%04d", SequenceNumber);
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

static VOID PciRemoveEntryFromList(IN PSINGLE_LIST_ENTRY ListHead,
				   IN PSINGLE_LIST_ENTRY Entry)
{
    /* We cannot remove the list head. */
    assert(ListHead != Entry);
    for (PSINGLE_LIST_ENTRY Prev = ListHead; Prev; Prev = Prev->Next) {
        if (Prev->Next == Entry) {
	    Prev->Next = Entry->Next;
	    Entry->Next = NULL;
        }
    }
    /* If we got here, Entry was not part of the list, which is an error. */
    assert(FALSE);
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
