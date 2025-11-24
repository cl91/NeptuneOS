/*
 * PROJECT:         ReactOS PCI Bus Driver
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            drivers/bus/pci/enum.c
 * PURPOSE:         PCI Bus/Device Enumeration
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

/* INCLUDES *******************************************************************/

#include "pcidrv.h"

/* GLOBALS ********************************************************************/

PCI_CONFIGURATOR PciConfigurators[] = {
    { Device_MassageHeaderForLimitsDetermination, Device_RestoreCurrent,
      Device_SaveLimits, Device_SaveCurrentSettings, Device_ChangeResourceSettings,
      Device_GetAdditionalResourceDescriptors, Device_ResetDevice },
    { PCIBridge_MassageHeaderForLimitsDetermination, PCIBridge_RestoreCurrent,
      PCIBridge_SaveLimits, PCIBridge_SaveCurrentSettings, PCIBridge_ChangeResourceSettings,
      PCIBridge_GetAdditionalResourceDescriptors, PCIBridge_ResetDevice },
    { Cardbus_MassageHeaderForLimitsDetermination, Cardbus_RestoreCurrent,
      Cardbus_SaveLimits, Cardbus_SaveCurrentSettings, Cardbus_ChangeResourceSettings,
      Cardbus_GetAdditionalResourceDescriptors, Cardbus_ResetDevice }
};

/* FUNCTIONS ******************************************************************/

NTSTATUS PciComputeNewCurrentSettings(IN PPCI_PDO_EXTENSION PdoExtension,
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
    CM_PARTIAL_RESOURCE_DESCRIPTOR ResourceArray[PCI_MAX_RESOURCE_COUNT];
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	ResourceArray[i].Type = CmResourceTypeNull;
    }

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
	    /* Base BAR resources */
	    case CmResourceTypePort:
	    case CmResourceTypeMemory:
		/* We don't need to do anything for BAR resources */
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

    /* Loop all the PCI function resources */
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	/* Get the current function resource descriptor, and the new one */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR CurrentDescriptor = &PciResources->Current[i];
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial = &ResourceArray[i];

	/* Prev is current during the first loop iteration */
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Prev = &PciResources->Current[(i == 0) ? 0 : (i-1)];

	/* Check if this new descriptor is different than the old one */
	if (((Partial->Type != CurrentDescriptor->Type) ||
	     (Partial->Type != CmResourceTypeNull)) &&
	    ((Partial->Generic.Start.QuadPart !=
	      CurrentDescriptor->Generic.Start.QuadPart) ||
	     (Partial->Generic.Length != CurrentDescriptor->Generic.Length))) {
	    /* Was there a range before? */
	    if (CurrentDescriptor->Type != CmResourceTypeNull) {
		/* Print it */
		DbgPrint("      Old range-\n");
		PciDebugPrintPartialResource(CurrentDescriptor);
	    } else {
		/* There was no range */
		DbgPrint("      Previously unset range\n");
	    }

	    /* Print new one */
	    DbgPrint("      changed to\n");
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

static VOID PciUpdateHardware(IN PPCI_PDO_EXTENSION PdoExtension,
			      IN PPCI_COMMON_HEADER PciData)
{
    /* Check if we're allowed to disable decodes */
    PciData->Command = PdoExtension->CommandEnables;
    if (!(PdoExtension->HackFlags & PCI_HACK_PRESERVE_COMMAND)) {
	/* Disable all decodes */
	PciData->Command &= ~(PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE |
			      PCI_ENABLE_BUS_MASTER | PCI_ENABLE_WRITE_AND_INVALIDATE);
    }

    /* Update the device configuration */
    PciData->Status = 0;
    PciWriteDeviceConfig(PdoExtension, PciData, 0, PCI_COMMON_HDR_LENGTH);

    /* Turn decodes back on */
    PciDecodeEnable(PdoExtension, TRUE, &PdoExtension->CommandEnables);
}

static PIO_RESOURCE_REQUIREMENTS_LIST PciAllocateIoRequirementsList(IN ULONG Count,
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

static PCM_RESOURCE_LIST PciAllocateCmResourceList(IN ULONG Count, IN ULONG BusNumber)
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

NTSTATUS PciQueryResources(IN PPCI_PDO_EXTENSION PdoExtension,
			   OUT PCM_RESOURCE_LIST *Buffer)
{
    PAGED_CODE();
    USHORT BridgeControl, PciCommand;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial, Resource;
#if DBG
    PCM_PARTIAL_RESOURCE_DESCRIPTOR LastResource;
#endif
    PCM_RESOURCE_LIST ResourceList;

    /* Assume failure */
    ULONG Count = 0;
    BOOLEAN HaveVga = FALSE;
    *Buffer = NULL;

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

    /* Loop maximum possible descriptors */
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
	PciReadDeviceConfig(PdoExtension, &BridgeControl,
			    FIELD_OFFSET(PCI_COMMON_HEADER, Type1.BridgeControl),
			    sizeof(USHORT));
	if (BridgeControl & PCI_ENABLE_BRIDGE_VGA) {
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
    ResourceList = PciAllocateCmResourceList(Count,
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
    *Buffer = ResourceList;
    return STATUS_SUCCESS;
}

NTSTATUS PciQueryTargetDeviceRelations(IN PPCI_PDO_EXTENSION PdoExtension,
				       IN OUT PDEVICE_RELATIONS *pDeviceRelations)
{
    PAGED_CODE();
    PDEVICE_RELATIONS DeviceRelations;

    /* If there were existing relations, free them */
    if (*pDeviceRelations)
	ExFreePoolWithTag(*pDeviceRelations, 0);

    /* Allocate a new structure for the relations */
    DeviceRelations = ExAllocatePoolWithTag(NonPagedPool, sizeof(DEVICE_RELATIONS),
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

NTSTATUS PciQueryEjectionRelations(IN PPCI_PDO_EXTENSION PdoExtension,
				   IN OUT PDEVICE_RELATIONS *pDeviceRelations)
{
    UNREFERENCED_PARAMETER(PdoExtension);
    UNREFERENCED_PARAMETER(pDeviceRelations);

    /* Not yet implemented */
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * Returns TRUE if the given IO resource descriptor that describes the port/memory
 * range limits (which we obtained from probing the device during enumeration) is
 * valid for reporting to the PNP manager. We only report a resource descriptor for
 * port or memory windows that have a non-zero length.
 */
FORCEINLINE BOOLEAN IsValidResource(IN PIO_RESOURCE_DESCRIPTOR Limit)
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

static NTSTATUS PciBuildRequirementsList(IN PPCI_PDO_EXTENSION PdoExtension,
					 IN PPCI_COMMON_HEADER PciData,
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

    /* Find out how many resource descriptors we need */
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	if (IsValidResource(&PdoExtension->Resources->Limit[i])) {
	    /* For each valid resource we generate the follwing resource descriptors:
	     * first the preferred resource descriptor, if the resource has been
	     * assigned (usually by the boot firmware), followed by the alternative
	     * resource requirement from the range limit we probed during device
	     * enumeration, followed by a CmResourceTypeDevicePrivate indicating
	     * the corresponding BAR index. Note this relies on the PNP manager
	     * respecting the order of the IO resource descriptors list. */
	    ResCount += 2;
	    if (IsResourceAssigned(&PdoExtension->Resources->Current[i])) {
		ResCount++;
	    }
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
	PciAllocateIoRequirementsList(ResCount,
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

        if (!IsValidResource(Limit)) {
            continue;
        }

	/* Write the resource requirement. If the current assigned resource has a
	 * non-zero base address, we make it a preferred resource. Otherwise, tell
	 * the PnP manager the acceptable resource window. */
        *Res = *Limit;
	assert(Res->Option == 0);
        Res->ShareDisposition = CmResourceShareDeviceExclusive;
        /* Set the positive decode bit and 16 bit decode for all IO port resources. */
        if (Limit->Type == CmResourceTypePort) {
            Res->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE | CM_RESOURCE_PORT_16_BIT_DECODE;
        }
	if (IsResourceAssigned(Current)) {
	    Res[1] = *Res;
	    Res[1].Option = IO_RESOURCE_ALTERNATIVE;
	    Res->Option = IO_RESOURCE_PREFERRED;
            Res->Generic.MinimumAddress = Current->Generic.Start;
            Res->Generic.MaximumAddress.QuadPart =
		Res->Generic.MinimumAddress.QuadPart + Res->Generic.Length - 1;
	    /* Since the preferred resource setting is a fixed window, we don't
	     * care about alignment. */
            Res->Generic.Alignment = 1;
	    Res++;
	}
	Res++;
	/* Populate a device private descriptor so we can know which BAR this resource
	 * come from in PciComputeNewCurrentSettings. */
	RtlZeroMemory(Res, sizeof(IO_RESOURCE_DESCRIPTOR));
	Res->Type = CmResourceTypeDevicePrivate;
	Res->ShareDisposition = CmResourceShareDeviceExclusive;
	Res->DevicePrivate.Data[0] = PciBarIndex;
	Res->DevicePrivate.Data[1] = i;
	Res++;
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
	Res->Interrupt.MinimumVector = CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN - MessageCount + 1;
	Res->Interrupt.MaximumVector = CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN;
	Res->Interrupt.AffinityPolicy = IrqPolicyOneCloseProcessor;
	Res->Interrupt.PriorityPolicy = IrqPriorityUndefined;
	Res->Interrupt.TargetedProcessors = (KAFFINITY)-1;
        Res++;
    }

    if (PdoExtension->AdditionalResourceCount != 0) {
	PCI_CONFIGURATOR_CONTEXT Context = {
	    .PdoExtension = PdoExtension,
	};
	PPCI_CONFIGURATOR Configurator = &PciConfigurators[PdoExtension->HeaderType];
        Configurator->GetAdditionalResourceDescriptors(&Context,
						       PciData,
						       Res);
        Res += PdoExtension->AdditionalResourceCount;
    }

    ASSERT(ReqList->ListSize == (ULONG_PTR)Res - (ULONG_PTR)ReqList);
    DPRINT1("Final resource count == %d\n",
	    (ULONG)(Res - ReqList->List[0].Descriptors));
    ASSERT((Res - ReqList->List[0].Descriptors) != 0);
    *Buffer = ReqList;

    return STATUS_SUCCESS;
}

NTSTATUS PciQueryRequirements(IN PPCI_PDO_EXTENSION PdoExtension,
			      IN OUT PIO_RESOURCE_REQUIREMENTS_LIST *RequirementsList)
{
    PAGED_CODE();
    *RequirementsList = NULL;

    /* Check if the PDO has any resources, or at least an interrupt */
    if (PdoExtension->Resources || PdoExtension->MsiInfo.CapabilityOffset) {
	/* Read the current PCI header */
	PCI_COMMON_HEADER PciHeader;
	PciReadDeviceConfig(PdoExtension, &PciHeader, 0, PCI_COMMON_HDR_LENGTH);

	/* Use it to build a list of requirements */
	NTSTATUS Status = PciBuildRequirementsList(PdoExtension,
						   &PciHeader,
						   RequirementsList);
	if (!NT_SUCCESS(Status))
	    return Status;

	if (*RequirementsList) {
	    PciDebugPrintIoResReqList(*RequirementsList);
	}
    } else {
	/* There aren't any resources, so simply return NULL */
	DPRINT1("PciQueryRequirements returning NULL requirements list\n");
    }

    /* This call always succeeds (but maybe with no requirements) */
    return STATUS_SUCCESS;
}

/*
 * 7. The IO/MEM/Busmaster decodes are disabled for the device.
 * 8. The PCI bus driver sets the operating mode bits of the Programming
 *    Interface byte to switch the controller to native mode.
 *
 *    Important: When the controller is set to native mode, it must quiet itself
 *    and must not decode I/O resources or generate interrupts until the operating
 *    system has enabled the ports in the PCI configuration header.
 *    The IO/MEM/BusMaster bits will be disabled before the mode change, but it
 *    is not possible to disable interrupts on the device. The device must not
 *    generate interrupts (either legacy or native mode) while the decodes are
 *    disabled in the command register.
 *
 *    This operation is expected to be instantaneous and the operating system does
 *    not stall afterward. It is also expected that the interrupt pin register in
 *    the PCI Configuration space for this device is accurate. The operating system
 *    re-reads this data after previously ignoring it.
 */
static BOOLEAN PciConfigureIdeController(IN PPCI_PDO_EXTENSION PdoExtension,
					 IN PPCI_COMMON_HEADER PciData,
					 IN BOOLEAN Initial)
{
    UCHAR MasterMode, SlaveMode, MasterFixed, SlaveFixed, ProgIf, NewProgIf;
    BOOLEAN Switched;
    USHORT Command;

    /* Assume it won't work */
    Switched = FALSE;

    /* Get master and slave current settings, and programmability flag */
    ProgIf = PciData->ProgIf;
    MasterMode = (ProgIf & 1) == 1;
    MasterFixed = (ProgIf & 2) == 0;
    SlaveMode = (ProgIf & 4) == 4;
    SlaveFixed = (ProgIf & 8) == 0;

    /*
     * In order for Windows XP SP1 and Windows Server 2003 to switch an ATA
     * controller from compatible mode to native mode, the following must be
     * true:
     *
     * - The controller must indicate in its programming interface that both channels
     *   can be switched to native mode. Windows XP SP1 and Windows Server 2003 do
     *   not support switching only one IDE channel to native mode. See the PCI IDE
     *   Controller Specification Revision 1.0 for details.
     */
    if (MasterMode != SlaveMode || MasterFixed != SlaveFixed) {
	/* Windows does not support this configuration, fail */
	DPRINT1("PCI: Warning unsupported IDE controller configuration for "
		"VEN_%04x&DEV_%04x!",
		PdoExtension->VendorId, PdoExtension->DeviceId);
	return Switched;
    }

    /* Check if the controller is already in native mode */
    if (MasterMode && SlaveMode) {
	/* Check if I/O decodes should be disabled */
	if (Initial || PdoExtension->IoSpaceUnderNativeIdeControl) {
	    /* Read the current command */
	    PciReadDeviceConfig(PdoExtension, &Command,
				FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));

	    /* Disable I/O space decode */
	    Command &= ~PCI_ENABLE_IO_SPACE;

	    /* Update new command in PCI IDE controller */
	    PciWriteDeviceConfig(PdoExtension, &Command,
				 FIELD_OFFSET(PCI_COMMON_HEADER, Command),
				 sizeof(USHORT));

	    /* Save updated command value */
	    PciData->Command = Command;
	}

	/* The controller is now in native mode */
	Switched = TRUE;
    } else if (!MasterFixed && !SlaveFixed &&
	       PdoExtension->BIOSAllowsIDESwitchToNativeMode &&
	       !(PdoExtension->HackFlags & PCI_HACK_DISABLE_IDE_NATIVE_MODE)) {
	/* Turn off decodes */
	PciDecodeEnable(PdoExtension, FALSE, NULL);

	/* Update the current command */
	PciReadDeviceConfig(PdoExtension, &PciData->Command,
			    FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));

	/* Enable native mode */
	ProgIf = PciData->ProgIf | 5;
	PciWriteDeviceConfig(PdoExtension, &ProgIf,
			     FIELD_OFFSET(PCI_COMMON_HEADER, ProgIf), sizeof(UCHAR));

	/* Verify the setting "stuck" */
	PciReadDeviceConfig(PdoExtension, &NewProgIf,
			    FIELD_OFFSET(PCI_COMMON_HEADER, ProgIf), sizeof(UCHAR));
	if (NewProgIf == ProgIf) {
	    /* Update the header and PDO data with the new programming mode */
	    PciData->ProgIf = ProgIf;
	    PdoExtension->ProgIf = NewProgIf;

	    /* Clear the first four BARs to reset current BAR settings */
	    PciData->Type0.BaseAddresses[0] = 0;
	    PciData->Type0.BaseAddresses[1] = 0;
	    PciData->Type0.BaseAddresses[2] = 0;
	    PciData->Type0.BaseAddresses[3] = 0;
	    PciWriteDeviceConfig(PdoExtension, PciData->Type0.BaseAddresses,
				 FIELD_OFFSET(PCI_COMMON_HEADER, Type0.BaseAddresses),
				 4 * sizeof(ULONG));

	    /* Re-read the BARs to have the latest data for native mode IDE */
	    PciReadDeviceConfig(PdoExtension, PciData->Type0.BaseAddresses,
				FIELD_OFFSET(PCI_COMMON_HEADER, Type0.BaseAddresses),
				4 * sizeof(ULONG));

	    /* Re-read the interrupt pin used for native mode IDE */
	    PciReadDeviceConfig(PdoExtension, &PciData->Type0.InterruptPin,
				FIELD_OFFSET(PCI_COMMON_HEADER, Type0.InterruptPin),
				sizeof(UCHAR));

	    /* The IDE Controller is now in native mode */
	    Switched = TRUE;
	} else {
	    /* Settings did not work, fail */
	    DPRINT1("PCI: Warning failed switch to native mode for IDE controller "
		    "VEN_%04x&DEV_%04x!",
		    PciData->VendorID, PciData->DeviceID);
	}
    }

    /* Return whether or not native mode was enabled on the IDE controller */
    return Switched;
}

static VOID PciApplyHacks(IN PPCI_FDO_EXTENSION DeviceExtension,
			  IN PPCI_COMMON_HEADER PciData,
			  IN PCI_SLOT_NUMBER SlotNumber,
			  IN ULONG OperationType,
			  PPCI_PDO_EXTENSION PdoExtension)
{
    ULONG LegacyBaseAddress;
    USHORT Command;
    UCHAR RegValue;

    UNREFERENCED_PARAMETER(SlotNumber);

    /* Check what kind of hack operation this is */
    switch (OperationType) {
    case PCI_HACK_FIXUP_BEFORE_CONFIGURATION:
	/*
         * This is mostly concerned with fixing up incorrect class data that can
         * exist on certain PCI hardware before the 2.0 spec was ratified.
         */

	/* Note that the i82375 PCI/EISA and the i82378 PCI/ISA bridges that
	 * are present on certain DEC/NT Alpha machines are pre-PCI 2.0 devices
	 * and appear as non-classified, so their correct class/subclass data
	 * is written here instead.
	 */
	if ((PciData->VendorID == 0x8086) &&
	    ((PciData->DeviceID == 0x482) || (PciData->DeviceID == 0x484))) {
	    /* Note that 0x482 is the i82375 (EISA), 0x484 is the i82378 (ISA) */
	    PciData->SubClass = PciData->DeviceID == 0x482 ? PCI_SUBCLASS_BR_EISA :
		PCI_SUBCLASS_BR_ISA;
	    PciData->BaseClass = PCI_CLASS_BRIDGE_DEV;

	    /*
	     * Because the software is modifying the actual header data from
	     * the BIOS, this flag tells the driver to ignore failures when
	     * comparing the original BIOS data with the PCI data.
	     */
	    if (PdoExtension)
		PdoExtension->ExpectedWritebackFailure = TRUE;
	}

	/* Note that in this case, an immediate return is issued */
	return;

    case PCI_HACK_FIXUP_AFTER_CONFIGURATION:
	/*
         * This is concerned with setting up interrupts correctly for native IDE
         * mode, but will also handle broken VGA decoding on older bridges as
         * well as a PAE-specific hack for certain Compaq Hot-Plug Controllers.
         */

	/* There should always be a PDO extension passed in */
	ASSERT(PdoExtension);

	/*
	 * On the OPTi Viper-M IDE controller, Linux doesn't support IDE-DMA
	 * and FreeBSD bug reports indicate that the system crashes when the
	 * feature is enabled (so it's disabled on that OS as well). In the
	 * NT PCI Bus Driver, it seems Microsoft too, completely disables
	 * Native IDE functionality on this controller, so it would seem OPTi
	 * simply frelled up this controller.
	 */
	if ((PciData->VendorID == 0x1045) && (PciData->DeviceID != 0xC621)) {
	    /* Disable native mode */
	    PciData->ProgIf &= ~5;
	    PciData->Type0.InterruptPin = 0;

	    /*
	     * Because the software is modifying the actual header data from
	     * the BIOS, this flag tells the driver to ignore failures when
	     * comparing the original BIOS data with the PCI data.
	     */
	    PdoExtension->ExpectedWritebackFailure = TRUE;
	} else if ((PciData->BaseClass == PCI_CLASS_MASS_STORAGE_CTLR) &&
		   (PciData->SubClass == PCI_SUBCLASS_MSC_IDE_CTLR)) {
	    /* For other IDE controllers, start out in compatible mode */
	    PdoExtension->BIOSAllowsIDESwitchToNativeMode = FALSE;

	    /*
	     * Evaluate the ACPI NATA method to see if the platform supports
	     * native ATA mode. See the section "BIOS and Platform Prerequisites
	     * for Switching a Native-Mode-Capable Controller" in the Storage
	     * section of the Windows Driver Kit for more details:
	     *
	     * 5. For each ATA controller enumerated, the PCI bus driver checks
	     *    the Programming Interface register of the IDE controller to
	     *    see if it supports switching both channels to native mode.
	     * 6. The PCI bus driver checks whether the BIOS/platform supports
	     *    switching the controller by checking the NATA method described
	     *    earlier in this article.
	     *
	     *    If an ATA controller does not indicate that it is native
	     *    mode-capable, or if the BIOS NATA control method is missing
	     *    or does not list that device, the PCI bus driver does not
	     *    switch the controller and it is assigned legacy resources.
	     *
	     *  If both the controller and the BIOS indicate that the controller
	     *  can be switched, the process of switching the controller begins
	     *  with the next step.
	     */
	    if (PciIsSlotPresentInParentMethod(PdoExtension, 'ATAN')) {
		/* The platform supports it, remember that */
		PdoExtension->BIOSAllowsIDESwitchToNativeMode = TRUE;

		/*
		 * Now switch the controller into native mode if both channels
		 * support native IDE mode. See "How Windows Switches an ATA
		 * Controller to Native Mode" in the Storage section of the
		 * Windows Driver Kit for more details.
		 */
		PdoExtension->IDEInNativeMode = PciConfigureIdeController(PdoExtension,
									  PciData, TRUE);
	    }

	    /* Is native mode enabled after all? */
	    if ((PciData->ProgIf & 5) != 5) {
		/* Compatible mode, so force ISA-style IRQ14 and IRQ 15 */
		PciData->Type0.InterruptPin = 0;
	    }
	}
	break;

    case PCI_HACK_FIXUP_BEFORE_UPDATE:
	/*
         * This is called whenever resources are changed and hardware needs to be
         * updated. It is concerned with two highly specific erratas on an IBM
         * hot-plug docking bridge used on the Thinkpad 600 Series and on Intel's
         * ICH PCI Bridges.
         */

	/* There should always be a PDO extension passed in */
	ASSERT(PdoExtension);

	/* Is this an IBM 20H2999 PCI Docking Bridge, used on Thinkpads? */
	if ((PdoExtension->VendorId == 0x1014) && (PdoExtension->DeviceId == 0x95)) {
	    /* Read the current command */
	    PciReadDeviceConfig(PdoExtension, &Command,
				FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));

	    /* Turn off the decodes */
	    PciDecodeEnable(PdoExtension, FALSE, &Command);

	    /* Apply the required IBM workaround */
	    PciReadDeviceConfig(PdoExtension, &RegValue, 0xE0, sizeof(UCHAR));
	    RegValue &= ~2;
	    RegValue |= 1;
	    PciWriteDeviceConfig(PdoExtension, &RegValue, 0xE0, sizeof(UCHAR));

	    /* Restore the command to its original value */
	    PciWriteDeviceConfig(PdoExtension, &Command,
				 FIELD_OFFSET(PCI_COMMON_HEADER, Command),
				 sizeof(USHORT));
	}

	/*
	 * Check for Intel ICH PCI-to-PCI (i82801) bridges (used on the i810,
	 * i820, i840, i845 Chipsets) that have subtractive decode enabled,
	 * and whose hack flags do not specify that this support is broken.
	 */
	if ((PdoExtension->HeaderType == PCI_BRIDGE_TYPE) &&
	    (PdoExtension->Dependent.Type1.SubtractiveDecode) &&
	    ((PdoExtension->VendorId == 0x8086) &&
	     ((PdoExtension->DeviceId == 0x2418) || (PdoExtension->DeviceId == 0x2428) ||
	      (PdoExtension->DeviceId == 0x244E) ||
	      (PdoExtension->DeviceId == 0x2448))) &&
	    !(PdoExtension->HackFlags & PCI_HACK_BROKEN_SUBTRACTIVE_DECODE)) {
	    /*
	     * The positive decode window shouldn't be used, these values are
	     * normally all read-only or initialized to 0 by the BIOS, but
	     * it appears Intel doesn't do this, so the PCI Bus Driver will
	     * do it in software instead. Note that this is used to prevent
	     * certain non-compliant PCI devices from breaking down due to the
	     * fact that these ICH bridges have a known "quirk" (which Intel
	     * documents as a known "erratum", although it's not not really
	     * an ICH bug since the PCI specification does allow for it) in
	     * that they will sometimes send non-zero addresses during special
	     * cycles (ie: non-zero data during the address phase). These
	     * broken PCI cards will mistakenly attempt to claim the special
	     * cycle and corrupt their I/O and RAM ranges. Again, in Intel's
	     * defense, the PCI specification only requires stable data, not
	     * necessarily zero data, during the address phase.
	     */
	    PciData->Type1.MemoryBase = 0xFFFF;
	    PciData->Type1.PrefetchBase = 0xFFFF;
	    PciData->Type1.IOBase = 0xFF;
	    PciData->Type1.IOLimit = 0;
	    PciData->Type1.MemoryLimit = 0;
	    PciData->Type1.PrefetchLimit = 0;
	    PciData->Type1.PrefetchBaseUpper32 = 0;
	    PciData->Type1.PrefetchLimitUpper32 = 0;
	    PciData->Type1.IOBaseUpper16 = 0;
	    PciData->Type1.IOLimitUpper16 = 0;
	}
	break;

    default:
	return;
    }

    /* Finally, also check if this is this a CardBUS device? */
    if (PCI_CONFIGURATION_TYPE(PciData) == PCI_CARDBUS_BRIDGE_TYPE) {
	/*
         * At offset 44h the LegacyBaseAddress is stored, which is cleared by
         * ACPI-aware versions of Windows, to disable legacy-mode I/O access to
         * CardBus controllers. For more information, see "Supporting CardBus
         * Controllers under ACPI" in the "CardBus Controllers and Windows"
         * Whitepaper on WHDC.
         */
	LegacyBaseAddress = 0;
	PciWriteDeviceConfig(PdoExtension, &LegacyBaseAddress,
			     sizeof(PCI_COMMON_HEADER) + sizeof(ULONG), sizeof(ULONG));
    }
}

static BOOLEAN PcipIsSameDevice(IN PPCI_PDO_EXTENSION DeviceExtension,
				IN PPCI_COMMON_HEADER PciData)
{
    BOOLEAN IdMatch, RevMatch, SubsysMatch;
    ULONGLONG HackFlags = DeviceExtension->HackFlags;

    /* Check if the IDs match */
    IdMatch = (PciData->VendorID == DeviceExtension->VendorId) &&
	(PciData->DeviceID == DeviceExtension->DeviceId);
    if (!IdMatch)
	return FALSE;

    /* If the device has a valid revision, check if it matches */
    RevMatch = (HackFlags & PCI_HACK_NO_REVISION_AFTER_D3) ||
	(PciData->RevisionID == DeviceExtension->RevisionId);
    if (!RevMatch)
	return FALSE;

    /* For multifunction devices, this is enough to assume they're the same */
    if (PCI_MULTIFUNCTION_DEVICE(PciData))
	return TRUE;

    /* For bridge devices, there's also nothing else that can be checked */
    if (DeviceExtension->BaseClass == PCI_CLASS_BRIDGE_DEV)
	return TRUE;

    /* Devices, on the other hand, have subsystem data that can be compared */
    SubsysMatch = (HackFlags &
		   (PCI_HACK_NO_SUBSYSTEM | PCI_HACK_NO_SUBSYSTEM_AFTER_D3)) ||
	((DeviceExtension->SubsystemVendorId == PciData->Type0.SubVendorID) &&
	 (DeviceExtension->SubsystemId == PciData->Type0.SubSystemID));
    return SubsysMatch;
}

static BOOLEAN PciSkipThisFunction(IN PPCI_COMMON_HEADER PciData,
				   IN PCI_SLOT_NUMBER Slot,
				   IN UCHAR OperationType,
				   IN ULONGLONG HackFlags)
{
    do {
	/* Check if this is device enumeration */
	if (OperationType == PCI_SKIP_DEVICE_ENUMERATION) {
	    /* Check if there's a hackflag saying not to enumerate this device */
	    if (HackFlags & PCI_HACK_NO_ENUM_AT_ALL)
		break;

	    /* Check if this is the high end of a double decker device */
	    if ((HackFlags & PCI_HACK_DOUBLE_DECKER) &&
		(Slot.Bits.DeviceNumber >= 16)) {
		/* It belongs to the same device, so skip it */
		DPRINT1("    Device (Ven %04x Dev %04x (d=0x%x, f=0x%x)) is a ghost.\n",
			PciData->VendorID, PciData->DeviceID, Slot.Bits.DeviceNumber,
			Slot.Bits.FunctionNumber);
		break;
	    }
	} else if (OperationType == PCI_SKIP_RESOURCE_ENUMERATION) {
	    /* Resource enumeration, check for a hackflag saying not to do it */
	    if (HackFlags & PCI_HACK_ENUM_NO_RESOURCE)
		break;
	} else {
	    /* Logic error in the driver */
	    ASSERTMSG("PCI Skip Function - Operation type unknown.\n", FALSE);
	}

	/* Check for legacy bridges during resource enumeration */
	if ((PciData->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
	    (PciData->SubClass <= PCI_SUBCLASS_BR_MCA) &&
	    (OperationType == PCI_SKIP_RESOURCE_ENUMERATION)) {
	    /* Their resources are not enumerated, only PCI and Cardbus/PCMCIA */
	    break;
	} else if (PciData->BaseClass == PCI_CLASS_NOT_DEFINED) {
	    /* Undefined base class (usually a PCI BIOS/ROM bug) */
	    DPRINT1("    Vendor %04x, Device %04x has class code of "
		    "PCI_CLASS_NOT_DEFINED\n",
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
		break;
	}

	/* Other normal PCI cards and bridges are enumerated */
	if (PCI_CONFIGURATION_TYPE(PciData) <= PCI_CARDBUS_BRIDGE_TYPE)
	    return FALSE;
    } while (FALSE);

    /* Hit one of the known bugs/hackflags, or this is a new kind of PCI unit */
    DPRINT1("   Device skipped (not enumerated).\n");
    return TRUE;
}

static VOID PciGetEnhancedCapabilities(IN PPCI_PDO_EXTENSION PdoExtension,
				       IN PPCI_COMMON_HEADER PciData)
{
    PAGED_CODE();

    /* Assume no known wake level */
    PdoExtension->PowerState.DeviceWakeLevel = PowerDeviceUnspecified;

    /* Make sure the device has capabilities */
    if (!(PciData->Status & PCI_STATUS_CAPABILITIES_LIST)) {
	/* If it doesn't, there will be no power management */
	PdoExtension->CapabilitiesPtr = 0;
	PdoExtension->HackFlags |= PCI_HACK_NO_PM_CAPS;
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
	PdoExtension->HackFlags |= PCI_HACK_NO_PM_CAPS;
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
    if (!(PdoExtension->HackFlags & PCI_HACK_NO_PM_CAPS)) {
	/* Query if this device supports power management */
	PCI_PM_CAPABILITY PowerCapabilities;
	if (!PciReadDeviceCapability(PdoExtension, PdoExtension->CapabilitiesPtr,
				     PCI_CAPABILITY_ID_POWER_MANAGEMENT,
				     &PowerCapabilities.Header,
				     sizeof(PCI_PM_CAPABILITY))) {
	    /* No power management, so act as if it had the hackflag set */
	    DPRINT1("No PM caps, disabling PM\n");
	    PdoExtension->HackFlags |= PCI_HACK_NO_PM_CAPS;
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
    if (PdoExtension->HackFlags & PCI_HACK_NO_PM_CAPS) {
	/* Then guess the current state based on whether the decodes are on */
	PdoExtension->PowerState.CurrentDeviceState = PciData->Command &
	    (PCI_ENABLE_IO_SPACE |
	     PCI_ENABLE_MEMORY_SPACE |
	     PCI_ENABLE_BUS_MASTER) ?
	    PowerDeviceD0 :
	    PowerDeviceD3;
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

	case PCI_CAPABILITY_ID_MSIX:
	    Name = "MSI-X";
	    Size = sizeof(PCI_MSIX_CAPABILITY);
	    break;

	    /* This driver doesn't really use anything other than that */
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
		DPRINT1("- Failed to read capability data. ***\n");
		ASSERT(TempOffset == CapOffset);
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

static VOID PciWriteLimitsAndRestoreCurrent(IN PVOID Reserved, IN PVOID Context2)
{
    PPCI_CONFIGURATOR_CONTEXT Context = Context2;
    PPCI_COMMON_HEADER PciData, Current;
    PPCI_PDO_EXTENSION PdoExtension;

    UNREFERENCED_PARAMETER(Reserved);

    /* Grab all parameters from the context */
    PdoExtension = Context->PdoExtension;
    Current = Context->Current;
    PciData = Context->PciData;

    /* Write the limit discovery header */
    PciWriteDeviceConfig(PdoExtension, PciData, 0, PCI_COMMON_HDR_LENGTH);

    /* Now read what the device indicated the limits are */
    PciReadDeviceConfig(PdoExtension, PciData, 0, PCI_COMMON_HDR_LENGTH);

    /* Then write back the original configuration header */
    PciWriteDeviceConfig(PdoExtension, Current, 0, PCI_COMMON_HDR_LENGTH);

    /* Copy back the original command that was saved in the context */
    Current->Command = Context->Command;
    if (Context->Command) {
	/* Program it back into the device */
	PciWriteDeviceConfig(PdoExtension, &Context->Command,
			     FIELD_OFFSET(PCI_COMMON_HEADER, Command), sizeof(USHORT));
    }

    /* Copy back the original status that was saved as well */
    Current->Status = Context->Status;

    /* Call the configurator to restore any other data that might've changed */
    Context->Configurator->RestoreCurrent(Context);
}

static NTSTATUS PcipGetFunctionLimits(IN PPCI_CONFIGURATOR_CONTEXT Context)
{
    PAGED_CODE();
    PPCI_CONFIGURATOR Configurator;
    PPCI_COMMON_HEADER PciData, Current;
    PPCI_PDO_EXTENSION PdoExtension;
    ULONG Offset;

    /* Grab all parameters from the context */
    PdoExtension = Context->PdoExtension;
    Current = Context->Current;
    PciData = Context->PciData;

    /* Save the current PCI Command and Status word */
    Context->Status = Current->Status;
    Context->Command = Current->Command;

    /* Now that they're saved, clear the status, and disable all decodes */
    Current->Status = 0;
    Current->Command &= ~(PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE |
			  PCI_ENABLE_BUS_MASTER);

    /* Make a copy of the current PCI configuration header (with decodes off) */
    RtlCopyMemory(PciData, Current, PCI_COMMON_HDR_LENGTH);

    /* Locate the correct resource configurator for this type of device */
    Configurator = &PciConfigurators[PdoExtension->HeaderType];
    Context->Configurator = Configurator;

    /* Initialize it, which will typically setup the BARs for limit discovery */
    Configurator->Initialize(Context);

    PciWriteLimitsAndRestoreCurrent(PdoExtension, Context);

    /*
     * Check if it's valid to compare the headers to see if limit discovery mode
     * has properly exited (the expected case is that the PCI header would now
     * be equal to what it was before). In some cases, it is known that this will
     * fail, because during PciApplyHacks (among other places), software hacks
     * had to be applied to the header, which the hardware-side will not see, and
     * thus the headers would appear "different".
     */
    if (!PdoExtension->ExpectedWritebackFailure) {
	/* Read the current PCI header now, after discovery has completed */
	PciReadDeviceConfig(PdoExtension, PciData + 1, 0, PCI_COMMON_HDR_LENGTH);

	/* Check if the current header at entry, is equal to the header now */
	Offset = RtlCompareMemory(PciData + 1, Current, PCI_COMMON_HDR_LENGTH);
	if (Offset != PCI_COMMON_HDR_LENGTH) {
	    /* It's not, which means configuration somehow changed, dump this */
	    DPRINT1("PCI - CFG space write verify failed at offset 0x%x\n", Offset);
	    PciDebugDumpCommonConfig(PciData + 1);
	    DPRINT1("----------\n");
	    PciDebugDumpCommonConfig(Current);
	}
    }

    /* This PDO should not already have resources, since this is only done once */
    ASSERT(PdoExtension->Resources == NULL);

    /* Allocate the structure that will hold the discovered resources and limits */
    PdoExtension->Resources = ExAllocatePoolWithTag(NonPagedPool,
						    sizeof(PCI_FUNCTION_RESOURCES),
						    'BicP');
    if (!PdoExtension->Resources)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Clear it out for now */
    RtlZeroMemory(PdoExtension->Resources, sizeof(PCI_FUNCTION_RESOURCES));

    /* Now call the configurator, which will first store the limits... */
    Configurator->SaveLimits(Context);

    /* ...and then store the current resources being used */
    Configurator->SaveCurrentSettings(Context);

    /* Loop all the limit descriptors and check if we have at least one resource */
    BOOLEAN HasResource = FALSE;
    for (ULONG i = 0; i < PCI_MAX_RESOURCE_COUNT; i++) {
	if (PdoExtension->Resources->Limit[i].Type != CmResourceTypeNull) {
	    HasResource = TRUE;
	    break;
	}
    }
    if (!HasResource) {
	/* This means the descriptor is NULL, which means discovery failed */
	DPRINT1("No PCI resource discovered!\n");

	/* No resources will be assigned for the device */
	ExFreePoolWithTag(PdoExtension->Resources, 'BicP');
	PdoExtension->Resources = NULL;
    }

    /* Return success here, even if the device has no assigned resources */
    return STATUS_SUCCESS;
}

static NTSTATUS PciGetFunctionLimits(IN PPCI_PDO_EXTENSION PdoExtension,
				     IN PPCI_COMMON_HEADER Current,
				     IN ULONGLONG HackFlags)
{
    PAGED_CODE();

    /* Do the hackflags indicate this device should be skipped? */
    if (PciSkipThisFunction(Current, PdoExtension->Slot, PCI_SKIP_RESOURCE_ENUMERATION,
			    HackFlags)) {
	/* Do not process its resources */
	return STATUS_SUCCESS;
    }

    /* Allocate a buffer to hold two PCI configuration headers */
    PPCI_COMMON_HEADER PciData = ExAllocatePoolWithTag(NonPagedPool,
						       2 * PCI_COMMON_HDR_LENGTH, 'BicP');
    if (!PciData)
	return STATUS_INSUFFICIENT_RESOURCES;

    /* Set up the context for the resource enumeration, and do it */
    PCI_CONFIGURATOR_CONTEXT Context = {
	.Current = Current,
	.PciData = PciData,
	.PdoExtension = PdoExtension
    };
    NTSTATUS Status = PcipGetFunctionLimits(&Context);

    /* Enumeration is completed, free the PCI headers and return the status */
    ExFreePoolWithTag(PciData, 0);
    return Status;
}

static VOID PciProcessBus(IN PPCI_FDO_EXTENSION DeviceExtension)
{
    PAGED_CODE();
    PPCI_PDO_EXTENSION PdoExtension;
    PDEVICE_OBJECT PhysicalDeviceObject;

    /* Get the PDO Extension */
    PhysicalDeviceObject = DeviceExtension->PhysicalDeviceObject;
    PdoExtension = (PPCI_PDO_EXTENSION)PhysicalDeviceObject->DeviceExtension;

    /* Cheeck if this is the root bus */
    if (!PCI_IS_ROOT_FDO(DeviceExtension)) {
	/* Not really handling this year */
	UNIMPLEMENTED_DBGBREAK();

	/* Check for PCI bridges with the ISA bit set, or required */
	if ((PdoExtension) && (PciClassifyDeviceType(PdoExtension) == PciTypePciBridge) &&
	    ((PdoExtension->Dependent.Type1.IsaBitRequired) ||
	     (PdoExtension->Dependent.Type1.IsaBitSet))) {
	    /* We'll need to do some legacy support */
	    UNIMPLEMENTED_DBGBREAK();
	}
    } else {
	/* Scan all of the root bus' children bridges */
	for (PdoExtension = DeviceExtension->ChildBridgePdoList; PdoExtension;
	     PdoExtension = PdoExtension->NextBridge) {
	    /* Find any that have the VGA decode bit on */
	    if (PdoExtension->Dependent.Type1.VgaBitSet) {
		/* Again, some more legacy support we'll have to do */
		UNIMPLEMENTED_DBGBREAK();
	    }
	}
    }

    /* Check for ACPI systems where the OS assigns bus numbers */
    if (PciAssignBusNumbers) {
	/* Not yet supported */
	UNIMPLEMENTED_DBGBREAK();
    }
}

NTSTATUS PciScanBus(IN PPCI_FDO_EXTENSION DeviceExtension)
{
    ULONG MaxDevice = PCI_MAX_DEVICES;
    BOOLEAN ProcessFlag = FALSE;
    UCHAR Buffer[PCI_COMMON_HDR_LENGTH] = {};
    UCHAR BiosBuffer[PCI_COMMON_HDR_LENGTH] = {};
    PPCI_COMMON_HEADER PciData = (PVOID)Buffer;
    PPCI_COMMON_HEADER BiosData = (PVOID)BiosBuffer;
    DPRINT1("PCI Scan Bus: FDO Extension @ %p, Base Bus = 0x%x\n", DeviceExtension,
	    DeviceExtension->BaseBus);

    /* If we are not scanning the root bus, check if we should apply the PCI hack
     * that only allows the bus to have one single child device. */
    if (!PCI_IS_ROOT_FDO(DeviceExtension)) {
	/* Get the PDO for the child bus */
	PPCI_PDO_EXTENSION PdoExtension = DeviceExtension->PhysicalDeviceObject->DeviceExtension;
	ASSERT_PDO(PdoExtension);

	/* Check for hack which only allows bus to have one child device */
	if (PdoExtension->HackFlags & PCI_HACK_ONE_CHILD)
	    MaxDevice = 1;
    }

    /* Loop every device on the bus */
    PCI_SLOT_NUMBER PciSlot = {};
    for (ULONG i = 0; i < MaxDevice; i++) {
	/* Loop every function of each device */
	PciSlot.Bits.DeviceNumber = i;
	for (ULONG j = 0; j < PCI_MAX_FUNCTION; j++) {
	    /* Build the final slot structure */
	    PciSlot.Bits.FunctionNumber = j;

	    /* Read the vendor for this slot */
	    PciReadSlotConfig(DeviceExtension, PciSlot, PciData, 0, sizeof(USHORT));

	    /* Skip invalid device */
	    if (PciData->VendorID == PCI_INVALID_VENDORID)
		continue;

	    /* Now read the whole header */
	    PciReadSlotConfig(DeviceExtension, PciSlot, &PciData->DeviceID,
			      sizeof(USHORT), PCI_COMMON_HDR_LENGTH - sizeof(USHORT));

	    /* Apply any hacks before even analyzing the configuration header */
	    PciApplyHacks(DeviceExtension, PciData, PciSlot,
			  PCI_HACK_FIXUP_BEFORE_CONFIGURATION, NULL);

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

	    /* Check for non-simple devices */
	    USHORT SubVendorId, SubSystemId;
	    if (PCI_MULTIFUNCTION_DEVICE(PciData) ||
		(PciData->BaseClass == PCI_CLASS_BRIDGE_DEV)) {
		/* No subsystem data defined for these kinds of bridges */
		SubVendorId = 0;
		SubSystemId = 0;
	    } else {
		/* Read the subsystem information from the PCI header */
		SubVendorId = PciData->Type0.SubVendorID;
		SubSystemId = PciData->Type0.SubSystemID;
	    }

	    /* Get any hack flags for this device */
	    LONGLONG HackFlags = PciGetHackFlags(PciData->VendorID,
						 PciData->DeviceID, SubVendorId,
						 SubSystemId, PciData->RevisionID);

	    /* Check if this device is considered critical by the OS */
	    if (PciIsCriticalDeviceClass(PciData->BaseClass, PciData->SubClass)) {
		/* Check if normally the decodes would be disabled */
		if (!(HackFlags & PCI_HACK_DONT_DISABLE_DECODES)) {
		    /* Because this device is critical, don't disable them */
		    DPRINT1("Not allowing PM Because device is critical\n");
		    HackFlags |= PCI_HACK_CRITICAL_DEVICE;
		}
	    }

	    /* PCI bridges with a VGA card are also considered critical */
	    if ((PciData->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
		(PciData->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI) &&
		(PciData->Type1.BridgeControl & PCI_ENABLE_BRIDGE_VGA) &&
		!(HackFlags & PCI_HACK_DONT_DISABLE_DECODES)) {
		/* Do not disable their decodes either */
		DPRINT1("Not allowing PM because device is VGA\n");
		HackFlags |= PCI_HACK_CRITICAL_DEVICE;
	    }

	    /* Check if the device should be skipped for whatever reason */
	    if (PciSkipThisFunction(PciData, PciSlot, PCI_SKIP_DEVICE_ENUMERATION,
				    HackFlags)) {
		/* Skip this device */
		continue;
	    }

	    /* Check if a PDO has already been created for this device */
	    PPCI_PDO_EXTENSION PdoExtension = PciFindPdoByFunction(DeviceExtension,
								   PciSlot.AsULONG,
								   PciData);
	    if (PdoExtension) {
		/* Rescan scenarios are not yet implemented */
		UNIMPLEMENTED_DBGBREAK();
	    }

	    /* Bus processing will need to happen */
	    ProcessFlag = TRUE;

	    /* Create the PDO for this device */
	    PDEVICE_OBJECT DeviceObject = NULL;
	    NTSTATUS Status = PciPdoCreate(DeviceExtension, PciSlot, &DeviceObject);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	    ASSERT(DeviceObject);
	    PPCI_PDO_EXTENSION NewExtension = (PPCI_PDO_EXTENSION)DeviceObject->DeviceExtension;

	    /* Check for broken devices with wrong/no class codes */
	    if (HackFlags & PCI_HACK_FAKE_CLASS_CODE) {
		/* Setup a default one */
		PciData->BaseClass = PCI_CLASS_BASE_SYSTEM_DEV;
		PciData->SubClass = PCI_SUBCLASS_SYS_OTHER;

		/* Device will behave erratically when reading back data */
		NewExtension->ExpectedWritebackFailure = TRUE;
	    }

	    /* Clone all the information from the header */
	    NewExtension->VendorId = PciData->VendorID;
	    NewExtension->DeviceId = PciData->DeviceID;
	    NewExtension->RevisionId = PciData->RevisionID;
	    NewExtension->ProgIf = PciData->ProgIf;
	    NewExtension->SubClass = PciData->SubClass;
	    NewExtension->BaseClass = PciData->BaseClass;
	    NewExtension->HeaderType = PCI_CONFIGURATION_TYPE(PciData);

	    /* Check for modern bridge types, which are managed by the driver */
	    if ((NewExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
		((NewExtension->SubClass == PCI_SUBCLASS_BR_PCI_TO_PCI) ||
		 (NewExtension->SubClass == PCI_SUBCLASS_BR_CARDBUS))) {
		/* Scan the bridge list until the first free entry */
		PPCI_PDO_EXTENSION *BridgeExtension;
		for (BridgeExtension = &DeviceExtension->ChildBridgePdoList;
		     *BridgeExtension; BridgeExtension = &(*BridgeExtension)->NextBridge)
		    ;

		/* Add this PDO as a bridge */
		*BridgeExtension = NewExtension;
		ASSERT(NewExtension->NextBridge == NULL);
	    }

	    /* Get the PCI BIOS configuration saved in the registry */
	    Status = PciGetBiosConfig(NewExtension, BiosData);
	    if (NT_SUCCESS(Status)) {
		/* This path has not yet been fully tested by eVb */
		DPRINT1("Have BIOS configuration!\n");
		UNIMPLEMENTED;

		/* Check if the PCI BIOS configuration has changed */
		if (!PcipIsSameDevice(NewExtension, BiosData)) {
		    /* This is considered failure, and new data will be saved */
		    Status = STATUS_UNSUCCESSFUL;
		} else {
		    /* Data is still correct, check for interrupt line change */
		    if (BiosData->Type0.InterruptLine != PciData->Type0.InterruptLine) {
			/* Update the current BIOS with the saved interrupt line */
			PciWriteDeviceConfig(NewExtension,
					     &BiosData->Type0.InterruptLine,
					     FIELD_OFFSET(PCI_COMMON_HEADER,
							  Type0.InterruptLine),
					     sizeof(UCHAR));
		    }

		    /* Save the initial command from the BIOS */
		    NewExtension->InitialCommand = BiosData->Command;
		}
	    }

	    /* Check if no saved data was present or if it was a mismatch */
	    if (!NT_SUCCESS(Status)) {
		/* Save the new data */
		Status = PciSaveBiosConfig(NewExtension, PciData);
		ASSERT(NT_SUCCESS(Status));

		/* Save the command from the device */
		NewExtension->InitialCommand = PciData->Command;
	    }

	    /* Save original command from the device and hack flags */
	    NewExtension->CommandEnables = PciData->Command;
	    NewExtension->HackFlags = HackFlags;

	    /* Get power, AGP, and other capability data */
	    PciGetEnhancedCapabilities(NewExtension, PciData);
	    PciDumpCapabilities(NewExtension);

	    /* Now configure the BARs */
	    Status = PciGetFunctionLimits(NewExtension, PciData, HackFlags);

	    if (!NT_SUCCESS(Status)) {
		PciPdoDestroy(DeviceObject);
		return Status;
	    }

	    /* Power up the device */
	    PciSetPowerManagedDevicePowerState(NewExtension, PowerDeviceD0, FALSE);

	    /* Apply any device hacks required for enumeration */
	    PciApplyHacks(DeviceExtension, PciData, PciSlot,
			  PCI_HACK_FIXUP_AFTER_CONFIGURATION, NewExtension);

	    /* Check if this device is used for PCI debugger cards */
	    NewExtension->OnDebugPath = PciIsDeviceOnDebugPath(NewExtension);

	    /* Check for devices with invalid/bogus subsystem data */
	    if (HackFlags & PCI_HACK_NO_SUBSYSTEM) {
		/* Set the subsystem information to zero instead */
		NewExtension->SubsystemVendorId = 0;
		NewExtension->SubsystemId = 0;
	    }

	    /* Check for IDE controllers */
	    if ((NewExtension->BaseClass == PCI_CLASS_MASS_STORAGE_CTLR) &&
		(NewExtension->SubClass == PCI_SUBCLASS_MSC_IDE_CTLR)) {
		/* Do not allow them to power down completely */
		NewExtension->DisablePowerDown = TRUE;
	    }

	    /*
             * Check if this is a legacy bridge. Note that the i82375 PCI/EISA
             * bridge that is present on certain NT Alpha machines appears as
             * non-classified so detect it manually by scanning for its VID/PID.
             */
	    if (((NewExtension->BaseClass == PCI_CLASS_BRIDGE_DEV) &&
		 ((NewExtension->SubClass == PCI_SUBCLASS_BR_ISA) ||
		  (NewExtension->SubClass == PCI_SUBCLASS_BR_EISA) ||
		  (NewExtension->SubClass == PCI_SUBCLASS_BR_MCA))) ||
		((NewExtension->VendorId == 0x8086) &&
		 (NewExtension->DeviceId == 0x482))) {
		/* Do not allow these legacy bridges to be powered down */
		NewExtension->DisablePowerDown = TRUE;
	    }

	    /* Check if the BIOS did not configure a cache line size */
	    if (!PciData->CacheLineSize) {
		/* Check if the device is disabled */
		if (!(NewExtension->CommandEnables &
		      (PCI_ENABLE_IO_SPACE | PCI_ENABLE_MEMORY_SPACE | PCI_ENABLE_BUS_MASTER))) {
		    /* Check if this is a PCI-X device*/
		    BOOLEAN IsPcix = NewExtension->InterfaceType == PciXMode1 ||
			NewExtension->InterfaceType == PciXMode2;

		    /*
                     * A device with default cache line size and latency timer
                     * settings is considered to be unconfigured. Note that on
                     * PCI-X, the reset value of the latency timer field in the
                     * header is 64, not 0, hence the value used here below.
                     */
		    if (!PciData->LatencyTimer ||
			(IsPcix && (PciData->LatencyTimer == 64))) {
			/* Keep track of the fact that it needs configuration */
			DPRINT1("PCI - ScanBus, PDOx %p found unconfigured\n",
				NewExtension);
			NewExtension->NeedsHotPlugConfiguration = TRUE;
		    }
		}
	    }

	    /* Save latency and cache size information */
	    NewExtension->SavedLatencyTimer = PciData->LatencyTimer;
	    NewExtension->SavedCacheLineSize = PciData->CacheLineSize;

	    /* The PDO is now ready to go */
	    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	}
    }

    /* Enumeration completed, do a final pass now that all devices are found */
    if (ProcessFlag)
	PciProcessBus(DeviceExtension);
    return STATUS_SUCCESS;
}

NTSTATUS PciQueryDeviceRelations(IN PPCI_FDO_EXTENSION DeviceExtension,
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

    /* Enumerate all children PDO again */
    for (PdoExtension = DeviceExtension->ChildPdoList; PdoExtension;
	 PdoExtension = PdoExtension->Next) {
	/* Check for PDOs that are still invalidated */
	if (PdoExtension->NotPresent) {
	    /* This means this PDO existed before, but not anymore */
	    PdoExtension->ReportedMissing = TRUE;
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

NTSTATUS PciSetResources(IN PPCI_PDO_EXTENSION PdoExtension,
			 IN BOOLEAN DoReset)
{
    PPCI_FDO_EXTENSION FdoExtension;
    UCHAR NewCacheLineSize, NewLatencyTimer;
    PCI_COMMON_HEADER PciData;
    UNUSED BOOLEAN Native;
    PPCI_CONFIGURATOR Configurator;

    /* Get the FDO and read the configuration data */
    FdoExtension = PdoExtension->ParentFdoExtension;
    PciReadDeviceConfig(PdoExtension, &PciData, 0, PCI_COMMON_HDR_LENGTH);

    /* Make sure this is still the same device */
    if (!PcipIsSameDevice(PdoExtension, &PciData)) {
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

    /* Check if an IDE controller is being reset */
    if (DoReset && (PdoExtension->BaseClass == PCI_CLASS_MASS_STORAGE_CTLR) &&
	(PdoExtension->SubClass == PCI_SUBCLASS_MSC_IDE_CTLR)) {
	/* Turn off native mode */
	Native = PciConfigureIdeController(PdoExtension, &PciData, FALSE);
	ASSERT(Native == PdoExtension->IDEInNativeMode);
    }

    /* Check for update of a hotplug device, or first configuration of one */
    if ((PdoExtension->NeedsHotPlugConfiguration) &&
	(FdoExtension->HotPlugParameters.Acquired)) {
	/* Don't have hotplug devices to test with yet, QEMU 0.14 should */
	UNIMPLEMENTED_DBGBREAK();
    }

    /* Disable interrupts (MSI or MSI-X) since we might modify the BAR ranges below. */
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

    /* Locate the correct resource configurator for this type of device */
    Configurator = &PciConfigurators[PdoExtension->HeaderType];

    /* Apply the settings change */
    Configurator->ChangeResourceSettings(PdoExtension, &PciData);

    /* Check if a reset is needed */
    if (DoReset) {
	/* Reset resources */
	Configurator->ResetDevice(PdoExtension, &PciData);
    }

    /* Enable MSI/MSI-X if we are supplied interrupt resources */
    if (!PdoExtension->InterruptResourceCount) {
	goto done;
    }
    assert(PdoExtension->MsiInfo.CapabilityOffset);
    /* If the device supports MSI-X, map the message table and program the table entries. */
    if (PdoExtension->MsiInfo.ExtendedMessage) {
	ULONG TableOffset = PdoExtension->MsiInfo.ExtendedMessageInfo.MessageTable;
	UCHAR TableIndex = TableOffset & PCI_MSIX_MESSAGE_TABLE_BAR_INDEX_MASK;
	TableOffset &= PCI_MSIX_MESSAGE_TABLE_OFFSET_MASK;
	PCM_PARTIAL_RESOURCE_DESCRIPTOR Res = PdoExtension->Resources[TableIndex].Current;
	assert(Res);
	assert(Res->Type == CmResourceTypeMemory);
	assert(Res->Memory.Start.QuadPart);
	assert(Res->Memory.Length > TableOffset);
	if (!Res || Res->Type != CmResourceTypeMemory || !Res->Memory.Start.QuadPart ||
	    Res->Memory.Length <= TableOffset) {
	    return STATUS_DEVICE_CONFIGURATION_ERROR;
	}
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

done:
    /* Check if the latency timer changed */
    NewLatencyTimer = PdoExtension->SavedLatencyTimer;
    if (PciData.LatencyTimer != NewLatencyTimer) {
	/* Debug notification */
	DPRINT1("PCI (pdox %p) changing latency from %02x to %02x.\n", PdoExtension,
		PciData.LatencyTimer, NewLatencyTimer);
    }

    /* Check if the cache line changed */
    NewCacheLineSize = PdoExtension->SavedCacheLineSize;
    if (PciData.CacheLineSize != NewCacheLineSize) {
	/* Debug notification */
	DPRINT1("PCI (pdox %p) changing cache line size from %02x to %02x.\n",
		PdoExtension, PciData.CacheLineSize, NewCacheLineSize);
    }

    /* Inherit data from PDO extension */
    PciData.LatencyTimer = PdoExtension->SavedLatencyTimer;
    PciData.CacheLineSize = PdoExtension->SavedCacheLineSize;

    /* Apply any resource hacks required */
    PciApplyHacks(FdoExtension, &PciData, PdoExtension->Slot,
		  PCI_HACK_FIXUP_BEFORE_UPDATE, PdoExtension);

    /* Check if I/O space was disabled by administrator or driver */
    if (PdoExtension->IoSpaceNotRequired) {
	/* Don't turn on the decode */
	PdoExtension->CommandEnables &= ~PCI_ENABLE_IO_SPACE;
    }

    /* Disable legacy interrupts */
    PdoExtension->CommandEnables |= PCI_DISABLE_LEVEL_INTERRUPT;

    /* Update the device with the new settings */
    PciUpdateHardware(PdoExtension, &PciData);

    /* Enable interrupts (MSI or MSI-X) */
    if (PdoExtension->InterruptResourceCount) {
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
    }

    /* Update complete */
    PdoExtension->NeedsHotPlugConfiguration = FALSE;
    return STATUS_SUCCESS;
}
