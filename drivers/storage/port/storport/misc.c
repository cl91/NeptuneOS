/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Storport helper functions
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"

/* FUNCTIONS ******************************************************************/

NTAPI NTSTATUS ForwardIrpAndForget(_In_ PDEVICE_OBJECT LowerDevice, _In_ PIRP Irp)
{
    ASSERT(LowerDevice);

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(LowerDevice, Irp);
}

INTERFACE_TYPE GetBusInterface(PDEVICE_OBJECT DeviceObject)
{
    GUID Guid;
    ULONG Length;
    NTSTATUS Status;

    Status = IoGetDeviceProperty(DeviceObject, DevicePropertyBusTypeGuid, sizeof(Guid),
				 &Guid, &Length);
    if (!NT_SUCCESS(Status))
	return InterfaceTypeUndefined;

    if (RtlCompareMemory(&Guid, &GUID_BUS_TYPE_PCMCIA, sizeof(GUID)) == sizeof(GUID))
	return PCMCIABus;
    else if (RtlCompareMemory(&Guid, &GUID_BUS_TYPE_PCI, sizeof(GUID)) == sizeof(GUID))
	return PCIBus;
    else if (RtlCompareMemory(&Guid, &GUID_BUS_TYPE_ISAPNP, sizeof(GUID)) == sizeof(GUID))
	return PNPISABus;

    return InterfaceTypeUndefined;
}

PCM_RESOURCE_LIST CopyResourceList(PCM_RESOURCE_LIST Source)
{
    DPRINT1("CopyResourceList(%p)\n", Source);

    /* Get the size of the resource list */
    ULONG Size = CmGetResourceListSize(Source);

    /* Allocate a new buffer */
    PCM_RESOURCE_LIST Destination = ExAllocatePoolWithTag(NonPagedPool,
							  Size, TAG_RESOURCE_LIST);
    if (Destination == NULL)
	return NULL;

    /* Copy the resource list */
    RtlCopyMemory(Destination, Source, Size);

    return Destination;
}

BOOLEAN TranslateResourceListAddress(PFDO_DEVICE_EXTENSION DeviceExtension,
				     INTERFACE_TYPE BusType,
				     ULONG SystemIoBusNumber,
				     STOR_PHYSICAL_ADDRESS IoAddress,
				     ULONG NumberOfBytes,
				     BOOLEAN InIoSpace,
				     PPHYSICAL_ADDRESS TranslatedAddress)
{
    DPRINT1("TranslateResourceListAddress(%p)\n", DeviceExtension);

    PCM_FULL_RESOURCE_DESCRIPTOR FullA = DeviceExtension->AllocatedResources->List;
    PCM_FULL_RESOURCE_DESCRIPTOR FullT = DeviceExtension->TranslatedResources->List;
    for (ULONG i = 0; i < DeviceExtension->AllocatedResources->Count; i++) {
	for (ULONG j = 0; j < FullA->PartialResourceList.Count; j++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialA =
		FullA->PartialResourceList.PartialDescriptors + j;
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialT =
		FullT->PartialResourceList.PartialDescriptors + j;

	    switch (PartialA->Type) {
	    case CmResourceTypePort:
		DPRINT1("Port: 0x%llx (0x%x)\n", PartialA->Port.Start.QuadPart,
			PartialA->Port.Length);
		if (InIoSpace && IoAddress.QuadPart >= PartialA->Port.Start.QuadPart &&
		    IoAddress.QuadPart + NumberOfBytes <=
		    PartialA->Port.Start.QuadPart + PartialA->Port.Length) {
		    TranslatedAddress->QuadPart =
			PartialT->Port.Start.QuadPart +
			(IoAddress.QuadPart - PartialA->Port.Start.QuadPart);
		    return TRUE;
		}
		break;

	    case CmResourceTypeMemory:
		DPRINT1("Memory: 0x%llx (0x%x)\n",
			PartialA->Memory.Start.QuadPart,
			PartialA->Memory.Length);
		if (!InIoSpace && IoAddress.QuadPart >= PartialA->Memory.Start.QuadPart &&
		    IoAddress.QuadPart + NumberOfBytes <=
		    PartialA->Memory.Start.QuadPart + PartialA->Memory.Length) {
		    TranslatedAddress->QuadPart =
			PartialT->Memory.Start.QuadPart +
			(IoAddress.QuadPart - PartialA->Memory.Start.QuadPart);
		    return TRUE;
		}
		break;
	    }
	}

	/* Advance to next CM_FULL_RESOURCE_DESCRIPTOR block in memory. */
	FullA = CmGetNextResourceDescriptor(FullA);
	FullT = CmGetNextResourceDescriptor(FullT);
    }

    return FALSE;
}

NTSTATUS GetResourceListInterrupt(PFDO_DEVICE_EXTENSION DeviceExtension,
				  PULONG Vector,
				  PKIRQL Irql,
				  KINTERRUPT_MODE *InterruptMode,
				  PBOOLEAN ShareVector,
				  PKAFFINITY Affinity)
{
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial;

    DPRINT1("GetResourceListInterrupt(%p)\n", DeviceExtension);

    PCM_FULL_RESOURCE_DESCRIPTOR Full = DeviceExtension->TranslatedResources->List;
    for (ULONG i = 0; i < DeviceExtension->TranslatedResources->Count; i++) {
	for (ULONG j = 0; j < Full->PartialResourceList.Count; j++) {
	    Partial = Full->PartialResourceList.PartialDescriptors + j;

	    switch (Partial->Type) {
	    case CmResourceTypeInterrupt:
		DPRINT1("Interrupt: Level %u  Vector %u\n",
			Partial->Interrupt.Level,
			Partial->Interrupt.Vector);

		*Vector = Partial->Interrupt.Vector;
		*Irql = (KIRQL)Partial->Interrupt.Level;
		*InterruptMode = (Partial->Flags & CM_RESOURCE_INTERRUPT_LATCHED) ?
		    Latched : LevelSensitive;
		*ShareVector = (Partial->ShareDisposition == CmResourceShareShared);
		*Affinity = Partial->Interrupt.Affinity;

		return STATUS_SUCCESS;
	    }
	}

	/* Advance to next CM_FULL_RESOURCE_DESCRIPTOR block in memory. */
	Full = CmGetNextResourceDescriptor(Full);
    }

    return STATUS_NOT_FOUND;
}

NTSTATUS AllocateAddressMapping(PMAPPED_ADDRESS *MappedAddressList,
				STOR_PHYSICAL_ADDRESS IoAddress,
				PVOID MappedAddress,
				ULONG NumberOfBytes,
				ULONG BusNumber)
{
    DPRINT1("AllocateAddressMapping()\n");

    PMAPPED_ADDRESS Mapping = ExAllocatePoolWithTag(NonPagedPool,
						    sizeof(MAPPED_ADDRESS),
						    TAG_ADDRESS_MAPPING);
    if (Mapping == NULL) {
	DPRINT1("No memory!\n");
	return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(Mapping, sizeof(MAPPED_ADDRESS));

    Mapping->NextMappedAddress = *MappedAddressList;
    *MappedAddressList = Mapping;

    Mapping->IoAddress = IoAddress;
    Mapping->MappedAddress = MappedAddress;
    Mapping->NumberOfBytes = NumberOfBytes;
    Mapping->BusNumber = BusNumber;

    return STATUS_SUCCESS;
}
