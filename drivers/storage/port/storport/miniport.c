/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Miniport interface code
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"

/* FUNCTIONS ******************************************************************/

static NTSTATUS InitializeConfiguration(IN PPORT_CONFIGURATION_INFORMATION PortConfig,
					IN PHW_INITIALIZATION_DATA InitData,
					IN ULONG BusNumber, IN ULONG SlotNumber)
{
    DPRINT1("InitializeConfiguration(%p %p %u %u)\n", PortConfig, InitData, BusNumber,
	    SlotNumber);

    /* Initialize the port configuration */
    RtlZeroMemory(PortConfig, sizeof(PORT_CONFIGURATION_INFORMATION));

    PortConfig->Length = sizeof(PORT_CONFIGURATION_INFORMATION);
    PortConfig->SystemIoBusNumber = BusNumber;
    PortConfig->SlotNumber = SlotNumber;
    PortConfig->AdapterInterfaceType = InitData->AdapterInterfaceType;

    PortConfig->MaximumTransferLength = SP_UNINITIALIZED_VALUE;

    PortConfig->MaximumNumberOfTargets = SCSI_MAXIMUM_TARGETS_PER_BUS;

    PortConfig->SpecificLuExtensionSize = InitData->SpecificLuExtensionSize;
    PortConfig->SrbExtensionSize = InitData->SrbExtensionSize;
    PortConfig->MaximumNumberOfLogicalUnits = SCSI_MAXIMUM_LOGICAL_UNITS;
    PortConfig->WmiDataProvider = TRUE;

    PortConfig->NumberOfAccessRanges = InitData->NumberOfAccessRanges;
    DPRINT1("NumberOfAccessRanges: %u\n", PortConfig->NumberOfAccessRanges);
    if (PortConfig->NumberOfAccessRanges != 0) {
	PortConfig->AccessRanges =
	    ExAllocatePoolWithTag(NonPagedPool,
				  PortConfig->NumberOfAccessRanges * sizeof(ACCESS_RANGE),
				  TAG_ACCRESS_RANGE);
	if (PortConfig->AccessRanges == NULL)
	    return STATUS_NO_MEMORY;

	RtlZeroMemory(PortConfig->AccessRanges,
		      PortConfig->NumberOfAccessRanges * sizeof(ACCESS_RANGE));
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(PortConfig->InitiatorBusId); i++) {
	PortConfig->InitiatorBusId[i] = (CCHAR)SP_UNINITIALIZED_VALUE;
    }

    return STATUS_SUCCESS;
}

static VOID AssignAccessRangesToConfiguration(IN PPORT_CONFIGURATION_INFORMATION PortConfig,
					      IN PCM_RESOURCE_LIST ResourceList,
					      IN ULONG NumberOfAccessRanges)
{
    PCM_FULL_RESOURCE_DESCRIPTOR FullDescriptor;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor;
    PCM_PARTIAL_RESOURCE_LIST PartialResourceList;
    ULONG RangeNumber = 0;

    DPRINT1("AssignResourceToConfiguration(%p %p %u)\n", PortConfig, ResourceList,
	    NumberOfAccessRanges);
    assert(ResourceList);

    FullDescriptor = &ResourceList->List[0];
    for (ULONG i = 0; i < ResourceList->Count; i++) {
	PartialResourceList = &FullDescriptor->PartialResourceList;

	for (ULONG j = 0; j < PartialResourceList->Count; j++) {
	    PartialDescriptor = &PartialResourceList->PartialDescriptors[j];

	    switch (PartialDescriptor->Type) {
	    case CmResourceTypePort:
		DPRINT1("Port: 0x%llx (0x%x)\n", PartialDescriptor->Port.Start.QuadPart,
			PartialDescriptor->Port.Length);
		if (RangeNumber < NumberOfAccessRanges) {
		    PACCESS_RANGE AccessRange = &((*(PortConfig->AccessRanges))[RangeNumber]);
		    AccessRange->RangeStart = PartialDescriptor->Port.Start;
		    AccessRange->RangeLength = PartialDescriptor->Port.Length;
		    AccessRange->RangeInMemory = FALSE;
		    RangeNumber++;
		}
		break;

	    case CmResourceTypeMemory:
		DPRINT1("Memory: 0x%llx (0x%x)\n",
			PartialDescriptor->Memory.Start.QuadPart,
			PartialDescriptor->Memory.Length);
		if (RangeNumber < NumberOfAccessRanges) {
		    PACCESS_RANGE AccessRange = &((*(PortConfig->AccessRanges))[RangeNumber]);
		    AccessRange->RangeStart = PartialDescriptor->Memory.Start;
		    AccessRange->RangeLength = PartialDescriptor->Memory.Length;
		    AccessRange->RangeInMemory = TRUE;
		    RangeNumber++;
		}
		break;

	    default:
		break;
	    }
	}

	/* Advance to next CM_FULL_RESOURCE_DESCRIPTOR block in memory. */
	FullDescriptor = (PVOID)(FullDescriptor->PartialResourceList.PartialDescriptors +
				 FullDescriptor->PartialResourceList.Count);
    }
}

NTSTATUS MiniportInitialize(IN PMINIPORT Miniport)
{
    DPRINT1("MiniportInitialize(%p)\n", Miniport);
    PFDO_DEVICE_EXTENSION DeviceExtension = Miniport->DeviceExtension;
    assert(DeviceExtension);
    PHW_INITIALIZATION_DATA InitData = Miniport->InitData;
    assert(InitData);

    /* Calculate the miniport device extension size */
    ULONG Size = sizeof(MINIPORT_DEVICE_EXTENSION) + Miniport->InitData->DeviceExtensionSize;

    /* Allocate and initialize the miniport device extension */
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = ExAllocatePoolWithTag(NonPagedPool, Size,
									 TAG_MINIPORT_DATA);
    if (MiniportExtension == NULL)
	return STATUS_NO_MEMORY;

    RtlZeroMemory(MiniportExtension, Size);

    MiniportExtension->Miniport = Miniport;
    Miniport->MiniportExtension = MiniportExtension;

    /* Initialize the port configuration */
    NTSTATUS Status = InitializeConfiguration(&Miniport->PortConfig, InitData,
					      DeviceExtension->BusNumber,
					      DeviceExtension->SlotNumber);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Assign the resources to the port configuration */
    AssignAccessRangesToConfiguration(&Miniport->PortConfig,
				      DeviceExtension->AllocatedResources,
				      InitData->NumberOfAccessRanges);

    return STATUS_SUCCESS;
}

NTSTATUS MiniportFindAdapter(IN PMINIPORT Miniport)
{
    BOOLEAN Reserved = FALSE;
    NTSTATUS Status;

    DPRINT1("MiniportFindAdapter(%p)\n", Miniport);

    /* Call the miniport HwFindAdapter routine */
    ULONG Result = Miniport->InitData->HwFindAdapter(
	&Miniport->MiniportExtension->HwDeviceExtension, NULL, NULL, NULL,
	&Miniport->PortConfig, &Reserved);
    DPRINT1("HwFindAdapter() returned %u\n", Result);

    /* Convert the result to a status code */
    switch (Result) {
    case SP_RETURN_NOT_FOUND:
	DPRINT1("SP_RETURN_NOT_FOUND\n");
	Status = STATUS_NOT_FOUND;
	break;

    case SP_RETURN_FOUND:
	DPRINT1("SP_RETURN_FOUND\n");
	if (Miniport->PortConfig.SynchronizationModel != StorSynchronizeFullDuplex) {
	    DPRINT("ERROR: half-duplex IO is NOT supported.\n");
	    /* Fix the miniport driver to use full-duplex IO. */
	    assert(FALSE);
	    Status = STATUS_DEVICE_CONFIGURATION_ERROR;
	} else {
	    Status = STATUS_SUCCESS;
	}
	break;

    case SP_RETURN_ERROR:
	DPRINT1("SP_RETURN_ERROR\n");
	Status = STATUS_ADAPTER_HARDWARE_ERROR;
	break;

    case SP_RETURN_BAD_CONFIG:
	DPRINT1("SP_RETURN_BAD_CONFIG\n");
	Status = STATUS_DEVICE_CONFIGURATION_ERROR;
	break;

    default:
	DPRINT1("Unknown result: %u\n", Result);
	Status = STATUS_INTERNAL_ERROR;
	break;
    }

    return Status;
}

NTSTATUS MiniportHwInitialize(IN PMINIPORT Miniport)
{
    DPRINT1("MiniportHwInitialize(%p)\n", Miniport);
    BOOLEAN Result =
	Miniport->InitData->HwInitialize(&Miniport->MiniportExtension->HwDeviceExtension);
    DPRINT1("HwInitialize() returned %u\n", Result);
    return Result ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

BOOLEAN MiniportHwInterrupt(IN PMINIPORT Miniport)
{
    return Miniport->InitData->HwInterrupt(&Miniport->MiniportExtension->HwDeviceExtension);
}

BOOLEAN MiniportHwMessageInterrupt(IN PMINIPORT Miniport,
				   IN ULONG MessageId)
{
    return Miniport->PortConfig.HwMSInterruptRoutine(
	&Miniport->MiniportExtension->HwDeviceExtension, MessageId);
}

BOOLEAN MiniportBuildIo(IN PMINIPORT Miniport,
			IN PSTORAGE_REQUEST_BLOCK Srb)
{
    DPRINT1("MiniportHwBuildIo(%p %p)\n", Miniport, Srb);
    return Miniport->InitData->HwBuildIo(&Miniport->MiniportExtension->HwDeviceExtension,
					 Srb);
}

BOOLEAN MiniportStartIo(IN PMINIPORT Miniport,
			IN PSTORAGE_REQUEST_BLOCK Srb)
{
    DPRINT1("MiniportHwStartIo(%p %p)\n", Miniport, Srb);
    return Miniport->InitData->HwStartIo(&Miniport->MiniportExtension->HwDeviceExtension,
					 Srb);
}
