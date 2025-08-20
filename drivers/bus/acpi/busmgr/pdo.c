#include "../precomp.h"
#include "acpi_bus.h"
#include "acpi_drivers.h"

#include <stdio.h>
#include <initguid.h>
#include <poclass.h>

static NTSTATUS Bus_PDO_QueryDeviceCaps(PPDO_DEVICE_DATA DeviceData, PIRP Irp)
{
    PAGED_CODE();
    PIO_STACK_LOCATION Stack;
    PDEVICE_CAPABILITIES DeviceCapabilities;
    PACPI_DEVICE Device = NULL;
    ULONG i;

    if (DeviceData->AcpiHandle)
	AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

    Stack = IoGetCurrentIrpStackLocation(Irp);

    //
    // Get the packet.
    //
    DeviceCapabilities = Stack->Parameters.DeviceCapabilities.Capabilities;

    //
    // Set the capabilities.
    //

    if (DeviceCapabilities->Version != 1 ||
	DeviceCapabilities->Size < sizeof(DEVICE_CAPABILITIES)) {
	return STATUS_UNSUCCESSFUL;
    }

    DeviceCapabilities->D1Latency = 0;
    DeviceCapabilities->D2Latency = 0;
    DeviceCapabilities->D3Latency = 0;

    DeviceCapabilities->DeviceState[PowerSystemWorking] = PowerDeviceD0;
    DeviceCapabilities->DeviceState[PowerSystemSleeping1] = PowerDeviceD3;
    DeviceCapabilities->DeviceState[PowerSystemSleeping2] = PowerDeviceD3;
    DeviceCapabilities->DeviceState[PowerSystemSleeping3] = PowerDeviceD3;

    for (i = 0; i < ACPI_D_STATE_COUNT && Device; i++) {
	if (!Device->Power.States[i].Flags.Valid)
	    continue;

	switch (i) {
	case ACPI_STATE_D0:
	    DeviceCapabilities->DeviceState[PowerSystemWorking] = PowerDeviceD0;
	    break;

	case ACPI_STATE_D1:
	    DeviceCapabilities->DeviceState[PowerSystemSleeping1] = PowerDeviceD1;
	    DeviceCapabilities->D1Latency = Device->Power.States[i].Latency;
	    break;

	case ACPI_STATE_D2:
	    DeviceCapabilities->DeviceState[PowerSystemSleeping2] = PowerDeviceD2;
	    DeviceCapabilities->D2Latency = Device->Power.States[i].Latency;
	    break;

	case ACPI_STATE_D3:
	    DeviceCapabilities->DeviceState[PowerSystemSleeping3] = PowerDeviceD3;
	    DeviceCapabilities->D3Latency = Device->Power.States[i].Latency;
	    break;
	}
    }

    // We can wake the system from D1
    DeviceCapabilities->DeviceWake = PowerDeviceD1;

    DeviceCapabilities->DeviceD1 =
	(DeviceCapabilities->DeviceState[PowerSystemSleeping1] == PowerDeviceD1);
    DeviceCapabilities->DeviceD2 =
	(DeviceCapabilities->DeviceState[PowerSystemSleeping2] == PowerDeviceD2);

    DeviceCapabilities->WakeFromD0 = FALSE;
    DeviceCapabilities->WakeFromD1 = TRUE; // Yes we can
    DeviceCapabilities->WakeFromD2 = FALSE;
    DeviceCapabilities->WakeFromD3 = FALSE;

    if (Device) {
	DeviceCapabilities->LockSupported = Device->Flags.Lockable;
	DeviceCapabilities->EjectSupported = Device->Flags.Ejectable;
	DeviceCapabilities->HardwareDisabled = !Device->Status.Enabled &&
					       !Device->Status.Functional;
	DeviceCapabilities->Removable = Device->Flags.Removable;
	DeviceCapabilities->SurpriseRemovalOK = Device->Flags.SurpriseRemovalOk;
	DeviceCapabilities->UniqueID = Device->Flags.UniqueId;
	DeviceCapabilities->NoDisplayInUI = !Device->Status.ShowInUi;
	DeviceCapabilities->Address = Device->Pnp.BusAddress;
    }

    if (!Device || (Device->Flags.HardwareId &&
		    (strstr(Device->Pnp.HardwareId, ACPI_BUTTON_HID_LID) ||
		     strstr(Device->Pnp.HardwareId, ACPI_THERMAL_HID) ||
		     strstr(Device->Pnp.HardwareId, ACPI_PROCESSOR_HID)))) {
	/* Allow ACPI to control the device if it is a lid button,
         * a thermal zone, a processor, or a fixed feature button */
	DeviceCapabilities->RawDeviceOK = TRUE;
    }

    DeviceCapabilities->SilentInstall = FALSE;
    DeviceCapabilities->UINumber = (ULONG)-1;

    return STATUS_SUCCESS;
}

static NTSTATUS Bus_PDO_QueryDeviceId(PPDO_DEVICE_DATA DeviceData, PIRP Irp)
{
    PAGED_CODE();
    PIO_STACK_LOCATION Stack;
    PWCHAR Buffer, Src;
    WCHAR Temp[256];
    ULONG Length, i;
    NTSTATUS Status = STATUS_SUCCESS;
    PACPI_DEVICE Device;

    Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->Parameters.QueryId.IdType) {
    case BusQueryDeviceID:
	/* This is a REG_SZ value */
	if (DeviceData->AcpiHandle) {
	    AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

	    if (strcmp(Device->Pnp.HardwareId, "Processor") == 0) {
		Length = wcslen(ProcessorIdString);
		wcscpy_s(Temp, sizeof(Temp), ProcessorIdString);
	    } else {
		Length = swprintf(Temp, L"ACPI\\%hs", Device->Pnp.HardwareId);
	    }
	} else {
	    /* We know it's a fixed feature button because
             * these are direct children of the ACPI root device
             * and therefore have no handle
             */
	    Length = swprintf(Temp, L"ACPI\\FixedButton");
	}

	Temp[Length++] = UNICODE_NULL;

	NT_ASSERT(Length * sizeof(WCHAR) <= sizeof(Temp));

	Buffer = ExAllocatePoolWithTag(Length * sizeof(WCHAR), ACPI_TAG);

	if (!Buffer) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	RtlCopyMemory(Buffer, Temp, Length * sizeof(WCHAR));
	Irp->IoStatus.Information = (ULONG_PTR)Buffer;
	DPRINT("BusQueryDeviceID: %ws\n", Buffer);
	break;

    case BusQueryInstanceID:
	/* See comment in BusQueryDeviceID case */
	if (DeviceData->AcpiHandle) {
	    AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

	    if (Device->Flags.UniqueId)
		Length = swprintf(Temp, L"%hs", Device->Pnp.UniqueId);
	    else
		/* FIXME: Generate unique id! */
		Length = swprintf(Temp, L"%ls", L"0");
	} else {
	    /* FIXME: Generate unique id! */
	    Length = swprintf(Temp, L"%ls", L"0");
	}

	Temp[Length++] = UNICODE_NULL;

	NT_ASSERT(Length * sizeof(WCHAR) <= sizeof(Temp));

	Buffer = ExAllocatePoolWithTag(Length * sizeof(WCHAR), ACPI_TAG);
	if (!Buffer) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	RtlCopyMemory(Buffer, Temp, Length * sizeof(WCHAR));
	DPRINT("BusQueryInstanceID: %ws\n", Buffer);
	Irp->IoStatus.Information = (ULONG_PTR)Buffer;
	break;

    case BusQueryHardwareIDs:
	/* This is a REG_MULTI_SZ value */
	Length = 0;
	Status = STATUS_NOT_SUPPORTED;

	/* See comment in BusQueryDeviceID case */
	if (DeviceData->AcpiHandle) {
	    AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

	    if (!Device->Flags.HardwareId) {
		/* We don't have the ID to satisfy this request */
		break;
	    }

	    DPRINT("Device name: %s\n", Device->Pnp.DeviceName);
	    DPRINT("Hardware ID: %s\n", Device->Pnp.HardwareId);

	    if (strcmp(Device->Pnp.HardwareId, "Processor") == 0) {
		Length = ProcessorHardwareIds.Length / sizeof(WCHAR);
		Src = ProcessorHardwareIds.Buffer;
	    } else {
		Length += swprintf(&Temp[Length], L"ACPI\\%hs", Device->Pnp.HardwareId);
		Temp[Length++] = UNICODE_NULL;

		Length += swprintf(&Temp[Length], L"*%hs", Device->Pnp.HardwareId);
		Temp[Length++] = UNICODE_NULL;
		Temp[Length++] = UNICODE_NULL;
		Src = Temp;
	    }
	} else {
	    Length += swprintf(&Temp[Length], L"ACPI\\FixedButton");
	    Temp[Length++] = UNICODE_NULL;

	    Length += swprintf(&Temp[Length], L"*FixedButton");
	    Temp[Length++] = UNICODE_NULL;
	    Temp[Length++] = UNICODE_NULL;
	    Src = Temp;
	}

	NT_ASSERT(Length * sizeof(WCHAR) <= sizeof(Temp));

	Buffer = ExAllocatePoolWithTag(Length * sizeof(WCHAR), ACPI_TAG);

	if (!Buffer) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	RtlCopyMemory(Buffer, Src, Length * sizeof(WCHAR));
	Irp->IoStatus.Information = (ULONG_PTR)Buffer;
	DPRINT("BusQueryHardwareIDs: Length %d, ", Length);
	for (ULONG i = 0; i < Length; i++) {
	    DbgPrint("%wc", Buffer[i]);
	}
	Status = STATUS_SUCCESS;
	break;

    case BusQueryCompatibleIDs:
	/* This is a REG_MULTI_SZ value */
	Length = 0;
	Status = STATUS_NOT_SUPPORTED;

	/* See comment in BusQueryDeviceID case */
	if (DeviceData->AcpiHandle) {
	    AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

	    if (!Device->Flags.HardwareId) {
		/* We don't have the ID to satisfy this request */
		break;
	    }

	    DPRINT("Device name: %s\n", Device->Pnp.DeviceName);
	    DPRINT("Hardware ID: %s\n", Device->Pnp.HardwareId);

	    if (strcmp(Device->Pnp.HardwareId, "Processor") == 0) {
		Length += swprintf(&Temp[Length], L"ACPI\\%hs", Device->Pnp.HardwareId);
		Temp[Length++] = UNICODE_NULL;

		Length += swprintf(&Temp[Length], L"*%hs", Device->Pnp.HardwareId);
		Temp[Length++] = UNICODE_NULL;
		Temp[Length++] = UNICODE_NULL;
	    } else if (Device->Flags.CompatibleIds) {
		for (i = 0; i < Device->Pnp.CidList->Count; i++) {
		    Length += swprintf(&Temp[Length], L"ACPI\\%hs",
				       Device->Pnp.CidList->Ids[i].String);
		    Temp[Length++] = UNICODE_NULL;

		    Length += swprintf(&Temp[Length], L"*%hs",
				       Device->Pnp.CidList->Ids[i].String);
		    Temp[Length++] = UNICODE_NULL;
		}

		Temp[Length++] = UNICODE_NULL;
	    } else {
		/* No compatible IDs */
		break;
	    }

	    NT_ASSERT(Length * sizeof(WCHAR) <= sizeof(Temp));

	    Buffer = ExAllocatePoolWithTag(Length * sizeof(WCHAR), ACPI_TAG);
	    if (!Buffer) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		break;
	    }

	    RtlCopyMemory(Buffer, Temp, Length * sizeof(WCHAR));
	    Irp->IoStatus.Information = (ULONG_PTR)Buffer;
	    DPRINT("BusQueryCompatibleIDs: Length %d, ", Length);
	    for (ULONG i = 0; i < Length; i++) {
		DbgPrint("%wc", Buffer[i]);
	    }
	    Status = STATUS_SUCCESS;
	}
	break;

    default:
	Status = STATUS_NOT_SUPPORTED;
    }
    return Status;
}

static NTSTATUS Bus_PDO_QueryDeviceText(PPDO_DEVICE_DATA DeviceData, PIRP Irp)
{
    PAGED_CODE();
    PWCHAR Buffer, Temp;
    PIO_STACK_LOCATION Stack;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;
    Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription:
	if (!Irp->IoStatus.Information) {
	    if (wcsstr(DeviceData->HardwareIDs, L"PNP000") != 0)
		Temp = L"Programmable interrupt controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP010") != 0)
		Temp = L"System timer";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP020") != 0)
		Temp = L"DMA controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP03") != 0)
		Temp = L"Keyboard";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP040") != 0)
		Temp = L"Parallel port";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP05") != 0)
		Temp = L"Serial port";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP06") != 0)
		Temp = L"Disk controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP07") != 0)
		Temp = L"Disk controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP09") != 0)
		Temp = L"Display adapter";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0A0") != 0)
		Temp = L"Bus controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0E0") != 0)
		Temp = L"PCMCIA controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0F") != 0)
		Temp = L"Mouse device";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP8") != 0)
		Temp = L"Network adapter";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNPA0") != 0)
		Temp = L"SCSI controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNPB0") != 0)
		Temp = L"Multimedia device";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNPC00") != 0)
		Temp = L"Modem";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0C0C") != 0)
		Temp = L"Power Button";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0C0E") != 0)
		Temp = L"Sleep Button";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0C0D") != 0)
		Temp = L"Lid Switch";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0C09") != 0)
		Temp = L"ACPI Embedded Controller";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0C0B") != 0)
		Temp = L"ACPI Fan";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0A03") != 0 ||
		     wcsstr(DeviceData->HardwareIDs, L"PNP0A08") != 0)
		Temp = L"PCI Root Bridge";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0C0A") != 0)
		Temp = L"ACPI Battery";
	    else if (wcsstr(DeviceData->HardwareIDs, L"PNP0C0F") != 0)
		Temp = L"PCI Interrupt Link";
	    else if (wcsstr(DeviceData->HardwareIDs, L"ACPI_PWR") != 0)
		Temp = L"ACPI Power Resource";
	    else if (wcsstr(DeviceData->HardwareIDs, L"Processor") != 0) {
		if (ProcessorNameString != NULL)
		    Temp = ProcessorNameString;
		else
		    Temp = L"Processor";
	    } else if (wcsstr(DeviceData->HardwareIDs, L"ThermalZone") != 0)
		Temp = L"ACPI Thermal Zone";
	    else if (wcsstr(DeviceData->HardwareIDs, L"ACPI0002") != 0)
		Temp = L"Smart Battery";
	    else if (wcsstr(DeviceData->HardwareIDs, L"ACPI0003") != 0)
		Temp = L"AC Adapter";
	    /* Simply checking if AcpiHandle is NULL eliminates the need to check
             * for the 4 different names that ACPI knows the fixed feature button as internally
             */
	    else if (!DeviceData->AcpiHandle)
		Temp = L"ACPI Fixed Feature Button";
	    else
		Temp = L"Other ACPI device";

	    Buffer = ExAllocatePoolWithTag((wcslen(Temp) + 1) * sizeof(WCHAR), ACPI_TAG);

	    if (!Buffer) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		break;
	    }

	    RtlCopyMemory(Buffer, Temp, (wcslen(Temp) + 1) * sizeof(WCHAR));

	    DPRINT("\tDeviceTextDescription :%ws\n", Buffer);

	    Irp->IoStatus.Information = (ULONG_PTR)Buffer;
	    Status = STATUS_SUCCESS;
	}
	break;

    default:
	break;
    }

    return Status;
}

#define PCI_SEGMENT_ECMA_SIZE (1UL << 28)

static VOID PciGetSegmentNumber(IN PPDO_DEVICE_DATA DeviceData,
				OUT ULONGLONG *SegmentNumber)
{
    PACPI_DEVICE Device;
    AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

    ACPI_STATUS Status = AcpiEvaluateInteger(DeviceData->AcpiHandle, METHOD_NAME__SEG,
					     NULL, SegmentNumber);
    if (Status != AE_OK) {
	DPRINT1("WARNING: Unable to get the PCI segment number using _SEG. Default to 0.\n");
	*SegmentNumber = 0;
    } else {
	DPRINT("Got PCI segment number %lld from _SEG.\n", *SegmentNumber);
    }
}

static VOID PciGetBusNumber(IN PPDO_DEVICE_DATA DeviceData,
			    OUT ULONGLONG *BusNumber)
{
    PACPI_DEVICE Device;
    AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

    ACPI_STATUS Status = AcpiEvaluateInteger(DeviceData->AcpiHandle, METHOD_NAME__BBN,
					     NULL, BusNumber);
    if (Status != AE_OK) {
	DPRINT1("WARNING: Unable to get the PCI bus number using _BBN. Default to 0.\n");
	*BusNumber = 0;
    } else {
	DPRINT("Got PCI bus number %lld from _BBN.\n", *BusNumber);
    }
}

static NTSTATUS Bus_PDO_QueryResources(PPDO_DEVICE_DATA DeviceData, PIRP Irp)
{
    ULONG NumberOfResources = 0;
    PCM_RESOURCE_LIST ResourceList;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR ResourceDescriptor;
    ACPI_STATUS AcpiStatus;
    ACPI_BUFFER Buffer;
    ACPI_RESOURCE *Resource;
    ULONG ResourceListSize;
    ULONG i;

    if (!DeviceData->AcpiHandle) {
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    /* Get current resources */
    Buffer.Length = 0;
    AcpiStatus = AcpiGetCurrentResources(DeviceData->AcpiHandle, &Buffer);
    if ((!ACPI_SUCCESS(AcpiStatus) && AcpiStatus != AE_BUFFER_OVERFLOW) ||
	Buffer.Length == 0) {
	/* Device does not have any resources. We will return success with
	 * an empty resource list. */
	return STATUS_SUCCESS;
    }

    Buffer.Pointer = ExAllocatePoolWithTag(Buffer.Length, 'BpcA');
    if (!Buffer.Pointer)
	return STATUS_INSUFFICIENT_RESOURCES;

    AcpiStatus = AcpiGetCurrentResources(DeviceData->AcpiHandle, &Buffer);
    if (!ACPI_SUCCESS(AcpiStatus)) {
	DPRINT1("AcpiGetCurrentResources #2 failed (0x%x)\n", AcpiStatus);
	ASSERT(FALSE);
	return STATUS_UNSUCCESSFUL;
    }

    Resource = Buffer.Pointer;
    /* Count number of resources */
    while (Resource->Type != ACPI_RESOURCE_TYPE_END_TAG) {
	switch (Resource->Type) {
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ: {
	    ACPI_RESOURCE_EXTENDED_IRQ *IrqData =
		(ACPI_RESOURCE_EXTENDED_IRQ *)&Resource->Data;
	    if (IrqData->ProducerConsumer == ACPI_PRODUCER)
		break;
	    NumberOfResources += IrqData->InterruptCount;
	    break;
	}
	case ACPI_RESOURCE_TYPE_IRQ: {
	    ACPI_RESOURCE_IRQ *IrqData = (ACPI_RESOURCE_IRQ *)&Resource->Data;
	    NumberOfResources += IrqData->InterruptCount;
	    break;
	}
	case ACPI_RESOURCE_TYPE_DMA: {
	    ACPI_RESOURCE_DMA *DmaData = (ACPI_RESOURCE_DMA *)&Resource->Data;
	    NumberOfResources += DmaData->ChannelCount;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS16:
	case ACPI_RESOURCE_TYPE_ADDRESS32:
	case ACPI_RESOURCE_TYPE_ADDRESS64:
	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64: {
	    ACPI_RESOURCE_ADDRESS *AddrRes = (ACPI_RESOURCE_ADDRESS *)&Resource->Data;
	    if (AddrRes->ProducerConsumer == ACPI_PRODUCER)
		break;
	    NumberOfResources++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_MEMORY24:
	case ACPI_RESOURCE_TYPE_MEMORY32:
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
	case ACPI_RESOURCE_TYPE_FIXED_IO:
	case ACPI_RESOURCE_TYPE_IO: {
	    NumberOfResources++;
	    break;
	}
	default: {
	    DPRINT1("Unknown resource type: %d\n", Resource->Type);
	    break;
	}
	}
	Resource = ACPI_NEXT_RESOURCE(Resource);
    }

    /* For the root PCI bus we find the PCI segment group number and pass
     * the its Enhanced Configuration Mechanism Address to the pci bus driver. */
    ULONGLONG SegmentNumber = 0;
    ULONGLONG BusNumber = 0;
    if (wcsstr(DeviceData->HardwareIDs, L"PNP0A03") != 0 ||
	wcsstr(DeviceData->HardwareIDs, L"PNP0A08") != 0) {
	PciGetSegmentNumber(DeviceData, &SegmentNumber);
	PciGetSegmentNumber(DeviceData, &BusNumber);
	NumberOfResources += 2;
    }

    /* Allocate memory */
    ResourceListSize = sizeof(CM_RESOURCE_LIST) + sizeof(CM_FULL_RESOURCE_DESCRIPTOR) +
		       sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) * NumberOfResources;
    ResourceList = ExAllocatePoolWithTag(ResourceListSize, 'RpcA');

    if (!ResourceList) {
	ExFreePoolWithTag(Buffer.Pointer, 'BpcA');
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    ResourceList->Count = 1;
    ResourceList->List[0].InterfaceType = Internal; /* FIXME */
    ResourceList->List[0].BusNumber = 0; /* We're the only ACPI bus device in the system */
    ResourceList->List[0].PartialResourceList.Version = 1;
    ResourceList->List[0].PartialResourceList.Revision = 1;
    ResourceList->List[0].PartialResourceList.Count = NumberOfResources;
    ResourceDescriptor = ResourceList->List[0].PartialResourceList.PartialDescriptors;

    /* Fill resources list structure */
    Resource = Buffer.Pointer;
    while (Resource->Type != ACPI_RESOURCE_TYPE_END_TAG) {
	switch (Resource->Type) {
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ: {
	    ACPI_RESOURCE_EXTENDED_IRQ *IrqData =
		(ACPI_RESOURCE_EXTENDED_IRQ *)&Resource->Data;
	    if (IrqData->ProducerConsumer == ACPI_PRODUCER)
		break;
	    for (i = 0; i < IrqData->InterruptCount; i++) {
		ResourceDescriptor->Type = CmResourceTypeInterrupt;

		ResourceDescriptor->ShareDisposition = (IrqData->Shareable == ACPI_SHARED ?
							CmResourceShareShared :
							CmResourceShareDeviceExclusive);
		ResourceDescriptor->Flags = (IrqData->Triggering == ACPI_LEVEL_SENSITIVE ?
					     CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE :
					     CM_RESOURCE_INTERRUPT_LATCHED);
		ResourceDescriptor->Interrupt.Level =
		    ResourceDescriptor->Interrupt.Vector = IrqData->Interrupts[i];
		ResourceDescriptor->Interrupt.Affinity = (KAFFINITY)(-1);

		ResourceDescriptor++;
	    }
	    break;
	}
	case ACPI_RESOURCE_TYPE_IRQ: {
	    ACPI_RESOURCE_IRQ *IrqData = (ACPI_RESOURCE_IRQ *)&Resource->Data;
	    for (i = 0; i < IrqData->InterruptCount; i++) {
		ResourceDescriptor->Type = CmResourceTypeInterrupt;

		ResourceDescriptor->ShareDisposition = (IrqData->Shareable == ACPI_SHARED ?
							CmResourceShareShared :
							CmResourceShareDeviceExclusive);
		ResourceDescriptor->Flags = (IrqData->Triggering == ACPI_LEVEL_SENSITIVE ?
					     CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE :
					     CM_RESOURCE_INTERRUPT_LATCHED);
		ResourceDescriptor->Interrupt.Level =
		    ResourceDescriptor->Interrupt.Vector = IrqData->Interrupts[i];
		ResourceDescriptor->Interrupt.Affinity = (KAFFINITY)(-1);

		ResourceDescriptor++;
	    }
	    break;
	}
	case ACPI_RESOURCE_TYPE_DMA: {
	    ACPI_RESOURCE_DMA *DmaData = (ACPI_RESOURCE_DMA *)&Resource->Data;
	    for (i = 0; i < DmaData->ChannelCount; i++) {
		ResourceDescriptor->Type = CmResourceTypeDma;
		ResourceDescriptor->Flags = 0;
		switch (DmaData->Type) {
		case ACPI_TYPE_A:
		    ResourceDescriptor->Flags |= CM_RESOURCE_DMA_TYPE_A;
		    break;
		case ACPI_TYPE_B:
		    ResourceDescriptor->Flags |= CM_RESOURCE_DMA_TYPE_B;
		    break;
		case ACPI_TYPE_F:
		    ResourceDescriptor->Flags |= CM_RESOURCE_DMA_TYPE_F;
		    break;
		}
		if (DmaData->BusMaster == ACPI_BUS_MASTER)
		    ResourceDescriptor->Flags |= CM_RESOURCE_DMA_BUS_MASTER;
		switch (DmaData->Transfer) {
		case ACPI_TRANSFER_8:
		    ResourceDescriptor->Flags |= CM_RESOURCE_DMA_8;
		    break;
		case ACPI_TRANSFER_16:
		    ResourceDescriptor->Flags |= CM_RESOURCE_DMA_16;
		    break;
		case ACPI_TRANSFER_8_16:
		    ResourceDescriptor->Flags |= CM_RESOURCE_DMA_8_AND_16;
		    break;
		}
		ResourceDescriptor->Dma.Channel = DmaData->Channels[i];

		ResourceDescriptor++;
	    }
	    break;
	}
	case ACPI_RESOURCE_TYPE_IO: {
	    ACPI_RESOURCE_IO *IoData = (ACPI_RESOURCE_IO *)&Resource->Data;
	    ResourceDescriptor->Type = CmResourceTypePort;
	    ResourceDescriptor->ShareDisposition = CmResourceShareDriverExclusive;
	    ResourceDescriptor->Flags = CM_RESOURCE_PORT_IO;
	    if (IoData->IoDecode == ACPI_DECODE_16)
		ResourceDescriptor->Flags |= CM_RESOURCE_PORT_16_BIT_DECODE;
	    else
		ResourceDescriptor->Flags |= CM_RESOURCE_PORT_10_BIT_DECODE;
	    ResourceDescriptor->Port.Start.QuadPart = IoData->Minimum;
	    ResourceDescriptor->Port.Length = IoData->AddressLength;

	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_FIXED_IO: {
	    ACPI_RESOURCE_FIXED_IO *IoData = (ACPI_RESOURCE_FIXED_IO *)&Resource->Data;
	    ResourceDescriptor->Type = CmResourceTypePort;
	    ResourceDescriptor->ShareDisposition = CmResourceShareDriverExclusive;
	    ResourceDescriptor->Flags = CM_RESOURCE_PORT_IO;
	    ResourceDescriptor->Port.Start.QuadPart = IoData->Address;
	    ResourceDescriptor->Port.Length = IoData->AddressLength;

	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS16: {
	    ACPI_RESOURCE_ADDRESS16 *Addr16Data =
		(ACPI_RESOURCE_ADDRESS16 *)&Resource->Data;
	    if (Addr16Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    if (Addr16Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		ResourceDescriptor->Type = CmResourceTypeBusNumber;
		ResourceDescriptor->ShareDisposition = CmResourceShareShared;
		ResourceDescriptor->Flags = 0;
		ResourceDescriptor->BusNumber.Start = Addr16Data->Address.Minimum;
		ResourceDescriptor->BusNumber.Length =
		    Addr16Data->Address.AddressLength;
	    } else if (Addr16Data->ResourceType == ACPI_IO_RANGE) {
		ResourceDescriptor->Type = CmResourceTypePort;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr16Data->Decode == ACPI_POS_DECODE)
		    ResourceDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		ResourceDescriptor->Port.Start.QuadPart = Addr16Data->Address.Minimum;
		ResourceDescriptor->Port.Length = Addr16Data->Address.AddressLength;
	    } else {
		ResourceDescriptor->Type = CmResourceTypeMemory;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = 0;
		if (Addr16Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr16Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		ResourceDescriptor->Memory.Start.QuadPart = Addr16Data->Address.Minimum;
		ResourceDescriptor->Memory.Length = Addr16Data->Address.AddressLength;
	    }
	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS32: {
	    ACPI_RESOURCE_ADDRESS32 *Addr32Data =
		(ACPI_RESOURCE_ADDRESS32 *)&Resource->Data;
	    if (Addr32Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    if (Addr32Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		ResourceDescriptor->Type = CmResourceTypeBusNumber;
		ResourceDescriptor->ShareDisposition = CmResourceShareShared;
		ResourceDescriptor->Flags = 0;
		ResourceDescriptor->BusNumber.Start = Addr32Data->Address.Minimum;
		ResourceDescriptor->BusNumber.Length =
		    Addr32Data->Address.AddressLength;
	    } else if (Addr32Data->ResourceType == ACPI_IO_RANGE) {
		ResourceDescriptor->Type = CmResourceTypePort;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr32Data->Decode == ACPI_POS_DECODE)
		    ResourceDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		ResourceDescriptor->Port.Start.QuadPart = Addr32Data->Address.Minimum;
		ResourceDescriptor->Port.Length = Addr32Data->Address.AddressLength;
	    } else {
		ResourceDescriptor->Type = CmResourceTypeMemory;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = 0;
		if (Addr32Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr32Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		ResourceDescriptor->Memory.Start.QuadPart = Addr32Data->Address.Minimum;
		ResourceDescriptor->Memory.Length = Addr32Data->Address.AddressLength;
	    }
	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS64: {
	    ACPI_RESOURCE_ADDRESS64 *Addr64Data =
		(ACPI_RESOURCE_ADDRESS64 *)&Resource->Data;
	    if (Addr64Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    if (Addr64Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		DPRINT1("64-bit bus address is not supported!\n");
		ResourceDescriptor->Type = CmResourceTypeBusNumber;
		ResourceDescriptor->ShareDisposition = CmResourceShareShared;
		ResourceDescriptor->Flags = 0;
		ResourceDescriptor->BusNumber.Start = (ULONG)
							    Addr64Data->Address.Minimum;
		ResourceDescriptor->BusNumber.Length =
		    Addr64Data->Address.AddressLength;
	    } else if (Addr64Data->ResourceType == ACPI_IO_RANGE) {
		ResourceDescriptor->Type = CmResourceTypePort;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr64Data->Decode == ACPI_POS_DECODE)
		    ResourceDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		ResourceDescriptor->Port.Start.QuadPart = Addr64Data->Address.Minimum;
		ResourceDescriptor->Port.Length = Addr64Data->Address.AddressLength;
	    } else {
		ResourceDescriptor->Type = CmResourceTypeMemory;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = 0;
		if (Addr64Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr64Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		ResourceDescriptor->Memory.Start.QuadPart = Addr64Data->Address.Minimum;
		ResourceDescriptor->Memory.Length = Addr64Data->Address.AddressLength;
	    }
	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64: {
	    ACPI_RESOURCE_EXTENDED_ADDRESS64 *Addr64Data =
		(ACPI_RESOURCE_EXTENDED_ADDRESS64 *)&Resource->Data;
	    if (Addr64Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    if (Addr64Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		DPRINT1("64-bit bus address is not supported!\n");
		ResourceDescriptor->Type = CmResourceTypeBusNumber;
		ResourceDescriptor->ShareDisposition = CmResourceShareShared;
		ResourceDescriptor->Flags = 0;
		ResourceDescriptor->BusNumber.Start = (ULONG)Addr64Data->Address.Minimum;
		ResourceDescriptor->BusNumber.Length =
		    Addr64Data->Address.AddressLength;
	    } else if (Addr64Data->ResourceType == ACPI_IO_RANGE) {
		ResourceDescriptor->Type = CmResourceTypePort;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr64Data->Decode == ACPI_POS_DECODE)
		    ResourceDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		ResourceDescriptor->Port.Start.QuadPart = Addr64Data->Address.Minimum;
		ResourceDescriptor->Port.Length = Addr64Data->Address.AddressLength;
	    } else {
		ResourceDescriptor->Type = CmResourceTypeMemory;
		ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		ResourceDescriptor->Flags = 0;
		if (Addr64Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr64Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		ResourceDescriptor->Memory.Start.QuadPart = Addr64Data->Address.Minimum;
		ResourceDescriptor->Memory.Length = Addr64Data->Address.AddressLength;
	    }
	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_MEMORY24: {
	    ACPI_RESOURCE_MEMORY24 *Mem24Data = (ACPI_RESOURCE_MEMORY24 *)&Resource->Data;
	    ResourceDescriptor->Type = CmResourceTypeMemory;
	    ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	    ResourceDescriptor->Flags = CM_RESOURCE_MEMORY_24;
	    if (Mem24Data->WriteProtect == ACPI_READ_ONLY_MEMORY)
		ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
	    else
		ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
	    ResourceDescriptor->Memory.Start.QuadPart = Mem24Data->Minimum;
	    ResourceDescriptor->Memory.Length = Mem24Data->AddressLength;

	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_MEMORY32: {
	    ACPI_RESOURCE_MEMORY32 *Mem32Data = (ACPI_RESOURCE_MEMORY32 *)&Resource->Data;
	    ResourceDescriptor->Type = CmResourceTypeMemory;
	    ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	    ResourceDescriptor->Flags = 0;
	    if (Mem32Data->WriteProtect == ACPI_READ_ONLY_MEMORY)
		ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
	    else
		ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
	    ResourceDescriptor->Memory.Start.QuadPart = Mem32Data->Minimum;
	    ResourceDescriptor->Memory.Length = Mem32Data->AddressLength;

	    ResourceDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32: {
	    ACPI_RESOURCE_FIXED_MEMORY32 *Memfixed32Data =
		(ACPI_RESOURCE_FIXED_MEMORY32 *)&Resource->Data;
	    ResourceDescriptor->Type = CmResourceTypeMemory;
	    ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	    ResourceDescriptor->Flags = 0;
	    if (Memfixed32Data->WriteProtect == ACPI_READ_ONLY_MEMORY)
		ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
	    else
		ResourceDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
	    ResourceDescriptor->Memory.Start.QuadPart = Memfixed32Data->Address;
	    ResourceDescriptor->Memory.Length = Memfixed32Data->AddressLength;

	    ResourceDescriptor++;
	    break;
	}
	default: {
	    break;
	}
	}
	Resource = ACPI_NEXT_RESOURCE(Resource);
    }

    if (wcsstr(DeviceData->HardwareIDs, L"PNP0A03") != 0 ||
	wcsstr(DeviceData->HardwareIDs, L"PNP0A08") != 0) {
	ACPI_PCI_ID PciBus = { .Segment = SegmentNumber };
	ResourceDescriptor->Type = CmResourceTypeMemory;
	ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	ResourceDescriptor->Memory.Length = PCI_SEGMENT_ECMA_SIZE;
	ResourceDescriptor->Memory.Start.QuadPart = OslGetPciConfigurationAddress(&PciBus);
	ResourceDescriptor++;
	ResourceDescriptor->Type = CmResourceTypeBusNumber;
	ResourceDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	ResourceDescriptor->BusNumber.Start = BusNumber;
	ResourceDescriptor->BusNumber.Length = 1;
    }

    ExFreePoolWithTag(Buffer.Pointer, 'BpcA');
    Irp->IoStatus.Information = (ULONG_PTR)ResourceList;
    return STATUS_SUCCESS;
}

static NTSTATUS Bus_PDO_QueryResourceRequirements(PPDO_DEVICE_DATA DeviceData, PIRP Irp)
{
    PAGED_CODE();
    ULONG NumberOfResources = 0;
    ACPI_STATUS AcpiStatus;
    ACPI_BUFFER Buffer;
    ACPI_RESOURCE *Resource;
    ULONG i, RequirementsListSize;
    PIO_RESOURCE_REQUIREMENTS_LIST RequirementsList;
    PIO_RESOURCE_DESCRIPTOR RequirementDescriptor;
    BOOLEAN CurrentRes = FALSE;
    BOOLEAN SeenStartDependent;

    if (!DeviceData->AcpiHandle) {
	return Irp->IoStatus.Status;
    }

    /* Get current resources */
    while (TRUE) {
	Buffer.Length = 0;
	if (CurrentRes)
	    AcpiStatus = AcpiGetCurrentResources(DeviceData->AcpiHandle, &Buffer);
	else
	    AcpiStatus = AcpiGetPossibleResources(DeviceData->AcpiHandle, &Buffer);
	if ((!ACPI_SUCCESS(AcpiStatus) && AcpiStatus != AE_BUFFER_OVERFLOW) ||
	    Buffer.Length == 0) {
	    if (!CurrentRes)
		CurrentRes = TRUE;
	    else
		return Irp->IoStatus.Status;
	} else
	    break;
    }

    Buffer.Pointer = ExAllocatePoolWithTag(Buffer.Length, 'BpcA');
    if (!Buffer.Pointer)
	return STATUS_INSUFFICIENT_RESOURCES;

    if (CurrentRes)
	AcpiStatus = AcpiGetCurrentResources(DeviceData->AcpiHandle, &Buffer);
    else
	AcpiStatus = AcpiGetPossibleResources(DeviceData->AcpiHandle, &Buffer);
    if (!ACPI_SUCCESS(AcpiStatus)) {
	DPRINT1("AcpiGetCurrentResources #2 failed (0x%x)\n", AcpiStatus);
	ASSERT(FALSE);
	return STATUS_UNSUCCESSFUL;
    }

    SeenStartDependent = FALSE;
    Resource = Buffer.Pointer;
    /* Count number of resources */
    while (Resource->Type != ACPI_RESOURCE_TYPE_END_TAG &&
	   Resource->Type != ACPI_RESOURCE_TYPE_END_DEPENDENT) {
	if (Resource->Type == ACPI_RESOURCE_TYPE_START_DEPENDENT) {
	    if (SeenStartDependent) {
		break;
	    }
	    SeenStartDependent = TRUE;
	}
	switch (Resource->Type) {
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ: {
	    ACPI_RESOURCE_EXTENDED_IRQ *IrqData =
		(ACPI_RESOURCE_EXTENDED_IRQ *)&Resource->Data;
	    if (IrqData->ProducerConsumer == ACPI_PRODUCER)
		break;
	    NumberOfResources += IrqData->InterruptCount;
	    break;
	}
	case ACPI_RESOURCE_TYPE_IRQ: {
	    ACPI_RESOURCE_IRQ *IrqData = (ACPI_RESOURCE_IRQ *)&Resource->Data;
	    NumberOfResources += IrqData->InterruptCount;
	    break;
	}
	case ACPI_RESOURCE_TYPE_DMA: {
	    ACPI_RESOURCE_DMA *DmaData = (ACPI_RESOURCE_DMA *)&Resource->Data;
	    NumberOfResources += DmaData->ChannelCount;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS16:
	case ACPI_RESOURCE_TYPE_ADDRESS32:
	case ACPI_RESOURCE_TYPE_ADDRESS64:
	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64: {
	    ACPI_RESOURCE_ADDRESS *ResAddr = (ACPI_RESOURCE_ADDRESS *)&Resource->Data;
	    if (ResAddr->ProducerConsumer == ACPI_PRODUCER)
		break;
	    NumberOfResources++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_MEMORY24:
	case ACPI_RESOURCE_TYPE_MEMORY32:
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
	case ACPI_RESOURCE_TYPE_FIXED_IO:
	case ACPI_RESOURCE_TYPE_IO: {
	    NumberOfResources++;
	    break;
	}
	default: {
	    break;
	}
	}
	Resource = ACPI_NEXT_RESOURCE(Resource);
    }

    /* For the root PCI bus we find the PCI segment group number and pass
     * the its Enhanced Configuration Mechanism Address to the pci bus driver. */
    ULONGLONG SegmentNumber = 0;
    ULONGLONG BusNumber = 0;
    if (wcsstr(DeviceData->HardwareIDs, L"PNP0A03") != 0 ||
	wcsstr(DeviceData->HardwareIDs, L"PNP0A08") != 0) {
	PciGetSegmentNumber(DeviceData, &SegmentNumber);
	PciGetBusNumber(DeviceData, &BusNumber);
	NumberOfResources += 2;
    }

    RequirementsListSize = sizeof(IO_RESOURCE_REQUIREMENTS_LIST) + sizeof(IO_RESOURCE_LIST) +
			   sizeof(IO_RESOURCE_DESCRIPTOR) * NumberOfResources;
    RequirementsList = ExAllocatePoolWithTag(RequirementsListSize, 'RpcA');

    if (!RequirementsList) {
	ExFreePoolWithTag(Buffer.Pointer, 'BpcA');
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    RequirementsList->ListSize = RequirementsListSize;
    RequirementsList->InterfaceType = Internal;
    RequirementsList->BusNumber = 0;
    RequirementsList->SlotNumber = 0; /* Not used by WDM drivers */
    RequirementsList->AlternativeLists = 1;
    RequirementsList->List[0].Version = 1;
    RequirementsList->List[0].Revision = 1;
    RequirementsList->List[0].Count = NumberOfResources;
    RequirementDescriptor = RequirementsList->List[0].Descriptors;

    /* Fill resources list structure */
    SeenStartDependent = FALSE;
    Resource = Buffer.Pointer;
    while (Resource->Type != ACPI_RESOURCE_TYPE_END_TAG &&
	   Resource->Type != ACPI_RESOURCE_TYPE_END_DEPENDENT) {
	if (Resource->Type == ACPI_RESOURCE_TYPE_START_DEPENDENT) {
	    if (SeenStartDependent) {
		break;
	    }
	    SeenStartDependent = TRUE;
	}
	switch (Resource->Type) {
	case ACPI_RESOURCE_TYPE_EXTENDED_IRQ: {
	    ACPI_RESOURCE_EXTENDED_IRQ *IrqData = &Resource->Data.ExtendedIrq;
	    if (IrqData->ProducerConsumer == ACPI_PRODUCER)
		break;
	    for (i = 0; i < IrqData->InterruptCount; i++) {
		RequirementDescriptor->Option = (i == 0) ? IO_RESOURCE_PREFERRED :
							   IO_RESOURCE_ALTERNATIVE;
		RequirementDescriptor->Type = CmResourceTypeInterrupt;
		RequirementDescriptor->ShareDisposition =
		    (IrqData->Shareable == ACPI_SHARED ? CmResourceShareShared :
							  CmResourceShareDeviceExclusive);
		RequirementDescriptor->Flags =
		    (IrqData->Triggering == ACPI_LEVEL_SENSITIVE ?
			 CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE :
			 CM_RESOURCE_INTERRUPT_LATCHED);
		RequirementDescriptor->Interrupt.MinimumVector =
		    RequirementDescriptor->Interrupt.MaximumVector =
			IrqData->Interrupts[i];
		RequirementDescriptor->Interrupt.TargetedProcessors = (KAFFINITY)-1;

		RequirementDescriptor++;
	    }
	    break;
	}
	case ACPI_RESOURCE_TYPE_IRQ: {
	    ACPI_RESOURCE_IRQ *IrqData = &Resource->Data.Irq;
	    for (i = 0; i < IrqData->InterruptCount; i++) {
		RequirementDescriptor->Option = (i == 0) ? IO_RESOURCE_PREFERRED :
							   IO_RESOURCE_ALTERNATIVE;
		RequirementDescriptor->Type = CmResourceTypeInterrupt;
		RequirementDescriptor->ShareDisposition =
		    (IrqData->Shareable == ACPI_SHARED ? CmResourceShareShared :
							  CmResourceShareDeviceExclusive);
		RequirementDescriptor->Flags =
		    (IrqData->Triggering == ACPI_LEVEL_SENSITIVE ?
			 CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE :
			 CM_RESOURCE_INTERRUPT_LATCHED);
		RequirementDescriptor->Interrupt.MinimumVector =
		    RequirementDescriptor->Interrupt.MaximumVector =
			IrqData->Interrupts[i];
		RequirementDescriptor->Interrupt.TargetedProcessors = (KAFFINITY)-1;

		RequirementDescriptor++;
	    }
	    break;
	}
	case ACPI_RESOURCE_TYPE_DMA: {
	    ACPI_RESOURCE_DMA *DmaData = &Resource->Data.Dma;
	    for (i = 0; i < DmaData->ChannelCount; i++) {
		RequirementDescriptor->Type = CmResourceTypeDma;
		RequirementDescriptor->Flags = 0;
		switch (DmaData->Type) {
		case ACPI_TYPE_A:
		    RequirementDescriptor->Flags |= CM_RESOURCE_DMA_TYPE_A;
		    break;
		case ACPI_TYPE_B:
		    RequirementDescriptor->Flags |= CM_RESOURCE_DMA_TYPE_B;
		    break;
		case ACPI_TYPE_F:
		    RequirementDescriptor->Flags |= CM_RESOURCE_DMA_TYPE_F;
		    break;
		}
		if (DmaData->BusMaster == ACPI_BUS_MASTER)
		    RequirementDescriptor->Flags |= CM_RESOURCE_DMA_BUS_MASTER;
		switch (DmaData->Transfer) {
		case ACPI_TRANSFER_8:
		    RequirementDescriptor->Flags |= CM_RESOURCE_DMA_8;
		    break;
		case ACPI_TRANSFER_16:
		    RequirementDescriptor->Flags |= CM_RESOURCE_DMA_16;
		    break;
		case ACPI_TRANSFER_8_16:
		    RequirementDescriptor->Flags |= CM_RESOURCE_DMA_8_AND_16;
		    break;
		}

		RequirementDescriptor->Option = (i == 0) ? IO_RESOURCE_PREFERRED :
							   IO_RESOURCE_ALTERNATIVE;
		RequirementDescriptor->ShareDisposition = CmResourceShareDriverExclusive;
		RequirementDescriptor->Dma.MinimumChannel =
		    RequirementDescriptor->Dma.MaximumChannel = DmaData->Channels[i];
		RequirementDescriptor++;
	    }
	    break;
	}
	case ACPI_RESOURCE_TYPE_IO: {
	    ACPI_RESOURCE_IO *IoData = &Resource->Data.Io;
	    RequirementDescriptor->Flags = CM_RESOURCE_PORT_IO;
	    if (IoData->IoDecode == ACPI_DECODE_16)
		RequirementDescriptor->Flags |= CM_RESOURCE_PORT_16_BIT_DECODE;
	    else
		RequirementDescriptor->Flags |= CM_RESOURCE_PORT_10_BIT_DECODE;
	    RequirementDescriptor->Port.Length = IoData->AddressLength;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    RequirementDescriptor->Type = CmResourceTypePort;
	    RequirementDescriptor->ShareDisposition = CmResourceShareDriverExclusive;
	    RequirementDescriptor->Port.Alignment = IoData->Alignment;
	    RequirementDescriptor->Port.MinimumAddress.QuadPart = IoData->Minimum;
	    RequirementDescriptor->Port.MaximumAddress.QuadPart =
		IoData->Maximum + IoData->AddressLength - 1;

	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_FIXED_IO: {
	    ACPI_RESOURCE_FIXED_IO *IoData = &Resource->Data.FixedIo;
	    RequirementDescriptor->Flags = CM_RESOURCE_PORT_IO;
	    RequirementDescriptor->Port.Length = IoData->AddressLength;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    RequirementDescriptor->Type = CmResourceTypePort;
	    RequirementDescriptor->ShareDisposition = CmResourceShareDriverExclusive;
	    RequirementDescriptor->Port.Alignment = 1;
	    RequirementDescriptor->Port.MinimumAddress.QuadPart = IoData->Address;
	    RequirementDescriptor->Port.MaximumAddress.QuadPart =
		IoData->Address + IoData->AddressLength - 1;

	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS16: {
	    ACPI_RESOURCE_ADDRESS16 *Addr16Data = &Resource->Data.Address16;
	    if (Addr16Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    if (Addr16Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		RequirementDescriptor->Type = CmResourceTypeBusNumber;
		RequirementDescriptor->ShareDisposition = CmResourceShareShared;
		RequirementDescriptor->Flags = 0;
		RequirementDescriptor->BusNumber.MinBusNumber =
		    Addr16Data->Address.Minimum;
		RequirementDescriptor->BusNumber.MaxBusNumber =
		    Addr16Data->Address.Maximum + Addr16Data->Address.AddressLength - 1;
		RequirementDescriptor->BusNumber.Length =
		    Addr16Data->Address.AddressLength;
	    } else if (Addr16Data->ResourceType == ACPI_IO_RANGE) {
		RequirementDescriptor->Type = CmResourceTypePort;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr16Data->Decode == ACPI_POS_DECODE)
		    RequirementDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		RequirementDescriptor->Port.MinimumAddress.QuadPart =
		    Addr16Data->Address.Minimum;
		RequirementDescriptor->Port.MaximumAddress.QuadPart =
		    Addr16Data->Address.Maximum + Addr16Data->Address.AddressLength - 1;
		RequirementDescriptor->Port.Length = Addr16Data->Address.AddressLength;
	    } else {
		RequirementDescriptor->Type = CmResourceTypeMemory;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = 0;
		if (Addr16Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr16Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		RequirementDescriptor->Memory.MinimumAddress.QuadPart =
		    Addr16Data->Address.Minimum;
		RequirementDescriptor->Memory.MaximumAddress.QuadPart =
		    Addr16Data->Address.Maximum + Addr16Data->Address.AddressLength - 1;
		RequirementDescriptor->Memory.Length =
		    Addr16Data->Address.AddressLength;
	    }
	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS32: {
	    ACPI_RESOURCE_ADDRESS32 *Addr32Data = &Resource->Data.Address32;
	    if (Addr32Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    if (Addr32Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		RequirementDescriptor->Type = CmResourceTypeBusNumber;
		RequirementDescriptor->ShareDisposition = CmResourceShareShared;
		RequirementDescriptor->Flags = 0;
		RequirementDescriptor->BusNumber.MinBusNumber =
		    Addr32Data->Address.Minimum;
		RequirementDescriptor->BusNumber.MaxBusNumber =
		    Addr32Data->Address.Maximum + Addr32Data->Address.AddressLength - 1;
		RequirementDescriptor->BusNumber.Length =
		    Addr32Data->Address.AddressLength;
	    } else if (Addr32Data->ResourceType == ACPI_IO_RANGE) {
		RequirementDescriptor->Type = CmResourceTypePort;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr32Data->Decode == ACPI_POS_DECODE)
		    RequirementDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		RequirementDescriptor->Port.MinimumAddress.QuadPart =
		    Addr32Data->Address.Minimum;
		RequirementDescriptor->Port.MaximumAddress.QuadPart =
		    Addr32Data->Address.Maximum + Addr32Data->Address.AddressLength - 1;
		RequirementDescriptor->Port.Length = Addr32Data->Address.AddressLength;
	    } else {
		RequirementDescriptor->Type = CmResourceTypeMemory;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = 0;
		if (Addr32Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr32Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		RequirementDescriptor->Memory.MinimumAddress.QuadPart =
		    Addr32Data->Address.Minimum;
		RequirementDescriptor->Memory.MaximumAddress.QuadPart =
		    Addr32Data->Address.Maximum + Addr32Data->Address.AddressLength - 1;
		RequirementDescriptor->Memory.Length =
		    Addr32Data->Address.AddressLength;
	    }
	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_ADDRESS64: {
	    ACPI_RESOURCE_ADDRESS64 *Addr64Data = &Resource->Data.Address64;
	    if (Addr64Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    if (Addr64Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		DPRINT1("64-bit bus address is not supported!\n");
		RequirementDescriptor->Type = CmResourceTypeBusNumber;
		RequirementDescriptor->ShareDisposition = CmResourceShareShared;
		RequirementDescriptor->Flags = 0;
		RequirementDescriptor->BusNumber.MinBusNumber =
		    (ULONG)Addr64Data->Address.Minimum;
		RequirementDescriptor->BusNumber.MaxBusNumber =
		    (ULONG)Addr64Data->Address.Maximum +
		    Addr64Data->Address.AddressLength - 1;
		RequirementDescriptor->BusNumber.Length =
		    Addr64Data->Address.AddressLength;
	    } else if (Addr64Data->ResourceType == ACPI_IO_RANGE) {
		RequirementDescriptor->Type = CmResourceTypePort;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr64Data->Decode == ACPI_POS_DECODE)
		    RequirementDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		RequirementDescriptor->Port.MinimumAddress.QuadPart =
		    Addr64Data->Address.Minimum;
		RequirementDescriptor->Port.MaximumAddress.QuadPart =
		    Addr64Data->Address.Maximum + Addr64Data->Address.AddressLength - 1;
		RequirementDescriptor->Port.Length = Addr64Data->Address.AddressLength;
	    } else {
		RequirementDescriptor->Type = CmResourceTypeMemory;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = 0;
		if (Addr64Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr64Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		RequirementDescriptor->Memory.MinimumAddress.QuadPart =
		    Addr64Data->Address.Minimum;
		RequirementDescriptor->Memory.MaximumAddress.QuadPart =
		    Addr64Data->Address.Maximum + Addr64Data->Address.AddressLength - 1;
		RequirementDescriptor->Memory.Length =
		    Addr64Data->Address.AddressLength;
	    }
	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64: {
	    ACPI_RESOURCE_EXTENDED_ADDRESS64 *Addr64Data = &Resource->Data.ExtAddress64;
	    if (Addr64Data->ProducerConsumer == ACPI_PRODUCER)
		break;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    if (Addr64Data->ResourceType == ACPI_BUS_NUMBER_RANGE) {
		DPRINT1("64-bit bus address is not supported!\n");
		RequirementDescriptor->Type = CmResourceTypeBusNumber;
		RequirementDescriptor->ShareDisposition = CmResourceShareShared;
		RequirementDescriptor->Flags = 0;
		RequirementDescriptor->BusNumber.MinBusNumber =
		    (ULONG)Addr64Data->Address.Minimum;
		RequirementDescriptor->BusNumber.MaxBusNumber =
		    (ULONG)Addr64Data->Address.Maximum +
		    Addr64Data->Address.AddressLength - 1;
		RequirementDescriptor->BusNumber.Length =
		    Addr64Data->Address.AddressLength;
	    } else if (Addr64Data->ResourceType == ACPI_IO_RANGE) {
		RequirementDescriptor->Type = CmResourceTypePort;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = CM_RESOURCE_PORT_IO;
		if (Addr64Data->Decode == ACPI_POS_DECODE)
		    RequirementDescriptor->Flags |= CM_RESOURCE_PORT_POSITIVE_DECODE;
		RequirementDescriptor->Port.MinimumAddress.QuadPart =
		    Addr64Data->Address.Minimum;
		RequirementDescriptor->Port.MaximumAddress.QuadPart =
		    Addr64Data->Address.Maximum + Addr64Data->Address.AddressLength - 1;
		RequirementDescriptor->Port.Length = Addr64Data->Address.AddressLength;
	    } else {
		RequirementDescriptor->Type = CmResourceTypeMemory;
		RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
		RequirementDescriptor->Flags = 0;
		if (Addr64Data->Info.Mem.WriteProtect == ACPI_READ_ONLY_MEMORY)
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
		else
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
		switch (Addr64Data->Info.Mem.Caching) {
		case ACPI_CACHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_CACHEABLE;
		    break;
		case ACPI_WRITE_COMBINING_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_COMBINEDWRITE;
		    break;
		case ACPI_PREFETCHABLE_MEMORY:
		    RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_PREFETCHABLE;
		    break;
		}
		RequirementDescriptor->Memory.MinimumAddress.QuadPart =
		    Addr64Data->Address.Minimum;
		RequirementDescriptor->Memory.MaximumAddress.QuadPart =
		    Addr64Data->Address.Maximum + Addr64Data->Address.AddressLength - 1;
		RequirementDescriptor->Memory.Length =
		    Addr64Data->Address.AddressLength;
	    }
	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_MEMORY24: {
	    ACPI_RESOURCE_MEMORY24 *Mem24Data = &Resource->Data.Memory24;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    RequirementDescriptor->Type = CmResourceTypeMemory;
	    RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	    RequirementDescriptor->Flags = CM_RESOURCE_MEMORY_24;
	    if (Mem24Data->WriteProtect == ACPI_READ_ONLY_MEMORY)
		RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
	    else
		RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
	    RequirementDescriptor->Memory.MinimumAddress.QuadPart = Mem24Data->Minimum;
	    RequirementDescriptor->Memory.MaximumAddress.QuadPart =
		Mem24Data->Maximum + Mem24Data->AddressLength - 1;
	    RequirementDescriptor->Memory.Length = Mem24Data->AddressLength;

	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_MEMORY32: {
	    ACPI_RESOURCE_MEMORY32 *Mem32Data = &Resource->Data.Memory32;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    RequirementDescriptor->Type = CmResourceTypeMemory;
	    RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	    RequirementDescriptor->Flags = 0;
	    if (Mem32Data->WriteProtect == ACPI_READ_ONLY_MEMORY)
		RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
	    else
		RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
	    RequirementDescriptor->Memory.MinimumAddress.QuadPart = Mem32Data->Minimum;
	    RequirementDescriptor->Memory.MaximumAddress.QuadPart =
		Mem32Data->Maximum + Mem32Data->AddressLength - 1;
	    RequirementDescriptor->Memory.Length = Mem32Data->AddressLength;

	    RequirementDescriptor++;
	    break;
	}
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32: {
	    ACPI_RESOURCE_FIXED_MEMORY32 *Fixedmem32Data = &Resource->Data.FixedMemory32;
	    RequirementDescriptor->Option = CurrentRes ? 0 : IO_RESOURCE_PREFERRED;
	    RequirementDescriptor->Type = CmResourceTypeMemory;
	    RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	    RequirementDescriptor->Flags = 0;
	    if (Fixedmem32Data->WriteProtect == ACPI_READ_ONLY_MEMORY)
		RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_ONLY;
	    else
		RequirementDescriptor->Flags |= CM_RESOURCE_MEMORY_READ_WRITE;
	    RequirementDescriptor->Memory.MinimumAddress.QuadPart =
		Fixedmem32Data->Address;
	    RequirementDescriptor->Memory.MaximumAddress.QuadPart =
		Fixedmem32Data->Address + Fixedmem32Data->AddressLength - 1;
	    RequirementDescriptor->Memory.Length = Fixedmem32Data->AddressLength;

	    RequirementDescriptor++;
	    break;
	}
	default: {
	    break;
	}
	}
	Resource = ACPI_NEXT_RESOURCE(Resource);
    }
    ExFreePoolWithTag(Buffer.Pointer, 'BpcA');

    if (wcsstr(DeviceData->HardwareIDs, L"PNP0A03") != 0 ||
	wcsstr(DeviceData->HardwareIDs, L"PNP0A08") != 0) {
	ACPI_PCI_ID PciBus = { .Segment = SegmentNumber, .Bus = BusNumber };
	RequirementDescriptor->Type = CmResourceTypeMemory;
	RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	RequirementDescriptor->Memory.Length = PCI_SEGMENT_ECMA_SIZE;
	RequirementDescriptor->Memory.MinimumAddress.QuadPart =
	    OslGetPciConfigurationAddress(&PciBus);
	RequirementDescriptor->Memory.MaximumAddress.QuadPart =
	    RequirementDescriptor->Memory.MinimumAddress.QuadPart + PCI_SEGMENT_ECMA_SIZE - 1;
	RequirementDescriptor++;
	RequirementDescriptor->Type = CmResourceTypeBusNumber;
	RequirementDescriptor->ShareDisposition = CmResourceShareDeviceExclusive;
	RequirementDescriptor->BusNumber.MinBusNumber = BusNumber;
	RequirementDescriptor->BusNumber.MaxBusNumber = BusNumber;
	RequirementDescriptor->BusNumber.Length = 1;
    }

    Irp->IoStatus.Information = (ULONG_PTR)RequirementsList;

    return STATUS_SUCCESS;
}

/*++

Routine Description:

    The PnP Manager sends this IRP to gather information about
    devices with a relationship to the specified device.
    Bus drivers must handle this request for TargetDeviceRelation
    for their child devices (child PDOs).

    If a driver returns relations in response to this IRP,
    it allocates a DEVICE_RELATIONS structure from paged
    memory containing a count and the appropriate number of
    device object pointers. The PnP Manager frees the structure
    when it is no longer needed. If a driver replaces a
    DEVICE_RELATIONS structure allocated by another driver,
    it must free the previous structure.

    A driver must reference the PDO of any device that it
    reports in this IRP (ObReferenceObject). The PnP Manager
    removes the reference when appropriate.

Arguments:

    DeviceData - Pointer to the PDO's device extension.
    Irp          - Pointer to the irp.

Return Value:

    NT STATUS

--*/
static NTSTATUS Bus_PDO_QueryDeviceRelations(PPDO_DEVICE_DATA DeviceData, PIRP Irp)
{
    PAGED_CODE();
    PIO_STACK_LOCATION Stack;
    PDEVICE_RELATIONS DeviceRelations;
    NTSTATUS Status;

    Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->Parameters.QueryDeviceRelations.Type) {
    case TargetDeviceRelation:

	DeviceRelations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
	if (DeviceRelations) {
	    //
	    // Only PDO can handle this request. Somebody above
	    // is not playing by rule.
	    //
	    ASSERTMSG("Someone above is handling TargetDeviceRelation\n",
		      !DeviceRelations);
	}

	DeviceRelations = ExAllocatePoolWithTag(sizeof(DEVICE_RELATIONS), ACPI_TAG);
	if (!DeviceRelations) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    break;
	}

	//
	// There is only one PDO pointer in the structure
	// for this relation type. The PnP Manager removes
	// the reference to the PDO when the driver or application
	// un-registers for notification on the device.
	//

	DeviceRelations->Count = 1;
	DeviceRelations->Objects[0] = DeviceData->Common.Self;
	// ObReferenceObject(DeviceData->Common.Self);

	Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = (ULONG_PTR)DeviceRelations;
	break;

    case BusRelations: // Not handled by PDO
    case EjectionRelations: // optional for PDO
    case RemovalRelations: // // optional for PDO
    default:
	Status = Irp->IoStatus.Status;
    }

    return Status;
}

/*++

Routine Description:

    The PnP Manager uses this IRP to request the type and
    instance number of a device's parent bus. Bus drivers
    should handle this request for their child devices (PDOs).

Arguments:

    DeviceData - Pointer to the PDO's device extension.
    Irp          - Pointer to the irp.

Return Value:

    NT STATUS

--*/
static NTSTATUS Bus_PDO_QueryBusInformation(PPDO_DEVICE_DATA DeviceData, PIRP Irp)
{
    PAGED_CODE();
    PPNP_BUS_INFORMATION BusInfo;

    BusInfo = ExAllocatePoolWithTag(sizeof(PNP_BUS_INFORMATION), ACPI_TAG);

    if (BusInfo == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    BusInfo->BusTypeGuid = GUID_ACPI_INTERFACE_STANDARD;

    BusInfo->LegacyBusType = InternalPowerBus;

    BusInfo->BusNumber = 0; //fixme

    Irp->IoStatus.Information = (ULONG_PTR)BusInfo;

    return STATUS_SUCCESS;
}

static NTSTATUS Bus_GetDeviceCapabilities(PDEVICE_OBJECT DeviceObject,
					  PDEVICE_CAPABILITIES DeviceCapabilities)
{
    PAGED_CODE();
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    PDEVICE_OBJECT TargetObject;
    PIO_STACK_LOCATION IrpStack;
    KEVENT Event;
    PIRP PnpIrp;

    //
    // Initialize the capabilities that we will send down
    //
    RtlZeroMemory(DeviceCapabilities, sizeof(DEVICE_CAPABILITIES));
    DeviceCapabilities->Size = sizeof(DEVICE_CAPABILITIES);
    DeviceCapabilities->Version = 1;
    DeviceCapabilities->Address = -1;
    DeviceCapabilities->UINumber = -1;

    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    TargetObject = IoGetAttachedDeviceReference(DeviceObject);

    //
    // Build an Irp
    //
    PnpIrp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, TargetObject, NULL,
					  0, NULL, &Event, &IoStatus);
    if (PnpIrp == NULL) {
	Status = STATUS_INSUFFICIENT_RESOURCES;
	goto GetDeviceCapabilitiesExit;
    }

    //
    // Pnp Irps all begin life as STATUS_NOT_SUPPORTED;
    //
    PnpIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    //
    // Get the top of stack
    //
    IrpStack = IoGetNextIrpStackLocation(PnpIrp);

    //
    // Set the top of stack
    //
    RtlZeroMemory(IrpStack, sizeof(IO_STACK_LOCATION));
    IrpStack->MajorFunction = IRP_MJ_PNP;
    IrpStack->MinorFunction = IRP_MN_QUERY_CAPABILITIES;
    IrpStack->Parameters.DeviceCapabilities.Capabilities = DeviceCapabilities;

    //
    // Call the driver and wait for the result
    //
    Status = IoCallDriver(TargetObject, PnpIrp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

GetDeviceCapabilitiesExit:
    //
    // Done with reference
    //
    ObDereferenceObject(TargetObject);

    //
    // Done
    //
    return Status;
}

NTSTATUS Bus_PDO_PnP(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpStack,
		     PPDO_DEVICE_DATA DeviceData)
{
    PAGED_CODE();
    NTSTATUS Status;
    POWER_STATE State;
    PACPI_DEVICE Device = NULL;

    if (DeviceData->AcpiHandle)
	AcpiBusGetDevice(DeviceData->AcpiHandle, &Device);

    //
    // NB: Because we are a bus enumerator, we have no one to whom we could
    // defer these irps.  Therefore we do not pass them down but merely
    // return them.
    //

    switch (IrpStack->MinorFunction) {
    case IRP_MN_START_DEVICE:
	//
	// Here we do what ever initialization and ``turning on'' that is
	// required to allow others to access this device.
	// Power up the device.
	//
	if (DeviceData->AcpiHandle && AcpiBusPowerManageable(DeviceData->AcpiHandle) &&
	    !ACPI_SUCCESS(AcpiBusSetPower(DeviceData->AcpiHandle, ACPI_STATE_D0))) {
	    DPRINT1("Device %p failed to start!\n", DeviceData->AcpiHandle);
	    Status = STATUS_UNSUCCESSFUL;
	    break;
	}

	DeviceData->InterfaceName.Length = 0;
	Status = STATUS_SUCCESS;

	if (!Device) {
	    Status = IoRegisterDeviceInterface(DeviceData->Common.Self,
					       &GUID_DEVICE_SYS_BUTTON, NULL,
					       &DeviceData->InterfaceName);
	} else if (Device->Flags.HardwareId &&
		   strstr(Device->Pnp.HardwareId, ACPI_THERMAL_HID)) {
	    Status = IoRegisterDeviceInterface(DeviceData->Common.Self,
					       &GUID_DEVICE_THERMAL_ZONE, NULL,
					       &DeviceData->InterfaceName);
	} else if (Device->Flags.HardwareId &&
		   strstr(Device->Pnp.HardwareId, ACPI_FAN_HID)) {
	    Status = IoRegisterDeviceInterface(DeviceData->Common.Self, &GUID_DEVICE_FAN,
					       NULL, &DeviceData->InterfaceName);
	} else if (Device->Flags.HardwareId &&
		   strstr(Device->Pnp.HardwareId, ACPI_BUTTON_HID_LID)) {
	    Status = IoRegisterDeviceInterface(DeviceData->Common.Self, &GUID_DEVICE_LID,
					       NULL, &DeviceData->InterfaceName);
	} else if (Device->Flags.HardwareId &&
		   strstr(Device->Pnp.HardwareId, ACPI_PROCESSOR_HID)) {
	    Status = IoRegisterDeviceInterface(DeviceData->Common.Self,
					       &GUID_DEVICE_PROCESSOR, NULL,
					       &DeviceData->InterfaceName);
	}

	/* Failure to register an interface is not a fatal failure so don't
	 * return a failure status */
	if (NT_SUCCESS(Status) && DeviceData->InterfaceName.Length != 0)
	    IoSetDeviceInterfaceState(&DeviceData->InterfaceName, TRUE);

	State.DeviceState = PowerDeviceD0;
	PoSetPowerState(DeviceData->Common.Self, DevicePowerState, State);
	DeviceData->Common.DevicePowerState = PowerDeviceD0;
	SET_NEW_PNP_STATE(DeviceData->Common, Started);
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_STOP_DEVICE:

	if (DeviceData->InterfaceName.Length != 0)
	    IoSetDeviceInterfaceState(&DeviceData->InterfaceName, FALSE);

	//
	// Here we shut down the device and give up and unmap any resources
	// we acquired for the device.
	//
	if (DeviceData->AcpiHandle && AcpiBusPowerManageable(DeviceData->AcpiHandle) &&
	    !ACPI_SUCCESS(AcpiBusSetPower(DeviceData->AcpiHandle, ACPI_STATE_D3))) {
	    DPRINT1("Device %p failed to stop!\n", DeviceData->AcpiHandle);
	    Status = STATUS_UNSUCCESSFUL;
	    break;
	}

	State.DeviceState = PowerDeviceD3;
	PoSetPowerState(DeviceData->Common.Self, DevicePowerState, State);
	DeviceData->Common.DevicePowerState = PowerDeviceD3;
	SET_NEW_PNP_STATE(DeviceData->Common, Stopped);
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_QUERY_STOP_DEVICE:

	//
	// No reason here why we can't stop the device.
	// If there were a reason we should speak now, because answering success
	// here may result in a stop device irp.
	//

	SET_NEW_PNP_STATE(DeviceData->Common, StopPending);
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_CANCEL_STOP_DEVICE:

	//
	// The stop was canceled.  Whatever state we set, or resources we put
	// on hold in anticipation of the forthcoming STOP device IRP should be
	// put back to normal.  Someone, in the long list of concerned parties,
	// has failed the stop device query.
	//

	//
	// First check to see whether you have received cancel-stop
	// without first receiving a query-stop. This could happen if someone
	// above us fails a query-stop and passes down the subsequent
	// cancel-stop.
	//

	if (StopPending == DeviceData->Common.DevicePnPState) {
	    //
	    // We did receive a query-stop, so restore.
	    //
	    RESTORE_PREVIOUS_PNP_STATE(DeviceData->Common);
	}
	Status = STATUS_SUCCESS; // We must not fail this IRP.
	break;

    case IRP_MN_REMOVE_DEVICE:
	//
	// We handle REMOVE_DEVICE just like STOP_DEVICE. This is because
	// the device is still physically present (or at least we don't know any better)
	// so we have to retain the PDO after stopping and removing power from it.
	//
	if (DeviceData->InterfaceName.Length != 0)
	    IoSetDeviceInterfaceState(&DeviceData->InterfaceName, FALSE);

	if (DeviceData->AcpiHandle && AcpiBusPowerManageable(DeviceData->AcpiHandle) &&
	    !ACPI_SUCCESS(AcpiBusSetPower(DeviceData->AcpiHandle, ACPI_STATE_D3))) {
	    DPRINT1("Device %p failed to enter D3!\n", DeviceData->AcpiHandle);
	    State.DeviceState = PowerDeviceD3;
	    PoSetPowerState(DeviceData->Common.Self, DevicePowerState, State);
	    DeviceData->Common.DevicePowerState = PowerDeviceD3;
	}

	SET_NEW_PNP_STATE(DeviceData->Common, Stopped);
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
	SET_NEW_PNP_STATE(DeviceData->Common, RemovalPending);
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
	if (RemovalPending == DeviceData->Common.DevicePnPState) {
	    RESTORE_PREVIOUS_PNP_STATE(DeviceData->Common);
	}
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_QUERY_CAPABILITIES:

	//
	// Return the capabilities of a device, such as whether the device
	// can be locked or ejected..etc
	//

	Status = Bus_PDO_QueryDeviceCaps(DeviceData, Irp);

	break;

    case IRP_MN_QUERY_ID:

	// Query the IDs of the device
	Status = Bus_PDO_QueryDeviceId(DeviceData, Irp);

	break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:

	DPRINT("\tQueryDeviceRelation Type: %s\n",
	       DbgDeviceRelationString(IrpStack->Parameters.QueryDeviceRelations.Type));

	Status = Bus_PDO_QueryDeviceRelations(DeviceData, Irp);

	break;

    case IRP_MN_QUERY_DEVICE_TEXT:

	Status = Bus_PDO_QueryDeviceText(DeviceData, Irp);

	break;

    case IRP_MN_QUERY_RESOURCES:

	Status = Bus_PDO_QueryResources(DeviceData, Irp);

	break;

    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:

	Status = Bus_PDO_QueryResourceRequirements(DeviceData, Irp);

	break;

    case IRP_MN_QUERY_BUS_INFORMATION:

	Status = Bus_PDO_QueryBusInformation(DeviceData, Irp);

	break;

    case IRP_MN_QUERY_INTERFACE:
	__fallthrough;

    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:

	//
	// OPTIONAL for bus drivers.
	// The PnP Manager sends this IRP to a device
	// stack so filter and function drivers can adjust the
	// resources required by the device, if appropriate.
	//

	__fallthrough;

    case IRP_MN_QUERY_PNP_DEVICE_STATE:

	//
	// OPTIONAL for bus drivers.
	// The PnP Manager sends this IRP after the drivers for
	// a device return success from the IRP_MN_START_DEVICE
	// request. The PnP Manager also sends this IRP when a
	// driver for the device calls IoInvalidateDeviceState.
	//

	__fallthrough;

    case IRP_MN_READ_CONFIG:
    case IRP_MN_WRITE_CONFIG:

	//
	// Bus drivers for buses with configuration space must handle
	// this request for their child devices. Our devices don't
	// have a config space.
	//

	__fallthrough;

    case IRP_MN_SET_LOCK:

	Status = STATUS_NOT_SUPPORTED;

	break;

    default:

	//
	// For PnP requests to the PDO that we do not understand we should
	// return the IRP WITHOUT setting the status or information fields.
	// These fields may have already been set by a filter (eg acpi).
	Status = Irp->IoStatus.Status;

	break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
