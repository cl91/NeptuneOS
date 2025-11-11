/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Storport FDO code
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"
#include <srbhelper.h>

/* FUNCTIONS ******************************************************************/

static NTAPI BOOLEAN PortFdoInterruptRoutine(IN PKINTERRUPT Interrupt,
					     IN PVOID ServiceContext)
{
    DPRINT1("PortFdoInterruptRoutine(%p %p)\n", Interrupt, ServiceContext);

    PINTERRUPT_INFO InterruptInfo = ServiceContext;
    PFDO_DEVICE_EXTENSION FdoExt = InterruptInfo->FdoExt;

    if (FdoExt->Miniport.PortConfig.HwMSInterruptRoutine) {
	return MiniportHwMessageInterrupt(&FdoExt->Miniport,
					  InterruptInfo - FdoExt->ConnectedInterrupts);
    }
    return MiniportHwInterrupt(&FdoExt->Miniport);
}

static NTSTATUS GetInterruptInfoFromResources(PFDO_DEVICE_EXTENSION DeviceExtension)
{
    DPRINT1("GetInterruptInfoFromResources(%p)\n", DeviceExtension);

    assert(!DeviceExtension->NumberfOfConnectedInterrupts);
    DeviceExtension->NumberfOfConnectedInterrupts = 0;
    PCM_FULL_RESOURCE_DESCRIPTOR Full = DeviceExtension->AllocatedResources->List;
    for (ULONG i = 0; i < DeviceExtension->AllocatedResources->Count; i++) {
	for (ULONG j = 0; j < Full->PartialResourceList.Count; j++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial =
		Full->PartialResourceList.PartialDescriptors + j;

	    switch (Partial->Type) {
	    case CmResourceTypeInterrupt:
		if (!(Partial->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
		    assert(FALSE);
		    continue;
		}
		DeviceExtension->NumberfOfConnectedInterrupts +=
		    Partial->MessageInterrupt.Raw.MessageCount;
	    }
	}

	Full = CmGetNextResourceDescriptor(Full);
    }

    ULONG Size = sizeof(INTERRUPT_INFO) * DeviceExtension->NumberfOfConnectedInterrupts;
    DeviceExtension->ConnectedInterrupts = ExAllocatePoolWithTag(NonPagedPool, Size,
								 TAG_INTERRUPT_INFO);
    if (!DeviceExtension->ConnectedInterrupts) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    Full = DeviceExtension->AllocatedResources->List;
    PCM_FULL_RESOURCE_DESCRIPTOR FullTranslated = DeviceExtension->TranslatedResources->List;
    ULONG InterruptNum = 0;
    for (ULONG i = 0; i < DeviceExtension->AllocatedResources->Count; i++) {
	for (ULONG j = 0; j < Full->PartialResourceList.Count; j++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial =
		Full->PartialResourceList.PartialDescriptors + j;
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialTranslated =
		FullTranslated->PartialResourceList.PartialDescriptors + j;

	    switch (Partial->Type) {
	    case CmResourceTypeInterrupt:
		if (!(Partial->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
		    assert(FALSE);
		    continue;
		}
		for (ULONG k = 0; k < Partial->MessageInterrupt.Raw.MessageCount; k++) {
		    DeviceExtension->ConnectedInterrupts[InterruptNum].FdoExt = DeviceExtension;
		    DeviceExtension->ConnectedInterrupts[InterruptNum].Vector =
			PartialTranslated->MessageInterrupt.Translated.Vector + k;
		    DeviceExtension->ConnectedInterrupts[InterruptNum].Level =
			PartialTranslated->MessageInterrupt.Translated.Level + k;
		    DeviceExtension->ConnectedInterrupts[InterruptNum].Affinity =
			PartialTranslated->MessageInterrupt.Translated.Affinity;
		    DeviceExtension->ConnectedInterrupts[InterruptNum].MessageAddress =
			Partial->MessageInterrupt.Raw.MessageAddress;
		    DeviceExtension->ConnectedInterrupts[InterruptNum].MessageData =
			Partial->MessageInterrupt.Raw.MessageData + k;
		    InterruptNum++;
		}
	    }
	}

	Full = CmGetNextResourceDescriptor(Full);
	FullTranslated = CmGetNextResourceDescriptor(FullTranslated);
    }
    assert(InterruptNum == DeviceExtension->NumberfOfConnectedInterrupts);

    return STATUS_SUCCESS;
}

static NTSTATUS PortFdoConnectInterrupt(IN PFDO_DEVICE_EXTENSION DeviceExtension)
{
    DPRINT1("PortFdoConnectInterrupt(%p)\n", DeviceExtension);

    /* No resources, no interrupt. Done! */
    if (DeviceExtension->AllocatedResources == NULL ||
	DeviceExtension->TranslatedResources == NULL) {
	return STATUS_SUCCESS;
    }

    /* Get the interrupt data from the resource list */
    NTSTATUS Status = GetInterruptInfoFromResources(DeviceExtension);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("GetInterruptInfoFromResources() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    /* Connect the interrupts */
    for (ULONG i = 0; i < DeviceExtension->NumberfOfConnectedInterrupts; i++) {
	Status = IoConnectInterrupt(&DeviceExtension->ConnectedInterrupts[i].Interrupt,
				    PortFdoInterruptRoutine,
				    &DeviceExtension->ConnectedInterrupts[i],
				    DeviceExtension->ConnectedInterrupts[i].Vector,
				    DeviceExtension->ConnectedInterrupts[i].Level,
				    DeviceExtension->ConnectedInterrupts[i].Level,
				    Latched, FALSE,
				    DeviceExtension->ConnectedInterrupts[i].Affinity, FALSE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("IoConnectInterrupt() failed (Status 0x%08x)\n", Status);
	    for (ULONG j = 0; j < i; j++) {
		assert(DeviceExtension->ConnectedInterrupts[j].Interrupt);
		IoDisconnectInterrupt(DeviceExtension->ConnectedInterrupts[j].Interrupt);
	    }
	    DeviceExtension->NumberfOfConnectedInterrupts = 0;
	    ExFreePool(DeviceExtension->ConnectedInterrupts);
	    break;
	}
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PortFdoStartMiniport(IN PFDO_DEVICE_EXTENSION DeviceExtension)
{
    DPRINT1("PortFdoStartMiniport(%p)\n", DeviceExtension);

    /* Initialize the miniport */
    assert(DeviceExtension == DeviceExtension->Miniport.DeviceExtension);
    NTSTATUS Status = MiniportInitialize(&DeviceExtension->Miniport);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("MiniportInitialize() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    /* Call the miniports FindAdapter function */
    Status = MiniportFindAdapter(&DeviceExtension->Miniport);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("MiniportFindAdapter() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    ULONG DumpBufferSize = DeviceExtension->Miniport.PortConfig.RequestedDumpBufferSize;
    if (DumpBufferSize) {
	PHYSICAL_ADDRESS Zero = {}, PhyAddr = {};
	PHYSICAL_ADDRESS HighestAddr = { .QuadPart = ULONG_MAX };
	PVOID VirtAddr = NULL;
	PVOID HwDevExt = DeviceExtension->Miniport.MiniportExtension->HwDeviceExtension;
	if (NT_SUCCESS(StorPortAllocateDmaMemory(HwDevExt,
						 DumpBufferSize,
						 Zero, HighestAddr, Zero,
						 MmNonCached, MM_ANY_NODE_OK,
						 &VirtAddr, &PhyAddr))) {
	    assert(PhyAddr.QuadPart);
	    assert(VirtAddr);
	    DeviceExtension->Miniport.PortConfig.DumpRegion.Length = DumpBufferSize;
	    DeviceExtension->Miniport.PortConfig.DumpRegion.PhysicalBase = PhyAddr;
	    DeviceExtension->Miniport.PortConfig.DumpRegion.VirtualBase = VirtAddr;
	}
    }

    /* Connect the configured interrupt */
    Status = PortFdoConnectInterrupt(DeviceExtension);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("PortFdoConnectInterrupt() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    /* Call the miniports HwInitialize function */
    Status = MiniportHwInitialize(&DeviceExtension->Miniport);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("MiniportHwInitialize() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    /* Call the HwPassiveInitRoutine function, if available */
    if (DeviceExtension->HwPassiveInitRoutine != NULL) {
	DPRINT1("Calling HwPassiveInitRoutine()\n");
	if (!DeviceExtension->HwPassiveInitRoutine(
		&DeviceExtension->Miniport.MiniportExtension->HwDeviceExtension)) {
	    DPRINT1("HwPassiveInitRoutine() failed\n");
	    return STATUS_UNSUCCESSFUL;
	}
    }

    return STATUS_SUCCESS;
}

NTSTATUS PortFdoInitDma(IN PFDO_DEVICE_EXTENSION FdoExt,
			IN PPORT_CONFIGURATION_INFORMATION PortConfig)
{
    if (FdoExt->DmaAdapter) {
	return STATUS_SUCCESS;
    }
    DEVICE_DESCRIPTION DevDesc = {
	.Version = DEVICE_DESCRIPTION_VERSION,
	.InterfaceType = PortConfig->AdapterInterfaceType,
	.BusNumber = PortConfig->SystemIoBusNumber,
	.ScatterGather = PortConfig->ScatterGather,
	.Master = TRUE,
	.Dma32BitAddresses = TRUE,
	.AutoInitialize = FALSE,
	.MaximumLength = PortConfig->MaximumTransferLength,
	.Dma64BitAddresses = PortConfig->Dma64BitAddresses
    };
    FdoExt->DmaAdapter = HalGetAdapter(&DevDesc, NULL);
    if (!FdoExt->DmaAdapter) {
	assert(FALSE);
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}

static PCM_RESOURCE_LIST CopyResourceList(PCM_RESOURCE_LIST Source)
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

static NTSTATUS PortFdoStartDevice(IN PFDO_DEVICE_EXTENSION DeviceExtension,
				   IN PIRP Irp)
{
    DPRINT1("PortFdoStartDevice(%p %p)\n", DeviceExtension, Irp);

    ASSERT(DeviceExtension->ExtensionType == FdoExtension);

    /* Get the current stack location */
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    /* Start the lower device if the FDO is in 'stopped' state */
    NTSTATUS Status;
    if (DeviceExtension->PnpState == dsStopped) {
	if (IoForwardIrpSynchronously(DeviceExtension->LowerDevice, Irp)) {
	    Status = Irp->IoStatus.Status;
	} else {
	    Status = STATUS_UNSUCCESSFUL;
	}

	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Lower device failed the IRP (Status 0x%08x)\n", Status);
	    return Status;
	}
    }

    /* Change to the 'started' state */
    DeviceExtension->PnpState = dsStarted;

    /* Copy the raw and translated resource lists into the device extension */
    assert(Stack->Parameters.StartDevice.AllocatedResources);
    assert(Stack->Parameters.StartDevice.AllocatedResourcesTranslated);
    if (Stack->Parameters.StartDevice.AllocatedResources != NULL &&
	Stack->Parameters.StartDevice.AllocatedResourcesTranslated != NULL) {
	DeviceExtension->AllocatedResources = CopyResourceList(
	    Stack->Parameters.StartDevice.AllocatedResources);
	if (DeviceExtension->AllocatedResources == NULL)
	    return STATUS_NO_MEMORY;

	DeviceExtension->TranslatedResources = CopyResourceList(
	    Stack->Parameters.StartDevice.AllocatedResourcesTranslated);
	if (DeviceExtension->TranslatedResources == NULL)
	    return STATUS_NO_MEMORY;
    }

    /* Start the miniport (FindAdapter & Initialize) */
    Status = PortFdoStartMiniport(DeviceExtension);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("FdoStartMiniport() failed (Status 0x%08x)\n", Status);
	DeviceExtension->PnpState = dsStopped;
    }

    /* Initialize the DMA adapter object if it hasn't been initialized yet. */
    Status = PortFdoInitDma(DeviceExtension, &DeviceExtension->Miniport.PortConfig);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("PortFdoInitDma() failed (Status 0x%08x)\n", Status);
	DeviceExtension->PnpState = dsStopped;
    }

    return Status;
}

static VOID PortInitializeSrb(IN PSTORAGE_REQUEST_BLOCK Srb,
			      IN PIRP Irp,
			      IN PSENSE_DATA SenseInfo,
			      IN PVOID DataBuffer,
			      IN ULONG DataBufferSize,
			      IN UCHAR BusId,
			      IN UCHAR TargetId,
			      IN UCHAR Lun)
{
    ULONG SrbSize = SRBEX_SCSI_CDB16_BUFFER_SIZE;
    RtlZeroMemory(Srb, SrbSize);

    Srb->Signature = SRB_SIGNATURE;
    Srb->Version = STORAGE_REQUEST_BLOCK_VERSION_1;
    Srb->SrbLength = SrbSize;
    Srb->OriginalRequest = Irp;
    Srb->SrbFunction = SRB_FUNCTION_EXECUTE_SCSI;
    Srb->SrbFlags = SRB_FLAGS_DATA_IN | SRB_FLAGS_DISABLE_SYNCH_TRANSFER;
    Srb->TimeOutValue = 4;

    Srb->AddressOffset = sizeof(STORAGE_REQUEST_BLOCK);
    PSTOR_ADDR_BTL8 AddrBtl8 = (PVOID)((PUCHAR)Srb + Srb->AddressOffset);
    AddrBtl8->Type = STOR_ADDRESS_TYPE_BTL8;
    AddrBtl8->AddressLength = STOR_ADDR_BTL8_ADDRESS_LENGTH;
    SrbSetPathTargetLun(Srb, BusId, TargetId, Lun);

    Srb->NumSrbExData = 1;
    Srb->SrbExDataOffset[0] = sizeof(STORAGE_REQUEST_BLOCK) + sizeof(STOR_ADDR_BTL8);
    PSRBEX_DATA_SCSI_CDB16 DataCdb16 = (PVOID)((PUCHAR)Srb + Srb->SrbExDataOffset[0]);
    DataCdb16->Type = SrbExDataTypeScsiCdb16;
    DataCdb16->Length = SRBEX_DATA_SCSI_CDB16_LENGTH;

    SrbSetSenseInfoBuffer(Srb, SenseInfo);
    SrbSetSenseInfoBufferLength(Srb, SENSE_BUFFER_SIZE);

    Srb->DataBuffer = DataBuffer;
    Srb->DataTransferLength = DataBufferSize;

    /* Attach Srb to the Irp */
    PIO_STACK_LOCATION IrpStack = IoGetNextIrpStackLocation(Irp);
    IrpStack->Parameters.Scsi.Srb = Srb;
}

static NTSTATUS PortSendInquirySrb(IN PPDO_DEVICE_EXTENSION PdoExtension)
{
    IO_STATUS_BLOCK IoStatusBlock;
    KEVENT Event;
    PIRP Irp;
    NTSTATUS Status;
    BOOLEAN KeepTrying = TRUE;
    ULONG RetryCount = 0;
    UCHAR SrbBuffer[SRBEX_SCSI_CDB16_BUFFER_SIZE];
    PSTORAGE_REQUEST_BLOCK Srb = (PSTORAGE_REQUEST_BLOCK)SrbBuffer;
    //    PSCSI_PORT_LUN_EXTENSION LunExtension;
    //    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT("PortSendInquirySrb(%p)\n", PdoExtension);

    if (PdoExtension->InquiryBuffer == NULL) {
	PdoExtension->InquiryBuffer = ExAllocatePoolWithTag(CachedDmaPool,
							    sizeof(INQUIRYDATA),
							    TAG_INQUIRY_DATA);
	if (PdoExtension->InquiryBuffer == NULL)
	    return STATUS_INSUFFICIENT_RESOURCES;
    }

    PSENSE_DATA SenseBuffer = ExAllocatePoolWithTag(CachedDmaPool,
						    SENSE_BUFFER_SIZE, TAG_SENSE_DATA);
    if (SenseBuffer == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (KeepTrying) {
	/* Initialize event for waiting */
	KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	/* Create an IRP */
	Irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_EXECUTE_IN, PdoExtension->Device,
					    NULL, 0, PdoExtension->InquiryBuffer,
					    INQUIRYDATABUFFERSIZE, TRUE, &Event,
					    &IoStatusBlock);
	if (Irp == NULL) {
	    DPRINT("IoBuildDeviceIoControlRequest() failed\n");

	    /* Quit the loop */
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    KeepTrying = FALSE;
	    continue;
	}

	PortInitializeSrb(Srb, Irp, SenseBuffer, PdoExtension->InquiryBuffer,
			  INQUIRYDATABUFFERSIZE, PdoExtension->Bus,
			  PdoExtension->Target, PdoExtension->Lun);

	/* Fill in CDB */
	SrbSetCdbLength(Srb, 6);
	PCDB Cdb = SrbGetCdb(Srb);
	Cdb->CDB6INQUIRY.OperationCode = SCSIOP_INQUIRY;
	Cdb->CDB6INQUIRY.LogicalUnitNumber = PdoExtension->Lun;
	Cdb->CDB6INQUIRY.AllocationLength = INQUIRYDATABUFFERSIZE;

	/* Call the driver */
	Status = IoCallDriver(PdoExtension->Device, Irp);

	/* Wait for it to complete */
	if (Status == STATUS_PENDING) {
	    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	    Status = IoStatusBlock.Status;
	}

	DPRINT("PortSendInquirySrb(): Request processed by driver, status = 0x%08X\n",
	       Status);

	if (SRB_STATUS(Srb->SrbStatus) == SRB_STATUS_SUCCESS) {
	    DPRINT("Found a device!\n");

	    /* Quit the loop */
	    Status = STATUS_SUCCESS;
	    break;
	}

	DPRINT("Inquiry SRB failed with SrbStatus 0x%08X\n", Srb->SrbStatus);

	/* Check if the queue is frozen */
	if (Srb->SrbStatus & SRB_STATUS_QUEUE_FROZEN) {
	    /* Something weird happened, deal with it (unfreeze the queue) */
	    KeepTrying = FALSE;

	    DPRINT("PortSendInquirySrb(): the queue is frozen at TargetId %d\n",
		   SrbGetTargetId(Srb));

	    //            LunExtension = SpiGetLunExtension(DeviceExtension,
	    //                                              LunInfo->PathId,
	    //                                              LunInfo->TargetId,
	    //                                              LunInfo->Lun);

	    /* Clear frozen flag */
	    //            LunExtension->Flags &= ~LUNEX_FROZEN_QUEUE;

	    /* Acquire the spinlock */
	    //            KeAcquireSpinLock(&DeviceExtension->SpinLock, &Irql);

	    /* Process the request */
	    //            SpiGetNextRequestFromLun(DeviceObject->DeviceExtension, LunExtension);

	    /* SpiGetNextRequestFromLun() releases the spinlock,
                so we just lower irql back to what it was before */
	    //            KeLowerIrql(Irql);
	}

	/* Check if data overrun happened */
	if (SRB_STATUS(Srb->SrbStatus) == SRB_STATUS_DATA_OVERRUN) {
	    DPRINT("Data overrun at TargetId %d\n", PdoExtension->Target);

	    /* Quit the loop */
	    Status = STATUS_SUCCESS;
	    KeepTrying = FALSE;
	} else if ((Srb->SrbStatus & SRB_STATUS_AUTOSENSE_VALID) &&
		   SenseBuffer->SenseKey == SCSI_SENSE_ILLEGAL_REQUEST) {
	    /* LUN is not valid, but some device responds there.
                Mark it as invalid anyway */

	    /* Quit the loop */
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    KeepTrying = FALSE;
	} else {
	    /* Retry a couple of times if no timeout happened */
	    if ((RetryCount < 2) && (SRB_STATUS(Srb->SrbStatus) != SRB_STATUS_NO_DEVICE) &&
		(SRB_STATUS(Srb->SrbStatus) != SRB_STATUS_SELECTION_TIMEOUT)) {
		RetryCount++;
		KeepTrying = TRUE;
	    } else {
		/* That's all, quit the loop */
		KeepTrying = FALSE;

		/* Set status according to SRB status */
		if (SRB_STATUS(Srb->SrbStatus) == SRB_STATUS_BAD_FUNCTION ||
		    SRB_STATUS(Srb->SrbStatus) == SRB_STATUS_BAD_SRB_BLOCK_LENGTH) {
		    Status = STATUS_INVALID_DEVICE_REQUEST;
		} else {
		    Status = STATUS_IO_DEVICE_ERROR;
		}
	    }
	}
    }

    /* Free the sense buffer */
    ExFreePoolWithTag(SenseBuffer, TAG_SENSE_DATA);

    DPRINT("PortSendInquirySrb() done with Status 0x%08X\n", Status);

    return Status;
}

/*
 * Send the REPORT-LUNS command to the host bus adapter and return the list
 * of available LUNs. This should be done after the initial INQUIRY to the
 * given target with LUN 0.
 */
static NTSTATUS PortSendReportLunsSrb(IN PDEVICE_OBJECT Fdo,
				      IN UCHAR BusId,
				      IN UCHAR TargetId,
				      OUT BOOLEAN *ValidLuns,
				      IN UCHAR MaxLuns)
{
    for (ULONG i = 0; i < MaxLuns; i++) {
	ValidLuns[i] = FALSE;
    }

    ULONG LunListSize = sizeof(LUN_LIST) + MaxLuns * sizeof(((PLUN_LIST)NULL)->Lun[0]);
    PLUN_LIST LunList = ExAllocatePoolWithTag(CachedDmaPool, LunListSize, TAG_LUN_LIST);
    if (!LunList) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    PSENSE_DATA SenseBuffer = ExAllocatePoolWithTag(CachedDmaPool,
						    SENSE_BUFFER_SIZE, TAG_SENSE_DATA);
    if (SenseBuffer == NULL) {
	ExFreePoolWithTag(LunList, TAG_LUN_LIST);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_EXECUTE_IN, Fdo, NULL, 0,
					     LunList, LunListSize, TRUE, &Event,
					     &IoStatus);
    if (!Irp) {
	ExFreePoolWithTag(LunList, TAG_LUN_LIST);
	ExFreePoolWithTag(SenseBuffer, TAG_SENSE_DATA);
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    UCHAR SrbBuffer[SRBEX_SCSI_CDB16_BUFFER_SIZE];
    PSTORAGE_REQUEST_BLOCK Srb = (PSTORAGE_REQUEST_BLOCK)SrbBuffer;
    PortInitializeSrb(Srb, Irp, SenseBuffer, LunList, LunListSize, BusId, TargetId, 0);

    /* Fill in CDB */
    SrbSetCdbLength(Srb, 12);
    PCDB Cdb = SrbGetCdb(Srb);
    Cdb->REPORT_LUNS.OperationCode = SCSIOP_REPORT_LUNS;
    Cdb->REPORT_LUNS.AllocationLength[0] = (UCHAR)(LunListSize >> 24);
    Cdb->REPORT_LUNS.AllocationLength[1] = (UCHAR)(LunListSize >> 16);
    Cdb->REPORT_LUNS.AllocationLength[2] = (UCHAR)(LunListSize >> 8);
    Cdb->REPORT_LUNS.AllocationLength[3] = (UCHAR)(LunListSize);

    /* Call the driver */
    NTSTATUS Status = IoCallDriver(Fdo, Irp);
    if (Status == STATUS_PENDING) {
	KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	Status = IoStatus.Status;
    }
    DPRINT("PortSendInquirySrb(): Request processed by driver, status = 0x%08X\n",
	   Status);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    ULONG NumLunEntries = (LunList->LunListLength[3] |
			   (LunList->LunListLength[2] << 8) |
			   (LunList->LunListLength[1] << 16) |
			   (LunList->LunListLength[0] << 24)) / sizeof(LunList->Lun[0]);
    for (ULONG i = 0; i < NumLunEntries; i++) {
	/* The 0-th byte of the LUN descriptor contains the address method and the
	 * bus ID, which we ignore. We only support single-level LUN addressing. */
	UCHAR Lun = LunList->Lun[i][1];
	if (Lun >= MaxLuns) {
	    assert(FALSE);
	    continue;
	}
	ValidLuns[Lun] = TRUE;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PortFdoScanBus(IN PFDO_DEVICE_EXTENSION DeviceExtension)
{
    NTSTATUS Status;

    DPRINT("PortFdoScanBus(%p)\n", DeviceExtension);

    UCHAR BusCount = DeviceExtension->Miniport.PortConfig.NumberOfBuses;
    UCHAR MaxTargets = DeviceExtension->Miniport.PortConfig.MaximumNumberOfTargets;
    UCHAR MaxLuns = DeviceExtension->Miniport.PortConfig.MaximumNumberOfLogicalUnits;
    DPRINT("NumberOfBuses: %u\n", BusCount);
    DPRINT("MaximumNumberOfTargets: %u\n", MaxTargets);
    DPRINT("MaximumNumberOfLogicalUnits: %u\n", MaxLuns);

    /* Scan all buses */
    BOOLEAN ValidLuns[MaxLuns];
    for (ULONG Bus = 0; Bus < BusCount; Bus++) {
	DPRINT("Scanning bus %d\n", Bus);

	/* Scan all targets */
	for (ULONG Target = 0; Target < MaxTargets; Target++) {
	    DPRINT("  Scanning target %d:%d\n", Bus, Target);

	    PPDO_DEVICE_EXTENSION PdoExtension;
	    Status = PortCreatePdo(DeviceExtension, Bus, Target, 0, &PdoExtension);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }

	    /* First send a REPORT-LUNS (to LUN 0) to get the list of valid LUNs. */
	    DPRINT("    Sending REPORT-LUNS to %d:%d:0\n", Bus, Target);
	    Status = PortSendReportLunsSrb(PdoExtension->Device, Bus, Target,
					   ValidLuns, MaxLuns);
	    /* REPORT-LUNS failed, so delete this PDO and try next target id. */
	    if (!NT_SUCCESS(Status)) {
		PortDeletePdo(PdoExtension);
		continue;
	    }

	    /* Now ask LUN 0 to identify itself. */
	    DPRINT("    Sending INQUIRY to %d:%d:0\n", Bus, Target);
	    Status = PortSendInquirySrb(PdoExtension);
	    DPRINT("PortSendInquiry returned 0x%08x\n", Status);
	    if (!NT_SUCCESS(Status)) {
		PortDeletePdo(PdoExtension);
		continue;
	    }
	    DPRINT("VendorId: %.8s\n", PdoExtension->InquiryBuffer->VendorId);
	    DPRINT("ProductId: %.16s\n", PdoExtension->InquiryBuffer->ProductId);
	    DPRINT("ProductRevisionLevel: %.4s\n",
		   PdoExtension->InquiryBuffer->ProductRevisionLevel);
	    DPRINT("VendorSpecific: %.20s\n",
		   PdoExtension->InquiryBuffer->VendorSpecific);

            /* Scan all remaining reported logical units */
            for (ULONG Lun = 1; Lun < MaxLuns; Lun++) {
		if (!ValidLuns[Lun]) {
		    continue;
		}
		PPDO_DEVICE_EXTENSION LunPdoExt;
		Status = PortCreatePdo(DeviceExtension, Bus, Target, Lun, &LunPdoExt);
		if (!NT_SUCCESS(Status)) {
		    break;
		}
                DPRINT("    Scanning logical unit %d:%d:%d\n", Bus, Target, Lun);
                Status = PortSendInquirySrb(LunPdoExt);
                DPRINT("PortSendInquiry returned 0x%08x\n", Status);
		/* INQUIRY for the given LUN failed. The logical unit might have been
		 * removed during the scan. Continue with the next logical unit. */
                if (!NT_SUCCESS(Status)) {
                    PortDeletePdo(LunPdoExt);
		    continue;
		}
            }
	}
    }

    DPRINT("PortFdoScanBus() done!\n");

    return STATUS_SUCCESS;
}

static NTSTATUS PortFdoQueryBusRelations(IN PFDO_DEVICE_EXTENSION DevExt,
					 OUT PULONG_PTR Information)
{
    DPRINT1("PortFdoQueryBusRelations(%p %p)\n", DevExt, Information);

    NTSTATUS Status = PortFdoScanBus(DevExt);
    DPRINT1("Units found: %u\n", DevExt->PdoCount);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Build the device relations list based on the bus enumeration result. */
    ULONG Size = sizeof(DEVICE_RELATIONS) + (DevExt->PdoCount * sizeof(PDEVICE_OBJECT));
    PDEVICE_RELATIONS DeviceRelations = ExAllocatePoolWithTag(NonPagedPool, Size,
							      TAG_DEV_RELATIONS);
    if (!DeviceRelations) {
        return STATUS_NO_MEMORY;
    }
    ULONG Index = 0;
    for (PLIST_ENTRY Entry = DevExt->PdoListHead.Flink;
	 Entry != &DevExt->PdoListHead; Entry = Entry->Flink) {
        PPDO_DEVICE_EXTENSION PdoDevExt = CONTAINING_RECORD(Entry,
							    PDO_DEVICE_EXTENSION,
							    PdoListEntry);
	assert(PdoDevExt->FdoExtension == DevExt);
	DeviceRelations->Objects[Index++] = PdoDevExt->Device;
    }
    assert(Index == DevExt->PdoCount);
    DeviceRelations->Count = Index;
    *Information = (ULONG_PTR)DeviceRelations;
    return STATUS_SUCCESS;
}

static NTSTATUS PortFdoFilterRequirements(IN PFDO_DEVICE_EXTENSION DeviceExtension,
					  IN OUT PULONG_PTR Information)
{
    DPRINT1("PortFdoFilterRequirements(%p %p)\n", DeviceExtension, Information);

    /* Get the bus number and the slot number */
    PIO_RESOURCE_REQUIREMENTS_LIST ReqList = (PVOID)(*Information);
    if (ReqList != NULL) {
	DeviceExtension->BusNumber = ReqList->BusNumber;
	DeviceExtension->SlotNumber = ReqList->SlotNumber;
    }

    /* Count the number of interrupts provided by the parent bus driver */
    ULONG ResCount = 0;
    ULONG InterruptCount = 0;
    ULONG NumRequested = DeviceExtension->Miniport.InitData->NumberOfMsiMessagesRequested;
    /* So far we only handle the case where there is exactly one resource requirements list. */
    assert(ReqList->AlternativeLists == 1);
    PIO_RESOURCE_LIST ResList = ReqList->List;
    for (ULONG i = 0; i < ResList->Count; i++) {
	PIO_RESOURCE_DESCRIPTOR Desc = &ResList->Descriptors[i];
	if (Desc->Type != CmResourceTypeInterrupt) {
	    ResCount++;
	} else if (!(Desc->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
	    assert(FALSE);
	    ResCount++;
	} else if (InterruptCount < NumRequested) {
	    InterruptCount += Desc->Interrupt.MaximumVector - Desc->Interrupt.MinimumVector + 1;
	    ResCount++;
	}
    }

    assert(ResCount <= ResList->Count);
    if (ResCount == ResList->Count) {
	return STATUS_SUCCESS;
    }
    ULONG NewListSize = sizeof(IO_RESOURCE_REQUIREMENTS_LIST) + sizeof(IO_RESOURCE_LIST) +
	sizeof(IO_RESOURCE_DESCRIPTOR) * ResCount;
    ULONG CopiedInterruptCount = 0;
    PIO_RESOURCE_REQUIREMENTS_LIST NewList = ExAllocatePoolWithTag(NonPagedPool,
								   NewListSize,
								   TAG_RESOURCE_LIST);
    if (!NewList) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    ResList = ReqList->List;
    *NewList = *ReqList;
    NewList->ListSize = NewListSize;
    NewList->List[0] = *ResList;
    NewList->List[0].Count = ResCount;
    for (ULONG i = 0; i < ResList->Count; i++) {
	PIO_RESOURCE_DESCRIPTOR Orig = &ResList->Descriptors[i];
	PIO_RESOURCE_DESCRIPTOR Dest = &NewList->List[0].Descriptors[i];
	if (Orig->Type != CmResourceTypeInterrupt) {
	    *Dest = *Orig;
	} else if (!(Orig->Flags & CM_RESOURCE_INTERRUPT_MESSAGE)) {
	    assert(FALSE);
	    *Dest = *Orig;
	} else if (CopiedInterruptCount < InterruptCount) {
	    CopiedInterruptCount +=
		Orig->Interrupt.MaximumVector - Orig->Interrupt.MinimumVector + 1;
	    *Dest = *Orig;
	}
    }
    ExFreePool(ReqList);
    *Information = (ULONG_PTR)NewList;

    return STATUS_SUCCESS;
}

NTSTATUS PortFdoScsi(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DPRINT("PortFdoScsi(%p %p)\n", DeviceObject, Irp);

    ASSERT((PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension);
    ASSERT(((PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->ExtensionType == FdoExtension);

    /* IRP_MJ_SCSI requests should be sent to the PDO, so we fail the IRP. */
    NTSTATUS Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS PortFdoIoctlStorageQueryProperty(IN PFDO_DEVICE_EXTENSION FdoExt,
						 IN PMINIPORT Miniport,
						 IN PVOID HwDevExt,
						 IN OUT PVOID Buffer,
						 IN ULONG InputLength,
						 IN ULONG OutputLength,
						 OUT ULONG_PTR *Information)
{
    PSTORAGE_PROPERTY_QUERY Query = Buffer;
    if (InputLength < FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters) ||
        Query->PropertyId != StorageAdapterProperty) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    switch (Query->QueryType) {
    case PropertyStandardQuery:
	if (OutputLength < sizeof(STORAGE_DESCRIPTOR_HEADER)) {
	    *Information = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
	    return STATUS_BUFFER_TOO_SMALL;
	}
	PSTORAGE_ADAPTER_DESCRIPTOR Descriptor = Buffer;
	Descriptor->Version = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
	Descriptor->Size = sizeof(STORAGE_ADAPTER_DESCRIPTOR);

	if (OutputLength < sizeof(STORAGE_ADAPTER_DESCRIPTOR)) {
	    *Information = sizeof(STORAGE_DESCRIPTOR_HEADER);
	    return STATUS_SUCCESS;
	}
	PPORT_CONFIGURATION_INFORMATION PortConfig = &Miniport->PortConfig;
	Descriptor->MaximumPhysicalPages = PortConfig->NumberOfPhysicalBreaks;
	Descriptor->MaximumTransferLength = PortConfig->MaximumTransferLength;
	Descriptor->AlignmentMask = PortConfig->AlignmentMask;
	Descriptor->AdapterUsesPio = FALSE;
	Descriptor->AdapterScansDown = FALSE;
	Descriptor->CommandQueueing = TRUE;
	Descriptor->AcceleratedTransfer = TRUE;

	assert(FdoExt->DriverExtension);
	Descriptor->BusType = FdoExt->DriverExtension->StorageBusType;
	Descriptor->BusMajorVersion = 2;
	Descriptor->BusMinorVersion = 0;
	*Information = sizeof(STORAGE_ADAPTER_DESCRIPTOR);
	return STATUS_SUCCESS;

    case PropertyExistsQuery:
	return STATUS_SUCCESS;

    default:
	return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS PortFdoIoctlStorageResetBus(IN PFDO_DEVICE_EXTENSION FdoExt,
					    IN PMINIPORT Miniport,
					    IN PVOID HwDevExt,
					    IN OUT PVOID Buffer,
					    IN ULONG InputLength,
					    IN ULONG OutputLength)
{
    assert(Miniport);
    assert(Miniport->InitData);
    assert(Miniport->InitData->HwResetBus);

    if (InputLength < sizeof(STORAGE_BUS_RESET_REQUEST)) {
        return STATUS_INVALID_PARAMETER;
    }
    PSTORAGE_BUS_RESET_REQUEST Req = Buffer;

    BOOLEAN Succ = Miniport->InitData->HwResetBus(HwDevExt,
						  Req->PathId);

    return (Succ ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL);
}

static NTSTATUS PortFdoIoctlStorageBreakReservation(IN PFDO_DEVICE_EXTENSION FdoExt,
						    IN PMINIPORT Miniport,
						    IN PVOID HwDevExt,
						    IN OUT PVOID Buffer,
						    IN ULONG InputLength,
						    IN ULONG OutputLength)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PortFdoIoctlScsiMiniport(IN PFDO_DEVICE_EXTENSION FdoExt,
					 IN PMINIPORT Miniport,
					 IN PVOID HwDevExt,
					 IN OUT PVOID Buffer,
					 IN ULONG InputLength,
					 IN ULONG OutputLength)
{
    /* TODO: Need to implement DMA buffer allocation first */
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PortFdoIoctlScsiGetCapabilities(IN PFDO_DEVICE_EXTENSION FdoExt,
						IN PMINIPORT Miniport,
						IN PVOID HwDevExt,
						IN OUT PVOID Buffer,
						IN ULONG InputLength,
						IN ULONG OutputLength,
						OUT ULONG_PTR *Information)
{
    if (OutputLength < sizeof(IO_SCSI_CAPABILITIES)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PPORT_CONFIGURATION_INFORMATION PortConfig = &Miniport->PortConfig;
    PIO_SCSI_CAPABILITIES Capabilities = Buffer;
    Capabilities->Length = sizeof(IO_SCSI_CAPABILITIES);
    Capabilities->MaximumTransferLength = PortConfig->MaximumTransferLength;
    Capabilities->MaximumPhysicalPages = PortConfig->NumberOfPhysicalBreaks;
    Capabilities->SupportedAsynchronousEvents = FALSE;
    Capabilities->AlignmentMask = PortConfig->AlignmentMask;
    Capabilities->TaggedQueuing = TRUE;
    Capabilities->AdapterScansDown = FALSE;
    Capabilities->AdapterUsesPio = FALSE;

    *Information = sizeof(IO_SCSI_CAPABILITIES);
    return STATUS_SUCCESS;
}

static NTSTATUS PortFdoIoctlScsiRescanBus(IN PFDO_DEVICE_EXTENSION FdoExt,
					  IN PMINIPORT Miniport,
					  IN PVOID HwDevExt,
					  IN OUT PVOID Buffer,
					  IN ULONG InputLength,
					  IN ULONG OutputLength)
{
    /* We have not implement storage bus rescanning yet. */
    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS PortFdoIoctlScsiPassThrough(IN PFDO_DEVICE_EXTENSION FdoExt,
					    IN PMINIPORT Miniport,
					    IN PVOID HwDevExt,
					    IN OUT PVOID Buffer,
					    IN ULONG InputLength,
					    IN ULONG OutputLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PortFdoIoctlScsiPassThroughDirect(IN PFDO_DEVICE_EXTENSION FdoExt,
						  IN PMINIPORT Miniport,
						  IN PVOID HwDevExt,
						  IN OUT PVOID Buffer,
						  IN ULONG InputLength,
						  IN ULONG OutputLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PortFdoIoctlScsiGetInquiryData(IN PFDO_DEVICE_EXTENSION FdoExt,
					       IN PMINIPORT Miniport,
					       IN PVOID HwDevExt,
					       IN OUT PVOID Buffer,
					       IN ULONG InputLength,
					       IN ULONG OutputLength)
{
    UNIMPLEMENTED_DBGBREAK();
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS PortFdoDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DPRINT("PortFdoDeviceControl(%p %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Information = 0;

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Ioctl = Stack->Parameters.DeviceIoControl.IoControlCode;
    PFDO_DEVICE_EXTENSION FdoExt = DeviceObject->DeviceExtension;
    ASSERT(FdoExt);
    ASSERT(FdoExt->ExtensionType == FdoExtension);
    PMINIPORT Miniport = &FdoExt->Miniport;
    assert(Miniport);
    assert(Miniport->InitData);
    assert(Miniport->MiniportExtension);
    PVOID HwDevExt = &Miniport->MiniportExtension->HwDeviceExtension;

    /* All of the IOCTLs we handle are METHOD_BUFFERED IOCTLs */
    PVOID Buffer = Irp->SystemBuffer;
    ULONG InputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    switch (Ioctl) {
    case IOCTL_STORAGE_QUERY_PROPERTY:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_STORAGE_QUERY_PROPERTY\n");
	Status = PortFdoIoctlStorageQueryProperty(FdoExt, Miniport, HwDevExt,
						  Buffer, InputLength, OutputLength,
						  &Irp->IoStatus.Information);
	break;

    case IOCTL_STORAGE_RESET_BUS:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_STORAGE_RESET_BUS\n");
	Status = PortFdoIoctlStorageResetBus(FdoExt, Miniport, HwDevExt, Buffer,
					     InputLength, OutputLength);
	break;

    case IOCTL_STORAGE_BREAK_RESERVATION:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_STORAGE_BREAK_RESERVATION\n");
	Status = PortFdoIoctlStorageBreakReservation(FdoExt, Miniport, HwDevExt,
						     Buffer, InputLength, OutputLength);
	break;

    case IOCTL_SCSI_MINIPORT:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_STORAGE_MINIPORT\n");
	Status = PortFdoIoctlScsiMiniport(FdoExt, Miniport, HwDevExt,
					  Buffer, InputLength, OutputLength);
	break;

    case IOCTL_SCSI_GET_CAPABILITIES:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_STORAGE_GET_CAPABILITIES\n");
	Status = PortFdoIoctlScsiGetCapabilities(FdoExt, Miniport, HwDevExt,
						 Buffer, InputLength, OutputLength,
						 &Irp->IoStatus.Information);
	break;

    case IOCTL_SCSI_RESCAN_BUS:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_SCSI_RESCAN_BUS\n");
	Status = PortFdoIoctlScsiRescanBus(FdoExt, Miniport, HwDevExt,
					   Buffer, InputLength, OutputLength);
	break;

    case IOCTL_SCSI_PASS_THROUGH:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_SCSI_PASS_THROUGH\n");
	Status = PortFdoIoctlScsiPassThrough(FdoExt, Miniport, HwDevExt,
					     Buffer, InputLength, OutputLength);
	break;

    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_SCSI_PASS_THROUGH_DIRECT\n");
	Status = PortFdoIoctlScsiPassThroughDirect(FdoExt, Miniport, HwDevExt,
						   Buffer, InputLength, OutputLength);
	break;

    case IOCTL_SCSI_GET_INQUIRY_DATA:
	DPRINT1("IRP_MJ_DEVICE_CONTROL / IOCTL_SCSI_GET_INQUIRY_DATA\n");
	Status = PortFdoIoctlScsiGetInquiryData(FdoExt, Miniport, HwDevExt,
						Buffer, InputLength, OutputLength);
	break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS PortFdoPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DPRINT1("PortFdoPnp(%p %p)\n", DeviceObject, Irp);

    PFDO_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(DeviceExtension);
    ASSERT(DeviceExtension->ExtensionType == FdoExtension);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG_PTR Information = Irp->IoStatus.Information;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    switch (Stack->MinorFunction) {
    case IRP_MN_START_DEVICE: /* 0x00 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_START_DEVICE\n");
	Status = PortFdoStartDevice(DeviceExtension, Irp);
	break;

    case IRP_MN_QUERY_REMOVE_DEVICE: /* 0x01 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_REMOVE_DEVICE\n");
	break;

    case IRP_MN_REMOVE_DEVICE: /* 0x02 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_REMOVE_DEVICE\n");
	break;

    case IRP_MN_CANCEL_REMOVE_DEVICE: /* 0x03 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_CANCEL_REMOVE_DEVICE\n");
	break;

    case IRP_MN_STOP_DEVICE: /* 0x04 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_STOP_DEVICE\n");
	break;

    case IRP_MN_QUERY_STOP_DEVICE: /* 0x05 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_STOP_DEVICE\n");
	break;

    case IRP_MN_CANCEL_STOP_DEVICE: /* 0x06 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_CANCEL_STOP_DEVICE\n");
	break;

    case IRP_MN_QUERY_DEVICE_RELATIONS: /* 0x07 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS\n");
	switch (Stack->Parameters.QueryDeviceRelations.Type) {
	case BusRelations:
	    DPRINT1("    IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / BusRelations\n");
	    Status = PortFdoQueryBusRelations(DeviceExtension, &Information);
	    break;

	case RemovalRelations:
	    DPRINT1("    IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / "
		    "RemovalRelations\n");
	    return ForwardIrpAndForget(DeviceExtension->LowerDevice, Irp);

	default:
	    DPRINT1("    IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / Unknown type "
		    "0x%x\n",
		    Stack->Parameters.QueryDeviceRelations.Type);
	    return ForwardIrpAndForget(DeviceExtension->LowerDevice, Irp);
	}
	break;

    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS: /* 0x0d */
	DPRINT1("IRP_MJ_PNP / IRP_MN_FILTER_RESOURCE_REQUIREMENTS\n");
	Status = PortFdoFilterRequirements(DeviceExtension, &Information);
	break;

    case IRP_MN_QUERY_PNP_DEVICE_STATE: /* 0x14 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_PNP_DEVICE_STATE\n");
	break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION: /* 0x16 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_DEVICE_USAGE_NOTIFICATION\n");
	break;

    case IRP_MN_SURPRISE_REMOVAL: /* 0x17 */
	DPRINT1("IRP_MJ_PNP / IRP_MN_SURPRISE_REMOVAL\n");
	break;

    default:
	DPRINT1("IRP_MJ_PNP / Unknown minor code 0x%x\n", Stack->MinorFunction);
	return ForwardIrpAndForget(DeviceExtension->LowerDevice, Irp);
    }

    Irp->IoStatus.Information = Information;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
