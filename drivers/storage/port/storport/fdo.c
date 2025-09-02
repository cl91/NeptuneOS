/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Storport FDO code
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"

/* FUNCTIONS ******************************************************************/

static NTAPI BOOLEAN PortFdoInterruptRoutine(IN PKINTERRUPT Interrupt,
					     IN PVOID ServiceContext)
{
    DPRINT1("PortFdoInterruptRoutine(%p %p)\n", Interrupt, ServiceContext);

    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)ServiceContext;

    return MiniportHwInterrupt(&DeviceExtension->Miniport);
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
    ULONG Vector;
    KIRQL Irql;
    KINTERRUPT_MODE InterruptMode;
    BOOLEAN ShareVector;
    KAFFINITY Affinity;
    NTSTATUS Status = GetResourceListInterrupt(DeviceExtension, &Vector,
					       &Irql, &InterruptMode,
					       &ShareVector, &Affinity);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("GetResourceListInterrupt() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    DPRINT1("Vector: %u\n", Vector);
    DPRINT1("Irql: %u\n", Irql);
    DPRINT1("Affinity: 0x%08zx\n", Affinity);

    /* Connect the interrupt */
    Status = IoConnectInterrupt(&DeviceExtension->Interrupt, PortFdoInterruptRoutine,
				DeviceExtension, Vector, Irql, Irql, InterruptMode,
				ShareVector, Affinity, FALSE);
    if (NT_SUCCESS(Status)) {
	DeviceExtension->InterruptIrql = Irql;
    } else {
	DPRINT1("IoConnectInterrupt() failed (Status 0x%08x)\n", Status);
    }

    return Status;
}

static NTSTATUS PortFdoStartMiniport(IN PFDO_DEVICE_EXTENSION DeviceExtension)
{
    DPRINT1("PortFdoStartMiniport(%p)\n", DeviceExtension);

    /* Get the interface type of the lower device */
    INTERFACE_TYPE InterfaceType = GetBusInterface(DeviceExtension->LowerDevice);
    if (InterfaceType == InterfaceTypeUndefined)
	return STATUS_NO_SUCH_DEVICE;

    /* Get the driver init data for the given interface type */
    PHW_INITIALIZATION_DATA InitData = PortGetDriverInitData(DeviceExtension->DriverExtension,
							     InterfaceType);
    if (InitData == NULL)
	return STATUS_NO_SUCH_DEVICE;

    /* Initialize the miniport */
    NTSTATUS Status = MiniportInitialize(&DeviceExtension->Miniport,
					 DeviceExtension, InitData);
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

static NTAPI NTSTATUS PortFdoStartDevice(IN PFDO_DEVICE_EXTENSION DeviceExtension,
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

    return Status;
}

static VOID PortInitializeSrb(IN PSCSI_REQUEST_BLOCK Srb,
			      IN PIRP Irp,
			      IN PSENSE_DATA SenseInfo,
			      IN PVOID DataBuffer,
			      IN ULONG DataBufferSize,
			      IN UCHAR BusId,
			      IN UCHAR TargetId,
			      IN UCHAR Lun)
{
    /* Prepare SRB */
    RtlZeroMemory(Srb, sizeof(SCSI_REQUEST_BLOCK));

    Srb->Length = sizeof(SCSI_REQUEST_BLOCK);
    Srb->OriginalRequest = Irp;
    Srb->PathId = BusId;
    Srb->TargetId = TargetId;
    Srb->Lun = Lun;
    Srb->Function = SRB_FUNCTION_EXECUTE_SCSI;
    Srb->SrbFlags = SRB_FLAGS_DATA_IN | SRB_FLAGS_DISABLE_SYNCH_TRANSFER;
    Srb->TimeOutValue = 4;

    Srb->SenseInfoBuffer = SenseInfo;
    Srb->SenseInfoBufferLength = SENSE_BUFFER_SIZE;

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
    SCSI_REQUEST_BLOCK Srb;
    //    PSCSI_PORT_LUN_EXTENSION LunExtension;
    //    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT("PortSendInquirySrb(%p)\n", PdoExtension);

    if (PdoExtension->InquiryBuffer == NULL) {
	PdoExtension->InquiryBuffer = ExAllocatePoolWithTag(INQUIRYDATABUFFERSIZE,
							    TAG_INQUIRY_DATA);
	if (PdoExtension->InquiryBuffer == NULL)
	    return STATUS_INSUFFICIENT_RESOURCES;
    }

    PSENSE_DATA SenseBuffer = ExAllocatePoolWithTag(SENSE_BUFFER_SIZE, TAG_SENSE_DATA);
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

	PortInitializeSrb(&Srb, Irp, SenseBuffer, PdoExtension->InquiryBuffer,
			  INQUIRYDATABUFFERSIZE, PdoExtension->Bus,
			  PdoExtension->Target, PdoExtension->Lun);

	/* Fill in CDB */
	Srb.CdbLength = 6;
	PCDB Cdb = (PCDB)&Srb.Cdb;
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

	if (SRB_STATUS(Srb.SrbStatus) == SRB_STATUS_SUCCESS) {
	    DPRINT("Found a device!\n");

	    /* Quit the loop */
	    Status = STATUS_SUCCESS;
	    break;
	}

	DPRINT("Inquiry SRB failed with SrbStatus 0x%08X\n", Srb.SrbStatus);

	/* Check if the queue is frozen */
	if (Srb.SrbStatus & SRB_STATUS_QUEUE_FROZEN) {
	    /* Something weird happened, deal with it (unfreeze the queue) */
	    KeepTrying = FALSE;

	    DPRINT("PortSendInquirySrb(): the queue is frozen at TargetId %d\n",
		   Srb.TargetId);

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
	if (SRB_STATUS(Srb.SrbStatus) == SRB_STATUS_DATA_OVERRUN) {
	    DPRINT("Data overrun at TargetId %d\n", PdoExtension->Target);

	    /* Quit the loop */
	    Status = STATUS_SUCCESS;
	    KeepTrying = FALSE;
	} else if ((Srb.SrbStatus & SRB_STATUS_AUTOSENSE_VALID) &&
		   SenseBuffer->SenseKey == SCSI_SENSE_ILLEGAL_REQUEST) {
	    /* LUN is not valid, but some device responds there.
                Mark it as invalid anyway */

	    /* Quit the loop */
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    KeepTrying = FALSE;
	} else {
	    /* Retry a couple of times if no timeout happened */
	    if ((RetryCount < 2) && (SRB_STATUS(Srb.SrbStatus) != SRB_STATUS_NO_DEVICE) &&
		(SRB_STATUS(Srb.SrbStatus) != SRB_STATUS_SELECTION_TIMEOUT)) {
		RetryCount++;
		KeepTrying = TRUE;
	    } else {
		/* That's all, quit the loop */
		KeepTrying = FALSE;

		/* Set status according to SRB status */
		if (SRB_STATUS(Srb.SrbStatus) == SRB_STATUS_BAD_FUNCTION ||
		    SRB_STATUS(Srb.SrbStatus) == SRB_STATUS_BAD_SRB_BLOCK_LENGTH) {
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
    PLUN_LIST LunList = ExAllocatePoolWithTag(LunListSize, TAG_LUN_LIST);
    if (!LunList) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    PSENSE_DATA SenseBuffer = ExAllocatePoolWithTag(SENSE_BUFFER_SIZE, TAG_SENSE_DATA);
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

    SCSI_REQUEST_BLOCK Srb;
    PortInitializeSrb(&Srb, Irp, SenseBuffer, LunList, LunListSize, BusId, TargetId, 0);

    /* Fill in CDB */
    Srb.CdbLength = 12;
    PCDB Cdb = (PCDB)&Srb.Cdb;
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
	    DPRINT("    Sending initial INQUIRY to %d:%d:0\n", Bus, Target);
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
	    InsertTailList(&DeviceExtension->AdapterListEntry, &PdoExtension->PdoListEntry);

	    /* If target responded, we should send a REPORT-LUNS (to LUN 0) to get
	     * the list of valid LUNs. */
	    Status = PortSendReportLunsSrb(DeviceExtension->Device, Bus, Target,
					   ValidLuns, MaxLuns);
	    /* Adapter does not support REPORT-LUNS, so we try to scan all LUNs. */
	    if (!NT_SUCCESS(Status)) {
		for (ULONG i = 0; i < MaxLuns; i++) {
		    ValidLuns[i] = TRUE;
		}
	    }

            /* Scan all reported logical units */
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
		InsertTailList(&DeviceExtension->AdapterListEntry, &LunPdoExt->PdoListEntry);
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
    PDEVICE_RELATIONS DeviceRelations = ExAllocatePoolWithTag(Size,
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

static NTSTATUS PortFdoFilterRequirements(PFDO_DEVICE_EXTENSION DeviceExtension, PIRP Irp)
{
    DPRINT1("PortFdoFilterRequirements(%p %p)\n", DeviceExtension, Irp);

    /* Get the bus number and the slot number */
    PIO_RESOURCE_REQUIREMENTS_LIST RequirementsList =
	(PIO_RESOURCE_REQUIREMENTS_LIST)Irp->IoStatus.Information;
    if (RequirementsList != NULL) {
	DeviceExtension->BusNumber = RequirementsList->BusNumber;
	DeviceExtension->SlotNumber = RequirementsList->SlotNumber;
    }

    return STATUS_SUCCESS;
}

NTAPI NTSTATUS PortFdoScsi(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
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

NTAPI NTSTATUS PortFdoPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DPRINT1("PortFdoPnp(%p %p)\n", DeviceObject, Irp);

    PFDO_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    ASSERT(DeviceExtension);
    ASSERT(DeviceExtension->ExtensionType == FdoExtension);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG_PTR Information = 0;
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
	PortFdoFilterRequirements(DeviceExtension, Irp);
	return ForwardIrpAndForget(DeviceExtension->LowerDevice, Irp);

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
	DPRINT1("IRP_MJ_PNP / Unknown IOCTL 0x%x\n", Stack->MinorFunction);
	return ForwardIrpAndForget(DeviceExtension->LowerDevice, Irp);
    }

    Irp->IoStatus.Information = Information;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
