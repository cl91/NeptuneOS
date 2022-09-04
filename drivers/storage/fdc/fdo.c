/*
 * PROJECT:        ReactOS Floppy Disk Controller Driver
 * LICENSE:        GNU GPLv2 only as published by the Free Software Foundation
 * FILE:           drivers/storage/fdc/fdc/fdo.c
 * PURPOSE:        Functional Device Object routines
 * PROGRAMMERS:    Eric Kohl
 * NOTES:
 *     This file implements the bus driver part of the FDC stack. This might
 * seem rather counter-intuitive, as this file is titled "Function Device
 * Object routines". See fdc.h for the reason why.
 */

/* INCLUDES *******************************************************************/

#include "fdc.h"

#include <stdio.h>

/* FUNCTIONS ******************************************************************/

NTAPI NTSTATUS ForwardIrpAndForget(IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp)
{
    PDEVICE_OBJECT LowerDevice = ((PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowerDevice;

    ASSERT(LowerDevice);

    return IoCallDriver(LowerDevice, Irp);
}

/*
 * FUNCTION: Stop the floppy motor
 * ARGUMENTS:
 *     UnusedDpc: DPC object that's going off
 *     DeferredContext: called with DRIVE_INFO for drive to turn off
 *     SystemArgument1: unused
 *     SystemArgument2: unused
 * NOTES:
 *     - This is dispatched at the end of a system service call so it is
 *       never called during StartMotor.
 */
static NTAPI VOID MotorStopDpcFunc(PKDPC UnusedDpc,
				   PVOID DeferredContext,
				   PVOID SystemArgument1,
				   PVOID SystemArgument2)
{
    PCONTROLLER_INFO ControllerInfo = (PCONTROLLER_INFO)DeferredContext;

    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    UNREFERENCED_PARAMETER(UnusedDpc);

    ASSERT(ControllerInfo);

    TRACE_(FLOPPY, "MotorStopDpcFunc called\n");

    if (!ControllerInfo->MotorStopCanceled) {
	HwTurnOffMotor(ControllerInfo);
    }
}

/*
 * FUNCTION: Start the motor
 * ARGUMENTS:
 *     DriveInfo: drive to start
 * NOTES:
 *     - Never call HwTurnOnMotor() directly
 *     - On ReactOS this function exists to manage a race condition between canceling
 *       the motor stop timer and turning on the motor. Since on Neptune OS DPCs are
 *       dispatched after system services have received a reply from server (in other
 *       words, DPCs are never dispatched when the StartMotor function is running), we
 *       do not have this problem. Therefore this function simply cancels the timer
 *       and calls HwTurnOnMotor.
 */
VOID StartMotor(PDRIVE_INFO DriveInfo)
{
    ASSERT(DriveInfo);

    TRACE_(FLOPPY, "StartMotor called\n");
    DriveInfo->ControllerInfo->MotorStopCanceled = TRUE;
    NTSTATUS Status = HwTurnOnMotor(DriveInfo);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY,
	      "StartMotor(): warning: HwTurnOnMotor failed with status 0x%x\n",
	      Status);
    }
}

/*
 * FUNCTION: Stop all motors on the controller
 * ARGUMENTS:
 *     DriveInfo: Drive to stop
 * NOTES:
 *     - Never call HwTurnOffMotor() directly
 *     - We set up a timer to wait for one second before turning off the motor.
 */
VOID StopMotor(PCONTROLLER_INFO ControllerInfo)
{
    LARGE_INTEGER StopTime;

    ASSERT(ControllerInfo);

    TRACE_(FLOPPY, "StopMotor called\n");

    /* one relative second, in 100-ns units */
    StopTime.QuadPart = 10000000;
    StopTime.QuadPart *= -1;

    KeSetTimer(&ControllerInfo->MotorTimer, StopTime,
	       &ControllerInfo->MotorStopDpc);
}

/*
 * FUNCTION: Wait for the controller to interrupt, and then clear the event
 * ARGUMENTS:
 *     ControllerInfo: Controller to wait for
 * NOTES:
 *     - There is a small chance that an unexpected or spurious interrupt could
 *       be lost with this clear/wait/clear scheme used in this driver.  This is
 *       deemed to be an acceptable risk due to the unlikeliness of the scenario,
 *       and the fact that it'll probably work fine next time.
 */
NTSTATUS WaitForControllerInterrupt(PCONTROLLER_INFO ControllerInfo,
				    PLARGE_INTEGER Timeout)
{
    ASSERT(ControllerInfo);

    NTSTATUS Status = KeWaitForSingleObject(&ControllerInfo->SynchEvent, Executive,
					    KernelMode, FALSE, Timeout);
    KeClearEvent(&ControllerInfo->SynchEvent);

    return Status;
}

/*
 * FUNCTION: Start the recalibration process
 * ARGUMENTS:
 *     DriveInfo: Pointer to the driveinfo struct associated with the targeted drive
 * RETURNS:
 *     STATUS_SUCCESS on successful starting of the process
 *     STATUS_IO_DEVICE_ERROR if it fails
 * NOTES:
 *     - Sometimes you have to do two recalibrations, particularly if the disk has <80 tracks.
 *     - PAGED_CODE because we wait
 */
NTSTATUS Recalibrate(PDRIVE_INFO DriveInfo)
{
    ASSERT(DriveInfo);

    /* First turn on the motor.
     * Must stop after every start, prior to return */
    StartMotor(DriveInfo);

    /* Set the data rate */
    WARN_(FLOPPY, "FIXME: UN-HARDCODE DATA RATE\n");
    NTSTATUS Status = HwSetDataRate(DriveInfo->ControllerInfo, 0);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "Recalibrate: HwSetDataRate failed with error 0x%x\n",
	      Status);
	Status = STATUS_IO_DEVICE_ERROR;
	goto out;
    }

    /* clear the event just in case the last call forgot */
    KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

    /* sometimes you have to do this twice; we'll just do it twice all the time since
     * we don't know if the people calling this Recalibrate routine expect a disk to
     * even be in the drive, and if so, if that disk is formatted.
     */
    for (int i = 0; i < 2; i++) {
	/* Send the command */
	Status = HwRecalibrate(DriveInfo);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "Recalibrate: HwRecalibrate returned error 0x%x\n",
		  Status);
	    /* We ignore this error and continue */
	    Status = STATUS_SUCCESS;
	    continue;
	}

	WaitForControllerInterrupt(DriveInfo->ControllerInfo, NULL);

	/* Get the results */
	Status = HwRecalibrateResult(DriveInfo->ControllerInfo);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "Recalibrate: HwRecalibrateResult returned error 0x%x\n",
		  Status);
	    break;
	}
    }

    KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

out:
    /* Must stop after every start, prior to return */
    StopMotor(DriveInfo->ControllerInfo);

    return Status;
}

/*
 * FUNCTION: Interrupt service routine for the controllers
 * ARGUMENTS:
 *     Interrupt: Interrupt object representing the interrupt that occured
 *     ServiceContext: Pointer to the ControllerInfo object that caused the interrupt
 * RETURNS:
 *     TRUE in all cases (see notes)
 * NOTES:
 *     - Because in our architecture interrupt service routines can block (or do pretty much anything
 *       it wants really), we simply set the event here in the ISR. There is no need for DPC here.
 * ORIGINAL REACTOS NOTES:
 *     - We should always be the target of the interrupt, being an edge-triggered ISA interrupt, but
 *       this won't be the case with a level-sensitive system like PCI
 *     - Note that it probably doesn't matter if the interrupt isn't dismissed, as it's edge-triggered.
 *       It probably won't keep re-interrupting.
 *     - There are two different ways to dismiss a floppy interrupt.  If the command has a result phase
 *       (see intel datasheet), you dismiss the interrupt by reading the first data byte.  If it does
 *       not, you dismiss the interrupt by doing a Sense Interrupt command.  Again, because it's edge-
 *       triggered, this is safe to not do here, as we can just wait for the DPC.
 *     - Either way, we don't want to do this here.  The controller shouldn't interrupt again, so we'll
 *       schedule a DPC to take care of it.
 *     - This driver really cannot share interrupts, as I don't know how to conclusively say
 *       whether it was our controller that interrupted or not.  I just have to assume that any time
 *       my ISR gets called, it was my board that called it.  Dumb design, yes, but it goes back to
 *       the semantics of ISA buses.  That, and I don't know much about ISA drivers. :-)
 *       UPDATE: The high bit of Status Register A seems to work on non-AT controllers.
 *     - Called at DIRQL
 */
static NTAPI BOOLEAN Isr(PKINTERRUPT Interrupt, PVOID ServiceContext)
{
    PCONTROLLER_INFO ControllerInfo = (PCONTROLLER_INFO) ServiceContext;

    UNREFERENCED_PARAMETER(Interrupt);

    ASSERT(ControllerInfo);

    TRACE_(FLOPPY, "ISR called\n");

    /*
     * Due to the stupidity of the drive/controller relationship on the floppy drive, only one device object
     * can have an active interrupt pending.  Due to the nature of these IRPs, though, there will only ever
     * be one thread expecting an interrupt at a time, and furthermore, Interrupts (outside of spurious ones)
     * won't ever happen unless a thread is expecting them.  Therefore, all we have to do is signal an event
     * and we're done.
     */
    KeSetEvent(&ControllerInfo->SynchEvent);

    return TRUE;
}

static NTSTATUS InitController(PCONTROLLER_INFO ControllerInfo)
/*
 * FUNCTION:  Initialize a newly-found controller
 * ARGUMENTS:
 *     ControllerInfo: pointer to the controller to be initialized
 * RETURNS:
 *     STATUS_SUCCESS if the controller is successfully initialized
 *     STATUS_IO_DEVICE_ERROR otherwise
 */
{
    UCHAR HeadLoadTime;
    UCHAR HeadUnloadTime;
    UCHAR StepRateTime;
    UCHAR ControllerVersion;

    ASSERT(ControllerInfo);

    TRACE_(FLOPPY, "InitController called with Controller 0x%p\n",
	   ControllerInfo);

    /* Get controller in a known state */
    NTSTATUS Status = HwConfigure(ControllerInfo, FALSE, TRUE, TRUE, 0, 0);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "InitController: unable to configure controller. Error = 0x%x\n",
	      Status);
	return STATUS_IO_DEVICE_ERROR;
    }

    /* Get the controller version */
    ControllerVersion = HwGetVersion(ControllerInfo);

    KeClearEvent(&ControllerInfo->SynchEvent);

    /* Reset the controller */
    Status = HwReset(ControllerInfo);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "InitController: unable to reset controller. Error = 0x%x\n",
	      Status);
	return STATUS_IO_DEVICE_ERROR;
    }

    INFO_(FLOPPY, "InitController: waiting for initial interrupt\n");

    /* Wait for an interrupt */
    WaitForControllerInterrupt(ControllerInfo, NULL);

    /* Reset means you have to clear each of the four interrupts (one per drive) */
    for (int i = 0; i < MAX_DRIVES_PER_CONTROLLER; i++) {
	INFO_(FLOPPY, "InitController: Sensing interrupt %d\n", i);

	Status = HwSenseInterruptStatus(ControllerInfo);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "InitController: Unable to clear interrupt for drive 0x%x. Error 0x%x\n",
		  i, Status);
	    return STATUS_IO_DEVICE_ERROR;
	}
    }

    INFO_(FLOPPY, "InitController: done sensing interrupts\n");

    /* Next, see if we have the right version to do implied seek */
    if (ControllerVersion == VERSION_ENHANCED) {
	/* If so, set that up -- all defaults below except first TRUE for EIS */
	Status = HwConfigure(ControllerInfo, TRUE, TRUE, TRUE, 0, 0);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "InitController: unable to set up implied seek. Error = 0x%x\n",
		  Status);
	    ControllerInfo->ImpliedSeeks = FALSE;
	} else {
	    INFO_(FLOPPY, "InitController: implied seeks set!\n");
	    ControllerInfo->ImpliedSeeks = TRUE;
	}

	/*
	 * FIXME: Figure out the answer to the below
	 *
	 * I must admit that I'm really confused about the Model 30 issue.  At least one
	 * important bit (the disk change bit in the DIR) is flipped if this is a Model 30
	 * controller.  However, at least one other floppy driver believes that there are only
	 * two computers that are guaranteed to have a Model 30 controller:
	 *  - IBM Thinkpad 750
	 *  - IBM PS2e
	 *
	 * ...and another driver only lists a config option for "thinkpad", that flips
	 * the change line.  A third driver doesn't mention the Model 30 issue at all.
	 *
	 * What I can't tell is whether or not the average, run-of-the-mill computer now has
	 * a Model 30 controller.  For the time being, I'm going to wire this to FALSE,
	 * and just not support the computers mentioned above, while I try to figure out
	 * how ubiquitous these newfangled 30 thingies are.
	 */
	//ControllerInfo->Model30 = TRUE;
	ControllerInfo->Model30 = FALSE;
    } else {
	INFO_(FLOPPY,
	      "InitController: enhanced version not supported; disabling implied seeks\n");
	ControllerInfo->ImpliedSeeks = FALSE;
	ControllerInfo->Model30 = FALSE;
    }

    /* Specify */
    WARN_(FLOPPY, "FIXME: Figure out speed\n");
    HeadLoadTime = SPECIFY_HLT_500K;
    HeadUnloadTime = SPECIFY_HUT_500K;
    StepRateTime = SPECIFY_SRT_500K;

    INFO_(FLOPPY, "InitController: setting data rate\n");

    /* Set data rate */
    Status = HwSetDataRate(ControllerInfo, DRSR_DSEL_500KBPS);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "InitController: unable to set data rate. Error = 0x%x\n",
	      Status);
	return STATUS_IO_DEVICE_ERROR;
    }

    INFO_(FLOPPY,
	  "InitController: issuing specify command to controller\n");

    /* Don't disable DMA --> enable dma (dumb & confusing) */
    Status = HwSpecify(ControllerInfo, HeadLoadTime, HeadUnloadTime,
		       StepRateTime, FALSE);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "InitController: unable to specify options. Error = 0x%x\n",
	      Status);
	return STATUS_IO_DEVICE_ERROR;
    }

    /* Init the stop stuff */
    KeInitializeDpc(&ControllerInfo->MotorStopDpc, MotorStopDpcFunc,
		    ControllerInfo);
    KeInitializeTimer(&ControllerInfo->MotorTimer);

    /*
     * Recalibrate each drive on the controller (depends on StartMotor, which depends on the timer stuff above)
     * We don't even know if there is a disk in the drive, so this may not work, but that's OK.
     */
    for (int i = 0; i < ControllerInfo->NumberOfDrives; i++) {
	INFO_(FLOPPY,
	      "InitController: recalibrating drive %d on controller 0x%p\n",
	      i, ControllerInfo);
	Recalibrate(&ControllerInfo->DriveInfo[i]);
    }

    INFO_(FLOPPY,
	  "InitController: done initializing; returning STATUS_SUCCESS\n");

    return STATUS_SUCCESS;
}

static NTSTATUS FdcFdoStartDevice(IN PDEVICE_OBJECT DeviceObject,
				  IN PCM_RESOURCE_LIST ResourceList,
				  IN PCM_RESOURCE_LIST ResourceListTranslated)
{
    DPRINT("FdcFdoStartDevice called\n");

    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    ASSERT(DeviceExtension);

    if (ResourceList == NULL || ResourceListTranslated == NULL) {
	DPRINT1("No allocated resources sent to driver\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (ResourceList->Count != 1) {
	DPRINT1("Wrong number of allocated resources sent to driver\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (ResourceList->List[0].PartialResourceList.Version != 1 ||
	ResourceList->List[0].PartialResourceList.Revision != 1 ||
	ResourceListTranslated->List[0].PartialResourceList.Version != 1 ||
	ResourceListTranslated->List[0].PartialResourceList.Revision != 1) {
	DPRINT1("Revision mismatch: %u.%u != 1.1 or %u.%u != 1.1\n",
		ResourceList->List[0].PartialResourceList.Version,
		ResourceList->List[0].PartialResourceList.Revision,
		ResourceListTranslated->List[0].PartialResourceList.Version,
		ResourceListTranslated->List[0].PartialResourceList.Revision);
	return STATUS_REVISION_MISMATCH;
    }

    BOOLEAN FoundPort = FALSE;
    BOOLEAN FoundInterrupt = FALSE;
    BOOLEAN FoundDma = FALSE;
    for (ULONG i = 0; i < ResourceList->List[0].PartialResourceList.Count; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor =
	    &ResourceList->List[0].PartialResourceList.PartialDescriptors[i];
	PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptorTranslated =
	    &ResourceListTranslated->List[0].PartialResourceList.PartialDescriptors[i];

	switch (PartialDescriptor->Type) {
	case CmResourceTypePort:
	    DPRINT("Port: 0x%x (%u)\n",
		   PartialDescriptor->u.Port.Start.u.LowPart,
		   PartialDescriptor->u.Port.Length);
	    if (PartialDescriptor->u.Port.Length >= 6) {
		DeviceExtension->ControllerInfo.BaseAddress = (PUCHAR)PartialDescriptor->u.Port.Start.QuadPart;
		assert(!FoundPort);
		FoundPort = TRUE;
	    }
	    break;

	case CmResourceTypeInterrupt:
	    DPRINT("Interrupt: Level %u  Vector %u\n",
		   PartialDescriptor->u.Interrupt.Level,
		   PartialDescriptor->u.Interrupt.Vector);
	    DeviceExtension->ControllerInfo.Level = (KIRQL)PartialDescriptorTranslated->u.Interrupt.Level;
	    DeviceExtension->ControllerInfo.Vector = PartialDescriptorTranslated->u.Interrupt.Vector;
	    DeviceExtension->ControllerInfo.Affinity = PartialDescriptorTranslated->u.Interrupt.Affinity;
	    if (PartialDescriptorTranslated->Flags & CM_RESOURCE_INTERRUPT_LATCHED) {
		DeviceExtension->ControllerInfo.InterruptMode = Latched;
	    } else {
		DeviceExtension->ControllerInfo.InterruptMode = LevelSensitive;
	    }
	    DeviceExtension->ControllerInfo.ShareInterrupt = (PartialDescriptorTranslated->ShareDisposition == CmResourceShareShared);
	    assert(!FoundInterrupt);
	    FoundInterrupt = TRUE;
	    break;

	case CmResourceTypeDma:
	    DPRINT("Dma: Channel %u\n", PartialDescriptor->u.Dma.Channel);
	    DeviceExtension->ControllerInfo.Dma = PartialDescriptorTranslated->u.Dma.Channel;
	    assert(!FoundDma);
	    FoundDma = TRUE;
	    break;
	}
    }

    if (!FoundPort || !FoundInterrupt || !FoundDma) {
	if (!FoundPort) {
	    ERR_(FLOPPY, "PnP manager did not supply a port resource\n");
	}
	if (!FoundInterrupt) {
	    ERR_(FLOPPY, "PnP manager did not supply an interupt resource\n");
	}
	if (!FoundDma) {
	    ERR_(FLOPPY, "PnP manager did not supply a DMA resource\n");
	}
	assert(FALSE);
	return STATUS_NO_SUCH_DEVICE;
    }

    /* 1: Connect the interrupt
     * NOTE: We cannot share our interrupt, even on level-triggered buses.
     * See Isr() for details. */
    NTSTATUS Status = IoConnectInterrupt(&DeviceExtension->ControllerInfo.InterruptObject,
					 Isr,
					 &DeviceExtension->ControllerInfo,
					 DeviceExtension->ControllerInfo.Vector,
					 DeviceExtension->ControllerInfo.Level,
					 DeviceExtension->ControllerInfo.Level,
					 DeviceExtension->ControllerInfo.InterruptMode,
					 FALSE,
					 DeviceExtension->ControllerInfo.Affinity,
					 FALSE);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "FdcFdoStartDevice: unable to connect interrupt\n");
	return Status;
    }

    /* 2: Set up DMA */
    DEVICE_DESCRIPTION DeviceDescription = {
	.Version = DEVICE_DESCRIPTION_VERSION,
	.DmaChannel = DeviceExtension->ControllerInfo.Dma,
	.InterfaceType = DeviceExtension->ControllerInfo.InterfaceType,
	.BusNumber = DeviceExtension->ControllerInfo.BusNumber,
	.MaximumLength = 2 * 18 * 512, /* based on a 1.44MB floppy */
	.DmaWidth = (DeviceExtension->ControllerInfo.Dma > 3) ? Width16Bits : Width8Bits /* DMA 0,1,2,3 are 8-bit; 4,5,6,7 are 16-bit (4 is chain I think) */
    };

    DeviceExtension->ControllerInfo.AdapterObject = HalGetAdapter(&DeviceDescription,
								  &DeviceExtension->ControllerInfo.MapRegisters);

    if (!DeviceExtension->ControllerInfo.AdapterObject) {
	WARN_(FLOPPY,
	      "FdcFdoStartDevice: unable to allocate an adapter object\n");
	Status = STATUS_NO_SUCH_DEVICE;
	goto err;
    }

    /* 3: Initialize the new controller */
    Status = InitController(&DeviceExtension->ControllerInfo);
    if (NT_SUCCESS(Status)) {
	WARN_(FLOPPY,
	      "FdcFdoStartDevice(): Unable to set up controller - initialization failed\n");
	goto err;
    }

    /* 4: Set the controller's initialized flag so we know to release stuff in Unload */
    DeviceExtension->ControllerInfo.Initialized = TRUE;

    return STATUS_SUCCESS;

err:
    IoDisconnectInterrupt(DeviceExtension->ControllerInfo.InterruptObject);
    return Status;
}

static NTAPI NTSTATUS FdcFdoConfigCallback(PVOID Context,
					   PUNICODE_STRING PathName,
					   INTERFACE_TYPE BusType,
					   ULONG BusNumber,
					   PKEY_VALUE_FULL_INFORMATION *BusInformation,
					   CONFIGURATION_TYPE ControllerType,
					   ULONG ControllerNumber,
					   PKEY_VALUE_FULL_INFORMATION *ControllerInformation,
					   CONFIGURATION_TYPE PeripheralType,
					   ULONG PeripheralNumber,
					   PKEY_VALUE_FULL_INFORMATION *PeripheralInformation)
{
    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)Context;
    BOOLEAN ControllerFound = FALSE;

    DPRINT("FdcFdoConfigCallback() called\n");

    /* Get the controller resources */
    PKEY_VALUE_FULL_INFORMATION ControllerFullDescriptor =
	ControllerInformation[IoQueryDeviceConfigurationData];
    PCM_FULL_RESOURCE_DESCRIPTOR ControllerResourceDescriptor =
	(PCM_FULL_RESOURCE_DESCRIPTOR)((PCHAR)ControllerFullDescriptor + ControllerFullDescriptor->DataOffset);

    DPRINT("Got %d controller partial resource list(s).\n", ControllerResourceDescriptor->PartialResourceList.Count);
    for (ULONG i = 0; i < ControllerResourceDescriptor->PartialResourceList.Count; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor =
	    &ControllerResourceDescriptor->PartialResourceList.PartialDescriptors[i];
	DPRINT("Got partial resource descriptor type %d\n", PartialDescriptor->Type);
	if (PartialDescriptor->Type == CmResourceTypePort) {
	    DPRINT("Got fdc controller port address 0x%llx. Checking if it matches.\n",
		   PartialDescriptor->u.Port.Start.QuadPart);
	    if ((PUCHAR)PartialDescriptor->u.Port.Start.QuadPart == DeviceExtension->ControllerInfo.BaseAddress) {
		ControllerFound = TRUE;
		DPRINT("Matches!\n");
	    }
	}
    }

    /* Leave, if the enumerated controller is not the one represented by the FDO */
    if (ControllerFound == FALSE) {
	DPRINT("No floppy disk controller found!\n");
	return STATUS_SUCCESS;
    }

    /* Get the peripheral resources */
    PKEY_VALUE_FULL_INFORMATION PeripheralFullDescriptor =
	PeripheralInformation[IoQueryDeviceConfigurationData];
    PCM_FULL_RESOURCE_DESCRIPTOR PeripheralResourceDescriptor =
	(PCM_FULL_RESOURCE_DESCRIPTOR)((PCHAR)PeripheralFullDescriptor + PeripheralFullDescriptor->DataOffset);

    /* Learn about drives attached to the controller */
    DPRINT("Got %d peripheral partial resource list(s).\n", PeripheralResourceDescriptor->PartialResourceList.Count);
    for (ULONG i = 0; i < PeripheralResourceDescriptor->PartialResourceList.Count; i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor =
	    &PeripheralResourceDescriptor->PartialResourceList.PartialDescriptors[i];

	if (PartialDescriptor->Type != CmResourceTypeDeviceSpecific) {
	    DPRINT("Peripheral partial resource descriptor is type %d. Skipping\n",
		   PartialDescriptor->Type);
	    continue;
	}

	PCM_FLOPPY_DEVICE_DATA FloppyDeviceData = (PCM_FLOPPY_DEVICE_DATA)(PartialDescriptor + 1);

	PDRIVE_INFO DriveInfo = &DeviceExtension->ControllerInfo.DriveInfo[DeviceExtension->ControllerInfo.NumberOfDrives];

	DriveInfo->ControllerInfo = &DeviceExtension->ControllerInfo;
	DriveInfo->UnitNumber = DeviceExtension->ControllerInfo.NumberOfDrives;
	DriveInfo->PeripheralNumber = PeripheralNumber;

	DriveInfo->FloppyDeviceData.MaxDensity = FloppyDeviceData->MaxDensity;
	DriveInfo->FloppyDeviceData.MountDensity = FloppyDeviceData->MountDensity;
	DriveInfo->FloppyDeviceData.StepRateHeadUnloadTime = FloppyDeviceData->StepRateHeadUnloadTime;
	DriveInfo->FloppyDeviceData.HeadLoadTime = FloppyDeviceData->HeadLoadTime;
	DriveInfo->FloppyDeviceData.MotorOffTime = FloppyDeviceData->MotorOffTime;
	DriveInfo->FloppyDeviceData.SectorLengthCode = FloppyDeviceData->SectorLengthCode;
	DriveInfo->FloppyDeviceData.SectorPerTrack = FloppyDeviceData->SectorPerTrack;
	DriveInfo->FloppyDeviceData.ReadWriteGapLength = FloppyDeviceData->ReadWriteGapLength;
	DriveInfo->FloppyDeviceData.FormatGapLength = FloppyDeviceData->FormatGapLength;
	DriveInfo->FloppyDeviceData.FormatFillCharacter = FloppyDeviceData->FormatFillCharacter;
	DriveInfo->FloppyDeviceData.HeadSettleTime = FloppyDeviceData->HeadSettleTime;
	DriveInfo->FloppyDeviceData.MotorSettleTime = FloppyDeviceData->MotorSettleTime;
	DriveInfo->FloppyDeviceData.MaximumTrackValue = FloppyDeviceData->MaximumTrackValue;
	DriveInfo->FloppyDeviceData.DataTransferLength = FloppyDeviceData->DataTransferLength;

	/* Once it's all set up, acknowledge its existence in the controller info object */
	DeviceExtension->ControllerInfo.NumberOfDrives++;
    }

    DeviceExtension->ControllerInfo.Populated = TRUE;
    DeviceExtension->ControllerInfo.ControllerNumber = ControllerNumber;
    DeviceExtension->ControllerInfo.InterfaceType = BusType;
    DeviceExtension->ControllerInfo.BusNumber = BusNumber;

    DPRINT("Detected %u floppy drives!\n",
	   DeviceExtension->ControllerInfo.NumberOfDrives);

    return STATUS_SUCCESS;
}

static NTSTATUS PciCreateHardwareIDsString(PUNICODE_STRING HardwareIDs)
{
    WCHAR Buffer[256];
    ULONG Index = swprintf(Buffer, L"FDC\\GENERIC_FLOPPY_DRIVE") + 1;
    Buffer[Index] = UNICODE_NULL;

    UNICODE_STRING BufferU = {
	.Length = (USHORT)Index * sizeof(WCHAR),
	.MaximumLength = (USHORT)Index * sizeof(WCHAR),
	.Buffer = Buffer
    };

    return RtlDuplicateUnicodeString(0, &BufferU, HardwareIDs);
}

static NTSTATUS PciCreateCompatibleIDsString(PUNICODE_STRING CompatibleIDs)
{
    WCHAR Buffer[256];
    ULONG Index = swprintf(Buffer, L"GenFloppyDisk") + 1;
    Buffer[Index] = UNICODE_NULL;

    UNICODE_STRING BufferU = {
	.Length = (USHORT)Index * sizeof(WCHAR),
	.MaximumLength = (USHORT)Index * sizeof(WCHAR),
	.Buffer = Buffer
    };

    return RtlDuplicateUnicodeString(0, &BufferU, CompatibleIDs);
}

static NTSTATUS PciCreateInstanceIDString(PUNICODE_STRING InstanceID,
					  ULONG PeripheralNumber)
{
    WCHAR Buffer[3];

    swprintf(Buffer, L"%02X", PeripheralNumber & 0xff);

    return RtlCreateUnicodeString(InstanceID, Buffer) ?
	STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

static NTSTATUS FdcFdoQueryBusRelations(IN PDEVICE_OBJECT DeviceObject,
					OUT PDEVICE_RELATIONS *DeviceRelations)
{
    PPDO_DEVICE_EXTENSION PdoDeviceExtension;
    INTERFACE_TYPE InterfaceType = Isa;
    CONFIGURATION_TYPE ControllerType = DiskController;
    CONFIGURATION_TYPE PeripheralType = FloppyDiskPeripheral;
    PDRIVE_INFO DriveInfo;
    UNICODE_STRING DeviceName;
    ULONG DeviceNumber = 0;

    DPRINT("FdcFdoQueryBusRelations() called\n");

    PFDO_DEVICE_EXTENSION FdoDeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    NTSTATUS Status = IoQueryDeviceDescription(&InterfaceType,
					       NULL,
					       &ControllerType,
					       NULL,
					       &PeripheralType,
					       NULL,
					       FdcFdoConfigCallback,
					       FdoDeviceExtension);
    if (!NT_SUCCESS(Status) && (Status != STATUS_NO_MORE_ENTRIES))
	return Status;

    ULONG Size = sizeof(DEVICE_RELATIONS) + sizeof(PDEVICE_OBJECT) *
	FdoDeviceExtension->ControllerInfo.NumberOfDrives;
    PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)ExAllocatePool(Size);
    if (Relations == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    Relations->Count = FdoDeviceExtension->ControllerInfo.NumberOfDrives;

    for (ULONG i = 0; i < FdoDeviceExtension->ControllerInfo.NumberOfDrives; i++) {
	DriveInfo = &FdoDeviceExtension->ControllerInfo.DriveInfo[i];

	if (DriveInfo->DeviceObject == NULL) {
	    PDEVICE_OBJECT Pdo;
	    do {
		swprintf(DriveInfo->DeviceNameBuffer, L"\\Device\\Floppy%u", DeviceNumber++);
		RtlInitUnicodeString(&DeviceName, DriveInfo->DeviceNameBuffer);
		DPRINT("Device name: %S\n", DriveInfo->DeviceNameBuffer);

		/* Create physical device object */
		Status = IoCreateDevice(FdoDeviceExtension->Common.DeviceObject->DriverObject,
					sizeof(PDO_DEVICE_EXTENSION),
					&DeviceName, FILE_DEVICE_DISK,
					FILE_DEVICE_SECURE_OPEN | FILE_REMOVABLE_MEDIA | FILE_FLOPPY_DISKETTE,
					FALSE, &Pdo);
	    } while (Status == STATUS_OBJECT_NAME_COLLISION);

	    if (!NT_SUCCESS(Status)) {
		DPRINT1("PDO creation failed (Status 0x%08x)\n", Status);
		goto done;
	    }

	    DPRINT("PDO created: %S\n", DriveInfo->DeviceNameBuffer);

	    DriveInfo->DeviceObject = Pdo;

	    PdoDeviceExtension = (PPDO_DEVICE_EXTENSION) Pdo->DeviceExtension;
	    RtlZeroMemory(PdoDeviceExtension,
			  sizeof(PDO_DEVICE_EXTENSION));

	    PdoDeviceExtension->Common.IsFDO = FALSE;
	    PdoDeviceExtension->Common.DeviceObject = Pdo;

	    PdoDeviceExtension->Fdo = FdoDeviceExtension->Common.DeviceObject;
	    PdoDeviceExtension->DriveInfo = DriveInfo;

	    Pdo->Flags |= DO_DIRECT_IO;
	    Pdo->Flags |= DO_POWER_PAGABLE;
	    Pdo->Flags &= ~DO_DEVICE_INITIALIZING;

	    /* Add Device ID string */
	    RtlCreateUnicodeString(&PdoDeviceExtension->DeviceId,
				   L"FDC\\GENERIC_FLOPPY_DRIVE");
	    DPRINT("DeviceID: %S\n", PdoDeviceExtension->DeviceId.Buffer);

	    /* Add Hardware IDs string */
	    Status = PciCreateHardwareIDsString(&PdoDeviceExtension->HardwareIds);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }

	    /* Add Compatible IDs string */
	    Status = PciCreateCompatibleIDsString(&PdoDeviceExtension->CompatibleIds);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }

	    /* Add Instance ID string */
	    Status = PciCreateInstanceIDString(&PdoDeviceExtension->InstanceId,
					       DriveInfo->PeripheralNumber);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }
	}

	Relations->Objects[i] = DriveInfo->DeviceObject;
    }

done:
    if (NT_SUCCESS(Status)) {
	*DeviceRelations = Relations;
    } else {
	if (Relations != NULL)
	    ExFreePool(Relations);
    }

    return Status;
}

NTSTATUS FdcFdoPnp(IN PDEVICE_OBJECT DeviceObject,
		   IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION FdoExtension;
    PIO_STACK_LOCATION IrpSp;
    PDEVICE_RELATIONS DeviceRelations = NULL;
    ULONG_PTR Information = 0;
    NTSTATUS Status = STATUS_NOT_SUPPORTED;

    DPRINT("FdcFdoPnp()\n");

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpSp->MinorFunction) {
    case IRP_MN_START_DEVICE:
	DPRINT("  IRP_MN_START_DEVICE received\n");

	/* Call lower driver */
	Status = STATUS_UNSUCCESSFUL;
	FdoExtension = DeviceObject->DeviceExtension;

	if (IoForwardIrpSynchronously(FdoExtension->LowerDevice, Irp)) {
	    Status = Irp->IoStatus.Status;
	    if (NT_SUCCESS(Status)) {
		Status = FdcFdoStartDevice(DeviceObject,
					   IrpSp->Parameters.StartDevice.AllocatedResources,
					   IrpSp->Parameters.StartDevice.AllocatedResourcesTranslated);
	    }
	}

	break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
	DPRINT("  IRP_MN_QUERY_REMOVE_DEVICE\n");
	break;

    case IRP_MN_REMOVE_DEVICE:
	DPRINT("  IRP_MN_REMOVE_DEVICE received\n");
	break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
	DPRINT("  IRP_MN_CANCEL_REMOVE_DEVICE\n");
	break;

    case IRP_MN_STOP_DEVICE:
	DPRINT("  IRP_MN_STOP_DEVICE received\n");
	break;

    case IRP_MN_QUERY_STOP_DEVICE:
	DPRINT("  IRP_MN_QUERY_STOP_DEVICE received\n");
	break;

    case IRP_MN_CANCEL_STOP_DEVICE:
	DPRINT("  IRP_MN_CANCEL_STOP_DEVICE\n");
	break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
	DPRINT("  IRP_MN_QUERY_DEVICE_RELATIONS\n");

	switch (IrpSp->Parameters.QueryDeviceRelations.Type) {
	case BusRelations:
	    DPRINT("    IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / BusRelations\n");
	    Status = FdcFdoQueryBusRelations(DeviceObject, &DeviceRelations);
	    Information = (ULONG_PTR) DeviceRelations;
	    break;

	case RemovalRelations:
	    DPRINT("    IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / RemovalRelations\n");
	    return ForwardIrpAndForget(DeviceObject, Irp);

	default:
	    DPRINT("    IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / Unknown type 0x%x\n",
		   IrpSp->Parameters.QueryDeviceRelations.Type);
	    return ForwardIrpAndForget(DeviceObject, Irp);
	}
	break;

    case IRP_MN_SURPRISE_REMOVAL:
	DPRINT("  IRP_MN_SURPRISE_REMOVAL received\n");
	break;

    default:
	DPRINT("  Unknown IOCTL 0x%x\n", IrpSp->MinorFunction);
	return ForwardIrpAndForget(DeviceObject, Irp);
    }

    Irp->IoStatus.Information = Information;
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}
