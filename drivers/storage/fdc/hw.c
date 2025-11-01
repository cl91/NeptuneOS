/*
 *  ReactOS Floppy Driver
 *  Copyright (C) 2004, Vizzini (vizzini@plasmic.com)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * PROJECT:         ReactOS Floppy Driver
 * FILE:            hardware.c
 * PURPOSE:         FDC Hardware control routines
 * PROGRAMMER:      Vizzini (vizzini@plasmic.com)
 * REVISIONS:
 *                  15-Feb-2004 vizzini - Created
 * NOTES:
 *     - Many of these functions are based directly on information from the
 *       Intel datasheet for their enhanced floppy controller.  SendByte and
 *       GetByte are direct C implementations of their flowcharts, and the
 *       read/write routine and others are loose adaptations of their charts.
 *     - These routines are generally designed to be small, atomic operations.  They
 *       do not wait for interrupts, deal with DMA, or do any other Windows-
 *       specific things, unless they have to.
 *     - The floppy controller is a *dumb* piece of hardware. It is slow and
 *       difficult to deal with.  An issue we currently have is that on some drives
 *       the interrupts comes in too slowly after a read command. This problem
 *       doesn't seem to appear on the QEMU-emulated floppy controller so I don't
 *       know how to debug this.
 *     - Some information taken from Intel 82077AA data sheet (order #290166-007)
 *
 * TODO: ATM the constants defined in hardware.h *might* be shifted to line up
 *       with the bit position in the register, or they *might not*.  This should
 *       all be converted to standardize on absolute values or shifts.
 *       I prefer bit fields, but they break endianness.
 */

#include "fdc.h"

/*
 * Hardware Support Routines
 */

/*
 * FUNCTION: Determine of the controller is ready to accept a byte on the FIFO
 * ARGUMENTS:
 *     ControllerInfo: Info structure for the FDC we're testing
 * RETURNS:
 *     TRUE if the controller can accept a byte right now
 *     FALSE otherwise
 * NOTES:
 *     - it is necessary to check both that the FIFO is set to "outbound"
 *       and that the "ready for i/o" bit is set.
 */
static BOOLEAN ReadyForWrite(PCONTROLLER_INFO ControllerInfo)
{
    UCHAR Status = READ_PORT_UCHAR(ControllerInfo->BaseAddress + MAIN_STATUS_REGISTER);

    if (Status & MSR_IO_DIRECTION)	/* 0 for out */
	return FALSE;

    if (!(Status & MSR_DATA_REG_READY_FOR_IO))
	return FALSE;

    return TRUE;
}

/*
 * FUNCTION: Determine of the controller is ready to read a byte on the FIFO
 * ARGUMENTS:
 *     ControllerInfo: Info structure for the FDC we're testing
 * RETURNS:
 *     TRUE if the controller can read a byte right now
 *     FALSE otherwise
 * NOTES:
 *     - it is necessary to check both that the FIFO is set to "inbound"
 *       and that the "ready for i/o" bit is set.
 */
static BOOLEAN ReadyForRead(PCONTROLLER_INFO ControllerInfo)
{
    UCHAR Status = READ_PORT_UCHAR(ControllerInfo->BaseAddress + MAIN_STATUS_REGISTER);

    if (!(Status & MSR_IO_DIRECTION))	/* Read = 1 */
	return FALSE;

    if (!(Status & MSR_DATA_REG_READY_FOR_IO))
	return FALSE;

    return TRUE;
}

/*
 * FUNCTION: Send a byte from the host to the controller's FIFO
 * ARGUMENTS:
 *     ControllerInfo: Info structure for the controller we're writing to
 *     Offset: Offset over the controller's base address that we're writing to
 *     Byte: Byte to write to the bus
 * RETURNS:
 *     STATUS_SUCCESS if the byte was written successfully
 *     STATUS_UNSUCCESSFUL if not
 * NOTES:
 *     - Function designed after flowchart in intel datasheet
 *     - 250us max delay.
 *     - This function is necessary because sometimes the FIFO reacts slowly
 *       and isn't yet ready to read or write the next byte
 */
static NTSTATUS SendByte(PCONTROLLER_INFO ControllerInfo,
			  UCHAR Byte)
{
    PAGED_CODE();
    int i;

    for (i = 0; i < 5; i++) {
	if (ReadyForWrite(ControllerInfo))
	    break;

	LARGE_INTEGER Delay = { .QuadPart = -500LL };
	KeDelayExecutionThread(FALSE, &Delay);
    }

    if (i < 5) {
	WRITE_PORT_UCHAR(ControllerInfo->BaseAddress + FIFO, Byte);
	return STATUS_SUCCESS;
    } else {
	INFO_(FLOPPY, "SendByte: timed out trying to write\n");
	HwDumpRegisters(ControllerInfo);
	return STATUS_UNSUCCESSFUL;
    }
}

/*
 * FUNCTION: Read a byte from the controller to the host
 * ARGUMENTS:
 *     ControllerInfo: Info structure for the controller we're reading from
 *     Offset: Offset over the controller's base address  that we're reading from
 *     Byte: Byte to read from the bus
 * RETURNS:
 *     STATUS_SUCCESS if the byte was read successfully
 *     STATUS_UNSUCCESSFUL if not
 * NOTES:
 *     - Function designed after flowchart in intel datasheet
 *     - 250us max delay.
 *     - Remember that we can be interrupted here, so this might
 *       take much more wall clock time than 250us
 */
static NTSTATUS GetByte(PCONTROLLER_INFO ControllerInfo,
			 PUCHAR Byte)
{
    PAGED_CODE();
    int i;

    for (i = 0; i < 5; i++) {
	if (ReadyForRead(ControllerInfo))
	    break;

	LARGE_INTEGER Delay = { .QuadPart = -500LL };
	KeDelayExecutionThread(FALSE, &Delay);
    }

    if (i < 5) {
	*Byte = READ_PORT_UCHAR(ControllerInfo->BaseAddress + FIFO);
	return STATUS_SUCCESS;
    } else {
	INFO_(FLOPPY, "GetByte: timed out trying to write\n");
	HwDumpRegisters(ControllerInfo);
	return STATUS_UNSUCCESSFUL;
    }
}

/*
 * FUNCTION: Set the data rate on a controller
 * ARGUMENTS:
 *     ControllerInfo: Controller whose rate is being set
 *     DataRate: Data rate code to set the controller to
 * RETURNS:
 *     STATUS_SUCCESS
 */
NTSTATUS HwSetDataRate(PCONTROLLER_INFO ControllerInfo,
		       UCHAR DataRate)
{
    TRACE_(FLOPPY,
	   "HwSetDataRate called; writing rate code 0x%x to offset 0x%x\n",
	   DataRate, DATA_RATE_SELECT_REGISTER);

    WRITE_PORT_UCHAR(ControllerInfo->BaseAddress + DATA_RATE_SELECT_REGISTER,
		     DataRate);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Turn off all motors
 * ARGUMENTS:
 *     DriveInfo: drive to turn off
 * RETURNS:
 *     STATUS_SUCCESS if the motor is successfully turned off
 * NOTES:
 *     - Don't call this routine directly unless you've thought about it
 *       and read the source to StartMotor() and StopMotor().
 *     - Called at DISPATCH_LEVEL
 */
NTSTATUS HwTurnOffMotor(PCONTROLLER_INFO ControllerInfo)
{
    TRACE_(FLOPPY, "HwTurnOffMotor: writing byte 0x%x to offset 0x%x\n",
	   DOR_FDC_ENABLE | DOR_DMA_IO_INTERFACE_ENABLE,
	   DIGITAL_OUTPUT_REGISTER);

    WRITE_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_OUTPUT_REGISTER,
		     DOR_FDC_ENABLE | DOR_DMA_IO_INTERFACE_ENABLE);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Turn on the motor on the selected drive
 * ARGUMENTS:
 *     DriveInfo: drive to turn on
 * RETURNS:
 *     STATUS_SUCCESS if the motor is successfully turned on
 *     STATUS_UNSUCCESSFUL otherwise
 * NOTES:
 *     - Doesn't interrupt
 *     - Currently cannot fail
 */
NTSTATUS HwTurnOnMotor(PDRIVE_INFO DriveInfo)
{
    PAGED_CODE();
    PCONTROLLER_INFO ControllerInfo = DriveInfo->ControllerInfo;
    UCHAR Unit = DriveInfo->UnitNumber;

    /* turn on motor */
    UCHAR Buffer = Unit;

    Buffer |= DOR_FDC_ENABLE;
    Buffer |= DOR_DMA_IO_INTERFACE_ENABLE;

    if (Unit == 0)
	Buffer |= DOR_FLOPPY_MOTOR_ON_A;
    else if (Unit == 1)
	Buffer |= DOR_FLOPPY_MOTOR_ON_B;
    else if (Unit == 2)
	Buffer |= DOR_FLOPPY_MOTOR_ON_C;
    else if (Unit == 3)
	Buffer |= DOR_FLOPPY_MOTOR_ON_D;

    TRACE_(FLOPPY, "HwTurnOnMotor: writing byte 0x%x to offset 0x%x\n",
	   Buffer, DIGITAL_OUTPUT_REGISTER);
    WRITE_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_OUTPUT_REGISTER,
		     Buffer);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Start a sense status command
 * ARGUMENTS:
 *     DriveInfo: Drive to inquire about
 * RETURNS:
 *     STATUS_SUCCESS if the command is successfully queued to the controller
 *     Error status if not
 * NOTES:
 *     - Generates an interrupt
 *     - hard-wired to head 0
 */
NTSTATUS HwSenseDriveStatus(PDRIVE_INFO DriveInfo)
{
    PAGED_CODE();
    UCHAR Buffer[2];

    TRACE_(FLOPPY, "HwSenseDriveStatus called\n");

    Buffer[0] = COMMAND_SENSE_DRIVE_STATUS;
    Buffer[1] = DriveInfo->UnitNumber;	/* hard-wired to head 0 for now */

    for (int i = 0; i < 2; i++) {
	NTSTATUS Status = SendByte(DriveInfo->ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwSenseDriveStatus: failed to write FIFO. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Read or write data to the drive
 * ARGUMENTS:
 *     ControllerInfo: controller to target the read/write request to
 *     Read: TRUE if the device should be read; FALSE if written
 *     Unit: Drive number to target
 *     Cylinder: cylinder to start the read on
 *     Head: head to start the read on
 *     Sector: sector to start the read on (1-based!)
 *     BytesPerSector: sector size constant (hardware.h)
 *     EndOfTrack: Marks the last sector number to read/write on the track
 *     Gap3Length: Gap length for the operation
 *     DataLength: Bytes to read, *unless* BytesPerSector is specified
 * RETURNS:
 *     STATUS_SUCCESS if the operation was successfully queued to the controller
 *     Error status otherwise
 * NOTES:
 *     - Generates an interrupt
 */
NTSTATUS HwReadWriteData(PCONTROLLER_INFO ControllerInfo,
			 BOOLEAN Read,
			 UCHAR Unit,
			 UCHAR Cylinder,
			 UCHAR Head,
			 UCHAR Sector,
			 UCHAR BytesPerSector,
			 UCHAR EndOfTrack,
			 UCHAR Gap3Length,
			 UCHAR DataLength)
{
    PAGED_CODE();
    UCHAR Buffer[9];

    /* Shouldn't be using DataLength in this driver */
    ASSERT(DataLength == 0xff);

    /* Build the command to send */
    if (Read)
	Buffer[0] = COMMAND_READ_DATA;
    else
	Buffer[0] = COMMAND_WRITE_DATA;

    Buffer[0] |= READ_DATA_MFM | READ_DATA_MT;

    Buffer[1] = (Head << COMMAND_HEAD_NUMBER_SHIFT) | Unit;
    Buffer[2] = Cylinder;
    Buffer[3] = Head;
    Buffer[4] = Sector;
    Buffer[5] = BytesPerSector;
    Buffer[6] = EndOfTrack;
    Buffer[7] = Gap3Length;
    Buffer[8] = DataLength;

    /* Send the command */
    for (int i = 0; i < ARRAYSIZE(Buffer); i++) {
	INFO_(FLOPPY, "HwReadWriteData: Sending a command byte to the FIFO: 0x%x\n",
	      Buffer[i]);

	NTSTATUS Status = SendByte(ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwReadWriteData: Unable to write to the FIFO. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Get the result of a recalibrate command
 * ARGUMENTS:
 *     ControllerInfo: controller to query
 * RETURNS:
 *     STATUS_SUCCESS if the recalibratewas a success
 *     Error status otherwise
 * NOTES:
 *     - This function tests the error conditions itself, and boils the
 *       whole thing down to a single SUCCESS or FAILURE result
 *     - Called post-interrupt; does not interrupt
 * TODO
 *     - perhaps handle more status
 */
NTSTATUS HwRecalibrateResult(PCONTROLLER_INFO ControllerInfo)
{
    PAGED_CODE();
    UCHAR Buffer[2];

    NTSTATUS Status = SendByte(ControllerInfo, COMMAND_SENSE_INTERRUPT_STATUS);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY,
	      "HwRecalibrateResult: Unable to write the controller. Error = 0x%x\n",
	      Status);
	return Status;
    }

    for (int i = 0; i < 2; i++) {
	Status = GetByte(ControllerInfo, &Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwRecalibrateResult: unable to read FIFO. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    /* Validate that it did what we told it to */
    INFO_(FLOPPY, "HwRecalibrateResult results: ST0: 0x%x PCN: 0x%x\n",
	  Buffer[0], Buffer[1]);

    /*
     * Buffer[0] = ST0
     * Buffer[1] = PCN
     */

    /* Is the PCN 0? */
    if (Buffer[1] != 0) {
	WARN_(FLOPPY, "HwRecalibrateResult: PCN not 0\n");
	return STATUS_UNSUCCESSFUL;
    }

    /* test seek complete */
    if ((Buffer[0] & SR0_SEEK_COMPLETE) != SR0_SEEK_COMPLETE) {
	WARN_(FLOPPY, "HwRecalibrateResult: Failed to complete the seek\n");
	return STATUS_UNSUCCESSFUL;
    }

    /* Is the equipment check flag set?  Could be no disk in drive... */
    if ((Buffer[0] & SR0_EQUIPMENT_CHECK) == SR0_EQUIPMENT_CHECK) {
	WARN_(FLOPPY, "HwRecalibrateResult: Seeked to track 0 successfully, "
	      "but EC is set; returning failure\n");
	return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Get the result of a read or write from the controller
 * ARGUMENTS:
 *     ControllerInfo: controller to query
 * RETURNS:
 *     STATUS_SUCCESS if the read/write was a success
 *     Error status otherwise
 * NOTES:
 *     - This function tests the error conditions itself, and boils the
 *       whole thing down to a single SUCCESS or FAILURE result
 *     - Called post-interrupt; does not interrupt
 * TODO:
 *     - perhaps handle more status
 */
NTSTATUS HwReadWriteResult(PCONTROLLER_INFO ControllerInfo)
{
    PAGED_CODE();
    UCHAR Buffer[7];

    for (int i = 0; i < 7; i++) {
	NTSTATUS Status = GetByte(ControllerInfo, &Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwReadWriteResult: unable to read fifo. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    /* Validate  that it did what we told it to */
    INFO_(FLOPPY,
	  "HwReadWriteResult results: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
	  Buffer[0], Buffer[1], Buffer[2], Buffer[3], Buffer[4], Buffer[5],
	  Buffer[6]);

    /* Last command successful? */
    if ((Buffer[0] & SR0_LAST_COMMAND_STATUS) != SR0_LCS_SUCCESS)
	return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Start a recalibration of a drive
 * ARGUMENTS:
 *     DriveInfo: Drive to recalibrate
 * RETURNS:
 *     STATUS_SUCCESS if the command was successfully queued to the controller
 *     Error status otherwise
 * NOTES:
 *     - Generates an interrupt
 */
NTSTATUS HwRecalibrate(PDRIVE_INFO DriveInfo)
{
    PAGED_CODE();
    PCONTROLLER_INFO ControllerInfo = DriveInfo->ControllerInfo;
    UCHAR Unit = DriveInfo->UnitNumber;
    UCHAR Buffer[2];

    TRACE_(FLOPPY, "HwRecalibrate called\n");

    Buffer[0] = COMMAND_RECALIBRATE;
    Buffer[1] = Unit;

    for (int i = 0; i < 2; i++) {
	NTSTATUS Status = SendByte(ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwRecalibrate: unable to write FIFO. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Send a sense interrupt status command to a controller
 * ARGUMENTS:
 *     ControllerInfo: controller to queue the command to
 * RETURNS:
 *     STATUS_SUCCESS if the command is queued successfully
 *     Error status if not
 */
NTSTATUS HwSenseInterruptStatus(PCONTROLLER_INFO ControllerInfo)
{
    PAGED_CODE();
    UCHAR Buffer[2];

    NTSTATUS Status = SendByte(ControllerInfo, COMMAND_SENSE_INTERRUPT_STATUS);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY,
	      "HwSenseInterruptStatus: failed to write controller. Error = 0x%x\n",
	      Status);
	return Status;
    }

    for (int i = 0; i < 2; i++) {
	Status = GetByte(ControllerInfo, &Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "HwSenseInterruptStatus: failed to read controller. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    INFO_(FLOPPY, "HwSenseInterruptStatus returned 0x%x 0x%x\n", Buffer[0],
	  Buffer[1]);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Issue a read id command to the drive
 * ARGUMENTS:
 *     DriveInfo: Drive to read id from
 *     Head: Head to read the ID from
 * RETURNS:
 *     STATUS_SUCCESS if the command is queued
 *     Error status otherwise
 * NOTES:
 *     - Generates an interrupt
 */
NTSTATUS HwReadId(PDRIVE_INFO DriveInfo, UCHAR Head)
{
    PAGED_CODE();
    UCHAR Buffer[2];

    TRACE_(FLOPPY, "HwReadId called\n");

    Buffer[0] = COMMAND_READ_ID | READ_ID_MFM;
    Buffer[1] = (Head << COMMAND_HEAD_NUMBER_SHIFT) | DriveInfo->UnitNumber;

    for (int i = 0; i < 2; i++) {
	NTSTATUS Status = SendByte(DriveInfo->ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwReadId: unable to send bytes to fifo. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Format a track
 * ARGUMENTS:
 *     ControllerInfo: controller to target with the request
 *     Unit: drive to format on
 *     Head: head to format on
 *     BytesPerSector: constant from hardware.h to select density
 *     SectorsPerTrack: sectors per track
 *     Gap3Length: gap length to use during format
 *     FillerPattern: pattern to write into the data portion of sectors
 * RETURNS:
 *     STATUS_SUCCESS if the command is successfully queued
 *     Error status otherwise
 */
NTSTATUS HwFormatTrack(PCONTROLLER_INFO ControllerInfo,
		       UCHAR Unit,
		       UCHAR Head,
		       UCHAR BytesPerSector,
		       UCHAR SectorsPerTrack,
		       UCHAR Gap3Length,
		       UCHAR FillerPattern)
{
    PAGED_CODE();
    UCHAR Buffer[6];

    TRACE_(FLOPPY, "HwFormatTrack called\n");

    Buffer[0] = COMMAND_FORMAT_TRACK;
    Buffer[1] = (Head << COMMAND_HEAD_NUMBER_SHIFT) | Unit;
    Buffer[2] = BytesPerSector;
    Buffer[3] = SectorsPerTrack;
    Buffer[4] = Gap3Length;
    Buffer[5] = FillerPattern;

    for (int i = 0; i < 6; i++) {
	NTSTATUS Status = SendByte(ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "HwFormatTrack: unable to send bytes to floppy. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Seek the heads to a particular cylinder
 * ARGUMENTS:
 *     DriveInfo: Drive to seek
 *     Cylinder: cylinder to move to
 * RETURNS:
 *     STATUS_SUCCESS if the command is successfully sent
 *     Error status otherwise
 * NOTES:
 *     - Generates an interrupt
 */
NTSTATUS HwSeek(PDRIVE_INFO DriveInfo, UCHAR Cylinder)
{
    PAGED_CODE();
    LARGE_INTEGER Delay;
    UCHAR Buffer[3];

    TRACE_(FLOPPY, "HwSeek called for cyl 0x%x\n", Cylinder);

    Buffer[0] = COMMAND_SEEK;
    Buffer[1] = DriveInfo->UnitNumber;
    Buffer[2] = Cylinder;

    for (int i = 0; i < 3; i++) {
	NTSTATUS Status = SendByte(DriveInfo->ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwSeek: failed to write fifo. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    /* Wait for the head to settle */
    Delay.QuadPart = 10 * 1000;
    Delay.QuadPart *= DriveInfo->FloppyDeviceData.HeadSettleTime;
    Delay.QuadPart *= -1LL;

    KeDelayExecutionThread(FALSE, &Delay);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Sends configuration to the drive
 * ARGUMENTS:
 *     ControllerInfo: controller to target with the request
 *     EIS: Enable implied seek
 *     EFIFO: Enable advanced fifo
 *     POLL: Enable polling
 *     FIFOTHR: fifo threshold
 *     PRETRK: precomp (see intel datasheet)
 * RETURNS:
 *     STATUS_SUCCESS if the command is successfully sent
 *     Error status otherwise
 * NOTES:
 *     - No interrupt
 */
NTSTATUS HwConfigure(PCONTROLLER_INFO ControllerInfo,
		     BOOLEAN EIS,
		     BOOLEAN EFIFO,
		     BOOLEAN POLL,
		     UCHAR FIFOTHR,
		     UCHAR PRETRK)
{
    PAGED_CODE();
    UCHAR Buffer[4];

    TRACE_(FLOPPY, "HwConfigure called\n");

    Buffer[0] = COMMAND_CONFIGURE;
    Buffer[1] = 0;
    Buffer[2] = EIS * CONFIGURE_EIS + (!EFIFO) * CONFIGURE_EFIFO +
	(!POLL) * CONFIGURE_POLL + FIFOTHR;
    Buffer[3] = PRETRK;

    for (int i = 0; i < 4; i++) {
	NTSTATUS Status = SendByte(ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwConfigure: failed to write the fifo. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Gets the version of the controller
 * ARGUMENTS:
 *     ControllerInfo: controller to target with the request
 * RETURNS:
 *     Version number returned by the command, or on failure
 * NOTE:
 *     - This command doesn't interrupt, so we go right to reading after
 *       we issue the command
 */
UCHAR HwGetVersion(PCONTROLLER_INFO ControllerInfo)
{
    PAGED_CODE();
    UCHAR Buffer;

    NTSTATUS Status = SendByte(ControllerInfo, COMMAND_VERSION);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "HwGetVersion: unable to write fifo. Error = 0x%x\n",
	      Status);
	return 0;
    }

    Status = GetByte(ControllerInfo, &Buffer);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "HwGetVersion: unable to write fifo. Error = 0x%x\n",
	      Status);
	return 0;
    }

    INFO_(FLOPPY, "HwGetVersion returning version 0x%x\n", Buffer);

    return Buffer;
}

/*
 * FUNCTION: Detect whether the hardware has sensed a disk change
 * ARGUMENTS:
 *     DriveInfo: pointer to the drive that we are to check
 *     DiskChanged: boolean that is set with whether or not the controller thinks there has been a disk change
 * RETURNS:
 *     STATUS_SUCCESS if the drive is successfully queried
 * NOTES:
 *     - Does not interrupt.
 *     - Guessing a bit at the Model30 stuff
 */
NTSTATUS HwDiskChanged(PDRIVE_INFO DriveInfo,
		       PBOOLEAN DiskChanged)
{
    PCONTROLLER_INFO ControllerInfo = DriveInfo->ControllerInfo;

    UCHAR Buffer = READ_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_INPUT_REGISTER);

    TRACE_(FLOPPY, "HwDiskChanged: read 0x%x from DIR\n", Buffer);

    if (ControllerInfo->Model30) {
	if (!(Buffer & DIR_DISKETTE_CHANGE)) {
	    INFO_(FLOPPY, "HwDiskChanged - Model30 - returning TRUE\n");
	    *DiskChanged = TRUE;
	} else {
	    INFO_(FLOPPY, "HwDiskChanged - Model30 - returning FALSE\n");
	    *DiskChanged = FALSE;
	}
    } else {
	if (Buffer & DIR_DISKETTE_CHANGE) {
	    INFO_(FLOPPY, "HwDiskChanged - PS2 - returning TRUE\n");
	    *DiskChanged = TRUE;
	} else {
	    INFO_(FLOPPY, "HwDiskChanged - PS2 - returning FALSE\n");
	    *DiskChanged = FALSE;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Get the result of a sense drive status command
 * ARGUMENTS:
 *     ControllerInfo: controller to query
 *     DriveStatus: Status from the drive sense command
 * RETURNS:
 *     STATUS_SUCCESS if we can successfully read the status
 *     Error status otherwise
 * NOTES:
 *     - Called post-interrupt; does not interrupt
 */
NTSTATUS HwSenseDriveStatusResult(PCONTROLLER_INFO ControllerInfo,
				  PUCHAR DriveStatus)
{
    PAGED_CODE();
    NTSTATUS Status = GetByte(ControllerInfo, DriveStatus);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "HwSenseDriveStatus: unable to read fifo. Error = 0x%x\n",
	      Status);
	return Status;
    }

    TRACE_(FLOPPY, "HwSenseDriveStatusResult: ST3: 0x%x\n", *DriveStatus);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Get the result of a read id command
 * ARGUMENTS:
 *     ControllerInfo: controller to query
 *     CurCylinder: Returns the cylinder that we're at
 *     CurHead: Returns the head that we're at
 * RETURNS:
 *     STATUS_SUCCESS if the read id was a success
 *     Error status otherwise
 * NOTES:
 *     - This function tests the error conditions itself, and boils the
 *       whole thing down to a single SUCCESS or FAILURE result
 *     - Called post-interrupt; does not interrupt
 * TODO
 *     - perhaps handle more status
 */
NTSTATUS HwReadIdResult(PCONTROLLER_INFO ControllerInfo,
			PUCHAR CurCylinder,
			PUCHAR CurHead)
{
    PAGED_CODE();
    UCHAR Buffer[7] = { 0, 0, 0, 0, 0, 0, 0 };

    for (int i = 0; i < 7; i++) {
	NTSTATUS Status = GetByte(ControllerInfo, &Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "ReadIdResult(): can't read from the controller. Error = 0x%x\n",
		  Status);
	    return Status;
	}
    }

    /* Validate  that it did what we told it to */
    INFO_(FLOPPY, "ReadId results: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
	  Buffer[0], Buffer[1], Buffer[2], Buffer[3], Buffer[4], Buffer[5],
	  Buffer[6]);

    /* Last command successful? */
    if ((Buffer[0] & SR0_LAST_COMMAND_STATUS) != SR0_LCS_SUCCESS) {
	WARN_(FLOPPY, "ReadId didn't return last command success\n");
	return STATUS_UNSUCCESSFUL;
    }

    /* ID mark found? */
    if (Buffer[1] & SR1_CANNOT_FIND_ID_ADDRESS) {
	WARN_(FLOPPY, "ReadId didn't find an address mark\n");
	return STATUS_UNSUCCESSFUL;
    }

    if (CurCylinder)
	*CurCylinder = Buffer[3];

    if (CurHead)
	*CurHead = Buffer[4];

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Set up timing and DMA mode for the controller
 * ARGUMENTS:
 *     ControllerInfo: Controller to set up
 *     HeadLoadTime: Head load time (see data sheet for details)
 *     HeadUnloadTime: Head unload time
 *     StepRateTime: Step rate time
 *     NonDma: TRUE to disable DMA mode
 * RETURNS:
 *     STATUS_SUCCESS if the controller is successfully programmed
 *     Error status if not
 * NOTES:
 *     - Does not interrupt
 *
 * TODO: Figure out timings
 */
NTSTATUS HwSpecify(PCONTROLLER_INFO ControllerInfo,
		   UCHAR HeadLoadTime,
		   UCHAR HeadUnloadTime,
		   UCHAR StepRateTime,
		   BOOLEAN NonDma)
{
    UCHAR Buffer[3];
    assert(HeadLoadTime < 0x80);
    assert(HeadUnloadTime < 0x10);
    assert(StepRateTime < 0x10);

    Buffer[0] = COMMAND_SPECIFY;
    Buffer[1] = (StepRateTime << 4) | HeadUnloadTime;
    Buffer[2] = (HeadLoadTime << 1) | (NonDma ? 1 : 0);

    INFO_(FLOPPY, "HwSpecify: sending 0x%x 0x%x 0x%x to FIFO\n", Buffer[0], Buffer[1], Buffer[2]);

    for (int i = 0; i < 3; i++) {
	NTSTATUS Status = SendByte(ControllerInfo, Buffer[i]);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "HwSpecify: unable to write to controller\n");
	    return Status;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Reset the controller
 * ARGUMENTS:
 *     ControllerInfo: controller to reset
 * RETURNS:
 *     STATUS_SUCCESS in all cases
 * NOTES:
 *     - Generates an interrupt that must be serviced four times (one per drive)
 */
NTSTATUS HwReset(PCONTROLLER_INFO ControllerInfo)
{
    TRACE_(FLOPPY, "HwReset called\n");

    /* Write the reset bit in the DRSR */
    WRITE_PORT_UCHAR(ControllerInfo->BaseAddress + DATA_RATE_SELECT_REGISTER,
		     DRSR_SW_RESET);

    /* Check for the reset bit in the DOR and set it if necessary (see Intel doc) */
    if (!(READ_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_OUTPUT_REGISTER) & DOR_RESET)) {
	HwDumpRegisters(ControllerInfo);
	INFO_(FLOPPY, "HwReset: Setting Enable bit\n");
	WRITE_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_OUTPUT_REGISTER,
			 DOR_DMA_IO_INTERFACE_ENABLE | DOR_RESET);
	HwDumpRegisters(ControllerInfo);

	if (!(READ_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_OUTPUT_REGISTER) & DOR_RESET)) {
	    WARN_(FLOPPY, "HwReset: failed to set the DOR enable bit!\n");
	    HwDumpRegisters(ControllerInfo);
	    return STATUS_UNSUCCESSFUL;
	}
    }

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Power down a controller
 * ARGUMENTS:
 *     ControllerInfo: Controller to power down
 * RETURNS:
 *     STATUS_SUCCESS
 * NOTES:
 *     - Wake up with a hardware reset
 */
NTSTATUS HwPowerOff(PCONTROLLER_INFO ControllerInfo)
{
    TRACE_(FLOPPY, "HwPowerOff called on controller %p\n",
	   ControllerInfo);

    WRITE_PORT_UCHAR(ControllerInfo->BaseAddress + DATA_RATE_SELECT_REGISTER,
		     DRSR_POWER_DOWN);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Dump all readable registers from the floppy controller
 * ARGUMENTS:
 *     ControllerInfo: Controller to dump registers from
 */
VOID HwDumpRegisters(PCONTROLLER_INFO ControllerInfo)
{
    UNREFERENCED_PARAMETER(ControllerInfo);

    INFO_(FLOPPY, "Status registers:\n");
    INFO_(FLOPPY, "STATUS_REGISTER_A = 0x%x\n",
	  READ_PORT_UCHAR(ControllerInfo->BaseAddress + STATUS_REGISTER_A));
    INFO_(FLOPPY, "STATUS_REGISTER_B = 0x%x\n",
	  READ_PORT_UCHAR(ControllerInfo->BaseAddress + STATUS_REGISTER_B));
    INFO_(FLOPPY, "DIGITAL_OUTPUT_REGISTER = 0x%x\n",
	  READ_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_OUTPUT_REGISTER));
    INFO_(FLOPPY, "MAIN_STATUS_REGISTER = 0x%x\n",
	  READ_PORT_UCHAR(ControllerInfo->BaseAddress + MAIN_STATUS_REGISTER));
    INFO_(FLOPPY, "DIGITAL_INPUT_REGISTER = 0x%x\n",
	  READ_PORT_UCHAR(ControllerInfo->BaseAddress + DIGITAL_INPUT_REGISTER));
}
