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
 * FILE:            readwrite.c
 * PURPOSE:         Read/Write handler routines
 * PROGRAMMER:      Vizzini (vizzini@plasmic.com)
 * REVISIONS:
 *                  15-Feb-2004 vizzini - Created
 * NOTES:
 *
 * READ/WRITE PROCESS
 *
 * This process is extracted from the Intel datasheet for the floppy controller.
 *
 * - Turn on the motor and set turnoff time
 * - Program the drive's data rate
 * - Seek
 * - Read ID
 * - Set up DMA
 * - Send read/write command to FDC
 * - Read result bytes
 *
 * This is mostly implemented in one big function, which waits on the SynchEvent as many
 * times as necessary to get through the process.  See ReadWritePassive() for more details.
 *
 * NOTES:
 *     - Currently doesn't support partial-sector transfers, which is really just a failing
 *       of RWComputeCHS.  I've never seen Windows send a partial-sector request, though, so
 *       this may not be a bad thing.  Should be looked into, regardless.
 *
 * TODO: Break up ReadWritePassive and handle errors better
 * TODO: Figure out data rate issues
 * TODO: Media type detection
 * TODO: Figure out perf issue - waiting after call to read/write for about a second each time
 * TODO: Figure out specify timings
 */

#include "fdc.h"

#define ALIGNED_BY(p, align)	((ULONG_PTR)(p) == ALIGN_DOWN_BY(p, align))

/*
 * FUNCTION: Acquire map registers in prep for DMA
 * ARGUMENTS:
 *     DeviceObject: unused
 *     Irp: unused
 *     MapRegisterBase: returned to blocked thread via a member var
 *     Context: contains a pointer to the right ControllerInfo struct
 * RETURNS:
 *     KeepObject, because that's what the DDK says to do
 */
static NTAPI IO_ALLOCATION_ACTION MapRegisterCallback(PDEVICE_OBJECT DeviceObject,
						      PIRP Irp,
						      PVOID MapRegisterBase,
						      PVOID Context)
{
    PCONTROLLER_INFO ControllerInfo = (PCONTROLLER_INFO)Context;
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    TRACE_(FLOPPY, "MapRegisterCallback Called\n");

    ControllerInfo->MapRegisterBase = MapRegisterBase;
    KeSetEvent(&ControllerInfo->SynchEvent);

    return KeepObject;
}

/*
 * FUNCTION: Determine the media type of the disk in the drive and fill in the geometry
 * ARGUMENTS:
 *     DriveInfo: drive to look at
 * RETURNS:
 *     STATUS_SUCCESS if the media was recognized and the geometry struct was filled in
 *     STATUS_UNRECOGNIZED_MEDIA if not
 *     STATUS_UNSUCCESSFUL if the controller can't be talked to
 * NOTES:
 *     - Expects the motor to already be running
 *     - Currently only supports 1.44MB 3.5" disks
 * TODO:
 *     - Support more disk types
 */
NTSTATUS RWDetermineMediaType(PDRIVE_INFO DriveInfo, BOOLEAN OneShot)
{
    UCHAR HeadLoadTime;
    UCHAR HeadUnloadTime;
    UCHAR StepRateTime;
    LARGE_INTEGER Timeout;

    TRACE_(FLOPPY, "RWDetermineMediaType called\n");

    /*
     * This algorithm assumes that a 1.44MB floppy is in the drive.  If it's not,
     * it works backwards until the read works unless OneShot try is asked.
     * Note that only 1.44 has been tested at all.
     */

    Timeout.QuadPart = -10000000;	/* 1 second. Is that enough? */

    do {
	/* Program data rate */
	if (HwSetDataRate(DriveInfo->ControllerInfo, DRSR_DSEL_500KBPS) !=
	    STATUS_SUCCESS) {
	    WARN_(FLOPPY,
		  "RWDetermineMediaType(): unable to set data rate\n");
	    return STATUS_UNSUCCESSFUL;
	}

	/* Specify */
	HeadLoadTime = SPECIFY_HLT_500K;
	HeadUnloadTime = SPECIFY_HUT_500K;
	StepRateTime = SPECIFY_SRT_500K;

	/* Don't disable DMA --> enable dma (dumb & confusing) */
	if (HwSpecify(DriveInfo->ControllerInfo, HeadLoadTime, HeadUnloadTime,
		      StepRateTime, FALSE) != STATUS_SUCCESS) {
	    WARN_(FLOPPY, "RWDetermineMediaType(): specify failed\n");
	    return STATUS_UNSUCCESSFUL;
	}

	/* clear any spurious interrupts in preparation for recalibrate */
	KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

	/* Recalibrate --> head over first track */
	for (int i = 0; i < 2; i++) {
	    NTSTATUS RecalStatus;

	    if (HwRecalibrate(DriveInfo) != STATUS_SUCCESS) {
		WARN_(FLOPPY,
		      "RWDetermineMediaType(): Recalibrate failed\n");
		return STATUS_UNSUCCESSFUL;
	    }

	    /* Wait for the recalibrate to finish */
	    WaitForControllerInterrupt(DriveInfo->ControllerInfo, NULL);

	    RecalStatus = HwRecalibrateResult(DriveInfo->ControllerInfo);

	    if (RecalStatus == STATUS_SUCCESS)
		break;

	    if (i == 1) {	/* failed for 2nd time */
		WARN_(FLOPPY,
		      "RWDetermineMediaType(): RecalibrateResult failed\n");
		return STATUS_UNSUCCESSFUL;
	    }
	}

	/* clear any spurious interrupts */
	KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

	/* Try to read an ID. Read the first ID we find, from head 0. */
	if (HwReadId(DriveInfo, 0) != STATUS_SUCCESS) {
	    WARN_(FLOPPY, "RWDetermineMediaType(): ReadId failed\n");
	    /* if we can't even write to the controller, it's hopeless */
	    return STATUS_UNSUCCESSFUL;
	}

	/* Wait for the ReadID to finish */
	NTSTATUS Status = WaitForControllerInterrupt(DriveInfo->ControllerInfo,
						     &Timeout);

	if (Status == STATUS_TIMEOUT ||
	    HwReadIdResult(DriveInfo->ControllerInfo, NULL, NULL) != STATUS_SUCCESS) {
	    WARN_(FLOPPY, "RWDetermineMediaType(): ReadIdResult failed\n");
	    if (OneShot) {
		break;
	    } else {
		continue;
	    }
	}

	/* Found the media; populate the geometry now */
	WARN_(FLOPPY, "Hardcoded media type!\n");
	INFO_(FLOPPY,
	      "RWDetermineMediaType(): Found 1.44 media; returning success\n");
	DriveInfo->DiskGeometry.MediaType = GEOMETRY_144_MEDIATYPE;
	DriveInfo->DiskGeometry.Cylinders.QuadPart = GEOMETRY_144_CYLINDERS;
	DriveInfo->DiskGeometry.TracksPerCylinder = GEOMETRY_144_TRACKSPERCYLINDER;
	DriveInfo->DiskGeometry.SectorsPerTrack = GEOMETRY_144_SECTORSPERTRACK;
	DriveInfo->DiskGeometry.BytesPerSector = GEOMETRY_144_BYTESPERSECTOR;
	DriveInfo->BytesPerSectorCode = HW_512_BYTES_PER_SECTOR;
	return STATUS_SUCCESS;
    } while (TRUE);

    TRACE_(FLOPPY, "RWDetermineMediaType(): failed to find media\n");
    return STATUS_UNRECOGNIZED_MEDIA;
}

/*
 * FUNCTION: Seek a particular drive to a particular track
 * ARGUMENTS:
 *     DriveInfo: Drive to seek
 *     Cylinder: track to seek to
 * RETURNS:
 *     STATUS_SUCCESS if the head was successfully seeked
 *     STATUS_UNSUCCESSFUL if not
 */
static NTSTATUS RWSeekToCylinder(PDRIVE_INFO DriveInfo, UCHAR Cylinder)
{
    UCHAR CurCylinder;

    TRACE_(FLOPPY, "RWSeekToCylinder called drive 0x%p cylinder %d\n",
	   DriveInfo, Cylinder);

    /* Clear any spurious interrupts */
    KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

    /* queue seek command */
    if (HwSeek(DriveInfo, Cylinder) != STATUS_SUCCESS) {
	WARN_(FLOPPY, "RWSeekToTrack(): unable to seek\n");
	return STATUS_UNSUCCESSFUL;
    }

    WaitForControllerInterrupt(DriveInfo->ControllerInfo, NULL);

    if (HwSenseInterruptStatus(DriveInfo->ControllerInfo) !=
	STATUS_SUCCESS) {
	WARN_(FLOPPY, "RWSeekToTrack(): unable to get seek results\n");
	return STATUS_UNSUCCESSFUL;
    }

    /* read ID mark from head 0 to verify */
    if (HwReadId(DriveInfo, 0) != STATUS_SUCCESS) {
	WARN_(FLOPPY, "RWSeekToTrack(): unable to queue ReadId\n");
	return STATUS_UNSUCCESSFUL;
    }

    WaitForControllerInterrupt(DriveInfo->ControllerInfo, NULL);

    if (HwReadIdResult(DriveInfo->ControllerInfo, &CurCylinder, NULL) !=
	STATUS_SUCCESS) {
	WARN_(FLOPPY, "RWSeekToTrack(): unable to get ReadId result\n");
	return STATUS_UNSUCCESSFUL;
    }

    if (CurCylinder != Cylinder) {
	WARN_(FLOPPY,
	      "RWSeekToTrack(): Seek to track failed; current cylinder is 0x%x\n",
	      CurCylinder);
	return STATUS_UNSUCCESSFUL;
    }

    INFO_(FLOPPY,
	  "RWSeekToCylinder: returning successfully, now on cyl %d\n",
	  Cylinder);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Compute the CHS from the absolute byte offset on disk
 * ARGUMENTS:
 *     DriveInfo: Drive to compute on
 *     DiskByteOffset: Absolute offset on disk of the starting byte
 *     Cylinder: Cylinder that the byte is on
 *     Head: Head that the byte is on
 *     Sector: Sector that the byte is on
 * RETURNS:
 *     STATUS_SUCCESS if CHS are determined correctly
 *     STATUS_UNSUCCESSFUL otherwise
 * NOTES:
 *     - Lots of ugly typecasts here
 *     - Sectors are 1-based!
 *     - This is really crummy code.  Please FIXME.
 */
static NTSTATUS RWComputeCHS(IN PDRIVE_INFO DriveInfo,
			     IN ULONG DiskByteOffset,
			     OUT PUCHAR Cylinder,
			     OUT PUCHAR Head,
			     OUT PUCHAR Sector)
{
    ULONG AbsoluteSector;
    UCHAR SectorsPerCylinder =
	(UCHAR) DriveInfo->DiskGeometry.SectorsPerTrack *
	(UCHAR) DriveInfo->DiskGeometry.TracksPerCylinder;

    TRACE_(FLOPPY, "RWComputeCHS: Called with offset 0x%x\n",
	   DiskByteOffset);

    /* First calculate the 1-based "absolute sector" based on the byte offset */
    /* FIXME: Only handle full sector transfers atm */
    ASSERT(!(DiskByteOffset % DriveInfo->DiskGeometry.BytesPerSector));

    /* Num of full sectors. AbsoluteSector is zero-based to make the
     * math a little easier */
    AbsoluteSector = DiskByteOffset / DriveInfo->DiskGeometry.BytesPerSector;

    /* Cylinder number is floor(AbsoluteSector / SectorsPerCylinder) */
    *Cylinder = (CHAR)(AbsoluteSector / SectorsPerCylinder);

    /* Head number is 0 if the sector within the cylinder < SectorsPerTrack; 1 otherwise */
    if ((AbsoluteSector % SectorsPerCylinder) < DriveInfo->DiskGeometry.SectorsPerTrack) {
	*Head = 0;
    } else {
	*Head = 1;
    }

    /* Sector number is the sector within the cylinder if on head 0;
     * that minus SectorsPerTrack if it's on head 1
     * (lots of casts to placate msvc).  1-based! */
    *Sector = (UCHAR)(AbsoluteSector % SectorsPerCylinder) + 1 -
	*Head * (UCHAR)DriveInfo->DiskGeometry.SectorsPerTrack;

    INFO_(FLOPPY, "RWComputeCHS: offset 0x%x is c:0x%x h:0x%x s:0x%x\n",
	  DiskByteOffset, *Cylinder, *Head, *Sector);

    /* Sanity checking */
    ASSERT(*Cylinder <= DriveInfo->DiskGeometry.Cylinders.QuadPart);
    ASSERT(*Head <= DriveInfo->DiskGeometry.TracksPerCylinder);
    ASSERT(*Sector <= DriveInfo->DiskGeometry.SectorsPerTrack);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Process an IRP when the media has changed, and possibly notify the user
 * ARGUMENTS:
 *     DeviceObject: DeviceObject associated with the IRP
 *     Irp: IRP that we're failing due to change
 * NOTES:
 *     - This procedure is documented in the DDK by "Notifying the File System of
 *       Possible Media Changes", and by "Responding to Check-Verify Requests from
 *       the File System".
 *     - Callable at <= DISPATCH_LEVEL
 */
NTSTATUS SignalMediaChanged(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PPDO_DEVICE_EXTENSION DevExt = DeviceObject->DeviceExtension;
    PDRIVE_INFO DriveInfo = DevExt->DriveInfo;

    TRACE_(FLOPPY, "SignalMediaChanged called\n");

    DriveInfo->DiskChangeCount++;

    /* Remind ourselves that we need to return STATUS_VERIFY_REQUIRED for
     * all future IRPs until device is verified again. */
    DriveInfo->DeviceObject->Flags |= DO_VERIFY_VOLUME;
    NTSTATUS Status = STATUS_MEDIA_CHANGED;
    Irp->IoStatus.Status = Status;

    return Status;
}

/*
 * FUNCTION: Reset the drive's change flag (as reflected in the DIR)
 * ARGUMENTS:
 *     DriveInfo: the drive to reset
 * RETURNS:
 *     STATUS_SUCCESS if the changeline is cleared
 *     STATUS_NO_MEDIA_IN_DEVICE if the changeline cannot be cleared
 *     STATUS_IO_DEVICE_ERROR if the controller cannot be communicated with
 * NOTES:
 *     - Change reset procedure: recalibrate, seek 1, seek 0
 *     - If the line is still set after that, there's clearly no disk in the
 *       drive, so we return STATUS_NO_MEDIA_IN_DEVICE
 */
NTSTATUS ResetChangeFlag(PDRIVE_INFO DriveInfo)
{
    BOOLEAN DiskChanged;

    ASSERT(DriveInfo);

    TRACE_(FLOPPY, "ResetChangeFlag called\n");

    /* Try to recalibrate.  We don't care if it works. */
    Recalibrate(DriveInfo);

    /* clear spurious interrupts in prep for seeks */
    KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

    /* must re-start the drive because Recalibrate() stops it */
    StartMotor(DriveInfo);

    /* Seek to 1 */
    NTSTATUS Status = HwSeek(DriveInfo, 1);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "ResetChangeFlag(): HwSeek failed with error 0x%x; "
	      "returning STATUS_IO_DEVICE_ERROR\n", Status);
	goto err;
    }

    WaitForControllerInterrupt(DriveInfo->ControllerInfo, NULL);

    Status = HwSenseInterruptStatus(DriveInfo->ControllerInfo);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY,
	      "ResetChangeFlag(): HwSenseInterruptStatus failed with error 0x%x\n",
	      Status);
	goto err;
    }

    /* Seek back to 0 */
    Status = HwSeek(DriveInfo, 0);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "ResetChangeFlag(): HwSeek failed with error 0x%x; "
	      "returning STATUS_IO_DEVICE_ERROR\n", Status);
	goto err;
    }

    WaitForControllerInterrupt(DriveInfo->ControllerInfo, NULL);

    Status = HwSenseInterruptStatus(DriveInfo->ControllerInfo);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY,
	      "ResetChangeFlag(): HwSenseInterruptStatus #2 failed with error 0x%x\n",
	      Status);
	goto err;
    }

    /* Check the change bit */
    Status = HwDiskChanged(DriveInfo, &DiskChanged);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "ResetChangeFlag(): HwDiskChanged failed with error 0x%x; "
	      "returning STATUS_IO_DEVICE_ERROR\n", Status);
	goto err;
    }

    /* If the change flag is still set, there's probably no media in the drive. */
    Status = DiskChanged ? STATUS_NO_MEDIA_IN_DEVICE : STATUS_SUCCESS;
    goto out;

err:
    Status = STATUS_IO_DEVICE_ERROR;

out:
    StopMotor(DriveInfo->ControllerInfo);

    return Status;
}

/*
 * FUNCTION: Handle a read or write IRP
 * ARGUMENTS:
 *     DeviceObject: DeviceObject that is the target of the IRP
 *     Irp: IRP to process
 * RETURNS:
 *     STATUS_MEDIA_CHANGED if we detected a media change. STATUS_NO_MEDIA_IN_DEVICE
 *     if there is no media in the device. STATUS_VERIFY_REQUIRED if the media has
 *     changed and we haven't verified the new disk. Otherwise return STATUS_SUCCESS
 *     if IO succeeded and the relevant error status if not.
 *
 * DETAILS:
 *  This routine manages the whole process of servicing a read or write request.
 *  It goes like this:
 *    1) Check the DO_VERIFY_VOLUME flag and return if it's set
 *    2) Check the disk change line and notify the OS if it's set and return
 *    3) Detect the media if we haven't already
 *    4) Set up DiskByteOffset, Length, and WriteToDevice parameters
 *    5) Get DMA map registers
 *    6) Then, in a loop for each track, until all bytes are transferred:
 *      a) Compute the current CHS to set the read/write head to
 *      b) Seek to that spot
 *      c) Compute the last sector to transfer on that track
 *      d) Map the transfer through DMA
 *      e) Send the read or write command to the controller
 *      f) Read the results of the command
 */
VOID ReadWrite(PDRIVE_INFO DriveInfo, PIRP Irp)
{
    PDEVICE_OBJECT DeviceObject = DriveInfo->DeviceObject;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    BOOLEAN WriteToDevice;
    ULONG DiskByteOffset;
    BOOLEAN DiskChanged;
    ULONG_PTR TransferByteOffset;
    UCHAR Gap;

    TRACE_(FLOPPY,
	   "ReadWrite called to %s 0x%x bytes from offset 0x%x\n",
	   (Stack->MajorFunction == IRP_MJ_READ ? "read" : "write"),
	   (Stack->MajorFunction == IRP_MJ_READ ?
	    Stack->Parameters.Read.Length : Stack->Parameters.Write.Length),
	   (Stack->MajorFunction == IRP_MJ_READ ?
	    Stack->Parameters.Read.ByteOffset.LowPart : Stack->Parameters.Write.ByteOffset.LowPart));

    /* Default return codes */
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG Length = 0;

    /*
     * Check to see if the volume needs to be verified.  If so,
     * we can get out of here quickly.
     */
    if (DeviceObject->Flags & DO_VERIFY_VOLUME &&
	!(Stack->Flags & SL_OVERRIDE_VERIFY_VOLUME)) {
	INFO_(FLOPPY, "ReadWrite(): DO_VERIFY_VOLUME set; "
	      "Completing with STATUS_VERIFY_REQUIRED\n");
	Status = STATUS_VERIFY_REQUIRED;
	goto out;
    }

    /*
     * Check the change line, and if it's set, return
     */
    StartMotor(DriveInfo);
    Status = HwDiskChanged(DriveInfo, &DiskChanged);
    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY, "ReadWrite(): unable to detect disk change, "
	      "error = 0x%x\n", Status);
	goto stop;
    }

    if (DiskChanged) {
	Status = SignalMediaChanged(DeviceObject, Irp);

	if (ResetChangeFlag(DriveInfo) == STATUS_NO_MEDIA_IN_DEVICE)
	    Status = STATUS_NO_MEDIA_IN_DEVICE;

	INFO_(FLOPPY, "ReadWrite(): signalling media changed; "
	      "Completing with status 0x%x\n", Status);

	goto stop;
    }

    /*
     * Figure out the media type, if we don't know it already
     */
    if (DriveInfo->DiskGeometry.MediaType == Unknown) {
	Status = RWDetermineMediaType(DriveInfo, FALSE);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "ReadWrite(): unable to determine media type, "
		  "error = 0x%x\n", Status);
	    goto stop;
	}

	if (DriveInfo->DiskGeometry.MediaType == Unknown) {
	    WARN_(FLOPPY, "ReadWrite(): Unknown media in drive; "
		  "completing with STATUS_UNRECOGNIZED_MEDIA\n");
	    Status = STATUS_UNRECOGNIZED_MEDIA;
	    goto stop;
	}
    }

    /* Set up parameters for read or write */
    if (Stack->MajorFunction == IRP_MJ_READ) {
	Length = Stack->Parameters.Read.Length;
	DiskByteOffset = Stack->Parameters.Read.ByteOffset.u.LowPart;
	WriteToDevice = FALSE;
    } else {
	Length = Stack->Parameters.Write.Length;
	DiskByteOffset = Stack->Parameters.Write.ByteOffset.u.LowPart;
	WriteToDevice = TRUE;
    }

    /* We can only read or write whole sectors, so reject the read/write if
     * Length is not a multiple of the sector size. */
    assert(DriveInfo->DiskGeometry.BytesPerSector != 0);
    if (!Length || !ALIGNED_BY(Length, DriveInfo->DiskGeometry.BytesPerSector)) {
	Status = STATUS_INVALID_BUFFER_SIZE;
	goto stop;
    }

    /*
     * FIXME:
     *   FloppyDeviceData.ReadWriteGapLength specify the value for the physical drive.
     *   We should set this value depend on the format of the inserted disk and possible
     *   depend on the request (read or write). A value of 0 results in one rotation
     *   between the sectors (7.2sec for reading a track).
     */
    Gap = DriveInfo->FloppyDeviceData.ReadWriteGapLength;

    /*
     * Set up DMA transfer
     *
     * NOTE: These are from the original ReactOS code and are still largely correct
     * in Neptune OS, so we will leave them here as a reference. ENDNOTE.
     *
     * This is as good of a place as any to document something that used to confuse me
     * greatly (and I even wrote some of the kernel's DMA code, so if it confuses me,
     * it probably confuses at least a couple of other people too).
     *
     * MmGetMdlVirtualAddress() returns the virtual address, as mapped in the buffer's
     * original process context, of the MDL.  In other words:  say you start with a
     * buffer at address X, then you build an MDL out of that buffer called Mdl. If you
     * call MmGetMdlVirtualAddress(Mdl), it will return X.
     *
     * There are two parameters that the function looks at to produce X again, given
     * the MDL: the first is the StartVa, which is the base virtual address of the page
     * that the buffer starts in.  If your buffer's virtual address is 0x12345678,
     * StartVa will be 0x12345000, assuming 4K pages (which is (almost) always the case
     * on x86).  Note well: this address is only valid in the process context that you
     * initially built the MDL from.  The physical pages that make up the MDL might
     * perhaps be mapped in other process contexts too (or even in the system space,
     * above 0x80000000 (default; 0xc0000000 on current ReactOS or /3GB Windows)), but
     * it will (possibly) be mapped at a different address.
     *
     * The second parameter is the ByteOffset.  Given an original buffer address of
     * 0x12345678, the ByteOffset would be 0x678.  Because MDLs can only describe full
     * pages (and therefore StartVa always points to the start address of a page), the
     * ByteOffset must be used to find the real start of the buffer.
     *
     * In general, if you add the StartVa and ByteOffset together, you get back your
     * original buffer pointer, which you are free to use if you're sure you're in the
     * right process context. You could tell by accessing the (hidden and not-to-be-used)
     * Process member of the MDL, but in general, if you have to ask whether or not you
     * are in the right context, then you shouldn't be using this address for anything
     * anyway.  There are also security implications (big ones, really, I wouldn't kid
     * about this) to directly accessing a user's buffer by VA, so Don't Do That.
     * (NOTE: On Neptune OS the Process member simply doesn't exist. See below.)
     *
     * There is a somewhat weird but very common use of the virtual address associated
     * with a MDL that pops up often in the context of DMA.  DMA APIs (particularly
     * MapTransfer()) need to know where the memory is that they should DMA into and out
     * of.  This memory is described by a MDL.  The controller eventually needs to know
     * a physical address on the host side, which is generally a 32-bit linear address
     * (on x86), and not just a page address.  Therefore, the DMA APIs look at the
     * ByteOffset field of the MDL to reconstruct the real address that should be
     * programmed into the DMA controller.
     *
     * It is often the case that a transfer needs to be broken down over more than one
     * DMA operation, particularly when it is a big transfer and the HAL doesn't give
     * you enough map registers to map the whole thing at once.  Therefore, the APIs
     * need a way to tell how far into the MDL they should look to transfer the next
     * chunk of bytes.  Now, Microsoft could have designed MapTransfer to take a "MDL
     * offset" argument, starting with 0, for how far into the buffer to start, but it
     * didn't.  Instead, MapTransfer asks for the virtual address of the MDL as an
     * "index" into the MDL.  The way it computes how far into the page to start the
     * transfer is by masking off all but the bottom 12 bits (on x86) of the number you
     * supply as the CurrentVa and using *that* as the ByteOffset instead of the one
     * in the MDL.  (OK, this varies a bit by OS and version, but this is the effect).
     *
     * In other words, you get a number back from MmGetMdlVirtualAddress that represents
     * the start of your buffer, and you pass it to the first MapTransfer call.  Then,
     * for each successive operation on the same buffer, you increment that address to
     * point to the next spot in the MDL that you want to DMA to/from.  The fact that
     * the virtual address you're manipulating is probably not mapped into the process
     * context that you're running in is irrelevant, since it's only being used to
     * index into the MDL.
     *
     * Note: On Neptune OS MmGetMdlVirtualAddress() always returns NULL and the MDL
     * doesn't have the Process member (you aren't supposed to access it anyway).
     */

    /* Get map registers for DMA */
    Status = IoAllocateAdapterChannel(DriveInfo->ControllerInfo->AdapterObject,
				      DeviceObject,
				      DriveInfo->ControllerInfo->MapRegisters,
				      MapRegisterCallback,
				      DriveInfo->ControllerInfo);

    if (!NT_SUCCESS(Status)) {
	WARN_(FLOPPY,
	      "ReadWrite(): unable allocate an adapter channel, error = 0x%x\n",
	      Status);
	goto stop;
    }

    /*
     * Read from (or write to) the device
     *
     * This has to be called in a loop, as you can only transfer data to/from a
     * single track at a time.
     */
    TransferByteOffset = 0;
    while (TransferByteOffset < Length) {
	UCHAR Cylinder;
	UCHAR Head;
	UCHAR StartSector;
	ULONG CurrentTransferBytes;
	UCHAR CurrentTransferSectors;

	INFO_(FLOPPY,
	      "ReadWrite(): iterating in while (TransferByteOffset = 0x%zx of 0x%x total) - allocating %d registers\n",
	      TransferByteOffset, Length, DriveInfo->ControllerInfo->MapRegisters);

	KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

	/*
	 * Compute starting CHS
	 */
	Status = RWComputeCHS(DriveInfo, DiskByteOffset + TransferByteOffset,
			      &Cylinder, &Head, &StartSector);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "ReadWrite(): unable to compute CHS; error = 0x%x\n", Status);
	    goto free;
	}

	/*
	 * Seek to the right track
	 */
	if (!DriveInfo->ControllerInfo->ImpliedSeeks) {
	    Status = RWSeekToCylinder(DriveInfo, Cylinder);
	    if (!NT_SUCCESS(Status)) {
		WARN_(FLOPPY,
		      "ReadWrite(): unable to seek; error = 0x%x\n", Status);
		goto free;
	    }
	}

	/*
	 * Compute last sector
	 *
	 * We can only ask for a transfer up to the end of the track.
	 * Then we have to re-seek and do more.
	 * TODO: Support the MT bit
	 */
	INFO_(FLOPPY,
	      "ReadWrite(): computing number of sectors to transfer (StartSector 0x%x).\n",
	      StartSector);

	/* 1-based sector number */
	if (((DriveInfo->DiskGeometry.TracksPerCylinder - Head)
	     * DriveInfo->DiskGeometry.SectorsPerTrack - StartSector + 1) <
	    (Length - TransferByteOffset) / DriveInfo->DiskGeometry.BytesPerSector) {
	    CurrentTransferSectors = (UCHAR)((DriveInfo->DiskGeometry.TracksPerCylinder - Head)
					     * DriveInfo->DiskGeometry.SectorsPerTrack - StartSector) + 1;
	} else {
	    CurrentTransferSectors = (UCHAR)((Length - TransferByteOffset)
					     / DriveInfo->DiskGeometry.BytesPerSector);
	}

	INFO_(FLOPPY, "CurrentTransferSectors = 0x%x\n", CurrentTransferSectors);

	CurrentTransferBytes = CurrentTransferSectors * DriveInfo->DiskGeometry.BytesPerSector;

	/*
	 * Adjust to map registers
	 * BUG: Does this take into account page crossings?
	 */
	INFO_(FLOPPY,
	      "ReadWrite(): Trying to transfer 0x%x bytes\n",
	      CurrentTransferBytes);

	ASSERT(CurrentTransferBytes);

	if (BYTES_TO_PAGES(CurrentTransferBytes) > DriveInfo->ControllerInfo->MapRegisters) {
	    CurrentTransferSectors = (UCHAR)((DriveInfo->ControllerInfo->MapRegisters * PAGE_SIZE) /
					     DriveInfo->DiskGeometry.BytesPerSector);

	    CurrentTransferBytes = CurrentTransferSectors * DriveInfo->DiskGeometry.BytesPerSector;

	    INFO_(FLOPPY,
		  "ReadWrite: limiting transfer to 0x%x bytes (0x%x sectors) due to map registers\n",
		  CurrentTransferBytes, CurrentTransferSectors);
	}

	/* Set up this round's dma operation */
	/* Param 2 is ReadOperation --> opposite of WriteToDevice that IoMapTransfer takes.  BAD MS. */
	KeFlushIoBuffers(Irp->MdlAddress, !WriteToDevice, TRUE);

	IoMapTransfer(DriveInfo->ControllerInfo->AdapterObject,
		      Irp->MdlAddress,
		      DriveInfo->ControllerInfo->MapRegisterBase,
		      (PVOID)((ULONG_PTR)MmGetMdlVirtualAddress(Irp->MdlAddress) + TransferByteOffset),
		      &CurrentTransferBytes,
		      WriteToDevice);

	/*
	 * Read or Write
	 */
	KeClearEvent(&DriveInfo->ControllerInfo->SynchEvent);

	/* Issue the read/write command to the controller.
	 * Note that it expects the opposite of WriteToDevice. */
	Status = HwReadWriteData(DriveInfo->ControllerInfo, !WriteToDevice,
				 DriveInfo->UnitNumber, Cylinder, Head, StartSector,
				 DriveInfo->BytesPerSectorCode,
				 DriveInfo->DiskGeometry.SectorsPerTrack, Gap, 0xff);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "ReadWrite(): HwReadWriteData returned error 0x%x; unable to read\n",
		  Status);
	    goto free;
	}

	INFO_(FLOPPY,
	      "ReadWrite(): HwReadWriteData returned -- waiting on event\n");

	/*
	 * At this point, we block and wait for an interrupt
	 * FIXME: this seems to take too long
	 */
	WaitForControllerInterrupt(DriveInfo->ControllerInfo, NULL);

	/* Read is complete; flush & free adapter channel */
	IoFlushAdapterBuffers(DriveInfo->ControllerInfo->AdapterObject,
			      Irp->MdlAddress,
			      DriveInfo->ControllerInfo->MapRegisterBase,
			      (PVOID)((ULONG_PTR)MmGetMdlVirtualAddress(Irp->MdlAddress) + TransferByteOffset),
			      CurrentTransferBytes, WriteToDevice);

	/* Read the results from the drive */
	Status = HwReadWriteResult(DriveInfo->ControllerInfo);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY,
		  "ReadWrite(): HwReadWriteResult returned error 0x%x; unable to read\n",
		  Status);
	    HwDumpRegisters(DriveInfo->ControllerInfo);
	    goto free;
	}

	TransferByteOffset += CurrentTransferBytes;
    }

    /* That's all folks! */
    INFO_(FLOPPY,
	  "ReadWrite(): success; Completing with STATUS_SUCCESS\n");
    Status = STATUS_SUCCESS;

free:
    IoFreeAdapterChannel(DriveInfo->ControllerInfo->AdapterObject);

stop:
    StopMotor(DriveInfo->ControllerInfo);

out:
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = NT_SUCCESS(Status) ? Length : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}
