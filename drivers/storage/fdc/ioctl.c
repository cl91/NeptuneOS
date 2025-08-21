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
 * FILE:            ioctl.c
 * PURPOSE:         IOCTL Routines
 * PROGRAMMER:      Vizzini (vizzini@plasmic.com)
 * REVISIONS:
 *                  15-Feb-2004 vizzini - Created
 * NOTES:
 *     - All IOCTL documentation taken from the DDK
 *     - This driver tries to support all of the IOCTLs that the DDK floppy
 *       sample does
 *
 * TODO: Implement format
 */

#include "fdc.h"

/*
 * FUNCTION: Handle IOCTL IRPs
 * ARGUMENTS:
 *     DriveInfo: Drive that the IOCTL is directed at
 *     Irp: IRP to process
 */
VOID DeviceIoctl(PDRIVE_INFO DriveInfo, PIRP Irp)
{
    ASSERT(DriveInfo);
    ASSERT(Irp);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID OutputBuffer = Irp->SystemBuffer;
    ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;
    BOOLEAN DiskChanged;
    PMOUNTDEV_NAME Name;
    PMOUNTDEV_UNIQUE_ID UniqueId;

    TRACE_(FLOPPY, "DeviceIoctl called\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    /*
     * Check to see if the volume needs to be verified.  If so,
     * return STATUS_VERIFY_REQUIRED.
     */
    if (DriveInfo->DeviceObject->Flags & DO_VERIFY_VOLUME
	&& !(Stack->Flags & SL_OVERRIDE_VERIFY_VOLUME)) {
	INFO_(FLOPPY,
	      "DeviceIoctl(): completing with STATUS_VERIFY_REQUIRED\n");
	Irp->IoStatus.Status = STATUS_VERIFY_REQUIRED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return;
    }

    /*
     * Start the drive to see if the disk has changed
     */
    StartMotor(DriveInfo);

    /*
     * Check the change line, and if it's set, return
     */
    if (HwDiskChanged(DriveInfo, &DiskChanged) != STATUS_SUCCESS) {
	WARN_(FLOPPY, "DeviceIoctl(): unable to sense disk change; "
	      "completing with STATUS_UNSUCCESSFUL\n");
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	Irp->IoStatus.Information = 0;
	goto out;
    }

    if (DiskChanged) {
	INFO_(FLOPPY, "DeviceIoctl(): detected disk changed; signalling "
	      "media change and completing\n");
	SignalMediaChanged(DriveInfo->DeviceObject, Irp);

	/* If there's really no disk in the drive, save time by reporting
	 * just that, rather than having the system ask me twice. */
	if (ResetChangeFlag(DriveInfo) == STATUS_NO_MEDIA_IN_DEVICE)
	    Irp->IoStatus.Status = STATUS_NO_MEDIA_IN_DEVICE;

	goto out;
    }

    /*
     * Figure out the media type, if we don't know it already
     */
    if (DriveInfo->DiskGeometry.MediaType == Unknown) {
	NTSTATUS Status = RWDetermineMediaType(DriveInfo);
	if (!NT_SUCCESS(Status)) {
	    WARN_(FLOPPY, "DeviceIoctl(): unable to determine media type, "
		  "error = 0x%x\n", Status);
	    Irp->IoStatus.Status = Status;
	    Irp->IoStatus.Information = 0;
	    goto out;
	}

	if (DriveInfo->DiskGeometry.MediaType == Unknown) {
	    WARN_(FLOPPY, "DeviceIoctl(): Unknown media in drive; "
		  "completing with STATUS_UNRECOGNIZED_MEDIA\n");
	    Irp->IoStatus.Status = STATUS_UNRECOGNIZED_MEDIA;
	    Irp->IoStatus.Information = 0;
	    goto out;
	}
    }

    switch (Code) {
    case IOCTL_DISK_IS_WRITABLE:
    {
	UCHAR Status;

	INFO_(FLOPPY, "IOCTL_DISK_IS_WRITABLE Called\n");

	/* This IRP always has 0 information */
	Irp->IoStatus.Information = 0;

	if (HwSenseDriveStatus(DriveInfo) != STATUS_SUCCESS) {
	    WARN_(FLOPPY,
		  "IoctlDiskIsWritable(): unable to sense drive status\n");
	    Irp->IoStatus.Status = STATUS_IO_DEVICE_ERROR;
	    break;
	}

	/* Now, read the drive's status back */
	if (HwSenseDriveStatusResult
	    (DriveInfo->ControllerInfo, &Status) != STATUS_SUCCESS) {
	    WARN_(FLOPPY,
		  "IoctlDiskIsWritable(): unable to read drive status result\n");
	    Irp->IoStatus.Status = STATUS_IO_DEVICE_ERROR;
	    break;
	}

	/* Check to see if the write flag is set. */
	if (Status & SR3_WRITE_PROTECT_STATUS_SIGNAL) {
	    INFO_(FLOPPY,
		  "IOCTL_DISK_IS_WRITABLE: disk is write protected\n");
	    Irp->IoStatus.Status = STATUS_MEDIA_WRITE_PROTECTED;
	} else
	    Irp->IoStatus.Status = STATUS_SUCCESS;
    }
    break;

    case IOCTL_DISK_CHECK_VERIFY:
	INFO_(FLOPPY, "IOCTL_DISK_CHECK_VERIFY called\n");
	if (OutputLength != 0) {
	    if (OutputLength < sizeof(ULONG)) {
		Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
		Irp->IoStatus.Information = 0;
	    } else {
		*((PULONG)OutputBuffer) = DriveInfo->DiskChangeCount;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(ULONG);
	    }
	} else {
	    Irp->IoStatus.Status = STATUS_SUCCESS;
	    Irp->IoStatus.Information = 0;
	}
	if (NT_SUCCESS(Irp->IoStatus.Status)) {
	    DriveInfo->DeviceObject->Flags &= ~DO_VERIFY_VOLUME;
	}
	break;

    case IOCTL_DISK_GET_MEDIA_TYPES:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    {
	if (OutputLength < sizeof(DISK_GEOMETRY)) {
	    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	    break;
	}

	/* This still works right even if DriveInfo->DiskGeometry->MediaType = Unknown */
	memcpy(OutputBuffer, &DriveInfo->DiskGeometry, sizeof(DISK_GEOMETRY));
	Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);
	DPRINT("Disk Geometry:\n");
	DPRINT("Cylinders         0x%llx\n", DriveInfo->DiskGeometry.Cylinders.QuadPart);
	DPRINT("MediaType           %d\n", DriveInfo->DiskGeometry.MediaType);
	DPRINT("TracksPerCylinder   %d\n", DriveInfo->DiskGeometry.TracksPerCylinder);
	DPRINT("SectorsPerTrack     %d\n", DriveInfo->DiskGeometry.SectorsPerTrack);
	DPRINT("BytesPerSector      %d\n", DriveInfo->DiskGeometry.BytesPerSector);
    }
    break;

    case IOCTL_DISK_FORMAT_TRACKS:
    case IOCTL_DISK_FORMAT_TRACKS_EX:
	ERR_(FLOPPY, "Format called; not supported yet\n");
	Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
	Irp->IoStatus.Information = 0;
	break;

    case IOCTL_DISK_GET_PARTITION_INFO:
	INFO_(FLOPPY, "IOCTL_DISK_GET_PARTITION_INFO Called; "
	      "not supported by floppy drives\n");
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Irp->IoStatus.Information = 0;
	break;

    case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
	if (OutputLength < sizeof(MOUNTDEV_UNIQUE_ID)) {
	    Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
	    Irp->IoStatus.Information = 0;
	    break;
	}

	UniqueId = Irp->SystemBuffer;
	UniqueId->UniqueIdLength = (USHORT)wcslen(DriveInfo->DeviceNameBuffer) * sizeof(WCHAR);

	if (OutputLength < FIELD_OFFSET(MOUNTDEV_UNIQUE_ID, UniqueId) + UniqueId->UniqueIdLength) {
	    Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
	    Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
	    break;
	}

	RtlCopyMemory(UniqueId->UniqueId, DriveInfo->DeviceNameBuffer,
		      UniqueId->UniqueIdLength);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = FIELD_OFFSET(MOUNTDEV_UNIQUE_ID, UniqueId) + UniqueId->UniqueIdLength;
	break;

    case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
	if (OutputLength < sizeof(MOUNTDEV_NAME)) {
	    Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
	    Irp->IoStatus.Information = 0;
	    break;
	}

	Name = Irp->SystemBuffer;
	Name->NameLength = (USHORT)wcslen(DriveInfo->DeviceNameBuffer) * sizeof(WCHAR);

	if (OutputLength < FIELD_OFFSET(MOUNTDEV_NAME, Name) + Name->NameLength) {
	    Irp->IoStatus.Status = STATUS_BUFFER_OVERFLOW;
	    Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
	    break;
	}

	RtlCopyMemory(Name->Name, &DriveInfo->DeviceNameBuffer[0],
		      Name->NameLength);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = FIELD_OFFSET(MOUNTDEV_NAME, Name) + Name->NameLength;
	break;

    default:
	ERR_(FLOPPY, "UNKNOWN IOCTL CODE: 0x%x\n", Code);
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	Irp->IoStatus.Information = 0;
	break;
    }

out:
    INFO_(FLOPPY, "ioctl: completing with status 0x%x\n",
	  Irp->IoStatus.Status);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    StopMotor(DriveInfo->ControllerInfo);
}
