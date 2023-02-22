/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Shutdown handlers
 * COPYRIGHT:   Copyright 2000-2013 Eric Kohl <eric.kohl@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS ****************************************************************/

static NTSTATUS FatDiskShutDown(PVCB Vcb)
{
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_SHUTDOWN, Vcb->StorageDevice,
				       NULL, 0, NULL, &Event, &IoStatus);
    if (Irp) {
	Status = IoCallDriver(Vcb->StorageDevice, Irp);
	if (Status == STATUS_PENDING) {
	    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	    Status = IoStatus.Status;
	}
    } else {
	Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    return Status;
}

NTAPI NTSTATUS FatShutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS Status;
    PLIST_ENTRY ListEntry;
    PDEVICE_EXTENSION DeviceExt;

    DPRINT("FatShutdown(DeviceObject %p, Irp %p)\n", DeviceObject, Irp);

    FsRtlEnterFileSystem();

    /* FIXME: block new mount requests */
    FatGlobalData->ShutdownStarted = TRUE;

    if (DeviceObject == FatGlobalData->DeviceObject) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	ExAcquireResourceExclusiveLite(&FatGlobalData->VolumeListLock,
				       TRUE);
	ListEntry = FatGlobalData->VolumeListHead.Flink;
	while (ListEntry != &FatGlobalData->VolumeListHead) {
	    DeviceExt = CONTAINING_RECORD(ListEntry, VCB, VolumeListEntry);
	    ListEntry = ListEntry->Flink;

	    ExAcquireResourceExclusiveLite(&DeviceExt->DirResource, TRUE);

	    /* Flush volume & files */
	    Status = FatFlushVolume(DeviceExt, DeviceExt->VolumeFcb);

	    /* We're performing a clean shutdown */
	    if (BooleanFlagOn(DeviceExt->VolumeFcb->Flags, VCB_CLEAR_DIRTY)
		&& BooleanFlagOn(DeviceExt->VolumeFcb->Flags,
				 VCB_IS_DIRTY)) {
		/* Drop the dirty bit */
		if (NT_SUCCESS(SetDirtyStatus(DeviceExt, FALSE)))
		    DeviceExt->VolumeFcb->Flags &= ~VCB_IS_DIRTY;
	    }

	    if (NT_SUCCESS(Status)) {
		Status = FatDiskShutDown(DeviceExt);
		if (!NT_SUCCESS(Status)) {
		    DPRINT1("FatDiskShutDown failed, status = %x\n",
			    Status);
		}
	    } else {
		DPRINT1("FatFlushVolume failed, status = %x\n", Status);
	    }
	    ExReleaseResourceLite(&DeviceExt->DirResource);

	    /* Unmount the logical volume */
#ifdef ENABLE_SWAPOUT
	    FatCheckForDismount(DeviceExt, FALSE);
#endif

	    if (!NT_SUCCESS(Status))
		Irp->IoStatus.Status = Status;
	}
	ExReleaseResourceLite(&FatGlobalData->VolumeListLock);

	/* FIXME: Free all global acquired resources */

	Status = Irp->IoStatus.Status;
    } else {
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    FsRtlExitFileSystem();

    return Status;
}
