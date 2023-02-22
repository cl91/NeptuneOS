/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Flushing routines
 * COPYRIGHT:   Copyright 2004-2013 Eric Kohl <eric.kohl@reactos.org>
 *              Copyright 2014-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ****************************************************************/

static NTSTATUS FatFlushFile(PDEVICE_EXTENSION DeviceExt, PFATFCB Fcb)
{
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    DPRINT("FatFlushFile(DeviceExt %p, Fcb %p) for '%wZ'\n", DeviceExt,
	   Fcb, &Fcb->PathNameU);

    CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, &IoStatus);
    if (IoStatus.Status == STATUS_INVALID_PARAMETER) {
	/* FIXME: Caching was possible not initialized */
	IoStatus.Status = STATUS_SUCCESS;
    }

    ExAcquireResourceExclusiveLite(&DeviceExt->DirResource, TRUE);
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_DIRTY)) {
	Status = FatUpdateEntry(DeviceExt, Fcb);
	if (!NT_SUCCESS(Status)) {
	    IoStatus.Status = Status;
	}
    }
    ExReleaseResourceLite(&DeviceExt->DirResource);

    return IoStatus.Status;
}

NTSTATUS FatFlushVolume(PDEVICE_EXTENSION DeviceExt, PFATFCB VolumeFcb)
{
    PLIST_ENTRY ListEntry;
    PFATFCB Fcb;
    NTSTATUS Status, ReturnStatus = STATUS_SUCCESS;
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatusBlock;

    DPRINT("FatFlushVolume(DeviceExt %p, VolumeFcb %p)\n", DeviceExt,
	   VolumeFcb);

    ASSERT(VolumeFcb == DeviceExt->VolumeFcb);

    ListEntry = DeviceExt->FcbListHead.Flink;
    while (ListEntry != &DeviceExt->FcbListHead) {
	Fcb = CONTAINING_RECORD(ListEntry, FATFCB, FcbListEntry);
	ListEntry = ListEntry->Flink;
	if (!FatFCBIsDirectory(Fcb)) {
	    ExAcquireResourceExclusiveLite(&Fcb->MainResource, TRUE);
	    Status = FatFlushFile(DeviceExt, Fcb);
	    ExReleaseResourceLite(&Fcb->MainResource);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("FatFlushFile failed, status = %x\n", Status);
		ReturnStatus = Status;
	    }
	}
	/* FIXME: Stop flushing if this is a removable media and the media was removed */
    }

    ListEntry = DeviceExt->FcbListHead.Flink;
    while (ListEntry != &DeviceExt->FcbListHead) {
	Fcb = CONTAINING_RECORD(ListEntry, FATFCB, FcbListEntry);
	ListEntry = ListEntry->Flink;
	if (FatFCBIsDirectory(Fcb)) {
	    ExAcquireResourceExclusiveLite(&Fcb->MainResource, TRUE);
	    Status = FatFlushFile(DeviceExt, Fcb);
	    ExReleaseResourceLite(&Fcb->MainResource);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("FatFlushFile failed, status = %x\n", Status);
		ReturnStatus = Status;
	    }
	}
	/* FIXME: Stop flushing if this is a removable media and the media was removed */
    }

    Fcb = (PFATFCB) DeviceExt->FATFileObject->FsContext;

    ExAcquireResourceExclusiveLite(&DeviceExt->FatResource, TRUE);
    Status = FatFlushFile(DeviceExt, Fcb);
    ExReleaseResourceLite(&DeviceExt->FatResource);

    /* Prepare an IRP to flush device buffers */
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_FLUSH_BUFFERS,
				       DeviceExt->StorageDevice,
				       NULL, 0, NULL, &Event,
				       &IoStatusBlock);
    if (Irp != NULL) {
	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Status = IoCallDriver(DeviceExt->StorageDevice, Irp);
	if (Status == STATUS_PENDING) {
	    KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	    Status = IoStatusBlock.Status;
	}

	/* Ignore device not supporting flush operation */
	if (Status == STATUS_INVALID_DEVICE_REQUEST) {
	    DPRINT1("Flush not supported, ignored\n");
	    Status = STATUS_SUCCESS;

	}
    } else {
	Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!NT_SUCCESS(Status)) {
	DPRINT1("FatFlushFile failed, status = %x\n", Status);
	ReturnStatus = Status;
    }

    return ReturnStatus;
}

NTSTATUS FatFlush(PFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status;
    PFATFCB Fcb;

    /* This request is not allowed on the main device object. */
    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	IrpContext->Irp->IoStatus.Information = 0;
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    Fcb = (PFATFCB) IrpContext->FileObject->FsContext;
    ASSERT(Fcb);

    if (BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME)) {
	ExAcquireResourceExclusiveLite(&IrpContext->DeviceExt->DirResource,
				       TRUE);
	Status = FatFlushVolume(IrpContext->DeviceExt, Fcb);
	ExReleaseResourceLite(&IrpContext->DeviceExt->DirResource);
    } else {
	ExAcquireResourceExclusiveLite(&Fcb->MainResource, TRUE);
	Status = FatFlushFile(IrpContext->DeviceExt, Fcb);
	ExReleaseResourceLite(&Fcb->MainResource);
    }

    IrpContext->Irp->IoStatus.Information = 0;
    return Status;
}
