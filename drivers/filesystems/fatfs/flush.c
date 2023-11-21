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

    CcFlushCache(&Fcb->Base, NULL, 0, &IoStatus);
    if (IoStatus.Status == STATUS_INVALID_PARAMETER) {
	/* FIXME: Caching was probably not initialized */
	IoStatus.Status = STATUS_SUCCESS;
    }

    if (BooleanFlagOn(Fcb->Flags, FCB_IS_DIRTY)) {
	Status = FatUpdateEntry(DeviceExt, Fcb);
	if (!NT_SUCCESS(Status)) {
	    IoStatus.Status = Status;
	}
    }

    return IoStatus.Status;
}

NTSTATUS FatFlushVolume(PDEVICE_EXTENSION DeviceExt, PFATFCB VolumeFcb)
{
    PLIST_ENTRY ListEntry;
    PFATFCB Fcb;
    NTSTATUS Status, ReturnStatus = STATUS_SUCCESS;
    PIRP Irp;
    IO_STATUS_BLOCK IoStatusBlock;

    DPRINT("FatFlushVolume(DeviceExt %p, VolumeFcb %p)\n", DeviceExt,
	   VolumeFcb);

    ASSERT(VolumeFcb == DeviceExt->VolumeFcb);

    ListEntry = DeviceExt->FcbListHead.Flink;
    while (ListEntry != &DeviceExt->FcbListHead) {
	Fcb = CONTAINING_RECORD(ListEntry, FATFCB, FcbListEntry);
	ListEntry = ListEntry->Flink;
	if (!FatFCBIsDirectory(Fcb)) {
	    Status = FatFlushFile(DeviceExt, Fcb);
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
	    Status = FatFlushFile(DeviceExt, Fcb);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("FatFlushFile failed, status = %x\n", Status);
		ReturnStatus = Status;
	    }
	}
	/* FIXME: Stop flushing if this is a removable media and the media was removed */
    }

    Fcb = (PFATFCB) DeviceExt->FatFileObject->FsContext;

    Status = FatFlushFile(DeviceExt, Fcb);

    /* Prepare an IRP to flush device buffers */
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_FLUSH_BUFFERS,
				       DeviceExt->StorageDevice,
				       NULL, 0, NULL, &IoStatusBlock);
    if (Irp != NULL) {
	Status = IoCallDriver(DeviceExt->StorageDevice, Irp);

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
	Status = FatFlushVolume(IrpContext->DeviceExt, Fcb);
    } else {
	Status = FatFlushFile(IrpContext->DeviceExt, Fcb);
    }

    IrpContext->Irp->IoStatus.Information = 0;
    return Status;
}
