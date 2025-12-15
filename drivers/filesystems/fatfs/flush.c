/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Flushing routines
 * COPYRIGHT:   Copyright 2004-2013 Eric Kohl <eric.kohl@reactos.org>
 *              Copyright 2014-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"
#include "ntstatus.h"

#include <debug.h>

/* FUNCTIONS ****************************************************************/

static NTSTATUS FatFlushFile(PDEVICE_EXTENSION DeviceExt, PFILE_OBJECT FileObject)
{
    PFATFCB Fcb = (PFATFCB)FileObject->FsContext;
    DPRINT("FatFlushFile(DeviceExt %p, Fcb %p) for '%wZ'\n", DeviceExt,
	   Fcb, &Fcb->PathNameU);

    NTSTATUS Status = STATUS_SUCCESS;
    IO_STATUS_BLOCK IoStatus;
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_DIRTY)) {
	Status = FatUpdateEntry(DeviceExt, Fcb);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("FatUpdateEntry failed, status = %x\n", Status);
	    assert(FALSE);
	}
	if (Fcb->ParentFcb && !BooleanFlagOn(Fcb->ParentFcb->Flags, FCB_IS_VOLUME)) {
	    assert(Fcb->ParentFcb->FileObject);
	    CcFlushCache(Fcb->ParentFcb->FileObject, NULL, 0, &IoStatus);
	    if (!NT_SUCCESS(IoStatus.Status)) {
		assert(FALSE);
		Status = IoStatus.Status;
	    }
	}
    }

    assert(FileObject);
    CcFlushCache(FileObject, NULL, 0, &IoStatus);
    if (!NT_SUCCESS(IoStatus.Status)) {
	assert(FALSE);
	return IoStatus.Status;
    }
    return Status;
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
	if (BooleanFlagOn(Fcb->Flags, FCB_IS_DIRTY)) {
	    Status = FatUpdateEntry(DeviceExt, Fcb);
	    if (!NT_SUCCESS(Status)) {
		DPRINT1("FatUpdateEntry failed, status = %x\n", Status);
		assert(FALSE);
		ReturnStatus = Status;
	    }
	}
    }

    /* Note we don't need to call CcFlushCache for every open file we have.
     * We only need to call it once, for the volume FCB, because what this
     * routine does is flushing the server-side dirty buffers. The client-side
     * dirty buffers have already been taken care of by CcSetDirtyData (this
     * is guaranteed to happen since we process IO messages sequentially). */
    IO_STATUS_BLOCK IoStatus;
    assert(VolumeFcb->FileObject);
    CcFlushCache(VolumeFcb->FileObject, NULL, 0, &IoStatus);
    if (!NT_SUCCESS(IoStatus.Status)) {
	assert(FALSE);
	return IoStatus.Status;
    }

    /* Prepare an IRP to flush device buffers */
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    Irp = IoBuildSynchronousFsdRequest(IRP_MJ_FLUSH_BUFFERS,
				       DeviceExt->StorageDevice,
				       NULL, 0, NULL, &Event, &IoStatusBlock);
    if (Irp != NULL) {
	Status = IoCallDriver(DeviceExt->StorageDevice, Irp);
        if (Status == STATUS_PENDING) {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatusBlock.Status;
        }

	/* Ignore device not supporting flush operation */
	if (Status == STATUS_INVALID_DEVICE_REQUEST || Status == STATUS_NOT_IMPLEMENTED) {
	    DPRINT1("Flush not supported, ignored\n");
	    Status = STATUS_SUCCESS;
	}
    } else {
	Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!NT_SUCCESS(Status)) {
	DPRINT1("FatFlushFile failed, status = %x\n", Status);
	assert(FALSE);
	ReturnStatus = Status;
    }

    return ReturnStatus;
}

NTSTATUS FatFlush(PFAT_IRP_CONTEXT IrpContext)
{
    /* This request is not allowed on the main device object. */
    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	IrpContext->Irp->IoStatus.Information = 0;
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    PFATFCB Fcb = (PFATFCB)IrpContext->FileObject->FsContext;
    ASSERT(Fcb);

    NTSTATUS Status;
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME)) {
	Status = FatFlushVolume(IrpContext->DeviceExt, Fcb);
    } else {
	Status = FatFlushFile(IrpContext->DeviceExt, IrpContext->FileObject);
    }

    return Status;
}
