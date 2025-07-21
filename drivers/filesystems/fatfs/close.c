/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     File close routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2014-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS ****************************************************************/

BOOLEAN FatCheckForDismount(IN PDEVICE_EXTENSION DeviceExt,
			    IN BOOLEAN Force)
{
    ULONG UnCleanCount;
    PVPB Vpb;
    BOOLEAN Delete;

    DPRINT1("FatCheckForDismount(%p, %u)\n", DeviceExt, Force);

    /* If the VCB is OK (not under uninitialization) and we don't
     * force dismount, do nothing */
    if (BooleanFlagOn(DeviceExt->Flags, VCB_GOOD) && !Force) {
	return FALSE;
    }

    /*
     * NOTE: In their CheckForDismount() function, our 3rd-party FS drivers
     * as well as MS' fastfat, perform a comparison check of the current VCB's
     * VPB ReferenceCount with some sort of "dangling"/"residual" open count,
     * depending on whether or not we are in IRP_MJ_CREATE.
     * It seems to be related to the fact that the volume root directory as
     * well as auxiliary data stream(s) are still opened, and only these are
     * allowed to be opened at that moment. After analysis it appears that for
     * the ReactOS' Fatfs, this number is equal to "2".
     */
    UnCleanCount = 2;

    /* Reference it and check if a create is being done */
    Vpb = DeviceExt->IoVPB;
    DPRINT("Vpb->ReferenceCount = %d\n", Vpb->ReferenceCount);
    if (Vpb->ReferenceCount != UnCleanCount || DeviceExt->OpenHandleCount != 0) {
	/* If we force-unmount, copy the VPB to our local own to prepare later dismount */
	if (Force && Vpb->RealDevice->Vpb == Vpb && DeviceExt->SpareVPB) {
	    RtlZeroMemory(DeviceExt->SpareVPB, sizeof(VPB));
	    DeviceExt->SpareVPB->Type = IO_TYPE_VPB;
	    DeviceExt->SpareVPB->Size = sizeof(VPB);
	    DeviceExt->SpareVPB->RealDevice = DeviceExt->IoVPB->RealDevice;
	    DeviceExt->SpareVPB->DeviceObject = NULL;
	    DeviceExt->SpareVPB->Flags = DeviceExt->IoVPB->Flags & VPB_REMOVE_PENDING;
	    DeviceExt->IoVPB->RealDevice->Vpb = DeviceExt->SpareVPB;
	    DeviceExt->SpareVPB = NULL;
	    DeviceExt->IoVPB->Flags |= VPB_PERSISTENT;

	    /* We are uninitializing, the VCB cannot be used anymore */
	    ClearFlag(DeviceExt->Flags, VCB_GOOD);
	}

	/* Don't do anything for now */
	Delete = FALSE;
    } else {
	/* Otherwise, delete the volume */
	Delete = TRUE;

	/* Swap the VPB with our local own */
	if (Vpb->RealDevice->Vpb == Vpb && DeviceExt->SpareVPB) {
	    RtlZeroMemory(DeviceExt->SpareVPB, sizeof(VPB));
	    DeviceExt->SpareVPB->Type = IO_TYPE_VPB;
	    DeviceExt->SpareVPB->Size = sizeof(VPB);
	    DeviceExt->SpareVPB->RealDevice = DeviceExt->IoVPB->RealDevice;
	    DeviceExt->SpareVPB->DeviceObject = NULL;
	    DeviceExt->SpareVPB->Flags = DeviceExt->IoVPB->Flags & VPB_REMOVE_PENDING;
	    DeviceExt->IoVPB->RealDevice->Vpb = DeviceExt->SpareVPB;
	    DeviceExt->SpareVPB = NULL;
	    DeviceExt->IoVPB->Flags |= VPB_PERSISTENT;

	    /* We are uninitializing, the VCB cannot be used anymore */
	    ClearFlag(DeviceExt->Flags, VCB_GOOD);
	}

	/*
	 * We defer setting the VPB's DeviceObject to NULL for later because
	 * we want to handle the closing of the internal opened meta-files.
	 */

	/* Clear the mounted and locked flags in the VPB */
	ClearFlag(Vpb->Flags, VPB_MOUNTED | VPB_LOCKED);
    }

    /* If we were to delete, delete volume */
    if (Delete) {
	LARGE_INTEGER Zero = {{0, 0}};

	/* We are uninitializing, the VCB cannot be used anymore */
	ClearFlag(DeviceExt->Flags, VCB_GOOD);

	/* Invalidate and close the internal meta-files */
	if (DeviceExt->RootFcb) {
	    CcUninitializeCacheMap(DeviceExt->RootFcb->FileObject, &Zero);
	    ObDereferenceObject(DeviceExt->RootFcb->FileObject);
	    FatDestroyFcb(DeviceExt->RootFcb);
	    DeviceExt->RootFcb = NULL;
	}
	if (DeviceExt->VolumeFcb) {
	    CcUninitializeCacheMap(DeviceExt->VolumeFcb->FileObject, &Zero);
	    ObDereferenceObject(DeviceExt->VolumeFcb->FileObject);
	    FatDestroyFcb(DeviceExt->VolumeFcb);
	    DeviceExt->VolumeFcb = NULL;
	}
	if (DeviceExt->FatFileObject) {
	    PFATFCB Fcb = DeviceExt->FatFileObject->FsContext;
	    CcUninitializeCacheMap(DeviceExt->FatFileObject, &Zero);
	    DeviceExt->FatFileObject->FsContext = NULL;
	    ObDereferenceObject(DeviceExt->FatFileObject);
	    DeviceExt->FatFileObject = NULL;
	    FatDestroyFcb(Fcb);
	}

	/*
	 * Now that the closing of the internal opened meta-files has been
	 * handled, we can now set the VPB's DeviceObject to NULL.
	 */
	Vpb->DeviceObject = NULL;

	/* If we have a local VPB, we'll have to delete it
	 * but we won't dismount us - something went bad before
	 */
	if (DeviceExt->SpareVPB) {
	    ExFreePool(DeviceExt->SpareVPB);
	} else if (DeviceExt->IoVPB->ReferenceCount == 0) {
	    /* Otherwise, delete any of the available VPB if its refcount is zero. */
	    ExFreePool(DeviceExt->IoVPB);
	}

	/* Remove the volume from the list */
	RemoveEntryList(&DeviceExt->VolumeListEntry);

	/* Release resources */
	ExFreePoolWithTag(DeviceExt->Statistics, TAG_STATS);

	/* Dismount our device if possible */
	ObDereferenceObject(DeviceExt->StorageDevice);
	IoDeleteDevice(DeviceExt->VolumeDevice);
    }

    return Delete;
}

/*
 * FUNCTION: Closes a file
 */
NTSTATUS FatCloseFile(PDEVICE_EXTENSION DeviceExt, PFILE_OBJECT FileObject)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("FatCloseFile(DeviceExt %p, FileObject %p)\n",
	   DeviceExt, FileObject);

    /* FIXME : update entry in directory? */
    PFATFCB Fcb = (PFATFCB)FileObject->FsContext;
    PFATCCB Ccb = (PFATCCB)FileObject->FsContext2;

    if (Fcb == NULL) {
	return STATUS_SUCCESS;
    }

    BOOLEAN IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);

    if (Ccb) {
	FatDestroyCcb(Ccb);
    }

    /* Nothing to do for volumes or for the FAT file object */
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_FAT | FCB_IS_VOLUME)) {
	return STATUS_SUCCESS;
    }

    /* Release the FCB, we likely cause its deletion */
    FatReleaseFcb(DeviceExt, Fcb);
    Fcb->Flags |= FCB_CLOSED;

    FileObject->FsContext2 = NULL;
    FileObject->FsContext = NULL;

    if (IsVolume && DeviceExt->OpenHandleCount == 0) {
	FatCheckForDismount(DeviceExt, FALSE);
    }

    return Status;
}

/*
 * FUNCTION: Closes a file
 */
NTSTATUS FatClose(PFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status;

    DPRINT("FatClose(DeviceObject %p, Irp %p)\n", IrpContext->DeviceObject,
	   IrpContext->Irp);

    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	DPRINT("Closing file system\n");
	IrpContext->Irp->IoStatus.Information = 0;
	return STATUS_SUCCESS;
    }

    Status = FatCloseFile(IrpContext->DeviceExt, IrpContext->FileObject);

    IrpContext->Irp->IoStatus.Information = 0;

    return Status;
}
