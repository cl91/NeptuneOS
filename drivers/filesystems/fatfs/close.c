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
    BOOLEAN Delete;

    DPRINT1("FatCheckForDismount(%p, %u)\n", DeviceExt, Force);

    /* If the VCB is OK (not under uninitialization) and we don't
     * force dismount, do nothing */
    if (BooleanFlagOn(DeviceExt->Flags, VCB_GOOD) && !Force) {
	DPRINT1("VCB GOOD. Not dismounting.\n");
	return FALSE;
    }

    DPRINT1("DeviceExt->OpenHandleCount %d\n", DeviceExt->OpenHandleCount);
    if (DeviceExt->OpenHandleCount) {
	if (Force) {
	    /* We are uninitializing, the VCB cannot be used anymore */
	    ClearFlag(DeviceExt->Flags, VCB_GOOD);
	}

	/* Don't do anything for now */
	Delete = FALSE;
    } else {
	/* Otherwise, delete the volume */
	Delete = TRUE;

	/* We are uninitializing, the VCB cannot be used anymore */
	ClearFlag(DeviceExt->Flags, VCB_GOOD);
    }

    /* If we were to delete, delete volume */
    if (Delete) {
	LARGE_INTEGER Zero = {{0, 0}};

	/* We are uninitializing, the VCB cannot be used anymore */
	ClearFlag(DeviceExt->Flags, VCB_GOOD);

	/* Invalidate and close the internal meta-files */
	if (DeviceExt->RootFcb) {
	    if (DeviceExt->RootFcb->FileObject) {
		CcUninitializeCacheMap(DeviceExt->RootFcb->FileObject, &Zero);
		ObDereferenceObject(DeviceExt->RootFcb->FileObject);
	    }
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
	PVPB Vpb = DeviceExt->VolumeDevice->Vpb;
	Vpb->DeviceObject = NULL;

	/* Remove the volume from the list */
	RemoveEntryList(&DeviceExt->VolumeListEntry);

	/* Release resources */
	ExFreePoolWithTag(DeviceExt->Statistics, TAG_STATS);

	/* Dereference the volume device object we created when mounting the volume.
	 * The VPB itself will be deleted when the storage device gets deleted.
	 * Note we do NOT need to dereference the storager device which the system
	 * referenced when creating the VPB, because the system will take care of
	 * that when receiving a CloseDevice message. */
	IoDeleteDevice(DeviceExt->VolumeDevice);
	/* The storage device should not have any lingering reference at this point. */
	DPRINT("DeviceExt->StorageDevice->Header.RefCount %d\n",
	       DeviceExt->StorageDevice->Header.RefCount);
	assert(DeviceExt->StorageDevice->Header.RefCount == 1);
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
    DPRINT("Fcb %p Ccb %p\n", Fcb, Ccb);

    if (Fcb == NULL) {
	return STATUS_SUCCESS;
    }

    BOOLEAN IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);
    DPRINT("IsVolume %d\n", IsVolume);

    if (Ccb) {
	FatDestroyCcb(Ccb);
    }

    /* Nothing to do for volume file object or FAT file object. Otherwise,
     * release the FCB, which will likely cause its deletion. */
    if (!BooleanFlagOn(Fcb->Flags, FCB_IS_FAT | FCB_IS_VOLUME)) {
	/* If cache is still initialized, we need to release it here. This only affects
	 * directories.
	 *
	 * TODO: This seems to leak the FCB refcount since FatFcbInitializeCacheFromVolume
	 * increased it when initializing caching. The overall FCB refcounting of the
	 * ReactOS vfatfs driver (which we took our code from) is very much unclear.
	 * I should have used the Microsoft fastfat code at the beginning, but now it's
	 * too late to change :(. */
	if (Fcb->OpenHandleCount == 0 && BooleanFlagOn(Fcb->Flags, FCB_CACHE_INITIALIZED)) {
	    PFILE_OBJECT FcbFileObject;
	    FcbFileObject = Fcb->FileObject;
	    if (FcbFileObject != NULL) {
		Fcb->FileObject = NULL;
		CcUninitializeCacheMap(FcbFileObject, NULL);
		ClearFlag(Fcb->Flags, FCB_CACHE_INITIALIZED);
		ObDereferenceObject(FcbFileObject);
	    }
	}

	FatReleaseFcb(DeviceExt, Fcb);
	Fcb->Flags |= FCB_CLOSED;

    }

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
