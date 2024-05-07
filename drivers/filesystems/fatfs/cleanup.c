/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Cleanup routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2014-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS ****************************************************************/

/*
 * FUNCTION: Cleans up after a file has been closed.
 * Returns whether the device was deleted
 */
static BOOLEAN FatCleanupFile(PFAT_IRP_CONTEXT IrpContext)
{
    PDEVICE_EXTENSION DeviceExt = IrpContext->DeviceExt;
    PFILE_OBJECT FileObject = IrpContext->FileObject;

    DPRINT("FatCleanupFile(DeviceExt %p, FileObject %p)\n",
	   IrpContext->DeviceExt, FileObject);

    /* FIXME: handle file/directory deletion here */
    PFATFCB Fcb = (PFATFCB)FileObject->FsContext;
    if (!Fcb)
	return FALSE;

    BOOLEAN IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);
    if (IsVolume) {
	Fcb->OpenHandleCount--;
	DeviceExt->OpenHandleCount--;

	if (Fcb->OpenHandleCount != 0) {
	    IoRemoveShareAccess(FileObject, &Fcb->FcbShareAccess);
	}
    } else {
	PFATCCB Ccb = FileObject->FsContext2;
	if (BooleanFlagOn(Ccb->Flags, CCB_DELETE_ON_CLOSE)) {
	    Fcb->Flags |= FCB_DELETE_PENDING;
	}

	/* Notify about the cleanup */
	FsRtlNotifyCleanup(FileObject);

	Fcb->OpenHandleCount--;
	DeviceExt->OpenHandleCount--;

	if (BooleanFlagOn(Fcb->Flags, FCB_IS_DIRTY)) {
	    FatUpdateEntry(DeviceExt, Fcb);
	}

	/* If the directory was marked for deletion but it's not empty, don't
	 * actually delete it. */
        if (FatFcbIsDirectory(Fcb) && !FatIsDirectoryEmpty(DeviceExt, Fcb)) {
	    Fcb->Flags &= ~FCB_DELETE_PENDING;
	}

	/* If the file was marked for deletion and the open handle count has reached
	 * zero, delete the file from the disk. */
	if (BooleanFlagOn(Fcb->Flags, FCB_DELETE_PENDING) && !Fcb->OpenHandleCount) {
	    PFILE_OBJECT MasterFileObject = Fcb->FileObject;
	    if (MasterFileObject != NULL) {
		Fcb->FileObject = NULL;
		CcUninitializeCacheMap(MasterFileObject, NULL);
		ClearFlag(Fcb->Flags, FCB_CACHE_INITIALIZED);
		/* The file object itself will be dereferenced (and hence deleted)
		 * in FatCloseFile, as a result of a CloseFile server message. */
	    }

	    Fcb->Base.FileSizes.ValidDataLength.QuadPart = 0;
	    Fcb->Base.FileSizes.FileSize.QuadPart = 0;
	    Fcb->Base.FileSizes.AllocationSize.QuadPart = 0;

            FatDelEntry(DeviceExt, Fcb, NULL);

	    FatReportChange(DeviceExt, Fcb,
			    (FatFcbIsDirectory(Fcb) ? FILE_NOTIFY_CHANGE_DIR_NAME :
			     FILE_NOTIFY_CHANGE_FILE_NAME),
			    FILE_ACTION_REMOVED);
	}

	if (Fcb->OpenHandleCount != 0) {
	    IoRemoveShareAccess(FileObject, &Fcb->FcbShareAccess);
	}

	FileObject->Flags |= FO_CLEANUP_COMPLETE;
	Fcb->Flags |= FCB_CLEANED_UP;
    }

    if (IsVolume && BooleanFlagOn(DeviceExt->Flags, VCB_DISMOUNT_PENDING)) {
	return FatCheckForDismount(DeviceExt, TRUE);
    }
    return FALSE;
}

/*
 * FUNCTION: Cleans up after a file has been closed.
 */
NTSTATUS FatCleanup(PFAT_IRP_CONTEXT IrpContext)
{
    DPRINT("FatCleanup(DeviceObject %p, Irp %p)\n",
	   IrpContext->DeviceObject, IrpContext->Irp);

    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	IrpContext->Irp->IoStatus.Information = 0;
	return STATUS_SUCCESS;
    }

    FatCleanupFile(IrpContext);

    IrpContext->Irp->IoStatus.Information = 0;
    return STATUS_SUCCESS;
}
