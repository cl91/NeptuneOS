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
    PFATFCB Fcb;
    PFATCCB pCcb;
    BOOLEAN IsVolume;
    PDEVICE_EXTENSION DeviceExt = IrpContext->DeviceExt;
    PFILE_OBJECT FileObject = IrpContext->FileObject;
    BOOLEAN Deleted = FALSE;

    DPRINT("FatCleanupFile(DeviceExt %p, FileObject %p)\n",
	   IrpContext->DeviceExt, FileObject);

    /* FIXME: handle file/directory deletion here */
    Fcb = (PFATFCB)FileObject->FsContext;
    if (!Fcb)
	return FALSE;

    IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);
    if (IsVolume) {
	Fcb->OpenHandleCount--;
	DeviceExt->OpenHandleCount--;

	if (Fcb->OpenHandleCount != 0) {
	    IoRemoveShareAccess(FileObject, &Fcb->FcbShareAccess);
	}
    } else {
	pCcb = FileObject->FsContext2;
	if (BooleanFlagOn(pCcb->Flags, CCB_DELETE_ON_CLOSE)) {
	    Fcb->Flags |= FCB_DELETE_PENDING;
	}

	/* Notify about the cleanup */
	FsRtlNotifyCleanup(FileObject);

	Fcb->OpenHandleCount--;
	DeviceExt->OpenHandleCount--;

	if (BooleanFlagOn(Fcb->Flags, FCB_IS_DIRTY)) {
	    FatUpdateEntry(DeviceExt, Fcb);
	}

	if (BooleanFlagOn(Fcb->Flags, FCB_DELETE_PENDING) &&
	    Fcb->OpenHandleCount == 0) {
	    if (FatFcbIsDirectory(Fcb) &&
		!FatIsDirectoryEmpty(DeviceExt, Fcb)) {
		Fcb->Flags &= ~FCB_DELETE_PENDING;
	    } else {
		PFILE_OBJECT tmpFileObject;
		tmpFileObject = Fcb->FileObject;
		if (tmpFileObject != NULL) {
		    Fcb->FileObject = NULL;
		    CcUninitializeCacheMap(tmpFileObject, NULL);
		    ClearFlag(Fcb->Flags, FCB_CACHE_INITIALIZED);
		    ObDereferenceObject(tmpFileObject);
		}

		Fcb->Base.FileSizes.ValidDataLength.QuadPart = 0;
		Fcb->Base.FileSizes.FileSize.QuadPart = 0;
		Fcb->Base.FileSizes.AllocationSize.QuadPart = 0;
	    }
	}

	/* Uninitialize the cache (should be done even if caching
	 * was never initialized) */
	CcUninitializeCacheMap(FileObject, &Fcb->Base.FileSizes.FileSize);

	if (BooleanFlagOn(Fcb->Flags, FCB_DELETE_PENDING) &&
	    Fcb->OpenHandleCount == 0) {
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
#ifdef KDBG
	Fcb->Flags |= FCB_CLEANED_UP;
#endif
    }

#ifdef ENABLE_SWAPOUT
    if (IsVolume && BooleanFlagOn(DeviceExt->Flags, VCB_DISMOUNT_PENDING)) {
	Deleted = FatCheckForDismount(DeviceExt, TRUE);
    }
#endif

    return Deleted;
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
