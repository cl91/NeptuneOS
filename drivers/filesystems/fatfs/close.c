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

VOID FatCommonCloseFile(PDEVICE_EXTENSION DeviceExt, PFATFCB pFcb)
{
    /* Nothing to do for volumes or for the FAT file object */
    if (BooleanFlagOn(pFcb->Flags, FCB_IS_FAT | FCB_IS_VOLUME)) {
	return;
    }

    /* If cache is still initialized, release it
     * This only affects directories
     */
    if (pFcb->OpenHandleCount == 0
	&& BooleanFlagOn(pFcb->Flags, FCB_CACHE_INITIALIZED)) {
	PFILE_OBJECT tmpFileObject;
	tmpFileObject = pFcb->FileObject;
	if (tmpFileObject != NULL) {
	    pFcb->FileObject = NULL;
	    CcUninitializeCacheMap(tmpFileObject, NULL, NULL);
	    ClearFlag(pFcb->Flags, FCB_CACHE_INITIALIZED);
	    ObDereferenceObject(tmpFileObject);
	}
    }
#ifdef KDBG
    pFcb->Flags |= FCB_CLOSED;
#endif

    /* Release the FCB, we likely cause its deletion */
    FatReleaseFCB(DeviceExt, pFcb);
}

VOID NTAPI FatCloseWorker(IN PDEVICE_OBJECT DeviceObject, IN PVOID Context)
{
    PLIST_ENTRY Entry;
    PFATFCB pFcb;
    PDEVICE_EXTENSION Vcb;
    PFAT_CLOSE_CONTEXT CloseContext;
    BOOLEAN ConcurrentDeletion;

    /* Start removing work items */
    ExAcquireFastMutex(&FatGlobalData->CloseMutex);
    while (!IsListEmpty(&FatGlobalData->CloseListHead)) {
	Entry = RemoveHeadList(&FatGlobalData->CloseListHead);
	CloseContext =
	    CONTAINING_RECORD(Entry, FAT_CLOSE_CONTEXT, CloseListEntry);

	/* One less */
	--FatGlobalData->CloseCount;
	/* Reset its entry to detect concurrent deletions */
	InitializeListHead(&CloseContext->CloseListEntry);
	ExReleaseFastMutex(&FatGlobalData->CloseMutex);

	/* Get the elements */
	Vcb = CloseContext->Vcb;
	pFcb = CloseContext->Fcb;
	ExAcquireResourceExclusiveLite(&Vcb->DirResource, TRUE);
	/* If it didn't got deleted in between */
	if (BooleanFlagOn(pFcb->Flags, FCB_DELAYED_CLOSE)) {
	    /* Close it! */
	    DPRINT("Late closing: %wZ\n", &pFcb->PathNameU);
	    ClearFlag(pFcb->Flags, FCB_DELAYED_CLOSE);
	    pFcb->CloseContext = NULL;
	    FatCommonCloseFile(Vcb, pFcb);
	    ConcurrentDeletion = FALSE;
	} else {
	    /* Otherwise, mark not to delete it */
	    ConcurrentDeletion = TRUE;
	}
	ExReleaseResourceLite(&Vcb->DirResource);

	/* If we were the fastest, delete the context */
	if (!ConcurrentDeletion) {
	    ExFreeToPagedLookasideList(&FatGlobalData->
				       CloseContextLookasideList,
				       CloseContext);
	}

	/* Lock again the list */
	ExAcquireFastMutex(&FatGlobalData->CloseMutex);
    }

    /* We're done, bye! */
    FatGlobalData->CloseWorkerRunning = FALSE;
    ExReleaseFastMutex(&FatGlobalData->CloseMutex);
}

NTSTATUS FatPostCloseFile(PDEVICE_EXTENSION DeviceExt,
			  PFILE_OBJECT FileObject)
{
    PFAT_CLOSE_CONTEXT CloseContext;

    /* Allocate a work item */
    CloseContext =
	ExAllocateFromPagedLookasideList(&FatGlobalData->
					 CloseContextLookasideList);
    if (CloseContext == NULL) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Set relevant fields */
    CloseContext->Vcb = DeviceExt;
    CloseContext->Fcb = FileObject->FsContext;
    CloseContext->Fcb->CloseContext = CloseContext;

    /* Acquire the lock to insert in list */
    ExAcquireFastMutex(&FatGlobalData->CloseMutex);

    /* One more element */
    InsertTailList(&FatGlobalData->CloseListHead,
		   &CloseContext->CloseListEntry);
    ++FatGlobalData->CloseCount;

    /* If we have more than 16 items in list, and no worker thread
     * start a new one
     */
    if (FatGlobalData->CloseCount > 16
	&& !FatGlobalData->CloseWorkerRunning) {
	FatGlobalData->CloseWorkerRunning = TRUE;
	IoQueueWorkItem(FatGlobalData->CloseWorkItem, FatCloseWorker,
			CriticalWorkQueue, NULL);
    }

    /* We're done */
    ExReleaseFastMutex(&FatGlobalData->CloseMutex);

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Closes a file
 */
NTSTATUS FatCloseFile(PDEVICE_EXTENSION DeviceExt, PFILE_OBJECT FileObject)
{
    PFATFCB pFcb;
    PFATCCB pCcb;
    BOOLEAN IsVolume;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("FatCloseFile(DeviceExt %p, FileObject %p)\n",
	   DeviceExt, FileObject);

    /* FIXME : update entry in directory? */
    pCcb = (PFATCCB) (FileObject->FsContext2);
    pFcb = (PFATFCB) (FileObject->FsContext);

    if (pFcb == NULL) {
	return STATUS_SUCCESS;
    }

    IsVolume = BooleanFlagOn(pFcb->Flags, FCB_IS_VOLUME);

    if (pCcb) {
	FatDestroyCCB(pCcb);
    }

    /* If we have to close immediately, or if delaying failed, close */
    if (FatGlobalData->ShutdownStarted
	|| !BooleanFlagOn(pFcb->Flags, FCB_DELAYED_CLOSE)
	|| !NT_SUCCESS(FatPostCloseFile(DeviceExt, FileObject))) {
	FatCommonCloseFile(DeviceExt, pFcb);
    }

    FileObject->FsContext2 = NULL;
    FileObject->FsContext = NULL;
    FileObject->SectionObjectPointer = NULL;

#ifdef ENABLE_SWAPOUT
    if (IsVolume && DeviceExt->OpenHandleCount == 0) {
	FatCheckForDismount(DeviceExt, FALSE);
    }
#endif

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
    if (!ExAcquireResourceExclusiveLite
	(&IrpContext->DeviceExt->DirResource,
	 BooleanFlagOn(IrpContext->Flags, IRPCONTEXT_CANWAIT))) {
	return FatMarkIrpContextForQueue(IrpContext);
    }

    Status = FatCloseFile(IrpContext->DeviceExt, IrpContext->FileObject);
    ExReleaseResourceLite(&IrpContext->DeviceExt->DirResource);

    IrpContext->Irp->IoStatus.Information = 0;

    return Status;
}
