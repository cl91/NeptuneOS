/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Reading and writing routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2008-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS *****************************************************************/

/*
 * Return the next cluster in a FAT chain, possibly extending the chain if
 * necessary.
 */
NTSTATUS NextCluster(PDEVICE_EXTENSION DeviceExt, ULONG FirstCluster,
		     PULONG CurrentCluster, BOOLEAN Extend)
{
    if (FirstCluster == 1) {
	(*CurrentCluster) += DeviceExt->FatInfo.SectorsPerCluster;
	return STATUS_SUCCESS;
    }

    if (Extend)
	return GetNextClusterExtend(DeviceExt, (*CurrentCluster),
				    CurrentCluster);
    else
	return GetNextCluster(DeviceExt, (*CurrentCluster),
			      CurrentCluster);
}

NTSTATUS OffsetToCluster(PDEVICE_EXTENSION DeviceExt, ULONG FirstCluster,
			 ULONG FileOffset, PULONG Cluster, BOOLEAN Extend)
{
    DPRINT("OffsetToCluster(DeviceExt %p, FirstCluster %x, "
	   "FileOffset %x, Cluster %p, Extend %d)\n", DeviceExt,
	   FirstCluster, FileOffset, Cluster, Extend);

    if (FirstCluster == 0) {
	DPRINT("OffsetToCluster is called with FirstCluster = 0\n");
	ASSERT(FALSE);
    }

    PFATINFO FatInfo = &DeviceExt->FatInfo;
    if (FirstCluster == 1) {
	/* This is the root directory of a FAT12 or FAT16 volume. */
	*Cluster = FatInfo->RootStart + FileOffset
	    / FatInfo->BytesPerCluster * FatInfo->SectorsPerCluster;
	return STATUS_SUCCESS;
    }

    ULONG CurrentCluster = FirstCluster;
    if (Extend) {
	for (ULONG i = 0; i < FileOffset / FatInfo->BytesPerCluster; i++) {
	    NTSTATUS Status = GetNextClusterExtend(DeviceExt, CurrentCluster,
						   &CurrentCluster);
	    if (!NT_SUCCESS(Status))
		return Status;
	}
	*Cluster = CurrentCluster;
    } else {
	for (ULONG i = 0; i < FileOffset / FatInfo->BytesPerCluster; i++) {
	    NTSTATUS Status = GetNextCluster(DeviceExt, CurrentCluster,
					     &CurrentCluster);
	    if (!NT_SUCCESS(Status))
		return Status;
	}
	*Cluster = CurrentCluster;
    }
    return STATUS_SUCCESS;
}

/*
 * If the IRP is an MDL read, call the cache manager to handle the MDL read.
 * Otherwise, forward the IO to the underlying disk.
 */
static NTSTATUS FatForwardReadIrp(PDEVICE_EXTENSION DeviceExt, PIRP Irp)
{
    ASSERT(DeviceExt);
    ASSERT(DeviceExt->VolumeFcb);
    ASSERT(Irp);
    ASSERT(!Irp->MdlAddress);
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(Stack);
    ASSERT(Stack->MajorFunction == IRP_MJ_READ);
    if (Stack->MinorFunction == IRP_MN_MDL) {
	/* The MDL chain will be freed when wdm.dll!IopDeleteIrp deletes Irp->MdlAddress
	 * so we don't need to call CcMdlReadComplete manually. */
	return CcMdlRead(DeviceExt->VolumeFcb->FileObject, &Stack->Parameters.Read.ByteOffset,
			 Stack->Parameters.Read.Length, &Irp->MdlAddress, &Irp->IoStatus);
    } else {
	return IoCallDriver(DeviceExt->StorageDevice, Irp);
    }
}

typedef struct _DISK_IO_REQUEST {
    PIRP Irp;
    LIST_ENTRY Link;
} DISK_IO_REQUEST, *PDISK_IO_REQUEST;

/* Traverse through the FAT using the cache manager and construct associated
 * IRPs. Pass these associated IRPs to the underlying storage device driver.
 * The master IRP will be automatically completed once all associated IRPs
 * are completed. */
static NTSTATUS FatReadWriteDisk(IN PFAT_IRP_CONTEXT IrpContext,
				 IN ULONG StartOffset,
				 IN ULONG Length,
				 IN ULONG FirstCluster,
				 IN BOOLEAN Write)
{
    PDEVICE_EXTENSION DeviceExt = IrpContext->DeviceExt;
    PIO_STACK_LOCATION Stack = IrpContext->Stack;
    ULONG BytesPerSector = DeviceExt->FatInfo.BytesPerSector;
    ASSERT(BytesPerSector);
    ULONG BytesPerCluster = DeviceExt->FatInfo.BytesPerCluster;
    ASSERT(BytesPerCluster);
    assert(!(StartOffset & (BytesPerCluster - 1)));

    LIST_ENTRY ReqList;
    InitializeListHead(&ReqList);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    /* First find the cluster number corresponding to the starting offset. */
    ULONG CurrentCluster = FirstCluster;
    Status = OffsetToCluster(DeviceExt, FirstCluster, StartOffset,
			     &CurrentCluster, FALSE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    BOOLEAN First = TRUE;
    ULONG ProcessedLength = 0;
    while (ProcessedLength < Length && CurrentCluster != 0xFFFFFFFF) {
	ULONG StartCluster = CurrentCluster;
	LARGE_INTEGER VolumeOffset = {
	    .QuadPart = ClusterToSector(DeviceExt, StartCluster) * BytesPerSector
	};
	ULONG ClusterCount = 0;

	do {
	    ClusterCount++;
	    Status = NextCluster(DeviceExt, FirstCluster, &CurrentCluster, FALSE);
	    if (!NT_SUCCESS(Status)) {
		goto ByeBye;
	    }
	} while ((StartCluster + ClusterCount == CurrentCluster) &&
		 (Length - ProcessedLength > ClusterCount * BytesPerCluster));
	DPRINT("StartCluster %08x, NextCluster %08x, ClusterCount 0x%x, "
	       "VolumeOffset 0x%llx\n", StartCluster, CurrentCluster,
	       ClusterCount, VolumeOffset.QuadPart);

	/* We will reuse the main IRP for the first disk request. */
	if (First) {
	    if (Write) {
		DPRINT("Reusing master WRITE IRP BO,LEN 0x%llx 0x%x --> 0x%llx 0x%x\n",
		       Stack->Parameters.Write.ByteOffset.QuadPart,
		       Stack->Parameters.Write.Length,
		       VolumeOffset.QuadPart, ClusterCount * BytesPerCluster);
		Stack->Parameters.Write.ByteOffset = VolumeOffset;
		Stack->Parameters.Write.Length = ClusterCount * BytesPerCluster;
	    } else {
		DPRINT("Reusing master READ IRP BO,LEN 0x%llx 0x%x --> 0x%llx 0x%x\n",
		       Stack->Parameters.Read.ByteOffset.QuadPart,
		       Stack->Parameters.Read.Length,
		       VolumeOffset.QuadPart, ClusterCount * BytesPerCluster);
		Stack->Parameters.Read.ByteOffset = VolumeOffset;
		Stack->Parameters.Read.Length = ClusterCount * BytesPerCluster;
	    }
	    First = FALSE;
	} else {
	    PVOID Buffer = (PUCHAR)IrpContext->Irp->UserBuffer + ProcessedLength;
	    DPRINT("Building associated IRP bo,len == 0x%llx 0x%x buffer %p\n",
		   VolumeOffset.QuadPart, ClusterCount * BytesPerCluster, Buffer);
	    ASSERT(IS_ALIGNED64(VolumeOffset.QuadPart, BytesPerCluster));
	    PDISK_IO_REQUEST Req = ExAllocatePool(sizeof(DISK_IO_REQUEST));
	    if (!Req) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto ByeBye;
	    }
	    InsertTailList(&ReqList, &Req->Link);
	    Req->Irp = IoBuildAsynchronousFsdRequest(Write ? IRP_MJ_WRITE : IRP_MJ_READ,
						     DeviceExt->StorageDevice, Buffer,
						     ClusterCount * BytesPerCluster,
						     &VolumeOffset);
	    if (!Req->Irp) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto ByeBye;
	    }
	    Req->Irp->MasterIrp = IrpContext->Irp;
	}
	ProcessedLength += ClusterCount * BytesPerCluster;
    }

    LoopOverList(Req, &ReqList, DISK_IO_REQUEST, Link) {
	IoCallDriver(DeviceExt->StorageDevice, Req->Irp);
	Req->Irp = NULL;
    }
    IoCallDriver(DeviceExt->StorageDevice, IrpContext->Irp);
    return STATUS_IRP_FORWARDED;

ByeBye:
    LoopOverList(Req, &ReqList, DISK_IO_REQUEST, Link) {
	if (Req->Irp) {
	    IoFreeIrp(Req->Irp);
	}
	ExFreePool(Req);
    }
    return Status;
}

/*
 * FUNCTION: Reads data from a file
 */
NTSTATUS FatRead(PFAT_IRP_CONTEXT IrpContext)
{
    ASSERT(IrpContext);
    DPRINT("FatRead(IrpContext %p)\n", IrpContext);
    ASSERT(IrpContext->DeviceObject);

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    /* This request is not allowed on the main device object */
    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	DPRINT("FatRead is called with the main device object.\n");
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto ByeBye;
    }

    PDEVICE_EXTENSION DeviceExt = IrpContext->DeviceExt;
    ASSERT(DeviceExt);
    ASSERT(IrpContext->FileObject);
    PFATFCB Fcb = IrpContext->FileObject->FsContext;
    ASSERT(Fcb);
    PIO_STACK_LOCATION Stack = IrpContext->Stack;
    ASSERT(Stack);
    PFATINFO FatInfo = &DeviceExt->FatInfo;
    ULONG BytesPerSector = FatInfo->BytesPerSector;
    ASSERT(BytesPerSector);
    ULONG BytesPerCluster = FatInfo->BytesPerCluster;
    ASSERT(BytesPerCluster);

    ULONG64 ByteOffset = Stack->Parameters.Read.ByteOffset.QuadPart;
    ULONG Length = Stack->Parameters.Read.Length;
    ULONG64 FileSize = Fcb->Base.FileSizes.FileSize.QuadPart;

    DPRINT("'%wZ', ReadOffset: 0x%llx, ReadLength 0x%x. FileLength 0x%llx\n",
	   &Fcb->PathNameU, ByteOffset, Length, FileSize);

    /* This should not happen, but we will allow it nonetheless. */
    if (Length == 0) {
	DPRINT("WARNING: Reading a length of zero!\n");
	IrpContext->Irp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
	goto ByeBye;
    }

    BOOLEAN IsPageFile = BooleanFlagOn(Fcb->Flags, FCB_IS_PAGE_FILE);
    BOOLEAN IsFatFile = BooleanFlagOn(Fcb->Flags, FCB_IS_FAT);
    BOOLEAN IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);

    /* Fatfs does not support files larger than 4GB. */
    if (ByteOffset > 0xFFFFFFFFULL && !IsVolume) {
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    if (ByteOffset + Length > FileSize) {
	IrpContext->Irp->IoStatus.Information = 0;
	Status = STATUS_END_OF_FILE;
	goto ByeBye;
    }

    if (ByteOffset & (BytesPerCluster - 1)) {
	/* Read must be cluster aligned. */
	DPRINT("Unaligned read: cluster size = 0x%x\n", BytesPerCluster);
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    /* The page file is always placed at the beginning of the data region, so
     * if this is a read of the page file, simply increment the byte offset. */
    if (IsPageFile) {
	Stack->Parameters.Read.ByteOffset.QuadPart += FatInfo->DataStart * BytesPerSector;
	DPRINT("Read from page file, disk offset %I64x\n",
	       Stack->Parameters.Read.ByteOffset.QuadPart);
    }

    /* Likewise, if this is a read of the FAT, simply increment the byte offset. */
    if (IsFatFile) {
	Stack->Parameters.Read.ByteOffset.QuadPart += FatInfo->FatStart * BytesPerSector;
	DPRINT("Reading the FAT file, disk offset 0x%llx\n",
	       Stack->Parameters.Read.ByteOffset.QuadPart);
    }

    /* Record the read statistics. */
    if (IsVolume) {
	FatAddToStat(DeviceExt, Base.MetaDataReads, 1);
	FatAddToStat(DeviceExt, Base.MetaDataReadBytes, Length);
    } else {
	FatAddToStat(DeviceExt, Fat.NonCachedReads, 1);
	FatAddToStat(DeviceExt, Fat.NonCachedReadBytes, Length);
    }

    if (IsVolume) {
	/* In the cases of a volume file read, simply pass the read request
	 * to the underlying storage device driver. */
	return IoCallDriver(DeviceExt->StorageDevice, IrpContext->Irp);
    } else if (IsPageFile || IsFatFile) {
	/* For page file or FAT file read, if MDL read is specified, go through
	 * Cc to do the read. Otherwise simply pass on to the storage driver. */
	return FatForwardReadIrp(DeviceExt, IrpContext->Irp);
    }

    /* Get the first cluster of the file. If the first cluster is one, we
     * are reading the root directory in a FAT12/16 drive, in which case we
     * can simply pass the request to the underlying disk driver directly. */
    ULONG FirstCluster = FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry);
    if (FirstCluster == 1) {
	if (ByteOffset + Length > FatInfo->RootDirectorySectors * BytesPerSector) {
	    Length = FatInfo->RootDirectorySectors * BytesPerSector - ByteOffset;
	}
	ByteOffset += FatInfo->RootStart * BytesPerSector;

	Stack->Parameters.Read.ByteOffset.QuadPart = ByteOffset;
	Stack->Parameters.Read.Length = Length;
	return FatForwardReadIrp(DeviceExt, IrpContext->Irp);
    }

    Status = FatReadWriteDisk(IrpContext, (ULONG)ByteOffset, Length, FirstCluster, FALSE);

ByeBye:
    DPRINT("Completing IRP with status 0x%08x\n", Status);
    IrpContext->Irp->IoStatus.Status = Status;
    return Status;
}

/*
 * FUNCTION: Writes data to a file
 */
NTSTATUS FatWrite(PFAT_IRP_CONTEXT *pIrpContext)
{
    PFAT_IRP_CONTEXT IrpContext = *pIrpContext;

    ASSERT(IrpContext);
    DPRINT("FatWrite(IrpContext %p)\n", IrpContext);
    ASSERT(IrpContext->DeviceObject);

    // This request is not allowed on the main device object
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	DPRINT("FatWrite is called with the main device object.\n");
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto ByeBye;
    }

    PDEVICE_EXTENSION DeviceExt = IrpContext->DeviceExt;
    ASSERT(DeviceExt);
    ASSERT(IrpContext->FileObject);
    PFATFCB Fcb = IrpContext->FileObject->FsContext;
    ASSERT(Fcb);
    PIO_STACK_LOCATION Stack = IrpContext->Stack;
    ASSERT(Stack);

    BOOLEAN IsPageFile = BooleanFlagOn(Fcb->Flags, FCB_IS_PAGE_FILE);
    BOOLEAN IsFatFile = BooleanFlagOn(Fcb->Flags, FCB_IS_FAT);
    BOOLEAN IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);

    DPRINT("<%wZ>\n", &Fcb->PathNameU);

    /* We don't allow writing to the volume file, the FAT file, or the page file as
     * writing to these file objects is done exclusively through the cache manager. */
    if (IsVolume || IsFatFile || IsPageFile) {
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto ByeBye;
    }

    LARGE_INTEGER OldFileSize = Fcb->Base.FileSizes.FileSize;
    LARGE_INTEGER ByteOffset = Stack->Parameters.Write.ByteOffset;

    ULONG BytesPerCluster = DeviceExt->FatInfo.BytesPerCluster;
    if (ByteOffset.LowPart & (BytesPerCluster - 1)) {
	/* Write must be cluster aligned. */
	DPRINT("Unaligned read: cluster size = 0x%x\n", BytesPerCluster);
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    LARGE_INTEGER NewFileSize = OldFileSize;
    ULONG Length = Stack->Parameters.Write.Length;
    if (ByteOffset.QuadPart + Length > OldFileSize.QuadPart) {
	NewFileSize.QuadPart = ByteOffset.QuadPart + Length;
    }

    if (Length == 0) {
	/* Update last write time */
	IrpContext->Irp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
	goto Metadata;
    }

    /* Fatfs does not support files larger than 4GB. */
    if (NewFileSize.HighPart) {
	Status = STATUS_FILE_SYSTEM_LIMITATION;
	goto ByeBye;
    }

    ULONG FirstCluster = FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry);
    if (FirstCluster == 1) {
	/* It is illegal to expand the root directory on FAT12 and FAT16. */
	Status = STATUS_END_OF_FILE;
	goto ByeBye;
    }

    if (NewFileSize.QuadPart != OldFileSize.QuadPart) {
	assert(NewFileSize.QuadPart > OldFileSize.QuadPart);
	Status = FatSetFileSizeInformation(IrpContext->FileObject, Fcb,
					   DeviceExt, &NewFileSize);
	if (!NT_SUCCESS(Status)) {
	    goto ByeBye;
	}
    }

    FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedWrites, 1);
    FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedWriteBytes, Length);

    Status = FatReadWriteDisk(IrpContext, ByteOffset.LowPart, Length, FirstCluster, TRUE);

Metadata:
    if (!FatFcbIsDirectory(Fcb)) {
	LARGE_INTEGER SystemTime;

	// set dates and times
	NtQuerySystemTime(&SystemTime);
	if (FatVolumeIsFatX(DeviceExt)) {
	    FsdSystemTimeToDosDateTime(DeviceExt, &SystemTime,
				       &Fcb->Entry.FatX.UpdateDate,
				       &Fcb->Entry.FatX.UpdateTime);
	    Fcb->Entry.FatX.AccessDate = Fcb->Entry.FatX.UpdateDate;
	    Fcb->Entry.FatX.AccessTime = Fcb->Entry.FatX.UpdateTime;
	} else {
	    FsdSystemTimeToDosDateTime(DeviceExt, &SystemTime,
				       &Fcb->Entry.Fat.UpdateDate,
				       &Fcb->Entry.Fat.UpdateTime);
	    Fcb->Entry.Fat.AccessDate = Fcb->Entry.Fat.UpdateDate;
	}
	/* Set date and times to dirty */
	Fcb->Flags |= FCB_IS_DIRTY;

	/* Time to notify the OS */
	FatReportChange(DeviceExt, Fcb, FILE_NOTIFY_CHANGE_LAST_WRITE |
			FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE,
			FILE_ACTION_MODIFIED);
    }

ByeBye:
    DPRINT("%x\n", Status);
    IrpContext->Irp->IoStatus.Status = Status;
    if (NT_SUCCESS(Status)) {
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;
    }
    return Status;
}
