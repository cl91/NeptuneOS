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

typedef struct _DISK_READ_REQUEST {
    PIRP Irp;
    LIST_ENTRY Link;
} DISK_READ_REQUEST, *PDISK_READ_REQUEST;

/*
 * FUNCTION: Reads data from a file
 */
NTSTATUS FatRead(PFAT_IRP_CONTEXT IrpContext)
{
    ASSERT(IrpContext);
    DPRINT("FatRead(IrpContext %p)\n", IrpContext);
    ASSERT(IrpContext->DeviceObject);

    LIST_ENTRY ReqList;
    InitializeListHead(&ReqList);
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

    if ((ByteOffset % BytesPerCluster) ||
	(ByteOffset + Length < FileSize && (Length % BytesPerCluster))) {
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

    /* For normal file reads, we first find the cluster number for the starting
     * offset of the requested read operation. */
    ULONG CurrentCluster = FirstCluster;
    Status = OffsetToCluster(DeviceExt, FirstCluster, ByteOffset,
			     &CurrentCluster, FALSE);
    if (!NT_SUCCESS(Status)) {
	goto ByeBye;
    }

    IrpContext->RefCount = 1;

    /* Traverse through the FAT using the cache manager and construct associated
     * IRPs. Pass these associated IRPs to the underlying storage device driver.
     * The master IRP will be automatically completed once all associated IRPs
     * are completed. */
    BOOLEAN First = TRUE;
    ULONG ProcessedLength = 0;
    while (ProcessedLength < Length && CurrentCluster != 0xFFFFFFFF) {
	ULONG StartCluster = CurrentCluster;
	ULONG ClusterCount = 0;
	do {
	    ClusterCount++;
	    Status = NextCluster(DeviceExt, FirstCluster, &CurrentCluster, FALSE);
	    if (!NT_SUCCESS(Status)) {
		goto ByeBye;
	    }
	} while (StartCluster + ClusterCount == CurrentCluster &&
		 ProcessedLength + ClusterCount * BytesPerCluster < Length);
	DPRINT("StartCluster %08x, NextCluster %08x, ClusterCount 0x%x\n",
	       StartCluster, CurrentCluster, ClusterCount);

	ULONG BytesToRead = ClusterCount * BytesPerCluster;
	LARGE_INTEGER ReadOffset = {
	    .QuadPart = ClusterToSector(DeviceExt, StartCluster) * BytesPerSector
	};
	/* We will reuse the main IRP for the first disk request. */
	if (First) {
	    DPRINT("Reusing master IRP BO,LEN 0x%llx 0x%x --> 0x%llx 0x%x\n",
		   Stack->Parameters.Read.ByteOffset.QuadPart, Stack->Parameters.Read.Length,
		   ReadOffset.QuadPart, BytesToRead);
	    Stack->Parameters.Read.ByteOffset = ReadOffset;
	    Stack->Parameters.Read.Length = BytesToRead;
	    First = FALSE;
	} else {
	    PDISK_READ_REQUEST Req = ExAllocatePool(sizeof(DISK_READ_REQUEST));
	    if (!Req) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto ByeBye;
	    }
	    InsertTailList(&ReqList, &Req->Link);
	    PVOID Buffer = (PUCHAR)IrpContext->Irp->UserBuffer + ProcessedLength;
	    Req->Irp = IoBuildAsynchronousFsdRequest(IRP_MJ_READ,
						     DeviceExt->StorageDevice,
						     Buffer, BytesToRead, &ReadOffset);
	    if (!Req->Irp) {
		Status = STATUS_INSUFFICIENT_RESOURCES;
		goto ByeBye;
	    }
	    DPRINT("Building associated IRP bo,len == 0x%llx 0x%x buffer %p\n",
		   ReadOffset.QuadPart, BytesToRead, Buffer);
	    Req->Irp->MasterIrp = IrpContext->Irp;
	}
	ProcessedLength += BytesToRead;
    }

    LoopOverList(Req, &ReqList, DISK_READ_REQUEST, Link) {
	IoCallDriver(DeviceExt->StorageDevice, Req->Irp);
	Req->Irp = NULL;
    }
    IoCallDriver(DeviceExt->StorageDevice, IrpContext->Irp);
    Status = STATUS_IRP_FORWARDED;

ByeBye:
    LoopOverList(Req, &ReqList, DISK_READ_REQUEST, Link) {
	if (Req->Irp) {
	    IoFreeIrp(Req->Irp);
	}
	ExFreePool(Req);
    }
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

    /* We don't allow writing to the FAT file (reading is OK). Writing to the
     * FAT is done exclusively through the cache manager to avoid inconsistency. */
    if (IsFatFile) {
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto ByeBye;
    }

    LARGE_INTEGER ByteOffset = Stack->Parameters.Write.ByteOffset;
    if (ByteOffset.LowPart == FILE_WRITE_TO_END_OF_FILE || ByteOffset.HighPart == -1) {
	/* File system drivers are not expected to handle FILE_WRITE_TO_END_OF_FILE. */
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    /* Fatfs does not support files larger than 4GB. */
    if (ByteOffset.HighPart && !IsVolume) {
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    /* The starting offset of the write must be sector aligned */
    PFATINFO FatInfo = &DeviceExt->FatInfo;
    ULONG BytesPerSector = FatInfo->BytesPerSector;
    ASSERT(BytesPerSector);
    if (ByteOffset.LowPart % BytesPerSector) {
	DPRINT("Unaligned write: byte offset %u\n", ByteOffset.LowPart);
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    LARGE_INTEGER OldFileSize = Fcb->Base.FileSizes.FileSize;
    LARGE_INTEGER NewFileSize = OldFileSize;
    ULONG Length = Stack->Parameters.Write.Length;
    if (Length == 0) {
	/* Update last write time */
	IrpContext->Irp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
	goto Metadata;
    }

    /* If the write exceeds the current file size, expand the file size. */
    if (ByteOffset.QuadPart + Length > OldFileSize.QuadPart) {
	if (IsFatFile || IsVolume ||
	    FatDirEntryGetFirstCluster(IrpContext->DeviceExt, &Fcb->Entry) == 1) {
	    /* It is illegal to expand the FAT file, the volume file, or (on FAT12/16)
	     * the root directory. */
	    Status = STATUS_END_OF_FILE;
	    goto ByeBye;
	}

	NewFileSize.QuadPart = ByteOffset.QuadPart + Length;
	Status = FatSetFileSizeInformation(IrpContext->FileObject, Fcb, DeviceExt,
					   &NewFileSize);
	if (!NT_SUCCESS(Status)) {
	    goto ByeBye;
	}
    } else if (Length % BytesPerSector) {
	/* If we are not extending the file size (ie. we are writing to the
	 * middle of the file), then the Length must also be sector aligned. */
	DPRINT("Unaligned write: byte offset 0x%x length 0x%x file size 0x%I64x\n",
	       ByteOffset.LowPart, Length, Fcb->Base.FileSizes.FileSize.QuadPart);
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    if (IsVolume) {
	FatAddToStat(IrpContext->DeviceExt, Base.MetaDataWrites, 1);
	FatAddToStat(IrpContext->DeviceExt, Base.MetaDataWriteBytes, Length);
    } else {
	FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedWrites, 1);
	FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedWriteBytes, Length);
    }

    if (IsPageFile) {
	Stack->Parameters.Write.ByteOffset.QuadPart += FatInfo->DataStart * BytesPerSector;
	DPRINT("Write to page file, disk offset %I64x\n",
	       Stack->Parameters.Write.ByteOffset.QuadPart);
    }

    if (IsPageFile || IsVolume) {
	Status = IoCallDriver(IrpContext->DeviceExt->StorageDevice,
			      IrpContext->Irp);
	return Status;
    }

    ULONG BytesPerCluster = DeviceExt->FatInfo.BytesPerCluster;
    ASSERT(BytesPerCluster);

    ULONG FirstCluster = FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry);
    if (FirstCluster == 1) {
	/* We don't allow writing to the FAT12/16 root directory as this should
	 * be done via the cache manager exclusively to avoid data inconsistency. */
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto ByeBye;
    }

    /* Find the cluster to start the write from */
    ULONG CurrentCluster = FirstCluster;
    Status = OffsetToCluster(DeviceExt, FirstCluster,
			     ROUND_DOWN_32(ByteOffset.LowPart, BytesPerCluster),
			     &CurrentCluster, FALSE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    IrpContext->RefCount = 1;

    BOOLEAN First = TRUE;
    while (Length > 0 && CurrentCluster != 0xffffffff) {
	ULONG StartCluster = CurrentCluster;
	LARGE_INTEGER StartOffset = {
	    .QuadPart = ClusterToSector(DeviceExt, StartCluster) * BytesPerSector
	};
	ULONG BytesDone = 0;
	ULONG ClusterCount = 0;

	do {
	    ClusterCount++;
	    if (First) {
		BytesDone = min(Length,
				BytesPerCluster -
				(ByteOffset.LowPart % BytesPerCluster));
		StartOffset.QuadPart += ByteOffset.LowPart % BytesPerCluster;
		First = FALSE;
	    } else {
		if (Length - BytesDone > BytesPerCluster) {
		    BytesDone += BytesPerCluster;
		} else {
		    BytesDone = Length;
		}
	    }
	    Status = NextCluster(DeviceExt, FirstCluster, &CurrentCluster, FALSE);
	} while ((StartCluster + ClusterCount == CurrentCluster)
		 && NT_SUCCESS(Status) && Length > BytesDone);
	DPRINT("start %08x, next %08x, count %u\n", StartCluster,
	       CurrentCluster, ClusterCount);

	/* TODO: Construct the associated IRPs */
#if 0
	Status = FatWriteDiskPartial(IrpContext, &StartOffset,
				     BytesDone, BufferOffset, FALSE);
	if (!NT_SUCCESS(Status) && Status != STATUS_PENDING) {
	    break;
	}
#endif
	Length -= BytesDone;
	ByteOffset.LowPart += BytesDone;
    }

    Status = STATUS_IRP_FORWARDED;

Metadata:
    if (!IsVolume && !FatFcbIsDirectory(Fcb)) {
	LARGE_INTEGER SystemTime;
	ULONG Filter;

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
	Filter = FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES;
	if (ByteOffset.QuadPart != OldFileSize.QuadPart)
	    Filter |= FILE_NOTIFY_CHANGE_SIZE;

	FatReportChange(DeviceExt, Fcb, Filter, FILE_ACTION_MODIFIED);
    }

ByeBye:
    DPRINT("%x\n", Status);
    IrpContext->Irp->IoStatus.Status = Status;
    if (NT_SUCCESS(Status)) {
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;
    }
    return Status;
}
