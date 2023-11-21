/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Reading and writing routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2008-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/*
 * Uncomment to enable strict verification of cluster/offset pair
 * caching. If this option is enabled you lose all the benefits of
 * the caching and the read/write operations will actually be
 * slower. It's meant only for debugging!!!
 * - Filip Navara, 26/07/2004
 */
/* #define DEBUG_VERIFY_OFFSET_CACHING */

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
    } else {
	if (Extend)
	    return GetNextClusterExtend(DeviceExt, (*CurrentCluster),
					CurrentCluster);
	else
	    return GetNextCluster(DeviceExt, (*CurrentCluster),
				  CurrentCluster);
    }
}

NTSTATUS OffsetToCluster(PDEVICE_EXTENSION DeviceExt, ULONG FirstCluster,
			 ULONG FileOffset, PULONG Cluster, BOOLEAN Extend)
{
    DPRINT("OffsetToCluster(DeviceExt %p, FirstCluster %x,"
	   " FileOffset %x, Cluster %p, Extend %d)\n", DeviceExt,
	   FirstCluster, FileOffset, Cluster, Extend);

    if (FirstCluster == 0) {
	DbgPrint("OffsetToCluster is called with FirstCluster = 0!\n");
	ASSERT(FALSE);
    }

    PFATINFO FatInfo = &DeviceExt->FatInfo;
    if (FirstCluster == 1) {
	/* root of FAT16 or FAT12 */
	*Cluster = FatInfo->RootStart + FileOffset
	    / FatInfo->BytesPerCluster * FatInfo->SectorsPerCluster;
	return STATUS_SUCCESS;
    } else {
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
}

/*
 * FUNCTION: Reads data from a file
 */
static NTSTATUS FatReadFileData(PFAT_IRP_CONTEXT IrpContext, ULONG Length,
				LARGE_INTEGER ReadOffset, PULONG LengthRead)
{
    ULONG CurrentCluster;
    ULONG FirstCluster;
    ULONG StartCluster;
    ULONG ClusterCount;
    LARGE_INTEGER StartOffset;
    PDEVICE_EXTENSION DeviceExt;
    BOOLEAN First = TRUE;
    PFATFCB Fcb;
    NTSTATUS Status;
    ULONG BytesDone;
    ULONG BytesPerSector;
    ULONG BytesPerCluster;
    ULONG LastCluster;
    ULONG LastOffset;

    /* PRECONDITION */
    ASSERT(IrpContext);
    DeviceExt = IrpContext->DeviceExt;
    ASSERT(DeviceExt);
    ASSERT(DeviceExt->FatInfo.BytesPerCluster);
    ASSERT(IrpContext->FileObject);
    ASSERT(IrpContext->FileObject->FsContext2 != NULL);

    DPRINT("FatReadFileData(DeviceExt %p, FileObject %p, "
	   "Length %u, ReadOffset 0x%I64x)\n", DeviceExt,
	   IrpContext->FileObject, Length, ReadOffset.QuadPart);

    *LengthRead = 0;

    Fcb = IrpContext->FileObject->FsContext;
    BytesPerSector = DeviceExt->FatInfo.BytesPerSector;
    BytesPerCluster = DeviceExt->FatInfo.BytesPerCluster;

    ASSERT((ReadOffset.QuadPart + Length) <= ROUND_UP_64(Fcb->Base.FileSize.QuadPart,
							 BytesPerSector));
    ASSERT(ReadOffset.u.LowPart % BytesPerSector == 0);
    ASSERT(Length % BytesPerSector == 0);

    /* Is this a read of the FAT? */
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_FAT)) {
	ReadOffset.QuadPart += DeviceExt->FatInfo.FATStart * BytesPerSector;
	Status = FatReadDiskPartial(IrpContext, &ReadOffset, Length, 0, TRUE);

	if (NT_SUCCESS(Status)) {
	    *LengthRead = Length;
	} else {
	    DPRINT1("FAT reading failed, Status %x\n", Status);
	}
	return Status;
    }

    /* Is this a read of the Volume ? */
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME)) {
	Status = FatReadDiskPartial(IrpContext, &ReadOffset, Length, 0, TRUE);
	if (NT_SUCCESS(Status)) {
	    *LengthRead = Length;
	} else {
	    DPRINT1("Volume reading failed, Status %x\n", Status);
	}
	return Status;
    }

    /* Find the first cluster */
    FirstCluster = CurrentCluster = FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry);

    if (FirstCluster == 1) {
	/* Directory of FAT12/16 needs a special handling */
	if (ReadOffset.u.LowPart + Length >
	    DeviceExt->FatInfo.RootDirectorySectors * BytesPerSector) {
	    Length = DeviceExt->FatInfo.RootDirectorySectors * BytesPerSector -
		ReadOffset.u.LowPart;
	}
	ReadOffset.u.LowPart += DeviceExt->FatInfo.RootStart * BytesPerSector;

	/* Fire up the read command */
	Status = FatReadDiskPartial(IrpContext, &ReadOffset, Length, 0, TRUE);
	if (NT_SUCCESS(Status)) {
	    *LengthRead = Length;
	}
	return Status;
    }

    LastCluster = Fcb->LastCluster;
    LastOffset = Fcb->LastOffset;

    /* Find the cluster to start the read from */
    if (LastCluster > 0 && ReadOffset.u.LowPart >= LastOffset) {
	Status = OffsetToCluster(DeviceExt, LastCluster,
				 ROUND_DOWN_32(ReadOffset.u.LowPart, BytesPerCluster)
				 - LastOffset, &CurrentCluster, FALSE);
#ifdef DEBUG_VERIFY_OFFSET_CACHING
	/* DEBUG VERIFICATION */
	ULONG CorrectCluster;
	OffsetToCluster(DeviceExt, FirstCluster,
			ROUND_DOWN_32(ReadOffset.u.LowPart, BytesPerCluster),
			&CorrectCluster, FALSE);
	assert(CorrectCluster == CurrentCluster);
#endif
    } else {
	Status = OffsetToCluster(DeviceExt, FirstCluster,
				 ROUND_DOWN_32(ReadOffset.u.LowPart, BytesPerCluster),
				 &CurrentCluster, FALSE);
    }

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Fcb->LastCluster = CurrentCluster;
    Fcb->LastOffset = ROUND_DOWN_32(ReadOffset.u.LowPart, BytesPerCluster);

    KeInitializeEvent(&IrpContext->Event, NotificationEvent, FALSE);
    IrpContext->RefCount = 1;

    while (Length > 0 && CurrentCluster != 0xffffffff) {
	StartCluster = CurrentCluster;
	StartOffset.QuadPart = ClusterToSector(DeviceExt, StartCluster) * BytesPerSector;
	BytesDone = 0;
	ClusterCount = 0;

	do {
	    ClusterCount++;
	    if (First) {
		BytesDone = min(Length,
				BytesPerCluster - (ReadOffset.u.LowPart % BytesPerCluster));
		StartOffset.QuadPart += ReadOffset.u.LowPart % BytesPerCluster;
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

	Fcb->LastCluster = StartCluster + (ClusterCount - 1);
	Fcb->LastOffset = ROUND_DOWN_32(ReadOffset.u.LowPart, BytesPerCluster) +
	    (ClusterCount - 1) * BytesPerCluster;

	/* Fire up the read command */
	Status = FatReadDiskPartial(IrpContext, &StartOffset, BytesDone, *LengthRead, FALSE);
	if (!NT_SUCCESS(Status) && Status != STATUS_PENDING) {
	    break;
	}
	*LengthRead += BytesDone;
	Length -= BytesDone;
	ReadOffset.u.LowPart += BytesDone;
    }

    if (InterlockedDecrement((PLONG)&IrpContext->RefCount) != 0) {
	KeWaitForSingleObject(&IrpContext->Event, Executive, KernelMode,
			      FALSE, NULL);
    }

    if (NT_SUCCESS(Status) || Status == STATUS_PENDING) {
	if (Length > 0) {
	    Status = STATUS_UNSUCCESSFUL;
	} else {
	    Status = IrpContext->Irp->IoStatus.Status;
	}
    }

    return Status;
}

static NTSTATUS FatWriteFileData(PFAT_IRP_CONTEXT IrpContext,
				 ULONG Length,
				 LARGE_INTEGER WriteOffset)
{
    PDEVICE_EXTENSION DeviceExt;
    PFATFCB Fcb;
    ULONG Count;
    ULONG FirstCluster;
    ULONG CurrentCluster;
    ULONG BytesDone;
    ULONG StartCluster;
    ULONG ClusterCount;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN First = TRUE;
    ULONG BytesPerSector;
    ULONG BytesPerCluster;
    LARGE_INTEGER StartOffset;
    ULONG BufferOffset;
    ULONG LastCluster;
    ULONG LastOffset;

    /* PRECONDITION */
    ASSERT(IrpContext);
    DeviceExt = IrpContext->DeviceExt;
    ASSERT(DeviceExt);
    ASSERT(DeviceExt->FatInfo.BytesPerCluster);
    ASSERT(IrpContext->FileObject);
    ASSERT(IrpContext->FileObject->FsContext2 != NULL);

    Fcb = IrpContext->FileObject->FsContext;
    BytesPerCluster = DeviceExt->FatInfo.BytesPerCluster;
    BytesPerSector = DeviceExt->FatInfo.BytesPerSector;

    DPRINT("FatWriteFileData(DeviceExt %p, FileObject %p, "
	   "Length %u, WriteOffset 0x%I64x), '%wZ'\n", DeviceExt,
	   IrpContext->FileObject, Length, WriteOffset.QuadPart,
	   &Fcb->PathNameU);

    ASSERT(WriteOffset.QuadPart + Length <= Fcb->Base.AllocationSize.QuadPart);
    ASSERT(WriteOffset.u.LowPart % BytesPerSector == 0);
    ASSERT(Length % BytesPerSector == 0);

    /* Is this a write of the volume? */
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME)) {
	Status = FatWriteDiskPartial(IrpContext, &WriteOffset, Length, 0, TRUE);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("Volume writing failed, Status %x\n", Status);
	}
	return Status;
    }

    /* Is this a write to the FAT? */
    if (BooleanFlagOn(Fcb->Flags, FCB_IS_FAT)) {
	WriteOffset.u.LowPart += DeviceExt->FatInfo.FATStart * BytesPerSector;
	IrpContext->RefCount = 1;
	for (Count = 0; Count < DeviceExt->FatInfo.FATCount; Count++) {
	    Status = FatWriteDiskPartial(IrpContext, &WriteOffset, Length, 0, FALSE);
	    if (!NT_SUCCESS(Status) && Status != STATUS_PENDING) {
		DPRINT1("FAT writing failed, Status %x\n", Status);
		break;
	    }
	    WriteOffset.u.LowPart += Fcb->Base.FileSize.u.LowPart;
	}

	if (InterlockedDecrement((PLONG) & IrpContext->RefCount) != 0) {
	    KeWaitForSingleObject(&IrpContext->Event, Executive,
				  KernelMode, FALSE, NULL);
	}

	if (NT_SUCCESS(Status) || Status == STATUS_PENDING) {
	    Status = IrpContext->Irp->IoStatus.Status;
	}
	return Status;
    }

    /*
     * Find the first cluster
     */
    FirstCluster = CurrentCluster = FatDirEntryGetFirstCluster(DeviceExt, &Fcb->Entry);

    if (FirstCluster == 1) {
	ASSERT(WriteOffset.u.LowPart + Length <= DeviceExt->FatInfo.RootDirectorySectors * BytesPerSector);
	// Directory of FAT12/16 needs a special handling
	WriteOffset.u.LowPart += DeviceExt->FatInfo.RootStart * BytesPerSector;
	// Fire up the write command
	Status = FatWriteDiskPartial(IrpContext, &WriteOffset, Length, 0, TRUE);
	return Status;
    }

    LastCluster = Fcb->LastCluster;
    LastOffset = Fcb->LastOffset;

    /*
     * Find the cluster to start the write from
     */
    if (LastCluster > 0 && WriteOffset.u.LowPart >= LastOffset) {
	Status = OffsetToCluster(DeviceExt, LastCluster,
				 ROUND_DOWN_32(WriteOffset.u.LowPart, BytesPerCluster)
				 - LastOffset, &CurrentCluster, FALSE);
#ifdef DEBUG_VERIFY_OFFSET_CACHING
	/* DEBUG VERIFICATION */
	{
	    ULONG CorrectCluster;
	    OffsetToCluster(DeviceExt, FirstCluster,
			    ROUND_DOWN_32(WriteOffset.u.LowPart, BytesPerCluster),
			    &CorrectCluster, FALSE);
	    if (CorrectCluster != CurrentCluster)
		KeBugCheck(FAT_FILE_SYSTEM);
	}
#endif
    } else {
	Status = OffsetToCluster(DeviceExt, FirstCluster,
				 ROUND_DOWN_32(WriteOffset.u.LowPart, BytesPerCluster),
				 &CurrentCluster, FALSE);
    }

    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    Fcb->LastCluster = CurrentCluster;
    Fcb->LastOffset = ROUND_DOWN_32(WriteOffset.u.LowPart, BytesPerCluster);

    IrpContext->RefCount = 1;
    BufferOffset = 0;

    while (Length > 0 && CurrentCluster != 0xffffffff) {
	StartCluster = CurrentCluster;
	StartOffset.QuadPart = ClusterToSector(DeviceExt, StartCluster) * BytesPerSector;
	BytesDone = 0;
	ClusterCount = 0;

	do {
	    ClusterCount++;
	    if (First) {
		BytesDone = min(Length,
				BytesPerCluster -
				(WriteOffset.u.LowPart % BytesPerCluster));
		StartOffset.QuadPart += WriteOffset.u.LowPart % BytesPerCluster;
		First = FALSE;
	    } else {
		if (Length - BytesDone > BytesPerCluster) {
		    BytesDone += BytesPerCluster;
		} else {
		    BytesDone = Length;
		}
	    }
	    Status = NextCluster(DeviceExt, FirstCluster, &CurrentCluster,
				 FALSE);
	} while ((StartCluster + ClusterCount == CurrentCluster)
		 && NT_SUCCESS(Status) && Length > BytesDone);
	DPRINT("start %08x, next %08x, count %u\n", StartCluster,
	       CurrentCluster, ClusterCount);

	Fcb->LastCluster = StartCluster + (ClusterCount - 1);
	Fcb->LastOffset = ROUND_DOWN_32(WriteOffset.u.LowPart, BytesPerCluster) +
	    (ClusterCount - 1) * BytesPerCluster;

	// Fire up the write command
	Status = FatWriteDiskPartial(IrpContext, &StartOffset,
				     BytesDone, BufferOffset, FALSE);
	if (!NT_SUCCESS(Status) && Status != STATUS_PENDING) {
	    break;
	}
	BufferOffset += BytesDone;
	Length -= BytesDone;
	WriteOffset.u.LowPart += BytesDone;
    }

    if (InterlockedDecrement((PLONG) & IrpContext->RefCount) != 0) {
	KeWaitForSingleObject(&IrpContext->Event, Executive, KernelMode, FALSE, NULL);
    }

    if (NT_SUCCESS(Status) || Status == STATUS_PENDING) {
	if (Length > 0) {
	    Status = STATUS_UNSUCCESSFUL;
	} else {
	    Status = IrpContext->Irp->IoStatus.Status;
	}
    }

    return Status;
}

NTSTATUS FatRead(PFAT_IRP_CONTEXT IrpContext)
{
    ASSERT(IrpContext);
    DPRINT("FatRead(IrpContext %p)\n", IrpContext);
    ASSERT(IrpContext->DeviceObject);

    // This request is not allowed on the main device object
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    if (IrpContext->DeviceObject == FatGlobalData->DeviceObject) {
	DPRINT("FatRead is called with the main device object.\n");
	Status = STATUS_INVALID_DEVICE_REQUEST;
	goto ByeBye;
    }

    ASSERT(IrpContext->DeviceExt);
    ASSERT(IrpContext->FileObject);
    PFATFCB Fcb = IrpContext->FileObject->FsContext;
    ASSERT(Fcb);

    BOOLEAN IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);

    if (BooleanFlagOn(Fcb->Flags, FCB_IS_PAGE_FILE)) {
	PFATINFO FatInfo = &IrpContext->DeviceExt->FatInfo;
	IrpContext->Stack->Parameters.Read.ByteOffset.QuadPart += FatInfo->DataStart * FatInfo->BytesPerSector;
	DPRINT("Read from page file, disk offset %I64x\n",
	       IrpContext->Stack->Parameters.Read.ByteOffset.QuadPart);
	Status = IoCallDriver(IrpContext->DeviceExt->StorageDevice,
			      IrpContext->Irp);
	return Status;
    }

    DPRINT("<%wZ>\n", &Fcb->PathNameU);

    LARGE_INTEGER ByteOffset = IrpContext->Stack->Parameters.Read.ByteOffset;
    ULONG Length = IrpContext->Stack->Parameters.Read.Length;
    ULONG BytesPerSector = IrpContext->DeviceExt->FatInfo.BytesPerSector;

    DPRINT("'%wZ', Offset: %u, Length %u\n", &Fcb->PathNameU,
	   ByteOffset.u.LowPart, Length);

    /* Fatfs does not support files larger than 4GB. */
    if (ByteOffset.u.HighPart && !IsVolume) {
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    if (Length == 0) {
	IrpContext->Irp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
	goto ByeBye;
    }

    if (ByteOffset.QuadPart >= Fcb->Base.FileSize.QuadPart) {
	IrpContext->Irp->IoStatus.Information = 0;
	Status = STATUS_END_OF_FILE;
	goto ByeBye;
    }

    if ((ByteOffset.u.LowPart % BytesPerSector) || (Length % BytesPerSector)) {
	// read must be sector aligned
	DPRINT("unaligned read: byte offset %u length %u\n",
	       ByteOffset.u.LowPart, Length);
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    PVOID Buffer = FatGetUserBuffer(IrpContext->Irp, PagingIo);
    if (ByteOffset.QuadPart + Length >
	ROUND_UP_64(Fcb->Base.FileSize.QuadPart, BytesPerSector)) {
	Length = (ULONG)(ROUND_UP_64(Fcb->Base.FileSize.QuadPart,
				     BytesPerSector) - ByteOffset.QuadPart);
    }

    if (!IsVolume) {
	FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedReads, 1);
	FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedReadBytes, Length);
    } else {
	FatAddToStat(IrpContext->DeviceExt, Base.MetaDataReads, 1);
	FatAddToStat(IrpContext->DeviceExt, Base.MetaDataReadBytes, Length);
    }

    ULONG ReturnedLength;
    Status = FatReadFileData(IrpContext, Length, ByteOffset, &ReturnedLength);
    if (NT_SUCCESS(Status)) {
	IrpContext->Irp->IoStatus.Information = ReturnedLength;
    }

ByeBye:
    DPRINT("%x\n", Status);
    IrpContext->Irp->IoStatus.Status = Status;
    if (NT_SUCCESS(Status)) {
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;
    }
    return Status;
}

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

    ASSERT(IrpContext->DeviceExt);
    ASSERT(IrpContext->FileObject);
    PFATFCB Fcb = IrpContext->FileObject->FsContext;
    ASSERT(Fcb);

    BOOLEAN IsVolume = BooleanFlagOn(Fcb->Flags, FCB_IS_VOLUME);
    BOOLEAN IsFAT = BooleanFlagOn(Fcb->Flags, FCB_IS_FAT);

    if (BooleanFlagOn(Fcb->Flags, FCB_IS_PAGE_FILE)) {
	PFATINFO FatInfo = &IrpContext->DeviceExt->FatInfo;
	IrpContext->Stack->Parameters.Write.ByteOffset.QuadPart +=
	    FatInfo->DataStart * FatInfo->BytesPerSector;
	DPRINT("Write to page file, disk offset %I64x\n",
	       IrpContext->Stack->Parameters.Write.ByteOffset.QuadPart);
	Status = IoCallDriver(IrpContext->DeviceExt->StorageDevice,
			      IrpContext->Irp);
	return Status;
    }

    DPRINT("<%wZ>\n", &Fcb->PathNameU);

    /* fail if file is a directory and no paged read */
    if (FatFCBIsDirectory(Fcb) && !PagingIo) {
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    LARGE_INTEGER ByteOffset = IrpContext->Stack->Parameters.Write.ByteOffset;
    if (ByteOffset.u.LowPart == FILE_WRITE_TO_END_OF_FILE &&
	ByteOffset.u.HighPart == -1) {
	ByteOffset.QuadPart = Fcb->Base.FileSize.QuadPart;
    }
    ULONG Length = IrpContext->Stack->Parameters.Write.Length;
    ULONG BytesPerSector = IrpContext->DeviceExt->FatInfo.BytesPerSector;

    if (ByteOffset.u.HighPart && !IsVolume) {
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    if (IsFAT || IsVolume || FatDirEntryGetFirstCluster(IrpContext->DeviceExt,
							&Fcb->Entry) == 1) {
	if (ByteOffset.QuadPart + Length > Fcb->Base.FileSize.QuadPart) {
	    // we can't extend the FAT, the volume or the root on FAT12/FAT16
	    Status = STATUS_END_OF_FILE;
	    goto ByeBye;
	}
    }

    if ((ByteOffset.u.LowPart % BytesPerSector) || (Length % BytesPerSector)) {
	// write must be sector aligned
	DPRINT("unaligned write: byte offset %u length %u\n",
	       ByteOffset.u.LowPart, Length);
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    LARGE_INTEGER OldFileSize = Fcb->Base.FileSize;

    if (Length == 0) {
	/* Update last write time */
	IrpContext->Irp->IoStatus.Information = 0;
	Status = STATUS_SUCCESS;
	goto Metadata;
    }

    if (ByteOffset.u.LowPart + Length > Fcb->Base.AllocationSize.u.LowPart) {
	Status = STATUS_INVALID_PARAMETER;
	goto ByeBye;
    }

    if (ByteOffset.u.LowPart + Length >
	ROUND_UP_32(Fcb->Base.AllocationSize.u.LowPart, BytesPerSector)) {
	Length = ROUND_UP_32(Fcb->Base.FileSize.u.LowPart,
			     BytesPerSector) - ByteOffset.u.LowPart;
    }

    PVOID Buffer = FatGetUserBuffer(IrpContext->Irp, PagingIo);

    if (!IsFAT && !IsVolume && !PagingIo &&
	ByteOffset.u.LowPart + Length > Fcb->Base.FileSize.u.LowPart) {
	LARGE_INTEGER AllocationSize;

	AllocationSize.QuadPart = ByteOffset.u.LowPart + Length;
	Status = FatSetAllocationSizeInformation(IrpContext->FileObject, Fcb,
						 IrpContext->DeviceExt,
						 &AllocationSize);

	if (!NT_SUCCESS(Status)) {
	    goto ByeBye;
	}
    }

    if (ByteOffset.QuadPart > OldFileSize.QuadPart) {
	CcZeroData(IrpContext->FileObject, &OldFileSize, &ByteOffset,
		   TRUE);
    }

    if (!IsVolume) {
	FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedWrites, 1);
	FatAddToStat(IrpContext->DeviceExt, Fat.NonCachedWriteBytes, Length);
    } else {
	FatAddToStat(IrpContext->DeviceExt, Base.MetaDataWrites, 1);
	FatAddToStat(IrpContext->DeviceExt, Base.MetaDataWriteBytes, Length);
    }

    Status = FatWriteFileData(IrpContext, Length, ByteOffset);
    if (NT_SUCCESS(Status)) {
	IrpContext->Irp->IoStatus.Information = Length;
    }

Metadata:
    /* TODO: this should be done on server side */
    if (!PagingIo && !IsFAT && !IsVolume) {
	if (!FatFCBIsDirectory(Fcb)) {
	    LARGE_INTEGER SystemTime;
	    ULONG Filter;

	    // set dates and times
	    NtQuerySystemTime(&SystemTime);
	    if (FatVolumeIsFatX(IrpContext->DeviceExt)) {
		FsdSystemTimeToDosDateTime(IrpContext->DeviceExt,
					   &SystemTime,
					   &Fcb->Entry.FatX.UpdateDate,
					   &Fcb->Entry.FatX.UpdateTime);
		Fcb->Entry.FatX.AccessDate = Fcb->Entry.FatX.UpdateDate;
		Fcb->Entry.FatX.AccessTime = Fcb->Entry.FatX.UpdateTime;
	    } else {
		FsdSystemTimeToDosDateTime(IrpContext->DeviceExt,
					   &SystemTime,
					   &Fcb->Entry.Fat.UpdateDate,
					   &Fcb->Entry.Fat.UpdateTime);
		Fcb->Entry.Fat.AccessDate = Fcb->Entry.Fat.UpdateDate;
	    }
	    /* set date and times to dirty */
	    Fcb->Flags |= FCB_IS_DIRTY;

	    /* Time to notify the OS */
	    Filter = FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES;
	    if (ByteOffset.QuadPart != OldFileSize.QuadPart)
		Filter |= FILE_NOTIFY_CHANGE_SIZE;

	    FatReportChange(IrpContext->DeviceExt, Fcb, Filter,
			    FILE_ACTION_MODIFIED);
	}
    }

ByeBye:
    DPRINT("%x\n", Status);
    IrpContext->Irp->IoStatus.Status = Status;
    if (NT_SUCCESS(Status)) {
	IrpContext->PriorityBoost = IO_DISK_INCREMENT;
    }
    return Status;
}
