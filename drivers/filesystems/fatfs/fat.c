/*
 * PROJECT:     FAT Filesystem
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     File Allocation Table routines
 * COPYRIGHT:   Copyright 1998 Jason Filby <jasonfilby@yahoo.com>
 *              Copyright 2015-2018 Pierre Schweitzer <pierre@reactos.org>
 */

/* INCLUDES *****************************************************************/

#include "fatfs.h"

/* FUNCTIONS ****************************************************************/

FORCEINLINE BOOLEAN IsFat12(IN PDEVICE_EXTENSION DevExt)
{
    return DevExt->FatInfo.FatType == FAT12;
}

FORCEINLINE BOOLEAN IsFat16(IN PDEVICE_EXTENSION DevExt)
{
    ULONG FatType = DevExt->FatInfo.FatType;
    return (FatType == FAT16) || (FatType == FATX16);
}

FORCEINLINE BOOLEAN IsFat32(IN PDEVICE_EXTENSION DevExt)
{
    ULONG FatType = DevExt->FatInfo.FatType;
    return (FatType == FAT32) || (FatType == FATX32);
}

FORCEINLINE PUSHORT Fat12GetBlock(IN PVOID BaseAddress,
				  IN ULONG Cluster,
				  OUT OPTIONAL PULONG pEntry)
{
    PUSHORT CBlock = (PUSHORT)((PUCHAR)BaseAddress + Cluster * 12 / 8);
    ULONG Entry;
    if ((Cluster % 2) == 0) {
	Entry = *CBlock & 0x0fff;
    } else {
	Entry = *CBlock >> 4;
    }
    if (pEntry) {
	*pEntry = Entry;
    }
    return CBlock;
}

static NTSTATUS FatMapCluster(IN PDEVICE_EXTENSION DevExt,
			      IN ULONG64 FatOffset,
			      OUT PVOID *Context,
			      OUT PVOID *MappedAddress)
{
    ULONG ClusterSize = DevExt->FatInfo.BytesPerCluster;
    LARGE_INTEGER Offset = { .QuadPart = FatOffset };
    ULONG MappedLength;
    NTSTATUS Status = CcMapData(DevExt->FatFileObject, &Offset, ClusterSize,
				MAP_WAIT, &MappedLength, Context, MappedAddress);
    if (!NT_SUCCESS(Status)) {
	DPRINT("CcMapData failed, error = 0x%x, fatoffset = 0x%llx, devext = %p\n",
	       Status, FatOffset, DevExt);
	return Status;
    }
    assert(MappedLength == ClusterSize);
    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Retrieve the next FAT12 cluster from the FAT table
 */
static NTSTATUS Fat12GetNextCluster(IN PDEVICE_EXTENSION DevExt,
				    IN ULONG CurrentCluster,
				    OUT PULONG NextCluster)
{
    *NextCluster = 0;

    PVOID Context, BaseAddress;
    NTSTATUS Status = FatMapCluster(DevExt, 0, &Context, &BaseAddress);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    ULONG Entry;
    Fat12GetBlock(BaseAddress, CurrentCluster, &Entry);

    if (Entry >= 0xff8 && Entry <= 0xfff)
	Entry = 0xffffffff;

    ASSERT(Entry != 0);
    *NextCluster = Entry;
    CcUnpinData(Context);
    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Retrieve the next FAT cluster from the FAT16 or FAT32 table by
 * reading the underlying physical disk (using the Cache Manager). This
 * function does not apply for FAT12.
 */
static NTSTATUS Fat1632GetNextCluster(PDEVICE_EXTENSION DevExt,
				      ULONG CurrentCluster,
				      PULONG NextCluster)
{
    assert(!IsFat12(DevExt));
    BOOLEAN Fat32 = IsFat32(DevExt);
    ULONG ClusterSize = DevExt->FatInfo.BytesPerCluster;
    ULONG FatOffset = ROUND_DOWN(CurrentCluster * (Fat32 ? 4 : 2), ClusterSize);
    PVOID Context, BaseAddress;
    NTSTATUS Status = FatMapCluster(DevExt, FatOffset, &Context, &BaseAddress);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    PCHAR Ptr = (PCHAR)BaseAddress + (FatOffset % ClusterSize);
    if (Fat32) {
	CurrentCluster = *(PULONG)Ptr & 0x0fffffff;
    } else {
	CurrentCluster = *(PUSHORT)Ptr;
    }

    ULONG ReservedClusterStart = Fat32 ? 0xffffff8 : 0xfff8;
    ULONG ReservedClusterEnd = Fat32 ? 0xfffffff : 0xffff;
    if (CurrentCluster >= ReservedClusterStart && CurrentCluster <= ReservedClusterEnd)
	CurrentCluster = 0xffffffff;

    if (CurrentCluster == 0) {
	DPRINT1("WARNING: File system corruption detected. You may need to "
		"run a disk repair utility.\n");
	Status = STATUS_FILE_CORRUPT_ERROR;
	if (FatGlobalData->Flags & FAT_BREAK_ON_CORRUPTION)
	    ASSERT(FALSE);
    }
    CcUnpinData(Context);
    *NextCluster = CurrentCluster;
    return Status;
}

/*
 * FUNCTION: Retrieve the next cluster depending on the FAT type
 */
NTSTATUS GetNextCluster(PDEVICE_EXTENSION DevExt,
			ULONG CurrentCluster, PULONG NextCluster)
{
    DPRINT("GetNextCluster(DeviceExt %p, CurrentCluster %x)\n",
	   DevExt, CurrentCluster);

    if (CurrentCluster == 0) {
	DPRINT1("WARNING: File system corruption detected. You may "
		"need to run a disk repair utility.\n");
	if (FatGlobalData->Flags & FAT_BREAK_ON_CORRUPTION)
	    ASSERT(CurrentCluster != 0);
	return STATUS_FILE_CORRUPT_ERROR;
    }

    if (IsFat12(DevExt)) {
	return Fat12GetNextCluster(DevExt, CurrentCluster, NextCluster);
    } else {
	return Fat1632GetNextCluster(DevExt, CurrentCluster, NextCluster);
    }
}

/*
 * FUNCTION: Finds the first available cluster in a FAT12 table
 */
static NTSTATUS Fat12FindAndMarkAvailableCluster(PDEVICE_EXTENSION DevExt,
						 PULONG Cluster)
{
    ULONG FatLength = DevExt->FatInfo.NumberOfClusters + 2;
    ULONG StartCluster = DevExt->LastAvailableCluster;
    *Cluster = 0;

    PVOID Context, BaseAddress;
    NTSTATUS Status = FatMapCluster(DevExt, 0, &Context, &BaseAddress);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    for (ULONG j = 0; j < 2; j++) {
	for (ULONG i = StartCluster; i < FatLength; i++) {
	    ULONG Entry;
	    PUSHORT CBlock = Fat12GetBlock(BaseAddress, i, &Entry);

	    if (Entry == 0) {
		DPRINT("Found available cluster 0x%x\n", i);
		DevExt->LastAvailableCluster = *Cluster = i;
		if ((i % 2) == 0)
		    *CBlock = (*CBlock & 0xf000) | 0xfff;
		else
		    *CBlock = (*CBlock & 0xf) | 0xfff0;
		CcSetDirtyData(Context);
		CcUnpinData(Context);
		if (DevExt->AvailableClustersValid) {
		    InterlockedDecrement((PLONG)&DevExt->AvailableClusters);
		}
		return STATUS_SUCCESS;
	    }
	}
	FatLength = StartCluster;
	StartCluster = 2;
    }
    CcUnpinData(Context);
    return STATUS_DISK_FULL;
}

/*
 * FUNCTION: Finds the first available cluster in an FAT16 or FAT32 table
 */
static NTSTATUS Fat1632FindAndMarkAvailableCluster(PDEVICE_EXTENSION DevExt,
						   PULONG Cluster)
{
    assert(!IsFat12(DevExt));
    BOOLEAN Fat32 = IsFat32(DevExt);
    ULONG WordSize = Fat32 ? 4 : 2;
    ULONG ClusterSize = DevExt->FatInfo.BytesPerCluster;
    ULONG FatLength = DevExt->FatInfo.NumberOfClusters + 2;
    ULONG StartCluster = DevExt->LastAvailableCluster;
    *Cluster = 0;

    for (ULONG j = 0; j < 2; j++) {
	for (ULONG i = StartCluster; i < FatLength; ) {
	    PVOID Context, BaseAddress;
	    NTSTATUS Status = FatMapCluster(DevExt, ROUND_DOWN(i*WordSize, ClusterSize),
					    &Context, &BaseAddress);
	    if (!NT_SUCCESS(Status)) {
		return Status;
	    }
	    ULONG_PTR Block = (ULONG_PTR)BaseAddress + (i * WordSize) % ClusterSize;
	    ULONG_PTR BlockEnd = (ULONG_PTR)BaseAddress + ClusterSize;

	    /* Now mark the whole block as available */
	    while (Block < BlockEnd && i < FatLength) {
		ULONG Word = Fat32 ? (*(PULONG)Block & 0x0fffffff) : *(PUSHORT)Block;
		if (Word == 0) {
		    DPRINT("Found available cluster 0x%x\n", i);
		    DevExt->LastAvailableCluster = *Cluster = i;
		    if (Fat32) {
			*(PULONG)Block = 0x0fffffff;
		    } else {
			*(PUSHORT)Block = 0xffff;
		    }
		    CcSetDirtyData(Context);
		    CcUnpinData(Context);
		    if (DevExt->AvailableClustersValid)
			InterlockedDecrement((PLONG)&DevExt->AvailableClusters);
		    return STATUS_SUCCESS;
		}

		Block += WordSize;
		i++;
	    }

	    CcUnpinData(Context);
	}

	FatLength = StartCluster;
	StartCluster = 2;
    }

    return STATUS_DISK_FULL;
}

/*
 * FUNCTION: Finds the first available cluster
 */
NTSTATUS FindAndMarkAvailableCluster(PDEVICE_EXTENSION DevExt,
				     PULONG Cluster)
{
    if (IsFat12(DevExt)) {
	return Fat12FindAndMarkAvailableCluster(DevExt, Cluster);
    } else {
	return Fat1632FindAndMarkAvailableCluster(DevExt, Cluster);
    }
}

/*
 * FUNCTION: Retrieve the next cluster, possibly extending the FAT.
 */
NTSTATUS GetNextClusterExtend(PDEVICE_EXTENSION DevExt,
			      ULONG CurrentCluster,
			      PULONG NextCluster)
{
    DPRINT("GetNextClusterExtend(DeviceExt %p, CurrentCluster %x)\n",
	   DevExt, CurrentCluster);

    /*
     * If the file hasn't any clusters allocated then we need special
     * handling
     */
    ULONG NewCluster;
    NTSTATUS Status;
    if (CurrentCluster == 0) {
	Status = FindAndMarkAvailableCluster(DevExt, &NewCluster);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
	*NextCluster = NewCluster;
	return STATUS_SUCCESS;
    }

    if (IsFat12(DevExt)) {
	Status = Fat12GetNextCluster(DevExt, CurrentCluster, NextCluster);
    } else {
	Status = Fat1632GetNextCluster(DevExt, CurrentCluster, NextCluster);
    }

    if ((*NextCluster) == 0xFFFFFFFF) {
	/* We are after last existing cluster, we must add one to file.
	 * First, find the next available open allocation unit and then
	 * mark it as end of file. */
	Status = FindAndMarkAvailableCluster(DevExt, &NewCluster);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}

	/* Now, write the AU of the LastCluster with the value of the newly
	   found AU */
	WriteCluster(DevExt, CurrentCluster, NewCluster);
	*NextCluster = NewCluster;
    }

    return Status;
}

/*
 * FUNCTION: Update the free cluster count in the device extension for
 * FAT12.
 */
static NTSTATUS Fat12CountAvailableClusters(PDEVICE_EXTENSION DevExt)
{
    PVOID Context, BaseAddress;
    NTSTATUS Status = FatMapCluster(DevExt, 0, &Context, &BaseAddress);
    if (!NT_SUCCESS(Status)) {
	return Status;;
    }

    ULONG NumberOfClusters = DevExt->FatInfo.NumberOfClusters + 2;
    ULONG Count = 0;
    for (ULONG i = 2; i < NumberOfClusters; i++) {
	ULONG Entry;
	Fat12GetBlock(BaseAddress, i, &Entry);
	if (Entry == 0)
	    Count++;
    }

    CcUnpinData(Context);
    DevExt->AvailableClusters = Count;
    DevExt->AvailableClustersValid = TRUE;

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Update the free cluster count in the device extension for
 * FAT16 and FAT32.
 */
static NTSTATUS Fat1632CountAvailableClusters(IN PDEVICE_EXTENSION DevExt)
{
    assert(!IsFat12(DevExt));
    BOOLEAN Fat32 = IsFat32(DevExt);
    ULONG WordSize = Fat32 ? 4 : 2;
    ULONG ClusterSize = DevExt->FatInfo.BytesPerCluster;
    ULONG FatLength = (DevExt->FatInfo.NumberOfClusters + 2);
    ULONG Count = 0;

    for (ULONG i = 2; i < FatLength; ) {
	PVOID BaseAddress, Context;
	NTSTATUS Status = FatMapCluster(DevExt, ROUND_DOWN(i*WordSize, ClusterSize),
					&Context, &BaseAddress);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
	ULONG_PTR Block = (ULONG_PTR)BaseAddress + (i * WordSize) % ClusterSize;
	ULONG_PTR BlockEnd =  (ULONG_PTR)BaseAddress + ClusterSize;

	/* Now process the whole block */
	while (Block < BlockEnd && i < FatLength) {
	    ULONG Word = Fat32 ? (*(PULONG)Block & 0x0fffffff) : *(PUSHORT)Block;
	    if (Word == 0)
		Count++;
	    Block += WordSize;
	    i++;
	}

	CcUnpinData(Context);
    }

    DevExt->AvailableClusters = Count;
    DevExt->AvailableClustersValid = TRUE;

    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Returns free clusters in the Clusters argument.
 */
NTSTATUS CountAvailableClusters(PDEVICE_EXTENSION DevExt,
				PLARGE_INTEGER Clusters)
{
    NTSTATUS Status = STATUS_SUCCESS;
    if (!DevExt->AvailableClustersValid) {
	if (IsFat12(DevExt)) {
	    Status = Fat12CountAvailableClusters(DevExt);
	} else {
	    Status = Fat1632CountAvailableClusters(DevExt);
	}
    }
    if (Clusters != NULL) {
	Clusters->QuadPart = DevExt->AvailableClusters;
    }
    return Status;
}

/*
 * FUNCTION: Write a changed FAT entry
 */
NTSTATUS WriteCluster(PDEVICE_EXTENSION DevExt,
		      ULONG ClusterToWrite,
		      ULONG NewValue)
{
    BOOLEAN Fat12 = IsFat12(DevExt);
    ULONG WordSize = IsFat32(DevExt) ? 4 : 2;
    ULONG FatOffset = Fat12 ? (ClusterToWrite*12/8) : (ClusterToWrite*WordSize);
    ULONG ClusterSize = DevExt->FatInfo.BytesPerCluster;
    PVOID BaseAddress, Context;
    NTSTATUS Status = FatMapCluster(DevExt, Fat12 ? 0 : ROUND_DOWN(FatOffset, ClusterSize),
				    &Context, &BaseAddress);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    DPRINT("Writing 0x%x for 0x%x at 0x%x\n", NewValue, ClusterToWrite, FatOffset);
    ULONG OldValue;
    if (Fat12) {
	PUCHAR CBlock = (PUCHAR)BaseAddress;
	if ((ClusterToWrite % 2) == 0) {
	    OldValue = CBlock[FatOffset] + ((CBlock[FatOffset + 1] & 0x0f) << 8);
	    CBlock[FatOffset] = (UCHAR) NewValue;
	    CBlock[FatOffset + 1] &= 0xf0;
	    CBlock[FatOffset + 1] |= (NewValue & 0xf00) >> 8;
	} else {
	    OldValue = (CBlock[FatOffset] >> 4) + (CBlock[FatOffset + 1] << 4);
	    CBlock[FatOffset] &= 0x0f;
	    CBlock[FatOffset] |= (NewValue & 0xf) << 4;
	    CBlock[FatOffset + 1] = (UCHAR) (NewValue >> 4);
	}
    } else {
	PUCHAR Ptr = (PUCHAR)BaseAddress + FatOffset % ClusterSize;
	if (IsFat16(DevExt)) {
	    PUSHORT Cluster = (PUSHORT)Ptr;
	    OldValue = *Cluster;
	    *Cluster = (USHORT) NewValue;
	} else {
	    PULONG Cluster = (PULONG)Ptr;
	    OldValue = *Cluster & 0x0fffffff;
	    *Cluster = (*Cluster & 0xf0000000) | (NewValue & 0x0fffffff);
	}
    }

    /* Write the changed FAT sector(s) to disk */
    CcSetDirtyData(Context);
    CcUnpinData(Context);

    /* Update the number of available clusters */
    if (DevExt->AvailableClustersValid) {
	if (OldValue && !NewValue)
	    InterlockedIncrement((PLONG)&DevExt->AvailableClusters);
	else if (!OldValue && NewValue)
	    InterlockedDecrement((PLONG)&DevExt->AvailableClusters);
    }
    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Converts the cluster number to a sector number for this physical
 *           device
 */
ULONGLONG ClusterToSector(PDEVICE_EXTENSION DevExt, ULONG Cluster)
{
    return DevExt->FatInfo.DataStart +
	(ULONGLONG)(Cluster-2) * DevExt->FatInfo.SectorsPerCluster;

}

/*
 * FUNCTION: Retrieve the dirty status
 */
NTSTATUS GetDirtyStatus(PDEVICE_EXTENSION DevExt,
			PBOOLEAN DirtyStatus)
{
    DPRINT("GetDirtyStatus(DevExt %p)\n", DevExt);

    ULONG FatType = DevExt->FatInfo.FatType;
    /* FAT12 has no dirty bit */
    if (FatType == FAT12) {
	*DirtyStatus = FALSE;
	return STATUS_SUCCESS;
    }

    BOOLEAN Fat32 = (FatType == FAT32 || FatType == FATX32);

    /* We'll read the bootsector at 0 */
    LARGE_INTEGER Offset = { .QuadPart = 0 };
    ULONG Length = DevExt->FatInfo.BytesPerSector;

    /* Go through Cc to read the disk */
    PVOID Context, Sector;
    ULONG MappedLength;
    NTSTATUS Status = CcMapData(DevExt->VolumeFcb->FileObject, &Offset,
				Length, MAP_WAIT, &MappedLength, &Context, &Sector);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(MappedLength == Length);

    /* Make sure we have a boot sector. */
    USHORT Signature = Fat32 ? ((PBOOT_SECTOR_FAT32)Sector)->Signature1
	: ((PBOOT_SECTOR)Sector)->Signature1;
    if (Signature != 0xaa55) {
	CcUnpinData(Context);
	return STATUS_DISK_CORRUPT_ERROR;
    }

    /* Return the status of the dirty bit */
    PUCHAR Byte = Fat32 ? &((PBOOT_SECTOR_FAT32)Sector)->Res4 : &((PBOOT_SECTOR)Sector)->Res1;
    if (*Byte & FAT_DIRTY_BIT)
	*DirtyStatus = TRUE;
    else
	*DirtyStatus = FALSE;

    CcUnpinData(Context);
    return STATUS_SUCCESS;
}

/*
 * FUNCTION: Set the dirty status
 */
NTSTATUS SetDirtyStatus(PDEVICE_EXTENSION DevExt, BOOLEAN DirtyStatus)
{
    DPRINT("SetDirtyStatus(DeviceExt %p, DirtyStatus %d)\n", DevExt,
	   DirtyStatus);

    /* FAT12 has no dirty bit */
    ULONG FatType = DevExt->FatInfo.FatType;
    if (FatType == FAT12) {
	return STATUS_SUCCESS;
    }

    BOOLEAN Fat32 = (FatType == FAT32 || FatType == FATX32);

    /* We'll read (and then write) the bootsector at 0 */
    LARGE_INTEGER Offset = { .QuadPart = 0 };
    ULONG Length = DevExt->FatInfo.BytesPerSector;

    /* Go through Cc to read the disk */
    PVOID Context, Sector;
    ULONG MappedLength;
    NTSTATUS Status = CcMapData(DevExt->VolumeFcb->FileObject, &Offset,
				Length, MAP_WAIT, &MappedLength, &Context, &Sector);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(MappedLength == Length);

    /* Make sure we have a boot sector. */
    USHORT Signature = Fat32 ? ((PBOOT_SECTOR_FAT32)Sector)->Signature1
	: ((PBOOT_SECTOR)Sector)->Signature1;
    if (Signature != 0xaa55) {
	CcUnpinData(Context);
	return STATUS_DISK_CORRUPT_ERROR;
    }

    /* Modify the dirty bit */
    PUCHAR Byte = Fat32 ? &((PBOOT_SECTOR_FAT32)Sector)->Res4 :
	&((PBOOT_SECTOR)Sector)->Res1;
    if (!DirtyStatus) {
	*Byte &= ~FAT_DIRTY_BIT;
    } else {
	*Byte |= FAT_DIRTY_BIT;
    }

    /* Mark boot sector dirty so that it gets written to the disk */
    CcSetDirtyData(Context);
    CcUnpinData(Context);
    return STATUS_SUCCESS;
}

NTSTATUS Fat32UpdateFreeClustersCount(PDEVICE_EXTENSION DevExt)
{
    if (!DevExt->AvailableClustersValid) {
	return STATUS_INVALID_PARAMETER;
    }

    /* We'll read (and then write) the fsinfo sector */
    LARGE_INTEGER Offset = { .QuadPart = DevExt->FatInfo.FSInfoSector *
	DevExt->FatInfo.BytesPerSector };
    ULONG Length = DevExt->FatInfo.BytesPerSector;

    /* Go through Cc to read the disk */
    ULONG MappedLength;
    PVOID Context;
    PFSINFO_SECTOR Sector;
    NTSTATUS Status = CcMapData(DevExt->VolumeFcb->FileObject, &Offset,
				Length, MAP_WAIT, &MappedLength, &Context, (PVOID *)&Sector);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(MappedLength == Length);

    /* Make sure we have a FSINFO sector */
    if (Sector->ExtBootSignature2 != 0x41615252 ||
	Sector->FSINFOSignature != 0x61417272 ||
	Sector->Signatur2 != 0xaa550000) {
	ASSERT(FALSE);
	CcUnpinData(Context);
	return STATUS_DISK_CORRUPT_ERROR;
    }

    /* Update the free clusters count */
    Sector->FreeCluster = InterlockedCompareExchange((PLONG)&DevExt->AvailableClusters,
						     0, 0);

    /* Mark FSINFO sector dirty so that it gets written to the disk */
    CcSetDirtyData(Context);
    CcUnpinData(Context);
    return STATUS_SUCCESS;
}
