#include <wdmp.h>
#include <pci.h>

LIST_ENTRY IopDmaPoolList;

NTAPI VOID ObReferenceObject(IN PVOID Obj)
{
    POBJECT_HEADER Header = Obj;
    Header->RefCount++;
}

NTAPI VOID ObDereferenceObject(IN PVOID Obj)
{
    POBJECT_HEADER Header = Obj;
    Header->RefCount--;
    if (Header->RefCount <= 0) {
	assert(Header->RefCount == 0);
	if (Header->Type == CLIENT_OBJECT_FILE) {
	    IopDeleteFileObject(Obj);
	} else if (Header->Type == CLIENT_OBJECT_DEVICE) {
	    IopDeleteDeviceObject(Obj);
	} else {
	    IopFreePool(Obj);
	}
    }
}

NTAPI NTSTATUS MmAllocateContiguousMemorySpecifyCache(IN SIZE_T NumberOfBytes,
						      IN PHYSICAL_ADDRESS HighestAddr,
						      IN PHYSICAL_ADDRESS BoundaryAddressMultiple,
						      IN MEMORY_CACHING_TYPE CacheType,
						      OUT PVOID *VirtBase,
						      OUT PHYSICAL_ADDRESS *PhysBase)
{
    ULONG BoundaryAddressBits = RtlFindLeastSignificantBit(BoundaryAddressMultiple.QuadPart) + 1;
    return WdmHalAllocateDmaBuffer(NumberOfBytes, &HighestAddr,
				   BoundaryAddressBits, CacheType,
				   VirtBase, PhysBase);
}

NTAPI VOID MmFreeContiguousMemorySpecifyCache(IN PVOID BaseAddress,
					      IN SIZE_T NumberOfBytes,
					      IN MEMORY_CACHING_TYPE CacheType)
{
    WdmHalFreeDmaBuffer(BaseAddress, NumberOfBytes, CacheType);
}

/*
 * A physically contiguous region of memory which driver can request if
 * it wants to know the physical address of the memory it has allocated.
 */
typedef struct _DMA_POOL {
    PVOID VirtualAddress;
    SIZE_T Size;
    PHYSICAL_ADDRESS PhysicalAddress;
    HANDLE Heap;
    LIST_ENTRY Link;
    MEMORY_CACHING_TYPE CacheType;
} DMA_POOL, *PDMA_POOL;

#define DMA_POOL_ALLOCATION_GRANULARITY	(64 * 1024)

static NTAPI NTSTATUS IopDmaPoolCommitRoutine(IN PVOID Base,
					      IN OUT PVOID *CommitAddress,
					      IN OUT PSIZE_T CommitSize)
{
    /* This routine should never be called. We need to supply one so RtlCreateHeap
     * will not try to query the allocated region size. */
    assert(FALSE);
    return STATUS_UNSUCCESSFUL;
}

static PVOID IopAllocateDmaPool(IN MEMORY_CACHING_TYPE CacheType,
				IN SIZE_T Size)
{
    /* Try allocating from existing DMA pool with the matching cache type. */
    LoopOverList(DmaPool, &IopDmaPoolList, DMA_POOL, Link) {
	if (CacheType != DmaPool->CacheType) {
	    continue;
	}
	assert(DmaPool->Heap);
	PVOID Ptr = RtlAllocateHeap(DmaPool->Heap, HEAP_ZERO_MEMORY, Size);
	if (Ptr) {
	    return Ptr;
	}
    }
    /* There isn't one available, so try allocating a new pool. */
    PDMA_POOL DmaPool = ExAllocatePool(NonPagedPool, sizeof(DMA_POOL));
    if (!DmaPool) {
	return NULL;
    }
    SIZE_T AllocationSize = ALIGN_UP_BY(Size, DMA_POOL_ALLOCATION_GRANULARITY);
    PHYSICAL_ADDRESS HighestAddr = { .QuadPart = ULONG_PTR_MAX };
    PHYSICAL_ADDRESS BoundaryAddressMultiple = {};
    NTSTATUS Status = MmAllocateContiguousMemorySpecifyCache(AllocationSize,
							     HighestAddr,
							     BoundaryAddressMultiple,
							     CacheType,
							     &DmaPool->VirtualAddress,
							     &DmaPool->PhysicalAddress);
    if (!NT_SUCCESS(Status)) {
	ExFreePool(DmaPool);
	return NULL;
    }
    assert(DmaPool->VirtualAddress);
    assert(DmaPool->PhysicalAddress.QuadPart);
    DmaPool->Size = AllocationSize;
    DmaPool->CacheType = CacheType;
    InsertTailList(&IopDmaPoolList, &DmaPool->Link);
    RTL_HEAP_PARAMETERS Parameters = {
	.Length = sizeof(RTL_HEAP_PARAMETERS),
	.SegmentReserve = AllocationSize,
	.SegmentCommit = AllocationSize,
	.DeCommitFreeBlockThreshold = PAGE_SIZE,
	.DeCommitTotalFreeThreshold = AllocationSize * 2,
	.MaximumAllocationSize = AllocationSize,
	.VirtualMemoryThreshold = SIZE_T_MAX,
	.InitialCommit = AllocationSize,
	.InitialReserve = AllocationSize,
	.CommitRoutine = IopDmaPoolCommitRoutine
    };
    DmaPool->Heap = RtlCreateHeap(HEAP_NO_SERIALIZE, DmaPool->VirtualAddress,
				  AllocationSize, AllocationSize, NULL, &Parameters);
    if (!DmaPool->Heap) {
	MmFreeContiguousMemorySpecifyCache(DmaPool->VirtualAddress, DmaPool->Size,
					   DmaPool->CacheType);
	ExFreePool(DmaPool);
	/* This shouldn't fail. */
	assert(FALSE);
	return NULL;
    }
    return RtlAllocateHeap(DmaPool->Heap, HEAP_ZERO_MEMORY, Size);
}

static PDMA_POOL IopPtrToDmaPool(IN PVOID Ptr)
{
    LoopOverList(DmaPool, &IopDmaPoolList, DMA_POOL, Link) {
	if ((ULONG_PTR)Ptr >= (ULONG_PTR)DmaPool->VirtualAddress &&
	    (ULONG_PTR)Ptr < ((ULONG_PTR)DmaPool->VirtualAddress + DmaPool->Size)) {
	    return DmaPool;
	}
    }
    return NULL;
}

NTAPI PVOID ExAllocatePoolWithTag(IN POOL_TYPE PoolType,
				  IN SIZE_T Size,
				  IN ULONG Tag)
{
    assert(PoolType < MaxPoolType);
    if (PoolType == CachedDmaPool) {
	return IopAllocateDmaPool(MmCached, Size);
    } else if (PoolType == UncachedDmaPool) {
	return IopAllocateDmaPool(MmNonCached, Size);
    }
    return RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

NTAPI VOID ExFreePoolWithTag(IN PVOID Pointer,
			     IN ULONG Tag)
{
    PDMA_POOL DmaPool = IopPtrToDmaPool(Pointer);
    PVOID Heap = DmaPool ? DmaPool->VirtualAddress : RtlGetProcessHeap();
    assert(Heap);
    assert(RtlValidateHeap(Heap, 0, Pointer));
    RtlFreeHeap(Heap, 0, Pointer);
}

static PHYSICAL_ADDRESS MiGetPhysicalAddress(IN PVOID Address,
					     OUT OPTIONAL SIZE_T *MappedLength)
{
    PHYSICAL_ADDRESS PhyAddr = {};
    PDMA_POOL DmaPool = IopPtrToDmaPool(Address);
    assert(DmaPool);
    if (DmaPool) {
	SIZE_T Offset = (ULONG_PTR)Address - (ULONG_PTR)DmaPool->VirtualAddress;
	PhyAddr.QuadPart = DmaPool->PhysicalAddress.QuadPart + Offset;
	assert(DmaPool->Size > Offset);
	if (MappedLength) {
	    *MappedLength = DmaPool->Size - Offset;
	}
    }
    return PhyAddr;
}

NTAPI PHYSICAL_ADDRESS MmGetPhysicalAddress(IN PVOID Address)
{
    return MiGetPhysicalAddress(Address, NULL);
}

NTAPI PVOID MmGetVirtualForPhysical(IN PHYSICAL_ADDRESS PhysicalAddress)
{
    LoopOverList(DmaPool, &IopDmaPoolList, DMA_POOL, Link) {
	if (PhysicalAddress.QuadPart >= DmaPool->PhysicalAddress.QuadPart &&
	    PhysicalAddress.QuadPart < (DmaPool->PhysicalAddress.QuadPart + DmaPool->Size)) {
	    return (PCHAR)DmaPool->VirtualAddress + DmaPool->PhysicalAddress.QuadPart +
		DmaPool->Size - PhysicalAddress.QuadPart;
	}
    }
    return NULL;
}

/*
 * Build a partial MDL that covers the specified virtual address range.
 * Note the virtual address of the MDL is obtained from MmGetMdlVirtualAddress.
 */
NTAPI PMDL IoBuildPartialMdl(IN PMDL SourceMdl,
			     IN PVOID VirtualAddress,
			     IN ULONG Length)
{
    if (!SourceMdl) {
	assert(FALSE);
	return NULL;
    }
    if (!Length) {
	assert(FALSE);
	return NULL;
    }
    if (VirtualAddress < MmGetMdlVirtualAddress(SourceMdl)) {
	assert(FALSE);
	return NULL;
    }
    if ((PUCHAR)VirtualAddress + Length >
	(PUCHAR)MmGetMdlVirtualAddress(SourceMdl) + SourceMdl->ByteCount) {
	assert(FALSE);
	return NULL;
    }

    /* Determine the starting PFN index and PFN count of the partial MDL */
    ULONG PfnIndex = 0;
    PHYSICAL_ADDRESS PhyAddr = MiGetMdlPhysicalAddress(SourceMdl,
						       VirtualAddress,
						       &PfnIndex);
    if (PfnIndex == ULONG_MAX) {
	assert(FALSE);
	return NULL;
    }
    ULONG PageShift = MDL_PFN_PAGE_LOG2SIZE(SourceMdl->PfnEntries[PfnIndex]);
    ULONG_PTR OldPfn = SourceMdl->PfnEntries[PfnIndex] >> PageShift;
    ULONG_PTR NewPfn = PhyAddr.QuadPart >> PageShift;
    assert(NewPfn >= OldPfn);
    ULONG PagesToSkip = NewPfn - OldPfn;
    ULONG OldPageCount = MDL_PFN_PAGE_COUNT(SourceMdl->PfnEntries[PfnIndex]);
    assert(OldPageCount > PagesToSkip);
    ULONG NewPageCount = OldPageCount - PagesToSkip;
    ULONG_PTR NewPfnEntry = (NewPfn << PageShift) | (NewPageCount << MDL_PFN_ATTR_BITS) |
	(SourceMdl->PfnEntries[PfnIndex] & MDL_PFN_ATTR_MASK);
    ULONG PfnCount = 0;
    MiGetMdlPhysicalAddress(SourceMdl, VirtualAddress + Length - 1, &PfnCount);
    if (PfnCount == ULONG_MAX) {
	assert(FALSE);
	return NULL;
    }
    if (PfnCount < PfnIndex) {
	assert(FALSE);
	return NULL;
    }
    PfnCount -= PfnIndex;
    PfnCount++;

    /* Allocate the partial MDL and copy the PFN database */
    PMDL PartialMdl = ExAllocatePool(NonPagedPool,
				    sizeof(MDL) + PfnCount * sizeof(ULONG_PTR));
    if (!PartialMdl) {
	return NULL;
    }

    ULONG Offset = VirtualAddress - MmGetMdlVirtualAddress(SourceMdl);
    PartialMdl->MappedSystemVa = SourceMdl->MappedSystemVa + Offset;
    PartialMdl->ByteOffset = SourceMdl->ByteOffset + Offset;
    PartialMdl->ByteOffset &= MDL_PFN_PAGE_SIZE(SourceMdl->PfnEntries[PfnIndex]) - 1;
    PartialMdl->ByteCount = Length;
    PartialMdl->PfnCount = PfnCount;
    RtlCopyMemory(PartialMdl->PfnEntries, &SourceMdl->PfnEntries[PfnIndex],
		  PfnCount * sizeof(ULONG_PTR));
    PartialMdl->PfnEntries[0] = NewPfnEntry;

    return PartialMdl;
}

NTAPI PMDL IoAllocateMdl(IN PVOID VirtualAddress,
			 IN ULONG Length)
{
    SIZE_T MappedLength = 0;
    ULONG64 PhyAddr = MiGetPhysicalAddress(VirtualAddress, &MappedLength).QuadPart;
    if (Length > MappedLength) {
	assert(FALSE);
	return NULL;
    }
    if (!PhyAddr) {
	return NULL;
    }
    /* For DMA memory we never allocate large pages. */
    ULONG_PTR AlignedAddress = PAGE_ALIGN(PhyAddr);
    ULONG_PTR AlignedEndAddress = PAGE_ALIGN_UP(PhyAddr + Length);
    ULONG PageCount = (AlignedEndAddress - AlignedAddress) >> PAGE_SHIFT;
    ULONG PfnEntryCount = ALIGN_UP_BY(PageCount, 1UL << MDL_PFN_PAGE_COUNT_BITS)
	>> MDL_PFN_PAGE_COUNT_BITS;
    ULONG_PTR PfnDb[PfnEntryCount] = {};
    for (ULONG i = 0; i < PfnEntryCount; i++) {
	ULONG MappedPages = min(PageCount, (1ULL << MDL_PFN_PAGE_COUNT_BITS) - 1);
	PfnDb[i] = AlignedAddress | (MappedPages << MDL_PFN_ATTR_BITS);
	AlignedAddress += MappedPages << PAGE_SHIFT;
	assert(PageCount >= MappedPages);
	PageCount -= MappedPages;
    }
    assert(!PageCount);
    assert(AlignedAddress == AlignedEndAddress);
    PMDL Mdl = NULL;
    if (!NT_SUCCESS(IopAllocateMdl(VirtualAddress, Length, PfnDb, PfnEntryCount,
				   TRUE, &Mdl))) {
	return NULL;
    }
    return Mdl;
}

/*
 * @implemented
 */
NTAPI PVOID MmPageEntireDriver(IN PVOID Address)
{
    PLDR_DATA_TABLE_ENTRY Module = NULL;
    NTSTATUS Status = LdrFindEntryForAddress(Address, &Module);
    if (!NT_SUCCESS(Status) || Module == NULL) {
	return NULL;
    }
    return Module->DllBase;
}

/*
 * @name MiGetMdlPhysicalAddress
 *
 * Returns the physical address corresponding to the specified offset
 * within the MDL.
 *
 * @param Mdl
 *        MDL to query
 * @param StartVa
 *        Starting virtual address of the buffer described by the MDL.
 *
 * @remarks
 *    Note that this function doesn't exist in Windows/ReactOS and is
 *    an Neptune OS addition.
 */
PHYSICAL_ADDRESS MiGetMdlPhysicalAddress(IN PMDL Mdl,
					 IN PVOID StartVa,
					 OUT OPTIONAL PULONG PfnIndex)
{
    ULONG_PTR CurrentVa = 0;
    PHYSICAL_ADDRESS PhyAddr = { .QuadPart = 0 };
    if (PfnIndex) {
	*PfnIndex = ULONG_MAX;
    }
    for (int i = 0; i < Mdl->PfnCount; i++) {
	ULONG PageCount = MDL_PFN_PAGE_COUNT(Mdl->PfnEntries[i]);
	SIZE_T PageSize = MDL_PFN_PAGE_SIZE(Mdl->PfnEntries[i]);
	ULONG_PTR NextVa = CurrentVa + PageCount * PageSize;
	if (CurrentVa <= (ULONG_PTR)StartVa && (ULONG_PTR)StartVa < NextVa) {
	    PhyAddr.QuadPart = MDL_PFN_PAGE_ADDRESS(Mdl->PfnEntries[i]) +
		(ULONG_PTR)StartVa - CurrentVa;
	    if (PfnIndex) {
		*PfnIndex = i;
	    }
	    break;
	}
	CurrentVa = NextVa;
    }
    assert(PhyAddr.QuadPart != 0);
    return PhyAddr;
}

/*
 * @name MiGetMdlPhysicallyContiguousRegion
 *
 * Returns the size of the physically contiguous region starting from the
 * specified virtual address of the MDL. If BoundAddrBits is not NULL, it
 * defines what is considered "physically contiguous".
 *
 * @param Mdl
 *        MDL to query
 * @param StartVa
 *        Starting virtual address of the buffer described by the MDL.
 * @param BoundAddrBits
 *        If this is non-zero, it will define the boundary addresses
 *        across which pages are considered physically non-contiguous.
 *        For instance, if 16 is specified here, addresses 0x1FFFF and
 *        0x20000 are considered non-contiguous. If specified, this
 *        must be at least PAGE_SHIFT (12).
 *
 * @remarks
 *    This doesn't exist in Windows/ReactOS and is Neptune OS only.
 */
SIZE_T MiGetMdlPhysicallyContiguousSize(IN PMDL Mdl,
					IN PVOID StartVa,
					IN ULONG BoundAddrBits)
{
    ULONG_PTR CurrentVa = 0;
    for (int i = 0; i < Mdl->PfnCount; i++) {
	ULONG PageCount = MDL_PFN_PAGE_COUNT(Mdl->PfnEntries[i]);
	SIZE_T PageSize = MDL_PFN_PAGE_SIZE(Mdl->PfnEntries[i]);
	ULONG_PTR NextVa = CurrentVa + PageCount * PageSize;
	if (CurrentVa <= (ULONG_PTR)StartVa && (ULONG_PTR)StartVa < NextVa) {
	    ULONG ByteOffset = (ULONG_PTR)StartVa & (PageSize - 1);
	    if (BoundAddrBits >= PAGE_SHIFT) {
		BoundAddrBits -= PAGE_SHIFT;
		ULONG_PTR Pfn = Mdl->PfnEntries[i] >> PAGE_SHIFT;
		ULONG_PTR PfnEnd = Pfn + (PageCount * PageSize >> PAGE_SHIFT);
		if ((Pfn ^ PfnEnd) & ~((1ULL << BoundAddrBits) - 1)) {
		    PfnEnd = ((Pfn >> BoundAddrBits) + 1) << BoundAddrBits;
		    return (PfnEnd - Pfn) * PAGE_SIZE - ByteOffset;
		}
	    }
	    return PageCount * PageSize - ByteOffset;
	}
	CurrentVa = NextVa;
    }
    assert(FALSE);
    return 0;
}

/*
 * For libsel4, required in both debug and release build.
 */
VOID __assert_fail(PCSTR str, PCSTR file, int line, PCSTR function)
{
    DbgPrint("Assertion %s failed in function %s at line %d of file %s\n",
	     str, function, line, file);
    /* Loop forever */
    while (1);
}

/*
 * Make a beep through the PC speaker. Returns TRUE is beep is successful.
 */
NTAPI BOOLEAN HalMakeBeep(IN ULONG Frequency)
{
    return NT_SUCCESS(WdmHalMakeBeep(Frequency));
}

/*
 * @implemented
 *
 * @remarks
 *     A driver that calls IoBuildDeviceIoControlRequest must NOT call IoFreeIrp.
 *     The IO manager will free these IRPs after IoCompleteRequest has been called.
 */
NTAPI PIRP IoBuildDeviceIoControlRequest(IN ULONG IoControlCode,
					 IN PDEVICE_OBJECT DeviceObject,
					 IN PVOID InputBuffer,
					 IN ULONG InputBufferLength,
					 IN PVOID OutputBuffer,
					 IN ULONG OutputBufferLength,
					 IN BOOLEAN InternalDeviceIoControl,
					 IN PKEVENT Event,
					 IN PIO_STATUS_BLOCK IoStatusBlock)
{
    if ((InputBuffer && !InputBufferLength) || (!InputBuffer && InputBufferLength)) {
	return NULL;
    }
    if ((OutputBuffer && !OutputBufferLength) || (!OutputBuffer && OutputBufferLength)) {
	return NULL;
    }

    PIRP Irp = IoAllocateIrp(DeviceObject->StackSize);
    if (!Irp)
	return NULL;

    PIO_STACK_LOCATION StackPtr = IoGetNextIrpStackLocation(Irp);
    StackPtr->DeviceObject = DeviceObject;
    ObReferenceObject(DeviceObject);
    StackPtr->MajorFunction = InternalDeviceIoControl ?
	IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL;

    StackPtr->Parameters.DeviceIoControl.IoControlCode = IoControlCode;
    StackPtr->Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
    StackPtr->Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;

    /* Note unlike Windows/ReactOS we simply store the buffer pointers
     * regardless of IO transfer type (buffered IO, direct IO, neither IO)
     * of the IOCTL code. Copying/mapping the IO buffers is taken care of
     * automatically by the system. */
    Irp->UserBuffer = OutputBuffer;
    StackPtr->Parameters.DeviceIoControl.Type3InputBuffer = InputBuffer;

    Irp->UserIosb = IoStatusBlock;
    Irp->UserEvent = Event;

    return Irp;
}

/*
 * @implemented
 */
NTAPI PIRP IoBuildAsynchronousFsdRequest(IN ULONG MajorFunction,
					 IN PDEVICE_OBJECT DeviceObject,
					 IN PVOID Buffer,
					 IN ULONG Length,
					 IN PLARGE_INTEGER StartingOffset,
					 IN OPTIONAL PIO_STATUS_BLOCK IoStatusBlock)
{
    if (Buffer && !Length) {
	assert(FALSE);
	return NULL;
    }

    PIRP Irp = IoAllocateIrp(DeviceObject->StackSize);
    if (!Irp)
	return NULL;

    PIO_STACK_LOCATION StackPtr = IoGetNextIrpStackLocation(Irp);
    StackPtr->DeviceObject = DeviceObject;
    ObReferenceObject(DeviceObject);
    StackPtr->MajorFunction = (UCHAR)MajorFunction;
    if (!Buffer && Length) {
	/* If Buffer is NULL but Length is not zero, in the case of a READ
	 * we set the IRP minor code to IRP_MN_MDL so the server will map the
	 * memory pages for us. In all other cases this is invalid. */
	if (MajorFunction == IRP_MJ_READ) {
	    StackPtr->MinorFunction = IRP_MN_MDL;
	} else {
	    IoFreeIrp(Irp);
	    assert(FALSE);
	    return NULL;
	}
    }

    /* Set the user buffer pointer if the IRP has one. Note again just like
     * the case in IoBuildDeviceIoControlRequest, unlike Windows/ReactOS
     * we ignore the IO transfer type and always assume NEITHER IO. */
    if ((MajorFunction != IRP_MJ_FLUSH_BUFFERS) && (MajorFunction != IRP_MJ_PNP) &&
	(MajorFunction != IRP_MJ_SHUTDOWN) && (MajorFunction != IRP_MJ_POWER)) {
	Irp->UserBuffer = Buffer;

	if (MajorFunction == IRP_MJ_READ) {
	    StackPtr->Parameters.Read.Length = Length;
	    StackPtr->Parameters.Read.ByteOffset = *StartingOffset;
	} else if (MajorFunction == IRP_MJ_WRITE) {
	    StackPtr->Parameters.Write.Length = Length;
	    StackPtr->Parameters.Write.ByteOffset = *StartingOffset;
	}
    }

    Irp->UserIosb = IoStatusBlock;
    return Irp;
}

/*
 * @implemented
 *
 * @remarks
 *     A driver that calls IoBuildSynchronousFsdRequest must NOT call IoFreeIrp.
 *     The IO manager will free these IRPs after IoCompleteRequest has been called.
 */
NTAPI PIRP IoBuildSynchronousFsdRequest(IN ULONG MajorFunction,
					IN PDEVICE_OBJECT DeviceObject,
					IN PVOID Buffer,
					IN ULONG Length,
					IN PLARGE_INTEGER StartingOffset,
					IN PKEVENT Event,
					IN PIO_STATUS_BLOCK IoStatusBlock)
{
    assert(Event);
    /* Do the big work to set up the IRP */
    PIRP Irp = IoBuildAsynchronousFsdRequest(MajorFunction,
					     DeviceObject,
					     Buffer,
					     Length,
					     StartingOffset,
					     IoStatusBlock);
    if (!Irp)
	return NULL;

    /* Set the user event which makes the IRP synchronous */
    Irp->UserEvent = Event;

    return Irp;
}

static NTAPI NTSTATUS IopSynchronousCompletion(IN PDEVICE_OBJECT DeviceObject,
					       IN PIRP Irp,
					       IN PVOID Context)
{
    KeSetEvent((PKEVENT)Context);
    /* Returns STATUS_MORE_PROCESSING_REQUIRED so the IRP processing is stopped.
     * The caller of IoForwardIrpSynchronously can take control of the IRP,
     * usually either completing it (if the IRP comes from a thread) or free it
     * (if the driver has requested the IO itself). */
    return STATUS_MORE_PROCESSING_REQUIRED;
}

/*
 * Forward the IRP to a lower device object, and wait for its completion.
 * After this routine returns, the caller is given full control of the IRP
 * object. It may complete the IRP if it comes from the IO manager, or free
 * it if the IRP is created by the device driver itself.
 */
NTAPI BOOLEAN IoForwardIrpSynchronously(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp)
{
    /* Check if next stack location is available */
    if (Irp->CurrentLocation > Irp->StackCount || Irp->CurrentLocation <= 1) {
	/* This should not happen. It usually means we did not track the
	 * StackSize of the device object correctly. */
	assert(FALSE);
        return FALSE;
    }

    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    IoCopyCurrentIrpStackLocationToNext(Irp);
    IoSetCompletionRoutine(Irp, IopSynchronousCompletion, &Event, TRUE, TRUE, TRUE);
    NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Suspended, KernelMode, FALSE, NULL);
    }
    return TRUE;
}

static NTSTATUS IopReadWritePciConfigSpace(IN PDEVICE_OBJECT DeviceObject,
					   IN BOOLEAN Write,
					   IN OUT PVOID Buffer,
					   IN ULONG Offset,
					   IN OUT ULONG *Length)
{
    PAGED_CODE();
    KEVENT Event;
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);
    IO_STATUS_BLOCK IoStatusBlock;
    PIRP Irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP,
					    DeviceObject,
					    NULL,
					    0,
					    NULL,
					    &Event,
					    &IoStatusBlock);
    if (Irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    PIO_STACK_LOCATION IoStack = IoGetNextIrpStackLocation(Irp);
    if (Write) {
        IoStack->MinorFunction = IRP_MN_WRITE_CONFIG;
    } else {
        IoStack->MinorFunction = IRP_MN_READ_CONFIG;
    }
    IoStack->Parameters.ReadWriteConfig.WhichSpace = PCI_WHICHSPACE_CONFIG;
    IoStack->Parameters.ReadWriteConfig.Buffer = Buffer;
    IoStack->Parameters.ReadWriteConfig.Offset = Offset;
    IoStack->Parameters.ReadWriteConfig.Length = *Length;

    NTSTATUS Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }
    *Length = Irp->IoStatus.Information;
    return Status;
}

/*
 * Read the PCI config data into the given buffer. The DeviceObject must be part
 * of a PCI device stack.
 */
NTSTATUS IoReadPciConfigSpace(IN PDEVICE_OBJECT DeviceObject,
			      OUT PVOID Buffer,
			      IN ULONG Offset,
			      IN OUT ULONG *Length)
{
    return IopReadWritePciConfigSpace(DeviceObject, FALSE, Buffer, Offset, Length);
}

/*
 * Write the PCI config data from the given buffer. The DeviceObject must be part
 * of a PCI device stack.
 */
NTSTATUS IoWritePciConfigSpace(IN PDEVICE_OBJECT DeviceObject,
			       IN PVOID Buffer,
			       IN ULONG Offset,
			       IN OUT ULONG *Length)
{
    return IopReadWritePciConfigSpace(DeviceObject, TRUE, Buffer, Offset, Length);
}

/*
 * UUID helper routines
 */
NTAPI NTSTATUS ExUuidCreate(OUT UUID *Uuid)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}
