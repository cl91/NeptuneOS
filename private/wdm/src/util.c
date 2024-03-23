#include <wdmp.h>

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
 * @name MmGetMdlPhysicalAddress
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
NTAPI PHYSICAL_ADDRESS MmGetMdlPhysicalAddress(IN PMDL Mdl,
					       IN PVOID StartVa)
{
    ULONG_PTR CurrentVa = 0;
    PHYSICAL_ADDRESS PhyAddr = { .QuadPart = 0 };
    for (int i = 0; i < Mdl->PfnCount; i++) {
	ULONG PageCount = MDL_PFN_PAGE_COUNT(Mdl->PfnEntries[i]);
	SIZE_T PageSize = MDL_PFN_PAGE_SIZE(Mdl->PfnEntries[i]);
	ULONG_PTR NextVa = CurrentVa + PageCount * PageSize;
	if (CurrentVa <= (ULONG_PTR)StartVa && (ULONG_PTR)StartVa < NextVa) {
	    PhyAddr.QuadPart = MDL_PFN_PAGE_ADDRESS(Mdl->PfnEntries[i]) +
		(ULONG_PTR)StartVa & (MDL_PFN_PAGE_SIZE(Mdl->PfnEntries[i]) - 1);
	    break;
	}
	CurrentVa = NextVa;
    }
    assert(PhyAddr.QuadPart != 0);
    return PhyAddr;
}

/*
 * @name MmGetMdlPhysicallyContiguousRegion
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
NTAPI SIZE_T MmGetMdlPhysicallyContiguousSize(IN PMDL Mdl,
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
 */
NTAPI PIRP IoBuildDeviceIoControlRequest(IN ULONG IoControlCode,
					 IN PDEVICE_OBJECT DeviceObject,
					 IN PVOID InputBuffer,
					 IN ULONG InputBufferLength,
					 IN PVOID OutputBuffer,
					 IN ULONG OutputBufferLength,
					 IN BOOLEAN InternalDeviceIoControl,
					 IN PIO_STATUS_BLOCK IoStatusBlock)
{
    if ((InputBuffer && !InputBufferLength) || (!InputBuffer && InputBufferLength)) {
	return NULL;
    }
    if ((OutputBuffer && !OutputBufferLength) || (!OutputBuffer && OutputBufferLength)) {
	return NULL;
    }

    PIRP Irp = IoAllocateIrp();
    if (!Irp)
	return NULL;

    PIO_STACK_LOCATION StackPtr = IoGetCurrentIrpStackLocation(Irp);
    StackPtr->DeviceObject = DeviceObject;
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

    return Irp;
}

/*
 * @implemented
 */
NTAPI PIRP IoBuildAsynchronousFsdRequest(IN ULONG MajorFunction,
					 IN PDEVICE_OBJECT DeviceObject,
					 IN PVOID Buffer,
					 IN ULONG Length,
					 IN PLARGE_INTEGER StartingOffset)
{
    if (Buffer && !Length) {
	assert(FALSE);
	return NULL;
    }

    PIRP Irp = IoAllocateIrp();
    if (!Irp)
	return NULL;

    PIO_STACK_LOCATION StackPtr = IoGetCurrentIrpStackLocation(Irp);
    StackPtr->DeviceObject = DeviceObject;
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

    return Irp;
}

NTAPI PIRP IoBuildSynchronousFsdRequest(IN ULONG MajorFunction,
					IN PDEVICE_OBJECT DeviceObject,
					IN PVOID Buffer,
					IN ULONG Length,
					IN PLARGE_INTEGER StartingOffset,
					IN PIO_STATUS_BLOCK IoStatusBlock)
{
    /* Do the big work to set up the IRP */
    PIRP Irp = IoBuildAsynchronousFsdRequest(MajorFunction,
					     DeviceObject,
					     Buffer,
					     Length,
					     StartingOffset);
    if (!Irp)
	return NULL;

    /* Set the IO status block which makes it Synchronous */
    Irp->UserIosb = IoStatusBlock;

    return Irp;
}
