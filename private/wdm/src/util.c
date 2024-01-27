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
 *        Index into the MDL, with respect to MmGetMdlVirtualAddress
 *
 * @remarks
 *    Note that this function doesn't exist in Windows/ReactOS and is
 *    an Neptune OS addition.
 */
NTAPI PHYSICAL_ADDRESS MmGetMdlPhysicalAddress(IN PMDL Mdl,
					       IN PVOID StartVa)
{
    ULONG_PTR Rva = (ULONG_PTR)StartVa - (ULONG_PTR)MmGetMdlVirtualAddress(Mdl);
    ULONG_PTR CurrentRva = 0;
    PHYSICAL_ADDRESS PhyAddr = { .QuadPart = 0 };
    for (int i = 0; i < Mdl->PfnCount; i++) {
	ULONG PageCount = (Mdl->PfnEntries[i] >> MDL_PFN_ATTR_BITS) & MDL_PFN_PAGE_COUNT_MASK;
	SIZE_T PageSize = (Mdl->PfnEntries[i] & MDL_PFN_ATTR_LARGE_PAGE) ? PAGE_SIZE : LARGE_PAGE_SIZE;
	ULONG_PTR NextRva = CurrentRva + PageCount * PageSize;
	if (CurrentRva <= Rva && Rva < NextRva) {
	    PhyAddr.QuadPart = (Mdl->PfnEntries[i] >> PAGE_SHIFT) << PAGE_SHIFT;
	    break;
	}
    }
    assert(PhyAddr.QuadPart != 0);
    return PhyAddr;
}

/*
 * @name MmGetMdlPhysicallyContiguousRegion
 *
 * Returns the size of the physically contiguous region starting from the
 * specified virtual address (with respect to MmGetMdlVirtualAddress) of
 * the MDL. If BoundAddrMul is not NULL, it defines what is considered
 * "physically contiguous".
 *
 * @param Mdl
 *        MDL to query
 * @param StartVa
 *        Index into the MDL, with respect to MmGetMdlVirtualAddress
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
    ULONG_PTR Rva = (ULONG_PTR)StartVa - (ULONG_PTR)MmGetMdlVirtualAddress(Mdl);
    ULONG_PTR CurrentRva = 0;
    for (int i = 0; i < Mdl->PfnCount; i++) {
	ULONG PageCount = (Mdl->PfnEntries[i] >> MDL_PFN_ATTR_BITS) & MDL_PFN_PAGE_COUNT_MASK;
	SIZE_T PageSize = (Mdl->PfnEntries[i] & MDL_PFN_ATTR_LARGE_PAGE) ? PAGE_SIZE : LARGE_PAGE_SIZE;
	ULONG_PTR NextRva = CurrentRva + PageCount * PageSize;
	if (CurrentRva <= Rva && Rva < NextRva) {
	    if (BoundAddrBits >= PAGE_SHIFT) {
		BoundAddrBits -= PAGE_SHIFT;
		ULONG_PTR Pfn = Mdl->PfnEntries[i] >> PAGE_SHIFT;
		ULONG_PTR PfnEnd = Pfn + (PageCount * PageSize >> PAGE_SHIFT);
		if ((Pfn ^ PfnEnd) & ~((1ULL << BoundAddrBits) - 1)) {
		    PfnEnd = ((Pfn >> BoundAddrBits) + 1) << BoundAddrBits;
		    return (PfnEnd - Pfn) * PAGE_SIZE;
		}
	    }
	    return PageCount * PageSize;
	}
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
    return NT_SUCCESS(HalpMakeBeep(Frequency));
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
    /* Allocate IRP */
    PIRP Irp = IoAllocateIrp();
    if (!Irp)
	return NULL;

    /* Get the Stack */
    PIO_STACK_LOCATION StackPtr = IoGetCurrentIrpStackLocation(Irp);

    /* Set the Device Object */
    StackPtr->DeviceObject = DeviceObject;

    /* Set the DevCtl Type */
    StackPtr->MajorFunction = InternalDeviceIoControl ?
	IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL;

    /* Set the IOCTL Data */
    StackPtr->Parameters.DeviceIoControl.IoControlCode = IoControlCode;
    StackPtr->Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
    StackPtr->Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;

    /* Note unlike Windows/ReactOS we simply store the buffer pointers
     * regardless of IO transfer type (buffered IO, direct IO, neither IO)
     * of the IOCTL code. Copying/mapping the IO buffers is taken care of
     * automatically by the system. */
    Irp->UserBuffer = OutputBuffer;
    StackPtr->Parameters.DeviceIoControl.Type3InputBuffer = InputBuffer;

    /* Now write the IoSB */
    Irp->UserIosb = IoStatusBlock;

    /* Return the IRP */
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
    /* Allocate IRP */
    PIRP Irp = IoAllocateIrp();
    if (!Irp)
	return NULL;

    /* Get the Stack */
    PIO_STACK_LOCATION StackPtr = IoGetCurrentIrpStackLocation(Irp);

    /* Set the Device Object */
    StackPtr->DeviceObject = DeviceObject;

    /* Write the Major function and then deal with it */
    StackPtr->MajorFunction = (UCHAR) MajorFunction;

    /* Set the user buffer pointer if the IRP has one. Note again just like
     * the case in IoBuildDeviceIoControlRequest, unlike Windows/ReactOS
     * we ignore the IO transfer type and always assume NEITHER IO. */
    if ((MajorFunction != IRP_MJ_FLUSH_BUFFERS) && (MajorFunction != IRP_MJ_PNP) &&
	(MajorFunction != IRP_MJ_SHUTDOWN) && (MajorFunction != IRP_MJ_POWER)) {
	Irp->UserBuffer = Buffer;

	/* Check if this is a read */
	if (MajorFunction == IRP_MJ_READ) {
	    /* Set the parameters for a read */
	    StackPtr->Parameters.Read.Length = Length;
	    StackPtr->Parameters.Read.ByteOffset = *StartingOffset;
	} else if (MajorFunction == IRP_MJ_WRITE) {
	    /* Otherwise, set write parameters */
	    StackPtr->Parameters.Write.Length = Length;
	    StackPtr->Parameters.Write.ByteOffset = *StartingOffset;
	}
    }

    /* Return the IRP */
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
