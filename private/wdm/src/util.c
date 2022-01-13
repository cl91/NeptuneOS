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

    /* Set the DevCtl Type */
    StackPtr->MajorFunction = InternalDeviceIoControl ?
	IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL;

    /* Set the IOCTL Data */
    StackPtr->Parameters.DeviceIoControl.IoControlCode = IoControlCode;
    StackPtr->Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
    StackPtr->Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;

    /* Note: unlink Windows/ReactOS we simply store the buffer pointers
     * since seL4 guarantees that mapped page access is always safe. */
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

    /* Write the Major function and then deal with it */
    StackPtr->MajorFunction = (UCHAR) MajorFunction;

    /* Set the user buffer pointer if the IRP has one */
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
