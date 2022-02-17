/*
 * PROJECT:     ReactOS i8042 (ps/2 keyboard-mouse controller) driver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        drivers/input/i8042prt/i8042prt.c
 * PURPOSE:     Driver entry function
 * PROGRAMMERS: Copyright Victor Kirhenshtein (sauros@iname.com)
 Copyright Jason Filby (jasonfilby@yahoo.com)
 Copyright Martijn Vernooij (o112w8r02@sneakemail.com)
 Copyright 2006-2007 Hervé Poussineau (hpoussin@reactos.org)
*/

/* INCLUDES ******************************************************************/

#include "i8042prt.h"
#include <debug.h>

/* FUNCTIONS *****************************************************************/

static DRIVER_STARTIO i8042StartIo;
static DRIVER_DISPATCH i8042DeviceControl;
static DRIVER_DISPATCH i8042InternalDeviceControl;
static DRIVER_DISPATCH i8042SystemControl;
static DRIVER_DISPATCH i8042Power;
DRIVER_INITIALIZE DriverEntry;

NTAPI NTSTATUS ForwardIrpAndForget(IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp)
{
    PDEVICE_OBJECT LowerDevice = ((PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->LowerDevice;
    assert(LowerDevice != NULL);

    return IoCallDriver(LowerDevice, Irp);
}

NTAPI NTSTATUS i8042AddDevice(IN PDRIVER_OBJECT DriverObject,
			      IN PDEVICE_OBJECT Pdo)
{
    TRACE_(I8042PRT, "i8042AddDevice(%p %p)\n", DriverObject, Pdo);

    PI8042_DRIVER_EXTENSION DriverExtension =
	(PI8042_DRIVER_EXTENSION)IoGetDriverObjectExtension(DriverObject,
							    DriverObject);

    if (Pdo == NULL) {
	/* This should never happen. Ignore it in release build and assert on debug build */
	assert(FALSE);
	return STATUS_SUCCESS;
    }

    /* Create new device object. As we don't know if the device would be a keyboard
     * or a mouse, we have to allocate the biggest device extension. */
    ULONG DeviceExtensionSize = MAX(sizeof(I8042_KEYBOARD_EXTENSION),
				    sizeof(I8042_MOUSE_EXTENSION));
    PDEVICE_OBJECT Fdo = NULL;
    NTSTATUS Status = IoCreateDevice(DriverObject, DeviceExtensionSize, NULL,
				     Pdo->DeviceType, FILE_DEVICE_SECURE_OPEN, TRUE,
				     &Fdo);
    if (!NT_SUCCESS(Status)) {
	WARN_(I8042PRT, "IoCreateDevice() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }

    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)Fdo->DeviceExtension;
    RtlZeroMemory(DeviceExtension, DeviceExtensionSize);
    DeviceExtension->Type = Unknown;
    DeviceExtension->Fdo = Fdo;
    DeviceExtension->Pdo = Pdo;
    DeviceExtension->PortDeviceExtension = &DriverExtension->Port;
    InitializeListHead(&DeviceExtension->PendingReadIrpList);
    Status = IoAttachDeviceToDeviceStackSafe(Fdo, Pdo,
					     &DeviceExtension->LowerDevice);
    if (!NT_SUCCESS(Status)) {
	WARN_(I8042PRT,
	      "IoAttachDeviceToDeviceStackSafe() failed with status 0x%08x\n",
	      Status);
	goto cleanup;
    }

    InsertTailList(&DriverExtension->DeviceListHead,
		   &DeviceExtension->ListEntry);

    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;

cleanup:
    if (DeviceExtension && DeviceExtension->LowerDevice)
	IoDetachDevice(DeviceExtension->LowerDevice);
    if (Fdo)
	IoDeleteDevice(Fdo);
    return Status;
}

NTAPI VOID i8042SendHookWorkItem(IN PDEVICE_OBJECT DeviceObject,
				 IN PVOID Context)
{
    TRACE_(I8042PRT, "i8042SendHookWorkItem(%p %p)\n", DeviceObject,
	   Context);

    PI8042_HOOK_WORKITEM WorkItemData = (PI8042_HOOK_WORKITEM)Context;
    PFDO_DEVICE_EXTENSION FdoDeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PPORT_DEVICE_EXTENSION PortDeviceExtension = FdoDeviceExtension->PortDeviceExtension;

    ULONG IoControlCode;
    PVOID InputBuffer;
    ULONG InputBufferLength;
    switch (FdoDeviceExtension->Type) {
    case Keyboard:
    {
	PI8042_KEYBOARD_EXTENSION DeviceExtension = (PI8042_KEYBOARD_EXTENSION) FdoDeviceExtension;
	IoControlCode = IOCTL_INTERNAL_I8042_HOOK_KEYBOARD;
	InputBuffer = &DeviceExtension->KeyboardHook;
	InputBufferLength = sizeof(INTERNAL_I8042_HOOK_KEYBOARD);
	break;
    }
    case Mouse:
    {
	PI8042_MOUSE_EXTENSION DeviceExtension = (PI8042_MOUSE_EXTENSION)FdoDeviceExtension;
	IoControlCode = IOCTL_INTERNAL_I8042_HOOK_MOUSE;
	InputBuffer = &DeviceExtension->MouseHook;
	InputBufferLength = sizeof(INTERNAL_I8042_HOOK_MOUSE);
	break;
    }
    default:
    {
	ERR_(I8042PRT, "Unknown FDO type %u\n",
	     FdoDeviceExtension->Type);
	ASSERT(FALSE);
	WorkItemData->Irp->IoStatus.Status = STATUS_INTERNAL_ERROR;
	goto cleanup;
    }
    }

    PDEVICE_OBJECT TopOfStack = IoGetAttachedDeviceReference(DeviceObject);

    IO_STATUS_BLOCK IoStatus;
    PIRP NewIrp = IoBuildDeviceIoControlRequest(IoControlCode,
						TopOfStack,
						InputBuffer,
						InputBufferLength,
						NULL,
						0, TRUE, &IoStatus);

    if (!NewIrp) {
	WARN_(I8042PRT, "IoBuildDeviceIoControlRequest() failed\n");
	WorkItemData->Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
	goto cleanup;
    }

    NTSTATUS Status = IoCallDriverEx(TopOfStack, NewIrp, NULL);

    if (FdoDeviceExtension->Type == Keyboard) {
	PI8042_KEYBOARD_EXTENSION DeviceExtension = (PI8042_KEYBOARD_EXTENSION)FdoDeviceExtension;
	/* Call the hooked initialization if it exists */
	if (DeviceExtension->KeyboardHook.InitializationRoutine) {
	    Status = DeviceExtension->KeyboardHook.InitializationRoutine(
		DeviceExtension->KeyboardHook.Context, PortDeviceExtension,
		i8042SynchReadPort, i8042SynchWritePortKbd, FALSE);
	    if (!NT_SUCCESS(Status)) {
		WARN_(I8042PRT,
		      "KeyboardHook.InitializationRoutine() failed with status 0x%08x\n",
		      Status);
		WorkItemData->Irp->IoStatus.Status = Status;
		goto cleanup;
	    }
	}
    }

    WorkItemData->Irp->IoStatus.Status = STATUS_SUCCESS;

cleanup:
    WorkItemData->Irp->IoStatus.Information = 0;
    IoCompleteRequest(WorkItemData->Irp, IO_NO_INCREMENT);

    IoFreeWorkItem(WorkItemData->WorkItem);
    ExFreePoolWithTag(WorkItemData, I8042PRT_TAG);
}

static NTAPI VOID i8042StartIo(IN PDEVICE_OBJECT DeviceObject,
			       IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    switch (DeviceExtension->Type) {
    case Keyboard:
	i8042KbdStartIo(DeviceObject, Irp);
	break;
    default:
	ERR_(I8042PRT, "Unknown FDO type %u\n", DeviceExtension->Type);
	ASSERT(FALSE);
	break;
    }
}

/* Write the current byte of the packet. Returns FALSE in case
 * of problems.
 */
static BOOLEAN i8042PacketWrite(IN PPORT_DEVICE_EXTENSION DeviceExtension)
{
    UCHAR Port = DeviceExtension->PacketPort;

    if (Port) {
	if (!i8042Write(DeviceExtension, DeviceExtension->ControlPort, Port)) {
	    /* something is really wrong! */
	    WARN_(I8042PRT, "Failed to send packet byte!\n");
	    return FALSE;
	}
    }

    return i8042Write(DeviceExtension,
		      DeviceExtension->DataPort,
		      DeviceExtension->Packet.Bytes[DeviceExtension->Packet.CurrentByte]);
}

BOOLEAN i8042PacketIsr(IN PPORT_DEVICE_EXTENSION DeviceExtension,
		       IN UCHAR Output)
{
    if (DeviceExtension->Packet.State == Idle)
	return FALSE;

    switch (Output) {
    case KBD_RESEND:
	DeviceExtension->PacketResends++;
	if (DeviceExtension->PacketResends > DeviceExtension->Settings.ResendIterations) {
	    DeviceExtension->Packet.State = Idle;
	    DeviceExtension->PacketComplete = TRUE;
	    DeviceExtension->PacketResult = STATUS_IO_TIMEOUT;
	    DeviceExtension->PacketResends = 0;
	    return TRUE;
	}
	DeviceExtension->Packet.CurrentByte--;
	break;

    case KBD_NACK:
	DeviceExtension->Packet.State = Idle;
	DeviceExtension->PacketComplete = TRUE;
	DeviceExtension->PacketResult = STATUS_UNEXPECTED_IO_ERROR;
	DeviceExtension->PacketResends = 0;
	return TRUE;

    default:
	DeviceExtension->PacketResends = 0;
    }

    if (DeviceExtension->Packet.CurrentByte >= DeviceExtension->Packet.ByteCount) {
	DeviceExtension->Packet.State = Idle;
	DeviceExtension->PacketComplete = TRUE;
	DeviceExtension->PacketResult = STATUS_SUCCESS;
	return TRUE;
    }

    if (!i8042PacketWrite(DeviceExtension)) {
	DeviceExtension->Packet.State = Idle;
	DeviceExtension->PacketComplete = TRUE;
	DeviceExtension->PacketResult = STATUS_IO_TIMEOUT;
	return TRUE;
    }
    DeviceExtension->Packet.CurrentByte++;

    return TRUE;
}

/*
 * This function starts a packet. It must be called with the
 * correct DIRQL.
 */
NTSTATUS i8042StartPacket(IN PPORT_DEVICE_EXTENSION DeviceExtension,
			  IN PFDO_DEVICE_EXTENSION FdoDeviceExtension,
			  IN PUCHAR Bytes,
			  IN ULONG ByteCount,
			  IN PIRP Irp)
{
    NTSTATUS Status;

    IoAcquireInterruptMutex(DeviceExtension->HighestDIRQLInterrupt);

    if (DeviceExtension->Packet.State != Idle) {
	Status = STATUS_DEVICE_BUSY;
	goto done;
    }

    switch (FdoDeviceExtension->Type) {
    case Keyboard:
	DeviceExtension->PacketPort = 0;
	break;
    case Mouse:
	DeviceExtension->PacketPort = CTRL_WRITE_MOUSE;
	break;
    default:
	ERR_(I8042PRT, "Unknown FDO type %u\n", FdoDeviceExtension->Type);
	ASSERT(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto done;
    }

    DeviceExtension->Packet.Bytes = Bytes;
    DeviceExtension->Packet.CurrentByte = 0;
    DeviceExtension->Packet.ByteCount = ByteCount;
    DeviceExtension->Packet.State = SendingBytes;
    DeviceExtension->PacketResult = Status = STATUS_PENDING;
    DeviceExtension->CurrentIrp = Irp;
    DeviceExtension->CurrentIrpDevice = FdoDeviceExtension->Fdo;

    if (!i8042PacketWrite(DeviceExtension)) {
	Status = STATUS_IO_TIMEOUT;
	DeviceExtension->Packet.State = Idle;
	DeviceExtension->PacketResult = STATUS_ABANDONED;
	goto done;
    }

    DeviceExtension->Packet.CurrentByte++;

done:
    IoReleaseInterruptMutex(DeviceExtension->HighestDIRQLInterrupt);

    if (Status != STATUS_PENDING) {
	DeviceExtension->CurrentIrp = NULL;
	DeviceExtension->CurrentIrpDevice = NULL;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    return Status;
}

static NTAPI NTSTATUS i8042DeviceControl(IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp)
{
    TRACE_(I8042PRT, "i8042DeviceControl(%p %p)\n", DeviceObject, Irp);
    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION) DeviceObject->DeviceExtension;

    switch (DeviceExtension->Type) {
    case Keyboard:
	return i8042KbdDeviceControl(DeviceObject, Irp);
    default:
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTAPI NTSTATUS i8042InternalDeviceControl(IN PDEVICE_OBJECT DeviceObject,
						 IN PIRP Irp)
{
    NTSTATUS Status;

    TRACE_(I8042PRT, "i8042InternalDeviceControl(%p %p)\n", DeviceObject,
	   Irp);
    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    switch (DeviceExtension->Type) {
    case Unknown:
    {
	ULONG ControlCode = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode;
	switch (ControlCode) {
	case IOCTL_INTERNAL_KEYBOARD_CONNECT:
	    Status = i8042KbdInternalDeviceControl(DeviceObject, Irp);
	    break;
	case IOCTL_INTERNAL_MOUSE_CONNECT:
	    Status = i8042MouInternalDeviceControl(DeviceObject, Irp);
	    break;
	default:
	    ERR_(I8042PRT, "Unknown IO control code 0x%x\n", ControlCode);
	    ASSERT(FALSE);
	    Status = STATUS_INVALID_DEVICE_REQUEST;
	    break;
	}
	break;
    }
    case Keyboard:
	Status = i8042KbdInternalDeviceControl(DeviceObject, Irp);
	break;
    case Mouse:
	Status = i8042MouInternalDeviceControl(DeviceObject, Irp);
	break;
    default:
	ERR_(I8042PRT, "Unknown FDO type %u\n", DeviceExtension->Type);
	ASSERT(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	break;
    }

    return Status;
}

static inline BOOLEAN IrpIsInPendingReadQueue(IN PIRP Irp,
					      IN PFDO_DEVICE_EXTENSION DevExt)
{
    LoopOverList(Entry, &DevExt->PendingReadIrpList, IRP, Tail.ListEntry) {
	if (Entry == Irp) {
	    return TRUE;
	}
    }
    return FALSE;
}

static NTAPI VOID i8042CancelReadIrp(IN PDEVICE_OBJECT DeviceObject,
				     IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;

    TRACE_(I8042PRT, "i8042CancelRoutine(DeviceObject %p, Irp %p)\n",
	   DeviceObject, Irp);

    assert(IrpIsInPendingReadQueue(Irp, DeviceExtension));

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static NTSTATUS FillEntries(IN PDEVICE_OBJECT DeviceObject,
			    IN PIRP Irp,
			    IN PVOID DataStart,
			    IN SIZE_T NumberOfEntries,
			    IN SIZE_T EntrySize)
{
    INFO_(I8042PRT, "FillEntries %zd entries\n", NumberOfEntries);
    NTSTATUS Status = STATUS_SUCCESS;
    SIZE_T Size = NumberOfEntries * EntrySize;

    if (DeviceObject->Flags & DO_BUFFERED_IO) {
	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, DataStart, Size);
    } else if (DeviceObject->Flags & DO_DIRECT_IO) {
	PVOID DestAddress = MmGetSystemAddressForMdl(Irp->MdlAddress);
	if (DestAddress) {
	    RtlCopyMemory(DestAddress, DataStart, Size);
	} else {
	    Status = STATUS_UNSUCCESSFUL;
	}
    } else {
	RtlCopyMemory(Irp->UserBuffer, DataStart, Size);
    }

    return Status;
}

static NTAPI NTSTATUS i8042HandleReadIrp(IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp)
{
    TRACE_(I8042PRT, "i8042HandleReadIrp(%p %p)\n", DeviceObject, Irp);
    PFDO_DEVICE_EXTENSION DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PPORT_DEVICE_EXTENSION PortDeviceExtension = DeviceExtension->PortDeviceExtension;

    SIZE_T EntrySize = 0;
    if (DeviceExtension->Type == Keyboard) {
	EntrySize = sizeof(KEYBOARD_INPUT_DATA);
    } else if(DeviceExtension->Type == Mouse) {
	EntrySize = sizeof(MOUSE_INPUT_DATA);
    } else {
	ERR_(I8042PRT, "Unknown FDO type %u\n", DeviceExtension->Type);
	ASSERT(FALSE);
	NTSTATUS Status = STATUS_NO_SUCH_DEVICE;
	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
    }

    PIO_STACK_LOCATION IoStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IoStack->MajorFunction == IRP_MJ_READ);

    IoAcquireInterruptMutex(PortDeviceExtension->HighestDIRQLInterrupt);
    ULONG EntriesInBuffer = DeviceExtension->EntriesInBuffer;
    IoReleaseInterruptMutex(PortDeviceExtension->HighestDIRQLInterrupt);

    if (EntriesInBuffer == 0) {
	/* We shouldn't have any synchronization issues here unlike Windows,
	 * so this IRP should never have been canceled at this point. */
	IoMarkIrpPending(Irp);
	InsertTailList(&DeviceExtension->PendingReadIrpList, &Irp->Tail.ListEntry);
	IoSetCancelRoutine(Irp, i8042CancelReadIrp);
	return STATUS_PENDING;
    }

    SIZE_T NumberOfEntries = IoStack->Parameters.Read.Length / EntrySize;
    if (NumberOfEntries > EntriesInBuffer) {
	NumberOfEntries = EntriesInBuffer;
    }
    NTSTATUS Status = FillEntries(DeviceObject, Irp, DeviceExtension->Buffer,
				  NumberOfEntries, EntrySize);
    if (NT_SUCCESS(Status)) {
	IoAcquireInterruptMutex(PortDeviceExtension->HighestDIRQLInterrupt);
	if (EntriesInBuffer > NumberOfEntries) {
	    RtlMoveMemory(DeviceExtension->Buffer,
			  DeviceExtension->Buffer + NumberOfEntries,
			  (EntriesInBuffer - NumberOfEntries) * EntrySize);
	}
	DeviceExtension->EntriesInBuffer -= NumberOfEntries;
	IoReleaseInterruptMutex(PortDeviceExtension->HighestDIRQLInterrupt);
	Irp->IoStatus.Information = NumberOfEntries * EntrySize;
    }

    /* Complete this request */
    Irp->IoStatus.Status = Status;
    IoSetCancelRoutine(Irp, NULL);
    IoCompleteRequest(Irp, IO_KEYBOARD_INCREMENT);
    return Status;
}

VOID ProcessPendingReadIrps(IN PDEVICE_OBJECT DeviceObject)
{
    PFDO_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    LoopOverList(Irp, &DeviceExtension->PendingReadIrpList, IRP, Tail.ListEntry) {
	RemoveEntryList(&Irp->Tail.ListEntry);
	if (i8042HandleReadIrp(DeviceObject, Irp) == STATUS_PENDING) {
	    InsertTailList(&DeviceExtension->PendingReadIrpList, &Irp->Tail.ListEntry);
	    break;
	}
    }
}

static NTAPI NTSTATUS i8042Power(IN PDEVICE_OBJECT DeviceObject,
				 IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
    PDEVICE_OBJECT LowerDevice = DeviceExtension->LowerDevice;

    return IoCallDriver(LowerDevice, Irp);
}

static NTAPI NTSTATUS i8042SystemControl(IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp)
{
    return ForwardIrpAndForget(DeviceObject, Irp);
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    PI8042_DRIVER_EXTENSION DriverExtension;
    NTSTATUS Status = IoAllocateDriverObjectExtension(DriverObject,
						      DriverObject,
						      sizeof(I8042_DRIVER_EXTENSION),
						      (PVOID *) &DriverExtension);
    if (!NT_SUCCESS(Status)) {
	WARN_(I8042PRT,
	      "IoAllocateDriverObjectExtension() failed with status 0x%08x\n",
	      Status);
	return Status;
    }
    RtlZeroMemory(DriverExtension, sizeof(I8042_DRIVER_EXTENSION));
    InitializeListHead(&DriverExtension->DeviceListHead);

    Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
				       RegistryPath,
				       &DriverExtension->RegistryPath);
    if (!NT_SUCCESS(Status)) {
	WARN_(I8042PRT,
	      "DuplicateUnicodeString() failed with status 0x%08x\n",
	      Status);
	return Status;
    }

    Status = ReadRegistryEntries(&DriverExtension->RegistryPath,
				 &DriverExtension->Port.Settings);
    if (!NT_SUCCESS(Status)) {
	WARN_(I8042PRT,
	      "ReadRegistryEntries() failed with status 0x%08x\n",
	      Status);
	return Status;
    }

    DriverObject->AddDevice = i8042AddDevice;
    DriverObject->DriverStartIo = i8042StartIo;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = i8042Create;
    DriverObject->MajorFunction[IRP_MJ_READ] = i8042HandleReadIrp;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = i8042Cleanup;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = i8042Close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = i8042DeviceControl;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = i8042InternalDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_POWER] = i8042Power;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = i8042SystemControl;
    DriverObject->MajorFunction[IRP_MJ_PNP] = i8042Pnp;

    // This is disabled for now since we don't want to implement WMI as of yet.
    // i8042InitializeHwHacks();

    return STATUS_SUCCESS;
}
