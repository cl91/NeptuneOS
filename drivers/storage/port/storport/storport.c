/*
 * PROJECT:     ReactOS Storport Driver
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Storport driver main file
 * COPYRIGHT:   Copyright 2017 Eric Kohl (eric.kohl@reactos.org)
 */

/* INCLUDES *******************************************************************/

#include "precomp.h"
#include <stdio.h>
#include <pci.h>

/* GLOBALS ********************************************************************/

ULONG PortNumber = 0;

/* FUNCTIONS ******************************************************************/

static NTSTATUS PortAddDriverInitData(PDRIVER_OBJECT_EXTENSION DriverExtension,
				      PHW_INITIALIZATION_DATA HwInitializationData)
{
    PDRIVER_INIT_DATA InitData;

    DPRINT1("PortAddDriverInitData()\n");

    InitData = ExAllocatePoolWithTag(sizeof(DRIVER_INIT_DATA), TAG_INIT_DATA);
    if (InitData == NULL)
	return STATUS_NO_MEMORY;

    RtlCopyMemory(&InitData->HwInitData, HwInitializationData,
		  sizeof(HW_INITIALIZATION_DATA));

    InsertHeadList(&DriverExtension->InitDataListHead, &InitData->Entry);

    return STATUS_SUCCESS;
}

static VOID PortDeleteDriverInitData(PDRIVER_OBJECT_EXTENSION DriverExtension)
{
    PDRIVER_INIT_DATA InitData;
    PLIST_ENTRY ListEntry;

    DPRINT1("PortDeleteDriverInitData()\n");

    ListEntry = DriverExtension->InitDataListHead.Flink;
    while (ListEntry != &DriverExtension->InitDataListHead) {
	InitData = CONTAINING_RECORD(ListEntry, DRIVER_INIT_DATA, Entry);

	RemoveEntryList(&InitData->Entry);

	ExFreePoolWithTag(InitData, TAG_INIT_DATA);

	ListEntry = DriverExtension->InitDataListHead.Flink;
    }
}

PHW_INITIALIZATION_DATA PortGetDriverInitData(PDRIVER_OBJECT_EXTENSION DriverExtension,
					      INTERFACE_TYPE InterfaceType)
{
    PDRIVER_INIT_DATA InitData;
    PLIST_ENTRY ListEntry;

    DPRINT1("PortGetDriverInitData()\n");

    ListEntry = DriverExtension->InitDataListHead.Flink;
    while (ListEntry != &DriverExtension->InitDataListHead) {
	InitData = CONTAINING_RECORD(ListEntry, DRIVER_INIT_DATA, Entry);
	if (InitData->HwInitData.AdapterInterfaceType == InterfaceType)
	    return &InitData->HwInitData;

	ListEntry = ListEntry->Flink;
    }

    return NULL;
}

static VOID PortAcquireSpinLock(PFDO_DEVICE_EXTENSION DeviceExtension,
				STOR_SPINLOCK SpinLock, PVOID LockContext,
				PSTOR_LOCK_HANDLE LockHandle)
{
    DPRINT1("PortAcquireSpinLock(%p %u %p %p)\n", DeviceExtension, SpinLock, LockContext,
	    LockHandle);

    LockHandle->Lock = SpinLock;

    switch (SpinLock) {
    case DpcLock: /* 1, */
	DPRINT1("DpcLock\n");
	/* TODO! This is not used by storahci so we don't need it yet. */
	assert(FALSE);
	break;

    case StartIoLock: /* 2 */
	DPRINT1("StartIoLock\n");
	/* We don't need locking for StartIo routines so do nothing here. */
	break;

    case InterruptLock: /* 3 */
	DPRINT1("InterruptLock\n");
	if (DeviceExtension->Interrupt) {
	    IoAcquireInterruptMutex(DeviceExtension->Interrupt);
	}
	break;
    }
}

static VOID PortReleaseSpinLock(PFDO_DEVICE_EXTENSION DeviceExtension,
				PSTOR_LOCK_HANDLE LockHandle)
{
    DPRINT1("PortReleaseSpinLock(%p %p)\n", DeviceExtension, LockHandle);

    switch (LockHandle->Lock) {
    case DpcLock: /* 1, */
	DPRINT1("DpcLock\n");
	break;

    case StartIoLock: /* 2 */
	DPRINT1("StartIoLock\n");
	break;

    case InterruptLock: /* 3 */
	DPRINT1("InterruptLock\n");
	if (DeviceExtension->Interrupt) {
	    IoReleaseInterruptMutex(DeviceExtension->Interrupt);
	}
	break;
    }
}

static NTAPI NTSTATUS PortAddDevice(IN PDRIVER_OBJECT DriverObject,
				    IN PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDRIVER_OBJECT_EXTENSION DriverObjectExtension;
    PFDO_DEVICE_EXTENSION DeviceExtension = NULL;
    WCHAR NameBuffer[80];
    UNICODE_STRING DeviceName;
    PDEVICE_OBJECT Fdo = NULL;
    NTSTATUS Status;

    DPRINT1("PortAddDevice(%p %p)\n", DriverObject, PhysicalDeviceObject);

    ASSERT(DriverObject);
    ASSERT(PhysicalDeviceObject);

    swprintf(NameBuffer, L"\\Device\\RaidPort%lu", PortNumber);
    RtlInitUnicodeString(&DeviceName, NameBuffer);
    PortNumber++;

    DPRINT1("Creating device: %wZ\n", &DeviceName);

    /* Create the port device */
    Status = IoCreateDevice(DriverObject, sizeof(FDO_DEVICE_EXTENSION), &DeviceName,
			    FILE_DEVICE_CONTROLLER,
			    FILE_DEVICE_SECURE_OPEN | DO_DIRECT_IO | DO_POWER_PAGABLE,
			    FALSE, &Fdo);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("IoCreateDevice() failed (Status 0x%08x)\n", Status);
	return Status;
    }

    DPRINT1("Created device: %wZ (%p)\n", &DeviceName, Fdo);

    /* Initialize the device extension */
    DeviceExtension = (PFDO_DEVICE_EXTENSION)Fdo->DeviceExtension;
    RtlZeroMemory(DeviceExtension, sizeof(FDO_DEVICE_EXTENSION));

    DeviceExtension->ExtensionType = FdoExtension;

    DeviceExtension->Device = Fdo;
    DeviceExtension->PhysicalDevice = PhysicalDeviceObject;

    DeviceExtension->PnpState = dsStopped;

    InitializeListHead(&DeviceExtension->PdoListHead);

    /* Attach the FDO to the device stack */
    Status = IoAttachDeviceToDeviceStackSafe(Fdo, PhysicalDeviceObject,
					     &DeviceExtension->LowerDevice);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("IoAttachDeviceToDeviceStackSafe() failed (Status 0x%08x)\n", Status);
	IoDeleteDevice(Fdo);
	return Status;
    }

    /* Insert the FDO to the drivers FDO list */
    DriverObjectExtension = IoGetDriverObjectExtension(DriverObject, (PVOID)DriverEntry);
    ASSERT(DriverObjectExtension->ExtensionType == DriverExtension);

    DeviceExtension->DriverExtension = DriverObjectExtension;

    InsertHeadList(&DriverObjectExtension->AdapterListHead,
		   &DeviceExtension->AdapterListEntry);
    DriverObjectExtension->AdapterCount++;

    /* The device has been initialized */
    Fdo->Flags &= ~DO_DEVICE_INITIALIZING;

    DPRINT1("PortAddDevice() done (Status 0x%08x)\n", Status);

    return Status;
}

static NTAPI VOID PortUnload(IN PDRIVER_OBJECT DriverObject)
{
    PDRIVER_OBJECT_EXTENSION DriverExtension;

    DPRINT1("PortUnload(%p)\n", DriverObject);

    DriverExtension = IoGetDriverObjectExtension(DriverObject, (PVOID)DriverEntry);
    if (DriverExtension != NULL) {
	PortDeleteDriverInitData(DriverExtension);
    }
}

static NTAPI NTSTATUS PortDispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DPRINT1("PortDispatchCreate(%p %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS PortDispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DPRINT1("PortDispatchClose(%p %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS PortDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject,
						IN PIRP Irp)
{
    DPRINT1("PortDispatchDeviceControl(%p %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS PortDispatchScsi(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT1("PortDispatchScsi(%p %p)\n", DeviceObject, Irp);

    DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    DPRINT1("ExtensionType: %u\n", DeviceExtension->ExtensionType);

    switch (DeviceExtension->ExtensionType) {
    case FdoExtension:
	return PortFdoScsi(DeviceObject, Irp);

    case PdoExtension:
	return PortPdoScsi(DeviceObject, Irp);

    default:
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS PortDispatchSystemControl(IN PDEVICE_OBJECT DeviceObject,
						IN PIRP Irp)
{
    DPRINT1("PortDispatchSystemControl(%p %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS PortDispatchPnp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT1("PortDispatchPnp(%p %p)\n", DeviceObject, Irp);

    DeviceExtension = (PFDO_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    DPRINT1("ExtensionType: %u\n", DeviceExtension->ExtensionType);

    switch (DeviceExtension->ExtensionType) {
    case FdoExtension:
	return PortFdoPnp(DeviceObject, Irp);

    case PdoExtension:
	return PortPdoPnp(DeviceObject, Irp);

    default:
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_UNSUCCESSFUL;
    }
}

static NTAPI NTSTATUS PortDispatchPower(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DPRINT1("PortDispatchPower(%p %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    DPRINT1("DriverEntry(%p %p)\n", DriverObject, RegistryPath);
    return STATUS_SUCCESS;
}

/*
 * @unimplemented
 */
NTAPI PUCHAR StorPortAllocateRegistryBuffer(IN PVOID HwDeviceExtension,
					    IN PULONG Length)
{
    DPRINT1("StorPortAllocateRegistryBuffer()\n");
    UNIMPLEMENTED;
    return NULL;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortBusy(IN PVOID HwDeviceExtension,
			   IN ULONG RequestsToComplete)
{
    DPRINT1("StorPortBuzy()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI VOID StorPortCompleteRequest(IN PVOID HwDeviceExtension,
				   IN UCHAR PathId, IN UCHAR TargetId,
				   IN UCHAR Lun, IN UCHAR SrbStatus)
{
    DPRINT1("StorPortCompleteRequest()\n");
    UNIMPLEMENTED;
}

/*
 * @implemented
 */
NTAPI ULONG StorPortConvertPhysicalAddressToUlong(IN STOR_PHYSICAL_ADDRESS Address)
{
    DPRINT1("StorPortConvertPhysicalAddressToUlong()\n");

    return Address.LowPart;
}

/*
 * @implemented
 */
NTAPI STOR_PHYSICAL_ADDRESS StorPortConvertUlongToPhysicalAddress(IN ULONG_PTR Addr)
{
    STOR_PHYSICAL_ADDRESS Address;

    DPRINT1("StorPortConvertUlongToPhysicalAddress()\n");

    Address.QuadPart = Addr;
    return Address;
}

/*
 * @implemented
 */
VOID StorPortDebugPrint(IN ULONG DebugPrintLevel,
			IN PCHAR DebugMessage, ...)
{
    va_list ap;

    DbgPrintEx(0x58, DebugPrintLevel, "STORMINI: ");
    va_start(ap, DebugMessage);
    vDbgPrintEx(0x58, DebugPrintLevel, DebugMessage, ap);
    va_end(ap);
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortDeviceBusy(IN PVOID HwDeviceExtension,
				 IN UCHAR PathId,
				 IN UCHAR TargetId,
				 IN UCHAR Lun,
				 IN ULONG RequestsToComplete)
{
    DPRINT1("StorPortDeviceBusy()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortDeviceReady(IN PVOID HwDeviceExtension,
				  IN UCHAR PathId,
				  IN UCHAR TargetId,
				  IN UCHAR Lun)
{
    DPRINT1("StorPortDeviceReady()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
ULONG StorPortExtendedFunction(IN STORPORT_FUNCTION_CODE FunctionCode,
			       IN PVOID HwDeviceExtension, ...)
{
    DPRINT1("StorPortExtendedFunction(%d %p ...)\n", FunctionCode, HwDeviceExtension);
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @implemented
 */
NTAPI VOID StorPortFreeDeviceBase(IN PVOID HwDeviceExtension,
				  IN PVOID MappedAddress)
{
    DPRINT1("StorPortFreeDeviceBase(%p %p)\n", HwDeviceExtension, MappedAddress);
}

/*
 * @unimplemented
 */
NTAPI VOID StorPortFreeRegistryBuffer(IN PVOID HwDeviceExtension,
				      IN PUCHAR Buffer)
{
    DPRINT1("StorPortFreeRegistryBuffer()\n");
    UNIMPLEMENTED;
}

/*
 * @implemented
 */
NTAPI PVOID StorPortGetDeviceBase(IN PVOID HwDeviceExtension,
				  IN INTERFACE_TYPE BusType,
				  IN ULONG SystemIoBusNumber,
				  IN STOR_PHYSICAL_ADDRESS IoAddress,
				  IN ULONG NumberOfBytes,
				  IN BOOLEAN InIoSpace)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PHYSICAL_ADDRESS TranslatedAddress;
    PVOID MappedAddress;
    NTSTATUS Status;

    DPRINT1("StorPortGetDeviceBase(%p %u %u 0x%llx %u %u)\n", HwDeviceExtension, BusType,
	    SystemIoBusNumber, IoAddress.QuadPart, NumberOfBytes, InIoSpace);

    /* Get the miniport extension */
    MiniportExtension = CONTAINING_RECORD(HwDeviceExtension, MINIPORT_DEVICE_EXTENSION,
					  HwDeviceExtension);
    DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n", HwDeviceExtension,
	    MiniportExtension);

    if (!TranslateResourceListAddress(MiniportExtension->Miniport->DeviceExtension,
				      BusType, SystemIoBusNumber, IoAddress,
				      NumberOfBytes, InIoSpace, &TranslatedAddress)) {
	DPRINT1("Checkpoint!\n");
	return NULL;
    }

    DPRINT1("Translated Address: 0x%llx\n", TranslatedAddress.QuadPart);

    /* In I/O space */
    if (InIoSpace) {
	DPRINT1("Translated Address: %p\n", (PVOID)(ULONG_PTR)TranslatedAddress.QuadPart);
	return (PVOID)(ULONG_PTR)TranslatedAddress.QuadPart;
    }

    /* In memory space */
    MappedAddress = MmMapIoSpace(TranslatedAddress, NumberOfBytes, FALSE);
    DPRINT1("Mapped Address: %p\n", MappedAddress);

    Status = AllocateAddressMapping(
	&MiniportExtension->Miniport->DeviceExtension->MappedAddressList, IoAddress,
	MappedAddress, NumberOfBytes, SystemIoBusNumber);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Checkpoint!\n");
	MappedAddress = NULL;
    }

    DPRINT1("Mapped Address: %p\n", MappedAddress);
    return MappedAddress;
}

/*
 * @unimplemented
 */
NTAPI PVOID StorPortGetLogicalUnit(IN PVOID HwDeviceExtension,
				   IN UCHAR PathId,
				   IN UCHAR TargetId,
				   IN UCHAR Lun)
{
    DPRINT1("StorPortGetLogicalUnit()\n");
    UNIMPLEMENTED;
    return NULL;
}

/*
 * Returns the corresponding physical address if the virtual address is within
 * the uncached extension. Otherwise, return zero.
 *
 * The Srb argument is needed when IOMMU is used, in order to translate system
 * physical address into a device address. Since we do not support IOMMU yet,
 * this parameter is ignored.
 *
 * @implemented
 */
NTAPI STOR_PHYSICAL_ADDRESS StorPortGetPhysicalAddress(IN PVOID HwDeviceExtension,
						       IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
						       IN PVOID VirtualAddress,
						       OUT ULONG *Length)
{
    DPRINT1("StorPortGetPhysicalAddress(%p %p %p %p)\n", HwDeviceExtension, Srb,
	    VirtualAddress, Length);

    /* Get the miniport extension */
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
								     MINIPORT_DEVICE_EXTENSION,
								     HwDeviceExtension);
    DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n", HwDeviceExtension,
	    MiniportExtension);

    PFDO_DEVICE_EXTENSION DeviceExtension = MiniportExtension->Miniport->DeviceExtension;

    STOR_PHYSICAL_ADDRESS PhysicalAddress = {0};
    ULONG_PTR Offset;
    /* Inside of the uncached extension? */
    if (((ULONG_PTR)VirtualAddress >=
	 (ULONG_PTR)DeviceExtension->UncachedExtensionVirtualBase) &&
	((ULONG_PTR)VirtualAddress <=
	 (ULONG_PTR)DeviceExtension->UncachedExtensionVirtualBase +
	 DeviceExtension->UncachedExtensionSize)) {
	Offset = (ULONG_PTR)VirtualAddress -
	    (ULONG_PTR)DeviceExtension->UncachedExtensionVirtualBase;

	PhysicalAddress.QuadPart =
	    DeviceExtension->UncachedExtensionPhysicalBase.QuadPart + Offset;
	*Length = DeviceExtension->UncachedExtensionSize - Offset;
    } else {
	*Length = 0;
    }
    return PhysicalAddress;
}


/*
 * Return the correspoinding virtual address if the physical address falls
 * within the uncached extension. Otherwise, return NULL.
 *
 * @implemented
 */
NTAPI PVOID StorPortGetVirtualAddress(IN PVOID HwDeviceExtension,
				      IN STOR_PHYSICAL_ADDRESS PhysicalAddress)
{
    DPRINT1("StorPortGetVirtualAddress(%p %llx)\n", HwDeviceExtension,
	    PhysicalAddress.QuadPart);
    /* Get the miniport extension */
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
								     MINIPORT_DEVICE_EXTENSION,
								     HwDeviceExtension);
    DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n", HwDeviceExtension,
	    MiniportExtension);

    PFDO_DEVICE_EXTENSION DeviceExtension = MiniportExtension->Miniport->DeviceExtension;

    ULONG64 PhysicalBase = DeviceExtension->UncachedExtensionPhysicalBase.QuadPart;
    ULONG ExtensionSize = DeviceExtension->UncachedExtensionSize;
    if (PhysicalAddress.QuadPart >= PhysicalBase &&
	PhysicalAddress.QuadPart < (PhysicalBase + ExtensionSize)) {
	ULONG Offset = PhysicalAddress.QuadPart - PhysicalBase;
	return (PCHAR)DeviceExtension->UncachedExtensionVirtualBase + Offset;
    }
    return NULL;
}

/*
 * @implemented
 */
NTAPI PVOID StorPortGetUncachedExtension(IN PVOID HwDeviceExtension,
					 IN PPORT_CONFIGURATION_INFORMATION ConfigInfo,
					 IN ULONG NumberOfBytes)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension;
    PFDO_DEVICE_EXTENSION DeviceExtension;

    DPRINT1("StorPortGetUncachedExtension(%p %p %u)\n", HwDeviceExtension, ConfigInfo,
	    NumberOfBytes);

    /* Get the miniport extension */
    MiniportExtension = CONTAINING_RECORD(HwDeviceExtension, MINIPORT_DEVICE_EXTENSION,
					  HwDeviceExtension);
    DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n", HwDeviceExtension,
	    MiniportExtension);

    DeviceExtension = MiniportExtension->Miniport->DeviceExtension;

    /* Return the uncached extension base address if we already have one */
    if (DeviceExtension->UncachedExtensionVirtualBase != NULL)
	return DeviceExtension->UncachedExtensionVirtualBase;

    // FIXME: Set DMA stuff here?

    /* Allocate the uncached extension */
    PHYSICAL_ADDRESS HighestAddress = { .QuadPart = 0x00000000FFFFFFFF };
    PHYSICAL_ADDRESS Alignment = {}, PhysicalBase = {};
    PVOID VirtualBase = NULL;
    if (!NT_SUCCESS(MmAllocateContiguousMemorySpecifyCache(NumberOfBytes,
							   HighestAddress,
							   Alignment,
							   MmCached,
							   &VirtualBase,
							   &PhysicalBase))) {
	return NULL;
    }
    assert(VirtualBase);
    assert(PhysicalBase.QuadPart);
    DeviceExtension->UncachedExtensionVirtualBase = VirtualBase;
    DeviceExtension->UncachedExtensionPhysicalBase = PhysicalBase;
    DeviceExtension->UncachedExtensionSize = NumberOfBytes;

    return DeviceExtension->UncachedExtensionVirtualBase;
}

/*
 * @unimplemented
 */
NTAPI PSTOR_SCATTER_GATHER_LIST StorPortGetScatterGatherList(IN PVOID DeviceExtension,
							     IN PSCSI_REQUEST_BLOCK Srb)
{
    DPRINT1("StorPortGetScatterGatherList()\n");
    UNIMPLEMENTED;
    return NULL;
}

/*
 * @implemented
 */
NTAPI PSCSI_REQUEST_BLOCK StorPortGetSrb(IN PVOID DeviceExtension,
					 IN UCHAR PathId,
					 IN UCHAR TargetId,
					 IN UCHAR Lun,
					 IN LONG QueueTag)
{
    DPRINT("StorPortGetSrb()\n");
    return NULL;
}

static ULONG StorPortReadWriteBusData(IN PVOID DeviceExtension,
				      IN ULONG BusDataType,
				      IN ULONG SystemIoBusNumber,
				      IN ULONG SlotNumber,
				      OUT PVOID Buffer,
				      IN ULONG Length,
				      BOOLEAN Write)
{
    if (!DeviceExtension) {
	assert(FALSE);
	return 0;
    }

    /* Get the miniport extension */
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = CONTAINING_RECORD(DeviceExtension,
								     MINIPORT_DEVICE_EXTENSION,
								     HwDeviceExtension);
    DPRINT1("DeviceExtension %p  MiniportExtension %p\n",
            DeviceExtension, MiniportExtension);

    PMINIPORT Miniport = MiniportExtension->Miniport;
    if (!Miniport) {
	assert(FALSE);
	return 0;
    }

    if (BusDataType != PCIConfiguration) {
	assert(FALSE);
	return 0;
    }

    if (SystemIoBusNumber != Miniport->PortConfig.SystemIoBusNumber) {
	assert(FALSE);
	return 0;
    }

    if (SlotNumber != Miniport->PortConfig.SlotNumber) {
	assert(FALSE);
	return 0;
    }

    if (!Miniport->DeviceExtension) {
	assert(FALSE);
	return 0;
    }

    PDEVICE_OBJECT Pdo = Miniport->DeviceExtension->PhysicalDevice;
    if (!Pdo) {
	assert(FALSE);
	return 0;
    }

    NTSTATUS Status = Write ? IoWritePciConfigSpace(Pdo, Buffer, 0, &Length) :
	IoReadPciConfigSpace(Pdo, Buffer, 0, &Length);
    return NT_SUCCESS(Status) ? Length : 0;
}

/*
 * @implemented
 */
NTAPI ULONG StorPortGetBusData(IN PVOID DeviceExtension,
			       IN ULONG BusDataType,
			       IN ULONG SystemIoBusNumber,
			       IN ULONG SlotNumber,
			       OUT PVOID Buffer,
			       IN ULONG Length)
{
    DPRINT1("StorPortGetBusData(%p %u %u %u %p %u)\n",
            DeviceExtension, BusDataType, SystemIoBusNumber, SlotNumber, Buffer, Length);

    return StorPortReadWriteBusData(DeviceExtension, BusDataType, SystemIoBusNumber,
				    SlotNumber, Buffer, Length, FALSE);
}

/*
 * @implemented
 */
NTAPI ULONG StorPortSetBusDataByOffset(IN PVOID DeviceExtension,
				       IN ULONG BusDataType,
				       IN ULONG SystemIoBusNumber,
				       IN ULONG SlotNumber,
				       IN PVOID Buffer,
				       IN ULONG Offset,
				       IN ULONG Length)
{
    DPRINT1("StorPortSetBusData(%p %u %u %u %p %u %u)\n",
            DeviceExtension, BusDataType, SystemIoBusNumber,
	    SlotNumber, Buffer, Offset, Length);

    return StorPortReadWriteBusData(DeviceExtension, BusDataType, SystemIoBusNumber,
				    SlotNumber, Buffer, Length, TRUE);
}

/*
 * @implemented
 */
NTAPI ULONG StorPortInitialize(IN PVOID Argument1,
			       IN PVOID Argument2,
			       IN PHW_INITIALIZATION_DATA InitData,
			       IN OPTIONAL PVOID HwContext)
{
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)Argument1;
    PUNICODE_STRING RegistryPath = (PUNICODE_STRING)Argument2;
    PDRIVER_OBJECT_EXTENSION DriverObjectExtension;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT1("StorPortInitialize(%p %p %p %p)\n", Argument1, Argument2,
	    InitData, HwContext);

    DPRINT1("HwInitializationDataSize: %u\n",
	    InitData->HwInitializationDataSize);
    DPRINT1("AdapterInterfaceType: %u\n", InitData->AdapterInterfaceType);
    DPRINT1("HwInitialize: %p\n", InitData->HwInitialize);
    DPRINT1("HwStartIo: %p\n", InitData->HwStartIo);
    DPRINT1("HwInterrupt: %p\n", InitData->HwInterrupt);
    DPRINT1("HwFindAdapter: %p\n", InitData->HwFindAdapter);
    DPRINT1("HwResetBus: %p\n", InitData->HwResetBus);
    DPRINT1("HwDmaStarted: %p\n", InitData->HwDmaStarted);
    DPRINT1("HwAdapterState: %p\n", InitData->HwAdapterState);
    DPRINT1("DeviceExtensionSize: %u\n", InitData->DeviceExtensionSize);
    DPRINT1("SpecificLuExtensionSize: %u\n",
	    InitData->SpecificLuExtensionSize);
    DPRINT1("SrbExtensionSize: %u\n", InitData->SrbExtensionSize);
    DPRINT1("NumberOfAccessRanges: %u\n", InitData->NumberOfAccessRanges);

    /* Check parameters */
    if ((DriverObject == NULL) || (RegistryPath == NULL) ||
	(InitData == NULL)) {
	DPRINT1("Invalid parameter!\n");
	return STATUS_INVALID_PARAMETER;
    }

    /* Check initialization data */
    if ((InitData->HwInitializationDataSize <
	 sizeof(HW_INITIALIZATION_DATA)) ||
	(InitData->HwInitialize == NULL) ||
	(InitData->HwStartIo == NULL) ||
	(InitData->HwFindAdapter == NULL) ||
	(InitData->HwResetBus == NULL)) {
	DPRINT1("Revision mismatch!\n");
	return STATUS_REVISION_MISMATCH;
    }

    DriverObjectExtension = IoGetDriverObjectExtension(DriverObject, (PVOID)DriverEntry);
    if (DriverObjectExtension == NULL) {
	DPRINT1("No driver object extension!\n");

	Status = IoAllocateDriverObjectExtension(DriverObject, (PVOID)DriverEntry,
						 sizeof(DRIVER_OBJECT_EXTENSION),
						 (PVOID *)&DriverObjectExtension);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("IoAllocateDriverObjectExtension() failed (Status 0x%08x)\n", Status);
	    return Status;
	}

	DPRINT1("Driver object extension created!\n");

	/* Initialize the driver object extension */
	RtlZeroMemory(DriverObjectExtension, sizeof(DRIVER_OBJECT_EXTENSION));

	DriverObjectExtension->ExtensionType = DriverExtension;
	DriverObjectExtension->DriverObject = DriverObject;

	InitializeListHead(&DriverObjectExtension->AdapterListHead);

	InitializeListHead(&DriverObjectExtension->InitDataListHead);

	/* Set handlers */
	DriverObject->AddDevice = PortAddDevice;
	//        DriverObject->DriverStartIo = PortStartIo;
	DriverObject->DriverUnload = PortUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = PortDispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = PortDispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PortDispatchDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_SCSI] = PortDispatchScsi;
	DriverObject->MajorFunction[IRP_MJ_POWER] = PortDispatchPower;
	DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PortDispatchSystemControl;
	DriverObject->MajorFunction[IRP_MJ_PNP] = PortDispatchPnp;
    }

    /* Add the initialzation data to the driver extension */
    Status = PortAddDriverInitData(DriverObjectExtension, InitData);

    DPRINT1("StorPortInitialize() done (Status 0x%08x)\n", Status);

    return Status;
}

/*
 * @unimplemented
 */
NTAPI VOID StorPortLogError(IN PVOID HwDeviceExtension,
			    IN OPTIONAL PSCSI_REQUEST_BLOCK Srb,
			    IN UCHAR PathId, IN UCHAR TargetId, IN UCHAR Lun,
			    IN ULONG ErrorCode, IN ULONG UniqueId)
{
    DPRINT1("ScsiPortLogError() called\n");
    DPRINT1("PathId: 0x%02x  TargetId: 0x%02x  Lun: 0x%02x  ErrorCode: 0x%08x  UniqueId: "
	    "0x%08x\n",
	    PathId, TargetId, Lun, ErrorCode, UniqueId);

    DPRINT1("ScsiPortLogError() done\n");
}

/*
 * @implemented
 */
NTAPI VOID StorPortMoveMemory(OUT PVOID Destination, IN PVOID Source,
			      IN ULONG Length)
{
    RtlMoveMemory(Destination, Source, Length);
}

/*
 * @unimplemented
 */
VOID StorPortNotification(IN SCSI_NOTIFICATION_TYPE NotificationType,
			  IN PVOID HwDeviceExtension, ...)
{
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = NULL;
    PFDO_DEVICE_EXTENSION DeviceExtension = NULL;
    PHW_PASSIVE_INITIALIZE_ROUTINE HwPassiveInitRoutine;
    PSTORPORT_EXTENDED_FUNCTIONS *ppExtendedFunctions;
    PBOOLEAN Result;
    PSTOR_DPC Dpc;
    PHW_DPC_ROUTINE HwDpcRoutine;
    va_list ap;

    STOR_SPINLOCK SpinLock;
    PVOID LockContext;
    PSTOR_LOCK_HANDLE LockHandle;
    PSCSI_REQUEST_BLOCK Srb;

    DPRINT1("StorPortNotification(%x %p)\n", NotificationType, HwDeviceExtension);

    /* Get the miniport extension */
    if (HwDeviceExtension != NULL) {
	MiniportExtension = CONTAINING_RECORD(HwDeviceExtension,
					      MINIPORT_DEVICE_EXTENSION,
					      HwDeviceExtension);
	DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n", HwDeviceExtension,
		MiniportExtension);

	DeviceExtension = MiniportExtension->Miniport->DeviceExtension;
    }

    va_start(ap, HwDeviceExtension);

    switch (NotificationType) {
    case RequestComplete:
	DPRINT1("RequestComplete\n");
	Srb = (PSCSI_REQUEST_BLOCK)va_arg(ap, PSCSI_REQUEST_BLOCK);
	DPRINT1("Srb %p\n", Srb);
	if (Srb->OriginalRequest != NULL) {
	    DPRINT1("Need to complete the IRP!\n");
	}
	break;

    case GetExtendedFunctionTable:
	DPRINT1("GetExtendedFunctionTable\n");
	ppExtendedFunctions = (PSTORPORT_EXTENDED_FUNCTIONS *)
	    va_arg(ap, PSTORPORT_EXTENDED_FUNCTIONS *);
	if (ppExtendedFunctions != NULL)
	    *ppExtendedFunctions = NULL; /* FIXME */
	break;

    case EnablePassiveInitialization:
	DPRINT1("EnablePassiveInitialization\n");
	HwPassiveInitRoutine = (PHW_PASSIVE_INITIALIZE_ROUTINE)
	    va_arg(ap, PHW_PASSIVE_INITIALIZE_ROUTINE);
	DPRINT1("HwPassiveInitRoutine %p\n", HwPassiveInitRoutine);
	Result = (PBOOLEAN)va_arg(ap, PBOOLEAN);

	*Result = FALSE;

	if ((DeviceExtension != NULL) &&
	    (DeviceExtension->HwPassiveInitRoutine == NULL)) {
	    DeviceExtension->HwPassiveInitRoutine = HwPassiveInitRoutine;
	    *Result = TRUE;
	}
	break;

    case InitializeDpc:
	DPRINT1("InitializeDpc\n");
	Dpc = (PSTOR_DPC)va_arg(ap, PSTOR_DPC);
	DPRINT1("Dpc %p\n", Dpc);
	HwDpcRoutine = (PHW_DPC_ROUTINE)va_arg(ap, PHW_DPC_ROUTINE);
	DPRINT1("HwDpcRoutine %p\n", HwDpcRoutine);

	KeInitializeDpc((PKDPC)&Dpc->Dpc, (PKDEFERRED_ROUTINE)HwDpcRoutine,
			(PVOID)DeviceExtension);
	break;

    case AcquireSpinLock:
	DPRINT1("AcquireSpinLock\n");
	SpinLock = (STOR_SPINLOCK)va_arg(ap, STOR_SPINLOCK);
	DPRINT1("SpinLock %u\n", SpinLock);
	LockContext = (PVOID)va_arg(ap, PVOID);
	DPRINT1("LockContext %p\n", LockContext);
	LockHandle = (PSTOR_LOCK_HANDLE)va_arg(ap, PSTOR_LOCK_HANDLE);
	DPRINT1("LockHandle %p\n", LockHandle);
	PortAcquireSpinLock(DeviceExtension, SpinLock, LockContext, LockHandle);
	break;

    case ReleaseSpinLock:
	DPRINT1("ReleaseSpinLock\n");
	LockHandle = (PSTOR_LOCK_HANDLE)va_arg(ap, PSTOR_LOCK_HANDLE);
	DPRINT1("LockHandle %p\n", LockHandle);
	PortReleaseSpinLock(DeviceExtension, LockHandle);
	break;

    default:
	DPRINT1("Unsupported Notification %x\n", NotificationType);
	break;
    }

    va_end(ap);
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortPause(IN PVOID HwDeviceExtension, IN ULONG TimeOut)
{
    DPRINT1("StorPortPause()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortPauseDevice(IN PVOID HwDeviceExtension,
				  IN UCHAR PathId, IN UCHAR TargetId,
				  IN UCHAR Lun, IN ULONG TimeOut)
{
    DPRINT1("StorPortPauseDevice()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @implemented
 */
/* KeQuerySystemTime is an inline function,
   so we cannot forward the export to ntoskrnl */
NTAPI VOID StorPortQuerySystemTime(OUT PLARGE_INTEGER CurrentTime)
{
    DPRINT1("StorPortQuerySystemTime(%p)\n", CurrentTime);

    KeQuerySystemTime(CurrentTime);
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortReady(IN PVOID HwDeviceExtension)
{
    DPRINT1("StorPortReady()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortRegistryRead(IN PVOID HwDeviceExtension,
				   IN PUCHAR ValueName, IN ULONG Global,
				   IN ULONG Type, IN PUCHAR Buffer,
				   IN PULONG BufferLength)
{
    DPRINT1("StorPortRegistryRead()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortRegistryWrite(IN PVOID HwDeviceExtension,
				    IN PUCHAR ValueName, IN ULONG Global,
				    IN ULONG Type, IN PUCHAR Buffer,
				    IN ULONG BufferLength)
{
    DPRINT1("StorPortRegistryWrite()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortResume(IN PVOID HwDeviceExtension)
{
    DPRINT1("StorPortResume()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortResumeDevice(IN PVOID HwDeviceExtension,
				   IN UCHAR PathId, IN UCHAR TargetId,
				   IN UCHAR Lun)
{
    DPRINT1("StorPortResumeDevice()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortSetDeviceQueueDepth(IN PVOID HwDeviceExtension,
					  IN UCHAR PathId, IN UCHAR TargetId,
					  IN UCHAR Lun, IN ULONG Depth)
{
    DPRINT1("StorPortSetDeviceQueueDepth()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @implemented
 */
NTAPI VOID StorPortStallExecution(IN ULONG Delay)
{
    KeStallExecutionProcessor(Delay);
}

/*
 * @unimplemented
 */
NTAPI VOID StorPortSynchronizeAccess(IN PVOID HwDeviceExtension,
				     IN PSTOR_SYNCHRONIZED_ACCESS Routine,
				     IN OPTIONAL PVOID Context)
{
    DPRINT1("StorPortSynchronizeAccess()\n");
    UNIMPLEMENTED;
}

/*
 * @implemented
 */
NTAPI BOOLEAN StorPortValidateRange(IN PVOID HwDeviceExtension,
				    IN INTERFACE_TYPE BusType,
				    IN ULONG SystemIoBusNumber,
				    IN STOR_PHYSICAL_ADDRESS IoAddress,
				    IN ULONG NumberOfBytes,
				    IN BOOLEAN InIoSpace)
{
    DPRINT1("StorPortValidateRange()\n");
    return TRUE;
}

NTAPI ULONG StorPortAllocateDmaMemory(IN PVOID HwDeviceExtension,
				      IN SIZE_T NumberOfBytes,
				      IN PHYSICAL_ADDRESS LowestAddress,
				      IN PHYSICAL_ADDRESS HighestAddress,
				      IN OPTIONAL PHYSICAL_ADDRESS AddressMultiple,
				      IN MEMORY_CACHING_TYPE CacheType,
				      IN NODE_REQUIREMENT PreferredNode,
				      OUT PVOID *BufferPointer,
				      OUT PPHYSICAL_ADDRESS PhysicalAddress)
{
    return STOR_STATUS_NOT_IMPLEMENTED;
}

NTAPI ULONG StorPortFreeDmaMemory(IN PVOID HwDeviceExtension,
				  IN PVOID BaseAddress,
				  IN SIZE_T NumberOfBytes,
				  IN MEMORY_CACHING_TYPE CacheType,
				  IN OPTIONAL PHYSICAL_ADDRESS PhysicalAddress)
{
    return STOR_STATUS_NOT_IMPLEMENTED;
}
