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
#include <srbhelper.h>

#define GET_VA_ARG(ArgList, Type, Name)		\
    Type Name = (Type)va_arg(ArgList, Type)

#define POINTER_IS_IN_REGION(Ptr, Start, Size)			\
    ((ULONG_PTR)(Ptr) >= (ULONG_PTR)(Start) &&			\
     (ULONG_PTR)(Ptr) < (ULONG_PTR)(Start) + (ULONG_PTR)(Size))	\

/* GLOBALS ********************************************************************/

static ULONG StorPortTotalPortCount = 0;

/* FUNCTIONS ******************************************************************/

static NTSTATUS PortAddDriverInitData(PDRIVER_OBJECT_EXTENSION DriverExtension,
				      PHW_INITIALIZATION_DATA HwInitializationData)
{
    PDRIVER_INIT_DATA InitData;

    DPRINT1("PortAddDriverInitData()\n");

    InitData = ExAllocatePoolWithTag(NonPagedPool,
				     sizeof(DRIVER_INIT_DATA), TAG_INIT_DATA);
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
				STOR_SPINLOCK SpinLock,
				PVOID LockContext,
				PSTOR_LOCK_HANDLE LockHandle)
{
    LockHandle->Lock = SpinLock;

    switch (SpinLock) {
    case DpcLock:
	DPRINT1("DpcLock\n");
	/* We don't need locking for STOR_DPC because our "DPC" is actually an IO work item. */
	break;

    case StartIoLock:
	DPRINT1("StartIoLock\n");
	/* We don't need locking for StartIo routines so do nothing here. */
	break;

    case InterruptLock:
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
    switch (LockHandle->Lock) {
    case DpcLock:
	DPRINT1("DpcLock\n");
	break;

    case StartIoLock:
	DPRINT1("StartIoLock\n");
	break;

    case InterruptLock:
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

    /* If we are matched against the PDO of logical units, simply return success. */
    if (PhysicalDeviceObject->DeviceExtension) {
	PPDO_DEVICE_EXTENSION PdoExt = PhysicalDeviceObject->DeviceExtension;
	assert(PdoExt->ExtensionType == PdoExtension);
	assert(PdoExt->Device == PhysicalDeviceObject);
	return STATUS_SUCCESS;
    }

    swprintf(NameBuffer, L"\\Device\\RaidPort%lu", StorPortTotalPortCount);
    RtlInitUnicodeString(&DeviceName, NameBuffer);

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
    DeviceExtension->PortNumber = StorPortTotalPortCount;
    StorPortTotalPortCount++;

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

static NTAPI NTSTATUS PortDispatchCreate(IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp)
{
    DPRINT1("PortDispatchCreate(%p %p)\n", DeviceObject, Irp);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = FILE_OPENED;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static NTAPI NTSTATUS PortDispatchClose(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp)
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

    PFDO_DEVICE_EXTENSION DeviceExtension = (PVOID)DeviceObject->DeviceExtension;
    DPRINT1("ExtensionType: %u\n", DeviceExtension->ExtensionType);

    switch (DeviceExtension->ExtensionType) {
    case FdoExtension:
	return PortFdoDeviceControl(DeviceObject, Irp);

    case PdoExtension:
	return PortPdoDeviceControl(DeviceObject, Irp);

    default:
	Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_UNSUCCESSFUL;
    }
}

static NTAPI NTSTATUS PortDispatchScsi(IN PDEVICE_OBJECT DeviceObject,
				       IN PIRP Irp)
{
    DPRINT1("PortDispatchScsi(%p %p)\n", DeviceObject, Irp);

    PFDO_DEVICE_EXTENSION DeviceExtension = (PVOID)DeviceObject->DeviceExtension;
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

static NTAPI NTSTATUS PortDispatchPnp(IN PDEVICE_OBJECT DeviceObject,
				      IN PIRP Irp)
{
    DPRINT1("PortDispatchPnp(%p %p)\n", DeviceObject, Irp);

    PFDO_DEVICE_EXTENSION DeviceExtension = DeviceObject->DeviceExtension;
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

static NTAPI NTSTATUS PortDispatchPower(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp)
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
 * @implemented
 */
NTAPI BOOLEAN StorPortDeviceBusy(IN PVOID HwDeviceExtension,
				 IN UCHAR PathId,
				 IN UCHAR TargetId,
				 IN UCHAR Lun,
				 IN ULONG RequestsToComplete)
{
    DPRINT1("StorPortDeviceBusy()\n");
    if (!HwDeviceExtension) {
	return FALSE;
    }
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION DevExt = MiniportExt->Miniport->DeviceExtension;
    for (PLIST_ENTRY Entry = DevExt->PdoListHead.Flink;
	 Entry != &DevExt->PdoListHead; Entry = Entry->Flink) {
        PPDO_DEVICE_EXTENSION PdoExt = CONTAINING_RECORD(Entry,
							 PDO_DEVICE_EXTENSION,
							 PdoListEntry);
	if (PdoExt->Bus == PathId && PdoExt->Target == TargetId && PdoExt->Lun == Lun) {
	    PortPdoSetBusy(PdoExt);
	    return TRUE;
	}
    }
    return FALSE;
}

/*
 * @implemented
 */
NTAPI BOOLEAN StorPortDeviceReady(IN PVOID HwDeviceExtension,
				  IN UCHAR PathId,
				  IN UCHAR TargetId,
				  IN UCHAR Lun)
{
    DPRINT1("StorPortDeviceReady()\n");
    if (!HwDeviceExtension) {
	return FALSE;
    }
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION DevExt = MiniportExt->Miniport->DeviceExtension;
    for (PLIST_ENTRY Entry = DevExt->PdoListHead.Flink;
	 Entry != &DevExt->PdoListHead; Entry = Entry->Flink) {
        PPDO_DEVICE_EXTENSION PdoExt = CONTAINING_RECORD(Entry,
							 PDO_DEVICE_EXTENSION,
							 PdoListEntry);
	if (PdoExt->Bus == PathId && PdoExt->Target == TargetId && PdoExt->Lun == Lun) {
	    PortPdoSetReady(PdoExt);
	    return TRUE;
	}
    }
    return FALSE;
}

/*
 * @implemented
 */
NTAPI BOOLEAN StorPortBusy(IN PVOID HwDeviceExtension,
			   IN ULONG RequestsToComplete)
{
    if (!HwDeviceExtension) {
	return FALSE;
    }
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION DevExt = MiniportExt->Miniport->DeviceExtension;
    for (PLIST_ENTRY Entry = DevExt->PdoListHead.Flink;
	 Entry != &DevExt->PdoListHead; Entry = Entry->Flink) {
        PPDO_DEVICE_EXTENSION PdoDevExt = CONTAINING_RECORD(Entry,
							    PDO_DEVICE_EXTENSION,
							    PdoListEntry);
	PortPdoSetBusy(PdoDevExt);
    }
    return TRUE;
}

/*
 * @implemented
 */
NTAPI BOOLEAN StorPortReady(IN PVOID HwDeviceExtension)
{
    DPRINT1("StorPortReady()\n");
    if (!HwDeviceExtension) {
	return FALSE;
    }
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION DevExt = MiniportExt->Miniport->DeviceExtension;
    for (PLIST_ENTRY Entry = DevExt->PdoListHead.Flink;
	 Entry != &DevExt->PdoListHead; Entry = Entry->Flink) {
        PPDO_DEVICE_EXTENSION PdoDevExt = CONTAINING_RECORD(Entry,
							    PDO_DEVICE_EXTENSION,
							    PdoListEntry);
	PortPdoSetReady(PdoDevExt);
    }
    return TRUE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortPause(IN PVOID HwDeviceExtension,
			    IN ULONG TimeOut)
{
    DPRINT1("StorPortPause()\n");
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
NTAPI BOOLEAN StorPortPauseDevice(IN PVOID HwDeviceExtension,
				  IN UCHAR PathId,
				  IN UCHAR TargetId,
				  IN UCHAR Lun,
				  IN ULONG TimeOut)
{
    DPRINT1("StorPortPauseDevice()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortResumeDevice(IN PVOID HwDeviceExtension,
				   IN UCHAR PathId,
				   IN UCHAR TargetId,
				   IN UCHAR Lun)
{
    DPRINT1("StorPortResumeDevice()\n");
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @unimplemented
 */
NTAPI VOID StorPortCompleteRequest(IN PVOID HwDeviceExtension,
				   IN UCHAR PathId,
				   IN UCHAR TargetId,
				   IN UCHAR Lun,
				   IN UCHAR SrbStatus)
{
    DPRINT1("StorPortCompleteRequest()\n");
    UNIMPLEMENTED;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortSetDeviceQueueDepth(IN PVOID HwDeviceExtension,
					  IN UCHAR PathId,
					  IN UCHAR TargetId,
					  IN UCHAR Lun,
					  IN ULONG Depth)
{
    DPRINT1("StorPortSetDeviceQueueDepth(%d:%d:%d, depth %d)\n", PathId, TargetId, Lun, Depth);
    UNIMPLEMENTED;
    return FALSE;
}

/*
 * @implemented
 */
NTAPI ULONG StorPortConvertPhysicalAddressToUlong(IN STOR_PHYSICAL_ADDRESS Address)
{
    return Address.LowPart;
}

/*
 * @implemented
 */
NTAPI STOR_PHYSICAL_ADDRESS StorPortConvertUlongToPhysicalAddress(IN ULONG_PTR Addr)
{
    STOR_PHYSICAL_ADDRESS Address;
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

static ULONG StorExtAllocatePool(IN PVOID HwDeviceExtension,
				 IN ULONG NumberOfBytes,
				 IN ULONG Tag,
				 PVOID *BufferPointer)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(Tag);
    if (!BufferPointer) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    *BufferPointer = ExAllocatePool(NonPagedPool, NumberOfBytes);
    if (*BufferPointer == NULL) {
	return STOR_STATUS_INSUFFICIENT_RESOURCES;
    }
    return STOR_STATUS_SUCCESS;
}

static ULONG StorExtFreePool(IN PVOID HwDeviceExtension,
			     IN PVOID BufferPointer)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    if (!BufferPointer) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    ExFreePoolWithTag(BufferPointer, 0);
    return STOR_STATUS_SUCCESS;
}

static ULONG
StorExtAllocateContiguousMemorySpecifyCacheNode(IN PVOID HwDeviceExtension,
						IN SIZE_T NumberOfBytes,
						IN PHYSICAL_ADDRESS LowestAcceptableAddress,
						IN PHYSICAL_ADDRESS HighestAcceptableAddress,
						IN OPTIONAL PHYSICAL_ADDRESS BoundaryAddrMultiple,
						IN MEMORY_CACHING_TYPE CacheType,
						IN NODE_REQUIREMENT PreferredNode,
						PVOID *VirtAddr)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    UNREFERENCED_PARAMETER(PreferredNode);

    if (!VirtAddr) {
	return STOR_STATUS_INVALID_PARAMETER;
    }

    /* We don't allow non-zero lowest acceptable address */
    if (LowestAcceptableAddress.QuadPart) {
	return STOR_STATUS_INVALID_PARAMETER;
    }

    *VirtAddr = NULL;
    PHYSICAL_ADDRESS PhyAddr = {};
    MmAllocateContiguousMemorySpecifyCache(NumberOfBytes,
					   HighestAcceptableAddress,
					   BoundaryAddrMultiple,
					   CacheType, VirtAddr, &PhyAddr);
    if (*VirtAddr == NULL || PhyAddr.QuadPart == 0) {
	return STOR_STATUS_INSUFFICIENT_RESOURCES;
    }

    return STOR_STATUS_SUCCESS;
}

static ULONG StorExtFreeContiguousMemorySpecifyCache(IN PVOID HwDeviceExtension,
						     IN PVOID BaseAddress,
						     IN SIZE_T NumberOfBytes,
						     IN MEMORY_CACHING_TYPE CacheType)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);

    MmFreeContiguousMemorySpecifyCache(BaseAddress, NumberOfBytes, CacheType);

    return STOR_STATUS_SUCCESS;
}

typedef struct _STORPORT_TIMER {
    KTIMER Timer;
    IO_WORKITEM WorkItem;
    PHW_TIMER_EX Callback;
    PVOID CallbackContext;
    BOOLEAN Active;
} STORPORT_TIMER, *PSTORPORT_TIMER;

static ULONG StorExtInitializeTimer(IN PVOID HwDeviceExtension,
				    OUT PVOID *TimerHandle)
{
    if (!HwDeviceExtension || !TimerHandle) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    /* Get the miniport extension */
    assert(HwDeviceExtension);
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION DevExt = MiniportExt->Miniport->DeviceExtension;

    PSTORPORT_TIMER Timer = ExAllocatePool(NonPagedPool, sizeof(STORPORT_TIMER));
    if (!Timer) {
	return STOR_STATUS_INSUFFICIENT_RESOURCES;
    }
    KeInitializeTimer(&Timer->Timer);
    IoInitializeWorkItem(DevExt->Device, &Timer->WorkItem);
    *TimerHandle = Timer;
    return STOR_STATUS_SUCCESS;
}

static NTAPI VOID StorExtTimerCallback(IN PDEVICE_OBJECT DeviceObject,
				       IN PVOID Context)
{
    assert(Context);
    PSTORPORT_TIMER Timer = Context;
    assert(Timer->Callback);
    PFDO_DEVICE_EXTENSION FdoExt = DeviceObject->DeviceExtension;
    PVOID HwDeviceExtension = FdoExt->Miniport.MiniportExtension->HwDeviceExtension;
    Timer->Active = FALSE;
    Timer->Callback(HwDeviceExtension, Timer->CallbackContext);
}

static ULONG StorExtRequestTimer(IN PVOID HwDeviceExtension,
				 IN PVOID TimerHandle,
				 IN PHW_TIMER_EX TimerCallback,
				 IN OPTIONAL PVOID CallbackContext,
				 IN ULONGLONG TimerValue,
				 IN ULONGLONG TolerableDelay)
{
    UNREFERENCED_PARAMETER(TolerableDelay);
    if (!HwDeviceExtension || !TimerHandle || !TimerCallback) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    PSTORPORT_TIMER Timer = TimerHandle;
    if (!TimerValue) {
	Timer->Active = FALSE;
	KeCancelTimer(&Timer->Timer);
    } else {
	if (Timer->Active) {
	    return STOR_STATUS_BUSY;
	}
	/* TimerValue is the relative due time from the current time. */
	LARGE_INTEGER DueTime = { .QuadPart = -TimerValue };
	Timer->Callback = TimerCallback;
	Timer->CallbackContext = CallbackContext;
	Timer->Active = TRUE;
	KeSetLowPriorityTimer(&Timer->Timer, DueTime, 0, &Timer->WorkItem,
			      StorExtTimerCallback, Timer);
    }
    return STOR_STATUS_SUCCESS;
}

static ULONG StorExtFreeTimer(IN PVOID HwDeviceExtension,
			      IN PVOID TimerHandle)
{
    UNREFERENCED_PARAMETER(HwDeviceExtension);
    if (!TimerHandle) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    PSTORPORT_TIMER Timer = TimerHandle;
    if (Timer->Active) {
	KeCancelTimer(&Timer->Timer);
    }
    ExFreePool(Timer);
    return STOR_STATUS_SUCCESS;
}

static ULONG StorExtInitializeWorker(IN PVOID HwDeviceExtension,
				     OUT PVOID *pWorker)
{
    if (!HwDeviceExtension || !pWorker) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    /* Get the miniport extension */
    assert(HwDeviceExtension);
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION DevExt = MiniportExt->Miniport->DeviceExtension;

    PIO_WORKITEM Worker = IoAllocateWorkItem(DevExt->Device);
    if (!Worker) {
	return STOR_STATUS_INSUFFICIENT_RESOURCES;
    }
    *pWorker = Worker;
    return STOR_STATUS_SUCCESS;
}

typedef struct _STORPORT_WORKITEM_CONTEXT {
    PHW_WORKITEM Callback;
    PVOID HwDeviceExtension;
    PVOID Worker;
    PVOID Context;
} STORPORT_WORKITEM_CONTEXT, *PSTORPORT_WORKITEM_CONTEXT;

static NTAPI VOID StorExtWorkItemCallback(IN PDEVICE_OBJECT DeviceObject,
					  IN PVOID Ctx)
{
    assert(Ctx);
    PSTORPORT_WORKITEM_CONTEXT Context = Ctx;
    Context->Callback(Context->HwDeviceExtension, Context->Context, Context->Worker);
    ExFreePool(Context);
}

static ULONG StorExtQueueWorkItem(IN PVOID HwDeviceExtension,
				  IN PHW_WORKITEM WorkItemCallback,
				  IN PVOID Worker,
				  IN OPTIONAL PVOID Context)
{
    if (!HwDeviceExtension || !WorkItemCallback || !Worker) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    PSTORPORT_WORKITEM_CONTEXT Ctx = ExAllocatePool(NonPagedPool,
						    sizeof(STORPORT_WORKITEM_CONTEXT));
    if (!Ctx) {
	return STOR_STATUS_INSUFFICIENT_RESOURCES;
    }
    Ctx->HwDeviceExtension = HwDeviceExtension;
    Ctx->Callback = WorkItemCallback;
    Ctx->Worker = Worker;
    Ctx->Context = Context;
    IoQueueWorkItem(Worker, StorExtWorkItemCallback, DelayedWorkQueue, Ctx);
    return STOR_STATUS_SUCCESS;
}

static ULONG StorExtFreeWorker(IN PVOID HwDeviceExtension,
			       IN PVOID Worker)
{
    if (!HwDeviceExtension || !Worker) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    IoFreeWorkItem(Worker);
    return STOR_STATUS_SUCCESS;
}

static ULONG StorExtRegistryReadWriteAdapterKey(IN PVOID HwDeviceExtension,
						IN OPTIONAL PUCHAR SubKeyName,
						IN PUCHAR ValueName,
						IN ULONG ValueType,
						IN OUT PVOID ValueData,
						IN OUT PULONG ValueDataLength,
						IN BOOLEAN Read)
{
    if (!HwDeviceExtension) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION FdoExt = MiniportExt->Miniport->DeviceExtension;
    HANDLE RegKey = NULL;
    NTSTATUS Status = IoOpenDeviceRegistryKey(FdoExt->Device, PLUGPLAY_REGKEY_DEVICE,
					      KEY_ALL_ACCESS, &RegKey);
    if (!NT_SUCCESS(Status)) {
	return STOR_STATUS_UNSUCCESSFUL;
    }

    if (SubKeyName) {
	HANDLE Subkey = NULL;
	UNICODE_STRING SubKeyNameU = {};
	Status = RtlCreateUnicodeStringFromAsciiz(&SubKeyNameU, (PCSTR)SubKeyName);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	OBJECT_ATTRIBUTES ObjAttr;
	InitializeObjectAttributes(&ObjAttr, &SubKeyNameU,
				   OBJ_CASE_INSENSITIVE,
				   RegKey, NULL);
	Status = NtCreateKey(&Subkey, KEY_ALL_ACCESS, &ObjAttr, 0, NULL,
			     REG_OPTION_VOLATILE, NULL);
	RtlFreeUnicodeString(&SubKeyNameU);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	NtClose(RegKey);
	RegKey = Subkey;
    }

    UNICODE_STRING ValueNameU = {};
    Status = RtlCreateUnicodeStringFromAsciiz(&ValueNameU, (PCSTR)ValueName);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    if (Read) {
	ULONG BufferSize = *ValueDataLength + sizeof(KEY_VALUE_PARTIAL_INFORMATION);
	PKEY_VALUE_PARTIAL_INFORMATION Buffer = ExAllocatePool(NonPagedPool, BufferSize);
	if (!Buffer) {
	    Status = STATUS_INSUFFICIENT_RESOURCES;
	    goto done;
	}
	ULONG ResultLength = 0;
	Status = NtQueryValueKey(RegKey,
				 &ValueNameU,
				 KeyValuePartialInformation,
				 Buffer,
				 BufferSize,
				 &ResultLength);
	assert(ResultLength >= sizeof(KEY_VALUE_PARTIAL_INFORMATION));
	*ValueDataLength = ResultLength - sizeof(KEY_VALUE_PARTIAL_INFORMATION);
	if (!NT_SUCCESS(Status)) {
	    goto done;
	}
	*ValueDataLength = Buffer->DataLength;
	RtlCopyMemory(ValueData, Buffer->Data, Buffer->DataLength);
	ExFreePool(Buffer);
    } else {
	Status = NtSetValueKey(RegKey, &ValueNameU, 0,
			       ValueType, ValueData, *ValueDataLength);
    }
done:
    RtlFreeUnicodeString(&ValueNameU);

out:
    NtClose(RegKey);
    return NT_SUCCESS(Status) ? STOR_STATUS_SUCCESS : STOR_STATUS_UNSUCCESSFUL;
}

static ULONG StorExtRegistryReadAdapterKey(IN PVOID HwDeviceExtension,
					   IN OPTIONAL PUCHAR SubKeyName,
					   IN PUCHAR ValueName,
					   IN ULONG ValueType,
					   IN OUT PVOID *ValueData,
					   IN OUT PULONG ValueDataLength)
{
    if (!ValueData || !*ValueData) {
	return STOR_STATUS_INVALID_PARAMETER;
    }
    return StorExtRegistryReadWriteAdapterKey(HwDeviceExtension,
					      SubKeyName,
					      ValueName,
					      ValueType,
					      *ValueData,
					      ValueDataLength,
					      TRUE);
}

static ULONG StorExtRegistryWriteAdapterKey(IN PVOID HwDeviceExtension,
					    IN OPTIONAL PUCHAR SubKeyName,
					    IN PUCHAR ValueName,
					    IN ULONG ValueType,
					    IN PVOID ValueData,
					    IN ULONG ValueDataLength)
{
    return StorExtRegistryReadWriteAdapterKey(HwDeviceExtension,
					      SubKeyName,
					      ValueName,
					      ValueType,
					      ValueData,
					      &ValueDataLength,
					      FALSE);
}

/*
 * @unimplemented
 */
ULONG StorPortExtendedFunction(IN STORPORT_FUNCTION_CODE FunctionCode,
			       IN PVOID HwDeviceExtension, ...)
{
    DPRINT1("StorPortExtendedFunction(%d %p ...)\n", FunctionCode, HwDeviceExtension);

    if (!HwDeviceExtension) {
	return STOR_STATUS_INVALID_PARAMETER;
    }

    va_list VaList;
    va_start(VaList, HwDeviceExtension);

    ULONG Status;
    switch (FunctionCode) {
    case ExtFunctionAllocatePool:
    {
	GET_VA_ARG(VaList, ULONG, NumberOfBytes);
	GET_VA_ARG(VaList, ULONG, Tag);
	GET_VA_ARG(VaList, PVOID *, Ptr);
	Status = StorExtAllocatePool(HwDeviceExtension, NumberOfBytes, Tag, Ptr);
	break;
    }

    case ExtFunctionFreePool:
    {
	GET_VA_ARG(VaList, PVOID, Ptr);
	Status = StorExtFreePool(HwDeviceExtension, Ptr);
	break;
    }

    case ExtFunctionAllocateContiguousMemorySpecifyCacheNode:
    {
	GET_VA_ARG(VaList, SIZE_T, NumberOfBytes);
	GET_VA_ARG(VaList, PHYSICAL_ADDRESS, LowestAcceptableAddress);
	GET_VA_ARG(VaList, PHYSICAL_ADDRESS, HighestAcceptableAddress);
	GET_VA_ARG(VaList, PHYSICAL_ADDRESS, BoundaryAddressMultiple);
	GET_VA_ARG(VaList, MEMORY_CACHING_TYPE, CacheType);
	GET_VA_ARG(VaList, NODE_REQUIREMENT, PreferredNode);
	GET_VA_ARG(VaList, PVOID *, DestPtr);
	Status = StorExtAllocateContiguousMemorySpecifyCacheNode(HwDeviceExtension,
								 NumberOfBytes,
								 LowestAcceptableAddress,
								 HighestAcceptableAddress,
								 BoundaryAddressMultiple,
								 CacheType, PreferredNode,
								 DestPtr);
	break;
    }

    case ExtFunctionFreeContiguousMemorySpecifyCache:
    {
	GET_VA_ARG(VaList, PVOID, BaseAddress);
	GET_VA_ARG(VaList, SIZE_T, NumberOfBytes);
	GET_VA_ARG(VaList, MEMORY_CACHING_TYPE, CacheType);
	Status = StorExtFreeContiguousMemorySpecifyCache(HwDeviceExtension,
							 BaseAddress,
							 NumberOfBytes,
							 CacheType);
	break;
    }

    case ExtFunctionInitializeTimer:
    {
	GET_VA_ARG(VaList, PVOID *, TimerHandle);
	Status = StorExtInitializeTimer(HwDeviceExtension, TimerHandle);
	break;
    }

    case ExtFunctionRequestTimer:
    {
	GET_VA_ARG(VaList, PVOID, TimerHandle);
	GET_VA_ARG(VaList, PHW_TIMER_EX, TimerCallback);
	GET_VA_ARG(VaList, PVOID, CallbackContext);
	GET_VA_ARG(VaList, ULONGLONG, TimerValue);
	GET_VA_ARG(VaList, ULONGLONG, TolerableDelay);
	Status = StorExtRequestTimer(HwDeviceExtension,
				     TimerHandle,
				     TimerCallback,
				     CallbackContext,
				     TimerValue,
				     TolerableDelay);
	break;
    }

    case ExtFunctionFreeTimer:
    {
	GET_VA_ARG(VaList, PVOID, TimerHandle);
	Status = StorExtFreeTimer(HwDeviceExtension, TimerHandle);
	break;
    }

    case ExtFunctionInitializeWorker:
    {
	GET_VA_ARG(VaList, PVOID *, Worker);
	Status = StorExtInitializeWorker(HwDeviceExtension, Worker);
	break;
    }

    case ExtFunctionQueueWorkItem:
    {
	GET_VA_ARG(VaList, PHW_WORKITEM, WorkItemCallback);
	GET_VA_ARG(VaList, PVOID, Worker);
	GET_VA_ARG(VaList, PVOID, Context);
	Status = StorExtQueueWorkItem(HwDeviceExtension, WorkItemCallback,
				      Worker, Context);
	break;
    }

    case ExtFunctionFreeWorker:
    {
	GET_VA_ARG(VaList, PVOID, Worker);
	Status = StorExtFreeWorker(HwDeviceExtension, Worker);
	break;
    }

    case ExtFunctionRegistryReadAdapterKey:
    {
	GET_VA_ARG(VaList, PUCHAR, SubKeyName);
	GET_VA_ARG(VaList, PUCHAR, ValueName);
	GET_VA_ARG(VaList, ULONG, ValueType);
	GET_VA_ARG(VaList, PVOID *, ValueData);
	GET_VA_ARG(VaList, PULONG, ValueDataLength);
	Status = StorExtRegistryReadAdapterKey(HwDeviceExtension,
					       SubKeyName,
					       ValueName,
					       ValueType,
					       ValueData,
					       ValueDataLength);
	break;
    }

    case ExtFunctionRegistryWriteAdapterKey:
    {
	GET_VA_ARG(VaList, PUCHAR, SubKeyName);
	GET_VA_ARG(VaList, PUCHAR, ValueName);
	GET_VA_ARG(VaList, ULONG, ValueType);
	GET_VA_ARG(VaList, PVOID, ValueData);
	GET_VA_ARG(VaList, ULONG, ValueDataLength);
	Status = StorExtRegistryWriteAdapterKey(HwDeviceExtension,
						SubKeyName,
						ValueName,
						ValueType,
						ValueData,
						ValueDataLength);
	break;
    }

    case ExtFunctionMarkDumpMemory:
    {
	UNIMPLEMENTED;
	Status = STOR_STATUS_NOT_IMPLEMENTED;
	break;
    }

    case ExtFunctionSetUnitAttributes:
    {
	UNIMPLEMENTED;
	Status = STOR_STATUS_NOT_IMPLEMENTED;
	break;
    }

    case ExtFunctionMiniportEtwEvent8:
    {
	UNIMPLEMENTED;
	Status = STOR_STATUS_NOT_IMPLEMENTED;
	break;
    }

    default:
	DPRINT1("StorPortExtendedFunction: unimplemented function code %d\n",
		FunctionCode);
	Status = STOR_STATUS_NOT_IMPLEMENTED;
	break;
    }

    va_end(VaList);
    return Status;
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
	assert(FALSE);
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
	assert(FALSE);
	MappedAddress = NULL;
    }

    DPRINT1("Mapped Address: %p\n", MappedAddress);
    return MappedAddress;
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
NTAPI VOID StorPortFreeRegistryBuffer(IN PVOID HwDeviceExtension,
				      IN PUCHAR Buffer)
{
    DPRINT1("StorPortFreeRegistryBuffer()\n");
    UNIMPLEMENTED;
}

/*
 * @unimplemented
 */
NTAPI BOOLEAN StorPortRegistryRead(IN PVOID HwDeviceExtension,
				   IN PUCHAR ValueName,
				   IN ULONG Global,
				   IN ULONG Type,
				   IN PUCHAR Buffer,
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
				    IN PUCHAR ValueName,
				    IN ULONG Global,
				    IN ULONG Type,
				    IN PUCHAR Buffer,
				    IN ULONG BufferLength)
{
    DPRINT1("StorPortRegistryWrite()\n");
    UNIMPLEMENTED;
    return FALSE;
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

/*
 * Returns the corresponding physical address if the virtual address is within
 * the uncached extension and the remaining length till the end of the uncached
 * extension. If that is not the case, check if the virtual address is within
 * the the data buffer or the sense info buffer of the SRB, or within the SRB
 * extension. If so, return its physical address and the remaining length till
 * the end of the buffer or SRB extension. If none of the above is applicable,
 * returns zero.
 *
 * @implemented
 */
NTAPI STOR_PHYSICAL_ADDRESS StorPortGetPhysicalAddress(IN PVOID HwDeviceExtension,
						       IN OPTIONAL PSTORAGE_REQUEST_BLOCK Srb,
						       IN PVOID VirtualAddress,
						       OUT ULONG *Length)
{
    DPRINT1("StorPortGetPhysicalAddress(%p %p %p %p)\n", HwDeviceExtension, Srb,
	    VirtualAddress, Length);
    *Length = 0;

    /* Get the miniport extension */
    PMINIPORT_DEVICE_EXTENSION MiniportExtension = CONTAINING_RECORD(
	HwDeviceExtension, MINIPORT_DEVICE_EXTENSION, HwDeviceExtension);
    DPRINT1("HwDeviceExtension %p  MiniportExtension %p\n", HwDeviceExtension,
	    MiniportExtension);

    PFDO_DEVICE_EXTENSION DeviceExtension = MiniportExtension->Miniport->DeviceExtension;

    STOR_PHYSICAL_ADDRESS PhysicalAddress = { 0 };
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
    } else if (!Srb) {
	assert(FALSE);
    } else if (SrbGetDataBuffer(Srb) &&
	       POINTER_IS_IN_REGION(VirtualAddress, SrbGetDataBuffer(Srb),
				    SrbGetDataTransferLength(Srb))) {
	/* Get the physical address from the scatter-gather list */
	UNIMPLEMENTED_DBGBREAK();
    } else {
	PVOID Buffer = NULL;
	ULONG BufferLength = 0;
	ULONG SrbExtensionSize = MiniportExtension->Miniport->InitData->SrbExtensionSize;
	if (SrbGetSenseInfoBuffer(Srb) &&
	    POINTER_IS_IN_REGION(VirtualAddress, SrbGetSenseInfoBuffer(Srb),
				 SrbGetSenseInfoBufferLength(Srb))) {
	    Buffer = SrbGetSenseInfoBuffer(Srb);
	    BufferLength = SrbGetSenseInfoBufferLength(Srb);
	} else if (SrbGetMiniportContext(Srb) &&
		   POINTER_IS_IN_REGION(VirtualAddress, SrbGetMiniportContext(Srb),
					SrbExtensionSize)) {
	    Buffer = SrbGetMiniportContext(Srb);
	    BufferLength = SrbExtensionSize;
	} else {
	    assert(FALSE);
	}
	if (Buffer && BufferLength) {
	    PhysicalAddress = MmGetPhysicalAddress(VirtualAddress);
	    assert((ULONG_PTR)Buffer + BufferLength > (ULONG_PTR)VirtualAddress);
	    *Length = (ULONG_PTR)Buffer + BufferLength - (ULONG_PTR)VirtualAddress;
	}
    }
    return PhysicalAddress;
}

/*
 * Return the correspoinding virtual address if the physical address falls within
 * the uncached extension or if it was obtained via StorPortGetPhysicalAddress.
 * Otherwise, return NULL.
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
    return MmGetVirtualForPhysical(PhysicalAddress);
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

    if (!NT_SUCCESS(PortFdoInitDma(DeviceExtension, ConfigInfo))) {
	return NULL;
    }

    /* Allocate the uncached extension */
    PHYSICAL_ADDRESS HighestAddress = { .QuadPart = 0x00000000FFFFFFFF };
    PHYSICAL_ADDRESS BoundaryAddressMultiple = {}, PhysicalBase = {};
    PVOID VirtualBase = NULL;
    if (!NT_SUCCESS(MmAllocateContiguousMemorySpecifyCache(NumberOfBytes, HighestAddress,
							   BoundaryAddressMultiple, MmCached,
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
 * @implemented
 */
NTAPI PSTOR_SCATTER_GATHER_LIST StorPortGetScatterGatherList(IN PVOID DeviceExtension,
							     IN PSTORAGE_REQUEST_BLOCK Srb)
{
    DPRINT1("StorPortGetScatterGatherList()\n");
    UNREFERENCED_PARAMETER(DeviceExtension);
    return (Srb && Srb->PortContext) ?
	(PSTOR_SCATTER_GATHER_LIST)((PSRB_PORT_CONTEXT)Srb->PortContext)->SgList : NULL;
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
    PMINIPORT_DEVICE_EXTENSION MiniportExtension =
	CONTAINING_RECORD(DeviceExtension, MINIPORT_DEVICE_EXTENSION, HwDeviceExtension);
    DPRINT1("DeviceExtension %p  MiniportExtension %p\n", DeviceExtension,
	    MiniportExtension);

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
    DPRINT1("StorPortGetBusData(%p %u %u %u %p %u)\n", DeviceExtension, BusDataType,
	    SystemIoBusNumber, SlotNumber, Buffer, Length);

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
    DPRINT1("StorPortSetBusData(%p %u %u %u %p %u %u)\n", DeviceExtension, BusDataType,
	    SystemIoBusNumber, SlotNumber, Buffer, Offset, Length);

    return StorPortReadWriteBusData(DeviceExtension, BusDataType, SystemIoBusNumber,
				    SlotNumber, Buffer, Length, TRUE);
}

static NTSTATUS MiniportGetStorageBusType(IN PUNICODE_STRING RegistryPath,
					  OUT STORAGE_BUS_TYPE *BusType)
{
    RTL_QUERY_REGISTRY_TABLE Parameters[3] = { 0 };

    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, RegistryPath,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE ServiceKey = NULL;
    NTSTATUS Status = NtOpenKey(&ServiceKey, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	assert(FALSE);
	return Status;
    }

    UNICODE_STRING ParamStr;
    RtlInitUnicodeString(&ParamStr, L"Parameters");
    InitializeObjectAttributes(&ObjectAttributes, &ParamStr,
			       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, ServiceKey,
			       NULL);

    HANDLE ParametersKey = NULL;
    Status = NtOpenKey(&ParametersKey, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    ULONG StorageBusType = BusTypeUnknown;
    Parameters[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    Parameters[0].Name = L"BusType";
    Parameters[0].EntryContext = &StorageBusType;
    Parameters[0].DefaultType = (REG_DWORD << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) |
				REG_DWORD;
    Parameters[0].DefaultData = &StorageBusType;
    Parameters[0].DefaultLength = sizeof(ULONG);

    Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE | RTL_REGISTRY_OPTIONAL,
				    ParametersKey, Parameters, NULL, NULL);
    if (NT_SUCCESS(Status)) {
	*BusType = StorageBusType;
    }

out:
    NtClose(ServiceKey);
    return Status;
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

    DPRINT1("StorPortInitialize(%p %p %p %p)\n", Argument1, Argument2, InitData,
	    HwContext);

    DPRINT1("HwInitializationDataSize: %u\n", InitData->HwInitializationDataSize);
    DPRINT1("AdapterInterfaceType: %u\n", InitData->AdapterInterfaceType);
    DPRINT1("HwInitialize: %p\n", InitData->HwInitialize);
    DPRINT1("HwStartIo: %p\n", InitData->HwStartIo);
    DPRINT1("HwInterrupt: %p\n", InitData->HwInterrupt);
    DPRINT1("HwFindAdapter: %p\n", InitData->HwFindAdapter);
    DPRINT1("HwResetBus: %p\n", InitData->HwResetBus);
    DPRINT1("HwDmaStarted: %p\n", InitData->HwDmaStarted);
    DPRINT1("HwAdapterState: %p\n", InitData->HwAdapterState);
    DPRINT1("DeviceExtensionSize: %u\n", InitData->DeviceExtensionSize);
    DPRINT1("SpecificLuExtensionSize: %u\n", InitData->SpecificLuExtensionSize);
    DPRINT1("SrbExtensionSize: %u\n", InitData->SrbExtensionSize);
    DPRINT1("NumberOfAccessRanges: %u\n", InitData->NumberOfAccessRanges);

    /* Check parameters */
    if ((DriverObject == NULL) || (RegistryPath == NULL) || (InitData == NULL)) {
	DPRINT1("Invalid parameter!\n");
	return STATUS_INVALID_PARAMETER;
    }

    /* Check initialization data */
    if ((InitData->HwInitializationDataSize < sizeof(HW_INITIALIZATION_DATA)) ||
	(InitData->HwInitialize == NULL) || (InitData->HwStartIo == NULL) ||
	(InitData->HwFindAdapter == NULL) || (InitData->HwResetBus == NULL)) {
	DPRINT1("Revision mismatch!\n");
	return STATUS_REVISION_MISMATCH;
    }

    /* Open the driver service registry to query the storage bus type (SATA, NVME, etc) */
    STORAGE_BUS_TYPE BusType = BusTypeUnknown;
    MiniportGetStorageBusType(RegistryPath, &BusType);

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
	DriverObjectExtension->StorageBusType = BusType;

	InitializeListHead(&DriverObjectExtension->AdapterListHead);

	InitializeListHead(&DriverObjectExtension->InitDataListHead);

	/* Set handlers */
	DriverObject->AddDevice = PortAddDevice;
	DriverObject->DriverUnload = PortUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = PortDispatchCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = PortDispatchClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PortDispatchDeviceControl;
	DriverObject->MajorFunction[IRP_MJ_SCSI] = PortDispatchScsi;
	DriverObject->MajorFunction[IRP_MJ_POWER] = PortDispatchPower;
	DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = PortDispatchSystemControl;
	DriverObject->MajorFunction[IRP_MJ_PNP] = PortDispatchPnp;

	/* We use our own device queues so driver StartIo should be set to NULL. */
	DriverObject->DriverStartIo = NULL;
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
			    IN OPTIONAL PSTORAGE_REQUEST_BLOCK Srb,
			    IN UCHAR PathId,
			    IN UCHAR TargetId,
			    IN UCHAR Lun,
			    IN ULONG ErrorCode,
			    IN ULONG UniqueId)
{
    DPRINT1("PathId: 0x%02x  TargetId: 0x%02x  Lun: 0x%02x  ErrorCode: 0x%08x  UniqueId: "
	    "0x%08x\n", PathId, TargetId, Lun, ErrorCode, UniqueId);
}

/*
 * @implemented
 */
NTAPI VOID StorPortMoveMemory(OUT PVOID Destination,
			      IN PVOID Source,
			      IN ULONG Length)
{
    RtlMoveMemory(Destination, Source, Length);
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
 * @implemented
 */
NTAPI PSTORAGE_REQUEST_BLOCK StorPortGetSrb(IN PVOID DeviceExtension,
					 IN UCHAR PathId,
					 IN UCHAR TargetId,
					 IN UCHAR Lun,
					 IN LONG QueueTag)
{
    DPRINT("StorPortGetSrb()\n");
    return NULL;
}

static NTAPI VOID StorPortDpcWorkerRoutine(IN PDEVICE_OBJECT DeviceObject,
					   IN PVOID Context)
{
    assert(Context);
    PSTOR_DPC Dpc = Context;
    assert(Dpc->HwDpcRoutine);
    PFDO_DEVICE_EXTENSION FdoDevExt = DeviceObject->DeviceExtension;
    PVOID HwDeviceExtension = FdoDevExt->Miniport.MiniportExtension->HwDeviceExtension;
    Dpc->HwDpcRoutine(Dpc, HwDeviceExtension,
		      Dpc->SystemArgument1, Dpc->SystemArgument2);
}

/*
 * @unimplemented
 */
VOID StorPortNotification(IN SCSI_NOTIFICATION_TYPE NotificationType,
			  IN PVOID HwDeviceExtension, ...)
{
    /* Get the miniport extension */
    assert(HwDeviceExtension != NULL);
    PMINIPORT_DEVICE_EXTENSION MiniportExt = CONTAINING_RECORD(HwDeviceExtension,
							       MINIPORT_DEVICE_EXTENSION,
							       HwDeviceExtension);
    PFDO_DEVICE_EXTENSION DevExt = MiniportExt->Miniport->DeviceExtension;

    va_list ap;
    va_start(ap, HwDeviceExtension);

    switch (NotificationType) {
    case RequestComplete:
    {
	GET_VA_ARG(ap, PSTORAGE_REQUEST_BLOCK, Srb);
	DPRINT1("RequestComplete Srb %p\n", Srb);
	PortCompleteRequest(Srb, FALSE);
	break;
    }

    case GetExtendedFunctionTable:
    {
	/* No miniport uses this routine yet so we don't bother implementing this. */
	DPRINT1("GetExtendedFunctionTable\n");
	UNIMPLEMENTED;
	UNIMPLEMENTED_DBGBREAK();
	GET_VA_ARG(ap, PSTORPORT_EXTENDED_FUNCTIONS *, ExtFcns);
	if (ExtFcns != NULL)
	    *ExtFcns = NULL; /* FIXME */
	break;
    }

    case EnablePassiveInitialization:
    {
	DPRINT1("EnablePassiveInitialization\n");
	GET_VA_ARG(ap, PHW_PASSIVE_INITIALIZE_ROUTINE, HwPassiveInitRoutine);
	GET_VA_ARG(ap, PBOOLEAN, Result);
	*Result = FALSE;
	if ((DevExt != NULL) &&
	    (DevExt->HwPassiveInitRoutine == NULL)) {
	    DevExt->HwPassiveInitRoutine = HwPassiveInitRoutine;
	    *Result = TRUE;
	}
	break;
    }

    case InitializeDpc:
    {
	DPRINT1("InitializeDpc\n");
	GET_VA_ARG(ap, PSTOR_DPC, Dpc);
	GET_VA_ARG(ap, PHW_DPC_ROUTINE, HwDpcRoutine);
	IoInitializeWorkItem(DevExt->Device, &Dpc->WorkItem);
	Dpc->HwDpcRoutine = HwDpcRoutine;
	break;
    }

    case IssueDpc:
    {
	DPRINT1("IssueDpc\n");
	GET_VA_ARG(ap, PSTOR_DPC, Dpc);
	GET_VA_ARG(ap, PVOID, SystemArgument1);
	GET_VA_ARG(ap, PVOID, SystemArgument2);
	Dpc->SystemArgument1 = SystemArgument1;
	Dpc->SystemArgument2 = SystemArgument2;
	IoQueueWorkItem(&Dpc->WorkItem, StorPortDpcWorkerRoutine,
			DelayedWorkQueue, Dpc);
	break;
    }

    case AcquireSpinLock:
    {
	DPRINT1("AcquireSpinLock\n");
	GET_VA_ARG(ap, STOR_SPINLOCK, SpinLock);
	GET_VA_ARG(ap, PVOID, LockContext);
	GET_VA_ARG(ap, PSTOR_LOCK_HANDLE, LockHandle);
	PortAcquireSpinLock(DevExt, SpinLock, LockContext, LockHandle);
	break;
    }

    case ReleaseSpinLock:
    {
	DPRINT1("ReleaseSpinLock\n");
	GET_VA_ARG(ap, PSTOR_LOCK_HANDLE, LockHandle);
	PortReleaseSpinLock(DevExt, LockHandle);
	break;
    }

    default:
	DPRINT1("Unsupported Notification %x\n", NotificationType);
	break;
    }

    va_end(ap);
}

/*
 * @implemented
 */
NTAPI VOID StorPortQuerySystemTime(OUT PLARGE_INTEGER CurrentTime)
{
    DPRINT1("StorPortQuerySystemTime(%p)\n", CurrentTime);

    KeQuerySystemTime(CurrentTime);
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
