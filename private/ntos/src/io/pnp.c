/*
  Copyright (c) 2022  Dr. Chang Liu, PhD.

Module Name:

    pnp.c

Abstract:

    This module implements the PnP Manager of the IO subsystem. Central
    to the PnP manager is a data structure called the device node, which
    represents either a device (such as a keyboard, a PCI bus, or a
    software-emulated device such as a virtual CD drive), or a single
    function on a multi-functional card (such as the MIDI synth function
    on a sound chip). Except for the root device node, a device node is
    always enumerated by a parent node, which represents the bus to
    which the child device is connected. This makes the set of all
    device nodes on a system into a tree, namely the device tree.

    The root node itself is created by the PnP manager and represents
    the device node for the root PnP enumerator driver (configured by
    smss to be pnp.sys). The root enumerator enumerates devices that
    cannot announce themselves. These include all legacy (non-PnP)
    devices configured by the smss, as well as the ACPI HAL. The ACPI
    driver will query the system ACPI tables to enumerate the primary
    system bus as well as other motherboard resources, which in turn
    causes their drivers to be loaded and their device nodes enumerated.
    By recursively enumerating the root device node, the device tree of
    the entire system is built. This is done on system startup, and can
    be trigger by user space via NtPlugPlayControl.

    At any given time, the state of a device node is represented by
    the enum DEVICE_NODE_STATE. Actions such as enumerating node,
    loading drivers, adding devices, starting devices, removing
    devices, etc will cause the device node to transit to another
    state. The transitions form a state machine, described below.
    The PnP manager uses a circular buffer for each device node to
    keep track of the state transition history of the node.


    DEVICE NODE STATE MACHINE

    0 (DeviceNodeUnspecified) ---> DeviceNodeInitialized
       When a device node is created, it is initialized to be in the
    state DeviceNodeInitialized. DeviceNodeUnspecified represents an
    invalid state.

    DeviceNodeInitialized ---> DeviceNodeDevicesAdded
    DeviceNodeInitialized ---> DeviceNodeAddDeviceFailed
    When...
 */

#include <initguid.h>
#include "iop.h"
#include <pnpguid.h>

#define REG_SERVICE_KEY	"\\Registry\\Machine\\System\\CurrentControlSet\\Services"
#define REG_CLASS_KEY	"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class"
#define REG_ENUM_KEY	"\\Registry\\Machine\\System\\CurrentControlSet\\Enum"

typedef struct _PNP_EVENT_ENTRY {
    LIST_ENTRY ListEntry;
    IO_PNP_EVENT_BLOCK Event;
} PNP_EVENT_ENTRY, *PPNP_EVENT_ENTRY;

static PDEVICE_NODE IopRootDeviceNode;
static LIST_ENTRY IopHardwareProfileChangeList;
static LIST_ENTRY IopDeviceInterfaceChangeList;
static LIST_ENTRY IopPnpEventQueueHead;
static KEVENT IopPnpNotifyEvent;

static RTL_RANGE_LIST IopDmaChannelsInUse;
static RTL_RANGE_LIST IopPortRangesInUse;
static RTL_RANGE_LIST IopMemoryRangesInUse;
static RTL_RANGE_LIST IopInterruptVectorsInUse;
static RTL_RANGE_LIST IopBusNumbersInUse;

/*
 * The created device node is in the DeviceNodeUnspecified state.
 */
static inline NTSTATUS IopCreateDeviceNode(IN OPTIONAL PDEVICE_NODE ParentNode,
					   OUT PDEVICE_NODE *pDevNode)
{
    assert(pDevNode != NULL);
    IopAllocatePool(DeviceNode, DEVICE_NODE);
    DeviceNode->Parent = ParentNode;
    InitializeListHead(&DeviceNode->ChildrenList);
    if (ParentNode != NULL) {
	InsertTailList(&ParentNode->ChildrenList, &DeviceNode->SiblingLink);
    }
    if (pDevNode != NULL) {
	*pDevNode = DeviceNode;
    }
    return STATUS_SUCCESS;
}

static inline VOID IopFreeDeviceNode(IN PDEVICE_NODE DeviceNode)
{
    assert(DeviceNode != NULL);
    assert(IsListEmpty(&DeviceNode->ChildrenList));
    if (DeviceNode->Parent != NULL) {
	RemoveEntryList(&DeviceNode->SiblingLink);
    }
    if (DeviceNode->DeviceId != NULL) {
	IopFreePool(DeviceNode->DeviceId);
    }
    if (DeviceNode->InstanceId != NULL) {
	IopFreePool(DeviceNode->InstanceId);
    }
    if (DeviceNode->RawResources != NULL) {
	IopFreePool(DeviceNode->RawResources);
    }
    if (DeviceNode->TranslatedResources != NULL) {
	IopFreePool(DeviceNode->TranslatedResources);
    }
    IopFreePool(DeviceNode);
}

static inline DEVICE_NODE_STATE IopDeviceNodeGetCurrentState(IN PDEVICE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CurrentState < DEVNODE_HISTORY_SIZE);
    return Node->StateHistory[Node->CurrentState % DEVNODE_HISTORY_SIZE];
}

static inline DEVICE_NODE_STATE IopDeviceNodeGetPreviousState(IN PDEVICE_NODE Node)
{
    assert(Node != NULL);
    assert(Node->CurrentState < DEVNODE_HISTORY_SIZE);
    return Node->StateHistory[(Node->CurrentState - 1) % DEVNODE_HISTORY_SIZE];
}

/*
 * Set the device node of a device object by finding its PDO (lowest
 * device object in the device stack) and set its DeviceNode member.
 */
static inline VOID IopSetDeviceNode(IN PIO_DEVICE_OBJECT DeviceObject,
				    IN PDEVICE_NODE DeviceNode)
{
    assert(DeviceObject != NULL);
    assert(DeviceNode != NULL);
    assert(DeviceNode->PhyDevObj == NULL);
    /* Locate the lowest device object */
    PIO_DEVICE_OBJECT Pdo = DeviceObject;
    while (Pdo != NULL && Pdo->AttachedTo != NULL) {
	assert(Pdo->DeviceNode == NULL);
	Pdo = Pdo->AttachedTo;
	assert(Pdo != NULL);
    }
    assert(Pdo->DeviceNode == NULL);
    Pdo->DeviceNode = DeviceNode;
    DeviceNode->PhyDevObj = Pdo;
}

static PCHAR IopDuplicateMultiSz(IN PCSTR String,
				 OUT ULONG *Length)
{
    *Length = 0;
    if (String[0] == '\0') {
	return NULL;
    }
    while (TRUE) {
	(*Length)++;
	if (String[*Length] == '\0') {
	    if (String[*Length+1] == L'\0') {
		(*Length)++;
		break;
	    }
	}
    }
    (*Length)++;
    PCHAR Dest = ExAllocatePoolWithTag(*Length, NTOS_IO_TAG);
    if (!Dest) {
	return NULL;
    }
    RtlCopyMemory(Dest, String, *Length);
    return Dest;
}

static inline NTSTATUS IopDeviceNodeSetDeviceId(IN PDEVICE_NODE DeviceNode,
						IN PCSTR DeviceId,
						IN BUS_QUERY_ID_TYPE IdType)
{
    assert(DeviceNode != NULL);
    if (!DeviceId || DeviceId[0] == '\0') {
	return STATUS_INVALID_PARAMETER;
    }
    switch (IdType) {
    case BusQueryDeviceID:
	assert(DeviceNode->DeviceId == NULL);
	DeviceNode->DeviceId = RtlDuplicateString(DeviceId, NTOS_IO_TAG);
	if (DeviceNode->DeviceId == NULL) {
	    return STATUS_NO_MEMORY;
	}
	break;
    case BusQueryInstanceID:
	assert(DeviceNode->InstanceId == NULL);
	DeviceNode->InstanceId = RtlDuplicateString(DeviceId, NTOS_IO_TAG);
	if (DeviceNode->InstanceId == NULL) {
	    return STATUS_NO_MEMORY;
	}
	break;
    case BusQueryHardwareIDs:
	assert(DeviceNode->HardwareIds == NULL);
	assert(DeviceNode->HardwareIdsLength == 0);
	DeviceNode->HardwareIds = IopDuplicateMultiSz(DeviceId,
						      &DeviceNode->HardwareIdsLength);
	if (DeviceNode->HardwareIdsLength && !DeviceNode->HardwareIds) {
	    return STATUS_NO_MEMORY;
	}
	break;
    case BusQueryCompatibleIDs:
	assert(DeviceNode->CompatibleIds == NULL);
	assert(DeviceNode->CompatibleIdsLength == 0);
	DeviceNode->CompatibleIds = IopDuplicateMultiSz(DeviceId,
							&DeviceNode->CompatibleIdsLength);
	if (DeviceNode->CompatibleIdsLength && !DeviceNode->CompatibleIds) {
	    return STATUS_NO_MEMORY;
	}
	break;
    default:
	DbgTrace("Invalid id type %d\n", IdType);
	assert(FALSE);
	return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static inline VOID IopFreeFilterDriverNames(IN ULONG Count,
					    IN PCSTR *Names)
{
    for (ULONG i = 0; i < Count; i++) {
	IopFreePool(Names[i]);
    }
    IopFreePool(Names);
}

static inline ULONG IopGetStringCount(IN PCSTR MultiSz)
{
    ULONG Count = 0;
    if (MultiSz != NULL) {
	PCSTR Ptr = MultiSz;
	while (*Ptr != '\0') {
	    ULONG Length = strlen(Ptr);
	    Count++;
	    Ptr += Length + 1;	/* NUL-terminated strings */
	}
    }
    return Count;
}

static inline NTSTATUS IopAllocateNames(IN PCSTR MultiSz,
					IN PCSTR *Names)
{
    ULONG Count = 0;
    if (MultiSz != NULL) {
	PCSTR Ptr = MultiSz;
	while (*Ptr != '\0') {
	    ULONG Length = strlen(Ptr);
	    Names[Count] = RtlDuplicateString(Ptr, NTOS_IO_TAG);
	    if (Names[Count] == NULL) {
		return STATUS_NO_MEMORY;
	    }
	    Ptr += Length + 1;
	    Count++;
	}
    }
    return STATUS_SUCCESS;
}

/*
 * Device filters come before class filters and are loaded before them.
 */
static NTSTATUS IopAllocateFilterDriverNames(IN PCSTR DeviceFilters,
					     IN PCSTR ClassFilters,
					     OUT ULONG *pFilterCount,
					     OUT PCSTR **pFilterDriverNames)
{
    ULONG DeviceFilterCount = IopGetStringCount(DeviceFilters);
    ULONG FilterCount = DeviceFilterCount + IopGetStringCount(ClassFilters);

    if (FilterCount == 0) {
	return STATUS_SUCCESS;
    }

    /* Count the number of strings (excluding the empty string) */
    PCSTR *FilterDriverNames = ExAllocatePoolWithTag(sizeof(PCSTR) * FilterCount,
						     NTOS_IO_TAG);
    if (FilterDriverNames == NULL) {
	goto err;
    }
    if (!NT_SUCCESS(IopAllocateNames(DeviceFilters, FilterDriverNames))) {
	goto err;
    }
    if (!NT_SUCCESS(IopAllocateNames(ClassFilters,
				     FilterDriverNames + DeviceFilterCount))) {
	goto err;
    }
    *pFilterCount = FilterCount;
    *pFilterDriverNames = FilterDriverNames;
    return STATUS_SUCCESS;

err:
    if (FilterDriverNames != NULL) {
	for (ULONG i = 0; i < FilterCount; i++) {
	    if (FilterDriverNames[i] != NULL) {
		IopFreePool(FilterDriverNames[i]);
	    }
	}
	IopFreePool(FilterDriverNames);
    }
    return STATUS_NO_MEMORY;
}

static ULONG IopGetRegDword(IN POBJECT Key,
			    IN PCSTR Value)
{
    ULONG RegValueType = 0;
    PULONG RegDword = NULL;
    if (NT_SUCCESS(CmReadKeyValueByPointer(Key, Value, &RegValueType, (PPVOID)&RegDword))) {
	if (RegValueType != REG_DWORD) {
	    assert(FALSE);
	    return 0;
	}
	assert(RegDword);
	return *RegDword;
    }
    return 0;
}

static PCSTR IopGetMultiSz(IN POBJECT Key,
			   IN PCSTR Value)
{
    ULONG RegValueType = 0;
    PCSTR MultiSz = NULL;
    if (NT_SUCCESS(CmReadKeyValueByPointer(Key, Value, &RegValueType, (PPVOID)&MultiSz))) {
	if (RegValueType != REG_MULTI_SZ) {
	    return NULL;
	}
    }
    return MultiSz;
}

static PCSTR IopGetRegSz(IN POBJECT Key,
			 IN PCSTR Value)
{
    ULONG RegValueType = 0;
    PCSTR RegSz = NULL;
    if (NT_SUCCESS(CmReadKeyValueByPointer(Key, Value, &RegValueType, (PPVOID)&RegSz))) {
	if (RegValueType != REG_SZ) {
	    return NULL;
	}
    }
    return RegSz;
}

/*
 * Load the specified driver service into a standalone driver process.
 */
static NTSTATUS IopLoadDriverByBaseName(IN ASYNC_STATE State,
					IN PTHREAD Thread,
					IN PCSTR BaseName)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State, Locals, {
	    CHAR DriverService[256];
	});
    snprintf(Locals.DriverService, sizeof(Locals.DriverService),
	     REG_SERVICE_KEY "\\%s", BaseName);
    AWAIT_EX(Status, IopLoadDriver, State, Locals, Thread,
	     Locals.DriverService);
    ASYNC_END(State, Status);
}

/*
 * Queue a message to the specified target driver and instruct it to load
 * the driver image with the given driver service base name. Note this is
 * a server notification message, and client reply is not needed.
 */
static NTSTATUS IopQueueLoadDriverMsg(IN PIO_DRIVER_OBJECT TargetDriver,
				      IN PCSTR BaseName)
{
    ULONG BaseNameLength = strlen(BaseName) + 1;
    /* Allocate a new IO packet of type ServerMessage */
    PIO_PACKET SrvMsg = NULL;
    NTSTATUS Status = IopAllocateIoPacket(IoPacketTypeServerMessage,
					  sizeof(IO_PACKET) + BaseNameLength,
					  &SrvMsg);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    assert(SrvMsg != NULL);
    SrvMsg->ServerMsg.Type = IoSrvMsgLoadDriver;
    SrvMsg->ServerMsg.LoadDriver.BaseNameLength = BaseNameLength;
    memcpy(SrvMsg->ServerMsg.LoadDriver.BaseName, BaseName, BaseNameLength);

    /* Add the server message IO packet to the driver IO packet queue */
    InsertTailList(&TargetDriver->IoPacketQueue, &SrvMsg->IoPacketLink);
    /* Signal the driver that an IO packet has been queued */
    KeSetEvent(&TargetDriver->IoPacketQueuedEvent);

    return STATUS_SUCCESS;
}

static NTSTATUS IopQueueDeviceInstallEvent(IN const GUID *EventGuid,
					   IN PDEVICE_NODE DeviceNode)
{
    ULONG StringSize = strlen(DeviceNode->DeviceId) + strlen(DeviceNode->InstanceId) + 2;
    ULONG TotalSize = FIELD_OFFSET(PNP_EVENT_ENTRY, Event.InstallDevice) + StringSize;
    PPNP_EVENT_ENTRY EventEntry = ExAllocatePoolWithTag(TotalSize, NTOS_IO_TAG);
    if (!EventEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&EventEntry->Event.EventGuid, EventGuid, sizeof(GUID));
    EventEntry->Event.EventCategory = DeviceInstallEvent;
    EventEntry->Event.TotalSize = TotalSize;
    snprintf(EventEntry->Event.InstallDevice.DeviceId, StringSize,
	     "%s\\%s", DeviceNode->DeviceId, DeviceNode->InstanceId);
    InsertHeadList(&IopPnpEventQueueHead, &EventEntry->ListEntry);
    KeSetEvent(&IopPnpNotifyEvent);
    return STATUS_SUCCESS;
}

static PCSTR IopGetDriverProcessName(IN PDEVICE_NODE DeviceNode)
{
    PCSTR DriverProcessName = DeviceNode->DriverServiceName;
    while (DeviceNode->Parent && DeviceNode->LoadIntoBusDriver) {
	DeviceNode = DeviceNode->Parent;
	DriverProcessName = DeviceNode->DriverServiceName;
    }
    assert(DriverProcessName);
    return DriverProcessName;
}

/*
 * Load the class, filter, and function driver(s) of the device node.
 *
 * For each class and filter driver, its driver image is loaded into two
 * processes: (1) as a standalone driver object within its own process,
 * and (2) inside the function driver process. The latter is loaded
 * after the function driver has finished loading. The reason for doing
 * this is so that the class and filter drivers can send IRPs to the
 * function driver without incurring context switch costs.
 *
 * For a function driver, its driver service registry can specify whether
 * the function driver is loaded into the same process as its bus driver,
 * or whether the function driver is loaded into its own address space.
 * In the former case, either driver crashing will bring down both the
 * bus device nodes and the child device nodes.
 *
 * A note about driver loading order: for the standalone driver objects,
 * device lower filters are loaded first, followed by class lower filters,
 * and then the function driver itself, and then device upper filters, and
 * finally class upper filters. In other words, class filter drivers are
 * always loaded after the device filter drivers on the same level. For
 * the driver images loaded inside the function driver process, the load
 * order follows the standalone driver objects, except that the function
 * driver is loaded first.
 */
static NTSTATUS IopDeviceNodeLoadDrivers(IN ASYNC_STATE State,
					 IN PTHREAD Thread,
					 IN PDEVICE_NODE DeviceNode)
{
    NTSTATUS Status;
    POBJECT ClassKey = NULL;
    POBJECT EnumKey = NULL;
    ULONG RegValueType = 0;
    PCSTR DriverServiceName = NULL;
    PCSTR DriverProcessName = NULL;

    ASYNC_BEGIN(State, Locals, {
	    CHAR KeyPath[256];
	    POBJECT EnumKey;
	    POBJECT ClassKey;
	    PCSTR DeviceUpperFilterNames;
	    PCSTR DeviceLowerFilterNames;
	    OB_OBJECT_ATTRIBUTES ObjectAttributes;
	    CM_OPEN_CONTEXT OpenContext;
	    PCSTR ClassUpperFilterNames;
	    PCSTR ClassLowerFilterNames;
	    ULONG Idx;
	});
    assert(DeviceNode != NULL);
    assert(DeviceNode->DeviceId != NULL);
    assert(DeviceNode->InstanceId != NULL);
    if (IopDeviceNodeGetCurrentState(DeviceNode) != DeviceNodeInitialized) {
	DbgTrace("Device node state is %d. Not loading drivers.\n",
		 IopDeviceNodeGetCurrentState(DeviceNode));
	ASYNC_RETURN(State, STATUS_INVALID_DEVICE_STATE);
    }

    /* If previous attempts at driver loading failed, we want to clear the
     * driver service name and filter driver names, just in case that these
     * have changed. */
    if (DeviceNode->DriverServiceName != NULL) {
	IopFreePool(DeviceNode->DriverServiceName);
	DeviceNode->DriverServiceName = NULL;
    }
    if (DeviceNode->UpperFilterNames != NULL) {
	IopFreeFilterDriverNames(DeviceNode->UpperFilterCount,
				 DeviceNode->UpperFilterNames);
	DeviceNode->UpperFilterCount = 0;
	DeviceNode->UpperFilterNames = NULL;
    }
    if (DeviceNode->LowerFilterNames != NULL) {
	IopFreeFilterDriverNames(DeviceNode->LowerFilterCount,
				 DeviceNode->LowerFilterNames);
	DeviceNode->LowerFilterCount = 0;
	DeviceNode->LowerFilterNames = NULL;
    }

    /* Query the device enum key to find the driver service to load */
    snprintf(Locals.KeyPath, sizeof(Locals.KeyPath), REG_ENUM_KEY "\\%s\\%s",
	     DeviceNode->DeviceId, DeviceNode->InstanceId);
    AWAIT_EX(Status, CmReadKeyValueByPath, State, Locals, Thread,
	     Locals.KeyPath, "Service", &EnumKey,
	     &RegValueType, (PPVOID)&DriverServiceName);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    assert(EnumKey);
    Locals.EnumKey = EnumKey;
    if (RegValueType != REG_SZ) {
	Status = STATUS_DRIVER_UNABLE_TO_LOAD;
	goto out;
    }
    assert(DriverServiceName);
    DeviceNode->DriverServiceName = RtlDuplicateString(DriverServiceName, NTOS_IO_TAG);
    if (DeviceNode->DriverServiceName == NULL) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }
    DeviceNode->LoadIntoBusDriver = IopGetRegDword(Locals.EnumKey, "LoadIntoBusDriver");

    /* Also query the upper and lower device filter drivers */
    Locals.DeviceUpperFilterNames = IopGetMultiSz(Locals.EnumKey, "UpperFilters");
    Locals.DeviceLowerFilterNames = IopGetMultiSz(Locals.EnumKey, "LowerFilters");

    /* Query the class key to find the upper and lower class filters */
    PCSTR ClassGuid = IopGetRegSz(Locals.EnumKey, "ClassGUID");
    if (!ClassGuid) {
	goto load;
    }

    snprintf(Locals.KeyPath, sizeof(Locals.KeyPath), REG_CLASS_KEY "\\%s",
	     ClassGuid);
    Locals.ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
    Locals.ObjectAttributes.ObjectNameBuffer = Locals.KeyPath;
    Locals.ObjectAttributes.ObjectNameBufferLength = strlen(Locals.KeyPath) + 1;
    Locals.OpenContext.Header.Type = OPEN_CONTEXT_KEY_OPEN;
    Locals.OpenContext.Create = FALSE;
    AWAIT_EX(Status, ObOpenObjectByNameEx, State, Locals, Thread,
	     Locals.ObjectAttributes, OBJECT_TYPE_KEY, KEY_ENUMERATE_SUB_KEYS,
	     (POB_OPEN_CONTEXT)&Locals.OpenContext, FALSE, &ClassKey);
    if (!NT_SUCCESS(Status)) {
	goto load;
    }
    assert(ClassKey);
    Locals.ClassKey = ClassKey;
    Locals.ClassUpperFilterNames = IopGetMultiSz(Locals.ClassKey, "UpperFilters");
    Locals.ClassLowerFilterNames = IopGetMultiSz(Locals.ClassKey, "LowerFilters");

load:
    /* Record the filter driver names in the device node */
    IF_ERR_GOTO(out, Status,
		IopAllocateFilterDriverNames(Locals.DeviceUpperFilterNames,
					     Locals.ClassUpperFilterNames,
					     &DeviceNode->UpperFilterCount,
					     &DeviceNode->UpperFilterNames));
    IF_ERR_GOTO(out, Status,
		IopAllocateFilterDriverNames(Locals.DeviceLowerFilterNames,
					     Locals.ClassLowerFilterNames,
					     &DeviceNode->LowerFilterCount,
					     &DeviceNode->LowerFilterNames));

    /* If the function driver service key specified that it should be loaded
     * into the bus driver, inject the entire driver stack (filters and
     * function) into the bus driver process. */
    if (DeviceNode->LoadIntoBusDriver) {
	goto inject;
    }

    /* Otherwise, load lower filter drivers first */
    Locals.Idx = 0;
lower:
    if (Locals.Idx >= DeviceNode->LowerFilterCount) {
	goto function;
    }
    AWAIT_EX(Status, IopLoadDriverByBaseName, State, Locals, Thread,
	     DeviceNode->LowerFilterNames[Locals.Idx]);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.Idx++;
    goto lower;

function:
    /* Load function driver next */
    AWAIT_EX(Status, IopLoadDriverByBaseName, State, Locals, Thread,
	     DeviceNode->DriverServiceName);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Finally, load upper filter drivers */
    Locals.Idx = 0;
upper:
    if (Locals.Idx >= DeviceNode->UpperFilterCount) {
	goto inject;
    }
    AWAIT_EX(Status, IopLoadDriverByBaseName, State, Locals, Thread,
	     DeviceNode->UpperFilterNames[Locals.Idx]);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.Idx++;
    goto upper;

inject:
    /* For each class/filter driver, instruct the function driver process to
     * load the driver image of the class/filter driver. Note we do not expect
     * the driver process to reply since we are simply queuing a server notification
     * message. If there was an error during the load, the driver process will
     * raise an exception, and clean up is done in IoUnloadDriver. */
    DriverProcessName = IopGetDriverProcessName(DeviceNode);
    assert(DriverProcessName);
    PIO_DRIVER_OBJECT DriverObject = IopGetDriverObject(DriverProcessName);
    if (!DriverObject) {
	Status = STATUS_DRIVER_UNABLE_TO_LOAD;
	goto out;
    }
    for (ULONG i = 0; i < DeviceNode->LowerFilterCount; i++) {
	IF_ERR_GOTO(out, Status,
		    IopQueueLoadDriverMsg(DriverObject,
					  DeviceNode->LowerFilterNames[i]));
    }
    if (DeviceNode->LoadIntoBusDriver) {
	IF_ERR_GOTO(out, Status,
		    IopQueueLoadDriverMsg(DriverObject,
					  DeviceNode->DriverServiceName));
    }
    for (ULONG i = 0; i < DeviceNode->UpperFilterCount; i++) {
	IF_ERR_GOTO(out, Status,
		    IopQueueLoadDriverMsg(DriverObject,
					  DeviceNode->UpperFilterNames[i]));
    }
    Status = STATUS_SUCCESS;

out:
    if (NT_SUCCESS(Status)) {
        IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeDriversLoaded);
    } else {
	/* If we failed to load the drivers for the device node, queue a PnP event
	 * so the client can install the drivers and re-enumerate the device node. */
        IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeInitialized);
	DeviceNode->ErrorStatus = IopQueueDeviceInstallEvent(&GUID_DEVICE_ENUMERATED,
							     DeviceNode);
    }
    /* Dereference the enum key object because the CmReadKeyValueByPath routine
     * increases its reference count. */
    if (Locals.EnumKey) {
	ObDereferenceObject(Locals.EnumKey);
    }
    if (Locals.ClassKey) {
	ObDereferenceObject(Locals.ClassKey);
    }
    ASYNC_END(State, Status);
}

static NTSTATUS IopQueueQueryDeviceRelationsRequest(IN PTHREAD Thread,
						    IN PIO_DEVICE_OBJECT DeviceObject,
						    IN DEVICE_RELATION_TYPE Type,
						    OUT PPENDING_IRP *PendingIrp)
{
    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_PNP,
	.MinorFunction = IRP_MN_QUERY_DEVICE_RELATIONS,
	.Device.Object = DeviceObject,
	.QueryDeviceRelations.Type = Type
    };
    return IopCallDriver(Thread, &Irp, PendingIrp);
}

static NTSTATUS IopQueueBusQueryIdRequest(IN PTHREAD Thread,
					  IN PIO_DEVICE_OBJECT ChildPhyDev,
					  IN BUS_QUERY_ID_TYPE IdType,
					  OUT PPENDING_IRP *PendingIrp)
{
    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_PNP,
	.MinorFunction = IRP_MN_QUERY_ID,
	.Device.Object = ChildPhyDev,
	.QueryId.IdType = IdType
    };
    return IopCallDriver(Thread, &Irp, PendingIrp);
}

static NTSTATUS IopQueueBusQueryInformationRequest(IN PTHREAD Thread,
						   IN PIO_DEVICE_OBJECT ChildPhyDev,
						   OUT PPENDING_IRP *PendingIrp)
{
    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_PNP,
	.MinorFunction = IRP_MN_QUERY_BUS_INFORMATION,
	.Device.Object = ChildPhyDev,
    };
    return IopCallDriver(Thread, &Irp, PendingIrp);
}

static NTSTATUS IopQueueAddDeviceRequest(IN PTHREAD Thread,
					 IN PDEVICE_NODE DeviceNode,
					 IN PIO_DRIVER_OBJECT DriverObject,
					 IN PCSTR DriverName,
					 OUT PPENDING_IRP *PendingIrp)
{
    assert(DriverName);
    PIO_DEVICE_OBJECT PhyDevObj = DeviceNode->PhyDevObj;
    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_ADD_DEVICE,
	.Device.Object = PhyDevObj
    };
    if (PhyDevObj) {
	Irp.AddDevice.PhysicalDeviceInfo = PhyDevObj->DeviceInfo;
    }
    ULONG BaseNameLength = strlen(DriverName) + 1;
    if (BaseNameLength > sizeof(Irp.AddDevice.BaseName)) {
	/* If this happens, we should increase the size of the BaseName buffer. */
	assert(FALSE);
	return STATUS_BUFFER_TOO_SMALL;
    }
    memcpy(Irp.AddDevice.BaseName, DriverName, BaseNameLength);
    return IopCallDriverEx(Thread, &Irp, DriverObject, PendingIrp);
}

/*
 * For each upper-filter/function/lower-filter driver, call the AddDevice
 * routine of the driver object. Of course, here "call" means queuing the
 * IRP and wait for driver response (we are a micro-kernel OS!). If the
 * function driver is loaded into the bus driver's address space, we send
 * the AddDevice messages to the bus driver, specifying the driver name
 * for the function and filter drivers. If the function driver is loaded
 * into its own driver process, for each filter driver two kinds of
 * AddDevice requests will be sent: first to the standalone, singleton
 * driver object of the filter driver, and then to the function driver,
 * specifying the filter driver service name. This is so that the filter
 * drivers can decide whether it wants to process the IRPs within the
 * function driver process or not. If the communication between filter
 * and function drivers is heavy, the filter drivers should preferably
 * process IRPs within the function driver process. In this case, the
 * filter driver's AddDevice routine should do nothing and simply return
 * STATUS_SUCCESS if it detects it's running in singleton mode (via the
 * IoIsSingletonMode routine). If on the other hand the filter driver
 * wishes to process IO in the standalone process, its AddDevice routine
 * should do nothing and return STATUS_SUCCESS if IoIsSingletonMode returns
 * FALSE.
 */
static NTSTATUS IopDeviceNodeAddDevice(IN ASYNC_STATE AsyncState,
				       IN PTHREAD Thread,
				       IN PDEVICE_NODE DeviceNode)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PPENDING_IRP PendingIrp;
	    PCSTR DriverName;
	    ULONG LowerFilterCount;
	    ULONG UpperFilterCount;
	    BOOLEAN FunctionDriverCalled;
	});

    if (IopDeviceNodeGetCurrentState(DeviceNode) != DeviceNodeDriversLoaded) {
	DbgTrace("Device node state is %d. Not adding device.\n",
		 IopDeviceNodeGetCurrentState(DeviceNode));
	ASYNC_RETURN(AsyncState, STATUS_INVALID_DEVICE_STATE);
    }

check:
    if (Locals.LowerFilterCount < DeviceNode->LowerFilterCount) {
	Locals.DriverName = DeviceNode->LowerFilterNames[Locals.LowerFilterCount++];
	goto call;
    }
    if (!Locals.FunctionDriverCalled) {
	Locals.DriverName = DeviceNode->DriverServiceName;
	Locals.FunctionDriverCalled = TRUE;
	goto call;
    }
    if (Locals.UpperFilterCount < DeviceNode->UpperFilterCount) {
	Locals.DriverName = DeviceNode->UpperFilterNames[Locals.UpperFilterCount++];
	goto call;
    }
    Status = STATUS_SUCCESS;
    goto end;

call:
    if (!Locals.DriverName) {
	assert(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto end;
    }
    PCSTR DriverProcessName = Locals.DriverName;
    if (DeviceNode->LoadIntoBusDriver) {
	assert(DeviceNode->Parent);
	DriverProcessName = IopGetDriverProcessName(DeviceNode);
    }
    assert(DriverProcessName);
    PIO_DRIVER_OBJECT DriverObject = IopGetDriverObject(DriverProcessName);
    IF_ERR_GOTO(end, Status, IopQueueAddDeviceRequest(Thread, DeviceNode,
						      DriverObject,
						      Locals.DriverName,
						      &Locals.PendingIrp));
    ObDereferenceObject(DriverObject);
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	goto end;
    }
    IopCleanupPendingIrp(Locals.PendingIrp);
    Locals.PendingIrp = NULL;
    if (DeviceNode->LoadIntoBusDriver ||
	Locals.DriverName == DeviceNode->DriverServiceName) {
	goto check;
    }

    /* For filter drivers, if the function driver is loaded in its own process,
     * we send another AddDevice request. */
    PIO_DRIVER_OBJECT FunctionDriver = IopGetDriverObject(DeviceNode->DriverServiceName);
    IF_ERR_GOTO(end, Status, IopQueueAddDeviceRequest(Thread, DeviceNode,
						      FunctionDriver,
						      Locals.DriverName,
						      &Locals.PendingIrp));
    ObDereferenceObject(FunctionDriver);
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	goto end;
    }
    IopCleanupPendingIrp(Locals.PendingIrp);
    Locals.PendingIrp = NULL;
    goto check;

end:
    if (DeviceNode == IopRootDeviceNode && NT_SUCCESS(Status)) {
	/* We need to manually set the PDO of the root device node */
	PIO_DEVICE_OBJECT RootEnumerator = NULL;
	IF_ERR_GOTO(out, Status,
		    ObReferenceObjectByName(PNP_ROOT_ENUMERATOR, OBJECT_TYPE_DEVICE,
					    NULL, FALSE, (POBJECT *)&RootEnumerator));
	assert(RootEnumerator != NULL);
	IopSetDeviceNode(RootEnumerator, IopRootDeviceNode);
    }
out:
    if (NT_SUCCESS(Status)) {
	IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeDevicesAdded);
    } else {
	IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeAddDeviceFailed);
	DeviceNode->ErrorStatus = Status;
    }
    if (Locals.PendingIrp != NULL) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    ASYNC_END(AsyncState, Status);
}

static NTSTATUS IopQueueQueryResourceRequirementsRequest(IN PTHREAD Thread,
							 IN PIO_DEVICE_OBJECT ChildPhyDev,
							 OUT PPENDING_IRP *PendingIrp)
{
    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_PNP,
	.MinorFunction = IRP_MN_QUERY_RESOURCE_REQUIREMENTS,
	.Device.Object = ChildPhyDev
    };
    return IopCallDriver(Thread, &Irp, PendingIrp);
}

static NTSTATUS IopQueueFilterResourceRequirementsRequest(IN PTHREAD Thread,
							  IN PIO_DEVICE_OBJECT DevObj,
							  IN PIO_RESOURCE_REQUIREMENTS_LIST Res,
							  OUT PPENDING_IRP *PendingIrp)
{
    ULONG DataSize = Res ? Res->ListSize : 0;
    PIO_REQUEST_PARAMETERS Irp = ExAllocatePoolWithTag(sizeof(IO_REQUEST_PARAMETERS) + DataSize,
						       NTOS_IO_TAG);
    if (!Irp) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    Irp->DataSize = DataSize;
    Irp->MajorFunction = IRP_MJ_PNP;
    Irp->MinorFunction = IRP_MN_FILTER_RESOURCE_REQUIREMENTS;
    Irp->Device.Object = DevObj;
    Irp->FilterResourceRequirements.ListSize = DataSize;
    if (Res) {
	memcpy(Irp->FilterResourceRequirements.Data, Res, DataSize);
    }
    NTSTATUS Status = IopCallDriver(Thread, Irp, PendingIrp);
    ExFreePoolWithTag(Irp, NTOS_IO_TAG);
    return Status;
}

static inline ULONG IopGetPartialResourceCount(IN PIO_RESOURCE_DESCRIPTOR List,
					       ULONG ListLength)
{
    ULONG Count = 0;
    for (ULONG i = 0; i < ListLength; i++) {
	if (List[i].Option == 0) {
	    Count++;
	} else if (List[i].Option == IO_RESOURCE_PREFERRED) {
	    Count++;
	    /* Skip all of the following descriptors marked as alternative resources */
	    while (i < ListLength) {
		if (List[i+1].Option & IO_RESOURCE_ALTERNATIVE) {
		    i++;
		} else {
		    break;
		}
	    }
	} else {
	    /* The client drivers should send the alternative descriptors after the
	     * preferred descriptor, so we assert if it did not maintain this order. */
	    assert(FALSE);
	}
    }
    return Count;
}

FORCEINLINE NTSTATUS IopAllocateResource(IN PRTL_RANGE_LIST RangeList,
					 IN PIO_RESOURCE_DESCRIPTOR Desc,
					 IN PDEVICE_NODE DevNode,
					 IN ULONGLONG Minimum,
					 IN ULONGLONG Maximum,
					 IN ULONG Length,
					 IN ULONG Alignment,
					 OUT PULONGLONG Start)
{
    assert(DevNode);
    BOOLEAN Shared = Desc->ShareDisposition == CmResourceShareShared;
    NTSTATUS Status = RtlFindRange(RangeList, Minimum, Maximum, Length,
				   Alignment ? Alignment : 1,
				   Shared ? RTL_RANGE_SHARED : 0, 0, NULL, NULL, Start);
    if (NT_SUCCESS(Status)) {
	Status = RtlAddRange(RangeList, *Start, *Start + Length - 1, 0,
			     Shared ? RTL_RANGE_LIST_ADD_SHARED : 0, NULL, DevNode);
	assert(NT_SUCCESS(Status));
	return Status;
    }
    /* TODO: Handle CmResourceShareDriverExclusive */
    if (Desc->ShareDisposition == CmResourceShareBusShared && Minimum &&
	(Desc->Type == CmResourceTypePort || Desc->Type == CmResourceTypeMemory)) {
	/* If the parent bus has been assigned this resource, also allow the child PDO
	 * to have it. */
	if (!DevNode->Parent || !DevNode->Parent->RawResources ||
	    !DevNode->Parent->TranslatedResources) {
	    return STATUS_CONFLICTING_ADDRESSES;
	}
	PCM_FULL_RESOURCE_DESCRIPTOR FullDesc = DevNode->Parent->RawResources->List;
	for (ULONG i = 0; i < DevNode->Parent->RawResources->Count; i++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Partial =
		FullDesc->PartialResourceList.PartialDescriptors;
	    for (ULONG j = 0; j < FullDesc->PartialResourceList.Count; j++) {
		ULONGLONG RangeStart = Partial->Generic.Start.QuadPart;
		ULONG RangeLength = Partial->Generic.Length;
		ULONGLONG RangeEnd = RangeStart + RangeLength;
		if (Partial->Type == Desc->Type && Minimum >= RangeStart &&
		    Maximum + 1 <= RangeEnd && Length <= RangeLength) {
		    *Start = Minimum;
		    return STATUS_SUCCESS;
		}
	    }
	    FullDesc = CmGetNextResourceDescriptor(FullDesc);
	}
    }
    return STATUS_CONFLICTING_ADDRESSES;
}

/*
 * Assign the IO resource given the preferred or alternative resource descriptor(s).
 */
static NTSTATUS IopAssignResource(IN PIO_RESOURCE_DESCRIPTOR Desc,
				  IN PDEVICE_NODE DevNode,
				  OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw,
				  OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR Translated)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONGLONG Start = 0;
    switch (Desc->Type) {
    case CmResourceTypeNull:
	/* Do nothing */
	break;

    case CmResourceTypePort:
	/* Assign the first available port */
	Status = IopAllocateResource(&IopPortRangesInUse, Desc, DevNode,
				     Desc->Port.MinimumAddress.QuadPart,
				     Desc->Port.MaximumAddress.QuadPart,
				     Desc->Port.Length,
				     Desc->Port.Alignment,
				     &Start);
	if (NT_SUCCESS(Status)) {
	    Raw->Port.Start.QuadPart = Translated->Port.Start.QuadPart = Start;
	    Raw->Port.Length = Translated->Port.Length = Desc->Port.Length;
	}
	break;

    case CmResourceTypeInterrupt:
	/* Ask the HAL to give us a free IRQ pin. Note this corresponds to the raw
	 * IO resource. */
	Status = STATUS_INSUFFICIENT_RESOURCES;

	/* Check if the device wants message interrupts and assign resources accordingly */
	if (Desc->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
	    LONG MsgCount = Desc->Interrupt.MaximumVector - Desc->Interrupt.MinimumVector + 1;
	    if (MsgCount <= 0 || MsgCount > USHORT_MAX) {
		assert(FALSE);
		Status = STATUS_INVALID_PARAMETER;
		break;
	    }
	    Status = IopAllocateResource(&IopInterruptVectorsInUse, Desc, DevNode,
					 0, ULONG_MAX, MsgCount, 1, &Start);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }
	    ULONG_PTR MessageAddress = HalComputeInterruptMessageAddress(0);
	    ULONG MessageData = HalComputeInterruptMessageData(Start);
	    Raw->MessageInterrupt.Raw.MessageCount = MsgCount;
	    Raw->MessageInterrupt.Raw.MessageData = MessageData;
	    Raw->MessageInterrupt.Raw.MessageAddress = MessageAddress;
	    Translated->MessageInterrupt.Translated.Level =
		Translated->MessageInterrupt.Translated.Vector = Start;
	    /* TODO: Implement interrupt affinity policy */
	    Translated->MessageInterrupt.Translated.Affinity = (KAFFINITY)-1;
	    Status = STATUS_SUCCESS;
	    break;
	}

	/* Assign regular IRQ lines */
	for (ULONG i = Desc->Interrupt.MinimumVector; i <= Desc->Interrupt.MaximumVector; i++) {
	    if (!NT_SUCCESS(HalAllocateIrq(i))) {
		continue;
	    }
	    /* Assign the first available CPU interrupt vector, which is the translated
	     * interrupt resource. */
	    Status = IopAllocateResource(&IopInterruptVectorsInUse, Desc, DevNode,
					 0, ULONG_MAX, 1, 1, &Start);
	    if (NT_SUCCESS(Status)) {
		Raw->Interrupt.Level = Raw->Interrupt.Vector = i;
		Translated->Interrupt.Level = Translated->Interrupt.Vector = Start;
		Raw->Interrupt.Affinity = Translated->Interrupt.Affinity =
		    Desc->Interrupt.TargetedProcessors;
	    } else {
		HalDeallocateIrq(i);
	    }
	    break;
	}
	break;

    case CmResourceTypeDma:
	/* Assign the first available DMA channel */
	Status = IopAllocateResource(&IopDmaChannelsInUse, Desc, DevNode,
				     Desc->Dma.MinimumChannel,
				     Desc->Dma.MaximumChannel,
				     1, 1, &Start);
	if (NT_SUCCESS(Status)) {
	    Raw->Dma.Channel = Translated->Dma.Channel = Start;
	    Raw->Dma.Port = Translated->Dma.Port = 0;
	}
	break;

    case CmResourceTypeMemory:
	/* Assign the first available memory-mapped IO region */
	Status = IopAllocateResource(&IopMemoryRangesInUse, Desc, DevNode,
				     Desc->Memory.MinimumAddress.QuadPart,
				     Desc->Memory.MaximumAddress.QuadPart,
				     Desc->Memory.Length,
				     Desc->Memory.Alignment, &Start);
	if (NT_SUCCESS(Status)) {
	    Raw->Memory.Start.QuadPart = Translated->Memory.Start.QuadPart = Start;
	    Raw->Memory.Length = Translated->Memory.Length = Desc->Memory.Length;
	}
	break;

    case CmResourceTypeBusNumber:
	/* Assign the first available bus number */
	Status = IopAllocateResource(&IopBusNumbersInUse, Desc, DevNode,
				     Desc->BusNumber.MinBusNumber,
				     Desc->BusNumber.MaxBusNumber,
				     Desc->BusNumber.Length,
				     1, &Start);
	if (NT_SUCCESS(Status)) {
	    Raw->BusNumber.Start = Translated->BusNumber.Start = Start;
	    Raw->BusNumber.Length = Translated->BusNumber.Length = Desc->BusNumber.Length;
	}
	break;

    case CmResourceTypeDevicePrivate:
	/* Pass the device private verbatim */
	RtlCopyMemory(&Raw->DevicePrivate, &Desc->DevicePrivate,
		      sizeof(Desc->DevicePrivate));
	RtlCopyMemory(&Translated->DevicePrivate, &Desc->DevicePrivate,
		      sizeof(Desc->DevicePrivate));
	break;

    default:
	assert(FALSE);
	Status = STATUS_INVALID_PARAMETER;
    }

    if (NT_SUCCESS(Status)) {
	Raw->Type = Translated->Type = Desc->Type;
	Raw->ShareDisposition = Raw->ShareDisposition = Desc->ShareDisposition;
	Raw->Flags = Translated->Flags = Desc->Flags;
	return STATUS_SUCCESS;
    } else {
	return STATUS_CONFLICTING_ADDRESSES;
    }
}

/*
 * Assign resources for the entire IO_RESOURCE_LIST.
 */
static NTSTATUS IopAssignResourcesForList(IN PDEVICE_NODE DeviceNode,
					  IN PIO_RESOURCE_REQUIREMENTS_LIST Header,
					  IN OUT PIO_RESOURCE_LIST *pResList)
{
    assert(pResList);
    PIO_RESOURCE_LIST ResList = *pResList;
    assert(ResList);
    assert(ResList->Count);
    *pResList = (PVOID)&ResList->Descriptors[ResList->Count];
    /* Allocate the CM_RESOURCE_LIST. Note since the resource requirements list
     * can have both preferred resources and alternative resources, the resource
     * count in the CM_RESOURCE_LIST may be less than the number of IO requirement
     * descriptors supplied by the bus driver. */
    ULONG PartialDescCount = IopGetPartialResourceCount(ResList->Descriptors,
							ResList->Count);
    ULONG Size = sizeof(CM_RESOURCE_LIST) + sizeof(CM_FULL_RESOURCE_DESCRIPTOR) +
	PartialDescCount * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
    assert(!DeviceNode->RawResources);
    DeviceNode->RawResources = (PCM_RESOURCE_LIST)ExAllocatePoolWithTag(Size, NTOS_IO_TAG);
    if (DeviceNode->RawResources == NULL) {
	return STATUS_NO_MEMORY;
    }
    DeviceNode->TranslatedResources = (PCM_RESOURCE_LIST)ExAllocatePoolWithTag(Size,
									       NTOS_IO_TAG);
    if (DeviceNode->TranslatedResources == NULL) {
	ExFreePoolWithTag(DeviceNode->RawResources, NTOS_IO_TAG);
	DeviceNode->RawResources = NULL;
	return STATUS_NO_MEMORY;
    }
    DeviceNode->RawResources->Count = 1;
    DeviceNode->RawResources->List[0].InterfaceType = Header->InterfaceType;
    DeviceNode->RawResources->List[0].BusNumber = Header->BusNumber;
    DeviceNode->RawResources->List[0].PartialResourceList.Version = ResList->Version;
    DeviceNode->RawResources->List[0].PartialResourceList.Revision = ResList->Revision;
    DeviceNode->RawResources->List[0].PartialResourceList.Count = PartialDescCount;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw =
	DeviceNode->RawResources->List[0].PartialResourceList.PartialDescriptors;
    DeviceNode->TranslatedResources->Count = 1;
    DeviceNode->TranslatedResources->List[0].InterfaceType = Header->InterfaceType;
    DeviceNode->TranslatedResources->List[0].BusNumber = Header->BusNumber;
    DeviceNode->TranslatedResources->List[0].PartialResourceList.Version = ResList->Version;
    DeviceNode->TranslatedResources->List[0].PartialResourceList.Revision = ResList->Revision;
    DeviceNode->TranslatedResources->List[0].PartialResourceList.Count = PartialDescCount;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR Translated =
	DeviceNode->TranslatedResources->List[0].PartialResourceList.PartialDescriptors;
    BOOLEAN Failed = FALSE;
    for (ULONG i = 0; i < ResList->Count; i++) {
	PIO_RESOURCE_DESCRIPTOR Desc = &ResList->Descriptors[i];
	if (Failed) {
	    /* If previous resource assignment failed, check if the bus driver has
	     * supplied alternative IO resources, and try satisfying them. */
	    if (Desc->Option & IO_RESOURCE_ALTERNATIVE) {
		goto assign;
	    } else {
		break;
	    }
	} else {
	    while ((Desc->Option & IO_RESOURCE_ALTERNATIVE) && (i < ResList->Count)) {
		DbgTrace("Skipping alternative descriptor %p (idx %d)\n", Desc, i);
		IoDbgPrintResourceDescriptor(Desc);
		Desc++;
		++i;
	    }
	    assert(i <= ResList->Count);
	    if (i >= ResList->Count) {
		return STATUS_INTERNAL_ERROR;
	    }
	}
    assign:
	Failed = !NT_SUCCESS(IopAssignResource(Desc, DeviceNode, Raw, Translated));
	if (Failed) {
	    DbgTrace("Resource assignment failed for descriptor %d\n", i);
	} else {
	    Raw++;
	    Translated++;
	}
    }
    if (Failed) {
	IopFreePool(DeviceNode->RawResources);
	DeviceNode->RawResources = NULL;
	IopFreePool(DeviceNode->TranslatedResources);
	DeviceNode->TranslatedResources = NULL;
	return STATUS_CONFLICTING_ADDRESSES;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS IopDeviceNodeAssignResources(IN ASYNC_STATE AsyncState,
					     IN PTHREAD Thread,
					     IN PDEVICE_NODE DeviceNode)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PPENDING_IRP QueryResPendingIrp;
	    PPENDING_IRP FilterResPendingIrp;
	    PIO_RESOURCE_REQUIREMENTS_LIST Res;
	});
    Locals.QueryResPendingIrp = NULL;
    Locals.FilterResPendingIrp = NULL;
    Locals.Res = NULL;

    if (IopDeviceNodeGetCurrentState(DeviceNode) != DeviceNodeDevicesAdded) {
	DbgTrace("Device node state is %d. Not assigning resources.\n",
		 IopDeviceNodeGetCurrentState(DeviceNode));
	ASYNC_RETURN(AsyncState, STATUS_INVALID_DEVICE_STATE);
    }

    /* If we are assigning resources for the root PnP enumerator, do not send the
     * QUERY-RESOURCE-REQUIREMENTS request (because it's supposed to be sent to
     * the device node's parent bus driver, and root PnP enumerator has no parent).
     * Instead, manually construct a resource requirement list with one memory range
     * resource for the ACPI XSDT. */
    if (DeviceNode == IopRootDeviceNode) {
	ULONG Length = 0;
	ULONG64 Address = HalAcpiGetRsdt(&Length);
	if (!Address) {
	    Status = STATUS_SUCCESS;
	    goto filter;
	}
	assert(Length);
	ULONG ListSize = sizeof(IO_RESOURCE_REQUIREMENTS_LIST) + sizeof(IO_RESOURCE_LIST) +
	    sizeof(IO_RESOURCE_DESCRIPTOR);
	Locals.Res = ExAllocatePoolWithTag(ListSize, NTOS_IO_TAG);
	if (!Locals.Res) {
	    Status = STATUS_NO_MEMORY;
	    goto out;
	}
	Locals.Res->ListSize = ListSize;
	Locals.Res->InterfaceType = Internal;
	Locals.Res->AlternativeLists = 1;
	Locals.Res->List[0].Count = 1;
	Locals.Res->List[0].Version = 1;
	Locals.Res->List[0].Revision = 1;
	Locals.Res->List[0].Descriptors[0].Type = CmResourceTypeMemory;
	Locals.Res->List[0].Descriptors[0].ShareDisposition = CmResourceShareDeviceExclusive;
	Locals.Res->List[0].Descriptors[0].Memory.Length = Length;
	Locals.Res->List[0].Descriptors[0].Memory.Alignment = 1;
	Locals.Res->List[0].Descriptors[0].Memory.MinimumAddress.QuadPart = Address;
	Locals.Res->List[0].Descriptors[0].Memory.MaximumAddress.QuadPart = Address+Length-1;
	goto filter;
    }

    IF_ERR_GOTO(out, Status,
		IopQueueQueryResourceRequirementsRequest(Thread, DeviceNode->PhyDevObj,
							 &Locals.QueryResPendingIrp));
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.QueryResPendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Status = Locals.QueryResPendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Failed to query device resource requirements for %s\\%s. Status = 0x%x\n",
		 DeviceNode->DeviceId, DeviceNode->InstanceId,
		 Status);
	goto out;
    }

    Locals.Res = Locals.QueryResPendingIrp->IoResponseData;
    if (Locals.Res == NULL) {
	Status = STATUS_SUCCESS;
	goto filter;
    }
    if (Locals.Res->ListSize <= MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE ||
	Locals.Res->ListSize != Locals.QueryResPendingIrp->IoResponseDataSize) {
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }
    Locals.QueryResPendingIrp->IoResponseData = NULL;

filter:
    /* Queue a FILTER-RESOURCE-REQUIREMENTS request to the function driver so it can
     * modify the resource requirements supplied by the bus driver, if needed. */
    IF_ERR_GOTO(out, Status,
		IopQueueFilterResourceRequirementsRequest(Thread,
							  IopGetTopDevice(DeviceNode->PhyDevObj),
							  Locals.Res,
							  &Locals.FilterResPendingIrp));
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.FilterResPendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Status = Locals.FilterResPendingIrp->IoResponseStatus.Status;
    if (NT_SUCCESS(Status) && Locals.FilterResPendingIrp->IoResponseData) {
	PIO_RESOURCE_REQUIREMENTS_LIST NewList = Locals.FilterResPendingIrp->IoResponseData;
	if (NewList->ListSize > MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE &&
	    NewList->ListSize == Locals.FilterResPendingIrp->IoResponseDataSize) {
	    IopFreePool(Locals.Res);
	    Locals.Res = NewList;
	    Locals.FilterResPendingIrp->IoResponseData = NULL;
	}
    }

    /* Free the resource lists in case a previous attempt to assign resources failed. */
    if (DeviceNode->RawResources != NULL) {
	IopFreePool(DeviceNode->RawResources);
	DeviceNode->RawResources = NULL;
    }
    if (DeviceNode->TranslatedResources != NULL) {
	IopFreePool(DeviceNode->TranslatedResources);
	DeviceNode->TranslatedResources = NULL;
    }

    if (!Locals.Res) {
	DbgTrace("Device node %s\\%s does not require any IO resource\n",
		 DeviceNode->DeviceId, DeviceNode->InstanceId);
	Status = STATUS_SUCCESS;
	goto out;
    }

    DbgTrace("Trying to satisfy the following resource requirements for "
	     "device node %s\\%s:\n", DeviceNode->DeviceId, DeviceNode->InstanceId);
    IoDbgPrintResouceRequirementsList(Locals.Res);
    assert(Locals.Res->AlternativeLists);

    /* For each alternative list, see if we can satisfy its resource requirements.
     * Each list represents a set of resources that must be satisfied simultaneously,
     * and we need at least one list satisfied for the resource arbitration to succeed. */
    PIO_RESOURCE_LIST List = Locals.Res->List;
    for (ULONG i = 0; i < Locals.Res->AlternativeLists; i++) {
	if (!List->Count) {
	    assert(FALSE);
	    Status = STATUS_INVALID_PARAMETER;
	    goto out;
	}
	DbgTrace("Trying to assign resources for list %d\n", i);
	Status = IopAssignResourcesForList(DeviceNode, Locals.Res, &List);
	if (NT_SUCCESS(Status)) {
	    DbgTrace("Successfully assigned resources for list %d\n", i);
	    DeviceNode->BusInformation.LegacyBusType = Locals.Res->InterfaceType;
	    DeviceNode->BusInformation.BusNumber = Locals.Res->BusNumber;
	    DeviceNode->SlotNumber = Locals.Res->SlotNumber;
	    break;
	} else {
	    DbgTrace("Failed to assign resources for list %d, error 0x%x\n", i, Status);
	}
    }

out:
    if (Locals.Res) {
	IopFreePool(Locals.Res);
    }
    if (Locals.QueryResPendingIrp) {
	IopCleanupPendingIrp(Locals.QueryResPendingIrp);
    }
    if (Locals.FilterResPendingIrp) {
	IopCleanupPendingIrp(Locals.FilterResPendingIrp);
    }
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Failed to assign resources for device node %s\\%s. Status = 0x%x\n",
		 DeviceNode->DeviceId, DeviceNode->InstanceId, Status);
	IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeResourcesAssignmentFailed);
	DeviceNode->ErrorStatus = Status;
    } else {
	IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeResourcesAssigned);
    }
    ASYNC_END(AsyncState, Status);
}

static NTSTATUS IopQueueStartDeviceRequest(IN PTHREAD Thread,
					   IN PDEVICE_NODE DeviceNode,
					   OUT PPENDING_IRP *PendingIrp)
{
    PCM_RESOURCE_LIST Raw = DeviceNode->RawResources;
    PCM_RESOURCE_LIST Translated = DeviceNode->TranslatedResources;
    ULONG RawSize = CmGetResourceListSize(Raw);
    ULONG TranslatedSize = CmGetResourceListSize(Translated);
    assert(RawSize == TranslatedSize);
    ULONG DataSize = RawSize + TranslatedSize;
    PIO_REQUEST_PARAMETERS Irp = ExAllocatePoolWithTag(sizeof(IO_REQUEST_PARAMETERS) + DataSize,
						       NTOS_IO_TAG);
    if (!Irp) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    Irp->DataSize = DataSize;
    Irp->MajorFunction = IRP_MJ_PNP;
    Irp->MinorFunction = IRP_MN_START_DEVICE;
    Irp->Device.Object = IopGetTopDevice(DeviceNode->PhyDevObj);
    Irp->StartDevice.ResourceListSize = RawSize;
    Irp->StartDevice.TranslatedListSize = TranslatedSize;
    if (RawSize) {
	memcpy(Irp->StartDevice.Data, Raw, RawSize);
	memcpy(&Irp->StartDevice.Data[RawSize], Translated, TranslatedSize);
    }
    DbgTrace("Starting device node %s\\%s with the following raw resources\n",
	     DeviceNode->DeviceId, DeviceNode->InstanceId);
    CmDbgPrintResourceList(Raw);
    DbgTrace("and the following translated resources\n");
    CmDbgPrintResourceList(Translated);
    NTSTATUS Status = IopCallDriver(Thread, Irp, PendingIrp);
    ExFreePoolWithTag(Irp, NTOS_IO_TAG);
    return Status;
}

static NTSTATUS IopDeviceNodeStartDevice(IN ASYNC_STATE AsyncState,
					 IN PTHREAD Thread,
					 IN PDEVICE_NODE DeviceNode)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PPENDING_IRP PendingIrp;
	});
    Locals.PendingIrp = NULL;

    if (IopDeviceNodeGetCurrentState(DeviceNode) != DeviceNodeResourcesAssigned) {
	DbgTrace("Device node state is %d. Not starting device.\n",
		 IopDeviceNodeGetCurrentState(DeviceNode));
	ASYNC_RETURN(AsyncState, STATUS_INVALID_DEVICE_STATE);
    }

    IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeStartPending);

    IF_ERR_GOTO(end, Status,
		IopQueueStartDeviceRequest(Thread, DeviceNode, &Locals.PendingIrp));
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Status = Locals.PendingIrp->IoResponseStatus.Status;

end:
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Failed to start device node %s\\%s. Status = 0x%x\n",
		 DeviceNode->DeviceId, DeviceNode->InstanceId, Status);
	IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeStartFailed);
	DeviceNode->ErrorStatus = Status;
    } else {
	IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeStarted);
    }
    ASYNC_END(AsyncState, Status);
}

/*
 * Send the query relations IRP to the device node and create child device nodes.
 *
 * The device node must be in the DeviceNodeStarted state. The device node must
 * not have any children.
 */
static NTSTATUS IopDeviceNodeEnumerate(IN ASYNC_STATE AsyncState,
				       IN PTHREAD Thread,
				       IN PDEVICE_NODE DevNode)
{
    assert(DevNode != NULL);
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PPENDING_IRP PendingIrp;
	    PPENDING_IRP *PendingIrps;
	    ULONG DeviceCount;
	});
    Locals.PendingIrp = NULL;
    Locals.PendingIrps = NULL;
    Locals.DeviceCount = 0;

    if (IopDeviceNodeGetCurrentState(DevNode) != DeviceNodeStarted) {
	DbgTrace("Device node state is %d. Not enumerating.\n",
		 IopDeviceNodeGetCurrentState(DevNode));
	ASYNC_RETURN(AsyncState, STATUS_INVALID_DEVICE_STATE);
    }

    /* TODO: We need to figure out re-enumeration. */
    if (!IsListEmpty(&DevNode->ChildrenList)) {
	assert(FALSE);
	ASYNC_RETURN(AsyncState, STATUS_NOT_IMPLEMENTED);
    }

    IopDeviceNodeSetCurrentState(DevNode, DeviceNodeEnumeratePending);

    /* Ask the device node about its child devices */
    IF_ERR_GOTO(out, Status,
		IopQueueQueryDeviceRelationsRequest(Thread, IopGetTopDevice(DevNode->PhyDevObj),
						    BusRelations, &Locals.PendingIrp));
    AWAIT(KeWaitForSingleObject, AsyncState, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);

    /* Get the PDO device handles from the response data */
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.DeviceCount = Locals.PendingIrp->IoResponseStatus.Information;
    PGLOBAL_HANDLE DeviceHandles = (PGLOBAL_HANDLE)Locals.PendingIrp->IoResponseData;
    /* In the case where server has run out of memory, IoResponseData will be NULL but
     * IoResponseDataSize is not zero. Otherwise, it means that the device node does not
     * have any child devices. */
    if (DeviceHandles == NULL) {
	Status = Locals.PendingIrp->IoResponseDataSize != 0 ? STATUS_NO_MEMORY : STATUS_SUCCESS;
	goto out;
    }

    /* Note that we can't free the PendingIrp here because DeviceHandles refers to it.
     * PendingIrp will be freed at the end of the routine. Now allocate the PPENDING_IRP
     * array so we can query the child devices of their IDs. Note that we need two pointers
     * for each child device because we need to send two IRPs each. */
    Locals.PendingIrps = ExAllocatePoolWithTag(sizeof(PPENDING_IRP) * Locals.DeviceCount * 5,
					       NTOS_IO_TAG);
    if (Locals.PendingIrps == NULL) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    /* Build the child device nodes and send the QUERY_ID requests to the child devices. */
    for (ULONG i = 0; i < Locals.DeviceCount; i++) {
	PIO_DRIVER_OBJECT DriverObject = IopGetTopDevice(DevNode->PhyDevObj)->DriverObject;
	assert(DriverObject != NULL);
	PIO_DEVICE_OBJECT ChildPhyDev = IopGetDeviceObject(DeviceHandles[i],
							   DriverObject);
	if (ChildPhyDev == NULL) {
	    DbgTrace("Invalid device handle %p received for driver object %p\n",
		     (PVOID)DeviceHandles[i], DriverObject);
	    Status = STATUS_NO_SUCH_DEVICE;
	    goto out;
	}
	PDEVICE_NODE ChildNode = NULL;
	IF_ERR_GOTO(out, Status, IopCreateDeviceNode(DevNode, &ChildNode));
	assert(ChildNode != NULL);
	IopSetDeviceNode(ChildPhyDev, ChildNode);
	IF_ERR_GOTO(out, Status,
		    IopQueueBusQueryIdRequest(Thread, ChildPhyDev, BusQueryDeviceID,
					      &Locals.PendingIrps[5*i]));
	IF_ERR_GOTO(out, Status,
		    IopQueueBusQueryIdRequest(Thread, ChildPhyDev, BusQueryInstanceID,
					      &Locals.PendingIrps[5*i+1]));
	IF_ERR_GOTO(out, Status,
		    IopQueueBusQueryIdRequest(Thread, ChildPhyDev, BusQueryHardwareIDs,
					      &Locals.PendingIrps[5*i+2]));
	IF_ERR_GOTO(out, Status,
		    IopQueueBusQueryIdRequest(Thread, ChildPhyDev, BusQueryCompatibleIDs,
					      &Locals.PendingIrps[5*i+3]));
	IF_ERR_GOTO(out, Status,
		    IopQueueBusQueryInformationRequest(Thread, ChildPhyDev,
						       &Locals.PendingIrps[5*i+4]));
    }
    AWAIT_EX(Status, IopWaitForMultipleIoCompletions, AsyncState, Locals, Thread,
	     FALSE, WaitAll, Locals.PendingIrps, Locals.DeviceCount * 5);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Set the device IDs of the child nodes. */
    for (ULONG i = 0; i < Locals.DeviceCount * 5; i++) {
	PPENDING_IRP PendingIrp = Locals.PendingIrps[i];
	assert(PendingIrp != NULL);
	assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	assert(PendingIrp->IoPacket->Request.MajorFunction == IRP_MJ_PNP);
	PIO_DEVICE_OBJECT DeviceObject = PendingIrp->IoPacket->Request.Device.Object;
	PDEVICE_NODE DeviceNode = IopGetDeviceNode(DeviceObject);
	if (PendingIrp->IoPacket->Request.MinorFunction == IRP_MN_QUERY_ID) {
	    BUS_QUERY_ID_TYPE IdType = PendingIrp->IoPacket->Request.QueryId.IdType;
	    assert(DeviceNode != NULL);
	    Status = IopDeviceNodeSetDeviceId(DeviceNode, PendingIrp->IoResponseData, IdType);
	    if (!NT_SUCCESS(Status) &&
		(IdType == BusQueryDeviceID || IdType == BusQueryInstanceID)) {
		goto out;
	    }
	} else {
	    assert(PendingIrp->IoPacket->Request.MinorFunction == IRP_MN_QUERY_BUS_INFORMATION);
	    assert(!PendingIrp->IoResponseData ||
		   PendingIrp->IoResponseDataSize == sizeof(PNP_BUS_INFORMATION));
	    if (PendingIrp->IoResponseData &&
		PendingIrp->IoResponseDataSize == sizeof(PNP_BUS_INFORMATION)) {
		memcpy(&DeviceNode->BusInformation, PendingIrp->IoResponseData,
		       sizeof(PNP_BUS_INFORMATION));
	    }
	}
    }

    /* All done! */
    Status = STATUS_SUCCESS;

out:
    if (NT_SUCCESS(Status)) {
	IopDeviceNodeSetCurrentState(DevNode, DeviceNodeEnumerateCompletion);
	LoopOverList(ChildDev, &DevNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	    IopDeviceNodeSetCurrentState(ChildDev, DeviceNodeInitialized);
	}
    } else {
	IopDeviceNodeSetCurrentState(DevNode, DeviceNodeEnumerateFailed);
	DevNode->ErrorStatus = Status;
	/* If any child devices were created during the enumeration, delete them. */
	LoopOverList(ChildDev, &DevNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	    IopFreeDeviceNode(ChildDev);
	}
    }
    if (Locals.PendingIrp != NULL) {
	IopCleanupPendingIrp(Locals.PendingIrp);
    }
    if (Locals.PendingIrps != NULL) {
	for (ULONG i = 0; i < Locals.DeviceCount * 5; i++) {
	    if (Locals.PendingIrps[i] != NULL) {
		IopCleanupPendingIrp(Locals.PendingIrps[i]);
	    }
	}
	IopFreePool(Locals.PendingIrps);
    }
    ASYNC_END(AsyncState, Status);
}

typedef BOOLEAN (*PDEVICE_NODE_VISITOR)(IN PDEVICE_NODE DeviceNode,
					IN PVOID Context);

static VOID IopDeviceNodeTraverseChildren(IN PDEVICE_NODE DeviceNode,
					  IN PDEVICE_NODE_VISITOR Visitor,
					  IN PVOID Context)
{
    LoopOverList(Child, &DeviceNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	if (!Visitor(Child, Context)) {
	    break;
	}
	IopDeviceNodeTraverseChildren(Child, Visitor, Context);
    }
}

typedef NTSTATUS (*PDEVICE_NODE_SYNC_VISITOR_EX)(IN ASYNC_STATE AsyncState,
						 IN PTHREAD Thread,
						 IN PDEVICE_NODE DeviceNode,
						 IN PVOID Context);

/*
 * Traverse the child device nodes of the given device node (but not the node
 * itself) and apply the visitor to it. If StopOnError is set to TRUE, the
 * traversal will stop if the visitor returned error at any point.
 *
 * If StopOnError is FALSE, the routine returns success regardless of whether
 * any error is encountered during the traversal. Otherwise error status is
 * returned if an error is encountered.
 */
static NTSTATUS IopDeviceNodeTraverseChildrenSyncEx(IN ASYNC_STATE AsyncState,
						    IN PTHREAD Thread,
						    IN PDEVICE_NODE DeviceNode,
						    IN PDEVICE_NODE_SYNC_VISITOR_EX Visitor,
						    IN PVOID Context,
						    IN BOOLEAN StopOnError)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PDEVICE_NODE ChildNode;
	});

    if (IsListEmpty(&DeviceNode->ChildrenList)) {
	Status = STATUS_SUCCESS;
	goto end;
    }
    Locals.ChildNode = CONTAINING_RECORD(DeviceNode->ChildrenList.Flink,
					 DEVICE_NODE, SiblingLink);
more:
    AWAIT_EX(Status, Visitor, AsyncState, Locals, Thread, Locals.ChildNode, Context);
    if (StopOnError && !NT_SUCCESS(Status)) {
	ASYNC_RETURN(AsyncState, Status);
    }
    if (Locals.ChildNode->SiblingLink.Flink != &DeviceNode->ChildrenList) {
	Locals.ChildNode = CONTAINING_RECORD(Locals.ChildNode->SiblingLink.Flink,
					     DEVICE_NODE, SiblingLink);
	goto more;
    }

end:
    ASYNC_END(AsyncState, StopOnError ? Status : STATUS_SUCCESS);
}

typedef NTSTATUS (*PDEVICE_NODE_SYNC_VISITOR)(IN ASYNC_STATE AsyncState,
					      IN PTHREAD Thread,
					      IN PDEVICE_NODE DeviceNode);

static NTSTATUS IopDeviceNodeSyncVisit(IN ASYNC_STATE AsyncState,
				       IN PTHREAD Thread,
				       IN PDEVICE_NODE DeviceNode,
				       IN PVOID Context)
{
    PDEVICE_NODE_SYNC_VISITOR Visitor = (PDEVICE_NODE_SYNC_VISITOR)Context;
    return Visitor(AsyncState, Thread, DeviceNode);
}

static NTSTATUS IopDeviceNodeTraverseChildrenSync(IN ASYNC_STATE AsyncState,
						  IN PTHREAD Thread,
						  IN PDEVICE_NODE DeviceNode,
						  IN PDEVICE_NODE_SYNC_VISITOR Visitor)
{
    return IopDeviceNodeTraverseChildrenSyncEx(AsyncState, Thread, DeviceNode,
					       IopDeviceNodeSyncVisit, Visitor, FALSE);
}

/*
 * Recursively enumerate the device tree and start devices. This will build the
 * entire device tree from the enumeration config in the registry.
 */
static NTSTATUS IopDeviceTreeEnumerate(IN ASYNC_STATE AsyncState,
				       IN PTHREAD Thread,
				       IN PDEVICE_NODE DeviceNode)
{
    assert(DeviceNode != NULL);
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState);

    /* We ignore the errors of the following function calls. This is ok since these
     * functions will not process the device node if it's not in the correct state. */
    AWAIT(IopDeviceNodeLoadDrivers, AsyncState, _, Thread, DeviceNode);
    AWAIT(IopDeviceNodeAddDevice, AsyncState, _, Thread, DeviceNode);
    AWAIT(IopDeviceNodeAssignResources, AsyncState, _, Thread, DeviceNode);
    AWAIT(IopDeviceNodeStartDevice, AsyncState, _, Thread, DeviceNode);

    /* If the device is not in the Started state, we can't enumerate it so exit. */
    if (IopDeviceNodeGetCurrentState(DeviceNode) != DeviceNodeStarted) {
	Status = STATUS_INVALID_DEVICE_STATE;
	goto out;
    }

    /* Now enumerate the device node. This will build child device nodes. */
    AWAIT_EX(Status, IopDeviceNodeEnumerate, AsyncState, _, Thread, DeviceNode);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* For each child node, recursively enumerate it. This will build the entire
     * device tree in a depth-first fashion. */
    AWAIT_EX(Status, IopDeviceNodeTraverseChildrenSync, AsyncState, _, Thread,
	     DeviceNode, IopDeviceTreeEnumerate);

out:
    ASYNC_END(AsyncState, Status);
}

typedef struct _IOP_FIND_DEVICE_INSTANCE_CONTEXT {
    OUT PDEVICE_NODE DeviceNode;
    IN PCSTR DeviceInstance;
} IOP_FIND_DEVICE_INSTANCE_CONTEXT, *PIOP_FIND_DEVICE_INSTANCE_CONTEXT;

static BOOLEAN IopFindDeviceInstanceVisitor(IN PDEVICE_NODE DeviceNode,
					    IN OUT PVOID Ctx)
{
    PIOP_FIND_DEVICE_INSTANCE_CONTEXT Context = Ctx;
    ULONG LastSeperator = ObLocateLastPathSeparator(Context->DeviceInstance);
    if (!LastSeperator) {
	/* Device instance is invalid. Return NULL. */
	Context->DeviceNode = NULL;
	return FALSE;
    }
    if (!_strnicmp(DeviceNode->DeviceId, Context->DeviceInstance, LastSeperator) &&
	!_stricmp(DeviceNode->InstanceId, Context->DeviceInstance + LastSeperator + 1)) {
        Context->DeviceNode = DeviceNode;
        /* Stop traversal */
        return FALSE;
    }
    /* Continue traversal */
    return TRUE;
}

static PDEVICE_NODE IopGetDeviceNodeFromDeviceInstance(IN PCSTR DeviceInstance)
{
    if (IopRootDeviceNode == NULL)
        return NULL;

    if (DeviceInstance == NULL || DeviceInstance[0] == '\0') {
	return IopRootDeviceNode;
    }

    IOP_FIND_DEVICE_INSTANCE_CONTEXT Context = {
	.DeviceInstance = DeviceInstance
    };
    if (!IopFindDeviceInstanceVisitor(IopRootDeviceNode, &Context)) {
	goto out;
    }

    /* Traverse the device tree to find the matching device node */
    IopDeviceNodeTraverseChildren(IopRootDeviceNode,
				  IopFindDeviceInstanceVisitor, &Context);
out:
    return Context.DeviceNode;
}

static NTSTATUS PiControlEnumerateDevice(IN ASYNC_STATE State,
					 IN PTHREAD Thread,
					 IN PDEVICE_NODE DevNode)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State, Locals, {
	});

    AWAIT_EX(Status, IopDeviceTreeEnumerate, State, Locals, Thread, DevNode);
    ASYNC_END(State, Status);
}

static NTSTATUS PiControlStartDevice(IN ASYNC_STATE State,
				     IN PTHREAD Thread,
				     IN PDEVICE_NODE DevNode)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PiControlResetDevice(IN ASYNC_STATE State,
				     IN PTHREAD Thread,
				     IN PDEVICE_NODE DevNode)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PiControlPerformDeviceAction(IN ASYNC_STATE State,
					     IN PTHREAD Thread,
					     IN PCSTR DeviceInstance,
					     IN PLUGPLAY_CONTROL_CLASS ControlClass)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State, Locals, {
	    PDEVICE_NODE DeviceNode;
	    BOOLEAN Deref;
	});

    assert(ControlClass == PlugPlayControlEnumerateDevice ||
           ControlClass == PlugPlayControlStartDevice ||
           ControlClass == PlugPlayControlResetDevice);

    Locals.DeviceNode = IopGetDeviceNodeFromDeviceInstance(DeviceInstance);
    if (!Locals.DeviceNode) {
        ASYNC_RETURN(State, STATUS_NO_SUCH_DEVICE);
    }
    /* Reference the PDO so the device node won't get deleted during the
     * device action below. Note for the root PnP device node the PDO may
     * be NULL if we are doing the very first PnP enumeration. */
    if (Locals.DeviceNode->PhyDevObj) {
	ObpReferenceObject(Locals.DeviceNode->PhyDevObj);
	Locals.Deref = TRUE;
    }

    if (ControlClass == PlugPlayControlEnumerateDevice) {
	goto enumerate;
    } else if (ControlClass == PlugPlayControlStartDevice) {
	goto start;
    } else {
	goto reset;
    }

enumerate:
    AWAIT_EX(Status, PiControlEnumerateDevice, State, Locals, Thread,
	     Locals.DeviceNode);
    goto out;

start:
    AWAIT_EX(Status, PiControlStartDevice, State, Locals, Thread,
	     Locals.DeviceNode);
    goto out;

reset:
    AWAIT_EX(Status, PiControlResetDevice, State, Locals, Thread,
	     Locals.DeviceNode);
    goto out;

out:
    if (Locals.Deref) {
	assert(Locals.DeviceNode);
	assert(Locals.DeviceNode->PhyDevObj);
	ObDereferenceObject(Locals.DeviceNode->PhyDevObj);
    }
    ASYNC_END(State, Status);
}

/*
 * Remove the current PnP event from the tail of the event queue
 * and signal IopPnpNotifyEvent if there is yet another event in the queue.
 */
static NTSTATUS IopRemovePlugPlayEvent(IN PPLUGPLAY_CONTROL_USER_RESPONSE_DATA ResponseData)
{
    /* Remove a pnp event entry from the tail of the queue */
    if (!IsListEmpty(&IopPnpEventQueueHead)) {
        IopFreePool(CONTAINING_RECORD(RemoveTailList(&IopPnpEventQueueHead),
				      PNP_EVENT_ENTRY, ListEntry));
    }

    /* Signal the next pnp event if there is one in the queue */
    if (!IsListEmpty(&IopPnpEventQueueHead)) {
        KeSetEvent(&IopPnpNotifyEvent);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PiControlQueryRemoveDevice(IN ASYNC_STATE State,
					   IN PTHREAD Thread,
					   IN PIO_PNP_CONTROL_QUERY_REMOVE_DATA Data)
{
    PDEVICE_NODE DeviceNode = IopGetDeviceNodeFromDeviceInstance(Data->DeviceInstance);
    if (!DeviceNode) {
        return STATUS_NO_SUCH_DEVICE;
    }

    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PiControlQueryIds(IN OUT PIO_PNP_CONTROL_QUERY_IDS_DATA Data,
				  IN PLUGPLAY_CONTROL_CLASS Class)
{
    PDEVICE_NODE DeviceNode = IopGetDeviceNodeFromDeviceInstance(Data->DeviceInstance);
    if (!DeviceNode) {
	return STATUS_NO_SUCH_DEVICE;
    }

    assert(Class == PlugPlayControlQueryHardwareIDs ||
	   Class == PlugPlayControlQueryCompatibleIDs);
    PCSTR String = DeviceNode->HardwareIds;
    ULONG BufferSize = DeviceNode->HardwareIdsLength;
    if (Class == PlugPlayControlQueryCompatibleIDs) {
	String = DeviceNode->CompatibleIds;
	BufferSize = DeviceNode->CompatibleIdsLength;
    }
    if (BufferSize > Data->BufferSize) {
	Data->BufferSize = BufferSize;
        return STATUS_BUFFER_TOO_SMALL;
    }
    Data->BufferSize = BufferSize;
    if (String) {
	RtlCopyMemory(Data->DeviceInstance + Data->DeviceInstanceLength,
		      String, BufferSize);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS IopGetRelatedDevice(IN OUT PIO_PNP_CONTROL_RELATED_DEVICE_DATA Data)
{
    PDEVICE_NODE DeviceNode = IopGetDeviceNodeFromDeviceInstance(Data->TargetDeviceInstance);
    if (!DeviceNode) {
	return STATUS_NO_SUCH_DEVICE;
    }

    PDEVICE_NODE RelatedDeviceNode = NULL;
    switch (Data->Relation) {
    case PNP_GET_PARENT_DEVICE:
	RelatedDeviceNode = DeviceNode->Parent;
	break;

    case PNP_GET_CHILD_DEVICE:
	if (!IsListEmpty(&DeviceNode->ChildrenList)) {
	    RelatedDeviceNode = CONTAINING_RECORD(DeviceNode->ChildrenList.Flink,
						  DEVICE_NODE, SiblingLink);
	}
	break;

    case PNP_GET_SIBLING_DEVICE:
	if (DeviceNode->Parent) {
	    PLIST_ENTRY Flink = DeviceNode->SiblingLink.Flink;
	    assert(Flink != &DeviceNode->SiblingLink);
	    assert(ListHasEntry(&DeviceNode->Parent->ChildrenList, &DeviceNode->SiblingLink));
	    if (Flink != &DeviceNode->Parent->ChildrenList) {
		RelatedDeviceNode = CONTAINING_RECORD(Flink, DEVICE_NODE, SiblingLink);
	    }
	    assert(RelatedDeviceNode != DeviceNode);
	}
	break;

    default:
	assert(FALSE);
    }

    if (!RelatedDeviceNode) {
	return STATUS_NO_SUCH_DEVICE;
    }

    ULONG BufferSize = strlen(RelatedDeviceNode->DeviceId) +
	strlen(RelatedDeviceNode->InstanceId) + 2;
    if (BufferSize > Data->RelatedDeviceInstanceLength) {
	Data->RelatedDeviceInstanceLength = BufferSize;
        return STATUS_BUFFER_TOO_SMALL;
    }
    Data->RelatedDeviceInstanceLength = BufferSize;

    /* TargetDeviceInstanceLength may be zero if the caller passed a NUL string. */
    assert(!Data->TargetDeviceInstanceLength ||
	   Data->TargetDeviceInstance[Data->TargetDeviceInstanceLength-1] == '\0');
#if DBG
    ULONG BytesWritten =
#endif
    snprintf(Data->TargetDeviceInstance + Data->TargetDeviceInstanceLength, BufferSize,
	     "%s\\%s", RelatedDeviceNode->DeviceId, RelatedDeviceNode->InstanceId);
    assert(BytesWritten + 1 == BufferSize);
    return STATUS_SUCCESS;
}

BOOLEAN IopIsInterruptVectorAssigned(IN PIO_DRIVER_OBJECT DriverObject,
				     IN ULONG Vector,
				     OUT PNP_BUS_INFORMATION *BusInfo,
				     OUT ULONG *SlotNumber,
				     OUT PCM_PARTIAL_RESOURCE_DESCRIPTOR *pRaw)
{
    BOOLEAN Available = FALSE;
    RtlIsRangeAvailable(&IopInterruptVectorsInUse, Vector, Vector,
			0, 0, NULL, NULL, &Available);
    if (Available) {
	DbgTrace("Vector %d not assigned\n", Vector);
	return FALSE;
    }
    /* Check the device objects created by the driver object and see if
     * one of them has been assigned the given interrupt resource. If none,
     * return FALSE. */
    LoopOverList(Device, &DriverObject->DeviceList, IO_DEVICE_OBJECT, DeviceLink) {
	PDEVICE_NODE DevNode = IopGetPhyDevObj(Device)->DeviceNode;
	if (!DevNode || !DevNode->RawResources || !DevNode->TranslatedResources) {
	    continue;
	}
	DbgTrace("Dev node %p raw res\n", DevNode);
	CmDbgPrintResourceList(DevNode->RawResources);
	DbgTrace("Dev node %p trans res\n", DevNode);
	CmDbgPrintResourceList(DevNode->TranslatedResources);
	PCM_FULL_RESOURCE_DESCRIPTOR RawDesc = DevNode->RawResources->List;
	PCM_FULL_RESOURCE_DESCRIPTOR TranslatedDesc =
	    DevNode->TranslatedResources->List;
	for (ULONG i = 0; i < DevNode->RawResources->Count; i++) {
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw =
		RawDesc->PartialResourceList.PartialDescriptors;
	    PCM_PARTIAL_RESOURCE_DESCRIPTOR Translated =
		TranslatedDesc->PartialResourceList.PartialDescriptors;
	    for (ULONG j = 0; j < TranslatedDesc->PartialResourceList.Count; j++) {
		if (Translated->Type != CmResourceTypeInterrupt) {
		    goto next;
		}
		BOOLEAN Found = FALSE;
		if (Raw->Flags & CM_RESOURCE_INTERRUPT_MESSAGE) {
		    ULONG VectorStart = Translated->MessageInterrupt.Translated.Vector;
		    ULONG VectorCount = Raw->MessageInterrupt.Raw.MessageCount;
		    Found = (Vector >= VectorStart) && (Vector < (VectorStart + VectorCount));
		} else {
		    Found = Translated->Interrupt.Vector == Vector;
		}
		if (Found) {
		    *BusInfo = DevNode->BusInformation;
		    *SlotNumber = DevNode->SlotNumber;
		    *pRaw = Raw;
		    return TRUE;
		}
	    next:
		Raw = CmGetNextPartialDescriptor(Raw);
		Translated = CmGetNextPartialDescriptor(Translated);
	    }
	    RawDesc = CmGetNextResourceDescriptor(RawDesc);
	    TranslatedDesc = CmGetNextResourceDescriptor(TranslatedDesc);
	}
    }
    return FALSE;
}

NTSTATUS IoMaskInterruptVector(IN ULONG Vector)
{
    BOOLEAN Available = FALSE;
    RtlIsRangeAvailable(&IopInterruptVectorsInUse, Vector, Vector,
			0, 0, NULL, NULL, &Available);
    if (Available) {
	return RtlAddRange(&IopInterruptVectorsInUse, Vector, Vector, 1, 0, NULL, NULL);
    }
    return STATUS_SUCCESS;
}

NTSTATUS IoAllocateInterruptVector(OUT ULONG *pVector)
{
    ULONGLONG Vector;
    NTSTATUS Status = RtlFindRange(&IopInterruptVectorsInUse, 0, ULONG_MAX - 1, 1,
				   1, 0, 0, NULL, NULL, &Vector);
    if (NT_SUCCESS(Status)) {
	Status = RtlAddRange(&IopInterruptVectorsInUse, Vector, Vector, 1, 0, NULL, NULL);
	if (NT_SUCCESS(Status)) {
	    *pVector = Vector;
	}
	return Status;
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS IopInitPnpManager()
{
    /* We can only be called once (during system startup). */
    assert(!IopRootDeviceNode);

    /* Initialize the RTL_RANGE_LISTs needed for resource arbitration. */
    RtlInitializeRangeList(&IopDmaChannelsInUse);
    RtlInitializeRangeList(&IopPortRangesInUse);
    RtlInitializeRangeList(&IopMemoryRangesInUse);
    RtlInitializeRangeList(&IopInterruptVectorsInUse);
    RtlInitializeRangeList(&IopBusNumbersInUse);

    /* Ask HAL to mask the unusable IRQLs so we won't assign it to devices later. */
    RET_ERR(HalMaskUnusableInterrupts());

    /* Initialize the PnP event notification system and the event queue. */
    InitializeListHead(&IopPnpEventQueueHead);
    InitializeListHead(&IopHardwareProfileChangeList);
    InitializeListHead(&IopDeviceInterfaceChangeList);
    KeInitializeEvent(&IopPnpNotifyEvent, SynchronizationEvent);

    /* Create the root device node. This is the device node for the root PnP enumerator. */
    RET_ERR(IopCreateDeviceNode(NULL, &IopRootDeviceNode));
    assert(IopRootDeviceNode != NULL);

    /* Set the device and instance ID of the root enumerator. */
    RET_ERR(IopDeviceNodeSetDeviceId(IopRootDeviceNode, "HTREE\\ROOT", BusQueryDeviceID));
    RET_ERR(IopDeviceNodeSetDeviceId(IopRootDeviceNode, "0", BusQueryInstanceID));
    IopDeviceNodeSetCurrentState(IopRootDeviceNode, DeviceNodeInitialized);

    return STATUS_SUCCESS;
}

/*
 * NtGetPlugPlayEvent
 *
 * Returns one Plug & Play event from a global queue.
 *
 * Parameters
 *    Poll
 *       If TRUE, this routine will always return immediately even if
 *       there is no pending PnP event.
 *
 *    Buffer
 *       The buffer that will be filled with the event information on
 *       successful return from the function.
 *
 *    BufferSize
 *       Size of the buffer pointed by the Buffer parameter. If the
 *       buffer size is not large enough to hold the whole event
 *       information, error STATUS_BUFFER_TOO_SMALL is returned and
 *       the buffer remains untouched.
 *
 * Plug and Play event structure used by NtGetPlugPlayEvent.
 *
 *    EventGuid
 *       Can be one of the following values:
 *         GUID_HWPROFILE_QUERY_CHANGE
 *         GUID_HWPROFILE_CHANGE_CANCELLED
 *         GUID_HWPROFILE_CHANGE_COMPLETE
 *         GUID_TARGET_DEVICE_QUERY_REMOVE
 *         GUID_TARGET_DEVICE_REMOVE_CANCELLED
 *         GUID_TARGET_DEVICE_REMOVE_COMPLETE
 *         GUID_PNP_CUSTOM_NOTIFICATION
 *         GUID_PNP_POWER_NOTIFICATION
 *         GUID_DEVICE_*
 *
 *    EventCategory
 *       Type of the event that happened.
 *
 *    TotalSize
 *       Size of the event block including the device IDs and other
 *       per category specific fields.
 *
 * Return Values
 *    STATUS_PRIVILEGE_NOT_HELD
 *    STATUS_BUFFER_TOO_SMALL
 *    STATUS_NO_MORE_ENTRIES
 *    STATUS_SUCCESS
 *
 * @implemented
 */
NTSTATUS NtGetPlugPlayEvent(IN ASYNC_STATE State,
			    IN PTHREAD Thread,
			    IN BOOLEAN Poll,
			    OUT PIO_PNP_EVENT_BLOCK Buffer,
			    IN ULONG BufferSize)
{
    NTSTATUS Status = STATUS_SUCCESS;
    ASYNC_BEGIN(State);

    /* TODO: check for Tcb privilege */

    /* Wait for a PnP event */
    AWAIT_EX_IF(!Poll, Status, KeWaitForSingleObject, State, _, Thread,
		&IopPnpNotifyEvent.Header, FALSE, NULL);
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(State, Status);
    }

    if (IsListEmpty(&IopPnpEventQueueHead)) {
	ASYNC_RETURN(State, STATUS_NO_MORE_ENTRIES);
    }

    /* Get entry from the tail of the queue and copy it to the client. Note we
     * do not remove the event from the queue. The event is removed by the
     * PlugPlayControlUserResponse control class of NtPlugPlayControl. */
    PPNP_EVENT_ENTRY Entry = CONTAINING_RECORD(IopPnpEventQueueHead.Blink,
					       PNP_EVENT_ENTRY,
					       ListEntry);
    assert(BufferSize >= FIELD_OFFSET(IO_PNP_EVENT_BLOCK, DeviceClass));
    if (BufferSize < Entry->Event.TotalSize) {
	Buffer->TotalSize = Entry->Event.TotalSize;
        ASYNC_RETURN(State, STATUS_BUFFER_TOO_SMALL);
    }
    Buffer->TotalSize = Entry->Event.TotalSize;
    RtlCopyMemory(Buffer, &Entry->Event, Entry->Event.TotalSize);
    ASYNC_END(State, STATUS_SUCCESS);
}

/*
 * NtPlugPlayControl
 *
 * A function for doing various Plug & Play operations from user mode.
 *
 * Parameters
 *    PlugPlayControlClass
 *       0x00   Reenumerate device tree
 *
 *              Buffer points to UNICODE_STRING decribing the instance
 *              path (like "HTREE\ROOT\0" or "Root\ACPI_HAL\0000"). For
 *              more information about instance paths see !devnode command
 *              in kernel debugger or look at "Inside Windows 2000" book,
 *              chapter "Driver Loading, Initialization, and Installation".
 *
 *       0x01   Register new device
 *       0x02   Deregister device
 *       0x03   Initialize device
 *       0x04   Start device
 *       0x06   Query and remove device
 *       0x07   User response
 *
 *              Called after processing the message from NtGetPlugPlayEvent.
 *
 *       0x08   Generate legacy device
 *       0x09   Get interface device list
 *       0x0A   Get property data
 *       0x0B   Device class association (Registration)
 *       0x0C   Get related device
 *       0x0D   Get device interface alias
 *       0x0E   Get/set/clear device status
 *       0x0F   Get device depth
 *       0x10   Query device relations
 *       0x11   Query target device relation
 *       0x12   Query conflict list
 *       0x13   Retrieve dock data
 *       0x14   Reset device
 *       0x15   Halt device
 *       0x16   Get blocked driver data
 *
 *    Buffer
 *       The buffer contains information that is specific to each control
 *       code. The buffer is read-only.
 *
 *    BufferSize
 *       Size of the buffer pointed by the Buffer parameter. If the
 *       buffer size specifies incorrect value for specified control
 *       code, STATUS_INVALID_PARAMETER is returned.
 *
 * Return Values
 *    STATUS_PRIVILEGE_NOT_HELD
 *    STATUS_SUCCESS
 *    ...
 *
 * @unimplemented
 */
NTSTATUS NtPlugPlayControl(IN ASYNC_STATE State,
                           IN PTHREAD Thread,
                           IN PLUGPLAY_CONTROL_CLASS ControlClass,
                           IN PVOID Buffer,
                           IN ULONG BufferSize)
{
    assert(Buffer);
    switch (ControlClass) {
    case PlugPlayControlEnumerateDevice:
    {
	PIO_PNP_CONTROL_ENUMERATE_DEVICE_DATA Data = Buffer;
	return PiControlPerformDeviceAction(State, Thread,
					    Data->DeviceInstance, ControlClass);
    }

    case PlugPlayControlRegisterNewDevice:
    case PlugPlayControlDeregisterDevice:
	/* These two control class are used on Windows NT to register and deregister
	 * the driver service registry keys of a device node. We do not support these
	 * two control classes as the relevant functions are implement client-side. */
	return STATUS_NOT_SUPPORTED;

    case PlugPlayControlInitializeDevice:
	/* This is used on Windows NT to add an ad-hoc device node (under the PnP root
	 * device node) for legacy non-PnP devices added manually by the user. We do
	 * not plan to support this on Neptune OS at this point in time. */
	return STATUS_NOT_SUPPORTED;

    case PlugPlayControlStartDevice:
    case PlugPlayControlResetDevice:
    {
	PIO_PNP_CONTROL_DEVICE_CONTROL_DATA Data = Buffer;
	return PiControlPerformDeviceAction(State, Thread,
					    Data->DeviceInstance, ControlClass);
    }

    case PlugPlayControlUnlockDevice:
	return STATUS_NOT_IMPLEMENTED;

    case PlugPlayControlQueryAndRemoveDevice:
	return PiControlQueryRemoveDevice(State, Thread, Buffer);

    case PlugPlayControlUserResponse:
	return IopRemovePlugPlayEvent(Buffer);

    case PlugPlayControlGenerateLegacyDevice:
	/* We do not support legacy device nodes. */
	return STATUS_NOT_SUPPORTED;

        /* case PlugPlayControlGetInterfaceDeviceList: */
        /*     return IopGetInterfaceDeviceList(State, Thread, Buffer); */

        /* case PlugPlayControlProperty: */
        /*     return IopGetDeviceProperty(State, Thread, Buffer); */

        /* case PlugPlayControlDeviceClassAssociation: */
        /*     return PiControlDeviceClassAssociation(State, Thread, Buffer); */

    case PlugPlayControlGetRelatedDevice:
	return IopGetRelatedDevice(Buffer);

        /* case PlugPlayControlGetInterfaceDeviceAlias: */
        /*     return PiControlGetInterfaceDeviceAlias(State, Thread, Buffer); */

        /* case PlugPlayControlDeviceStatus: */
        /*     return IopDeviceStatus(State, Thread, Buffer); */

        /* case PlugPlayControlGetDeviceDepth: */
        /*     return IopGetDeviceDepth(State, Thread, Buffer); */

        /* case PlugPlayControlQueryDeviceRelations: */
        /*     return IopGetDeviceRelations(State, Thread, Buffer); */

//        case PlugPlayControlTargetDeviceRelation:
//        case PlugPlayControlQueryConflictList:
//        case PlugPlayControlRetrieveDock:
//        case PlugPlayControlHaltDevice:
//        case PlugPlayControlGetBlockedDriverList:

    case PlugPlayControlQueryHardwareIDs:
    case PlugPlayControlQueryCompatibleIDs:
	return PiControlQueryIds(Buffer, ControlClass);

    default:
	break;
    }

    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS WdmGetDeviceProperty(IN ASYNC_STATE AsyncState,
                              IN PTHREAD Thread,
                              IN GLOBAL_HANDLE DeviceHandle,
                              IN DEVICE_REGISTRY_PROPERTY DeviceProperty,
                              IN ULONG BufferLength,
                              OUT PVOID PropertyBuffer,
                              OUT ULONG *pResultLength)
{
    PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(DeviceHandle, NULL);
    if (!DeviceObject) {
	return STATUS_INVALID_HANDLE;
    }
    PDEVICE_NODE DeviceNode = IopGetDeviceNode(DeviceObject);
    if (!DeviceNode) {
	return STATUS_INVALID_DEVICE_REQUEST;
    }

    PVOID Data = NULL;
    ULONG ResultLength = 0;
    BOOLEAN UnicodeOutput = FALSE;
    CHAR Buffer[512];
    *pResultLength = 0;

    switch (DeviceProperty) {
    case DevicePropertyBusTypeGuid:
	Data = &DeviceNode->BusInformation.BusTypeGuid;
	ResultLength = sizeof(GUID);
	break;

    case DevicePropertyLegacyBusType:
	UNIMPLEMENTED;
	break;

    case DevicePropertyBusNumber:
	UNIMPLEMENTED;
	break;

    case DevicePropertyEnumeratorName:
	UNIMPLEMENTED;
	break;

    case DevicePropertyBootConfigurationTranslated:
	UNIMPLEMENTED;
	break;

    case DevicePropertyPhysicalDeviceObjectName:
	assert(DeviceNode->PhyDevObj);
	RET_ERR(ObQueryNameString(DeviceNode->PhyDevObj, Buffer, sizeof(Buffer), NULL));
	UnicodeOutput = TRUE;
	Data = Buffer;
	ResultLength = strlen(Buffer) + 1;
	break;

    case DevicePropertyInstancePath:
	snprintf(Buffer, sizeof(Buffer), "%s\\%s",
		 DeviceNode->DeviceId, DeviceNode->InstanceId);
	UnicodeOutput = TRUE;
	Data = Buffer;
	ResultLength = strlen(Buffer) + 1;
	break;

    case DevicePropertyAddress:
	return STATUS_NOT_SUPPORTED;
    default:
	return STATUS_INVALID_PARAMETER_2;
    }

    if (!Data) {
	return STATUS_NOT_IMPLEMENTED;
    }

    if (UnicodeOutput) {
	return RtlUTF8ToUnicodeN(PropertyBuffer, BufferLength, pResultLength,
				 Data, ResultLength);
    } else {
	*pResultLength = ResultLength;
	if (ResultLength > BufferLength) {
	    return STATUS_BUFFER_TOO_SMALL;
	}
	RtlCopyMemory(PropertyBuffer, Data, ResultLength);
	return STATUS_SUCCESS;
    }
}

NTSTATUS WdmRegisterPlugPlayNotification(IN ASYNC_STATE AsyncState,
                                         IN PTHREAD Thread,
                                         IN IO_NOTIFICATION_EVENT_CATEGORY EventCategory,
					 IN PGUID EventGuid,
					 IN GLOBAL_HANDLE EventDeviceHandle)
{
    assert(IopThreadIsAtPassiveLevel(Thread));
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    IopAllocatePool(Entry, PLUG_PLAY_NOTIFICATION);
    Entry->EventCategory = EventCategory;
    switch (EventCategory) {
    case EventCategoryHardwareProfileChange:
	LoopOverList(ExistingEntry, &DriverObject->PlugPlayNotificationList,
		     PLUG_PLAY_NOTIFICATION, DriverLink) {
	    assert(ExistingEntry->DriverObject == DriverObject);
	    if (ExistingEntry->EventCategory == EventCategoryHardwareProfileChange) {
		assert(FALSE);
		IopFreePool(Entry);
		return STATUS_ALREADY_REGISTERED;
	    }
	}
	InsertTailList(&IopHardwareProfileChangeList, &Entry->ListLink);
	break;
    case EventCategoryDeviceInterfaceChange:
	LoopOverList(ExistingEntry, &DriverObject->PlugPlayNotificationList,
		     PLUG_PLAY_NOTIFICATION, DriverLink) {
	    assert(ExistingEntry->DriverObject == DriverObject);
	    if (ExistingEntry->EventCategory == EventCategoryDeviceInterfaceChange &&
		IsEqualGUID(&ExistingEntry->EventGuid, EventGuid)) {
		assert(FALSE);
		IopFreePool(Entry);
		return STATUS_ALREADY_REGISTERED;
	    }
	}
	InsertTailList(&IopDeviceInterfaceChangeList, &Entry->ListLink);
	break;
    case EventCategoryTargetDeviceChange:
	LoopOverList(ExistingEntry, &DriverObject->PlugPlayNotificationList,
		     PLUG_PLAY_NOTIFICATION, DriverLink) {
	    assert(ExistingEntry->DriverObject == DriverObject);
	    if (ExistingEntry->EventCategory == EventCategoryTargetDeviceChange &&
		OBJECT_TO_GLOBAL_HANDLE(ExistingEntry->DriverObject) == EventDeviceHandle) {
		assert(FALSE);
		IopFreePool(Entry);
		return STATUS_ALREADY_REGISTERED;
	    }
	}
	PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(EventDeviceHandle,
							    DriverObject);
	if (!DeviceObject) {
	    assert(FALSE);
	    IopFreePool(Entry);
	    return STATUS_INVALID_HANDLE;
	}
	Entry->DeviceObject = DeviceObject;
	ObpReferenceObject(DeviceObject);
	InsertTailList(&DeviceObject->DeviceChangeNotificationList,
		       &Entry->ListLink);
	break;
    default:
	assert(FALSE);
	IopFreePool(Entry);
	return STATUS_INVALID_PARAMETER;
    }
    Entry->DriverObject = DriverObject;
    InsertTailList(&DriverObject->PlugPlayNotificationList, &Entry->DriverLink);
    return STATUS_SUCCESS;
}

VOID IopUnregisterPlugPlayNotification(IN PPLUG_PLAY_NOTIFICATION Entry)
{
    switch (Entry->EventCategory) {
    case EventCategoryHardwareProfileChange:
	assert(ListHasEntry(&IopHardwareProfileChangeList, &Entry->ListLink));
	RemoveEntryList(&Entry->ListLink);
	break;
    case EventCategoryDeviceInterfaceChange:
	assert(ListHasEntry(&IopDeviceInterfaceChangeList, &Entry->ListLink));
	RemoveEntryList(&Entry->ListLink);
	break;
    case EventCategoryTargetDeviceChange:
	assert(Entry->DeviceObject);
	assert(ListHasEntry(&Entry->DeviceObject->DeviceChangeNotificationList,
			    &Entry->ListLink));
	RemoveEntryList(&Entry->ListLink);
	ObDereferenceObject(Entry->DeviceObject);
	break;
    default:
	assert(FALSE);
    }
    RemoveEntryList(&Entry->DriverLink);
    IopFreePool(Entry);
}

NTSTATUS WdmUnregisterPlugPlayNotification(IN ASYNC_STATE AsyncState,
					   IN PTHREAD Thread,
					   IN IO_NOTIFICATION_EVENT_CATEGORY EventCategory,
					   IN PGUID EventGuid,
					   IN GLOBAL_HANDLE EventDeviceHandle)
{
    assert(IopThreadIsAtPassiveLevel(Thread));
    assert(Thread->Process != NULL);
    PIO_DRIVER_OBJECT DriverObject = Thread->Process->DriverObject;
    assert(DriverObject != NULL);
    LoopOverList(Entry, &DriverObject->PlugPlayNotificationList,
		 PLUG_PLAY_NOTIFICATION, DriverLink) {
	if (Entry->EventCategory != EventCategory) {
	    continue;
	}
	if (EventCategory == EventCategoryTargetDeviceChange &&
	    EventDeviceHandle != OBJECT_TO_GLOBAL_HANDLE(Entry->DeviceObject)) {
	    continue;
	}
	if (EventCategory == EventCategoryDeviceInterfaceChange &&
	    IsEqualGUID(EventGuid, &Entry->EventGuid)) {
	    continue;
	}
	IopUnregisterPlugPlayNotification(Entry);
    }
    return STATUS_SUCCESS;
}
