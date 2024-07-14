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

    DeviceNodeInitialized ---> DeviceNodeDriversLoaded
    When...
 */

#include "iop.h"

#define REG_SERVICE_KEY	"\\Registry\\Machine\\System\\CurrentControlSet\\Services"
#define REG_CLASS_KEY	"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class"
#define REG_ENUM_KEY	"\\Registry\\Machine\\System\\CurrentControlSet\\Enum"

/*
 * Device node state.
 */
typedef enum _DEVICE_NODE_STATE {
    DeviceNodeUnspecified,
    DeviceNodeInitialized,
    DeviceNodeLoadDriverFailed,
    DeviceNodeDriversLoaded,
    DeviceNodeAddDeviceFailed,
    DeviceNodeDevicesAdded,
    DeviceNodeResourcesAssignmentFailed,
    DeviceNodeResourcesAssigned,
    DeviceNodeStartPending,
    DeviceNodeStartCompletion,
    DeviceNodeStartPostWork,
    DeviceNodeStartFailed,
    DeviceNodeStarted,
    DeviceNodeQueryStopped,
    DeviceNodeStopped,
    DeviceNodeRestartCompletion,
    DeviceNodeEnumeratePending,
    DeviceNodeEnumerateFailed,
    DeviceNodeEnumerateCompletion,
    DeviceNodeAwaitingQueuedDeletion,
    DeviceNodeAwaitingQueuedRemoval,
    DeviceNodeQueryRemoved,
    DeviceNodeRemovePendingCloses,
    DeviceNodeRemoved,
    DeviceNodeDeletePendingCloses,
    DeviceNodeDeleted,
    MaxDeviceNodeState
} DEVICE_NODE_STATE, *PDEVICE_NODE_STATE;

#define DEVNODE_HISTORY_SIZE	(16)	/* must be a multiple of two */

/*
 * Device Node for the PNP manager
 */
typedef struct _DEVICE_NODE {
    DEVICE_NODE_STATE StateHistory[DEVNODE_HISTORY_SIZE];
    ULONG CurrentState;		/* Index into StateHistory */
    NTSTATUS ErrorStatus;
    PIO_DEVICE_OBJECT PhyDevObj;
    PCSTR DeviceId;
    PCSTR InstanceId;
    struct _DEVICE_NODE *Parent;
    LIST_ENTRY ChildrenList;
    LIST_ENTRY SiblingLink;
    PCSTR DriverServiceName;
    ULONG UpperFilterCount;
    ULONG LowerFilterCount;
    PCSTR *UpperFilterDriverNames;
    PCSTR *LowerFilterDriverNames;
    PIO_DRIVER_OBJECT FunctionDriverObject;
    PIO_DRIVER_OBJECT *UpperFilterDrivers;
    PIO_DRIVER_OBJECT *LowerFilterDrivers;
    PCM_RESOURCE_LIST Resources;
} DEVICE_NODE, *PDEVICE_NODE;

static PDEVICE_NODE IopRootDeviceNode;

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
    if (DeviceNode->Resources != NULL) {
	IopFreePool(DeviceNode->Resources);
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

static inline VOID IopDeviceNodeSetCurrentState(IN PDEVICE_NODE Node,
						IN DEVICE_NODE_STATE State)
{
    assert(Node != NULL);
    assert(Node->CurrentState < DEVNODE_HISTORY_SIZE);
    Node->CurrentState++;
    Node->CurrentState %= DEVNODE_HISTORY_SIZE;
    Node->StateHistory[Node->CurrentState] = State;
}

/*
 * Call this if you need to get the device node of a device object.
 * DO NOT just do DeviceObject->DeviceNode since we only keep track
 * of device nodes for PDOs (lowest device object in a device stack).
 */
static inline PDEVICE_NODE IopGetDeviceNode(IN PIO_DEVICE_OBJECT DeviceObject)
{
    assert(DeviceObject != NULL);
    /* Locate the lowest device object */
    PIO_DEVICE_OBJECT Pdo = DeviceObject;
    while (Pdo->AttachedTo != NULL) {
	Pdo = Pdo->AttachedTo;
	assert(Pdo != NULL);
    }
    return Pdo->DeviceNode;
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

static inline NTSTATUS IopDeviceNodeSetDeviceId(IN PDEVICE_NODE DeviceNode,
						IN PCSTR DeviceId,
						IN BUS_QUERY_ID_TYPE IdType)
{
    assert(DeviceNode != NULL);
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
	ULONG Length = strlen(Ptr);
	Names[Count] = RtlDuplicateString(Ptr, NTOS_IO_TAG);
	if (Names[Count] == NULL) {
	    return STATUS_NO_MEMORY;
	}
	Ptr += Length + 1;
	Count++;
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

static NTSTATUS IopLoadDriverByBaseName(IN ASYNC_STATE State,
					IN PTHREAD Thread,
					IN PCSTR BaseName,
					OUT PIO_DRIVER_OBJECT *DriverObject)
{
    NTSTATUS Status;
    ASYNC_BEGIN(State, Locals, {
	    CHAR DriverService[256];
	});
    snprintf(Locals.DriverService, sizeof(Locals.DriverService),
	     REG_SERVICE_KEY "\\%s", BaseName);
    AWAIT_EX(Status, IopLoadDriver, State, Locals, Thread,
	     Locals.DriverService, DriverObject);
    ASYNC_END(State, Status);
}

/*
 * A note about driver loading order: device lower filters are loaded
 * first, followed by class lower filters, and then the function driver
 * itself, and then device upper filters, and finally class upper filters.
 * In other words, class filter drivers are always loaded after the device
 * filter drivers on the same level.
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
    if (DeviceNode->UpperFilterDriverNames != NULL) {
	IopFreeFilterDriverNames(DeviceNode->UpperFilterCount,
				 DeviceNode->UpperFilterDriverNames);
	DeviceNode->UpperFilterCount = 0;
	DeviceNode->UpperFilterDriverNames = NULL;
    }
    if (DeviceNode->LowerFilterDriverNames != NULL) {
	IopFreeFilterDriverNames(DeviceNode->LowerFilterCount,
				 DeviceNode->LowerFilterDriverNames);
	DeviceNode->LowerFilterCount = 0;
	DeviceNode->LowerFilterDriverNames = NULL;
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
					     &DeviceNode->UpperFilterDriverNames));
    IF_ERR_GOTO(out, Status,
		IopAllocateFilterDriverNames(Locals.DeviceLowerFilterNames,
					     Locals.ClassLowerFilterNames,
					     &DeviceNode->LowerFilterCount,
					     &DeviceNode->LowerFilterDriverNames));

    /* Load lower filter drivers first */
    if (DeviceNode->LowerFilterCount != 0) {
	DeviceNode->LowerFilterDrivers = (PIO_DRIVER_OBJECT *)ExAllocatePoolWithTag(
	    sizeof(PIO_DRIVER_OBJECT) * DeviceNode->LowerFilterCount, NTOS_IO_TAG);
	if (DeviceNode->LowerFilterDrivers == NULL) {
	    Status = STATUS_NO_MEMORY;
	    goto out;
	}
    }

    Locals.Idx = 0;
lower:
    if (Locals.Idx >= DeviceNode->LowerFilterCount) {
	goto function;
    }
    AWAIT_EX(Status, IopLoadDriverByBaseName, State, Locals, Thread,
	     DeviceNode->LowerFilterDriverNames[Locals.Idx],
	     &DeviceNode->LowerFilterDrivers[Locals.Idx]);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.Idx++;
    goto lower;

function:
    /* Load function driver next */
    AWAIT_EX(Status, IopLoadDriverByBaseName, State, Locals, Thread,
	     DeviceNode->DriverServiceName, &DeviceNode->FunctionDriverObject);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Finally, load upper filter drivers */
    if (DeviceNode->UpperFilterCount != 0) {
	DeviceNode->UpperFilterDrivers = (PIO_DRIVER_OBJECT *)ExAllocatePoolWithTag(
	    sizeof(PIO_DRIVER_OBJECT) * DeviceNode->UpperFilterCount, NTOS_IO_TAG);
	if (DeviceNode->UpperFilterDrivers == NULL) {
	    Status = STATUS_NO_MEMORY;
	    goto out;
	}
    }
    Locals.Idx = 0;
upper:
    if (Locals.Idx >= DeviceNode->UpperFilterCount) {
	goto done;
    }
    AWAIT_EX(Status, IopLoadDriverByBaseName, State, Locals, Thread,
	     DeviceNode->UpperFilterDriverNames[Locals.Idx],
	     &DeviceNode->UpperFilterDrivers[Locals.Idx]);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Locals.Idx++;
    goto upper;

done:
    Status = STATUS_SUCCESS;

out:
    if (NT_SUCCESS(Status)) {
        IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeDriversLoaded);
    } else {
        IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeLoadDriverFailed);
	DeviceNode->ErrorStatus = Status;
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

static NTSTATUS IopQueueAddDeviceRequest(IN PTHREAD Thread,
					 IN PDEVICE_NODE DeviceNode,
					 IN PIO_DRIVER_OBJECT DriverObject,
					 OUT PPENDING_IRP *PendingIrp)
{
    PIO_DEVICE_OBJECT PhyDevObj = DeviceNode->PhyDevObj;
    IO_REQUEST_PARAMETERS Irp = {
	.MajorFunction = IRP_MJ_ADD_DEVICE,
	.Device.Object = PhyDevObj
    };
    if (PhyDevObj) {
	Irp.AddDevice.PhysicalDeviceInfo = PhyDevObj->DeviceInfo;
    }
    return IopCallDriverEx(Thread, &Irp, DriverObject, PendingIrp);
}

/*
 * For each upper-filter/function/lower-filter driver, call the AddDevice
 * routine of the driver object. (Of course, here "call" means queuing the
 * IRP and wait for driver response. We are a micro-kernel OS.) Note that
 * we need to wait for lower drivers to complete the request before we can
 * continue sending AddDevice to higher drivers.
 */
static NTSTATUS IopDeviceNodeAddDevice(IN ASYNC_STATE AsyncState,
				       IN PTHREAD Thread,
				       IN PDEVICE_NODE DeviceNode)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PIO_DRIVER_OBJECT DriverObject;
	    PPENDING_IRP PendingIrp;
	    ULONG LowerFilterCount;
	    ULONG UpperFilterCount;
	    BOOLEAN FunctionDriverCalled;
	});
    Locals.PendingIrp = NULL;
    Locals.LowerFilterCount = 0;
    Locals.UpperFilterCount = 0;
    Locals.FunctionDriverCalled = FALSE;

    if (IopDeviceNodeGetCurrentState(DeviceNode) != DeviceNodeDriversLoaded) {
	DbgTrace("Device node state is %d. Not adding device.\n",
		 IopDeviceNodeGetCurrentState(DeviceNode));
	ASYNC_RETURN(AsyncState, STATUS_INVALID_DEVICE_STATE);
    }

check:
    if (Locals.LowerFilterCount < DeviceNode->LowerFilterCount) {
	Locals.DriverObject = DeviceNode->LowerFilterDrivers[Locals.LowerFilterCount++];
	goto call;
    }
    if (!Locals.FunctionDriverCalled && DeviceNode->FunctionDriverObject != NULL) {
	Locals.DriverObject = DeviceNode->FunctionDriverObject;
	Locals.FunctionDriverCalled = TRUE;
	goto call;
    }
    if (Locals.UpperFilterCount < DeviceNode->UpperFilterCount) {
	Locals.DriverObject = DeviceNode->UpperFilterDrivers[Locals.UpperFilterCount++];
	goto call;
    }
    Status = STATUS_SUCCESS;
    goto end;

call:
    assert(Locals.DriverObject != NULL);
    if (Locals.DriverObject->AddDeviceCalled) {
	goto check;
    }
    IF_ERR_GOTO(end, Status, IopQueueAddDeviceRequest(Thread, DeviceNode,
						      Locals.DriverObject,
						      &Locals.PendingIrp));
    Locals.DriverObject->AddDeviceCalled = TRUE;
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

static inline CM_PARTIAL_RESOURCE_DESCRIPTOR IopAssignResource(IN IO_RESOURCE_DESCRIPTOR Desc)
{
    CM_PARTIAL_RESOURCE_DESCRIPTOR Res = {
	.Type = Desc.Type,
	.ShareDisposition = Desc.ShareDisposition,
	.Flags = Desc.Flags
    };
    switch (Res.Type) {
    case CmResourceTypeNull:
	/* Do nothing */
	break;

    case CmResourceTypePort:
	/* Assign the first available port */
	Res.u.Port.Start = Desc.u.Port.MinimumAddress;
	Res.u.Port.Length = Desc.u.Port.Length;
	break;

    case CmResourceTypeInterrupt:
	/* Assign the first available interrupt vector */
	Res.u.Interrupt.Level = Desc.u.Interrupt.MinimumVector;
	Res.u.Interrupt.Vector = Desc.u.Interrupt.MinimumVector;
	Res.u.Interrupt.Affinity = Desc.u.Interrupt.TargetedProcessors;
	break;

    case CmResourceTypeDma:
	/* Assign the first available DMA channel */
	Res.u.Dma.Channel = Desc.u.Dma.MinimumChannel;
	Res.u.Dma.Port = 0;
	break;

    case CmResourceTypeMemory:
	/* Assign the first available memory-mapped IO region */
	Res.u.Memory.Start = Desc.u.Memory.MinimumAddress;
	Res.u.Memory.Length = Desc.u.Memory.Length;
	break;

    default:
	assert(FALSE);
    }
    return Res;
}

static NTSTATUS IopDeviceNodeAssignResources(IN ASYNC_STATE AsyncState,
					     IN PTHREAD Thread,
					     IN PDEVICE_NODE DeviceNode)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PPENDING_IRP PendingIrp;
	});
    Locals.PendingIrp = NULL;

    if (IopDeviceNodeGetCurrentState(DeviceNode) != DeviceNodeDevicesAdded) {
	DbgTrace("Device node state is %d. Not assigning resources.\n",
		 IopDeviceNodeGetCurrentState(DeviceNode));
	ASYNC_RETURN(AsyncState, STATUS_INVALID_DEVICE_STATE);
    }

    IF_ERR_GOTO(out, Status,
		IopQueueQueryResourceRequirementsRequest(Thread, DeviceNode->PhyDevObj,
							 &Locals.PendingIrp));
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.PendingIrp->IoCompletionEvent.Header, FALSE, NULL);
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Failed to query device resource requirements for %s\\%s. Status = 0x%x\n",
		 DeviceNode->DeviceId, DeviceNode->InstanceId,
		 Status);
	goto out;
    }

    PIO_RESOURCE_REQUIREMENTS_LIST Res = (PIO_RESOURCE_REQUIREMENTS_LIST)Locals.PendingIrp->IoResponseData;
    if (Res == NULL) {
	Status = STATUS_SUCCESS;
	goto out;
    }
    if (DeviceNode->Resources != NULL) {
	IopFreePool(DeviceNode->Resources);
    }
    if (Res->ListSize <= MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE) {
	Status = STATUS_INVALID_PARAMETER;
	goto out;
    }
    ULONG Size = sizeof(CM_RESOURCE_LIST) + sizeof(CM_FULL_RESOURCE_DESCRIPTOR) +
	Res->List[0].Count * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
    DeviceNode->Resources = (PCM_RESOURCE_LIST)ExAllocatePoolWithTag(Size, NTOS_IO_TAG);
    if (DeviceNode->Resources == NULL) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }
    DeviceNode->Resources->Count = 1;
    DeviceNode->Resources->List[0].InterfaceType = Res->InterfaceType;
    DeviceNode->Resources->List[0].BusNumber = Res->BusNumber;
    DeviceNode->Resources->List[0].PartialResourceList.Version = Res->List[0].Version;
    DeviceNode->Resources->List[0].PartialResourceList.Revision = Res->List[0].Revision;
    DeviceNode->Resources->List[0].PartialResourceList.Count = Res->List[0].Count;
    for (ULONG i = 0; i < Res->List[0].Count; i++) {
	DeviceNode->Resources->List[0].PartialResourceList.PartialDescriptors[i] =
	    IopAssignResource(Res->List[0].Descriptors[i]);
    }
    Status = STATUS_SUCCESS;

out:
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
    PCM_RESOURCE_LIST Res = DeviceNode->Resources;
    ULONG ResSize = 0;
    if (Res) {
	ResSize = sizeof(CM_RESOURCE_LIST) + Res->Count * sizeof(CM_FULL_RESOURCE_DESCRIPTOR);
	for (ULONG i = 0; i < Res->Count; i++) {
	    ResSize += Res->List[i].PartialResourceList.Count * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
	}
    }
    PIO_REQUEST_PARAMETERS Irp = ExAllocatePoolWithTag(sizeof(IO_REQUEST_PARAMETERS) + ResSize*2,
						       NTOS_IO_TAG);
    if (!Irp) {
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    Irp->DataSize = ResSize * 2;
    Irp->MajorFunction = IRP_MJ_PNP;
    Irp->MinorFunction = IRP_MN_START_DEVICE;
    Irp->Device.Object = IopGetTopDevice(DeviceNode->PhyDevObj);
    Irp->StartDevice.ResourceListSize = ResSize;
    Irp->StartDevice.TranslatedListSize = ResSize;
    if (ResSize) {
	memcpy(Irp->StartDevice.Data, Res, ResSize);
	memcpy(&Irp->StartDevice.Data[ResSize], Res, ResSize);
    }
    return IopCallDriver(Thread, Irp, PendingIrp);
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
    Locals.PendingIrps = ExAllocatePoolWithTag(sizeof(PPENDING_IRP) * Locals.DeviceCount * 2,
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
					      &Locals.PendingIrps[2*i]));
	IF_ERR_GOTO(out, Status,
		    IopQueueBusQueryIdRequest(Thread, ChildPhyDev, BusQueryInstanceID,
					      &Locals.PendingIrps[2*i+1]));
    }
    AWAIT_EX(Status, IopWaitForMultipleIoCompletions, AsyncState, Locals, Thread,
	     FALSE, WaitAll, Locals.PendingIrps, Locals.DeviceCount * 2);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Set the device IDs of the child nodes. */
    for (ULONG i = 0; i < Locals.DeviceCount * 2; i++) {
	PPENDING_IRP PendingIrp = Locals.PendingIrps[i];
	assert(PendingIrp != NULL);
	assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	assert(PendingIrp->IoPacket->Request.MajorFunction == IRP_MJ_PNP);
	assert(PendingIrp->IoPacket->Request.MinorFunction == IRP_MN_QUERY_ID);
	BUS_QUERY_ID_TYPE IdType = PendingIrp->IoPacket->Request.QueryId.IdType;
	PIO_DEVICE_OBJECT DeviceObject = PendingIrp->IoPacket->Request.Device.Object;
	PDEVICE_NODE DeviceNode = IopGetDeviceNode(DeviceObject);
	assert(DeviceNode != NULL);
	IF_ERR_GOTO(out, Status,
		    IopDeviceNodeSetDeviceId(DeviceNode, PendingIrp->IoResponseData, IdType));
	IopDeviceNodeSetCurrentState(DeviceNode, DeviceNodeInitialized);
    }

    /* All done! */
    Status = STATUS_SUCCESS;

out:
    if (NT_SUCCESS(Status)) {
	IopDeviceNodeSetCurrentState(DevNode, DeviceNodeEnumerateCompletion);
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
	for (ULONG i = 0; i < Locals.DeviceCount * 2; i++) {
	    if (Locals.PendingIrps[i] != NULL) {
		IopCleanupPendingIrp(Locals.PendingIrps[i]);
	    }
	}
	IopFreePool(Locals.PendingIrps);
    }
    ASYNC_END(AsyncState, Status);
}

typedef NTSTATUS (*PDEVICE_NODE_VISITOR_EX)(IN ASYNC_STATE AsyncState,
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
static NTSTATUS IopDeviceNodeTraverseChildrenEx(IN ASYNC_STATE AsyncState,
						IN PTHREAD Thread,
						IN PDEVICE_NODE DeviceNode,
						IN PDEVICE_NODE_VISITOR_EX Visitor,
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

typedef NTSTATUS (*PDEVICE_NODE_VISITOR)(IN ASYNC_STATE AsyncState,
					 IN PTHREAD Thread,
					 IN PDEVICE_NODE DeviceNode);

static NTSTATUS IopDeviceNodeVisit(IN ASYNC_STATE AsyncState,
				   IN PTHREAD Thread,
				   IN PDEVICE_NODE DeviceNode,
				   IN PVOID Context)
{
    PDEVICE_NODE_VISITOR Visitor = (PDEVICE_NODE_VISITOR)Context;
    return Visitor(AsyncState, Thread, DeviceNode);
}

static NTSTATUS IopDeviceNodeTraverseChildren(IN ASYNC_STATE AsyncState,
					      IN PTHREAD Thread,
					      IN PDEVICE_NODE DeviceNode,
					      IN PDEVICE_NODE_VISITOR Visitor)
{
    return IopDeviceNodeTraverseChildrenEx(AsyncState, Thread, DeviceNode,
					   IopDeviceNodeVisit, Visitor, FALSE);
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
    AWAIT_EX(Status, IopDeviceNodeTraverseChildren, AsyncState, _, Thread,
	     DeviceNode, IopDeviceTreeEnumerate);

out:
    ASYNC_END(AsyncState, Status);
}

static inline PCSTR IopSanitizeName(IN PCSTR Name)
{
    return Name ? Name : "????";
}

static VOID IopPrintDeviceNode(IN PDEVICE_NODE DeviceNode,
			       IN ULONG IndentLevel)
{
    CHAR Indent[32];
    if (IndentLevel >= ARRAYSIZE(Indent)) {
	IndentLevel = ARRAYSIZE(Indent)-1;
    }
    for (ULONG i = 0; i < IndentLevel; i++) {
	Indent[i] = ' ';
    }
    Indent[IndentLevel] = '\0';
    HalVgaPrint("%sFound device \\%s\\%s.", Indent,
		IopSanitizeName(DeviceNode->DeviceId),
		IopSanitizeName(DeviceNode->InstanceId));
    if (IopDeviceNodeGetCurrentState(DeviceNode) >= DeviceNodeDriversLoaded) {
	assert(DeviceNode->DriverServiceName != NULL);
	if (DeviceNode->UpperFilterCount != 0 || DeviceNode->LowerFilterCount != 0) {
	    HalVgaPrint(" Loaded drivers:");
	    for (ULONG i = 0; i < DeviceNode->LowerFilterCount; i++) {
		HalVgaPrint(" %s", DeviceNode->LowerFilterDriverNames[i]);
	    }
	    HalVgaPrint(" %s", DeviceNode->DriverServiceName);
	    for (ULONG i = 0; i < DeviceNode->UpperFilterCount; i++) {
		HalVgaPrint(" %s", DeviceNode->UpperFilterDriverNames[i]);
	    }
	} else {
	    HalVgaPrint(" Loaded driver: %s", DeviceNode->DriverServiceName);
	}
	if (IopDeviceNodeGetCurrentState(DeviceNode) >= DeviceNodeStarted) {
	    HalVgaPrint(". STARTED.\n");
	} else {
	    HalVgaPrint(". START FAIL.\n");
	}
    } else if (DeviceNode->DriverServiceName != NULL) {
	HalVgaPrint(" FAILED to load driver %s.\n", DeviceNode->DriverServiceName);
    } else {
	HalVgaPrint("\n");
    }
}

#define DEVICE_TREE_INDENTATION	2
static VOID IopPrintDeviceTree(IN PDEVICE_NODE RootDeviceNode,
			       IN ULONG IndentLevel)
{
    LoopOverList(DeviceNode, &RootDeviceNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	IopPrintDeviceNode(DeviceNode, IndentLevel);
	IopPrintDeviceTree(DeviceNode, IndentLevel + DEVICE_TREE_INDENTATION);
    }
}

/*
 * Assign resources to the root device node. We simply pass the address and size
 * of the XSDT (eXtended System Descriptor Table) to the root PnP enumerator.
 */
static NTSTATUS IopRootNodeAssignResources()
{
    ULONG Size = sizeof(CM_RESOURCE_LIST) + sizeof(CM_FULL_RESOURCE_DESCRIPTOR) +
	sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
    IopRootDeviceNode->Resources = (PCM_RESOURCE_LIST)ExAllocatePoolWithTag(Size, NTOS_IO_TAG);
    if (IopRootDeviceNode->Resources == NULL) {
	return STATUS_NO_MEMORY;
    }
    IopRootDeviceNode->Resources->Count = 1;
    IopRootDeviceNode->Resources->List[0].InterfaceType = Internal;
    IopRootDeviceNode->Resources->List[0].BusNumber = 0;
    IopRootDeviceNode->Resources->List[0].PartialResourceList.Version = 1;
    IopRootDeviceNode->Resources->List[0].PartialResourceList.Revision = 1;
    IopRootDeviceNode->Resources->List[0].PartialResourceList.Count = 1;
    IopRootDeviceNode->Resources->List[0].PartialResourceList.PartialDescriptors[0] =
	HalAcpiGetRsdtResource();
    IopDeviceNodeSetCurrentState(IopRootDeviceNode, DeviceNodeResourcesAssigned);
    return STATUS_SUCCESS;
}

/*
 * Before calling this system service the session manager needs to
 * initialize the hardware database in the registry.
 */
NTSTATUS NtPlugPlayInitialize(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState);

    /* We can only be called once (typically during system startup). */
    if (IopRootDeviceNode != NULL) {
	ASYNC_RETURN(AsyncState, STATUS_INVALID_SYSTEM_SERVICE);
    }

    HalVgaPrint("Enumerating Plug and Play devices...\n");

    /* Create the root device node. This is the device node for the root PnP enumerator. */
    IF_ERR_GOTO(out, Status, IopCreateDeviceNode(NULL, &IopRootDeviceNode));
    assert(IopRootDeviceNode != NULL);

    /* Set the device and instance ID of the root enumerator. */
    IF_ERR_GOTO(out, Status,
		IopDeviceNodeSetDeviceId(IopRootDeviceNode, "HTREE\\ROOT", BusQueryDeviceID));
    IF_ERR_GOTO(out, Status,
		IopDeviceNodeSetDeviceId(IopRootDeviceNode, "0", BusQueryInstanceID));

    /* Load the root PnP enumerator driver and call AddDevice to create the root enumerator. */
    IopDeviceNodeSetCurrentState(IopRootDeviceNode, DeviceNodeInitialized);
    AWAIT_EX(Status, IopDeviceNodeLoadDrivers, AsyncState, _, Thread, IopRootDeviceNode);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    AWAIT_EX(Status, IopDeviceNodeAddDevice, AsyncState, _, Thread, IopRootDeviceNode);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* We need to manually set the PDO of the root device node */
    PIO_DEVICE_OBJECT RootEnumerator = NULL;
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByName(PNP_ROOT_ENUMERATOR, OBJECT_TYPE_DEVICE,
					NULL, FALSE, (POBJECT *)&RootEnumerator));
    assert(RootEnumerator != NULL);
    IopSetDeviceNode(RootEnumerator, IopRootDeviceNode);

    /* Assign resources for the root enumerator, and start its device node. */
    Status = IopRootNodeAssignResources();
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    AWAIT(IopDeviceNodeStartDevice, AsyncState, _, Thread, IopRootDeviceNode);

    /* Recursively enumerate the root node and start all boot devices.
     * This will build the entire boot-time device tree. */
    AWAIT_EX(Status, IopDeviceTreeEnumerate, AsyncState, _, Thread, IopRootDeviceNode);

    /* Inform the user of device enumeration results */
    IopPrintDeviceTree(IopRootDeviceNode, 2);

    ASYNC_RETURN(AsyncState, STATUS_SUCCESS);

out:
    if (IopRootDeviceNode) {
	IopFreeDeviceNode(IopRootDeviceNode);
	IopRootDeviceNode = NULL;
    }

    ASYNC_END(AsyncState, Status);
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
 *       code, error ??? is returned.
 *
 * Return Values
 *    STATUS_PRIVILEGE_NOT_HELD
 *    STATUS_SUCCESS
 *    ...
 *
 * @unimplemented
 */
NTSTATUS NtPlugPlayControl(IN ASYNC_STATE AsyncState,
                           IN PTHREAD Thread,
                           IN PLUGPLAY_CONTROL_CLASS PlugPlayControlClass,
                           IN PVOID Buffer,
                           IN ULONG BufferSize)
{
    UNIMPLEMENTED;
}

NTSTATUS WdmOpenDeviceRegistryKey(IN ASYNC_STATE AsyncState,
                                  IN PTHREAD Thread,
                                  IN GLOBAL_HANDLE DeviceHandle,
                                  IN ULONG DevInstKeyType,
                                  IN ACCESS_MASK DesiredAccess,
                                  OUT HANDLE *DevInstRegKey)
{
    UNIMPLEMENTED;
}
