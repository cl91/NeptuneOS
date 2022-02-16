#include "iop.h"

#define REG_SERVICE_KEY	"\\Registry\\Machine\\CurrentControlSet\\Services"
#define REG_CLASS_KEY	"\\Registry\\Machine\\CurrentControlSet\\Control\\Class"
#define REG_ENUM_KEY	"\\Registry\\Machine\\CurrentControlSet\\Enum"

static PDEVICE_NODE IopRootDeviceNode;

static inline VOID IopInitializeDeviceNode(IN PDEVICE_NODE DeviceNode,
					   IN PIO_DEVICE_OBJECT DeviceObject,
					   IN OPTIONAL PDEVICE_NODE ParentNode)
{
    assert(DeviceNode != NULL);
    assert(DeviceObject != NULL);
    /* Locate the lowest device object */
    PIO_DEVICE_OBJECT Pdo = DeviceObject;
    while (Pdo->AttachedTo != NULL) {
	Pdo = Pdo->AttachedTo;
    }
    DeviceNode->PhyDevObj = Pdo;
    DeviceNode->Parent = ParentNode;
    InitializeListHead(&DeviceNode->ChildrenList);
    if (ParentNode != NULL) {
	InsertTailList(&ParentNode->ChildrenList, &DeviceNode->SiblingLink);
    }
    DeviceObject = Pdo;
    while (DeviceObject != NULL) {
	DeviceObject->DeviceNode = DeviceNode;
	DeviceObject = DeviceObject->AttachedDevice;
    }
}

static inline NTSTATUS IopCreateDeviceNode(IN PIO_DEVICE_OBJECT DeviceObject,
					   IN OPTIONAL PDEVICE_NODE ParentNode,
					   OUT OPTIONAL PDEVICE_NODE *pDevNode)
{
    IopAllocatePool(DeviceNode, DEVICE_NODE);
    IopInitializeDeviceNode(DeviceNode, DeviceObject, ParentNode);
    if (pDevNode) {
	*pDevNode = DeviceNode;
    }
    return STATUS_SUCCESS;
}

static inline VOID IopFreeDeviceNode(IN PDEVICE_NODE DeviceNode)
{
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
	ExFreePool(Names[i]);
    }
    ExFreePool(Names);
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
		ExFreePool(FilterDriverNames[i]);
	    }
	}
	ExFreePool(FilterDriverNames);
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
    assert(RegSz != NULL);
    return RegSz;
}

static inline NTSTATUS IopLoadDriverByBaseName(IN PCSTR BaseName,
					       OUT PIO_DRIVER_OBJECT *DriverObject)
{
    CHAR DriverService[256];
    snprintf(DriverService, sizeof(DriverService), REG_SERVICE_KEY "\\%s",
	     BaseName);
    return IopLoadDriver(DriverService, DriverObject);
}

/*
 * A note about driver loading order: device lower filters are loaded
 * first, followed by class lower filers, and then the function driver
 * itself, and then device upper filters, and finally class upper filters.
 * Don't ask me why. Microsoft made it this way.
 */
static NTSTATUS IopDeviceNodeLoadDriver(IN PDEVICE_NODE DeviceNode)
{
    assert(DeviceNode != NULL);
    assert(DeviceNode->DeviceId != NULL);
    assert(DeviceNode->InstanceId != NULL);
    if (DeviceNode->DriverLoaded) {
	return STATUS_SUCCESS;
    }

    /* If previous attempts at driver loading failed, we want to clear the
     * driver service name and filter driver names, just in case that these
     * have changed. */
    if (DeviceNode->DriverServiceName != NULL) {
	ExFreePool(DeviceNode->DriverServiceName);
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
    NTSTATUS Status = STATUS_SUCCESS;
    POBJECT EnumKey = NULL;
    CHAR EnumKeyPath[256];
    snprintf(EnumKeyPath, sizeof(EnumKeyPath), REG_ENUM_KEY "\\%s\\%s",
	     DeviceNode->DeviceId, DeviceNode->InstanceId);
    ULONG RegValueType;
    PCSTR DriverServiceName = NULL;
    RET_ERR(CmReadKeyValueByPath(EnumKeyPath, "Service", &EnumKey,
				 &RegValueType, (PPVOID)&DriverServiceName));
    assert(EnumKey != NULL);
    if (RegValueType != REG_SZ) {
	Status = STATUS_DRIVER_UNABLE_TO_LOAD;
	goto out;
    }
    assert(DriverServiceName != NULL);
    DeviceNode->DriverServiceName = RtlDuplicateString(DriverServiceName, NTOS_IO_TAG);
    if (DeviceNode->DriverServiceName == NULL) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    /* Also query the upper and lower device filter drivers */
    PCSTR DeviceUpperFilterNames = IopGetMultiSz(EnumKey, "UpperFilters");
    PCSTR DeviceLowerFilterNames = IopGetMultiSz(EnumKey, "LowerFilters");

    /* Query the class key to find the upper and lower class filters */
    PCSTR ClassGuid = IopGetRegSz(EnumKey, "ClassGUID");
    PCSTR ClassUpperFilterNames = NULL;
    PCSTR ClassLowerFilterNames = NULL;
    POBJECT ClassKey = NULL;
    if (ClassGuid != NULL) {
	CHAR ClassKeyPath[256];
	snprintf(ClassKeyPath, sizeof(ClassKeyPath), REG_CLASS_KEY "\\%s",
		 ClassGuid);
	IF_ERR_GOTO(out, Status,
		    ObReferenceObjectByName(ClassKeyPath, OBJECT_TYPE_KEY, NULL, &ClassKey));
	ClassUpperFilterNames = IopGetMultiSz(ClassKey, "UpperFilters");
	ClassLowerFilterNames = IopGetMultiSz(EnumKey, "LowerFilters");
    }

    /* Record the filter driver names in the device node */
    IF_ERR_GOTO(out, Status,
		IopAllocateFilterDriverNames(DeviceUpperFilterNames,
					     ClassUpperFilterNames,
					     &DeviceNode->UpperFilterCount,
					     &DeviceNode->UpperFilterDriverNames));
    IF_ERR_GOTO(out, Status,
		IopAllocateFilterDriverNames(DeviceLowerFilterNames,
					     ClassLowerFilterNames,
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
    for (ULONG i = 0; i < DeviceNode->LowerFilterCount; i++) {
	IF_ERR_GOTO(out, Status, IopLoadDriverByBaseName(DeviceNode->LowerFilterDriverNames[i],
							 &DeviceNode->LowerFilterDrivers[i]));
    }

    /* Load function driver next */
    IF_ERR_GOTO(out, Status, IopLoadDriverByBaseName(DeviceNode->DriverServiceName,
						     &DeviceNode->FunctionDriverObject));

    /* Finally, load upper filter drivers */
    if (DeviceNode->UpperFilterCount != 0) {
	DeviceNode->UpperFilterDrivers = (PIO_DRIVER_OBJECT *)ExAllocatePoolWithTag(
	    sizeof(PIO_DRIVER_OBJECT) * DeviceNode->UpperFilterCount, NTOS_IO_TAG);
	if (DeviceNode->UpperFilterDrivers == NULL) {
	    Status = STATUS_NO_MEMORY;
	    goto out;
	}
    }
    for (ULONG i = 0; i < DeviceNode->UpperFilterCount; i++) {
	IF_ERR_GOTO(out, Status, IopLoadDriverByBaseName(DeviceNode->UpperFilterDriverNames[i],
							 &DeviceNode->UpperFilterDrivers[i]));
    }

    DeviceNode->DriverLoaded = TRUE;
    Status = STATUS_SUCCESS;
out:
    /* Dereference the enum key object because the CmReadKeyValueByPath routine
     * increases its reference count. */
    if (EnumKey != NULL) {
	ObDereferenceObject(EnumKey);
    }
    if (ClassKey != NULL) {
	ObDereferenceObject(ClassKey);
    }
    return Status;
}

static NTSTATUS IopDeviceTreeLoadDrivers(IN PDEVICE_NODE RootDeviceNode)
{
    assert(RootDeviceNode != NULL);
    RET_ERR(IopDeviceNodeLoadDriver(RootDeviceNode));
    LoopOverList(ChildNode, &RootDeviceNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	RET_ERR(IopDeviceTreeLoadDrivers(ChildNode));
    }
    return STATUS_SUCCESS;
}

static NTSTATUS IopCreateBusDeviceNode(IN PIO_DRIVER_OBJECT DriverObject,
				       IN PCSTR BusDeviceId,
				       IN PCSTR BusInstanceId,
				       IN PIO_DEVICE_OBJECT BusFdo,
				       IN OPTIONAL ULONG DeviceCount,
				       IN OPTIONAL PGLOBAL_HANDLE DeviceHandles,
				       IN OPTIONAL PDEVICE_NODE ParentDeviceNode,
				       OUT PDEVICE_NODE *pDeviceNode)
{
    assert(DriverObject != NULL);
    assert(BusFdo != NULL);
    assert(DeviceCount == 0 || DeviceHandles != NULL);
    assert(pDeviceNode != NULL);
    PDEVICE_NODE BusDeviceNode = NULL;
    RET_ERR(IopCreateDeviceNode(BusFdo, ParentDeviceNode, &BusDeviceNode));
    assert(BusDeviceNode != NULL);
    RET_ERR(IopDeviceNodeSetDeviceId(BusDeviceNode, BusDeviceId, BusQueryDeviceID));
    RET_ERR(IopDeviceNodeSetDeviceId(BusDeviceNode, BusInstanceId, BusQueryInstanceID));
    for (ULONG i = 0; i < DeviceCount; i++) {
	PIO_DEVICE_OBJECT DeviceObject = IopGetDeviceObject(DeviceHandles[i],
							    DriverObject);
	if (DeviceObject == NULL) {
	    DbgTrace("Invalid device handle %p received for driver object %p\n",
		     (PVOID)DeviceHandles[i], DriverObject);
	    return STATUS_NO_SUCH_DEVICE;
	}
	RET_ERR(IopCreateDeviceNode(DeviceObject, BusDeviceNode, NULL));
    }
    BusDeviceNode->FunctionDriverObject = DriverObject;
    /* TODO: Bus filter drivers */
    *pDeviceNode = BusDeviceNode;
    return STATUS_SUCCESS;
}

static inline VOID IopPopulatePnpRequest(IN PIO_PACKET IoPacket,
					 IN PIO_DEVICE_OBJECT DeviceObject,
					 IN UCHAR MinorFunction)
{
    IoPacket->Request.MajorFunction = IRP_MJ_PNP;
    IoPacket->Request.MinorFunction = MinorFunction;
    IoPacket->Request.Device.Object = DeviceObject;
}

static inline VOID IopPopulateQueryDeviceRelationsRequest(IN PIO_PACKET IoPacket,
							  IN PIO_DEVICE_OBJECT BusDevice,
							  IN DEVICE_RELATION_TYPE Type)
{
    IopPopulatePnpRequest(IoPacket, BusDevice, IRP_MN_QUERY_DEVICE_RELATIONS);
    IoPacket->Request.QueryDeviceRelations.Type = Type;
}

static inline VOID IopPopulateQueryIdRequest(IN PIO_PACKET IoPacket,
					     IN PIO_DEVICE_OBJECT ChildPhyDev,
					     IN BUS_QUERY_ID_TYPE IdType)
{
    IopPopulatePnpRequest(IoPacket, ChildPhyDev, IRP_MN_QUERY_ID);
    IoPacket->Request.QueryId.IdType = IdType;
}

static NTSTATUS IopQueueQueryDeviceRelationsRequest(IN PTHREAD Thread,
						    IN PIO_DEVICE_OBJECT DeviceObject,
						    IN DEVICE_RELATION_TYPE Type,
						    OUT PPENDING_IRP *PendingIrp)
{
    PIO_PACKET IoPacket = NULL;
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
    assert(IoPacket != NULL);
    IopPopulateQueryDeviceRelationsRequest(IoPacket, DeviceObject, Type);
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, Thread, PendingIrp),
	       ExFreePool(IoPacket));
    IopQueueIoPacket(*PendingIrp, Thread);
    return STATUS_SUCCESS;
}

static NTSTATUS IopQueueBusQueryChildDeviceIdRequests(IN PTHREAD Thread,
						      IN PDEVICE_NODE EnumeratorNode,
						      IN BUS_QUERY_ID_TYPE IdType)
{
    LoopOverList(ChildNode, &EnumeratorNode->ChildrenList, DEVICE_NODE, SiblingLink) {
	PIO_PACKET IoPacket = NULL;
	RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
	assert(IoPacket != NULL);
	IopPopulateQueryIdRequest(IoPacket, ChildNode->PhyDevObj, IdType);
	PPENDING_IRP PendingIrp = NULL;
	RET_ERR_EX(IopAllocatePendingIrp(IoPacket, Thread, &PendingIrp),
		   ExFreePool(IoPacket));
	assert(PendingIrp != NULL);
	IopQueueIoPacket(PendingIrp, Thread);
    }
    return STATUS_SUCCESS;
}

static inline NTSTATUS IopDeviceNodeQueueAddDeviceRequest(IN PTHREAD Thread,
						IN PDEVICE_NODE DeviceNode,
						IN PIO_DRIVER_OBJECT DriverObject,
						OUT PPENDING_IRP *pPendingIrp)
{
    PIO_DEVICE_OBJECT PhyDevObj = DeviceNode->PhyDevObj;
    PIO_PACKET IoPacket = NULL;
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
    assert(IoPacket != NULL);
    IoPacket->Request.MajorFunction = IRP_MJ_ADD_DEVICE;
    IoPacket->Request.Device.Object = PhyDevObj;
    IoPacket->Request.AddDevice.PhysicalDeviceInfo = PhyDevObj->DeviceInfo;
    PPENDING_IRP PendingIrp = NULL;
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, Thread, &PendingIrp),
	       ExFreePool(IoPacket));
    assert(PendingIrp != NULL);
    IopQueueAddDeviceRequest(PendingIrp, DriverObject, Thread);
    *pPendingIrp = PendingIrp;
    return STATUS_SUCCESS;
}

static NTSTATUS IopDeviceNodeAddDevice(IN ASYNC_STATE AsyncState,
				       IN PTHREAD Thread,
				       PDEVICE_NODE DeviceNode)
{
    NTSTATUS Status = STATUS_NTOS_BUG;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PIO_DRIVER_OBJECT DriverObject;
	    PPENDING_IRP PendingIrp;
	    ULONG LowerFilterCount;
	    ULONG UpperFilterCount;
	    BOOLEAN FunctionDriverLoaded;
	});

    Locals.LowerFilterCount = 0;
    Locals.UpperFilterCount = 0;
    Locals.FunctionDriverLoaded = FALSE;

check:
    if (Locals.LowerFilterCount < DeviceNode->LowerFilterCount) {
	Locals.DriverObject = DeviceNode->LowerFilterDrivers[Locals.LowerFilterCount++];
	goto load;
    }
    if (!Locals.FunctionDriverLoaded && DeviceNode->FunctionDriverObject != NULL) {
	Locals.DriverObject = DeviceNode->FunctionDriverObject;
	Locals.FunctionDriverLoaded = TRUE;
	goto load;
    }
    if (Locals.UpperFilterCount < DeviceNode->UpperFilterCount) {
	Locals.DriverObject = DeviceNode->UpperFilterDrivers[Locals.UpperFilterCount++];
	goto load;
    }
    Status = STATUS_SUCCESS;
    goto end;

load:
    assert(Locals.DriverObject != NULL);
    IF_ERR_GOTO(end, Status, IopDeviceNodeQueueAddDeviceRequest(Thread, DeviceNode,
								Locals.DriverObject,
								&Locals.PendingIrp));
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	goto end;
    }
    goto check;

end:
    ASYNC_END(AsyncState, Status);
}

static NTSTATUS IopDeviceTreeAddDevices(IN ASYNC_STATE AsyncState,
					IN PTHREAD Thread,
					PDEVICE_NODE RootDeviceNode)
{
    NTSTATUS Status = STATUS_NTOS_BUG;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PDEVICE_NODE ChildNode;
	});

    if (IsListEmpty(&RootDeviceNode->ChildrenList)) {
	goto end;
    }
    Locals.ChildNode = CONTAINING_RECORD(RootDeviceNode->ChildrenList.Flink,
					 DEVICE_NODE, SiblingLink);
more:
    AWAIT_EX(Status, IopDeviceNodeAddDevice, AsyncState, Locals, Thread, Locals.ChildNode);
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(AsyncState, Status);
    }
    if (Locals.ChildNode->SiblingLink.Flink != &RootDeviceNode->ChildrenList) {
	Locals.ChildNode = CONTAINING_RECORD(Locals.ChildNode->SiblingLink.Flink,
					     DEVICE_NODE, SiblingLink);
	goto more;
    }

end:
    ASYNC_END(AsyncState, Status);
}

static NTSTATUS IopQueueQueryResourceRequirementsRequest(IN PTHREAD Thread,
							 IN PIO_DEVICE_OBJECT ChildPhyDev,
							 OUT PPENDING_IRP *PendingIrp)
{
    PIO_PACKET IoPacket = NULL;
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, sizeof(IO_PACKET), &IoPacket));
    assert(IoPacket != NULL);
    IopPopulatePnpRequest(IoPacket, ChildPhyDev, IRP_MN_QUERY_RESOURCE_REQUIREMENTS);
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, Thread, PendingIrp),
	       ExFreePool(IoPacket));
    IopQueueIoPacket(*PendingIrp, Thread);
    return STATUS_SUCCESS;
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

    default:
	assert(FALSE);
    }
    return Res;
}

static NTSTATUS IopQueueStartDeviceRequest(IN PTHREAD Thread,
					   IN PDEVICE_NODE DeviceNode,
					   OUT PPENDING_IRP *PendingIrp)
{
    PIO_PACKET IoPacket = NULL;
    PCM_RESOURCE_LIST Res = DeviceNode->Resources;
    ULONG ResSize = 0;
    if (Res != NULL) {
	ResSize = sizeof(CM_RESOURCE_LIST) + Res->Count * sizeof(CM_FULL_RESOURCE_DESCRIPTOR);
	for (ULONG i = 0; i < Res->Count; i++) {
	    ResSize += Res->List[i].PartialResourceList.Count * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
	}
    }
    ULONG Size = FIELD_OFFSET(IO_PACKET, Request.StartDevice.Data) + 2 * ResSize;
    if (Size < sizeof(IO_PACKET)) {
	Size = sizeof(IO_PACKET);
    }
    RET_ERR(IopAllocateIoPacket(IoPacketTypeRequest, Size, &IoPacket));
    assert(IoPacket != NULL);
    PIO_DEVICE_OBJECT DeviceObject = IopGetTopDevice(DeviceNode->PhyDevObj);
    IopPopulatePnpRequest(IoPacket, DeviceObject, IRP_MN_START_DEVICE);
    IoPacket->Request.StartDevice.ResourceListSize = ResSize;
    IoPacket->Request.StartDevice.TranslatedListSize = ResSize;
    memcpy(IoPacket->Request.StartDevice.Data, Res, ResSize);
    memcpy(&IoPacket->Request.StartDevice.Data[ResSize], Res, ResSize);
    RET_ERR_EX(IopAllocatePendingIrp(IoPacket, Thread, PendingIrp),
	       ExFreePool(IoPacket));
    IopQueueIoPacket(*PendingIrp, Thread);
    return STATUS_SUCCESS;
}

static NTSTATUS IopDeviceNodeAssignResources(IN PDEVICE_NODE Node,
					     IN PVOID Data)
{
    PIO_RESOURCE_REQUIREMENTS_LIST Res = (PIO_RESOURCE_REQUIREMENTS_LIST)Data;
    if (Res == NULL) {
	return STATUS_SUCCESS;
    }
    if (Node->Resources != NULL) {
	ExFreePool(Node->Resources);
    }
    if (Res->ListSize <= MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE) {
	return STATUS_INVALID_PARAMETER;
    }
    ULONG Size = sizeof(CM_RESOURCE_LIST) + sizeof(CM_FULL_RESOURCE_DESCRIPTOR) +
	Res->List[0].Count * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
    Node->Resources = (PCM_RESOURCE_LIST)ExAllocatePoolWithTag(Size, NTOS_IO_TAG);
    if (Node->Resources == NULL) {
	return STATUS_NO_MEMORY;
    }
    Node->Resources->Count = 1;
    Node->Resources->List[0].InterfaceType = Res->InterfaceType;
    Node->Resources->List[0].BusNumber = Res->BusNumber;
    Node->Resources->List[0].PartialResourceList.Version = Res->List[0].Version;
    Node->Resources->List[0].PartialResourceList.Revision = Res->List[0].Revision;
    Node->Resources->List[0].PartialResourceList.Count = Res->List[0].Count;
    for (ULONG i = 0; i < Res->List[0].Count; i++) {
	Node->Resources->List[0].PartialResourceList.PartialDescriptors[i] =
	    IopAssignResource(Res->List[0].Descriptors[i]);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS IopDeviceTreeAssignResources(IN ASYNC_STATE AsyncState,
					     IN PTHREAD Thread,
					     PDEVICE_NODE RootDeviceNode)
{
    NTSTATUS Status = STATUS_NTOS_BUG;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PDEVICE_NODE ChildNode;
	    PPENDING_IRP PendingIrp;
	});

    if (IsListEmpty(&RootDeviceNode->ChildrenList)) {
	goto end;
    }

    /* Query the bus driver for device resource requirements */
    Locals.ChildNode = CONTAINING_RECORD(RootDeviceNode->ChildrenList.Flink,
					 DEVICE_NODE, SiblingLink);
more:
    IF_ERR_GOTO(end, Status,
		IopQueueQueryResourceRequirementsRequest(Thread, Locals.ChildNode->PhyDevObj,
							 &Locals.PendingIrp));
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Failed to query device resource requirements for %s\\%s. Status = 0x%x\n",
		 Locals.ChildNode->DeviceId, Locals.ChildNode->InstanceId,
		 Status);
	/* TODO: Set the device node state to error */
	assert(FALSE);
	goto more;
    }
    IF_ERR_GOTO(end, Status,
		IopDeviceNodeAssignResources(Locals.ChildNode,
					     Locals.PendingIrp->IoResponseData));
    IF_ERR_GOTO(end, Status,
		IopQueueStartDeviceRequest(Thread, Locals.ChildNode,
					   &Locals.PendingIrp));
    AWAIT_EX(Status, KeWaitForSingleObject, AsyncState, Locals, Thread,
	     &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	DbgTrace("Failed to start device node %s\\%s. Status = 0x%x\n",
		 Locals.ChildNode->DeviceId, Locals.ChildNode->InstanceId,
		 Status);
	assert(FALSE);
    } else {
	Locals.ChildNode->DeviceStarted = TRUE;
    }
    if (Locals.ChildNode->SiblingLink.Flink != &RootDeviceNode->ChildrenList) {
	Locals.ChildNode = CONTAINING_RECORD(Locals.ChildNode->SiblingLink.Flink,
					     DEVICE_NODE, SiblingLink);
	goto more;
    }

end:
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
    if (DeviceNode->DriverLoaded) {
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
	    HalVgaPrint(" Driver %s loaded.", DeviceNode->DriverServiceName);
	}
	if (DeviceNode->DeviceStarted) {
	    HalVgaPrint(". STARTED.\n");
	} else {
	    HalVgaPrint(". START FAIL.\n");
	}
    } else if (DeviceNode->DriverServiceName != NULL) {
	HalVgaPrint(" FAILED to load driver %s\n", DeviceNode->DriverServiceName);
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
 * Before calling this system service the session manager must have
 * already loaded the root enumerator driver pnp.sys.
 */
NTSTATUS NtPlugPlayInitialize(IN ASYNC_STATE AsyncState,
			      IN PTHREAD Thread)
{
    NTSTATUS Status;
    ASYNC_BEGIN(AsyncState, Locals, {
	    PIO_DRIVER_OBJECT PnpDriver;
	    PIO_DEVICE_OBJECT RootEnumerator;
	    PPENDING_IRP PendingIrp;
	});
    assert(IsListEmpty(&Thread->PendingIrpList));
    assert(IopRootDeviceNode == NULL);
    Locals.PnpDriver = NULL;
    Locals.RootEnumerator = NULL;
    Locals.PendingIrp = NULL;
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByName(PNP_ROOT_BUS_DRIVER, OBJECT_TYPE_DRIVER,
					NULL, (POBJECT *)&Locals.PnpDriver));
    IF_ERR_GOTO(out, Status,
		ObReferenceObjectByName(PNP_ROOT_ENUMERATOR, OBJECT_TYPE_DEVICE,
					NULL, (POBJECT *)&Locals.RootEnumerator));

    /* Ask the root bus driver about its child devices */
    HalVgaPrint("Enumerating Plug and Play devices...\n");
    assert(Locals.RootEnumerator->DriverObject == Locals.PnpDriver);
    IF_ERR_GOTO(out, Status,
		IopQueueQueryDeviceRelationsRequest(Thread, Locals.RootEnumerator, BusRelations,
						    &Locals.PendingIrp));
    AWAIT(KeWaitForSingleObject, AsyncState, Locals, Thread,
	  &Locals.PendingIrp->IoCompletionEvent.Header, FALSE);

    /* Get the PDO device handles from the response data */
    Status = Locals.PendingIrp->IoResponseStatus.Status;
    if (!NT_SUCCESS(Status)) {
	ASYNC_RETURN(AsyncState, Status);
    }
    ULONG DeviceCount = Locals.PendingIrp->IoResponseStatus.Information;
    PGLOBAL_HANDLE DeviceHandles = (PGLOBAL_HANDLE)Locals.PendingIrp->IoResponseData;
    /* IoResponseData can be NULL in which case the server most likely has run out of memory.
     * Otherwise, it means that bus driver does not have any child devices. Weird flex but ok. */
    if (DeviceHandles == NULL) {
	Status = Locals.PendingIrp->IoResponseDataSize != 0 ? STATUS_NO_MEMORY : STATUS_SUCCESS;
	goto out;
    }
    Locals.PendingIrp->IoResponseData = NULL;
    IopCleanupPendingIrp(Locals.PendingIrp);

    /* Create the root device node and insert the child device nodes under it */
    IF_ERR_GOTO(out, Status,
		IopCreateBusDeviceNode(Locals.PnpDriver, "HTREE\\ROOT", "0", Locals.RootEnumerator,
				       DeviceCount, DeviceHandles, NULL,
				       &IopRootDeviceNode));
    assert(IopRootDeviceNode != NULL);
    IopRootDeviceNode->DriverLoaded = TRUE;

    /* Send the QUERY_ID requests to the physical device objects */
    IF_ERR_GOTO(out, Status,
		IopQueueBusQueryChildDeviceIdRequests(Thread, IopRootDeviceNode,
						      BusQueryDeviceID));
    IF_ERR_GOTO(out, Status,
		IopQueueBusQueryChildDeviceIdRequests(Thread, IopRootDeviceNode,
						      BusQueryInstanceID));
    AWAIT(IopThreadWaitForIoCompletion, AsyncState, Locals, Thread, FALSE, WaitAll);

    /* Record the device IDs that the bus driver has provided */
    LoopOverList(PendingIrp, &Thread->PendingIrpList, PENDING_IRP, Link) {
	assert(PendingIrp->IoPacket->Type == IoPacketTypeRequest);
	assert(PendingIrp->IoPacket->Request.MajorFunction == IRP_MJ_PNP);
	assert(PendingIrp->IoPacket->Request.MinorFunction == IRP_MN_QUERY_ID);
	BUS_QUERY_ID_TYPE IdType = PendingIrp->IoPacket->Request.QueryId.IdType;
	PIO_DEVICE_OBJECT DeviceObject = PendingIrp->IoPacket->Request.Device.Object;
	PDEVICE_NODE DeviceNode = DeviceObject->DeviceNode;
	assert(DeviceNode != NULL);
	IF_ERR_GOTO(out, Status,
		    IopDeviceNodeSetDeviceId(DeviceNode, PendingIrp->IoResponseData, IdType));
    }

    /* Load the device drivers for the root device node and all its children */
    IopDeviceTreeLoadDrivers(IopRootDeviceNode);

    /* Send the AddDevice request to the drivers. Note that we need to wait for lower drivers
     * to complete the request before we can continue sending AddDevice to higher drivers. */
    AWAIT_EX(Status, IopDeviceTreeAddDevices, AsyncState, Locals, Thread, IopRootDeviceNode);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Ask the bus driver for device resource requirements, assign resources, and start devices */
    AWAIT_EX(Status, IopDeviceTreeAssignResources, AsyncState, Locals, Thread, IopRootDeviceNode);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }

    /* Inform the user of the device enumeration result */
    IopPrintDeviceTree(IopRootDeviceNode, 2);

    Status = STATUS_SUCCESS;

out:
    if (!NT_SUCCESS(Status)) {
	if (IopRootDeviceNode) {
	    IopFreeDeviceNode(IopRootDeviceNode);
	    IopRootDeviceNode = NULL;
	}
	if (Locals.RootEnumerator) {
	    ObDereferenceObject(Locals.RootEnumerator);
	}
	if (Locals.PnpDriver) {
	    ObDereferenceObject(Locals.PnpDriver);
	}
    }
    IopCleanupPendingIrpList(Thread);

    ASYNC_END(AsyncState, Status);
}

NTSTATUS NtPlugPlayControl(IN ASYNC_STATE AsyncState,
                           IN PTHREAD Thread,
                           IN PLUGPLAY_CONTROL_CLASS PlugPlayControlClass,
                           IN PVOID Buffer,
                           IN ULONG BufferSize)
{
    UNIMPLEMENTED;
}
