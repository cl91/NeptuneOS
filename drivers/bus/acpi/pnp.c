#include "precomp.h"

#if DBG
static PCHAR PnPMinorFunctionString(UCHAR MinorFunction)
{
    switch (MinorFunction) {
    case IRP_MN_START_DEVICE:
	return "IRP_MN_START_DEVICE";
    case IRP_MN_QUERY_REMOVE_DEVICE:
	return "IRP_MN_QUERY_REMOVE_DEVICE";
    case IRP_MN_REMOVE_DEVICE:
	return "IRP_MN_REMOVE_DEVICE";
    case IRP_MN_CANCEL_REMOVE_DEVICE:
	return "IRP_MN_CANCEL_REMOVE_DEVICE";
    case IRP_MN_STOP_DEVICE:
	return "IRP_MN_STOP_DEVICE";
    case IRP_MN_QUERY_STOP_DEVICE:
	return "IRP_MN_QUERY_STOP_DEVICE";
    case IRP_MN_CANCEL_STOP_DEVICE:
	return "IRP_MN_CANCEL_STOP_DEVICE";
    case IRP_MN_QUERY_DEVICE_RELATIONS:
	return "IRP_MN_QUERY_DEVICE_RELATIONS";
    case IRP_MN_QUERY_INTERFACE:
	return "IRP_MN_QUERY_INTERFACE";
    case IRP_MN_QUERY_CAPABILITIES:
	return "IRP_MN_QUERY_CAPABILITIES";
    case IRP_MN_QUERY_RESOURCES:
	return "IRP_MN_QUERY_RESOURCES";
    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	return "IRP_MN_QUERY_RESOURCE_REQUIREMENTS";
    case IRP_MN_QUERY_DEVICE_TEXT:
	return "IRP_MN_QUERY_DEVICE_TEXT";
    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	return "IRP_MN_FILTER_RESOURCE_REQUIREMENTS";
    case IRP_MN_READ_CONFIG:
	return "IRP_MN_READ_CONFIG";
    case IRP_MN_WRITE_CONFIG:
	return "IRP_MN_WRITE_CONFIG";
    case IRP_MN_EJECT:
	return "IRP_MN_EJECT";
    case IRP_MN_SET_LOCK:
	return "IRP_MN_SET_LOCK";
    case IRP_MN_QUERY_ID:
	return "IRP_MN_QUERY_ID";
    case IRP_MN_QUERY_PNP_DEVICE_STATE:
	return "IRP_MN_QUERY_PNP_DEVICE_STATE";
    case IRP_MN_QUERY_BUS_INFORMATION:
	return "IRP_MN_QUERY_BUS_INFORMATION";
    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
	return "IRP_MN_DEVICE_USAGE_NOTIFICATION";
    case IRP_MN_SURPRISE_REMOVAL:
	return "IRP_MN_SURPRISE_REMOVAL";
    default:
	return "unknown_pnp_irp";
    }
}

PCHAR DbgDeviceRelationString(DEVICE_RELATION_TYPE Type)
{
    switch (Type) {
    case BusRelations:
	return "BusRelations";
    case EjectionRelations:
	return "EjectionRelations";
    case RemovalRelations:
	return "RemovalRelations";
    case TargetDeviceRelation:
	return "TargetDeviceRelation";
    default:
	return "UnKnown Relation";
    }
}

static PCHAR DbgDeviceIDString(BUS_QUERY_ID_TYPE Type)
{
    switch (Type) {
    case BusQueryDeviceID:
	return "BusQueryDeviceID";
    case BusQueryHardwareIDs:
	return "BusQueryHardwareIDs";
    case BusQueryCompatibleIDs:
	return "BusQueryCompatibleIDs";
    case BusQueryInstanceID:
	return "BusQueryInstanceID";
    case BusQueryDeviceSerialNumber:
	return "BusQueryDeviceSerialNumber";
    default:
	return "UnKnown ID";
    }
}
#else
#define PnPMinorFunctionString(MinorFunction) ""
#define DbgDeviceIDString(Type) ""
#endif

static NTSTATUS Bus_StartFdo(IN PDEVICE_OBJECT Fdo,
			     IN PFDO_DEVICE_DATA FdoData, IN PIRP Irp,
			     IN PCM_RESOURCE_LIST ResourceList,
			     IN PCM_RESOURCE_LIST ResourceListTranslated)
{
    PAGED_CODE();
    NTSTATUS Status;
    if (ResourceList == NULL || ResourceListTranslated == NULL) {
	DPRINT1("No allocated resources sent to driver\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    PCM_PARTIAL_RESOURCE_LIST PartialList = &ResourceList->List[0].PartialResourceList;
    if (ResourceList->Count != 1 || PartialList->Count != 1) {
	DPRINT1("Wrong number of allocated resources sent to driver\n");
	return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (PartialList->Version != 1 || PartialList->Revision != 1 ||
	ResourceListTranslated->List[0].PartialResourceList.Version != 1 ||
	ResourceListTranslated->List[0].PartialResourceList.Revision != 1) {
	DPRINT1("Revision mismatch: %u.%u != 1.1 or %u.%u != 1.1\n",
		PartialList->Version, PartialList->Revision,
		ResourceListTranslated->List[0].PartialResourceList.Version,
		ResourceListTranslated->List[0].PartialResourceList.Revision);
	return STATUS_REVISION_MISMATCH;
    }

    PCM_PARTIAL_RESOURCE_DESCRIPTOR Res = &PartialList->PartialDescriptors[0];
    if (Res->Type != CmResourceTypeMemory) {
	DPRINT1("Invalid resource type %d\n", Res->Type);
	return STATUS_DEVICE_ENUMERATION_ERROR;
    }
    if (!Res->Memory.Start.QuadPart || !Res->Memory.Length) {
	DPRINT1("Invalid IO memory 0x%llx length 0x%x\n",
		Res->Memory.Start.QuadPart, Res->Memory.Length);
	assert(FALSE);
	return STATUS_DEVICE_ENUMERATION_ERROR;
    }
    AcpiOsSetBusFdo(Fdo);
    AcpiOsSetRootSystemTable(Res->Memory.Start.QuadPart,
			     Res->Memory.Length);

    FdoData->Common.DevicePowerState = PowerDeviceD0;
    POWER_STATE PowerState = { .DeviceState = PowerDeviceD0 };
    PoSetPowerState(FdoData->Common.Self, DevicePowerState, PowerState);

    SET_NEW_PNP_STATE(FdoData->Common, Started);

    ACPI_STATUS AcpiStatus = AcpiInitializeSubsystem();
    if (ACPI_FAILURE(AcpiStatus)) {
	DPRINT1("Unable to AcpiInitializeSubsystem\n");
	return STATUS_UNSUCCESSFUL;
    }

    AcpiStatus = AcpiInitializeTables(NULL, 16, 0);
    if (ACPI_FAILURE(AcpiStatus)) {
	DPRINT1("Unable to AcpiInitializeTables\n");
	return STATUS_UNSUCCESSFUL;
    }

    AcpiStatus = AcpiLoadTables();
    if (ACPI_FAILURE(AcpiStatus)) {
	DPRINT1("Unable to AcpiLoadTables\n");
	AcpiTerminate();
	return STATUS_UNSUCCESSFUL;
    }

    Status = AcpiCreateVolatileRegistryTables();
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Unable to create ACPI tables in registry\n");
    }

    DPRINT("Acpi subsystem init\n");
    /* Initialize ACPI bus manager */
    AcpiStatus = AcpiBusInitializeManager();
    if (!ACPI_SUCCESS(AcpiStatus)) {
	DPRINT1("AcpiBusInitializeManager() failed with status 0x%X\n", AcpiStatus);
	AcpiTerminate();
	return STATUS_UNSUCCESSFUL;
    }
    Status = Bus_EnumerateDevices(FdoData);

    return Status;
}

static NTSTATUS Bus_StopFdo(IN PDEVICE_OBJECT Fdo,
			    IN PFDO_DEVICE_DATA FdoData, IN PIRP Irp)
{
    AcpiBusTerminateManager();
    /* TODO: undo Bus_StartFdo */
    return STATUS_SUCCESS;
}

static NTSTATUS Bus_FDO_PnP(PDEVICE_OBJECT DeviceObject,
			    PIRP Irp,
			    PIO_STACK_LOCATION IrpStack,
			    PFDO_DEVICE_DATA DeviceData)
{
    PAGED_CODE();
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG Length, PrevCount, NumPdosPresent;
    PLIST_ENTRY Entry;
    PPDO_DEVICE_DATA PdoData;
    PDEVICE_RELATIONS Relations, OldRelations;

    switch (IrpStack->MinorFunction) {
    case IRP_MN_START_DEVICE:
	Status = Bus_StartFdo(DeviceObject, DeviceData, Irp,
			      IrpStack->Parameters.StartDevice.AllocatedResources,
			      IrpStack->Parameters.StartDevice.AllocatedResourcesTranslated);
	break;

    case IRP_MN_QUERY_STOP_DEVICE:
	//
	// The PnP manager is trying to stop the device
	// for resource rebalancing.
	//
	SET_NEW_PNP_STATE(DeviceData->Common, StopPending);
	Status = Bus_StopFdo(DeviceObject, DeviceData, Irp);
	break;

    case IRP_MN_CANCEL_STOP_DEVICE:
	//
	// The PnP Manager sends this IRP, at some point after an
	// IRP_MN_QUERY_STOP_DEVICE, to inform the drivers for a
	// device that the device will not be stopped for
	// resource reconfiguration.
	//
	//
	// First check to see whether you have received cancel-stop
	// without first receiving a query-stop. This could happen if
	//  someone above us fails a query-stop and passes down the subsequent
	// cancel-stop.
	//

	if (StopPending == DeviceData->Common.DevicePnPState) {
	    //
	    // We did receive a query-stop, so restore.
	    //
	    RESTORE_PREVIOUS_PNP_STATE(DeviceData->Common);
	    ASSERT(DeviceData->Common.DevicePnPState == Started);
	}
	Irp->IoStatus.Status = STATUS_SUCCESS; // We must not fail the IRP.
	break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
	DPRINT("\tQueryDeviceRelation Type: %s\n",
	       DbgDeviceRelationString(IrpStack->Parameters.QueryDeviceRelations.Type));

	if (BusRelations != IrpStack->Parameters.QueryDeviceRelations.Type) {
	    //
	    // We don't support any other Device Relations
	    //
	    break;
	}

	OldRelations = (PDEVICE_RELATIONS)Irp->IoStatus.Information;
	if (OldRelations) {
	    PrevCount = OldRelations->Count;
	    if (!DeviceData->NumPDOs) {
		//
		// There is a device relations struct already present and we have
		// nothing to add to it, so just call IoSkip and IoCall
		//
		break;
	    }
	} else {
	    PrevCount = 0;
	}

	//
	// Calculate the number of PDOs actually present on the bus
	//
	NumPdosPresent = 0;
	for (Entry = DeviceData->ListOfPDOs.Flink; Entry != &DeviceData->ListOfPDOs;
	     Entry = Entry->Flink) {
	    PdoData = CONTAINING_RECORD(Entry, PDO_DEVICE_DATA, Link);
	    NumPdosPresent++;
	}

	//
	// Need to allocate a new relations structure and add our
	// PDOs to it.
	//
	Length = sizeof(DEVICE_RELATIONS) +
		 ((NumPdosPresent + PrevCount) * sizeof(PDEVICE_OBJECT));

	Relations = ExAllocatePoolWithTag(NonPagedPool, Length, ACPI_TAG);

	if (NULL == Relations) {
	    //
	    // Fail the IRP
	    //
	    Irp->IoStatus.Status = Status = STATUS_INSUFFICIENT_RESOURCES;
	    return Status;
	}

	//
	// Copy in the device objects so far
	//
	if (PrevCount) {
	    RtlCopyMemory(Relations->Objects, OldRelations->Objects,
			  PrevCount * sizeof(PDEVICE_OBJECT));
	}

	Relations->Count = PrevCount + NumPdosPresent;

	//
	// For each PDO present on this bus add a pointer to the device relations
	// buffer, being sure to take out a reference to that object.
	// The Plug & Play system will dereference the object when it is done
	// with it and free the device relations buffer.
	//

	for (Entry = DeviceData->ListOfPDOs.Flink; Entry != &DeviceData->ListOfPDOs;
	     Entry = Entry->Flink) {
	    PdoData = CONTAINING_RECORD(Entry, PDO_DEVICE_DATA, Link);
	    Relations->Objects[PrevCount] = PdoData->Common.Self;
	    // ObReferenceObject(pdoData->Common.Self);
	    PrevCount++;
	}

	DPRINT("\t#PDOs present = %d\n\t#PDOs reported = %d\n", DeviceData->NumPDOs,
	       Relations->Count);

	//
	// Replace the relations structure in the IRP with the new
	// one.
	//
	if (OldRelations) {
	    ExFreePoolWithTag(OldRelations, 0);
	}
	Irp->IoStatus.Information = (ULONG_PTR)Relations;

	//
	// Set up and pass the IRP further down the stack
	//
	Status = STATUS_SUCCESS;
	break;

    default:
	// In the default case we simply fail the IRP.
	break;
    }

    Irp->IoStatus.Status = Status;
    return Status;
}

NTAPI NTSTATUS Bus_PnP(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PAGED_CODE();
    PIO_STACK_LOCATION IrpStack;
    NTSTATUS Status;
    PCOMMON_DEVICE_DATA CommonData;

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    ASSERT(IRP_MJ_PNP == IrpStack->MajorFunction);

    CommonData = (PCOMMON_DEVICE_DATA)DeviceObject->DeviceExtension;

    if (CommonData->IsFDO) {
	DPRINT("FDO %s IRP:0x%p\n", PnPMinorFunctionString(IrpStack->MinorFunction), Irp);
	//
	// Request is for the bus FDO
	//
	Status = Bus_FDO_PnP(DeviceObject, Irp, IrpStack, (PFDO_DEVICE_DATA)CommonData);
    } else {
	DPRINT("PDO %s IRP: 0x%p\n", PnPMinorFunctionString(IrpStack->MinorFunction),
	       Irp);
	//
	// Request is for the child PDO.
	//
	Status = Bus_PDO_PnP(DeviceObject, Irp, IrpStack, (PPDO_DEVICE_DATA)CommonData);
    }

    return Status;
}
