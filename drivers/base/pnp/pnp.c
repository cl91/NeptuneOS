/*
 * PNP Root Enumerator (Root Bus) Driver
 *
 * This driver implements the root bus, also known as the root enumerator,
 * of the Plug and Play subsystem. On Windows this is part of the NTOSKRNL
 * PNP manager. Here in NeptuneOS the root bus is a standard PNP driver
 * that implements the PNP bus driver interface.
 */

#include <stdio.h>
#include <assert.h>
#include <ntddk.h>
#include <wchar.h>
#include "arc.h"

#define PNP_ROOT_ENUMERATOR_U	L"\\Device\\pnp"

/* On machines with a broken ACPI BIOS that does not implement the _FDC
 * method correctly, you should set this to TRUE so the PnP root enumerator
 * will enumerate the floppy controller.
 * TODO: Read this from the boot-time configuration database? */
static BOOLEAN ForceFdcEnumeration;
/* Likewise, set this to TRUE if you want to for the PnP root enumerator
 * to enumerate the i8042 controller. */
static BOOLEAN ForceI8042Enumeration;

typedef struct _PNP_DEVICE {
    // Device Type
    DEVICE_TYPE DeviceType;
    // Physical device object
    PDEVICE_OBJECT Pdo;
    // Device ID
    PCWSTR DeviceID;
    // Instance ID
    PCWSTR InstanceID;
    // Device description
    PCWSTR DeviceDescription;
    // Resource descriptors
    PIO_RESOURCE_DESCRIPTOR ResourceDescriptors;
    // Size of the resource descriptor array
    ULONG ResourceDescriptorSize;
    // Number of array elements in the resource descriptor array
    ULONG ResourceDescriptorCount;
    // Resource requirement list
    PIO_RESOURCE_REQUIREMENTS_LIST ResourceRequirementsList;
} PNP_DEVICE, *PPNP_DEVICE;

typedef struct _PNP_DEVICE_EXTENSION {
    PPNP_DEVICE DeviceInfo; /* If NULL, device is the root enumerator */
} PNP_DEVICE_EXTENSION, *PPNP_DEVICE_EXTENSION;

static IO_RESOURCE_DESCRIPTOR AcpiResourceDescriptors[] = {
    {
	.Option = IO_RESOURCE_PREFERRED,
	.Type = CmResourceTypeMemory,
	.ShareDisposition = CmResourceShareDeviceExclusive,
	.Flags = 0,
    },
};

static IO_RESOURCE_DESCRIPTOR I8042ResourceDescriptors[] = {
    {
	.Option = IO_RESOURCE_PREFERRED,
	.Type = CmResourceTypeInterrupt,
	.ShareDisposition = CmResourceShareDeviceExclusive,
	.Flags = 0,
	.Interrupt = {
	    .MinimumVector = 1, /* IRQ1 is the first keyboard IRQ */
	    .MaximumVector = 1
	}
    },

    {
	.Option = IO_RESOURCE_PREFERRED,
	.Type = CmResourceTypePort,
	.ShareDisposition = CmResourceShareDeviceExclusive,
	.Flags = CM_RESOURCE_PORT_IO,
	.Port = {
	    .Length = 1,
	    .MinimumAddress = { .QuadPart = 0x60ULL }, /* Data port must be first */
	    .MaximumAddress = { .QuadPart = 0x60ULL }
	}
    },

    {
	.Option = IO_RESOURCE_PREFERRED,
	.Type = CmResourceTypePort,
	.ShareDisposition = CmResourceShareDeviceExclusive,
	.Flags = CM_RESOURCE_PORT_IO,
	.Port = {
	    .Length = 1,
	    .MinimumAddress = { .QuadPart = 0x64ULL }, /* Control port must be second */
	    .MaximumAddress = { .QuadPart = 0x64ULL }
	}
    },
};

static IO_RESOURCE_DESCRIPTOR FdcResourceDescriptors[] = {
    {
	.Option = IO_RESOURCE_PREFERRED,
	.Type = CmResourceTypeInterrupt,
	.ShareDisposition = CmResourceShareUndetermined,
	.Flags = CM_RESOURCE_INTERRUPT_LATCHED,
	.Interrupt = {
	    .MinimumVector = 6, /* IRQ6 is the floppy disk controller IRQ */
	    .MaximumVector = 6,
	}
    },

    {
	.Option = IO_RESOURCE_PREFERRED,
	.Type = CmResourceTypePort,
	.ShareDisposition = CmResourceShareDeviceExclusive,
	.Flags = CM_RESOURCE_PORT_IO,
	.Port = {
	    .Length = 8,
	    .MinimumAddress = { .QuadPart = 0x03F0ULL },
	    .MaximumAddress = { .QuadPart = 0x03F8ULL },
	}
    },

    {
	.Option = IO_RESOURCE_PREFERRED,
	.Type = CmResourceTypeDma,
	.ShareDisposition = CmResourceShareUndetermined,
	.Flags = 0,
	.Dma = {
	    .MinimumChannel = 2,
	    .MaximumChannel = 2,
	}
    }
};

#define DECLARE_RESOURCE_DESCRIPTORS(Desc)		\
    .ResourceDescriptors = Desc,			\
	.ResourceDescriptorSize = sizeof(Desc),		\
	.ResourceDescriptorCount = ARRAYSIZE(Desc)

static PNP_DEVICE AcpiBus = {
    .DeviceType = FILE_DEVICE_ACPI,
    .DeviceID = L"ACPI",
    .InstanceID = L"0",
    DECLARE_RESOURCE_DESCRIPTORS(AcpiResourceDescriptors)
};

static PNP_DEVICE I8042Controller = {
    .DeviceType = FILE_DEVICE_8042_PORT,
    .DeviceID = L"PNP0303",
    .InstanceID = L"0",
    DECLARE_RESOURCE_DESCRIPTORS(I8042ResourceDescriptors)
};

static PNP_DEVICE FloppyController = {
    .DeviceType = FILE_DEVICE_CONTROLLER,
    .DeviceID = L"PNP0700",
    .InstanceID = L"0",
    DECLARE_RESOURCE_DESCRIPTORS(FdcResourceDescriptors)
};

static NTSTATUS IsaPnpSetupFdcControllerKey(IN PCONFIGURATION_COMPONENT_DATA BusKey,
					    OUT PCONFIGURATION_COMPONENT_DATA *ControllerKey)
{
    /* We need to build the configuration manager partial resource list first
     * becasue the PnpDevices array has the IO manager version. */
    ULONG Size = sizeof(CM_PARTIAL_RESOURCE_LIST) + ARRAYSIZE(FdcResourceDescriptors) * sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR);
    PCM_PARTIAL_RESOURCE_LIST PartialResourceList = ExAllocatePool(Size);
    if (PartialResourceList == NULL) {
        ERR_(ISAPNP, "Failed to allocate resource list\n");
        return STATUS_NO_MEMORY;
    }

    /* Initialize resource descriptor */
    RtlZeroMemory(PartialResourceList, Size);
    PartialResourceList->Version = 1;
    PartialResourceList->Revision = 1;
    PartialResourceList->Count = ARRAYSIZE(FdcResourceDescriptors);

    for (ULONG i = 0; i < ARRAYSIZE(FdcResourceDescriptors); i++) {
	PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor = &PartialResourceList->PartialDescriptors[i];
	PartialDescriptor->Type = FdcResourceDescriptors[i].Type;
	PartialDescriptor->ShareDisposition = FdcResourceDescriptors[i].ShareDisposition;
	PartialDescriptor->Flags = FdcResourceDescriptors[i].Flags;

	/* Set IO Port */
	switch (PartialDescriptor->Type) {
	case CmResourceTypePort:
	    PartialDescriptor->Port.Start.QuadPart = FdcResourceDescriptors[i].Port.MinimumAddress.QuadPart;
	    PartialDescriptor->Port.Length = FdcResourceDescriptors[i].Port.Length;
	    break;

	case CmResourceTypeInterrupt:
	    PartialDescriptor->Interrupt.Level = FdcResourceDescriptors[i].Interrupt.MinimumVector;
	    PartialDescriptor->Interrupt.Vector = FdcResourceDescriptors[i].Interrupt.MinimumVector;
	    PartialDescriptor->Interrupt.Affinity = 0xFFFFFFFF;
	    break;

	case CmResourceTypeDma:
	    PartialDescriptor->Dma.Channel = FdcResourceDescriptors[i].Dma.MinimumChannel;
	    PartialDescriptor->Dma.Port = 0;
	    break;

	default:
	    assert(FALSE);
	}
    }

    /* Create floppy disk controller */
    return ArcCreateComponentKey(BusKey,
				 ControllerClass,
				 DiskController,
				 Output | Input,
				 0x0,
				 0xFFFFFFFF,
				 NULL,
				 PartialResourceList,
				 Size,
				 ControllerKey);
}

static NTSTATUS IsaPnpSetupFdcPeripheralKey(IN PCONFIGURATION_COMPONENT_DATA BusKey,
					    IN PCONFIGURATION_COMPONENT_DATA ControllerKey)
{
    ULONG Size = sizeof(CM_PARTIAL_RESOURCE_LIST) + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) + sizeof(CM_FLOPPY_DEVICE_DATA);
    PCM_PARTIAL_RESOURCE_LIST PartialResourceList = ExAllocatePool(Size);
    if (PartialResourceList == NULL) {
        ERR_(ISAPNP, "Failed to allocate resource list\n");
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(PartialResourceList, Size);
    PartialResourceList->Version = 1;
    PartialResourceList->Revision = 1;
    PartialResourceList->Count = 1;

    PCM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptor = &PartialResourceList->PartialDescriptors[0];
    PartialDescriptor->Type = CmResourceTypeDeviceSpecific;
    PartialDescriptor->ShareDisposition = CmResourceShareUndetermined;
    PartialDescriptor->DeviceSpecificData.DataSize = sizeof(CM_FLOPPY_DEVICE_DATA);

    /* Floppy data follows immediately after the partial descriptor above. */
    PCM_FLOPPY_DEVICE_DATA FloppyData = (PCM_FLOPPY_DEVICE_DATA)&PartialResourceList->PartialDescriptors[1];
    UCHAR FloppyType = 4;
    ULONG MaxDensity[6] = {0, 360, 1200, 720, 1440, 2880};
    FloppyData->Version = 2;
    FloppyData->Revision = 0;
    FloppyData->MaxDensity = MaxDensity[FloppyType];
    FloppyData->MountDensity = 0;
    /* From OSDEV wiki: HUT ("Head Unload Time") is the time the controller
     * should wait before deactivating the head. To calculate the value for
     * the HUT setting from a given time, use
     *   HUT_value = milliseconds * data_rate / 8000000.
     * For a 1.44 MB floppy and a 240 mS delay this gives
     *   HUT_value = 24 * 500000 / 8000000
     * or 15. However, it seems likely that the smartest thing to do is
     * just to set the value to 0 (which is the maximum in any mode).  */
    FloppyData->StepRateHeadUnloadTime = 0;
    FloppyData->MaximumTrackValue = (FloppyType == 1) ? 39 : 79;
    FloppyData->DataTransferRate = 0;

    PCONFIGURATION_COMPONENT_DATA PeripheralKey = NULL;
    return ArcCreateComponentKey(ControllerKey,
				 PeripheralClass,
				 FloppyDiskPeripheral,
				 Input | Output,
				 0,
				 0xFFFFFFFF,
				 "FLOPPY0",
				 PartialResourceList,
				 Size,
				 &PeripheralKey);
}

/*
 * For now we will simply hard-code the 1.44MB A: drive. Eventually this
 * should be done by the ACPI enumerator which will invoke the _FDE ACPI
 * method to enumerate the floopy disk controllers present on the system.
 * Note that on Windows for BIOS systems there is an additional mechanism
 * for floppy disk controller detection, via the BIOS INT 0x1e. On NT 5.x
 * and before this is done by ntdetect.com which was loaded and invoked
 * by NTLDR prior to loading the NTOSKRNL (on ReactOS ntdetect is part of
 * the ReactOS loader freeldr). This is removed in Vista+. On Neptune OS
 * we do not plan to support this type of FDC enumeration. Only ACPI will
 * be supported.
 */
static NTSTATUS IsaPnpDetectFDC(IN PCONFIGURATION_COMPONENT_DATA BusKey)
{
    PCONFIGURATION_COMPONENT_DATA ControllerKey = NULL;
    NTSTATUS Status = IsaPnpSetupFdcControllerKey(BusKey, &ControllerKey);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    return IsaPnpSetupFdcPeripheralKey(BusKey, ControllerKey);
}

static NTSTATUS PnpInitProcessorDatabase(IN PCONFIGURATION_COMPONENT_DATA SystemKey,
					 IN PSYSTEM_BASIC_INFORMATION BasicInfo,
					 IN PSYSTEM_PROCESSOR_INFORMATION CpuInfo)
{
    /* Query basic system information and basic processor information */
    NTSTATUS Status = NtQuerySystemInformation(SystemBasicInformation,
					       BasicInfo, sizeof(*BasicInfo), NULL);
    if (!NT_SUCCESS(Status))
	return Status;
    Status = NtQuerySystemInformation(SystemProcessorInformation,
				      CpuInfo, sizeof(*CpuInfo), NULL);
    if (!NT_SUCCESS(Status))
	return Status;

    for (ULONG i = 0; i < BasicInfo->NumberOfProcessors; i++) {
	/* Build full ID string for each processor */
	CHAR Buffer[128];
	PCHAR FamilyId = "Unknown";
	if (CpuInfo->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
	    FamilyId = "x86";
	} else if (CpuInfo->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
	    FamilyId = "AMD64";
	}
	snprintf(Buffer, sizeof(Buffer), "%s Family %u Model %u Stepping %u",
		 FamilyId, CpuInfo->ProcessorLevel, CpuInfo->ProcessorRevision >> 8,
		 CpuInfo->ProcessorRevision & 0xff);
	/* Setup the Configuration Entry for the Processor */
	PCONFIGURATION_COMPONENT_DATA ConfigData;
	Status = ArcCreateComponentKey(SystemKey, ProcessorClass, CentralProcessor,
				       0, i, AFFINITY_MASK(i), Buffer, NULL, 0,
				       &ConfigData);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
	/* Add the same configuration entry for the floating point processor.
	 * We require i686 so FPU is always available. */
	Status = ArcCreateComponentKey(SystemKey, ProcessorClass, FloatingPointProcessor,
				       0, i, AFFINITY_MASK(i), Buffer, NULL, 0,
				       &ConfigData);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }
    return STATUS_SUCCESS;
}

/* Add the string value to the registry under the given key */
static NTSTATUS PnpSetRegStringValue(IN HANDLE KeyHandle,
				     IN PCWSTR ValueNameBuffer,
				     IN PCSTR ValueStringBuffer)
{
    ANSI_STRING ValueStringA;
    UNICODE_STRING ValueString;
    RtlInitAnsiString(&ValueStringA, ValueStringBuffer);
    NTSTATUS Status = RtlAnsiStringToUnicodeString(&ValueString, &ValueStringA, TRUE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    UNICODE_STRING ValueName;
    RtlInitUnicodeString(&ValueName, ValueNameBuffer);
    Status = NtSetValueKey(KeyHandle, &ValueName, 0, REG_SZ, ValueString.Buffer,
			   ValueString.Length + sizeof(UNICODE_NULL));
    RtlFreeUnicodeString(&ValueString);
    return Status;
}

static NTSTATUS PnpPopulateProcessorDatabase(IN PSYSTEM_BASIC_INFORMATION BasicInfo,
					     IN PSYSTEM_PROCESSOR_INFORMATION CpuInfo)
{
    for (ULONG i = 0; i < BasicInfo->NumberOfProcessors; i++) {
	/* Open the CPU hardware description key */
	WCHAR Buffer[256];
	_snwprintf(Buffer, sizeof(Buffer), L"%ws\\System\\CentralProcessor\\%d",
		   HARDWARE_DESCRIPTION_KEY, i);
	UNICODE_STRING KeyName;
	RtlInitUnicodeString(&KeyName, Buffer);
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &KeyName, OBJ_CASE_INSENSITIVE, NULL,
				   NULL);
	HANDLE KeyHandle = NULL;
	NTSTATUS Status = NtOpenKey(&KeyHandle, KEY_READ | KEY_WRITE, &ObjectAttributes);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}

	CHAR AnsiBuffer[64];
	memset(AnsiBuffer, 0, sizeof(AnsiBuffer));
#if defined(_M_IX86) || defined(_M_AMD64)
	/* Check if we have extended CPUID that supports name ID. If we do,
	 * populate the ProcessorNameString value in the registry. */
	int CPUID[4];
	__cpuid(CPUID, 0x80000000);
	int ExtendedId = CPUID[0];
	PCHAR Ptr = AnsiBuffer;
	if (ExtendedId >= 0x80000004) {
	    /* Do all the CPUIDs required to get the full name */
	    for (ExtendedId = 2; ExtendedId <= 4; ExtendedId++) {
		/* Do the CPUID and save the name string */
		__cpuid(CPUID, 0x80000000 | ExtendedId);
		((PULONG)Ptr)[0] = CPUID[0];
		((PULONG)Ptr)[1] = CPUID[1];
		((PULONG)Ptr)[2] = CPUID[2];
		((PULONG)Ptr)[3] = CPUID[3];
		/* Go to the next name string */
		Ptr += 16;
	    }
	}
	Status = PnpSetRegStringValue(KeyHandle, L"ProcessorNameString", AnsiBuffer);
#elif defined(_M_ARM64)
	Status = PnpSetRegStringValue(KeyHandle, L"ProcessorNameString", "ARMv8 Processor");
#else
#error "Unsupported architecture"
#endif
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}

#if defined(_M_IX86) || defined(_M_AMD64)
        /* Get the Vendor ID and add it to the registry */
	__cpuid(CPUID, 0);
	memset(AnsiBuffer, 0, sizeof(AnsiBuffer));
	Ptr = AnsiBuffer;
	((PULONG)Ptr)[0] = CPUID[1];
	((PULONG)Ptr)[1] = CPUID[3];
	((PULONG)Ptr)[2] = CPUID[2];
	Status = PnpSetRegStringValue(KeyHandle, L"VendorIdentifier", AnsiBuffer);
#elif defined(_M_ARM64)
	Status = PnpSetRegStringValue(KeyHandle, L"VendorIdentifier", "ARM");
#else
#error "Unsupported architecture"
#endif
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}

        /* Add the FeatureBits to the registry. */
	Status = NtSetValueKeyA(KeyHandle, "FeatureSet", 0, REG_DWORD,
				&CpuInfo->ProcessorFeatureBits, 4);
    out:
	NtClose(KeyHandle);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }
    return STATUS_SUCCESS;
}

static NTSTATUS PnpInitHardwareDatabase()
{
    PCONFIGURATION_COMPONENT_DATA SystemKey = NULL;
    NTSTATUS Status = ArcCreateSystemKey(&SystemKey);
    if (!NT_SUCCESS(Status)) {
        ERR_(ISAPNP, "Failed to create root ARC configuration key, status = 0x%x\n",
	     Status);
	return Status;
    }

    SYSTEM_BASIC_INFORMATION BasicInfo;
    SYSTEM_PROCESSOR_INFORMATION CpuInfo;
    Status = PnpInitProcessorDatabase(SystemKey, &BasicInfo, &CpuInfo);
    if (!NT_SUCCESS(Status)) {
        ERR_(PNPMGR, "Failed to initialize processor database, status = 0x%x\n", Status);
	return Status;
    }

    /* Set 'Configuration Data' value */
    ULONG Size = sizeof(CM_PARTIAL_RESOURCE_LIST);
    PCM_PARTIAL_RESOURCE_LIST PartialResourceList;
    PartialResourceList = ExAllocatePool(Size);
    if (PartialResourceList == NULL) {
        ERR_(ISAPNP, "Failed to allocate resource descriptor\n");
        Status = STATUS_NO_MEMORY;
	goto out;
    }

    /* Initialize resource descriptor */
    RtlZeroMemory(PartialResourceList, Size);
    PartialResourceList->Version = 1;
    PartialResourceList->Revision = 1;
    PartialResourceList->Count = 0;

    /* Create new bus key */
    PCONFIGURATION_COMPONENT_DATA BusKey = NULL;
    Status = ArcCreateComponentKey(SystemKey,
				   AdapterClass,
				   MultiFunctionAdapter,
				   0x0,
				   0x0,
				   0xFFFFFFFF,
				   "ISA",
				   PartialResourceList,
				   Size,
				   &BusKey);
    if (!NT_SUCCESS(Status)) {
        ERR_(ISAPNP, "Failed to create ISA bus key, status = 0x%x\n", Status);
	goto out;
    }

    Status = IsaPnpDetectFDC(BusKey);
    if (!NT_SUCCESS(Status)) {
        ERR_(ISAPNP, "Failed to detect floppy disk controllers, error = 0x%x\n",
	     Status);
	goto out;
    }

    Status = ArcSetupHardwareDescriptionDatabase(SystemKey);
    if (!NT_SUCCESS(Status)) {
        ERR_(PNPMGR, "Failed to setup hardware description database, error = 0x%x\n",
	     Status);
	goto out;
    }

    Status = PnpPopulateProcessorDatabase(&BasicInfo, &CpuInfo);
    if (!NT_SUCCESS(Status)) {
        ERR_(PNPMGR, "Failed to setup processor database, error = 0x%x\n",
	     Status);
	goto out;
    }

out:
    if (SystemKey != NULL) {
	ArcDestroySystemKey(SystemKey);
    }
    return Status;
}

static NTSTATUS PnpCreatePdo(IN PPNP_DEVICE PnpDevice,
			     IN PDRIVER_OBJECT DriverObject)
{
    if (PnpDevice->Pdo != NULL) {
	return STATUS_ALREADY_INITIALIZED;
    }
    NTSTATUS Status = IoCreateDevice(DriverObject, sizeof(PNP_DEVICE_EXTENSION),
				     NULL, PnpDevice->DeviceType,
				     FILE_AUTOGENERATED_DEVICE_NAME,
				     FALSE, &PnpDevice->Pdo);
    if (!NT_SUCCESS(Status)) {
	DPRINT("IoCreateDevice() failed with status 0x%08x\n",
	       Status);
	return Status;
    }
    PPNP_DEVICE_EXTENSION DeviceExtension = PnpDevice->Pdo->DeviceExtension;
    DeviceExtension->DeviceInfo = PnpDevice;
    return STATUS_SUCCESS;
}

/*
 * PNP QueryDeviceRelations handler for the root enumerator device
 */
static NTSTATUS PnpRootQueryDeviceRelations(IN PDEVICE_OBJECT DeviceObject,
					    IN PIRP Irp)
{
    DPRINT("PnpRootQueryDeviceRelations(FDO %p, Irp %p)\n",
	   DeviceObject, Irp);

    PIO_STACK_LOCATION IoSp = IoGetCurrentIrpStackLocation(Irp);
    if (IoSp->Parameters.QueryDeviceRelations.Type != BusRelations) {
	return STATUS_INVALID_PARAMETER;
    }

    ULONG NumDevices = 1;
    if (ForceI8042Enumeration) {
	NumDevices++;
    }
    if (ForceFdcEnumeration) {
	NumDevices++;
    }
    ULONG Size = sizeof(DEVICE_RELATIONS) + NumDevices * sizeof(PDEVICE_OBJECT);
    PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)ExAllocatePool(Size);
    NTSTATUS Status = STATUS_SUCCESS;
    if (!Relations) {
	DPRINT("ExAllocatePool() failed\n");
	return STATUS_NO_MEMORY;
    }
    Relations->Count = NumDevices;

    ULONG Count = 0;
    Status = PnpCreatePdo(&AcpiBus, DeviceObject->DriverObject);
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    Relations->Objects[Count++] = AcpiBus.Pdo;

    if (ForceI8042Enumeration) {
	Status = PnpCreatePdo(&I8042Controller, DeviceObject->DriverObject);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	Relations->Objects[Count++] = I8042Controller.Pdo;
    }

    if (ForceFdcEnumeration) {
	Status = PnpCreatePdo(&FloppyController, DeviceObject->DriverObject);
	if (!NT_SUCCESS(Status)) {
	    goto out;
	}
	Relations->Objects[Count++] = FloppyController.Pdo;
    }

out:
    if (NT_SUCCESS(Status)) {
	Irp->IoStatus.Information = (ULONG_PTR)Relations;
    } else {
	Irp->IoStatus.Information = 0;
	assert(Relations != NULL);
	ExFreePool(Relations);
    }

    return Status;
}

/*
 * PNP QueryDeviceRelations handler for the child devices
 */
static NTSTATUS PnpDeviceQueryDeviceRelations(IN PDEVICE_OBJECT DeviceObject,
					      IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
	return STATUS_INVALID_DEVICE_REQUEST;

    DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_DEVICE_RELATIONS / TargetDeviceRelation\n");
    ULONG Size = sizeof(DEVICE_RELATIONS) + sizeof(PDEVICE_OBJECT);
    PDEVICE_RELATIONS Relations = (PDEVICE_RELATIONS)ExAllocatePool(Size);
    if (!Relations) {
	DPRINT("ExAllocatePoolWithTag() failed\n");
	return STATUS_NO_MEMORY;
    } else {
	Relations->Count = 1;
	Relations->Objects[0] = DeviceObject;
	Irp->IoStatus.Information = (ULONG_PTR)Relations;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS PnpDeviceQueryCapabilities(IN PDEVICE_OBJECT DeviceObject,
					   IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpDeviceRemoveDevice(IN PDEVICE_OBJECT DeviceObject,
				      IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpDeviceQueryPnpDeviceState(IN PDEVICE_OBJECT DeviceObject,
					     IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpDeviceQueryResources(IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpDeviceQueryResourceRequirements(IN PDEVICE_OBJECT DeviceObject,
						   IN PIRP Irp)
{
    PPNP_DEVICE_EXTENSION DeviceExtension = (PPNP_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    assert(DeviceExtension != NULL);
    assert(DeviceExtension->DeviceInfo != NULL);
    PIO_RESOURCE_REQUIREMENTS_LIST ResList = DeviceExtension->DeviceInfo->ResourceRequirementsList;

    if (ResList) {
	/* Copy existing resource requirement list */
	PIO_RESOURCE_REQUIREMENTS_LIST Dest =  ExAllocatePool(ResList->ListSize);
	if (!Dest)
	    return STATUS_NO_MEMORY;
	RtlCopyMemory(Dest, ResList, ResList->ListSize);
	Irp->IoStatus.Information = (ULONG_PTR)Dest;
    } else {
	Irp->IoStatus.Information = 0;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS PnpDeviceQueryId(IN PDEVICE_OBJECT Pdo,
				 IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PPNP_DEVICE_EXTENSION DeviceExtension = (PPNP_DEVICE_EXTENSION)Pdo->DeviceExtension;
    BUS_QUERY_ID_TYPE IdType = IrpSp->Parameters.QueryId.IdType;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

    switch (IdType) {
    case BusQueryDeviceID:
    {
	WCHAR Buffer[128];
	ULONG Length = _snwprintf(Buffer, ARRAYSIZE(Buffer), L"Root\\%s",
				  DeviceExtension->DeviceInfo->DeviceID);
	UNICODE_STRING StringBuffer = {
	    .Buffer = Buffer,
	    .Length = Length * sizeof(WCHAR),
	    .MaximumLength = Length * sizeof(WCHAR)
	};
	UNICODE_STRING String;
	DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryDeviceID\n");

	Status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
					   &StringBuffer, &String);
	Irp->IoStatus.Information = (ULONG_PTR)String.Buffer;
	break;
    }

    case BusQueryHardwareIDs:
    case BusQueryCompatibleIDs:
	/* Optional, do nothing */
	break;

    case BusQueryInstanceID:
    {
	DPRINT("IRP_MJ_PNP / IRP_MN_QUERY_ID / BusQueryInstanceID\n");

	UNICODE_STRING String;
	Status = RtlCreateUnicodeString(&String, DeviceExtension->DeviceInfo->InstanceID);
	Irp->IoStatus.Information = (ULONG_PTR)String.Buffer;
	break;
    }

    default:
	DPRINT1("IRP_MJ_PNP / IRP_MN_QUERY_ID / unknown query id type 0x%x\n", IdType);
    }

    return Status;
}

static NTSTATUS PnpDeviceQueryDeviceText(IN PDEVICE_OBJECT DeviceObject,
					 IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpDeviceFilterResourceRequirements(IN PDEVICE_OBJECT DeviceObject,
						    IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpDeviceQueryBusInformation(IN PDEVICE_OBJECT DeviceObject,
					     IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpDeviceQueryDeviceUsageNotification(IN PDEVICE_OBJECT DeviceObject,
						      IN PIRP Irp)
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS PnpBuildDeviceRequirementLists(IN PPNP_DEVICE PnpDevice)
{
    ULONG Size = MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE + PnpDevice->ResourceDescriptorSize;
    PIO_RESOURCE_REQUIREMENTS_LIST ResList = (PIO_RESOURCE_REQUIREMENTS_LIST)ExAllocatePool(Size);
    if (ResList == NULL) {
	return STATUS_NO_MEMORY;
    }
    ResList->ListSize = Size;
    ResList->List[0].Version = 1;
    ResList->List[0].Revision = 1;
    ResList->List[0].Count = PnpDevice->ResourceDescriptorCount;
    memcpy((PCHAR)ResList + MINIMAL_IO_RESOURCE_REQUIREMENTS_LIST_SIZE,
	   PnpDevice->ResourceDescriptors, PnpDevice->ResourceDescriptorSize);
    PnpDevice->ResourceRequirementsList = ResList;
    return STATUS_SUCCESS;
}

static NTSTATUS PnpRootStartDevice(IN PDEVICE_OBJECT DeviceObject,
				   IN PCM_RESOURCE_LIST ResourceList,
				   IN PCM_RESOURCE_LIST ResourceListTranslated)
{
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
	assert(FALSE);
	return STATUS_DEVICE_ENUMERATION_ERROR;
    }
    if (!Res->Memory.Start.QuadPart || !Res->Memory.Length) {
	DPRINT1("Invalid IO memory 0x%llx length 0x%x\n",
		Res->Memory.Start.QuadPart, Res->Memory.Length);
	assert(FALSE);
	return STATUS_DEVICE_ENUMERATION_ERROR;
    }
    AcpiResourceDescriptors[0].Memory.MinimumAddress = Res->Memory.Start;
    AcpiResourceDescriptors[0].Memory.MaximumAddress = Res->Memory.Start;
    AcpiResourceDescriptors[0].Memory.Length = Res->Memory.Length;

    /* Allocate the resource requirement lists */
    NTSTATUS Status = PnpBuildDeviceRequirementLists(&AcpiBus);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }
    if (ForceI8042Enumeration) {
	Status = PnpBuildDeviceRequirementLists(&I8042Controller);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }
    if (ForceFdcEnumeration) {
	Status = PnpBuildDeviceRequirementLists(&FloppyController);
	if (!NT_SUCCESS(Status)) {
	    return Status;
	}
    }
    return STATUS_SUCCESS;;
}

/*
 * PNP dispatch function for the root enumerator device
 */
static NTSTATUS PnpRootDispatch(IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    switch (IrpSp->MinorFunction) {
    case IRP_MN_START_DEVICE:
	Status = PnpRootStartDevice(DeviceObject,
				    IrpSp->Parameters.StartDevice.AllocatedResources,
				    IrpSp->Parameters.StartDevice.AllocatedResourcesTranslated);
	break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
	Status = PnpRootQueryDeviceRelations(DeviceObject, Irp);
	break;

    default:
	Status = STATUS_INVALID_DEVICE_REQUEST;
	DPRINT("Invalid PnP code for root enumerator: %X\n",
	       IrpSp->MinorFunction);
	break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

/*
 * PNP dispatch function for the child devices
 */
static NTSTATUS PnpDeviceDispatch(IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS Status;
    switch (IrpSp->MinorFunction) {
    case IRP_MN_START_DEVICE:
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_STOP_DEVICE:
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_QUERY_STOP_DEVICE:
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
	Status = STATUS_SUCCESS;
	break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
	Status = PnpDeviceQueryDeviceRelations(DeviceObject, Irp);
	break;

    case IRP_MN_QUERY_CAPABILITIES:
	Status = PnpDeviceQueryCapabilities(DeviceObject, Irp);
	break;

    case IRP_MN_SURPRISE_REMOVAL:
	Status = PnpDeviceRemoveDevice(DeviceObject, Irp);
	break;

    case IRP_MN_REMOVE_DEVICE:
	Status = PnpDeviceRemoveDevice(DeviceObject, Irp);
	break;

    case IRP_MN_QUERY_PNP_DEVICE_STATE:
	Status = PnpDeviceQueryPnpDeviceState(DeviceObject, Irp);
	break;

    case IRP_MN_QUERY_RESOURCES:
	Status = PnpDeviceQueryResources(DeviceObject, Irp);
	break;

    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	Status = PnpDeviceQueryResourceRequirements(DeviceObject, Irp);
	break;

    case IRP_MN_QUERY_ID:
	Status = PnpDeviceQueryId(DeviceObject, Irp);
	break;

    case IRP_MN_QUERY_DEVICE_TEXT:
	Status = PnpDeviceQueryDeviceText(DeviceObject, Irp);
	break;

    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	Status = PnpDeviceFilterResourceRequirements(DeviceObject, Irp);
	break;

    case IRP_MN_QUERY_BUS_INFORMATION:
	Status = PnpDeviceQueryBusInformation(DeviceObject, Irp);
	break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
	Status = PnpDeviceQueryDeviceUsageNotification(DeviceObject, Irp);
	break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
    case IRP_MN_CANCEL_STOP_DEVICE:
	Status = STATUS_SUCCESS;
	break;

    default:
	Status = STATUS_INVALID_DEVICE_REQUEST;
	DPRINT("Unknown PnP code: %X\n", IrpSp->MinorFunction);
	break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

NTAPI NTSTATUS PnpDispatch(IN PDEVICE_OBJECT DeviceObject,
			   IN PIRP Irp)
{
    PPNP_DEVICE_EXTENSION DeviceExtension = (PPNP_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    assert(DeviceExtension != NULL);
    if (DeviceExtension->DeviceInfo != NULL) {
	/* Device is a child device enumerated by the root bus */
	return PnpDeviceDispatch(DeviceObject, Irp);
    }
    /* Otherwise, device is the root enumerator itself */
    return PnpRootDispatch(DeviceObject, Irp);
}

static NTSTATUS NTAPI PnpAddDevice(IN PDRIVER_OBJECT DriverObject,
				   IN PDEVICE_OBJECT Pdo)
{
    DPRINT("PnpAddDevice()\n");

    ASSERT(DriverObject);

    /* Create the root enumerator device object */
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(PNP_ROOT_ENUMERATOR_U);
    PDEVICE_OBJECT RootEnumerator;
    return IoCreateDevice(DriverObject, sizeof(PNP_DEVICE_EXTENSION),
			  &DeviceName, FILE_DEVICE_BUS_EXTENDER, 0, FALSE,
			  &RootEnumerator);
}

NTAPI NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
			   IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = PnpInitHardwareDatabase();
    if (!NT_SUCCESS(Status)) {
        ERR_(PNPMGR, "Failed to initialize PNP hardware database, status = 0x%x\n", Status);
	return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_PNP] = PnpDispatch;
    DriverObject->AddDevice = PnpAddDevice;

    return STATUS_SUCCESS;
}
