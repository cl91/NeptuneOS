#include <initguid.h>
#include "smss.h"
#include <pnpguid.h>
#define TEXT(t) L##t
#include <regstr.h>

#define SYSTEM_KEY_PATH				"\\Registry\\Machine\\System"
#define HARDWARE_KEY_PATH			"\\Registry\\Machine\\Hardware"
#define DEVICEMAP_KEY_PATH			HARDWARE_KEY_PATH "\\DeviceMap"
#define CURRENT_CONTROL_SET_KEY_PATH		SYSTEM_KEY_PATH "\\CurrentControlSet"
#define SERVICE_KEY_PATH			CURRENT_CONTROL_SET_KEY_PATH "\\Services"
#define CURRENT_CONTROL_SET_CONTROL_KEY_PATH	CURRENT_CONTROL_SET_KEY_PATH "\\Control"
#define CLASS_KEY_PATH				CURRENT_CONTROL_SET_CONTROL_KEY_PATH "\\Class"
#define ENUM_KEY_PATH				CURRENT_CONTROL_SET_KEY_PATH "\\Enum"
#define PARAMETERS_KEY_NAME			"Parameters"

/*
 * Eventually these will be retrieved from the corresponding .inf file.
 */
typedef struct _DRIVER_SERVICE_PARAMETER {
    PCSTR Name;
    ULONG Type;
    ULONG DataSize;
    PVOID Data;
} DRIVER_SERVICE_PARAMETER, *PDRIVER_SERVICE_PARAMETER;

typedef struct _DRIVER_SERVICE {
    PCSTR ServiceName;
    PWSTR MatchString;		/* MULTI_SZ */
    ULONG_PTR ServiceParameterCount;
    PDRIVER_SERVICE_PARAMETER ServiceParameters;
    BOOLEAN LoadIntoBusDriver;
    BOOLEAN LoadFailed;
} DRIVER_SERVICE, *PDRIVER_SERVICE;

static ULONG DefaultConnectMultiplePorts = 1;
static DRIVER_SERVICE_PARAMETER KbdclassParameters[] = {
    { "ConnectMultiplePorts", REG_DWORD, sizeof(ULONG), &DefaultConnectMultiplePorts }
};

static ULONG StorAhciBusType = 0xb;
static DRIVER_SERVICE_PARAMETER StorAhciParameters[] = {
    { "BusType", REG_DWORD, sizeof(ULONG), &StorAhciBusType }
};

static ULONG StorNvmeBusType = 0x11;
static DRIVER_SERVICE_PARAMETER StorNvmeParameters[] = {
    { "BusType", REG_DWORD, sizeof(ULONG), &StorNvmeBusType }
};

static CHAR DriverExtensionPath[] = "\\??\\BootModules\\lnxdrv.elf";
static CHAR ModulesAliasPath[] = "\\??\\BootModules\\modules.alias";
static CHAR ModulesDepPath[] = "\\??\\BootModules\\modules.dep";
static DRIVER_SERVICE_PARAMETER LnxdrvParameters[] = {
    { "DriverExtensionImage", REG_SZ,
      sizeof(DriverExtensionPath), DriverExtensionPath },
    { "ModulesAliasDatabase", REG_SZ,
      sizeof(ModulesAliasPath), ModulesAliasPath },
    { "ModulesDepDatabase", REG_SZ,
      sizeof(ModulesDepPath), ModulesDepPath },
};

static CHAR MemDrvModules[] = "\\??\\BootModules\\mem.ko\0";
static DRIVER_SERVICE_PARAMETER MemDrvParameters[] = {
    { "Modules", REG_MULTI_SZ,
      sizeof(MemDrvModules), MemDrvModules }
};

/* For now these are hard-coded, Eventually we want to move this to a
 * registry file (boot configuration database). */
static DRIVER_SERVICE BootDrivers[] = {
    { "null" },
    { "beep" },
    { "fatfs" },
    { "pnp", L"HTREE\\ROOT\\0\0" },
    { "acpi", L"ROOT\\ACPI\\0\0" },
    { "pci", L"*PNP0A03\0*PNP0A08\0PCI\\CC_0604\0CC_0607\0" },
    { "fdc", L"*PNP0700\0FDC\\GENERIC_FLOPPY_DRIVE\0" },
    { "i8042prt", L"*PNP0303\0" },
    { "kbdclass", NULL, ARRAYSIZE(KbdclassParameters), KbdclassParameters },
    { "storahci", L"PCI\\CC_0106\0",
      ARRAYSIZE(StorAhciParameters), StorAhciParameters },
    { "stornvme", L"PCI\\CC_010802\0",
      ARRAYSIZE(StorNvmeParameters), StorNvmeParameters },
    { "disk", L"GenDisk\0", 0, NULL, TRUE },
    { "partmgr", L"STORAGE\\Volume\0", 0, NULL, TRUE },
    { "mountmgr" },
    { "lnxdrv", NULL, ARRAYSIZE(LnxdrvParameters), LnxdrvParameters },
    { "mem", NULL, ARRAYSIZE(MemDrvParameters), MemDrvParameters },
    { "pvpanic", L"PCI\\VEN_1B36&DEV_0011\0" },
    { "usbhci", L"PCI\\CC_0C03\0" },
    { "ethernet", L"PCI\\CC_0200\0" },
    { "videoprt", L"PCI\\CC_0300\0" }
};

static struct {
    PCSTR ClassName;
    PCSTR ClassGuid;
    PWSTR MatchString;		/* MULTI_SZ */
    PCSTR LowerFilters;		/* MULTI_SZ */
    PCSTR UpperFilters;		/* MULTI_SZ */
} ClassDrivers[] = {
    { "Keyboard", "{4D36E96B-E325-11CE-BFC1-08002BE10318}",
      L"*PNP0303\0", NULL, "kbdclass\0" },
    { "Disk", "{4D36E967-E325-11CE-BFC1-08002BE10318}",
      L"GenDisk\0", NULL, "partmgr\0" }
};

static NTSTATUS SmInitBootDriverConfigs()
{
    CHAR ServiceFullPath[256];
    CHAR ParametersKeyPath[256];
    CHAR ImagePath[128];

    for (ULONG i = 0; i < ARRAYSIZE(BootDrivers); i++) {
	snprintf(ServiceFullPath, sizeof(ServiceFullPath),
		 SERVICE_KEY_PATH "\\%s", BootDrivers[i].ServiceName);
	snprintf(ParametersKeyPath, sizeof(ParametersKeyPath),
		 SERVICE_KEY_PATH "\\%s\\" PARAMETERS_KEY_NAME,
		 BootDrivers[i].ServiceName);
	snprintf(ImagePath, sizeof(ImagePath),
		 "\\??\\BootModules\\%s.sys", BootDrivers[i].ServiceName);
	HANDLE ServiceKey = NULL;
	RET_ERR(SmCreateRegistryKey(ServiceFullPath, FALSE, &ServiceKey));
	assert(ServiceKey != NULL);
	RET_ERR(SmSetRegKeyValue(ServiceKey, "ImagePath", REG_SZ, ImagePath, 0));
	HANDLE ParametersKey = NULL;
	RET_ERR(SmCreateRegistryKey(ParametersKeyPath, FALSE, &ParametersKey));
	assert(ParametersKey != NULL);
	for (ULONG j = 0; j < BootDrivers[i].ServiceParameterCount; j++) {
	    RET_ERR(SmSetRegKeyValue(ParametersKey,
				     BootDrivers[i].ServiceParameters[j].Name,
				     BootDrivers[i].ServiceParameters[j].Type,
				     BootDrivers[i].ServiceParameters[j].Data,
				     BootDrivers[i].ServiceParameters[j].DataSize));
	}
    }

    CHAR ClassKeyPath[256];
    for (ULONG i = 0; i < ARRAYSIZE(ClassDrivers); i++) {
	snprintf(ClassKeyPath, sizeof(ClassKeyPath), CLASS_KEY_PATH "\\%s",
		 ClassDrivers[i].ClassGuid);
	HANDLE ClassKey = NULL;
	RET_ERR(SmCreateRegistryKey(ClassKeyPath, FALSE, &ClassKey));
	assert(ClassKey != NULL);
	RET_ERR(SmSetRegKeyValue(ClassKey, "Class", REG_SZ,
				 (PVOID)ClassDrivers[i].ClassName, 0));
	if (ClassDrivers[i].LowerFilters != NULL) {
	    RET_ERR(SmSetRegKeyValue(ClassKey, "LowerFilters", REG_MULTI_SZ,
				     (PVOID)ClassDrivers[i].LowerFilters, 0));
	}
	if (ClassDrivers[i].UpperFilters != NULL) {
	    RET_ERR(SmSetRegKeyValue(ClassKey, "UpperFilters", REG_MULTI_SZ,
				     (PVOID)ClassDrivers[i].UpperFilters, 0));
	}
    }
    return STATUS_SUCCESS;
}

NTSTATUS SmLoadDriver(IN PCSTR DriverToLoad)
{
    CHAR ServiceFullPath[512];
    snprintf(ServiceFullPath, sizeof(ServiceFullPath),
	     SERVICE_KEY_PATH "\\%s", DriverToLoad);
    SmPrint("Loading driver %s... ", ServiceFullPath);
    RET_ERR_EX(NtLoadDriverA(ServiceFullPath),
	       SmPrint("FAIL\n"));
    SmPrint("OK\n");
    return STATUS_SUCCESS;
}

static NTSTATUS SmQueryIds(IN BOOLEAN CompatibleIds,
			   IN PWCHAR DeviceId,
			   OUT PWCHAR *pBuffer,
			   OUT ULONG *pBufferSize)
{
    ULONG BufferSize = 512;
    PWCHAR Buffer = SmAllocatePool(BufferSize);
    if (!Buffer) {
	*pBufferSize = 0;
	return STATUS_NO_MEMORY;
    }
    PLUGPLAY_CONTROL_QUERY_IDS_DATA Data = {
	.Buffer = Buffer,
	.BufferSize = BufferSize
    };
    RtlInitUnicodeString(&Data.DeviceInstance, DeviceId);
    PLUGPLAY_CONTROL_CLASS Class = CompatibleIds ? PlugPlayControlQueryCompatibleIDs :
	PlugPlayControlQueryHardwareIDs;
    NTSTATUS Status = NtPlugPlayControl(Class, &Data,
					sizeof(PLUGPLAY_CONTROL_QUERY_IDS_DATA));
    if (Status == STATUS_BUFFER_TOO_SMALL) {
	SmFreePool(Buffer);
	BufferSize = Data.BufferSize;
	Buffer = SmAllocatePool(BufferSize);
	if (!Buffer) {
	    *pBufferSize = Data.BufferSize;
	    return STATUS_NO_MEMORY;
	}
	Data.Buffer = Buffer;
	Data.BufferSize = BufferSize;
	Status = NtPlugPlayControl(Class, &Data,
				   sizeof(PLUGPLAY_CONTROL_QUERY_IDS_DATA));
    }
    if (!NT_SUCCESS(Status)) {
	SmFreePool(Buffer);
	*pBuffer = NULL;
	*pBufferSize = 0;
	return Status;
    }
    *pBuffer = Buffer;
    *pBufferSize = BufferSize;
    return STATUS_SUCCESS;
}

static BOOLEAN SmMatchMultiSz(IN PWCHAR Target,
			      IN PWCHAR Src)
{
    for (PWCHAR Id = Src; *Id != L'\0'; Id += wcslen(Id) + 1) {
	if (!_wcsicmp(Target, Id)) {
	    return TRUE;
	}
    }
    return FALSE;
}

static LIST_ENTRY SmKnownDeviceList;

typedef struct _SM_KNOWN_DEVICE {
    UNICODE_STRING InstancePath;
    LIST_ENTRY Link;
    BOOLEAN Installed;
} SM_KNOWN_DEVICE, *PSM_KNOWN_DEVICE;

static LONG SmFindDriver(IN PWCHAR InstancePath, OUT PCSTR *ClassGuid,
			 OUT PWSTR *HardwareIDs, OUT ULONG *HardwareIDsSize,
			 OUT PWSTR *CompatibleIDs, OUT ULONG *CompatibleIDsSize)
{
    *ClassGuid = NULL;
    LONG Driver = -1;
    /* First try if we can find an exact match for the device instance path. */
    for (ULONG i = 0; i < ARRAYSIZE(BootDrivers); i++) {
	if (BootDrivers[i].MatchString &&
	    SmMatchMultiSz(InstancePath, BootDrivers[i].MatchString)) {
	    Driver = i;
	    break;
	}
    }
    /* Also try finding the class driver from the device instance path */
    for (ULONG i = 0; i < ARRAYSIZE(ClassDrivers); i++) {
	assert(ClassDrivers[i].ClassGuid);
	if (ClassDrivers[i].MatchString &&
	    SmMatchMultiSz(InstancePath, ClassDrivers[i].MatchString)) {
	    *ClassGuid = ClassDrivers[i].ClassGuid;
	    break;
	}
    }
    if (Driver >= 0) {
	goto out;
    }

    SmQueryIds(FALSE, InstancePath, HardwareIDs, HardwareIDsSize);
    SmQueryIds(TRUE, InstancePath, CompatibleIDs, CompatibleIDsSize);
    /* Look at the hardware IDs of the device and try finding a matching driver for it. */
    if (*HardwareIDs) {
	for (PWCHAR Id = *HardwareIDs; *Id != L'\0'; Id += wcslen(Id) + 1) {
	    DPRINT("Got hardware ids %ws\n", Id);
	    if (!*ClassGuid) {
		for (ULONG i = 0; i < ARRAYSIZE(ClassDrivers); i++) {
		    assert(ClassDrivers[i].ClassGuid);
		    if (ClassDrivers[i].MatchString &&
			SmMatchMultiSz(Id, ClassDrivers[i].MatchString)) {
			*ClassGuid = ClassDrivers[i].ClassGuid;
			break;
		    }
		}
	    }
	    for (ULONG i = 0; i < ARRAYSIZE(BootDrivers); i++) {
		if (BootDrivers[i].MatchString &&
		    SmMatchMultiSz(Id, BootDrivers[i].MatchString)) {
		    Driver = i;
		    break;
		}
	    }
	}
	if (Driver >= 0) {
	    goto out;
	}
    }

    /* Look at the compatible IDs of the device and try finding a matching driver for it. */
    if (*CompatibleIDs) {
	for (PWCHAR Id = *CompatibleIDs; *Id != L'\0'; Id += wcslen(Id) + 1) {
	    DPRINT("Got compatible ids %ws\n", Id);
	    if (!*ClassGuid) {
		for (ULONG i = 0; i < ARRAYSIZE(ClassDrivers); i++) {
		    assert(ClassDrivers[i].ClassGuid);
		    if (ClassDrivers[i].MatchString &&
			SmMatchMultiSz(Id, ClassDrivers[i].MatchString)) {
			*ClassGuid = ClassDrivers[i].ClassGuid;
			break;
		    }
		}
	    }
	    for (ULONG i = 0; i < ARRAYSIZE(BootDrivers); i++) {
		if (BootDrivers[i].MatchString &&
		    SmMatchMultiSz(Id, BootDrivers[i].MatchString)) {
		    Driver = i;
		    break;
		}
	    }
	}
    }

out:
    return Driver;
}

static NTSTATUS SmInstallDevice(IN PWCHAR InstancePath)
{
    UNICODE_STRING InstancePathU = {};
    if (!RtlCreateUnicodeString(&InstancePathU, InstancePath)) {
	return STATUS_UNSUCCESSFUL;
    }
    PSM_KNOWN_DEVICE InstalledDevice = SmAllocatePool(sizeof(SM_KNOWN_DEVICE));
    if (!InstalledDevice) {
	RtlFreeUnicodeString(&InstancePathU);
	return STATUS_NO_MEMORY;
    }

    DPRINT("Trying to install device %ws\n", InstancePath);
    LoopOverList(Device, &SmKnownDeviceList, SM_KNOWN_DEVICE, Link) {
	if (!RtlCompareUnicodeString(&Device->InstancePath, &InstancePathU, TRUE)) {
	    DPRINT("Known device %wZ (%s). Skipping installation.\n",
		   &Device->InstancePath,
		   Device->Installed ? "installed" : "installation failed");
	    RtlFreeUnicodeString(&InstancePathU);
	    SmFreePool(InstalledDevice);
	    return STATUS_UNSUCCESSFUL;
	}
    }
    InstalledDevice->InstancePath = InstancePathU;
    InsertTailList(&SmKnownDeviceList, &InstalledDevice->Link);

    PCSTR ClassGuid = NULL;
    PWSTR HardwareIDs = NULL;
    ULONG HardwareIDsSize = 0;
    PWSTR CompatibleIDs = NULL;
    ULONG CompatibleIDsSize = 0;
    LONG Index = SmFindDriver(InstancePath, &ClassGuid,
			      &HardwareIDs, &HardwareIDsSize,
			      &CompatibleIDs, &CompatibleIDsSize);
    NTSTATUS Status;
    if (Index < 0) {
	DPRINT("No matching driver found for %ws\n", InstancePath);
	Status = STATUS_UNSUCCESSFUL;
	goto out;
    }
    DPRINT("Found driver %s for %ws\n", BootDrivers[Index].ServiceName, InstancePath);

    CHAR EnumKeyPath[256];
    snprintf(EnumKeyPath, sizeof(EnumKeyPath), ENUM_KEY_PATH "\\%ws",
	     InstancePath);
    /* Find the last and second to last path separators */
    LONG InstanceId = strlen(EnumKeyPath);
    assert(EnumKeyPath[InstanceId] == '\0');
    while (EnumKeyPath[--InstanceId] != '\\') {}
    if (InstanceId <= 0) {
	assert(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto out;
    }
    EnumKeyPath[InstanceId] = '\0';
    LONG DeviceId = strlen(EnumKeyPath);
    assert(EnumKeyPath[DeviceId] == '\0');
    while (EnumKeyPath[--DeviceId] != '\\') {}
    if (DeviceId <= 0) {
	assert(FALSE);
	Status = STATUS_INTERNAL_ERROR;
	goto out;
    }
    EnumKeyPath[DeviceId] = '\0';

    RET_ERR(SmCreateRegistryKey(EnumKeyPath, FALSE, NULL));
    EnumKeyPath[DeviceId] = '\\';
    RET_ERR(SmCreateRegistryKey(EnumKeyPath, FALSE, NULL));
    EnumKeyPath[InstanceId] = '\\';
    HANDLE EnumKey = NULL;
    RET_ERR(SmCreateRegistryKey(EnumKeyPath, FALSE, &EnumKey));
    assert(EnumKey != NULL);
    RET_ERR(SmSetRegKeyValue(EnumKey, "Service", REG_SZ,
			     (PVOID)BootDrivers[Index].ServiceName, 0));
    if (ClassGuid) {
	RET_ERR(SmSetRegKeyValue(EnumKey, "ClassGUID", REG_SZ, (PVOID)ClassGuid, 0));
    }
    if (BootDrivers[Index].LoadIntoBusDriver) {
	ULONG Data = 1;
	RET_ERR(SmSetRegKeyValue(EnumKey, "LoadIntoBusDriver", REG_DWORD,
				 &Data, sizeof(ULONG)));
    }
    if (HardwareIDs) {
	assert(HardwareIDsSize);
	RET_ERR(SmSetRegKeyValueW(EnumKey, REGSTR_VAL_HARDWAREID, REG_MULTI_SZ,
				  HardwareIDs, HardwareIDsSize));
    }
    if (CompatibleIDs) {
	assert(CompatibleIDsSize);
	RET_ERR(SmSetRegKeyValueW(EnumKey, REGSTR_VAL_COMPATIBLEIDS, REG_MULTI_SZ,
				  CompatibleIDs, CompatibleIDsSize));
    }

    InstalledDevice->Installed = TRUE;
    Status = STATUS_SUCCESS;
out:
    if (HardwareIDs) {
	SmFreePool(HardwareIDs);
    }
    if (CompatibleIDs) {
	SmFreePool(CompatibleIDs);
    }

    return Status;
}

static NTSTATUS SmInitPnp()
{
    SmPrint("Enumerating Plug and Play devices...\n");

    PLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA Buffer = {};
    RtlInitUnicodeString(&Buffer.DeviceInstance, L"HTREE\\ROOT\\0");
    NTSTATUS Status = NtPlugPlayControl(PlugPlayControlEnumerateDevice, &Buffer,
					sizeof(PLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA));
    if (!NT_SUCCESS(Status) && Status != STATUS_INVALID_DEVICE_STATE) {
	goto out;
    }

    /* NtPlugPlayControl is guaranteed to finish emitting plug and play events
     * before returning, so we can simply poll the PnP event queue without waiting. */
    ULONG BufferSize = sizeof(PLUGPLAY_EVENT_BLOCK) + 512;
    PPLUGPLAY_EVENT_BLOCK Event = SmAllocatePool(BufferSize);
    if (!Event) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }
    while (TRUE) {
	Status = NtGetPlugPlayEvent(TRUE, Event, BufferSize);
	if (Status == STATUS_BUFFER_TOO_SMALL) {
	    assert(Event->TotalSize > BufferSize);
	    BufferSize = Event->TotalSize;
	    SmFreePool(Event);
	    Event = SmAllocatePool(BufferSize);
	    if (!Event) {
		Status = STATUS_NO_MEMORY;
		goto out;
	    }
	    continue;
	} else if (Status == STATUS_NO_MORE_ENTRIES) {
	    Status = STATUS_SUCCESS;
	    break;
	} else if (!NT_SUCCESS(Status)) {
	    break;
	}

	/* We have a PnP event. Process the event. */
	if (Event->EventCategory == DeviceInstallEvent) {
	    if (IsEqualGUID(&Event->EventGuid, &GUID_DEVICE_ENUMERATED)) {
		Status = SmInstallDevice(Event->InstallDevice.DeviceId);
		/* If we successfully installed a driver for a device, re-enumerate it. */
		if (NT_SUCCESS(Status)) {
		    RtlInitUnicodeString(&Buffer.DeviceInstance,
					 Event->InstallDevice.DeviceId);
		    NtPlugPlayControl(PlugPlayControlEnumerateDevice, &Buffer,
				      sizeof(PLUGPLAY_CONTROL_ENUMERATE_DEVICE_DATA));
		}
	    } else {
		DPRINT("Unknown PnP event, GUID "
		       "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
		       Event->EventGuid.Data1, Event->EventGuid.Data2,
		       Event->EventGuid.Data3, Event->EventGuid.Data4[0],
		       Event->EventGuid.Data4[1], Event->EventGuid.Data4[2],
		       Event->EventGuid.Data4[3], Event->EventGuid.Data4[4],
		       Event->EventGuid.Data4[5], Event->EventGuid.Data4[6],
		       Event->EventGuid.Data4[7]);
		assert(FALSE);
	    }
	} else {
	    DPRINT("Unknown PnP event category %d\n", Event->EventCategory);
	    assert(FALSE);
	}

	/* Dequeue the PnP event so we can get the next one. */
	PLUGPLAY_CONTROL_USER_RESPONSE_DATA ResponseData = {};
	Status = NtPlugPlayControl(PlugPlayControlUserResponse,
				   &ResponseData, sizeof(ResponseData));
	if (!NT_SUCCESS(Status)) {
	    break;
	}
    }
    SmFreePool(Event);

out:
    if (!NT_SUCCESS(Status)) {
	SmPrint("Failed to initialize the Plug and Play subsystem. Error = 0x%x\n",
		Status);
    }
    return Status;
}

NTSTATUS SmInitHardwareDatabase()
{
    InitializeListHead(&SmKnownDeviceList);
    RET_ERR(SmCreateRegistryKey(SYSTEM_KEY_PATH, TRUE, NULL));
    RET_ERR(SmCreateRegistryKey(HARDWARE_KEY_PATH, TRUE, NULL));
    RET_ERR(SmCreateRegistryKey(DEVICEMAP_KEY_PATH, TRUE, NULL));
    RET_ERR(SmCreateRegistryKey(CURRENT_CONTROL_SET_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(SERVICE_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(CURRENT_CONTROL_SET_CONTROL_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(CLASS_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(ENUM_KEY_PATH, FALSE, NULL));

    RET_ERR(SmInitBootDriverConfigs());
    RET_ERR(SmInitPnp());
    RET_ERR(SmLoadDriver("fatfs"));
    return STATUS_SUCCESS;
}
