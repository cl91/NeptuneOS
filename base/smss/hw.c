#include "smss.h"

#define HARDWARE_KEY_PATH			"\\Registry\\Machine\\Hardware"
#define DEVICEMAP_KEY_PATH			HARDWARE_KEY_PATH "\\DeviceMap"
#define CURRENT_CONTROL_SET_KEY_PATH		"\\Registry\\Machine\\CurrentControlSet"
#define SERVICE_KEY_PATH			CURRENT_CONTROL_SET_KEY_PATH "\\Services"
#define CURRENT_CONTROL_SET_CONTROL_KEY_PATH	CURRENT_CONTROL_SET_KEY_PATH "\\Control"
#define CLASS_KEY_PATH				CURRENT_CONTROL_SET_CONTROL_KEY_PATH "\\Class"
#define ENUM_KEY_PATH				CURRENT_CONTROL_SET_KEY_PATH "\\Enum"
#define PARAMETERS_KEY_NAME			"Parameters"

#define KBDCLASS_GUID		"{4D36E96B-E325-11CE-BFC1-08002BE10318}"

typedef struct _DRIVER_SERVICE_PARAMETER {
    PCSTR Name;
    ULONG Type;
    ULONG DataSize;
    PVOID Data;
} DRIVER_SERVICE_PARAMETER, *PDRIVER_SERVICE_PARAMETER;

static DRIVER_SERVICE_PARAMETER I8042prtParameters[] = {
};

static ULONG DefaultConnectMultiplePorts = 1;
static DRIVER_SERVICE_PARAMETER KbdclassParameters[] = {
    { "ConnectMultiplePorts", REG_DWORD, sizeof(ULONG), &DefaultConnectMultiplePorts }
};

/* For now this is hard-coded */
static struct {
    PCSTR ServiceName;
    ULONG_PTR ServiceParameterCount;
    PDRIVER_SERVICE_PARAMETER ServiceParameters;
    PCSTR BusId;
    PCSTR DeviceId;
    PCSTR InstanceId;
    PCSTR ClassGuid;
} BootDrivers[] = {
    { "null", 0, NULL, NULL, NULL, NULL, NULL },
    { "beep", 0, NULL, NULL, NULL, NULL, NULL },
    { "fatfs", 0, NULL, NULL, NULL, NULL, NULL },
    { "pnp", 0, NULL, "HTREE", "ROOT", "0", NULL },
    { "acpi", 0, NULL, "ROOT", "ACPI", "0", NULL },
    { "i8042prt", ARRAYSIZE(I8042prtParameters), I8042prtParameters, "Root", "PNP0303", "0", KBDCLASS_GUID },
    { "kbdclass", ARRAYSIZE(KbdclassParameters), KbdclassParameters, NULL, NULL, NULL, NULL },
    { "fdc", 0, NULL, "Root", "PNP0700", "0", NULL },
    { "fdc", 0, NULL, "FDC", "GENERIC_FLOPPY_DRIVE", "00", NULL },
};

static struct {
    PCSTR ClassName;
    PCSTR ClassGuid;
    PCSTR LowerFilters;		/* MULTI_SZ */
    PCSTR UpperFilters;		/* MULTI_SZ */
} ClassDrivers[] = {
    { "Keyboard", KBDCLASS_GUID, NULL, "kbdclass\0" }
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
	if (BootDrivers[i].BusId != NULL) {
	    assert(BootDrivers[i].DeviceId != NULL);
	    assert(BootDrivers[i].InstanceId != NULL);
	    CHAR EnumKeyPath[256];
	    snprintf(EnumKeyPath, sizeof(EnumKeyPath), ENUM_KEY_PATH "\\%s",
		     BootDrivers[i].BusId);
	    RET_ERR(SmCreateRegistryKey(EnumKeyPath, FALSE, NULL));
	    snprintf(EnumKeyPath, sizeof(EnumKeyPath), ENUM_KEY_PATH "\\%s\\%s",
		     BootDrivers[i].BusId, BootDrivers[i].DeviceId);
	    RET_ERR(SmCreateRegistryKey(EnumKeyPath, FALSE, NULL));
	    snprintf(EnumKeyPath, sizeof(EnumKeyPath), ENUM_KEY_PATH "\\%s\\%s\\%s",
		     BootDrivers[i].BusId, BootDrivers[i].DeviceId,
		     BootDrivers[i].InstanceId);
	    HANDLE EnumKey = NULL;
	    RET_ERR(SmCreateRegistryKey(EnumKeyPath, FALSE, &EnumKey));
	    assert(EnumKey != NULL);
	    RET_ERR(SmSetRegKeyValue(EnumKey, "Service", REG_SZ,
				     (PVOID)BootDrivers[i].ServiceName, 0));
	    if (BootDrivers[i].ClassGuid != NULL) {
		RET_ERR(SmSetRegKeyValue(EnumKey, "ClassGUID", REG_SZ,
					 (PVOID)BootDrivers[i].ClassGuid, 0));
	    }
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

static NTSTATUS SmLoadDriver(IN PCSTR DriverToLoad)
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

static NTSTATUS SmInitPnp()
{
    RET_ERR_EX(NtPlugPlayInitialize(),
	       SmPrint("Failed to initialize the Plug and"
		       " Play subsystem. Status = 0x%x\n", Status));
    return STATUS_SUCCESS;
}

NTSTATUS SmInitHardwareDatabase()
{
    RET_ERR(SmCreateRegistryKey(HARDWARE_KEY_PATH, TRUE, NULL));
    RET_ERR(SmCreateRegistryKey(DEVICEMAP_KEY_PATH, TRUE, NULL));
    RET_ERR(SmCreateRegistryKey(CURRENT_CONTROL_SET_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(SERVICE_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(CURRENT_CONTROL_SET_CONTROL_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(CLASS_KEY_PATH, FALSE, NULL));
    RET_ERR(SmCreateRegistryKey(ENUM_KEY_PATH, FALSE, NULL));

    RET_ERR(SmInitBootDriverConfigs());
    RET_ERR(SmInitPnp());
    RET_ERR(SmLoadDriver("null"));
    RET_ERR(SmLoadDriver("beep"));
    RET_ERR(SmLoadDriver("fatfs"));
    return STATUS_SUCCESS;
}
