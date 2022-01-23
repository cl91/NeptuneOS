#include <smss.h>

#define HARDWARE_KEY_PATH	"\\Registry\\Machine\\Hardware"
#define SERVICE_KEY_PATH	"\\Registry\\Machine\\CurrentControlSet\\Services"
#define PARAMETERS_KEY_NAME	"Parameters"

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
} BootDrivers[] = {
    { "null", 0, NULL },
    { "beep", 0, NULL },
    { "pnp", 0, NULL },
    { "i8042prt", ARRAYSIZE(I8042prtParameters), I8042prtParameters },
    { "kbdclass", ARRAYSIZE(KbdclassParameters), KbdclassParameters }
};

static NTSTATUS SmInitBootDriverConfigs()
{
    CHAR ServiceFullPath[256];
    CHAR ParametersKeyPath[256];
    CHAR ImagePath[128];
    RET_ERR(SmCreateRegistryKey(SERVICE_KEY_PATH, FALSE, NULL));
    for (ULONG i = 0; i < ARRAYSIZE(BootDrivers); i++) {
	snprintf(ServiceFullPath, sizeof(ServiceFullPath),
		 SERVICE_KEY_PATH "\\%s", BootDrivers[i].ServiceName);
	snprintf(ParametersKeyPath, sizeof(ParametersKeyPath),
		 SERVICE_KEY_PATH "\\%s\\" PARAMETERS_KEY_NAME,
		 BootDrivers[i].ServiceName);
	snprintf(ImagePath, sizeof(ImagePath),
		 "\\BootModules\\%s.sys", BootDrivers[i].ServiceName);
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
    RET_ERR(SmLoadDriver("pnp"));
    RET_ERR_EX(NtPlugPlayInitialize(),
	       SmPrint("Failed to initialize the Plug and"
		       " Play subsystem. Status = 0x%x\n", Status));
    return STATUS_SUCCESS;
}

NTSTATUS SmInitHardwareDatabase()
{
    RET_ERR(SmCreateRegistryKey(HARDWARE_KEY_PATH, TRUE, NULL));
    RET_ERR(SmInitBootDriverConfigs());
    RET_ERR(SmInitPnp());
    return STATUS_SUCCESS;
}
