#include <initguid.h>
#include <wmidata.h>
#include <wmistr.h>
#include <dmilib.h>
#include "acpi_bus.h"

static PWNODE_ALL_DATA AcpiWmiRawSmbiosTables;

typedef ACPI_STATUS (*ACPI_HWHACK_START_DEVICE_HOOK)(IN PACPI_DEVICE Device);

static ACPI_STATUS GpdMicropcKeyboardStartDeviceHook(IN PACPI_DEVICE Device)
{
    return EcWrite(0x11, 0x0);
}

typedef struct _MATCH_TABLE {
    PCSTR SysVendor;
    PCSTR SysProduct;
    PCSTR HardwareId;
    ACPI_HWHACK_START_DEVICE_HOOK StartDeviceHook;
} MATCH_TABLE;

typedef const MATCH_TABLE *PMATCH_TABLE;

static const MATCH_TABLE AcpiHwhacksMatchTable[] = {
    { "GPD", "MicroPC", "PNP0303", GpdMicropcKeyboardStartDeviceHook }
};

static PCSTR AcpiSmbiosStrings[SMBIOS_ID_STRINGS_MAX] = {};

static PMATCH_TABLE AcpiHwhackMatchHardware(IN PCSTR Strings[SMBIOS_ID_STRINGS_MAX],
					    IN PACPI_DEVICE Device)
{
    for (ULONG i = 0; i < _ARRAYSIZE(AcpiHwhacksMatchTable); i++) {
	if (!AcpiHwhacksMatchTable[i].SysVendor || !Strings[SYS_VENDOR] ||
	    !AcpiHwhacksMatchTable[i].SysProduct || !Strings[SYS_PRODUCT] ||
	    !AcpiHwhacksMatchTable[i].HardwareId ||
	    !ACPI_DEVICE_HID(Device)) {
	    continue;
	}
	if (!strcmp(AcpiHwhacksMatchTable[i].SysVendor, Strings[SYS_VENDOR]) &&
	    !strcmp(AcpiHwhacksMatchTable[i].SysProduct, Strings[SYS_PRODUCT]) &&
	    !strcmp(AcpiHwhacksMatchTable[i].HardwareId, ACPI_DEVICE_HID(Device))) {
	    return &AcpiHwhacksMatchTable[i];
	}
    }
    return NULL;
}

static VOID AcpiParseSMBiosTables(IN PVOID SMBiosTables)
{
    ParseSMBiosTables(SMBiosTables, AcpiSmbiosStrings);

    DbgPrint("ACPI: Dumping DMI data:\n");
    DbgPrint("BIOS_VENDOR: %s\n", AcpiSmbiosStrings[BIOS_VENDOR]);
    DbgPrint("BIOS_VERSION: %s\n", AcpiSmbiosStrings[BIOS_VERSION]);
    DbgPrint("BIOS_DATE: %s\n", AcpiSmbiosStrings[BIOS_DATE]);
    DbgPrint("SYS_VENDOR: %s\n", AcpiSmbiosStrings[SYS_VENDOR]);
    DbgPrint("SYS_PRODUCT: %s\n", AcpiSmbiosStrings[SYS_PRODUCT]);
    DbgPrint("SYS_VERSION: %s\n", AcpiSmbiosStrings[SYS_VERSION]);
    DbgPrint("SYS_SERIAL: %s\n", AcpiSmbiosStrings[SYS_SERIAL]);
    DbgPrint("BOARD_VENDOR: %s\n", AcpiSmbiosStrings[BOARD_VENDOR]);
    DbgPrint("BOARD_NAME: %s\n", AcpiSmbiosStrings[BOARD_NAME]);
    DbgPrint("BOARD_VERSION: %s\n", AcpiSmbiosStrings[BOARD_VERSION]);
    DbgPrint("BOARD_SERIAL: %s\n", AcpiSmbiosStrings[BOARD_SERIAL]);
    DbgPrint("BOARD_ASSET_TAG: %s\n", AcpiSmbiosStrings[BOARD_ASSET_TAG]);
}

VOID AcpiInitializeHwHacks(VOID)
{
    /* Open the data block object for the SMBIOS table */
    PVOID DataBlockObject = NULL;
    NTSTATUS Status = IoWMIOpenBlock(&MSSmBios_RawSMBiosTables_GUID,
				     WMIGUID_QUERY, &DataBlockObject);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("IoWMIOpenBlock failed: 0x%08x\n", Status);
	return;
    }

    /* Query the required buffer size */
    ULONG BufferSize = 0;
    Status = IoWMIQueryAllData(DataBlockObject, &BufferSize, NULL);
    if (!NT_SUCCESS(Status) && Status != STATUS_BUFFER_TOO_SMALL) {
	DPRINT1("IoWMIOpenBlock failed: 0x%08x\n", Status);
	return;
    }

    AcpiWmiRawSmbiosTables = ExAllocatePoolWithTag(NonPagedPool,
						   BufferSize, 'BTMS');
    if (AcpiWmiRawSmbiosTables == NULL) {
	DPRINT1("Failed to allocate %u bytes for SMBIOS tables\n",
		BufferSize);
	return;
    }

    /* Query the buffer data */
    Status = IoWMIQueryAllData(DataBlockObject, &BufferSize, AcpiWmiRawSmbiosTables);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("IoWMIOpenBlock failed: 0x%08x\n", Status);
	ExFreePoolWithTag(AcpiWmiRawSmbiosTables, 'BTMS');
	return;
    }

    /* Parse the table */
    AcpiParseSMBiosTables(AcpiWmiRawSmbiosTables + 1);
}

ACPI_STATUS AcpiApplyStartDeviceHacks(IN PACPI_DEVICE Device)
{
    if (Device) {
	PMATCH_TABLE Match = AcpiHwhackMatchHardware(AcpiSmbiosStrings, Device);
	if (!Match || !Match->StartDeviceHook) {
	    return AE_OK;
	}
	return Match->StartDeviceHook(Device);
    }
    return AE_OK;
}
