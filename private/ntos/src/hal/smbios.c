#include "halp.h"
#include <wmidata.h>
#include <dmilib.h>

#define EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249

static GUID HalpSmbiosTableGuid = {
    0xeb9d2d31, 0x2d88, 0x11d3,
    {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}
};

static GUID HalpSmbios3TableGuid = {
    0xf2fd1544, 0x9794, 0x4a2c,
    {0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94}
};

typedef struct _EFI_TABLE_HEADER {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER, *PEFI_TABLE_HEADER;

typedef struct _EFI_CONFIGURATION_TABLE {
    GUID VendorGuid;
    PVOID VendorTable;
} EFI_CONFIGURATION_TABLE, *PEFI_CONFIGURATION_TABLE;

typedef struct _EFI_SYSYEM_TABLE {
    EFI_TABLE_HEADER Hdr;
    WCHAR *FirmwareVendor;
    UINT32 FirmwareRevision;
    PVOID ConsoleInHandle;
    PVOID ConIn;
    PVOID ConsoleOutHandle;
    PVOID ConOut;
    PVOID StandardErrorHandle;
    PVOID StdErr;
    PVOID RuntimeServices;
    PVOID BootServices;
    UINT32 NumberOfTableEntries;
    EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE, *PEFI_SYSTEM_TABLE;

#include <pshpack1.h>
typedef struct _SMBIOS21_ENTRY_POINT {
    CHAR AnchorString[4];
    UCHAR Checksum;
    UCHAR Length;
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    USHORT MaxStructureSize;
    UCHAR EntryPointRevision;
    CHAR FormattedArea[5];
    CHAR AnchorString2[5];
    UCHAR Checksum2;
    USHORT TableLength;
    ULONG TableAddress;
    USHORT NumberOfStructures;
    UCHAR BCDRevision;
} SMBIOS21_ENTRY_POINT, *PSMBIOS21_ENTRY_POINT;

typedef struct _SMBIOS30_ENTRY_POINT {
    CHAR AnchorString[5];
    UCHAR Checksum;
    UCHAR Length;
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    UCHAR Docref;
    UCHAR Revision;
    UCHAR Reserved;
    ULONG TableMaxSize;
    ULONG64 TableAddress;
} SMBIOS30_ENTRY_POINT, *PSMBIOS30_ENTRY_POINT;
#include <poppack.h>

static PHYSICAL_ADDRESS HalpEfiSystemTablePointer;
static PMSSmBios_RawSMBiosTables HalpRawSmbiosTables;
static PCSTR HalpSmbiosStrings[SMBIOS_ID_STRINGS_MAX];

VOID HalRegisterEfiSystemTablePointer(IN ULONG64 PhysAddr)
{
    HalpEfiSystemTablePointer.QuadPart = PhysAddr;
}

static PVOID HalpMapTable(IN PHYSICAL_ADDRESS PhyAddr,
			  IN ULONG Size)
{
    ULONG64 AlignedAddr = PAGE_ALIGN64(PhyAddr.QuadPart);
    ULONG WindowSize = PAGE_ALIGN_UP64(PhyAddr.QuadPart + Size) - AlignedAddr;
    NTSTATUS Status = MmMapPhysicalMemory(AlignedAddr, EX_DYN_VSPACE_START,
					  WindowSize, PAGE_READONLY);
    if (!NT_SUCCESS(Status)) {
	assert(FALSE);
	return NULL;
    }
    return (PVOID)(MWORD)(PhyAddr.QuadPart - AlignedAddr + EX_DYN_VSPACE_START);
}

#define VALIDATE_SMBIOS_ENTRYPOINT(ExpectedAnchorString)	\
    /* Check Anchor String first */				\
    if (!RtlEqualMemory(EntryPoint->AnchorString,		\
			ExpectedAnchorString,			\
			sizeof(EntryPoint->AnchorString))) {	\
	return FALSE;						\
    }								\
    if (EntryPoint->Length > 32)				\
	return FALSE;						\
    /* Validate checksum */					\
    UCHAR Checksum = EntryPoint->Checksum;			\
    /* Add all bytes */						\
    for (ULONG i = 0; i < EntryPoint->Length; i++) {		\
	Checksum += ((PCHAR)EntryPoint)[i];			\
    }								\
    return Checksum == EntryPoint->Checksum

static BOOLEAN IsValidSmbios3EntryPoint(IN PSMBIOS30_ENTRY_POINT EntryPoint)
{
    VALIDATE_SMBIOS_ENTRYPOINT("_SM3_");
}

static BOOLEAN IsValidSmbios21EntryPoint(IN PSMBIOS21_ENTRY_POINT EntryPoint)
{
    VALIDATE_SMBIOS_ENTRYPOINT("_SM_");
}

static NTSTATUS HalpEfiFindSmbiosTable(OUT PPVOID EntryPointStructure,
				       OUT PBOOLEAN pIsSmbios3)
{
    if (!HalpEfiSystemTablePointer.QuadPart) {
	return STATUS_NOT_FOUND;
    }
    PEFI_SYSTEM_TABLE SystemTable = HalpMapTable(HalpEfiSystemTablePointer,
						 sizeof(EFI_SYSTEM_TABLE));
    if (!SystemTable) {
	return STATUS_NOT_FOUND;
    }
    if (SystemTable->Hdr.Signature != EFI_SYSTEM_TABLE_SIGNATURE) {
	DbgTrace("Invalid EFI system table signature 0x%llx\n", SystemTable->Hdr.Signature);
	MmUnmapPhysicalMemory((MWORD)SystemTable);
	return STATUS_NOT_FOUND;
    }
    DbgTrace("UEFI Firmware Revision %d.%d\n",
	     SystemTable->FirmwareRevision >> 16,
	     SystemTable->FirmwareRevision & 0xffff);
    DbgTrace("Number of UEFI configuration tables: %d\n",
	     SystemTable->NumberOfTableEntries);
    PHYSICAL_ADDRESS ConfigTablesPhyAddr = {
	.QuadPart = (MWORD)SystemTable->ConfigurationTable
    };
    ULONG NumConfigTables = SystemTable->NumberOfTableEntries;
    ULONG ConfigTablesSize = NumConfigTables * sizeof(EFI_CONFIGURATION_TABLE);
    MmUnmapPhysicalMemory((MWORD)SystemTable);
    if (!NumConfigTables) {
	return STATUS_NOT_FOUND;
    }
    PEFI_CONFIGURATION_TABLE ConfigTables = HalpMapTable(ConfigTablesPhyAddr,
							 ConfigTablesSize);
    if (!ConfigTables) {
	return STATUS_NOT_FOUND;
    }
    for (ULONG i = 0; i < NumConfigTables; i++) {
	BOOLEAN IsSmbios3 = IsEqualGUID(&ConfigTables[i].VendorGuid, &HalpSmbios3TableGuid);
	BOOLEAN IsSmbios = IsEqualGUID(&ConfigTables[i].VendorGuid, &HalpSmbiosTableGuid);
	if (!(IsSmbios3 || IsSmbios)) {
	    continue;
	}
	PHYSICAL_ADDRESS TablePhyAddr = { .QuadPart = (MWORD)ConfigTables[i].VendorTable };
	MmUnmapPhysicalMemory((MWORD)ConfigTables);
	ULONG TableSize = IsSmbios ? sizeof(SMBIOS21_ENTRY_POINT) : sizeof(SMBIOS30_ENTRY_POINT);
	PVOID MappedTable = HalpMapTable(TablePhyAddr, TableSize);
	if (!MappedTable) {
	    return STATUS_NOT_FOUND;
	}
	if (IsValidSmbios3EntryPoint(MappedTable)) {
	    *EntryPointStructure = MappedTable;
	    *pIsSmbios3 = TRUE;
	    return STATUS_SUCCESS;
	} else if (IsValidSmbios21EntryPoint(MappedTable)) {
	    *EntryPointStructure = MappedTable;
	    *pIsSmbios3 = FALSE;
	    return STATUS_SUCCESS;
	}
	assert(FALSE);
	return STATUS_NOT_FOUND;
    }
    return STATUS_NOT_FOUND;
}

/*
 * Search in the physical memory window 0xF0000--0xFFFFF to find the SMBIOS
 * entry point structure.
 */
static NTSTATUS HalpLegacyFindSmbiosTable(OUT PPVOID EntryPointStructure,
					  OUT PBOOLEAN IsSmbios3)
{
    PHYSICAL_ADDRESS WindowStart = { .QuadPart = 0xF0000 };
    ULONG WindowSize = 0xFFFF;
    PCHAR SearchWindow = HalpMapTable(WindowStart, WindowSize);
    if (!SearchWindow) {
	return STATUS_NOT_FOUND;
    }
    ULONG WindowOffset = 0;
    while (WindowOffset < WindowSize) {
	if (IsValidSmbios3EntryPoint((PVOID)(SearchWindow + WindowOffset))) {
	    *EntryPointStructure = &SearchWindow[WindowOffset];
	    *IsSmbios3 = TRUE;
	    return STATUS_SUCCESS;
	} else if (IsValidSmbios21EntryPoint((PVOID)(SearchWindow + WindowOffset))) {
	    *EntryPointStructure = &SearchWindow[WindowOffset];
	    *IsSmbios3 = FALSE;
	    return STATUS_SUCCESS;
	}
        /* Next 16-byte-aligned address */
	WindowOffset += 16;
    }
    MmUnmapPhysicalMemory((MWORD)SearchWindow);
    return STATUS_NOT_FOUND;
}

static NTSTATUS HalpParseSmbiosTables()
{
    assert(HalpRawSmbiosTables);
    ParseSMBiosTables(HalpRawSmbiosTables, HalpSmbiosStrings);
    for (ULONG i = 0; i < SMBIOS_ID_STRINGS_MAX; i++) {
	if (!HalpSmbiosStrings[i]) {
	    HalpSmbiosStrings[i] = "";
	}
    }

    DbgTrace("SMBIOS version %d.%d, dmi revision %d, size 0x%x:\n",
	     HalpRawSmbiosTables->SmbiosMajorVersion,
	     HalpRawSmbiosTables->SmbiosMinorVersion,
	     HalpRawSmbiosTables->DmiRevision,
	     HalpRawSmbiosTables->Size);
    DbgPrint("    BIOS_VENDOR = %s\n"
	     "    BIOS_VERSION = %s\n"
	     "    BIOS_DATE = %s\n"
	     "    SYS_VENDOR = %s\n"
	     "    SYS_PRODUCT = %s\n"
	     "    SYS_VERSION = %s\n"
	     "    SYS_SERIAL = %s\n"
	     "    SYS_SKU = %s\n"
	     "    SYS_FAMILY = %s\n"
	     "    BOARD_VENDOR = %s\n"
	     "    BOARD_NAME = %s\n"
	     "    BOARD_VERSION = %s\n"
	     "    BOARD_SERIAL = %s\n"
	     "    BOARD_ASSET_TAG = %s\n",
	     HalpSmbiosStrings[BIOS_VENDOR],
	     HalpSmbiosStrings[BIOS_VERSION],
	     HalpSmbiosStrings[BIOS_DATE],
	     HalpSmbiosStrings[SYS_VENDOR],
	     HalpSmbiosStrings[SYS_PRODUCT],
	     HalpSmbiosStrings[SYS_VERSION],
	     HalpSmbiosStrings[SYS_SERIAL],
	     HalpSmbiosStrings[SYS_SKU],
	     HalpSmbiosStrings[SYS_FAMILY],
	     HalpSmbiosStrings[BOARD_VENDOR],
	     HalpSmbiosStrings[BOARD_NAME],
	     HalpSmbiosStrings[BOARD_VERSION],
	     HalpSmbiosStrings[BOARD_SERIAL],
	     HalpSmbiosStrings[BOARD_ASSET_TAG]);

    return STATUS_SUCCESS;
}

NTSTATUS HalpInitSmbios(VOID)
{
    PVOID EntryPointStructure = NULL;
    BOOLEAN IsSmbios3 = FALSE;
    NTSTATUS Status = HalpEfiFindSmbiosTable(&EntryPointStructure, &IsSmbios3);
    if (!NT_SUCCESS(Status)) {
	Status = HalpLegacyFindSmbiosTable(&EntryPointStructure, &IsSmbios3);
    }
    if (!NT_SUCCESS(Status)) {
	goto out;
    }
    assert(EntryPointStructure);
    PHYSICAL_ADDRESS TablePhyAddr = {};
    UCHAR SmbiosMajorVersion = 0;
    UCHAR SmbiosMinorVersion = 0;
    UCHAR DmiRevision = 0;
    ULONG SmbiosTableSize = 0;
    if (IsSmbios3) {
	PSMBIOS30_ENTRY_POINT EntryPoint = EntryPointStructure;
	TablePhyAddr.QuadPart = EntryPoint->TableAddress;
	SmbiosMajorVersion = EntryPoint->MajorVersion;
	SmbiosMinorVersion = EntryPoint->MinorVersion;
	DmiRevision = EntryPoint->Revision;
	SmbiosTableSize = EntryPoint->TableMaxSize;
    } else {
	PSMBIOS21_ENTRY_POINT EntryPoint = EntryPointStructure;
	TablePhyAddr.QuadPart = EntryPoint->TableAddress;
	SmbiosMajorVersion = EntryPoint->MajorVersion;
	SmbiosMinorVersion = EntryPoint->MinorVersion;
	DmiRevision = EntryPoint->EntryPointRevision;
	SmbiosTableSize = EntryPoint->TableLength;
    }
    ULONG RawSmbiosTableLength = SmbiosTableSize + FIELD_OFFSET(MSSmBios_RawSMBiosTables,
								SMBiosData);
    DbgTrace("SMBIOS table at physical address 0x%llx length 0x%x type SMBIOS%s\n",
	     TablePhyAddr.QuadPart, SmbiosTableSize, IsSmbios3 ? "3" : "21");
    MmUnmapPhysicalMemory((MWORD)EntryPointStructure);
    if (!TablePhyAddr.QuadPart || !SmbiosTableSize) {
	assert(FALSE);
	goto out;
    }
    HalpRawSmbiosTables = ExAllocatePoolWithTag(RawSmbiosTableLength, NTOS_HAL_TAG);
    if (!HalpRawSmbiosTables) {
	assert(FALSE);
	goto out;
    }
    PVOID MappedTable = HalpMapTable(TablePhyAddr, SmbiosTableSize);
    if (!MappedTable) {
	goto out;
    }
    RtlCopyMemory(HalpRawSmbiosTables->SMBiosData, MappedTable, SmbiosTableSize);
    MmUnmapPhysicalMemory((MWORD)MappedTable);
    HalpRawSmbiosTables->SmbiosMajorVersion = SmbiosMajorVersion;
    HalpRawSmbiosTables->SmbiosMinorVersion = SmbiosMinorVersion;
    HalpRawSmbiosTables->DmiRevision = DmiRevision;
    HalpRawSmbiosTables->Size = SmbiosTableSize;
    HalpParseSmbiosTables();

out:
    /* Not being able to map the SMBIOS table is not a fatal error, so we always
     * return SUCCESS */
    return STATUS_SUCCESS;
}
