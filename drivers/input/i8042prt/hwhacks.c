/*
 * PROJECT:     ReactOS i8042 (ps/2 keyboard-mouse controller) driver
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        drivers/input/i8042prt/hwhacks.c
 * PURPOSE:     Mouse specific functions
 * PROGRAMMERS: Timo Kreuzer (timo.kreuzer@reactos.org)
 * REFERENCES:  - http://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.0.0.pdf
 *              -
 */

#include "i8042prt.h"
#include <wmiguid.h>
#include <wmidata.h>
#include <wmistr.h>
#include <dmilib.h>

PVOID i8042SMBiosTables;
ULONG i8042HwFlags;

typedef struct _MATCH_ENTRY {
    ULONG Type;
    PCHAR String;
} SMBIOS_MATCH_ENTRY;

#define MAX_MATCH_ENTRIES 3
typedef struct _HARDWARE_TABLE {
    SMBIOS_MATCH_ENTRY MatchEntries[MAX_MATCH_ENTRIES];
    ULONG Flags;
} HARDWARE_TABLE;

typedef const HARDWARE_TABLE *PHARDWARE_TABLE;

static const HARDWARE_TABLE i8042HardwareTable[] = {
//  { { { BOARD_VENDOR, "RIOWORKS" },
//      { BOARD_NAME, "HDAMB" },
//      { BOARD_VERSION, "Rev E" } },
//    FL_NOLOOP },
//  { { { BOARD_VENDOR, "ASUSTeK Computer Inc."},
//      { BOARD_NAME, "G1S" },
//      { BOARD_VERSION, "1.0" }},
//    FL_NOLOOP },

    { { { SYS_VENDOR, "Microsoft Corporation" },
	{ SYS_PRODUCT, "Virtual Machine" } },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Inspiron 6000                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D430                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D530                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D531                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D600                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D610                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D620                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D630                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude D810                   "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude E4300                  "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude E4310                  "} },
      FL_INITHACK },
    { { { SYS_VENDOR, "Dell Inc."},
	{ SYS_PRODUCT, "Latitude E6400                  "} },
      FL_INITHACK },
};

static PCSTR i8042SmbiosStrings[SMBIOS_ID_STRINGS_MAX] = {};

static PHARDWARE_TABLE i8042HwhackMatchHardware(IN PCSTR Strings[SMBIOS_ID_STRINGS_MAX])
{
    for (ULONG i = 0; i < _ARRAYSIZE(i8042HardwareTable); i++) {
	ULONG j;
	for (j = 0; j < MAX_MATCH_ENTRIES; j++) {
	    ULONG Type = i8042HardwareTable[i].MatchEntries[j].Type;

	    if (Type == SMBIOS_STRING_ID_NONE) {
		/* Note this does NOT skip the increment (j++). */
		continue;
	    }

	    /* If the specified string does not match, break out of the loop.
	     * Note in this case j will be strictly less than MAX_MATCH_ENTRIES. */
	    if (!Strings[Type] ||
		strcmp(i8042HardwareTable[i].MatchEntries[j].String,
		       Strings[i8042HardwareTable[i].MatchEntries[j].Type])) {
		break;
	    }
	}

	if (j == MAX_MATCH_ENTRIES) {
	    /* All items matched! */
	    DPRINT("Found match for hw table index %u\n", i);
	    return &i8042HardwareTable[i];
	}
    }
    return NULL;
}

static VOID i8042ParseSMBiosTables(IN PVOID SMBiosTables)
{
    ParseSMBiosTables(SMBiosTables, i8042SmbiosStrings);

    DbgPrint("i8042prt: Dumping DMI data:\n");
    DbgPrint("BIOS_VENDOR: %s\n", i8042SmbiosStrings[BIOS_VENDOR]);
    DbgPrint("BIOS_VERSION: %s\n", i8042SmbiosStrings[BIOS_VERSION]);
    DbgPrint("BIOS_DATE: %s\n", i8042SmbiosStrings[BIOS_DATE]);
    DbgPrint("SYS_VENDOR: %s\n", i8042SmbiosStrings[SYS_VENDOR]);
    DbgPrint("SYS_PRODUCT: %s\n", i8042SmbiosStrings[SYS_PRODUCT]);
    DbgPrint("SYS_VERSION: %s\n", i8042SmbiosStrings[SYS_VERSION]);
    DbgPrint("SYS_SERIAL: %s\n", i8042SmbiosStrings[SYS_SERIAL]);
    DbgPrint("BOARD_VENDOR: %s\n", i8042SmbiosStrings[BOARD_VENDOR]);
    DbgPrint("BOARD_NAME: %s\n", i8042SmbiosStrings[BOARD_NAME]);
    DbgPrint("BOARD_VERSION: %s\n", i8042SmbiosStrings[BOARD_VERSION]);
    DbgPrint("BOARD_SERIAL: %s\n", i8042SmbiosStrings[BOARD_SERIAL]);
    DbgPrint("BOARD_ASSET_TAG: %s\n", i8042SmbiosStrings[BOARD_ASSET_TAG]);

    /* Now loop the hardware table to find a match */
    PHARDWARE_TABLE Hw = i8042HwhackMatchHardware(i8042SmbiosStrings);
    if (Hw) {
	i8042HwFlags = Hw->Flags;
    }
}

VOID i8042InitializeHwHacks(VOID)
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

    PWNODE_ALL_DATA AllData = ExAllocatePoolWithTag(NonPagedPool,
						    BufferSize, 'BTMS');
    if (AllData == NULL) {
	DPRINT1("Failed to allocate %u bytes for SMBIOS tables\n",
		BufferSize);
	return;
    }

    /* Query the buffer data */
    Status = IoWMIQueryAllData(DataBlockObject, &BufferSize, AllData);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("IoWMIOpenBlock failed: 0x%08x\n", Status);
	ExFreePoolWithTag(AllData, 'BTMS');
	return;
    }

    /* Parse the table */
    i8042ParseSMBiosTables(AllData + 1);

    /* Free the buffer */
    ExFreePoolWithTag(AllData, 'BTMS');
}
