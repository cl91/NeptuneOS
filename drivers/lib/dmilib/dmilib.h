/*
 * PROJECT:     ReactOS DMI/SMBIOS Library
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        dmilib.h
 * PURPOSE:     SMBIOS table parsing functions
 * PROGRAMMERS: Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#ifndef DMILIB_H
#define DMILIB_H

enum _SMBIOS_ID_STRINGS {
    SMBIOS_STRING_ID_NONE = 0,
    BIOS_VENDOR,
    BIOS_VERSION,
    BIOS_DATE,
    SYS_VENDOR,
    SYS_PRODUCT,
    SYS_VERSION,
    SYS_SERIAL,
    SYS_SKU,
    SYS_FAMILY,
    BOARD_VENDOR,
    BOARD_NAME,
    BOARD_VERSION,
    BOARD_SERIAL,
    BOARD_ASSET_TAG,

    SMBIOS_ID_STRINGS_MAX,
};

VOID ParseSMBiosTables(IN PMSSmBios_RawSMBiosTables SmbiosTables,
		       OUT PCSTR Strings[SMBIOS_ID_STRINGS_MAX]);

#endif	/* DMILIB_H */
