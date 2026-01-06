/*++

Copyright (c) 2026  Dr. Chang Liu, PhD.

Module Name:

    lnxdrv.h

Abstract:

    This is the public master header for the lnxdrv library. Drivers that links
    with lnxdrv should include this header file.

Revision History:

    2026-01-05  File created
*/

#pragma once

#include <ntddk.h>
#include <ntlnxdrv.h>

NTSTATUS LnxInitializeDriver(IN PDRIVER_OBJECT DriverObject,
			     IN PUNICODE_STRING RegistryPath);
PLNX_DRV_EXPORT_TABLE LnxDrvGetExportTable(IN PDRIVER_OBJECT DriverObject);
