/*++

Copyright (c) 2026  Dr. Chang Liu, PhD.

Module Name:

    lnxdrv.h

Abstract:

    This is the public master header for all NT drivers that delegate their
    functions to a Linkable Extension Driver (lnxdrv). The PE portion of a
    NT Linkable Extension Driver should include this header file. For more
    details of the Linkable Extension Driver design, see ntlnxdrv.h.

Revision History:

    2026-01-05  File created
*/

#pragma once

#include <ntddk.h>
#include <ntlnxdrv.h>

NTSTATUS LnxInitializeDriver(IN PDRIVER_OBJECT DriverObject,
			     IN PUNICODE_STRING RegistryPath);
PLNX_DRV_EXPORT_TABLE LnxDrvGetExportTable(IN PDRIVER_OBJECT DriverObject);
