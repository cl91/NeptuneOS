/*++

Copyright (c) 2026  Dr. Chang Liu, PhD.

Module Name:

    lnxdrv.h

Abstract:

    This is the public master header for all NT drivers that delegate their
    functions to a Linkable Extension Driver (lnxdrv). The PE portion of a
    NT Linkable Extension Driver should include this header file. For more
    details of the Linkable Extension Driver design, see ntlnxdrv.h in the
    Linux kernel submodule (arch/ntos/include/ntlnxdrv.h).

Revision History:

    2026-01-05  File created
*/

#pragma once

#include <ntddk.h>

#define LNXDRV_DEV_OBJ_PATH	(L"\\Device\\LnxDrv")

#ifndef LNXDRV_SYS
#define LNXDRV_API DECLSPEC_IMPORT
#else
#define LNXDRV_API
#endif

NTSTATUS NTAPI LNXDRV_API LnxInitializeDriver(IN PDRIVER_OBJECT DriverObject,
					      IN PUNICODE_STRING RegistryPath);

VOID LNXDRV_API LnxEnableOnScreenDbgPrint(VOID);
