/*
 * Public Master Header for the VideoPort driver. A video miniport driver
 * should include this master header.
 */

#pragma once

#include <ntddk.h>

#ifdef _VIDEOPRT_
#define VIDEOPRT_API
#else
#define VIDEOPRT_API DECLSPEC_IMPORT
#endif

typedef struct _VIDEO_HW_INITIALIZATION_DATA {
    ULONG HwInitDataSize;
} VIDEO_HW_INITIALIZATION_DATA, *PVIDEO_HW_INITIALIZATION_DATA;

NTAPI VIDEOPRT_API NTSTATUS VideoPortInitialize(IN PDRIVER_OBJECT DriverObject,
						IN PUNICODE_STRING RegistryPath,
						IN PVIDEO_HW_INITIALIZATION_DATA HwInitData,
						IN PVOID HwContext);
