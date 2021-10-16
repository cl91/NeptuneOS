#pragma once

#include <sel4/sel4.h>

#define BOOTMODULE_OBJECT_DIRECTORY	"\\BootModules"
#define NTDLL_NAME_NO_EXT		"ntdll"
#define NTDLL_NAME			NTDLL_NAME_NO_EXT ".dll"
#define NTDLL_PATH			BOOTMODULE_OBJECT_DIRECTORY "\\" NTDLL_NAME
#define HAL_DLL_NAME			"hal.dll"
#define HAL_PATH			BOOTMODULE_OBJECT_DIRECTORY "\\" HAL_DLL_NAME
#define SMSS_EXE_NAME			"smss.exe"
#define SMSS_PATH			BOOTMODULE_OBJECT_DIRECTORY "\\" SMSS_EXE_NAME

/* boot.c */
NTSTATUS LdrLoadBootModules();

/* pe.c */
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base);

static inline PVOID RtlImageRvaToPtr(IN PVOID FileBuffer,
				     IN ULONG Rva)
{
    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(FileBuffer);
    if (NtHeader == NULL) {
	return NULL;
    }
    return RtlImageRvaToVa(NtHeader, FileBuffer, Rva, NULL);
}
