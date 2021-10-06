#pragma once

#include <sel4/sel4.h>

#define BOOTMODULE_PARENT_DIRECTORY	"\\"
#define BOOTMODULE_DIRECTORY		"BootModules"
#define BOOTMODULE_PATH			BOOTMODULE_PARENT_DIRECTORY BOOTMODULE_DIRECTORY
#define NTDLL_NAME_NO_EXT		"ntdll"
#define NTDLL_NAME			NTDLL_NAME_NO_EXT ".dll"
#define NTDLL_PATH			BOOTMODULE_PATH "\\" NTDLL_NAME

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
