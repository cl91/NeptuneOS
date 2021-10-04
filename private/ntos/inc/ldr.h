#pragma once

#include <sel4/sel4.h>

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
