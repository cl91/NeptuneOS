#pragma once

#include <ntdll.h>

/* pe.c */
ULONG NTAPI LdrpRelocateImage(IN PVOID BaseAddress,
			      IN PCCH  LoaderName,
			      IN ULONG Success,
			      IN ULONG Conflict,
			      IN ULONG Invalid);
ULONG NTAPI LdrpRelocateImageWithBias(IN PVOID BaseAddress,
				      IN LONGLONG AdditionalBias,
				      IN PCCH  LoaderName,
				      IN ULONG Success,
				      IN ULONG Conflict,
				      IN ULONG Invalid);

/* ../rtl/critical.c */
VOID LdrpInitCriticalSection(HANDLE CriticalSectionLockSemaphore);
