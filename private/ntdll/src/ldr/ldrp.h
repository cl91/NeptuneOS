#pragma once

#include <ntdll.h>

/* pe.c */
ULONG LdrpRelocateImage(IN PVOID BaseAddress,
			IN PCCH  LoaderName,
			IN ULONG Success,
			IN ULONG Conflict,
			IN ULONG Invalid);
ULONG LdrpRelocateImageWithBias(IN PVOID BaseAddress,
				IN LONGLONG AdditionalBias,
				IN PCCH  LoaderName,
				IN ULONG Success,
				IN ULONG Conflict,
				IN ULONG Invalid);

/* ../rtl/critical.c */
VOID LdrpInitCriticalSection(HANDLE CriticalSectionLockSemaphore);

NTSTATUS RtlpInitializeCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection,
				       IN HANDLE LockSemaphore,
				       IN ULONG SpinCount);
/* ../rtl/heap.c */
NTSTATUS LdrpInitializeHeapManager(IN PNTDLL_PROCESS_INIT_INFO InitInfo,
				   IN ULONG ProcessHeapFlags,
				   IN PRTL_HEAP_PARAMETERS ProcessHeapParams);

/* ../rtl/vectoreh.c */
VOID RtlpInitializeVectoredExceptionHandling(IN PNTDLL_PROCESS_INIT_INFO InitInfo);
