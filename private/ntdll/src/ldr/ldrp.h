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

/* ../rtl/heap.c */
NTSTATUS LdrpInitializeHeapManager(IN PVOID ProcessHeap,
				   IN ULONG ProcessHeapFlags,
				   IN SIZE_T ProcessHeapReserve,
				   IN SIZE_T ProcessHeapCommit,
				   IN PRTL_HEAP_PARAMETERS ProcessHeapParams,
				   IN PVOID LoaderHeap);

/* ../rtl/vectoreh.c */
VOID RtlpInitializeVectoredExceptionHandling(VOID);
