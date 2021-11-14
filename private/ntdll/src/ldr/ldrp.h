#pragma once

#include <ntdll.h>

/* Change this to 0 to enable debug tracing */
#if 1
#undef DbgTrace
#define DbgTrace(...)
#endif

#define LDRP_HASH_TABLE_ENTRIES 32
#define LDRP_GET_HASH_ENTRY(x) (RtlpHashString((x)) & (LDRP_HASH_TABLE_ENTRIES - 1))
extern LIST_ENTRY LdrpHashTable[LDRP_HASH_TABLE_ENTRIES];
extern PVOID LdrpHeap;
extern RTL_CRITICAL_SECTION LdrpLoaderLock;
extern PLDR_DATA_TABLE_ENTRY LdrpImageEntry;

static inline NTSTATUS LdrpUtf8ToUnicodeString(IN PCSTR String,
					       OUT PUNICODE_STRING UnicodeString)
{
    return RtlpUtf8ToUnicodeString(LdrpHeap, String, UnicodeString);
}

static inline VOID LdrpFreeUnicodeString(IN UNICODE_STRING String)
{
    return RtlpFreeUnicodeString(LdrpHeap, String);
}

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
NTSTATUS LdrpWalkImportDescriptor(IN PLDR_DATA_TABLE_ENTRY LdrEntry);
VOID LdrpInsertMemoryTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				IN PCSTR BaseDllName);
PLDR_DATA_TABLE_ENTRY LdrpAllocateDataTableEntry(IN PVOID BaseAddress);
PVOID LdrpFetchAddressOfEntryPoint(IN PVOID ImageBase);
BOOLEAN LdrpCheckForLoadedDll(IN PCSTR DllName,
			      OUT OPTIONAL PLDR_DATA_TABLE_ENTRY *LdrEntry);

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
