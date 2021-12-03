#include "ldrp.h"

static inline BOOLEAN LdrpCheckModuleAddress(IN PLDR_DATA_TABLE_ENTRY Entry,
					     PVOID Address)
{
    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(Entry->DllBase);
    if (NtHeader) {
	/* Get the Image Base */
	ULONG_PTR DllBase = (ULONG_PTR) Entry->DllBase;
	ULONG_PTR DllEnd = DllBase + NtHeader->OptionalHeader.SizeOfImage;

	/* Check if they match */
	return ((ULONG_PTR)Address >= DllBase) && ((ULONG_PTR)Address < DllEnd);
    }
    return FALSE;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrFindEntryForAddress(IN PVOID Address,
				      OUT PLDR_DATA_TABLE_ENTRY *Module)
{
    PPEB_LDR_DATA Ldr = NtCurrentPeb()->LdrData;

    /* Nothing to do */
    if (!Ldr) {
	return STATUS_NO_MORE_ENTRIES;
    }

    /* Get the current entry */
    if (LdrpImageEntry && LdrpCheckModuleAddress(LdrpImageEntry, Address)) {
	*Module = LdrpImageEntry;
	return STATUS_SUCCESS;
    }

    /* Loop the module list */
    PLIST_ENTRY ListHead = &Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	/* Get the entry and check if supplied address falls within the module */
	PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY,
							   InMemoryOrderLinks);
	if (LdrpCheckModuleAddress(LdrEntry, Address)) {
	    /* Return it */
	    *Module = LdrEntry;
	    return STATUS_SUCCESS;
	}
	/* Next Entry */
	NextEntry = NextEntry->Flink;
    }

    /* Nothing found */
    DbgTrace("LDR: data table entry for module %p not found\n", Address)
    return STATUS_NO_MORE_ENTRIES;
}

/*
 * @implemented
 */
NTAPI VOID RtlAcquirePebLock(VOID)
{
   PPEB Peb = NtCurrentPeb ();
   RtlEnterCriticalSection(Peb->FastPebLock);
}

/*
 * @implemented
 */
NTAPI VOID RtlReleasePebLock(VOID)
{
   PPEB Peb = NtCurrentPeb ();
   RtlLeaveCriticalSection(Peb->FastPebLock);
}
