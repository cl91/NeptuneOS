/*
 * PROJECT:     ReactOS RTL
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Dynamic function table support routines
 * COPYRIGHT:   Copyright 2022 Timo Kreuzer (timo.kreuzer@reactos.org)
 */

#include "../rtlp.h"

#define TAG_RTLDYNFNTBL 'tfDP'

typedef PRUNTIME_FUNCTION GET_RUNTIME_FUNCTION_CALLBACK(IN DWORD64 ControlPc,
							IN OPTIONAL PVOID Context);
typedef GET_RUNTIME_FUNCTION_CALLBACK *PGET_RUNTIME_FUNCTION_CALLBACK;

typedef DWORD OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK(IN HANDLE Process,
						     IN PVOID TableAddress,
						     OUT PULONG Entries,
						     OUT PRUNTIME_FUNCTION *Functions);
typedef OUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK *POUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK;

typedef enum _FUNCTION_TABLE_TYPE {
    RF_SORTED = 0x0,
    RF_UNSORTED = 0x1,
    RF_CALLBACK = 0x2,
    RF_KERNEL_DYNAMIC = 0x3,
} FUNCTION_TABLE_TYPE;

typedef struct _DYNAMIC_FUNCTION_TABLE {
    LIST_ENTRY ListEntry;
    PRUNTIME_FUNCTION FunctionTable;
    LARGE_INTEGER TimeStamp;
    ULONG64 MinimumAddress;
    ULONG64 MaximumAddress;
    ULONG64 BaseAddress;
    PGET_RUNTIME_FUNCTION_CALLBACK Callback;
    PVOID Context;
    PWCHAR OutOfProcessCallbackDll;
    FUNCTION_TABLE_TYPE Type;
    ULONG EntryCount;
} DYNAMIC_FUNCTION_TABLE, *PDYNAMIC_FUNCTION_TABLE;

RTL_SRWLOCK RtlpDynamicFunctionTableLock = { 0 };
LIST_ENTRY RtlpDynamicFunctionTableList = {
    &RtlpDynamicFunctionTableList,
    &RtlpDynamicFunctionTableList
};

FORCEINLINE VOID AcquireDynamicFunctionTableLockExclusive()
{
    RtlAcquireSRWLockExclusive(&RtlpDynamicFunctionTableLock);
}

FORCEINLINE VOID ReleaseDynamicFunctionTableLockExclusive()
{
    RtlReleaseSRWLockExclusive(&RtlpDynamicFunctionTableLock);
}

FORCEINLINE VOID AcquireDynamicFunctionTableLockShared()
{
    RtlAcquireSRWLockShared(&RtlpDynamicFunctionTableLock);
}

FORCEINLINE VOID ReleaseDynamicFunctionTableLockShared()
{
    RtlReleaseSRWLockShared(&RtlpDynamicFunctionTableLock);
}

/*
 * https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlgetfunctiontablelisthead
 */
NTAPI PLIST_ENTRY RtlGetFunctionTableListHead(void)
{
    return &RtlpDynamicFunctionTableList;
}

static VOID RtlpInsertDynamicFunctionTable(PDYNAMIC_FUNCTION_TABLE DynamicTable)
{
    AcquireDynamicFunctionTableLockExclusive();

    /* Insert it into the list */
    InsertTailList(&RtlpDynamicFunctionTableList, &DynamicTable->ListEntry);

    // TODO: insert into RB-trees

    ReleaseDynamicFunctionTableLockExclusive();
}

NTAPI BOOLEAN RtlAddFunctionTable(IN PRUNTIME_FUNCTION FunctionTable,
				  IN DWORD EntryCount,
				  IN DWORD64 BaseAddress)
{
    PDYNAMIC_FUNCTION_TABLE DynamicTable;

    /* Allocate a dynamic function table */
    DynamicTable = RtlpAllocateMemory(sizeof(*DynamicTable), TAG_RTLDYNFNTBL);
    if (DynamicTable == NULL) {
	DPRINT1("Failed to allocate dynamic function table\n");
	return FALSE;
    }

    /* Initialize fields */
    DynamicTable->FunctionTable = FunctionTable;
    DynamicTable->EntryCount = EntryCount;
    DynamicTable->BaseAddress = BaseAddress;
    DynamicTable->Callback = NULL;
    DynamicTable->Context = NULL;
    DynamicTable->Type = RF_UNSORTED;

    /* Loop all entries to find the margins */
    DynamicTable->MinimumAddress = ULONG64_MAX;
    DynamicTable->MaximumAddress = 0;
    for (ULONG i = 0; i < EntryCount; i++) {
	DynamicTable->MinimumAddress = min(DynamicTable->MinimumAddress,
					   FunctionTable[i].BeginAddress);
	DynamicTable->MaximumAddress = max(DynamicTable->MaximumAddress,
					   FunctionTable[i].EndAddress);
    }

    /* Insert the table into the list */
    RtlpInsertDynamicFunctionTable(DynamicTable);

    return TRUE;
}

NTAPI BOOLEAN RtlInstallFunctionTableCallback(IN DWORD64 TableIdentifier,
					      IN DWORD64 BaseAddress,
					      IN DWORD Length,
					      IN PGET_RUNTIME_FUNCTION_CALLBACK Callback,
					      IN PVOID Context,
					      IN OPTIONAL PCWSTR OutOfProcessCallbackDll)
{
    PDYNAMIC_FUNCTION_TABLE DynamicTable;
    SIZE_T StringLength, AllocationSize;

    /* Make sure the identifier is valid */
    if ((TableIdentifier & 3) != 3) {
	return FALSE;
    }

    /* Check if we have a DLL name */
    if (OutOfProcessCallbackDll != NULL) {
	StringLength = wcslen(OutOfProcessCallbackDll) + 1;
    } else {
	StringLength = 0;
    }

    /* Calculate required size */
    AllocationSize = sizeof(DYNAMIC_FUNCTION_TABLE) + StringLength * sizeof(WCHAR);

    /* Allocate a dynamic function table */
    DynamicTable = RtlpAllocateMemory(AllocationSize, TAG_RTLDYNFNTBL);
    if (DynamicTable == NULL) {
	DPRINT1("Failed to allocate dynamic function table\n");
	return FALSE;
    }

    /* Initialize fields */
    DynamicTable->FunctionTable = (PRUNTIME_FUNCTION)TableIdentifier;
    DynamicTable->EntryCount = 0;
    DynamicTable->BaseAddress = BaseAddress;
    DynamicTable->Callback = Callback;
    DynamicTable->Context = Context;
    DynamicTable->Type = RF_CALLBACK;
    DynamicTable->MinimumAddress = BaseAddress;
    DynamicTable->MaximumAddress = BaseAddress + Length;

    /* If we have a DLL name, copy that, too */
    if (OutOfProcessCallbackDll != NULL) {
	DynamicTable->OutOfProcessCallbackDll = (PWCHAR)(DynamicTable + 1);
	RtlCopyMemory(DynamicTable->OutOfProcessCallbackDll, OutOfProcessCallbackDll,
		      StringLength * sizeof(WCHAR));
    } else {
	DynamicTable->OutOfProcessCallbackDll = NULL;
    }

    /* Insert the table into the list */
    RtlpInsertDynamicFunctionTable(DynamicTable);

    return TRUE;
}

NTAPI BOOLEAN RtlDeleteFunctionTable(IN PRUNTIME_FUNCTION FunctionTable)
{
    PLIST_ENTRY ListLink;
    PDYNAMIC_FUNCTION_TABLE DynamicTable;
    BOOL Removed = FALSE;

    AcquireDynamicFunctionTableLockExclusive();

    /* Loop all tables to find the one to delete */
    for (ListLink = RtlpDynamicFunctionTableList.Flink;
	 ListLink != &RtlpDynamicFunctionTableList; ListLink = ListLink->Flink) {
	DynamicTable = CONTAINING_RECORD(ListLink, DYNAMIC_FUNCTION_TABLE, ListEntry);

	if (DynamicTable->FunctionTable == FunctionTable) {
	    RemoveEntryList(&DynamicTable->ListEntry);
	    Removed = TRUE;
	    break;
	}
    }

    ReleaseDynamicFunctionTableLockExclusive();

    /* If we were successful, free the memory */
    if (Removed) {
	RtlpFreeMemory(DynamicTable, TAG_RTLDYNFNTBL);
    }

    return Removed;
}

NTAPI PRUNTIME_FUNCTION RtlpLookupDynamicFunctionEntry(IN DWORD64 ControlPc,
						       OUT PDWORD64 ImageBase,
						       IN PUNWIND_HISTORY_TABLE HistoryTable)
{
    PLIST_ENTRY ListLink;
    PDYNAMIC_FUNCTION_TABLE DynamicTable;
    PRUNTIME_FUNCTION FunctionTable, FoundEntry = NULL;
    PGET_RUNTIME_FUNCTION_CALLBACK Callback;

    AcquireDynamicFunctionTableLockShared();

    /* Loop all tables to find the one matching ControlPc */
    for (ListLink = RtlpDynamicFunctionTableList.Flink;
	 ListLink != &RtlpDynamicFunctionTableList; ListLink = ListLink->Flink) {
	DynamicTable = CONTAINING_RECORD(ListLink, DYNAMIC_FUNCTION_TABLE, ListEntry);

	if ((ControlPc >= DynamicTable->MinimumAddress) &&
	    (ControlPc < DynamicTable->MaximumAddress)) {
	    /* Check if there is a callback */
	    Callback = DynamicTable->Callback;
	    if (Callback != NULL) {
		PVOID context = DynamicTable->Context;

		*ImageBase = DynamicTable->BaseAddress;
		ReleaseDynamicFunctionTableLockShared();
		return Callback(ControlPc, context);
	    }

	    /* Loop all entries in the function table */
	    FunctionTable = DynamicTable->FunctionTable;
	    for (ULONG i = 0; i < DynamicTable->EntryCount; i++) {
		/* Check if this entry contains the address */
		if ((ControlPc >= FunctionTable[i].BeginAddress) &&
		    (ControlPc < FunctionTable[i].EndAddress)) {
		    FoundEntry = &FunctionTable[i];
		    *ImageBase = DynamicTable->BaseAddress;
		    goto Exit;
		}
	    }
	}
    }

Exit:
    ReleaseDynamicFunctionTableLockShared();

    return FoundEntry;
}
