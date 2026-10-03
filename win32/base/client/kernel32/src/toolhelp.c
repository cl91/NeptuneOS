/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            dll/win32/kernel32/client/toolhelp.c
 * PURPOSE:         Toolhelp functions
 * PROGRAMMER:      Thomas Weidenmueller <w3seek@reactos.com>
 *                  Robert Dickenson (robd@mok.lvcm.com)
 *
 * NOTES:           Do NOT use the heap functions in here because they
 *                  adulterate the heap statistics!
 *
 * UPDATE HISTORY:
 *                  10/30/2004 Implemented some parts (w3)
 *                             Inspired by the book "Windows NT Native API"
 *                  Created 05 January 2003 (robd)
 */

#include <k32.h>

/* INTERNAL DEFINITIONS *******************************************************/

typedef struct _RTLP_HEAP_ENTRY {
    ULONG Size;
    USHORT Flags;
    USHORT Unknown1; /* FIXME */
    ULONG Unknown2; /* FIXME */
    PVOID Address;
} RTLP_HEAP_ENTRY, *PRTLP_HEAP_ENTRY;

#define CHECK_PARAM_SIZE(ptr, siz)                 \
    if ((ptr) == NULL || (ptr)->dwSize != (siz)) { \
	SetLastError(ERROR_INVALID_PARAMETER);     \
	return FALSE;                              \
    }

/*
 * Tests in win showed that the dwSize field can be greater than the actual size
 * of the structure for the ansi functions. I found this out by accidently
 * forgetting to set the dwSize field in a test application and it just didn't
 * work in ros but in win.
 */

#define CHECK_PARAM_SIZEA(ptr, siz)               \
    if ((ptr) == NULL || (ptr)->dwSize < (siz)) { \
	SetLastError(ERROR_INVALID_PARAMETER);    \
	return FALSE;                             \
    }

#define OffsetToPtr(Snapshot, Offset) ((ULONG_PTR)((Snapshot) + 1) + (ULONG_PTR)(Offset))

typedef struct _TH32SNAPSHOT {
    /* Heap list */
    ULONG HeapListCount;
    ULONG HeapListIndex;
    ULONG_PTR HeapListOffset;
    /* Module list */
    ULONG ModuleListCount;
    ULONG ModuleListIndex;
    ULONG_PTR ModuleListOffset;
    /* Process list */
    ULONG ProcessListCount;
    ULONG ProcessListIndex;
    ULONG_PTR ProcessListOffset;
    /* Thread list */
    ULONG ThreadListCount;
    ULONG ThreadListIndex;
    ULONG_PTR ThreadListOffset;
} TH32SNAPSHOT, *PTH32SNAPSHOT;

/* INTERNAL FUNCTIONS *********************************************************/

static VOID TH32FreeAllocatedResources(PRTL_DEBUG_INFORMATION HeapDebug,
				       PRTL_DEBUG_INFORMATION ModuleDebug,
				       PVOID ProcThrdInfo, SIZE_T ProcThrdInfoSize)
{
    if (HeapDebug != NULL) {
	RtlDestroyQueryDebugBuffer(HeapDebug);
    }
    if (ModuleDebug != NULL) {
	RtlDestroyQueryDebugBuffer(ModuleDebug);
    }

    if (ProcThrdInfo != NULL) {
	NtFreeVirtualMemory(NtCurrentProcess(), &ProcThrdInfo, &ProcThrdInfoSize,
			    MEM_RELEASE);
    }
}

static NTSTATUS TH32CreateSnapshot(DWORD dwFlags, DWORD Th32ProcessId,
				   PRTL_DEBUG_INFORMATION *HeapDebug,
				   PRTL_DEBUG_INFORMATION *ModuleDebug,
				   PVOID *ProcThrdInfo, SIZE_T *ProcThrdInfoSize)
{
    NTSTATUS Status = STATUS_SUCCESS;

    *HeapDebug = NULL;
    *ModuleDebug = NULL;
    *ProcThrdInfo = NULL;
    *ProcThrdInfoSize = 0;

    /*
     * Allocate the debug information for a heap snapshot
     */
    if (dwFlags & TH32CS_SNAPHEAPLIST) {
	*HeapDebug = RtlCreateQueryDebugBuffer(0, FALSE);
	if (*HeapDebug != NULL) {
	    Status = RtlQueryProcessDebugInformation(Th32ProcessId, RTL_DEBUG_QUERY_HEAPS,
						     *HeapDebug);
	} else
	    Status = STATUS_UNSUCCESSFUL;
    }

    /*
     * Allocate the debug information for a module snapshot
     */
    if (dwFlags & TH32CS_SNAPMODULE && NT_SUCCESS(Status)) {
	*ModuleDebug = RtlCreateQueryDebugBuffer(0, FALSE);
	if (*ModuleDebug != NULL) {
	    Status = RtlQueryProcessDebugInformation(Th32ProcessId,
						     RTL_DEBUG_QUERY_MODULES,
						     *ModuleDebug);
	} else
	    Status = STATUS_UNSUCCESSFUL;
    }

    /*
     * Allocate enough memory for the system's process list
     */

    if (dwFlags & (TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD) && NT_SUCCESS(Status)) {
	for (;;) {
	    (*ProcThrdInfoSize) += 0x10000;
	    Status = NtAllocateVirtualMemory(NtCurrentProcess(), ProcThrdInfo, 0,
					     ProcThrdInfoSize, MEM_COMMIT,
					     PAGE_READWRITE);
	    if (!NT_SUCCESS(Status)) {
		break;
	    }

	    Status = NtQuerySystemInformation(SystemProcessInformation, *ProcThrdInfo,
					      *ProcThrdInfoSize, NULL);
	    if (Status == STATUS_INFO_LENGTH_MISMATCH) {
		NtFreeVirtualMemory(NtCurrentProcess(), ProcThrdInfo, ProcThrdInfoSize,
				    MEM_RELEASE);
		*ProcThrdInfo = NULL;
	    } else {
		break;
	    }
	}
    }

    /*
     * Free resources in case of failure!
     */

    if (!NT_SUCCESS(Status)) {
	TH32FreeAllocatedResources(*HeapDebug, *ModuleDebug, *ProcThrdInfo,
				   *ProcThrdInfoSize);
    }

    return Status;
}

static NTSTATUS TH32CreateSnapshotSectionInitialize(DWORD dwFlags, DWORD Th32ProcessId,
						    PRTL_DEBUG_INFORMATION HeapDebug,
						    PRTL_DEBUG_INFORMATION ModuleDebug,
						    PVOID ProcThrdInfo,
						    HANDLE *SectionHandle)
{
    PSYSTEM_PROCESS_INFORMATION ProcessInfo;
    LPHEAPLIST32 HeapListEntry;
    LPMODULEENTRY32W ModuleListEntry;
    LPPROCESSENTRY32W ProcessListEntry;
    LPTHREADENTRY32 ThreadListEntry;
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER SSize, SOffset;
    HANDLE hSection;
    PTH32SNAPSHOT Snapshot;
    ULONG_PTR DataOffset;
    SIZE_T ViewSize;
    ULONG i, nProcesses = 0, nThreads = 0, nHeaps = 0, nModules = 0;
    ULONG RequiredSnapshotSize = sizeof(TH32SNAPSHOT);
    PRTL_PROCESS_HEAPS HeapInfo = NULL;
    PRTL_PROCESS_MODULES ModulesInfo = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    /*
     * Determine the required size for the heap snapshot
     */
    if (dwFlags & TH32CS_SNAPHEAPLIST) {
	HeapInfo = (PRTL_PROCESS_HEAPS)HeapDebug->Heaps;
	nHeaps = HeapInfo->NumberOfHeaps;
	RequiredSnapshotSize += nHeaps * sizeof(HEAPLIST32);
    }

    /*
     * Determine the required size for the module snapshot
     */
    if (dwFlags & TH32CS_SNAPMODULE) {
	ModulesInfo = (PRTL_PROCESS_MODULES)ModuleDebug->Modules;
	nModules = ModulesInfo->NumberOfModules;
	RequiredSnapshotSize += nModules * sizeof(MODULEENTRY32W);
    }

    /*
     * Determine the required size for the processes and threads snapshot
     */
    if (dwFlags & (TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD)) {
	ULONG ProcOffset = 0;

	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ProcThrdInfo;
	do {
	    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)ProcessInfo +
							ProcOffset);
	    nProcesses++;
	    nThreads += ProcessInfo->NumberOfThreads;
	    ProcOffset = ProcessInfo->NextEntryOffset;
	} while (ProcOffset != 0);

	if (dwFlags & TH32CS_SNAPPROCESS) {
	    RequiredSnapshotSize += nProcesses * sizeof(PROCESSENTRY32W);
	}
	if (dwFlags & TH32CS_SNAPTHREAD) {
	    RequiredSnapshotSize += nThreads * sizeof(THREADENTRY32);
	}
    }

    /*
     * Create and map the section
     */

    SSize.QuadPart = RequiredSnapshotSize;

    InitializeObjectAttributes(&ObjectAttributes, NULL,
			       ((dwFlags & TH32CS_INHERIT) ? OBJ_INHERIT : 0), NULL,
			       NULL);

    Status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, &ObjectAttributes, &SSize,
			     PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSection, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
	NtClose(hSection);
	return Status;
    }

    RtlZeroMemory(Snapshot, sizeof(TH32SNAPSHOT));
    DataOffset = 0;

    /*
     * Initialize the section data and fill it with all the data we collected
     */

    /* initialize the heap list */
    if (dwFlags & TH32CS_SNAPHEAPLIST) {
	Snapshot->HeapListCount = nHeaps;
	Snapshot->HeapListOffset = DataOffset;
	HeapListEntry = (LPHEAPLIST32)OffsetToPtr(Snapshot, DataOffset);
	for (i = 0; i < nHeaps; i++) {
	    HeapListEntry->dwSize = sizeof(HEAPLIST32);
	    HeapListEntry->th32ProcessID = Th32ProcessId;
	    HeapListEntry->th32HeapID = (ULONG_PTR)HeapInfo->Heaps[i].BaseAddress;
	    HeapListEntry->dwFlags = HeapInfo->Heaps[i].Flags;

	    HeapListEntry++;
	}

	DataOffset += HeapInfo->NumberOfHeaps * sizeof(HEAPLIST32);
    }

    /* initialize the module list */
    if (dwFlags & TH32CS_SNAPMODULE) {
	Snapshot->ModuleListCount = nModules;
	Snapshot->ModuleListOffset = DataOffset;
	ModuleListEntry = (LPMODULEENTRY32W)OffsetToPtr(Snapshot, DataOffset);
	for (i = 0; i < nModules; i++) {
	    ModuleListEntry->dwSize = sizeof(MODULEENTRY32W);
	    ModuleListEntry->th32ModuleID = 1; /* no longer used, always set to one! */
	    ModuleListEntry->th32ProcessID = Th32ProcessId;
	    ModuleListEntry->GlblcntUsage = ModulesInfo->Modules[i].LoadCount;
	    ModuleListEntry->ProccntUsage = ModulesInfo->Modules[i].LoadCount;
	    ModuleListEntry->modBaseAddr = (BYTE *)ModulesInfo->Modules[i].ImageBase;
	    ModuleListEntry->modBaseSize = ModulesInfo->Modules[i].ImageSize;
	    ModuleListEntry->hModule = (HMODULE)ModulesInfo->Modules[i].ImageBase;

	    MultiByteToWideChar(
		CP_ACP, 0,
		&ModulesInfo->Modules[i]
		     .FullPathName[ModulesInfo->Modules[i].OffsetToFileName],
		-1, ModuleListEntry->szModule,
		sizeof(ModuleListEntry->szModule) / sizeof(ModuleListEntry->szModule[0]));

	    MultiByteToWideChar(CP_ACP, 0, ModulesInfo->Modules[i].FullPathName, -1,
				ModuleListEntry->szExePath,
				sizeof(ModuleListEntry->szExePath) /
				    sizeof(ModuleListEntry->szExePath[0]));

	    ModuleListEntry++;
	}

	DataOffset += ModulesInfo->NumberOfModules * sizeof(MODULEENTRY32W);
    }

    /* initialize the process list */
    if (dwFlags & TH32CS_SNAPPROCESS) {
	ULONG ProcOffset = 0;

	Snapshot->ProcessListCount = nProcesses;
	Snapshot->ProcessListOffset = DataOffset;
	ProcessListEntry = (LPPROCESSENTRY32W)OffsetToPtr(Snapshot, DataOffset);
	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ProcThrdInfo;
	do {
	    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)ProcessInfo +
							ProcOffset);

	    ProcessListEntry->dwSize = sizeof(PROCESSENTRY32W);
	    ProcessListEntry->cntUsage = 0; /* no longer used */
	    ProcessListEntry->th32ProcessID = (ULONG_PTR)ProcessInfo->UniqueProcessId;
	    ProcessListEntry->th32DefaultHeapID = 0; /* no longer used */
	    ProcessListEntry->th32ModuleID = 0; /* no longer used */
	    ProcessListEntry->cntThreads = ProcessInfo->NumberOfThreads;
	    ProcessListEntry->th32ParentProcessID =
		(ULONG_PTR)ProcessInfo->InheritedFromUniqueProcessId;
	    ProcessListEntry->pcPriClassBase = ProcessInfo->BasePriority;
	    ProcessListEntry->dwFlags = 0; /* no longer used */
	    if (ProcessInfo->ImageName.Buffer != NULL) {
		ULONG ExeFileLength = min(ProcessInfo->ImageName.Length,
					  sizeof(ProcessListEntry->szExeFile) -
					      sizeof(WCHAR));
		RtlCopyMemory(ProcessListEntry->szExeFile, ProcessInfo->ImageName.Buffer,
			      ExeFileLength);
		ProcessListEntry->szExeFile[ExeFileLength / sizeof(WCHAR)] = UNICODE_NULL;
	    } else {
		lstrcpyW(ProcessListEntry->szExeFile, L"[System Process]");
	    }

	    ProcessListEntry++;

	    ProcOffset = ProcessInfo->NextEntryOffset;
	} while (ProcOffset != 0);

	DataOffset += nProcesses * sizeof(PROCESSENTRY32W);
    }

    /* initialize the thread list */
    if (dwFlags & TH32CS_SNAPTHREAD) {
	ULONG ProcOffset = 0;

	Snapshot->ThreadListCount = nThreads;
	Snapshot->ThreadListOffset = DataOffset;
	ThreadListEntry = (LPTHREADENTRY32)OffsetToPtr(Snapshot, DataOffset);
	ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ProcThrdInfo;
	do {
	    PSYSTEM_THREAD_INFORMATION ThreadInfo;
	    ULONG n;

	    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)ProcessInfo +
							ProcOffset);
	    ThreadInfo = (PSYSTEM_THREAD_INFORMATION)(ProcessInfo + 1);

	    for (n = 0; n < ProcessInfo->NumberOfThreads; n++) {
		ThreadListEntry->dwSize = sizeof(THREADENTRY32);
		ThreadListEntry->cntUsage = 0; /* no longer used */
		ThreadListEntry->th32ThreadID = (ULONG_PTR)
						    ThreadInfo->ClientId.UniqueThread;
		ThreadListEntry->th32OwnerProcessID =
		    (ULONG_PTR)ThreadInfo->ClientId.UniqueProcess;
		ThreadListEntry->tpBasePri = ThreadInfo->BasePriority;
		ThreadListEntry->tpDeltaPri = 0; /* no longer used */
		ThreadListEntry->dwFlags = 0; /* no longer used */

		ThreadInfo++;
		ThreadListEntry++;
	    }

	    ProcOffset = ProcessInfo->NextEntryOffset;
	} while (ProcOffset != 0);
    }

    /*
     * We're done, unmap the view and return the section handle
     */

    Status = NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);

    if (NT_SUCCESS(Status)) {
	*SectionHandle = hSection;
    } else {
	NtClose(hSection);
    }

    return Status;
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*
 * @implemented
 */
WINAPI BOOL Heap32First(LPHEAPENTRY32 lpHeapEntry, DWORD Th32ProcessId, DWORD Th32HeapId)
{
    PRTL_DEBUG_INFORMATION DebugInfo;
    PRTL_HEAP_INFORMATION Heap;
    PRTLP_HEAP_ENTRY Block, LastBlock;
    ULONG i;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpHeapEntry, sizeof(HEAPENTRY32));

    DebugInfo = RtlCreateQueryDebugBuffer(0, FALSE);
    if (DebugInfo == NULL) {
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return FALSE;
    }

    Status = RtlQueryProcessDebugInformation(
	Th32ProcessId, RTL_DEBUG_QUERY_HEAPS | RTL_DEBUG_QUERY_HEAP_BLOCKS, DebugInfo);

    if (NT_SUCCESS(Status)) {
	Status = STATUS_NO_MORE_FILES;

	for (i = 0; i != DebugInfo->Heaps->NumberOfHeaps; i++) {
	    Heap = &DebugInfo->Heaps->Heaps[i];

	    if ((ULONG_PTR)Heap->BaseAddress == Th32HeapId) {
		lpHeapEntry->hHandle = (HANDLE)Heap->BaseAddress;
		lpHeapEntry->dwAddress = 0;
		lpHeapEntry->dwBlockSize = 0;
		lpHeapEntry->dwFlags = 0;
		lpHeapEntry->dwLockCount = 0;
		lpHeapEntry->dwResvd = 0;
		lpHeapEntry->th32ProcessID = Th32ProcessId;
		lpHeapEntry->th32HeapID = (ULONG_PTR)Heap->BaseAddress;

		Block = (PRTLP_HEAP_ENTRY)Heap->Entries;
		LastBlock = Block + Heap->NumberOfEntries;

		while (Block != LastBlock &&
		       (Block->Flags & PROCESS_HEAP_UNCOMMITTED_RANGE)) {
		    lpHeapEntry->dwResvd++;
		    lpHeapEntry->dwAddress = (ULONG_PTR)((ULONG_PTR)Block->Address +
							 Heap->EntryOverhead);
		    Block++;
		}

		if (Block != LastBlock && lpHeapEntry->dwResvd != 0) {
		    lpHeapEntry->dwBlockSize = Block->Size;

		    if (Block->Flags & 0x2F1) /* FIXME */
			lpHeapEntry->dwFlags = LF32_FIXED;
		    else if (Block->Flags & 0x20) /* FIXME */
			lpHeapEntry->dwFlags = LF32_MOVEABLE;
		    else if (Block->Flags & 0x100) /* FIXME */
			lpHeapEntry->dwFlags = LF32_FREE;

		    Status = STATUS_SUCCESS;
		}

		break;
	    }
	}
    }

    RtlDestroyQueryDebugBuffer(DebugInfo);

    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL Heap32Next(LPHEAPENTRY32 lpHeapEntry)
{
    PRTL_DEBUG_INFORMATION DebugInfo;
    PRTL_HEAP_INFORMATION Heap;
    PRTLP_HEAP_ENTRY Block, LastBlock;
    BOOLEAN FoundUncommitted = FALSE;
    ULONG i;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpHeapEntry, sizeof(HEAPENTRY32));

    DebugInfo = RtlCreateQueryDebugBuffer(0, FALSE);
    if (DebugInfo == NULL) {
	SetLastError(ERROR_NOT_ENOUGH_MEMORY);
	return FALSE;
    }

    Status = RtlQueryProcessDebugInformation(lpHeapEntry->th32ProcessID,
					     RTL_DEBUG_QUERY_HEAPS |
						 RTL_DEBUG_QUERY_HEAP_BLOCKS,
					     DebugInfo);

    if (NT_SUCCESS(Status)) {
	Status = STATUS_NO_MORE_FILES;

	for (i = 0; i != DebugInfo->Heaps->NumberOfHeaps; i++) {
	    Heap = &DebugInfo->Heaps->Heaps[i];

	    if ((ULONG_PTR)Heap->BaseAddress == lpHeapEntry->th32HeapID) {
		if (++lpHeapEntry->dwResvd < Heap->NumberOfEntries) {
		    lpHeapEntry->dwFlags = 0;

		    Block = (PRTLP_HEAP_ENTRY)Heap->Entries + lpHeapEntry->dwResvd;
		    LastBlock = (PRTLP_HEAP_ENTRY)Heap->Entries + Heap->NumberOfEntries;

		    while (Block < LastBlock &&
			   (Block->Flags & PROCESS_HEAP_UNCOMMITTED_RANGE)) {
			lpHeapEntry->dwResvd++;
			lpHeapEntry->dwAddress = (ULONG_PTR)((ULONG_PTR)Block->Address +
							     Heap->EntryOverhead);
			FoundUncommitted = TRUE;
			Block++;
		    }

		    if (Block < LastBlock) {
			if (!FoundUncommitted)
			    lpHeapEntry->dwAddress += lpHeapEntry->dwBlockSize;

			lpHeapEntry->dwBlockSize = Block->Size;

			if (Block->Flags & 0x2F1) /* FIXME */
			    lpHeapEntry->dwFlags = LF32_FIXED;
			else if (Block->Flags & 0x20) /* FIXME */
			    lpHeapEntry->dwFlags = LF32_MOVEABLE;
			else if (Block->Flags & 0x100) /* FIXME */
			    lpHeapEntry->dwFlags = LF32_FREE;

			Status = STATUS_SUCCESS;
		    }
		}

		break;
	    }
	}
    }

    RtlDestroyQueryDebugBuffer(DebugInfo);

    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
WINAPI BOOL Heap32ListFirst(HANDLE hSnapshot, LPHEAPLIST32 lpHeapList)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpHeapList, sizeof(HEAPLIST32));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if (Snapshot->HeapListCount > 0) {
	    LPHEAPLIST32 Entries = (LPHEAPLIST32)OffsetToPtr(Snapshot,
							     Snapshot->HeapListOffset);
	    Snapshot->HeapListIndex = 1;
	    RtlCopyMemory(lpHeapList, &Entries[0], sizeof(HEAPLIST32));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Heap32ListNext(HANDLE hSnapshot, LPHEAPLIST32 lpHeapList)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpHeapList, sizeof(HEAPLIST32));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if (Snapshot->HeapListCount > 0 &&
	    Snapshot->HeapListIndex < Snapshot->HeapListCount) {
	    LPHEAPLIST32 Entries = (LPHEAPLIST32)OffsetToPtr(Snapshot,
							     Snapshot->HeapListOffset);
	    RtlCopyMemory(lpHeapList, &Entries[Snapshot->HeapListIndex++],
			  sizeof(HEAPLIST32));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpModuleEntry)
{
    MODULEENTRY32W ModuleEntry;
    BOOL Ret;

    CHECK_PARAM_SIZEA(lpModuleEntry, sizeof(MODULEENTRY32));

    ModuleEntry.dwSize = sizeof(MODULEENTRY32W);

    Ret = Module32FirstW(hSnapshot, &ModuleEntry);
    if (Ret) {
	lpModuleEntry->th32ModuleID = ModuleEntry.th32ModuleID;
	lpModuleEntry->th32ProcessID = ModuleEntry.th32ProcessID;
	lpModuleEntry->GlblcntUsage = ModuleEntry.GlblcntUsage;
	lpModuleEntry->ProccntUsage = ModuleEntry.ProccntUsage;
	lpModuleEntry->modBaseAddr = ModuleEntry.modBaseAddr;
	lpModuleEntry->modBaseSize = ModuleEntry.modBaseSize;
	lpModuleEntry->hModule = ModuleEntry.hModule;

	WideCharToMultiByte(CP_ACP, 0, ModuleEntry.szModule, -1, lpModuleEntry->szModule,
			    sizeof(lpModuleEntry->szModule), 0, 0);
	WideCharToMultiByte(CP_ACP, 0, ModuleEntry.szExePath, -1,
			    lpModuleEntry->szExePath, sizeof(lpModuleEntry->szExePath), 0,
			    0);
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI BOOL Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpModuleEntry)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpModuleEntry, sizeof(MODULEENTRY32W));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if (Snapshot->ModuleListCount > 0) {
	    LPMODULEENTRY32W Entries = (LPMODULEENTRY32W)
		OffsetToPtr(Snapshot, Snapshot->ModuleListOffset);
	    Snapshot->ModuleListIndex = 1;
	    RtlCopyMemory(lpModuleEntry, &Entries[0], sizeof(MODULEENTRY32W));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpModuleEntry)
{
    MODULEENTRY32W ModuleEntry;
    BOOL Ret;

    CHECK_PARAM_SIZEA(lpModuleEntry, sizeof(MODULEENTRY32));

    ModuleEntry.dwSize = sizeof(MODULEENTRY32W);

    Ret = Module32NextW(hSnapshot, &ModuleEntry);
    if (Ret) {
	lpModuleEntry->th32ModuleID = ModuleEntry.th32ModuleID;
	lpModuleEntry->th32ProcessID = ModuleEntry.th32ProcessID;
	lpModuleEntry->GlblcntUsage = ModuleEntry.GlblcntUsage;
	lpModuleEntry->ProccntUsage = ModuleEntry.ProccntUsage;
	lpModuleEntry->modBaseAddr = ModuleEntry.modBaseAddr;
	lpModuleEntry->modBaseSize = ModuleEntry.modBaseSize;
	lpModuleEntry->hModule = ModuleEntry.hModule;

	WideCharToMultiByte(CP_ACP, 0, ModuleEntry.szModule, -1, lpModuleEntry->szModule,
			    sizeof(lpModuleEntry->szModule), 0, 0);
	WideCharToMultiByte(CP_ACP, 0, ModuleEntry.szExePath, -1,
			    lpModuleEntry->szExePath, sizeof(lpModuleEntry->szExePath), 0,
			    0);
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI BOOL Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpModuleEntry)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpModuleEntry, sizeof(MODULEENTRY32W));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if ((Snapshot->ModuleListCount > 0) &&
	    (Snapshot->ModuleListIndex < Snapshot->ModuleListCount)) {
	    LPMODULEENTRY32W Entries = (LPMODULEENTRY32W)
		OffsetToPtr(Snapshot, Snapshot->ModuleListOffset);
	    RtlCopyMemory(lpModuleEntry, &Entries[Snapshot->ModuleListIndex++],
			  sizeof(MODULEENTRY32W));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lpProcessEntry)
{
    PROCESSENTRY32W ProcessEntry;
    BOOL Ret;

    CHECK_PARAM_SIZEA(lpProcessEntry, sizeof(PROCESSENTRY32));

    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    Ret = Process32FirstW(hSnapshot, &ProcessEntry);
    if (Ret) {
	lpProcessEntry->cntUsage = ProcessEntry.cntUsage;
	lpProcessEntry->th32ProcessID = ProcessEntry.th32ProcessID;
	lpProcessEntry->th32DefaultHeapID = ProcessEntry.th32DefaultHeapID;
	lpProcessEntry->th32ModuleID = ProcessEntry.th32ModuleID;
	lpProcessEntry->cntThreads = ProcessEntry.cntThreads;
	lpProcessEntry->th32ParentProcessID = ProcessEntry.th32ParentProcessID;
	lpProcessEntry->pcPriClassBase = ProcessEntry.pcPriClassBase;
	lpProcessEntry->dwFlags = ProcessEntry.dwFlags;

	WideCharToMultiByte(CP_ACP, 0, ProcessEntry.szExeFile, -1,
			    lpProcessEntry->szExeFile, sizeof(lpProcessEntry->szExeFile),
			    0, 0);
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI BOOL Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lpProcessEntry)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpProcessEntry, sizeof(PROCESSENTRY32W));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if (Snapshot->ProcessListCount > 0) {
	    LPPROCESSENTRY32W Entries = (LPPROCESSENTRY32W)
		OffsetToPtr(Snapshot, Snapshot->ProcessListOffset);

	    Snapshot->ProcessListIndex = 1;
	    RtlCopyMemory(lpProcessEntry, &Entries[0], sizeof(PROCESSENTRY32W));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lpProcessEntry)
{
    PROCESSENTRY32W ProcessEntry;
    BOOL Ret;

    CHECK_PARAM_SIZEA(lpProcessEntry, sizeof(PROCESSENTRY32));

    ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

    Ret = Process32NextW(hSnapshot, &ProcessEntry);
    if (Ret) {
	lpProcessEntry->cntUsage = ProcessEntry.cntUsage;
	lpProcessEntry->th32ProcessID = ProcessEntry.th32ProcessID;
	lpProcessEntry->th32DefaultHeapID = ProcessEntry.th32DefaultHeapID;
	lpProcessEntry->th32ModuleID = ProcessEntry.th32ModuleID;
	lpProcessEntry->cntThreads = ProcessEntry.cntThreads;
	lpProcessEntry->th32ParentProcessID = ProcessEntry.th32ParentProcessID;
	lpProcessEntry->pcPriClassBase = ProcessEntry.pcPriClassBase;
	lpProcessEntry->dwFlags = ProcessEntry.dwFlags;

	WideCharToMultiByte(CP_ACP, 0, ProcessEntry.szExeFile, -1,
			    lpProcessEntry->szExeFile, sizeof(lpProcessEntry->szExeFile),
			    0, 0);
    }

    return Ret;
}

/*
 * @implemented
 */
WINAPI BOOL Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lpProcessEntry)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpProcessEntry, sizeof(PROCESSENTRY32W));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if (Snapshot->ProcessListCount > 0 &&
	    Snapshot->ProcessListIndex < Snapshot->ProcessListCount) {
	    LPPROCESSENTRY32W Entries = (LPPROCESSENTRY32W)
		OffsetToPtr(Snapshot, Snapshot->ProcessListOffset);
	    RtlCopyMemory(lpProcessEntry, &Entries[Snapshot->ProcessListIndex++],
			  sizeof(PROCESSENTRY32W));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpThreadEntry)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpThreadEntry, sizeof(THREADENTRY32));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if (Snapshot->ThreadListCount > 0) {
	    LPTHREADENTRY32 Entries = (LPTHREADENTRY32)
		OffsetToPtr(Snapshot, Snapshot->ThreadListOffset);
	    Snapshot->ThreadListIndex = 1;
	    RtlCopyMemory(lpThreadEntry, &Entries[0], sizeof(THREADENTRY32));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpThreadEntry)
{
    PTH32SNAPSHOT Snapshot;
    LARGE_INTEGER SOffset;
    SIZE_T ViewSize;
    NTSTATUS Status;

    CHECK_PARAM_SIZE(lpThreadEntry, sizeof(THREADENTRY32));

    SOffset.QuadPart = 0;
    ViewSize = 0;
    Snapshot = NULL;

    Status = NtMapViewOfSection(hSnapshot, NtCurrentProcess(), (PVOID *)&Snapshot, 0, 0,
				&SOffset, &ViewSize, ViewShare, 0, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
	BOOL Ret;

	if (Snapshot->ThreadListCount > 0 &&
	    Snapshot->ThreadListIndex < Snapshot->ThreadListCount) {
	    LPTHREADENTRY32 Entries = (LPTHREADENTRY32)
		OffsetToPtr(Snapshot, Snapshot->ThreadListOffset);
	    RtlCopyMemory(lpThreadEntry, &Entries[Snapshot->ThreadListIndex++],
			  sizeof(THREADENTRY32));
	    Ret = TRUE;
	} else {
	    SetLastError(ERROR_NO_MORE_FILES);
	    Ret = FALSE;
	}

	NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)Snapshot);
	return Ret;
    }

    BaseSetLastNTError(Status);
    return FALSE;
}

/*
 * @implemented
 */
WINAPI BOOL Toolhelp32ReadProcessMemory(DWORD Th32ProcessId, LPCVOID lpBaseAddress,
					LPVOID lpBuffer, SIZE_T cbRead,
					SIZE_T *lpNumberOfBytesRead)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, Th32ProcessId);
    if (hProcess != NULL) {
	BOOL Ret = ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, cbRead,
				     lpNumberOfBytesRead);
	CloseHandle(hProcess);
	return Ret;
    }

    return FALSE;
}

/*
 * @implemented
 */
WINAPI HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD Th32ProcessId)
{
    PRTL_DEBUG_INFORMATION HeapDebug, ModuleDebug;
    PVOID ProcThrdInfo;
    SIZE_T ProcThrdInfoSize;
    NTSTATUS Status;
    HANDLE hSnapShotSection = NULL;

    if (Th32ProcessId == 0) {
	Th32ProcessId = GetCurrentProcessId();
    }

    /*
     * Get all information required for the snapshot
     */
    Status = TH32CreateSnapshot(dwFlags, Th32ProcessId, &HeapDebug, &ModuleDebug,
				&ProcThrdInfo, &ProcThrdInfoSize);
    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return NULL;
    }

    /*
     * Create a section handle and initialize the collected information
     */
    Status = TH32CreateSnapshotSectionInitialize(dwFlags, Th32ProcessId, HeapDebug,
						 ModuleDebug, ProcThrdInfo,
						 &hSnapShotSection);

    /*
     * Free the temporarily allocated memory which is no longer needed
     */
    TH32FreeAllocatedResources(HeapDebug, ModuleDebug, ProcThrdInfo, ProcThrdInfoSize);

    if (!NT_SUCCESS(Status)) {
	BaseSetLastNTError(Status);
	return NULL;
    }

    return hSnapShotSection;
}

/* EOF */
