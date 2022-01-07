/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/image.c
 * PURPOSE:         Image handling functions
 *                  Relocate functions were previously located in
 *                  ntoskrnl/ldr/loader.c and
 *                  dll/ntdll/ldr/utils.c files
 * PROGRAMMER:      Eric Kohl + original authors from loader.c and utils.c file
 *                  Aleksey Bragin
 */

/* INCLUDES *****************************************************************/

#include "ldrp.h"
#include <string.h>

#define LDR_DLL_DEFAULT_EXTENSION	".dll"

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 * @note: This is the version of RtlpImageNtHeaderEx guarded by SEH.
 */
NTSTATUS NTAPI RtlImageNtHeaderEx(IN ULONG Flags,
				  IN PVOID Base,
				  IN ULONG64 Size,
				  OUT PIMAGE_NT_HEADERS *OutHeaders)
{
    NTSTATUS Status;

    _SEH2_TRY {
	/* Assume failure. This is also done in RtlpImageNtHeaderEx,
	 * but this is guarded by SEH. */
	if (OutHeaders != NULL) {
	    *OutHeaders = NULL;
	}
        Status = RtlpImageNtHeaderEx(Flags, Base, Size, OutHeaders);
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        /* Fail with the SEH error */
        Status = _SEH2_GetExceptionCode();
    }

    return Status;
}

/*
 * @implemented
 */
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID Base)
{
    PIMAGE_NT_HEADERS NtHeader;

    /* Call the new API */
    RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK,
                       Base, 0, &NtHeader);
    return NtHeader;
}

static PIMAGE_BASE_RELOCATION
LdrpProcessRelocationBlockLongLong(IN ULONG_PTR Address,
				   IN ULONG Count,
				   IN PUSHORT TypeOffset,
				   IN LONGLONG Delta)
{
    SHORT Offset;
    USHORT Type;
    ULONG i;
    PUSHORT ShortPtr;
    PULONG LongPtr;
    PULONGLONG LongLongPtr;

    for (i = 0; i < Count; i++) {
        Offset = SWAPW(*TypeOffset) & 0xFFF;
        Type = SWAPW(*TypeOffset) >> 12;
        ShortPtr = (PUSHORT)(RVA(Address, Offset));
        /*
	 * Don't relocate within the relocation section itself.
	 * GCC/LD sometimes generates relocation records for the relocation section.
	 * This is a bug in GCC/LD.
	 * Fix for it disabled, since it was only in ntoskrnl and not in ntdll
	 */
        /*
	  if ((ULONG_PTR)ShortPtr < (ULONG_PTR)RelocationDir ||
	  (ULONG_PTR)ShortPtr >= (ULONG_PTR)RelocationEnd)
	  {*/
        switch (Type) {
            /* case IMAGE_REL_BASED_SECTION : */
            /* case IMAGE_REL_BASED_REL32 : */
        case IMAGE_REL_BASED_ABSOLUTE:
            break;

        case IMAGE_REL_BASED_HIGH:
            *ShortPtr = HIWORD(MAKELONG(0, *ShortPtr) + (Delta & 0xFFFFFFFF));
            break;

        case IMAGE_REL_BASED_LOW:
            *ShortPtr = SWAPW(*ShortPtr) + LOWORD(Delta & 0xFFFF);
            break;

        case IMAGE_REL_BASED_HIGHLOW:
            LongPtr = (PULONG)RVA(Address, Offset);
            *LongPtr = SWAPD(*LongPtr) + (Delta & 0xFFFFFFFF);
            break;

        case IMAGE_REL_BASED_DIR64:
            LongLongPtr = (PUINT64)RVA(Address, Offset);
            *LongLongPtr = SWAPQ(*LongLongPtr) + Delta;
            break;

        case IMAGE_REL_BASED_HIGHADJ:
        case IMAGE_REL_BASED_MIPS_JMPADDR:
        default:
            DPRINT1("Unknown/unsupported fixup type %hu.\n", Type);
            DPRINT1("Address %p, Current %u, Count %u, *TypeOffset %x\n",
                    (PVOID)Address, i, Count, SWAPW(*TypeOffset));
            return (PIMAGE_BASE_RELOCATION)NULL;
        }

        TypeOffset++;
    }

    return (PIMAGE_BASE_RELOCATION)TypeOffset;
}

ULONG LdrpRelocateImage(IN PVOID BaseAddress,
			IN PCCH LoaderName,
			IN ULONG Success,
			IN ULONG Conflict,
			IN ULONG Invalid)
{
    return LdrpRelocateImageWithBias(BaseAddress, 0, LoaderName,
				     Success, Conflict, Invalid);
}

ULONG LdrpRelocateImageWithBias(IN PVOID BaseAddress,
				IN LONGLONG AdditionalBias,
				IN PCCH LoaderName,
				IN ULONG Success,
				IN ULONG Conflict,
				IN ULONG Invalid)
{
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_DATA_DIRECTORY RelocationDDir;
    PIMAGE_BASE_RELOCATION RelocationDir, RelocationEnd;
    ULONG Count;
    ULONG_PTR Address;
    PUSHORT TypeOffset;
    LONGLONG Delta;

    NtHeaders = RtlImageNtHeader(BaseAddress);

    if (NtHeaders == NULL)
        return Invalid;

    if (SWAPW(NtHeaders->FileHeader.Characteristics) & IMAGE_FILE_RELOCS_STRIPPED) {
        return Conflict;
    }

    RelocationDDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (SWAPD(RelocationDDir->VirtualAddress) == 0 || SWAPD(RelocationDDir->Size) == 0) {
        return Success;
    }

    Delta = (ULONG_PTR)BaseAddress - SWAPD(NtHeaders->OptionalHeader.ImageBase) + AdditionalBias;
    RelocationDir = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)BaseAddress + SWAPD(RelocationDDir->VirtualAddress));
    RelocationEnd = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)RelocationDir + SWAPD(RelocationDDir->Size));

    while (RelocationDir < RelocationEnd && SWAPW(RelocationDir->SizeOfBlock) > 0) {
        Count = (SWAPW(RelocationDir->SizeOfBlock) - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        Address = (ULONG_PTR)RVA(BaseAddress, SWAPD(RelocationDir->VirtualAddress));
        TypeOffset = (PUSHORT)(RelocationDir + 1);

        RelocationDir = LdrpProcessRelocationBlockLongLong(Address,
							   Count,
							   TypeOffset,
							   Delta);

        if (RelocationDir == NULL) {
            DPRINT1("Error during call to LdrpProcessRelocationBlockLongLong()!\n");
            return Invalid;
        }
    }

    return Success;
}

PLDR_DATA_TABLE_ENTRY LdrpAllocateDataTableEntry(IN PVOID BaseAddress)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;

    /* Make sure the header is valid */
    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(BaseAddress);
    DPRINT("LdrpAllocateDataTableEntry(%p), NtHeader %p\n", BaseAddress,
	   NtHeader);

    if (NtHeader) {
	/* Allocate an entry */
	LdrEntry = RtlAllocateHeap(LdrpHeap,
				   HEAP_ZERO_MEMORY,
				   sizeof(LDR_DATA_TABLE_ENTRY));

	/* Make sure we got one */
	if (LdrEntry) {
	    /* Set it up */
	    LdrEntry->DllBase = BaseAddress;
	    LdrEntry->SizeOfImage = NtHeader->OptionalHeader.SizeOfImage;
	    LdrEntry->TimeDateStamp = NtHeader->FileHeader.TimeDateStamp;
	    LdrEntry->PatchInformation = NULL;
	}
    }

    /* Return the entry */
    return LdrEntry;
}

VOID LdrpFreeDataTableEntry(IN PLDR_DATA_TABLE_ENTRY Entry)
{
    RtlFreeHeap(LdrpHeap, 0, Entry);
}

PVOID LdrpFetchAddressOfEntryPoint(IN PVOID ImageBase)
{
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG_PTR EntryPoint = 0;

    /* Get entry point offset from NT headers */
    NtHeaders = RtlImageNtHeader(ImageBase);
    if (NtHeaders) {
	/* Add image base */
	EntryPoint = NtHeaders->OptionalHeader.AddressOfEntryPoint;
	if (EntryPoint)
	    EntryPoint += (ULONG_PTR) ImageBase;
    }

    /* Return calculated pointer (or zero in case of failure) */
    return (PVOID) EntryPoint;
}

VOID LdrpInsertMemoryTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				IN PCSTR BaseDllName)
{
    PPEB_LDR_DATA PebData = NtCurrentPeb()->LdrData;

    /* Insert into hash table */
    ULONG i = LDRP_GET_HASH_ENTRY(BaseDllName);
    InsertTailList(&LdrpHashTable[i], &LdrEntry->HashLinks);

    /* Insert into other lists */
    InsertTailList(&PebData->InLoadOrderModuleList, &LdrEntry->InLoadOrderLinks);
    InsertTailList(&PebData->InMemoryOrderModuleList, &LdrEntry->InMemoryOrderLinks);
}

BOOLEAN LdrpCheckForLoadedDll(IN PCSTR DllName,
			      OUT OPTIONAL PLDR_DATA_TABLE_ENTRY *LdrEntry)
{

    /* Check if a dll name was provided */
    if (!DllName) {
	return FALSE;
    }

    /* Get hash index */
    ULONG HashIndex = LDRP_GET_HASH_ENTRY(DllName);
    UNICODE_STRING BaseDllName;
    RET_ERR(LdrpUtf8ToUnicodeString(DllName, &BaseDllName));

    /* Traverse that list */
    PLIST_ENTRY ListHead = &LdrpHashTable[HashIndex];
    PLIST_ENTRY ListEntry = ListHead->Flink;
    while (ListEntry != ListHead) {
	/* Get the current entry */
	PLDR_DATA_TABLE_ENTRY CurEntry = CONTAINING_RECORD(ListEntry,
							   LDR_DATA_TABLE_ENTRY,
							   HashLinks);

	/* Check base name of that module */
	if (RtlEqualUnicodeString(&BaseDllName, &CurEntry->BaseDllName, TRUE)) {
	    /* It matches, return it */
	    if (LdrEntry != NULL) {
		*LdrEntry = CurEntry;
	    }
	    DbgTrace("Module '%s' already loaded at %p\n", DllName, CurEntry->DllBase);
	    return TRUE;
	}

	/* Advance to the next entry */
	ListEntry = ListEntry->Flink;
    }

    /* Module was not found, return failure */
    DbgTrace("Module '%s' is not loaded\n", DllName);

    return FALSE;
}

static NTSTATUS LdrpMapDll(IN PCSTR DllName,
			   IN BOOLEAN Static,
			   OUT PLDR_DATA_TABLE_ENTRY *DataTableEntry)
{
    DPRINT1("LDR: LdrpMapDll: Image Name %s\n", DllName);

    PLDRP_LOADED_MODULE FoundModule = NULL;
    PLOADER_SHARED_DATA LdrShared = (PLOADER_SHARED_DATA)LOADER_SHARED_DATA_CLIENT_ADDR;
    PLDRP_LOADED_MODULE Module = (PLDRP_LOADED_MODULE)(LOADER_SHARED_DATA_CLIENT_ADDR + LdrShared->LoadedModules);
    for (ULONG i = 0; i < LdrShared->LoadedModuleCount; i++) {
	PCSTR FoundDllName = (PCSTR)(LOADER_SHARED_DATA_CLIENT_ADDR + Module->DllName);
	if (!strcasecmp(DllName, FoundDllName)) {
	    FoundModule = Module;
	    break;
	}
	Module = (PLDRP_LOADED_MODULE)((MWORD)(Module) + Module->EntrySize);
    }

    if (FoundModule == NULL) {
	if (!Static) {
	    /* TODO: Call server */
	    return STATUS_NOT_IMPLEMENTED;
	} else {
	    return STATUS_DLL_NOT_FOUND;
	}
    }

    /* Get the NT Header */
    PVOID ViewBase = (PVOID) FoundModule->ViewBase;
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ViewBase);
    if (!NtHeaders) {
	/* Invalid image. This should never happen. Assert in debug build. */
	assert(FALSE);
	return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Allocate an entry */
    PLDR_DATA_TABLE_ENTRY LdrEntry = LdrpAllocateDataTableEntry(ViewBase);
    if (!LdrEntry) {
	/* Invalid image, unmap, close handle and fail */
	/* TODO: Call server to unmap the image if dynamic loading */
	return STATUS_NO_MEMORY;
    }

    /* Setup the entry */
    UNICODE_STRING FullDllName, BaseDllName;
    PCSTR DllPath = (PCSTR)(LOADER_SHARED_DATA_CLIENT_ADDR + FoundModule->DllPath);
    RET_ERR_EX(LdrpUtf8ToUnicodeString(DllPath, &FullDllName),
	       LdrpFreeDataTableEntry(LdrEntry));
    RET_ERR_EX(LdrpUtf8ToUnicodeString(DllName, &BaseDllName),
	       {
		   LdrpFreeDataTableEntry(LdrEntry);
		   LdrpFreeUnicodeString(FullDllName);
	       });
    LdrEntry->Flags = Static ? LDRP_STATIC_LINK : 0;
    LdrEntry->LoadCount = 0;
    LdrEntry->FullDllName = FullDllName;
    LdrEntry->BaseDllName = BaseDllName;
    LdrEntry->EntryPoint = LdrpFetchAddressOfEntryPoint(LdrEntry->DllBase);

    DPRINT1("LDR: LdrpMapDll: Full Name %wZ, Base Name %wZ\n",
	    &FullDllName, &BaseDllName);

    /* Insert this entry */
    LdrpInsertMemoryTableEntry(LdrEntry, DllName);

    /* The image was valid. Is it a DLL? */
    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
	/* Set the DLL Flag */
	LdrEntry->Flags |= LDRP_IMAGE_DLL;
    }

    /* If we're not a DLL, clear the entrypoint */
    if (!(LdrEntry->Flags & LDRP_IMAGE_DLL)) {
	LdrEntry->EntryPoint = 0;
    }

    /* Return it for the caller */
    *DataTableEntry = LdrEntry;

    /* Check if we loaded somewhere else */
    ULONG_PTR ImageBase = (ULONG_PTR) NtHeaders->OptionalHeader.ImageBase;
    if ((ULONG_PTR)ViewBase != ImageBase) {
	DPRINT("LDR: LdrpMapDll Relocating Image Name %s (%p-%p -> %p-%p)\n",
	       DllName, (PVOID) ImageBase, (PVOID) ImageBase + FoundModule->ViewSize,
	       ViewBase, (PVOID) ((MWORD)ViewBase + FoundModule->ViewSize));

	LdrEntry->Flags |= LDRP_IMAGE_NOT_AT_BASE;
	/* Are we dealing with a DLL? */
	if (LdrEntry->Flags & LDRP_IMAGE_DLL) {
	    /* Check if relocs were stripped */
	    if (!(NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		/* Get the relocation data */
		ULONG RelocDataSize = 0;
		PVOID RelocData = RtlImageDirectoryEntryToData(ViewBase,
							       TRUE,
							       IMAGE_DIRECTORY_ENTRY_BASERELOC,
							       &RelocDataSize);

		/* Does the DLL not have any? */
		if (!RelocData && !RelocDataSize) {
		    /* We'll allow this and simply continue */
		    goto done;
		}
	    }

	    /* Can't relocate user32 or kernel32 */
	    BOOLEAN RelocatableDll = TRUE;
	    if (!strcasecmp(DllName, "user32.dll") || !strcasecmp(DllName, "kernel32.dll")) {
		RelocatableDll = FALSE;
	    }

	    /* Do the relocation */
	    RET_ERR_EX(LdrpRelocateImageWithBias(ViewBase, 0LL, NULL,
						 STATUS_SUCCESS,
						 STATUS_CONFLICTING_ADDRESSES,
						 STATUS_INVALID_IMAGE_FORMAT),
		       {
			   /* TODO: Call server to unload the dll */

			   /* Remove module entry from the lists */
			   RemoveEntryList(&LdrEntry->InLoadOrderLinks);
			   RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
			   RemoveEntryList(&LdrEntry->HashLinks);

			   /* Clear the entry */
			   LdrpFreeUnicodeString(FullDllName);
			   LdrpFreeUnicodeString(BaseDllName);
			   LdrpFreeDataTableEntry(LdrEntry);
			   *DataTableEntry = NULL;

			   DPRINT1("LDR: Fixups unsuccessfully re-applied @ %p\n",
				   ViewBase);
		       });

	    DPRINT1("LDR: Fixups successfully re-applied @ %p\n", ViewBase);
	} else {
	    /* Not a DLL, or no relocation needed */
	    DPRINT1("LDR: Fixups won't be re-applied to non-Dll @ %p\n",
		    ViewBase);
	}
    }

done:
    /* TODO: Call server to change the protection */
    /* TODO: Validate image for SMP */
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpLoadImportModule(IN PCSTR ImportName,
				     OUT PLDR_DATA_TABLE_ENTRY *DataTableEntry,
				     OUT OPTIONAL PBOOLEAN Existing)
{
    ULONG ImportNameLength = strlen(ImportName);
    NTSTATUS Status = STATUS_SUCCESS;
    PPEB Peb = RtlGetCurrentPeb();

    DPRINT("LdrpLoadImportModule('%s' %p %p)\n", ImportName,
	   DataTableEntry, Existing);

    /* Find the extension, if present */
    BOOLEAN GotExtension = FALSE;
    for (ULONG i = ImportNameLength; i > 0; i--) {
	if (ImportName[i] == '.') {
	    GotExtension = TRUE;
	    break;
	} else if (ImportName[i] == '\\') {
	    break;
	}
    }

    /* If no extension was found, add the default extension */
    if (!GotExtension) {
	/* sizeof() includes terminating nul */
	PCHAR ImportNameExt = RtlAllocateHeap(LdrpHeap, 0, ImportNameLength + sizeof(LDR_DLL_DEFAULT_EXTENSION));
	if (ImportNameExt == NULL) {
	    return STATUS_NO_MEMORY;
	}
	memcpy(ImportNameExt, ImportName, ImportNameLength);
	memcpy(&ImportNameExt[ImportNameLength], LDR_DLL_DEFAULT_EXTENSION, sizeof(LDR_DLL_DEFAULT_EXTENSION));
	ImportName = ImportNameExt;
    }

    /* Check if it's loaded */
    if (LdrpCheckForLoadedDll(ImportName, DataTableEntry)) {
	/* It's already existing in the list */
	if (Existing) {
	    *Existing = TRUE;
	}
	Status = STATUS_SUCCESS;
	goto done;
    }

    /* We're loading it for the first time */
    if (Existing) {
	*Existing = FALSE;
    }

    /* Map it */
    Status = LdrpMapDll(ImportName, TRUE, DataTableEntry);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("LDR: LdrpMapDll failed with status %x for dll %s\n",
		Status, ImportName);
	goto done;
    }
    assert(*DataTableEntry != NULL);

    /* Walk its import descriptor table */
    Status = LdrpWalkImportDescriptor(*DataTableEntry);
    if (!NT_SUCCESS(Status)) {
	/* In case of failure, we still want the dll to be inserted
	 * into the init-order module list. Do it here. If successful
	 * LdrpWalkImportDescriptor has already inserted the dll. */
	InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
		       &(*DataTableEntry)->InInitializationOrderLinks);
    }

done:
    if (!GotExtension) {
	RtlFreeHeap(LdrpHeap, 0, (PVOID) ImportName);
    }

    return Status;
}

static NTSTATUS LdrpLoadDll(IN PCSTR DllName,
			    OUT PVOID *BaseAddress)
{
    PLDR_DATA_TABLE_ENTRY DataTableEntry = NULL;
    RET_ERR(LdrpLoadImportModule(DllName, &DataTableEntry, NULL));
    assert(DataTableEntry != NULL);
    DataTableEntry->LoadCount++;
    *BaseAddress = DataTableEntry->DllBase;
    return STATUS_SUCCESS;
}

static USHORT LdrpNameToOrdinal(IN PCSTR ImportName,
				IN ULONG NumberOfNames,
				IN PVOID ExportBase,
				IN PULONG NameTable,
				IN PUSHORT OrdinalTable)
{
    LONG Start, End, Next, CmpResult;

    /* Use classical binary search to find the ordinal */
    Start = Next = 0;
    End = NumberOfNames - 1;
    while (End >= Start) {
	/* Next will be exactly between Start and End */
	Next = (Start + End) >> 1;

	/* Compare this name with the one we need to find */
	CmpResult = strcmp(ImportName, (PCHAR)((ULONG_PTR) ExportBase + NameTable[Next]));

	/* We found our entry if result is 0 */
	if (!CmpResult)
	    break;

	/* We didn't find, update our range then */
	if (CmpResult < 0) {
	    End = Next - 1;
	} else if (CmpResult > 0) {
	    Start = Next + 1;
	}
    }

    /* If end is before start, then the search failed */
    if (End < Start)
	return -1;

    /* Return found name */
    return OrdinalTable[Next];
}

static BOOLEAN LdrpCheckForLoadedDllHandle(IN PVOID Base,
					   OUT PLDR_DATA_TABLE_ENTRY *LdrEntry)
{
    static PLDR_DATA_TABLE_ENTRY LdrpLoadedDllHandleCache = NULL;
    PLDR_DATA_TABLE_ENTRY Current;
    PLIST_ENTRY ListHead, Next;

    /* Check the cache first */
    if ((LdrpLoadedDllHandleCache) && (LdrpLoadedDllHandleCache->DllBase == Base)) {
	/* We got lucky, return the cached entry */
	*LdrEntry = LdrpLoadedDllHandleCache;
	return TRUE;
    }

    /* Time for a lookup */
    ListHead = &NtCurrentPeb()->LdrData->InLoadOrderModuleList;
    Next = ListHead->Flink;
    while (Next != ListHead) {
	/* Get the current entry */
	Current = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	/* Make sure it's not unloading and check for a match */
	if ((Current->InMemoryOrderLinks.Flink) && (Base == Current->DllBase)) {
	    /* Save in cache */
	    LdrpLoadedDllHandleCache = Current;

	    /* Return it */
	    *LdrEntry = Current;
	    return TRUE;
	}

	/* Move to the next one */
	Next = Next->Flink;
    }

    /* Nothing found */
    return FALSE;
}

static NTSTATUS LdrpSnapThunk(IN PVOID ExportBase,
			      IN PVOID ImportBase,
			      IN PIMAGE_THUNK_DATA OriginalThunk,
			      IN OUT PIMAGE_THUNK_DATA Thunk,
			      IN PIMAGE_EXPORT_DIRECTORY ExportDirectory,
			      IN ULONG ExportSize,
			      IN BOOLEAN Static,
			      IN PCSTR DllName)
{
    PCSTR ImportName = NULL;

    /* Check if the snap is by ordinal */
    USHORT Ordinal;
    ULONG OriginalOrdinal = 0;
    BOOLEAN IsOrdinal = IMAGE_SNAP_BY_ORDINAL(OriginalThunk->u1.Ordinal);
    if (IsOrdinal) {
	/* Get the ordinal number, and its normalized version */
	OriginalOrdinal = IMAGE_ORDINAL(OriginalThunk->u1.Ordinal);
	Ordinal = (USHORT)(OriginalOrdinal - ExportDirectory->Base);
    } else {
	/* First get the data VA */
	PIMAGE_IMPORT_BY_NAME AddressOfData = (PIMAGE_IMPORT_BY_NAME)
	    ((ULONG_PTR) ImportBase + ((ULONG_PTR) OriginalThunk->u1.AddressOfData & 0xffffffff));

	/* Get the name */
	ImportName = (PCSTR) AddressOfData->Name;

	/* Now get the VA of the Name and Ordinal Tables */
	PULONG NameTable = (PULONG) ((ULONG_PTR) ExportBase + (ULONG_PTR) ExportDirectory->AddressOfNames);
	PUSHORT OrdinalTable = (PUSHORT) ((ULONG_PTR) ExportBase + (ULONG_PTR) ExportDirectory->AddressOfNameOrdinals);

	/* Get the hint */
	USHORT Hint = AddressOfData->Hint;

	/* Try to get a match by using the hint */
	if (((ULONG) Hint < ExportDirectory->NumberOfNames) &&
	    (!strcmp(ImportName, ((PCSTR) ((ULONG_PTR) ExportBase + NameTable[Hint]))))) {
	    /* We got a match, get the Ordinal from the hint */
	    Ordinal = OrdinalTable[Hint];
	} else {
	    /* Well bummer, hint didn't work, do it the long way */
	    Ordinal = LdrpNameToOrdinal(ImportName, ExportDirectory->NumberOfNames,
					ExportBase, NameTable, OrdinalTable);
	}
    }

    /* Check if the ordinal is valid */
    if ((ULONG) Ordinal < ExportDirectory->NumberOfFunctions) {
	/* The ordinal seems correct, get the AddressOfFunctions VA */
	PULONG AddressOfFunctions = (PULONG)((ULONG_PTR) ExportBase + (ULONG_PTR) ExportDirectory->AddressOfFunctions);

	/* Write the function pointer */
	Thunk->u1.Function = (ULONG_PTR) ExportBase + AddressOfFunctions[Ordinal];

	/* Make sure it's within the exports */
	if ((Thunk->u1.Function > (ULONG_PTR) ExportDirectory) &&
	    (Thunk->u1.Function < ((ULONG_PTR) ExportDirectory + ExportSize))) {
	    /* Get the Import and Forwarder Names */
	    ImportName = (PCSTR) Thunk->u1.Function;
	    PCSTR DotPosition = strchr(ImportName, '.');
	    ASSERT(DotPosition != NULL);
	    if (!DotPosition) {
		goto FailurePath;
	    }

	    /* Load the forwarder */
	    PVOID ForwarderHandle;
	    NTSTATUS Status = LdrpLoadDll(ImportName, &ForwarderHandle);
	    /* If the load failed, use the failure path */
	    if (!NT_SUCCESS(Status))
		goto FailurePath;

	    /* Now set up a name for the actual forwarder dll */
	    ANSI_STRING ForwarderName;
	    RtlInitAnsiString(&ForwarderName, DotPosition + sizeof(CHAR));

	    /* Check if it's an ordinal forward */
	    ULONG ForwardOrdinal;
	    PANSI_STRING ForwardName;
	    if ((ForwarderName.Length > 1) && (*ForwarderName.Buffer == '#')) {
		/* We don't have an actual function name */
		ForwardName = NULL;

		/* Convert the string into an ordinal */
		Status = RtlCharToInteger(ForwarderName.Buffer + sizeof(CHAR),
					  0, &ForwardOrdinal);

		/* If this fails, then error out */
		if (!NT_SUCCESS(Status))
		    goto FailurePath;
	    } else {
		/* Import by name */
		ForwardName = &ForwarderName;
		ForwardOrdinal = 0;
	    }

	    /* Get the pointer */
	    Status = LdrGetProcedureAddress(ForwarderHandle, ForwardName, ForwardOrdinal,
					    (PVOID *)(&Thunk->u1.Function));
	    /* If this fails, then error out */
	    if (!NT_SUCCESS(Status))
		goto FailurePath;
	} else {
	    /* It's not within the exports, let's hope it's valid */
	    if (!AddressOfFunctions[Ordinal])
		goto FailurePath;
	}
    }

    /* If we got here, then it's success */
    return STATUS_SUCCESS;

FailurePath:
    /* Is this a static snap? */
    if (Static) {
	UNICODE_STRING SnapTarget;
	PLDR_DATA_TABLE_ENTRY LdrEntry;

	/* What was the module we were searching in */
	ANSI_STRING TempString;
	RtlInitAnsiString(&TempString, DllName ? DllName : "Unknown");

	/* What was the module we were searching for */
	if (LdrpCheckForLoadedDllHandle(ImportBase, &LdrEntry)) {
	    SnapTarget = LdrEntry->BaseDllName;
	} else {
	    RtlInitUnicodeString(&SnapTarget, L"Unknown");
	}

	/* Inform the debug log */
	if (IsOrdinal) {
	    DPRINT1("Failed to snap ordinal %Z!0x%x for %wZ\n",
		    &TempString, OriginalOrdinal, &SnapTarget);
	} else {
	    DPRINT1("Failed to snap %Z!%s for %wZ\n", &TempString,
		    ImportName, &SnapTarget);
	}

	/* These are critical errors. Setup a string for the DLL name */
	ULONG_PTR HardErrorParameters[3];
	HARDERROR_RESPONSE Response;

	/* Check if we have an ordinal */
	if (IsOrdinal) {
	    /* Then set the ordinal as the 1st parameter */
	    HardErrorParameters[0] = OriginalOrdinal;
	}

	/* Raise the error */
	NtRaiseHardError(IsOrdinal ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND,
			 2, 0, HardErrorParameters, OptionOk, &Response);

	/* Free our string */
	if (!IsOrdinal) {
	    /* Free our second string. Return entrypoint error */
	    return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	/* Return ordinal error */
	return STATUS_ORDINAL_NOT_FOUND;
    } else {
	/* Inform the debug log */
	if (IsOrdinal) {
	    DPRINT("Non-fatal: Failed to snap ordinal 0x%x\n",
		   OriginalOrdinal);
	} else {
	    DPRINT("Non-fatal: Failed to snap %s\n", ImportName ? ImportName : "(nil)");
	}
    }

    /* Set this as a bad DLL */
    Thunk->u1.Function = (ULONG_PTR) 0xffbadd11;

    /* Return the right error code */
    return IsOrdinal ? STATUS_ORDINAL_NOT_FOUND : STATUS_ENTRYPOINT_NOT_FOUND;
}

NTSTATUS LdrGetProcedureAddress(IN PVOID BaseAddress,
				IN PANSI_STRING Name,
				IN ULONG Ordinal,
				OUT PVOID *ProcedureAddress)
{
    NTSTATUS Status = STATUS_SUCCESS;
    UCHAR ImportBuffer[64];
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    IMAGE_THUNK_DATA Thunk;
    PVOID ImageBase;
    PIMAGE_IMPORT_BY_NAME ImportName = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDir;
    ULONG ExportDirSize, Length;
    PLIST_ENTRY Entry;

    DPRINT1("LDR: LdrGetProcedureAddress by ");

    /* Check if we got a name */
    if (Name) {
	DbgPrint("NAME - %s\n", Name->Buffer);

	/* Make sure it's not too long */
	Length = Name->Length + sizeof(CHAR) + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name);
	if (Length > UNICODE_STRING_MAX_BYTES) {
	    /* Won't have enough space to add the hint */
	    return STATUS_NAME_TOO_LONG;
	}

	/* Check if our buffer is large enough */
	if (Length > sizeof(ImportBuffer)) {
	    /* Allocate from heap, plus 2 bytes for the Hint */
	    ImportName = RtlAllocateHeap(RtlGetProcessHeap(), 0, Length);
	} else {
	    /* Use our internal buffer */
	    ImportName = (PIMAGE_IMPORT_BY_NAME) ImportBuffer;
	}

	/* Clear the hint */
	ImportName->Hint = 0;

	/* Copy the name and null-terminate it */
	RtlCopyMemory(ImportName->Name, Name->Buffer, Name->Length);
	ImportName->Name[Name->Length] = ANSI_NULL;

	/* Clear the high bit */
	ImageBase = ImportName;
	Thunk.u1.AddressOfData = 0;
    } else {
	/* Do it by ordinal */
	ImageBase = NULL;

	DbgPrint("ORDINAL - %x\n", Ordinal);

	/* Make sure an ordinal was given */
	if (!Ordinal) {
	    /* No ordinal */
	    DPRINT1("No ordinal and no name\n");
	    return STATUS_INVALID_PARAMETER;
	}

	/* Set the original flag in the thunk */
	Thunk.u1.Ordinal = Ordinal | IMAGE_ORDINAL_FLAG;
    }

    /* Acquire lock */
    RtlEnterCriticalSection(&LdrpLoaderLock);

    /* Try to find the loaded DLL */
    if (!LdrpCheckForLoadedDllHandle(BaseAddress, &LdrEntry)) {
	/* Invalid base */
	DPRINT1("Invalid base address %p\n", BaseAddress);
	Status = STATUS_DLL_NOT_FOUND;
	goto Quickie;
    }

    /* Get the pointer to the export directory */
    ExportDir = RtlImageDirectoryEntryToData(LdrEntry->DllBase,
					     TRUE,
					     IMAGE_DIRECTORY_ENTRY_EXPORT,
					     &ExportDirSize);

    if (!ExportDir) {
	DPRINT1("Image %wZ has no exports, but were trying to get procedure %Z. BaseAddress asked 0x%p, got entry BA 0x%p\n",
		&LdrEntry->BaseDllName, Name, BaseAddress, LdrEntry->DllBase);
	Status = STATUS_PROCEDURE_NOT_FOUND;
	goto Quickie;
    }

    /* Now get the thunk */
    Status = LdrpSnapThunk(LdrEntry->DllBase,
			   ImageBase,
			   &Thunk,
			   &Thunk,
			   ExportDir, ExportDirSize, FALSE, NULL);

    /* Make sure we're OK till here */
    if (NT_SUCCESS(Status)) {
	/* Return the address */
	*ProcedureAddress = (PVOID) Thunk.u1.Function;
    }

 Quickie:
    /* Cleanup */
    if (ImportName && (ImportName != (PIMAGE_IMPORT_BY_NAME) ImportBuffer)) {
	/* We allocated from heap, free it */
	RtlFreeHeap(RtlGetProcessHeap(), 0, ImportName);
    }

    /* Release the lock */
    RtlLeaveCriticalSection(&LdrpLoaderLock);

    /* We're done */
    return Status;
}

static NTSTATUS LdrpSnapIAT(IN PLDR_DATA_TABLE_ENTRY ExportLdrEntry,
			    IN PLDR_DATA_TABLE_ENTRY ImportLdrEntry,
			    IN PIMAGE_IMPORT_DESCRIPTOR IatEntry,
			    IN BOOLEAN EntriesValid)
{
    PVOID Iat;
    NTSTATUS Status;
    PIMAGE_THUNK_DATA OriginalThunk, FirstThunk;
    PIMAGE_NT_HEADERS NtHeader;
    PIMAGE_SECTION_HEADER SectionHeader;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    PCSTR ImportName;
    ULONG ForwarderChain, Rva, OldProtect, IatSize, ExportSize;
    SIZE_T ImportSize;

    DPRINT("LdrpSnapIAT(%wZ %wZ %p %u)\n", &ExportLdrEntry->BaseDllName,
	   &ImportLdrEntry->BaseDllName, IatEntry, EntriesValid);

    /* Get export directory */
    ExportDirectory = RtlImageDirectoryEntryToData(ExportLdrEntry->DllBase,
						   TRUE,
						   IMAGE_DIRECTORY_ENTRY_EXPORT,
						   &ExportSize);

    /* Make sure it has one */
    if (!ExportDirectory) {
	/* Fail */
	DbgTrace("LDR: %wZ doesn't contain an EXPORT table\n",
		 &ExportLdrEntry->BaseDllName);
	return STATUS_INVALID_IMAGE_FORMAT;
    }

    /* Get the IAT */
    Iat = RtlImageDirectoryEntryToData(ImportLdrEntry->DllBase,
				       TRUE,
				       IMAGE_DIRECTORY_ENTRY_IAT,
				       &IatSize);
    ImportSize = IatSize;

    /* Check if we don't have one */
    if (!Iat) {
	/* Get the NT Header and the first section */
	NtHeader = RtlImageNtHeader(ImportLdrEntry->DllBase);
	if (!NtHeader) {
	    return STATUS_INVALID_IMAGE_FORMAT;
	}
	SectionHeader = IMAGE_FIRST_SECTION(NtHeader);

	/* Get the RVA of the import directory */
	Rva = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	/* Make sure we got one */
	if (Rva) {
	    /* Loop all the sections */
	    for (ULONG i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
		/* Check if we are inside this section */
		if ((Rva >= SectionHeader->VirtualAddress) &&
		    (Rva < (SectionHeader->VirtualAddress + SectionHeader->SizeOfRawData))) {
		    /* We are, so set the IAT here */
		    Iat = (PVOID)((ULONG_PTR)(ImportLdrEntry->DllBase) + SectionHeader->VirtualAddress);

		    /* Set the size */
		    IatSize = SectionHeader->Misc.VirtualSize;

		    /* Deal with Watcom and other retarded compilers */
		    if (!IatSize) {
			IatSize = SectionHeader->SizeOfRawData;
		    }

		    /* Found it, get out */
		    break;
		}

		/* No match, move to the next section */
		SectionHeader++;
	    }
	}

	/* If we still don't have an IAT, that's bad */
	if (!Iat) {
	    /* Fail */
	    DbgPrint("LDR: Unable to locate IAT for %wZ (Image Base %p)\n",
		     &ImportLdrEntry->BaseDllName, ImportLdrEntry->DllBase);
	    return STATUS_INVALID_IMAGE_FORMAT;
	}

	/* Set the right size */
	ImportSize = IatSize;
    }

    /* Check if the Thunks are already valid */
    if (EntriesValid) {
	/* We'll only do forwarders. Get the import name */
	ImportName = (PCSTR)((ULONG_PTR)(ImportLdrEntry->DllBase) + IatEntry->Name);

	/* Get the list of forwarders */
	ForwarderChain = IatEntry->ForwarderChain;

	/* Loop them */
	while (ForwarderChain != -1) {
	    /* Get the cached thunk VA */
	    OriginalThunk = (PIMAGE_THUNK_DATA)
		((ULONG_PTR) ImportLdrEntry->DllBase + IatEntry->OriginalFirstThunk +
		 (ForwarderChain * sizeof(IMAGE_THUNK_DATA)));

	    /* Get the first thunk */
	    FirstThunk = (PIMAGE_THUNK_DATA)
		((ULONG_PTR) ImportLdrEntry->DllBase + IatEntry->FirstThunk +
		 (ForwarderChain * sizeof(IMAGE_THUNK_DATA)));

	    /* Get the Forwarder from the thunk */
	    ForwarderChain = (ULONG) FirstThunk->u1.Ordinal;

	    /* Snap the thunk */
	    Status = LdrpSnapThunk(ExportLdrEntry->DllBase,
				   ImportLdrEntry->DllBase,
				   OriginalThunk,
				   FirstThunk,
				   ExportDirectory,
				   ExportSize, TRUE, ImportName);

	    /* If we messed up, exit */
	    if (!NT_SUCCESS(Status))
		break;

	    /* Move to the next thunk */
	    FirstThunk++;
	}
    } else if (IatEntry->FirstThunk) {
	/* Full snapping. Get the First thunk */
	FirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR) ImportLdrEntry->DllBase + IatEntry->FirstThunk);

	/* Get the NT Header */
	NtHeader = RtlImageNtHeader(ImportLdrEntry->DllBase);

	/* Get the Original thunk VA, watch out for weird images */
	if ((IatEntry->Characteristics < NtHeader->OptionalHeader.SizeOfHeaders)
	    || (IatEntry->Characteristics >= NtHeader->OptionalHeader.SizeOfImage)) {
	    /* Refuse it, this is a strange linked file */
	    OriginalThunk = FirstThunk;
	} else {
	    /* Get the address from the field and convert to VA */
	    OriginalThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR) ImportLdrEntry->DllBase + IatEntry->OriginalFirstThunk);
	}

	/* Get the Import name VA */
	ImportName = (PCSTR) ((ULONG_PTR) ImportLdrEntry->DllBase + IatEntry->Name);

	/* Loop while it's valid */
	while (OriginalThunk->u1.AddressOfData) {
	    /* Snap the Thunk */
	    Status = LdrpSnapThunk(ExportLdrEntry->DllBase,
				   ImportLdrEntry->DllBase,
				   OriginalThunk,
				   FirstThunk,
				   ExportDirectory,
				   ExportSize, TRUE, ImportName);

	    /* If we failed the snap, break out */
	    if (!NT_SUCCESS(Status))
		break;

	    /* Next thunks */
	    OriginalThunk++;
	    FirstThunk++;
	}
    }

    /* Return to Caller */
    return Status;
}

static NTSTATUS LdrpHandleBoundDescriptor(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
					  IN PIMAGE_BOUND_IMPORT_DESCRIPTOR *BoundEntryPtr,
					  IN PIMAGE_BOUND_IMPORT_DESCRIPTOR FirstEntry)
{
    PCSTR ImportName = NULL;
    BOOLEAN AlreadyLoaded = FALSE, Stale;
    PIMAGE_IMPORT_DESCRIPTOR ImportEntry;
    PLDR_DATA_TABLE_ENTRY DllLdrEntry, ForwarderLdrEntry;
    PIMAGE_BOUND_FORWARDER_REF ForwarderEntry;
    PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundEntry;
    PPEB Peb = NtCurrentPeb();

    /* Get the pointer to the bound entry */
    BoundEntry = *BoundEntryPtr;

    /* Get the name's VA */
    PCSTR BoundImportName = (PCSTR) FirstEntry + BoundEntry->OffsetModuleName;

    /* Show debug message */
    DPRINT1("LDR: %wZ bound to %s\n", &LdrEntry->BaseDllName, BoundImportName);

    /* Load the module for this entry */
    NTSTATUS Status = LdrpLoadImportModule(BoundImportName,
					   &DllLdrEntry, &AlreadyLoaded);
    if (!NT_SUCCESS(Status)) {
	/* Show debug message */
	DPRINT1("LDR: %wZ failed to load import module %s; status = %x\n",
		&LdrEntry->BaseDllName, BoundImportName, Status);
	goto Quickie;
    }

    /* Check if it wasn't already loaded */
    if (!AlreadyLoaded) {
	/* Add it to our list */
	InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
		       &DllLdrEntry->InInitializationOrderLinks);
    }

    /* Check if the Bound Entry is now invalid */
    if ((BoundEntry->TimeDateStamp != DllLdrEntry->TimeDateStamp) ||
	(DllLdrEntry->Flags & LDRP_IMAGE_NOT_AT_BASE)) {
	/* Show debug message */
	DPRINT1("LDR: %wZ has stale binding to %s\n",
		&LdrEntry->BaseDllName, BoundImportName);

	/* Remember it's become stale */
	Stale = TRUE;
    } else {
	/* Show debug message */
	DPRINT1("LDR: %wZ has correct binding to %s\n",
		&LdrEntry->BaseDllName, BoundImportName);

	/* Remember it's valid */
	Stale = FALSE;
    }

    /* Get the forwarders */
    ForwarderEntry = (PIMAGE_BOUND_FORWARDER_REF) (BoundEntry + 1);

    /* Loop them */
    for (ULONG i = 0; i < BoundEntry->NumberOfModuleForwarderRefs; i++) {
	/* Get the name */
	PCSTR ForwarderName = (PCSTR) FirstEntry + ForwarderEntry->OffsetModuleName;

	/* Show debug message */
	DPRINT1("LDR: %wZ bound to %s via forwarder(s) from %wZ\n",
		&LdrEntry->BaseDllName,
		ForwarderName, &DllLdrEntry->BaseDllName);

	/* Load the module */
	Status = LdrpLoadImportModule(ForwarderName, &ForwarderLdrEntry, &AlreadyLoaded);
	if (NT_SUCCESS(Status)) {
	    /* Loaded it, was it already loaded? */
	    if (!AlreadyLoaded) {
		/* Add it to our list */
		InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
			       &ForwarderLdrEntry->InInitializationOrderLinks);
	    }
	}

	/* Check if the Bound Entry is now invalid */
	if (!(NT_SUCCESS(Status)) || (ForwarderEntry->TimeDateStamp != ForwarderLdrEntry->TimeDateStamp)
	    || (ForwarderLdrEntry->Flags & LDRP_IMAGE_NOT_AT_BASE)) {
	    /* Show debug message */
	    DPRINT1("LDR: %wZ has stale binding to %s\n",
		    &LdrEntry->BaseDllName, ForwarderName);

	    /* Remember it's become stale */
	    Stale = TRUE;
	} else {
	    /* Show debug message */
	    DPRINT1("LDR: %wZ has correct binding to %s\n",
		    &LdrEntry->BaseDllName, ForwarderName);

	    /* Remember it's valid */
	    Stale = FALSE;
	}

	/* Move to the next one */
	ForwarderEntry++;
    }

    /* Set the next bound entry to the forwarder */
    FirstEntry = (PIMAGE_BOUND_IMPORT_DESCRIPTOR) ForwarderEntry;

    /* Check if the binding was stale */
    if (Stale) {
	ULONG IatSize;
	/* It was, so find the IAT entry for it */
	ImportEntry = RtlImageDirectoryEntryToData(LdrEntry->DllBase,
						   TRUE,
						   IMAGE_DIRECTORY_ENTRY_IMPORT,
						   &IatSize);

	/* Make sure it has a name */
	while (ImportEntry->Name) {
	    /* Get the name */
	    ImportName = (PCSTR) ((ULONG_PTR) LdrEntry->DllBase + ImportEntry->Name);

	    /* Compare it */
	    if (!strcasecmp(ImportName, BoundImportName))
		break;

	    /* Move to next entry */
	    ImportEntry++;
	}

	/* If we didn't find a name, fail */
	if (!ImportEntry->Name) {
	    /* Show debug message */
	    DPRINT1("LDR: LdrpWalkImportTable - failing with"
		    "STATUS_OBJECT_NAME_INVALID due to no import descriptor name\n");

	    /* Return error */
	    Status = STATUS_OBJECT_NAME_INVALID;
	    goto Quickie;
	}

	/* Show debug message */
	DPRINT1("LDR: Stale Bind %s from %wZ\n", ImportName, &LdrEntry->BaseDllName);

	/* Snap the IAT Entry */
	Status = LdrpSnapIAT(DllLdrEntry, LdrEntry, ImportEntry, FALSE);

	/* Make sure we didn't fail */
	if (!NT_SUCCESS(Status)) {
	    /* Show debug message */
	    DPRINT1("LDR: %wZ failed to load import module %s; status = %x\n",
		    &LdrEntry->BaseDllName, BoundImportName, Status);

	    /* Return */
	    goto Quickie;
	}
    }

    /* All done */
    Status = STATUS_SUCCESS;

Quickie:
    /* Write where we are now and return */
    *BoundEntryPtr = FirstEntry;
    return Status;
}

static NTSTATUS LdrpHandleBoundTable(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				     IN PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundEntry)
{
    PIMAGE_BOUND_IMPORT_DESCRIPTOR FirstEntry = BoundEntry;

    /* Make sure we have a name */
    while (BoundEntry->OffsetModuleName) {
	/* Parse this descriptor */
	RET_ERR(LdrpHandleBoundDescriptor(LdrEntry, &BoundEntry, FirstEntry));
    }

    /* Done */
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpHandleImportDescriptor(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
					   IN PIMAGE_IMPORT_DESCRIPTOR *ImportEntry)
{
    PCSTR ImportName;
    BOOLEAN AlreadyLoaded = FALSE;
    PLDR_DATA_TABLE_ENTRY DllLdrEntry;
    PIMAGE_THUNK_DATA FirstThunk;
    PPEB Peb = NtCurrentPeb();

    /* Get the import name's VA */
    ImportName = (PCSTR) ((ULONG_PTR) LdrEntry->DllBase + (*ImportEntry)->Name);

    /* Get the first thunk */
    FirstThunk = (PIMAGE_THUNK_DATA) ((ULONG_PTR) LdrEntry->DllBase + (*ImportEntry)->FirstThunk);

    /* Make sure it's valid */
    if (!FirstThunk->u1.Function)
	goto SkipEntry;

    /* Show debug message */
    DPRINT1("LDR: %s used by %wZ\n", ImportName, &LdrEntry->BaseDllName);

    /* Load the module associated to it */
    NTSTATUS Status = LdrpLoadImportModule(ImportName, &DllLdrEntry, &AlreadyLoaded);
    if (!NT_SUCCESS(Status)) {
	/* Fail */
	DbgPrint("LDR: LdrpWalkImportTable - LdrpLoadImportModule failed "
		 "on import %s with status %x\n", ImportName, Status);
	/* Return */
	return Status;
    }

    /* Show debug message */
    DPRINT1("LDR: Snapping imports for %wZ from %s\n",
	    &LdrEntry->BaseDllName, ImportName);

    /* Check if it wasn't already loaded */
    if (!AlreadyLoaded) {
	/* Add the DLL to our list */
	InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
		       &DllLdrEntry->InInitializationOrderLinks);
    }

    /* Now snap the IAT Entry */
    Status = LdrpSnapIAT(DllLdrEntry, LdrEntry, *ImportEntry, FALSE);
    if (!NT_SUCCESS(Status)) {
	/* Fail */
	DbgPrint("LDR: LdrpWalkImportTable - LdrpSnapIAT #2 failed with "
		 "status %x\n", Status);
	/* Return */
	return Status;
    }

SkipEntry:
    /* Move on */
    (*ImportEntry)++;
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpHandleImportTable(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				      IN PIMAGE_IMPORT_DESCRIPTOR ImportEntry)
{
    /* Check for Name and Thunk */
    while ((ImportEntry->Name) && (ImportEntry->FirstThunk)) {
	/* Parse this descriptor */
	RET_ERR(LdrpHandleImportDescriptor(LdrEntry, &ImportEntry));
    }

    /* Done */
    return STATUS_SUCCESS;
}

NTSTATUS LdrpWalkImportDescriptor(IN PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PIMAGE_BOUND_IMPORT_DESCRIPTOR BoundEntry = NULL;
    ULONG BoundTableSize = 0, ImportTableSize = 0;

    DbgTrace("Walking import table (%wZ loaded at %p)\n",
	     &LdrEntry->BaseDllName, LdrEntry->DllBase);

    /* Check if we were redirected */
    if (!(LdrEntry->Flags & LDRP_REDIRECTED)) {
	/* Get the Bound IAT */
	BoundEntry = RtlImageDirectoryEntryToData(LdrEntry->DllBase, TRUE,
						  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
						  &BoundTableSize);
    }

    /* Get the regular IAT, for fallback */
    PIMAGE_IMPORT_DESCRIPTOR ImportEntry = RtlImageDirectoryEntryToData(LdrEntry->DllBase, TRUE,
									IMAGE_DIRECTORY_ENTRY_IMPORT,
									&ImportTableSize);

    /* Check if we got at least one */
    if ((BoundEntry) || (ImportEntry)) {
	/* Do we have a Bound IAT */
	if (BoundEntry) {
	    /* Handle the descriptor */
	    RET_ERR(LdrpHandleBoundTable(LdrEntry, BoundEntry));
	} else {
	    /* Handle the descriptor */
	    RET_ERR(LdrpHandleImportTable(LdrEntry, ImportEntry));
	}
    }

    /* Return status */
    return STATUS_SUCCESS;
}
