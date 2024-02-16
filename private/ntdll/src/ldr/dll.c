#include "ldrp.h"
#include <printf.h>

#define LDR_DLL_DEFAULT_EXTENSION	".dll"

PLDR_DATA_TABLE_ENTRY LdrpAllocateDataTableEntry(IN PVOID BaseAddress)
{
    /* Make sure the header is valid */
    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(BaseAddress);
    DPRINT("LdrpAllocateDataTableEntry(%p), NtHeader %p\n", BaseAddress,
	   NtHeader);
    if (!NtHeader) {
	return NULL;
    }

    PLDR_DATA_TABLE_ENTRY LdrEntry = RtlAllocateHeap(LdrpHeap,
						     HEAP_ZERO_MEMORY,
						     sizeof(LDR_DATA_TABLE_ENTRY));
    if (!LdrEntry) {
	return NULL;
    }

    LdrEntry->DllBase = BaseAddress;
    LdrEntry->SizeOfImage = NtHeader->OptionalHeader.SizeOfImage;
    LdrEntry->TimeDateStamp = NtHeader->FileHeader.TimeDateStamp;
    LdrEntry->PatchInformation = NULL;
    return LdrEntry;
}

VOID LdrpInsertMemoryTableEntry(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				IN PCSTR BaseDllName)
{
    PPEB_LDR_DATA PebData = NtCurrentPeb()->LdrData;

    ULONG i = LDRP_GET_HASH_ENTRY(BaseDllName);
    InsertTailList(&LdrpHashTable[i], &LdrEntry->HashLinks);

    InsertTailList(&PebData->InLoadOrderModuleList, &LdrEntry->InLoadOrderLinks);
    InsertTailList(&PebData->InMemoryOrderModuleList, &LdrEntry->InMemoryOrderLinks);
}

VOID LdrpFreeDataTableEntry(IN PLDR_DATA_TABLE_ENTRY Entry)
{
    RtlFreeHeap(LdrpHeap, 0, Entry);
}

BOOLEAN LdrpCheckForLoadedDll(IN PCSTR DllName,
			      OUT OPTIONAL PLDR_DATA_TABLE_ENTRY *LdrEntry)
{
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

BOOLEAN LdrpCheckForLoadedDllHandle(IN PVOID Base,
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

static NTSTATUS LdrpCreateDllSection(IN OPTIONAL PUNICODE_STRING FullName,
				     IN OPTIONAL HANDLE FileHandle,
				     OUT PHANDLE SectionHandle)
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;

    *SectionHandle = NULL;
    /* If the caller did not supply a file handle, open the file first. */
    HANDLE NewFileHandle = NULL;
    if (!FileHandle) {
	if (!FullName) {
	    return STATUS_INVALID_PARAMETER;
	}

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, FullName,
				   OBJ_CASE_INSENSITIVE, NULL, NULL);
	Status = NtOpenFile(&NewFileHandle,
			    SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA,
			    &ObjectAttributes,
			    &IoStatusBlock,
			    FILE_SHARE_READ | FILE_SHARE_DELETE,
			    FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

	if (!NT_SUCCESS(Status)) {
	    DPRINT1("LDR: LdrpCreateDllSection - NtOpenFile failed; status = %x\n",
		    Status);
	    return Status == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_DLL_NOT_FOUND : Status;
	}
	FileHandle = NewFileHandle;
    }

    /* Create a section for the DLL */
    Status = NtCreateSection(SectionHandle,
			     SECTION_MAP_READ | SECTION_MAP_EXECUTE |
			     SECTION_MAP_WRITE | SECTION_QUERY,
			     NULL, NULL, PAGE_EXECUTE, SEC_IMAGE, FileHandle);

    if (!NT_SUCCESS(Status)) {
	*SectionHandle = NULL;
	if (NewFileHandle) {
	    NtClose(NewFileHandle);
	}
	return Status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LdrpMapDll(IN PCSTR DllName,
			   IN BOOLEAN Static,
			   OUT PLDR_DATA_TABLE_ENTRY *DataTableEntry)
{
    HANDLE SectionHandle = NULL;
    PVOID ViewBase = NULL;
    PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;
    DPRINT1("LDR: LdrpMapDll: Image Name %s\n", DllName);

    /* For now we will hard code the search path to \BootModules */
    CHAR PathBuf[512];
    snprintf(PathBuf, sizeof(PathBuf), "\\BootModules\\%s", DllName);
    UNICODE_STRING BaseDllName = {};
    UNICODE_STRING FullDllPath = {};
    NTSTATUS Status;
    IF_ERR_GOTO(err, Status, LdrpUtf8ToUnicodeString(DllName, &BaseDllName));
    IF_ERR_GOTO(err, Status, LdrpUtf8ToUnicodeString(PathBuf, &FullDllPath));

    /* Open the dll file and create an image section for it */
    IF_ERR_GOTO(err, Status, LdrpCreateDllSection(&FullDllPath, NULL,
						   &SectionHandle));

    /* Map the section view. The server will first try to map the image at its
     * preferred image base, and if that's not possible, it will search for an
     * appropriate space and map the image there. */
    SIZE_T ViewSize = 0;
    Status = NtMapViewOfSection(SectionHandle, NtCurrentProcess(),
				&ViewBase, 0, 0, NULL, &ViewSize,
				ViewShare, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status)) {
	goto err;
    }

    /* Get the NT Header */
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ViewBase);
    if (!NtHeaders) {
	/* Invalid image. This should never happen. Assert in debug build. */
	assert(FALSE);
	Status = STATUS_INVALID_IMAGE_FORMAT;
	goto err;
    }

    /* Allocate an entry in the loader database */
    LdrEntry = LdrpAllocateDataTableEntry(ViewBase);
    if (!LdrEntry) {
	Status = STATUS_NO_MEMORY;
	goto err;
    }

    /* Setup the entry */
    LdrEntry->Flags = Static ? LDRP_STATIC_LINK : 0;
    LdrEntry->LoadCount = 0;
    LdrEntry->FullDllName = FullDllPath;
    LdrEntry->BaseDllName = BaseDllName;
    LdrEntry->EntryPoint = LdrpFetchAddressOfEntryPoint(LdrEntry->DllBase);

    DPRINT1("LDR: LdrpMapDll: Full Name %wZ, Base Name %wZ\n",
	    &FullDllPath, &BaseDllName);

    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) {
	LdrEntry->Flags |= LDRP_IMAGE_DLL;
    }

    /* If we're not a DLL, clear the entrypoint */
    if (!(LdrEntry->Flags & LDRP_IMAGE_DLL)) {
	LdrEntry->EntryPoint = 0;
    }

    /* If the image is not mapped at its preferred image base, do the relocation. */
    ULONG_PTR ImageBase = (ULONG_PTR)NtHeaders->OptionalHeader.ImageBase;
    if ((ULONG_PTR)ViewBase != ImageBase) {
	/* In this case the image must not have its relocation information stripped. */
	if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
	    Status = STATUS_INVALID_IMAGE_FORMAT;
	    goto err;
	}
	ULONG RelocDataSize = 0;
	PVOID RelocData = RtlImageDirectoryEntryToData(ViewBase, TRUE,
						       IMAGE_DIRECTORY_ENTRY_BASERELOC,
						       &RelocDataSize);

	if (!RelocData && !RelocDataSize) {
	    Status = STATUS_INVALID_IMAGE_FORMAT;
	    goto err;
	}

	DPRINT("LDR: LdrpMapDll Relocating Image Name %s (%p-%p -> %p-%p)\n",
	       DllName, (PVOID)ImageBase, (PVOID)((SIZE_T)ImageBase + ViewSize),
	       ViewBase, (PVOID)((SIZE_T)ViewBase + ViewSize));

	/* Do the relocation */
	Status = LdrpRelocateImageWithBias(ViewBase, 0LL, NULL,
					   STATUS_SUCCESS,
					   STATUS_CONFLICTING_ADDRESSES,
					   STATUS_INVALID_IMAGE_FORMAT);
	if (!NT_SUCCESS(Status)) {
	    DPRINT1("LDR: Fixups unsuccessfully applied @ %p\n",
		    ViewBase);
	    goto err;
	}
	DPRINT1("LDR: Fixups successfully applied @ %p\n", ViewBase);
	LdrEntry->Flags |= LDRP_IMAGE_NOT_AT_BASE;
    }

    LdrpInsertMemoryTableEntry(LdrEntry, DllName);
    *DataTableEntry = LdrEntry;
    return STATUS_SUCCESS;

err:
    if (FullDllPath.Buffer) {
	LdrpFreeUnicodeString(FullDllPath);
    }
    if (BaseDllName.Buffer) {
	LdrpFreeUnicodeString(BaseDllName);
    }
    if (ViewBase) {
    	NtUnmapViewOfSection(NtCurrentProcess(), ViewBase);
    }
    if (SectionHandle) {
	NtClose(SectionHandle);
    }
    if (LdrEntry) {
	LdrpFreeDataTableEntry(LdrEntry);
    }
    return Status;
}

NTSTATUS LdrpLoadImportModule(IN PCSTR ImportName,
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
	PCHAR ImportNameExt = RtlAllocateHeap(LdrpHeap, 0,
					      ImportNameLength + sizeof(LDR_DLL_DEFAULT_EXTENSION));
	if (ImportNameExt == NULL) {
	    return STATUS_NO_MEMORY;
	}
	memcpy(ImportNameExt, ImportName, ImportNameLength);
	memcpy(&ImportNameExt[ImportNameLength], LDR_DLL_DEFAULT_EXTENSION,
	       sizeof(LDR_DLL_DEFAULT_EXTENSION));
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
	RtlFreeHeap(LdrpHeap, 0, (PVOID)ImportName);
    }

    return Status;
}

/*
 * Load the given dll and increase the load count in its loader database
 * entry (unless the entry is locked).
 */
NTSTATUS LdrpLoadDll(IN PCSTR DllName,
		     OUT PVOID *BaseAddress)
{
    PLDR_DATA_TABLE_ENTRY DataTableEntry = NULL;
    RET_ERR(LdrpLoadImportModule(DllName, &DataTableEntry, NULL));
    assert(DataTableEntry != NULL);
    if (DataTableEntry->LoadCount != 0xFFFF) {
	DataTableEntry->LoadCount++;
    }
    *BaseAddress = DataTableEntry->DllBase;
    return STATUS_SUCCESS;
}
