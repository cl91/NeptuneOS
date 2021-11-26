#include "ldrp.h"

/* TLS ***********************************************************************/

/*
 * Executable always has _tls_index == 0.
 * NTDLL always has _tls_index == SYSTEMDLL_TLS_INDEX == 1
 * We will set this during LdrpInitialize
 */
ULONG _tls_index;

#define MAX_NUMBER_OF_TLS_SLOTS	500

typedef struct _LDRP_TLS_DATA {
    LIST_ENTRY TlsLinks;
    IMAGE_TLS_DIRECTORY TlsDirectory;
} LDRP_TLS_DATA, *PLDRP_TLS_DATA;

/*
 * This must be placed at the very beginning ot the .tls section.
 *
 * Note: LDRP_INIT_THREAD_TLS_VECTOR is the tls vector for the initial thread.
 * Subsequent threads have different tls vectors. Use the ThreadLocalStoragePointer
 * member in the TEB to locate the tls vector for the current thread. This member
 * is set up by the NTOS server on thread creation.
 */
__declspec(allocate(".tls")) PVOID LDRP_INIT_THREAD_TLS_VECTOR[MAX_NUMBER_OF_TLS_SLOTS];

/* Address for the IPC buffer of the initial thread. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;

/* System service endpoint capability */
__thread seL4_CPtr KiSystemServiceCap;

/* GLOBALS *******************************************************************/

BOOLEAN LdrpShutdownInProgress;
HANDLE LdrpShutdownThreadId;

LIST_ENTRY LdrpHashTable[LDRP_HASH_TABLE_ENTRIES];
PLDR_DATA_TABLE_ENTRY LdrpImageEntry;
PLDR_DATA_TABLE_ENTRY LdrpNtdllEntry;

RTL_BITMAP TlsBitMap;
RTL_BITMAP TlsExpansionBitMap;
RTL_BITMAP FlsBitMap;
BOOLEAN LdrpImageHasTls;
LIST_ENTRY LdrpTlsList;

NLSTABLEINFO LdrpNlsTable;

extern LARGE_INTEGER RtlpTimeout;
PVOID LdrpHeap;

PEB_LDR_DATA PebLdr;

RTL_CRITICAL_SECTION_DEBUG LdrpLoaderLockDebug;
RTL_CRITICAL_SECTION LdrpLoaderLock = {
    &LdrpLoaderLockDebug,
    -1,
    0,
    0,
    0,
    0
};

RTL_CRITICAL_SECTION FastPebLock;

#ifdef _WIN64
#define DEFAULT_SECURITY_COOKIE 0x00002B992DDFA232ll
#else
#define DEFAULT_SECURITY_COOKIE 0xBB40E64E
#endif

/* FUNCTIONS *****************************************************************/

/*
 * Loop the tls array and allocate the tls region
 *
 * Note that the tls list does not include the TLS region for NTDLL, which is
 * allocated by the server and set up on server side and upon LdrpInitialize.
 */
static NTSTATUS LdrpAllocateTls(VOID)
{
    PPVOID TlsVector = NtCurrentTeb()->ThreadLocalStoragePointer;
    PLIST_ENTRY ListHead = &LdrpTlsList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	/* Get the entry */
	PLDRP_TLS_DATA TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks);
	NextEntry = NextEntry->Flink;

	/* Strictly speaking the .tls section does not need to be a dedicated
	 * section, and can be merged with other data sections, as long as all
	 * TLS data remain contiguous in memory. We do this to the hal.dll
	 * and merge the .tls section and the .data section in order to save memory.
	 *
	 * However when generating code clang seems to assume that the tls data
	 * always start at a section boundary (which is aligned at page boundary).
	 * Therefore when merging the .tls section with other sections the .tls
	 * section must always be at the very beginning of the final section.
	 * If this is not the case, heap corruption will occur when accessing
	 * thread local variables. Warn the user in this case. */
	if (!IS_PAGE_ALIGNED(TlsData->TlsDirectory.StartAddressOfRawData)) {
	    DPRINT("LDR: WARNING: TLS data does not align at page boundary. Heap corruption might occur! Tls data start address %p\n",
		   (PVOID) TlsData->TlsDirectory.StartAddressOfRawData);
	}

	/* Allocate this vector */
	SIZE_T TlsDataSize = TlsData->TlsDirectory.EndAddressOfRawData -
	    TlsData->TlsDirectory.StartAddressOfRawData;
	TlsVector[TlsData->TlsDirectory.Characteristics] =
	    RtlAllocateHeap(RtlGetProcessHeap(), 0, TlsDataSize);
	if (!TlsVector[TlsData->TlsDirectory.Characteristics]) {
	    /* Out of memory */
	    return STATUS_NO_MEMORY;
	}

	DPRINT1("LDR: TlsData of size 0x%zx is copied from %p to %p (TlsIndex %u = %p, TlsVector = %p)\n",
		TlsDataSize, (PVOID) TlsData->TlsDirectory.StartAddressOfRawData,
		TlsVector[TlsData->TlsDirectory.Characteristics],
		TlsData->TlsDirectory.Characteristics,
		&TlsVector[TlsData->TlsDirectory.Characteristics], TlsVector);

	/* Copy the data */
	RtlCopyMemory(TlsVector[TlsData->TlsDirectory.Characteristics],
		      (PVOID) TlsData->TlsDirectory.StartAddressOfRawData,
		      TlsDataSize);
    }

    return STATUS_SUCCESS;
}

static VOID LdrpFreeTls()
{
    PPVOID TlsVector = NtCurrentTeb()->ThreadLocalStoragePointer;
    /* Loop through it */
    PLIST_ENTRY ListHead = &LdrpTlsList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	PLDRP_TLS_DATA TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA,
						   TlsLinks);
	NextEntry = NextEntry->Flink;

	/* Free each entry */
	if (TlsVector[TlsData->TlsDirectory.Characteristics]) {
	    RtlFreeHeap(RtlGetProcessHeap(), 0,
			TlsVector[TlsData->TlsDirectory.Characteristics]);
	}
    }
}

static NTSTATUS LdrpInitializeTls(VOID)
{
    /* Initialize the TLS List */
    InitializeListHead(&LdrpTlsList);

    /* The executable image has tls_index == 0. NTDLL has tls_index = 1.
     * All other modules start from tls_index == 2 */
    ULONG NextTlsIndex = 2;

    /* Loop all the modules */
    PLIST_ENTRY ListHead = &NtCurrentPeb()->LdrData->InLoadOrderModuleList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    while (ListHead != NextEntry) {
	/* Get the entry */
	PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(NextEntry,
							   LDR_DATA_TABLE_ENTRY,
							   InLoadOrderLinks);
	NextEntry = NextEntry->Flink;

	/* Skip the ntdll entry */
	if (LdrEntry == LdrpNtdllEntry)
	    continue;

	/* Get the TLS directory */
	ULONG TlsDirectorySize;
	PIMAGE_TLS_DIRECTORY TlsDirectory = RtlImageDirectoryEntryToData(LdrEntry->DllBase,
									 TRUE,
									 IMAGE_DIRECTORY_ENTRY_TLS,
									 &TlsDirectorySize);

	/* Check if we have a directory */
	if (!TlsDirectory)
	    continue;

	/* Check if the image has TLS */
	if (!LdrpImageHasTls)
	    LdrpImageHasTls = TRUE;

	DPRINT1("LDR: Tls Found in %wZ at %p\n", &LdrEntry->BaseDllName, TlsDirectory);

	/* Allocate an entry */
	PLDRP_TLS_DATA TlsData = (PLDRP_TLS_DATA) RtlAllocateHeap(RtlGetProcessHeap(), 0,
								  sizeof(LDRP_TLS_DATA));
	if (!TlsData)
	    return STATUS_NO_MEMORY;

	/* Set the load count to -1 to mark the module as pinned in memory
	 * for the lifetime of the process */
	LdrEntry->LoadCount = -1;

	/* For some stupid reason the TlsIndex member is always set to -1
	 * in the M$ implementation (although not on WINE). We follow the
	 * M$ convention here though this is quite frankly retarded. See
	 * http://www.nynaeve.net/?p=186 */
	LdrEntry->TlsIndex = -1;

	/* Save the cached TLS data */
	TlsData->TlsDirectory = *TlsDirectory;
	InsertTailList(&LdrpTlsList, &TlsData->TlsLinks);

	/* Update the index. For the executable image itself, we
	 * force the tls index to be 0 (some image assumes this). */
	ULONG TlsIndex = 0;
	if (LdrEntry != LdrpImageEntry) {
	    TlsIndex = NextTlsIndex++;
	}
	if (TlsIndex >= MAX_NUMBER_OF_TLS_SLOTS) {
	    return STATUS_NO_MEMORY;
	}
	*(PLONG) TlsData->TlsDirectory.AddressOfIndex = TlsIndex;
	TlsData->TlsDirectory.Characteristics = TlsIndex;
    }

    return LdrpAllocateTls();
}

static PVOID LdrpFetchAddressOfSecurityCookie(IN PVOID BaseAddress,
					      IN ULONG SizeOfImage)
{
    PIMAGE_LOAD_CONFIG_DIRECTORY ConfigDir;
    ULONG DirSize;
    PVOID Cookie = NULL;

    /* Check NT header first */
    if (!RtlImageNtHeader(BaseAddress))
	return NULL;

    /* Get the pointer to the config directory */
    ConfigDir = RtlImageDirectoryEntryToData(BaseAddress,
					     TRUE,
					     IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
					     &DirSize);

    /* Check for sanity */
    if (!ConfigDir || (DirSize != 64 && ConfigDir->Size != DirSize) ||
	(ConfigDir->Size < 0x48))
	return NULL;

    /* Now get the cookie */
    Cookie = (PVOID) ConfigDir->SecurityCookie;

    /* Check this cookie */
    if ((PCHAR) Cookie <= (PCHAR) BaseAddress ||
	(PCHAR) Cookie >= (PCHAR) BaseAddress + SizeOfImage) {
	Cookie = NULL;
    }

    /* Return validated security cookie */
    return Cookie;
}

static PVOID LdrpInitSecurityCookie(PLDR_DATA_TABLE_ENTRY LdrEntry)
{
    PULONG_PTR Cookie;
    LARGE_INTEGER Counter;
    ULONG_PTR NewCookie;

    /* Fetch address of the cookie */
    Cookie = LdrpFetchAddressOfSecurityCookie(LdrEntry->DllBase,
					      LdrEntry->SizeOfImage);

    if (Cookie) {
	/* Check if it's a default one */
	if ((*Cookie == DEFAULT_SECURITY_COOKIE) || (*Cookie == 0xBB40)) {
	    /* Make up a cookie from a bunch of values which may uniquely represent
	       current moment of time, environment, etc */
	    NtQueryPerformanceCounter(&Counter, NULL);

	    NewCookie = Counter.LowPart ^ Counter.HighPart;
	    NewCookie ^= (ULONG_PTR) NtCurrentTeb()->ClientId.UniqueProcess;
	    NewCookie ^= (ULONG_PTR) NtCurrentTeb()->ClientId.UniqueThread;

	    /* Loop like it's done in KeQueryTickCount(). We don't want to call it directly. */
	    while (SharedUserData->SystemTime.High1Time != SharedUserData->SystemTime.High2Time) {
		YieldProcessor();
	    };

	    /* Calculate the milliseconds value and xor it to the cookie */
	    NewCookie ^= Int64ShrlMod32(UInt32x32To64(SharedUserData->TickCountMultiplier,
						      SharedUserData->TickCount.LowPart), 24)
		+ SharedUserData->TickCountMultiplier * (SharedUserData->TickCount.High1Time << 8);

	    /* Make the cookie 16bit if necessary */
	    if (*Cookie == 0xBB40)
		NewCookie &= 0xFFFF;

	    /* If the result is 0 or the same as we got, just subtract one from the existing value
	       and that's it */
	    if ((NewCookie == 0) || (NewCookie == *Cookie)) {
		NewCookie = *Cookie - 1;
	    }

	    /* Set the new cookie value */
	    *Cookie = NewCookie;
	}
    }

    return Cookie;
}

static BOOLEAN LdrpCallInitRoutine(IN PDLL_INIT_ROUTINE EntryPoint,
				   IN PVOID BaseAddress,
				   IN ULONG Reason,
				   IN PVOID Context)
{
    /* Call the entry */
    return EntryPoint(BaseAddress, Reason, Context);
}

static VOID LdrpCallTlsInitializers(IN PLDR_DATA_TABLE_ENTRY LdrEntry,
				    IN ULONG Reason)
{
    PIMAGE_TLS_DIRECTORY TlsDirectory;
    PIMAGE_TLS_CALLBACK *Array, Callback;
    ULONG Size;

    /* Get the TLS Directory */
    TlsDirectory = RtlImageDirectoryEntryToData(LdrEntry->DllBase,
						TRUE,
						IMAGE_DIRECTORY_ENTRY_TLS,
						&Size);

    /* Protect against invalid pointers */
    _SEH2_TRY {
	/* Make sure it's valid */
	if (TlsDirectory) {
	    /* Get the array */
	    Array = (PIMAGE_TLS_CALLBACK *) TlsDirectory->AddressOfCallBacks;
	    if (Array) {
		/* Display debug */
		DPRINT1("LDR: Tls Callbacks Found. Imagebase %p Tls %p CallBacks %p\n",
			LdrEntry->DllBase, TlsDirectory, Array);

		/* Loop the array */
		while (*Array) {
		    /* Get the TLS Entrypoint */
		    Callback = *Array++;

		    /* Display debug */
		    DPRINT1("LDR: Calling Tls Callback Imagebase %p Function %p\n",
			    LdrEntry->DllBase, Callback);

		    /* Call it */
		    LdrpCallInitRoutine((PDLL_INIT_ROUTINE) Callback,
					LdrEntry->DllBase, Reason, NULL);
		}
	    }
	}
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	DPRINT1("LDR: Exception 0x%lx during Tls Callback(%u) for %wZ\n",
		_SEH2_GetExceptionCode(), Reason, &LdrEntry->BaseDllName);
    }
}

static NTSTATUS LdrpRunInitializeRoutines(IN PCONTEXT Context OPTIONAL)
{
#if 0
    PLDR_DATA_TABLE_ENTRY LocalArray[16];
    PLIST_ENTRY ListHead;
    PLIST_ENTRY NextEntry;
    PLDR_DATA_TABLE_ENTRY LdrEntry, *LdrRootEntry, OldInitializer;
    PVOID EntryPoint;
    ULONG Count, i;
    NTSTATUS Status = STATUS_SUCCESS;
    PPEB Peb = NtCurrentPeb();
    ULONG BreakOnDllLoad;
    BOOLEAN DllStatus;

    DPRINT("LdrpRunInitializeRoutines() called for %wZ (%p/%p)\n",
	   &LdrpImageEntry->BaseDllName,
	   NtCurrentTeb()->RealClientId.UniqueProcess,
	   NtCurrentTeb()->RealClientId.UniqueThread);

    /* Get the number of entries to call */
    if ((Count = LdrpClearLoadInProgress())) {
	/* Check if we can use our local buffer */
	if (Count > 16) {
	    /* Allocate space for all the entries */
	    LdrRootEntry = RtlAllocateHeap(LdrpHeap,
					   0,
					   Count * sizeof(*LdrRootEntry));
	    if (!LdrRootEntry)
		return STATUS_NO_MEMORY;
	} else {
	    /* Use our local array */
	    LdrRootEntry = LocalArray;
	}
    } else {
	/* Don't need one */
	LdrRootEntry = NULL;
    }

    /* Show debug message */
    DPRINT1("[%p,%p] LDR: Real INIT LIST for Process %wZ\n",
	    NtCurrentTeb()->RealClientId.UniqueThread,
	    NtCurrentTeb()->RealClientId.UniqueProcess,
	    &Peb->ProcessParameters->ImagePathName);

    /* Loop in order */
    ListHead = &Peb->LdrData->InInitializationOrderModuleList;
    NextEntry = ListHead->Flink;
    i = 0;
    while (NextEntry != ListHead) {
	/* Get the Data Entry */
	LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY,
				     InInitializationOrderLinks);

	/* Check if we have a Root Entry */
	if (LdrRootEntry) {
	    /* Check flags */
	    if (!(LdrEntry->Flags & LDRP_ENTRY_PROCESSED)) {
		/* Setup the Cookie for the DLL */
		LdrpInitSecurityCookie(LdrEntry);

		/* Check for valid entrypoint */
		if (LdrEntry->EntryPoint) {
		    /* Write in array */
		    ASSERT(i < Count);
		    LdrRootEntry[i] = LdrEntry;

		    /* Display debug message */
		    DPRINT1("[%p,%p] LDR: %wZ init routine %p\n",
			    NtCurrentTeb()->RealClientId.UniqueThread,
			    NtCurrentTeb()->RealClientId.UniqueProcess,
			    &LdrEntry->FullDllName,
			    LdrEntry->EntryPoint);
		    i++;
		}
	    }
	}

	/* Set the flag */
	LdrEntry->Flags |= LDRP_ENTRY_PROCESSED;
	NextEntry = NextEntry->Flink;
    }

    Status = STATUS_SUCCESS;

    /* No root entry? return */
    if (!LdrRootEntry)
	return Status;

    /* Loop */
    i = 0;
    while (i < Count) {
	/* Get an entry */
	LdrEntry = LdrRootEntry[i];

	/* FIXME: Verify NX Compat */

	/* Move to next entry */
	i++;

	/* Get its entrypoint */
	EntryPoint = LdrEntry->EntryPoint;

	/* Are we being debugged? */
	BreakOnDllLoad = 0;
	if (Peb->BeingDebugged || Peb->ReadImageFileExecOptions) {
	    /* Check if we should break on load */
	    Status = LdrQueryImageFileExecutionOptions(&LdrEntry->BaseDllName,
						       L"BreakOnDllLoad",
						       REG_DWORD,
						       &BreakOnDllLoad,
						       sizeof(ULONG), NULL);
	    if (!NT_SUCCESS(Status))
		BreakOnDllLoad = 0;

	    /* Reset status back to STATUS_SUCCESS */
	    Status = STATUS_SUCCESS;
	}

	/* Break if aksed */
	if (BreakOnDllLoad) {
	    /* Check if we should show a message */
	    DPRINT1("LDR: %wZ loaded.", &LdrEntry->BaseDllName);
	    DPRINT1(" - About to call init routine at %p\n", EntryPoint);

	    /* Break in debugger */
	    DbgBreakPoint();
	}

	/* Make sure we have an entrypoint */
	if (EntryPoint) {
	    /* Save the old Dll Initializer and write the current one */
	    OldInitializer = LdrpCurrentDllInitializer;
	    LdrpCurrentDllInitializer = LdrEntry;

	    _SEH2_TRY {
		/* Check if it has TLS */
		if (LdrEntry->TlsIndex && Context) {
		    /* Call TLS */
		    LdrpCallTlsInitializers(LdrEntry, DLL_PROCESS_ATTACH);
		}

		/* Call the Entrypoint */
		DPRINT1("%wZ - Calling entry point at %p for DLL_PROCESS_ATTACH\n",
			&LdrEntry->BaseDllName, EntryPoint);
		DllStatus = LdrpCallInitRoutine(EntryPoint,
						LdrEntry->DllBase,
						DLL_PROCESS_ATTACH,
						Context);
	    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
		DllStatus = FALSE;
		DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_PROCESS_ATTACH) for %wZ\n",
			_SEH2_GetExceptionCode(), &LdrEntry->BaseDllName);
	    }

	    /* Save the Current DLL Initializer */
	    LdrpCurrentDllInitializer = OldInitializer;

	    /* Mark the entry as processed */
	    LdrEntry->Flags |= LDRP_PROCESS_ATTACH_CALLED;

	    /* Fail if DLL init failed */
	    if (!DllStatus) {
		DPRINT1("LDR: DLL_PROCESS_ATTACH for dll \"%wZ\" (InitRoutine: %p) failed\n",
			&LdrEntry->BaseDllName, EntryPoint);

		Status = STATUS_DLL_INIT_FAILED;
		goto Quickie;
	    }
	}
    }

    /* Loop in order */
    ListHead = &Peb->LdrData->InInitializationOrderModuleList;
    NextEntry = NextEntry->Flink;
    while (NextEntry != ListHead) {
	/* Get the Data Entry */
	LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY,
				     InInitializationOrderLinks);

	/* FIXME: Verify NX Compat */
	// LdrpCheckNXCompatibility()

	/* Next entry */
	NextEntry = NextEntry->Flink;
    }

    /* Check for TLS */
    if (LdrpImageHasTls && Context) {
	_SEH2_TRY {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_PROCESS_ATTACH);
	} _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	    /* Do nothing */
	}
    }

Quickie:

    /* Check if the array is in the heap */
    if (LdrRootEntry != LocalArray) {
	/* Free the array */
	RtlFreeHeap(LdrpHeap, 0, LdrRootEntry);
    }

    /* Return to caller */
    DPRINT("LdrpRunInitializeRoutines() done\n");
    return Status;
#endif
    return STATUS_SUCCESS;
}

/*
 * Allocate loader data table entry for given module and recursively walk its
 * import table to load all dependent DLLs, performing relocation if necessary.
 */
static NTSTATUS LdrpLoadRootModule(IN PVOID ImageBase,
				   IN PCSTR ImagePath,
				   IN PCSTR ImageName,
				   OUT OPTIONAL PLDR_DATA_TABLE_ENTRY *pEntry)
{
    /* Allocate a data entry for the Image */
    PLDR_DATA_TABLE_ENTRY Entry = LdrpAllocateDataTableEntry(ImageBase);

    /* Set it up */
    Entry->EntryPoint = LdrpFetchAddressOfEntryPoint(ImageBase);
    Entry->LoadCount = -1;
    Entry->EntryPointActivationContext = 0;
    RET_ERR(LdrpUtf8ToUnicodeString(ImagePath, &Entry->FullDllName));
    RET_ERR(LdrpUtf8ToUnicodeString(ImageName, &Entry->BaseDllName));

    /* Processing done, insert it */
    LdrpInsertMemoryTableEntry(Entry, ImageName);
    Entry->Flags |= LDRP_ENTRY_PROCESSED;

    /* Walk the IAT and load all the dependent DLLs */
    RET_ERR(LdrpWalkImportDescriptor(Entry));

    /* Check if relocation is needed */
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBase);
    if (!NtHeaders) {
	/* Invalid image. This should never happen. Assert in debug build. */
	assert(FALSE);
	return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (ImageBase != (PVOID) NtHeaders->OptionalHeader.ImageBase) {
	DPRINT1("LDR: Performing image relocation for image %s\n", ImagePath);
	/* Do the relocation */
	RET_ERR(LdrpRelocateImageWithBias(ImageBase,
					  0LL,
					  NULL,
					  STATUS_SUCCESS,
					  STATUS_CONFLICTING_ADDRESSES,
					  STATUS_INVALID_IMAGE_FORMAT));
    }

    if (pEntry != NULL) {
	*pEntry = Entry;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS LdrpInitializeProcess(PNTDLL_PROCESS_INIT_INFO InitInfo)
{
    /* Set a NULL SEH Filter */
    RtlSetUnhandledExceptionFilter(NULL);

    /* Set the critical section timeout from PEB */
    PPEB Peb = NtCurrentPeb();
    RtlpTimeout = Peb->CriticalSectionTimeout;

    /* Check if this is a .NET executable */
    ULONG ComSectionSize;
    if (RtlImageDirectoryEntryToData(Peb->ImageBaseAddress, TRUE,
				     IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
				     &ComSectionSize)) {
	DPRINT1("We don't support .NET applications yet\n");
	return STATUS_NOT_IMPLEMENTED;
    }

    /* Get the Image Config Directory */
    ULONG ConfigSize;
    PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfig = RtlImageDirectoryEntryToData(Peb->ImageBaseAddress, TRUE,
									   IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, &ConfigSize);

    /* Setup the Process Heap Parameters */
    RTL_HEAP_PARAMETERS ProcessHeapParams;    
    RtlZeroMemory(&ProcessHeapParams, sizeof(RTL_HEAP_PARAMETERS));
    ULONG ProcessHeapFlags = HEAP_GROWABLE;
    ProcessHeapParams.Length = sizeof(RTL_HEAP_PARAMETERS);

    /* Check if we have Configuration Data */
#define VALID_CONFIG_FIELD(Name) (ConfigSize >= (FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY, Name) + sizeof(LoadConfig->Name)))
    /* The 'original' load config ends after SecurityCookie */
    if ((LoadConfig) && ConfigSize && (VALID_CONFIG_FIELD(SecurityCookie) || ConfigSize == LoadConfig->Size)) {
	if (ConfigSize != sizeof(IMAGE_LOAD_CONFIG_DIRECTORY))
	    DPRINT1("WARN: Accepting different LOAD_CONFIG size!\n");
	else
	    DPRINT1("Applying LOAD_CONFIG\n");

	if (VALID_CONFIG_FIELD(GlobalFlagsSet) && LoadConfig->GlobalFlagsSet)
	    Peb->NtGlobalFlag |= LoadConfig->GlobalFlagsSet;

	if (VALID_CONFIG_FIELD(GlobalFlagsClear) && LoadConfig->GlobalFlagsClear)
	    Peb->NtGlobalFlag &= ~LoadConfig->GlobalFlagsClear;

	if (VALID_CONFIG_FIELD(CriticalSectionDefaultTimeout) && LoadConfig->CriticalSectionDefaultTimeout)
	    RtlpTimeout.QuadPart = Int32x32To64(LoadConfig->CriticalSectionDefaultTimeout, -10000000);

	if (VALID_CONFIG_FIELD(DeCommitFreeBlockThreshold) && LoadConfig->DeCommitFreeBlockThreshold)
	    ProcessHeapParams.DeCommitFreeBlockThreshold = LoadConfig->DeCommitFreeBlockThreshold;

	if (VALID_CONFIG_FIELD(DeCommitTotalFreeThreshold) && LoadConfig->DeCommitTotalFreeThreshold)
	    ProcessHeapParams.DeCommitTotalFreeThreshold = LoadConfig->DeCommitTotalFreeThreshold;

	if (VALID_CONFIG_FIELD(MaximumAllocationSize) && LoadConfig->MaximumAllocationSize)
	    ProcessHeapParams.MaximumAllocationSize = LoadConfig->MaximumAllocationSize;

	if (VALID_CONFIG_FIELD(VirtualMemoryThreshold) && LoadConfig->VirtualMemoryThreshold)
	    ProcessHeapParams.VirtualMemoryThreshold = LoadConfig->VirtualMemoryThreshold;

	if (VALID_CONFIG_FIELD(ProcessHeapFlags) && LoadConfig->ProcessHeapFlags)
	    ProcessHeapFlags = LoadConfig->ProcessHeapFlags;
    }

    /* Initialize Critical Section Data */
    LdrpInitCriticalSection(InitInfo->CriticalSectionLockSemaphore);

    /* Initialize VEH Call lists */
    RtlpInitializeVectoredExceptionHandling(InitInfo);

    /* Set TLS/FLS Bitmap data */
    Peb->FlsBitmap = &FlsBitMap;
    Peb->TlsBitmap = &TlsBitMap;
    Peb->TlsExpansionBitmap = &TlsExpansionBitMap;

    /* Initialize FLS Bitmap */
    RtlInitializeBitMap(&FlsBitMap, Peb->FlsBitmapBits, RTL_FLS_MAXIMUM_AVAILABLE);
    RtlSetBit(&FlsBitMap, 0);
    InitializeListHead(&Peb->FlsListHead);

    /* Initialize TLS Bitmap */
    RtlInitializeBitMap(&TlsBitMap, Peb->TlsBitmapBits, TLS_MINIMUM_AVAILABLE);
    RtlSetBit(&TlsBitMap, 0);
    RtlInitializeBitMap(&TlsExpansionBitMap, Peb->TlsExpansionBitmapBits, TLS_EXPANSION_SLOTS);
    RtlSetBit(&TlsExpansionBitMap, 0);

    /* Initialize the Hash Table */
    for (ULONG i = 0; i < LDRP_HASH_TABLE_ENTRIES; i++) {
        InitializeListHead(&LdrpHashTable[i]);
    }

    /* Initialize the Loader Lock. */
    RtlpInitializeCriticalSection(&LdrpLoaderLock, InitInfo->LoaderLockSemaphore, 0);
    Peb->LoaderLock = &LdrpLoaderLock;

    /* Check if User Stack Trace Database support was requested */
    if (Peb->NtGlobalFlag & FLG_USER_STACK_TRACE_DB) {
	DPRINT1("We don't support user stack trace databases yet\n");
    }

    /* Setup the Fast PEB Lock. */
    RtlpInitializeCriticalSection(&FastPebLock, InitInfo->FastPebLockSemaphore, 0);
    Peb->FastPebLock = &FastPebLock;

    /* Initialize NLS data */
    RtlInitNlsTables(Peb->AnsiCodePageData,
		     Peb->OemCodePageData,
		     Peb->UnicodeCaseTableData, &LdrpNlsTable);

    /* Reset NLS Translations */
    RtlResetRtlTranslations(&LdrpNlsTable);

    /* For old executables, use 16-byte aligned heap */
    PIMAGE_NT_HEADERS NtHeader = RtlImageNtHeader(Peb->ImageBaseAddress);
    if ((NtHeader->OptionalHeader.MajorSubsystemVersion <= 3) &&
	(NtHeader->OptionalHeader.MinorSubsystemVersion < 51)) {
	ProcessHeapFlags |= HEAP_CREATE_ALIGN_16;
    }

    /* Setup the process heap and the loader heap */
    RET_ERR(LdrpInitializeHeapManager(InitInfo, ProcessHeapFlags, &ProcessHeapParams));
    LdrpHeap = (HANDLE) InitInfo->LoaderHeapStart;

    /* Setup Loader Data */
    Peb->LdrData = &PebLdr;
    InitializeListHead(&PebLdr.InLoadOrderModuleList);
    InitializeListHead(&PebLdr.InMemoryOrderModuleList);
    InitializeListHead(&PebLdr.InInitializationOrderModuleList);
    PebLdr.Length = sizeof(PEB_LDR_DATA);
    PebLdr.Initialized = TRUE;

    /* Populate the Process Parameters structure */
    PLOADER_SHARED_DATA LdrSharedData = (PLOADER_SHARED_DATA) LOADER_SHARED_DATA_CLIENT_ADDR;
    PCSTR ImagePath = (PCSTR)(LOADER_SHARED_DATA_CLIENT_ADDR + LdrSharedData->ImagePath);
    PCSTR ImageName = (PCSTR)(LOADER_SHARED_DATA_CLIENT_ADDR + LdrSharedData->ImageName);
    PCSTR CommandLine = (PCSTR)(LOADER_SHARED_DATA_CLIENT_ADDR + LdrSharedData->CommandLine);
    Peb->ProcessParameters = RtlAllocateHeap(LdrpHeap, 0, sizeof(RTL_USER_PROCESS_PARAMETERS));
    if (Peb->ProcessParameters == NULL) {
	return STATUS_NO_MEMORY;
    }
    RET_ERR(LdrpUtf8ToUnicodeString(CommandLine, &Peb->ProcessParameters->CommandLine));
    Peb->ProcessParameters->Flags &= RTL_USER_PROCESS_PARAMETERS_NORMALIZED;

    RET_ERR(LdrpLoadRootModule(Peb->ImageBaseAddress, ImagePath, ImageName, &LdrpImageEntry));
    Peb->ProcessParameters->ImagePathName = LdrpImageEntry->FullDllName;

    /* Check whether server has injected dll modules that are not part of the
     * static dependencies of the image and load them. This is used for instance
     * when server loads a driver process and the driver image does not explicitly
     * specify hal.dll dependency. */
    PLOADER_SHARED_DATA LdrShared = (PLOADER_SHARED_DATA) LOADER_SHARED_DATA_CLIENT_ADDR;
    PLDRP_LOADED_MODULE Module = (PLDRP_LOADED_MODULE)(LOADER_SHARED_DATA_CLIENT_ADDR + LdrShared->LoadedModules);
    for (ULONG i = 0; i < LdrShared->LoadedModuleCount; i++) {
	PCSTR DllName = (PCSTR)(LOADER_SHARED_DATA_CLIENT_ADDR + Module->DllName);
	if (!LdrpCheckForLoadedDll(DllName, NULL)) {
	    PCSTR DllPath = (PCSTR)(LOADER_SHARED_DATA_CLIENT_ADDR + Module->DllPath);
	    RET_ERR(LdrpLoadRootModule((PVOID) Module->ViewBase, DllPath, DllName, NULL));
	}
	Module = (PLDRP_LOADED_MODULE)((MWORD)(Module) + Module->EntrySize);
    }

    if (!LdrpCheckForLoadedDll("ntdll.dll", &LdrpNtdllEntry)) {
	DbgTrace("Server should inject ntdll.dll to the loaded module list even if image does not explicitly depend on it. Exiting\n");
	return STATUS_INVALID_IMAGE_FORMAT;
    }
    assert(LdrpNtdllEntry != NULL);

    /* Initialize TLS */
    RET_ERR_EX(LdrpInitializeTls(),
	       DPRINT1("LDR: LdrpProcessInitialization failed to initialize TLS slots; status %x\n",
		       Status));

    /* Notify the debugger now */
    if (Peb->BeingDebugged) {
	/* Break */
	DbgBreakPoint();
    }

    /* Now call the Init Routines */
    RET_ERR_EX(LdrpRunInitializeRoutines(NULL /* TODO: FIXME Context */),
	       DPRINT1("LDR: LdrpProcessInitialization failed running initialization routines; status %x\n",
		       Status));

    /* Check if we have a user-defined Post Process Routine */
    if (Peb->PostProcessInitRoutine) {
	/* Call it */
	Peb->PostProcessInitRoutine();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LdrpInitializeThread()
{
    DPRINT("LdrpInitializeThread() called for %wZ (%p/%p)\n",
	   &LdrpImageEntry->BaseDllName,
	   NtCurrentTeb()->RealClientId.UniqueProcess,
	   NtCurrentTeb()->RealClientId.UniqueThread);

    /* Make sure we are not shutting down */
    if (LdrpShutdownInProgress)
	return STATUS_SUCCESS;

    /* Allocate the tls regions, except for NTDLL. For NTDLL we use
     * the server supplied region (already set up at this point) */
    RET_ERR(LdrpAllocateTls());

    /* For each DLL module (except the executable image), call the tls
     * initializer and the dll initialization routine */
    PPEB Peb = NtCurrentPeb();
    PLIST_ENTRY ListHead = &Peb->LdrData->InMemoryOrderModuleList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	/* Get the current entry */
	PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(NextEntry,
							   LDR_DATA_TABLE_ENTRY,
							   InMemoryOrderLinks);

	/* Make sure it's not the executable image itself */
	if (Peb->ImageBaseAddress != LdrEntry->DllBase) {
	    /* Check if we should call */
	    if (!(LdrEntry->Flags & LDRP_DONT_CALL_FOR_THREADS)) {
		/* Get the entrypoint */
		PVOID EntryPoint = LdrEntry->EntryPoint;

		/* Check if we are ready to call it */
		if ((EntryPoint) && (LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED) &&
		    (LdrEntry->Flags & LDRP_IMAGE_DLL)) {
		    _SEH2_TRY {
			/* Check if it has TLS */
			if (LdrEntry->TlsIndex) {
			    /* Make sure we're not shutting down */
			    if (!LdrpShutdownInProgress) {
				/* Call TLS */
				LdrpCallTlsInitializers(LdrEntry, DLL_THREAD_ATTACH);
			    }
			}

			/* Make sure we're not shutting down */
			if (!LdrpShutdownInProgress) {
			    /* Call the Entrypoint */
			    DPRINT("%wZ - Calling entry point at %p for thread attaching, %p/%p\n",
				   &LdrEntry->BaseDllName,
				   LdrEntry->EntryPoint,
				   NtCurrentTeb()->RealClientId.
				   UniqueProcess,
				   NtCurrentTeb()->RealClientId.
				   UniqueThread);
			    LdrpCallInitRoutine(LdrEntry->EntryPoint,
						LdrEntry->DllBase,
						DLL_THREAD_ATTACH, NULL);
			}
		    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
			DPRINT1("WARNING: Exception 0x%lx during LdrpCallInitRoutine(DLL_THREAD_ATTACH) for %wZ\n",
				_SEH2_GetExceptionCode(),
				&LdrEntry->BaseDllName);
		    }
		}
	    }
	}

	/* Next entry */
	NextEntry = NextEntry->Flink;
    }

    /* For the image module itself, call the tls initializer (if it has one) */
    if (LdrpImageHasTls && !LdrpShutdownInProgress) {
	_SEH2_TRY {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_THREAD_ATTACH);
	} _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	    /* Do nothing */
	}
    }

    DPRINT("LdrpInitializeThread() done\n");
    return STATUS_SUCCESS;
}

/*
 * On process startup, NTDLL_PROCESS_INIT_INFO is placed at the beginning
 * of IpcBuffer.
 */
FASTCALL VOID LdrpInitialize(IN seL4_IPCBuffer *IpcBuffer,
			     IN PPVOID SystemDllTlsRegion)
{
    _tls_index = SYSTEMDLL_TLS_INDEX;
    SystemDllTlsRegion[SYSTEMDLL_TLS_INDEX] = SystemDllTlsRegion;
    __sel4_ipc_buffer = IpcBuffer;

    PTEB Teb = NtCurrentTeb();
    PPEB Peb = NtCurrentPeb();

    DPRINT("LdrpInitialize() process %p thread %p\n",
	   NtCurrentTeb()->RealClientId.UniqueProcess,
	   NtCurrentTeb()->RealClientId.UniqueThread);

    /* Check if we have already setup LDR data */
    PVOID EntryPoint = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    if (!Peb->LdrData) {
	/* At process startup the process init info is placed at the beginning
	 * of the ipc buffer. */
	NTDLL_PROCESS_INIT_INFO InitInfo = *((PNTDLL_PROCESS_INIT_INFO)(IpcBuffer));
	/* Now that the init info has been copied to the stack, clear the original. */
	memset(IpcBuffer, 0, sizeof(NTDLL_PROCESS_INIT_INFO));

	/* Set the per-thread variable for the system service endpoint capability */
	KiSystemServiceCap = InitInfo.ThreadInitInfo.SystemServiceCap;

	/* Initialize the Process */
	Status = LdrpInitializeProcess(&InitInfo);

	if (InitInfo.DriverProcess) {
	    PLDR_DATA_TABLE_ENTRY HalDllEntry = NULL;
	    LdrpCheckForLoadedDll("hal.dll", &HalDllEntry);
	    if (HalDllEntry == NULL) {
		/* This should never happen. Assert in debug build. */
		assert(FALSE);
		DbgTrace("Fatal error: driver process does not have hal.dll loaded.\n");
		Status = STATUS_ENTRYPOINT_NOT_FOUND;
	    } else {
		EntryPoint = HalDllEntry->EntryPoint;
		((PHAL_START_ROUTINE)HalDllEntry->EntryPoint)(IpcBuffer,
							      InitInfo.ThreadInitInfo.HalServiceCap,
							      &InitInfo.DriverInitInfo);
	    }
	} else {
	    /* Calls the image entry point */
	    EntryPoint = LdrpImageEntry->EntryPoint;
	    ((PTHREAD_START_ROUTINE)LdrpImageEntry->EntryPoint)(Peb);
	}
    } else if (Peb->InheritedAddressSpace) {
	/* Loader data is there... is this a fork() ? */
	/* Handle the fork() */
	//LoaderStatus = LdrpForkProcess();
	Status = STATUS_NOT_IMPLEMENTED;
	UNIMPLEMENTED;
    } else {
	/* At process startup the process init info is placed at the beginning
	 * of the ipc buffer. */
	NTDLL_THREAD_INIT_INFO InitInfo = *((PNTDLL_THREAD_INIT_INFO)(IpcBuffer));
	/* Now that the init info has been copied to the stack, clear the original. */
	memset(IpcBuffer, 0, sizeof(NTDLL_THREAD_INIT_INFO));

	/* Set the per-thread variable for the system service endpoint capability */
	KiSystemServiceCap = InitInfo.SystemServiceCap;

	/* This is a new thread initializing */
	Status = LdrpInitializeThread();
	/* TODO: Call thread entry point */
	/* EntryPoint = ...; */
    }

    /* Bail out if initialization has failed */
    if (!NT_SUCCESS(Status)) {
	HARDERROR_RESPONSE Response;

	/* Print a debug message */
	DPRINT1("LDR: Initialization failure for process %p thread %p. Image is %wZ; NTSTATUS = %08x\n",
		NtCurrentTeb()->RealClientId.UniqueProcess,
		NtCurrentTeb()->RealClientId.UniqueThread,
		&Peb->ProcessParameters->ImagePathName, Status);

	/* Send HARDERROR_MSG LPC message to CSRSS */
	NtRaiseHardError(STATUS_APP_INIT_FAILURE, 1, 0,
			 (PULONG_PTR) &Status, OptionOk, &Response);

	/* Raise a status to terminate the thread. */
	RtlRaiseStatus(Status);
    }

    /* The thread entry point should never return. Shutdown the thread if it does. */
    DPRINT1("LDR: Thread entry point %p returned for thread %p of process %p, shutting down thread\n",
	    EntryPoint, NtCurrentTeb()->RealClientId.UniqueThread,
	    NtCurrentTeb()->RealClientId.UniqueProcess);
    RtlExitUserThread(STATUS_UNSUCCESSFUL);
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrShutdownProcess(VOID)
{
#if 0
    PPEB Peb = NtCurrentPeb();
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PLIST_ENTRY NextEntry, ListHead;
    PVOID EntryPoint;

    DPRINT("LdrShutdownProcess() called for %wZ\n", &LdrpImageEntry->BaseDllName);
    if (LdrpShutdownInProgress)
	return STATUS_SUCCESS;

    /* Set the shutdown variables */
    LdrpShutdownThreadId = NtCurrentTeb()->RealClientId.UniqueThread;
    LdrpShutdownInProgress = TRUE;

    /* Enter the Loader Lock */
    RtlEnterCriticalSection(&LdrpLoaderLock);

    /* Cleanup trace logging data (Etw) */
    if (SharedUserData->TraceLogging) {
	/* FIXME */
	DPRINT1("We don't support Etw yet.\n");
    }

    /* Start at the end */
    ListHead = &Peb->LdrData->InInitializationOrderModuleList;
    NextEntry = ListHead->Blink;
    while (NextEntry != ListHead) {
	/* Get the current entry */
	LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY,
				     InInitializationOrderLinks);
	NextEntry = NextEntry->Blink;

	/* Make sure it's not ourselves */
	if (Peb->ImageBaseAddress != LdrEntry->DllBase) {
	    /* Get the entrypoint */
	    EntryPoint = LdrEntry->EntryPoint;

	    /* Check if we are ready to call it */
	    if (EntryPoint && (LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED) && LdrEntry->Flags) {
		_SEH2_TRY {
		    /* Check if it has TLS */
		    if (LdrEntry->TlsIndex) {
			/* Call TLS */
			LdrpCallTlsInitializers(LdrEntry,
						DLL_PROCESS_DETACH);
		    }

		    /* Call the Entrypoint */
		    DPRINT("%wZ - Calling entry point at %p for thread detaching\n",
			   &LdrEntry->BaseDllName, LdrEntry->EntryPoint);
		    LdrpCallInitRoutine(EntryPoint, LdrEntry->DllBase,
					DLL_PROCESS_DETACH, (PVOID) 1);
		} _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
		    DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_PROCESS_DETACH) for %wZ\n",
			    _SEH2_GetExceptionCode(), &LdrEntry->BaseDllName);
		}
	    }
	}
    }

    /* Check for TLS */
    if (LdrpImageHasTls) {
	_SEH2_TRY {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_PROCESS_DETACH);
	} _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	    /* Do nothing */
	}
    }

    /* FIXME: Do Heap detection and Etw final shutdown */

    /* Release the lock */
    RtlLeaveCriticalSection(&LdrpLoaderLock);
    DPRINT("LdrpShutdownProcess() done\n");
#endif
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrShutdownThread(VOID)
{
#if 0
    PPEB Peb = NtCurrentPeb();
    PTEB Teb = NtCurrentTeb();
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PLIST_ENTRY NextEntry, ListHead;
    PVOID EntryPoint;

    DPRINT("LdrShutdownThread() called for %wZ\n", &LdrpImageEntry->BaseDllName);

    /* Cleanup trace logging data (Etw) */
    if (SharedUserData->TraceLogging) {
	/* FIXME */
	DPRINT1("We don't support Etw yet.\n");
    }

    /* Get the Ldr Lock */
    RtlEnterCriticalSection(&LdrpLoaderLock);

    /* Start at the end */
    ListHead = &Peb->LdrData->InInitializationOrderModuleList;
    NextEntry = ListHead->Blink;
    while (NextEntry != ListHead) {
	/* Get the current entry */
	LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY,
				     InInitializationOrderLinks);
	NextEntry = NextEntry->Blink;

	/* Make sure it's not ourselves */
	if (Peb->ImageBaseAddress != LdrEntry->DllBase) {
	    /* Check if we should call */
	    if (!(LdrEntry->Flags & LDRP_DONT_CALL_FOR_THREADS) &&
		(LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED) &&
		(LdrEntry->Flags & LDRP_IMAGE_DLL)) {
		/* Get the entrypoint */
		EntryPoint = LdrEntry->EntryPoint;

		/* Check if we are ready to call it */
		if (EntryPoint) {
		    _SEH2_TRY {
			/* Check if it has TLS */
			if (LdrEntry->TlsIndex) {
			    /* Make sure we're not shutting down */
			    if (!LdrpShutdownInProgress) {
				/* Call TLS */
				LdrpCallTlsInitializers(LdrEntry, DLL_THREAD_DETACH);
			    }
			}

			/* Make sure we're not shutting down */
			if (!LdrpShutdownInProgress) {
			    /* Call the Entrypoint */
			    DPRINT("%wZ - Calling entry point at %p for thread detaching\n",
				   &LdrEntry->BaseDllName,
				   LdrEntry->EntryPoint);
			    LdrpCallInitRoutine(EntryPoint,
						LdrEntry->DllBase,
						DLL_THREAD_DETACH, NULL);
			}
		    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
			DPRINT1("WARNING: Exception 0x%x during LdrpCallInitRoutine(DLL_THREAD_DETACH) for %wZ\n",
				_SEH2_GetExceptionCode(),
				&LdrEntry->BaseDllName);
		    }
		}
	    }
	}
    }

    /* Check for TLS */
    if (LdrpImageHasTls) {
	_SEH2_TRY {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_THREAD_DETACH);
	} _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
	    /* Do nothing */
	}
    }

    /* Free TLS */
    LdrpFreeTls();
    RtlLeaveCriticalSection(&LdrpLoaderLock);

    /* Check for expansion slots */
    if (Teb->TlsExpansionSlots) {
	/* Free expansion slots */
	RtlFreeHeap(RtlGetProcessHeap(), 0, Teb->TlsExpansionSlots);
    }

    /* Check for FLS Data */
    if (Teb->FlsData) {
	/* Mimic BaseRundownFls */
	ULONG n, FlsHighIndex;
	PRTL_FLS_DATA pFlsData;
	PFLS_CALLBACK_FUNCTION lpCallback;

	pFlsData = Teb->FlsData;

	RtlAcquirePebLock();
	FlsHighIndex = NtCurrentPeb()->FlsHighIndex;
	RemoveEntryList(&pFlsData->ListEntry);
	RtlReleasePebLock();

	for (n = 1; n <= FlsHighIndex; ++n) {
	    lpCallback = NtCurrentPeb()->FlsCallback[n];
	    if (lpCallback && pFlsData->Data[n]) {
		lpCallback(pFlsData->Data[n]);
	    }
	}

	RtlFreeHeap(RtlGetProcessHeap(), 0, pFlsData);
	Teb->FlsData = NULL;
    }

    /* Check for Fiber data */
    if (Teb->HasFiberData) {
	/* Free Fiber data */
	RtlFreeHeap(RtlGetProcessHeap(), 0, Teb->NtTib.FiberData);
	Teb->NtTib.FiberData = NULL;
    }

    DPRINT("LdrShutdownThread() done\n");
#endif
    return STATUS_SUCCESS;
}
