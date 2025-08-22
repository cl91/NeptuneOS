#include "ldrp.h"

/* TLS ***********************************************************************/

typedef struct _LDRP_TLS_DATA {
    LIST_ENTRY TlsLinks;
    IMAGE_TLS_DIRECTORY TlsDirectory;
} LDRP_TLS_DATA, *PLDRP_TLS_DATA;

/* GLOBALS *******************************************************************/

CHAR RtlpDbgTraceModuleNameBuffer[128] = "NTDLL";
PCSTR RtlpDbgTraceModuleName = RtlpDbgTraceModuleNameBuffer;

BOOLEAN LdrpInLdrInit = TRUE;
BOOLEAN LdrpShutdownInProgress;
BOOLEAN LdrpDriverProcess;
HANDLE LdrpShutdownThreadId;

LIST_ENTRY LdrpHashTable[LDRP_HASH_TABLE_ENTRIES];
PLDR_DATA_TABLE_ENTRY LdrpImageEntry;
PLDR_DATA_TABLE_ENTRY LdrpNtdllEntry;

RTL_BITMAP TlsBitMap;
RTL_BITMAP TlsExpansionBitMap;
RTL_BITMAP FlsBitMap;
BOOLEAN LdrpImageHasTls;
LIST_ENTRY LdrpTlsList;
ULONG LdrpNumberOfTlsEntries;

extern LARGE_INTEGER RtlpTimeout;
PVOID LdrpHeap;

PEB_LDR_DATA PebLdr;
static PPEB Peb;

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
 * Loop the tls list and allocate the tls data for each module
 */
static NTSTATUS LdrpAllocateTls()
{
    /* If we don't have any static TLS variables in any module, exit. */
    if (!LdrpNumberOfTlsEntries)
        return STATUS_SUCCESS;

    /* Allocate the TLS vector */
    PPVOID TlsVector = RtlAllocateHeap(RtlGetProcessHeap(), 0,
				       LdrpNumberOfTlsEntries * sizeof(PVOID));
    if (!TlsVector) {
	return STATUS_NO_MEMORY;
    }
    NtCurrentTeb()->ThreadLocalStoragePointer = TlsVector;
    PLIST_ENTRY ListHead = &LdrpTlsList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	/* Get the entry */
	PLDRP_TLS_DATA TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks);
	NextEntry = NextEntry->Flink;

	/* Allocate this vector */
	SIZE_T TlsDataSize = TlsData->TlsDirectory.EndAddressOfRawData -
	    TlsData->TlsDirectory.StartAddressOfRawData;
	TlsVector[TlsData->TlsDirectory.Characteristics] =
	    RtlAllocateHeap(RtlGetProcessHeap(), 0, TlsDataSize);
	if (!TlsVector[TlsData->TlsDirectory.Characteristics]) {
	    /* Out of memory */
	    return STATUS_NO_MEMORY;
	}

	DPRINT1("LDR: TlsData of size 0x%zx is copied from %p to %p "
		"(TlsIndex %u = %p, TlsVector = %p)\n",
		TlsDataSize, (PVOID)TlsData->TlsDirectory.StartAddressOfRawData,
		TlsVector[TlsData->TlsDirectory.Characteristics],
		TlsData->TlsDirectory.Characteristics,
		&TlsVector[TlsData->TlsDirectory.Characteristics], TlsVector);

	RtlCopyMemory(TlsVector[TlsData->TlsDirectory.Characteristics],
		      (PVOID)TlsData->TlsDirectory.StartAddressOfRawData,
		      TlsDataSize);
    }

    return STATUS_SUCCESS;
}

static VOID LdrpFreeTls()
{
    PPVOID TlsVector = NtCurrentTeb()->ThreadLocalStoragePointer;
    /* Loop through the TLS list and free all entries */
    PLIST_ENTRY ListHead = &LdrpTlsList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    while (NextEntry != ListHead) {
	PLDRP_TLS_DATA TlsData = CONTAINING_RECORD(NextEntry, LDRP_TLS_DATA, TlsLinks);
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

    /* Loop all the modules. This will start from the executable image. */
    PLIST_ENTRY ListHead = &Peb->LdrData->InLoadOrderModuleList;
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
	PIMAGE_TLS_DIRECTORY TlsDirectory =
	    RtlImageDirectoryEntryToData(LdrEntry->DllBase, TRUE,
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
	PLDRP_TLS_DATA TlsData = (PLDRP_TLS_DATA)RtlAllocateHeap(RtlGetProcessHeap(), 0,
								 sizeof(LDRP_TLS_DATA));
	if (!TlsData)
	    return STATUS_NO_MEMORY;

	/* Set the load count to -1 to mark the module as pinned in memory
	 * for the lifetime of the process */
	LdrEntry->LoadCount = -1;

	/* Save the cached TLS data */
	TlsData->TlsDirectory = *TlsDirectory;
	InsertTailList(&LdrpTlsList, &TlsData->TlsLinks);

	/* Update the TLS index. Since we start the loop with the executable
	 * image, it will have TLS index zero. */
	ULONG TlsIndex = LdrpNumberOfTlsEntries++;
	*(PLONG)TlsData->TlsDirectory.AddressOfIndex = TlsIndex;
	TlsData->TlsDirectory.Characteristics = TlsIndex;

	/* For some stupid reason the TlsIndex member in the loader
	 * TLS entry is always set to -1 in the M$ implementation.
	 * We follow the WINE implementation which correctly sets
	 * this member. See http://www.nynaeve.net/?p=186 */
	LdrEntry->TlsIndex = TlsIndex;
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
    ConfigDir = RtlImageDirectoryEntryToData(BaseAddress, TRUE,
					     IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
					     &DirSize);

    /* Check for sanity */
    if (!ConfigDir || (DirSize != 64 && ConfigDir->Size != DirSize) ||
	(ConfigDir->Size < 0x48))
	return NULL;

    /* Now get the cookie */
    Cookie = (PVOID)ConfigDir->SecurityCookie;

    /* Check this cookie */
    if ((PCHAR)Cookie <= (PCHAR)BaseAddress ||
	(PCHAR)Cookie >= (PCHAR)BaseAddress + SizeOfImage) {
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
	    NewCookie ^= (ULONG_PTR)NtCurrentTib()->ClientId.UniqueProcess;
	    NewCookie ^= (ULONG_PTR)NtCurrentTib()->ClientId.UniqueThread;

	    /* Loop till the SystemTime is fully updated. */
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

	    /* If the result is 0 or the same as we got, just subtract one from
	     * the existing value and that's it */
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
    __try {
	/* Make sure it's valid */
	if (TlsDirectory) {
	    /* Get the array */
	    Array = (PIMAGE_TLS_CALLBACK *)TlsDirectory->AddressOfCallBacks;
	    if (Array) {
		DPRINT1("LDR: Tls Callbacks Found. Imagebase %p Tls %p CallBacks %p\n",
			LdrEntry->DllBase, TlsDirectory, Array);

		/* Loop over the array */
		while (*Array) {
		    /* Get the TLS Entrypoint */
		    Callback = *Array++;

		    DPRINT1("LDR: Calling Tls Callback Imagebase %p Function %p\n",
			    LdrEntry->DllBase, Callback);

		    LdrpCallInitRoutine((PDLL_INIT_ROUTINE)Callback,
					LdrEntry->DllBase, Reason, NULL);
		}
	    }
	}
    } __except(EXCEPTION_EXECUTE_HANDLER) {
	DPRINT1("LDR: Exception 0x%lx during Tls Callback(%u) for %wZ\n",
		GetExceptionCode(), Reason, &LdrEntry->BaseDllName);
    }
}

static ULONG LdrpGetInitializationModuleCount(VOID)
{
    ULONG ModulesCount = 0;
    /* Traverse the init list */
    PLIST_ENTRY ListHead = &Peb->LdrData->InInitializationOrderModuleList;
    PLIST_ENTRY Entry = ListHead->Flink;
    while (Entry != ListHead) {
	/* Get the loader entry */
	PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY,
							   InInitializationOrderLinks);

	/* Check for modules with entry point count but not processed yet */
	if (LdrEntry->EntryPoint && !(LdrEntry->Flags & LDRP_ENTRY_PROCESSED)) {
	    /* Increase counter */
	    ModulesCount++;
	}

	/* Advance to the next entry */
	Entry = Entry->Flink;
    }

    /* Return final count */
    return ModulesCount;
}

static NTSTATUS LdrpRunInitializeRoutines(IN PCONTEXT Context OPTIONAL)
{
    DPRINT("LdrpRunInitializeRoutines() called for %wZ (%p/%p)\n",
	   &LdrpImageEntry->BaseDllName,
	   NtCurrentTib()->ClientId.UniqueProcess,
	   NtCurrentTib()->ClientId.UniqueThread);

    /* Loop in initialization order */
    PLIST_ENTRY ListHead = &Peb->LdrData->InInitializationOrderModuleList;
    PLIST_ENTRY NextEntry = ListHead->Flink;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    while (NextEntry != ListHead) {
	/* Get the Data Entry */
	LdrEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY,
				     InInitializationOrderLinks);

	/* Check flags */
	if (!(LdrEntry->Flags & LDRP_ENTRY_PROCESSED)) {
	    /* Setup the Cookie for the DLL */
	    LdrpInitSecurityCookie(LdrEntry);

	    /* Are we being debugged? */
	    ULONG BreakOnDllLoad = 0;
	    if (Peb->BeingDebugged || Peb->ReadImageFileExecOptions) {
		/* Check if we should break on load */
		if (!NT_SUCCESS(LdrQueryImageFileExecutionOptions(&LdrEntry->BaseDllName,
								  L"BreakOnDllLoad",
								  REG_DWORD,
								  &BreakOnDllLoad,
								  sizeof(ULONG),
								  NULL))) {
		    BreakOnDllLoad = 0;
		}
	    }

	    /* Break if aksed */
	    if (BreakOnDllLoad) {
		/* Check if we should show a message */
		DPRINT1("LDR: %wZ loaded.", &LdrEntry->BaseDllName);
		DPRINT1(" - About to call init routine at %p\n", LdrEntry->EntryPoint);

		/* Break in debugger */
		DbgBreakPoint();
	    }

	    /* Check for valid entrypoint */
	    if (LdrEntry->EntryPoint) {
		DPRINT1("[%p,%p] LDR: %wZ init routine %p\n",
			NtCurrentTib()->ClientId.UniqueThread,
			NtCurrentTib()->ClientId.UniqueProcess,
			&LdrEntry->FullDllName, LdrEntry->EntryPoint);

		BOOLEAN DllStatus;
		__try {
		    /* Check if it has TLS */
		    if (LdrEntry->TlsIndex && Context) {
			/* Call TLS */
			LdrpCallTlsInitializers(LdrEntry, DLL_PROCESS_ATTACH);
		    }

		    /* Call the Entrypoint */
		    DPRINT1("%wZ - Calling entry point at %p for DLL_PROCESS_ATTACH\n",
			    &LdrEntry->BaseDllName, LdrEntry->EntryPoint);
		    DllStatus = LdrpCallInitRoutine(LdrEntry->EntryPoint,
						    LdrEntry->DllBase,
						    DLL_PROCESS_ATTACH,
						    Context);
		} __except(EXCEPTION_EXECUTE_HANDLER) {
		    DllStatus = FALSE;
		    DPRINT1("WARNING: Exception 0x%lx during "
			    "LdrpCallInitRoutine(DLL_PROCESS_ATTACH) for %wZ\n",
			    GetExceptionCode(), &LdrEntry->BaseDllName);
		}

		/* Mark the entry as processed */
		LdrEntry->Flags |= LDRP_PROCESS_ATTACH_CALLED;

		/* Fail if DLL init failed */
		if (!DllStatus) {
		    DPRINT1("LDR: DLL_PROCESS_ATTACH for dll "
			    "\"%wZ\" (InitRoutine: %p) failed\n",
			    &LdrEntry->BaseDllName, LdrEntry->EntryPoint);
		    return STATUS_DLL_INIT_FAILED;
		}
	    }
	}

	/* Set the flag to indicate that the entry has been processed */
	LdrEntry->Flags |= LDRP_ENTRY_PROCESSED;
	NextEntry = NextEntry->Flink;
    }

    /* Check for TLS */
    if (LdrpImageHasTls && Context) {
	__try {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_PROCESS_ATTACH);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    /* Do nothing */
	}
    }

    return STATUS_SUCCESS;
}

/* Scan the FullDllName and find the base file name. */
static VOID LdrpSetBaseDllName(IN PUNICODE_STRING FullDllName,
			       OUT PUNICODE_STRING BaseDllName)
{
    ULONG BaseNameStart = 0;
    for (ULONG i = 0; i < FullDllName->Length / sizeof(WCHAR); i++) {
	if (FullDllName->Buffer[i] == '\\') {
	    BaseNameStart = i+1;
	}
    }
    BaseDllName->Buffer = &FullDllName->Buffer[BaseNameStart];
    BaseDllName->Length = FullDllName->Length - BaseNameStart * sizeof(WCHAR);
    BaseDllName->MaximumLength = BaseDllName->Length;
}

static NTSTATUS LdrpInitializeProcess(PNTDLL_PROCESS_INIT_INFO InitInfo)
{
    LdrpDriverProcess = InitInfo->DriverProcess;

    /* Set up the image base address in the process environment block. */
    Peb->ImageBaseAddress = (HMODULE)InitInfo->ImageBase;

    /* Place the process heap book keeping structures immediately after the PEB */
    ULONG PebSize = ALIGN_UP(sizeof(PEB), PVOID);
    Peb->MaximumNumberOfHeaps = (PAGE_SIZE - PebSize) / sizeof(PVOID);
    Peb->ProcessHeaps = (PPVOID)((PCHAR)Peb + PebSize);

    /* Set a NULL SEH Filter */
    RtlSetUnhandledExceptionFilter(NULL);

    /* Set the critical section timeout from PEB */
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
    PIMAGE_LOAD_CONFIG_DIRECTORY LoadConfig =
	RtlImageDirectoryEntryToData(Peb->ImageBaseAddress, TRUE,
				     IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
				     &ConfigSize);

    /* Setup the Process Heap Parameters */
    RTL_HEAP_PARAMETERS ProcessHeapParams;
    RtlZeroMemory(&ProcessHeapParams, sizeof(RTL_HEAP_PARAMETERS));
    ULONG ProcessHeapFlags = HEAP_GROWABLE;
    ProcessHeapParams.Length = sizeof(RTL_HEAP_PARAMETERS);

    /* Check if we have Configuration Data */
#define VALID_CONFIG_FIELD(Name)					\
    (ConfigSize >= (FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY, Name) + sizeof(LoadConfig->Name)))
    /* The 'original' load config ends after SecurityCookie */
    if ((LoadConfig) && ConfigSize &&
	(VALID_CONFIG_FIELD(SecurityCookie) || ConfigSize == LoadConfig->Size)) {
	if (ConfigSize != sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)) {
	    DPRINT1("WARN: Accepting different LOAD_CONFIG size!\n");
	} else {
	    DPRINT1("Applying LOAD_CONFIG\n");
	}

	if (VALID_CONFIG_FIELD(GlobalFlagsSet) && LoadConfig->GlobalFlagsSet)
	    Peb->NtGlobalFlag |= LoadConfig->GlobalFlagsSet;

	if (VALID_CONFIG_FIELD(GlobalFlagsClear) && LoadConfig->GlobalFlagsClear)
	    Peb->NtGlobalFlag &= ~LoadConfig->GlobalFlagsClear;

	if (VALID_CONFIG_FIELD(CriticalSectionDefaultTimeout)
	    && LoadConfig->CriticalSectionDefaultTimeout)
	    RtlpTimeout.QuadPart = Int32x32To64(LoadConfig->CriticalSectionDefaultTimeout,
						-10000000);

	if (VALID_CONFIG_FIELD(DeCommitFreeBlockThreshold)
	    && LoadConfig->DeCommitFreeBlockThreshold)
	    ProcessHeapParams.DeCommitFreeBlockThreshold = LoadConfig->DeCommitFreeBlockThreshold;

	if (VALID_CONFIG_FIELD(DeCommitTotalFreeThreshold)
	    && LoadConfig->DeCommitTotalFreeThreshold)
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
    RtlInitializeBitMap(&TlsExpansionBitMap,
			Peb->TlsExpansionBitmapBits, TLS_EXPANSION_SLOTS);
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

    /* Initialize the unicode case tables */
    RtlResetRtlTranslations(NULL);

    /* Setup the process heap and the loader heap */
    RET_ERR(LdrpInitializeHeapManager(InitInfo, ProcessHeapFlags, &ProcessHeapParams));
    LdrpHeap = (HANDLE)InitInfo->LoaderHeapStart;

    /* Set the IopDbgTraceModuleName to the image base name */
    ULONG ImageNameLength = strlen(InitInfo->ImageName);
    ImageNameLength = min(ImageNameLength, sizeof(RtlpDbgTraceModuleNameBuffer) - 2);
    memcpy(RtlpDbgTraceModuleNameBuffer, InitInfo->ImageName, ImageNameLength+1);

    /* If the parent process (or whoever created us) has set the Process Parameters
     * structure, it will be in denormalized form (where pointers are replaced with
     * offsets). In this case we should normalize the process parameters. If it
     * is not set, allocate one and populate a minimal set of information using
     * the data supplied by the server. The latter case mostly applies to smss.exe
     * and the driver processes started by the server, and these don't really use
     * much of the Process Parameters. */
    if (Peb->ProcessParameters) {
	RtlNormalizeProcessParams(Peb->ProcessParameters);
    } else {
	Peb->ProcessParameters = RtlAllocateHeap(LdrpHeap, HEAP_ZERO_MEMORY,
						 sizeof(RTL_USER_PROCESS_PARAMETERS));
	if (!Peb->ProcessParameters) {
	    return STATUS_NO_MEMORY;
	}
	Peb->ProcessParameters->MaximumLength = sizeof(RTL_USER_PROCESS_PARAMETERS);
	Peb->ProcessParameters->Flags &= RTL_USER_PROCESS_PARAMETERS_NORMALIZED;
	DPRINT("Populating process parameters\n");
	RET_ERR(LdrpUtf8ToUnicodeString(InitInfo->ImageName,
					&Peb->ProcessParameters->ImagePathName));
	/* For drivers, CommandLine is actually the driver registry path. */
	if (InitInfo->DriverProcess) {
	    RET_ERR(LdrpUtf8ToUnicodeString(InitInfo->DriverInitInfo.ServicePath,
					    &Peb->ProcessParameters->CommandLine));
	}
    }

    /* If the the process parameters did not specify a current directory, use the
     * system root. */
    if (!Peb->ProcessParameters->CurrentDirectory.DosPath.Buffer) {
	ULONG BufferSize = MAX_PATH * sizeof(WCHAR);
	PWCHAR Buffer = RtlAllocateHeap(LdrpHeap, HEAP_ZERO_MEMORY, BufferSize);
	if (!Buffer) {
	    return STATUS_INSUFFICIENT_RESOURCES;
	}
	Peb->ProcessParameters->CurrentDirectory.DosPath.Buffer = Buffer;
	Peb->ProcessParameters->CurrentDirectory.DosPath.Length = 0;
	Peb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength = BufferSize;
    }
    if (!Peb->ProcessParameters->CurrentDirectory.DosPath.Length ||
	Peb->ProcessParameters->CurrentDirectory.DosPath.Buffer[0] == L'\0') {
	ULONG PathLen = wcslen(SharedUserData->NtSystemRoot) * sizeof(WCHAR);
	ULONG MaxLen = Peb->ProcessParameters->CurrentDirectory.DosPath.MaximumLength;
	RtlCopyMemory(Peb->ProcessParameters->CurrentDirectory.DosPath.Buffer,
		      SharedUserData->NtSystemRoot,
		      min(PathLen + sizeof(WCHAR), MaxLen));
	Peb->ProcessParameters->CurrentDirectory.DosPath.Length = min(PathLen, MaxLen);
    }
    DbgTrace("%ws\n", SharedUserData->NtSystemRoot);
    RET_ERR(RtlSetCurrentDirectory_U(&Peb->ProcessParameters->CurrentDirectory.DosPath));

    /* Setup Loader Data */
    Peb->LdrData = &PebLdr;
    InitializeListHead(&PebLdr.InLoadOrderModuleList);
    InitializeListHead(&PebLdr.InMemoryOrderModuleList);
    InitializeListHead(&PebLdr.InInitializationOrderModuleList);
    PebLdr.Length = sizeof(PEB_LDR_DATA);
    PebLdr.Initialized = TRUE;

    /* Allocate a loader database entry for the image itself, set it up,
     * and insert it into the loader database. */
    PVOID ImageBase = Peb->ImageBaseAddress;
    LdrpImageEntry = LdrpAllocateDataTableEntry(ImageBase);
    if (!LdrpImageEntry) {
	return STATUS_NO_MEMORY;
    }
    LdrpImageEntry->EntryPoint = LdrpFetchAddressOfEntryPoint(ImageBase);
    LdrpImageEntry->LoadCount = -1;
    LdrpImageEntry->EntryPointActivationContext = 0;
    LdrpImageEntry->FullDllName = Peb->ProcessParameters->ImagePathName;
    RET_ERR(LdrpUtf8ToUnicodeString(InitInfo->ImageName,
				    &LdrpImageEntry->BaseDllName));
    LdrpInsertMemoryTableEntry(LdrpImageEntry, InitInfo->ImageName);
    LdrpImageEntry->Flags |= LDRP_ENTRY_PROCESSED;
    InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
                   &LdrpImageEntry->InInitializationOrderLinks);

    /* Now do the same for NTDLL */
    LdrpNtdllEntry = LdrpAllocateDataTableEntry((PVOID)InitInfo->NtdllViewBase);
    if (!LdrpNtdllEntry) {
	return STATUS_NO_MEMORY;
    }
    LdrpNtdllEntry->Flags = LDRP_IMAGE_DLL;
    LdrpNtdllEntry->EntryPoint = NULL;
    LdrpNtdllEntry->LoadCount = -1;
    LdrpNtdllEntry->EntryPointActivationContext = 0;
    RET_ERR(LdrpUtf8ToUnicodeString(InitInfo->NtdllPath,
				    &LdrpNtdllEntry->FullDllName));
    LdrpSetBaseDllName(&LdrpNtdllEntry->FullDllName, &LdrpNtdllEntry->BaseDllName);
    LdrpInsertMemoryTableEntry(LdrpNtdllEntry, "ntdll.dll");
    InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
                   &LdrpNtdllEntry->InInitializationOrderLinks);

    /* Let the world know */
    DPRINT1("LDR: NEW PROCESS\n");
    DPRINT1("     Image Path: %wZ (%wZ)\n",
	    &LdrpImageEntry->FullDllName, &LdrpImageEntry->BaseDllName);
    DPRINT1("     Current Directory: %wZ\n",
	    &Peb->ProcessParameters->CurrentDirectory.DosPath);
    DPRINT1("     Search Path: %wZ\n",
	    &Peb->ProcessParameters->DllPath);

    /* If we are a driver process, load the wdm.dll first */
    if (InitInfo->DriverProcess) {
	PLDR_DATA_TABLE_ENTRY WdmDllEntry = NULL;
	RET_ERR(LdrpLoadImportModule("wdm.dll", &WdmDllEntry, NULL));
	assert(WdmDllEntry);
	WdmDllEntry->LoadCount++;
	InsertTailList(&Peb->LdrData->InInitializationOrderModuleList,
		       &WdmDllEntry->InInitializationOrderLinks);
    }

    /* Walk the import table of the image and load all dependent DLLs, performing
     * relocation if necessary. This is recursive until all dependent DLLs are
     * loaded, including all the indirect dependencies. */
    RET_ERR(LdrpWalkImportDescriptor(LdrpImageEntry));

    /* Check if the image itself needs relocation (usually not) and do the
     * relocation if needed. */
    PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBase);
    if (!NtHeaders) {
	/* Invalid image. This should never happen. Assert in debug build. */
	assert(FALSE);
	return STATUS_INVALID_IMAGE_FORMAT;
    }
    if (ImageBase != (PVOID)NtHeaders->OptionalHeader.ImageBase) {
	DPRINT1("LDR: Performing image relocation for image %wZ\n",
		&Peb->ProcessParameters->ImagePathName);
	RET_ERR(LdrpRelocateImageWithBias(ImageBase, 0LL, NULL,
					  STATUS_SUCCESS,
					  STATUS_CONFLICTING_ADDRESSES,
					  STATUS_INVALID_IMAGE_FORMAT));
    }

    /* Initialize TLS */
    RET_ERR_EX(LdrpInitializeTls(),
	       DPRINT1("LDR: failed to initialize TLS slots, error 0x%x\n", Status));

    /* Notify the debugger if we are being debugged. */
    if (Peb->BeingDebugged) {
	DbgBreakPoint();
    }

    if (!InitInfo->DriverProcess) {
	/* Now call the Init Routines (DllMain, TLS callbacks), unless we
	 * are a driver process. Driver processes do not load regular DLLs. */
	RET_ERR_EX(LdrpRunInitializeRoutines(&InitInfo->ThreadInitInfo.Context),
		   DPRINT1("LDR: LdrpProcessInitialization failed running "
			   "initialization routines; status %x\n", Status));
    }

    /* Call the user-defined Post Process Routine if there is one */
    if (Peb->PostProcessInitRoutine) {
	Peb->PostProcessInitRoutine();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LdrpInitializeThread()
{
    DPRINT("LdrpInitializeThread() called for %wZ (%p/%p)\n",
	   &LdrpImageEntry->BaseDllName,
	   NtCurrentTib()->ClientId.UniqueProcess,
	   NtCurrentTib()->ClientId.UniqueThread);

    /* Make sure we are not shutting down */
    if (LdrpShutdownInProgress)
	return STATUS_SUCCESS;

    /* Allocate the tls regions */
    RET_ERR(LdrpAllocateTls());

    /* For each DLL module (except the executable image), call the tls
     * initializer and the dll initialization routine */
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
		    __try {
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
			    DPRINT("%wZ - Calling entry point at %p for "
				   "thread attaching, %p/%p\n",
				   &LdrEntry->BaseDllName,
				   LdrEntry->EntryPoint,
				   NtCurrentTib()->ClientId.
				   UniqueProcess,
				   NtCurrentTib()->ClientId.
				   UniqueThread);
			    LdrpCallInitRoutine(LdrEntry->EntryPoint,
						LdrEntry->DllBase,
						DLL_THREAD_ATTACH, NULL);
			}
		    } __except(EXCEPTION_EXECUTE_HANDLER) {
			DPRINT1("WARNING: Exception 0x%lx during "
				"LdrpCallInitRoutine(DLL_THREAD_ATTACH) for %wZ\n",
				GetExceptionCode(), &LdrEntry->BaseDllName);
		    }
		}
	    }
	}

	/* Next entry */
	NextEntry = NextEntry->Flink;
    }

    /* For the image module itself, call the tls initializer (if it has one) */
    if (LdrpImageHasTls && !LdrpShutdownInProgress) {
	__try {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_THREAD_ATTACH);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    /* Do nothing */
	}
    }

    DPRINT("LdrpInitializeThread() done\n");
    return STATUS_SUCCESS;
}

/*
 * On process startup, NTDLL_PROCESS_INIT_INFO is placed at the beginning
 * of IpcBuffer. Likewise, on thread startup, NTDLL_THREAD_INIT_INFO is
 * placed at the beginning of IpcBuffer.
 */
FASTCALL VOID LdrpInitialize(PNT_TIB NtTib)
{
    NtTib->Self = NtTib;
    PTHREAD_START_ROUTINE EntryPoint = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID IpcBuffer = seL4_GetIPCBuffer();
    /* Check if we have already setup the PEB. If not, we are the initial thread. */
    BOOLEAN InitThread = !Peb;
    if (InitThread) {
	/* At process startup the process init info is placed at the beginning
	 * of the ipc buffer. */
	NTDLL_PROCESS_INIT_INFO InitInfo = *((PNTDLL_PROCESS_INIT_INFO)(IpcBuffer));
	/* Now that the init info has been copied to the stack, clear the IPC buffer. */
	memset(IpcBuffer, 0, PAGE_SIZE);

	/* Set up the system service endpoint capability in the thread information block */
	NtTib->SystemServiceCap = InitInfo.ThreadInitInfo.SystemServiceCap;

	/* Set up the stack base and limit in the thread information block */
	NtTib->StackBase = (PVOID)InitInfo.ThreadInitInfo.StackTop;
	/* Note that since we have marked the stack of the initial thread as
	 * commit-on-demand, the stack limit should be the whole stack. */
	NtTib->StackLimit = ((PTEB)NtTib)->DeallocationStack =
	    (PVOID)(InitInfo.ThreadInitInfo.StackTop - InitInfo.ThreadInitInfo.StackReserve);

	/* Set up the client id in the thread information block */
	NtTib->ClientId = InitInfo.ThreadInitInfo.ClientId;

	/* Set up the process environment block address in the thread environment block */
	Peb = ((PTEB)NtTib)->ProcessEnvironmentBlock = (PVOID)InitInfo.PebAddress;

	/* Initialize the Process */
	Status = LdrpInitializeProcess(&InitInfo);

        /* We're not initializing anymore */
        LdrpInLdrInit = FALSE;

	if (!NT_SUCCESS(Status)) {
	    goto err;
	}

	if (InitInfo.DriverProcess) {
	    PLDR_DATA_TABLE_ENTRY WdmDllEntry = NULL;
	    LdrpCheckForLoadedDll("wdm.dll", &WdmDllEntry);
	    if (!WdmDllEntry) {
		/* This should never happen. Assert in debug build. */
		assert(FALSE);
		DbgTrace("Fatal error: driver process does not have wdm.dll loaded.\n");
		Status = STATUS_ENTRYPOINT_NOT_FOUND;
		goto err;
	    }

	    EntryPoint = (PTHREAD_START_ROUTINE)WdmDllEntry->EntryPoint;
	    ((PWDM_DLL_ENTRYPOINT)EntryPoint)(InitInfo.ThreadInitInfo.WdmServiceCap,
					      &InitInfo.DriverInitInfo,
					      &Peb->ProcessParameters->CommandLine);
	} else {
	    /* Call the supplied thread entry point if specifed.
	     * Otherwise call the image entry point */
	    PVOID Parameter;
	    KeGetEntryPointFromThreadContext(&InitInfo.ThreadInitInfo.Context,
					     &EntryPoint, &Parameter);
	    if (!EntryPoint) {
		EntryPoint = LdrpImageEntry->EntryPoint;
		Parameter = Peb;
	    }
	    (*EntryPoint)(Parameter);
	}
    } else if (Peb->InheritedAddressSpace) {
	/* Loader data is there... is this a fork() ? */
	/* Handle the fork() */
	//LoaderStatus = LdrpForkProcess();
	Status = STATUS_NOT_IMPLEMENTED;
	UNIMPLEMENTED;
    } else {
	/* At thread startup the thread init info is placed at the beginning
	 * of the ipc buffer. */
	NTDLL_THREAD_INIT_INFO InitInfo = *((PNTDLL_THREAD_INIT_INFO)(IpcBuffer));
	/* Now that the init info has been copied to the stack, clear the IPC buffer. */
	memset(IpcBuffer, 0, PAGE_SIZE);

	/* Set up the system service endpoint capability in the thread information block */
	NtTib->SystemServiceCap = InitInfo.SystemServiceCap;

	/* Set up the stack base and limit in the thread information block */
	NtTib->StackBase = (PVOID)InitInfo.StackTop;
	NtTib->StackLimit = ((PTEB)NtTib)->DeallocationStack =
	    (PVOID)(InitInfo.StackTop - InitInfo.StackReserve);

	/* Set up the client id in the thread information block */
	NtTib->ClientId = InitInfo.ClientId;

	/* Set up the process environment block address in the thread environment block.
	 * Note we need to do this for each thread. */
	((PTEB)NtTib)->ProcessEnvironmentBlock = Peb;

	/* This is a new thread initializing */
	Status = LdrpInitializeThread();
	/* Call thread entry point */
	PVOID Parameter;
	KeGetEntryPointFromThreadContext(&InitInfo.Context,
					 &EntryPoint, &Parameter);
	(*EntryPoint)(Parameter);
    }

err:
    /* Bail out if initialization has failed */
    if (!NT_SUCCESS(Status)) {
	HARDERROR_RESPONSE Response;

	/* Print a debug message */
	DPRINT1("LDR: Initialization failure for process %p thread %p. "
		"Image is %s; NTSTATUS = %08x\n",
		NtCurrentTib()->ClientId.UniqueProcess,
		NtCurrentTib()->ClientId.UniqueThread,
		RtlpDbgTraceModuleName, Status);

	/* Send HARDERROR_MSG LPC message to CSRSS */
	NtRaiseHardError(STATUS_APP_INIT_FAILURE, 1, 0,
			 (PULONG_PTR)&Status, OptionOk, &Response);

	/* Raise a status to terminate the thread. */
	RtlRaiseStatus(Status);
    }

    /* The thread entry point should never return. Shutdown the thread if it did.
     * If we are the init thread, also shutdown the entire process. */
    DPRINT1("LDR: Thread entry point %p returned for thread %p of process %p, "
	    "shutting down %s.\n",
	    EntryPoint, NtCurrentTib()->ClientId.UniqueThread,
	    NtCurrentTib()->ClientId.UniqueProcess,
	    InitThread ? "process" : "thread");
    if (InitThread) {
	LdrShutdownProcess();
	NtTerminateProcess(NtCurrentProcess(), STATUS_UNSUCCESSFUL);
    } else {
	RtlExitUserThread(STATUS_UNSUCCESSFUL);
    }
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrShutdownProcess(VOID)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PLIST_ENTRY NextEntry, ListHead;
    PVOID EntryPoint;

    DPRINT("LdrShutdownProcess() called for %wZ\n", &LdrpImageEntry->BaseDllName);
    if (LdrpShutdownInProgress)
	return STATUS_SUCCESS;

    /* Set the shutdown variables */
    LdrpShutdownThreadId = NtCurrentTib()->ClientId.UniqueThread;
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
	    if (EntryPoint && (LdrEntry->Flags & LDRP_PROCESS_ATTACH_CALLED)
		&& LdrEntry->Flags) {
		__try {
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
		} __except(EXCEPTION_EXECUTE_HANDLER) {
		    DPRINT1("WARNING: Exception 0x%lx during "
			    "LdrpCallInitRoutine(DLL_PROCESS_DETACH) for %wZ\n",
			    GetExceptionCode(), &LdrEntry->BaseDllName);
		}
	    }
	}
    }

    /* Check for TLS */
    if (LdrpImageHasTls) {
	__try {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_PROCESS_DETACH);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
	    /* Do nothing */
	}
    }

    /* FIXME: Do Heap detection and Etw final shutdown */

    /* Release the lock */
    RtlLeaveCriticalSection(&LdrpLoaderLock);
    DPRINT("LdrpShutdownProcess() done\n");

    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrShutdownThread(VOID)
{
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
		    __try {
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
		    } __except(EXCEPTION_EXECUTE_HANDLER) {
			DPRINT1("WARNING: Exception 0x%lx during "
				"LdrpCallInitRoutine(DLL_THREAD_DETACH) for %wZ\n",
				GetExceptionCode(), &LdrEntry->BaseDllName);
		    }
		}
	    }
	}
    }

    /* Check for TLS */
    if (LdrpImageHasTls) {
	__try {
	    /* Do TLS callbacks */
	    LdrpCallTlsInitializers(LdrpImageEntry, DLL_THREAD_DETACH);
	} __except(EXCEPTION_EXECUTE_HANDLER) {
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
	FlsHighIndex = Peb->FlsHighIndex;
	RemoveEntryList(&pFlsData->ListEntry);
	RtlReleasePebLock();

	for (n = 1; n <= FlsHighIndex; ++n) {
	    lpCallback = Peb->FlsCallback[n];
	    if (lpCallback && pFlsData->Data[n]) {
		lpCallback(pFlsData->Data[n]);
	    }
	}

	RtlFreeHeap(RtlGetProcessHeap(), 0, pFlsData);
	Teb->FlsData = NULL;
    }

    /* Check for Fiber data */
    if (Teb->NtTib.FiberData) {
	/* Free Fiber data */
	RtlFreeHeap(RtlGetProcessHeap(), 0, Teb->NtTib.FiberData);
	Teb->NtTib.FiberData = NULL;
    }

    DPRINT("LdrShutdownThread() done\n");
    return STATUS_SUCCESS;
}
