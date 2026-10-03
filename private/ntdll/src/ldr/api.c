#include "ldrp.h"

static volatile long LdrpLoaderLockAcquisitionCount;

static inline BOOLEAN LdrpCheckModuleAddress(IN PLDR_DATA_TABLE_ENTRY Entry,
					     PVOID Address)
{
    if (Entry->Flags & LDRP_IMAGE_ELF) {
	return (ULONG_PTR)Address >= (ULONG_PTR)Entry->DllBase &&
	    ((ULONG_PTR)Address < (ULONG_PTR)Entry->DllBase + Entry->SizeOfImage);
    } else {
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
}

FORCEINLINE ULONG_PTR LdrpMakeCookie(VOID)
{
    /* Generate a cookie */
    return (((ULONG_PTR)NtCurrentTeb()->NtTib.ClientId.UniqueThread & 0xFFF) << 16) |
            (_InterlockedIncrement(&LdrpLoaderLockAcquisitionCount) & 0xFFFF);
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
    DbgTrace("LDR: data table entry for module %p not found\n", Address);
    return STATUS_NO_MORE_ENTRIES;
}

NTAPI VOID LdrSetDllManifestProber(_In_ PLDR_MANIFEST_PROBER_ROUTINE Routine)
{
    /* Do nothing */
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

/*
 * @implemented
 */
NTAPI NTSTATUS LdrLockLoaderLock(IN ULONG Flags,
				 OUT OPTIONAL PULONG Disposition,
				 OUT OPTIONAL PULONG_PTR Cookie)
{
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN InInit = LdrpInLdrInit;

    DPRINT("LdrLockLoaderLock(%x %p %p)\n", Flags, Disposition, Cookie);

    /* Zero out the outputs */
    if (Disposition)
	*Disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID;
    if (Cookie)
	*Cookie = 0;

    /* Validate the flags */
    if (Flags & ~(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS |
		  LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY)) {
	/* Flags are invalid, check how to fail */
	if (Flags & LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	    /* The caller wants us to raise status */
	    RtlRaiseStatus(STATUS_INVALID_PARAMETER_1);
	}

	/* A normal failure */
	return STATUS_INVALID_PARAMETER_1;
    }

    /* Make sure we got a cookie */
    if (!Cookie) {
	/* No cookie check how to fail */
	if (Flags & LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	    /* The caller wants us to raise status */
	    RtlRaiseStatus(STATUS_INVALID_PARAMETER_3);
	}

	/* A normal failure */
	return STATUS_INVALID_PARAMETER_3;
    }

    /* If the flag is set, make sure we have a valid pointer to use */
    if ((Flags & LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY) && !(Disposition)) {
	/* No pointer to return the data to */
	if (Flags & LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	    /* The caller wants us to raise status */
	    RtlRaiseStatus(STATUS_INVALID_PARAMETER_2);
	}

	/* Fail */
	return STATUS_INVALID_PARAMETER_2;
    }

    /* Return now if we are in the init phase */
    if (InInit)
	return STATUS_SUCCESS;

    /* Check what locking semantic to use */
    if (Flags & LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	/* Check if we should enter or simply try */
	if (Flags & LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY) {
	    /* Do a try */
	    if (!RtlTryEnterCriticalSection(&LdrpLoaderLock)) {
		/* It's locked */
		*Disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED;
	    } else {
		/* It worked */
		*Disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED;
		*Cookie = LdrpMakeCookie();
	    }
	} else {
	    /* Do a enter */
	    RtlEnterCriticalSection(&LdrpLoaderLock);

	    /* See if result was requested */
	    if (Disposition)
		*Disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED;
	    *Cookie = LdrpMakeCookie();
	}
    } else {
	/* Wrap this in SEH, since we're not supposed to raise */
	__try {
	    /* Check if we should enter or simply try */
	    if (Flags & LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY) {
		/* Do a try */
		if (!RtlTryEnterCriticalSection(&LdrpLoaderLock)) {
		    /* It's locked */
		    *Disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED;
		} else {
		    /* It worked */
		    *Disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED;
		    *Cookie = LdrpMakeCookie();
		}
	    } else {
		/* Do an enter */
		RtlEnterCriticalSection(&LdrpLoaderLock);

		/* See if result was requested */
		if (Disposition)
		    *Disposition = LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED;
		*Cookie = LdrpMakeCookie();
	    }
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
	    /* We should use the LDR Filter instead */
	    Status = GetExceptionCode();
	}
    }

    /* Return status */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrUnlockLoaderLock(IN OPTIONAL ULONG Flags,
				   IN OPTIONAL ULONG_PTR Cookie)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("LdrUnlockLoaderLock(%x %Ix)\n", Flags, Cookie);

    /* Check for valid flags */
    if (Flags & ~LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	/* Flags are invalid, check how to fail */
	if (Flags & LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	    /* The caller wants us to raise status */
	    RtlRaiseStatus(STATUS_INVALID_PARAMETER_1);
	}

	/* A normal failure */
	return STATUS_INVALID_PARAMETER_1;
    }

    /* If we don't have a cookie, just return */
    if (!Cookie)
	return STATUS_SUCCESS;

    /* Validate the cookie */
    if ((Cookie & 0xF0000000) ||
	((Cookie >> 16) ^ (HandleToUlong(NtCurrentTeb()->NtTib.ClientId.UniqueThread) & 0xFFF))) {
	DPRINT1("LdrUnlockLoaderLock() called with an invalid cookie!\n");

	/* Invalid cookie, check how to fail */
	if (Flags & LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	    /* The caller wants us to raise status */
	    RtlRaiseStatus(STATUS_INVALID_PARAMETER_2);
	}

	/* A normal failure */
	return STATUS_INVALID_PARAMETER_2;
    }

    /* Ready to release the lock */
    if (Flags & LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS) {
	/* Do a direct leave */
	RtlLeaveCriticalSection(&LdrpLoaderLock);
    } else {
	/* Wrap this in SEH, since we're not supposed to raise */
	__try {
	    /* Leave the lock */
	    RtlLeaveCriticalSection(&LdrpLoaderLock);
	} __except(EXCEPTION_EXECUTE_HANDLER)
	{
	    /* We should use the LDR Filter instead */
	    Status = GetExceptionCode();
	}
    }

    /* All done */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrDisableThreadCalloutsForDll(IN PVOID BaseAddress)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    NTSTATUS Status;
    BOOLEAN LockHeld;
    ULONG_PTR Cookie;
    DPRINT("LdrDisableThreadCalloutsForDll (BaseAddress %p)\n", BaseAddress);

    /* Don't do it during shutdown */
    if (LdrpShutdownInProgress)
	return STATUS_SUCCESS;

    /* Check if we should grab the lock */
    LockHeld = FALSE;
    if (!LdrpInLdrInit) {
	/* Grab the lock */
	Status = LdrLockLoaderLock(0, NULL, &Cookie);
	if (!NT_SUCCESS(Status))
	    return Status;
	LockHeld = TRUE;
    }

    /* Make sure the DLL is valid and get its entry */
    Status = STATUS_DLL_NOT_FOUND;
    if (LdrpCheckForLoadedDllHandle(BaseAddress, &LdrEntry)) {
	/* Get if it has a TLS slot */
	if (!LdrEntry->TlsIndex) {
	    /* It doesn't, so you're allowed to call this */
	    LdrEntry->Flags |= LDRP_DONT_CALL_FOR_THREADS;
	    Status = STATUS_SUCCESS;
	}
    }

    /* Check if the lock was held */
    if (LockHeld) {
	/* Release it */
	LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    }

    /* Return the status */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrAddRefDll(IN ULONG Flags, IN PVOID BaseAddress)
{
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG_PTR Cookie;
    BOOLEAN Locked = FALSE;

    /* Check for invalid flags */
    if (Flags & ~(LDR_ADDREF_DLL_PIN)) {
	/* Fail with invalid parameter status if so */
	Status = STATUS_INVALID_PARAMETER;
	goto quickie;
    }

    /* Acquire the loader lock if not in init phase */
    if (!LdrpInLdrInit) {
	/* Acquire the lock */
	Status = LdrLockLoaderLock(0, NULL, &Cookie);
	if (!NT_SUCCESS(Status))
	    goto quickie;
	Locked = TRUE;
    }

    /* Get this module's data table entry */
    if (LdrpCheckForLoadedDllHandle(BaseAddress, &LdrEntry)) {
	if (!LdrEntry) {
	    /* Shouldn't happen */
	    Status = STATUS_INTERNAL_ERROR;
	    goto quickie;
	}

	/* If this is not a pinned module */
	if (LdrEntry->LoadCount != 0xFFFF) {
	    /* Update its load count */
	    if (Flags & LDR_ADDREF_DLL_PIN) {
		/* Pin it by setting load count to -1 */
		LdrEntry->LoadCount = 0xFFFF;
	    } else {
		/* Increase its load count by one */
		LdrEntry->LoadCount++;
	    }
	}
    } else {
	/* There was an error getting this module's handle, return invalid param status */
	Status = STATUS_INVALID_PARAMETER;
    }

quickie:
    /* Check for error case */
    if (!NT_SUCCESS(Status)) {
	/* Print debug information */
	DPRINT1("LDR: LdrAddRefDll(%p) error 0x%08x\n", BaseAddress, Status);
    }

    /* Release the lock if needed */
    if (Locked)
	LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrGetDllHandle(IN OPTIONAL PWSTR DllPath,
			       IN OPTIONAL PULONG DllCharacteristics,
			       IN PUNICODE_STRING DllName,
			       OUT PVOID *DllHandle)
{
    /* Call the newer API */
    return LdrGetDllHandleEx(LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT, DllPath,
			     DllCharacteristics, DllName, DllHandle);
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrGetDllHandleEx(IN ULONG Flags,
				 IN OPTIONAL PWSTR DllPath,
				 IN OPTIONAL PULONG DllCharacteristics,
				 IN PUNICODE_STRING DllName,
				 OUT OPTIONAL PVOID *DllHandle)
{
    NTSTATUS Status;
    PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;
    CHAR RawDllName[512] = {};
    BOOLEAN Locked = FALSE;
    ULONG_PTR Cookie = 0;

    /* Clear the handle */
    if (DllHandle)
	*DllHandle = NULL;

    /* Check for a valid flag combination */
    if ((Flags &
	 ~(LDR_GET_DLL_HANDLE_EX_PIN | LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT)) ||
	(!DllHandle && !(Flags & LDR_GET_DLL_HANDLE_EX_PIN))) {
	DPRINT1("Flags are invalid or no DllHandle given\n");
	Status = STATUS_INVALID_PARAMETER;
	goto Quickie;
    }

    /* If not initializing */
    if (!LdrpInLdrInit) {
	/* Acquire the lock */
	Status = LdrLockLoaderLock(0, NULL, &Cookie);
	if (!NT_SUCCESS(Status))
	    goto Quickie;

	/* Remember we own it */
	Locked = TRUE;
    }

    /* Set default failure code */
    Status = STATUS_DLL_NOT_FOUND;

    /* Locate the last path separator in the DllName, if any. */
    PCWSTR p = DllName->Buffer + DllName->Length / sizeof(WCHAR);
    ULONG DllNameLength = 0;
    while (*p != OBJ_NAME_PATH_SEPARATOR) {
	p--;
	DllNameLength++;
	if (p == DllName->Buffer) {
	    break;
	}
    }
    assert(p >= DllName->Buffer);
    if (*p == OBJ_NAME_PATH_SEPARATOR) {
	p++;
	assert(DllNameLength > 0);
	DllNameLength--;
    }

    /* Convert the unicode string into utf-8 */
    ULONG BytesWritten = 0;
    RtlUnicodeToUTF8N(RawDllName, sizeof(RawDllName) - 1, &BytesWritten,
		      p, DllNameLength * sizeof(WCHAR));
    RawDllName[BytesWritten] = '\0';

    /* Append ".dll" if the name does not have an extension */
    if (!strchr(RawDllName, '.')) {
	strcat_s(RawDllName, sizeof(RawDllName), ".dll");
    }

    /* Display debug string */
    DPRINT1("LDR: LdrGetDllHandleEx, searching for %s from %ws\n", RawDllName,
	    DllPath ? ((ULONG_PTR)DllPath == 1 ? L"" : DllPath) : L"");

    /* Do the lookup */
    if (LdrpCheckForLoadedDll(RawDllName, &LdrEntry)) {
	/* Return success */
	Status = STATUS_SUCCESS;
    } else {
	/* Make sure to NULL this */
	LdrEntry = NULL;
    }

Quickie:
    /* The success path must have a valid loader entry */
    ASSERT((LdrEntry != NULL) == NT_SUCCESS(Status));

    /* Check if we got an entry and success */
    DPRINT("Got LdrEntry->BaseDllName %wZ\n", LdrEntry ? &LdrEntry->BaseDllName : NULL);
    if ((LdrEntry) && (NT_SUCCESS(Status))) {
	/* Check if the DLL is locked */
	if ((LdrEntry->LoadCount != 0xFFFF) &&
	    !(Flags & LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT)) {
	    /* Check what to do with the load count */
	    if (Flags & LDR_GET_DLL_HANDLE_EX_PIN) {
		/* Pin it */
		LdrEntry->LoadCount = 0xFFFF;
	    } else {
		/* Increase the load count */
		LdrEntry->LoadCount++;
	    }
	}

	/* Check if the caller is requesting the handle */
	if (DllHandle)
	    *DllHandle = LdrEntry->DllBase;
    }

    /* Release lock */
    if (Locked) {
	LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    }

    /* Return */
    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrLoadDll(IN OPTIONAL PWSTR SearchPath,
			  IN OPTIONAL PULONG DllCharacteristics,
			  IN PUNICODE_STRING DllName,
			  OUT PVOID *BaseAddress)
{
    ANSI_STRING DllNameA = {};
    NTSTATUS Status = RtlUnicodeStringToAnsiString(&DllNameA, DllName, TRUE);
    if (!NT_SUCCESS(Status)) {
	return Status;
    }

    /* Lock the loader lock */
    ULONG_PTR Cookie;
    LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, NULL, &Cookie);

    __try {
	/* Load the DLL */
	Status = LdrpLoadDll(DllNameA.Buffer, BaseAddress);
	if (NT_SUCCESS(Status)) {
	    Status = STATUS_SUCCESS;
	} else if ((Status != STATUS_NO_SUCH_FILE) && (Status != STATUS_DLL_NOT_FOUND) &&
		   (Status != STATUS_OBJECT_NAME_NOT_FOUND) &&
		   (Status != STATUS_DLL_INIT_FAILED)) {
	    DbgPrintEx(DPFLTR_LDR_ID, DPFLTR_WARNING_LEVEL,
		       "LDR: %s - failing because LdrpLoadDll(%wZ) returned status %x\n",
		       __FUNCTION__, DllName, Status);
	}
    } __finally {
	/* Release the lock */
	LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    }

    RtlFreeAnsiString(&DllNameA);
    return Status;
}

/*
 * @unimplemented
 */
NTAPI NTSTATUS LdrUnloadDll(IN PVOID BaseAddress)
{
    UNIMPLEMENTED;
    return STATUS_NOT_IMPLEMENTED;
}

/*
 * @implemented
 */
NTAPI NTSTATUS LdrEnumerateLoadedModules(IN ULONG ReservedFlag,
					 IN PLDR_ENUM_CALLBACK EnumProc,
					 IN OPTIONAL PVOID Context)
{
    PLIST_ENTRY ListHead, ListEntry;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    NTSTATUS Status;
    ULONG_PTR Cookie;
    BOOLEAN Stop = FALSE;

    /* Check parameters */
    if ((ReservedFlag) || !(EnumProc))
	return STATUS_INVALID_PARAMETER;

    /* Acquire the loader lock */
    Status = LdrLockLoaderLock(0, NULL, &Cookie);
    if (!NT_SUCCESS(Status))
	return Status;

    /* Loop all the modules and call enum proc */
    ListHead = &NtCurrentPeb()->LdrData->InLoadOrderModuleList;
    ListEntry = ListHead->Flink;
    while (ListHead != ListEntry) {
	/* Get the entry */
	LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	/* Call the enumeration proc inside SEH */
	__try {
	    EnumProc(LdrEntry, Context, &Stop);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
	    /* Ignoring the exception */
	}

	/* Break if we were asked to stop enumeration */
	if (Stop) {
	    break;
	}

	/* Advance to the next module */
	ListEntry = ListEntry->Flink;
    }

    /* Release loader lock */
    Status = LdrUnlockLoaderLock(0, Cookie);
    ASSERT(NT_SUCCESS(Status));

    /* Reset any successful status to STATUS_SUCCESS,
     * but leave failure to the caller */
    if (NT_SUCCESS(Status))
	Status = STATUS_SUCCESS;

    /* Return any possible failure status */
    return Status;
}

static NTSTATUS LdrpRegisterElfModule(IN PVOID BaseAddress,
				      IN PVOID EntryPoint,
				      IN ULONG SizeOfImage,
				      IN OPTIONAL PCUNICODE_STRING ModulePath,
				      IN OPTIONAL PCSTR BaseName)
{
    if (!BaseAddress || !SizeOfImage) {
	return STATUS_INVALID_PARAMETER;
    }

    /* Make sure we do not have a module with the same base address */
    LoopOverList(Entry, &NtCurrentPeb()->LdrData->InMemoryOrderModuleList,
		 LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) {
	if (Entry->DllBase == BaseAddress) {
	    return STATUS_ALREADY_REGISTERED;
	}
    }

    PLDR_DATA_TABLE_ENTRY Entry = RtlAllocateHeap(LdrpHeap,
						  HEAP_ZERO_MEMORY,
						  sizeof(LDR_DATA_TABLE_ENTRY));
    if (!Entry) {
	return STATUS_NO_MEMORY;
    }
    NTSTATUS Status;
    if (ModulePath) {
	IF_ERR_GOTO(err, Status,
		    RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE,
					      ModulePath, &Entry->FullDllName));
	LdrpSetBaseDllName(&Entry->FullDllName, &Entry->BaseDllName);
    } else if (BaseName) {
	IF_ERR_GOTO(err, Status, LdrpUtf8ToUnicodeString(BaseName, &Entry->FullDllName));
	Entry->BaseDllName = Entry->FullDllName;
    } else {
	Status = STATUS_INVALID_PARAMETER;
	goto err;
    }

    Entry->DllBase = BaseAddress;
    Entry->EntryPoint = EntryPoint;
    Entry->SizeOfImage = SizeOfImage;
    Entry->Flags = LDRP_IMAGE_ELF;
    InsertTailList(&NtCurrentPeb()->LdrData->InInitializationOrderModuleList,
                   &Entry->InInitializationOrderLinks);
    LdrpInsertMemoryTableEntry(Entry, BaseName);
    return STATUS_SUCCESS;

err:
    if (Entry->FullDllName.Buffer) {
	RtlFreeUnicodeString(&Entry->FullDllName);
    }
    RtlFreeHeap(LdrpHeap, 0, Entry);
    return Status;
}

NTAPI NTSTATUS LdrRegisterElfModule(IN PVOID BaseAddress,
				    IN PVOID EntryPoint,
				    IN ULONG SizeOfImage,
				    IN OPTIONAL PCUNICODE_STRING ModulePath,
				    IN OPTIONAL PCSTR BaseName)
{
    ULONG_PTR Cookie;
    LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, NULL, &Cookie);

    NTSTATUS Status = LdrpRegisterElfModule(BaseAddress, EntryPoint, SizeOfImage,
					    ModulePath, BaseName);
    LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    return Status;
}
