#include "ldrp.h"

static volatile long LdrpLoaderLockAcquisitionCount;

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
