/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS system libraries
 * FILE:            lib/rtl/critical.c
 * PURPOSE:         Critical sections
 * PROGRAMMERS:     Alex Ionescu (alex@relsoft.net)
 *                  Gunnar Dalsnes
 */

/* INCLUDES *****************************************************************/

#include <ntdll.h>

#define MAX_STATIC_CS_DEBUG_OBJECTS 64

/* Protects the list of critical sections owned by the process */
static RTL_CRITICAL_SECTION RtlpCriticalSectionLock;
/* List of critical sections owned by the process, used for debug purposes */
static LIST_ENTRY RtlpCriticalSectionList = {
    .Blink = &RtlpCriticalSectionList,
    .Flink = &RtlpCriticalSectionList
};
/* Statically allocated critical section debug info structure. The rest are
 * dynamically allocated on the process heap. */
static RTL_CRITICAL_SECTION_DEBUG RtlpStaticDebugInfo[MAX_STATIC_CS_DEBUG_OBJECTS];
/* Bitmap to track the usage status of the static debug info array */
static ULONG RtlpStaticDebugInfoBitmapBuffer[MAX_STATIC_CS_DEBUG_OBJECTS / 32];
static RTL_BITMAP RtlpStaticDebugInfoFreeMap = {
    .SizeOfBitMap = MAX_STATIC_CS_DEBUG_OBJECTS,
    .Buffer = RtlpStaticDebugInfoBitmapBuffer
};
LARGE_INTEGER RtlpTimeout;

extern BOOLEAN LdrpShutdownInProgress;
extern HANDLE LdrpShutdownThreadId;

/* FUNCTIONS *****************************************************************/

/*++
 * RtlpWaitForCriticalSection
 *
 *     Slow path of RtlEnterCriticalSection. Waits on an Event Object.
 *
 * Params:
 *     CriticalSection - Critical section to acquire.
 *
 * Returns:
 *     STATUS_SUCCESS, or raises an exception if a deadlock is occuring.
 *
 * Remarks:
 *     None
 *
 *--*/
static NTSTATUS RtlpWaitForCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    NTSTATUS Status;
    BOOLEAN LastChance = FALSE;

    /* Increase the Debug Entry count */
    DPRINT("Waiting on Critical Section Event: %p %p\n",
	   CriticalSection, CriticalSection->LockSemaphore);

    if (CriticalSection->DebugInfo) {
	CriticalSection->DebugInfo->EntryCount++;
    }

    /*
     * If we're shutting down the process, we're allowed to acquire any
     * critical sections by force (the loader lock in particular)
     */
    if (LdrpShutdownInProgress &&
	LdrpShutdownThreadId == NtCurrentTib()->ClientId.UniqueThread) {
	DPRINT("Forcing ownership of critical section %p\n", CriticalSection);
	return STATUS_SUCCESS;
    }

    for (;;) {
	/* Increase the number of times we've had contention */
	if (CriticalSection->DebugInfo) {
	    CriticalSection->DebugInfo->ContentionCount++;
	}

	/* Wait on the Event */
	Status = NtWaitForSingleObject(CriticalSection->LockSemaphore,
				       FALSE, &RtlpTimeout);

	/* We have Timed out */
	if (Status == STATUS_TIMEOUT) {
	    /* Is this the 2nd time we've timed out? */
	    if (LastChance) {
		ERROR_DBGBREAK("Deadlock: %p\n", CriticalSection);
		/* Yes it is, we are raising an exception */
		EXCEPTION_RECORD ExceptionRecord;
		ExceptionRecord.ExceptionCode = STATUS_POSSIBLE_DEADLOCK;
		ExceptionRecord.ExceptionFlags = 0;
		ExceptionRecord.ExceptionRecord = NULL;
		ExceptionRecord.ExceptionAddress = RtlRaiseException;
		ExceptionRecord.NumberParameters = 1;
		ExceptionRecord.ExceptionInformation[0] = (ULONG_PTR) CriticalSection;
		RtlRaiseException(&ExceptionRecord);
	    }
	    /* One more try */
	    LastChance = TRUE;
	} else if (!NT_SUCCESS(Status)) {
	    /* Either STATUS_INVALID_HANDLE or STATUS_ACCESS_DENIED is returned.
	     * This is a hard error. */
	    RtlRaiseStatus(Status);
	} else {
	    /* If we are here, everything went fine */
	    return STATUS_SUCCESS;
	}
    }
}

/*++
 * RtlpUnWaitCriticalSection
 *
 *     Slow path of RtlLeaveCriticalSection. Fires an Event Object.
 *
 * Params:
 *     CriticalSection - Critical section to release.
 *
 * Returns:
 *     None. Raises an exception if the system call failed.
 *
 * Remarks:
 *     None
 *
 *--*/
static VOID RtlpUnWaitCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    NTSTATUS Status;

    /* Signal the Event */
    DPRINT("Signaling Critical Section Event: %p, %p\n",
	   CriticalSection, CriticalSection->LockSemaphore);

    /* Set the event */
    Status = NtSetEvent(CriticalSection->LockSemaphore, NULL);

    /* Throws an exception in case of failure */
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Signaling failed for: %p, %p, 0x%08x\n",
		CriticalSection, CriticalSection->LockSemaphore, Status);
	RtlRaiseStatus(Status);
    }
}

/*++
 * RtlpAllocateDebugInfo
 *
 *     Finds or allocates memory for a Critical Section Debug Object
 *
 * Params:
 *     None
 *
 * Returns:
 *     A pointer to an empty Critical Section Debug Object.
 *
 * Remarks:
 *     For optimization purposes, the first 64 entries can be cached. From
 *     then on, future Critical Sections will allocate memory from the heap.
 *
 *--*/
static PRTL_CRITICAL_SECTION_DEBUG RtlpAllocateDebugInfo(VOID)
{
    ULONG i;

    /* Try to allocate from our buffer first */
    for (i = 0; i < MAX_STATIC_CS_DEBUG_OBJECTS; i++) {
	/* Check if Entry is free */
	if (!RtlTestBit(&RtlpStaticDebugInfoFreeMap, i)) {
	    /* Mark entry in use */
	    DPRINT("Using entry: %u. Buffer: %p\n", i,
		   &RtlpStaticDebugInfo[i]);
	    RtlSetBit(&RtlpStaticDebugInfoFreeMap, i);

	    /* Use free entry found */
	    return &RtlpStaticDebugInfo[i];
	}
    }

    /* We are out of static buffer, allocate dynamic */
    return RtlAllocateHeap(RtlGetProcessHeap(), 0,
			   sizeof(RTL_CRITICAL_SECTION_DEBUG));
}

/*++
 * RtlpFreeDebugInfo
 *
 *     Frees the memory for a Critical Section Debug Object
 *
 * Params:
 *     DebugInfo - Pointer to Critical Section Debug Object to free.
 *
 * Returns:
 *     None.
 *
 * Remarks:
 *     If the pointer is part of the static buffer, then the entry is made
 *     free again. If not, the object is de-allocated from the heap.
 *
 *--*/
static VOID RtlpFreeDebugInfo(PRTL_CRITICAL_SECTION_DEBUG DebugInfo)
{
    /* Is it part of our cached entries? */
    if ((DebugInfo >= RtlpStaticDebugInfo) &&
	(DebugInfo <= &RtlpStaticDebugInfo[MAX_STATIC_CS_DEBUG_OBJECTS - 1])) {
	/* Yes. zero it out */
	RtlZeroMemory(DebugInfo, sizeof(RTL_CRITICAL_SECTION_DEBUG));
	/* Mark as free */
	SIZE_T EntryId = (DebugInfo - RtlpStaticDebugInfo);
	DPRINT("Freeing from Buffer: %p. Entry: %Iu inside Process: %p\n",
	       DebugInfo, EntryId, NtCurrentTib()->ClientId.UniqueProcess);
	RtlClearBit(&RtlpStaticDebugInfoFreeMap, EntryId);
    } else if (!DebugInfo->Flags) {
	/* It's a dynamic one, so free from the heap */
	DPRINT("Freeing from Heap: %p inside Process: %p\n",
	       DebugInfo, NtCurrentTib()->ClientId.UniqueProcess);
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, DebugInfo);
    } else {
	/* Wine stores a section name pointer in the Flags member */
	DPRINT("Assuming static: %p inside Process: %p\n",
	       DebugInfo, NtCurrentTib()->ClientId.UniqueProcess);
    }
}

/*++
 * RtlDeleteCriticalSection
 * @implemented NT4
 *
 *     Deletes a Critical Section
 *
 * Params:
 *     CriticalSection - Critical section to delete.
 *
 * Returns:
 *     STATUS_SUCCESS, or error value returned by NtClose.
 *
 * Remarks:
 *     The critical section members should not be read after this call.
 *
 *--*/
NTAPI NTSTATUS RtlDeleteCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("Deleting Critical Section: %p\n", CriticalSection);

    /* We should never delete the process critical section list lock. */
    assert(CriticalSection != &RtlpCriticalSectionLock);

    /* Close the Event Object Handle if it exists */
    if (CriticalSection->LockSemaphore) {
	/* In case NtClose fails, return the status */
	Status = NtClose(CriticalSection->LockSemaphore);
    }

    /* Protect List */
    RtlEnterCriticalSection(&RtlpCriticalSectionLock);

    if (CriticalSection->DebugInfo) {
	/* Remove it from the list */
	RemoveEntryList(&CriticalSection->DebugInfo->ProcessLocksList);
	/* We cannot zero the DebugInfo struct here since we need to
	 * preserve Flags for RtlpFreeDebugInfo. We will zero it below. */
    }

    /* Unprotect */
    RtlLeaveCriticalSection(&RtlpCriticalSectionLock);

    if (CriticalSection->DebugInfo) {
	/* Free it */
	RtlpFreeDebugInfo(CriticalSection->DebugInfo);
    }

    /* Wipe it out */
    RtlZeroMemory(CriticalSection, sizeof(RTL_CRITICAL_SECTION));

    /* In the case where NtClose above fails, return the status */
    return Status;
}

/*++
 * RtlSetCriticalSectionSpinCount
 * @implemented NT4
 *
 *     Sets the spin count for a critical section.
 *
 * Params:
 *     CriticalSection - Critical section to set the spin count for.
 *
 *     SpinCount - Spin count for the critical section.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     SpinCount is ignored on single-processor systems.
 *
 *--*/
NTAPI ULONG RtlSetCriticalSectionSpinCount(PRTL_CRITICAL_SECTION CriticalSection,
					   ULONG SpinCount)
{
    ULONG OldCount = (ULONG) CriticalSection->SpinCount;

    /* Set to parameter if MP, or to 0 if this is Uniprocessor */
    CriticalSection->SpinCount = (NtCurrentPeb()->NumberOfProcessors > 1) ? SpinCount : 0;
    return OldCount;
}

/*++
 * RtlEnterCriticalSection
 * @implemented NT4
 *
 *     Waits to gain ownership of the critical section.
 *
 * Params:
 *     CriticalSection - Critical section to wait for.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     Uses a fast-path unless contention happens.
 *
 *--*/
NTAPI NTSTATUS RtlEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    HANDLE Thread = (HANDLE)NtCurrentTib()->ClientId.UniqueThread;

    /* Try to lock it */
    if (InterlockedIncrement(&CriticalSection->LockCount) != 0) {
	/* We've failed to lock it! Does this thread actually own it? */
	if (Thread == CriticalSection->OwningThread) {
	    /*
	     * You own it, so you'll get it when you're done with it! No need to
	     * use the interlocked functions as only the thread who already owns
	     * the lock can modify this data.
	     */
	    CriticalSection->RecursionCount++;
	    return STATUS_SUCCESS;
	}

	/* NOTE - CriticalSection->OwningThread can be NULL here because changing
	   this information is not serialized. This happens when thread a
	   acquires the lock (LockCount == 0) and thread b tries to
	   acquire it as well (LockCount == 1) but thread a hasn't had a
	   chance to set the OwningThread! So it's not an error when
	   OwningThread is NULL here! */

	/* We don't own it, so we must wait for it */
	RtlpWaitForCriticalSection(CriticalSection);
    }

    /*
     * Lock successful. Changing this information has not to be serialized
     * because only one thread at a time can actually change it (the one who
     * acquired the lock)!
     */
    CriticalSection->OwningThread = Thread;
    CriticalSection->RecursionCount = 1;
    return STATUS_SUCCESS;
}

/*++
 * RtlInitializeCriticalSection
 * @implemented NT4
 *
 *     Initialises a new critical section.
 *
 * Params:
 *     CriticalSection - Critical section to initialise
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     Simply calls RtlInitializeCriticalSectionAndSpinCount
 *
 *--*/
NTAPI NTSTATUS RtlInitializeCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    /* Call the Main Function */
    return RtlInitializeCriticalSectionAndSpinCount(CriticalSection, 0);
}

/*
 * Allocate the critical section debug infor and populate the RTL_CRITICAL_SECTION
 * data structure.
 */
NTSTATUS RtlpInitializeCriticalSection(IN PRTL_CRITICAL_SECTION CriticalSection,
				       IN HANDLE LockSemaphore,
				       IN ULONG SpinCount)
{
    assert(CriticalSection != NULL);

    PRTL_CRITICAL_SECTION_DEBUG CriticalSectionDebugData;

    /* First things first, set up the Object */
    DPRINT("Initializing Critical Section: %p (handle %p spincount %d)\n",
	   CriticalSection, LockSemaphore, SpinCount);
    CriticalSection->LockCount = -1;
    CriticalSection->RecursionCount = 0;
    CriticalSection->OwningThread = 0;
    CriticalSection->SpinCount = (NtCurrentPeb()->NumberOfProcessors > 1) ? SpinCount : 0;
    CriticalSection->LockSemaphore = LockSemaphore;

    /* Allocate the Debug Data */
    CriticalSectionDebugData = RtlpAllocateDebugInfo();
    DPRINT("Allocated Debug Data: %p inside Process: %p\n",
	   CriticalSectionDebugData, NtCurrentTib()->ClientId.UniqueProcess);

    if (!CriticalSectionDebugData) {
	/* This is bad! */
	DPRINT1("Couldn't allocate Debug Data for: %p\n", CriticalSection);
	return STATUS_NO_MEMORY;
    }

    /* Set it up */
    CriticalSectionDebugData->Type = RTL_CRITSECT_TYPE;
    CriticalSectionDebugData->ContentionCount = 0;
    CriticalSectionDebugData->EntryCount = 0;
    CriticalSectionDebugData->CriticalSection = CriticalSection;
    CriticalSectionDebugData->Flags = 0;
    CriticalSection->DebugInfo = CriticalSectionDebugData;

    return STATUS_SUCCESS;
}

/*++
 * LdrpInitCriticalSection
 *
 *     Initializes the Critical Section implementation. This is called
 *     during the process startup sequence by the loader component.
 *
 * Params:
 *     None
 *
 * Returns:
 *     None.
 *
 * Remarks:
 *     After this call, the Process Critical Section list is protected.
 *
 *--*/
VOID LdrpInitCriticalSection(HANDLE CriticalSectionLockSemaphore)
{
    /* Initialize the critical section protecting the process
     * critical section list */
    RtlpInitializeCriticalSection(&RtlpCriticalSectionLock,
				  CriticalSectionLockSemaphore, 0);

    DPRINT("Inserting into ProcessLocks: %p, %p, %p\n",
	   &RtlpCriticalSectionLock.DebugInfo->ProcessLocksList,
	   &RtlpCriticalSectionLock, &RtlpCriticalSectionList);

    /* Add it to the process critical section list */
    InsertTailList(&RtlpCriticalSectionList,
		   &RtlpCriticalSectionLock.DebugInfo->ProcessLocksList);
}

/*++
 * RtlInitializeCriticalSectionAndSpinCount
 * @implemented NT4
 *
 *     Initialises a new critical section.
 *
 * Params:
 *     CriticalSection - Critical section to initialise
 *
 *     SpinCount - Spin count for the critical section.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     SpinCount is ignored on single-processor systems.
 *
 *--*/
NTAPI NTSTATUS
RtlInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION CriticalSection,
					 ULONG SpinCount)
{
    assert(CriticalSection != &RtlpCriticalSectionLock);

    HANDLE LockSemaphore = NULL;
    RET_ERR(NtCreateEvent(&LockSemaphore, EVENT_ALL_ACCESS,
			  NULL, SynchronizationEvent, FALSE));
    DPRINT("Created Event: %p\n", LockSemaphore);
    assert(LockSemaphore != NULL);

    RET_ERR_EX(RtlpInitializeCriticalSection(CriticalSection,
					     LockSemaphore,
					     SpinCount),
	       NtClose(LockSemaphore));

    /*
     * Add it to the List of Critical Sections owned by the process.
     *
     * Here CriticalSection->DebugInfo->ProcessLocksList is the list entry,
     * and RtlpCriticalSectionList is the list head.
     *
     * This is protected by the critical section lock.
     */
    DPRINT("Securely inserting into ProcessLocks: %p, %p, %p\n",
	   &CriticalSection->DebugInfo->ProcessLocksList, CriticalSection,
	   &RtlpCriticalSectionList);

    /* Protect List */
    RtlEnterCriticalSection(&RtlpCriticalSectionLock);

    /* Add this critical section to the list */
    InsertTailList(&RtlpCriticalSectionList,
		   &CriticalSection->DebugInfo->ProcessLocksList);

    /* Unprotect */
    RtlLeaveCriticalSection(&RtlpCriticalSectionLock);

    return STATUS_SUCCESS;
}

/*++
 * RtlGetCriticalSectionRecursionCount
 * @implemented NT5.2 SP1
 *
 *     Retrieves the recursion count of a given critical section.
 *
 * Params:
 *     CriticalSection - Critical section to retrieve its recursion count.
 *
 * Returns:
 *     The recursion count.
 *
 * Remarks:
 *     We return the recursion count of the critical section if it is owned
 *     by the current thread, and otherwise we return zero.
 *
 *--*/
NTAPI LONG RtlGetCriticalSectionRecursionCount(PRTL_CRITICAL_SECTION CriticalSection)
{
    if (CriticalSection->OwningThread == NtCurrentTib()->ClientId.UniqueThread) {
	/*
	 * The critical section is owned by the current thread,
	 * therefore retrieve its actual recursion count.
	 */
	return CriticalSection->RecursionCount;
    } else {
	/*
	 * It is not owned by the current thread, so
	 * for this thread there is no recursion.
	 */
	return 0;
    }
}

/*++
 * RtlLeaveCriticalSection
 * @implemented NT4
 *
 *     Releases a critical section and makes if available for new owners.
 *
 * Params:
 *     CriticalSection - Critical section to release.
 *
 * Returns:
 *     STATUS_SUCCESS.
 *
 * Remarks:
 *     If another thread was waiting, the slow path is entered.
 *
 *--*/
NTAPI NTSTATUS RtlLeaveCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    HANDLE Thread = (HANDLE)NtCurrentTib()->ClientId.UniqueThread;
    /*
     * This isn't checked in Windows but it's a valid check so we do it.
     */
    if (Thread != CriticalSection->OwningThread) {
	DPRINT1("Releasing critical section not owned!\n");
	RtlRaiseStatus(STATUS_INVALID_PARAMETER);
    }

    /*
     * Decrease the Recursion Count. No need to do this atomically because only
     * the thread who holds the lock can call this function (unless the program
     * is totally screwed, in which case we throw an exception which hopefully
     * will either terminate the program or trap in to a debugger).
     */
    if (--CriticalSection->RecursionCount) {
	if (CriticalSection->RecursionCount < 0) {
	    DPRINT1("CRITICAL SECTION MESS: Section %p is not acquired!\n",
		    CriticalSection);
	    RtlRaiseStatus(STATUS_INVALID_PARAMETER);
	}
	/* Someone still owns us, but we are free. This needs to be done atomically. */
	InterlockedDecrement(&CriticalSection->LockCount);
    } else {
	/*
	 * Nobody owns us anymore. No need to do this atomically.
	 * See comment above.
	 */
	CriticalSection->OwningThread = 0;

	/* Was someone wanting us? This needs to be done atomically. */
	if (-1 != InterlockedDecrement(&CriticalSection->LockCount)) {
	    /* Let him have us */
	    RtlpUnWaitCriticalSection(CriticalSection);
	}
    }

    /* Sucessful! */
    return STATUS_SUCCESS;
}

/*++
 * RtlTryEnterCriticalSection
 * @implemented NT4
 *
 *     Attemps to gain ownership of the critical section without waiting.
 *
 * Params:
 *     CriticalSection - Critical section to attempt acquiring.
 *
 * Returns:
 *     TRUE if the critical section has been acquired, FALSE otherwise.
 *
 * Remarks:
 *     None
 *
 *--*/
NTAPI BOOLEAN RtlTryEnterCriticalSection(PRTL_CRITICAL_SECTION CriticalSection)
{
    /* Try to take control */
    if (InterlockedCompareExchange(&CriticalSection->LockCount, 0, -1) == -1) {
	/* It's ours */
	CriticalSection->OwningThread = NtCurrentTib()->ClientId.UniqueThread;
	CriticalSection->RecursionCount = 1;
	return TRUE;
    } else if (CriticalSection->OwningThread == NtCurrentTib()->ClientId.UniqueThread) {
	/* It's already ours */
	InterlockedIncrement(&CriticalSection->LockCount);
	CriticalSection->RecursionCount++;
	return TRUE;
    }

    /* It's not ours */
    return FALSE;
}

NTAPI VOID RtlCheckForOrphanedCriticalSections(HANDLE ThreadHandle)
{
    UNIMPLEMENTED;
}

NTAPI ULONG RtlIsCriticalSectionLocked(PRTL_CRITICAL_SECTION CriticalSection)
{
    return CriticalSection->RecursionCount != 0;
}

NTAPI ULONG RtlIsCriticalSectionLockedByThread(PRTL_CRITICAL_SECTION CriticalSection)
{
    return CriticalSection->OwningThread == NtCurrentTib()->ClientId.UniqueThread
	&& CriticalSection->RecursionCount != 0;
}
