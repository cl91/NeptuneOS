/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS Client/Server Runtime SubSystem
 * FILE:            subsystems/win32/csrsrv/thredsup.c
 * PURPOSE:         CSR Server DLL Thread Management
 * PROGRAMMERS:     ReactOS Portable Systems Group
 *                  Alex Ionescu (alex@relsoft.net)
 */

/* INCLUDES *******************************************************************/

#include "srv.h"

/* PRIVATE FUNCTIONS **********************************************************/

FORCEINLINE ULONG_PTR CsrpHashThread(HANDLE ThreadId)
{
    return (ULONG_PTR)ThreadId % NUMBER_THREAD_HASH_BUCKETS;
}

/*++
 * @name CsrpProtectHandle
 * @implemented NT5.2
 *
 * The CsrpProtectHandle routine protects an object handle against closure.
 *
 * @return TRUE or FALSE.
 *
 * @remarks None.
 *
 *--*/
BOOLEAN CsrpProtectHandle(IN HANDLE ObjectHandle)
{
    NTSTATUS Status;
    OBJECT_HANDLE_ATTRIBUTE_INFORMATION HandleInfo;

    /* Query current state */
    Status = NtQueryObject(ObjectHandle, ObjectHandleFlagInformation, &HandleInfo,
			   sizeof(HandleInfo), NULL);
    if (NT_SUCCESS(Status)) {
	/* Enable protect from close */
	HandleInfo.ProtectFromClose = TRUE;
	Status = NtSetInformationObject(ObjectHandle, ObjectHandleFlagInformation,
					&HandleInfo, sizeof(HandleInfo));
	if (NT_SUCCESS(Status))
	    return TRUE;
    }

    /* We failed to or set the state */
    return FALSE;
}

/*++
 * @name CsrpUnProtectHandle
 * @implemented NT5.2
 *
 * The CsrpUnProtectHandle routine unprotects an object handle against closure.
 *
 * @return TRUE or FALSE.
 *
 * @remarks None.
 *
 *--*/
BOOLEAN CsrpUnProtectHandle(IN HANDLE ObjectHandle)
{
    NTSTATUS Status;
    OBJECT_HANDLE_ATTRIBUTE_INFORMATION HandleInfo;

    /* Query current state */
    Status = NtQueryObject(ObjectHandle, ObjectHandleFlagInformation, &HandleInfo,
			   sizeof(HandleInfo), NULL);
    if (NT_SUCCESS(Status)) {
	/* Disable protect from close */
	HandleInfo.ProtectFromClose = FALSE;
	Status = NtSetInformationObject(ObjectHandle, ObjectHandleFlagInformation,
					&HandleInfo, sizeof(HandleInfo));
	if (NT_SUCCESS(Status))
	    return TRUE;
    }

    /* We failed to or set the state */
    return FALSE;
}

/*++
 * @name CsrpAllocateClientThread
 *
 * The CsrpAllocateClientThread routine allocates a new CSR Thread object.
 *
 * @param CsrProcess
 *        Pointer to the CSR Process which will contain this CSR Thread.
 *
 * @return Pointer to the newly allocated CSR Thread.
 *
 * @remarks None.
 *
 *--*/
PCSR_THREAD CsrpAllocateClientThread(IN PCSR_PROCESS CsrProcess)
{
    PCSR_THREAD CsrThread;

    /* Allocate the structure */
    CsrThread = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CSR_THREAD));
    if (!CsrThread)
	return NULL;

    /* Reference the Thread and Process */
    CsrpLockedReferenceClientThread(CsrThread);
    CsrpLockedReferenceClientProcess(CsrProcess);

    /* Set the Parent Process */
    CsrThread->Process = CsrProcess;

    /* Return Thread */
    return CsrThread;
}

/*++
 * @name CsrpLockedReferenceClientThread
 *
 * The CsrpLockedReferenceClientThread references a CSR Thread while the
 * Process Lock is already being held.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread to be referenced.
 *
 * @return None.
 *
 * @remarks This routine will return with the Process Lock held.
 *
 *--*/
VOID CsrpLockedReferenceClientThread(IN PCSR_THREAD CsrThread)
{
    /* Increment the reference count */
    ++CsrThread->ReferenceCount;
}

/*++
 * @name CsrpLocateClientThreadByClientId
 *
 * The CsrpLocateClientThreadByClientId routine locates the CSR Thread and,
 * optionally, its parent CSR Process, corresponding to a Client ID.
 *
 * @param Process
 *        Optional pointer to a CSR Process pointer which will contain
 *        the CSR Thread's parent.
 *
 * @param ClientId
 *        Pointer to a Client ID structure containing the Unique Thread ID
 *        to look up.
 *
 * @return Pointer to the CSR Thread corresponding to this CID, or NULL if
 *         none was found.
 *
 * @remarks None.
 *
 *--*/
PCSR_THREAD CsrpLocateClientThreadByThreadId(OUT OPTIONAL PCSR_PROCESS *Process,
					     IN HANDLE ThreadId)
{
    ULONG i;
    PLIST_ENTRY ListHead, NextEntry;
    PCSR_THREAD FoundThread;
    ASSERT(CsrpProcessStructureListLocked());

    if (Process)
	*Process = NULL;

    /* Hash the Thread */
    i = CsrpHashThread(ThreadId);

    /* Set the list pointers */
    ListHead = &CsrSrv->ClientThreadHashTable[i];
    NextEntry = ListHead->Flink;

    /* Star the loop */
    while (NextEntry != ListHead) {
	/* Get the thread */
	FoundThread = CONTAINING_RECORD(NextEntry, CSR_THREAD, HashLinks);

	/* Move to the next entry */
	NextEntry = NextEntry->Flink;

	/* Compare the TID */
	if (FoundThread->ClientId.UniqueThread == ThreadId) {
	    /* Match found, return the process */
	    if (Process)
		*Process = FoundThread->Process;

	    /* Return thread too */
	    return FoundThread;
	}
    }

    /* Nothing found */
    return NULL;
}

/*++
 * @name CsrpInsertClientThread
 *
 * The CsrpInsertClientThread routine inserts a CSR Thread into its parent's
 * Thread List and into the Thread Hash Table.
 *
 * @param Process
 *        Pointer to the CSR Process containing this CSR Thread.
 *
 * @param Thread
 *        Pointer to the CSR Thread to be inserted.
 *
 * @return None.
 *
 * @remarks None.
 *
 *--*/
NTSTATUS CsrpInsertClientThread(IN PCSR_PROCESS Process, IN PCSR_THREAD Thread)
{
    ULONG i;
    NTSTATUS Status;
    ULONG ThreadInfo;
    // ASSERT(ProcessStructureListLocked());

    /* Make sure the thread isn't already dead by the time we got this */
    Status = NtQueryInformationThread(Thread->ThreadHandle, ThreadIsTerminated,
				      &ThreadInfo, sizeof(ThreadInfo), NULL);
    if (!NT_SUCCESS(Status))
	return Status;
    if (ThreadInfo)
	return STATUS_THREAD_IS_TERMINATING;

    /* Insert it into the Regular List */
    InsertTailList(&Process->ThreadList, &Thread->Link);

    /* Increase Thread Count */
    Process->ThreadCount++;

    /* Hash the Thread */
    i = CsrpHashThread(Thread->ClientId.UniqueThread);

    /* Insert it there too */
    InsertHeadList(&CsrSrv->ClientThreadHashTable[i], &Thread->HashLinks);
    return STATUS_SUCCESS;
}

/*++
 * @name CsrpDeallocateClientThread
 *
 * The CsrpDeallocateClientThread frees the memory associated with a CSR Thread.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread to be freed.
 *
 * @return None.
 *
 * @remarks Do not call this routine. It is reserved for the internal
 *          thread management routines when a CSR Thread has been cleanly
 *          dereferenced and killed.
 *
 *--*/
VOID CsrpDeallocateClientThread(IN PCSR_THREAD CsrThread)
{
    /* Free the process object from the heap */
    // ASSERT(CsrThread->WaitBlock == NULL);
    RtlFreeHeap(RtlGetProcessHeap(), 0, CsrThread);
}

/*++
 * @name CsrpRemoveThread
 *
 * The CsrpRemoveThread function undoes a CsrInsertThread operation and
 * removes the CSR Thread from the the Hash Table and Thread List.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread to remove.
 *
 * @return None.
 *
 * @remarks If this CSR Thread is the last one inside a CSR Process, the
 *          parent will be dereferenced and the CsrProcessLastThreadTerminated
 *          flag will be set.
 *
 *          After executing this routine, the CSR Thread will have the
 *          CsrThreadInTermination flag set.
 *
 *--*/
static VOID CsrpRemoveThread(IN PCSR_THREAD CsrThread)
{
    ASSERT(CsrpProcessStructureListLocked());

    /* Remove it from the List */
    RemoveEntryList(&CsrThread->Link);

    /* Decreate the thread count of the process */
    CsrThread->Process->ThreadCount--;

    /* Remove it from the Hash List as well */
    if (CsrThread->HashLinks.Flink)
	RemoveEntryList(&CsrThread->HashLinks);

    /* Check if this is the last Thread */
    if (CsrThread->Process->ThreadCount == 0) {
	/* Check if it's not already been marked for deletion */
	if ((CsrThread->Process->Flags & CsrProcessLastThreadTerminated) == 0) {
	    /* Let everyone know this process is about to lose the thread */
	    CsrThread->Process->Flags |= CsrProcessLastThreadTerminated;

	    /* Reference the Process */
	    CsrpLockedDereferenceClientProcess(CsrThread->Process);
	}
    }

    /* Mark the thread for deletion */
    CsrThread->Flags |= CsrThreadInTermination;
}

/*++
 * @name CsrpThreadRefcountZero
 *
 * The CsrpThreadRefcountZero routine is executed when a CSR Thread has lost
 * all its active references. It removes and de-allocates the CSR Thread.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread that is to be deleted.
 *
 * @return None.
 *
 * @remarks Do not call this routine. It is reserved for the internal
 *          thread management routines when a CSR Thread has lost all
 *          its references.
 *
 *          This routine is called with the Process Lock held.
 *
 *--*/
static VOID CsrpThreadRefcountZero(IN PCSR_THREAD CsrThread)
{
    PCSR_PROCESS CsrProcess = CsrThread->Process;
    NTSTATUS Status;
    ASSERT(CsrpProcessStructureListLocked());

    /* Remove this thread */
    CsrpRemoveThread(CsrThread);

    /* Release the Process Lock */
    CsrReleaseProcessLock();

    /* Close the NT Thread Handle */
    if (CsrThread->ThreadHandle) {
	CsrpUnProtectHandle(CsrThread->ThreadHandle);
	Status = NtClose(CsrThread->ThreadHandle);
	ASSERT(NT_SUCCESS(Status));
    }

    /* De-allocate the CSR Thread Object */
    CsrpDeallocateClientThread(CsrThread);

    /* Remove a reference from the process */
    CsrDereferenceProcess(CsrProcess);
}

/*++
 * @name CsrLockedDereferenceThread
 *
 * The CsrLockedDereferenceThread dereferences a CSR Thread while the
 * Process Lock is already being held.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread to be dereferenced.
 *
 * @return None.
 *
 * @remarks This routine will return with the Process Lock held.
 *
 *--*/
VOID CsrpLockedDereferenceClientThread(IN PCSR_THREAD CsrThread)
{
    LONG LockCount;

    /* Decrease reference count */
    LockCount = --CsrThread->ReferenceCount;
    ASSERT(LockCount >= 0);
    if (LockCount == 0) {
	/* Call the generic cleanup code */
	CsrpThreadRefcountZero(CsrThread);
	/* Acquire the lock again, it was released by CsrThreadRefcountZero */
	CsrAcquireProcessLock();
    }
}

/* PUBLIC FUNCTIONS ***********************************************************/

/*++
 * @name CsrCreateRemoteThread
 * @implemented NT4
 *
 * The CsrCreateRemoteThread routine creates a CSR Thread object for
 * an NT Thread which is not part of the current NT Process.
 *
 * @param hThread
 *        Handle to an existing NT Thread to which to associate this
 *        CSR Thread.
 *
 * @param ClientId
 *        Pointer to the Client ID structure of the NT Thread to associate
 *        with this CSR Thread.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrCreateRemoteThread(IN HANDLE hThread, IN PCLIENT_ID ClientId)
{
    NTSTATUS Status;
    HANDLE ThreadHandle;
    PCSR_THREAD CsrThread;
    PCSR_PROCESS CsrProcess;
    KERNEL_USER_TIMES KernelTimes;

    /* Get the Thread Create Time */
    Status = NtQueryInformationThread(hThread, ThreadTimes, &KernelTimes,
				      sizeof(KernelTimes), NULL);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Failed to query thread times: %x\n", Status);
	return Status;
    }

    /* Lock the Owner Process */
    Status = CsrLockProcessByClientId(ClientId->UniqueProcess, &CsrProcess);
    if (!NT_SUCCESS(Status)) {
	DPRINT1("No known process for %p\n", ClientId->UniqueProcess);
	return Status;
    }

    /* Make sure the thread didn't terminate */
    if (KernelTimes.ExitTime.QuadPart) {
	/* Unlock the process and return */
	CsrUnlockProcess(CsrProcess);
	DPRINT1("Dead thread: %I64x\n", KernelTimes.ExitTime.QuadPart);
	return STATUS_THREAD_IS_TERMINATING;
    }

    /* Allocate a CSR Thread Structure */
    CsrThread = CsrpAllocateClientThread(CsrProcess);
    if (!CsrThread) {
	DPRINT1("CSRSRV: %s: out of memory!\n", __FUNCTION__);
	CsrUnlockProcess(CsrProcess);
	return STATUS_NO_MEMORY;
    }

    /* Duplicate the Thread Handle */
    Status = NtDuplicateObject(NtCurrentProcess(), hThread, NtCurrentProcess(),
			       &ThreadHandle, 0, 0, DUPLICATE_SAME_ACCESS);
    /* Allow failure */
    if (!NT_SUCCESS(Status)) {
	DPRINT1("Thread duplication failed: %x\n", Status);
	ThreadHandle = hThread;
    }

    /* Save the data we have */
    CsrThread->CreateTime = KernelTimes.CreateTime;
    CsrThread->ClientId = *ClientId;
    CsrThread->ThreadHandle = ThreadHandle;
    CsrpProtectHandle(ThreadHandle);
    CsrThread->Flags = 0;

    /* Insert the Thread into the Process */
    Status = CsrpInsertClientThread(CsrProcess, CsrThread);
    if (!NT_SUCCESS(Status)) {
	/* Bail out */
	CsrpUnProtectHandle(CsrThread->ThreadHandle);
	if (CsrThread->ThreadHandle != hThread)
	    NtClose(CsrThread->ThreadHandle);
	CsrUnlockProcess(CsrProcess);
	CsrpDeallocateClientThread(CsrThread);
	return Status;
    }

    /* Release the lock and return */
    CsrUnlockProcess(CsrProcess);
    return STATUS_SUCCESS;
}

/*++
 * @name CsrCreateThread
 * @implemented NT4
 *
 * The CsrCreateThread routine creates a CSR Thread object for an NT Thread.
 *
 * @param CsrProcess
 *        Pointer to the CSR Process which will contain the CSR Thread.
 *
 * @param hThread
 *        Handle to an existing NT Thread to which to associate this
 *        CSR Thread.
 *
 * @param ClientId
 *        Pointer to the Client ID structure of the NT Thread to associate
 *        with this CSR Thread.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrCreateThread(IN PCSR_PROCESS CsrProcess, IN HANDLE hThread,
			       IN PCLIENT_ID ClientId, IN BOOLEAN HaveClient)
{
    NTSTATUS Status;
    PCSR_THREAD CsrThread, CurrentThread;
    PCSR_PROCESS CurrentProcess;
    CLIENT_ID CurrentCid;
    KERNEL_USER_TIMES KernelTimes;

    if (HaveClient) {
	/* Get the current thread and CID */
	CurrentThread = CsrGetClientThread();
	CurrentCid = CurrentThread->ClientId;

	/* Acquire the Process Lock */
	CsrAcquireProcessLock();

	/* Get the current Process and make sure the Thread is valid with this CID */
	CurrentThread = CsrpLocateClientThreadByThreadId(&CurrentProcess, &CurrentCid);

	/* Something is wrong if we get an empty thread back */
	if (!CurrentThread) {
	    DPRINT1("CSRSRV: %s: invalid thread!\n", __FUNCTION__);
	    CsrReleaseProcessLock();
	    return STATUS_THREAD_IS_TERMINATING;
	}
    } else {
	/* Acquire the Process Lock */
	CsrAcquireProcessLock();
    }

    /* Get the Thread Create Time */
    Status = NtQueryInformationThread(hThread, ThreadTimes, &KernelTimes,
				      sizeof(KernelTimes), NULL);
    if (!NT_SUCCESS(Status)) {
	CsrReleaseProcessLock();
	return Status;
    }

    /* Allocate a CSR Thread Structure */
    CsrThread = CsrpAllocateClientThread(CsrProcess);
    if (!CsrThread) {
	DPRINT1("CSRSRV: %s: out of memory!\n", __FUNCTION__);
	CsrReleaseProcessLock();
	return STATUS_NO_MEMORY;
    }

    /* Save the data we have */
    CsrThread->CreateTime = KernelTimes.CreateTime;
    CsrThread->ClientId = *ClientId;
    CsrThread->ThreadHandle = hThread;
    CsrpProtectHandle(hThread);
    CsrThread->Flags = 0;

    /* Insert the Thread into the Process */
    Status = CsrpInsertClientThread(CsrProcess, CsrThread);
    if (!NT_SUCCESS(Status)) {
	/* Bail out */
	CsrpUnProtectHandle(CsrThread->ThreadHandle);
	CsrUnlockProcess(CsrProcess);
	CsrpDeallocateClientThread(CsrThread);
	return Status;
    }

    /* Release the lock and return */
    CsrReleaseProcessLock();

    return STATUS_SUCCESS;
}

/*++
 * @name CsrDereferenceThread
 * @implemented NT4
 *
 * The CsrDereferenceThread routine removes a reference from a CSR Thread.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread to dereference.
 *
 * @return None.
 *
 * @remarks If the reference count has reached zero (ie: the CSR Thread has
 *          no more active references), it will be deleted.
 *
 *--*/
NTAPI VOID CsrDereferenceThread(IN PCSR_THREAD CsrThread)
{
    /* Acquire process lock */
    CsrAcquireProcessLock();

    /* Decrease reference count */
    ASSERT(CsrThread->ReferenceCount > 0);
    if ((--CsrThread->ReferenceCount) == 0) {
	/* Call the generic cleanup code */
	CsrpThreadRefcountZero(CsrThread);
    } else {
	/* Just release the lock */
	CsrReleaseProcessLock();
    }
}

/*++
 * @name CsrDestroyThread
 * @implemented NT4
 *
 * The CsrDestroyThread routine destroys the CSR Thread corresponding to
 * a given Thread ID.
 *
 * @param Cid
 *        Pointer to the Client ID Structure corresponding to the CSR
 *        Thread which is about to be destroyed.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_THREAD_IS_TERMINATING
 *         if the CSR Thread is already terminating.
 *
 * @remarks None.
 *
 *--*/
NTAPI NTSTATUS CsrDestroyThread(IN PCLIENT_ID Cid)
{
    CLIENT_ID ClientId = *Cid;
    PCSR_THREAD CsrThread;
    PCSR_PROCESS CsrProcess;

    /* Acquire lock */
    CsrAcquireProcessLock();

    /* Find the thread */
    CsrThread = CsrpLocateClientThreadByThreadId(&CsrProcess, &ClientId);

    /* Make sure we got one back, and that it's not already gone */
    if (!CsrThread || (CsrThread->Flags & CsrThreadTerminated)) {
	/* Release the lock and return failure */
	CsrReleaseProcessLock();
	return STATUS_THREAD_IS_TERMINATING;
    }

    /* Set the terminated flag */
    CsrThread->Flags |= CsrThreadTerminated;

    /* Dereference the thread */
    CsrpLockedDereferenceClientThread(CsrThread);

    /* Release the Process Lock and return success */
    CsrReleaseProcessLock();
    return STATUS_SUCCESS;
}

/*++
 * @name CsrLockThreadByClientId
 * @implemented NT4
 *
 * The CsrLockThreadByClientId routine locks the CSR Thread corresponding
 * to the given Thread ID and optionally returns it.
 *
 * @param Tid
 *        Thread ID corresponding to the CSR Thread which will be locked.
 *
 * @param CsrThread
 *        Optional pointer to a CSR Thread pointer which will hold the
 *        CSR Thread corresponding to the given Thread ID.
 *
 * @return STATUS_SUCCESS in case of success, STATUS_UNSUCCESSFUL otherwise.
 *
 * @remarks Locking a CSR Thread is defined as acquiring an extra
 *          reference to it and returning with the Process Lock held.
 *
 *--*/
NTAPI NTSTATUS CsrLockThreadByClientId(IN HANDLE Tid, OUT PCSR_THREAD *CsrThread)
{
    PLIST_ENTRY NextEntry;
    PCSR_THREAD CurrentThread = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG i;

    /* Acquire the lock */
    CsrAcquireProcessLock();

    /* Assume failure */
    ASSERT(CsrThread != NULL);
    *CsrThread = NULL;

    /* Convert to Hash */
    i = CsrpHashThread(Tid);

    /* Setup the List Pointers */
    NextEntry = CsrSrv->ClientThreadHashTable[i].Flink;

    /* Start Loop */
    while (NextEntry != &CsrSrv->ClientThreadHashTable[i]) {
	/* Get the Thread */
	CurrentThread = CONTAINING_RECORD(NextEntry, CSR_THREAD, HashLinks);

	/* Check for TID Match */
	if ((CurrentThread->ClientId.UniqueThread == Tid) &&
	    (CurrentThread->Flags & CsrThreadTerminated) == 0) {
	    /* Get out of here */
	    break;
	}

	/* Move to the next entry */
	NextEntry = NextEntry->Flink;
    }

    /* Nothing found if we got back to the list */
    if (NextEntry == &CsrSrv->ClientThreadHashTable[i])
	CurrentThread = NULL;

    /* Did the loop find something? */
    if (CurrentThread) {
	/* Reference the found thread */
	Status = STATUS_SUCCESS;
	CsrpLockedReferenceClientThread(CurrentThread);
	*CsrThread = CurrentThread;
    } else {
	/* Nothing found, release the lock */
	Status = STATUS_UNSUCCESSFUL;
	CsrReleaseProcessLock();
    }

    /* Return the status */
    return Status;
}

/*++
 * @name CsrReferenceThread
 * @implemented NT4
 *
 * The CsrReferenceThread routine increases the active reference count of
 * a CSR Thread.
 *
 * @param CsrThread
 *        Pointer to the CSR Thread whose reference count will be increased.
 *
 * @return None.
 *
 * @remarks Do not use this routine if the Process Lock is already held.
 *
 *--*/
NTAPI VOID CsrReferenceThread(IN PCSR_THREAD CsrThread)
{
    /* Acquire process lock */
    CsrAcquireProcessLock();

    /* Sanity checks */
    ASSERT((CsrThread->Flags & CsrThreadTerminated) == 0);
    ASSERT(CsrThread->ReferenceCount != 0);

    /* Increment reference count */
    CsrThread->ReferenceCount++;

    /* Release the lock */
    CsrReleaseProcessLock();
}

/*++
 * @name CsrUnlockThread
 * @implemented NT4
 *
 * The CsrUnlockThread undoes a previous CsrLockThreadByClientId operation.
 *
 * @param CsrThread
 *        Pointer to a previously locked CSR Thread.
 *
 * @return STATUS_SUCCESS.
 *
 * @remarks This routine must be called with the Process Lock held.
 *
 *--*/
NTAPI NTSTATUS CsrUnlockThread(IN PCSR_THREAD CsrThread)
{
    /* Dereference the Thread */
    ASSERT(CsrpProcessStructureListLocked());
    CsrpLockedDereferenceClientThread(CsrThread);

    /* Release the lock and return */
    CsrReleaseProcessLock();
    return STATUS_SUCCESS;
}

/* EOF */
