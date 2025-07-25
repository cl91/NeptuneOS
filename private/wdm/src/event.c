#include <wdmp.h>

/*
 * Initialize an event.
 *
 * This routine can be called at any IRQL.
 */
NTAPI VOID KeInitializeEvent(OUT PKEVENT Event,
			     IN EVENT_TYPE Type,
			     IN BOOLEAN InitialState)
{
    RtlZeroMemory(Event, sizeof(KEVENT));
    ObInitializeObject(&Event->Header, CLIENT_OBJECT_EVENT, KEVENT);
    Event->Header.Type = Type;
    InitializeListHead(&Event->Header.EnvList);
    if (InitialState) {
	KeSetEvent(Event);
    }
}

/*
 * Set the given waitable object to the signaled state.
 *
 * This routine can be called at any IRQL. You must not have acquired the
 * DPC mutex before calling this routine.
 */
BOOLEAN KiSignalWaitableObject(IN PWAITABLE_OBJECT_HEADER Object,
			       IN BOOLEAN AcquireLock)
{
    if (AcquireLock) {
	IoAcquireDpcMutex();
    }
    BOOLEAN PreviousState = Object->Signaled;
    if (PreviousState) {
	goto out;
    }
    Object->Signaled = TRUE;
    assert(!ListHasEntry(&IopSignaledObjectList, &Object->QueueListEntry));
    InsertTailList(&IopSignaledObjectList, &Object->QueueListEntry);
out:
    if (AcquireLock) {
	IoReleaseDpcMutex();
    }
    NtCurrentTeb()->Wdm.EventSignaled = TRUE;
    return PreviousState;
}

BOOLEAN KiCancelWaitableObject(IN PWAITABLE_OBJECT_HEADER Object,
			       IN BOOLEAN AcquireLock)
{
    if (AcquireLock) {
	IoAcquireDpcMutex();
    }
    LONG PreviousState = Object->Signaled;
    if (!PreviousState) {
	goto out;
    }
    Object->Signaled = FALSE;
    assert(ListHasEntry(&IopSignaledObjectList, &Object->QueueListEntry));
    RemoveEntryList(&Object->QueueListEntry);
out:
    if (AcquireLock) {
	IoReleaseDpcMutex();
    }
    return PreviousState;
}

/*
 * Set the given KEVENT object to the signaled state.
 *
 * Porting guide: remove the Increment and Wait arguments in Windows/ReactOS.
 * They are meaningless in Neptune OS due to architectural differences.
 *
 * This routine can be called at any IRQL.
 */
NTAPI LONG KeSetEvent(IN PKEVENT Event)
{
    return KiSignalWaitableObject(&Event->Header, TRUE);
}

NTAPI LONG KeResetEvent(IN PKEVENT Event)
{
    return KiCancelWaitableObject(&Event->Header, TRUE);
}

NTAPI VOID KeClearEvent(IN PKEVENT Event)
{
    KeResetEvent(Event);
}

NTAPI NTSTATUS KeWaitForSingleObject(IN PVOID Object,
				     IN KWAIT_REASON WaitReason,
				     IN KPROCESSOR_MODE WaitMode,
				     IN BOOLEAN Alertable,
				     IN PLARGE_INTEGER Timeout)
{
    /* Object must be waitable. */
    PWAITABLE_OBJECT_HEADER Header = Object;
    assert(ObjectTypeIsWaitable(Header->Header.Type));

    /* KeWaitForSingleObject must always be called in a context where we are
     * allowed to sleep. */
    PAGED_CODE();
    assert(KiCurrentCoroutineStackTop);

    /* If the object has already been signaled, don't wait and simply return. */
    if (Header->Signaled) {
	return STATUS_SUCCESS;
    }

    /* Add the current execution environment to the dispatcher object
     * so we can wake it up when the dispatcher object is signaled. */
    assert(IopCurrentEnv);
    assert(!ListHasEntry(&Header->EnvList, &IopCurrentEnv->EventLink));
    InsertHeadList(&Header->EnvList, &IopCurrentEnv->EventLink);

    DbgTrace("Suspending execution environment %p coroutine stack %p waiting for object %p\n",
	     IopCurrentEnv, KiCurrentCoroutineStackTop, Object);
    /* Yield the current coroutine to the main thread. The control flow will
     * return to either KiStartCoroutine or KiResumeCoroutine. */
    KiYieldCoroutine();

    /* Where the coroutine resumes, this is where the control jumps to. We
     * simply return success. */
    return STATUS_SUCCESS;
}
