#include "rtlp.h"

/******************************************************************
 *              RtlRunOnceInitialize (NTDLL.@)
 */
NTAPI VOID RtlRunOnceInitialize(OUT PRTL_RUN_ONCE RunOnce)
{
    RunOnce->Ptr = NULL;
}

/******************************************************************
 *              RtlRunOnceBeginInitialize (NTDLL.@)
 */
NTAPI NTSTATUS RtlRunOnceBeginInitialize(IN OUT PRTL_RUN_ONCE RunOnce, IN ULONG Flags,
					 OUT OPTIONAL PVOID *Context)
{
    if (Flags & RTL_RUN_ONCE_CHECK_ONLY) {
	ULONG_PTR Val = (ULONG_PTR)RunOnce->Ptr;

	if (Flags & RTL_RUN_ONCE_ASYNC)
	    return STATUS_INVALID_PARAMETER;
	if ((Val & 3) != 2)
	    return STATUS_UNSUCCESSFUL;
	if (Context)
	    *Context = (void *)(Val & ~3);
	return STATUS_SUCCESS;
    }

    for (;;) {
	ULONG_PTR Next, Val = (ULONG_PTR)RunOnce->Ptr;

	switch (Val & 3) {
	case 0: /* first time */
	    if (!InterlockedCompareExchangePointer(&RunOnce->Ptr,
						   (Flags & RTL_RUN_ONCE_ASYNC) ? (void *)3 :
						   (void *)1, 0))
		return STATUS_PENDING;
	    break;

	case 1: /* in progress, wait */
	    if (Flags & RTL_RUN_ONCE_ASYNC)
		return STATUS_INVALID_PARAMETER;
	    Next = Val & ~3;
	    if (InterlockedCompareExchangePointer(&RunOnce->Ptr, (void *)((ULONG_PTR)&Next | 1),
						  (void *)Val) == (void *)Val)
		NtWaitForKeyedEvent(0, &Next, FALSE, NULL);
	    break;

	case 2: /* done */
	    if (Context)
		*Context = (void *)(Val & ~3);
	    return STATUS_SUCCESS;

	case 3: /* in progress, async */
	    if (!(Flags & RTL_RUN_ONCE_ASYNC))
		return STATUS_INVALID_PARAMETER;
	    return STATUS_PENDING;
	}
    }
}

/******************************************************************
 *              RtlRunOnceComplete (NTDLL.@)
 */
NTAPI NTSTATUS RtlRunOnceComplete(IN OUT PRTL_RUN_ONCE RunOnce, IN ULONG Flags,
				  IN OPTIONAL PVOID Context)
{
    if ((ULONG_PTR)Context & 3)
	return STATUS_INVALID_PARAMETER;

    if (Flags & RTL_RUN_ONCE_INIT_FAILED) {
	if (Context)
	    return STATUS_INVALID_PARAMETER;
	if (Flags & RTL_RUN_ONCE_ASYNC)
	    return STATUS_INVALID_PARAMETER;
    } else
	Context = (void *)((ULONG_PTR)Context | 2);

    for (;;) {
	ULONG_PTR Val = (ULONG_PTR)RunOnce->Ptr;

	switch (Val & 3) {
	case 1: /* in progress */
	    if (InterlockedCompareExchangePointer(&RunOnce->Ptr, Context, (void *)Val) !=
		(void *)Val)
		break;
	    Val &= ~3;
	    while (Val) {
		ULONG_PTR Next = *(ULONG_PTR *)Val;
		NtReleaseKeyedEvent(0, (void *)Val, FALSE, NULL);
		Val = Next;
	    }
	    return STATUS_SUCCESS;

	case 3: /* in progress, async */
	    if (!(Flags & RTL_RUN_ONCE_ASYNC))
		return STATUS_INVALID_PARAMETER;
	    if (InterlockedCompareExchangePointer(&RunOnce->Ptr, Context, (void *)Val) !=
		(void *)Val)
		break;
	    return STATUS_SUCCESS;

	default:
	    return STATUS_UNSUCCESSFUL;
	}
    }
}

/******************************************************************
 *              RtlRunOnceExecuteOnce (NTDLL.@)
 */
NTAPI NTSTATUS RtlRunOnceExecuteOnce(IN OUT PRTL_RUN_ONCE RunOnce,
				     IN PRTL_RUN_ONCE_INIT_FN InitFn,
				     IN OUT OPTIONAL PVOID Parameter,
				     OUT OPTIONAL PVOID *Context)
{
    DWORD Ret = RtlRunOnceBeginInitialize(RunOnce, 0, Context);

    if (Ret != STATUS_PENDING)
	return Ret;

    if (!InitFn(RunOnce, Parameter, Context)) {
	RtlRunOnceComplete(RunOnce, RTL_RUN_ONCE_INIT_FAILED, NULL);
	return STATUS_UNSUCCESSFUL;
    }

    return RtlRunOnceComplete(RunOnce, 0, Context ? *Context : NULL);
}
