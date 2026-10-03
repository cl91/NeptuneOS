#include "k32.h"

/***********************************************************************
 *           CreateThreadpoolTimer   (kernelbase.@)
 */
WINAPI DECLSPEC_HOTPATCH PTP_TIMER CreateThreadpoolTimer(PTP_TIMER_CALLBACK Callback,
							 PVOID Userdata,
							 TP_CALLBACK_ENVIRON *Environment)
{
    TP_TIMER *Timer;

    NTSTATUS Status = TpAllocTimer(&Timer, Callback, Userdata, Environment);
    if (!NT_SUCCESS(Status)) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }

    return Timer;
}

static WINAPI void TpIoCallback(TP_CALLBACK_INSTANCE *Instance, void *Userdata,
				  void *Cvalue, IO_STATUS_BLOCK *Iosb, TP_IO *Io)
{
    PTP_WIN32_IO_CALLBACK Callback = *(void **)Io;
    Callback(Instance, Userdata, Cvalue, RtlNtStatusToDosError(Iosb->Status),
	     Iosb->Information, Io);
}

/***********************************************************************
 *           CreateThreadpoolIo   (kernelbase.@)
 */
WINAPI DECLSPEC_HOTPATCH PTP_IO CreateThreadpoolIo(HANDLE Handle,
						   PTP_WIN32_IO_CALLBACK Callback,
						   PVOID Userdata,
						   TP_CALLBACK_ENVIRON *Environment)
{
    TP_IO *Io;

    NTSTATUS Status = TpAllocIoCompletion(&Io, Handle, TpIoCallback, Userdata,
					  Environment);
    *(void **)Io = Callback; /* ntdll leaves us space to store our callback at the
				beginning of TP_IO struct */
    if (!NT_SUCCESS(Status)) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }

    return Io;
}

/***********************************************************************
 *           CreateThreadpoolWait   (kernelbase.@)
 */
WINAPI DECLSPEC_HOTPATCH PTP_WAIT CreateThreadpoolWait(PTP_WAIT_CALLBACK Callback,
						       PVOID Userdata,
						       TP_CALLBACK_ENVIRON *Environment)
{
    TP_WAIT *Wait;

    NTSTATUS Status = TpAllocWait(&Wait, Callback, Userdata, Environment);
    if (!NT_SUCCESS(Status)) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }

    return Wait;
}

/***********************************************************************
 *           CreateThreadpoolWork   (kernelbase.@)
 */
WINAPI DECLSPEC_HOTPATCH PTP_WORK CreateThreadpoolWork(PTP_WORK_CALLBACK Callback,
						       PVOID Userdata,
						       TP_CALLBACK_ENVIRON *Environment)
{
    TP_WORK *Work;

    NTSTATUS Status = TpAllocWork(&Work, Callback, Userdata, Environment);
    if (!NT_SUCCESS(Status)) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }
    return Work;
}

/***********************************************************************
 *           TrySubmitThreadpoolCallback   (kernelbase.@)
 */
WINAPI DECLSPEC_HOTPATCH BOOL TrySubmitThreadpoolCallback(
    PTP_SIMPLE_CALLBACK Callback, PVOID Userdata, TP_CALLBACK_ENVIRON *Environment)
{
    NTSTATUS Status = TpSimpleTryPost(Callback, Userdata, Environment);
    if (!NT_SUCCESS(Status)) {
	SetLastError(RtlNtStatusToDosError(Status));
	return FALSE;
    }

    return TRUE;
}

/***********************************************************************
 *           CreateThreadpoolCleanupGroup   (kernelbase.@)
 */
WINAPI DECLSPEC_HOTPATCH PTP_CLEANUP_GROUP CreateThreadpoolCleanupGroup(void)
{
    TP_CLEANUP_GROUP *Group;
    NTSTATUS Status = TpAllocCleanupGroup(&Group);

    if (!NT_SUCCESS(Status)) {
	SetLastError(RtlNtStatusToDosError(Status));
	return NULL;
    }

    return Group;
}

/***********************************************************************
 *           CreateThreadpool   (kernelbase.@)
 */
WINAPI DECLSPEC_HOTPATCH PTP_POOL CreateThreadpool(void *Reserved)
{
    TP_POOL *Pool = NULL;
    NTSTATUS Status = TpAllocPool(&Pool, Reserved);

    if (!NT_SUCCESS(Status)) {
	SetLastError(RtlNtStatusToDosError(Status));
	return NULL;
    }
    return Pool;
}
