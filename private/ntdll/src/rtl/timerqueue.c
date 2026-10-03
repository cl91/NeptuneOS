/*
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS system libraries
 * PURPOSE:           Timer Queue implementation
 * FILE:              lib/rtl/timerqueue.c
 * PROGRAMMER:
 */

/* INCLUDES *****************************************************************/

#include "rtlp.h"

/* From winbase.h */
#define INFINITE 0xFFFFFFFFUL

/* FUNCTIONS ***************************************************************/

static inline PLARGE_INTEGER GetNtTimeout(PLARGE_INTEGER pTime, ULONG Timeout)
{
    if (Timeout == INFINITE)
	return NULL;
    pTime->QuadPart = (ULONGLONG)Timeout * -10000;
    return pTime;
}

struct _TIMER_QUEUE;
typedef struct _TIMER {
    struct _TIMER_QUEUE *Queue;
    LIST_ENTRY Entry;
    ULONG Runcount; /* number of callbacks pending execution */
    WAITORTIMERCALLBACKFUNC Callback;
    PVOID Param;
    DWORD Period;
    ULONG Flags;
    ULONGLONG Expire;
    BOOL Destroy; /* timer should be deleted; once set, never unset */
    HANDLE Event; /* removal event */
} TIMER, *PTIMER;

typedef struct _TIMER_QUEUE {
    DWORD Magic;
    RTL_CRITICAL_SECTION Lock;
    LIST_ENTRY Timers; /* sorted by expiration time */
    BOOL Quit; /* queue should be deleted; once set, never unset */
    HANDLE Event;
    HANDLE Thread;
} TIMER_QUEUE, *PTIMER_QUEUE;

#define EXPIRE_NEVER (~(ULONGLONG)0)
#define TIMER_QUEUE_MAGIC 0x516d6954 /* TimQ */

static void QueueRemoveTimer(struct _TIMER *t)
{
    /* We MUST hold the queue cs while calling this function.  This ensures
       that we cannot queue another callback for this timer.  The runcount
       being zero makes sure we don't have any already queued.  */
    PTIMER_QUEUE q = t->Queue;

    assert(t->Runcount == 0);
    assert(t->Destroy);

    RemoveEntryList(&t->Entry);
    if (t->Event)
	NtSetEvent(t->Event, NULL);
    RtlFreeHeap(RtlGetProcessHeap(), 0, t);

    if (q->Quit && IsListEmpty(&q->Timers))
	NtSetEvent(q->Event, NULL);
}

static void TimerCleanupCallback(struct _TIMER *t)
{
    PTIMER_QUEUE q = t->Queue;
    RtlEnterCriticalSection(&q->Lock);

    assert(0 < t->Runcount);
    --t->Runcount;

    if (t->Destroy && t->Runcount == 0)
	QueueRemoveTimer(t);

    RtlLeaveCriticalSection(&q->Lock);
}

static NTAPI VOID TimerCallbackWrapper(LPVOID p)
{
    struct _TIMER *t = p;
    t->Callback(t->Param, TRUE);
    TimerCleanupCallback(t);
}

static inline ULONGLONG QueueCurrentTime(void)
{
    LARGE_INTEGER Now, Freq;
    NtQueryPerformanceCounter(&Now, &Freq);
    return Now.QuadPart * 1000 / Freq.QuadPart;
}

static void QueueAddTimer(struct _TIMER *t, ULONGLONG Time, BOOL SetEvent)
{
    /* We MUST hold the queue cs while calling this function.  */
    PTIMER_QUEUE q = t->Queue;
    PLIST_ENTRY Ptr = &q->Timers;

    assert(!q->Quit || (t->Destroy && Time == EXPIRE_NEVER));

    if (Time != EXPIRE_NEVER)
	LoopOverList(Cur, &q->Timers, TIMER, Entry) {
	    if (Time < Cur->Expire) {
		Ptr = &Cur->Entry;
		break;
	    }
	}
    InsertTailList(Ptr, &t->Entry);

    t->Expire = Time;

    /* If we insert at the head of the list, we need to expire sooner
       than expected.  */
    if (SetEvent && &t->Entry == q->Timers.Flink)
	NtSetEvent(q->Event, NULL);
}

static inline void QueueMoveTimer(struct _TIMER *t, ULONGLONG Time, BOOL SetEvent)
{
    /* We MUST hold the queue cs while calling this function.  */
    RemoveEntryList(&t->Entry);
    QueueAddTimer(t, Time, SetEvent);
}

static void QueueTimerExpire(PTIMER_QUEUE q)
{
    struct _TIMER *t = NULL;

    RtlEnterCriticalSection(&q->Lock);
    if (!IsListEmpty(&q->Timers)) {
	ULONGLONG Now, Next;
	t = GetNextEntryList(&q->Timers, TIMER, Entry, &q->Timers);
	if (!t->Destroy && t->Expire <= ((Now = QueueCurrentTime()))) {
	    ++t->Runcount;
	    if (t->Period) {
		Next = t->Expire + t->Period;
		/* avoid trigger cascade if overloaded / hibernated */
		if (Next < Now)
		    Next = Now + t->Period;
	    } else
		Next = EXPIRE_NEVER;
	    QueueMoveTimer(t, Next, FALSE);
	} else
	    t = NULL;
    }
    RtlLeaveCriticalSection(&q->Lock);

    if (t) {
	if (t->Flags & WT_EXECUTEINTIMERTHREAD)
	    TimerCallbackWrapper(t);
	else {
	    ULONG Flags = (t->Flags &
			   (WT_EXECUTEINIOTHREAD | WT_EXECUTEINPERSISTENTTHREAD |
			    WT_EXECUTELONGFUNCTION | WT_TRANSFER_IMPERSONATION));
	    NTSTATUS Status = RtlQueueWorkItem(TimerCallbackWrapper, t, Flags);
	    if (Status != STATUS_SUCCESS)
		TimerCleanupCallback(t);
	}
    }
}

static ULONG QueueGetTimeout(PTIMER_QUEUE q)
{
    struct _TIMER *t;
    ULONG Timeout = INFINITE;

    RtlEnterCriticalSection(&q->Lock);
    if (!IsListEmpty(&q->Timers)) {
	t = GetNextEntryList(&q->Timers, TIMER, Entry, &q->Timers);
	assert(!t->Destroy || t->Expire == EXPIRE_NEVER);

	if (t->Expire != EXPIRE_NEVER) {
	    ULONGLONG Time = QueueCurrentTime();
	    Timeout = t->Expire < Time ? 0 : (ULONG)(t->Expire - Time);
	}
    }
    RtlLeaveCriticalSection(&q->Lock);

    return Timeout;
}

static NTAPI DWORD TimerQueueThreadProc(LPVOID p)
{
    PTIMER_QUEUE q = p;
    ULONG TimeoutMs;

    TimeoutMs = INFINITE;
    for (;;) {
	LARGE_INTEGER Timeout;
	NTSTATUS Status;
	BOOL Done = FALSE;

	Status = NtWaitForSingleObject(q->Event, FALSE,
				       GetNtTimeout(&Timeout, TimeoutMs));

	if (Status == STATUS_WAIT_0) {
	    /* There are two possible ways to trigger the event.  Either
	       we are quitting and the last timer got removed, or a new
	       timer got put at the head of the list so we need to adjust
	       our timeout.  */
	    RtlEnterCriticalSection(&q->Lock);
	    if (q->Quit && IsListEmpty(&q->Timers))
		Done = TRUE;
	    RtlLeaveCriticalSection(&q->Lock);
	} else if (Status == STATUS_TIMEOUT)
	    QueueTimerExpire(q);

	if (Done)
	    break;

	TimeoutMs = QueueGetTimeout(q);
    }

    NtClose(q->Event);
    RtlDeleteCriticalSection(&q->Lock);
    q->Magic = 0;
    RtlFreeHeap(RtlGetProcessHeap(), 0, q);
    RtlpExitThreadFunc(STATUS_SUCCESS);
    return 0;
}

static void QueueDestroyTimer(struct _TIMER *t)
{
    /* We MUST hold the queue cs while calling this function.  */
    t->Destroy = TRUE;
    if (t->Runcount == 0)
	/* Ensure a timer is promptly removed.  If callbacks are pending,
	   it will be removed after the last one finishes by the callback
	   cleanup wrapper.  */
	QueueRemoveTimer(t);
    else
	/* Make sure no destroyed timer masks an active timer at the head
	   of the sorted list.  */
	QueueMoveTimer(t, EXPIRE_NEVER, FALSE);
}

/***********************************************************************
 *              RtlCreateTimerQueue   (NTDLL.@)
 *
 * Creates a timer queue object and returns a handle to it.
 *
 * PARAMS
 *  NewTimerQueue [O] The newly created queue.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 */
NTAPI NTSTATUS RtlCreateTimerQueue(PHANDLE NewTimerQueue)
{
    NTSTATUS Status;
    PTIMER_QUEUE q = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof *q);
    if (!q)
	return STATUS_NO_MEMORY;

    RtlInitializeCriticalSection(&q->Lock);
    InitializeListHead(&q->Timers);
    q->Quit = FALSE;
    q->Magic = TIMER_QUEUE_MAGIC;
    Status = NtCreateEvent(&q->Event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent,
			   FALSE);
    if (Status != STATUS_SUCCESS) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, q);
	return Status;
    }
    Status = RtlpStartThreadFunc(TimerQueueThreadProc, q, &q->Thread);
    if (Status != STATUS_SUCCESS) {
	NtClose(q->Event);
	RtlFreeHeap(RtlGetProcessHeap(), 0, q);
	return Status;
    }

    NtResumeThread(q->Thread, NULL);
    *NewTimerQueue = q;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *              RtlDeleteTimerQueueEx   (NTDLL.@)
 *
 * Deletes a timer queue object.
 *
 * PARAMS
 *  TimerQueue      [I] The timer queue to destroy.
 *  CompletionEvent [I] If NULL, return immediately.  If INVALID_HANDLE_VALUE,
 *                      wait until all timers are finished firing before
 *                      returning.  Otherwise, return immediately and set the
 *                      event when all timers are done.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS if synchronous, STATUS_PENDING if not.
 *  Failure: Any NTSTATUS code.
 */
NTAPI NTSTATUS RtlDeleteTimerQueueEx(HANDLE TimerQueue, HANDLE CompletionEvent)
{
    PTIMER_QUEUE q = TimerQueue;
    HANDLE Thread;
    NTSTATUS Status;

    if (!q || q->Magic != TIMER_QUEUE_MAGIC)
	return STATUS_INVALID_HANDLE;

    Thread = q->Thread;

    RtlEnterCriticalSection(&q->Lock);
    q->Quit = TRUE;
    if (!IsListEmpty(&q->Timers)) {
	/* When the last timer is removed, it will signal the timer thread to
	   exit...  */
	LoopOverList(t, &q->Timers, TIMER, Entry) {
	    QueueDestroyTimer(t);
	}
    } else {
	/* However if we have none, we must do it ourselves.  */
	NtSetEvent(q->Event, NULL);
    }
    RtlLeaveCriticalSection(&q->Lock);

    if (CompletionEvent == INVALID_HANDLE_VALUE) {
	NtWaitForSingleObject(Thread, FALSE, NULL);
	Status = STATUS_SUCCESS;
    } else {
	if (CompletionEvent) {
	    DPRINT1("asynchronous return on completion event unimplemented\n");
	    NtWaitForSingleObject(Thread, FALSE, NULL);
	    NtSetEvent(CompletionEvent, NULL);
	}
	Status = STATUS_PENDING;
    }

    NtClose(Thread);
    return Status;
}

static PTIMER_QUEUE GetTimerQueue(HANDLE TimerQueue)
{
    static PTIMER_QUEUE DefaultTimerQueue;

    if (TimerQueue)
	return TimerQueue;
    else {
	if (!DefaultTimerQueue) {
	    HANDLE q;
	    NTSTATUS Status = RtlCreateTimerQueue(&q);
	    if (Status == STATUS_SUCCESS) {
		PVOID p = InterlockedCompareExchangePointer((void **)&DefaultTimerQueue,
							    q, NULL);
		if (p)
		    /* Got beat to the punch.  */
		    RtlDeleteTimerQueueEx(q, NULL);
	    }
	}
	return DefaultTimerQueue;
    }
}

/***********************************************************************
 *              RtlCreateTimer   (NTDLL.@)
 *
 * Creates a new timer associated with the given queue.
 *
 * PARAMS
 *  NewTimer   [O] The newly created timer.
 *  TimerQueue [I] The queue to hold the timer.
 *  Callback   [I] The callback to fire.
 *  Parameter  [I] The argument for the callback.
 *  DueTime    [I] The delay, in milliseconds, before first firing the
 *                 timer.
 *  Period     [I] The period, in milliseconds, at which to fire the timer
 *                 after the first callback.  If zero, the timer will only
 *                 fire once.  It still needs to be deleted with
 *                 RtlDeleteTimer.
 * Flags       [I] Flags controlling the execution of the callback.  In
 *                 addition to the WT_* thread pool flags (see
 *                 RtlQueueWorkItem), WT_EXECUTEINTIMERTHREAD and
 *                 WT_EXECUTEONLYONCE are supported.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 */
NTAPI NTSTATUS RtlCreateTimer(HANDLE TimerQueue, PHANDLE NewTimer,
			       WAITORTIMERCALLBACKFUNC Callback, PVOID Parameter,
			       DWORD DueTime, DWORD Period, ULONG Flags)
{
    NTSTATUS Status;
    PTIMER t;
    PTIMER_QUEUE q = GetTimerQueue(TimerQueue);

    if (!q)
	return STATUS_NO_MEMORY;
    if (q->Magic != TIMER_QUEUE_MAGIC)
	return STATUS_INVALID_HANDLE;

    t = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof *t);
    if (!t)
	return STATUS_NO_MEMORY;

    t->Queue = q;
    t->Runcount = 0;
    t->Callback = Callback;
    t->Param = Parameter;
    t->Period = Period;
    t->Flags = Flags;
    t->Destroy = FALSE;
    t->Event = NULL;

    Status = STATUS_SUCCESS;
    RtlEnterCriticalSection(&q->Lock);
    if (q->Quit)
	Status = STATUS_INVALID_HANDLE;
    else
	QueueAddTimer(t, QueueCurrentTime() + DueTime, TRUE);
    RtlLeaveCriticalSection(&q->Lock);

    if (Status == STATUS_SUCCESS)
	*NewTimer = t;
    else
	RtlFreeHeap(RtlGetProcessHeap(), 0, t);

    return Status;
}

NTAPI NTSTATUS RtlSetTimer(HANDLE TimerQueue, PHANDLE NewTimer,
			   WAITORTIMERCALLBACKFUNC Callback, PVOID Parameter,
			   DWORD DueTime, DWORD Period, ULONG Flags)
{
    return RtlCreateTimer(TimerQueue, NewTimer, Callback, Parameter, DueTime, Period,
			  Flags);
}

/***********************************************************************
 *              RtlUpdateTimer   (NTDLL.@)
 *
 * Changes the time at which a timer expires.
 *
 * PARAMS
 *  TimerQueue [I] The queue that holds the timer.
 *  Timer      [I] The timer to update.
 *  DueTime    [I] The delay, in milliseconds, before next firing the timer.
 *  Period     [I] The period, in milliseconds, at which to fire the timer
 *                 after the first callback.  If zero, the timer will not
 *                 refire once.  It still needs to be deleted with
 *                 RtlDeleteTimer.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 */
NTAPI NTSTATUS RtlUpdateTimer(HANDLE TimerQueue, HANDLE Timer, DWORD DueTime,
			       DWORD Period)
{
    PTIMER t = Timer;
    PTIMER_QUEUE q = t->Queue;

    RtlEnterCriticalSection(&q->Lock);
    /* Can't change a timer if it was once-only or destroyed.  */
    if (t->Expire != EXPIRE_NEVER) {
	t->Period = Period;
	QueueMoveTimer(t, QueueCurrentTime() + DueTime, TRUE);
    }
    RtlLeaveCriticalSection(&q->Lock);

    return STATUS_SUCCESS;
}

/***********************************************************************
 *              RtlDeleteTimer   (NTDLL.@)
 *
 * Cancels a timer-queue timer.
 *
 * PARAMS
 *  TimerQueue      [I] The queue that holds the timer.
 *  Timer           [I] The timer to update.
 *  CompletionEvent [I] If NULL, return immediately.  If INVALID_HANDLE_VALUE,
 *                      wait until the timer is finished firing all pending
 *                      callbacks before returning.  Otherwise, return
 *                      immediately and set the timer is done.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS if the timer is done, STATUS_PENDING if not,
	     or if the completion event is NULL.
 *  Failure: Any NTSTATUS code.
 */
NTAPI NTSTATUS RtlDeleteTimer(HANDLE TimerQueue, HANDLE Timer, HANDLE CompletionEvent)
{
    PTIMER t = Timer;
    PTIMER_QUEUE q;
    NTSTATUS Status = STATUS_PENDING;
    HANDLE Event = NULL;

    if (!Timer)
	return STATUS_INVALID_PARAMETER_1;
    q = t->Queue;
    if (CompletionEvent == INVALID_HANDLE_VALUE) {
	Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent,
			       FALSE);
	if (Status == STATUS_SUCCESS)
	    Status = STATUS_PENDING;
    } else if (CompletionEvent)
	Event = CompletionEvent;

    RtlEnterCriticalSection(&q->Lock);
    t->Event = Event;
    if (t->Runcount == 0 && Event)
	Status = STATUS_SUCCESS;
    QueueDestroyTimer(t);
    RtlLeaveCriticalSection(&q->Lock);

    if (CompletionEvent == INVALID_HANDLE_VALUE && Event) {
	if (Status == STATUS_PENDING) {
	    NtWaitForSingleObject(Event, FALSE, NULL);
	    Status = STATUS_SUCCESS;
	}
	NtClose(Event);
    }

    return Status;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlCancelTimer(HANDLE TimerQueue, HANDLE Timer)
{
    return RtlDeleteTimer(TimerQueue, Timer, NULL);
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlDeleteTimerQueue(HANDLE TimerQueue)
{
    return RtlDeleteTimerQueueEx(TimerQueue, INVALID_HANDLE_VALUE);
}

/* EOF */
