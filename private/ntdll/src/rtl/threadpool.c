/*
 * Thread pooling
 *
 * Copyright (c) 2006 Robert Shearman
 * Copyright (c) 2014-2016 Sebastian Lackner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "rtlp.h"

#define TRACE(...) TRACE_(RTLTHREADPOOL, __VA_ARGS__)
#define FIXME(...) INFO_(RTLTHREADPOOL, __VA_ARGS__)
#define WARN(...) WARN_(RTLTHREADPOOL, __VA_ARGS__)
#define ERR(...) ERR_(RTLTHREADPOOL, __VA_ARGS__)

FORCEINLINE ULONG GetCurrentThreadId(VOID)
{
    return HandleToULong(NtCurrentTeb()->NtTib.ClientId.UniqueThread);
}

static NTSTATUS RtlpCreateNativeThread(PTHREAD_START_ROUTINE Function, PVOID Parameter,
				       SIZE_T StackReserve, SIZE_T StackCommit,
				       PHANDLE ThreadHandle)
{
    return RtlCreateUserThread(NtCurrentProcess(), NULL, TRUE, 0, StackReserve,
			       StackCommit, Function, Parameter, ThreadHandle, NULL);
}

static NTSTATUS NTAPI RtlpStartThread(PTHREAD_START_ROUTINE Function, PVOID Parameter,
				      PHANDLE ThreadHandle)
{
    return RtlpCreateNativeThread(Function, Parameter, 0, 0, ThreadHandle);
}

static NTSTATUS NTAPI RtlpExitThread(NTSTATUS ExitStatus)
{
    RtlExitUserThread(ExitStatus);
    return STATUS_SUCCESS;
}

PRTL_START_POOL_THREAD RtlpStartThreadFunc = RtlpStartThread;
PRTL_EXIT_POOL_THREAD RtlpExitThreadFunc = RtlpExitThread;

static NTSTATUS RtlpCreateThreadWithStack(PTHREAD_START_ROUTINE Function, PVOID Parameter,
					  SIZE_T StackReserve, SIZE_T StackCommit,
					  PHANDLE ThreadHandle)
{
    NTSTATUS Status;

    /* The callback ABI cannot carry stack sizes, so preserve them on the native path. */
    if (RtlpStartThreadFunc == RtlpStartThread)
	Status = RtlpCreateNativeThread(Function, Parameter, StackReserve, StackCommit,
					ThreadHandle);
    else
	Status = RtlpStartThreadFunc(Function, Parameter, ThreadHandle);
    if (!NT_SUCCESS(Status))
	return Status;

    Status = NtResumeThread(*ThreadHandle, NULL);
    if (!NT_SUCCESS(Status)) {
	NtTerminateThread(*ThreadHandle, Status);
	NtClose(*ThreadHandle);
	*ThreadHandle = NULL;
    }

    return Status;
}

static NTSTATUS RtlpCreateThread(PTHREAD_START_ROUTINE Function, PVOID Parameter,
				 PHANDLE ThreadHandle)
{
    return RtlpCreateThreadWithStack(Function, Parameter, 0, 0, ThreadHandle);
}

NTAPI NTSTATUS RtlSetThreadPoolStartFunc(PRTL_START_POOL_THREAD StartPoolThread,
					 PRTL_EXIT_POOL_THREAD ExitPoolThread)
{
    RtlpStartThreadFunc = StartPoolThread;
    RtlpExitThreadFunc = ExitPoolThread;
    return STATUS_SUCCESS;
}

/*
 * Legacy thread pooling API
 */

typedef struct _RTL_WORK_ITEM {
    WORKERCALLBACKFUNC Function;
    PVOID Context;
} RTL_WORK_ITEM, *PRTL_WORK_ITEM;

typedef enum _THREADPOOL_CALLBACK_TYPE {
    THREADPOOL_CALLBACK_SIMPLE,
    THREADPOOL_CALLBACK_WORK,
    THREADPOOL_CALLBACK_TIMER,
    THREADPOOL_CALLBACK_WAIT,
    THREADPOOL_CALLBACK_IO,
} THREADPOOL_CALLBACK_TYPE;

typedef VOID(NTAPI *PRTLP_THREADPOOL_CALLBACK_DISPATCHER)(
    PVOID Callback, ULONG_PTR Argument0, ULONG_PTR Argument1, ULONG_PTR Argument2,
    ULONG_PTR Argument3, ULONG_PTR Argument4);

static PRTLP_THREADPOOL_CALLBACK_DISPATCHER volatile ThreadPoolCallbackDispatcher;

NTAPI VOID
RtlpSetThreadPoolCallbackDispatcher(PRTLP_THREADPOOL_CALLBACK_DISPATCHER Dispatcher)
{
    InterlockedExchangePointer((PVOID volatile *)&ThreadPoolCallbackDispatcher,
			       (PVOID)Dispatcher);
}

NTAPI VOID RtlpCallWaitOrTimerCallback(WAITORTIMERCALLBACKFUNC Callback, PVOID Context,
				       BOOLEAN TimerOrWaitFired)
{
    PRTLP_THREADPOOL_CALLBACK_DISPATCHER Dispatcher;

    Dispatcher = (PRTLP_THREADPOOL_CALLBACK_DISPATCHER)InterlockedCompareExchangePointer(
	(PVOID volatile *)&ThreadPoolCallbackDispatcher, NULL, NULL);
    if (Dispatcher) {
	Dispatcher((PVOID)Callback, (ULONG_PTR)Context, TimerOrWaitFired, 0, 0, 0);
	return;
    }

    Callback(Context, TimerOrWaitFired);
}

NTAPI VOID RtlpCallWorkItemCallback(WORKERCALLBACKFUNC Callback, PVOID Context)
{
    PRTLP_THREADPOOL_CALLBACK_DISPATCHER Dispatcher;

    Dispatcher = (PRTLP_THREADPOOL_CALLBACK_DISPATCHER)InterlockedCompareExchangePointer(
	(PVOID volatile *)&ThreadPoolCallbackDispatcher, NULL, NULL);
    if (Dispatcher) {
	Dispatcher((PVOID)Callback, (ULONG_PTR)Context, 0, 0, 0, 0);
	return;
    }

    Callback(Context);
}

static VOID ThreadPoolCallCallback(THREADPOOL_CALLBACK_TYPE Type, PVOID Callback,
				   ULONG_PTR Argument0, ULONG_PTR Argument1,
				   ULONG_PTR Argument2, ULONG_PTR Argument3,
				   ULONG_PTR Argument4)
{
    PRTLP_THREADPOOL_CALLBACK_DISPATCHER Dispatcher;

    Dispatcher = (PRTLP_THREADPOOL_CALLBACK_DISPATCHER)InterlockedCompareExchangePointer(
	(PVOID volatile *)&ThreadPoolCallbackDispatcher, NULL, NULL);
    if (Dispatcher) {
	Dispatcher(Callback, Argument0, Argument1, Argument2, Argument3, Argument4);
	return;
    }

    switch (Type) {
    case THREADPOOL_CALLBACK_SIMPLE:
	((PTP_SIMPLE_CALLBACK)Callback)((PTP_CALLBACK_INSTANCE)Argument0,
					(PVOID)Argument1);
	break;
    case THREADPOOL_CALLBACK_WORK:
	((PTP_WORK_CALLBACK)Callback)((PTP_CALLBACK_INSTANCE)Argument0,
				      (PVOID)Argument1, (PTP_WORK)Argument2);
	break;
    case THREADPOOL_CALLBACK_TIMER:
	((PTP_TIMER_CALLBACK)Callback)((PTP_CALLBACK_INSTANCE)Argument0,
				       (PVOID)Argument1, (PTP_TIMER)Argument2);
	break;
    case THREADPOOL_CALLBACK_WAIT:
	((PTP_WAIT_CALLBACK)Callback)((PTP_CALLBACK_INSTANCE)Argument0,
				      (PVOID)Argument1, (PTP_WAIT)Argument2,
				      (TP_WAIT_RESULT)Argument3);
	break;
    case THREADPOOL_CALLBACK_IO:
	((PTP_IO_CALLBACK)Callback)((PTP_CALLBACK_INSTANCE)Argument0, (PVOID)Argument1,
				    (PVOID)Argument2, (PIO_STATUS_BLOCK)Argument3,
				    (PTP_IO)Argument4);
	break;
    }
}

#define EXPIRE_NEVER (~(ULONGLONG)0)
#define TIMER_QUEUE_MAGIC 0x516d6954 /* TimQ */

struct _TIMER_QUEUE;
typedef struct _TIMER {
    struct _TIMER_QUEUE *q;
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
    RTL_CRITICAL_SECTION Cs;
    LIST_ENTRY Timers; /* sorted by expiration time */
    BOOL Quit; /* queue should be deleted; once set, never unset */
    HANDLE Event;
    HANDLE Thread;
} TIMER_QUEUE, *PTIMER_QUEUE;

/*
 * Object-oriented thread pooling API
 */

#define THREADPOOL_WORKER_TIMEOUT 5000
#define MAXIMUM_WAITQUEUE_OBJECTS (MAXIMUM_WAIT_OBJECTS - 1)

/* internal threadpool representation */
typedef struct _THREAD_POOL {
    LONG Refcount;
    LONG Objcount;
    BOOL Shutdown;
    RTL_CRITICAL_SECTION Cs;
    /* Pools of work items, locked via .cs, order matches TP_CALLBACK_PRIORITY - high,
     * normal, low. */
    LIST_ENTRY Pools[3];
    RTL_CONDITION_VARIABLE UpdateEvent;
    /* information about worker threads, locked via .cs */
    int MaxWorkers;
    int MinWorkers;
    int NumWorkers;
    int NumBusyWorkers;
    HANDLE ComplPort;
    TP_POOL_STACK_INFORMATION StackInfo;
} THREAD_POOL, *PTHREAD_POOL;
typedef const THREAD_POOL *PCTHREAD_POOL;

typedef enum _THREAD_POOL_OBJECT_TYPE {
    TP_OBJECT_TYPE_SIMPLE,
    TP_OBJECT_TYPE_WORK,
    TP_OBJECT_TYPE_TIMER,
    TP_OBJECT_TYPE_WAIT,
    TP_OBJECT_TYPE_IO,
} THREAD_POOL_OBJECT_TYPE;

typedef struct _IO_COMPLETION {
    IO_STATUS_BLOCK Iosb;
    ULONG_PTR Cvalue;
} IO_COMPLETION, *PIO_COMPLETION;

/* Internal threadpool object representation */
typedef struct _THREAD_POOL_OBJECT {
    PVOID Win32Callback; /* leave space for kernelbase to store win32 callback */
    LONG Refcount;
    BOOL Shutdown;
    /* read-only information */
    THREAD_POOL_OBJECT_TYPE Type;
    PTHREAD_POOL Pool;
    struct _THREAD_POOL_GROUP *Group;
    PVOID Userdata;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK GroupCancelCallback;
    PTP_SIMPLE_CALLBACK FinalizationCallback;
    BOOL MayRunLong;
    HMODULE RaceDll;
    TP_CALLBACK_PRIORITY Priority;
    /* information about the group, locked via .group->cs */
    LIST_ENTRY GroupEntry;
    BOOL IsGroupMember;
    /* information about the pool, locked via .pool->cs */
    LIST_ENTRY PoolEntry;
    RTL_CONDITION_VARIABLE FinishedEvent;
    RTL_CONDITION_VARIABLE GroupFinishedEvent;
    HANDLE CompletedEvent;
    LONG NumPendingCallbacks;
    LONG NumRunningCallbacks;
    LONG NumAssociatedCallbacks;
    LONG UpdateSerial;
    /* arguments for callback */
    union {
	struct {
	    PTP_SIMPLE_CALLBACK Callback;
	} Simple;
	struct {
	    PTP_WORK_CALLBACK Callback;
	} Work;
	struct {
	    PTP_TIMER_CALLBACK Callback;
	    /* Information about the timer, locked via TimerQueue.Lock */
	    BOOL TimerInitialized;
	    BOOL TimerPending;
	    LIST_ENTRY TimerEntry;
	    BOOL TimerSet;
	    ULONGLONG Timeout;
	    LONG Period;
	    LONG WindowLength;
	} Timer;
	struct {
	    PTP_WAIT_CALLBACK Callback;
	    LONG Signaled;
	    /* information about the wait object, locked via WaitQueue.Lock */
	    struct WAITQUEUE_BUCKET *Bucket;
	    BOOL WaitPending;
	    LIST_ENTRY WaitEntry;
	    ULONGLONG Timeout;
	    HANDLE Handle;
	    HANDLE DupedHandle;
	    DWORD Flags;
	    WAITORTIMERCALLBACKFUNC RtlCallback;
	    LIST_ENTRY RtlCallers;
	} Wait;
	struct {
	    PTP_IO_CALLBACK Callback;
	    /* locked via .pool->cs */
	    unsigned int PendingCount, SkippedCount, CompletionCount, CompletionMax;
	    BOOL ShuttingDown;
	    PIO_COMPLETION Completions;
	} Io;
    };
} THREAD_POOL_OBJECT, *PTHREAD_POOL_OBJECT;

/* Internal threadpool instance representation */
typedef struct _THREAD_POOL_INSTANCE {
    PTHREAD_POOL_OBJECT Object;
    DWORD Threadid;
    BOOL Associated;
    BOOL MayRunLong;
    struct {
	PRTL_CRITICAL_SECTION CriticalSection;
	HANDLE Mutex;
	HANDLE Semaphore;
	LONG SemaphoreCount;
	HANDLE Event;
	HMODULE Library;
    } Cleanup;
} THREAD_POOL_INSTANCE, *PTHREAD_POOL_INSTANCE;

/* Internal threadpool group representation */
typedef struct _THREAD_POOL_GROUP {
    LONG Refcount;
    BOOL Shutdown;
    RTL_CRITICAL_SECTION Lock;
    /* List of group members, locked via .Lock */
    LIST_ENTRY Members;
} THREAD_POOL_GROUP, *PTHREAD_POOL_GROUP;

enum { ABS_TIMER, REL_TIMER };

#define LIST_INIT(x)	(LIST_ENTRY) { .Flink = &(x), .Blink = &(x) }

static struct {
    RTL_CRITICAL_SECTION Lock;
    LONG Objcount;
    BOOL ThreadRunning;
    HANDLE Timers[2];
    LIST_ENTRY AbsTimers;
    LIST_ENTRY RelTimers;
} TimerQueue = { { 0 },
		 0,
		 FALSE,
		 { 0, 0 },
		 LIST_INIT(TimerQueue.AbsTimers),
		 LIST_INIT(TimerQueue.RelTimers) };

static struct {
    RTL_CRITICAL_SECTION Lock;
    LONG NumBuckets;
    LIST_ENTRY Buckets;
} WaitQueue = { { 0 }, 0, LIST_INIT(WaitQueue.Buckets) };

struct WAITQUEUE_BUCKET {
    LIST_ENTRY BucketEntry;
    LONG Objcount;
    LIST_ENTRY Reserved;
    LIST_ENTRY Waiting;
    HANDLE UpdateEvent;
    BOOL Alertable;
};

static struct {
    RTL_CRITICAL_SECTION Lock;
    LONG Objcount;
    BOOL ThreadRunning;
    HANDLE Port;
    RTL_CONDITION_VARIABLE UpdateEvent;
} IoQueue;

static inline PTHREAD_POOL ImplFromTpPool(PTP_POOL Pool)
{
    return (PTHREAD_POOL)Pool;
}

static inline PTHREAD_POOL_OBJECT ImplFromTpWork(PTP_WORK Work)
{
    PTHREAD_POOL_OBJECT Object = (PTHREAD_POOL_OBJECT)Work;
    assert(Object->Type == TP_OBJECT_TYPE_WORK);
    return Object;
}

static inline PTHREAD_POOL_OBJECT ImplFromTpTimer(PTP_TIMER Timer)
{
    PTHREAD_POOL_OBJECT Object = (PTHREAD_POOL_OBJECT)Timer;
    assert(Object->Type == TP_OBJECT_TYPE_TIMER);
    return Object;
}

static inline PTHREAD_POOL_OBJECT ImplFromTpWait(PTP_WAIT Wait)
{
    PTHREAD_POOL_OBJECT Object = (PTHREAD_POOL_OBJECT)Wait;
    assert(Object->Type == TP_OBJECT_TYPE_WAIT);
    return Object;
}

static inline PTHREAD_POOL_OBJECT ImplFromTpIo(PTP_IO Io)
{
    PTHREAD_POOL_OBJECT Object = (PTHREAD_POOL_OBJECT)Io;
    assert(Object->Type == TP_OBJECT_TYPE_IO);
    return Object;
}

static inline PTHREAD_POOL_GROUP ImplFromTpCleanupGroup(PTP_CLEANUP_GROUP Group)
{
    return (PTHREAD_POOL_GROUP)Group;
}

static inline PTHREAD_POOL_INSTANCE ImplFromTpCallbackInstance(PTP_CALLBACK_INSTANCE Instance)
{
    return (PTHREAD_POOL_INSTANCE)Instance;
}

NTAPI ULONG ThreadPoolWorkerProc(PVOID Param);
static VOID TpObjectSubmit(PTHREAD_POOL_OBJECT Object, BOOL Signaled);
static VOID TpObjectExecute(PTHREAD_POOL_OBJECT Object, BOOL WaitThread);
static VOID TpObjectPrepareShutdown(PTHREAD_POOL_OBJECT Object);
static BOOL TpObjectRelease(PTHREAD_POOL_OBJECT Object);
static PTHREAD_POOL DefaultThreadPool = NULL;

static BOOL ArrayReserve(PVOID *Elements, PULONG Capacity, ULONG Count,
			 ULONG Size)
{
    ULONG NewCapacity, MaxCapacity;
    PVOID NewElements;

    if (Count <= *Capacity)
	return TRUE;

    MaxCapacity = ~(SIZE_T)0 / Size;
    if (Count > MaxCapacity)
	return FALSE;

    NewCapacity = max(4, *Capacity);
    while (NewCapacity < Count && NewCapacity <= MaxCapacity / 2)
	NewCapacity *= 2;
    if (NewCapacity < Count)
	NewCapacity = MaxCapacity;

    if (!(NewElements = RtlReAllocateHeap(RtlGetProcessHeap(), 0, *Elements,
					  NewCapacity * Size)))
	return FALSE;

    *Elements = NewElements;
    *Capacity = NewCapacity;

    return TRUE;
}

static VOID SetThreadName(const WCHAR *Name)
{
    THREAD_NAME_INFORMATION Info;

    RtlInitUnicodeString(&Info.ThreadName, Name);
    NtSetInformationThread(NtCurrentThread(), ThreadNameInformation, &Info, sizeof(Info));
}

static NTAPI VOID ProcessRtlWorkItem(PTP_CALLBACK_INSTANCE Instance, PVOID Userdata)
{
    PRTL_WORK_ITEM Item = Userdata;

    TRACE("executing %p(%p)\n", Item->Function, Item->Context);
    Item->Function(Item->Context);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Item);
}

/***********************************************************************
 *              RtlQueueWorkItem   (NTDLL.@)
 *
 * Queues a work item into a thread in the thread pool.
 *
 * PARAMS
 *  function [I] Work function to execute.
 *  context  [I] Context to pass to the work function when it is executed.
 *  flags    [I] Flags. See notes.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 *
 * NOTES
 *  Flags can be one or more of the following:
 *    WT_EXECUTEDEFAULT - Executes the work item in a non-I/O worker thread.
 *    WT_EXECUTEINIOTHREAD - Executes the work item in an I/O worker thread.
 *    WT_EXECUTEINPERSISTENTTHREAD - Executes the work item in a thread that is
 * persistent. WT_EXECUTELONGFUNCTION - Hints that the execution can take a long time.
 *    WT_TRANSFER_IMPERSONATION - Executes the function with the current access token.
 */
NTAPI NTSTATUS RtlQueueWorkItem(WORKERCALLBACKFUNC Function, PVOID Context, ULONG Flags)
{
    TP_CALLBACK_ENVIRON Environment;
    PRTL_WORK_ITEM Item;
    NTSTATUS Status;

    TRACE("%p %p %u\n", Function, Context, Flags);

    Item = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Item));
    if (!Item)
	return STATUS_NO_MEMORY;

    memset(&Environment, 0, sizeof(Environment));
    Environment.Version = 1;
    Environment.u.s.LongFunction = (Flags & WT_EXECUTELONGFUNCTION) != 0;
    Environment.u.s.Persistent = (Flags & WT_EXECUTEINPERSISTENTTHREAD) != 0;

    Item->Function = Function;
    Item->Context = Context;

    Status = TpSimpleTryPost(ProcessRtlWorkItem, Item, &Environment);
    if (Status)
	RtlFreeHeap(RtlGetProcessHeap(), 0, Item);
    return Status;
}

static inline PLARGE_INTEGER GetNtTimeout(PLARGE_INTEGER pTime, ULONG Timeout)
{
    if (Timeout == INFINITE)
	return NULL;
    pTime->QuadPart = (ULONGLONG)Timeout * -10000;
    return pTime;
}

/************************** Timer Queue Impl **************************/

static VOID QueueRemoveTimer(PTIMER t)
{
    /* We MUST hold the queue cs while calling this function.  This ensures
       that we cannot queue another callback for this timer.  The runcount
       being zero makes sure we don't have any already queued.  */
    PTIMER_QUEUE q = t->q;

    assert(t->Runcount == 0);
    assert(t->Destroy);

    RemoveEntryList(&t->Entry);
    if (t->Event)
	NtSetEvent(t->Event, NULL);
    RtlFreeHeap(RtlGetProcessHeap(), 0, t);

    if (q->Quit && IsListEmpty(&q->Timers))
	NtSetEvent(q->Event, NULL);
}

static VOID TimerCleanupCallback(PTIMER t)
{
    PTIMER_QUEUE q = t->q;
    RtlEnterCriticalSection(&q->Cs);

    assert(0 < t->Runcount);
    --t->Runcount;

    if (t->Destroy && t->Runcount == 0)
	QueueRemoveTimer(t);

    RtlLeaveCriticalSection(&q->Cs);
}

static NTAPI VOID TimerCallbackWrapper(LPVOID p)
{
    PTIMER t = p;
    t->Callback(t->Param, TRUE);
    TimerCleanupCallback(t);
}

static inline ULONGLONG QueueCurrentTime(VOID)
{
    LARGE_INTEGER Now, Freq;
    NtQueryPerformanceCounter(&Now, &Freq);
    return Now.QuadPart * 1000 / Freq.QuadPart;
}

static VOID QueueAddTimer(PTIMER t, ULONGLONG Time, BOOL SetEvent)
{
    /* We MUST hold the queue cs while calling this function.  */
    PTIMER_QUEUE q = t->q;
    PLIST_ENTRY Ptr = &q->Timers;

    assert(!q->Quit || (t->Destroy && Time == EXPIRE_NEVER));

    if (Time != EXPIRE_NEVER) {
	LoopOverList(Timer, &q->Timers, TIMER, Entry) {
	    if (Time < Timer->Expire)
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

static inline VOID QueueMoveTimer(PTIMER t, ULONGLONG Time, BOOL SetEvent)
{
    /* We MUST hold the queue cs while calling this function.  */
    RemoveEntryList(&t->Entry);
    QueueAddTimer(t, Time, SetEvent);
}

static VOID QueueTimerExpire(PTIMER_QUEUE q)
{
    PTIMER t = NULL;

    RtlEnterCriticalSection(&q->Cs);
    if (!IsListEmpty(&q->Timers)) {
	ULONGLONG Now, Next;
	t = GetNextEntryList(&q->Timers, TIMER, Entry, &q->Timers);
	if (!t->Destroy && t->Expire <= ((Now = QueueCurrentTime()))) {
	    ++t->Runcount;
	    if (t->Period) {
		Next = t->Expire + t->Period;
		/* Avoid triggering cascade if overloaded / hibernated */
		if (Next < Now)
		    Next = Now + t->Period;
	    } else
		Next = EXPIRE_NEVER;
	    QueueMoveTimer(t, Next, FALSE);
	} else
	    t = NULL;
    }
    RtlLeaveCriticalSection(&q->Cs);

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
    PTIMER t;
    ULONG Timeout = INFINITE;

    RtlEnterCriticalSection(&q->Cs);
    if (!IsListEmpty(&q->Timers)) {
	t = GetNextEntryList(&q->Timers, TIMER, Entry, &q->Timers);
	assert(!t->Destroy || t->Expire == EXPIRE_NEVER);

	if (t->Expire != EXPIRE_NEVER) {
	    ULONGLONG Time = QueueCurrentTime();
	    Timeout = t->Expire < Time ? 0 : t->Expire - Time;
	}
    }
    RtlLeaveCriticalSection(&q->Cs);

    return Timeout;
}

static NTAPI ULONG LegacyTimerQueueThreadProc(PVOID p)
{
    PTIMER_QUEUE q = p;
    ULONG TimeoutMs;

    SetThreadName(L"ThreadPoolTimerQueue");
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
	    RtlEnterCriticalSection(&q->Cs);
	    if (q->Quit && IsListEmpty(&q->Timers))
		Done = TRUE;
	    RtlLeaveCriticalSection(&q->Cs);
	} else if (Status == STATUS_TIMEOUT)
	    QueueTimerExpire(q);

	if (Done)
	    break;

	TimeoutMs = QueueGetTimeout(q);
    }

    NtClose(q->Event);
    RtlDeleteCriticalSection(&q->Cs);
    q->Magic = 0;
    RtlFreeHeap(RtlGetProcessHeap(), 0, q);
    RtlpExitThreadFunc(0);
    return STATUS_SUCCESS;
}

static VOID QueueDestroyTimer(PTIMER t)
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

    RtlInitializeCriticalSection(&q->Cs);
    InitializeListHead(&q->Timers);
    q->Quit = FALSE;
    q->Magic = TIMER_QUEUE_MAGIC;
    Status = NtCreateEvent(&q->Event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent,
			   FALSE);
    if (Status != STATUS_SUCCESS) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, q);
	return Status;
    }
    Status = RtlpCreateThread(LegacyTimerQueueThreadProc, q, &q->Thread);
    if (Status != STATUS_SUCCESS) {
	NtClose(q->Event);
	RtlFreeHeap(RtlGetProcessHeap(), 0, q);
	return Status;
    }

    *NewTimerQueue = q;
    return STATUS_SUCCESS;
}

/*
 * @implemented
 */
NTAPI NTSTATUS RtlDeleteTimerQueue(HANDLE TimerQueue)
{
    return RtlDeleteTimerQueueEx(TimerQueue, INVALID_HANDLE_VALUE);
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

    RtlEnterCriticalSection(&q->Cs);
    q->Quit = TRUE;
    if (!IsListEmpty(&q->Timers)) {
	/* When the last timer is removed, it will signal the timer thread to exit. */
	LoopOverList(t, &q->Timers, TIMER, Entry) {
	    QueueDestroyTimer(t);
	}
    } else {
	/* However if we have none, we must do it ourselves.  */
	NtSetEvent(q->Event, NULL);
    }
    RtlLeaveCriticalSection(&q->Cs);

    if (CompletionEvent == INVALID_HANDLE_VALUE) {
	NtWaitForSingleObject(Thread, FALSE, NULL);
	Status = STATUS_SUCCESS;
    } else {
	if (CompletionEvent) {
	    FIXME("asynchronous return on completion event unimplemented\n");
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
		PVOID p = InterlockedCompareExchangePointer((PVOID *)&DefaultTimerQueue,
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
 *  TimerQueue [I] The queue to hold the timer.
 *  NewTimer   [O] The newly created timer.
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
NTAPI NTSTATUS RtlCreateTimer(HANDLE TimerQueue, HANDLE *NewTimer,
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

    t->q = q;
    t->Runcount = 0;
    t->Callback = Callback;
    t->Param = Parameter;
    t->Period = Period;
    t->Flags = Flags;
    t->Destroy = FALSE;
    t->Event = NULL;

    Status = STATUS_SUCCESS;
    RtlEnterCriticalSection(&q->Cs);
    if (q->Quit)
	Status = STATUS_INVALID_HANDLE;
    else
	QueueAddTimer(t, QueueCurrentTime() + DueTime, TRUE);
    RtlLeaveCriticalSection(&q->Cs);

    if (Status == STATUS_SUCCESS)
	*NewTimer = t;
    else
	RtlFreeHeap(RtlGetProcessHeap(), 0, t);

    return Status;
}

/*
 * @implemented
 */
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
    PTIMER_QUEUE q = t->q;

    RtlEnterCriticalSection(&q->Cs);
    /* Can't change a timer if it was once-only or destroyed.  */
    if (t->Expire != EXPIRE_NEVER) {
	t->Period = Period;
	QueueMoveTimer(t, QueueCurrentTime() + DueTime, TRUE);
    }
    RtlLeaveCriticalSection(&q->Cs);

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
    q = t->q;
    if (CompletionEvent == INVALID_HANDLE_VALUE) {
	Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent,
			       FALSE);
	if (Status == STATUS_SUCCESS)
	    Status = STATUS_PENDING;
    } else if (CompletionEvent)
	Event = CompletionEvent;

    RtlEnterCriticalSection(&q->Cs);
    t->Event = Event;
    if (t->Runcount == 0 && Event)
	Status = STATUS_SUCCESS;
    QueueDestroyTimer(t);
    RtlLeaveCriticalSection(&q->Cs);

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

#define TICKS_100NS_PER_SECOND 10000000ULL

static ULONGLONG QpcFrom100ns(ULONGLONG Value)
{
    LARGE_INTEGER Counter, Frequency;
    ULONGLONG Seconds, Remainder;

    NtQueryPerformanceCounter(&Counter, &Frequency);
    Seconds = Value / TICKS_100NS_PER_SECOND;
    Remainder = Value % TICKS_100NS_PER_SECOND;
    if (Seconds > MAXLONGLONG / Frequency.QuadPart)
	return MAXLONGLONG;
    return Seconds * Frequency.QuadPart +
	   Remainder * Frequency.QuadPart / TICKS_100NS_PER_SECOND;
}

static ULONGLONG QpcTo100ns(ULONGLONG Value)
{
    LARGE_INTEGER Counter, Frequency;
    ULONGLONG Seconds, Remainder;

    NtQueryPerformanceCounter(&Counter, &Frequency);
    Seconds = Value / Frequency.QuadPart;
    Remainder = Value % Frequency.QuadPart;
    if (Seconds > MAXLONGLONG / TICKS_100NS_PER_SECOND)
	return MAXLONGLONG;
    return Seconds * TICKS_100NS_PER_SECOND +
	   Remainder * TICKS_100NS_PER_SECOND / Frequency.QuadPart;
}

static ULONGLONG QpcAdd100ns(ULONGLONG Base, ULONGLONG Value)
{
    ULONGLONG Delta = QpcFrom100ns(Value);

    if (Delta >= MAXLONGLONG - Base)
	return MAXLONGLONG;
    return Base + Delta;
}

/***********************************************************************
 *           submit_expired_timers     (internal)
 *
 * TimerQueue.Locka held by caller.
 */
static VOID SubmitExpiredTimers(PLIST_ENTRY Queue, ULONGLONG QueueNow, ULONGLONG RelNow)
{
    PLIST_ENTRY Ptr;

    while ((Ptr = Queue->Flink)) {
	PTHREAD_POOL_OBJECT Timer = CONTAINING_RECORD(Ptr, THREAD_POOL_OBJECT,
						      Timer.TimerEntry);
	assert(Timer->Type == TP_OBJECT_TYPE_TIMER);
	assert(Timer->Timer.TimerPending);
	if (Timer->Timer.Timeout > QueueNow)
	    return;

	/* Queue a new callback in one of the worker threads. */
	RemoveEntryList(&Timer->Timer.TimerEntry);
	Timer->Timer.TimerPending = FALSE;
	TpObjectSubmit(Timer, FALSE);

	/* Insert the timer back into the queue, except it's marked for shutdown. */
	if (Timer->Timer.Period && !Timer->Shutdown) {
	    /* Update timeout when moving timer to relative queue */
	    if (Queue == &TimerQueue.AbsTimers)
		Timer->Timer.Timeout = RelNow;

	    Timer->Timer.Timeout = QpcAdd100ns(Timer->Timer.Timeout,
					       (ULONGLONG)Timer->Timer.Period * 10000);
	    if (Timer->Timer.Timeout <= RelNow)
		Timer->Timer.Timeout = RelNow + 1;

	    LoopOverList(OtherTimer, &TimerQueue.RelTimers, THREAD_POOL_OBJECT,
			 Timer.TimerEntry) {
		assert(OtherTimer->Type == TP_OBJECT_TYPE_TIMER);
		if (Timer->Timer.Timeout < OtherTimer->Timer.Timeout) {
		    InsertTailList(&OtherTimer->Timer.TimerEntry, &Timer->Timer.TimerEntry);
		    break;
		}
	    }
	    Timer->Timer.TimerPending = TRUE;
	}
    }
}

/***********************************************************************
 *           get_next_timeout          (internal)
 *
 * timerqueue.cs held by caller.
 */
static ULONGLONG GetNextTimeout(PLIST_ENTRY List)
{
    ULONGLONG TimeoutLower, TimeoutUpper, NewTimeout;

    TimeoutLower = TimeoutUpper = MAXLONGLONG;

    /* Determine next timeout and use the window length to optimize wakeup times. */
    LoopOverList(OtherTimer, List, THREAD_POOL_OBJECT, Timer.TimerEntry) {
	assert(OtherTimer->Type == TP_OBJECT_TYPE_TIMER);
	if (OtherTimer->Timer.Timeout >= TimeoutUpper)
	    break;

	TimeoutLower = OtherTimer->Timer.Timeout;
	if (List == &TimerQueue.RelTimers)
	    NewTimeout = QpcAdd100ns(TimeoutLower,
				     (ULONGLONG)OtherTimer->Timer.WindowLength * 10000);
	else
	    NewTimeout = TimeoutLower + (ULONGLONG)OtherTimer->Timer.WindowLength * 10000;
	if (NewTimeout < TimeoutUpper)
	    TimeoutUpper = NewTimeout;
    }
    return TimeoutLower;
}

/***********************************************************************
 *           update_timers             (internal)
 *
 * timerqueue.cs held by caller.
 */
static VOID UpdateTimers(ULONGLONG RelNow)
{
    LARGE_INTEGER Timeout;

    Timeout.QuadPart = GetNextTimeout(&TimerQueue.AbsTimers);
    NtSetTimer(TimerQueue.Timers[ABS_TIMER], &Timeout, NULL, NULL, FALSE, 0, NULL);

    if (TimerQueue.Objcount) {
	Timeout.QuadPart = GetNextTimeout(&TimerQueue.RelTimers);
	if (Timeout.QuadPart > RelNow)
	    Timeout.QuadPart = -(LONGLONG)QpcTo100ns(Timeout.QuadPart - RelNow);
	else
	    Timeout.QuadPart = 0;
    } else {
	/* All timers have been destroyed, if no new timers are created
	 * within some amount of time, then we can shutdown this thread. */
	Timeout.QuadPart = (ULONGLONG)THREADPOOL_WORKER_TIMEOUT * -10000;
    }
    NtSetTimer(TimerQueue.Timers[REL_TIMER], &Timeout, NULL, NULL, FALSE, 0, NULL);
}

/***********************************************************************
 *           timerqueue_thread_proc    (internal)
 */
NTAPI ULONG TimerQueueThreadProc(PVOID Param)
{
    LARGE_INTEGER AbsNow, RelNow;

    TRACE("starting timer queue thread\n");
    SetThreadName(L"ThreadPoolTimerQueue");

    RtlEnterCriticalSection(&TimerQueue.Lock);
    for (;;) {
	NtQuerySystemTime(&AbsNow);
	NtQueryPerformanceCounter(&RelNow, NULL);

	SubmitExpiredTimers(&TimerQueue.AbsTimers, AbsNow.QuadPart, RelNow.QuadPart);
	SubmitExpiredTimers(&TimerQueue.RelTimers, RelNow.QuadPart, RelNow.QuadPart);
	UpdateTimers(RelNow.QuadPart);

	RtlLeaveCriticalSection(&TimerQueue.Lock);
	NtWaitForMultipleObjects(ARRAYSIZE(TimerQueue.Timers), TimerQueue.Timers, WaitAny,
				 FALSE, NULL);
	RtlEnterCriticalSection(&TimerQueue.Lock);

	if (!TimerQueue.Objcount)
	    break;
    }

    NtClose(TimerQueue.Timers[ABS_TIMER]);
    NtClose(TimerQueue.Timers[REL_TIMER]);

    TimerQueue.ThreadRunning = FALSE;
    RtlLeaveCriticalSection(&TimerQueue.Lock);

    TRACE("terminating timer queue thread\n");
    RtlpExitThreadFunc(0);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           tp_new_worker_thread    (internal)
 *
 * Create and account a new worker thread for the desired pool.
 */
static NTSTATUS TpNewWorkerThread(PTHREAD_POOL Pool)
{
    HANDLE Thread;
    NTSTATUS Status;

    Status = RtlpCreateThreadWithStack(ThreadPoolWorkerProc, Pool,
				       Pool->StackInfo.StackReserve,
				       Pool->StackInfo.StackCommit, &Thread);
    if (Status == STATUS_SUCCESS) {
	InterlockedIncrement(&Pool->Refcount);
	Pool->NumWorkers++;
	NtClose(Thread);
    }
    return Status;
}

/***********************************************************************
 *           tp_timerqueue_lock    (internal)
 *
 * Acquires a lock on the global timerqueue. When the lock is acquired
 * successfully, it is guaranteed that the timer thread is running.
 */
static NTSTATUS TpTimerQueueLock(PTHREAD_POOL_OBJECT Timer)
{
    assert(Timer->Type == TP_OBJECT_TYPE_TIMER);

    Timer->Timer.TimerInitialized = FALSE;
    Timer->Timer.TimerPending = FALSE;
    Timer->Timer.TimerSet = FALSE;
    Timer->Timer.Timeout = 0;
    Timer->Timer.Period = 0;
    Timer->Timer.WindowLength = 0;

    RtlEnterCriticalSection(&TimerQueue.Lock);

    /* Make sure that the timerqueue thread is running. */
    if (!TimerQueue.ThreadRunning) {
	NTSTATUS Status;
	HANDLE Thread;

	Status = NtCreateTimer(&TimerQueue.Timers[ABS_TIMER], TIMER_ALL_ACCESS, NULL,
			       NotificationTimer);
	if (Status != STATUS_SUCCESS) {
	    RtlLeaveCriticalSection(&TimerQueue.Lock);
	    return Status;
	}

	Status = NtCreateTimer(&TimerQueue.Timers[REL_TIMER], TIMER_ALL_ACCESS, NULL,
			       NotificationTimer);
	if (Status != STATUS_SUCCESS) {
	    NtClose(TimerQueue.Timers[ABS_TIMER]);
	    RtlLeaveCriticalSection(&TimerQueue.Lock);
	    return Status;
	}

	Status = RtlpCreateThread(TimerQueueThreadProc, NULL, &Thread);
	if (Status != STATUS_SUCCESS) {
	    NtClose(TimerQueue.Timers[ABS_TIMER]);
	    NtClose(TimerQueue.Timers[REL_TIMER]);
	    RtlLeaveCriticalSection(&TimerQueue.Lock);
	    return Status;
	}
	TimerQueue.ThreadRunning = TRUE;
	NtClose(Thread);
    }

    Timer->Timer.TimerInitialized = TRUE;
    TimerQueue.Objcount++;

    RtlLeaveCriticalSection(&TimerQueue.Lock);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           tp_timerqueue_unlock    (internal)
 *
 * Releases a lock on the global timerqueue.
 */
static VOID TpTimerQueueUnlock(PTHREAD_POOL_OBJECT Timer)
{
    assert(Timer->Type == TP_OBJECT_TYPE_TIMER);

    RtlEnterCriticalSection(&TimerQueue.Lock);
    if (Timer->Timer.TimerInitialized) {
	/* If timer was pending, remove it. */
	if (Timer->Timer.TimerPending) {
	    RemoveEntryList(&Timer->Timer.TimerEntry);
	    Timer->Timer.TimerPending = FALSE;
	}

	/* If the last timer object was destroyed, then update timeout. */
	if (!--TimerQueue.Objcount) {
	    LARGE_INTEGER RelNow;

	    assert(IsListEmpty(&TimerQueue.AbsTimers));
	    assert(IsListEmpty(&TimerQueue.RelTimers));
	    NtQueryPerformanceCounter(&RelNow, NULL);
	    UpdateTimers(RelNow.QuadPart);
	}

	Timer->Timer.TimerInitialized = FALSE;
    }
    RtlLeaveCriticalSection(&TimerQueue.Lock);
}

/***********************************************************************
 *           waitqueue_thread_proc    (internal)
 */
NTAPI VOID WaitQueueThreadProc(PVOID Param)
{
    PTHREAD_POOL_OBJECT Objects[MAXIMUM_WAITQUEUE_OBJECTS];
    LONG UpdateSerials[MAXIMUM_WAITQUEUE_OBJECTS];
    HANDLE Handles[MAXIMUM_WAITQUEUE_OBJECTS + 1];
    struct WAITQUEUE_BUCKET *Bucket = Param;
    LARGE_INTEGER Now, Timeout;
    DWORD NumHandles;
    NTSTATUS Status;
    BOOLEAN DuplicatedHandles[MAXIMUM_WAITQUEUE_OBJECTS];

    TRACE("starting wait queue thread\n");
    SetThreadName(L"wine_threadpool_waitqueue");

    RtlEnterCriticalSection(&WaitQueue.Lock);

    for (;;) {
	NtQuerySystemTime(&Now);
	Timeout.QuadPart = MAXLONGLONG;
	NumHandles = 0;

	LoopOverList(Wait, &Bucket->Waiting, THREAD_POOL_OBJECT, Wait.WaitEntry) {
	    assert(Wait->Type == TP_OBJECT_TYPE_WAIT);
	    assert(Wait->Wait.WaitPending);
	    if (Wait->Wait.Timeout <= Now.QuadPart) {
		/* Wait object timed out. */
		if ((Wait->Wait.Flags & WT_EXECUTEONLYONCE)) {
		    RemoveEntryList(&Wait->Wait.WaitEntry);
		    InsertTailList(&Bucket->Reserved, &Wait->Wait.WaitEntry);
		    Wait->Wait.WaitPending = FALSE;
		}
		if ((Wait->Wait.Flags &
		     (WT_EXECUTEINWAITTHREAD | WT_EXECUTEINIOTHREAD))) {
		    InterlockedIncrement(&Wait->Refcount);
		    Wait->NumPendingCallbacks++;
		    RtlEnterCriticalSection(&Wait->Pool->Cs);
		    TpObjectExecute(Wait, TRUE);
		    RtlLeaveCriticalSection(&Wait->Pool->Cs);
		    TpObjectRelease(Wait);
		} else
		    TpObjectSubmit(Wait, FALSE);
	    } else {
		if (Wait->Wait.Timeout < Timeout.QuadPart)
		    Timeout.QuadPart = Wait->Wait.Timeout;

		assert(NumHandles < MAXIMUM_WAITQUEUE_OBJECTS);
		InterlockedIncrement(&Wait->Refcount);
		Objects[NumHandles] = Wait;
		/* NtWaitForMultipleObjects() fails if any invalid handles are passed, and
		 * one invalid handle should not affect other waiting items. The calling
		 * app is allowed to close waitable timer handles immediately after
		 * submission, so we need a duplicate for those in particular. */
		HANDLE SourceHandle = Wait->Wait.DupedHandle ? Wait->Wait.DupedHandle :
							       Wait->Wait.Handle;
		Handles[NumHandles] = SourceHandle;
		DuplicatedHandles[NumHandles] =
		    SourceHandle &&
		    NT_SUCCESS(NtDuplicateObject(NtCurrentProcess(), SourceHandle,
						 NtCurrentProcess(), &Handles[NumHandles],
						 0, 0, DUPLICATE_SAME_ACCESS));
		UpdateSerials[NumHandles] = Wait->UpdateSerial;
		NumHandles++;
	    }
	}

	if (!Bucket->Objcount) {
	    /* All wait objects have been destroyed, if no new wait objects are created
	     * within some amount of time, then we can shutdown this thread. */
	    assert(NumHandles == 0);
	    RtlLeaveCriticalSection(&WaitQueue.Lock);
	    Timeout.QuadPart = (ULONGLONG)THREADPOOL_WORKER_TIMEOUT * -10000;
	    Status = NtWaitForMultipleObjects(1, &Bucket->UpdateEvent, WaitAny,
					      Bucket->Alertable, &Timeout);
	    RtlEnterCriticalSection(&WaitQueue.Lock);

	    if (Status == STATUS_TIMEOUT && !Bucket->Objcount)
		break;
	} else {
	    Handles[NumHandles] = Bucket->UpdateEvent;
	    RtlLeaveCriticalSection(&WaitQueue.Lock);
	    Status = NtWaitForMultipleObjects(NumHandles + 1, Handles, WaitAny,
					      Bucket->Alertable, &Timeout);
	    for (ULONG i = 0; i < NumHandles; ++i)
		if (DuplicatedHandles[i])
		    NtClose(Handles[i]);
	    RtlEnterCriticalSection(&WaitQueue.Lock);

	    if (Status >= STATUS_WAIT_0 && Status < STATUS_WAIT_0 + NumHandles) {
		PTHREAD_POOL_OBJECT Wait = Objects[Status - STATUS_WAIT_0];
		assert(Wait->Type == TP_OBJECT_TYPE_WAIT);
		if (Wait->Wait.Bucket &&
		    Wait->UpdateSerial == UpdateSerials[Status - STATUS_WAIT_0]) {
		    /* Wait object signaled. */
		    assert(Wait->Wait.Bucket == Bucket);
		    if ((Wait->Wait.Flags & WT_EXECUTEONLYONCE)) {
			RemoveEntryList(&Wait->Wait.WaitEntry);
			InsertTailList(&Bucket->Reserved, &Wait->Wait.WaitEntry);
			Wait->Wait.WaitPending = FALSE;
		    }
		    if ((Wait->Wait.Flags &
			 (WT_EXECUTEINWAITTHREAD | WT_EXECUTEINIOTHREAD))) {
			Wait->Wait.Signaled++;
			Wait->NumPendingCallbacks++;
			RtlEnterCriticalSection(&Wait->Pool->Cs);
			TpObjectExecute(Wait, TRUE);
			RtlLeaveCriticalSection(&Wait->Pool->Cs);
		    } else
			TpObjectSubmit(Wait, TRUE);
		} else {
		    WARN("wait object %p triggered while object was %s.\n", Wait,
			 Wait->Wait.Bucket ? "updated" : "destroyed");
		}
	    }

	    /* Release temporary references to wait objects. */
	    while (NumHandles) {
		PTHREAD_POOL_OBJECT Wait = Objects[--NumHandles];
		assert(Wait->Type == TP_OBJECT_TYPE_WAIT);
		TpObjectRelease(Wait);
	    }
	}

	/* Try to merge bucket with other threads. */
	if (WaitQueue.NumBuckets > 1 && Bucket->Objcount &&
	    Bucket->Objcount <= MAXIMUM_WAITQUEUE_OBJECTS * 1 / 3) {
	    LoopOverList(OtherBucket, &WaitQueue.Buckets, struct WAITQUEUE_BUCKET,
			 BucketEntry) {
		if (OtherBucket != Bucket && OtherBucket->Objcount &&
		    OtherBucket->Alertable == Bucket->Alertable &&
		    OtherBucket->Objcount + Bucket->Objcount <=
			MAXIMUM_WAITQUEUE_OBJECTS * 2 / 3) {
		    OtherBucket->Objcount += Bucket->Objcount;
		    Bucket->Objcount = 0;

		    /* Update reserved list. */
		    LoopOverList(Wait, &Bucket->Reserved, THREAD_POOL_OBJECT,
				 Wait.WaitEntry) {
			assert(Wait->Type == TP_OBJECT_TYPE_WAIT);
			Wait->Wait.Bucket = OtherBucket;
		    }
		    AppendTailListHead(&OtherBucket->Reserved, &Bucket->Reserved);

		    /* Update waiting list. */
		    LoopOverList(Wait, &Bucket->Waiting, THREAD_POOL_OBJECT,
				 Wait.WaitEntry) {
			assert(Wait->Type == TP_OBJECT_TYPE_WAIT);
			Wait->Wait.Bucket = OtherBucket;
		    }
		    AppendTailListHead(&OtherBucket->Waiting, &Bucket->Waiting);

		    /* Move bucket to the end, to keep the probability of
		     * newly added wait objects as small as possible. */
		    RemoveEntryList(&Bucket->BucketEntry);
		    InsertTailList(&WaitQueue.Buckets, &Bucket->BucketEntry);

		    NtSetEvent(OtherBucket->UpdateEvent, NULL);
		    break;
		}
	    }
	}
    }

    /* Remove this bucket from the list. */
    RemoveEntryList(&Bucket->BucketEntry);
    if (!--WaitQueue.NumBuckets)
	assert(IsListEmpty(&WaitQueue.Buckets));

    RtlLeaveCriticalSection(&WaitQueue.Lock);

    TRACE("terminating wait queue thread\n");

    assert(Bucket->Objcount == 0);
    assert(IsListEmpty(&Bucket->Reserved));
    assert(IsListEmpty(&Bucket->Waiting));
    NtClose(Bucket->UpdateEvent);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Bucket);
    RtlpExitThreadFunc(0);
}

/***********************************************************************
 *           tp_waitqueue_lock    (internal)
 */
static NTSTATUS TpWaitQueueLock(PTHREAD_POOL_OBJECT Wait)
{
    struct WAITQUEUE_BUCKET *Bucket;
    NTSTATUS Status;
    HANDLE Thread;
    BOOL Alertable = (Wait->Wait.Flags & WT_EXECUTEINIOTHREAD) != 0;
    assert(Wait->Type == TP_OBJECT_TYPE_WAIT);

    Wait->Wait.Signaled = 0;
    Wait->Wait.Bucket = NULL;
    Wait->Wait.WaitPending = FALSE;
    Wait->Wait.Timeout = 0;
    Wait->Wait.Handle = NULL;
    Wait->Wait.DupedHandle = NULL;

    RtlEnterCriticalSection(&WaitQueue.Lock);

    /* Try to assign to existing bucket if possible. */
    LoopOverList(Bucket, &WaitQueue.Buckets, struct WAITQUEUE_BUCKET, BucketEntry) {
	if (Bucket->Objcount < MAXIMUM_WAITQUEUE_OBJECTS &&
	    Bucket->Alertable == Alertable) {
	    InsertTailList(&Bucket->Reserved, &Wait->Wait.WaitEntry);
	    Wait->Wait.Bucket = Bucket;
	    Bucket->Objcount++;

	    Status = STATUS_SUCCESS;
	    goto out;
	}
    }

    /* Create a new bucket and corresponding worker thread. */
    Bucket = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Bucket));
    if (!Bucket) {
	Status = STATUS_NO_MEMORY;
	goto out;
    }

    Bucket->Objcount = 0;
    Bucket->Alertable = Alertable;
    InitializeListHead(&Bucket->Reserved);
    InitializeListHead(&Bucket->Waiting);

    Status = NtCreateEvent(&Bucket->UpdateEvent, EVENT_ALL_ACCESS, NULL,
			   SynchronizationEvent, FALSE);
    if (Status) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Bucket);
	goto out;
    }

    Status = RtlpCreateThread((PTHREAD_START_ROUTINE)WaitQueueThreadProc, Bucket,
			      &Thread);
    if (Status == STATUS_SUCCESS) {
	InsertTailList(&WaitQueue.Buckets, &Bucket->BucketEntry);
	WaitQueue.NumBuckets++;

	InsertTailList(&Bucket->Reserved, &Wait->Wait.WaitEntry);
	Wait->Wait.Bucket = Bucket;
	Bucket->Objcount++;

	NtClose(Thread);
    } else {
	NtClose(Bucket->UpdateEvent);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Bucket);
    }

out:
    RtlLeaveCriticalSection(&WaitQueue.Lock);
    return Status;
}

/***********************************************************************
 *           tp_waitqueue_unlock    (internal)
 */
static VOID TpWaitQueueUnlock(PTHREAD_POOL_OBJECT Wait)
{
    assert(Wait->Type == TP_OBJECT_TYPE_WAIT);

    RtlEnterCriticalSection(&WaitQueue.Lock);
    if (Wait->Wait.Bucket) {
	struct WAITQUEUE_BUCKET *Bucket = Wait->Wait.Bucket;
	assert(Bucket->Objcount > 0);

	RemoveEntryList(&Wait->Wait.WaitEntry);
	Wait->Wait.Bucket = NULL;
	Bucket->Objcount--;

	NtSetEvent(Bucket->UpdateEvent, NULL);
    }
    RtlLeaveCriticalSection(&WaitQueue.Lock);
}

NTAPI ULONG IoQueueThreadProc(PVOID Param)
{
    PIO_COMPLETION Completion;
    PTHREAD_POOL_OBJECT Io;
    IO_STATUS_BLOCK Iosb;
    PVOID Key, Value;
    BOOL Destroy, Skip;
    NTSTATUS Status;

    TRACE("starting I/O completion thread\n");
    SetThreadName(L"wine_threadpool_ioqueue");

    RtlEnterCriticalSection(&IoQueue.Lock);

    for (;;) {
	RtlLeaveCriticalSection(&IoQueue.Lock);
	if ((Status = NtRemoveIoCompletion(IoQueue.Port, &Key, &Value, &Iosb, NULL)))
	    ERR("NtRemoveIoCompletion failed, status %#x.\n", Status);
	RtlEnterCriticalSection(&IoQueue.Lock);

	Destroy = Skip = FALSE;
	Io = (PTHREAD_POOL_OBJECT)Key;

	TRACE("io %p, iosb.Status %#x.\n", Io, Iosb.Status);

	if (Io && (Io->Shutdown || Io->Io.ShuttingDown)) {
	    RtlEnterCriticalSection(&Io->Pool->Cs);
	    if (!Io->Io.PendingCount) {
		if (Io->Io.SkippedCount)
		    --Io->Io.SkippedCount;

		if (Io->Io.SkippedCount)
		    Skip = TRUE;
		else
		    Destroy = TRUE;
	    }
	    RtlLeaveCriticalSection(&Io->Pool->Cs);
	    if (Skip)
		continue;
	}

	if (Destroy) {
	    --IoQueue.Objcount;
	    TRACE("Releasing io %p.\n", Io);
	    Io->Shutdown = TRUE;
	    TpObjectRelease(Io);
	} else if (Io) {
	    RtlEnterCriticalSection(&Io->Pool->Cs);

	    TRACE("pending_count %u.\n", Io->Io.PendingCount);

	    if (Io->Io.PendingCount) {
		--Io->Io.PendingCount;
		if (!ArrayReserve((PVOID *)&Io->Io.Completions, &Io->Io.CompletionMax,
				  Io->Io.CompletionCount + 1,
				  sizeof(*Io->Io.Completions))) {
		    ERR("Failed to allocate memory.\n");
		    RtlLeaveCriticalSection(&Io->Pool->Cs);
		    continue;
		}

		Completion = &Io->Io.Completions[Io->Io.CompletionCount++];
		Completion->Iosb = Iosb;
		Completion->Cvalue = (ULONG_PTR)Value;

		TpObjectSubmit(Io, FALSE);
	    }
	    RtlLeaveCriticalSection(&Io->Pool->Cs);
	}

	if (!IoQueue.Objcount) {
	    /* All I/O objects have been destroyed; if no new objects are
	     * created within some amount of time, then we can shutdown this
	     * thread. */
	    LARGE_INTEGER Timeout = { .QuadPart = (ULONGLONG)THREADPOOL_WORKER_TIMEOUT *
						  -10000 };
	    if (RtlSleepConditionVariableCS(&IoQueue.UpdateEvent, &IoQueue.Lock,
					    &Timeout) == STATUS_TIMEOUT &&
		!IoQueue.Objcount)
		break;
	}
    }

    IoQueue.ThreadRunning = FALSE;
    RtlLeaveCriticalSection(&IoQueue.Lock);

    TRACE("terminating I/O completion thread\n");

    RtlpExitThreadFunc(0);

    return STATUS_SUCCESS;
}

static NTSTATUS TpIoQueueLock(PTHREAD_POOL_OBJECT Io, HANDLE File)
{
    NTSTATUS Status = STATUS_SUCCESS;

    assert(Io->Type == TP_OBJECT_TYPE_IO);

    RtlEnterCriticalSection(&IoQueue.Lock);

    if (!IoQueue.Port &&
	(Status = NtCreateIoCompletion(&IoQueue.Port, IO_COMPLETION_ALL_ACCESS, NULL,
				       0))) {
	RtlLeaveCriticalSection(&IoQueue.Lock);
	return Status;
    }

    if (!IoQueue.ThreadRunning) {
	HANDLE Thread;

	if (!(Status = RtlpCreateThread(IoQueueThreadProc, NULL, &Thread))) {
	    IoQueue.ThreadRunning = TRUE;
	    NtClose(Thread);
	}
    }

    if (Status == STATUS_SUCCESS) {
	FILE_COMPLETION_INFORMATION Info;
	IO_STATUS_BLOCK Iosb;

	Info.Port = IoQueue.Port;
	Info.Key = Io;

	Status = NtSetInformationFile(File, &Iosb, &Info, sizeof(Info),
				      FileCompletionInformation);
    }

    if (Status == STATUS_SUCCESS) {
	if (!IoQueue.Objcount++)
	    RtlWakeConditionVariable(&IoQueue.UpdateEvent);
    }

    RtlLeaveCriticalSection(&IoQueue.Lock);
    return Status;
}

/***********************************************************************
 *           tp_threadpool_alloc    (internal)
 *
 * Allocates a new threadpool object.
 */
static NTSTATUS TpThreadPoolAlloc(PTHREAD_POOL *Out)
{
    IMAGE_NT_HEADERS *Nt =
	RtlImageNtHeader(NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress);
    PTHREAD_POOL Pool = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Pool));
    if (!Pool)
	return STATUS_NO_MEMORY;

    Pool->Refcount = 1;
    Pool->Objcount = 0;
    Pool->Shutdown = FALSE;

    RtlInitializeCriticalSectionEx(&Pool->Cs, 0,
				   RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);

    for (ULONG i = 0; i < ARRAYSIZE(Pool->Pools); ++i)
	InitializeListHead(&Pool->Pools[i]);
    RtlInitializeConditionVariable(&Pool->UpdateEvent);

    Pool->MaxWorkers = 500;
    Pool->MinWorkers = 0;
    Pool->NumWorkers = 0;
    Pool->NumBusyWorkers = 0;
    Pool->StackInfo.StackReserve = Nt->OptionalHeader.SizeOfStackReserve;
    Pool->StackInfo.StackCommit = Nt->OptionalHeader.SizeOfStackCommit;

    TRACE("allocated threadpool %p\n", Pool);

    *Out = Pool;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           tp_threadpool_shutdown    (internal)
 *
 * Prepares the shutdown of a threadpool object and notifies all worker
 * threads to terminate (after all remaining work items have been
 * processed).
 */
static VOID TpThreadPoolShutdown(PTHREAD_POOL Pool)
{
    assert(Pool != DefaultThreadPool);

    Pool->Shutdown = TRUE;
    RtlWakeAllConditionVariable(&Pool->UpdateEvent);
}

/***********************************************************************
 *           tp_threadpool_release    (internal)
 *
 * Releases a reference to a threadpool object.
 */
static BOOL TpThreadPoolRelease(PTHREAD_POOL Pool)
{
    if (InterlockedDecrement(&Pool->Refcount))
	return FALSE;

    TRACE("destroying threadpool %p\n", Pool);

    assert(Pool->Shutdown);
    assert(!Pool->Objcount);
    for (ULONG i = 0; i < ARRAYSIZE(Pool->Pools); ++i)
	assert(IsListEmpty(&Pool->Pools[i]));
    RtlDeleteCriticalSection(&Pool->Cs);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Pool);
    return TRUE;
}

/***********************************************************************
 *           tp_threadpool_lock    (internal)
 *
 * Acquires a lock on a threadpool, specified with an TP_CALLBACK_ENVIRON
 * block. When the lock is acquired successfully, it is guaranteed that
 * there is at least one worker thread to process tasks.
 */
static NTSTATUS TpThreadPoolLock(PTHREAD_POOL *Out, PTP_CALLBACK_ENVIRON Environment)
{
    PTHREAD_POOL Pool = NULL;
    NTSTATUS Status = STATUS_SUCCESS;

    if (Environment) {
	/* Validate environment parameters. */
	if (Environment->Version == 3) {
	    TP_CALLBACK_ENVIRON_V3 *Environment3 = (TP_CALLBACK_ENVIRON_V3 *)Environment;

	    switch (Environment3->CallbackPriority) {
	    case TP_CALLBACK_PRIORITY_HIGH:
	    case TP_CALLBACK_PRIORITY_NORMAL:
	    case TP_CALLBACK_PRIORITY_LOW:
		break;
	    default:
		return STATUS_INVALID_PARAMETER;
	    }
	}
	Pool = (PTHREAD_POOL)Environment->Pool;
    }

    if (!Pool) {
	if (!DefaultThreadPool) {
	    Status = TpThreadPoolAlloc(&Pool);
	    if (Status != STATUS_SUCCESS)
		return Status;

	    if (InterlockedCompareExchangePointer((PVOID)&DefaultThreadPool, Pool,
						  NULL) != NULL) {
		TpThreadPoolShutdown(Pool);
		TpThreadPoolRelease(Pool);
	    }
	}

	Pool = DefaultThreadPool;
    }

    RtlEnterCriticalSection(&Pool->Cs);

    /* Make sure that the threadpool has at least one thread. */
    if (!Pool->NumWorkers)
	Status = TpNewWorkerThread(Pool);

    /* Keep a reference, and increment objcount to ensure that the
     * last thread doesn't terminate. */
    if (Status == STATUS_SUCCESS) {
	InterlockedIncrement(&Pool->Refcount);
	Pool->Objcount++;
    }

    RtlLeaveCriticalSection(&Pool->Cs);

    if (Status != STATUS_SUCCESS)
	return Status;

    *Out = Pool;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           tp_threadpool_unlock    (internal)
 *
 * Releases a lock on a threadpool.
 */
static VOID TpThreadPoolUnlock(PTHREAD_POOL Pool)
{
    RtlEnterCriticalSection(&Pool->Cs);
    Pool->Objcount--;
    RtlLeaveCriticalSection(&Pool->Cs);
    TpThreadPoolRelease(Pool);
}

/***********************************************************************
 *           tp_group_alloc    (internal)
 *
 * Allocates a new threadpool group object.
 */
static NTSTATUS TpGroupAlloc(PTHREAD_POOL_GROUP *Out)
{
    PTHREAD_POOL_GROUP Group;

    Group = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Group));
    if (!Group)
	return STATUS_NO_MEMORY;

    Group->Refcount = 1;
    Group->Shutdown = FALSE;

    RtlInitializeCriticalSectionEx(&Group->Lock, 0,
				   RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO);

    InitializeListHead(&Group->Members);

    TRACE("allocated group %p\n", Group);

    *Out = Group;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           tp_group_shutdown    (internal)
 *
 * Marks the group object for shutdown.
 */
static VOID TpGroupShutdown(PTHREAD_POOL_GROUP Group)
{
    Group->Shutdown = TRUE;
}

/***********************************************************************
 *           tp_group_release    (internal)
 *
 * Releases a reference to a group object.
 */
static BOOL TpGroupRelease(PTHREAD_POOL_GROUP Group)
{
    if (InterlockedDecrement(&Group->Refcount))
	return FALSE;

    TRACE("destroying group %p\n", Group);

    assert(Group->Shutdown);
    assert(IsListEmpty(&Group->Members));

    RtlDeleteCriticalSection(&Group->Lock);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Group);
    return TRUE;
}

/***********************************************************************
 *           tp_object_initialize    (internal)
 *
 * Initializes members of a threadpool object.
 */
static VOID TpObjectInitialize(PTHREAD_POOL_OBJECT Object, PTHREAD_POOL Pool,
			       PVOID Userdata, PTP_CALLBACK_ENVIRON Environment)
{
    BOOL IsSimpleCallback = (Object->Type == TP_OBJECT_TYPE_SIMPLE);

    Object->Refcount = 1;
    Object->Shutdown = FALSE;

    Object->Pool = Pool;
    Object->Group = NULL;
    Object->Userdata = Userdata;
    Object->GroupCancelCallback = NULL;
    Object->FinalizationCallback = NULL;
    Object->MayRunLong = 0;
    Object->RaceDll = NULL;
    Object->Priority = TP_CALLBACK_PRIORITY_NORMAL;

    memset(&Object->GroupEntry, 0, sizeof(Object->GroupEntry));
    Object->IsGroupMember = FALSE;

    memset(&Object->PoolEntry, 0, sizeof(Object->PoolEntry));
    RtlInitializeConditionVariable(&Object->FinishedEvent);
    RtlInitializeConditionVariable(&Object->GroupFinishedEvent);
    Object->CompletedEvent = NULL;
    Object->NumPendingCallbacks = 0;
    Object->NumRunningCallbacks = 0;
    Object->NumAssociatedCallbacks = 0;
    Object->UpdateSerial = 0;

    if (Environment) {
	if (Environment->Version != 1 && Environment->Version != 3)
	    FIXME("unsupported environment version %u\n", Environment->Version);

	Object->Group = ImplFromTpCleanupGroup(Environment->CleanupGroup);
	Object->GroupCancelCallback = Environment->CleanupGroupCancelCallback;
	Object->FinalizationCallback = Environment->FinalizationCallback;
	Object->MayRunLong = Environment->u.s.LongFunction != 0;
	Object->RaceDll = Environment->RaceDll;
	if (Environment->Version == 3) {
	    TP_CALLBACK_ENVIRON_V3 *EnvironmentV3 = (TP_CALLBACK_ENVIRON_V3 *)Environment;

	    Object->Priority = EnvironmentV3->CallbackPriority;
	    assert(Object->Priority < ARRAYSIZE(Pool->Pools));
	}
	if (Environment->ActivationContext)
	    FIXME("activation context not supported yet\n");

	if (Environment->u.s.Persistent)
	    FIXME("persistent threads not supported yet\n");
    }

    if (Object->RaceDll)
	LdrAddRefDll(0, Object->RaceDll);

    TRACE("allocated object %p of type %u\n", Object, Object->Type);

    /* For simple callbacks we have to run tp_object_submit before adding this object
     * to the cleanup group. As soon as the cleanup group members are released ->shutdown
     * will be set, and tp_object_submit would fail with an assertion. */

    if (IsSimpleCallback)
	TpObjectSubmit(Object, FALSE);

    if (Object->Group) {
	PTHREAD_POOL_GROUP Group = Object->Group;
	InterlockedIncrement(&Group->Refcount);

	RtlEnterCriticalSection(&Group->Lock);
	InsertTailList(&Group->Members, &Object->GroupEntry);
	Object->IsGroupMember = TRUE;
	RtlLeaveCriticalSection(&Group->Lock);
    }

    if (IsSimpleCallback)
	TpObjectRelease(Object);
}

static VOID TpObjectPrioQueue(PTHREAD_POOL_OBJECT Object)
{
    ++Object->Pool->NumBusyWorkers;
    InsertTailList(&Object->Pool->Pools[Object->Priority], &Object->PoolEntry);
}

/***********************************************************************
 *           tp_object_submit    (internal)
 *
 * Submits a threadpool object to the associated threadpool. This
 * function has to be VOID because TpPostWork can never fail on Windows.
 */
static VOID TpObjectSubmit(PTHREAD_POOL_OBJECT Object, BOOL Signaled)
{
    PTHREAD_POOL Pool = Object->Pool;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    assert(!Object->Shutdown);
    assert(!Pool->Shutdown);

    RtlEnterCriticalSection(&Pool->Cs);

    /* Start new worker threads if required. */
    if (Pool->NumBusyWorkers >= Pool->NumWorkers && Pool->NumWorkers < Pool->MaxWorkers)
	Status = TpNewWorkerThread(Pool);

    /* Queue work item and increment refcount. */
    InterlockedIncrement(&Object->Refcount);
    if (!Object->NumPendingCallbacks++)
	TpObjectPrioQueue(Object);

    /* Count how often the object was signaled. */
    if (Object->Type == TP_OBJECT_TYPE_WAIT && Signaled)
	Object->Wait.Signaled++;

    /* No new thread started - wake up one existing thread. */
    if (Status != STATUS_SUCCESS) {
	assert(Pool->NumWorkers > 0);
	RtlWakeConditionVariable(&Pool->UpdateEvent);
    }

    RtlLeaveCriticalSection(&Pool->Cs);
}

/***********************************************************************
 *           tp_object_cancel    (internal)
 *
 * Cancels all currently pending callbacks for a specific object.
 */
static VOID TpObjectCancel(PTHREAD_POOL_OBJECT Object)
{
    PTHREAD_POOL Pool = Object->Pool;
    LONG PendingCallbacks = 0;

    RtlEnterCriticalSection(&Pool->Cs);
    if (Object->NumPendingCallbacks) {
	PendingCallbacks = Object->NumPendingCallbacks;
	Object->NumPendingCallbacks = 0;
	RemoveEntryList(&Object->PoolEntry);

	if (Object->Type == TP_OBJECT_TYPE_WAIT)
	    Object->Wait.Signaled = 0;
    }
    if (Object->Type == TP_OBJECT_TYPE_IO) {
	Object->Io.SkippedCount += Object->Io.PendingCount;
	Object->Io.PendingCount = 0;
    }
    RtlLeaveCriticalSection(&Pool->Cs);

    while (PendingCallbacks--)
	TpObjectRelease(Object);
}

static BOOL ObjectIsFinished(PTHREAD_POOL_OBJECT Object, BOOL Group)
{
    if (Object->NumPendingCallbacks)
	return FALSE;
    if (Object->Type == TP_OBJECT_TYPE_IO && Object->Io.PendingCount)
	return FALSE;

    if (Group)
	return !Object->NumRunningCallbacks;
    else
	return !Object->NumAssociatedCallbacks;
}

/***********************************************************************
 *           tp_object_wait    (internal)
 *
 * Waits until all pending and running callbacks of a specific object
 * have been processed.
 */
static VOID TpObjectWait(PTHREAD_POOL_OBJECT Object, BOOL GroupWait)
{
    PTHREAD_POOL Pool = Object->Pool;

    RtlEnterCriticalSection(&Pool->Cs);
    while (!RtlDllShutdownInProgress() && !ObjectIsFinished(Object, GroupWait)) {
	if (GroupWait)
	    RtlSleepConditionVariableCS(&Object->GroupFinishedEvent, &Pool->Cs, NULL);
	else
	    RtlSleepConditionVariableCS(&Object->FinishedEvent, &Pool->Cs, NULL);
    }
    RtlLeaveCriticalSection(&Pool->Cs);
}

static VOID TpIoQueueUnlock(PTHREAD_POOL_OBJECT Io)
{
    assert(Io->Type == TP_OBJECT_TYPE_IO);

    RtlEnterCriticalSection(&IoQueue.Lock);

    assert(IoQueue.Objcount);

    if (!Io->Shutdown && !--IoQueue.Objcount)
	NtSetIoCompletion(IoQueue.Port, 0, 0, STATUS_SUCCESS, 0);

    RtlLeaveCriticalSection(&IoQueue.Lock);
}

/***********************************************************************
 *           tp_object_prepare_shutdown    (internal)
 *
 * Prepares a threadpool object for shutdown.
 */
static VOID TpObjectPrepareShutdown(PTHREAD_POOL_OBJECT Object)
{
    if (Object->Type == TP_OBJECT_TYPE_TIMER)
	TpTimerQueueUnlock(Object);
    else if (Object->Type == TP_OBJECT_TYPE_WAIT)
	TpWaitQueueUnlock(Object);
    else if (Object->Type == TP_OBJECT_TYPE_IO)
	TpIoQueueUnlock(Object);
}

static VOID TpWaitCloseDupedHandle(PTHREAD_POOL_OBJECT Wait)
{
    if (Wait->Wait.DupedHandle) {
	NtClose(Wait->Wait.DupedHandle);
	Wait->Wait.DupedHandle = NULL;
    }
}

/***********************************************************************
 *           tp_object_release    (internal)
 *
 * Releases a reference to a threadpool object.
 */
static BOOL TpObjectRelease(PTHREAD_POOL_OBJECT Object)
{
    if (InterlockedDecrement(&Object->Refcount))
	return FALSE;

    TRACE("destroying object %p of type %u\n", Object, Object->Type);

    assert(Object->Shutdown);
    assert(!Object->NumPendingCallbacks);
    assert(!Object->NumRunningCallbacks);
    assert(!Object->NumAssociatedCallbacks);

    /* release reference to the group */
    if (Object->Group) {
	PTHREAD_POOL_GROUP Group = Object->Group;

	RtlEnterCriticalSection(&Group->Lock);
	if (Object->IsGroupMember) {
	    RemoveEntryList(&Object->GroupEntry);
	    Object->IsGroupMember = FALSE;
	}
	RtlLeaveCriticalSection(&Group->Lock);

	TpGroupRelease(Group);
    }

    if (Object->Type == TP_OBJECT_TYPE_WAIT)
	TpWaitCloseDupedHandle(Object);

    TpThreadPoolUnlock(Object->Pool);

    if (Object->RaceDll)
	LdrUnloadDll(Object->RaceDll);

    if (Object->CompletedEvent && Object->CompletedEvent != INVALID_HANDLE_VALUE)
	NtSetEvent(Object->CompletedEvent, NULL);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
    return TRUE;
}

static PLIST_ENTRY ThreadPoolGetNextItem(PCTHREAD_POOL Pool)
{
    PLIST_ENTRY Ptr = NULL;
    for (ULONG i = 0; i < ARRAYSIZE(Pool->Pools); ++i) {
	if ((Ptr = Pool->Pools[i].Flink))
	    break;
    }

    return Ptr;
}

/***********************************************************************
 *           tp_object_execute    (internal)
 *
 * Executes a threadpool object callback, object->pool->cs has to be
 * held.
 */
static VOID TpObjectExecute(PTHREAD_POOL_OBJECT Object, BOOL WaitThread)
{
    PTP_CALLBACK_INSTANCE CallbackInstance;
    THREAD_POOL_INSTANCE Instance;
    IO_COMPLETION Completion;
    PTHREAD_POOL Pool = Object->Pool;
    TP_WAIT_RESULT WaitResult = 0;
    NTSTATUS Status;

    Object->NumPendingCallbacks--;

    /* For wait objects check if they were signaled or have timed out. */
    if (Object->Type == TP_OBJECT_TYPE_WAIT) {
	WaitResult = Object->Wait.Signaled ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
	if (WaitResult == WAIT_OBJECT_0)
	    Object->Wait.Signaled--;
    } else if (Object->Type == TP_OBJECT_TYPE_IO) {
	assert(Object->Io.CompletionCount);
	Completion = Object->Io.Completions[--Object->Io.CompletionCount];
    }

    /* Leave critical section and do the actual callback. */
    Object->NumAssociatedCallbacks++;
    Object->NumRunningCallbacks++;
    RtlLeaveCriticalSection(&Pool->Cs);
    if (WaitThread)
	RtlLeaveCriticalSection(&WaitQueue.Lock);

    /* Initialize threadpool instance struct. */
    CallbackInstance = (PTP_CALLBACK_INSTANCE)&Instance;
    Instance.Object = Object;
    Instance.Threadid = GetCurrentThreadId();
    Instance.Associated = TRUE;
    Instance.MayRunLong = Object->MayRunLong;
    Instance.Cleanup.CriticalSection = NULL;
    Instance.Cleanup.Mutex = NULL;
    Instance.Cleanup.Semaphore = NULL;
    Instance.Cleanup.SemaphoreCount = 0;
    Instance.Cleanup.Event = NULL;
    Instance.Cleanup.Library = NULL;

    switch (Object->Type) {
    case TP_OBJECT_TYPE_SIMPLE: {
	TRACE("executing simple callback %p(%p, %p)\n", Object->Simple.Callback,
	      CallbackInstance, Object->Userdata);
	ThreadPoolCallCallback(THREADPOOL_CALLBACK_SIMPLE, Object->Simple.Callback,
			       (ULONG_PTR)CallbackInstance, (ULONG_PTR)Object->Userdata,
			       0, 0, 0);
	TRACE("callback %p returned\n", Object->Simple.Callback);
	break;
    }

    case TP_OBJECT_TYPE_WORK: {
	TRACE("executing work callback %p(%p, %p, %p)\n", Object->Work.Callback,
	      CallbackInstance, Object->Userdata, Object);
	ThreadPoolCallCallback(THREADPOOL_CALLBACK_WORK, Object->Work.Callback,
			       (ULONG_PTR)CallbackInstance, (ULONG_PTR)Object->Userdata,
			       (ULONG_PTR)Object, 0, 0);
	TRACE("callback %p returned\n", Object->Work.Callback);
	break;
    }

    case TP_OBJECT_TYPE_TIMER: {
	TRACE("executing timer callback %p(%p, %p, %p)\n", Object->Timer.Callback,
	      CallbackInstance, Object->Userdata, Object);
	ThreadPoolCallCallback(THREADPOOL_CALLBACK_TIMER, Object->Timer.Callback,
			       (ULONG_PTR)CallbackInstance, (ULONG_PTR)Object->Userdata,
			       (ULONG_PTR)Object, 0, 0);
	TRACE("callback %p returned\n", Object->Timer.Callback);
	break;
    }

    case TP_OBJECT_TYPE_WAIT: {
	TRACE("executing wait callback %p(%p, %p, %p, %u)\n", Object->Wait.Callback,
	      CallbackInstance, Object->Userdata, Object, WaitResult);
	ThreadPoolCallCallback(THREADPOOL_CALLBACK_WAIT, Object->Wait.Callback,
			       (ULONG_PTR)CallbackInstance, (ULONG_PTR)Object->Userdata,
			       (ULONG_PTR)Object, WaitResult, 0);
	TRACE("callback %p returned\n", Object->Wait.Callback);
	break;
    }

    case TP_OBJECT_TYPE_IO: {
	TRACE("executing I/O callback %p(%p, %p, %#Ix, %p, %p)\n", Object->Io.Callback,
	      CallbackInstance, Object->Userdata, Completion.Cvalue, &Completion.Iosb,
	      (PTP_IO)Object);
	ThreadPoolCallCallback(THREADPOOL_CALLBACK_IO, Object->Io.Callback,
			       (ULONG_PTR)CallbackInstance, (ULONG_PTR)Object->Userdata,
			       Completion.Cvalue, (ULONG_PTR)&Completion.Iosb,
			       (ULONG_PTR)Object);
	TRACE("callback %p returned\n", Object->Io.Callback);
	break;
    }

    default:
	assert(0);
	break;
    }

    /* Execute finalization callback. */
    if (Object->FinalizationCallback) {
	TRACE("executing finalization callback %p(%p, %p)\n",
	      Object->FinalizationCallback, CallbackInstance, Object->Userdata);
	ThreadPoolCallCallback(THREADPOOL_CALLBACK_SIMPLE, Object->FinalizationCallback,
			       (ULONG_PTR)CallbackInstance, (ULONG_PTR)Object->Userdata,
			       0, 0, 0);
	TRACE("callback %p returned\n", Object->FinalizationCallback);
    }

    /* Execute cleanup tasks. */
    if (Instance.Cleanup.CriticalSection) {
	RtlLeaveCriticalSection(Instance.Cleanup.CriticalSection);
    }
    if (Instance.Cleanup.Mutex) {
	Status = NtReleaseMutant(Instance.Cleanup.Mutex, NULL);
	if (Status != STATUS_SUCCESS)
	    goto skip_cleanup;
    }
    if (Instance.Cleanup.Semaphore) {
	Status = NtReleaseSemaphore(Instance.Cleanup.Semaphore,
				    Instance.Cleanup.SemaphoreCount, NULL);
	if (Status != STATUS_SUCCESS)
	    goto skip_cleanup;
    }
    if (Instance.Cleanup.Event) {
	Status = NtSetEvent(Instance.Cleanup.Event, NULL);
	if (Status != STATUS_SUCCESS)
	    goto skip_cleanup;
    }
    if (Instance.Cleanup.Library) {
	Status = LdrUnloadDll(Instance.Cleanup.Library);
	if (Status != STATUS_SUCCESS)
	    goto skip_cleanup;
    }
skip_cleanup:
    if (WaitThread)
	RtlEnterCriticalSection(&WaitQueue.Lock);
    RtlEnterCriticalSection(&Pool->Cs);

    /* Simple callbacks are automatically shutdown after execution. */
    if (Object->Type == TP_OBJECT_TYPE_SIMPLE) {
	TpObjectPrepareShutdown(Object);
	Object->Shutdown = TRUE;
    }

    Object->NumRunningCallbacks--;
    if (ObjectIsFinished(Object, TRUE))
	RtlWakeAllConditionVariable(&Object->GroupFinishedEvent);

    if (Instance.Associated) {
	Object->NumAssociatedCallbacks--;
	if (ObjectIsFinished(Object, FALSE))
	    RtlWakeAllConditionVariable(&Object->FinishedEvent);
    }
}

/***********************************************************************
 *           threadpool_worker_proc    (internal)
 */
NTAPI ULONG ThreadPoolWorkerProc(PVOID Param)
{
    PTHREAD_POOL Pool = Param;
    LARGE_INTEGER Timeout;
    PLIST_ENTRY Ptr;

    TRACE("starting worker thread for pool %p\n", Pool);
    SetThreadName(L"wine_threadpool_worker");

    RtlEnterCriticalSection(&Pool->Cs);
    for (;;) {
	while ((Ptr = ThreadPoolGetNextItem(Pool))) {
	    PTHREAD_POOL_OBJECT Object = CONTAINING_RECORD(Ptr, THREAD_POOL_OBJECT,
							   PoolEntry);
	    assert(Object->NumPendingCallbacks > 0);

	    /* If further pending callbacks are queued, move the work item to
	     * the end of the pool list. Otherwise remove it from the pool. */
	    RemoveEntryList(&Object->PoolEntry);
	    if (Object->NumPendingCallbacks > 1)
		TpObjectPrioQueue(Object);

	    TpObjectExecute(Object, FALSE);

	    assert(Pool->NumBusyWorkers);
	    Pool->NumBusyWorkers--;

	    TpObjectRelease(Object);
	}

	/* Shutdown worker thread if requested. */
	if (Pool->Shutdown)
	    break;

	/* Wait for new tasks or until the timeout expires. A thread only terminates
	 * when no new tasks are available, and the number of threads can be
	 * decreased without violating the min_workers limit. An exception is when
	 * min_workers == 0, then objcount is used to detect if the last thread
	 * can be terminated. */
	Timeout.QuadPart = (ULONGLONG)THREADPOOL_WORKER_TIMEOUT * -10000;
	if (RtlSleepConditionVariableCS(&Pool->UpdateEvent, &Pool->Cs, &Timeout) ==
		STATUS_TIMEOUT &&
	    !ThreadPoolGetNextItem(Pool) &&
	    (Pool->NumWorkers > max(Pool->MinWorkers, 1) ||
	     (!Pool->MinWorkers && !Pool->Objcount))) {
	    break;
	}
    }
    Pool->NumWorkers--;
    RtlLeaveCriticalSection(&Pool->Cs);

    TRACE("terminating worker thread for pool %p\n", Pool);
    TpThreadPoolRelease(Pool);
    RtlpExitThreadFunc(0);
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           TpAllocCleanupGroup    (NTDLL.@)
 */
NTAPI NTSTATUS TpAllocCleanupGroup(PTP_CLEANUP_GROUP *Out)
{
    TRACE("%p\n", Out);

    return TpGroupAlloc((PTHREAD_POOL_GROUP *)Out);
}

/***********************************************************************
 *           TpAllocIoCompletion    (NTDLL.@)
 */
NTAPI NTSTATUS TpAllocIoCompletion(PTP_IO *Out, HANDLE File, PTP_IO_CALLBACK Callback,
				   PVOID Userdata, PTP_CALLBACK_ENVIRON Environment)
{
    PTHREAD_POOL_OBJECT Object;
    PTHREAD_POOL Pool;
    NTSTATUS Status;

    TRACE("%p %p %p %p %p\n", Out, File, Callback, Userdata, Environment);

    if (!(Object = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY,
				   sizeof(*Object))))
	return STATUS_NO_MEMORY;

    if ((Status = TpThreadPoolLock(&Pool, Environment))) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    Object->Type = TP_OBJECT_TYPE_IO;
    Object->Io.Callback = Callback;
    if (!(Object->Io.Completions = RtlAllocateHeap(
	      RtlGetProcessHeap(), 0, 8 * sizeof(*Object->Io.Completions)))) {
	TpThreadPoolUnlock(Pool);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    if ((Status = TpIoQueueLock(Object, File))) {
	TpThreadPoolUnlock(Pool);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object->Io.Completions);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    TpObjectInitialize(Object, Pool, Userdata, Environment);

    *Out = (PTP_IO)Object;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           TpAllocPool    (NTDLL.@)
 */
NTAPI NTSTATUS TpAllocPool(PTP_POOL *Out, PVOID Reserved)
{
    TRACE("%p %p\n", Out, Reserved);

    if (Reserved)
	FIXME("reserved argument is nonzero (%p)\n", Reserved);

    return TpThreadPoolAlloc((PTHREAD_POOL *)Out);
}

/***********************************************************************
 *           TpAllocTimer    (NTDLL.@)
 */
NTAPI NTSTATUS TpAllocTimer(PTP_TIMER *Out, PTP_TIMER_CALLBACK Callback, PVOID Userdata,
			    PTP_CALLBACK_ENVIRON Environment)
{
    PTHREAD_POOL_OBJECT Object;
    PTHREAD_POOL Pool;
    NTSTATUS Status;

    TRACE("%p %p %p %p\n", Out, Callback, Userdata, Environment);

    Object = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Object));
    if (!Object)
	return STATUS_NO_MEMORY;

    Status = TpThreadPoolLock(&Pool, Environment);
    if (Status) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    Object->Type = TP_OBJECT_TYPE_TIMER;
    Object->Timer.Callback = Callback;

    Status = TpTimerQueueLock(Object);
    if (Status) {
	TpThreadPoolUnlock(Pool);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    TpObjectInitialize(Object, Pool, Userdata, Environment);

    *Out = (PTP_TIMER)Object;
    return STATUS_SUCCESS;
}

static NTSTATUS TpAllocWaitEx(PTP_WAIT *Out, PTP_WAIT_CALLBACK Callback, PVOID Userdata,
			      PTP_CALLBACK_ENVIRON Environment, DWORD Flags)
{
    PTHREAD_POOL_OBJECT Object;
    PTHREAD_POOL Pool;
    NTSTATUS Status;

    Object = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Object));
    if (!Object)
	return STATUS_NO_MEMORY;

    Status = TpThreadPoolLock(&Pool, Environment);
    if (Status) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    Object->Type = TP_OBJECT_TYPE_WAIT;
    Object->Wait.Callback = Callback;
    Object->Wait.Flags = Flags;

    Status = TpWaitQueueLock(Object);
    if (Status) {
	TpThreadPoolUnlock(Pool);
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    TpObjectInitialize(Object, Pool, Userdata, Environment);

    *Out = (PTP_WAIT)Object;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           TpAllocWait     (NTDLL.@)
 */
NTAPI NTSTATUS TpAllocWait(PTP_WAIT *Out, PTP_WAIT_CALLBACK Callback, PVOID Userdata,
			   PTP_CALLBACK_ENVIRON Environment)
{
    TRACE("%p %p %p %p\n", Out, Callback, Userdata, Environment);
    return TpAllocWaitEx(Out, Callback, Userdata, Environment, WT_EXECUTEONLYONCE);
}

/***********************************************************************
 *           TpAllocWork    (NTDLL.@)
 */
NTAPI NTSTATUS TpAllocWork(PTP_WORK *Out, PTP_WORK_CALLBACK Callback, PVOID Userdata,
			   PTP_CALLBACK_ENVIRON Environment)
{
    PTHREAD_POOL_OBJECT Object;
    PTHREAD_POOL Pool;
    NTSTATUS Status;

    TRACE("%p %p %p %p\n", Out, Callback, Userdata, Environment);

    Object = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Object));
    if (!Object)
	return STATUS_NO_MEMORY;

    Status = TpThreadPoolLock(&Pool, Environment);
    if (Status) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    Object->Type = TP_OBJECT_TYPE_WORK;
    Object->Work.Callback = Callback;
    TpObjectInitialize(Object, Pool, Userdata, Environment);

    *Out = (PTP_WORK)Object;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           TpCancelAsyncIoOperation    (NTDLL.@)
 */
NTAPI VOID TpCancelAsyncIoOperation(PTP_IO Io)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpIo(Io);

    TRACE("%p\n", Io);

    RtlEnterCriticalSection(&This->Pool->Cs);

    TRACE("pending_count %u.\n", This->Io.PendingCount);

    This->Io.PendingCount--;
    if (ObjectIsFinished(This, TRUE))
	RtlWakeAllConditionVariable(&This->GroupFinishedEvent);
    if (ObjectIsFinished(This, FALSE))
	RtlWakeAllConditionVariable(&This->FinishedEvent);

    RtlLeaveCriticalSection(&This->Pool->Cs);
}

/***********************************************************************
 *           TpCallbackLeaveCriticalSectionOnCompletion    (NTDLL.@)
 */
NTAPI VOID TpCallbackLeaveCriticalSectionOnCompletion(PTP_CALLBACK_INSTANCE Instance,
						      PRTL_CRITICAL_SECTION Crit)
{
    PTHREAD_POOL_INSTANCE This = ImplFromTpCallbackInstance(Instance);

    TRACE("%p %p\n", Instance, Crit);

    if (!This->Cleanup.CriticalSection)
	This->Cleanup.CriticalSection = Crit;
}

/***********************************************************************
 *           TpCallbackMayRunLong    (NTDLL.@)
 */
NTAPI NTSTATUS TpCallbackMayRunLong(PTP_CALLBACK_INSTANCE Instance)
{
    PTHREAD_POOL_INSTANCE This = ImplFromTpCallbackInstance(Instance);
    PTHREAD_POOL_OBJECT Object = This->Object;
    PTHREAD_POOL Pool;
    NTSTATUS Status = STATUS_SUCCESS;

    TRACE("%p\n", Instance);

    if (This->Threadid != GetCurrentThreadId()) {
	ERR("called from wrong thread, ignoring\n");
	return STATUS_UNSUCCESSFUL; /* FIXME */
    }

    if (This->MayRunLong)
	return STATUS_SUCCESS;

    Pool = Object->Pool;
    RtlEnterCriticalSection(&Pool->Cs);

    /* Start new worker threads if required. */
    if (Pool->NumBusyWorkers >= Pool->NumWorkers) {
	if (Pool->NumWorkers < Pool->MaxWorkers) {
	    Status = TpNewWorkerThread(Pool);
	} else {
	    Status = STATUS_TOO_MANY_THREADS;
	}
    }

    RtlLeaveCriticalSection(&Pool->Cs);
    This->MayRunLong = TRUE;
    return Status;
}

/***********************************************************************
 *           TpCallbackReleaseMutexOnCompletion    (NTDLL.@)
 */
NTAPI VOID TpCallbackReleaseMutexOnCompletion(PTP_CALLBACK_INSTANCE Instance,
					      HANDLE Mutex)
{
    PTHREAD_POOL_INSTANCE This = ImplFromTpCallbackInstance(Instance);

    TRACE("%p %p\n", Instance, Mutex);

    if (!This->Cleanup.Mutex)
	This->Cleanup.Mutex = Mutex;
}

/***********************************************************************
 *           TpCallbackReleaseSemaphoreOnCompletion    (NTDLL.@)
 */
NTAPI VOID TpCallbackReleaseSemaphoreOnCompletion(PTP_CALLBACK_INSTANCE Instance,
						  HANDLE Semaphore, DWORD Count)
{
    PTHREAD_POOL_INSTANCE This = ImplFromTpCallbackInstance(Instance);

    TRACE("%p %p %u\n", Instance, Semaphore, Count);

    if (!This->Cleanup.Semaphore) {
	This->Cleanup.Semaphore = Semaphore;
	This->Cleanup.SemaphoreCount = Count;
    }
}

/***********************************************************************
 *           TpCallbackSetEventOnCompletion    (NTDLL.@)
 */
NTAPI VOID TpCallbackSetEventOnCompletion(PTP_CALLBACK_INSTANCE Instance, HANDLE Event)
{
    PTHREAD_POOL_INSTANCE This = ImplFromTpCallbackInstance(Instance);

    TRACE("%p %p\n", Instance, Event);

    if (!This->Cleanup.Event)
	This->Cleanup.Event = Event;
}

/***********************************************************************
 *           TpCallbackUnloadDllOnCompletion    (NTDLL.@)
 */
NTAPI VOID TpCallbackUnloadDllOnCompletion(PTP_CALLBACK_INSTANCE Instance, HMODULE Module)
{
    PTHREAD_POOL_INSTANCE This = ImplFromTpCallbackInstance(Instance);

    TRACE("%p %p\n", Instance, Module);

    if (!This->Cleanup.Library)
	This->Cleanup.Library = Module;
}

/***********************************************************************
 *           TpDisassociateCallback    (NTDLL.@)
 */
NTAPI VOID TpDisassociateCallback(PTP_CALLBACK_INSTANCE Instance)
{
    PTHREAD_POOL_INSTANCE This = ImplFromTpCallbackInstance(Instance);
    PTHREAD_POOL_OBJECT Object = This->Object;
    PTHREAD_POOL Pool;

    TRACE("%p\n", Instance);

    if (This->Threadid != GetCurrentThreadId()) {
	ERR("called from wrong thread, ignoring\n");
	return;
    }

    if (!This->Associated)
	return;

    Pool = Object->Pool;
    RtlEnterCriticalSection(&Pool->Cs);

    Object->NumAssociatedCallbacks--;
    if (ObjectIsFinished(Object, FALSE))
	RtlWakeAllConditionVariable(&Object->FinishedEvent);

    RtlLeaveCriticalSection(&Pool->Cs);
    This->Associated = FALSE;
}

/***********************************************************************
 *           TpIsTimerSet    (NTDLL.@)
 */
NTAPI BOOL TpIsTimerSet(PTP_TIMER Timer)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpTimer(Timer);

    TRACE("%p\n", Timer);

    return This->Timer.TimerSet;
}

/***********************************************************************
 *           TpPostWork    (NTDLL.@)
 */
NTAPI VOID TpPostWork(PTP_WORK Work)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpWork(Work);

    TRACE("%p\n", Work);

    TpObjectSubmit(This, FALSE);
}

/***********************************************************************
 *           TpReleaseCleanupGroup    (NTDLL.@)
 */
NTAPI VOID TpReleaseCleanupGroup(PTP_CLEANUP_GROUP Group)
{
    PTHREAD_POOL_GROUP This = ImplFromTpCleanupGroup(Group);

    TRACE("%p\n", Group);

    TpGroupShutdown(This);
    TpGroupRelease(This);
}

/***********************************************************************
 *           TpReleaseCleanupGroupMembers    (NTDLL.@)
 */
NTAPI VOID TpReleaseCleanupGroupMembers(PTP_CLEANUP_GROUP Group, BOOL CancelPending,
					PVOID Userdata)
{
    PTHREAD_POOL_GROUP This = ImplFromTpCleanupGroup(Group);
    LIST_ENTRY Members;

    TRACE("%p %u %p\n", Group, CancelPending, Userdata);

    RtlEnterCriticalSection(&This->Lock);

    /* Unset group, increase references, and mark objects for shutdown */
    LoopOverList(Object, &This->Members, THREAD_POOL_OBJECT, GroupEntry) {
	assert(Object->Group == This);
	assert(Object->IsGroupMember);

	if (InterlockedIncrement(&Object->Refcount) == 1) {
	    /* Object is basically already destroyed, but group reference
	     * was not deleted yet. We can safely ignore this object. */
	    InterlockedDecrement(&Object->Refcount);
	    RemoveEntryList(&Object->GroupEntry);
	    Object->IsGroupMember = FALSE;
	    continue;
	}

	Object->IsGroupMember = FALSE;
	TpObjectPrepareShutdown(Object);
    }

    /* Move members to a new temporary list */
    InitializeListHead(&Members);
    AppendTailListHead(&Members, &This->Members);

    RtlLeaveCriticalSection(&This->Lock);

    /* Cancel pending callbacks if requested */
    if (CancelPending) {
	LoopOverList(Object, &Members, THREAD_POOL_OBJECT, GroupEntry) {
	    TpObjectCancel(Object);
	}
    }

    /* Wait for remaining callbacks to finish */
    LoopOverList(Object, &Members, THREAD_POOL_OBJECT, GroupEntry) {
	TpObjectWait(Object, TRUE);

	if (!Object->Shutdown) {
	    /* Execute group cancellation callback if defined, and if this was actually a
	     * group cancel. */
	    if (CancelPending && Object->GroupCancelCallback) {
		TRACE("executing group cancel callback %p(%p, %p)\n",
		      Object->GroupCancelCallback, Object->Userdata, Userdata);
		ThreadPoolCallCallback(THREADPOOL_CALLBACK_SIMPLE,
				       Object->GroupCancelCallback,
				       (ULONG_PTR)Object->Userdata, (ULONG_PTR)Userdata,
				       0, 0, 0);
		TRACE("callback %p returned\n", Object->GroupCancelCallback);
	    }

	    if (Object->Type != TP_OBJECT_TYPE_SIMPLE)
		TpObjectRelease(Object);
	}

	Object->Shutdown = TRUE;
	TpObjectRelease(Object);
    }
}

/***********************************************************************
 *           TpReleaseIoCompletion    (NTDLL.@)
 */
NTAPI VOID TpReleaseIoCompletion(PTP_IO Io)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpIo(Io);
    BOOL CanDestroy;

    TRACE("%p\n", Io);

    RtlEnterCriticalSection(&This->Pool->Cs);
    This->Io.ShuttingDown = TRUE;
    CanDestroy = !This->Io.PendingCount && !This->Io.SkippedCount;
    RtlLeaveCriticalSection(&This->Pool->Cs);

    if (CanDestroy) {
	TpObjectPrepareShutdown(This);
	This->Shutdown = TRUE;
	TpObjectRelease(This);
    }
}

/***********************************************************************
 *           TpReleasePool    (NTDLL.@)
 */
NTAPI VOID TpReleasePool(PTP_POOL Pool)
{
    PTHREAD_POOL This = ImplFromTpPool(Pool);

    TRACE("%p\n", Pool);

    TpThreadPoolShutdown(This);
    TpThreadPoolRelease(This);
}

/***********************************************************************
 *           TpReleaseTimer     (NTDLL.@)
 */
NTAPI VOID TpReleaseTimer(PTP_TIMER Timer)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpTimer(Timer);

    TRACE("%p\n", Timer);

    TpObjectPrepareShutdown(This);
    This->Shutdown = TRUE;
    TpObjectRelease(This);
}

/***********************************************************************
 *           TpReleaseWait    (NTDLL.@)
 */
NTAPI VOID TpReleaseWait(PTP_WAIT Wait)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpWait(Wait);

    TRACE("%p\n", Wait);

    TpObjectPrepareShutdown(This);
    This->Shutdown = TRUE;
    TpObjectRelease(This);
}

/***********************************************************************
 *           TpReleaseWork    (NTDLL.@)
 */
NTAPI VOID TpReleaseWork(PTP_WORK Work)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpWork(Work);

    TRACE("%p\n", Work);

    TpObjectPrepareShutdown(This);
    This->Shutdown = TRUE;
    TpObjectRelease(This);
}

/***********************************************************************
 *           TpSetPoolMaxThreads    (NTDLL.@)
 */
NTAPI VOID TpSetPoolMaxThreads(PTP_POOL Pool, DWORD Maximum)
{
    PTHREAD_POOL This = ImplFromTpPool(Pool);

    TRACE("%p %u\n", Pool, Maximum);

    RtlEnterCriticalSection(&This->Cs);
    This->MaxWorkers = max(Maximum, 1);
    This->MinWorkers = min(This->MinWorkers, This->MaxWorkers);
    RtlLeaveCriticalSection(&This->Cs);
}

/***********************************************************************
 *           TpSetPoolMinThreads    (NTDLL.@)
 */
NTAPI BOOL TpSetPoolMinThreads(PTP_POOL Pool, DWORD Minimum)
{
    PTHREAD_POOL This = ImplFromTpPool(Pool);
    NTSTATUS Status = STATUS_SUCCESS;

    TRACE("%p %u\n", Pool, Minimum);

    RtlEnterCriticalSection(&This->Cs);

    while (This->NumWorkers < Minimum) {
	Status = TpNewWorkerThread(This);
	if (Status != STATUS_SUCCESS)
	    break;
    }

    if (Status == STATUS_SUCCESS) {
	This->MinWorkers = Minimum;
	This->MaxWorkers = max(This->MinWorkers, This->MaxWorkers);
    }

    RtlLeaveCriticalSection(&This->Cs);
    return !Status;
}

/***********************************************************************
 *           TpSetTimer    (NTDLL.@)
 */
NTAPI VOID TpSetTimer(PTP_TIMER Timer, PLARGE_INTEGER Timeout, LONG Period,
		      LONG WindowLength)
{
    TpSetTimerEx(Timer, Timeout, Period, WindowLength);
}

/***********************************************************************
 *           TpSetTimerEx    (NTDLL.@)
 */
NTAPI BOOL TpSetTimerEx(PTP_TIMER Timer, PLARGE_INTEGER Timeout, LONG Period,
			LONG WindowLength)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpTimer(Timer);
    PLIST_ENTRY PendingTimers;
    BOOL SubmitTimer = FALSE;
    BOOL WasPending;
    ULONGLONG Timestamp;

    TRACE("%p %p %d %d\n", Timer, Timeout, Period, WindowLength);

    RtlEnterCriticalSection(&TimerQueue.Lock);

    assert(This->Timer.TimerInitialized);
    WasPending = This->Timer.TimerPending;
    This->Timer.TimerSet = Timeout != NULL;

    /* Convert relative timeout to absolute timestamp and handle a timeout
     * of zero, which means that the timer is submitted immediately. */
    if (Timeout) {
	if (Timeout->QuadPart > 0) {
	    Timestamp = Timeout->QuadPart;
	    PendingTimers = &TimerQueue.AbsTimers;
	} else if (Timeout->QuadPart < 0) {
	    LARGE_INTEGER RelNow;
	    NtQueryPerformanceCounter(&RelNow, NULL);
	    Timestamp = QpcAdd100ns(RelNow.QuadPart, 0 - (ULONGLONG)Timeout->QuadPart);
	    PendingTimers = &TimerQueue.RelTimers;
	} else if (!Period) {
	    Timeout = NULL;
	    SubmitTimer = TRUE;
	} else {
	    LARGE_INTEGER RelNow;
	    NtQueryPerformanceCounter(&RelNow, NULL);
	    Timestamp = QpcAdd100ns(RelNow.QuadPart, (ULONGLONG)Period * 10000);
	    PendingTimers = &TimerQueue.RelTimers;
	    SubmitTimer = TRUE;
	}
    }

    /* First remove existing timeout. */
    if (This->Timer.TimerPending) {
	RemoveEntryList(&This->Timer.TimerEntry);
	This->Timer.TimerPending = FALSE;
    }

    /* If the timer was enabled, then add it back to the queue. */
    if (Timeout) {
	This->Timer.Timeout = Timestamp;
	This->Timer.Period = Period;
	This->Timer.WindowLength = WindowLength;

	LoopOverList(OtherTimer, PendingTimers, THREAD_POOL_OBJECT, Timer.TimerEntry) {
	    assert(OtherTimer->Type == TP_OBJECT_TYPE_TIMER);
	    if (This->Timer.Timeout < OtherTimer->Timer.Timeout) {
		InsertTailList(&OtherTimer->Timer.TimerEntry, &This->Timer.TimerEntry);
		break;
	    }
	}

	/* Update timeout if needed. */
	if (PendingTimers->Flink == &This->Timer.TimerEntry) {
	    LARGE_INTEGER RelNow;
	    NtQueryPerformanceCounter(&RelNow, NULL);
	    UpdateTimers(RelNow.QuadPart);
	}

	This->Timer.TimerPending = TRUE;
    }

    RtlLeaveCriticalSection(&TimerQueue.Lock);

    if (SubmitTimer)
	TpObjectSubmit(This, FALSE);

    return WasPending;
}

/***********************************************************************
 *           TpSetWait    (NTDLL.@)
 */
NTAPI VOID TpSetWait(PTP_WAIT Wait, HANDLE Handle, PLARGE_INTEGER Timeout)
{
    TpSetWaitEx(Wait, Handle, Timeout, NULL);
}

/***********************************************************************
 *           TpSetWaitEx    (NTDLL.@)
 */
NTAPI BOOL TpSetWaitEx(PTP_WAIT Wait, HANDLE Handle, PLARGE_INTEGER Timeout,
		       PVOID Reserved)
{
    if (Reserved)
	return FALSE;

    PTHREAD_POOL_OBJECT This = ImplFromTpWait(Wait);
    ULONGLONG Timestamp = MAXLONGLONG;
    BOOL WasPending;
    BOOL SameHandle;

    TRACE("%p %p %p\n", Wait, Handle, Timeout);

    RtlEnterCriticalSection(&WaitQueue.Lock);

    assert(This->Wait.Bucket);
    WasPending = This->Wait.WaitPending;

    SameHandle = This->Wait.Handle == Handle;
    TpWaitCloseDupedHandle(This);
    if (Handle && NtDuplicateObject(NtCurrentProcess(), Handle, NtCurrentProcess(),
				    &This->Wait.DupedHandle, 0, 0,
				    DUPLICATE_SAME_ACCESS) != STATUS_SUCCESS) {
	WARN("Failed to duplicate handle.\n");
    }
    This->Wait.Handle = Handle;

    if (Handle || This->Wait.WaitPending) {
	struct WAITQUEUE_BUCKET *Bucket = This->Wait.Bucket;
	RemoveEntryList(&This->Wait.WaitEntry);

	/* Convert relative timeout to absolute timestamp. */
	if (Handle && Timeout) {
	    Timestamp = Timeout->QuadPart;
	    if ((LONGLONG)Timestamp < 0) {
		LARGE_INTEGER Now;
		NtQuerySystemTime(&Now);
		Timestamp = Now.QuadPart - Timestamp;
	    }
	}

	/* Add wait object back into one of the queues. */
	if (Handle) {
	    InsertTailList(&Bucket->Waiting, &This->Wait.WaitEntry);
	    This->Wait.WaitPending = TRUE;
	    This->Wait.Timeout = Timestamp;
	} else {
	    InsertTailList(&Bucket->Reserved, &This->Wait.WaitEntry);
	    This->Wait.WaitPending = FALSE;
	}

	/* Wake up the wait queue thread. */
	if (!SameHandle)
	    ++This->UpdateSerial;
	NtSetEvent(Bucket->UpdateEvent, NULL);
    }

    RtlLeaveCriticalSection(&WaitQueue.Lock);

    return WasPending;
}

/***********************************************************************
 *           TpSimpleTryPost    (NTDLL.@)
 */
NTAPI NTSTATUS TpSimpleTryPost(PTP_SIMPLE_CALLBACK Callback, PVOID Userdata,
			       PTP_CALLBACK_ENVIRON Environment)
{
    PTHREAD_POOL_OBJECT Object;
    PTHREAD_POOL Pool;
    NTSTATUS Status;

    TRACE("%p %p %p\n", Callback, Userdata, Environment);

    Object = RtlAllocateHeap(RtlGetProcessHeap(), 0, sizeof(*Object));
    if (!Object)
	return STATUS_NO_MEMORY;

    Status = TpThreadPoolLock(&Pool, Environment);
    if (Status) {
	RtlFreeHeap(RtlGetProcessHeap(), 0, Object);
	return Status;
    }

    Object->Type = TP_OBJECT_TYPE_SIMPLE;
    Object->Simple.Callback = Callback;
    TpObjectInitialize(Object, Pool, Userdata, Environment);

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           TpStartAsyncIoOperation    (NTDLL.@)
 */
NTAPI VOID TpStartAsyncIoOperation(PTP_IO Io)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpIo(Io);

    TRACE("%p\n", Io);

    RtlEnterCriticalSection(&This->Pool->Cs);

    This->Io.PendingCount++;

    RtlLeaveCriticalSection(&This->Pool->Cs);
}

/***********************************************************************
 *           TpWaitForIoCompletion    (NTDLL.@)
 */
NTAPI VOID TpWaitForIoCompletion(PTP_IO Io, BOOL CancelPending)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpIo(Io);

    TRACE("%p %d\n", Io, CancelPending);

    if (CancelPending)
	TpObjectCancel(This);
    TpObjectWait(This, FALSE);
}

/***********************************************************************
 *           TpWaitForTimer    (NTDLL.@)
 */
NTAPI VOID TpWaitForTimer(PTP_TIMER Timer, BOOL CancelPending)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpTimer(Timer);

    TRACE("%p %d\n", Timer, CancelPending);

    if (CancelPending)
	TpObjectCancel(This);
    TpObjectWait(This, FALSE);
}

/***********************************************************************
 *           TpWaitForWait    (NTDLL.@)
 */
NTAPI VOID TpWaitForWait(PTP_WAIT Wait, BOOL CancelPending)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpWait(Wait);

    TRACE("%p %d\n", Wait, CancelPending);

    if (CancelPending)
	TpObjectCancel(This);
    TpObjectWait(This, FALSE);
}

/***********************************************************************
 *           TpWaitForWork    (NTDLL.@)
 */
NTAPI VOID TpWaitForWork(PTP_WORK Work, BOOL CancelPending)
{
    PTHREAD_POOL_OBJECT This = ImplFromTpWork(Work);

    TRACE("%p %u\n", Work, CancelPending);

    if (CancelPending)
	TpObjectCancel(This);
    TpObjectWait(This, FALSE);
}

/***********************************************************************
 *           TpSetPoolStackInformation    (NTDLL.@)
 */
NTAPI NTSTATUS TpSetPoolStackInformation(PTP_POOL Pool,
					 PTP_POOL_STACK_INFORMATION StackInfo)
{
    PTHREAD_POOL This = ImplFromTpPool(Pool);

    TRACE("%p %p\n", Pool, StackInfo);

    if (!StackInfo)
	return STATUS_INVALID_PARAMETER;

    RtlEnterCriticalSection(&This->Cs);
    This->StackInfo = *StackInfo;
    RtlLeaveCriticalSection(&This->Cs);

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           TpQueryPoolStackInformation    (NTDLL.@)
 */
NTAPI NTSTATUS TpQueryPoolStackInformation(PTP_POOL Pool,
					   PTP_POOL_STACK_INFORMATION StackInfo)
{
    PTHREAD_POOL This = ImplFromTpPool(Pool);

    TRACE("%p %p\n", Pool, StackInfo);

    if (!StackInfo)
	return STATUS_INVALID_PARAMETER;

    RtlEnterCriticalSection(&This->Cs);
    *StackInfo = This->StackInfo;
    RtlLeaveCriticalSection(&This->Cs);

    return STATUS_SUCCESS;
}

typedef struct _RTL_WAIT_CALLER {
    LIST_ENTRY Entry;
    HANDLE Thread;
} RTL_WAIT_CALLER, *PRTL_WAIT_CALLER;

static NTAPI VOID RtlWaitCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Userdata,
				  PTP_WAIT Wait, TP_WAIT_RESULT Result)
{
    PTHREAD_POOL_OBJECT Object = ImplFromTpWait(Wait);
    RTL_WAIT_CALLER Caller;

    Caller.Thread = NtCurrentTeb()->NtTib.ClientId.UniqueThread;
    RtlEnterCriticalSection(&Object->Pool->Cs);
    InsertTailList(&Object->Wait.RtlCallers, &Caller.Entry);
    RtlLeaveCriticalSection(&Object->Pool->Cs);
    RtlpCallWaitOrTimerCallback(Object->Wait.RtlCallback, Userdata,
				Result != STATUS_WAIT_0);
    RtlEnterCriticalSection(&Object->Pool->Cs);
    RemoveEntryList(&Caller.Entry);
    RtlLeaveCriticalSection(&Object->Pool->Cs);
}

/***********************************************************************
 *              RtlRegisterWait   (NTDLL.@)
 *
 * Registers a wait for a handle to become signaled.
 *
 * PARAMS
 *  NewWaitObject [I] Handle to the new wait object. Use RtlDeregisterWait() to free it.
 *  Object   [I] Object to wait to become signaled.
 *  Callback [I] Callback function to execute when the wait times out or the handle is
 * signaled. Context  [I] Context to pass to the callback function when it is executed.
 *  Milliseconds [I] Number of milliseconds to wait before timing out.
 *  Flags    [I] Flags. See notes.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 *
 * NOTES
 *  Flags can be one or more of the following:
 *|WT_EXECUTEDEFAULT - Executes the work item in a non-I/O worker thread.
 *|WT_EXECUTEINIOTHREAD - Executes the work item in an I/O worker thread.
 *|WT_EXECUTEINPERSISTENTTHREAD - Executes the work item in a thread that is persistent.
 *|WT_EXECUTELONGFUNCTION - Hints that the execution can take a long time.
 *|WT_TRANSFER_IMPERSONATION - Executes the function with the current access token.
 */
NTAPI NTSTATUS RtlRegisterWait(HANDLE *Out, HANDLE Handle,
			       WAITORTIMERCALLBACKFUNC Callback, PVOID Context,
			       ULONG Milliseconds, ULONG Flags)
{
    PTHREAD_POOL_OBJECT Object;
    TP_CALLBACK_ENVIRON Environment;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    PTP_WAIT Wait;

    TRACE("out %p, handle %p, callback %p, context %p, milliseconds %u, flags %x\n", Out,
	  Handle, Callback, Context, Milliseconds, Flags);

    memset(&Environment, 0, sizeof(Environment));
    Environment.Version = 1;
    Environment.u.s.LongFunction = (Flags & WT_EXECUTELONGFUNCTION) != 0;
    Environment.u.s.Persistent = (Flags & WT_EXECUTEINPERSISTENTTHREAD) != 0;

    Flags &= (WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD | WT_EXECUTEINIOTHREAD);
    if ((Status = TpAllocWaitEx(&Wait, RtlWaitCallback, Context, &Environment, Flags)))
	return Status;

    Object = ImplFromTpWait(Wait);
    Object->Wait.RtlCallback = Callback;
    InitializeListHead(&Object->Wait.RtlCallers);

    RtlEnterCriticalSection(&WaitQueue.Lock);
    TpSetWait((PTP_WAIT)Object, Handle, GetNtTimeout(&Timeout, Milliseconds));

    *Out = Object;
    RtlLeaveCriticalSection(&WaitQueue.Lock);

    return STATUS_SUCCESS;
}

/***********************************************************************
 *              RtlDeregisterWaitEx   (NTDLL.@)
 *
 * Cancels a wait operation and frees the resources associated with calling
 * RtlRegisterWait().
 *
 * PARAMS
 *  WaitObject [I] Handle to the wait object to free.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 */
NTAPI NTSTATUS RtlDeregisterWaitEx(HANDLE Handle, HANDLE Event)
{
    PTHREAD_POOL_OBJECT Object = Handle;
    NTSTATUS Status;
    LONG Own = 0;

    TRACE("handle %p, event %p\n", Handle, Event);

    if (!Object)
	return STATUS_INVALID_HANDLE;

    TpSetWait((PTP_WAIT)Object, NULL, NULL);

    if (Event == INVALID_HANDLE_VALUE)
	TpWaitForWait((PTP_WAIT)Object, TRUE);
    else {
	assert(Object->CompletedEvent == NULL);
	Object->CompletedEvent = Event;
    }

    RtlEnterCriticalSection(&Object->Pool->Cs);
    LoopOverList(Caller, &Object->Wait.RtlCallers, RTL_WAIT_CALLER, Entry) {
	if (Caller->Thread == NtCurrentTeb()->NtTib.ClientId.UniqueThread)
	    Own += 2;
	if (Object->NumPendingCallbacks + Object->NumRunningCallbacks +
	    Object->NumAssociatedCallbacks > Own)
	    Status = STATUS_PENDING;
	else
	    Status = STATUS_SUCCESS;
    }
    RtlLeaveCriticalSection(&Object->Pool->Cs);

    TpReleaseWait((PTP_WAIT)Object);
    return Status;
}

/***********************************************************************
 *              RtlDeregisterWait   (NTDLL.@)
 *
 * Cancels a wait operation and frees the resources associated with calling
 * RtlRegisterWait().
 *
 * PARAMS
 *  WaitObject [I] Handle to the wait object to free.
 *
 * RETURNS
 *  Success: STATUS_SUCCESS.
 *  Failure: Any NTSTATUS code.
 */
NTAPI NTSTATUS RtlDeregisterWait(HANDLE WaitHandle)
{
    return RtlDeregisterWaitEx(WaitHandle, NULL);
}

VOID RtlpInitializeThreadPooling(VOID)
{
    RtlInitializeCriticalSection(&TimerQueue.Lock);
    RtlInitializeCriticalSection(&WaitQueue.Lock);
    RtlInitializeCriticalSection(&IoQueue.Lock);
}
