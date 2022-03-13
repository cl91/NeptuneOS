#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include <printf.h>
#include <util.h>
#include <intrin.h>
#include "mm.h"

#define NTOS_KE_TAG			(EX_POOL_TAG('n','t','k','e'))

/* Size of the TLS section of the NTOS root task image */
#define NTOS_TLS_AREA_SIZE		(64)

struct _THREAD;
struct _SYSTEM_THREAD;

/* Not to be confused with CONTEXT, defined in the NT headers */
typedef seL4_UserContext THREAD_CONTEXT, *PTHREAD_CONTEXT;
typedef enum _THREAD_PRIORITY {
    PASSIVE_LEVEL = 1,
    DEVICE_INTERRUPT_MIN_LEVEL = 10,
    TIMER_INTERRUPT_LEVEL = 255
} THREAD_PRIORITY;

#define LoopOverUntyped(cap, desc, bootinfo)				\
    for (MWORD cap = bootinfo->untyped.start;				\
	 cap < bootinfo->untyped.end; cap++)				\
	for (seL4_UntypedDesc *desc =					\
		 &bootinfo->untypedList[cap - bootinfo->untyped.start]; \
	     desc != NULL; desc = NULL)

/*
 * IPC Endpoint
 */
typedef struct _IPC_ENDPOINT {
    CAP_TREE_NODE TreeNode;	/* Must be first member */
    MWORD Badge;
} IPC_ENDPOINT, *PIPC_ENDPOINT;

#define ENDPOINT_RIGHTS_WRITE_GRANTREPLY	seL4_CapRights_new(1, 0, 0, 1)

static inline VOID KeInitializeIpcEndpoint(IN PIPC_ENDPOINT Self,
					   IN PCNODE CSpace,
					   IN MWORD Cap,
					   IN MWORD Badge)
{
    assert(Self != NULL);
    assert(CSpace != NULL);
    MmInitializeCapTreeNode(&Self->TreeNode, CAP_TREE_NODE_ENDPOINT, Cap,
			    CSpace, NULL);
    Self->Badge = Badge;
}

/*
 * Notification Object
 */
typedef struct _NOTIFICATION {
    CAP_TREE_NODE TreeNode;	/* Must be first member */
    MWORD Badge;
} NOTIFICATION, *PNOTIFICATION;

static inline VOID KeInitializeNotification(IN PNOTIFICATION Self,
					    IN PCNODE CSpace,
					    IN MWORD Cap,
					    IN MWORD Badge)
{
    assert(Self != NULL);
    assert(CSpace != NULL);
    MmInitializeCapTreeNode(&Self->TreeNode, CAP_TREE_NODE_NOTIFICATION, Cap,
			    CSpace, NULL); /* Parent will be set when retyping */
    Self->Badge = Badge;
}

static inline NTSTATUS KeCreateNotificationEx(IN PNOTIFICATION Notification,
					      IN PCNODE CSpace)
{
    PUNTYPED Untyped = NULL;
    RET_ERR(MmRequestUntyped(seL4_NotificationBits, &Untyped));
    assert(Untyped != NULL);
    KeInitializeNotification(Notification, CSpace, 0, 0);
    RET_ERR_EX(MmRetypeIntoObject(Untyped, seL4_NotificationObject,
				  seL4_NotificationBits,
				  &Notification->TreeNode),
	       MmReleaseUntyped(Untyped));
    return STATUS_SUCCESS;
}

static inline NTSTATUS KeCreateNotification(IN PNOTIFICATION Notification)
{
    extern CNODE MiNtosCNode;
    return KeCreateNotificationEx(Notification, &MiNtosCNode);
}

/*
 * This destroys the notification object but do not free the pool memory.
 * All descendant notification objects are destroyed as well.
 */
static inline NTSTATUS KeDestroyNotification(IN PNOTIFICATION Notification)
{
    PCAP_TREE_NODE Node = Notification->TreeNode.Parent;
    while (Node->Type != CAP_TREE_NODE_UNTYPED) {
	Node = Node->Parent;
    }
    assert(Node != NULL);
    return MmReleaseUntyped(TREE_NODE_TO_UNTYPED(Node));
}

static inline VOID KeWaitOnNotification(IN PNOTIFICATION Notification)
{
    seL4_Wait(Notification->TreeNode.Cap, NULL);
}

static inline VOID KeSignalNotification(IN PNOTIFICATION Notification)
{
    seL4_Signal(Notification->TreeNode.Cap);
}

/*
 * X86 IO Port
 */
typedef struct _X86_IOPORT {
    CAP_TREE_NODE TreeNode; /* Must be first member */
    USHORT PortNum;	    /* Port number */
    LIST_ENTRY Link;	    /* Links all enabled ports of a process */
} X86_IOPORT, *PX86_IOPORT;

/*
 * IRQ Handler
 */
typedef struct _IRQ_HANDLER {
    CAP_TREE_NODE TreeNode;	/* Must be first member */
    MWORD Irq;
} IRQ_HANDLER, *PIRQ_HANDLER;

static inline VOID KeInitializeIrqHandler(IN PIRQ_HANDLER Self,
					  IN PCNODE CSpace,
					  IN MWORD Cap,
					  IN MWORD Irq)
{
    assert(Self != NULL);
    assert(CSpace != NULL);
    MmInitializeCapTreeNode(&Self->TreeNode, CAP_TREE_NODE_IRQ_HANDLER, Cap,
			    CSpace, NULL);
    Self->Irq = Irq;
}

/*
 * Asynchronous routine helpers
 *
 * (This is inspired by protothread [1] and async.h from naasking [2].)
 *
 * IMPORTANT NOTE: Be careful with async functions. Local variables are not
 * preserved when async functions are suspended and resumed unless defined
 * via ASYNC_BEGIN!
 *
 * RULES:
 * 1. AWAIT, AWAIT_EX, AWAIT_IF, ASYNC_YIELD, ASYNC_BEGIN and ASYNC_END should
 *    always be in the outermost scope explicitly. In other words, the following
 *    is strictly forbidden:
 *        if (...) {
 *            AWAIT(...);
 *        }
 *    This is a programming error: the if-condition is a no-op and the AWAIT
 *    statement is always evaluated. Unfortunately the compiler cannot catch this.
 *    Instead, use AWAIT_IF if you want to await conditionally.
 *
 * 2. Use the ASYNC_BEGIN macro to define local variables that need to be
 *    saved across async function calls. This generally applies to IN variables
 *    of an async functions. OUT variables should not be saved across async
 *    calls and should not be defined this way. For IN OUT variables it is best
 *    to manually manage variable saving.
 *
 * 3. Use ASYNC_RETURN when you need to return a status from an async function.
 *    Simply using the C return statement is INCORRECT!
 *
 * 4. You must end all async function with ASYNC_END. Otherwise it won't compile.
 *
 * DESCRIPTION:
 *
 * When the NTOS server gets a client NTAPI request, it is often the case that
 * the request cannot be immediately satisfied. For instance, the client may
 * request to read a file into a buffer, but the file hasn't yet been read from
 * the disk. We do not want to wait synchronously for the driver process to
 * complete the read since (1) this incurs a process switch which is costly
 * and (2) more importantly, a misbehaving driver may never complete the read,
 * thus locking the entire system.
 *
 * Instead we save the current state of the system service handler function
 * into a designated place in the thread's THREAD object, and add the thread
 * to the relevant wait queue to suspend the execution of the currently running
 * system service handler function, such that in the future when the driver
 * process does complete the read request, the system service handler function
 * can be resumed and can complete the request this time.
 *
 * Since a system service handler may invoke multiple asynchronous subroutines,
 * it is necessary for the benefit of readability to devise a way to automate
 * the writing of boilerplate asynchronous state management code. The basic idea
 * is for any function that can be called asynchronously, we add an additional
 * input parameter of type ASYNC_STATE as the first parameter of the function. This
 * parameter keeps track of the progress that the asynchronous subroutine has made
 * up till the point that it must block. When the async function needs to block and
 * wait for the completion of an external event, it returns the line number from
 * which future resumption of execution should start, as well as a special status
 * indicating that the subroutine has blocked asynchronously. By examining the
 * asynchronous state, future invocation of the same asynchronous subroutine can
 * determine where its last execution has been and resume from there. Since an
 * asynchronous function may invoke other asynchronous routines (or itself), the
 * status of all asynchronous functions form a stack, ie. the ASYNC_STATE struct.
 *
 * [1] http://dunkels.com/adam/pt/
 * [2] https://github.com/naasking/async.h
 */

#define ASYNC_MAX_CALL_STACK	(256 * sizeof(MWORD))

/*
 * Starting from the top level function (ie. a service handler), all
 * async function calls push onto the top of the ASYNC_STACK their
 * own async status word (ie. line number from which to resume execution),
 * followed by the local variables that must be preserved across async calls.
 * At the entry of the service handler, StackTop is 0, indicating that the
 * stack is empty.
 */
typedef struct _ASYNC_STACK {
    CHAR Stack[ASYNC_MAX_CALL_STACK]; /* Stack of line numbers from which execution is to be resumed */
} ASYNC_STACK, *PASYNC_STACK;

/*
 * For each async function, it takes an async state parameter which records
 * the async stack top of the current call frame. At the entry of the service
 * handler, StackTop is 0, indicating that the stack is empty.
 *
 * NOTE: An async state is function-scope and represents the current call frame.
 * It should always be passed as value and should never be passed as pointer.
 */
typedef struct _ASYNC_STATE {
    PASYNC_STACK AsyncStack;
    ULONG StackTop; /* Points to the async status of the current call frame */
} ASYNC_STATE;

#define KI_DEFINE_INIT_ASYNC_STATE(state, thread)	\
    ASYNC_STATE state = {				\
	.AsyncStack = &thread->AsyncStack,		\
	.StackTop = 0					\
    }

/**
 * Dump the async state of the function
 */
#define ASYNC_DUMP(state)						\
    {									\
	PTHREAD Thread = CONTAINING_RECORD(state.AsyncStack,		\
					   THREAD, AsyncStack);		\
	DbgTrace("Async state for thread %s|%p: Stack top %d. "		\
		 "Async stack:",					\
		 Thread->Process->ImageFile->FileName, Thread,		\
		 (state).StackTop);					\
    }									\
    for (ULONG StackPtr = 0; StackPtr < (state).StackTop; ) {		\
	PASYNC_STACK_FRAME Frame = (PASYNC_STACK_FRAME)(		\
	    (MWORD)((state).AsyncStack) + StackPtr);			\
	DbgPrint(" (FS %d LN %d)",					\
		 Frame->Size, Frame->LineNum);				\
	assert(Frame->Size != 0);					\
	StackPtr += Frame->Size;					\
    }									\
    DbgPrint("\n")

/*
 * The following macros that start with an underscore shall not be
 * called directly.
 */
#define _ASYNC_GET_MACRO(_1, _2, _3, NAME, ...) NAME
#define _ASYNC_GET_FRAME(state)						\
    ((PASYNC_STACK_FRAME)((MWORD)((state).AsyncStack) +			\
			  (state).StackTop - sizeof(ASYNC_STACK_FRAME)))
#define _ASYNC_GET_NEXT_FRAME(state)					\
    ((PASYNC_STACK_FRAME)((MWORD)((state).AsyncStack)			\
			  + (state).StackTop))
#define _ASYNC_GET_LINENUM(state)		\
    (_ASYNC_GET_FRAME(state)->LineNum)
#define _ASYNC_GET_LOCALS(state)		\
    (_ASYNC_GET_FRAME(state)->Locals)
#define _ASYNC_BEGIN_NO_LOCALS(state)					\
    typedef struct POINTER_ALIGNMENT _ASYNC_STACK_FRAME {		\
	ULONG LineNum;							\
	ULONG Size;							\
    } ASYNC_STACK_FRAME, *PASYNC_STACK_FRAME
#define _ASYNC_BEGIN_LOCALS(state, locals, vars)			\
    struct POINTER_ALIGNMENT _ASYNC_SAVED_LOCALS vars locals;		\
    typedef struct POINTER_ALIGNMENT _ASYNC_STACK_FRAME {		\
	ULONG LineNum;							\
	ULONG Size;							\
	struct POINTER_ALIGNMENT _ASYNC_SAVED_LOCALS Locals;		\
    } ASYNC_STACK_FRAME, *PASYNC_STACK_FRAME;				\
    locals = _ASYNC_GET_NEXT_FRAME(state)->Locals
/* We define an unused typedef below so in non-async functions we can
 * generate an error if certain macros (RET_ERR, RET_ERR_EX) are used */
#define _ASYNC_BEGIN_COMMON(state, ...)					\
    typedef ASYNC_STACK_FRAME __ASYNC_RETURN_CHECK_HELPER;		\
    _ASYNC_GET_NEXT_FRAME(state)->Size = sizeof(ASYNC_STACK_FRAME);	\
    (state).StackTop += sizeof(ASYNC_STACK_FRAME);			\
    ASYNC_DUMP(state);							\
    switch (_ASYNC_GET_LINENUM(state)) {				\
    case 0: {
/* This is magic! */
#define _ASYNC_MAKE_EMPTY_ARG_			,
#define _ASYNC_GET_SECOND_ARG(x, y, ...)	y
#define _ASYNC_DEFERRED_EXPAND(x, ...)		\
    _ASYNC_GET_SECOND_ARG(x, __VA_ARGS__)
#define _ASYNC_SAVE_LOCALS(state, locals)				\
    _ASYNC_DEFERRED_EXPAND(_ASYNC_MAKE_EMPTY_ARG##locals,		\
			   _ASYNC_GET_LOCALS(state) = locals, )
#define _ASYNC_RESTORE_LOCALS(state, locals)			\
    _ASYNC_DEFERRED_EXPAND(_ASYNC_MAKE_EMPTY_ARG##locals,	\
			   locals = _ASYNC_GET_LOCALS(state), )

/**
 * Mark the start of an async subroutine
 *
 * There are two valid syntax:
 *
 *   Without defining local variables:
 *     ASYNC_BEGIN(AsyncState);
 *     @param AsyncState The current async state
 *
 *   Defining local variables:
 *     ASYNC_BEGIN(AsyncState, Locals, {
 *         ULONG Local1;
 *         ULONG Local2;
 *         ...
 *     });
 *     @param AsyncState The current async state
 *     @param Locals The local variables that are saved across async calls
 */
#define ASYNC_BEGIN(...)						\
    _ASYNC_GET_MACRO(__VA_ARGS__, _ASYNC_BEGIN_LOCALS, ,		\
		     _ASYNC_BEGIN_NO_LOCALS)(__VA_ARGS__);		\
    _ASYNC_BEGIN_COMMON(__VA_ARGS__)

/**
 * Check that we are inside an ASYNC_BEGIN ASYNC_END block
 */
#define COMPILE_CHECK_ASYNC_FRAME_SIZE					\
    { compile_assert(ERROR_YOU_MUST_USE_NON_ASYNC_RETURN,		\
		     sizeof(__ASYNC_RETURN_CHECK_HELPER) ==		\
		     sizeof(ASYNC_STACK_FRAME)); }

/**
 * Return a status from the async function.
 *
 * IMPORTANT: You must use ASYNC_RETURN to return from an async function.
 *    Simply doing return Status is INCORRECT!
 */
#define ASYNC_RETURN(state, status)					\
    COMPILE_CHECK_ASYNC_FRAME_SIZE;					\
    assert(!IS_ASYNC_STATUS(status));					\
    memset(_ASYNC_GET_FRAME(state), 0, sizeof(ASYNC_STACK_FRAME));	\
    return status;

/**
 * Use these instead of RET_ERR and RET_ERR_EX inside async functions
 */
#define ASYNC_RET_ERR_EX(State, Expr, OnError)				\
    COMPILE_CHECK_ASYNC_FRAME_SIZE;					\
    {									\
	NTSTATUS Status = (Expr);					\
	if (!NT_SUCCESS(Status)) {					\
	    DbgPrint("Expression %s in function %s @ %s:%d returned"	\
		     " error 0x%x\n",					\
		     #Expr, __func__, __FILE__, __LINE__, Status);	\
	    {OnError;}							\
	    ASYNC_RETURN(State, Status);				\
	}								\
    }
#define ASYNC_RET_ERR(State, Expr)	ASYNC_RET_ERR_EX(State, Expr, {})

/**
 * Mark the end of a async subroutine.
 * @param state The async state of the current function.
 * @param status The NTSTATUS to return to the caller. Must not be an
 *        async status.
 */
#define ASYNC_END(state, status)				\
    ASYNC_RETURN(state, status); }				\
    default:							\
    KeBugCheckMsg("BUGBUG! Async function error.\n");		\
    return STATUS_UNSUCCESSFUL; }

/**
 * Check if async subroutine is done
 * @param status The NTSTATUS returned by the async function
 */
static inline BOOLEAN KiAsyncIsDone(IN NTSTATUS Status)
{
    return Status != STATUS_ASYNC_PENDING;
}

/**
 * Wait for the completion of the asynchronous function
 *
 * @param func Function to call
 * @param state Async state of the current function
 * @param locals Saved local variables declared in ASYNC_BEGIN.
 *        If empty, use _
 *
 * Examples:
 *     AWAIT(KeWaitForSingleObject, AsyncState, Locals, Thread, ...)
 *   If no local variables are being saved, use _ in place of Locals:
 *     AWAIT(KeWaitForSingleObject, AsyncState, _, Thread, ...)
 *
 * A note about __LINE__: It doesn't matter if the macro definition is
 * written in multiple lines. One might wonder if the macro invocations
 * should be written in the same line. Compilers can differ greatly
 * in terms of what the __LINE__ macro expands to. For instance, see
 * this bug report [1]. That being said, as long as it is consistent
 * there should be no problem writing AWAIT macro invocations in multiple
 * lines since the async functions never cross process boundary and are
 * always compiled with the same compiler.
 *
 * [1] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=94535
 */
#define AWAIT(func, state, locals, ...)				\
    _ASYNC_SAVE_LOCALS(state, locals);				\
    } case __LINE__: {						\
    if (!KiAsyncIsDone(func(state __VA_OPT__(,) __VA_ARGS__)))	\
	return _KI_ASYNC_YIELD(state, __LINE__);		\
    _ASYNC_RESTORE_LOCALS(state, locals)

/**
 * Wait for the completion of the asynchronous function and store its return status
 */
#define AWAIT_EX(status, func, state, locals, ...)			\
    _ASYNC_SAVE_LOCALS(state, locals);					\
    } case __LINE__: {							\
    if (!KiAsyncIsDone(status = func(state __VA_OPT__(,) __VA_ARGS__)))	\
	return _KI_ASYNC_YIELD(state, __LINE__);			\
    _ASYNC_RESTORE_LOCALS(state, locals)

/**
 * IMPORTANT: You MUST use the following macros, AWAIT_IF if you want to await
 * conditionally. Enclosing the AWAIT statement in an if-statement is INCORRECT!
 */
#define AWAIT_IF(cond, func, state, locals, ...)			\
    if (cond) {								\
	_ASYNC_SAVE_LOCALS(state, locals);				\
    case __LINE__:							\
	if (!KiAsyncIsDone(func(state __VA_OPT__(,) __VA_ARGS__)))	\
	    return _KI_ASYNC_YIELD(state, __LINE__);			\
	_ASYNC_RESTORE_LOCALS(state, locals);				\
    } } {

/**
 * IMPORTANT: You MUST use the following macros if you want to await conditionally
 * and get the return status. Enclosing the AWAIT_EX statement in an if-statement
 * is INCORRECT!
 */
#define AWAIT_EX_IF(cond, status, func, state, locals, ...)		\
    if (cond) {								\
	_ASYNC_SAVE_LOCALS(state, locals);				\
    case __LINE__:							\
	if (!KiAsyncIsDone(status =					\
			   func(state __VA_OPT__(,) __VA_ARGS__)))	\
	    return _KI_ASYNC_YIELD(state, __LINE__);			\
	_ASYNC_RESTORE_LOCALS(state, locals);				\
    } } {

/**
 * Yield execution
 */
#define ASYNC_YIELD(state, locals)		\
    _ASYNC_SAVE_LOCALS(state, locals);		\
    return _KI_ASYNC_YIELD(state, __LINE__);	\
    } case __LINE__: {				\
    _ASYNC_RESTORE_LOCALS(state, locals);

/* bugcheck.c */
VOID KeBugCheckMsg(IN PCSTR Format, ...) __attribute__ ((format(printf, 1, 2)));

static inline VOID KiCheckAsyncStack(IN ASYNC_STATE State)
{
    if (State.StackTop <= 0) {
	KeBugCheckMsg("BUGBUG Async call stack underflow.\n");
    }
    if (State.StackTop >= ASYNC_MAX_CALL_STACK) {
	KeBugCheckMsg("BUGBUG Async call stack overflow.\n");
    }
}

/*
 * Record the line number from which to resume the async function and
 * return async pending status.
 */
#define _KI_ASYNC_YIELD(State, LineNum)				\
    (KiCheckAsyncStack(State),					\
     _ASYNC_GET_LINENUM(State) = LineNum,			\
     STATUS_ASYNC_PENDING)

/*
 * Synchronization Primitives
 *
 * A thread can block on a number of kernel objects, collectively known as
 * the dispatcher objects. When a thread blocks on a dispatcher object the
 * system service handler returns STATUS_ASYNC_PENDING and the system
 * executive dispatcher saves the reply capability (generated by the seL4
 * microkernel) into the THREAD object, and simply moves on to the next
 * system service message. The thread is effectively suspended until a
 * later time when the NTOS server replies to the saved reply capability.
 *
 * KeWaitForSingleObject() and KeWaitForMultipleObjects() add the the
 * dispatcher header to the thread's root wait block, which represents
 * a boolean formula that must be satisfied for the thread to wake up.
 * When a dispatcher object is signaled later, the root wait block is
 * evaluated and if it is satisfied, the thread is added to the ready
 * thread list and resumed by the executive service dispatcher.
 */
typedef enum _WAIT_TYPE {
    WaitOne,
    WaitAny,
    WaitAll
} WAIT_TYPE;

typedef struct _DISPATCHER_HEADER {
    LIST_ENTRY WaitBlockList;	/* Points to the list of KWAIT_BLOCK chained by its DispatcherLink */
    BOOLEAN Signaled;
    EVENT_TYPE EventType;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef PDISPATCHER_HEADER (*KE_DISPATCHER_ITERATOR)(PVOID IteratorContext);

static inline VOID KiInitializeDispatcherHeader(IN PDISPATCHER_HEADER Header,
						IN EVENT_TYPE EventType)
{
    assert(Header != NULL);
    InitializeListHead(&Header->WaitBlockList);
    Header->EventType = EventType;
    Header->Signaled = FALSE;
}

/*
 * A wait block represents a boolean condition that is satisfied when a dispatcher
 * object is signaled. Wait blocks form a boolean formula via logical disjunction
 * (or) and logical conjunction (and). In memory this is represented via sub-blocks
 * linked via the SiblingLink of the SubBlockList of the parent wait block. The
 * WaitType determines whether a given wait block is a conjunction (WaitAll) of its
 * sub-blocks or a disjunction (WaitAny) of its sub-blocks. For a leaf-node wait
 * block, the WaitType is WaitOne and the SubBlockList is replaced by DispatcherLink
 * which chains all wait blocks satisfied by a given dispatcher object.
 *
 * The root wait block of the THREAD object represents the master boolean formula
 * that must be satisfied for the thread to wake up. Once it is satisfied, the system
 * service dispatcher will invoke the reply capability stored in the THREAD object
 * to resume the thread.
 *
 * A schematic diagram is as follows:
 *
 *   |--------- |             |------------|
 *   |  THREAD  |             |  THREAD    |
 *   |----------|             |------------|
 *   |   Root   |             | Root Wait  |
 *   |   Wait   |             | Block TY=  |
 *   |   Block  |             |  WaitAll   |
 *   |TY=WaitOne|             |  WaitAll   |
 *   |----------|             |SubBlockList|--->|--------|---->|--------|
 *     |   ^-------------     |------------|    |SubBlock|     |SubBlock|<----------------
 *    \|/               |                       |--------|     |--------|                |
 *   |---------------|  |                           ^  |            |                    |
 *   |  DISPATCHER   |  |                           |  |            |Dispatcher          |
 *   |---------------|  |                           |  |           \|/                   |
 *   | WaitBlockList |-------------------------------  |     |---------------|           |
 *   |---------------|                                 |     |  DISPATCHER   |           |
 *          ^                                          |     |---------------|           |
 *          |                 Dispatcher               |     | WaitBlockList |------------
 *          -------------------------------------------|     |---------------|
 */
typedef struct _KWAIT_BLOCK {
    struct _THREAD *Thread;
    WAIT_TYPE WaitType;	/* For WaitOne, the union below is DispatcherLink. */
    union {
	LIST_ENTRY SubBlockList; /* Chains all sub-blocks via SiblingLink */
	struct {
	    LIST_ENTRY DispatcherLink; /* List entry for DISPATCHER_HEADER.WaitBlockList */
	    PDISPATCHER_HEADER Dispatcher; /* The dispatcher object of this wait block */
	};
    };
    LIST_ENTRY SiblingLink; /* List entry for KWAIT_BLOCK.SubBlockList */
    BOOLEAN Satisfied; /* Initially FALSE. TRUE when the dispatcher object is signaled. */
} KWAIT_BLOCK, *PKWAIT_BLOCK;

/*
 * A kernel event is simply a dispatcher header.
 *
 * Note: you may wonder why we didn't call it "Executive" Event, since we are
 * in the NTOS executive. The reason is to match WinNT/ReactOS. Additionally,
 * for both the original Windows design and our seL4-based NTOS, the ke component
 * is supposed to be a thin wrapper around native hardward constructs (or seL4
 * constructs in our case), and the ex component contains objects that are
 * implemented using primitives in ke. Since KEVENT is simply a small header,
 * it belongs to ke more than it does ex.
 */
typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT;

static inline VOID KeInitializeEvent(IN PKEVENT Event,
				     IN EVENT_TYPE EventType)
{
    assert(Event != NULL);
    KiInitializeDispatcherHeader(&Event->Header, EventType);
}

static inline VOID KeSetEvent(IN PKEVENT Event)
{
    VOID KiSignalDispatcherObject(IN PDISPATCHER_HEADER Dispatcher);
    KiSignalDispatcherObject(&Event->Header);
}

/*
 * Lightweight mutex, mainly used for protecting concurrent access to timer database
 * (but is not restricted to the timer database: any data structure that is accessed
 * by multiple threads can be protected by KMUTEX).
 *
 * Description:
 *
 * Although we run the NTOS Executive and drivers in their separate process, this is
 * not to say that we don't have any synchronization issues. The main event loops of
 * both NTOS and drivers run in a single thread within their container processes, so
 * there is no need to synchronize access to data that are only accessed within the
 * event loop thread. However, we DO run our interrupt handlers in their separate
 * thread, and since interrupts can arrive at any time, we must protect the access of
 * shared data shared by the interrupt handlers and the main event loop thread.
 *
 * The following object, KMUTEX, can be used for protecting the timer queue and the
 * expired timer list, since they are accessed by both the timer interrupt handler
 * and the main event loop thread. The main job of the timer interrupt handler is to
 * update the timer tick count and traverse the timer queue and see if any of them
 * expired, and move the expired timer object to the expired timer list. Since the
 * main event loop might be modifying the timer queue and the expired timer list when
 * the timer interrupt is signaled (since timer interrupt thread has a higher priority,
 * it gets to preempt the main event loop thread), without synchronization we would
 * eventually have data corruptions.
 *
 * Our solution is to use a mutex to protect the relevant timer database, and in the
 * timer interrupt handler we will try to acquire the mutex. If it succeeds then we
 * can modify the timer database freely. If mutex acquisition failed, it means that
 * the main event loop thread has acquired the mutex and is modifying the timer lists.
 * In this case we sleep on a notification object which will be signaled by the main
 * event loop once it is done with the timer lists. When we are waken up we attempt
 * to reacquire the mutex, and this process is repeated until we successfully acquired
 * the mutex. Likewise, when the main event loop wants to access the timer database,
 * it will try to acquire the mutex before doing so. On a single processor machine
 * this should always succeed since the timer interrupt thread runs in a higher
 * priority. On a multi-processor machine the timer interrupt thread might be running
 * on a different core, and thus the mutex acquisition may fail. In this case we wait
 * on the notification object for it to be signaled by the timer interrupt thread.
 * Once the code is done with the timer database, the lock will be released.
 */
typedef struct POINTER_ALIGNMENT _KMUTEX {
    NOTIFICATION Notification;	/* Notification object */
    LONG Counter;		/* 0 == Mutex available.
				 * 1 == Lock is held by the main event loop thread.
				 * 2 == Lock is held by the main event loop thread AND
				 *      the timer interrupt handler is sleeping on the
				 *      notification object. */
} KMUTEX, *PKMUTEX;

static inline NTSTATUS KeCreateMutex(IN PKMUTEX Mutex)
{
    assert(Mutex != NULL);
    Mutex->Counter = 0;
    return KeCreateNotification(&Mutex->Notification);
}

/*
 * Acquire the lock. If the lock is free, simply acquire the lock and return.
 * If the lock has already been acquired by another thread, wait on the notification
 * object.
 */
static inline VOID KeAcquireMutex(IN PKMUTEX Mutex)
{
    assert(Mutex != NULL);
    if (InterlockedIncrement(&Mutex->Counter) != 1) {
	KeWaitOnNotification(&Mutex->Notification);
    }
}

/*
 * Release the mutex that is previously acquired. Note that you must only call
 * this function after you have acquired the mutex (KeTryAcquireMutex returns TRUE).
 * On debug build we assert if this has not been enforced.
 */
static inline VOID KeReleaseMutex(IN PKMUTEX Mutex)
{
    assert(Mutex != NULL);
    LONG Counter = InterlockedDecrement(&Mutex->Counter);
    assert(Counter >= 0);
    if (Counter >= 1) {
	KeSignalNotification(&Mutex->Notification);
    }
}

/*
 * Asynchronous Procedure Call Object
 */
typedef struct _KAPC {
    struct _THREAD *Thread;
    LIST_ENTRY ThreadApcListEntry;
    APC_OBJECT Object;		/* ApcRoutine and ApcContext */
    BOOLEAN Inserted;
} KAPC, *PKAPC;

/*
 * Timer object
 */
typedef struct _TIMER {
    DISPATCHER_HEADER Header;
    ULARGE_INTEGER DueTime;	/* Absolute due time in units of 100ns */
    struct _THREAD *ApcThread;
    PTIMER_APC_ROUTINE ApcRoutine;
    PVOID ApcContext;
    LIST_ENTRY ListEntry;	/* List entry for KiTimerList */
    union {
	LIST_ENTRY QueueEntry;  /* List entry for KiQueuedTimerList */
	LIST_ENTRY ExpiredListEntry; /* List entry KiExpiredTimerList */
    };
    LONG Period;
    BOOLEAN State;		/* TRUE if timer is set */
} TIMER, *PTIMER;

/* async.c */
NTSTATUS KeWaitForSingleObject(IN ASYNC_STATE State,
			       IN struct _THREAD *Thread,
			       IN PDISPATCHER_HEADER DispatcherObject,
			       IN BOOLEAN Alertable);
NTSTATUS KeWaitForMultipleObjects(IN ASYNC_STATE State,
				  IN struct _THREAD *Thread,
				  IN BOOLEAN Alertable,
				  IN WAIT_TYPE WaitType,
				  IN KE_DISPATCHER_ITERATOR Iterator,
				  IN PVOID IteratorContext);
NTSTATUS KeQueueApcToThread(IN struct _THREAD *Thread,
			    IN PKAPC_ROUTINE ApcRoutine,
			    IN PVOID SystemArgument1,
			    IN PVOID SystemArgument2,
			    IN PVOID SystemArgument3);

/* bugcheck.c */
VOID KeBugCheck(IN PCSTR Function,
		IN PCSTR File,
		IN ULONG Line,
		IN ULONG Error);

#define BUGCHECK_IF_ERR(Expr)	{NTSTATUS Error = (Expr); if (!NT_SUCCESS(Error)) { \
	    KeBugCheck(__func__, __FILE__, __LINE__, Error);}}

/* event.c */
VOID KeSetEvent(IN PKEVENT Event);

/* services.c */
struct _IO_DRIVER_OBJECT;
NTSTATUS KeEnableSystemServices(IN struct _THREAD *Thread);
NTSTATUS KeEnableWdmServices(IN struct _THREAD *Thread);
NTSTATUS KeEnableThreadFaultHandler(IN struct _THREAD *Thread);
NTSTATUS KeEnableSystemThreadFaultHandler(IN struct _SYSTEM_THREAD *Thread);
NTSTATUS KeLoadThreadContext(IN MWORD ThreadCap,
			     IN PTHREAD_CONTEXT Context);
NTSTATUS KeSetThreadContext(IN MWORD ThreadCap,
			    IN PTHREAD_CONTEXT Context);

/* ioport.c */
NTSTATUS KeEnableIoPortEx(IN PCNODE CSpace,
			  IN USHORT PortNum,
			  IN PX86_IOPORT IoPort);
NTSTATUS KeReadPort8(IN PX86_IOPORT Port,
		     OUT UCHAR *Out);
NTSTATUS KeWritePort8(IN PX86_IOPORT Port,
		      IN UCHAR Data);

static inline NTSTATUS KeEnableIoPort(IN USHORT PortNum,
				      IN PX86_IOPORT IoPort)
{
    extern CNODE MiNtosCNode;
    return KeEnableIoPortEx(&MiNtosCNode, PortNum, IoPort);
}

/* init.c */
extern ULONG KeX86TscFreq;
extern ULONG KeProcessorCount;
extern ULONG KeProcessorArchitecture;
extern ULONG KeProcessorLevel;
extern ULONG KeProcessorRevision;
extern ULONG KeFeatureBits;

/* irq.c */
NTSTATUS KeCreateIrqHandlerEx(IN PIRQ_HANDLER IrqHandler,
			      IN MWORD IrqLine,
			      IN PCNODE CSpace);
NTSTATUS KeConnectIrqNotification(IN PIRQ_HANDLER IrqHandler,
				  IN PNOTIFICATION Notification);

NTSTATUS KeCreateIrqHandler(IN PIRQ_HANDLER IrqHandler,
			    IN MWORD IrqLine)
{
    extern CNODE MiNtosCNode;
    return KeCreateIrqHandlerEx(IrqHandler, IrqLine, &MiNtosCNode);
}

/* timer.c */
VOID KeInitializeTimer(IN PTIMER Timer,
		       IN TIMER_TYPE Type);
ULONGLONG KeQuerySystemTime();
ULONGLONG KeQueryInterruptTime();

/* ../tests/tests.c */
VOID KeRunAllTests();
