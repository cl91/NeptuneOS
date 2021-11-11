#pragma once

#include <nt.h>
#include <sel4/sel4.h>
#include <printf.h>
#include "mm.h"

#define NTOS_KE_TAG			(EX_POOL_TAG('n','t','k','e'))

struct _THREAD;

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
    CAP_TREE_NODE TreeNode;
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

typedef struct _X86_IOPORT {
    CAP_TREE_NODE TreeNode; /* capability with which to invoke seL4_X86_IOPort_* */
    USHORT PortNum;	    /* port number */
} X86_IOPORT, *PX86_IOPORT;

#define VGA_BLUE			(1)
#define VGA_WHITE			(15)
#define VGA_BG_COLOR			(VGA_BLUE << 4)
#define VGA_FG_COLOR			(VGA_WHITE)
#define VGA_TEXT_COLOR			(VGA_BG_COLOR | VGA_FG_COLOR)


/*
 * Asynchronous routine helpers
 *
 * (This is inspired by protothread [1] and async.h from naasking [2].)
 *
 * When the NTOS server gets a client NTAPI request, it is often the case that
 * the request cannot be immediately satisfied. For instance, the client may
 * request to read a file into a buffer, but the file hasn't yet been read from
 * the disk. We do not want to synchronously wait for the driver process to
 * complete the read since (1) this incurs a process switch which is costly
 * and (2) more importantly, a misbehaving driver may never complete the read,
 * thus locking the entire system.
 *
 * Instead we save the current state of the system service handler function
 * into a designated place in the thread's THREAD object, and add the thread
 * to the relevant wait queue to suspend the execution of the currently running
 * system service handler function, such that in the future when the driver
 * process does complete the read request, the system service handler function
 * is resumed and can complete the request this time.
 *
 * Since a system service handler may invoke multiple asynchronous subroutines,
 * it is necessary for the benefit of readability to devise a way to automate
 * the writing of boilerplate asynchronous state management code. The basic idea
 * is for any function that can be called asynchronously, we add an additional
 * input parameter of type ASYNC_STACK as the first parameter of the function. This
 * parameter keeps track of the progress that the asynchronous subroutine has made
 * up till the point that it must block. When the async function needs to block and
 * wait for the completion of an external event, it returns the line number from
 * which future resumption of execution should start, as well as a special status
 * indicating that the subroutine has blocked asynchronously. By examining the
 * asynchronous state, future invocation of the same asynchronous subroutine can
 * determine where its last execution has been and resume from there. Since an
 * asynchronous function may invoke other asynchronous routines (or itself), the
 * status of all asynchronous functions form a stack, ie. the ASYNC_STACK struct.
 *
 * [1] http://dunkels.com/adam/pt/
 * [2] https://github.com/naasking/async.h
 */

#define ASYNC_MAX_CALL_STACK	32

/*
 * Starting from the top level function (ie. a service handler), all
 * async function calls push onto the top of the ASYNC_STACK their
 * own async status word (ie. line number from which to resume execution).
 * At the entry of the service handler, StackTop is -1, indicating that the
 * stack is empty.
 */
typedef struct _ASYNC_STACK {
    ULONG Stack[ASYNC_MAX_CALL_STACK]; /* Stack of line numbers from which execution is to be resumed */
} ASYNC_STACK, *PASYNC_STACK;

/*
 * For each async function, it takes an async state parameter which records
 * the async stack top of the current call frame. At the entry of the service
 * handler, StackTop is -1, indicating that the stack is empty.
 *
 * NOTE: An async state is function-scope and represents the current call frame.
 * It should always be passed as value and should never be passed as pointer.
 */
typedef struct _ASYNC_STATE {
    PASYNC_STACK AsyncStack;
    LONG StackTop; /* Points to the async status of the current call frame */
} ASYNC_STATE;

#define KI_DEFINE_INIT_ASYNC_STATE(state, thread)	\
    ASYNC_STATE state = {				\
	.AsyncStack = &thread->AsyncStack,		\
	.StackTop = -1					\
    }

/*
 * Dump the async state of the function
 */
#define ASYNC_DUMP(state)						\
    DbgTrace("Dumping async state for thread %p: Stack top %d. "	\
	     "Async states:",						\
	     CONTAINING_RECORD(state.AsyncStack, THREAD, AsyncStack),	\
	     state.StackTop);						\
    for (LONG __async_tmp_i = 0;					\
	 __async_tmp_i <= state.StackTop;				\
	 __async_tmp_i++) {						\
	DbgPrint(" %d", state.AsyncStack->Stack[__async_tmp_i]);	\
    }									\
    DbgPrint("\n")

/**
 * Mark the start of an async subroutine
 * @param thread The thread on which the function is being executed
 */
#define ASYNC_BEGIN(state)						\
    (state).StackTop++;							\
    if ((state).StackTop >= ASYNC_MAX_CALL_STACK) {			\
	assert(FALSE);							\
	return STATUS_ASYNC_STACK_OVERFLOW;				\
    }									\
    switch (KiAsyncGetLineNum(state)) { case 0:

/**
 * Mark the end of a async subroutine.
 * @param Status The NTSTATUS to return to the caller. Must not be from
 * the async facility.
 */
#define ASYNC_END(status)			\
    assert(!IS_ASYNC_STATUS(status));		\
    return status;				\
    default:					\
    assert(FALSE);				\
    return STATUS_ASYNC_BUGBUG; }

/**
 * Check if async subroutine is done
 * @param status The NTSTATUS returned by the async function
 */
#define ASYNC_IS_DONE(status)			\
    (status != STATUS_ASYNC_PENDING)

/**
 * Wait for the completion of the asynchronous function
 *
 * NOTE: Just to be safe this macro is written in a single line (since we use the __LINE__ macro)
 */
#define AWAIT(func, state, ...) case __LINE__: if (!ASYNC_IS_DONE(func(state __VA_OPT__(,) __VA_ARGS__))) return KiAsyncYield(state, __LINE__)

/**
 * Yield execution
 *
 * NOTE: Just to be safe this macro is written in a single line (since we use the __LINE__ macro)
 */
#define ASYNC_YIELD(state) return KiAsyncYield(state, __LINE__); case __LINE__:

/*
 * Returns the line number from which the current async function should
 * resume execution. For a new async stack frame, we use zero as the line
 * number since __LINE__ is always greater than 0 for any (reasonable)
 * translation unit.
 */
static inline LONG KiAsyncGetLineNum(ASYNC_STATE State)
{
    assert(State.StackTop < ASYNC_MAX_CALL_STACK);
    return State.AsyncStack->Stack[State.StackTop];
}

/*
 * Record the line number from which to resume the async function and
 * return async pending status.
 */
static inline NTSTATUS KiAsyncYield(ASYNC_STATE State, LONG LineNum)
{
    assert(State.StackTop < ASYNC_MAX_CALL_STACK);
    State.AsyncStack->Stack[State.StackTop] = LineNum;
    return STATUS_ASYNC_PENDING;
}


/*
 * Synchronization Primitives
 *
 * A thread can block on a number of kernel objects, collectively known as
 * the dispatcher objects. When a thread blocks on a dispatcher object the
 * system service handler returns STATUS_ASYNC_PENDING and the system
 * service dispatcher saves the reply capability (generated by the seL4
 * microkernel) into the THREAD object, and simply moves on to the next
 * system service message. The thread is effectively suspended until a
 * later time when the NTOS server replies to the saved reply capability.
 *
 * KeWaitForSingleObject() and KeWaitForMultipleObjects() ...
 */
typedef enum _WAIT_TYPE {
    WaitOne,
    WaitAny,
    WaitAll
} WAIT_TYPE;

typedef struct _DISPATCHER_HEADER {
    LIST_ENTRY WaitBlockList;	/* Points to the list of KWAIT_BLOCK chained by its DispatcherLink */
    BOOLEAN Signaled;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

static inline VOID KiInitializeDispatcherHeader(IN PDISPATCHER_HEADER Header)
{
    assert(Header != NULL);
    InitializeListHead(&Header->WaitBlockList);
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
 */
typedef struct _KWAIT_BLOCK {
    struct _THREAD *Thread;
    WAIT_TYPE WaitType;	/* For WaitOne, the union below is DispatcherLink. */
    union {
	LIST_ENTRY SubBlockList; /* Chains all sub-blocks via SiblingLink */
	LIST_ENTRY DispatcherLink; /* List entry for DISPATCHER_HEADER.WaitBlockList */
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
    EVENT_TYPE EventType;
} KEVENT, *PKEVENT;

static inline VOID KeInitializeEvent(IN PKEVENT Event,
				     IN EVENT_TYPE EventType)
{
    assert(Event != NULL);
    KiInitializeDispatcherHeader(&Event->Header);
    Event->EventType = EventType;
}

/* async.c */
NTSTATUS KeWaitForSingleObject(IN ASYNC_STATE State,
			       IN struct _THREAD *Thread,
			       IN PDISPATCHER_HEADER DispatcherObject);

/* bugcheck.c */
VOID KeBugCheckMsg(IN PCSTR Format, ...);

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
NTSTATUS KeEnableHalServices(IN struct _THREAD *Thread);

/* port.c */
NTSTATUS KeEnableIoPortX86(IN PCNODE CSpace,
			   IN USHORT PortNum,
			   IN PX86_IOPORT IoPort);

/* vga.c */
VOID KeVgaWriteStringEx(UCHAR Color, PCSTR String);

static inline VOID KeVgaWriteString(PCSTR String)
{
    KeVgaWriteStringEx(VGA_TEXT_COLOR, String);
}

static inline __attribute__((format(printf, 1, 2))) VOID KeVgaPrint(PCSTR Format, ...)
{
    char buf[512];
    va_list arglist;
    va_start(arglist, Format);
    vsnprintf(buf, sizeof(buf), Format, arglist);
    va_end(arglist);
    KeVgaWriteString(buf);
}

/* ../tests/tests.c */
VOID KeRunAllTests();
