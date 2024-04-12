#pragma once

#include <util.h>

/*
 * This is placed at the top of the coroutine stack. The top of the
 * stack is a pointer to the stack top of the next coroutine stack,
 * followed by CoroutineSavedSP which saves the stack pointer at the
 * time that the coroutine yields execution via KiCoroutineYield.
 *
 * Following the SavedState pointer is the SP and IP of the master
 * thread before it switches to the coroutine via KiStartCoroutine
 * or KiResumeCoroutine. KiCoroutineYield will then restore these
 * when it yields the execution of the coroutine and switches back
 * to the master thread stack. This will appear to the master thread
 * as if KiStartCoroutine or KiResumeCoroutine were an ordinary function
 * that never messed with the stack.
 *
 * Note: Stack grows in the direction of lower address.
 *
 * Schematics of the coroutine stack: (assuming i386, stack top is at 0x1000)
 *
 *   0xff0           0xff4           0xff8              0xffc          0x1000
 *   |-----------------------------------------------------------------|
 *   | MasterSavedSP | MasterSavedIP | CoroutineSavedSP | NextStackTop |
 *   |-----------------------------------------------------------------|
 *   ^                                                                 ^
 *   Beginning of the call stacks inside the                           StackTop
 *   coroutine, starting with IopCallDispatchRoutine
 *
 * IMPORTANT: If you change this you must change arch/coroutine.S
 */
typedef struct _KI_COROUTINE_STACK {
    PVOID MasterSavedSP; /* The master thread esp/rsp at the time that
			  * KiStartCoroutine or KiResumeCoroutine is called */
    PVOID MasterSavedIP; /* Address that KiCoroutineYield will jump back to */
    PVOID CoroutineSavedSP; /* The stack pointer of the coroutine stack at the time
			    * that KiYieldCoroutine yielded execution */
    PVOID NextStackTop; /* Pointer to the next coroutine stack. */
} KI_COROUTINE_STACK, *PKI_COROUTINE_STACK;


/*
 * Coroutine entry point. This is called by KiStartCoroutine
 *
 * Context is passed via %ecx (i386) or %rcx (amd64)
 */
typedef NTSTATUS (FASTCALL *KI_COROUTINE_ENTRYPOINT)(IN PVOID Context);

struct _IOP_EXEC_ENV;
typedef VOID (*PIOP_EXEC_ENV_FINALIZER)(struct _IOP_EXEC_ENV *Env, NTSTATUS Status);

/*
 * Represents an execution environment in which a dispatch function or
 * IO work item is running.
 */
typedef struct _IOP_EXEC_ENV {
    PVOID CoroutineStackTop;
    PVOID Context;
    KI_COROUTINE_ENTRYPOINT EntryPoint;
    PIOP_EXEC_ENV_FINALIZER Finalizer;
    struct _IOP_EXEC_ENV *EnvToWakeUp; /* Saved Irp->Private.EnvToWakeUp pointer */
    LIST_ENTRY Link;
    BOOLEAN Suspended;
} IOP_EXEC_ENV, *PIOP_EXEC_ENV;

/* coroutine.c */
extern PVOID KiCoroutineStackChainHead;
extern PVOID KiCurrentCoroutineStackTop;
PVOID KiGetFirstAvailableCoroutineStack();
VOID KiDbgDumpCoroutineStacks();

static inline VOID KiReleaseCoroutineStack(PVOID StackTop)
{
    assert(StackTop != NULL);
    PKI_COROUTINE_STACK Stack = (PKI_COROUTINE_STACK)StackTop - 1;
    DbgTrace("Releasing coroutine stack %p saved SP %p\n",
	     StackTop, Stack->CoroutineSavedSP);
    /* CoroutineSavedSP may already be NULL here if the coroutine
     * has never been suspended. */
    Stack->CoroutineSavedSP = NULL;
}

static inline PVOID KiGetCoroutineSavedSP(PVOID StackTop)
{
    assert(StackTop != NULL);
    PKI_COROUTINE_STACK Stack = (PKI_COROUTINE_STACK)StackTop - 1;
    return Stack->CoroutineSavedSP;
}

/* arch/coroutine.S */
NTSTATUS KiStartCoroutine(IN PVOID StackTop,
			  IN KI_COROUTINE_ENTRYPOINT EntryPoint,
			  IN PVOID Context);
VOID KiYieldCoroutine();
FASTCALL NTSTATUS KiResumeCoroutine(IN PVOID StackTop);
