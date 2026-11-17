#pragma once

#include <nt.h>

/*
 * This is placed at the top of the coroutine stack. The top of the
 * stack is a pointer to the stack top of the next coroutine stack,
 * followed by Fiber which is the FIBER associated with this stack.
 *
 * Schematics of the coroutine stack: (assuming i386, stack top is at 0x1000)
 *
 *   0xfec                0xff0               0xff8   0xffc          0x1000
 *   |--------------------|------------------------------------------|
 *   | return addr (NULL) | alignment padding | Fiber | NextStackTop |
 *   |--------------------|------------------------------------------|
 *   ^                    ^                                          ^
 *   Beginning of the     Stack pointer at the time                  StackTop
 *   call stack inside    KiCoroutineEntryPoint is entered
 *   the coroutine,
 *   starting with
 *   IopCallDispatchRoutine
 *
 * Note: stack grows in the direction of lower address, so this structure
 * needs to be defined with that in mind.
 */
typedef struct _KI_COROUTINE_STACK_TOP {
#ifdef _M_IX86
    ULONG_PTR ReturnAddress; /* We push a zero as the return address so an exception
			      * will be raised when the fiber entry point tries to
			      * return (it should not). */
    ULONG_PTR Paddings[2]; /* GCC assumes a 16-byte aligned stack before
			    * the call instruction pushes the return address. */
#elif defined(_M_AMD64)
    ULONG_PTR ReturnAddress; /* We push a zero as the return address so an exception
			      * will be raised when the fiber entry point tries to
			      * return (it should not). */
    ULONG_PTR Paddings[4]; /* MS amd64 ABI requires a 32-byte shadow space
			    * before the call instruction pushes the return
			    * address. */
#endif
    PFIBER Fiber;          /* If NULL, this coroutine stack is free to use.
			    * This must be at the beginning of this struct. */
    PVOID NextStackTop;	   /* Pointer to the next coroutine stack. */
} KI_COROUTINE_STACK_TOP, *PKI_COROUTINE_STACK_TOP;

/*
 * Coroutine entry point. This is called when the fiber is first scheduled.
 */
typedef NTSTATUS (*KI_COROUTINE_ENTRYPOINT)(IN PVOID Context);

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
    LIST_ENTRY QueueListEntry;
    LIST_ENTRY EventLink; /* List entry for WAITABLE_OBJECT_HEADER::EnvList */
    BOOLEAN Suspended;
} IOP_EXEC_ENV, *PIOP_EXEC_ENV;

/* coroutine.c */
NTSTATUS KiStartCoroutine(IN PIOP_EXEC_ENV Env);
NTSTATUS KiResumeCoroutine(IN PIOP_EXEC_ENV Env);
VOID KiStopCoroutine(PIOP_EXEC_ENV Env);
VOID KiYieldCoroutine(VOID);
VOID KiDbgDumpCoroutineStacks(VOID);
NTSTATUS KiInitCoroutine(PVOID CoroutineChainHead);

static inline PFIBER KiGetCoroutineFiber(PVOID StackTop)
{
    assert(StackTop != NULL);
    PKI_COROUTINE_STACK_TOP Stack = (PKI_COROUTINE_STACK_TOP)StackTop - 1;
    return Stack->Fiber;
}

static inline VOID KiSetCoroutineFiber(PVOID StackTop,
				       IN PFIBER Fiber)
{
    assert(StackTop != NULL);
    PKI_COROUTINE_STACK_TOP Stack = (PKI_COROUTINE_STACK_TOP)StackTop - 1;
    Stack->Fiber = Fiber;
}

static inline PIOP_EXEC_ENV KiGetCurrentEnv(VOID)
{
    PFIBER Fiber = NtCurrentTeb()->NtTib.FiberData;
    return Fiber ? Fiber->FiberData : NULL;
}

static inline PVOID KiGetCurrentCoroutineStackTop(VOID)
{
    return KiGetCurrentEnv() ? KiGetCurrentEnv()->CoroutineStackTop : NULL;
}
